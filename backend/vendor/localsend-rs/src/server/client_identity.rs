//! The identity a sender proves during the TLS handshake.
//!
//! A LocalSend peer presents its own certificate as a TLS client certificate.
//! The receiver asks for one without requiring it and without validating a
//! chain, since peers are self-signed: any certificate is admitted, but the
//! handshake signature is still verified, so the peer has shown that it holds
//! the private key for the certificate it presented. The SHA-256 of that
//! certificate is the peer's LocalSend fingerprint. The `fingerprint` a sender
//! writes in a request body is only a claim, and anyone who has seen an
//! announcement can repeat it.

/// SHA-256 of the client certificate a connection proved possession of, or
/// `None` when the peer presented none.
#[derive(Clone, Debug)]
pub(crate) struct ClientCertificate(pub(crate) Option<String>);

#[cfg(feature = "https")]
pub(crate) use tls::{ClientIdentityAcceptor, server_config};

#[cfg(feature = "https")]
mod tls {
    use super::ClientCertificate;
    use crate::error::LocalSendError;
    use crate::server::limits::{ConnectionLimit, LimitedStream};
    use axum::Extension;
    use axum::middleware::AddExtension;
    use axum_server::accept::Accept;
    use axum_server::tls_rustls::RustlsAcceptor;
    use futures_util::future::BoxFuture;
    use rustls::pki_types::{CertificateDer, UnixTime};
    use rustls::server::danger::{ClientCertVerified, ClientCertVerifier};
    use std::sync::Arc;
    use tokio_rustls::server::TlsStream;
    use tower::Layer;

    /// Admits any client certificate, and none, while still verifying that the
    /// peer signed the handshake with the certificate's key.
    #[derive(Debug)]
    struct AnyClientCertificate {
        algorithms: rustls::crypto::WebPkiSupportedAlgorithms,
    }

    impl ClientCertVerifier for AnyClientCertificate {
        fn root_hint_subjects(&self) -> &[rustls::DistinguishedName] {
            &[]
        }

        fn client_auth_mandatory(&self) -> bool {
            false
        }

        fn verify_client_cert(
            &self,
            _end_entity: &CertificateDer<'_>,
            _intermediates: &[CertificateDer<'_>],
            _now: UnixTime,
        ) -> Result<ClientCertVerified, rustls::Error> {
            Ok(ClientCertVerified::assertion())
        }

        fn verify_tls12_signature(
            &self,
            message: &[u8],
            cert: &CertificateDer<'_>,
            dss: &rustls::DigitallySignedStruct,
        ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
            rustls::crypto::verify_tls12_signature(message, cert, dss, &self.algorithms)
        }

        fn verify_tls13_signature(
            &self,
            message: &[u8],
            cert: &CertificateDer<'_>,
            dss: &rustls::DigitallySignedStruct,
        ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
            rustls::crypto::verify_tls13_signature(message, cert, dss, &self.algorithms)
        }

        fn supported_verify_schemes(&self) -> Vec<rustls::SignatureScheme> {
            self.algorithms.supported_schemes()
        }
    }

    /// The receiver's TLS configuration: its own certificate, an optional
    /// client certificate, and HTTP/1.1 only (see `serve_http1`), so HTTP/2 is
    /// not offered during the handshake.
    pub(crate) fn server_config(
        cert_pem: &str,
        key_pem: &str,
    ) -> crate::Result<rustls::ServerConfig> {
        let invalid = |error: &dyn std::fmt::Display| {
            LocalSendError::network(format!("TLS config error: {error}"))
        };
        let certificates = rustls_pemfile::certs(&mut cert_pem.as_bytes())
            .collect::<Result<Vec<_>, _>>()
            .map_err(|error| invalid(&error))?;
        let key = rustls_pemfile::private_key(&mut key_pem.as_bytes())
            .map_err(|error| invalid(&error))?
            .ok_or_else(|| invalid(&"missing private key"))?;
        let provider = Arc::new(rustls::crypto::ring::default_provider());
        let verifier = Arc::new(AnyClientCertificate {
            algorithms: provider.signature_verification_algorithms,
        });
        let mut config = rustls::ServerConfig::builder_with_provider(provider)
            .with_safe_default_protocol_versions()
            .map_err(|error| invalid(&error))?
            .with_client_cert_verifier(verifier)
            .with_single_cert(certificates, key)
            .map_err(|error| invalid(&error))?;
        config.alpn_protocols = vec![b"http/1.1".to_vec()];
        Ok(config)
    }

    /// Completes the TLS handshake, then hands every request on the connection
    /// the fingerprint of the client certificate that handshake verified.
    #[derive(Clone)]
    pub(crate) struct ClientIdentityAcceptor {
        inner: RustlsAcceptor<ConnectionLimit>,
    }

    impl ClientIdentityAcceptor {
        pub(crate) fn new(inner: RustlsAcceptor<ConnectionLimit>) -> Self {
            Self { inner }
        }
    }

    impl<S: Send + 'static> Accept<tokio::net::TcpStream, S> for ClientIdentityAcceptor {
        type Stream = TlsStream<LimitedStream>;
        type Service = AddExtension<S, ClientCertificate>;
        type Future = BoxFuture<'static, std::io::Result<(Self::Stream, Self::Service)>>;

        fn accept(&self, stream: tokio::net::TcpStream, service: S) -> Self::Future {
            let handshake = self.inner.accept(stream, service);
            Box::pin(async move {
                let (stream, service) = handshake.await?;
                let fingerprint = stream
                    .get_ref()
                    .1
                    .peer_certificates()
                    .and_then(|certificates| certificates.first())
                    .map(|certificate| crate::crypto::sha256_from_bytes(certificate.as_ref()));
                Ok((
                    stream,
                    Extension(ClientCertificate(fingerprint)).layer(service),
                ))
            })
        }
    }
}

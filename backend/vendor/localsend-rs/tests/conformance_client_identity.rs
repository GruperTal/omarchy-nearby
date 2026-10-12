//! The receiver reports the TLS client certificate a sender proved possession
//! of, separately from the fingerprint the sender merely declares.

mod common;

use localsend_rs::server::{LocalSendServer, ServerEvent};
use localsend_rs::{
    DeviceInfo, LocalSendClient, Protocol, TlsTrustPolicy, build_file_metadata,
    generate_tls_certificate,
};
use std::collections::HashMap;
use std::time::Duration;
use tokio::sync::mpsc::UnboundedReceiver;

async fn start_receiver(
    save_dir: &std::path::Path,
    protocol: Protocol,
) -> (LocalSendServer, UnboundedReceiver<ServerEvent>) {
    LocalSendServer::builder()
        .alias("Receiver")
        .port(0)
        .save_dir(save_dir)
        .protocol(protocol)
        .auto_accept(false)
        .build()
        .await
        .expect("start receiver")
}

fn target(server: &LocalSendServer, protocol: Protocol) -> DeviceInfo {
    let mut target = DeviceInfo::new("Receiver".to_string(), server.port(), protocol);
    target.ip = Some("127.0.0.1".to_string());
    target.fingerprint = server.device().fingerprint.clone();
    target
}

/// Offer one file and return what the receiver's consumer was told about the
/// sender: the fingerprint it declared and the certificate it proved.
async fn offer(
    client: LocalSendClient,
    target: DeviceInfo,
    events: &mut UnboundedReceiver<ServerEvent>,
) -> (String, Option<String>) {
    let source = tempfile::tempdir().expect("source directory");
    let (path, _) = common::make_random_file(source.path(), "a.bin", 64);
    let metadata = build_file_metadata(&path).await.expect("metadata");
    let files = HashMap::from([(metadata.id.clone(), metadata)]);
    let sending = tokio::spawn(async move { client.prepare_upload(&target, files, None).await });

    let request = tokio::time::timeout(Duration::from_secs(10), async {
        loop {
            match events.recv().await {
                Some(ServerEvent::TransferRequest(request)) => break request,
                Some(_) => continue,
                None => panic!("receiver stopped before the request arrived"),
            }
        }
    })
    .await
    .expect("the request must reach the consumer");
    let seen = (
        request.sender().fingerprint.clone(),
        request.sender_certificate_fingerprint().map(str::to_owned),
    );
    request.decline();
    let _ = sending.await;
    seen
}

#[tokio::test(flavor = "multi_thread")]
async fn a_sender_that_presents_its_certificate_is_identified_by_it() {
    let save = tempfile::tempdir().expect("save directory");
    let (mut server, mut events) = start_receiver(save.path(), Protocol::Https).await;
    let target = target(&server, Protocol::Https);

    let certificate = generate_tls_certificate().expect("sender certificate");
    let mut sender = DeviceInfo::new("Sender".to_string(), 53317, Protocol::Https);
    sender.fingerprint = certificate.fingerprint.clone();
    let client = LocalSendClient::with_trust_policy_and_identity(
        sender,
        TlsTrustPolicy::new([target.fingerprint.clone()]),
        &certificate,
    )
    .expect("client");

    let (declared, proved) = offer(client, target, &mut events).await;
    assert_eq!(declared, certificate.fingerprint);
    assert_eq!(proved.as_deref(), Some(certificate.fingerprint.as_str()));
    server.stop();
}

#[tokio::test(flavor = "multi_thread")]
async fn a_declared_fingerprint_does_not_replace_the_certificate_that_was_presented() {
    let save = tempfile::tempdir().expect("save directory");
    let (mut server, mut events) = start_receiver(save.path(), Protocol::Https).await;
    let target = target(&server, Protocol::Https);

    // The sender holds its own key, and claims to be someone else: a
    // fingerprint is announced on the network, so it is trivial to learn.
    let trusted = generate_tls_certificate().expect("trusted certificate");
    let own = generate_tls_certificate().expect("sender certificate");
    let mut sender = DeviceInfo::new("Sender".to_string(), 53317, Protocol::Https);
    sender.fingerprint = trusted.fingerprint.clone();
    let client = LocalSendClient::with_trust_policy_and_identity(
        sender,
        TlsTrustPolicy::new([target.fingerprint.clone()]),
        &own,
    )
    .expect("client");

    let (declared, proved) = offer(client, target, &mut events).await;
    assert_eq!(declared, trusted.fingerprint, "the claim arrives as sent");
    assert_eq!(
        proved.as_deref(),
        Some(own.fingerprint.as_str()),
        "the proved identity must be the certificate presented, not the one claimed"
    );
    assert_ne!(proved.as_deref(), Some(trusted.fingerprint.as_str()));
    server.stop();
}

#[tokio::test(flavor = "multi_thread")]
async fn a_sender_without_a_certificate_is_still_served_but_proves_nothing() {
    let save = tempfile::tempdir().expect("save directory");
    let (mut server, mut events) = start_receiver(save.path(), Protocol::Https).await;
    let target = target(&server, Protocol::Https);

    let trusted = generate_tls_certificate().expect("trusted certificate");
    let mut sender = DeviceInfo::new("Sender".to_string(), 53317, Protocol::Https);
    sender.fingerprint = trusted.fingerprint.clone();
    let client = LocalSendClient::with_trust_policy(
        sender,
        TlsTrustPolicy::new([target.fingerprint.clone()]),
    )
    .expect("client");

    let (declared, proved) = offer(client, target, &mut events).await;
    assert_eq!(declared, trusted.fingerprint);
    assert_eq!(
        proved, None,
        "a client certificate is requested, not required"
    );
    server.stop();
}

#[tokio::test(flavor = "multi_thread")]
async fn plain_http_never_proves_an_identity() {
    let save = tempfile::tempdir().expect("save directory");
    let (mut server, mut events) = start_receiver(save.path(), Protocol::Http).await;
    let target = target(&server, Protocol::Http);

    let trusted = generate_tls_certificate().expect("trusted certificate");
    let mut sender = DeviceInfo::new("Sender".to_string(), 53317, Protocol::Http);
    sender.fingerprint = trusted.fingerprint.clone();

    let (declared, proved) = offer(LocalSendClient::new(sender), target, &mut events).await;
    assert_eq!(declared, trusted.fingerprint);
    assert_eq!(proved, None);
    server.stop();
}

/// Trusts whatever certificate the receiver presents; this client only exists
/// to misbehave towards it.
#[derive(Debug)]
struct AnyServerCertificate(rustls::crypto::WebPkiSupportedAlgorithms);

impl rustls::client::danger::ServerCertVerifier for AnyServerCertificate {
    fn verify_server_cert(
        &self,
        _end_entity: &rustls::pki_types::CertificateDer<'_>,
        _intermediates: &[rustls::pki_types::CertificateDer<'_>],
        _server_name: &rustls::pki_types::ServerName<'_>,
        _ocsp_response: &[u8],
        _now: rustls::pki_types::UnixTime,
    ) -> Result<rustls::client::danger::ServerCertVerified, rustls::Error> {
        Ok(rustls::client::danger::ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &rustls::pki_types::CertificateDer<'_>,
        dss: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        rustls::crypto::verify_tls12_signature(message, cert, dss, &self.0)
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &rustls::pki_types::CertificateDer<'_>,
        dss: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        rustls::crypto::verify_tls13_signature(message, cert, dss, &self.0)
    }

    fn supported_verify_schemes(&self) -> Vec<rustls::SignatureScheme> {
        self.0.supported_schemes()
    }
}

/// Presents one certificate while signing with another key.
#[derive(Debug)]
struct MismatchedIdentity(std::sync::Arc<rustls::sign::CertifiedKey>);

impl rustls::client::ResolvesClientCert for MismatchedIdentity {
    fn resolve(
        &self,
        _root_hint_subjects: &[&[u8]],
        _sigschemes: &[rustls::SignatureScheme],
    ) -> Option<std::sync::Arc<rustls::sign::CertifiedKey>> {
        Some(self.0.clone())
    }

    fn has_certs(&self) -> bool {
        true
    }
}

/// Ask the receiver for `/info` over a TLS connection built from `config` and
/// return whatever it answered, or nothing if the connection did not survive.
async fn info_response(port: u16, config: rustls::ClientConfig) -> String {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    let connector = tokio_rustls::TlsConnector::from(std::sync::Arc::new(config));
    let tcp = tokio::net::TcpStream::connect(("127.0.0.1", port))
        .await
        .expect("connect");
    let name = rustls::pki_types::ServerName::try_from("localhost").expect("server name");
    let Ok(mut stream) = connector.connect(name, tcp).await else {
        return String::new();
    };
    let request =
        b"GET /api/localsend/v2/info HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n";
    if stream.write_all(request).await.is_err() {
        return String::new();
    }
    let mut response = Vec::new();
    let _ = tokio::time::timeout(Duration::from_secs(10), stream.read_to_end(&mut response)).await;
    String::from_utf8_lossy(&response).into_owned()
}

#[tokio::test(flavor = "multi_thread")]
async fn a_certificate_presented_without_its_key_is_refused() {
    let save = tempfile::tempdir().expect("save directory");
    let (mut server, _events) = start_receiver(save.path(), Protocol::Https).await;
    let provider = std::sync::Arc::new(rustls::crypto::ring::default_provider());
    let client_config = |identity: std::sync::Arc<rustls::sign::CertifiedKey>| {
        rustls::ClientConfig::builder_with_provider(provider.clone())
            .with_safe_default_protocol_versions()
            .expect("protocol versions")
            .dangerous()
            .with_custom_certificate_verifier(std::sync::Arc::new(AnyServerCertificate(
                provider.signature_verification_algorithms,
            )))
            .with_client_cert_resolver(std::sync::Arc::new(MismatchedIdentity(identity)))
    };
    let identity = |certificate: &localsend_rs::TlsCertificate,
                    key: &localsend_rs::TlsCertificate| {
        let key = rustls_pemfile::private_key(&mut key.key_pem.as_bytes())
            .expect("key")
            .expect("one key");
        std::sync::Arc::new(rustls::sign::CertifiedKey::new(
            vec![rustls::pki_types::CertificateDer::from(
                certificate.cert_der.clone(),
            )],
            rustls::crypto::ring::sign::any_supported_type(&key).expect("signing key"),
        ))
    };

    // The certificate is public: the trusted device presents it to every peer
    // it connects to. Only its owner can sign a handshake with it.
    let trusted = generate_tls_certificate().expect("trusted certificate");
    let attacker = generate_tls_certificate().expect("attacker certificate");

    let honest = info_response(server.port(), client_config(identity(&trusted, &trusted))).await;
    assert!(
        honest.starts_with("HTTP/1.1 200"),
        "a certificate presented with its own key must be served, got: {honest:?}"
    );

    let forged = info_response(server.port(), client_config(identity(&trusted, &attacker))).await;
    assert!(
        !forged.contains("HTTP/1.1"),
        "a certificate presented without its key must not get a response, got: {forged:?}"
    );
    server.stop();
}

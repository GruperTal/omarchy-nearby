use crate::secure_state::StateDir;
use anyhow::{Context, Result, anyhow};
use serde::{Deserialize, Serialize};
#[cfg(test)]
use std::fs;
use std::io::Read;
use std::path::{Path, PathBuf};
#[cfg(test)]
use std::sync::atomic::{AtomicU64, Ordering};

const SETTINGS_VERSION: u32 = 1;
const MAX_INCOMING_PIN_LENGTH: usize = 64;
const MAX_SETTINGS_BYTES: usize = 16 * 1024;
/// Devices whose transfers are accepted without asking. Small on purpose: it
/// is a list of the user's own devices, and it has to fit the settings cap.
const MAX_TRUSTED_DEVICES: usize = 32;
const MAX_TRUSTED_ALIAS_CHARS: usize = 128;
#[cfg(test)]
static TEMP_SEQUENCE: AtomicU64 = AtomicU64::new(0);

/// A device trusted by the certificate it proves in the TLS handshake. The
/// alias is only a label for the user; it identifies nothing.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct TrustedDevice {
    pub fingerprint: String,
    pub alias: String,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Settings {
    version: u32,
    #[serde(default)]
    pub incoming_pin: Option<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub trusted_devices: Vec<TrustedDevice>,
}

impl Default for Settings {
    fn default() -> Self {
        Self {
            version: SETTINGS_VERSION,
            incoming_pin: None,
            trusted_devices: Vec::new(),
        }
    }
}

/// A certificate fingerprint in the one form it is stored and compared in:
/// the 64 lowercase hex digits of a SHA-256.
pub fn certificate_fingerprint(value: &str) -> Option<String> {
    (value.len() == 64 && value.bytes().all(|byte| byte.is_ascii_hexdigit()))
        .then(|| value.to_ascii_lowercase())
}

fn valid_trusted_alias(alias: &str) -> bool {
    alias.chars().count() <= MAX_TRUSTED_ALIAS_CHARS && !alias.chars().any(char::is_control)
}

pub fn valid_incoming_pin(pin: &str) -> bool {
    !pin.is_empty()
        && pin.len() <= MAX_INCOMING_PIN_LENGTH
        && pin
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b'~' | b'-'))
}

fn validate(settings: &Settings) -> Result<()> {
    if settings.version != SETTINGS_VERSION {
        return Err(anyhow!("unsupported security settings version"));
    }
    if settings
        .incoming_pin
        .as_deref()
        .is_some_and(|pin| !valid_incoming_pin(pin))
    {
        return Err(anyhow!("invalid incoming PIN configuration"));
    }
    if settings.trusted_devices.len() > MAX_TRUSTED_DEVICES {
        return Err(anyhow!("too many trusted devices"));
    }
    for (index, device) in settings.trusted_devices.iter().enumerate() {
        let stored_form = certificate_fingerprint(&device.fingerprint);
        if stored_form.as_deref() != Some(device.fingerprint.as_str())
            || !valid_trusted_alias(&device.alias)
            || settings.trusted_devices[..index]
                .iter()
                .any(|earlier| earlier.fingerprint == device.fingerprint)
        {
            return Err(anyhow!("invalid trusted device configuration"));
        }
    }
    Ok(())
}

pub fn state_dir(home: &Path) -> PathBuf {
    std::env::var("XDG_STATE_HOME")
        .map(PathBuf::from)
        .unwrap_or_else(|_| home.join(".local/state"))
        .join("omarchy-nearby")
}

fn read_bounded(reader: impl Read) -> Result<Vec<u8>> {
    let mut data = Vec::new();
    reader
        .take((MAX_SETTINGS_BYTES + 1) as u64)
        .read_to_end(&mut data)
        .context("could not read security settings")?;
    if data.len() > MAX_SETTINGS_BYTES {
        return Err(anyhow!("security settings exceed 16 KiB"));
    }
    Ok(data)
}

pub fn load(path: &Path) -> Result<Settings> {
    let parent = path
        .parent()
        .ok_or_else(|| anyhow!("security settings path has no parent"))?;
    let name = path
        .file_name()
        .and_then(|name| name.to_str())
        .ok_or_else(|| anyhow!("invalid security settings file name"))?;
    let state = StateDir::open_or_create(parent)?;
    let Some((mut file, metadata)) = state.open_regular(name)? else {
        return Ok(Settings::default());
    };
    if metadata.len() > MAX_SETTINGS_BYTES as u64 {
        return Err(anyhow!("security settings exceed 16 KiB"));
    }
    let data = read_bounded(&mut file)?;
    let settings: Settings =
        serde_json::from_slice(&data).context("could not parse security settings")?;
    validate(&settings)?;
    Ok(settings)
}

pub fn save(path: &Path, settings: &Settings) -> Result<()> {
    validate(settings)?;
    let parent = path
        .parent()
        .ok_or_else(|| anyhow!("security settings path has no parent"))?;
    let name = path
        .file_name()
        .and_then(|name| name.to_str())
        .ok_or_else(|| anyhow!("invalid security settings file name"))?;
    let state = StateDir::open_or_create(parent)?;
    let mut data = serde_json::to_vec_pretty(settings).context("could not serialize settings")?;
    data.push(b'\n');
    state.replace(name, &data)
}

pub fn updated(current: &Settings, incoming_pin: Option<String>) -> Result<Settings> {
    let next = Settings {
        incoming_pin,
        ..current.clone()
    };
    validate(&next)?;
    Ok(next)
}

/// `current` with one device trusted. Trusting a device again only refreshes
/// its label.
pub fn with_trusted_device(current: &Settings, fingerprint: &str, alias: &str) -> Result<Settings> {
    let fingerprint =
        certificate_fingerprint(fingerprint).ok_or_else(|| anyhow!("invalid fingerprint"))?;
    let mut next = without_trusted_device(current, &fingerprint);
    next.trusted_devices.push(TrustedDevice {
        fingerprint,
        alias: alias.to_string(),
    });
    validate(&next)?;
    Ok(next)
}

/// `current` without a device. Removing one that is not trusted changes nothing.
pub fn without_trusted_device(current: &Settings, fingerprint: &str) -> Settings {
    let mut next = current.clone();
    next.trusted_devices
        .retain(|device| !device.fingerprint.eq_ignore_ascii_case(fingerprint));
    next
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_directory(name: &str) -> PathBuf {
        std::env::temp_dir().join(format!(
            "omarchy-nearby-settings-{name}-{}-{}",
            std::process::id(),
            TEMP_SEQUENCE.fetch_add(1, Ordering::Relaxed)
        ))
    }

    #[test]
    fn incoming_pin_profile_is_exact() {
        for pin in ["1", "123456", "Abc-_.~09", &"x".repeat(64)] {
            assert!(valid_incoming_pin(pin), "expected valid PIN: {pin}");
        }
        for pin in [
            "",
            "with space",
            "a+b",
            "a&b",
            "contraseña",
            &"x".repeat(65),
        ] {
            assert!(!valid_incoming_pin(pin), "expected invalid PIN: {pin}");
        }
    }

    #[test]
    fn missing_settings_are_disabled_and_valid_settings_round_trip() {
        let directory = test_directory("round-trip");
        let path = directory.join("settings.json");
        assert_eq!(load(&path).unwrap(), Settings::default());

        let settings = updated(&Settings::default(), Some("Abc-123".to_string())).unwrap();
        save(&path, &settings).unwrap();
        assert_eq!(load(&path).unwrap(), settings);
        assert_eq!(fs::read_dir(&directory).unwrap().count(), 1);

        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            assert_eq!(
                fs::metadata(&directory).unwrap().permissions().mode() & 0o777,
                0o700
            );
            assert_eq!(
                fs::metadata(&path).unwrap().permissions().mode() & 0o777,
                0o600
            );
        }
        fs::remove_dir_all(directory).unwrap();
    }

    #[test]
    fn malformed_unsupported_and_invalid_settings_fail_closed() {
        let directory = test_directory("invalid");
        fs::create_dir_all(&directory).unwrap();
        let path = directory.join("settings.json");

        for data in [
            b"not json".as_slice(),
            br#"{"version":2,"incomingPin":null}"#,
            br#"{"version":1,"incomingPin":"a+b"}"#,
        ] {
            fs::write(&path, data).unwrap();
            assert!(load(&path).is_err());
        }

        fs::write(
            &path,
            br#"{"version":1,"incomingPin":"Safe-1","futureField":true}"#,
        )
        .unwrap();
        assert_eq!(load(&path).unwrap().incoming_pin.as_deref(), Some("Safe-1"));
        for data in [
            br#"{"version":1}"#.as_slice(),
            br#"{"version":1,"incomingPin":null}"#,
        ] {
            fs::write(&path, data).unwrap();
            assert_eq!(load(&path).unwrap(), Settings::default());
        }
        fs::remove_dir_all(directory).unwrap();
    }

    #[test]
    fn settings_size_boundary_and_compatible_json_are_preserved() {
        let directory = test_directory("size");
        fs::create_dir_all(&directory).unwrap();
        let path = directory.join("settings.json");
        let mut data = br#"{"version":1,"incomingPin":null,"futureField":true}"#.to_vec();
        data.resize(MAX_SETTINGS_BYTES, b' ');
        fs::write(&path, &data).unwrap();
        assert_eq!(load(&path).unwrap(), Settings::default());

        data.push(b' ');
        fs::write(&path, &data).unwrap();
        assert!(load(&path).is_err(), "valid JSON beyond the cap must fail");
        assert_eq!(fs::read(&path).unwrap(), data);

        let settings = updated(&Settings::default(), Some("x".repeat(64))).unwrap();
        save(&path, &settings).unwrap();
        save(&path, &settings).unwrap();
        assert!(fs::metadata(&path).unwrap().len() < MAX_SETTINGS_BYTES as u64);
        assert_eq!(load(&path).unwrap(), settings);
        assert_eq!(fs::read_dir(&directory).unwrap().count(), 1);
        fs::remove_dir_all(directory).unwrap();
    }

    #[test]
    fn trusted_devices_round_trip_and_survive_a_pin_change() {
        let directory = test_directory("trusted");
        let path = directory.join("settings.json");
        let upper = "AB".repeat(32);
        let lower = "ab".repeat(32);

        let trusted = with_trusted_device(&Settings::default(), &upper, "Phone").unwrap();
        assert_eq!(
            trusted.trusted_devices,
            vec![TrustedDevice {
                fingerprint: lower.clone(),
                alias: "Phone".into()
            }],
            "a fingerprint is stored in the one form it is compared in"
        );
        save(&path, &trusted).unwrap();
        assert_eq!(load(&path).unwrap(), trusted);

        let with_pin = updated(&trusted, Some("Abc-123".into())).unwrap();
        assert_eq!(
            with_pin.trusted_devices, trusted.trusted_devices,
            "changing the PIN must not forget trusted devices"
        );

        let relabelled = with_trusted_device(&with_pin, &lower, "Pixel").unwrap();
        assert_eq!(relabelled.trusted_devices.len(), 1, "one entry per device");
        assert_eq!(relabelled.trusted_devices[0].alias, "Pixel");

        let removed = without_trusted_device(&relabelled, &upper);
        assert!(removed.trusted_devices.is_empty());
        assert_eq!(removed.incoming_pin.as_deref(), Some("Abc-123"));
        assert_eq!(without_trusted_device(&removed, &lower), removed);

        save(&path, &Settings::default()).unwrap();
        assert!(
            !fs::read_to_string(&path)
                .unwrap()
                .contains("trustedDevices"),
            "settings without trusted devices keep the document older helpers wrote"
        );
        fs::remove_dir_all(directory).unwrap();
    }

    #[test]
    fn invalid_trusted_devices_are_refused_and_fail_closed() {
        let lower = "ab".repeat(32);
        for fingerprint in ["", "abc", &"g".repeat(64), &"ab".repeat(33), "sender-fp"] {
            assert!(
                with_trusted_device(&Settings::default(), fingerprint, "Phone").is_err(),
                "expected an invalid fingerprint: {fingerprint}"
            );
        }
        assert!(with_trusted_device(&Settings::default(), &lower, "line\nbreak").is_err());
        assert!(with_trusted_device(&Settings::default(), &lower, &"x".repeat(129)).is_err());

        let mut full = Settings::default();
        for index in 0..MAX_TRUSTED_DEVICES {
            full = with_trusted_device(&full, &format!("{index:064x}"), "Device").unwrap();
        }
        assert!(with_trusted_device(&full, &lower, "One too many").is_err());
        assert!(
            with_trusted_device(&full, &format!("{:064x}", 0), "Relabelled").is_ok(),
            "a full list must still let a trusted device be relabelled"
        );

        let directory = test_directory("trusted-invalid");
        fs::create_dir_all(&directory).unwrap();
        let path = directory.join("settings.json");
        let upper = "AB".repeat(32);
        for data in [
            format!(
                r#"{{"version":1,"trustedDevices":[{{"fingerprint":"{upper}","alias":"Phone"}}]}}"#
            ),
            format!(
                r#"{{"version":1,"trustedDevices":[{{"fingerprint":"{lower}","alias":"A"}},{{"fingerprint":"{lower}","alias":"B"}}]}}"#
            ),
            r#"{"version":1,"trustedDevices":[{"fingerprint":"short","alias":"Phone"}]}"#
                .to_string(),
            r#"{"version":1,"trustedDevices":"all"}"#.to_string(),
        ] {
            fs::write(&path, &data).unwrap();
            assert!(
                load(&path).is_err(),
                "a trust list that cannot be read exactly must stop startup: {data}"
            );
        }
        fs::remove_dir_all(directory).unwrap();
    }

    #[test]
    fn bounded_reader_stops_after_cap_plus_one_bytes() {
        struct CountingReader(usize);
        impl Read for CountingReader {
            fn read(&mut self, buffer: &mut [u8]) -> std::io::Result<usize> {
                buffer.fill(b' ');
                self.0 += buffer.len();
                Ok(buffer.len())
            }
        }
        let mut reader = CountingReader(0);
        assert!(read_bounded(&mut reader).is_err());
        assert_eq!(reader.0, MAX_SETTINGS_BYTES + 1);
    }

    #[cfg(unix)]
    #[test]
    fn symlinks_and_non_regular_settings_are_rejected() {
        use std::os::unix::fs::symlink;

        let directory = test_directory("unsafe-types");
        fs::create_dir_all(&directory).unwrap();
        let target = directory.join("valid.json");
        let bytes = br#"{"version":1,"incomingPin":"Safe-1"}"#;
        fs::write(&target, bytes).unwrap();

        let link = directory.join("settings.json");
        symlink(&target, &link).unwrap();
        assert!(
            load(&link).is_err(),
            "a valid symlink target must not be read"
        );
        assert_eq!(fs::read(&target).unwrap(), bytes);
        assert_eq!(fs::read_link(&link).unwrap(), target);

        fs::remove_file(&link).unwrap();
        symlink(directory.join("missing.json"), &link).unwrap();
        assert!(load(&link).is_err(), "a broken symlink is not absence");
        assert!(
            fs::symlink_metadata(&link)
                .unwrap()
                .file_type()
                .is_symlink()
        );

        fs::remove_file(&link).unwrap();
        fs::create_dir(&link).unwrap();
        assert!(load(&link).is_err(), "a directory is not settings");
        fs::remove_dir_all(directory).unwrap();
    }

    #[cfg(unix)]
    #[test]
    fn opened_settings_must_belong_to_the_expected_user() {
        let directory = test_directory("owner");
        fs::create_dir_all(&directory).unwrap();
        let path = directory.join("settings.json");
        fs::write(&path, br#"{"version":1}"#).unwrap();
        let file = fs::File::open(&path).unwrap();
        let current_uid = unsafe { libc::geteuid() };
        let metadata = file.metadata().unwrap();
        assert!(crate::secure_state::validate_owned_regular_file(&metadata, current_uid).is_ok());
        assert!(
            crate::secure_state::validate_owned_regular_file(
                &metadata,
                current_uid.wrapping_add(1)
            )
            .is_err()
        );
        assert_eq!(fs::read(&path).unwrap(), br#"{"version":1}"#);
        fs::remove_dir_all(directory).unwrap();
    }

    #[cfg(unix)]
    #[test]
    fn fifo_child() {
        if let Some(path) = std::env::var_os("NEARBY_TEST_SETTINGS_FIFO") {
            assert!(load(Path::new(&path)).is_err());
        }
    }

    #[cfg(unix)]
    #[test]
    fn fifo_without_writer_is_rejected_without_blocking() {
        use std::ffi::CString;
        use std::os::unix::ffi::OsStrExt;
        use std::process::{Command, Stdio};
        use std::time::{Duration, Instant};

        let directory = test_directory("fifo");
        fs::create_dir_all(&directory).unwrap();
        let path = directory.join("settings.json");
        let c_path = CString::new(path.as_os_str().as_bytes()).unwrap();
        assert_eq!(unsafe { libc::mkfifo(c_path.as_ptr(), 0o600) }, 0);

        let mut child = Command::new(std::env::current_exe().unwrap())
            .args(["--exact", "settings::tests::fifo_child"])
            .env("NEARBY_TEST_SETTINGS_FIFO", &path)
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .unwrap();
        let deadline = Instant::now() + Duration::from_secs(5);
        let status = loop {
            if let Some(status) = child.try_wait().unwrap() {
                break Some(status);
            }
            if Instant::now() >= deadline {
                child.kill().unwrap();
                child.wait().unwrap();
                break None;
            }
            std::thread::sleep(Duration::from_millis(10));
        };
        fs::remove_dir_all(directory).unwrap();
        assert!(
            status.is_some_and(|status| status.success()),
            "FIFO load blocked or failed"
        );
    }

    #[test]
    fn ancestor_symlink_and_relative_xdg_state_are_rejected() {
        use std::os::unix::fs::symlink;

        let base = test_directory("ancestor");
        let target = base.join("target");
        fs::create_dir_all(&target).unwrap();
        let link = base.join("linked");
        symlink(&target, &link).unwrap();
        let path = link.join("omarchy-nearby/settings.json");
        assert!(load(&path).is_err());
        assert!(save(&path, &Settings::default()).is_err());
        assert!(fs::read_dir(&target).unwrap().next().is_none());
        assert!(StateDir::open_or_create(Path::new("relative/omarchy-nearby")).is_err());
        fs::remove_dir_all(base).unwrap();
    }

    #[test]
    fn concurrent_saves_leave_a_complete_settings_document() {
        let directory = test_directory("concurrent");
        let path = directory.join("settings.json");
        save(&path, &Settings::default()).unwrap();
        std::thread::scope(|scope| {
            for index in 0..8 {
                let path = &path;
                scope.spawn(move || {
                    let next = updated(&Settings::default(), Some(format!("Pin-{index}"))).unwrap();
                    for _ in 0..16 {
                        save(path, &next).unwrap();
                    }
                });
            }
        });
        let loaded = load(&path).unwrap();
        assert!(loaded.incoming_pin.unwrap().starts_with("Pin-"));
        assert_eq!(fs::read_dir(&directory).unwrap().count(), 1);
        fs::remove_dir_all(directory).unwrap();
    }
}

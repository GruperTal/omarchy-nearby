use crate::error::{LocalSendError, Result};
use std::path::{Path, PathBuf};

/// Bounds for slash-separated LocalSend file names, measured in UTF-8 bytes.
pub const MAX_REMOTE_PATH_BYTES: usize = 4096;
pub const MAX_REMOTE_COMPONENT_BYTES: usize = 255;
pub const MAX_REMOTE_DIRECTORY_DEPTH: usize = 32;

/// Validate the wire spelling before Path::components can normalize away `.`
/// or empty segments. Apply the same rules on send and before receive approval.
pub fn validate_remote_file_name(remote_name: &str) -> Result<()> {
    if remote_name.is_empty()
        || remote_name.len() > MAX_REMOTE_PATH_BYTES
        || remote_name.contains('\0')
        || remote_name.contains('\\')
        || remote_name.contains(':')
        || remote_name.split('/').count() > MAX_REMOTE_DIRECTORY_DEPTH + 1
        || remote_name.split('/').any(|part| {
            part.is_empty() || part.starts_with('.') || part.len() > MAX_REMOTE_COMPONENT_BYTES
        })
    {
        return Err(LocalSendError::invalid_file("Unsafe remote file name"));
    }
    Ok(())
}

pub(crate) fn safe_join(base: &Path, remote_name: &str) -> Result<PathBuf> {
    validate_remote_file_name(remote_name)?;
    let relative = Path::new(remote_name);

    // Remote file names may carry relative directory components for folder
    // transfers. Ensure no component inside base is an existing symlink to
    // prevent symlinked-parent directory traversal escapes.
    let mut check_path = base.to_path_buf();
    for part in relative.components() {
        check_path.push(part);
        match std::fs::symlink_metadata(&check_path) {
            Ok(meta) if meta.file_type().is_symlink() => {
                return Err(LocalSendError::invalid_file(
                    "Unsafe symlink in remote path",
                ));
            }
            Ok(_) => {}
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
            Err(error) => return Err(error.into()),
        }
    }

    Ok(base.join(relative))
}

#[cfg(test)]
mod tests {
    use super::safe_join;
    use std::path::Path;

    #[test]
    fn rejects_unsafe_wire_spellings_without_normalizing() {
        for name in [
            "",
            ".",
            "..",
            "./file",
            "folder/./file",
            "folder//file",
            "folder/",
            ".config/autostart/app.desktop",
            "folder/.hidden",
            "folder/../file",
            "/absolute",
            "x\\y",
            "x:y",
            "x\0y",
        ] {
            assert!(
                safe_join(Path::new("/tmp/localsend"), name).is_err(),
                "{name:?}"
            );
        }
    }

    #[test]
    fn bounds_wire_paths_in_utf8_bytes_and_directory_depth() {
        use super::{MAX_REMOTE_PATH_BYTES, validate_remote_file_name};
        let at_depth = format!("{}file", "d/".repeat(32));
        assert!(validate_remote_file_name(&at_depth).is_ok());
        assert!(validate_remote_file_name(&format!("d/{at_depth}")).is_err());
        assert!(validate_remote_file_name(&"é".repeat(127)).is_ok());
        assert!(validate_remote_file_name(&"é".repeat(128)).is_err());
        let long = vec!["a".repeat(255); 16].join("/");
        assert_eq!(long.len(), MAX_REMOTE_PATH_BYTES - 1);
        assert!(validate_remote_file_name(&long).is_ok());
        assert!(validate_remote_file_name(&format!("{long}/a")).is_err());
    }

    #[test]
    fn allows_safe_nested_relative_paths() {
        let base = Path::new("/tmp/localsend");
        assert_eq!(
            safe_join(base, "nested/file.txt").unwrap(),
            base.join("nested/file.txt")
        );
        assert_eq!(
            safe_join(base, "a/b/c/file.txt").unwrap(),
            base.join("a/b/c/file.txt")
        );
    }

    #[test]
    fn rejects_symlink_in_nested_path() {
        let dir = std::env::temp_dir().join(format!("lsrs-symlink-test-{}", uuid::Uuid::new_v4()));
        std::fs::create_dir_all(&dir).unwrap();
        let target =
            std::env::temp_dir().join(format!("lsrs-symlink-target-{}", uuid::Uuid::new_v4()));
        std::fs::create_dir_all(&target).unwrap();
        let link = dir.join("link_dir");
        #[cfg(unix)]
        std::os::unix::fs::symlink(&target, &link).unwrap();

        #[cfg(unix)]
        assert!(safe_join(&dir, "link_dir/file.txt").is_err());

        let _ = std::fs::remove_dir_all(&dir);
        let _ = std::fs::remove_dir_all(&target);
    }

    #[test]
    fn rejects_parent_directory_escape() {
        let base = Path::new("/tmp/localsend");

        assert!(safe_join(base, "../evil.txt").is_err());
        assert!(safe_join(base, "nested/../../evil.txt").is_err());
    }

    #[test]
    fn rejects_absolute_paths() {
        let base = Path::new("/tmp/localsend");

        assert!(safe_join(base, "/tmp/evil.txt").is_err());
    }

    #[test]
    fn rejects_windows_style_paths() {
        let base = Path::new("/tmp/localsend");

        assert!(safe_join(base, "C:\\Users\\evil.txt").is_err());
        assert!(safe_join(base, "nested\\evil.txt").is_err());
    }
}

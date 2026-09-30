//! Command flows (`push`, `pull`, `list`, `delete`) orchestrated against the `Store` trait.

use anyhow::{Result, bail};

/// Maximum key-name length in bytes (all allowed characters are ASCII).
pub const MAX_KEY_NAME_LEN: usize = 128;

/// Suffix appended to a key name to form its Drive file name.
pub const DRIVE_SUFFIX: &str = ".enc";

/// Validates a user-supplied key name against `^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$`.
///
/// Runs before any I/O. The restricted alphabet rules out path traversal, Drive query
/// injection, and Unicode look-alikes; the name is also bound into the AEAD tag.
pub fn validate_key_name(name: &str) -> Result<()> {
    let bytes = name.as_bytes();
    let Some(first) = bytes.first() else {
        bail!("key name must not be empty");
    };
    if bytes.len() > MAX_KEY_NAME_LEN {
        bail!("key name must be at most {MAX_KEY_NAME_LEN} characters");
    }
    if !first.is_ascii_alphanumeric() {
        bail!("key name must start with a letter or digit");
    }
    if !bytes
        .iter()
        .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'_' | b'-'))
    {
        bail!("key name may only contain letters, digits, '.', '_' and '-'");
    }
    Ok(())
}

/// Drive file name for a (validated) key name: `<key name>.enc`.
pub fn drive_name(key_name: &str) -> String {
    format!("{key_name}{DRIVE_SUFFIX}")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn accepts_valid_names() {
        for name in [
            "a",
            "7",
            "prod-bastion.pem",
            "Prod_Cluster-01.key.pem",
            "x..y",
            "ends-with-dot.",
            &"a".repeat(MAX_KEY_NAME_LEN),
        ] {
            assert!(validate_key_name(name).is_ok(), "{name:?}");
        }
    }

    #[test]
    fn rejects_invalid_names() {
        for name in [
            "",
            &"a".repeat(MAX_KEY_NAME_LEN + 1),
            ".hidden.pem",
            "-flag.pem",
            "_x",
            "../x",
            "a/b.pem",
            "a\\b.pem",
            "it's.pem",
            "quote\".pem",
            "space name.pem",
            "tab\t.pem",
            "new\nline",
            "nul\0.pem",
            "clé.pem",
            "ｐｒｏｄ.pem", // full-width look-alikes
            "prod.pem\u{200b}",
        ] {
            assert!(validate_key_name(name).is_err(), "{name:?}");
        }
    }

    #[test]
    fn drive_name_appends_suffix() {
        assert_eq!(drive_name("prod-bastion.pem"), "prod-bastion.pem.enc");
    }
}

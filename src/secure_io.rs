//! Local secret handling: bounded input reads, exclusive `0600` output writes, TTY passphrase prompts.

use std::fs::{self, File, OpenOptions};
use std::io::{self, Read, Write};
use std::path::Path;

use anyhow::{Context, Result, bail};
use zeroize::Zeroizing;

/// Largest `.pem` file `push` accepts. Real private keys are a few KiB at most.
pub const MAX_INPUT_LEN: usize = 1024 * 1024;

/// Minimum master-passphrase length (in characters) for new envelopes.
pub const MIN_PASSPHRASE_CHARS: usize = 12;

const PASSPHRASE_ATTEMPTS: usize = 3;

/// Reads a local key file into a zeroize-on-drop buffer.
///
/// - Rejects anything that is not a regular file (devices, FIFOs, directories).
/// - Rejects empty files and files over [`MAX_INPUT_LEN`]; at most `MAX_INPUT_LEN + 1` bytes
///   are ever read, whatever the file's size.
/// - Reads into a single buffer allocated up front, so no reallocation leaves plaintext
///   copies behind in freed memory.
/// - Prints a warning, but continues, if the content does not look like PEM.
pub fn read_input(path: &Path) -> Result<Zeroizing<Vec<u8>>> {
    let display = path.display();
    let mut file = File::open(path).with_context(|| format!("cannot open {display}"))?;
    let metadata = file
        .metadata()
        .with_context(|| format!("cannot inspect {display}"))?;
    if !metadata.is_file() {
        bail!("{display} is not a regular file");
    }

    // The size limit is enforced on the bytes actually read (not on metadata, which can change
    // between the check and the read); one byte of headroom detects oversized files.
    let mut buf = Zeroizing::new(vec![0u8; MAX_INPUT_LEN + 1]);
    let mut filled = 0;
    while filled < buf.len() {
        match file.read(&mut buf[filled..]) {
            Ok(0) => break,
            Ok(n) => filled += n,
            Err(e) if e.kind() == io::ErrorKind::Interrupted => {}
            Err(e) => return Err(e).with_context(|| format!("cannot read {display}")),
        }
    }
    if filled > MAX_INPUT_LEN {
        bail!("{display} is larger than {} KiB", MAX_INPUT_LEN / 1024);
    }
    if filled == 0 {
        bail!("{display} is empty");
    }
    // `truncate` keeps the allocation; `Zeroizing` scrubs the full capacity on drop.
    buf.truncate(filled);

    if !looks_like_pem(&buf) {
        eprintln!(
            "[!] {display} does not look like a PEM file (no \"-----BEGIN\"); encrypting it anyway"
        );
    }
    Ok(buf)
}

fn looks_like_pem(bytes: &[u8]) -> bool {
    bytes.trim_ascii_start().starts_with(b"-----BEGIN")
}

/// Writes decrypted key material to a **new** file.
///
/// - `create_new` (`O_CREAT | O_EXCL`): never overwrites, and fails on any existing path,
///   including symlinks (dangling or not), so it cannot be redirected elsewhere.
/// - Unix: the file is created with mode `0600` atomically, before any bytes are written.
/// - The data is flushed with `sync_all`; if writing or syncing fails, the partial file is
///   deleted.
/// - Windows: the file inherits its folder's ACLs, and a warning says so.
pub fn write_secure(path: &Path, bytes: &[u8]) -> Result<()> {
    write_secure_with(path, |file| file.write_all(bytes))
}

fn write_secure_with(path: &Path, write: impl FnOnce(&mut File) -> io::Result<()>) -> Result<()> {
    let display = path.display();
    let mut options = OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }

    let mut file = match options.open(path) {
        Ok(file) => file,
        Err(e) if e.kind() == io::ErrorKind::AlreadyExists => {
            bail!("{display} already exists; refusing to overwrite it (choose a new --output path)")
        }
        Err(e) => return Err(e).with_context(|| format!("cannot create {display}")),
    };

    if let Err(e) = write(&mut file).and_then(|()| file.sync_all()) {
        drop(file);
        let cleanup = fs::remove_file(path);
        let err = Err::<(), _>(e).with_context(|| format!("failed to write {display}"));
        return match cleanup {
            Ok(()) => err,
            Err(_) => err.context(format!(
                "could not remove the partially written file {display}; delete it manually"
            )),
        };
    }

    #[cfg(windows)]
    eprintln!(
        "[!] {display} inherits its folder's permissions on Windows; it is not restricted to your user"
    );
    Ok(())
}

/// Prompts for the master passphrase on the terminal (never from arguments or environment).
///
/// With `confirm` (used by `push`), the passphrase must be at least
/// [`MIN_PASSPHRASE_CHARS`] characters and typed twice; the user gets
/// three attempts.
pub fn prompt_passphrase(confirm: bool) -> Result<Zeroizing<String>> {
    if !confirm {
        let passphrase = read_tty("Enter master passphrase: ")?;
        if passphrase.is_empty() {
            bail!("passphrase must not be empty");
        }
        return Ok(passphrase);
    }

    for attempt in 1..=PASSPHRASE_ATTEMPTS {
        let first = read_tty("Enter master passphrase: ")?;
        let result = check_new_passphrase(&first).and_then(|()| {
            let second = read_tty("Confirm master passphrase: ")?;
            if *first == *second {
                Ok(())
            } else {
                bail!("passphrases do not match")
            }
        });
        match result {
            Ok(()) => return Ok(first),
            Err(e) if attempt < PASSPHRASE_ATTEMPTS => eprintln!("[!] {e}; try again"),
            Err(e) => return Err(e),
        }
    }
    unreachable!("the loop returns on the last attempt")
}

/// Policy for new master passphrases.
fn check_new_passphrase(passphrase: &str) -> Result<()> {
    if passphrase.chars().count() < MIN_PASSPHRASE_CHARS {
        bail!("passphrase must be at least {MIN_PASSPHRASE_CHARS} characters");
    }
    Ok(())
}

fn read_tty(prompt: &str) -> Result<Zeroizing<String>> {
    rpassword::prompt_password(prompt)
        .map(Zeroizing::new)
        .context("cannot read the passphrase: an interactive terminal is required")
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    const PEM: &[u8] = b"-----BEGIN PRIVATE KEY-----\nNOT-A-REAL-KEY\n-----END PRIVATE KEY-----\n";

    fn dir() -> TempDir {
        tempfile::tempdir().unwrap()
    }

    // ---- read_input ---------------------------------------------------------------------

    #[test]
    fn reads_pem_file() {
        let d = dir();
        let path = d.path().join("in.pem");
        fs::write(&path, PEM).unwrap();
        assert_eq!(read_input(&path).unwrap().as_slice(), PEM);
    }

    #[test]
    fn reads_file_at_exact_limit() {
        let d = dir();
        let path = d.path().join("max.pem");
        fs::write(&path, vec![b'a'; MAX_INPUT_LEN]).unwrap();
        assert_eq!(read_input(&path).unwrap().len(), MAX_INPUT_LEN);
    }

    #[test]
    fn rejects_oversized_input() {
        let d = dir();
        let path = d.path().join("big.pem");
        fs::write(&path, vec![b'a'; MAX_INPUT_LEN + 1]).unwrap();
        let err = read_input(&path).unwrap_err().to_string();
        assert!(err.contains("larger than"), "{err}");
    }

    #[test]
    fn rejects_empty_input() {
        let d = dir();
        let path = d.path().join("empty.pem");
        fs::write(&path, b"").unwrap();
        assert!(read_input(&path).unwrap_err().to_string().contains("empty"));
    }

    #[test]
    fn rejects_directory_and_missing_file() {
        let d = dir();
        assert!(read_input(d.path()).is_err());
        assert!(read_input(&d.path().join("missing.pem")).is_err());
    }

    #[cfg(unix)]
    #[test]
    fn rejects_device_file() {
        let err = read_input(Path::new("/dev/zero")).unwrap_err().to_string();
        assert!(err.contains("not a regular file"), "{err}");
    }

    #[test]
    fn pem_detection() {
        assert!(looks_like_pem(PEM));
        assert!(looks_like_pem(b"\n  -----BEGIN OPENSSH PRIVATE KEY-----"));
        assert!(!looks_like_pem(b"ssh-ed25519 AAAA..."));
        assert!(!looks_like_pem(b""));
    }

    // ---- write_secure ---------------------------------------------------------------------

    #[test]
    fn writes_new_file_with_contents() {
        let d = dir();
        let path = d.path().join("out.pem");
        write_secure(&path, PEM).unwrap();
        assert_eq!(fs::read(&path).unwrap(), PEM);
    }

    #[cfg(unix)]
    #[test]
    fn created_file_has_mode_0600() {
        use std::os::unix::fs::PermissionsExt;
        let d = dir();
        let path = d.path().join("out.pem");
        write_secure(&path, PEM).unwrap();
        let mode = fs::metadata(&path).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, 0o600, "mode {mode:o}");
    }

    #[test]
    fn refuses_existing_target_and_leaves_it_unchanged() {
        let d = dir();
        let path = d.path().join("out.pem");
        fs::write(&path, b"original").unwrap();
        let err = write_secure(&path, PEM).unwrap_err().to_string();
        assert!(err.contains("already exists"), "{err}");
        assert_eq!(fs::read(&path).unwrap(), b"original");
    }

    #[cfg(unix)]
    #[test]
    fn refuses_symlink_to_existing_file() {
        let d = dir();
        let victim = d.path().join("victim");
        fs::write(&victim, b"original").unwrap();
        let link = d.path().join("out.pem");
        std::os::unix::fs::symlink(&victim, &link).unwrap();
        assert!(write_secure(&link, PEM).is_err());
        assert_eq!(fs::read(&victim).unwrap(), b"original");
    }

    #[cfg(unix)]
    #[test]
    fn refuses_dangling_symlink() {
        let d = dir();
        let target = d.path().join("would-be-created");
        let link = d.path().join("out.pem");
        std::os::unix::fs::symlink(&target, &link).unwrap();
        assert!(write_secure(&link, PEM).is_err());
        assert!(!target.exists(), "write followed the symlink");
    }

    #[test]
    fn partial_file_is_removed_when_write_fails() {
        let d = dir();
        let path = d.path().join("out.pem");
        let err = write_secure_with(&path, |file| {
            file.write_all(b"-----BEGIN PARTIAL")?;
            Err(io::Error::other("disk full"))
        })
        .unwrap_err();
        assert!(format!("{err:#}").contains("disk full"));
        assert!(!path.exists(), "partial plaintext left on disk");
    }

    #[test]
    fn missing_parent_directory_is_an_error() {
        let d = dir();
        assert!(write_secure(&d.path().join("no/such/dir/out.pem"), PEM).is_err());
    }

    // ---- passphrase policy ---------------------------------------------------------------

    #[test]
    fn passphrase_length_policy() {
        assert!(check_new_passphrase("").is_err());
        assert!(check_new_passphrase("elevenchars").is_err());
        assert!(check_new_passphrase("twelve chars").is_ok());
        // Counted in characters, not bytes: 11 multi-byte characters are still too short.
        assert!(check_new_passphrase("ééééééééééé").is_err());
    }
}

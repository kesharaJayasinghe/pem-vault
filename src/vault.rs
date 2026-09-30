//! Command flows (`push`, `pull`, `list`, `delete`) orchestrated against the `Store` trait.
//!
//! Each command is split into a local `plan_*` step (name validation, local file checks; no
//! network, no prompts) and an async step that talks to the [`Store`]. `main` runs the plan
//! before signing in, so obvious mistakes fail fast without a browser round-trip.

use std::io::{BufRead, IsTerminal, Write};
use std::path::{Path, PathBuf};

use anyhow::{Context, Result, anyhow, bail};
use zeroize::Zeroizing;

use crate::crypto;
use crate::drive::{DriveFile, Store};
use crate::hardening::Locked;
use crate::secure_io;

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

// ---- User interaction ------------------------------------------------------------------------

/// Everything a flow asks the user. The terminal implementation is used in production;
/// tests script the answers.
pub trait Prompter {
    fn passphrase(&mut self, confirm: bool) -> Result<Zeroizing<String>>;
    /// Returns `true` only if the user typed `key_name` exactly.
    fn confirm_delete(&mut self, key_name: &str, copies: usize) -> Result<bool>;
}

pub struct TerminalPrompter;

impl Prompter for TerminalPrompter {
    fn passphrase(&mut self, confirm: bool) -> Result<Zeroizing<String>> {
        secure_io::prompt_passphrase(confirm)
    }

    fn confirm_delete(&mut self, key_name: &str, copies: usize) -> Result<bool> {
        if !std::io::stdin().is_terminal() {
            bail!("deleting needs confirmation on a terminal; pass --yes to skip it");
        }
        let what = if copies == 1 {
            format!("'{key_name}'")
        } else {
            format!("all {copies} copies of '{key_name}'")
        };
        eprintln!("[!] This permanently deletes {what} from the vault. It cannot be undone.");
        eprint!("    Type the key name to confirm: ");
        std::io::stderr().flush()?;
        let mut typed = String::new();
        std::io::stdin().lock().read_line(&mut typed)?;
        Ok(typed.trim_end_matches(['\r', '\n']) == key_name)
    }
}

// ---- Lookups ---------------------------------------------------------------------------------

/// Resolves a key name to exactly one Drive file; never guesses between duplicates.
async fn find_one<S: Store>(store: &S, key_name: &str) -> Result<Option<DriveFile>> {
    let mut matches = store.find(&drive_name(key_name)).await?;
    match matches.len() {
        0 => Ok(None),
        1 => Ok(matches.pop()),
        _ => Err(duplicates_error(key_name, &matches)),
    }
}

/// Values from Drive are network input: replace control characters so a crafted file name or
/// ID can't inject terminal escape sequences into pem-vault's output.
fn printable(value: &str) -> String {
    value
        .chars()
        .map(|c| if c.is_control() { '?' } else { c })
        .collect()
}

fn duplicates_error(key_name: &str, files: &[DriveFile]) -> anyhow::Error {
    let ids: Vec<String> = files.iter().map(|f| printable(&f.id)).collect();
    anyhow!(
        "the vault has {} files named '{key_name}' (IDs: {}); refusing to guess which one to use. \
         Run `pem-vault delete --name {key_name}` to remove all copies, then push it again",
        files.len(),
        ids.join(", ")
    )
}

fn not_found(key_name: &str) -> anyhow::Error {
    anyhow!("no key named '{key_name}' in the vault (see `pem-vault list`)")
}

// ---- push ------------------------------------------------------------------------------------

/// A validated `push`, with the plaintext already read into zeroizing memory.
/// Deliberately not `Debug`: it holds the plaintext key.
pub struct PushPlan {
    key_name: String,
    plaintext: Locked<Vec<u8>>,
    force: bool,
}

/// Local half of `push`: resolve and validate the key name, then read the input file.
pub fn plan_push(input: &Path, name: Option<&str>, force: bool) -> Result<PushPlan> {
    let key_name = match name {
        Some(name) => name.to_owned(),
        None => input
            .file_name()
            .and_then(|n| n.to_str())
            .ok_or_else(|| {
                anyhow!(
                    "cannot derive a key name from {}; pass --name",
                    input.display()
                )
            })?
            .to_owned(),
    };
    validate_key_name(&key_name).with_context(|| format!("invalid key name '{key_name}'"))?;
    let plaintext = Locked::new(secure_io::read_input(input)?);
    Ok(PushPlan {
        key_name,
        plaintext,
        force,
    })
}

/// Encrypts and uploads. Checks for an existing key *before* asking for the passphrase, and
/// verifies the envelope decrypts locally before anything leaves the machine.
pub async fn push<S: Store>(
    store: &S,
    prompter: &mut impl Prompter,
    plan: PushPlan,
) -> Result<DriveFile> {
    let PushPlan {
        key_name,
        plaintext,
        force,
    } = plan;

    let existing = find_one(store, &key_name).await?;
    if existing.is_some() && !force {
        bail!("'{key_name}' already exists in the vault; pass --force to replace it");
    }

    let passphrase = Locked::new(prompter.passphrase(true)?);
    let envelope = crypto::encrypt(&plaintext, passphrase.as_bytes(), &key_name)?;
    eprintln!("[+] Derived 256-bit key via Argon2id (64 MiB)");
    eprintln!("[+] Encrypted {key_name} (AAD-bound)");

    let round_trip = Locked::new(crypto::decrypt(
        &envelope,
        passphrase.as_bytes(),
        &key_name,
    )?);
    if round_trip.as_slice() != plaintext.as_slice() {
        bail!(
            "internal error: the encrypted key did not decrypt back to the original; nothing was uploaded"
        );
    }
    eprintln!("[+] Verified local round-trip");

    let file = match existing {
        Some(file) => {
            let updated = store.update(&file.id, &envelope).await?;
            eprintln!("[+] Replaced existing key (file ID: {})", updated.id);
            updated
        }
        None => {
            let created = store.create(&drive_name(&key_name), &envelope).await?;
            eprintln!("[+] Uploaded to appDataFolder (file ID: {})", created.id);
            created
        }
    };
    Ok(file)
}

// ---- pull ------------------------------------------------------------------------------------

#[derive(Debug)]
pub struct PullPlan {
    key_name: String,
    output: PathBuf,
}

/// Local half of `pull`: validate the name and refuse an existing output path up front.
pub fn plan_pull(name: &str, output: &Path) -> Result<PullPlan> {
    validate_key_name(name).with_context(|| format!("invalid key name '{name}'"))?;
    // `symlink_metadata` also catches dangling symlinks, which `exists()` would miss.
    if output.symlink_metadata().is_ok() {
        bail!(
            "{} already exists; refusing to overwrite it (choose a new --output path)",
            output.display()
        );
    }
    Ok(PullPlan {
        key_name: name.to_owned(),
        output: output.to_owned(),
    })
}

/// Downloads, verifies and decrypts, then writes a new `0600` file.
pub async fn pull<S: Store>(store: &S, prompter: &mut impl Prompter, plan: PullPlan) -> Result<()> {
    let file = find_one(store, &plan.key_name)
        .await?
        .ok_or_else(|| not_found(&plan.key_name))?;
    let envelope = store.download(&file.id).await?;
    eprintln!("[+] Downloaded encrypted envelope");

    let passphrase = Locked::new(prompter.passphrase(false)?);
    let plaintext = Locked::new(crypto::decrypt(
        &envelope,
        passphrase.as_bytes(),
        &plan.key_name,
    )?);
    eprintln!("[+] Verified Poly1305 tag and AAD (\"{}\")", plan.key_name);

    secure_io::write_secure(&plan.output, &plaintext)?;
    let mode = if cfg!(unix) { " (mode 0600)" } else { "" };
    eprintln!("[+] Wrote {}{mode}", plan.output.display());
    Ok(())
}

// ---- list ------------------------------------------------------------------------------------

#[derive(Debug, PartialEq, Eq)]
pub struct VaultEntry {
    pub key_name: String,
    pub size: Option<u64>,
    pub modified: Option<String>,
}

/// All vault entries, sorted by key name. Duplicates are shown, not hidden.
pub async fn list<S: Store>(store: &S) -> Result<Vec<VaultEntry>> {
    let mut entries: Vec<VaultEntry> = store
        .list()
        .await?
        .into_iter()
        .map(|f| VaultEntry {
            key_name: printable(f.name.strip_suffix(DRIVE_SUFFIX).unwrap_or(&f.name)),
            size: f.size(),
            modified: f.modified_time.as_deref().map(printable),
        })
        .collect();
    entries.sort_by(|a, b| a.key_name.cmp(&b.key_name));
    Ok(entries)
}

/// Renders entries as an aligned table (for stdout).
pub fn format_list(entries: &[VaultEntry]) -> String {
    let width = entries
        .iter()
        .map(|e| e.key_name.len())
        .max()
        .unwrap_or(0)
        .max("NAME".len());
    let mut out = format!("{:<width$}  {:>10}  MODIFIED (UTC)\n", "NAME", "SIZE");
    for e in entries {
        let size = e.size.map_or_else(|| "?".into(), |s| format!("{s} B"));
        let modified = e
            .modified
            .as_deref()
            .map_or_else(|| "?".into(), format_timestamp);
        out.push_str(&format!("{:<width$}  {size:>10}  {modified}\n", e.key_name));
    }
    out
}

/// `2026-09-30T06:24:05.000Z` → `2026-09-30 06:24`; anything unexpected is shown as-is.
fn format_timestamp(rfc3339: &str) -> String {
    match (rfc3339.get(..10), rfc3339.get(10..11), rfc3339.get(11..16)) {
        (Some(date), Some("T"), Some(time)) => format!("{date} {time}"),
        _ => rfc3339.to_owned(),
    }
}

// ---- delete ----------------------------------------------------------------------------------

/// Deletes every file stored under `key_name` after typed confirmation (or `--yes`).
///
/// Unlike push/pull, duplicates are not an error here: removing *all* copies is the one
/// unambiguous action, and it is how the user recovers from a duplicate state.
pub async fn delete<S: Store>(
    store: &S,
    prompter: &mut impl Prompter,
    key_name: &str,
    yes: bool,
) -> Result<usize> {
    validate_key_name(key_name).with_context(|| format!("invalid key name '{key_name}'"))?;
    let files = store.find(&drive_name(key_name)).await?;
    if files.is_empty() {
        return Err(not_found(key_name));
    }
    if !yes && !prompter.confirm_delete(key_name, files.len())? {
        bail!("confirmation did not match; nothing was deleted");
    }
    for file in &files {
        store.delete(&file.id).await?;
    }
    eprintln!(
        "[+] Deleted '{key_name}' from the vault{}",
        if files.len() > 1 {
            format!(" ({} copies)", files.len())
        } else {
            String::new()
        }
    );
    Ok(files.len())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::cell::{Cell, RefCell};
    use std::collections::VecDeque;
    use std::fs;

    const PASS: &str = "correct horse battery staple";
    const PEM: &[u8] = b"-----BEGIN PRIVATE KEY-----\nNOT-A-REAL-KEY\n-----END PRIVATE KEY-----\n";

    // ---- Test doubles -----------------------------------------------------------------------

    #[derive(Default)]
    struct FakeStore {
        files: RefCell<Vec<(DriveFile, Vec<u8>)>>,
        next_id: Cell<u32>,
        calls: RefCell<Vec<&'static str>>,
    }

    impl FakeStore {
        fn insert(&self, name: &str, bytes: Vec<u8>) -> String {
            let id = format!("id{}", self.next_id.get());
            self.next_id.set(self.next_id.get() + 1);
            let file = DriveFile::for_test(&id, name, bytes.len());
            self.files.borrow_mut().push((file, bytes));
            id
        }
        fn bytes(&self, id: &str) -> Vec<u8> {
            self.files
                .borrow()
                .iter()
                .find(|(f, _)| f.id == id)
                .unwrap()
                .1
                .clone()
        }
        fn count(&self) -> usize {
            self.files.borrow().len()
        }
        fn called(&self, op: &str) -> bool {
            self.calls.borrow().contains(&op)
        }
    }

    impl Store for FakeStore {
        async fn list(&self) -> Result<Vec<DriveFile>> {
            self.calls.borrow_mut().push("list");
            Ok(self.files.borrow().iter().map(|(f, _)| f.clone()).collect())
        }
        async fn find(&self, drive_name: &str) -> Result<Vec<DriveFile>> {
            self.calls.borrow_mut().push("find");
            Ok(self
                .files
                .borrow()
                .iter()
                .filter(|(f, _)| f.name == drive_name)
                .map(|(f, _)| f.clone())
                .collect())
        }
        async fn create(&self, drive_name: &str, envelope: &[u8]) -> Result<DriveFile> {
            self.calls.borrow_mut().push("create");
            let id = self.insert(drive_name, envelope.to_vec());
            Ok(DriveFile::for_test(&id, drive_name, envelope.len()))
        }
        async fn update(&self, file_id: &str, envelope: &[u8]) -> Result<DriveFile> {
            self.calls.borrow_mut().push("update");
            let mut files = self.files.borrow_mut();
            let entry = files.iter_mut().find(|(f, _)| f.id == file_id).unwrap();
            entry.1 = envelope.to_vec();
            Ok(entry.0.clone())
        }
        async fn download(&self, file_id: &str) -> Result<Vec<u8>> {
            self.calls.borrow_mut().push("download");
            Ok(self.bytes(file_id))
        }
        async fn delete(&self, file_id: &str) -> Result<()> {
            self.calls.borrow_mut().push("delete");
            self.files.borrow_mut().retain(|(f, _)| f.id != file_id);
            Ok(())
        }
    }

    #[derive(Default)]
    struct Scripted {
        passphrases: VecDeque<&'static str>,
        confirm: bool,
        passphrase_prompts: usize,
        confirm_prompts: usize,
    }

    impl Scripted {
        fn with_passphrase(p: &'static str) -> Self {
            Self {
                passphrases: [p].into(),
                ..Self::default()
            }
        }
    }

    impl Prompter for Scripted {
        fn passphrase(&mut self, _confirm: bool) -> Result<Zeroizing<String>> {
            self.passphrase_prompts += 1;
            let p = self
                .passphrases
                .pop_front()
                .expect("unexpected passphrase prompt");
            Ok(Zeroizing::new(p.into()))
        }
        fn confirm_delete(&mut self, _key_name: &str, _copies: usize) -> Result<bool> {
            self.confirm_prompts += 1;
            Ok(self.confirm)
        }
    }

    fn key_file(dir: &tempfile::TempDir, name: &str, content: &[u8]) -> PathBuf {
        let path = dir.path().join(name);
        fs::write(&path, content).unwrap();
        path
    }

    async fn pushed(store: &FakeStore, key_name: &str, content: &[u8]) -> String {
        let dir = tempfile::tempdir().unwrap();
        let input = key_file(&dir, "in.pem", content);
        let plan = plan_push(&input, Some(key_name), false).unwrap();
        push(store, &mut Scripted::with_passphrase(PASS), plan)
            .await
            .unwrap()
            .id
    }

    // ---- Names ------------------------------------------------------------------------------

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

    // ---- push -------------------------------------------------------------------------------

    #[tokio::test]
    async fn push_uploads_an_envelope_that_decrypts_to_the_input() {
        let store = FakeStore::default();
        let id = pushed(&store, "prod.pem", PEM).await;

        let stored = store.bytes(&id);
        assert!(stored.starts_with(crypto::MAGIC));
        assert!(
            !stored.windows(PEM.len()).any(|w| w == PEM),
            "plaintext found in the uploaded bytes"
        );
        let plaintext = crypto::decrypt(&stored, PASS.as_bytes(), "prod.pem").unwrap();
        assert_eq!(plaintext.as_slice(), PEM);
        assert_eq!(store.files.borrow()[0].0.name, "prod.pem.enc");
    }

    #[tokio::test]
    async fn push_defaults_the_name_to_the_input_file_name() {
        let dir = tempfile::tempdir().unwrap();
        let input = key_file(&dir, "bastion.pem", PEM);
        let plan = plan_push(&input, None, false).unwrap();
        assert_eq!(plan.key_name, "bastion.pem");
    }

    #[test]
    fn push_rejects_invalid_name_before_reading_input() {
        let err = plan_push(Path::new("/definitely/missing.pem"), Some("../evil"), false)
            .err()
            .unwrap();
        assert!(format!("{err:#}").contains("invalid key name"), "{err:#}");
    }

    #[tokio::test]
    async fn push_refuses_existing_key_without_force_and_before_prompting() {
        let store = FakeStore::default();
        let id = pushed(&store, "prod.pem", PEM).await;
        let before = store.bytes(&id);

        let dir = tempfile::tempdir().unwrap();
        let plan = plan_push(&key_file(&dir, "in.pem", b"other"), Some("prod.pem"), false).unwrap();
        let mut prompter = Scripted::default();
        let err = push(&store, &mut prompter, plan)
            .await
            .unwrap_err()
            .to_string();

        assert!(
            err.contains("already exists") && err.contains("--force"),
            "{err}"
        );
        assert_eq!(
            prompter.passphrase_prompts, 0,
            "asked for a passphrase needlessly"
        );
        assert_eq!(store.bytes(&id), before);
        assert_eq!(store.count(), 1);
    }

    #[tokio::test]
    async fn push_with_force_replaces_in_place() {
        let store = FakeStore::default();
        let id = pushed(&store, "prod.pem", PEM).await;

        let dir = tempfile::tempdir().unwrap();
        let plan = plan_push(
            &key_file(&dir, "in.pem", b"-----BEGIN NEW-----"),
            Some("prod.pem"),
            true,
        )
        .unwrap();
        let file = push(&store, &mut Scripted::with_passphrase(PASS), plan)
            .await
            .unwrap();

        assert_eq!(file.id, id, "file ID must be kept");
        assert_eq!(store.count(), 1);
        assert!(store.called("update"));
        let creates = store
            .calls
            .borrow()
            .iter()
            .filter(|c| **c == "create")
            .count();
        assert_eq!(creates, 1, "only the initial push may create a file");
        let plaintext = crypto::decrypt(&store.bytes(&id), PASS.as_bytes(), "prod.pem").unwrap();
        assert_eq!(plaintext.as_slice(), b"-----BEGIN NEW-----");
    }

    #[tokio::test]
    async fn push_refuses_duplicates_even_with_force() {
        let store = FakeStore::default();
        let a = store.insert("prod.pem.enc", b"x".to_vec());
        let b = store.insert("prod.pem.enc", b"y".to_vec());

        let dir = tempfile::tempdir().unwrap();
        let plan = plan_push(&key_file(&dir, "in.pem", PEM), Some("prod.pem"), true).unwrap();
        let err = push(&store, &mut Scripted::default(), plan)
            .await
            .unwrap_err()
            .to_string();

        assert!(
            err.contains(&a) && err.contains(&b) && err.contains("pem-vault delete"),
            "{err}"
        );
        assert!(!store.called("update") && !store.called("create"));
    }

    // ---- pull -------------------------------------------------------------------------------

    #[tokio::test]
    async fn pull_round_trips_to_a_new_0600_file() {
        let store = FakeStore::default();
        pushed(&store, "prod.pem", PEM).await;
        let dir = tempfile::tempdir().unwrap();
        let output = dir.path().join("out.pem");

        let plan = plan_pull("prod.pem", &output).unwrap();
        pull(&store, &mut Scripted::with_passphrase(PASS), plan)
            .await
            .unwrap();

        assert_eq!(fs::read(&output).unwrap(), PEM);
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            assert_eq!(
                fs::metadata(&output).unwrap().permissions().mode() & 0o777,
                0o600
            );
        }
    }

    #[test]
    fn pull_refuses_existing_output_or_symlink_before_anything_else() {
        let dir = tempfile::tempdir().unwrap();
        let existing = key_file(&dir, "exists.pem", b"keep me");
        assert!(
            plan_pull("prod.pem", &existing)
                .unwrap_err()
                .to_string()
                .contains("already exists")
        );
        #[cfg(unix)]
        {
            let link = dir.path().join("dangling.pem");
            std::os::unix::fs::symlink(dir.path().join("nowhere"), &link).unwrap();
            assert!(plan_pull("prod.pem", &link).is_err());
        }
        assert!(plan_pull("../evil", &dir.path().join("new.pem")).is_err());
        assert_eq!(fs::read(&existing).unwrap(), b"keep me");
    }

    #[tokio::test]
    async fn pull_of_missing_key_fails_before_prompting() {
        let store = FakeStore::default();
        let dir = tempfile::tempdir().unwrap();
        let mut prompter = Scripted::default();
        let err = pull(
            &store,
            &mut prompter,
            plan_pull("nope.pem", &dir.path().join("o.pem")).unwrap(),
        )
        .await
        .unwrap_err()
        .to_string();
        assert!(err.contains("no key named 'nope.pem'"), "{err}");
        assert_eq!(prompter.passphrase_prompts, 0);
    }

    #[tokio::test]
    async fn pull_refuses_duplicates() {
        let store = FakeStore::default();
        store.insert("prod.pem.enc", b"x".to_vec());
        store.insert("prod.pem.enc", b"y".to_vec());
        let dir = tempfile::tempdir().unwrap();
        let err = pull(
            &store,
            &mut Scripted::default(),
            plan_pull("prod.pem", &dir.path().join("o.pem")).unwrap(),
        )
        .await
        .unwrap_err()
        .to_string();
        assert!(err.contains("2 files named"), "{err}");
        assert!(!store.called("download"));
    }

    #[tokio::test]
    async fn pull_with_wrong_passphrase_fails_and_writes_nothing() {
        let store = FakeStore::default();
        pushed(&store, "prod.pem", PEM).await;
        let dir = tempfile::tempdir().unwrap();
        let output = dir.path().join("out.pem");

        let err = pull(
            &store,
            &mut Scripted::with_passphrase("wrong passphrase!"),
            plan_pull("prod.pem", &output).unwrap(),
        )
        .await
        .unwrap_err()
        .to_string();
        assert!(
            err.contains("wrong passphrase, corrupted data, or name mismatch"),
            "{err}"
        );
        assert!(!output.exists());
    }

    #[tokio::test]
    async fn pull_detects_files_swapped_in_drive() {
        let store = FakeStore::default();
        let a = pushed(&store, "a.pem", b"-----BEGIN A-----").await;
        let b = pushed(&store, "b.pem", b"-----BEGIN B-----").await;
        // Attacker swaps the contents of the two Drive files.
        let (bytes_a, bytes_b) = (store.bytes(&a), store.bytes(&b));
        for (file, bytes) in store.files.borrow_mut().iter_mut() {
            *bytes = if file.id == a {
                bytes_b.clone()
            } else {
                bytes_a.clone()
            };
        }
        let dir = tempfile::tempdir().unwrap();
        let output = dir.path().join("a.pem");
        assert!(
            pull(
                &store,
                &mut Scripted::with_passphrase(PASS),
                plan_pull("a.pem", &output).unwrap()
            )
            .await
            .is_err()
        );
        assert!(!output.exists());
    }

    // ---- list -------------------------------------------------------------------------------

    #[tokio::test]
    async fn list_strips_suffix_sorts_and_keeps_duplicates() {
        let store = FakeStore::default();
        store.insert("zeta.pem.enc", vec![0; 134]);
        store.insert("alpha.pem.enc", vec![0; 200]);
        store.insert("alpha.pem.enc", vec![0; 201]);
        let names: Vec<_> = list(&store)
            .await
            .unwrap()
            .into_iter()
            .map(|e| e.key_name)
            .collect();
        assert_eq!(names, ["alpha.pem", "alpha.pem", "zeta.pem"]);
    }

    #[tokio::test]
    async fn list_neutralizes_control_characters_from_drive() {
        let store = FakeStore::default();
        store.insert("evil\u{1b}[2J\u{7}.pem.enc", vec![0; 70]);
        let entries = list(&store).await.unwrap();
        assert_eq!(entries[0].key_name, "evil?[2J?.pem");
        assert!(!format_list(&entries).contains('\u{1b}'));
    }

    #[test]
    fn list_table_is_aligned() {
        let table = format_list(&[
            VaultEntry {
                key_name: "prod-bastion.pem".into(),
                size: Some(134),
                modified: Some("2026-09-30T06:24:05.000Z".into()),
            },
            VaultEntry {
                key_name: "x".into(),
                size: None,
                modified: None,
            },
        ]);
        let lines: Vec<_> = table.lines().collect();
        assert_eq!(lines[0], "NAME                    SIZE  MODIFIED (UTC)");
        assert_eq!(lines[1], "prod-bastion.pem       134 B  2026-09-30 06:24");
        assert_eq!(lines[2], "x                          ?  ?");
    }

    // ---- delete -----------------------------------------------------------------------------

    #[tokio::test]
    async fn delete_requires_matching_confirmation() {
        let store = FakeStore::default();
        store.insert("prod.pem.enc", b"x".to_vec());

        let mut declined = Scripted::default();
        assert!(
            delete(&store, &mut declined, "prod.pem", false)
                .await
                .is_err()
        );
        assert_eq!(declined.confirm_prompts, 1);
        assert_eq!(store.count(), 1);

        let mut confirmed = Scripted {
            confirm: true,
            ..Scripted::default()
        };
        assert_eq!(
            delete(&store, &mut confirmed, "prod.pem", false)
                .await
                .unwrap(),
            1
        );
        assert_eq!(store.count(), 0);
    }

    #[tokio::test]
    async fn delete_with_yes_skips_prompt_and_removes_all_duplicates() {
        let store = FakeStore::default();
        store.insert("prod.pem.enc", b"x".to_vec());
        store.insert("prod.pem.enc", b"y".to_vec());
        store.insert("other.pem.enc", b"z".to_vec());

        let mut prompter = Scripted::default();
        assert_eq!(
            delete(&store, &mut prompter, "prod.pem", true)
                .await
                .unwrap(),
            2
        );
        assert_eq!(prompter.confirm_prompts, 0);
        assert_eq!(store.count(), 1, "other keys must be untouched");
    }

    #[tokio::test]
    async fn delete_of_missing_key_fails() {
        let store = FakeStore::default();
        let err = delete(&store, &mut Scripted::default(), "nope.pem", true)
            .await
            .unwrap_err();
        assert!(err.to_string().contains("no key named"));
    }
}

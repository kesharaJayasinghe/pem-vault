# Backlog

This is the ordered implementation plan for `pem-vault`. Work top to bottom: later tasks depend on earlier ones.

**Legend:** `[ ]` todo · `[~]` in progress · `[x]` done · 👤 manual task for the owner · 🤖 Claude can implement it

**Definition of done** (every 🤖 task):
1. The acceptance criteria (AC) are met.
2. `cargo fmt --check && cargo clippy --all-targets -- -D warnings && cargo test` passes.
3. Security-relevant changes pass the `invariant-check` skill.
4. The task's checkbox is updated here, and any new decision is added to the [Decision log](#decision-log).

The README's *Security design* section is the specification. If a task conflicts with it, fix the spec first (with a decision-log entry) and then write the code.

---

## Phase 0: Workstation and repository

- [x] **P0.1** 👤 Install the Rust toolchain.
  - `curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh`, then `rustup component add rustfmt clippy`
  - AC: `cargo --version` reports ≥ 1.85.
- [x] **P0.2** 🤖 Initialize the repository in place.
  - `git init`, then `cargo init --name pem-vault`. Use `cargo init`, not `cargo new`, which would create a nested `pem-vault/` directory.
  - `.gitignore`: `/target`, `*.pem`, `*.pem.enc`, `.env*`
  - AC: `cargo run` prints the hello-world output; `git status` shows no build artifacts.
- [x] **P0.3** 🤖 Install the audit tooling: `cargo install cargo-audit --locked`.
  - AC: `cargo audit` runs cleanly.

## Phase 1: Google Cloud setup (👤)

Detailed click-paths are in [README → Google Cloud setup](README.md#google-cloud-setup).

- [ ] **P1.1** 👤 Create the Google Cloud project `pem-vault-storage`.
- [ ] **P1.2** 👤 Enable the Google Drive API: `gcloud services enable drive.googleapis.com --project=<PROJECT_ID>`.
- [ ] **P1.3** 👤 In Google Auth Platform, set up Branding, set the Audience to *External*, and **publish to production** so refresh tokens don't expire after 7 days. Under Data Access, add `drive.appdata`.
- [ ] **P1.4** 👤 Create a *Desktop app* client named `pem-vault-cli` and store its ID and secret in a password manager.
- [ ] **P1.5** 👤 Export `PEM_VAULT_CLIENT_ID` and `PEM_VAULT_CLIENT_SECRET` in your shell profile. Never commit them.
  - AC: `echo $PEM_VAULT_CLIENT_ID` works in a new terminal.

## Phase 2: Scaffold

- [ ] **P2.1** 🤖 Write `Cargo.toml`. Confirm the latest compatible versions with `cargo search` first. Starting point:
  ```toml
  [package]
  name = "pem-vault"
  version = "0.1.0"
  edition = "2024"
  rust-version = "1.85"

  [dependencies]
  clap = { version = "4", features = ["derive"] }
  tokio = { version = "1", features = ["rt-multi-thread", "macros", "net", "io-util", "time"] }
  anyhow = "1"
  argon2 = "0.5"
  chacha20poly1305 = "0.10"
  rand_core = { version = "0.6", features = ["getrandom"] }   # must match chacha20poly1305's rand_core
  zeroize = "1.8"
  rpassword = "7"
  reqwest = { version = "0.12", default-features = false, features = ["json", "rustls-tls"] }
  oauth2 = { version = "5", default-features = false, features = ["reqwest", "rustls-tls"] }
  keyring = { version = "3", features = ["apple-native", "windows-native", "sync-secret-service"] }
  serde = { version = "1", features = ["derive"] }
  serde_json = "1"
  webbrowser = "1"

  [dev-dependencies]
  tempfile = "3"
  wiremock = "0.6"

  [profile.release]
  strip = true
  lto = true
  codegen-units = 1
  # Keep the default panic = "unwind": with "abort", Zeroizing destructors never run.
  ```
  - AC: `cargo build` succeeds, and `cargo tree -d` shows **no duplicate `reqwest`**. If `oauth2` pulls in a second copy, drop the crate and hand-roll PKCE with `sha2` + `base64` (log the decision).
  - AC: keyring platform features are enabled. Without them keyring v3 silently uses an in-memory mock store.
- [ ] **P2.2** 🤖 Create the module skeleton with `#![deny(unsafe_code)]` at the crate root:
  ```text
  src/
  ├── main.rs        # entry point: hardening init, CLI dispatch, exit codes
  ├── cli.rs         # clap definitions only
  ├── vault.rs       # command orchestration against the `Store` trait
  ├── crypto.rs      # envelope, KDF, AEAD (pure, no I/O)
  ├── secure_io.rs   # input reading, 0600 output writing, passphrase prompts
  ├── auth.rs        # OAuth2 loopback + PKCE, keyring token persistence
  └── drive.rs       # Drive v3 client for appDataFolder; implements `Store`
  ```
  - AC: it compiles, and each module has a one-line doc comment describing what it's responsible for.

## Phase 3: Crypto engine (`crypto.rs`)

- [ ] **P3.1** 🤖 Add the constants and header type: `MAGIC = b"PEMVAULT"`, `VERSION = 0x01`, `SALT_LEN = 16`, `NONCE_LEN = 24`, `HEADER_LEN = 49`, `TAG_LEN = 16`. Add `Header` serialize and parse functions.
- [ ] **P3.2** 🤖 Add `derive_key(passphrase, salt, params) -> Zeroizing<[u8; 32]>` using Argon2id v0x13 with m = 65536 KiB, t = 3, p = 4. Production code always uses the v1 params; tests use a `#[cfg(test)]` fast parameter set.
- [ ] **P3.3** 🤖 Add `encrypt(plaintext, passphrase, key_name) -> Vec<u8>`. It draws a new salt and nonce from `OsRng` and uses **AAD = header bytes ‖ key_name**.
- [ ] **P3.4** 🤖 Add `decrypt(envelope, passphrase, key_name) -> Zeroizing<Vec<u8>>`. It checks the length (at least 65 bytes), the magic and the version. On authentication failure it returns a single generic error: "wrong passphrase, corrupted data, or name mismatch".
- [ ] **P3.5** 🤖 Unit tests:
  - Round-trip; empty and 1 MiB payloads
  - Wrong passphrase, wrong key name → error
  - Flip each of the 49 header bytes → error (unsupported-version or auth error)
  - Flip a ciphertext byte and a tag byte → error
  - Truncated inputs (0, 48, 64 bytes) → error
  - Two encryptions of the same input use different salts, nonces and ciphertexts
- [ ] **P3.6** 🤖 Add `validate_key_name()` with the regex `^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$` (no regex crate needed), plus `drive_name(key) = key + ".enc"`. Test edge cases: empty, 129 characters, `../x`, quotes, unicode, a leading dot.

## Phase 4: Secure local I/O (`secure_io.rs`)

- [ ] **P4.1** 🤖 Add `read_input(path) -> Zeroizing<Vec<u8>>`. Reject files over 1 MiB. Warn, but continue, if the content doesn't start with `-----BEGIN`.
- [ ] **P4.2** 🤖 Add `write_secure(path, bytes)`. It opens with `create_new(true)` and mode `0o600` (Unix), writes, calls `sync_all`, and **deletes the file if any step after creation fails**. On Windows, print a warning that the ACLs are inherited.
- [ ] **P4.3** 🤖 Add `prompt_passphrase(confirm: bool) -> Zeroizing<String>` using `rpassword` on the TTY. On `push`, require confirmation and at least 12 characters. Never read the passphrase from args or env.
- [ ] **P4.4** 🤖 Tests with `tempfile`:
  - The created file has mode `0600`.
  - An existing target → error, with its content unchanged.
  - A symlink target → error.
  - An oversized input → error.

## Phase 5: Authentication (`auth.rs`)

- [ ] **P5.1** 🤖 Add keyring storage: `save_refresh_token`, `load_refresh_token -> Zeroizing<String>` and `delete_refresh_token`, using service `pem-vault-cli` and account `google-drive-refresh-token`.
  - AC (manual, macOS): the entry is visible in Keychain Access after `auth`.
- [ ] **P5.2** 🤖 Add `Config::from_env()`, which reads `PEM_VAULT_CLIENT_ID` and `PEM_VAULT_CLIENT_SECRET`. If either is missing, the error message points to the README setup section.
- [ ] **P5.3** 🤖 Implement the `auth` loopback flow:
  - Bind `127.0.0.1:0` and use redirect URI `http://127.0.0.1:{port}`.
  - Use PKCE (S256) and a random `state`, with `access_type=offline`, `prompt=consent` and scope `drive.appdata`.
  - Open the browser with `webbrowser`, and also print the URL.
  - Accept one request with a 5-minute timeout. Verify `state` and handle the `error=` parameter. Reply with a minimal HTML page ("You can close this tab").
  - Exchange the code. Fail if the response has no `refresh_token`; otherwise save it.
- [ ] **P5.4** 🤖 Add `access_token()`, which does the refresh-token grant. On `invalid_grant`, show: "Session expired or revoked. Run `pem-vault auth`."
- [ ] **P5.5** 🤖 Implement `logout`: POST to `https://oauth2.googleapis.com/revoke`, then delete the keyring entry. Succeed even if revocation fails, but warn.
- [ ] **P5.6** 🤖 Tests: parsing the callback URL (state mismatch, `error=access_denied`, missing code), with the token endpoint mocked in `wiremock`.

## Phase 6: Google Drive client (`drive.rs`)

The API reference is in the `drive-api` skill.

- [ ] **P6.1** 🤖 Define the `Store` trait (`list`, `find`, `create`, `update`, `download`, `delete`) and a `DriveClient` implementation. Base URLs are injectable for tests.
- [ ] **P6.2** 🤖 Add `escape_query_literal()`, which escapes `\` → `\\` and `'` → `\'`, with tests. Names are validated too; this is defense in depth.
- [ ] **P6.3** 🤖 Add `list()` with `spaces=appDataFolder` and `fields=nextPageToken,files(id,name,size,modifiedTime)`, following `nextPageToken` pagination.
- [ ] **P6.4** 🤖 Add `find(drive_name) -> Vec<DriveFile>`. It returns every match; callers treat more than one match as an error.
- [ ] **P6.5** 🤖 Add `create()`: a hand-built `multipart/related` upload with the JSON metadata `{name, parents:["appDataFolder"]}` plus the octet-stream body. Don't use reqwest's `multipart`, which sends `form-data`.
- [ ] **P6.6** 🤖 Add `update(file_id, bytes)`: `PATCH /upload/drive/v3/files/{id}?uploadType=media`.
- [ ] **P6.7** 🤖 Add `download(file_id)`: `alt=media`, rejecting responses larger than 2 MiB.
- [ ] **P6.8** 🤖 Add `delete(file_id)`.
- [ ] **P6.9** 🤖 Add error mapping for 401, 403, 404, 429 and 5xx, with actionable messages. Retry 429 and 5xx with exponential backoff, at most 3 attempts.
- [ ] **P6.10** 🤖 Add `wiremock` integration tests for every call: the request shape (headers, query, multipart boundary), pagination and error paths.

## Phase 7: CLI commands (`cli.rs`, `vault.rs`)

- [ ] **P7.1** 🤖 Add the clap definitions: `auth`, `logout`, `push --input --name [--force]`, `pull --name --output`, `list`, `delete --name [--yes]`.
- [ ] **P7.2** 🤖 Implement the `push` flow:
  1. Validate the name.
  2. Read the input.
  3. Get an access token.
  4. Call `find`: more than one match → error listing the IDs; exactly one and no `--force` → error "already exists".
  5. Prompt for the passphrase with confirmation.
  6. Encrypt.
  7. **Decrypt locally to verify.**
  8. `create` or `update`.
  9. Print the file ID.
- [ ] **P7.3** 🤖 Implement the `pull` flow:
  1. Validate the name.
  2. **Fail fast if the output path already exists.**
  3. `find`: 0 matches → not found; more than 1 → error.
  4. Download.
  5. Prompt for the passphrase.
  6. Decrypt.
  7. Call `write_secure`.
- [ ] **P7.4** 🤖 Implement `list`: a table of key names (with `.enc` stripped), sizes and modified times, sorted by name.
- [ ] **P7.5** 🤖 Implement `delete`: require the user to type the key name to confirm, unless `--yes` is passed. Warn that deletion is permanent.
- [ ] **P7.6** 🤖 Output conventions: status on stderr with `[+]` / `[!]` prefixes, `list` data on stdout, exit code 0 for success and 1 for errors. Never print secrets.
- [ ] **P7.7** 🤖 Unit-test the `vault.rs` flows against an in-memory `FakeStore`, covering duplicates, `--force`, an existing output, not found and a wrong passphrase.

## Phase 8: Hardening

- [ ] **P8.1** 🤖 Disable core dumps at startup on Unix: `setrlimit(RLIMIT_CORE, 0)`, plus `prctl(PR_SET_DUMPABLE, 0)` on Linux. Put this in a small `hardening.rs` with a scoped `#[allow(unsafe_code)]`, or use the safe `rlimit` crate.
- [ ] **P8.2** 🤖 Best-effort `mlock` of the key and plaintext buffers (`region` or `memsec` crate). If locking fails, print a warning instead of failing.
- [ ] **P8.3** 🤖 Add `cargo audit` to the pre-commit routine and fix any advisories.
- [ ] **P8.4** 🤖 Run the `invariant-check` skill over the **whole codebase** and fix every finding.

## Phase 9: Verification and release

- [ ] **P9.1** 👤🤖 Run the `smoke-test` skill end to end against real Drive on macOS, and on Linux if available.
- [ ] **P9.2** 🤖 Update the README: remove "pre-alpha / intended interface" wording and make sure the examples match the real output.
- [ ] **P9.3** 🤖 (Optional) Add GitHub Actions CI on macOS and Linux running fmt, clippy, test and audit.
- [ ] **P9.4** 👤 Choose a license, then tag `v0.1.0`.

---

## Future ideas (not scheduled)

- `rekey` command to change the master passphrase for all keys
- Envelope v2 that stores the Argon2 parameters in the header so costs can be raised later
- `pull --output -` to pipe straight into `ssh-add -` without touching disk
- Windows ACL hardening (owner-only DACL on created files)
- Versioned history (keep the previous N versions on `--force`)

## Decision log

| # | Decision | Reason |
|---|---|---|
| D1 | AAD = 49-byte header ‖ key name (the original spec used the name only) | Authenticates the version byte and header; costs nothing |
| D2 | Drive name = `<key name>.enc`; key names limited to `[A-Za-z0-9._-]`, max 128 characters | Removes the ambiguity between `.pem` and `.pem.enc`; prevents Drive query injection and path tricks |
| D3 | Duplicate handling is core behavior, not optional hardening: `push` refuses unless `--force` (update in place); more than one match is an error | Otherwise `pull` could silently return a stale key |
| D4 | keyring v3 with explicit platform features | By default v3 uses a non-persistent mock store |
| D5 | `oauth2` v5 (or hand-rolled PKCE) instead of v4 | v4 pulls in reqwest 0.11 alongside 0.12 |
| D6 | Hand-built `multipart/related` uploads | Matches Drive's documented contract; reqwest's `multipart` sends `form-data` |
| D7 | Publish the OAuth app to *In production* | In *Testing* status, refresh tokens expire after 7 days |
| D8 | Keep `panic = "unwind"` | With abort, `Zeroizing` destructors never run |
| D9 | Verify a local decrypt before uploading | Catches passphrase typos and bugs before the only copy lives in the cloud |
| D10 | Edition 2024, MSRV 1.85 | Current stable edition |

# CLAUDE.md

`pem-vault` is a Rust CLI that encrypts `.pem` private keys locally (Argon2id + XChaCha20-Poly1305) and stores only the ciphertext in Google Drive's `appDataFolder`.

- **Spec:** see the *Security design* section of `README.md` (envelope format, AAD, naming rules). Don't deviate from it silently.
- **Plan:** `BACKLOG.md` lists the tasks in order, with acceptance criteria and a decision log. Always work on the first unchecked 🤖 task unless the user says otherwise.
- **Status:** pre-alpha. Check `BACKLOG.md` for what already exists before assuming a module is there.

## Commands

```bash
cargo build                                   # debug build
cargo build --release                         # ./target/release/pem-vault
cargo test                                    # all tests (never touch real Google APIs)
cargo fmt --check                             # formatting
cargo clippy --all-targets -- -D warnings     # lints (warnings are errors)
cargo audit                                   # dependency advisories
cargo tree -d                                 # duplicate deps (reqwest must not be duplicated)
```

Pre-commit gate: `cargo fmt --check && cargo clippy --all-targets -- -D warnings && cargo test`

## Architecture

```text
src/main.rs        entry: hardening init → CLI parse → dispatch → exit code
src/cli.rs         clap definitions only
src/vault.rs       command flows (push/pull/list/delete) against the `Store` trait
src/crypto.rs      envelope + Argon2id + XChaCha20-Poly1305; pure, no I/O
src/secure_io.rs   input reading, 0600 output writing, TTY passphrase prompts
src/auth.rs        OAuth2 loopback + PKCE; refresh token in the OS keyring
src/drive.rs       Drive v3 REST client (appDataFolder); implements `Store`
```

Dependency direction: `main → vault → {crypto, secure_io, Store}`, with `drive` and `auth` behind the `Store` trait and token provider. `crypto` depends on nothing in the crate.

## Security invariants (non-negotiable)

Breaking any of these is a bug, even if the tests pass. Use the `invariant-check` skill to review diffs.

1. **Plaintext never leaves the machine.** Only envelopes from `crypto::encrypt` are sent to Drive.
2. **Secrets are `Zeroizing`:** passphrases, derived keys, plaintext PEM buffers and refresh/access tokens. Never `clone()` one into a plain `String` or `Vec`, and never `Debug`/`Display` it.
3. **Secrets never reach output:** not stdout, stderr, logs, error messages, panics or test snapshots. Error messages never include file contents or tokens.
4. **Passphrases come only from the TTY prompt**, never from CLI args, env vars or files.
5. **Crypto parameters are frozen per version.** Magic, version `0x01`, Argon2id (64 MiB, t=3, p=4), 16-byte salt, 24-byte nonce and AAD = `header ‖ key_name` never change without bumping `VERSION`. Decryption of every older version must keep working. Salt and nonce always come from the OS CSPRNG (`getrandom`); never reuse them or make them deterministic.
6. **Decrypt failures are opaque.** Report a single generic message; never say which of passphrase, data or name was wrong.
7. **Output files:** `create_new(true)` + mode `0o600` at creation, never overwrite, delete the file if the write fails.
8. **OAuth scope is exactly `drive.appdata`**, and all Drive calls use `appDataFolder`.
9. **Key names are validated** (`^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$`) before any I/O, and Drive query literals are escaped.
10. **More than one Drive file with the same name is an error**; never pick one arbitrarily.
11. **No `unsafe`** except in a scoped `hardening.rs` with a `// SAFETY:` comment.
12. **Release profile keeps `panic = "unwind"`**, so Zeroizing destructors run.

## Conventions

- Use `anyhow::Result` with `.context("…")` for errors. No `unwrap()`/`expect()` outside tests, except for provably infallible cases with a comment.
- User-facing status goes to **stderr** with `[+]` for progress and `[!]` for warnings; command data (`list`) goes to stdout.
- Prefer RustCrypto crates. Don't add a dependency without a reason in the commit message and a clean `cargo audit`.
- Tests: crypto tests use `#[cfg(test)]` fast Argon2 params; Drive and OAuth use `wiremock`; vault flows use an in-memory `FakeStore`; file tests use `tempfile`. **Tests never call real Google endpoints or the real OS keyring.**
- Keep modules focused. Clap types stay in `cli.rs`; HTTP stays in `drive.rs`/`auth.rs`.
- Doc-comment every public function in `crypto.rs` and `secure_io.rs` with its security properties.

## Workflow

- Start implementation with the `next-task` skill. It picks the next backlog item, implements it, verifies it and ticks it off.
- Tasks marked 👤 are the owner's (installing Rust, the Google Cloud Console). Don't attempt them; tell the user what to do.
- Record any decision that changes the spec or plan in the `BACKLOG.md` decision log, and update the README spec in the same change.
- Don't run the real binary against Google Drive or the keyring unless the user asks. Use the `smoke-test` skill for that. Passphrase prompts need a real TTY, so the user runs those commands with the `!` prefix.
- Drive REST details (endpoints, multipart format, query escaping, errors) are in the `drive-api` skill.

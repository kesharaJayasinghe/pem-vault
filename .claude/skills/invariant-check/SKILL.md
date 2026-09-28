---
name: invariant-check
description: Review a pem-vault diff (or the whole codebase) against its security invariants — secret handling, zeroization, crypto parameters, AAD, file permissions, OAuth scope, Drive query safety. Use after changing crypto.rs, secure_io.rs, auth.rs, drive.rs, vault.rs or Cargo.toml, before ticking a backlog task, or when asked for a security check.
---

# invariant-check

This is a focused security review for `pem-vault`. It complements generic bug review; this skill checks project-specific rules.

## Scope

- Default: the uncommitted diff (`git diff HEAD`), or all of `src/` if the repo has no commits.
- "Whole codebase" or backlog P8.4: every file in `src/` plus `Cargo.toml`.

Read each changed function completely, not just the diff hunks.

## Checklist

For each item, answer PASS, FAIL (with `file:line` and why) or N/A.

### Secrets in memory
- [ ] Passphrases, derived keys, plaintext PEM bytes, refresh tokens and access tokens are held in `Zeroizing<…>` from the moment they're created.
- [ ] No `.clone()`, `.to_vec()`, `.to_string()`, `format!` or `String::from` copies a secret into a non-zeroizing buffer. Intermediate `Vec`s returned by library calls, such as `cipher.decrypt`, are wrapped immediately.
- [ ] No secret-bearing type derives or implements `Debug`, `Display` or `Serialize`.
- [ ] Secrets aren't moved into long-lived structs or statics.

### Secrets in output
- [ ] No `println!`, `eprintln!`, `dbg!`, log or error message includes a secret, file contents or a token.
- [ ] `anyhow` contexts don't wrap errors whose `Display` could include secrets, such as serde errors over token JSON.
- [ ] HTTP error handling doesn't echo response bodies from the token endpoint.

### Passphrase input
- [ ] The passphrase is read only via `rpassword` from the TTY. There's no CLI flag, env var or file path for it.
- [ ] `push` requires confirmation and at least 12 characters.

### Crypto (`crypto.rs`)
- [ ] Constants are unchanged: `PEMVAULT`, `0x01`, salt 16, nonce 24, header 49, tag 16.
- [ ] Argon2id v0x13, m = 65536, t = 3, p = 4, 32-byte output. Fast params are only used under `#[cfg(test)]`.
- [ ] Salt and nonce are new per encryption from `OsRng`. There's no fixed, derived or reused nonce.
- [ ] AAD = the full 49-byte header ‖ key name, on **both** encrypt and decrypt.
- [ ] Length, magic and version are checked before slicing; there are no panicking index operations on untrusted input.
- [ ] Decrypt failure produces one generic message, with no oracle distinguishing passphrase, data and name.
- [ ] Any format change bumps `VERSION` and keeps older versions decryptable.

### Local files (`secure_io.rs`)
- [ ] Output uses `create_new(true)` + `mode(0o600)` at open time, not with `chmod` afterwards.
- [ ] Output never overwrites and never follows a symlink.
- [ ] A partially written output is removed on error.
- [ ] Input size is capped, and oversized input is rejected before it's fully read into memory.

### Auth (`auth.rs`)
- [ ] The scope is exactly `https://www.googleapis.com/auth/drive.appdata`.
- [ ] The loopback listener binds `127.0.0.1` (not `0.0.0.0`) and accepts one callback with a timeout.
- [ ] PKCE uses S256; `state` is random and checked before the code is used.
- [ ] The refresh token is stored only in the OS keyring, and the keyring crate has platform features enabled in `Cargo.toml`.

### Drive (`drive.rs`, `vault.rs`)
- [ ] Every request is limited to `spaces=appDataFolder` / `parents: ["appDataFolder"]`.
- [ ] Key names are validated before use, and query literals go through `escape_query_literal`.
- [ ] More than one match for a name is an error; a result is never picked by index.
- [ ] `push` doesn't overwrite without `--force`; `pull` checks that the output doesn't exist before downloading or prompting.
- [ ] Download size is capped.
- [ ] Only envelopes produced by `crypto::encrypt` are uploaded.

### Build and dependencies
- [ ] No `unsafe` outside `hardening.rs`, and each `unsafe` block has a `// SAFETY:` comment.
- [ ] `[profile.release]` doesn't set `panic = "abort"`.
- [ ] Any new dependency is justified, `cargo audit` is clean, and `cargo tree -d` shows no duplicate `reqwest` or crypto crates.

## Report

List only the FAIL items, most severe first, each with `file:line`, the violated invariant and a concrete fix. Then give a one-line PASS summary. If you were asked to fix issues, apply the fixes and re-run the pre-commit gate from `CLAUDE.md`.

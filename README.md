# pem-vault

**Zero-knowledge encryption and Google Drive backup for `.pem` private keys.**

`pem-vault` is a Rust command-line tool that encrypts sensitive `.pem` keys on your machine with a master passphrase, stores only the ciphertext in Google Drive's hidden `appDataFolder`, and retrieves and decrypts them on demand. Google never sees plaintext keys or your passphrase.

> **Status: v0.1.0.** All commands are implemented and covered by 102 automated tests, and have been verified end to end against real Google Drive on **macOS**. Linux and Windows builds are expected to work but haven't been run yet. See [`BACKLOG.md`](BACKLOG.md) for the plan and decision log.

> ⚠️ **There is no recovery.** If you forget your master passphrase, your vaulted keys are unrecoverable. That is the point of zero-knowledge encryption.

---

## Contents

- [Features](#features)
- [Security design](#security-design)
- [Threat model](#threat-model)
- [Requirements](#requirements)
- [Google Cloud setup](#google-cloud-setup)
- [Build](#build)
- [Usage](#usage)
- [Troubleshooting](#troubleshooting)
- [Operational hardening tips](#operational-hardening-tips)
- [Contributing](#contributing)

---

## Features

- **Client-side encryption:** Argon2id key derivation + XChaCha20-Poly1305 authenticated encryption.
- **Tamper and swap detection:** the envelope header and the key's name are authenticated, so a renamed, swapped or modified file fails to decrypt.
- **Least-privilege cloud access:** uses only the `drive.appdata` OAuth scope. The tool cannot see or touch your normal Drive files, and its files don't appear in the Drive web UI.
- **OS-native token storage:** the OAuth refresh token lives in macOS Keychain, Linux Secret Service or Windows Credential Manager, never in a plaintext config file.
- **Memory and file hygiene:** secrets are zeroized when they're dropped and locked in RAM while held; core dumps are disabled; decrypted files are created exclusively with `0600` permissions and never overwrite an existing file.
- **Fails safe:** a wrong passphrase, a tampered file or a name mismatch all give the same error and write nothing; `push` checks the new envelope decrypts before uploading; duplicate names are refused instead of guessed.

## Security design

### Cryptography

| Component | Choice | Parameters |
|---|---|---|
| Key derivation | Argon2id (v0x13) | 64 MiB memory, 3 iterations, 4 lanes, 16-byte random salt → 256-bit key |
| Cipher | XChaCha20-Poly1305 (AEAD) | 256-bit key, 192-bit random nonce, 128-bit tag |
| Randomness | OS CSPRNG (`getrandom`) | New salt and nonce for every encryption |

Every `push` generates a new salt and nonce, so the same key encrypted twice produces unrelated ciphertexts.

### Envelope format (`.pem.enc`, version `0x01`)

```text
offset  size        field
0       8           magic         "PEMVAULT"
8       1           version       0x01
9       16          salt          Argon2id salt (CSPRNG)
25      24          nonce         XChaCha20 nonce (CSPRNG)
49      N + 16      ciphertext    encrypted PEM + Poly1305 tag
```

The header is 49 bytes, so a valid envelope is at least 65 bytes.

### Associated data (AAD)

The Poly1305 tag authenticates:

```text
AAD = header (bytes 0..49) || UTF-8 key name
```

- **Header binding:** changing any header byte, including the version, makes decryption fail.
- **Name binding:** the key name (for example `prod-bastion.pem`) is part of the tag. If an attacker renames or swaps two files in Drive, `pull` fails instead of handing you the wrong key.

### Naming

| Concept | Example | Rule |
|---|---|---|
| Key name (used in the CLI and AAD) | `prod-bastion.pem` | `^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$` |
| Drive file name | `prod-bastion.pem.enc` | key name + `.enc` |

Key names must be unique in the vault. `push` refuses to overwrite an existing key unless you pass `--force`, which replaces the file content in place with the same Drive file ID.

### Storage and credentials

- **Scope:** `https://www.googleapis.com/auth/drive.appdata` only.
- **Location:** Drive `appDataFolder`, which is private to this OAuth client and hidden from the Drive UI.
- **Refresh token:** OS keychain, service `pem-vault-cli`, account `google-drive-refresh-token`.
- **Client ID and secret:** read from environment variables. For Desktop OAuth clients, Google doesn't treat the client secret as confidential; access is protected by your Google login and the refresh token in the keychain.

### Local hygiene

- Passphrases, plaintext PEM buffers and derived keys are wrapped in `zeroize::Zeroizing` and cleared when dropped.
- Passphrases are only read from an interactive terminal prompt, never from arguments or environment variables.
- Decrypted files are opened with `O_CREAT | O_EXCL` and mode `0600`, so they're never world-readable, never follow symlinks and never overwrite an existing file. A partially written file is deleted if writing fails.
- Before uploading, `push` decrypts the new envelope locally to confirm it round-trips.
- Core dumps are disabled at startup on Unix (`RLIMIT_CORE = 0`); on Linux the process is also marked non-dumpable, which blocks same-user `ptrace` and `/proc/<pid>/mem` reads.
- Plaintext keys and passphrases are locked in RAM (`mlock`) while held, so they're not written to swap. This is best effort: if the OS memory-lock limit is too low, pem-vault warns once and continues.
- Argon2's 64 MiB working memory, which is derived from the passphrase, is zeroized after every key derivation.

## Threat model

**Protects against:**
- Compromise of your Google account or of Google's storage. The attacker gets only Argon2id-protected ciphertext.
- Tampering, renaming or swapping of vault files.
- Other local users reading decrypted keys (Unix `0600`).

**Does not protect against:**
- A weak master passphrase. Use a long, random passphrase from a password manager.
- Malware or a root user on the machine where you run `push`/`pull`.
- Keys after you decrypt them. Once written to disk, the plaintext `.pem` is your responsibility (see the tips below).
- Deletion. Anyone with your Google session can delete vault files. Keep an offline backup of critical keys.
- Windows file permissions: on Windows, decrypted files inherit the parent directory's ACL instead of being restricted to `0600`.

## Requirements

- Rust **1.88+** (edition 2024): install via [rustup](https://rustup.rs)
- A Google account and a Google Cloud project (free)
- macOS (verified), Linux with a Secret Service provider such as GNOME Keyring or KWallet (untested), or Windows (untested; decrypted files aren't restricted to your user, see the threat model)

## Google Cloud setup

You only need to do this once.

1. **Create a project:** in the [Google Cloud Console](https://console.cloud.google.com/), create a project (for example `pem-vault-storage`).
2. **Enable the Drive API:** go to **APIs & Services → Library → Google Drive API → Enable**, or run:
   ```bash
   gcloud services enable drive.googleapis.com --project=<PROJECT_ID>
   ```
3. **Configure Google Auth Platform** (formerly the "OAuth consent screen"):
   - **Branding:** app name `pem-vault`, plus your support email.
   - **Audience:** choose *External*, leave the status as *Testing*, and add your Google account as a **test user**.
     > In *Testing* status, refresh tokens **expire after 7 days**. For occasional use that's fine: when the token has expired, `pem-vault` offers to open the browser and sign you in again before continuing. If you'd rather sign in once, click **Publish app** (*In production*). `drive.appdata` doesn't require Google verification.
   - **Data Access:** add the scope `https://www.googleapis.com/auth/drive.appdata`.
4. **Create a client:** go to **Clients → Create client**, choose *Desktop app*, name it `pem-vault-cli`, and copy the client ID and secret into your password manager.
5. **Make the credentials available in every shell.** An `export` typed at the prompt only lasts for that terminal, so add the variables to your shell startup file (`~/.zshrc` for zsh).

   **Recommended (macOS):** keep the values in the login Keychain, not in plaintext dotfiles. Store them once:
   ```bash
   security add-generic-password -U -a "$USER" -s pem-vault-client-id     -w "<client id>"
   security add-generic-password -U -a "$USER" -s pem-vault-client-secret -w "<client secret>"
   ```
   Then add to `~/.zshrc`:
   ```bash
   # pem-vault OAuth client (values stored in the macOS Keychain)
   export PEM_VAULT_CLIENT_ID="$(security find-generic-password -a "$USER" -s pem-vault-client-id -w 2>/dev/null)"
   export PEM_VAULT_CLIENT_SECRET="$(security find-generic-password -a "$USER" -s pem-vault-client-secret -w 2>/dev/null)"
   ```

   **Simple (any OS):** add these to your startup file:
   ```bash
   export PEM_VAULT_CLIENT_ID="xxxxxxxx.apps.googleusercontent.com"
   export PEM_VAULT_CLIENT_SECRET="xxxxxxxx"
   ```

   Open a new terminal and check with `echo $PEM_VAULT_CLIENT_ID`.

Because the app is unverified, Google shows a "Google hasn't verified this app" screen during `auth`. Since you own the app, it's safe to continue.

## Build

```bash
cargo build --release          # binary: ./target/release/pem-vault
cargo install --path . --locked   # or install it as ~/.cargo/bin/pem-vault
```

## Usage

| Command | Description |
|---|---|
| `pem-vault auth` | Sign in with Google in the browser and store the refresh token in the OS keychain |
| `pem-vault logout` | Revoke the refresh token and remove it from the keychain |
| `pem-vault push --input <FILE> [--name <KEY>] [--force]` | Encrypt a local `.pem` and upload it (the name defaults to the file name) |
| `pem-vault pull --name <KEY> --output <FILE>` | Download, verify and decrypt to a new `0600` file |
| `pem-vault list` | List vaulted keys, with size and last-modified time |
| `pem-vault delete --name <KEY> [--yes]` | Permanently delete a vaulted key, including any duplicate copies (type the name to confirm, or pass `--yes`) |

### Examples

```text
$ pem-vault push -i ~/.ssh/prod-cluster.pem          # name defaults to "prod-cluster.pem"
[!] Not signed in to Google. Sign in now? [Y/n]        # only when there's no valid session
[+] Opening your browser to sign in to Google…
[+] Signed in; Google session saved to the OS credential store
Enter master passphrase:
Confirm master passphrase:
[+] Derived 256-bit key via Argon2id (64 MiB)
[+] Encrypted prod-cluster.pem (AAD-bound)
[+] Verified local round-trip
[+] Uploaded to appDataFolder (file ID: 1uluywNUj8A0t-emDLPj…)

$ pem-vault list
NAME                    SIZE  MODIFIED (UTC)
prod-cluster.pem       184 B  2026-09-30 06:58

$ pem-vault pull -n prod-cluster.pem -o /tmp/prod-cluster.pem
[+] Downloaded encrypted envelope
Enter master passphrase:
[+] Verified Poly1305 tag and AAD ("prod-cluster.pem")
[+] Wrote /tmp/prod-cluster.pem (mode 0600)

$ pem-vault delete -n prod-cluster.pem
[!] This permanently deletes 'prod-cluster.pem' from the vault. It cannot be undone.
    Type the key name to confirm: prod-cluster.pem
[+] Deleted 'prod-cluster.pem' from the vault
```

- Status messages go to stderr; only `list`'s table goes to stdout. Secrets are never printed.
- Exit code `0` on success, `1` on any error (printed as `[!] Error: …`).
- While the OAuth app is in *Testing* status, expect the sign-in prompt about once a week.

## Troubleshooting

| Message | Cause and fix |
|---|---|
| `PEM_VAULT_CLIENT_ID is not set` | The variables only exist in the terminal where you typed `export`. Add them to `~/.zshrc` ([setup step 5](#google-cloud-setup)) and open a new terminal. |
| Google: *"403: access_denied … can only be accessed by developer-approved testers"* | The Google account you chose isn't a test user **of the project that owns this client ID** (its number is the prefix of the client ID). Add it under *Google Auth Platform → Audience → Test users* and pick that account in the browser. |
| `Google session expired. Sign in again now?` | Normal in *Testing* status (7-day tokens). Answer `y`. Without a terminal, run `pem-vault auth` first. |
| `the Google Drive API is not enabled for your Cloud project` | Enable it ([setup step 2](#google-cloud-setup)). |
| `the Google Drive app-data permission was not granted` | You unticked the Drive permission on the consent screen. Run `pem-vault auth` and leave it ticked. |
| `decryption failed: wrong passphrase, corrupted data, or name mismatch` | Deliberately generic. Check the passphrase and the exact `--name`. |
| `the vault has 2 files named …` | Rare: an upload that timed out but actually succeeded and was retried, or two pushes of the same name at the same moment. Run `pem-vault delete --name <KEY>` to remove all copies, then push again. |
| `Could not lock key material in memory` | The OS memory-lock limit is too low (common on Linux). pem-vault still works; raise the limit with `ulimit -l` to keep secrets out of swap. |

## Operational hardening tips

- **Linux:** decrypt to RAM-backed storage so the plaintext never reaches an SSD, for example `--output /dev/shm/prod-cluster.pem`.
- **macOS:** decrypt into an encrypted APFS volume or a RAM disk, and delete the file as soon as you're done.
- Use an ssh-agent (`ssh-add` from the temporary file, then delete the file) rather than keeping decrypted keys on disk.
- Keep an offline backup of irreplaceable keys. A cloud vault is not a backup of last resort.

## Contributing

- [`BACKLOG.md`](BACKLOG.md): ordered implementation plan and decision log
- [`CLAUDE.md`](CLAUDE.md): engineering conventions and security invariants (also read by Claude Code)

Before each commit, run:

```bash
cargo fmt --check && cargo clippy --all-targets -- -D warnings && cargo test && cargo audit
```

Or enable the bundled hook once per clone, and git runs this for you:

```bash
git config core.hooksPath .githooks
```

## License

Licensed under either of

- Apache License, Version 2.0 ([`LICENSE-APACHE`](LICENSE-APACHE))
- MIT license ([`LICENSE-MIT`](LICENSE-MIT))

at your option. Unless you explicitly state otherwise, any contribution you intentionally submit for inclusion in this work, as defined in the Apache-2.0 license, is dual-licensed as above, without any additional terms or conditions.

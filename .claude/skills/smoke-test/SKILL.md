---
name: smoke-test
description: End-to-end smoke test of the real pem-vault binary against the user's Google Drive and OS keyring — auth, push, list, pull, negative cases, delete — using a throwaway key. Use only when the user asks to smoke-test, run the app for real, or verify a release (backlog P9.1).
---

# smoke-test

This runs the real binary against real Google APIs, so only do it when the user asks.

**Run everything in the user's own terminal.** Passphrase prompts need a real TTY, and Claude's shell doesn't load the user's `PEM_VAULT_CLIENT_*` variables (they come from `~/.zshrc` via the Keychain). So:

1. Claude builds the release binary, generates the throwaway key and a unique key name in `$S`, and writes a script that runs steps 2–12 in order. Each step prints its exit code and appends `step N rc=… expect=…` to `$S/results.txt`, and `2>&1 | tee` saves the output of every step, including the expected failures, so their messages can be checked too.
2. The user runs the script in their terminal and says when it's finished.
3. Claude checks `results.txt`, the saved outputs and the files left in `$S` (cmp, mode, unchanged hash, absent files, same file ID), then cleans up.

The steps table below still defines what is tested and what's expected.

Use a throwaway passphrase such as `smoke-test-passphrase-123` and a generated key. Never use a real key.

## Preconditions (Claude checks)

```bash
command -v cargo && cargo build --release
security find-generic-password -s pem-vault-client-id >/dev/null && echo creds-ok   # macOS; values are not printed
```

If the credentials are missing, point the user to backlog Phase 1.

## Setup (Claude runs)

Use the session scratchpad directory as `$S`, and use a unique key name `K=smoke-<unix-timestamp>.pem`.

```bash
openssl genpkey -algorithm ed25519 -out "$S/in.pem"
```

## Steps

| # | Who | Command | Expected |
|---|---|---|---|
| 1 | user `!` | `pem-vault auth` (skip if already authenticated) | Browser consent; `[+]` saved to the keychain |
| 2 | user `!` | `pem-vault push --input $S/in.pem --name $K` | Uploaded; a file ID is printed |
| 3 | Claude | `pem-vault list` | `$K` appears |
| 4 | user `!` | `pem-vault push --input $S/in.pem --name $K` | **Fails**: already exists |
| 5 | user `!` | `pem-vault pull --name $K --output $S/out.pem` | Written, mode 0600 |
| 6 | Claude | `cmp $S/in.pem $S/out.pem && stat -f %Lp $S/out.pem` (Linux: `stat -c %a`) | Identical; `600` |
| 7 | user `!` | `pem-vault pull --name $K --output $S/out.pem` | **Fails**: output exists; file unchanged |
| 8 | user `!` | `pem-vault pull --name $K --output $S/bad.pem` with a **wrong** passphrase | **Fails** with the generic error; `$S/bad.pem` doesn't exist |
| 9 | user `!` | `pem-vault push --input $S/in.pem --name $K --force` | Updated in place, same file ID |
| 10 | Claude | `pem-vault pull --name does-not-exist.pem --output $S/x.pem` | Not found (it fails before the prompt, so Claude can run it) |
| 11 | user `!` | `pem-vault delete --name $K` | Deleted after typed confirmation |
| 12 | Claude | `pem-vault list` | `$K` is gone |

On macOS, also confirm the keychain entry exists:
`security find-generic-password -s pem-vault-cli -a google-drive-refresh-token >/dev/null && echo present` (this doesn't print the secret).

## Cleanup (always, even on failure)

```bash
rm -f "$S"/in.pem "$S"/out.pem "$S"/bad.pem "$S"/x.pem
```

If step 11 wasn't reached, ask the user to run `! pem-vault delete --name $K --yes`.

## Report

Show a table of steps with PASS or FAIL and the actual output of any failing step. Add any bug you find to `BACKLOG.md` as a new task, and don't fix it silently.

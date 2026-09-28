---
name: next-task
description: Pick the next unchecked task from BACKLOG.md, implement it to its acceptance criteria, verify it, and tick it off. Use when the user says "next task", "continue", "keep going", "work on the backlog", or names a backlog ID like P3.2.
---

# next-task

Moves `pem-vault` forward one backlog item at a time.

## 1. Select

1. Read `BACKLOG.md`.
2. If the user named a task ID, use that one. Otherwise take the **first** task that is `[ ]` or `[~]` in document order.
3. If that task is 👤-only (manual), stop. Tell the user exactly what they need to do, quoting the task and pointing to the relevant README section, and ask them to confirm when it's done. Don't skip ahead past an unmet dependency. For example, Phase 2+ needs `cargo` to be installed; check with `command -v cargo`.
4. Mark the task `[~]` in `BACKLOG.md`.

## 2. Understand

- Re-read the task's AC and any README *Security design* rules it touches.
- Read the existing modules it depends on. Don't assume code exists because an earlier task is ticked; check.
- For Drive work, load the `drive-api` skill.

## 3. Implement

- Follow `CLAUDE.md` conventions and **security invariants**.
- Write the tests the AC calls for in the same change.
- Keep the change scoped to the task. Put anything else you notice in the backlog as a new task instead.

## 4. Verify

Run the whole gate. Don't claim success on a partial run:

```bash
cargo fmt --check && cargo clippy --all-targets -- -D warnings && cargo test
```

If the task touched `crypto.rs`, `secure_io.rs`, `auth.rs`, `drive.rs`, `vault.rs` or `Cargo.toml`, also run the `invariant-check` skill on the diff and fix its findings.

If the gate fails and you can't fix it, leave the task `[~]` and report the failing output verbatim.

## 5. Record

- Tick the task `[x]` in `BACKLOG.md`.
- If you made a design decision (a different crate, a deviation from the spec, a new constraint), add a row to the **Decision log** and update the README spec if needed.
- If you found follow-up work, add it as a new unchecked task in the right phase.

## 6. Report

Give a short summary: the task ID, what changed (files), how it was verified, and the next task in line. Don't commit unless the user asks.

//! `pem-vault`: zero-knowledge encryption and Google Drive backup for `.pem` private keys.
//!
//! Entry point: process hardening, CLI parsing, command dispatch and exit codes.
//! The security specification lives in the README's *Security design* section.

#![deny(unsafe_code)]

mod auth;
mod cli;
#[cfg_attr(not(test), expect(dead_code, reason = "wired into the CLI in P7"))]
mod crypto;
mod drive;
// Unconditional: the TTY prompt functions stay unused in test builds until P7.
#[expect(dead_code, reason = "wired into the CLI in P7")]
mod secure_io;
#[cfg_attr(not(test), expect(dead_code, reason = "wired into the CLI in P7"))]
mod vault;

fn main() {
    // Hardening (P8.1), CLI parsing (P7.1) and dispatch (P7.2-P7.5) are wired in later tasks.
    eprintln!("[!] pem-vault is under development; no commands are implemented yet.");
    std::process::exit(1);
}

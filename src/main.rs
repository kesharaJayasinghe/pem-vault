//! `pem-vault`: zero-knowledge encryption and Google Drive backup for `.pem` private keys.
//!
//! Entry point: process hardening, CLI parsing, command dispatch and exit codes.
//! The security specification lives in the README's *Security design* section.

#![deny(unsafe_code)]

// Unconditional: `access_token` and `confirm_on_terminal` are unused until P7.
#[expect(dead_code, reason = "wired into the CLI in P7")]
mod auth;
mod cli;
#[cfg_attr(not(test), expect(dead_code, reason = "wired into the CLI in P7"))]
mod crypto;
// Unconditional: `DriveClient::new` and the production endpoints are unused by tests.
#[expect(dead_code, reason = "wired into the CLI in P7")]
mod drive;
// Unconditional: the TTY prompt functions stay unused in test builds until P7.
#[expect(dead_code, reason = "wired into the CLI in P7")]
mod secure_io;
#[cfg_attr(not(test), expect(dead_code, reason = "wired into the CLI in P7"))]
mod vault;

use std::process::ExitCode;

use anyhow::Result;
use clap::Parser;

use crate::auth::{Auth, Config, KeyringStore};
use crate::cli::{Cli, Command};

#[tokio::main(flavor = "current_thread")]
async fn main() -> ExitCode {
    // Hardening (P8.1) is added here later.
    let cli = Cli::parse();
    match run(cli).await {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            // `{:#}` prints the context chain on one line; errors never contain secrets.
            eprintln!("[!] Error: {e:#}");
            ExitCode::FAILURE
        }
    }
}

async fn run(cli: Cli) -> Result<()> {
    let config = Config::from_env()?;
    let http = auth::http_client()?;
    let auth = Auth::new(&http, &config, &KeyringStore);
    match cli.command {
        Command::Auth => auth.sign_in().await.map(drop),
        Command::Logout => auth.logout().await,
    }
}

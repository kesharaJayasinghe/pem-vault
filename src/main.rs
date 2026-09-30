//! `pem-vault`: zero-knowledge encryption and Google Drive backup for `.pem` private keys.
//!
//! Entry point: process hardening, CLI parsing, command dispatch and exit codes.
//! The security specification lives in the README's *Security design* section.

#![deny(unsafe_code)]

mod auth;
mod cli;
mod crypto;
mod drive;
mod secure_io;
mod vault;

use std::process::ExitCode;

use anyhow::{Context, Result};
use clap::Parser;
use reqwest::Client;

use crate::auth::{Auth, Config, KeyringStore};
use crate::cli::{Cli, Command};
use crate::drive::DriveClient;
use crate::vault::TerminalPrompter;

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
    let http = auth::http_client()?;
    match cli.command {
        Command::Auth => {
            let config = Config::from_env()?;
            Auth::new(&http, &config, &KeyringStore).sign_in().await?;
        }
        Command::Logout => auth::logout(&http, &KeyringStore).await?,
        Command::Push { input, name, force } => {
            // Local checks first: a bad name or unreadable file fails before any sign-in.
            let plan = vault::plan_push(&input, name.as_deref(), force)?;
            let store = connect(&http).await?;
            vault::push(&store, &mut TerminalPrompter, plan).await?;
        }
        Command::Pull { name, output } => {
            let plan = vault::plan_pull(&name, &output)?;
            let store = connect(&http).await?;
            vault::pull(&store, &mut TerminalPrompter, plan).await?;
        }
        Command::List => {
            let store = connect(&http).await?;
            let entries = vault::list(&store).await?;
            if entries.is_empty() {
                eprintln!("[+] The vault is empty");
            } else {
                print!("{}", vault::format_list(&entries));
            }
        }
        Command::Delete { name, yes } => {
            vault::validate_key_name(&name)
                .with_context(|| format!("invalid key name '{name}'"))?;
            let store = connect(&http).await?;
            vault::delete(&store, &mut TerminalPrompter, &name, yes).await?;
        }
    }
    Ok(())
}

/// Signs in (refreshing, or offering an inline browser sign-in if the session expired) and
/// returns a Drive client holding a fresh access token.
async fn connect(http: &Client) -> Result<DriveClient> {
    let config = Config::from_env()?;
    let token = Auth::new(http, &config, &KeyringStore)
        .access_token(auth::confirm_on_terminal)
        .await?;
    Ok(DriveClient::new(http.clone(), token))
}

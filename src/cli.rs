//! Command-line interface definitions (clap derive types only; no logic).

use clap::{Parser, Subcommand};

/// Zero-knowledge encryption and Google Drive backup for .pem private keys.
#[derive(Parser)]
#[command(name = "pem-vault", version, about)]
pub struct Cli {
    #[command(subcommand)]
    pub command: Command,
}

#[derive(Subcommand)]
pub enum Command {
    /// Sign in to Google in your browser and save the session in the OS keychain
    Auth,
    /// Revoke the Google session and remove it from the OS keychain
    Logout,
}

#[cfg(test)]
mod tests {
    use super::*;
    use clap::CommandFactory;

    #[test]
    fn cli_definition_is_valid() {
        Cli::command().debug_assert();
    }

    #[test]
    fn parses_subcommands() {
        assert!(matches!(
            Cli::try_parse_from(["pem-vault", "auth"]).unwrap().command,
            Command::Auth
        ));
        assert!(matches!(
            Cli::try_parse_from(["pem-vault", "logout"])
                .unwrap()
                .command,
            Command::Logout
        ));
        assert!(Cli::try_parse_from(["pem-vault"]).is_err());
        assert!(Cli::try_parse_from(["pem-vault", "auth", "--extra"]).is_err());
    }
}

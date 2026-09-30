//! Command-line interface definitions (clap derive types only; no logic).

use std::path::PathBuf;

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
    /// Encrypt a local key file and upload it to the vault
    Push {
        /// The key file to encrypt (e.g. ~/.ssh/prod.pem)
        #[arg(short, long, value_name = "FILE")]
        input: PathBuf,
        /// Name to store it under [default: the input file's name]
        #[arg(short, long, value_name = "KEY")]
        name: Option<String>,
        /// Replace an existing key with the same name
        #[arg(long)]
        force: bool,
    },
    /// Download a key from the vault, decrypt it and write it to a new 0600 file
    Pull {
        /// Name of the key in the vault
        #[arg(short, long, value_name = "KEY")]
        name: String,
        /// New file to write (must not exist)
        #[arg(short, long, value_name = "FILE")]
        output: PathBuf,
    },
    /// List the keys in the vault
    List,
    /// Permanently delete a key from the vault
    Delete {
        /// Name of the key in the vault
        #[arg(short, long, value_name = "KEY")]
        name: String,
        /// Skip the confirmation prompt
        #[arg(short, long)]
        yes: bool,
    },
}

#[cfg(test)]
mod tests {
    use super::*;
    use clap::CommandFactory;

    fn parse(args: &[&str]) -> Result<Command, clap::Error> {
        Cli::try_parse_from(std::iter::once("pem-vault").chain(args.iter().copied()))
            .map(|cli| cli.command)
    }

    #[test]
    fn cli_definition_is_valid() {
        Cli::command().debug_assert();
    }

    #[test]
    fn parses_all_commands() {
        assert!(matches!(parse(&["auth"]), Ok(Command::Auth)));
        assert!(matches!(parse(&["logout"]), Ok(Command::Logout)));
        assert!(matches!(parse(&["list"]), Ok(Command::List)));
        assert!(matches!(
            parse(&["push", "-i", "k.pem"]),
            Ok(Command::Push {
                name: None,
                force: false,
                ..
            })
        ));
        assert!(matches!(
            parse(&["push", "--input", "k.pem", "--name", "x.pem", "--force"]),
            Ok(Command::Push {
                name: Some(_),
                force: true,
                ..
            })
        ));
        assert!(matches!(
            parse(&["pull", "-n", "x.pem", "-o", "/tmp/x.pem"]),
            Ok(Command::Pull { .. })
        ));
        assert!(matches!(
            parse(&["delete", "--name", "x.pem", "--yes"]),
            Ok(Command::Delete { yes: true, .. })
        ));
    }

    #[test]
    fn rejects_missing_required_arguments() {
        for args in [
            &[][..],
            &["push"],
            &["pull", "-n", "x.pem"],
            &["pull", "-o", "out.pem"],
            &["delete"],
            &["auth", "--extra"],
        ] {
            assert!(parse(args).is_err(), "{args:?}");
        }
    }

    #[test]
    fn has_no_passphrase_argument() {
        // Invariant 4: passphrases only come from the TTY prompt.
        let help = Cli::command().render_long_help().to_string().to_lowercase();
        for sub in Cli::command().get_subcommands() {
            for arg in sub.get_arguments() {
                let id = arg.get_id().as_str().to_lowercase();
                assert!(!id.contains("pass") && !id.contains("secret"), "{id}");
            }
        }
        assert!(!help.contains("--passphrase"));
    }
}

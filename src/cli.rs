//! Command-line interface definitions (clap derive types only; no logic).

use std::path::PathBuf;

use clap::{Parser, Subcommand};

const MAIN_EXAMPLES: &str = "\
Examples:
  pem-vault auth                                Sign in to Google (opens your browser)
  pem-vault push -i ~/.ssh/prod.pem             Encrypt and upload a key (stored as prod.pem)
  pem-vault list                                Show the keys in the vault
  pem-vault pull -n prod.pem -o /tmp/prod.pem   Decrypt a key to a new 0600 file
  pem-vault delete -n prod.pem                  Permanently delete a key

Run `pem-vault <COMMAND> --help` for more examples.";

const AUTH_EXAMPLES: &str = "\
Examples:
  pem-vault auth       Sign in once; other commands also offer to sign in when needed";

const LOGOUT_EXAMPLES: &str = "\
Examples:
  pem-vault logout     Revoke access at Google and forget the session on this machine";

const PUSH_EXAMPLES: &str = "\
Examples:
  pem-vault push -i ~/.ssh/prod.pem                   Store as \"prod.pem\"
  pem-vault push -i ~/.ssh/id_ed25519 -n github.pem   Store under a different name
  pem-vault push -i ~/.ssh/prod.pem --force           Replace the stored \"prod.pem\" (old version is lost)";

const PULL_EXAMPLES: &str = "\
Examples:
  pem-vault pull -n prod.pem -o /tmp/prod.pem   Decrypt to a new file (never overwrites)

  Load it into ssh-agent, then remove the file:
  pem-vault pull -n prod.pem -o /tmp/prod.pem && ssh-add /tmp/prod.pem; rm -f /tmp/prod.pem";

const LIST_EXAMPLES: &str = "\
Examples:
  pem-vault list       Name, encrypted size and last-modified time (UTC) of every key";

const DELETE_EXAMPLES: &str = "\
Examples:
  pem-vault delete -n prod.pem         Asks you to type the name to confirm
  pem-vault delete -n prod.pem --yes   No prompt (for scripts); removes all copies";

/// Zero-knowledge encryption and Google Drive backup for .pem private keys.
#[derive(Parser)]
#[command(name = "pem-vault", version, about, after_help = MAIN_EXAMPLES)]
pub struct Cli {
    #[command(subcommand)]
    pub command: Command,
}

#[derive(Subcommand)]
pub enum Command {
    /// Sign in to Google in your browser and save the session in the OS keychain
    #[command(after_help = AUTH_EXAMPLES)]
    Auth,
    /// Revoke the Google session and remove it from the OS keychain
    #[command(after_help = LOGOUT_EXAMPLES)]
    Logout,
    /// Encrypt a local key file and upload it to the vault
    #[command(after_help = PUSH_EXAMPLES)]
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
    #[command(after_help = PULL_EXAMPLES)]
    Pull {
        /// Name of the key in the vault
        #[arg(short, long, value_name = "KEY")]
        name: String,
        /// New file to write (must not exist)
        #[arg(short, long, value_name = "FILE")]
        output: PathBuf,
    },
    /// List the keys in the vault
    #[command(after_help = LIST_EXAMPLES)]
    List,
    /// Permanently delete a key from the vault
    #[command(after_help = DELETE_EXAMPLES)]
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

    /// Every `pem-vault …` example in the help text must be valid syntax, so the examples
    /// can't silently go stale when an argument changes.
    #[test]
    fn help_examples_parse() {
        let mut checked = 0;
        for text in [
            MAIN_EXAMPLES,
            AUTH_EXAMPLES,
            LOGOUT_EXAMPLES,
            PUSH_EXAMPLES,
            PULL_EXAMPLES,
            LIST_EXAMPLES,
            DELETE_EXAMPLES,
        ] {
            for line in text.lines().map(str::trim_start) {
                let Some(rest) = line.strip_prefix("pem-vault ") else {
                    continue;
                };
                // The command ends at a shell operator or at the two-space gap before the
                // description.
                let command = rest
                    .split(" && ")
                    .next()
                    .and_then(|c| c.split("  ").next())
                    .unwrap();
                let args: Vec<&str> = command.split_whitespace().collect();
                assert!(
                    parse(&args).is_ok(),
                    "example doesn't parse: pem-vault {command}"
                );
                checked += 1;
            }
        }
        assert!(checked >= 13, "only {checked} examples found");
    }

    #[test]
    fn every_command_shows_examples() {
        let mut cli = Cli::command();
        assert!(cli.render_help().to_string().contains("Examples:"));
        // clap's built-in `help` subcommand is the only one without examples.
        for sub in cli.get_subcommands_mut().filter(|s| s.get_name() != "help") {
            let help = sub.render_help().to_string();
            assert!(
                help.contains("Examples:"),
                "{} has no examples",
                sub.get_name()
            );
        }
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

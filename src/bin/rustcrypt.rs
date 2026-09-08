//! `rustcrypt`: command-line tool for the `rustcrypt-jasypt` library.
//!
//! Mirrors `gocrypt-cli` (and the pycrypt / nodecrypt CLIs) so the same
//! commands work across the whole family:
//!
//! ```text
//! rustcrypt encrypt      -p <password> -v <value> [--no-prefix] [--jasypt | --jasypt-strong]
//! rustcrypt decrypt      -p <password> -v <value>               [--jasypt | --jasypt-strong]
//! rustcrypt encrypt-file -p <password> -i <in> [-o <out>|-]     [--jasypt | --jasypt-strong]
//! rustcrypt decrypt-file -p <password> -i <in> [-o <out>|-]     [--jasypt | --jasypt-strong]
//! rustcrypt version | --version
//! rustcrypt help    | --help
//! ```
//!
//! The password may also be supplied through the `RUSTCRYPT_PASSWORD`
//! environment variable.

use std::env;
use std::fs::File;
use std::io::{self, BufRead, BufReader, BufWriter, Write};
use std::path::PathBuf;
use std::process::ExitCode;

use clap::{Args, Parser, Subcommand};
use rustcrypt_jasypt::{
    is_encrypted, Encryptor, JasyptEncryptor, JasyptStrongEncryptor, StringEncryptor,
};

const ENV_PASSWORD: &str = "RUSTCRYPT_PASSWORD";

const AFTER_HELP: &str = "\
Examples:
  # Encrypt a database password
  rustcrypt encrypt -p mySecret -v \"db_password123\"

  # Decrypt a value
  rustcrypt decrypt -p mySecret -v \"ENC(base64encodedvalue)\"

  # Encrypt values in a .env file
  rustcrypt encrypt-file -p mySecret -i .env.plain -o .env.encrypted

  # Decrypt all ENC(...) values in a file
  rustcrypt decrypt-file -p mySecret -i .env.encrypted -o .env.plain

  # Use Jasypt-compatible encryption (readable by Java Jasypt)
  rustcrypt encrypt -p mySecret -v \"secret\" --jasypt

Environment Variables:
  RUSTCRYPT_PASSWORD  Password for encryption/decryption

An idea from Fariz (github.com/farizfadian) and made with love by Claude AI (claude.ai)";

/// Jasypt-like encryption for Rust configurations.
///
/// Encrypt and decrypt ENC(...) values compatible with GoCrypt, PyCrypt,
/// NodeCrypt, PHPCrypt and (in --jasypt mode) Java Jasypt.
#[derive(Parser)]
#[command(
    name = "rustcrypt",
    version,
    about = "rustcrypt - Jasypt-like encryption for Rust configurations",
    long_about = None,
    after_help = AFTER_HELP,
    arg_required_else_help = true
)]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Args)]
struct Common {
    /// Encryption password (or set RUSTCRYPT_PASSWORD env var)
    #[arg(short = 'p', long)]
    password: Option<String>,

    /// Use Jasypt-compatible algorithm (PBEWithMD5AndDES)
    #[arg(long, conflicts_with = "jasypt_strong")]
    jasypt: bool,

    /// Use Jasypt strong algorithm (PBEWithHmacSHA256AndAES_256)
    #[arg(long)]
    jasypt_strong: bool,
}

#[derive(Subcommand)]
enum Command {
    /// Encrypt a single value
    Encrypt {
        #[command(flatten)]
        common: Common,

        /// Value to encrypt
        #[arg(short = 'v', long)]
        value: Option<String>,

        /// Don't wrap encrypted value with ENC(...)
        #[arg(long)]
        no_prefix: bool,
    },

    /// Decrypt a single value (ENC(...) wrapper is optional)
    Decrypt {
        #[command(flatten)]
        common: Common,

        /// Value to decrypt
        #[arg(short = 'v', long)]
        value: Option<String>,
    },

    /// Encrypt all KEY=VALUE values in a file
    EncryptFile {
        #[command(flatten)]
        common: Common,

        /// Input file path
        #[arg(short = 'i', long)]
        input: Option<String>,

        /// Output file path (omit or "-" for stdout)
        #[arg(short = 'o', long)]
        output: Option<String>,
    },

    /// Decrypt all ENC(...) values in a file
    DecryptFile {
        #[command(flatten)]
        common: Common,

        /// Input file path
        #[arg(short = 'i', long)]
        input: Option<String>,

        /// Output file path (omit or "-" for stdout)
        #[arg(short = 'o', long)]
        output: Option<String>,
    },

    /// Show version information
    Version,
}

fn main() -> ExitCode {
    let cli = match Cli::try_parse() {
        Ok(cli) => cli,
        Err(err) => {
            // Usage errors exit 1 (like gocrypt-cli); --help/--version exit 0.
            let _ = err.print();
            return if err.use_stderr() {
                ExitCode::from(1)
            } else {
                ExitCode::SUCCESS
            };
        }
    };

    match run(cli.command) {
        Ok(()) => ExitCode::SUCCESS,
        Err(message) => {
            eprintln!("{message}");
            ExitCode::from(1)
        }
    }
}

fn run(command: Command) -> Result<(), String> {
    match command {
        Command::Encrypt {
            common,
            value,
            no_prefix,
        } => {
            let password = resolve_password(common.password.as_deref())?;
            let value = require_value(value)?;
            let enc = create_encryptor(&password, &common)?;
            let result = if no_prefix {
                enc.encrypt(&value)
            } else {
                enc.encrypt_with_prefix(&value)
            }
            .map_err(error)?;
            println!("{result}");
            Ok(())
        }

        Command::Decrypt { common, value } => {
            let password = resolve_password(common.password.as_deref())?;
            let value = require_value(value)?;
            let enc = create_encryptor(&password, &common)?;
            let result = if is_encrypted(&value) {
                enc.decrypt_prefixed(&value)
            } else {
                enc.decrypt(&value)
            }
            .map_err(error)?;
            println!("{result}");
            Ok(())
        }

        Command::EncryptFile {
            common,
            input,
            output,
        } => {
            let password = resolve_password(common.password.as_deref())?;
            let input = require_input(input)?;
            let enc = create_encryptor(&password, &common)?;
            process_file(&input, output.as_deref(), |line| {
                encrypt_line(enc.as_ref(), line)
            })
        }

        Command::DecryptFile {
            common,
            input,
            output,
        } => {
            let password = resolve_password(common.password.as_deref())?;
            let input = require_input(input)?;
            let enc = create_encryptor(&password, &common)?;
            process_file(&input, output.as_deref(), |line| {
                Ok(enc.decrypt_all_in_string_lossy(line))
            })
        }

        Command::Version => {
            println!("rustcrypt version {}", env!("CARGO_PKG_VERSION"));
            Ok(())
        }
    }
}

/// Formats a library error the way gocrypt-cli does: `Error: <message>`.
fn error(err: impl std::fmt::Display) -> String {
    format!("Error: {err}")
}

/// `-p` wins when non-empty, otherwise `RUSTCRYPT_PASSWORD`.
fn resolve_password(flag: Option<&str>) -> Result<String, String> {
    if let Some(p) = flag.filter(|p| !p.is_empty()) {
        return Ok(p.to_owned());
    }
    match env::var(ENV_PASSWORD) {
        Ok(p) if !p.is_empty() => Ok(p),
        _ => Err(format!(
            "Error: password is required (-p or {ENV_PASSWORD})"
        )),
    }
}

fn require_value(value: Option<String>) -> Result<String, String> {
    value
        .filter(|v| !v.is_empty())
        .ok_or_else(|| "Error: value is required (-v)".to_owned())
}

fn require_input(input: Option<String>) -> Result<PathBuf, String> {
    input
        .filter(|p| !p.is_empty())
        .map(PathBuf::from)
        .ok_or_else(|| "Error: input file is required (-i)".to_owned())
}

fn create_encryptor(password: &str, common: &Common) -> Result<Box<dyn StringEncryptor>, String> {
    let enc: Box<dyn StringEncryptor> = if common.jasypt {
        Box::new(JasyptEncryptor::new(password).map_err(error)?)
    } else if common.jasypt_strong {
        Box::new(JasyptStrongEncryptor::new(password).map_err(error)?)
    } else {
        Box::new(Encryptor::new(password).map_err(error)?)
    };
    Ok(enc)
}

/// Applies `transform` to every line of `input` and writes the result to
/// `output` (a path, or stdout when omitted / `-`).
fn process_file(
    input: &PathBuf,
    output: Option<&str>,
    mut transform: impl FnMut(&str) -> Result<String, String>,
) -> Result<(), String> {
    let file = File::open(input).map_err(|e| format!("Error opening input file: {e}"))?;
    let reader = BufReader::new(file);

    let mut writer: Box<dyn Write> = match output {
        None | Some("-") | Some("") => Box::new(BufWriter::new(io::stdout())),
        Some(path) => Box::new(BufWriter::new(
            File::create(path).map_err(|e| format!("Error creating output file: {e}"))?,
        )),
    };

    for line in reader.lines() {
        let line = line.map_err(|e| format!("Error reading file: {e}"))?;
        let out = transform(&line)?;
        writeln!(writer, "{out}").map_err(|e| format!("Error writing output: {e}"))?;
    }
    writer
        .flush()
        .map_err(|e| format!("Error writing output: {e}"))
}

/// gocrypt-cli `encrypt-file` line rule: a `KEY=VALUE` line whose trimmed
/// form does not start with `#` gets its value (with surrounding quotes
/// removed) encrypted, unless the value is empty or already `ENC(...)`.
/// Every other line passes through unchanged.
fn encrypt_line(enc: &dyn StringEncryptor, line: &str) -> Result<String, String> {
    if line.contains('=') && !line.trim().starts_with('#') {
        if let Some((key, raw_value)) = line.split_once('=') {
            let value = raw_value.trim_matches(|c| c == '"' || c == '\'');
            if !is_encrypted(value) && !value.is_empty() {
                let encrypted = enc
                    .encrypt_with_prefix(value)
                    .map_err(|e| format!("Error encrypting {key}: {e}"))?;
                return Ok(format!("{key}={encrypted}"));
            }
        }
    }
    Ok(line.to_owned())
}

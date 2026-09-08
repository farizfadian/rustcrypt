//! End-to-end tests for the `rustcrypt` binary (feature `cli`).
#![cfg(feature = "cli")]

use std::fs;

use assert_cmd::Command;
use predicates::prelude::*;
use rustcrypt_jasypt::{Encryptor, JasyptEncryptor, JasyptStrongEncryptor};
use tempfile::tempdir;

const PASSWORD: &str = "rustcrypt-test-2026";
const UTF8: &str = "Selamat pagi, Fariz 🦀";

fn rustcrypt() -> Command {
    let mut cmd = Command::new(env!("CARGO_BIN_EXE_rustcrypt"));
    cmd.env_remove("RUSTCRYPT_PASSWORD");
    cmd
}

fn stdout_line(cmd: &mut Command) -> String {
    let output = cmd.assert().success().get_output().stdout.clone();
    String::from_utf8(output)
        .unwrap()
        .trim_end_matches(['\r', '\n'])
        .to_owned()
}

const MODES: [Option<&str>; 3] = [None, Some("--jasypt"), Some("--jasypt-strong")];

fn with_mode<'a>(cmd: &'a mut Command, mode: Option<&str>) -> &'a mut Command {
    if let Some(flag) = mode {
        cmd.arg(flag);
    }
    cmd
}

// ─────────────────────────────────────────────────────────────────────────────
// encrypt / decrypt
// ─────────────────────────────────────────────────────────────────────────────

#[test]
fn encrypt_then_decrypt_roundtrip_in_every_mode() {
    for mode in MODES {
        for plaintext in ["hello", "Password123!", UTF8] {
            let wrapped = stdout_line(with_mode(
                rustcrypt().args(["encrypt", "-p", PASSWORD, "-v", plaintext]),
                mode,
            ));
            assert!(
                wrapped.starts_with("ENC(") && wrapped.ends_with(')'),
                "{wrapped}"
            );

            let decrypted = stdout_line(with_mode(
                rustcrypt().args(["decrypt", "-p", PASSWORD, "-v", &wrapped]),
                mode,
            ));
            assert_eq!(decrypted, plaintext, "mode={mode:?}");
        }
    }
}

#[test]
fn cli_output_is_readable_by_the_library_and_vice_versa() {
    let wrapped =
        stdout_line(rustcrypt().args(["encrypt", "-p", PASSWORD, "-v", "lib", "--jasypt"]));
    assert_eq!(
        JasyptEncryptor::new(PASSWORD)
            .unwrap()
            .decrypt_prefixed(&wrapped)
            .unwrap(),
        "lib"
    );

    let from_lib = JasyptStrongEncryptor::new(PASSWORD)
        .unwrap()
        .encrypt_with_prefix("strong")
        .unwrap();
    let out = stdout_line(rustcrypt().args([
        "decrypt",
        "-p",
        PASSWORD,
        "-v",
        &from_lib,
        "--jasypt-strong",
    ]));
    assert_eq!(out, "strong");
}

#[test]
fn no_prefix_emits_raw_payload_that_decrypt_accepts() {
    let raw =
        stdout_line(rustcrypt().args(["encrypt", "-p", PASSWORD, "-v", "raw", "--no-prefix"]));
    assert!(!raw.contains("ENC("));
    assert_eq!(
        Encryptor::new(PASSWORD).unwrap().decrypt(&raw).unwrap(),
        "raw"
    );
    // decrypt auto-detects the missing wrapper
    let out = stdout_line(rustcrypt().args(["decrypt", "-p", PASSWORD, "-v", &raw]));
    assert_eq!(out, "raw");
}

#[test]
fn password_falls_back_to_environment_variable() {
    let wrapped = stdout_line(
        rustcrypt()
            .env("RUSTCRYPT_PASSWORD", PASSWORD)
            .args(["encrypt", "-v", "from-env"]),
    );
    // An empty -p also falls back to the environment (gocrypt-cli semantics).
    let out = stdout_line(
        rustcrypt()
            .env("RUSTCRYPT_PASSWORD", PASSWORD)
            .args(["decrypt", "-p", "", "-v", &wrapped]),
    );
    assert_eq!(out, "from-env");
}

#[test]
fn missing_password_is_an_error() {
    rustcrypt()
        .args(["encrypt", "-v", "x"])
        .assert()
        .code(1)
        .stderr(predicate::str::contains(
            "Error: password is required (-p or RUSTCRYPT_PASSWORD)",
        ));
}

#[test]
fn missing_value_is_an_error() {
    rustcrypt()
        .args(["encrypt", "-p", PASSWORD])
        .assert()
        .code(1)
        .stderr(predicate::str::contains("Error: value is required (-v)"));
    rustcrypt()
        .args(["decrypt", "-p", PASSWORD, "-v", ""])
        .assert()
        .code(1)
        .stderr(predicate::str::contains("Error: value is required (-v)"));
}

#[test]
fn jasypt_flags_are_mutually_exclusive() {
    rustcrypt()
        .args([
            "encrypt",
            "-p",
            PASSWORD,
            "-v",
            "x",
            "--jasypt",
            "--jasypt-strong",
        ])
        .assert()
        .code(1)
        .stderr(predicate::str::contains("cannot be used with"));
}

#[test]
fn wrong_password_reports_decryption_failed() {
    let wrapped = stdout_line(rustcrypt().args(["encrypt", "-p", PASSWORD, "-v", "x"]));
    rustcrypt()
        .args(["decrypt", "-p", "wrong", "-v", &wrapped])
        .assert()
        .code(1)
        .stdout(predicate::str::is_empty())
        .stderr(predicate::str::contains("Error: decryption failed"));
}

#[test]
fn invalid_input_reports_library_error() {
    rustcrypt()
        .args(["decrypt", "-p", PASSWORD, "-v", "ENC(not base64!)"])
        .assert()
        .code(1)
        .stderr(predicate::str::starts_with("Error: base64 decode error"));
}

// ─────────────────────────────────────────────────────────────────────────────
// encrypt-file / decrypt-file
// ─────────────────────────────────────────────────────────────────────────────

const ENV_PLAIN: &str = "# Database settings\n\
DB_HOST=localhost\n\
DB_PASS=\"s3cr3t\"\n\
\n\
EMPTY=\n\
ALREADY=ENC(abc)\n\
NOT A PAIR\n\
API_KEY='key with spaces'\n\
\x20 # indented comment=1\n";

#[test]
fn encrypt_file_then_decrypt_file_roundtrip() {
    for mode in MODES {
        let dir = tempdir().unwrap();
        let plain = dir.path().join(".env.plain");
        let encrypted = dir.path().join(".env.encrypted");
        let restored = dir.path().join(".env.restored");
        fs::write(&plain, ENV_PLAIN).unwrap();

        with_mode(
            rustcrypt()
                .args(["encrypt-file", "-p", PASSWORD])
                .arg("-i")
                .arg(&plain)
                .arg("-o")
                .arg(&encrypted),
            mode,
        )
        .assert()
        .success()
        .stdout(predicate::str::is_empty());

        let enc_text = fs::read_to_string(&encrypted).unwrap();
        let lines: Vec<&str> = enc_text.lines().collect();
        assert_eq!(lines.len(), 9, "{enc_text}");
        assert_eq!(lines[0], "# Database settings");
        assert!(lines[1].starts_with("DB_HOST=ENC(") && lines[1].ends_with(')'));
        assert!(lines[2].starts_with("DB_PASS=ENC("));
        assert!(
            !lines[2].contains('"'),
            "quotes must be stripped before encrypting"
        );
        assert_eq!(lines[3], "");
        assert_eq!(lines[4], "EMPTY=");
        assert_eq!(lines[5], "ALREADY=ENC(abc)");
        assert_eq!(lines[6], "NOT A PAIR");
        assert!(lines[7].starts_with("API_KEY=ENC("));
        assert_eq!(lines[8], "  # indented comment=1");
        assert!(enc_text.ends_with('\n'));

        with_mode(
            rustcrypt()
                .args(["decrypt-file", "-p", PASSWORD])
                .arg("-i")
                .arg(&encrypted)
                .arg("-o")
                .arg(&restored),
            mode,
        )
        .assert()
        .success();

        let restored_text = fs::read_to_string(&restored).unwrap();
        assert_eq!(
            restored_text,
            "# Database settings\n\
             DB_HOST=localhost\n\
             DB_PASS=s3cr3t\n\
             \n\
             EMPTY=\n\
             ALREADY=ENC(abc)\n\
             NOT A PAIR\n\
             API_KEY=key with spaces\n\
             \x20 # indented comment=1\n",
            "mode={mode:?}"
        );
    }
}

#[test]
fn file_commands_write_to_stdout_when_output_is_dash_or_omitted() {
    let dir = tempdir().unwrap();
    let plain = dir.path().join("in.env");
    fs::write(&plain, "K=v\n").unwrap();

    let to_dash = stdout_line(
        rustcrypt()
            .args(["encrypt-file", "-p", PASSWORD, "--jasypt"])
            .arg("-i")
            .arg(&plain)
            .args(["-o", "-"]),
    );
    assert!(to_dash.starts_with("K=ENC("), "{to_dash}");

    let omitted = stdout_line(
        rustcrypt()
            .args(["encrypt-file", "-p", PASSWORD, "--jasypt"])
            .arg("-i")
            .arg(&plain),
    );
    assert!(omitted.starts_with("K=ENC("), "{omitted}");

    let back = stdout_line(
        rustcrypt()
            .args(["decrypt-file", "-p", PASSWORD, "--jasypt", "-i"])
            .arg({
                let encrypted = dir.path().join("out.env");
                fs::write(&encrypted, format!("{omitted}\nX=ENC(not base64!)\n")).unwrap();
                encrypted
            }),
    );
    assert_eq!(
        back, "K=v\nX=ENC(not base64!)",
        "bad values are kept verbatim"
    );
}

#[test]
fn file_commands_report_missing_or_unreadable_input() {
    rustcrypt()
        .args(["encrypt-file", "-p", PASSWORD])
        .assert()
        .code(1)
        .stderr(predicate::str::contains(
            "Error: input file is required (-i)",
        ));
    rustcrypt()
        .args(["decrypt-file", "-p", PASSWORD, "-i", ""])
        .assert()
        .code(1)
        .stderr(predicate::str::contains(
            "Error: input file is required (-i)",
        ));

    let missing = std::env::temp_dir().join("rustcrypt-cli-missing-2026.env");
    rustcrypt()
        .args(["encrypt-file", "-p", PASSWORD, "-i"])
        .arg(&missing)
        .assert()
        .code(1)
        .stderr(predicate::str::starts_with("Error opening input file:"));
}

// ─────────────────────────────────────────────────────────────────────────────
// version / help / usage errors
// ─────────────────────────────────────────────────────────────────────────────

#[test]
fn version_outputs() {
    rustcrypt()
        .arg("version")
        .assert()
        .success()
        .stdout(predicate::str::contains(format!(
            "rustcrypt version {}",
            env!("CARGO_PKG_VERSION")
        )));
    rustcrypt()
        .arg("--version")
        .assert()
        .success()
        .stdout(predicate::str::contains(format!(
            "rustcrypt {}",
            env!("CARGO_PKG_VERSION")
        )));
}

#[test]
fn help_ends_with_family_footer() {
    let footer =
        "An idea from Fariz (github.com/farizfadian) and made with love by Claude AI (claude.ai)";
    for args in [vec!["--help"], vec!["help"], vec!["-h"]] {
        rustcrypt()
            .args(&args)
            .assert()
            .success()
            .stdout(predicate::str::contains("encrypt-file"))
            .stdout(predicate::str::contains("RUSTCRYPT_PASSWORD"))
            .stdout(predicate::str::ends_with(format!("{footer}\n")));
    }
}

#[test]
fn no_args_prints_usage_and_fails() {
    rustcrypt()
        .assert()
        .code(1)
        .stderr(predicate::str::contains("Usage:"));
}

#[test]
fn unknown_command_fails() {
    rustcrypt()
        .arg("frobnicate")
        .assert()
        .code(1)
        .stderr(predicate::str::contains("frobnicate"));
}

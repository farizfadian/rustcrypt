//! ConfigLoader tests (feature `config`): .env, flat YAML, JSON and set_to_env.
#![cfg(feature = "config")]

use std::io::Write;

use rustcrypt_jasypt::{
    ConfigLoader, Encryptor, Error, JasyptEncryptor, JasyptStrongEncryptor, StringEncryptor,
};
use serde::Deserialize;
use tempfile::NamedTempFile;

const PASSWORD: &str = "rustcrypt-test-2026";

fn temp_file(contents: &str) -> NamedTempFile {
    let mut file = NamedTempFile::new().unwrap();
    file.write_all(contents.as_bytes()).unwrap();
    file.flush().unwrap();
    file
}

fn gcm() -> Encryptor {
    Encryptor::new(PASSWORD).unwrap()
}

// ─────────────────────────────────────────────────────────────────────────────
// .env
// ─────────────────────────────────────────────────────────────────────────────

#[test]
fn load_env_file_parses_like_gocrypt() {
    let secret = gcm().encrypt_with_prefix("s3cr3t").unwrap();
    let file = temp_file(&format!(
        "# comment line\n\
         DB_HOST=localhost\n\
         \n\
         DB_PORT=\"5432\"\n\
         DB_PASS={secret}\n\
         QUOTED='single quoted'\n\
         EQUALS=a=b=c\n\
         MALFORMED LINE WITHOUT SEPARATOR\n\
         \t  SPACED   =   value with spaces   \n\
         EMPTY=\n\
         WRAPPED=  {secret}  \n"
    ));

    let loader = ConfigLoader::new(PASSWORD).unwrap();
    let config = loader.load_env_file(file.path()).unwrap();

    assert_eq!(config["DB_HOST"], "localhost");
    assert_eq!(config["DB_PORT"], "5432");
    assert_eq!(config["DB_PASS"], "s3cr3t");
    assert_eq!(config["QUOTED"], "single quoted");
    assert_eq!(config["EQUALS"], "a=b=c");
    assert_eq!(config["SPACED"], "value with spaces");
    assert_eq!(config["EMPTY"], "");
    assert_eq!(config["WRAPPED"], "s3cr3t");
    assert!(!config.contains_key("MALFORMED LINE WITHOUT SEPARATOR"));
    assert_eq!(config.len(), 8);
}

#[test]
fn load_env_file_handles_crlf() {
    let secret = gcm().encrypt_with_prefix("crlf").unwrap();
    let file = temp_file(&format!("A=1\r\nB={secret}\r\n"));
    let config = ConfigLoader::new(PASSWORD)
        .unwrap()
        .load_env_file(file.path())
        .unwrap();
    assert_eq!(config["A"], "1");
    assert_eq!(config["B"], "crlf");
}

#[test]
fn load_env_file_reports_failing_key() {
    let wrong = Encryptor::new("another-password")
        .unwrap()
        .encrypt_with_prefix("x")
        .unwrap();
    let file = temp_file(&format!("OK=1\nDB_PASS={wrong}\n"));
    let err = ConfigLoader::new(PASSWORD)
        .unwrap()
        .load_env_file(file.path())
        .unwrap_err();
    assert!(err
        .to_string()
        .starts_with("failed to decrypt key DB_PASS: "));
    match err {
        Error::KeyDecrypt { key, source } => {
            assert_eq!(key, "DB_PASS");
            assert!(matches!(*source, Error::DecryptionFailed));
        }
        other => panic!("unexpected error {other:?}"),
    }
}

#[test]
fn missing_file_is_io_error() {
    let loader = ConfigLoader::new(PASSWORD).unwrap();
    let missing = std::env::temp_dir().join("rustcrypt-does-not-exist-2026.env");
    assert!(matches!(loader.load_env_file(&missing), Err(Error::Io(_))));
    assert!(matches!(loader.load_yaml(&missing), Err(Error::Io(_))));
    assert!(matches!(
        loader.load_json::<serde_json::Value>(&missing),
        Err(Error::Io(_))
    ));
}

#[test]
fn empty_password_rejected() {
    assert!(matches!(ConfigLoader::new(""), Err(Error::EmptyPassword)));
}

// ─────────────────────────────────────────────────────────────────────────────
// YAML (flat, GoCrypt-compatible)
// ─────────────────────────────────────────────────────────────────────────────

#[test]
fn load_yaml_flattens_like_gocrypt() {
    let secret = gcm().encrypt_with_prefix("yaml-secret").unwrap();
    let file = temp_file(&format!(
        "# config\n\
         database:\n\
         \x20 host: localhost\n\
         \x20 port: 5432\n\
         \x20 password: \"{secret}\"\n\
         url: http://example.com:8080\n\
         - not a pair\n"
    ));
    let config = ConfigLoader::new(PASSWORD)
        .unwrap()
        .load_yaml(file.path())
        .unwrap();

    assert_eq!(config["database"], "");
    assert_eq!(config["host"], "localhost");
    assert_eq!(config["port"], "5432");
    assert_eq!(config["password"], "yaml-secret");
    assert_eq!(config["url"], "http://example.com:8080");
    assert_eq!(config.len(), 5);
}

// ─────────────────────────────────────────────────────────────────────────────
// JSON (nested + arrays, serde)
// ─────────────────────────────────────────────────────────────────────────────

#[derive(Debug, Deserialize, PartialEq)]
struct Database {
    host: String,
    password: String,
}

#[derive(Debug, Deserialize, PartialEq)]
struct Server {
    name: String,
    token: String,
}

#[derive(Debug, Deserialize, PartialEq)]
struct Config {
    database: Database,
    api_keys: Vec<String>,
    servers: Vec<Server>,
    retries: u32,
    enabled: bool,
    note: String,
    nested: Vec<Vec<String>>,
}

#[test]
fn load_json_decrypts_recursively_into_struct() {
    let enc = gcm();
    let db_pass = enc.encrypt_with_prefix("db-pass").unwrap();
    let key1 = enc.encrypt_with_prefix("key-1").unwrap();
    let token = enc.encrypt_with_prefix("tok").unwrap();
    let deep = enc.encrypt_with_prefix("deep").unwrap();
    let invalid = "ENC(not base64!)";

    let file = temp_file(&format!(
        r#"{{
            "database": {{ "host": "localhost", "password": "{db_pass}" }},
            "api_keys": ["{key1}", "plain-key"],
            "servers": [ {{ "name": "a", "token": "{token}" }}, {{ "name": "b", "token": "plain" }} ],
            "retries": 3,
            "enabled": true,
            "note": "{invalid}",
            "nested": [["{deep}", "x"], []]
        }}"#
    ));

    let config: Config = ConfigLoader::new(PASSWORD)
        .unwrap()
        .load_json(file.path())
        .unwrap();

    assert_eq!(
        config,
        Config {
            database: Database {
                host: "localhost".into(),
                password: "db-pass".into()
            },
            api_keys: vec!["key-1".into(), "plain-key".into()],
            servers: vec![
                Server {
                    name: "a".into(),
                    token: "tok".into()
                },
                Server {
                    name: "b".into(),
                    token: "plain".into()
                },
            ],
            retries: 3,
            enabled: true,
            note: invalid.into(), // kept verbatim on failure
            nested: vec![vec!["deep".into(), "x".into()], vec![]],
        }
    );
}

#[test]
fn load_json_invalid_json_is_json_error() {
    let file = temp_file("{ not json");
    let err = ConfigLoader::new(PASSWORD)
        .unwrap()
        .load_json::<serde_json::Value>(file.path())
        .unwrap_err();
    assert!(matches!(err, Error::Json(_)));
    assert!(err.to_string().starts_with("json error: "));
}

#[test]
fn decrypt_json_value_in_place() {
    let secret = gcm().encrypt_with_prefix("v").unwrap();
    let mut value = serde_json::json!({ "a": secret, "b": [1, null, {"c": secret}] });
    ConfigLoader::new(PASSWORD)
        .unwrap()
        .decrypt_json_value(&mut value);
    assert_eq!(
        value,
        serde_json::json!({ "a": "v", "b": [1, null, {"c": "v"}] })
    );
}

// ─────────────────────────────────────────────────────────────────────────────
// set_to_env
// ─────────────────────────────────────────────────────────────────────────────

#[test]
fn set_to_env_exports_decrypted_values() {
    let secret = gcm().encrypt_with_prefix("env-secret").unwrap();
    let file = temp_file(&format!(
        "RUSTCRYPT_TEST_SET_TO_ENV_PLAIN=plain\nRUSTCRYPT_TEST_SET_TO_ENV_SECRET={secret}\n"
    ));
    ConfigLoader::new(PASSWORD)
        .unwrap()
        .set_to_env(file.path())
        .unwrap();
    assert_eq!(
        std::env::var("RUSTCRYPT_TEST_SET_TO_ENV_PLAIN").unwrap(),
        "plain"
    );
    assert_eq!(
        std::env::var("RUSTCRYPT_TEST_SET_TO_ENV_SECRET").unwrap(),
        "env-secret"
    );
}

#[test]
fn set_to_env_rejects_invalid_key() {
    let file = temp_file("=value-without-key\n");
    let err = ConfigLoader::new(PASSWORD)
        .unwrap()
        .set_to_env(file.path())
        .unwrap_err();
    assert!(matches!(err, Error::InvalidParameter(_)));
}

// ─────────────────────────────────────────────────────────────────────────────
// Custom encryptors
// ─────────────────────────────────────────────────────────────────────────────

#[test]
fn with_jasypt_encryptor_reads_java_compatible_values() {
    let jasypt = JasyptEncryptor::new(PASSWORD).unwrap();
    let secret = jasypt.encrypt_with_prefix("java-shared").unwrap();
    let file = temp_file(&format!("DB_PASS={secret}\n"));

    let loader = ConfigLoader::with_encryptor(JasyptEncryptor::new(PASSWORD).unwrap());
    assert_eq!(loader.encryptor().iterations(), 1_000);
    let config = loader.load_env_file(file.path()).unwrap();
    assert_eq!(config["DB_PASS"], "java-shared");

    // The AES-GCM loader must NOT be able to read it.
    let err = ConfigLoader::new(PASSWORD)
        .unwrap()
        .load_env_file(file.path())
        .unwrap_err();
    assert!(matches!(err, Error::KeyDecrypt { .. }));
}

#[test]
fn with_strong_encryptor_and_custom_options() {
    let strong = JasyptStrongEncryptor::new(PASSWORD)
        .unwrap()
        .with_iterations(2_000);
    let secret = strong.encrypt_with_prefix("strong").unwrap();
    let file = temp_file(&format!("password: {secret}\n"));

    let loader = ConfigLoader::with_encryptor(strong);
    assert_eq!(loader.load_yaml(file.path()).unwrap()["password"], "strong");

    let custom = Encryptor::new(PASSWORD)
        .unwrap()
        .with_iterations(1_000)
        .with_salt_size(8);
    let secret = custom.encrypt_with_prefix("custom").unwrap();
    let file = temp_file(&format!("K={secret}\n"));
    let loader = ConfigLoader::with_encryptor(custom);
    assert_eq!(loader.load_env_file(file.path()).unwrap()["K"], "custom");
}

#[test]
fn with_boxed_dyn_encryptor() {
    let boxed: Box<dyn StringEncryptor> = Box::new(JasyptEncryptor::new(PASSWORD).unwrap());
    let secret = boxed.encrypt_with_prefix("dyn").unwrap();
    let file = temp_file(&format!("K={secret}\n"));
    let loader = ConfigLoader::with_encryptor(boxed);
    assert_eq!(loader.load_env_file(file.path()).unwrap()["K"], "dyn");
}

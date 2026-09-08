//! Loading `.env`, YAML and JSON configuration with automatic `ENC(...)`
//! decryption (requires the default `config` feature).
//!
//! Run with: `cargo run --example config_loader`

use std::fs;

use rustcrypt_jasypt::{ConfigLoader, JasyptEncryptor};
use serde::Deserialize;

#[derive(Debug, Deserialize)]
struct Database {
    host: String,
    password: String,
}

#[derive(Debug, Deserialize)]
struct AppConfig {
    database: Database,
    api_keys: Vec<String>,
}

fn main() -> rustcrypt_jasypt::Result<()> {
    let password = "my-secret-password";
    let dir = std::env::temp_dir().join("rustcrypt-example");
    fs::create_dir_all(&dir)?;

    // ── AES-256-GCM loader (default, like GoCrypt's NewConfigLoader) ──────
    let loader = ConfigLoader::new(password)?;
    let enc = loader.encryptor();

    let env_path = dir.join(".env");
    fs::write(
        &env_path,
        format!(
            "# Application settings\nDB_HOST=localhost\nDB_PASS={}\nAPI_KEY=\"{}\"\n",
            enc.encrypt_with_prefix("s3cr3t")?,
            enc.encrypt_with_prefix("sk-live-123")?
        ),
    )?;
    let config = loader.load_env_file(&env_path)?;
    println!("--- .env ---");
    for key in ["DB_HOST", "DB_PASS", "API_KEY"] {
        println!("{key} = {}", config[key]);
    }

    let yaml_path = dir.join("config.yml");
    fs::write(
        &yaml_path,
        format!(
            "database:\n  host: localhost\n  password: {}\n",
            enc.encrypt_with_prefix("yaml-secret")?
        ),
    )?;
    let config = loader.load_yaml(&yaml_path)?;
    println!("\n--- config.yml (flat) ---");
    println!("host     = {}", config["host"]);
    println!("password = {}", config["password"]);

    let json_path = dir.join("config.json");
    fs::write(
        &json_path,
        format!(
            r#"{{ "database": {{ "host": "localhost", "password": "{}" }},
                 "api_keys": ["{}", "plain-key"] }}"#,
            enc.encrypt_with_prefix("json-secret")?,
            enc.encrypt_with_prefix("key-1")?
        ),
    )?;
    let app: AppConfig = loader.load_json(&json_path)?;
    println!("\n--- config.json (serde) ---");
    println!("database.host     = {}", app.database.host);
    println!("database.password = {}", app.database.password);
    println!("api_keys          = {:?}", app.api_keys);

    // ── Export to the process environment ─────────────────────────────────
    loader.set_to_env(&env_path)?;
    println!(
        "\nDB_PASS from std::env = {}",
        std::env::var("DB_PASS").unwrap()
    );

    // ── Jasypt loader for configs shared with Java ─────────────────────────
    let jasypt = JasyptEncryptor::new(password)?;
    let shared_path = dir.join("shared.env");
    fs::write(
        &shared_path,
        format!(
            "REPORT_DB_PASS={}\n",
            jasypt.encrypt_with_prefix("java-readable")?
        ),
    )?;
    let loader = ConfigLoader::with_encryptor(jasypt);
    let config = loader.load_env_file(&shared_path)?;
    println!("\n--- shared.env via JasyptEncryptor ---");
    println!("REPORT_DB_PASS = {}", config["REPORT_DB_PASS"]);

    fs::remove_dir_all(&dir)?;
    Ok(())
}

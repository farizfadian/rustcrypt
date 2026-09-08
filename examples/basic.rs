//! Basic usage of the family-internal AES-256-GCM encryptor.
//!
//! Run with: `cargo run --example basic`

use std::collections::HashMap;

use rustcrypt_jasypt::{is_encrypted, Encryptor};

fn main() -> rustcrypt_jasypt::Result<()> {
    // In real code read the password from the environment, never hard-code it.
    let enc = Encryptor::new("my-secret-password")?;

    // ── Single values ─────────────────────────────────────────────────────
    let wrapped = enc.encrypt_with_prefix("db_password_123")?;
    println!("Encrypted : {wrapped}");
    println!("Decrypted : {}", enc.decrypt_prefixed(&wrapped)?);

    // Raw payload without the ENC(...) wrapper.
    let raw = enc.encrypt("db_password_123")?;
    println!("Raw       : {raw}");
    println!("Decrypted : {}", enc.decrypt(&raw)?);

    // ── Helpers ───────────────────────────────────────────────────────────
    println!("is_encrypted(wrapped) = {}", is_encrypted(&wrapped));
    println!("is_encrypted(plain)   = {}", is_encrypted("plain-text"));

    // Replace every ENC(...) in a block of text (config file, template, ...).
    let api_key = enc.encrypt_with_prefix("sk-live-123")?;
    let text = format!("DB_HOST=localhost\nDB_PASS={wrapped}\nAPI_KEY={api_key}\n");
    println!(
        "\n--- decrypt_all_in_string ---\n{}",
        enc.decrypt_all_in_string(&text)?
    );

    // Decrypt every ENC(...) value of a map, passing other values through.
    let mut config = HashMap::new();
    config.insert("host".to_owned(), "localhost".to_owned());
    config.insert("password".to_owned(), wrapped.clone());
    let decrypted = enc.decrypt_map(&config)?;
    println!("--- decrypt_map ---");
    println!("host     = {}", decrypted["host"]);
    println!("password = {}", decrypted["password"]);

    // ── Custom parameters (both sides must agree) ─────────────────────────
    let tuned = Encryptor::new("my-secret-password")?
        .with_iterations(50_000)
        .with_salt_size(32)
        .with_key_size(32)?;
    let value = tuned.encrypt_with_prefix("tuned")?;
    assert_eq!(tuned.decrypt_prefixed(&value)?, "tuned");
    // The default encryptor cannot read it: the parameters are not encoded.
    assert!(enc.decrypt_prefixed(&value).is_err());
    println!("\nCustom-parameter round trip OK");

    Ok(())
}

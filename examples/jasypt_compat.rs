//! Java Jasypt compatibility: `JasyptEncryptor` (PBEWithMD5AndDES) and the
//! family's `JasyptStrongEncryptor`.
//!
//! Run with: `cargo run --example jasypt_compat`

use rustcrypt_jasypt::{JasyptEncryptor, JasyptStrongEncryptor};

fn main() -> rustcrypt_jasypt::Result<()> {
    // ── PBEWithMD5AndDES: readable by Java Jasypt (e.g. JasperReport) ─────
    let jasypt = JasyptEncryptor::new("rustcrypt-test-2026")?;

    // This value was produced by GoCrypt; the format is byte-identical to
    // Java Jasypt's StandardPBEStringEncryptor with PBEWithMD5AndDES.
    let from_go = "ENC(sIAlbZnxY3KGqbnsHk+t2w==)";
    println!("From GoCrypt/Java : {from_go}");
    println!("Decrypted         : {}", jasypt.decrypt_prefixed(from_go)?);

    // Values we produce can be decrypted by Java, Go, Python, Node.js and PHP.
    let for_java = jasypt.encrypt_with_prefix("shared-secret")?;
    println!("For Java          : {for_java}");
    println!(
        "Round trip        : {}",
        jasypt.decrypt_prefixed(&for_java)?
    );

    // Match the Java side's keyObtentionIterations when it is not 1000.
    let tuned = JasyptEncryptor::new("rustcrypt-test-2026")?.with_iterations(2_000);
    let value = tuned.encrypt_with_prefix("x")?;
    assert_eq!(tuned.decrypt_prefixed(&value)?, "x");

    // ── PBEWithHmacSHA256AndAES_256 (family format) ───────────────────────
    let strong = JasyptStrongEncryptor::new("rustcrypt-test-2026")?.with_iterations(5_000);
    let wrapped = strong.encrypt_with_prefix("stronger-secret")?;
    println!("\nStrong            : {wrapped}");
    println!("Decrypted         : {}", strong.decrypt_prefixed(&wrapped)?);

    // DES-CBC has no integrity check: a wrong password usually fails the
    // padding check but can occasionally return garbage instead of an error.
    let wrong = JasyptEncryptor::new("wrong-password")?;
    match wrong.decrypt_prefixed(&for_java) {
        Ok(garbage) => println!("\nWrong password returned garbage: {garbage:?}"),
        Err(err) => println!("\nWrong password: {err}"),
    }

    Ok(())
}

//! # rustcrypt-jasypt
//!
//! Jasypt-compatible `ENC(...)` encryption for Rust configuration: the 🦀 Rust
//! member of a cross-language family whose members all read each other's
//! values.
//!
//! | Library | Language | Package |
//! |---|---|---|
//! | [GoCrypt](https://github.com/farizfadian/gocrypt) | Go | `github.com/farizfadian/gocrypt` |
//! | [PyCrypt](https://github.com/farizfadian/pycrypt) | Python | `pycrypt-jasypt` |
//! | [NodeCrypt](https://github.com/farizfadian/nodecrypt) | Node.js | `nodecrypt-jasypt` |
//! | [PHPCrypt](https://github.com/farizfadian/phpcrypt) | PHP | `farizfadian/phpcrypt` |
//! | **RustCrypt** (this crate) | Rust | `rustcrypt-jasypt` |
//! | [Jasypt](http://www.jasypt.org/) | Java | the original |
//!
//! One `.env` / YAML / JSON file containing `ENC(...)` values can therefore be
//! shared by services written in any of these languages.
//!
//! ## Three encryptors
//!
//! | Type | Algorithm | Readable by Java Jasypt | Use when |
//! |---|---|---|---|
//! | [`Encryptor`] | AES-256-GCM, PBKDF2-HMAC-SHA256 | no | only family members read the value; authenticated encryption |
//! | [`JasyptEncryptor`] | `PBEWithMD5AndDES` | **yes** | the config is shared with Java Jasypt (e.g. a JasperReport service) |
//! | [`JasyptStrongEncryptor`] | PBKDF2-HMAC-SHA256, AES-256-CBC | family format only | a stronger Jasypt-style mode shared inside the family |
//!
//! ## Quick start
//!
//! ```
//! use rustcrypt_jasypt::{Encryptor, JasyptEncryptor};
//!
//! # fn main() -> rustcrypt_jasypt::Result<()> {
//! // Family-internal AES-256-GCM
//! let enc = Encryptor::new("my-password")?;
//! let wrapped = enc.encrypt_with_prefix("db_password_123")?; // "ENC(...)"
//! assert_eq!(enc.decrypt_prefixed(&wrapped)?, "db_password_123");
//!
//! // Java-compatible PBEWithMD5AndDES
//! let jasypt = JasyptEncryptor::new("my-password")?;
//! let wrapped = jasypt.encrypt_with_prefix("shared-secret")?;
//! assert_eq!(jasypt.decrypt_prefixed(&wrapped)?, "shared-secret");
//!
//! // Builder-style options (both sides must agree)
//! let tuned = Encryptor::new("my-password")?
//!     .with_iterations(50_000)
//!     .with_salt_size(32);
//! # let _ = tuned;
//! # Ok(())
//! # }
//! ```
//!
//! ## Helpers
//!
//! ```
//! use std::collections::HashMap;
//! use rustcrypt_jasypt::{is_encrypted, Encryptor};
//!
//! # fn main() -> rustcrypt_jasypt::Result<()> {
//! let enc = Encryptor::new("my-password")?;
//! let secret = enc.encrypt_with_prefix("s3cr3t")?;
//! assert!(is_encrypted(&secret));
//!
//! // Replace every ENC(...) inside a block of text
//! let text = format!("DB_HOST=localhost\nDB_PASS={secret}\n");
//! assert_eq!(
//!     enc.decrypt_all_in_string(&text)?,
//!     "DB_HOST=localhost\nDB_PASS=s3cr3t\n"
//! );
//!
//! // Decrypt only the ENC(...) values of a map
//! let mut map = HashMap::new();
//! map.insert("host".to_string(), "localhost".to_string());
//! map.insert("password".to_string(), secret);
//! let decrypted = enc.decrypt_map(&map)?;
//! assert_eq!(decrypted["host"], "localhost");
//! assert_eq!(decrypted["password"], "s3cr3t");
//! # Ok(())
//! # }
//! ```
//!
//! ## Config files (feature `config`, enabled by default)
//!
//! ```no_run
//! # #[cfg(feature = "config")]
//! # fn main() -> rustcrypt_jasypt::Result<()> {
//! use rustcrypt_jasypt::{ConfigLoader, JasyptEncryptor};
//!
//! // AES-256-GCM, like GoCrypt's NewConfigLoader
//! let loader = ConfigLoader::new("my-password")?;
//! let config = loader.load_env_file(".env")?;     // HashMap<String, String>
//! let yaml = loader.load_yaml("config.yml")?;     // flat key: value lines
//! loader.set_to_env(".env")?;                     // export to std::env
//!
//! // Jasypt mode for files shared with Java
//! let loader = ConfigLoader::with_encryptor(JasyptEncryptor::new("my-password")?);
//! let shared = loader.load_env_file("shared.env")?;
//! # let _ = (config, yaml, shared);
//! # Ok(())
//! # }
//! # #[cfg(not(feature = "config"))]
//! # fn main() {}
//! ```
//!
//! `load_json` deserialises into any `serde` type after decrypting every
//! `ENC(...)` string at any depth; see [`ConfigLoader`] for details.
//!
//! ## Generic code
//!
//! All three encryptors implement [`StringEncryptor`], so code can be written
//! once for any of them (or for `Box<dyn StringEncryptor>`):
//!
//! ```
//! use rustcrypt_jasypt::{Encryptor, JasyptEncryptor, StringEncryptor};
//!
//! fn roundtrip<E: StringEncryptor>(enc: &E) -> rustcrypt_jasypt::Result<String> {
//!     let wrapped = enc.encrypt_with_prefix("value")?;
//!     enc.decrypt_prefixed(&wrapped)
//! }
//!
//! # fn main() -> rustcrypt_jasypt::Result<()> {
//! assert_eq!(roundtrip(&Encryptor::new("pw")?)?, "value");
//! assert_eq!(roundtrip(&JasyptEncryptor::new("pw")?)?, "value");
//! let boxed: Box<dyn StringEncryptor> = Box::new(Encryptor::new("pw")?);
//! assert_eq!(roundtrip(&boxed)?, "value");
//! # Ok(())
//! # }
//! ```
//!
//! ## Command line (feature `cli`, enabled by default)
//!
//! ```text
//! cargo install rustcrypt-jasypt
//!
//! rustcrypt encrypt      -p mySecret -v "db_password"            # ENC(...)
//! rustcrypt encrypt      -p mySecret -v "db_password" --jasypt   # Java-readable
//! rustcrypt decrypt      -p mySecret -v "ENC(...)"
//! rustcrypt encrypt-file -p mySecret -i .env.plain -o .env.encrypted
//! rustcrypt decrypt-file -p mySecret -i .env.encrypted -o -
//! ```
//!
//! The password can also come from the `RUSTCRYPT_PASSWORD` environment
//! variable.
//!
//! ## Feature flags
//!
//! | Feature | Default | Adds |
//! |---|---|---|
//! | `config` | yes | [`ConfigLoader`] (`serde`, `serde_json`) |
//! | `cli` | yes | the `rustcrypt` binary (`clap`); implies `config` |
//!
//! With `default-features = false` only the encryptors and helpers remain,
//! backed purely by RustCrypto crates (no OpenSSL, no C code).
//!
//! ## Wire formats
//!
//! Every payload is standard, padded base64 and is wrapped as `ENC(base64)`
//! by the `*_with_prefix` methods. All three formats are byte-identical to
//! GoCrypt (the reference implementation) and are verified against vectors
//! generated by it in this crate's test suite.
//!
//! * [`Encryptor`]: `salt(16) ‖ nonce(12) ‖ ciphertext ‖ tag(16)`
//! * [`JasyptEncryptor`]: `salt(8) ‖ DES-CBC ciphertext` (PKCS5 padding)
//! * [`JasyptStrongEncryptor`]: `salt(16) ‖ AES-256-CBC ciphertext` (PKCS7 padding)
//!
//! ## Known issues
//!
//! * [`JasyptStrongEncryptor`] uses the family's layout, which is **not**
//!   byte-identical to Java Jasypt's real `PBEWithHmacSHA256AndAES_256`
//!   (Java prepends a random IV). It is fully interoperable with GoCrypt,
//!   PyCrypt, NodeCrypt and PHPCrypt.
//! * [`JasyptEncryptor`] relies on DES and MD5, which are weak by modern
//!   standards, and has no integrity check: a wrong password can occasionally
//!   yield garbage instead of an error. Use it for Java compatibility only.

#![deny(unsafe_code)]
#![warn(missing_docs)]
#![deny(rustdoc::broken_intra_doc_links)]

#[cfg(feature = "config")]
mod config_loader;
mod encryptor;
pub mod error;
#[cfg(test)]
mod golden;
mod jasypt;
mod kdf;
mod prefix;

#[cfg(feature = "config")]
pub use config_loader::ConfigLoader;
pub use encryptor::{Encryptor, DEFAULT_ITERATIONS, DEFAULT_KEY_SIZE, DEFAULT_SALT_SIZE};
pub use error::{Error, Result};
pub use jasypt::{
    JasyptEncryptor, JasyptStrongEncryptor, JASYPT_DEFAULT_ITERATIONS, JASYPT_SALT_SIZE,
    JASYPT_STRONG_DEFAULT_ITERATIONS, JASYPT_STRONG_DEFAULT_SALT_SIZE,
};
pub use prefix::{is_encrypted, StringEncryptor, ENC_PREFIX, ENC_SUFFIX};

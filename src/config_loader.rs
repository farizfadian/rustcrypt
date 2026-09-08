//! [`ConfigLoader`]: load `.env`, flat YAML and JSON configuration files with
//! automatic `ENC(...)` decryption (feature `config`).

use std::collections::HashMap;
use std::fs;
use std::io::{BufRead, BufReader};
use std::path::Path;

use serde::de::DeserializeOwned;
use serde_json::Value;

use crate::prefix::is_encrypted;
use crate::{Encryptor, Error, Result, StringEncryptor};

/// Loads configuration files and transparently decrypts every `ENC(...)`
/// value with the configured encryptor.
///
/// The loader is generic over the encryptor. [`ConfigLoader::new`] uses
/// [`Encryptor`] (AES-256-GCM) like GoCrypt's `NewConfigLoader`; use
/// [`ConfigLoader::with_encryptor`] to read files shared with Java Jasypt:
///
/// ```
/// use rustcrypt_jasypt::{ConfigLoader, JasyptEncryptor};
///
/// # fn main() -> rustcrypt_jasypt::Result<()> {
/// // AES-256-GCM (family-internal format)
/// let loader = ConfigLoader::new("password")?;
///
/// // PBEWithMD5AndDES, readable by Java Jasypt (e.g. a JasperReport service)
/// let loader = ConfigLoader::with_encryptor(JasyptEncryptor::new("password")?);
/// # let _ = loader;
/// # Ok(())
/// # }
/// ```
///
/// # File formats
///
/// * [`load_env_file`](Self::load_env_file): `KEY=VALUE` lines. Blank lines
///   and lines starting with `#` are skipped, keys and values are trimmed and
///   surrounding single or double quotes are removed from the value.
/// * [`load_yaml`](Self::load_yaml): the same line-based parser splitting on
///   the first `:`. This intentionally mirrors GoCrypt's simplified loader: it
///   flattens nesting (a `database:` line yields an empty `database` entry and
///   `  password: ENC(...)` yields `password`). Use a real YAML crate plus
///   [`decrypt_map`](StringEncryptor::decrypt_map) for complex documents.
/// * [`load_json`](Self::load_json): full JSON via serde. Every string inside
///   objects and arrays, at any depth, that looks like `ENC(...)` is decrypted;
///   strings that fail to decrypt are kept as-is.
#[derive(Debug, Clone)]
pub struct ConfigLoader<E: StringEncryptor = Encryptor> {
    encryptor: E,
}

impl ConfigLoader<Encryptor> {
    /// Creates a loader backed by an [`Encryptor`] (AES-256-GCM) with default
    /// parameters. Returns [`Error::EmptyPassword`] for an empty password.
    pub fn new(password: &str) -> Result<Self> {
        Ok(Self {
            encryptor: Encryptor::new(password)?,
        })
    }
}

impl<E: StringEncryptor> ConfigLoader<E> {
    /// Creates a loader backed by any [`StringEncryptor`], for example a
    /// [`JasyptEncryptor`](crate::JasyptEncryptor) or an [`Encryptor`] with
    /// custom iterations.
    pub fn with_encryptor(encryptor: E) -> Self {
        Self { encryptor }
    }

    /// The underlying encryptor.
    pub fn encryptor(&self) -> &E {
        &self.encryptor
    }

    /// Loads a `.env`-style file and returns its key/value pairs with every
    /// `ENC(...)` value decrypted.
    ///
    /// A value that fails to decrypt aborts with [`Error::KeyDecrypt`] naming
    /// the key. I/O problems are reported as [`Error::Io`].
    ///
    /// ```no_run
    /// use rustcrypt_jasypt::ConfigLoader;
    ///
    /// # fn main() -> rustcrypt_jasypt::Result<()> {
    /// let loader = ConfigLoader::new(&std::env::var("RUSTCRYPT_PASSWORD").unwrap())?;
    /// let config = loader.load_env_file(".env")?;
    /// println!("{}", config["DATABASE_PASSWORD"]);
    /// # Ok(())
    /// # }
    /// ```
    pub fn load_env_file(&self, path: impl AsRef<Path>) -> Result<HashMap<String, String>> {
        self.load_key_values(path.as_ref(), '=')
    }

    /// Loads a simple flat YAML file (`key: value` lines) and returns its
    /// pairs with every `ENC(...)` value decrypted. See the type-level docs
    /// for the (GoCrypt-compatible) limitations of this parser.
    pub fn load_yaml(&self, path: impl AsRef<Path>) -> Result<HashMap<String, String>> {
        self.load_key_values(path.as_ref(), ':')
    }

    fn load_key_values(&self, path: &Path, separator: char) -> Result<HashMap<String, String>> {
        let file = fs::File::open(path)?;
        let mut config = HashMap::new();

        for line in BufReader::new(file).lines() {
            let line = line?;
            let line = line.trim();
            if line.is_empty() || line.starts_with('#') {
                continue;
            }
            let Some((key, value)) = line.split_once(separator) else {
                continue;
            };
            let key = key.trim();
            let value = value.trim().trim_matches(|c| c == '"' || c == '\'');

            let value = if is_encrypted(value) {
                self.encryptor
                    .decrypt_prefixed(value)
                    .map_err(|err| Error::key_decrypt(key, err))?
            } else {
                value.to_owned()
            };
            config.insert(key.to_owned(), value);
        }

        Ok(config)
    }

    /// Loads a JSON file into `T`, decrypting every `ENC(...)` string at any
    /// depth first. Strings that fail to decrypt are left unchanged so the
    /// caller can surface them.
    ///
    /// ```no_run
    /// use rustcrypt_jasypt::ConfigLoader;
    /// use serde::Deserialize;
    ///
    /// #[derive(Deserialize)]
    /// struct Database { host: String, password: String }
    ///
    /// #[derive(Deserialize)]
    /// struct Config { database: Database }
    ///
    /// # fn main() -> rustcrypt_jasypt::Result<()> {
    /// let loader = ConfigLoader::new("password")?;
    /// let config: Config = loader.load_json("config.json")?;
    /// println!("{}", config.database.password);
    /// # Ok(())
    /// # }
    /// ```
    pub fn load_json<T: DeserializeOwned>(&self, path: impl AsRef<Path>) -> Result<T> {
        let data = fs::read_to_string(path)?;
        let mut value: Value = serde_json::from_str(&data)?;
        self.decrypt_json_value(&mut value);
        Ok(serde_json::from_value(value)?)
    }

    /// Recursively decrypts every `ENC(...)` string inside `value` (objects,
    /// arrays and nested combinations). Strings that fail to decrypt are left
    /// unchanged; non-string values are untouched.
    pub fn decrypt_json_value(&self, value: &mut Value) {
        match value {
            Value::String(s) => {
                if is_encrypted(s) {
                    if let Ok(decrypted) = self.encryptor.decrypt_prefixed(s) {
                        *s = decrypted;
                    }
                }
            }
            Value::Array(items) => items.iter_mut().for_each(|v| self.decrypt_json_value(v)),
            Value::Object(map) => map.values_mut().for_each(|v| self.decrypt_json_value(v)),
            Value::Null | Value::Bool(_) | Value::Number(_) => {}
        }
    }

    /// Loads a `.env`-style file with [`load_env_file`](Self::load_env_file)
    /// and exports every pair as a process environment variable.
    ///
    /// Call this during single-threaded start-up: the standard library's
    /// `set_var` is not safe to run while other threads read the environment.
    /// Returns [`Error::InvalidParameter`] for a key that cannot be an
    /// environment variable name (empty, or containing `=` / NUL).
    pub fn set_to_env(&self, path: impl AsRef<Path>) -> Result<()> {
        let config = self.load_env_file(path)?;
        for (key, value) in config {
            set_env_var(&key, &value)?;
        }
        Ok(())
    }
}

/// Sets a process environment variable after validating the name.
///
/// `std::env::set_var` is safe to call in edition 2021 but is `unsafe` from
/// edition 2024 onwards (mutating the environment can race with concurrent
/// reads on some platforms). The `unsafe` block documents that contract now so
/// the crate is ready for the edition bump.
#[allow(unsafe_code, unused_unsafe)]
fn set_env_var(key: &str, value: &str) -> Result<()> {
    if key.is_empty() || key.contains('=') || key.contains('\0') || value.contains('\0') {
        return Err(Error::InvalidParameter(format!(
            "cannot set environment variable {key:?}"
        )));
    }
    // SAFETY: `set_to_env` is documented to be called during single-threaded
    // start-up before other threads read the environment (the same contract
    // as GoCrypt's SetToEnv / os.Setenv). The key was validated above so the
    // call cannot panic.
    unsafe { std::env::set_var(key, value) };
    Ok(())
}

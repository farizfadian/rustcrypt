//! [`Encryptor`]: AES-GCM with PBKDF2-HMAC-SHA256 (the family's own format).

use std::fmt;

use aes_gcm::aead::consts::U12;
use aes_gcm::aead::{Aead, KeyInit};
use aes_gcm::aes::{Aes128, Aes192, Aes256};
use aes_gcm::{AesGcm, Nonce};
use base64::engine::general_purpose::STANDARD as BASE64;
use base64::Engine;
use rand_core::{OsRng, RngCore};

use crate::kdf;
use crate::prefix::impl_string_encryptor;
use crate::{Error, Result};

/// Default PBKDF2 iteration count for [`Encryptor`].
pub const DEFAULT_ITERATIONS: u32 = 10_000;

/// Default salt size in bytes for [`Encryptor`].
pub const DEFAULT_SALT_SIZE: usize = 16;

/// Default AES key size in bytes for [`Encryptor`] (32 = AES-256).
pub const DEFAULT_KEY_SIZE: usize = 32;

/// GCM nonce size in bytes (fixed, matches Go's `cipher.NewGCM`).
pub(crate) const GCM_NONCE_SIZE: usize = 12;

/// AES-GCM cipher selected by key size.
enum Gcm {
    Aes128(AesGcm<Aes128, U12>),
    Aes192(AesGcm<Aes192, U12>),
    Aes256(AesGcm<Aes256, U12>),
}

impl Gcm {
    fn new(key: &[u8]) -> Result<Self> {
        let invalid = || Error::InvalidParameter("key size must be 16, 24 or 32".to_owned());
        match key.len() {
            16 => AesGcm::new_from_slice(key).map(Gcm::Aes128),
            24 => AesGcm::new_from_slice(key).map(Gcm::Aes192),
            32 => AesGcm::new_from_slice(key).map(Gcm::Aes256),
            _ => return Err(invalid()),
        }
        .map_err(|_| invalid())
    }

    fn encrypt(&self, nonce: &Nonce<U12>, plaintext: &[u8]) -> aes_gcm::aead::Result<Vec<u8>> {
        match self {
            Gcm::Aes128(c) => c.encrypt(nonce, plaintext),
            Gcm::Aes192(c) => c.encrypt(nonce, plaintext),
            Gcm::Aes256(c) => c.encrypt(nonce, plaintext),
        }
    }

    fn decrypt(&self, nonce: &Nonce<U12>, ciphertext: &[u8]) -> aes_gcm::aead::Result<Vec<u8>> {
        match self {
            Gcm::Aes128(c) => c.decrypt(nonce, ciphertext),
            Gcm::Aes192(c) => c.decrypt(nonce, ciphertext),
            Gcm::Aes256(c) => c.decrypt(nonce, ciphertext),
        }
    }
}

/// AES-256-GCM encryptor with PBKDF2-HMAC-SHA256 key derivation.
///
/// This is the recommended encryptor for values that only need to be read by
/// members of the GoCrypt/PyCrypt/NodeCrypt/PHPCrypt/RustCrypt family. It
/// provides authenticated encryption, so a wrong password or tampered
/// ciphertext is always detected. **It is not readable by Java Jasypt**; use
/// [`JasyptEncryptor`](crate::JasyptEncryptor) for that.
///
/// # Wire format
///
/// `base64( salt ‖ nonce ‖ ciphertext ‖ tag )` with a random `salt`
/// (16 bytes by default), a random 12-byte GCM `nonce`, and the 16-byte GCM
/// tag appended to the ciphertext. No associated data is used.
///
/// # Example
///
/// ```
/// use rustcrypt_jasypt::Encryptor;
///
/// # fn main() -> rustcrypt_jasypt::Result<()> {
/// let enc = Encryptor::new("my-password")?;
/// let wrapped = enc.encrypt_with_prefix("db_password_123")?;
/// assert!(wrapped.starts_with("ENC("));
/// assert_eq!(enc.decrypt_prefixed(&wrapped)?, "db_password_123");
/// # Ok(())
/// # }
/// ```
///
/// Parameters can be tuned with the builder methods:
///
/// ```
/// use rustcrypt_jasypt::Encryptor;
///
/// # fn main() -> rustcrypt_jasypt::Result<()> {
/// let enc = Encryptor::new("my-password")?
///     .with_iterations(50_000)
///     .with_salt_size(32)
///     .with_key_size(32)?;
/// # let _ = enc;
/// # Ok(())
/// # }
/// ```
#[derive(Clone)]
pub struct Encryptor {
    password: Vec<u8>,
    iterations: u32,
    salt_size: usize,
    key_size: usize,
}

impl Encryptor {
    /// Creates an encryptor with the default parameters
    /// ([`DEFAULT_ITERATIONS`], [`DEFAULT_SALT_SIZE`], [`DEFAULT_KEY_SIZE`]).
    ///
    /// Returns [`Error::EmptyPassword`] when `password` is empty.
    pub fn new(password: &str) -> Result<Self> {
        if password.is_empty() {
            return Err(Error::EmptyPassword);
        }
        Ok(Self {
            password: password.as_bytes().to_vec(),
            iterations: DEFAULT_ITERATIONS,
            salt_size: DEFAULT_SALT_SIZE,
            key_size: DEFAULT_KEY_SIZE,
        })
    }

    /// Sets the PBKDF2 iteration count (default `10000`). Higher is slower
    /// but stronger. Both sides must use the same value.
    #[must_use]
    pub fn with_iterations(mut self, iterations: u32) -> Self {
        self.iterations = iterations;
        self
    }

    /// Sets the salt size in bytes (default `16`). Both sides must use the
    /// same value because the salt length is not encoded in the output.
    #[must_use]
    pub fn with_salt_size(mut self, salt_size: usize) -> Self {
        self.salt_size = salt_size;
        self
    }

    /// Sets the AES key size in bytes: `16` (AES-128), `24` (AES-192) or
    /// `32` (AES-256, default).
    ///
    /// Returns [`Error::InvalidParameter`] for any other value.
    pub fn with_key_size(mut self, key_size: usize) -> Result<Self> {
        match key_size {
            16 | 24 | 32 => {
                self.key_size = key_size;
                Ok(self)
            }
            _ => Err(Error::InvalidParameter(
                "key size must be 16, 24 or 32".to_owned(),
            )),
        }
    }

    /// The configured PBKDF2 iteration count.
    pub fn iterations(&self) -> u32 {
        self.iterations
    }

    /// The configured salt size in bytes.
    pub fn salt_size(&self) -> usize {
        self.salt_size
    }

    /// The configured AES key size in bytes.
    pub fn key_size(&self) -> usize {
        self.key_size
    }

    /// Encrypts `plaintext` and returns the base64 payload (without the
    /// `ENC(...)` wrapper). A fresh random salt and nonce are used every time.
    ///
    /// Returns [`Error::EmptyValue`] when `plaintext` is empty.
    pub fn encrypt(&self, plaintext: &str) -> Result<String> {
        if plaintext.is_empty() {
            return Err(Error::EmptyValue);
        }
        let mut salt = vec![0u8; self.salt_size];
        OsRng.fill_bytes(&mut salt);
        let mut nonce = [0u8; GCM_NONCE_SIZE];
        OsRng.fill_bytes(&mut nonce);
        self.encrypt_with_salt_nonce(&salt, &nonce, plaintext)
    }

    /// Deterministic core of [`encrypt`](Self::encrypt) used by tests to
    /// compare against vectors produced by GoCrypt.
    pub(crate) fn encrypt_with_salt_nonce(
        &self,
        salt: &[u8],
        nonce: &[u8],
        plaintext: &str,
    ) -> Result<String> {
        if plaintext.is_empty() {
            return Err(Error::EmptyValue);
        }
        if nonce.len() != GCM_NONCE_SIZE {
            return Err(Error::InvalidParameter(format!(
                "nonce must be {GCM_NONCE_SIZE} bytes"
            )));
        }
        let key = kdf::pbkdf2_sha256(&self.password, salt, self.iterations, self.key_size);
        let ciphertext = Gcm::new(&key)?
            .encrypt(Nonce::<U12>::from_slice(nonce), plaintext.as_bytes())
            .map_err(|_| Error::InvalidParameter("AES-GCM encryption failed".to_owned()))?;

        let mut combined = Vec::with_capacity(salt.len() + nonce.len() + ciphertext.len());
        combined.extend_from_slice(salt);
        combined.extend_from_slice(nonce);
        combined.extend_from_slice(&ciphertext);
        Ok(BASE64.encode(combined))
    }

    /// Decrypts a base64 payload produced by [`encrypt`](Self::encrypt) (or by
    /// any family member's default encryptor with the same parameters).
    ///
    /// Returns [`Error::EmptyValue`] for empty input, [`Error::Base64`] for
    /// malformed base64 and [`Error::DecryptionFailed`] for a wrong password,
    /// tampered data or a payload that is too short.
    pub fn decrypt(&self, encoded: &str) -> Result<String> {
        if encoded.is_empty() {
            return Err(Error::EmptyValue);
        }
        let combined = BASE64.decode(encoded)?;
        if combined.len() < self.salt_size + GCM_NONCE_SIZE {
            return Err(Error::DecryptionFailed);
        }
        let (salt, rest) = combined.split_at(self.salt_size);
        let (nonce, ciphertext) = rest.split_at(GCM_NONCE_SIZE);

        let key = kdf::pbkdf2_sha256(&self.password, salt, self.iterations, self.key_size);
        let plaintext = Gcm::new(&key)?
            .decrypt(Nonce::<U12>::from_slice(nonce), ciphertext)
            .map_err(|_| Error::DecryptionFailed)?;
        String::from_utf8(plaintext).map_err(|_| Error::DecryptionFailed)
    }
}

impl_string_encryptor!(Encryptor);

impl fmt::Debug for Encryptor {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Encryptor")
            .field("password", &"<redacted>")
            .field("iterations", &self.iterations)
            .field("salt_size", &self.salt_size)
            .field("key_size", &self.key_size)
            .finish()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn debug_does_not_leak_password() {
        let enc = Encryptor::new("super-secret").unwrap();
        let dbg = format!("{enc:?}");
        assert!(dbg.contains("<redacted>"));
        assert!(!dbg.contains("super-secret"));
    }

    #[test]
    fn fixed_salt_nonce_is_deterministic() {
        let enc = Encryptor::new("rustcrypt-test-2026").unwrap();
        let salt = [1u8; 16];
        let nonce = [2u8; 12];
        let a = enc.encrypt_with_salt_nonce(&salt, &nonce, "hello").unwrap();
        let b = enc.encrypt_with_salt_nonce(&salt, &nonce, "hello").unwrap();
        assert_eq!(a, b);
        assert_eq!(enc.decrypt(&a).unwrap(), "hello");
        // Layout: salt(16) ‖ nonce(12) ‖ ct(5) ‖ tag(16) = 49 bytes.
        assert_eq!(BASE64.decode(&a).unwrap().len(), 16 + 12 + 5 + 16);
    }

    #[test]
    fn wrong_nonce_length_is_rejected() {
        let enc = Encryptor::new("pw").unwrap();
        assert!(matches!(
            enc.encrypt_with_salt_nonce(&[0u8; 16], &[0u8; 11], "x"),
            Err(Error::InvalidParameter(_))
        ));
    }
}

//! Java Jasypt compatible encryptors: [`JasyptEncryptor`] (`PBEWithMD5AndDES`)
//! and [`JasyptStrongEncryptor`] (the family's `PBEWithHmacSHA256AndAES_256`
//! format).

use std::fmt;

use aes::Aes256;
use base64::engine::general_purpose::STANDARD as BASE64;
use base64::Engine;
use cipher::block_padding::Pkcs7;
use cipher::{BlockDecryptMut, BlockEncryptMut, KeyIvInit};
use des::Des;
use rand_core::{OsRng, RngCore};

use crate::kdf;
use crate::prefix::impl_string_encryptor;
use crate::{Error, Result};

/// Default iteration count for [`JasyptEncryptor`] (Jasypt's default).
pub const JASYPT_DEFAULT_ITERATIONS: u32 = 1_000;

/// Salt size in bytes used by [`JasyptEncryptor`] (fixed at 8 for DES).
pub const JASYPT_SALT_SIZE: usize = 8;

/// Default iteration count for [`JasyptStrongEncryptor`].
pub const JASYPT_STRONG_DEFAULT_ITERATIONS: u32 = 1_000;

/// Default salt size in bytes for [`JasyptStrongEncryptor`].
pub const JASYPT_STRONG_DEFAULT_SALT_SIZE: usize = 16;

const DES_BLOCK_SIZE: usize = 8;
const AES_BLOCK_SIZE: usize = 16;

type DesCbcEnc = cbc::Encryptor<Des>;
type DesCbcDec = cbc::Decryptor<Des>;
type Aes256CbcEnc = cbc::Encryptor<Aes256>;
type Aes256CbcDec = cbc::Decryptor<Aes256>;

fn invalid_key_iv() -> Error {
    Error::InvalidParameter("invalid key or IV length".to_owned())
}

// ═══════════════════════════════════════════════════════════════════════════
// JasyptEncryptor — PBEWithMD5AndDES
// ═══════════════════════════════════════════════════════════════════════════

/// Encryptor compatible with Java Jasypt's default algorithm,
/// `PBEWithMD5AndDES`.
///
/// Use this when values must be shared with Java Jasypt (for example a
/// JasperReport service) or with any other family member in Jasypt mode.
///
/// # Wire format
///
/// `base64( salt ‖ ciphertext )` with a random 8-byte `salt`. The DES key and
/// IV are the first and second 8 bytes of PBKDF1-MD5
/// (`md5(password ‖ salt)` iterated `iterations` times, default 1000).
/// The ciphertext is DES-CBC with PKCS5 padding.
///
/// # Security
///
/// DES is a legacy 56-bit cipher and MD5 is a weak hash: this mode is provided
/// **for compatibility only**. It also has no integrity check, so decrypting
/// with a wrong password can either fail with
/// [`Error::DecryptionFailed`] or, occasionally, succeed and return garbage.
///
/// # Example
///
/// ```
/// use rustcrypt_jasypt::JasyptEncryptor;
///
/// # fn main() -> rustcrypt_jasypt::Result<()> {
/// let enc = JasyptEncryptor::new("my-password")?;
/// let wrapped = enc.encrypt_with_prefix("secret")?;
/// assert_eq!(enc.decrypt_prefixed(&wrapped)?, "secret");
/// # Ok(())
/// # }
/// ```
#[derive(Clone)]
pub struct JasyptEncryptor {
    password: Vec<u8>,
    iterations: u32,
}

impl JasyptEncryptor {
    /// Creates a `PBEWithMD5AndDES` encryptor with Jasypt's default 1000
    /// iterations.
    ///
    /// Returns [`Error::EmptyPassword`] when `password` is empty.
    pub fn new(password: &str) -> Result<Self> {
        if password.is_empty() {
            return Err(Error::EmptyPassword);
        }
        Ok(Self {
            password: password.as_bytes().to_vec(),
            iterations: JASYPT_DEFAULT_ITERATIONS,
        })
    }

    /// Sets the key-derivation iteration count (default `1000`). Must match
    /// the `keyObtentionIterations` used on the Java side.
    #[must_use]
    pub fn with_iterations(mut self, iterations: u32) -> Self {
        self.iterations = iterations;
        self
    }

    /// The configured iteration count.
    pub fn iterations(&self) -> u32 {
        self.iterations
    }

    /// Encrypts `plaintext` and returns the base64 payload (without the
    /// `ENC(...)` wrapper). A fresh random salt is used every time.
    ///
    /// Returns [`Error::EmptyValue`] when `plaintext` is empty.
    pub fn encrypt(&self, plaintext: &str) -> Result<String> {
        if plaintext.is_empty() {
            return Err(Error::EmptyValue);
        }
        let mut salt = [0u8; JASYPT_SALT_SIZE];
        OsRng.fill_bytes(&mut salt);
        self.encrypt_with_salt(&salt, plaintext)
    }

    /// Deterministic core of [`encrypt`](Self::encrypt) used by tests.
    pub(crate) fn encrypt_with_salt(
        &self,
        salt: &[u8; JASYPT_SALT_SIZE],
        plaintext: &str,
    ) -> Result<String> {
        if plaintext.is_empty() {
            return Err(Error::EmptyValue);
        }
        let derived = kdf::pbkdf1_md5(&self.password, salt, self.iterations);
        let (key, iv) = derived.split_at(8);
        let ciphertext = DesCbcEnc::new_from_slices(key, iv)
            .map_err(|_| invalid_key_iv())?
            .encrypt_padded_vec_mut::<Pkcs7>(plaintext.as_bytes());

        let mut combined = Vec::with_capacity(salt.len() + ciphertext.len());
        combined.extend_from_slice(salt);
        combined.extend_from_slice(&ciphertext);
        Ok(BASE64.encode(combined))
    }

    /// Decrypts a base64 payload produced by Java Jasypt (`PBEWithMD5AndDES`)
    /// or by any family member's Jasypt encryptor.
    ///
    /// Returns [`Error::EmptyValue`] for empty input, [`Error::Base64`] for
    /// malformed base64, [`Error::InvalidJasyptData`] when the payload is
    /// shorter than 16 bytes or not a multiple of the DES block size, and
    /// [`Error::DecryptionFailed`] when the padding check fails.
    pub fn decrypt(&self, encoded: &str) -> Result<String> {
        if encoded.is_empty() {
            return Err(Error::EmptyValue);
        }
        let combined = BASE64.decode(encoded)?;
        // Minimum: 8 (salt) + 8 (one DES block).
        if combined.len() < JASYPT_SALT_SIZE + DES_BLOCK_SIZE {
            return Err(Error::InvalidJasyptData);
        }
        let (salt, ciphertext) = combined.split_at(JASYPT_SALT_SIZE);
        if ciphertext.len() % DES_BLOCK_SIZE != 0 {
            return Err(Error::InvalidJasyptData);
        }

        let derived = kdf::pbkdf1_md5(&self.password, salt, self.iterations);
        let (key, iv) = derived.split_at(8);
        let plaintext = DesCbcDec::new_from_slices(key, iv)
            .map_err(|_| invalid_key_iv())?
            .decrypt_padded_vec_mut::<Pkcs7>(ciphertext)
            .map_err(|_| Error::DecryptionFailed)?;
        String::from_utf8(plaintext).map_err(|_| Error::DecryptionFailed)
    }
}

impl_string_encryptor!(JasyptEncryptor);

impl fmt::Debug for JasyptEncryptor {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("JasyptEncryptor")
            .field("password", &"<redacted>")
            .field("iterations", &self.iterations)
            .finish()
    }
}

// ═══════════════════════════════════════════════════════════════════════════
// JasyptStrongEncryptor — PBEWithHmacSHA256AndAES_256 (family format)
// ═══════════════════════════════════════════════════════════════════════════

/// Stronger Jasypt-style encryptor: PBKDF2-HMAC-SHA256 + AES-256-CBC.
///
/// # Wire format
///
/// `base64( salt ‖ ciphertext )` with a random `salt` (16 bytes by default).
/// PBKDF2-HMAC-SHA256 (`iterations`, default 1000) derives 48 bytes: the first
/// 32 are the AES-256 key and the remaining 16 the CBC IV. The ciphertext is
/// AES-256-CBC with PKCS7 padding.
///
/// # Compatibility note
///
/// This is the format shared by GoCrypt, PyCrypt, NodeCrypt, PHPCrypt and
/// RustCrypt, and it is fully interoperable between them. It is **not**
/// byte-identical to Java Jasypt's real `PBEWithHmacSHA256AndAES_256`, which
/// prepends a random IV (`salt ‖ iv ‖ ciphertext`). Do not change this format
/// here; any move to the true Jasypt layout will be a coordinated release of
/// all five libraries.
///
/// Like every CBC mode without a MAC it has no integrity check: a wrong
/// password usually fails the padding check but can occasionally yield
/// garbage.
///
/// # Example
///
/// ```
/// use rustcrypt_jasypt::JasyptStrongEncryptor;
///
/// # fn main() -> rustcrypt_jasypt::Result<()> {
/// let enc = JasyptStrongEncryptor::new("my-password")?.with_iterations(5_000);
/// let wrapped = enc.encrypt_with_prefix("secret")?;
/// assert_eq!(enc.decrypt_prefixed(&wrapped)?, "secret");
/// # Ok(())
/// # }
/// ```
#[derive(Clone)]
pub struct JasyptStrongEncryptor {
    password: Vec<u8>,
    iterations: u32,
    salt_size: usize,
}

impl JasyptStrongEncryptor {
    /// Creates a strong encryptor with the defaults
    /// ([`JASYPT_STRONG_DEFAULT_ITERATIONS`], [`JASYPT_STRONG_DEFAULT_SALT_SIZE`]).
    ///
    /// Returns [`Error::EmptyPassword`] when `password` is empty.
    pub fn new(password: &str) -> Result<Self> {
        if password.is_empty() {
            return Err(Error::EmptyPassword);
        }
        Ok(Self {
            password: password.as_bytes().to_vec(),
            iterations: JASYPT_STRONG_DEFAULT_ITERATIONS,
            salt_size: JASYPT_STRONG_DEFAULT_SALT_SIZE,
        })
    }

    /// Sets the PBKDF2 iteration count (default `1000`).
    #[must_use]
    pub fn with_iterations(mut self, iterations: u32) -> Self {
        self.iterations = iterations;
        self
    }

    /// Sets the salt size in bytes (default `16`). Both sides must agree.
    #[must_use]
    pub fn with_salt_size(mut self, salt_size: usize) -> Self {
        self.salt_size = salt_size;
        self
    }

    /// The configured PBKDF2 iteration count.
    pub fn iterations(&self) -> u32 {
        self.iterations
    }

    /// The configured salt size in bytes.
    pub fn salt_size(&self) -> usize {
        self.salt_size
    }

    /// Encrypts `plaintext` and returns the base64 payload (without the
    /// `ENC(...)` wrapper). A fresh random salt is used every time.
    ///
    /// Returns [`Error::EmptyValue`] when `plaintext` is empty.
    pub fn encrypt(&self, plaintext: &str) -> Result<String> {
        if plaintext.is_empty() {
            return Err(Error::EmptyValue);
        }
        let mut salt = vec![0u8; self.salt_size];
        OsRng.fill_bytes(&mut salt);
        self.encrypt_with_salt(&salt, plaintext)
    }

    /// Deterministic core of [`encrypt`](Self::encrypt) used by tests.
    pub(crate) fn encrypt_with_salt(&self, salt: &[u8], plaintext: &str) -> Result<String> {
        if plaintext.is_empty() {
            return Err(Error::EmptyValue);
        }
        let derived = kdf::pbkdf2_sha256(&self.password, salt, self.iterations, 48);
        let (key, iv) = derived.split_at(32);
        let ciphertext = Aes256CbcEnc::new_from_slices(key, iv)
            .map_err(|_| invalid_key_iv())?
            .encrypt_padded_vec_mut::<Pkcs7>(plaintext.as_bytes());

        let mut combined = Vec::with_capacity(salt.len() + ciphertext.len());
        combined.extend_from_slice(salt);
        combined.extend_from_slice(&ciphertext);
        Ok(BASE64.encode(combined))
    }

    /// Decrypts a base64 payload produced by any family member's strong
    /// encryptor with the same parameters.
    ///
    /// Returns [`Error::EmptyValue`] for empty input, [`Error::Base64`] for
    /// malformed base64, [`Error::InvalidJasyptData`] when the payload is
    /// shorter than `salt_size + 16` bytes or not a multiple of the AES block
    /// size, and [`Error::DecryptionFailed`] when the padding check fails.
    pub fn decrypt(&self, encoded: &str) -> Result<String> {
        if encoded.is_empty() {
            return Err(Error::EmptyValue);
        }
        let combined = BASE64.decode(encoded)?;
        if combined.len() < self.salt_size + AES_BLOCK_SIZE {
            return Err(Error::InvalidJasyptData);
        }
        let (salt, ciphertext) = combined.split_at(self.salt_size);
        if ciphertext.len() % AES_BLOCK_SIZE != 0 {
            return Err(Error::InvalidJasyptData);
        }

        let derived = kdf::pbkdf2_sha256(&self.password, salt, self.iterations, 48);
        let (key, iv) = derived.split_at(32);
        let plaintext = Aes256CbcDec::new_from_slices(key, iv)
            .map_err(|_| invalid_key_iv())?
            .decrypt_padded_vec_mut::<Pkcs7>(ciphertext)
            .map_err(|_| Error::DecryptionFailed)?;
        String::from_utf8(plaintext).map_err(|_| Error::DecryptionFailed)
    }
}

impl_string_encryptor!(JasyptStrongEncryptor);

impl fmt::Debug for JasyptStrongEncryptor {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("JasyptStrongEncryptor")
            .field("password", &"<redacted>")
            .field("iterations", &self.iterations)
            .field("salt_size", &self.salt_size)
            .finish()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn des_fixed_salt_is_deterministic_and_block_aligned() {
        let enc = JasyptEncryptor::new("rustcrypt-test-2026").unwrap();
        let salt = [1u8, 2, 3, 4, 5, 6, 7, 8];
        let a = enc.encrypt_with_salt(&salt, "hello").unwrap();
        let b = enc.encrypt_with_salt(&salt, "hello").unwrap();
        assert_eq!(a, b);
        assert_eq!(enc.decrypt(&a).unwrap(), "hello");
        // salt(8) + one padded DES block(8)
        assert_eq!(BASE64.decode(&a).unwrap().len(), 16);
        // exactly one block of input needs a full padding block
        let full = enc.encrypt_with_salt(&salt, "12345678").unwrap();
        assert_eq!(BASE64.decode(&full).unwrap().len(), 8 + 16);
    }

    #[test]
    fn strong_fixed_salt_is_deterministic_and_block_aligned() {
        let enc = JasyptStrongEncryptor::new("rustcrypt-test-2026").unwrap();
        let salt = [7u8; 16];
        let a = enc.encrypt_with_salt(&salt, "hello").unwrap();
        let b = enc.encrypt_with_salt(&salt, "hello").unwrap();
        assert_eq!(a, b);
        assert_eq!(enc.decrypt(&a).unwrap(), "hello");
        assert_eq!(BASE64.decode(&a).unwrap().len(), 16 + 16);
        let full = enc.encrypt_with_salt(&salt, "0123456789abcdef").unwrap();
        assert_eq!(BASE64.decode(&full).unwrap().len(), 16 + 32);
    }

    #[test]
    fn debug_does_not_leak_password() {
        let a = format!("{:?}", JasyptEncryptor::new("hunter2").unwrap());
        let b = format!("{:?}", JasyptStrongEncryptor::new("hunter2").unwrap());
        assert!(!a.contains("hunter2") && a.contains("<redacted>"));
        assert!(!b.contains("hunter2") && b.contains("<redacted>"));
    }
}

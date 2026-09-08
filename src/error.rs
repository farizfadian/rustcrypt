//! Error type shared by every encryptor and loader in the crate.

/// Convenience alias used throughout the crate.
pub type Result<T> = std::result::Result<T, Error>;

/// All errors produced by `rustcrypt_jasypt`.
///
/// The enum is `#[non_exhaustive]`: new variants may be added in minor
/// releases, so always keep a wildcard arm when matching on it.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum Error {
    /// The password passed to a constructor was empty.
    #[error("password cannot be empty")]
    EmptyPassword,

    /// The plaintext or ciphertext passed to encrypt/decrypt was empty.
    #[error("value cannot be empty")]
    EmptyValue,

    /// A value was expected to look like `ENC(...)` but did not.
    #[error("invalid encrypted format, expected ENC(...)")]
    InvalidEncFormat,

    /// The decoded Jasypt payload is too short or not block-aligned.
    #[error("invalid jasypt encrypted data")]
    InvalidJasyptData,

    /// Authentication or padding check failed (wrong password or tampered data).
    ///
    /// Details are intentionally not exposed so that callers cannot use this
    /// library as a padding/authentication oracle.
    #[error("decryption failed")]
    DecryptionFailed,

    /// The value was not valid standard (padded) base64.
    #[error("base64 decode error: {0}")]
    Base64(#[from] base64::DecodeError),

    /// I/O error while reading or writing a configuration file.
    #[error("io error: {0}")]
    Io(#[from] std::io::Error),

    /// JSON parse or conversion error (feature `config`).
    #[cfg(feature = "config")]
    #[error("json error: {0}")]
    Json(#[from] serde_json::Error),

    /// A specific key in a map or config file could not be decrypted.
    #[error("failed to decrypt key {key}: {source}")]
    KeyDecrypt {
        /// The key whose value failed to decrypt.
        key: String,
        /// The underlying decryption error.
        #[source]
        source: Box<Error>,
    },

    /// A builder parameter was out of range (for example a key size that is
    /// not 16, 24 or 32 bytes).
    #[error("invalid parameter: {0}")]
    InvalidParameter(String),
}

impl Error {
    /// Wraps `source` as a [`Error::KeyDecrypt`] for `key`.
    pub(crate) fn key_decrypt(key: impl Into<String>, source: Error) -> Self {
        Error::KeyDecrypt {
            key: key.into(),
            source: Box::new(source),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn display_messages_match_gocrypt() {
        assert_eq!(Error::EmptyPassword.to_string(), "password cannot be empty");
        assert_eq!(Error::EmptyValue.to_string(), "value cannot be empty");
        assert_eq!(
            Error::InvalidEncFormat.to_string(),
            "invalid encrypted format, expected ENC(...)"
        );
        assert_eq!(
            Error::InvalidJasyptData.to_string(),
            "invalid jasypt encrypted data"
        );
        assert_eq!(Error::DecryptionFailed.to_string(), "decryption failed");
        assert_eq!(
            Error::InvalidParameter("key size must be 16, 24 or 32".into()).to_string(),
            "invalid parameter: key size must be 16, 24 or 32"
        );
    }

    #[test]
    fn key_decrypt_wraps_source() {
        let err = Error::key_decrypt("DB_PASS", Error::DecryptionFailed);
        assert_eq!(
            err.to_string(),
            "failed to decrypt key DB_PASS: decryption failed"
        );
        let source = std::error::Error::source(&err).expect("source");
        assert_eq!(source.to_string(), "decryption failed");
    }

    #[test]
    fn base64_error_converts() {
        use base64::Engine;
        let err: Error = base64::engine::general_purpose::STANDARD
            .decode("not base64!")
            .unwrap_err()
            .into();
        assert!(matches!(err, Error::Base64(_)));
        assert!(err.to_string().starts_with("base64 decode error: "));
    }
}

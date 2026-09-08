//! `ENC(...)` wrapper helpers and the [`StringEncryptor`] trait shared by
//! every encryptor in the crate.

use std::collections::HashMap;
use std::sync::OnceLock;

use regex::Regex;

use crate::{Error, Result};

/// Prefix of a wrapped encrypted value (`ENC(`).
pub const ENC_PREFIX: &str = "ENC(";

/// Suffix of a wrapped encrypted value (`)`).
pub const ENC_SUFFIX: &str = ")";

/// Returns `true` when `value` (ignoring surrounding whitespace) looks like an
/// `ENC(...)` wrapped value.
///
/// This only checks the wrapper, not whether the payload is valid.
///
/// ```
/// use rustcrypt_jasypt::is_encrypted;
///
/// assert!(is_encrypted("ENC(abc123)"));
/// assert!(is_encrypted("  ENC(abc123)  "));
/// assert!(!is_encrypted("abc123"));
/// ```
pub fn is_encrypted(value: &str) -> bool {
    let v = value.trim();
    v.starts_with(ENC_PREFIX) && v.ends_with(ENC_SUFFIX)
}

/// Wraps an encoded payload as `ENC(payload)`.
pub(crate) fn wrap(encoded: &str) -> String {
    let mut out = String::with_capacity(ENC_PREFIX.len() + encoded.len() + ENC_SUFFIX.len());
    out.push_str(ENC_PREFIX);
    out.push_str(encoded);
    out.push_str(ENC_SUFFIX);
    out
}

/// Validates the `ENC(...)` wrapper (after trimming whitespace) and returns
/// the inner payload, which may be empty.
pub(crate) fn unwrap_enc(value: &str) -> Result<&str> {
    let v = value.trim();
    if !(v.starts_with(ENC_PREFIX) && v.ends_with(ENC_SUFFIX)) {
        return Err(Error::InvalidEncFormat);
    }
    v.get(ENC_PREFIX.len()..v.len() - ENC_SUFFIX.len())
        .ok_or(Error::InvalidEncFormat)
}

/// The compiled `ENC\(([^)]+)\)` pattern used to scan free text.
pub(crate) fn enc_pattern() -> &'static Regex {
    static PATTERN: OnceLock<Regex> = OnceLock::new();
    PATTERN.get_or_init(|| Regex::new(r"ENC\(([^)]+)\)").expect("ENC pattern is a valid regex"))
}

/// Replaces every `ENC(...)` match in `input` with `f(match)`.
///
/// When `f` fails for a match the original text is kept and the error is
/// remembered; the *last* error is returned alongside the fully processed
/// string (GoCrypt `DecryptAllInString` semantics).
pub(crate) fn replace_all_enc<F>(input: &str, mut f: F) -> (String, Option<Error>)
where
    F: FnMut(&str) -> Result<String>,
{
    let mut last_err = None;
    let out = enc_pattern().replace_all(input, |caps: &regex::Captures<'_>| {
        let matched = caps.get(0).map(|m| m.as_str()).unwrap_or_default();
        match f(matched) {
            Ok(replacement) => replacement,
            Err(err) => {
                last_err = Some(err);
                matched.to_owned()
            }
        }
    });
    (out.into_owned(), last_err)
}

/// Decrypts every value of `map` that [`is_encrypted`] using `f`; other values
/// are copied through unchanged. The first failure aborts with
/// [`Error::KeyDecrypt`] carrying the offending key.
pub(crate) fn decrypt_map_with<F>(
    map: &HashMap<String, String>,
    mut f: F,
) -> Result<HashMap<String, String>>
where
    F: FnMut(&str) -> Result<String>,
{
    let mut out = HashMap::with_capacity(map.len());
    for (key, value) in map {
        let decrypted = if is_encrypted(value) {
            f(value).map_err(|err| Error::key_decrypt(key.clone(), err))?
        } else {
            value.clone()
        };
        out.insert(key.clone(), decrypted);
    }
    Ok(out)
}

/// Common interface implemented by [`Encryptor`](crate::Encryptor),
/// [`JasyptEncryptor`](crate::JasyptEncryptor) and
/// [`JasyptStrongEncryptor`](crate::JasyptStrongEncryptor).
///
/// Every concrete encryptor also exposes these methods inherently, so you only
/// need to import the trait when writing code that is generic over the
/// encryptor (for example `fn load<E: StringEncryptor>(enc: &E)`), or when
/// working with `Box<dyn StringEncryptor>`.
pub trait StringEncryptor {
    /// Encrypts `plaintext` and returns the raw base64 payload (no `ENC(...)`).
    fn encrypt(&self, plaintext: &str) -> Result<String>;

    /// Decrypts a raw base64 payload (no `ENC(...)` wrapper).
    fn decrypt(&self, encoded: &str) -> Result<String>;

    /// Encrypts `plaintext` and wraps the result as `ENC(...)`.
    fn encrypt_with_prefix(&self, plaintext: &str) -> Result<String> {
        Ok(wrap(&self.encrypt(plaintext)?))
    }

    /// Decrypts an `ENC(...)`-wrapped value. Surrounding whitespace is ignored.
    ///
    /// Returns [`Error::InvalidEncFormat`] when the wrapper is missing.
    fn decrypt_prefixed(&self, value: &str) -> Result<String> {
        self.decrypt(unwrap_enc(value)?)
    }

    /// Replaces every `ENC(...)` occurrence in `input` with its plaintext.
    ///
    /// Matches that fail to decrypt are left untouched and, after the whole
    /// input has been processed, the last error is returned (GoCrypt
    /// semantics). Use [`decrypt_all_in_string_lossy`](Self::decrypt_all_in_string_lossy)
    /// when you want the best-effort output regardless of failures.
    fn decrypt_all_in_string(&self, input: &str) -> Result<String> {
        let (out, err) = replace_all_enc(input, |m| self.decrypt_prefixed(m));
        match err {
            Some(err) => Err(err),
            None => Ok(out),
        }
    }

    /// Like [`decrypt_all_in_string`](Self::decrypt_all_in_string) but never
    /// fails: matches that cannot be decrypted are kept verbatim
    /// (NodeCrypt/PyCrypt semantics, and what the `rustcrypt decrypt-file`
    /// command uses).
    fn decrypt_all_in_string_lossy(&self, input: &str) -> String {
        replace_all_enc(input, |m| self.decrypt_prefixed(m)).0
    }

    /// Decrypts every `ENC(...)` value in `map`; other values are copied as-is.
    ///
    /// The first failure aborts with [`Error::KeyDecrypt`] naming the key.
    fn decrypt_map(&self, map: &HashMap<String, String>) -> Result<HashMap<String, String>> {
        decrypt_map_with(map, |v| self.decrypt_prefixed(v))
    }
}

impl<T: StringEncryptor + ?Sized> StringEncryptor for &T {
    fn encrypt(&self, plaintext: &str) -> Result<String> {
        (**self).encrypt(plaintext)
    }
    fn decrypt(&self, encoded: &str) -> Result<String> {
        (**self).decrypt(encoded)
    }
    fn encrypt_with_prefix(&self, plaintext: &str) -> Result<String> {
        (**self).encrypt_with_prefix(plaintext)
    }
    fn decrypt_prefixed(&self, value: &str) -> Result<String> {
        (**self).decrypt_prefixed(value)
    }
    fn decrypt_all_in_string(&self, input: &str) -> Result<String> {
        (**self).decrypt_all_in_string(input)
    }
    fn decrypt_all_in_string_lossy(&self, input: &str) -> String {
        (**self).decrypt_all_in_string_lossy(input)
    }
    fn decrypt_map(&self, map: &HashMap<String, String>) -> Result<HashMap<String, String>> {
        (**self).decrypt_map(map)
    }
}

impl<T: StringEncryptor + ?Sized> StringEncryptor for Box<T> {
    fn encrypt(&self, plaintext: &str) -> Result<String> {
        (**self).encrypt(plaintext)
    }
    fn decrypt(&self, encoded: &str) -> Result<String> {
        (**self).decrypt(encoded)
    }
    fn encrypt_with_prefix(&self, plaintext: &str) -> Result<String> {
        (**self).encrypt_with_prefix(plaintext)
    }
    fn decrypt_prefixed(&self, value: &str) -> Result<String> {
        (**self).decrypt_prefixed(value)
    }
    fn decrypt_all_in_string(&self, input: &str) -> Result<String> {
        (**self).decrypt_all_in_string(input)
    }
    fn decrypt_all_in_string_lossy(&self, input: &str) -> String {
        (**self).decrypt_all_in_string_lossy(input)
    }
    fn decrypt_map(&self, map: &HashMap<String, String>) -> Result<HashMap<String, String>> {
        (**self).decrypt_map(map)
    }
}

/// Generates the inherent convenience methods for an encryptor type that
/// already has inherent `encrypt` / `decrypt` methods, and implements
/// [`StringEncryptor`] by forwarding to them.
macro_rules! impl_string_encryptor {
    ($t:ty) => {
        impl $t {
            /// Encrypts `plaintext` and wraps the result as `ENC(...)`.
            ///
            /// Each call produces a different ciphertext because the salt
            /// (and nonce, where applicable) is random.
            pub fn encrypt_with_prefix(&self, plaintext: &str) -> $crate::Result<String> {
                Ok($crate::prefix::wrap(&self.encrypt(plaintext)?))
            }

            /// Decrypts an `ENC(...)`-wrapped value. Surrounding whitespace is
            /// ignored.
            ///
            /// Returns [`Error::InvalidEncFormat`]($crate::Error::InvalidEncFormat)
            /// when the wrapper is missing.
            pub fn decrypt_prefixed(&self, value: &str) -> $crate::Result<String> {
                self.decrypt($crate::prefix::unwrap_enc(value)?)
            }

            /// Replaces every `ENC(...)` occurrence in `input` with its
            /// plaintext.
            ///
            /// Matches that fail to decrypt are left untouched and, after the
            /// whole input has been processed, the last error is returned
            /// (GoCrypt semantics). Use
            /// [`decrypt_all_in_string_lossy`](Self::decrypt_all_in_string_lossy)
            /// for the best-effort output regardless of failures.
            pub fn decrypt_all_in_string(&self, input: &str) -> $crate::Result<String> {
                let (out, err) =
                    $crate::prefix::replace_all_enc(input, |m| self.decrypt_prefixed(m));
                match err {
                    Some(err) => Err(err),
                    None => Ok(out),
                }
            }

            /// Like [`decrypt_all_in_string`](Self::decrypt_all_in_string) but
            /// never fails: matches that cannot be decrypted are kept verbatim.
            pub fn decrypt_all_in_string_lossy(&self, input: &str) -> String {
                $crate::prefix::replace_all_enc(input, |m| self.decrypt_prefixed(m)).0
            }

            /// Decrypts every `ENC(...)` value in `map`; other values are
            /// copied as-is. The first failure aborts with
            /// [`Error::KeyDecrypt`]($crate::Error::KeyDecrypt) naming the key.
            pub fn decrypt_map(
                &self,
                map: &::std::collections::HashMap<String, String>,
            ) -> $crate::Result<::std::collections::HashMap<String, String>> {
                $crate::prefix::decrypt_map_with(map, |v| self.decrypt_prefixed(v))
            }
        }

        impl $crate::StringEncryptor for $t {
            fn encrypt(&self, plaintext: &str) -> $crate::Result<String> {
                <$t>::encrypt(self, plaintext)
            }
            fn decrypt(&self, encoded: &str) -> $crate::Result<String> {
                <$t>::decrypt(self, encoded)
            }
            fn encrypt_with_prefix(&self, plaintext: &str) -> $crate::Result<String> {
                <$t>::encrypt_with_prefix(self, plaintext)
            }
            fn decrypt_prefixed(&self, value: &str) -> $crate::Result<String> {
                <$t>::decrypt_prefixed(self, value)
            }
            fn decrypt_all_in_string(&self, input: &str) -> $crate::Result<String> {
                <$t>::decrypt_all_in_string(self, input)
            }
            fn decrypt_all_in_string_lossy(&self, input: &str) -> String {
                <$t>::decrypt_all_in_string_lossy(self, input)
            }
            fn decrypt_map(
                &self,
                map: &::std::collections::HashMap<String, String>,
            ) -> $crate::Result<::std::collections::HashMap<String, String>> {
                <$t>::decrypt_map(self, map)
            }
        }
    };
}

pub(crate) use impl_string_encryptor;

#[cfg(test)]
mod tests {
    use super::*;

    /// Toy encryptor: "encrypts" by reversing; fails to decrypt "bad".
    struct Reverse;

    impl StringEncryptor for Reverse {
        fn encrypt(&self, plaintext: &str) -> Result<String> {
            if plaintext.is_empty() {
                return Err(Error::EmptyValue);
            }
            Ok(plaintext.chars().rev().collect())
        }
        fn decrypt(&self, encoded: &str) -> Result<String> {
            if encoded == "bad" {
                return Err(Error::DecryptionFailed);
            }
            Ok(encoded.chars().rev().collect())
        }
    }

    #[test]
    fn is_encrypted_matches_gocrypt() {
        for ok in ["ENC(abc)", "  ENC(abc)  ", "ENC()", "\tENC(a b)\n"] {
            assert!(is_encrypted(ok), "{ok:?}");
        }
        for bad in [
            "enc(abc)",
            "ENC(abc",
            "abc",
            "",
            "ENC(",
            "ENC",
            ")",
            "xENC(abc)",
        ] {
            assert!(!is_encrypted(bad), "{bad:?}");
        }
    }

    #[test]
    fn unwrap_enc_extracts_payload() {
        assert_eq!(unwrap_enc("ENC(x)").unwrap(), "x");
        assert_eq!(unwrap_enc("  ENC(abc==)\n").unwrap(), "abc==");
        assert_eq!(unwrap_enc("ENC()").unwrap(), "");
        assert!(matches!(unwrap_enc("x"), Err(Error::InvalidEncFormat)));
        assert!(matches!(unwrap_enc("ENC(x"), Err(Error::InvalidEncFormat)));
        assert!(matches!(unwrap_enc(""), Err(Error::InvalidEncFormat)));
    }

    #[test]
    fn wrap_adds_prefix_and_suffix() {
        assert_eq!(wrap("abc"), "ENC(abc)");
        assert_eq!(wrap(""), "ENC()");
    }

    #[test]
    fn replace_all_enc_zero_one_many() {
        let upper = |m: &str| Ok(unwrap_enc(m)?.to_uppercase());

        let (out, err) = replace_all_enc("nothing here", upper);
        assert_eq!(out, "nothing here");
        assert!(err.is_none());

        let (out, err) = replace_all_enc("k=ENC(abc)", upper);
        assert_eq!(out, "k=ABC");
        assert!(err.is_none());

        let (out, err) = replace_all_enc("a=ENC(x) b=ENC(y)\nc=ENC(z)", upper);
        assert_eq!(out, "a=X b=Y\nc=Z");
        assert!(err.is_none());
    }

    #[test]
    fn replace_all_enc_keeps_failed_match_and_returns_last_error() {
        let f = |m: &str| {
            let inner = unwrap_enc(m)?;
            if inner == "bad" {
                Err(Error::DecryptionFailed)
            } else {
                Ok(inner.to_uppercase())
            }
        };
        let (out, err) = replace_all_enc("a=ENC(x) b=ENC(bad) c=ENC(y)", f);
        assert_eq!(out, "a=X b=ENC(bad) c=Y");
        assert!(matches!(err, Some(Error::DecryptionFailed)));
    }

    #[test]
    fn replace_all_enc_regex_edge_cases() {
        let mut seen = Vec::new();
        let mut spy = |m: &str| {
            seen.push(m.to_owned());
            Ok(String::from("_"))
        };
        // `ENC()` needs at least one char, so it is not a match; nested
        // wrappers match greedily up to the first `)`.
        let (out, _) = replace_all_enc("ENC() ENC(ENC(x)) ENC(a(b)", &mut spy);
        assert_eq!(out, "ENC() _) _");
        assert_eq!(seen, vec!["ENC(ENC(x)", "ENC(a(b)"]);
    }

    #[test]
    fn decrypt_map_with_mixed_values() {
        let mut map = HashMap::new();
        map.insert("host".to_owned(), "localhost".to_owned());
        map.insert("secret".to_owned(), "ENC(abc)".to_owned());
        let out = decrypt_map_with(&map, |v| Ok(unwrap_enc(v)?.to_uppercase())).unwrap();
        assert_eq!(out["host"], "localhost");
        assert_eq!(out["secret"], "ABC");
        assert_eq!(out.len(), 2);
    }

    #[test]
    fn decrypt_map_with_reports_failing_key() {
        let mut map = HashMap::new();
        map.insert("ok".to_owned(), "ENC(abc)".to_owned());
        map.insert("api_key".to_owned(), "ENC(bad)".to_owned());
        let err = decrypt_map_with(&map, |v| {
            let inner = unwrap_enc(v)?;
            if inner == "bad" {
                Err(Error::DecryptionFailed)
            } else {
                Ok(inner.to_owned())
            }
        })
        .unwrap_err();
        match err {
            Error::KeyDecrypt { key, source } => {
                assert_eq!(key, "api_key");
                assert!(matches!(*source, Error::DecryptionFailed));
            }
            other => panic!("unexpected error: {other:?}"),
        }
    }

    #[test]
    fn trait_default_methods() {
        let enc = Reverse;
        assert_eq!(enc.encrypt_with_prefix("abc").unwrap(), "ENC(cba)");
        assert_eq!(enc.decrypt_prefixed(" ENC(cba) ").unwrap(), "abc");
        assert!(matches!(
            enc.decrypt_prefixed("cba"),
            Err(Error::InvalidEncFormat)
        ));
        assert_eq!(
            enc.decrypt_all_in_string("x=ENC(cba) y=ENC(fed)").unwrap(),
            "x=abc y=def"
        );
        assert!(matches!(
            enc.decrypt_all_in_string("x=ENC(cba) y=ENC(bad)"),
            Err(Error::DecryptionFailed)
        ));
        assert_eq!(
            enc.decrypt_all_in_string_lossy("x=ENC(cba) y=ENC(bad)"),
            "x=abc y=ENC(bad)"
        );

        let mut map = HashMap::new();
        map.insert("a".to_owned(), "ENC(cba)".to_owned());
        map.insert("b".to_owned(), "plain".to_owned());
        let out = enc.decrypt_map(&map).unwrap();
        assert_eq!(out["a"], "abc");
        assert_eq!(out["b"], "plain");
    }

    #[test]
    fn trait_is_object_safe_and_forwards_through_box_and_ref() {
        let boxed: Box<dyn StringEncryptor> = Box::new(Reverse);
        assert_eq!(boxed.encrypt_with_prefix("abc").unwrap(), "ENC(cba)");
        let by_ref: &dyn StringEncryptor = &Reverse;
        assert_eq!(by_ref.decrypt_prefixed("ENC(cba)").unwrap(), "abc");

        fn generic<E: StringEncryptor>(e: E) -> String {
            e.decrypt("cba").unwrap()
        }
        assert_eq!(generic(&Reverse), "abc");
        assert_eq!(generic(boxed), "abc");
    }
}

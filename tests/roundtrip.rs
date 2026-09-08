//! Round-trip and error-path tests for the three encryptors.

use std::collections::HashMap;

use base64::engine::general_purpose::STANDARD as BASE64;
use base64::Engine;
use rustcrypt_jasypt::{
    is_encrypted, Encryptor, Error, JasyptEncryptor, JasyptStrongEncryptor, StringEncryptor,
};

const PASSWORD: &str = "rustcrypt-test-2026";
const UTF8: &str = "Selamat pagi, Fariz 🦀";

fn long_text() -> String {
    "0123456789".repeat(20)
}

/// Every plaintext round-trips, wrapped and unwrapped, through the trait API.
fn assert_roundtrips<E: StringEncryptor>(enc: &E) {
    for plaintext in [
        "hello",
        "Password123!",
        UTF8,
        &long_text(),
        "a",
        "12345678",
        "x".repeat(16).as_str(),
    ] {
        let raw = enc.encrypt(plaintext).unwrap();
        assert!(!is_encrypted(&raw), "raw payload must not be wrapped");
        assert_eq!(enc.decrypt(&raw).unwrap(), plaintext);

        let wrapped = enc.encrypt_with_prefix(plaintext).unwrap();
        assert!(wrapped.starts_with("ENC(") && wrapped.ends_with(')'));
        assert!(is_encrypted(&wrapped));
        assert_eq!(enc.decrypt_prefixed(&wrapped).unwrap(), plaintext);
        assert_eq!(
            enc.decrypt_prefixed(&format!("  {wrapped}\n")).unwrap(),
            plaintext
        );
    }
}

fn assert_random_salt<E: StringEncryptor>(enc: &E) {
    let a = enc.encrypt("same input").unwrap();
    let b = enc.encrypt("same input").unwrap();
    assert_ne!(a, b, "random salt must change the output");
}

fn assert_empty_value_errors<E: StringEncryptor>(enc: &E) {
    assert!(matches!(enc.encrypt(""), Err(Error::EmptyValue)));
    assert!(matches!(
        enc.encrypt_with_prefix(""),
        Err(Error::EmptyValue)
    ));
    assert!(matches!(enc.decrypt(""), Err(Error::EmptyValue)));
    assert!(matches!(
        enc.decrypt_prefixed("ENC()"),
        Err(Error::EmptyValue)
    ));
}

fn assert_invalid_format_and_base64<E: StringEncryptor>(enc: &E) {
    assert!(matches!(
        enc.decrypt_prefixed("plain"),
        Err(Error::InvalidEncFormat)
    ));
    assert!(matches!(
        enc.decrypt_prefixed("ENC(abc"),
        Err(Error::InvalidEncFormat)
    ));
    assert!(matches!(enc.decrypt("not base64!"), Err(Error::Base64(_))));
    assert!(matches!(
        enc.decrypt_prefixed("ENC(not base64!)"),
        Err(Error::Base64(_))
    ));
}

/// Flips the last byte of the decoded payload and re-encodes it.
fn tamper_last_byte(encoded: &str) -> String {
    let mut bytes = BASE64.decode(encoded).unwrap();
    let last = bytes.len() - 1;
    bytes[last] ^= 0x01;
    BASE64.encode(bytes)
}

fn truncate_to(encoded: &str, len: usize) -> String {
    let bytes = BASE64.decode(encoded).unwrap();
    BASE64.encode(&bytes[..len])
}

fn assert_decrypt_all_and_map<E: StringEncryptor>(enc: &E) {
    let a = enc.encrypt_with_prefix("alpha").unwrap();
    let b = enc.encrypt_with_prefix("beta").unwrap();

    assert_eq!(
        enc.decrypt_all_in_string("no secrets").unwrap(),
        "no secrets"
    );
    assert_eq!(
        enc.decrypt_all_in_string(&format!("k={a}")).unwrap(),
        "k=alpha"
    );
    assert_eq!(
        enc.decrypt_all_in_string(&format!("a={a}\nb={b} tail"))
            .unwrap(),
        "a=alpha\nb=beta tail"
    );

    let mixed = format!("a={a} bad=ENC(not base64!) b={b}");
    assert!(matches!(
        enc.decrypt_all_in_string(&mixed),
        Err(Error::Base64(_))
    ));
    assert_eq!(
        enc.decrypt_all_in_string_lossy(&mixed),
        "a=alpha bad=ENC(not base64!) b=beta"
    );

    let mut map = HashMap::new();
    map.insert("host".to_owned(), "localhost".to_owned());
    map.insert("password".to_owned(), a.clone());
    map.insert("token".to_owned(), b.clone());
    let out = enc.decrypt_map(&map).unwrap();
    assert_eq!(out["host"], "localhost");
    assert_eq!(out["password"], "alpha");
    assert_eq!(out["token"], "beta");

    map.insert("api_key".to_owned(), "ENC(not base64!)".to_owned());
    match enc.decrypt_map(&map).unwrap_err() {
        Error::KeyDecrypt { key, source } => {
            assert_eq!(key, "api_key");
            assert!(matches!(*source, Error::Base64(_)));
        }
        other => panic!("unexpected error {other:?}"),
    }
}

mod aes_gcm {
    use super::*;

    #[test]
    fn roundtrip_defaults() {
        let enc = Encryptor::new(PASSWORD).unwrap();
        assert_roundtrips(&enc);
        assert_random_salt(&enc);
        assert_empty_value_errors(&enc);
        assert_invalid_format_and_base64(&enc);
        assert_decrypt_all_and_map(&enc);
    }

    #[test]
    fn inherent_methods_do_not_need_trait_import() {
        // This module imports the trait, but the call below resolves to the
        // inherent method (same behaviour) — the point is that both exist.
        let enc = Encryptor::new(PASSWORD).unwrap();
        let wrapped = Encryptor::encrypt_with_prefix(&enc, "x").unwrap();
        assert_eq!(Encryptor::decrypt_prefixed(&enc, &wrapped).unwrap(), "x");
    }

    #[test]
    fn empty_password_rejected() {
        assert!(matches!(Encryptor::new(""), Err(Error::EmptyPassword)));
    }

    #[test]
    fn wrong_password_fails_authentication() {
        let enc = Encryptor::new(PASSWORD).unwrap();
        let other = Encryptor::new("wrong-password").unwrap();
        let wrapped = enc.encrypt_with_prefix("secret").unwrap();
        assert!(matches!(
            other.decrypt_prefixed(&wrapped),
            Err(Error::DecryptionFailed)
        ));
    }

    #[test]
    fn tampered_ciphertext_fails_authentication() {
        let enc = Encryptor::new(PASSWORD).unwrap();
        let raw = enc.encrypt("secret").unwrap();
        assert!(matches!(
            enc.decrypt(&tamper_last_byte(&raw)),
            Err(Error::DecryptionFailed)
        ));
    }

    #[test]
    fn too_short_payload_fails() {
        let enc = Encryptor::new(PASSWORD).unwrap();
        let raw = enc.encrypt("secret").unwrap();
        // salt(16) + nonce(12) - 1
        assert!(matches!(
            enc.decrypt(&truncate_to(&raw, 27)),
            Err(Error::DecryptionFailed)
        ));
        // exactly salt + nonce but no ciphertext/tag
        assert!(matches!(
            enc.decrypt(&truncate_to(&raw, 28)),
            Err(Error::DecryptionFailed)
        ));
    }

    #[test]
    fn builder_options_roundtrip_and_must_match() {
        let enc = Encryptor::new(PASSWORD)
            .unwrap()
            .with_iterations(1_000)
            .with_salt_size(8);
        assert_eq!(enc.iterations(), 1_000);
        assert_eq!(enc.salt_size(), 8);
        assert_eq!(enc.key_size(), 32);
        assert_roundtrips(&enc);

        let wrapped = enc.encrypt_with_prefix("secret").unwrap();
        let default = Encryptor::new(PASSWORD).unwrap();
        assert!(default.decrypt_prefixed(&wrapped).is_err());
    }

    #[test]
    fn all_key_sizes_roundtrip() {
        for key_size in [16usize, 24, 32] {
            let enc = Encryptor::new(PASSWORD)
                .unwrap()
                .with_key_size(key_size)
                .unwrap();
            assert_eq!(enc.key_size(), key_size);
            assert_roundtrips(&enc);
        }
        let err = Encryptor::new(PASSWORD)
            .unwrap()
            .with_key_size(20)
            .unwrap_err();
        assert!(matches!(err, Error::InvalidParameter(_)));
        assert_eq!(
            err.to_string(),
            "invalid parameter: key size must be 16, 24 or 32"
        );
    }
}

mod jasypt_des {
    use super::*;

    #[test]
    fn roundtrip_defaults() {
        let enc = JasyptEncryptor::new(PASSWORD).unwrap();
        assert_eq!(enc.iterations(), 1_000);
        assert_roundtrips(&enc);
        assert_random_salt(&enc);
        assert_empty_value_errors(&enc);
        assert_invalid_format_and_base64(&enc);
        assert_decrypt_all_and_map(&enc);
    }

    #[test]
    fn empty_password_rejected() {
        assert!(matches!(
            JasyptEncryptor::new(""),
            Err(Error::EmptyPassword)
        ));
    }

    #[test]
    fn wrong_password_errors_or_returns_garbage() {
        // DES-CBC has no integrity check: the padding check usually fails,
        // but with probability ~1/256 the garbage happens to have valid
        // padding. Either way the result must not equal the plaintext.
        let enc = JasyptEncryptor::new(PASSWORD).unwrap();
        let other = JasyptEncryptor::new("wrong-password").unwrap();
        for _ in 0..20 {
            let wrapped = enc.encrypt_with_prefix("secret").unwrap();
            match other.decrypt_prefixed(&wrapped) {
                Err(Error::DecryptionFailed) => {}
                Ok(garbage) => assert_ne!(garbage, "secret"),
                Err(other) => panic!("unexpected error {other:?}"),
            }
        }
    }

    #[test]
    fn tampered_ciphertext_errors_or_returns_garbage() {
        let enc = JasyptEncryptor::new(PASSWORD).unwrap();
        let raw = enc.encrypt("secret value").unwrap();
        match enc.decrypt(&tamper_last_byte(&raw)) {
            Err(Error::DecryptionFailed) => {}
            Ok(garbage) => assert_ne!(garbage, "secret value"),
            Err(other) => panic!("unexpected error {other:?}"),
        }
    }

    #[test]
    fn short_or_misaligned_payload_is_invalid_jasypt_data() {
        let enc = JasyptEncryptor::new(PASSWORD).unwrap();
        let raw = enc.encrypt("secret value").unwrap(); // 8 + 16 bytes
        assert!(matches!(
            enc.decrypt(&truncate_to(&raw, 15)),
            Err(Error::InvalidJasyptData)
        ));
        assert!(matches!(
            enc.decrypt(&truncate_to(&raw, 17)),
            Err(Error::InvalidJasyptData)
        ));
        assert_eq!(enc.decrypt(&truncate_to(&raw, 24)).unwrap(), "secret value");
    }

    #[test]
    fn iterations_must_match() {
        let enc = JasyptEncryptor::new(PASSWORD)
            .unwrap()
            .with_iterations(2_000);
        assert_eq!(enc.iterations(), 2_000);
        assert_roundtrips(&enc);
        let wrapped = enc.encrypt_with_prefix("secret").unwrap();
        let default = JasyptEncryptor::new(PASSWORD).unwrap();
        match default.decrypt_prefixed(&wrapped) {
            Err(Error::DecryptionFailed) => {}
            Ok(garbage) => assert_ne!(garbage, "secret"),
            Err(other) => panic!("unexpected error {other:?}"),
        }
    }
}

mod jasypt_strong {
    use super::*;

    #[test]
    fn roundtrip_defaults() {
        let enc = JasyptStrongEncryptor::new(PASSWORD).unwrap();
        assert_eq!(enc.iterations(), 1_000);
        assert_eq!(enc.salt_size(), 16);
        assert_roundtrips(&enc);
        assert_random_salt(&enc);
        assert_empty_value_errors(&enc);
        assert_invalid_format_and_base64(&enc);
        assert_decrypt_all_and_map(&enc);
    }

    #[test]
    fn empty_password_rejected() {
        assert!(matches!(
            JasyptStrongEncryptor::new(""),
            Err(Error::EmptyPassword)
        ));
    }

    #[test]
    fn wrong_password_errors_or_returns_garbage() {
        let enc = JasyptStrongEncryptor::new(PASSWORD).unwrap();
        let other = JasyptStrongEncryptor::new("wrong-password").unwrap();
        for _ in 0..20 {
            let wrapped = enc.encrypt_with_prefix("secret").unwrap();
            match other.decrypt_prefixed(&wrapped) {
                Err(Error::DecryptionFailed) => {}
                Ok(garbage) => assert_ne!(garbage, "secret"),
                Err(other) => panic!("unexpected error {other:?}"),
            }
        }
    }

    #[test]
    fn tampered_ciphertext_errors_or_returns_garbage() {
        let enc = JasyptStrongEncryptor::new(PASSWORD).unwrap();
        let raw = enc.encrypt("secret value").unwrap();
        match enc.decrypt(&tamper_last_byte(&raw)) {
            Err(Error::DecryptionFailed) => {}
            Ok(garbage) => assert_ne!(garbage, "secret value"),
            Err(other) => panic!("unexpected error {other:?}"),
        }
    }

    #[test]
    fn short_or_misaligned_payload_is_invalid_jasypt_data() {
        let enc = JasyptStrongEncryptor::new(PASSWORD).unwrap();
        let raw = enc.encrypt("secret value").unwrap(); // 16 + 16 bytes
        assert!(matches!(
            enc.decrypt(&truncate_to(&raw, 31)),
            Err(Error::InvalidJasyptData)
        ));
        let long = enc.encrypt(&long_text()).unwrap(); // 16 + 208 bytes
        assert!(matches!(
            enc.decrypt(&truncate_to(&long, 16 + 17)),
            Err(Error::InvalidJasyptData)
        ));
    }

    #[test]
    fn builder_options_roundtrip_and_must_match() {
        let enc = JasyptStrongEncryptor::new(PASSWORD)
            .unwrap()
            .with_iterations(5_000)
            .with_salt_size(32);
        assert_eq!(enc.iterations(), 5_000);
        assert_eq!(enc.salt_size(), 32);
        assert_roundtrips(&enc);

        let wrapped = enc.encrypt_with_prefix("secret").unwrap();
        let default = JasyptStrongEncryptor::new(PASSWORD).unwrap();
        match default.decrypt_prefixed(&wrapped) {
            Err(Error::DecryptionFailed) | Err(Error::InvalidJasyptData) => {}
            Ok(garbage) => assert_ne!(garbage, "secret"),
            Err(other) => panic!("unexpected error {other:?}"),
        }
    }
}

#[test]
fn encryptors_are_not_cross_compatible() {
    let gcm = Encryptor::new(PASSWORD).unwrap();
    let des = JasyptEncryptor::new(PASSWORD).unwrap();
    let strong = JasyptStrongEncryptor::new(PASSWORD).unwrap();
    let v = gcm.encrypt_with_prefix("secret").unwrap();
    assert_ne!(des.decrypt_prefixed(&v).ok().as_deref(), Some("secret"));
    assert_ne!(strong.decrypt_prefixed(&v).ok().as_deref(), Some("secret"));
    let v = des.encrypt_with_prefix("secret").unwrap();
    assert!(gcm.decrypt_prefixed(&v).is_err());
}

#[test]
fn boxed_dyn_encryptor_works() {
    let encs: Vec<Box<dyn StringEncryptor>> = vec![
        Box::new(Encryptor::new(PASSWORD).unwrap()),
        Box::new(JasyptEncryptor::new(PASSWORD).unwrap()),
        Box::new(JasyptStrongEncryptor::new(PASSWORD).unwrap()),
    ];
    for enc in &encs {
        let wrapped = enc.encrypt_with_prefix(UTF8).unwrap();
        assert_eq!(enc.decrypt_prefixed(&wrapped).unwrap(), UTF8);
    }
}

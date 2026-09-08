//! Fixed-salt golden tests: byte-for-byte comparison of the deterministic
//! encryption cores against values computed by GoCrypt's own code
//! (`scripts/gen-vectors`, section `fixed`).

use serde::Deserialize;

use crate::{kdf, Encryptor, JasyptEncryptor, JasyptStrongEncryptor};

const FIXTURE: &str = include_str!("../tests/fixtures/gocrypt_vectors.json");

#[derive(Deserialize)]
struct Fixture {
    password: String,
    fixed: Fixed,
}

#[derive(Deserialize)]
struct Fixed {
    pbkdf2_sha256: Vec<Pbkdf2Vector>,
    pbkdf1_md5: Vec<Pbkdf1Vector>,
    aes_gcm: Vec<GcmVector>,
    jasypt_des: Vec<CbcVector>,
    jasypt_strong: Vec<CbcVector>,
}

#[derive(Deserialize)]
struct Pbkdf2Vector {
    salt_hex: String,
    iterations: u32,
    len: usize,
    out_hex: String,
}

#[derive(Deserialize)]
struct Pbkdf1Vector {
    salt_hex: String,
    iterations: u32,
    out_hex: String,
}

#[derive(Deserialize)]
struct GcmVector {
    salt_hex: String,
    nonce_hex: String,
    iterations: u32,
    key_size: usize,
    plaintext: String,
    encoded: String,
}

#[derive(Deserialize)]
struct CbcVector {
    salt_hex: String,
    iterations: u32,
    plaintext: String,
    encoded: String,
}

fn fixture() -> Fixture {
    serde_json::from_str(FIXTURE).expect("fixture parses")
}

fn unhex(s: &str) -> Vec<u8> {
    hex::decode(s).expect("valid hex")
}

#[test]
fn pbkdf2_sha256_matches_gocrypt() {
    let f = fixture();
    assert!(!f.fixed.pbkdf2_sha256.is_empty());
    for v in &f.fixed.pbkdf2_sha256 {
        let out = kdf::pbkdf2_sha256(
            f.password.as_bytes(),
            &unhex(&v.salt_hex),
            v.iterations,
            v.len,
        );
        assert_eq!(
            hex::encode(out),
            v.out_hex,
            "salt={} iters={} len={}",
            v.salt_hex,
            v.iterations,
            v.len
        );
    }
}

#[test]
fn pbkdf1_md5_matches_gocrypt() {
    let f = fixture();
    assert!(!f.fixed.pbkdf1_md5.is_empty());
    for v in &f.fixed.pbkdf1_md5 {
        let out = kdf::pbkdf1_md5(f.password.as_bytes(), &unhex(&v.salt_hex), v.iterations);
        assert_eq!(
            hex::encode(out),
            v.out_hex,
            "salt={} iters={}",
            v.salt_hex,
            v.iterations
        );
    }
}

#[test]
fn aes_gcm_fixed_salt_matches_gocrypt() {
    let f = fixture();
    assert!(!f.fixed.aes_gcm.is_empty());
    for v in &f.fixed.aes_gcm {
        let salt = unhex(&v.salt_hex);
        let nonce = unhex(&v.nonce_hex);
        let enc = Encryptor::new(&f.password)
            .unwrap()
            .with_iterations(v.iterations)
            .with_salt_size(salt.len())
            .with_key_size(v.key_size)
            .unwrap();
        let got = enc
            .encrypt_with_salt_nonce(&salt, &nonce, &v.plaintext)
            .unwrap();
        assert_eq!(
            got, v.encoded,
            "aes_gcm plaintext={:?} key_size={}",
            v.plaintext, v.key_size
        );
        assert_eq!(enc.decrypt(&v.encoded).unwrap(), v.plaintext);
    }
}

#[test]
fn jasypt_des_fixed_salt_matches_gocrypt() {
    let f = fixture();
    assert!(!f.fixed.jasypt_des.is_empty());
    for v in &f.fixed.jasypt_des {
        let salt: [u8; 8] = unhex(&v.salt_hex).try_into().expect("8-byte salt");
        let enc = JasyptEncryptor::new(&f.password)
            .unwrap()
            .with_iterations(v.iterations);
        let got = enc.encrypt_with_salt(&salt, &v.plaintext).unwrap();
        assert_eq!(
            got, v.encoded,
            "jasypt_des plaintext={:?} iters={}",
            v.plaintext, v.iterations
        );
        assert_eq!(enc.decrypt(&v.encoded).unwrap(), v.plaintext);
    }
}

#[test]
fn jasypt_strong_fixed_salt_matches_gocrypt() {
    let f = fixture();
    assert!(!f.fixed.jasypt_strong.is_empty());
    for v in &f.fixed.jasypt_strong {
        let salt = unhex(&v.salt_hex);
        let enc = JasyptStrongEncryptor::new(&f.password)
            .unwrap()
            .with_iterations(v.iterations)
            .with_salt_size(salt.len());
        let got = enc.encrypt_with_salt(&salt, &v.plaintext).unwrap();
        assert_eq!(
            got, v.encoded,
            "jasypt_strong plaintext={:?} iters={}",
            v.plaintext, v.iterations
        );
        assert_eq!(enc.decrypt(&v.encoded).unwrap(), v.plaintext);
    }
}

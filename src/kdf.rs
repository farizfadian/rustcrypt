//! Key-derivation functions used by the encryptors.
//!
//! Both functions reproduce the GoCrypt reference implementation exactly:
//!
//! * [`pbkdf2_sha256`]: PBKDF2 with HMAC-SHA256 (RFC 8018), used by
//!   [`Encryptor`](crate::Encryptor) and
//!   [`JasyptStrongEncryptor`](crate::JasyptStrongEncryptor).
//! * [`pbkdf1_md5`]: the PBKDF1/MD5 scheme behind Java's
//!   `PBEWithMD5AndDES`, used by [`JasyptEncryptor`](crate::JasyptEncryptor).

use md5::{Digest, Md5};
use sha2::Sha256;

/// PBKDF2-HMAC-SHA256 producing `out_len` bytes of key material.
pub(crate) fn pbkdf2_sha256(
    password: &[u8],
    salt: &[u8],
    iterations: u32,
    out_len: usize,
) -> Vec<u8> {
    let mut out = vec![0u8; out_len];
    pbkdf2::pbkdf2_hmac::<Sha256>(password, salt, iterations, &mut out);
    out
}

/// PBKDF1 with MD5 exactly as Jasypt/GoCrypt implement it:
/// `h = md5(password ‖ salt)`, then `h = md5(h)` repeated `iterations - 1`
/// more times (so `iterations` MD5 invocations in total).
///
/// The 16-byte result is split by the caller into an 8-byte DES key and an
/// 8-byte IV. `iterations == 0` behaves like `1`, matching GoCrypt.
pub(crate) fn pbkdf1_md5(password: &[u8], salt: &[u8], iterations: u32) -> [u8; 16] {
    let mut hasher = Md5::new();
    hasher.update(password);
    hasher.update(salt);
    let mut h: [u8; 16] = hasher.finalize().into();
    for _ in 1..iterations {
        h = Md5::digest(h).into();
    }
    h
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn pbkdf2_sha256_known_vectors() {
        // Widely published PBKDF2-HMAC-SHA256 vectors (password/salt, 32 bytes).
        let cases = [
            (
                1,
                "120fb6cffcf8b32c43e7225256c4f837a86548c92ccc35480805987cb70be17b",
            ),
            (
                2,
                "ae4d0c95af6b46d32d0adff928f06dd02a303f8ef3c251dfd6e2d85a95474c43",
            ),
            (
                4096,
                "c5e478d59288c841aa530db6845c4c8d962893a001ce4e11a4963873aa98134a",
            ),
        ];
        for (iterations, expected) in cases {
            let out = pbkdf2_sha256(b"password", b"salt", iterations, 32);
            assert_eq!(hex::encode(out), expected, "iterations={iterations}");
        }
    }

    #[test]
    fn pbkdf2_sha256_multi_block_output_is_prefix_consistent() {
        // 48 bytes spans two SHA-256 blocks (used by JasyptStrongEncryptor).
        let short = pbkdf2_sha256(b"password", b"salt", 1000, 32);
        let long = pbkdf2_sha256(b"password", b"salt", 1000, 48);
        assert_eq!(long.len(), 48);
        assert_eq!(&long[..32], &short[..]);
    }

    #[test]
    fn pbkdf1_md5_single_iteration_is_plain_md5() {
        let expected: [u8; 16] = Md5::digest(b"passwordsalt1234").into();
        assert_eq!(pbkdf1_md5(b"password", b"salt1234", 1), expected);
        // 0 iterations behaves like 1 (GoCrypt loop `for i := 1; i < n` never runs).
        assert_eq!(pbkdf1_md5(b"password", b"salt1234", 0), expected);
    }

    #[test]
    fn pbkdf1_md5_chains_digests() {
        let first: [u8; 16] = Md5::digest(b"passwordsalt1234").into();
        let second: [u8; 16] = Md5::digest(first).into();
        assert_eq!(pbkdf1_md5(b"password", b"salt1234", 2), second);
    }

    // Exact GoCrypt-computed values for both KDFs are asserted in
    // `crate::golden` against tests/fixtures/gocrypt_vectors.json.
}

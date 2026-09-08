# Security Policy

## 🔒 Supported Versions

| Version | Supported          |
| ------- | ------------------ |
| 1.x.x   | ✅ Yes             |
| < 1.0   | ❌ No              |

---

## 🚨 Reporting a Vulnerability

We take security seriously. If you discover a security vulnerability, please follow these steps:

### DO NOT

- ❌ Open a public GitHub issue
- ❌ Discuss the vulnerability publicly before it's fixed

### DO

1. **Use GitHub's private vulnerability reporting** on the repository (Security → Report a vulnerability), or **email the maintainer directly** at the address listed in the GitHub profile
2. **Include the following information:**
   - Description of the vulnerability
   - Steps to reproduce
   - Potential impact
   - Suggested fix (if any)

### What to Expect

- **Acknowledgment**: Within 48 hours
- **Initial Assessment**: Within 1 week
- **Resolution Timeline**: Depends on severity
  - Critical: 1-3 days
  - High: 1-2 weeks
  - Medium: 2-4 weeks
  - Low: Next release

Because RustCrypt shares its wire formats with GoCrypt, PyCrypt, NodeCrypt and PHPCrypt, a format-level issue will be coordinated and fixed across all five libraries.

---

## 🛡️ Security Model

| Encryptor | Cipher | KDF | Integrity | Assessment |
|-----------|--------|-----|-----------|------------|
| `Encryptor` | AES-256-GCM | PBKDF2-HMAC-SHA256, 10 000 iterations | AEAD tag | ✅ Recommended |
| `JasyptStrongEncryptor` | AES-256-CBC | PBKDF2-HMAC-SHA256, 1 000 iterations | none (PKCS7 padding only) | ✅ Acceptable within the family |
| `JasyptEncryptor` | DES-CBC | PBKDF1-MD5, 1 000 iterations | none (PKCS5 padding only) | ⚠️ Legacy, Java-compatibility only |

Known limitations (documented, not considered vulnerabilities):

- `JasyptEncryptor` uses DES (56-bit key) and MD5 because Java Jasypt's default algorithm does. It exists for compatibility with existing Java deployments; use `Encryptor` whenever Java does not need to read the value.
- CBC modes have no authentication: a wrong password or tampered ciphertext is usually detected by the padding check but can occasionally decrypt to garbage. `Encryptor` (AES-GCM) always detects it.
- `JasyptStrongEncryptor` derives the IV from PBKDF2 together with the key (family format) instead of using a random IV like real Java Jasypt. Every encryption still uses a fresh random salt, so key and IV differ per message.
- `Error::DecryptionFailed` intentionally carries no detail so the library cannot be used as a padding or authentication oracle.
- Passwords and derived keys are not zeroized on drop in 1.0.

---

## 🔐 Best Practices for Users

1. **Never hardcode passwords** - Use environment variables (`RUSTCRYPT_PASSWORD`) or a secret manager
2. **Use strong passwords** (minimum 16 characters, random)
3. **Prefer `Encryptor`** unless Java Jasypt must read the value
4. **Rotate passwords regularly** and re-encrypt configuration
5. **Keep the crate updated** - releases are audited with `cargo audit` in CI
6. **Do not log decrypted values**

---

## 📦 Dependencies

RustCrypt is pure Rust and depends only on audited [RustCrypto](https://github.com/RustCrypto) crates for cryptography (`aes`, `aes-gcm`, `cbc`, `des`, `md-5`, `sha2`, `pbkdf2`) plus `base64`, `regex`, `thiserror`, and optionally `serde`/`serde_json` (feature `config`) and `clap` (feature `cli`). No OpenSSL, no C code. CI runs `cargo audit` against the RustSec advisory database.

// Command gen-vectors produces tests/fixtures/gocrypt_vectors.json, the
// cross-language golden vectors that RustCrypt must decrypt.
//
// Two kinds of vectors are generated:
//
//   - "vectors": produced with the public GoCrypt API (random salt/nonce), for
//     all three modes and several plaintexts. RustCrypt must decrypt them.
//   - "fixed": produced with VERBATIM copies of GoCrypt's key derivation and
//     cipher code but with an injected, fixed salt/nonce, so RustCrypt's
//     deterministic cores can be compared byte-for-byte.
//
// Usage (from the repository root):
//
//	cd scripts/gen-vectors
//	go run . -commit <gocrypt commit> -out ../../tests/fixtures/gocrypt_vectors.json
package main

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/des"
	"crypto/hmac"
	"crypto/md5"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/farizfadian/gocrypt"
)

const password = "rustcrypt-test-2026"

var plaintexts = []string{
	"hello",
	"Password123!",
	strings.Repeat("0123456789", 20), // 200 chars
	"Selamat pagi, Fariz 🦀",
}

type vector struct {
	Mode      string `json:"mode"`
	Plaintext string `json:"plaintext"`
	Encrypted string `json:"encrypted"`
}

type pbkdf2Vector struct {
	SaltHex    string `json:"salt_hex"`
	Iterations int    `json:"iterations"`
	Len        int    `json:"len"`
	OutHex     string `json:"out_hex"`
}

type pbkdf1Vector struct {
	SaltHex    string `json:"salt_hex"`
	Iterations int    `json:"iterations"`
	OutHex     string `json:"out_hex"`
}

type gcmVector struct {
	SaltHex    string `json:"salt_hex"`
	NonceHex   string `json:"nonce_hex"`
	Iterations int    `json:"iterations"`
	KeySize    int    `json:"key_size"`
	Plaintext  string `json:"plaintext"`
	Encoded    string `json:"encoded"`
}

type cbcVector struct {
	SaltHex    string `json:"salt_hex"`
	Iterations int    `json:"iterations"`
	Plaintext  string `json:"plaintext"`
	Encoded    string `json:"encoded"`
}

type fixed struct {
	Pbkdf2Sha256 []pbkdf2Vector `json:"pbkdf2_sha256"`
	Pbkdf1Md5    []pbkdf1Vector `json:"pbkdf1_md5"`
	AesGcm       []gcmVector    `json:"aes_gcm"`
	JasyptDes    []cbcVector    `json:"jasypt_des"`
	JasyptStrong []cbcVector    `json:"jasypt_strong"`
}

type fixture struct {
	Generator     string   `json:"generator"`
	GocryptModule string   `json:"gocrypt_module"`
	GocryptCommit string   `json:"gocrypt_commit"`
	GeneratedAt   string   `json:"generated_at"`
	Password      string   `json:"password"`
	Vectors       []vector `json:"vectors"`
	Fixed         fixed    `json:"fixed"`
}

func main() {
	commit := flag.String("commit", "unknown", "gocrypt git commit used")
	out := flag.String("out", "../../tests/fixtures/gocrypt_vectors.json", "output path")
	flag.Parse()

	f := fixture{
		Generator:     "scripts/gen-vectors/main.go",
		GocryptModule: "github.com/farizfadian/gocrypt v1.0.0",
		GocryptCommit: *commit,
		GeneratedAt:   time.Now().UTC().Format("2006-01-02"),
		Password:      password,
	}

	// ── random-salt vectors via the public GoCrypt API ────────────────────
	std, err := gocrypt.NewEncryptor(password)
	check(err)
	jas, err := gocrypt.NewJasyptEncryptor(password)
	check(err)
	strong, err := gocrypt.NewJasyptStrongEncryptor(password)
	check(err)

	for _, pt := range plaintexts {
		v, err := std.EncryptWithPrefix(pt)
		check(err)
		f.Vectors = append(f.Vectors, vector{"default", pt, v})

		v, err = jas.EncryptWithPrefix(pt)
		check(err)
		f.Vectors = append(f.Vectors, vector{"jasypt", pt, v})

		v, err = strong.EncryptWithPrefix(pt)
		check(err)
		f.Vectors = append(f.Vectors, vector{"jasypt-strong", pt, v})
	}

	// Sanity: GoCrypt itself must round-trip everything it produced.
	for _, v := range f.Vectors {
		var got string
		switch v.Mode {
		case "default":
			got, err = std.DecryptPrefixed(v.Encrypted)
		case "jasypt":
			got, err = jas.DecryptPrefixed(v.Encrypted)
		case "jasypt-strong":
			got, err = strong.DecryptPrefixed(v.Encrypted)
		}
		check(err)
		if got != v.Plaintext {
			panic(fmt.Sprintf("gocrypt round-trip mismatch for %s", v.Mode))
		}
	}

	// ── fixed-salt vectors via verbatim copies of GoCrypt internals ───────
	salt8 := unhex("0102030405060708")
	salt16 := unhex("000102030405060708090a0b0c0d0e0f")
	salt32 := unhex("202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f")
	nonce := unhex("a1a2a3a4a5a6a7a8a9aaabac")

	for _, c := range []struct {
		salt  []byte
		iters int
		n     int
	}{{salt16, 10000, 32}, {salt16, 1000, 48}, {salt32, 5000, 48}, {salt8, 1, 16}} {
		f.Fixed.Pbkdf2Sha256 = append(f.Fixed.Pbkdf2Sha256, pbkdf2Vector{
			hex.EncodeToString(c.salt), c.iters, c.n,
			hex.EncodeToString(pbkdf2Key([]byte(password), c.salt, c.iters, c.n)),
		})
	}

	for _, iters := range []int{1, 2, 1000, 2000} {
		f.Fixed.Pbkdf1Md5 = append(f.Fixed.Pbkdf1Md5, pbkdf1Vector{
			hex.EncodeToString(salt8), iters, hex.EncodeToString(pbkdf1MD5(password, salt8, iters)),
		})
	}

	for _, pt := range []string{"hello", "Selamat pagi, Fariz 🦀"} {
		f.Fixed.AesGcm = append(f.Fixed.AesGcm, gcmVector{
			hex.EncodeToString(salt16), hex.EncodeToString(nonce), 10000, 32, pt,
			gcmEncryptFixed(password, salt16, nonce, 10000, 32, pt),
		})
		f.Fixed.JasyptDes = append(f.Fixed.JasyptDes, cbcVector{
			hex.EncodeToString(salt8), 1000, pt, desEncryptFixed(password, salt8, 1000, pt),
		})
		f.Fixed.JasyptStrong = append(f.Fixed.JasyptStrong, cbcVector{
			hex.EncodeToString(salt16), 1000, pt, strongEncryptFixed(password, salt16, 1000, pt),
		})
	}
	// Non-default parameters.
	f.Fixed.AesGcm = append(f.Fixed.AesGcm, gcmVector{
		hex.EncodeToString(salt8), hex.EncodeToString(nonce), 1000, 16, "hello",
		gcmEncryptFixed(password, salt8, nonce, 1000, 16, "hello"),
	})
	f.Fixed.JasyptDes = append(f.Fixed.JasyptDes, cbcVector{
		hex.EncodeToString(salt8), 2000, "12345678", desEncryptFixed(password, salt8, 2000, "12345678"),
	})
	f.Fixed.JasyptStrong = append(f.Fixed.JasyptStrong, cbcVector{
		hex.EncodeToString(salt32), 5000, "0123456789abcdef", strongEncryptFixed(password, salt32, 5000, "0123456789abcdef"),
	})

	// Sanity: the fixed vectors must decrypt with the public API too.
	for _, v := range f.Fixed.AesGcm {
		e, err := gocrypt.NewEncryptor(password, gocrypt.WithIterations(v.Iterations),
			gocrypt.WithSaltSize(len(unhex(v.SaltHex))), gocrypt.WithKeySize(v.KeySize))
		check(err)
		got, err := e.Decrypt(v.Encoded)
		check(err)
		mustEqual(got, v.Plaintext, "aes_gcm fixed")
	}
	for _, v := range f.Fixed.JasyptDes {
		e, err := gocrypt.NewJasyptEncryptor(password, gocrypt.WithJasyptIterations(v.Iterations))
		check(err)
		got, err := e.Decrypt(v.Encoded)
		check(err)
		mustEqual(got, v.Plaintext, "jasypt_des fixed")
	}
	for _, v := range f.Fixed.JasyptStrong {
		e, err := gocrypt.NewJasyptStrongEncryptor(password, gocrypt.WithStrongIterations(v.Iterations),
			gocrypt.WithStrongSaltSize(len(unhex(v.SaltHex))))
		check(err)
		got, err := e.Decrypt(v.Encoded)
		check(err)
		mustEqual(got, v.Plaintext, "jasypt_strong fixed")
	}

	data, err := json.MarshalIndent(f, "", "  ")
	check(err)
	check(os.WriteFile(*out, append(data, '\n'), 0o644))
	fmt.Printf("wrote %s (%d vectors, %d fixed)\n", *out, len(f.Vectors),
		len(f.Fixed.Pbkdf2Sha256)+len(f.Fixed.Pbkdf1Md5)+len(f.Fixed.AesGcm)+len(f.Fixed.JasyptDes)+len(f.Fixed.JasyptStrong))
}

// ── verbatim copies of GoCrypt internals (gocrypt.go / jasypt_compat.go) ───

// pbkdf2Key implements PBKDF2 key derivation (RFC 2898) — copied from gocrypt.go.
func pbkdf2Key(password, salt []byte, iterations, keyLen int) []byte {
	hashLen := sha256.Size
	numBlocks := (keyLen + hashLen - 1) / hashLen

	dk := make([]byte, 0, numBlocks*hashLen)

	for block := 1; block <= numBlocks; block++ {
		dk = append(dk, pbkdf2F(password, salt, iterations, block)...)
	}

	return dk[:keyLen]
}

func pbkdf2F(password, salt []byte, iterations, blockNum int) []byte {
	h := hmac.New(sha256.New, password)

	h.Write(salt)
	h.Write([]byte{byte(blockNum >> 24), byte(blockNum >> 16), byte(blockNum >> 8), byte(blockNum)})
	u := h.Sum(nil)

	result := make([]byte, len(u))
	copy(result, u)

	for i := 2; i <= iterations; i++ {
		h.Reset()
		h.Write(u)
		u = h.Sum(nil)
		for j := range result {
			result[j] ^= u[j]
		}
	}

	return result
}

// pbkdf1MD5 mirrors JasyptEncryptor.deriveKeyAndIV from jasypt_compat.go.
func pbkdf1MD5(password string, salt []byte, iterations int) []byte {
	data := append([]byte(password), salt...)

	hash := md5.Sum(data)
	result := hash[:]

	for i := 1; i < iterations; i++ {
		hash = md5.Sum(result)
		result = hash[:]
	}
	return result
}

func pkcs5Pad(data []byte, blockSize int) []byte {
	padding := blockSize - (len(data) % blockSize)
	padText := make([]byte, padding)
	for i := range padText {
		padText[i] = byte(padding)
	}
	return append(data, padText...)
}

// gcmEncryptFixed mirrors Encryptor.Encrypt with an injected salt and nonce.
func gcmEncryptFixed(password string, salt, nonce []byte, iterations, keySize int, plaintext string) string {
	key := pbkdf2Key([]byte(password), salt, iterations, keySize)
	block, err := aes.NewCipher(key)
	check(err)
	gcm, err := cipher.NewGCM(block)
	check(err)
	ciphertext := gcm.Seal(nil, nonce, []byte(plaintext), nil)

	combined := make([]byte, 0, len(salt)+len(nonce)+len(ciphertext))
	combined = append(combined, salt...)
	combined = append(combined, nonce...)
	combined = append(combined, ciphertext...)
	return base64.StdEncoding.EncodeToString(combined)
}

// desEncryptFixed mirrors JasyptEncryptor.Encrypt with an injected salt.
func desEncryptFixed(password string, salt []byte, iterations int, plaintext string) string {
	derived := pbkdf1MD5(password, salt, iterations)
	key, iv := derived[:8], derived[8:16]
	block, err := des.NewCipher(key)
	check(err)
	padded := pkcs5Pad([]byte(plaintext), des.BlockSize)
	mode := cipher.NewCBCEncrypter(block, iv)
	ciphertext := make([]byte, len(padded))
	mode.CryptBlocks(ciphertext, padded)

	combined := make([]byte, 0, len(salt)+len(ciphertext))
	combined = append(combined, salt...)
	combined = append(combined, ciphertext...)
	return base64.StdEncoding.EncodeToString(combined)
}

// strongEncryptFixed mirrors JasyptStrongEncryptor.Encrypt with an injected salt.
func strongEncryptFixed(password string, salt []byte, iterations int, plaintext string) string {
	derived := pbkdf2Key([]byte(password), salt, iterations, 48)
	key := derived[:32]
	iv := derived[32:48]
	block, err := aes.NewCipher(key)
	check(err)
	padded := pkcs5Pad([]byte(plaintext), block.BlockSize())
	mode := cipher.NewCBCEncrypter(block, iv)
	ciphertext := make([]byte, len(padded))
	mode.CryptBlocks(ciphertext, padded)

	combined := make([]byte, 0, len(salt)+len(ciphertext))
	combined = append(combined, salt...)
	combined = append(combined, ciphertext...)
	return base64.StdEncoding.EncodeToString(combined)
}

func unhex(s string) []byte {
	b, err := hex.DecodeString(s)
	check(err)
	return b
}

func check(err error) {
	if err != nil {
		panic(err)
	}
}

func mustEqual(got, want, what string) {
	if got != want {
		panic(fmt.Sprintf("%s: got %q want %q", what, got, want))
	}
}

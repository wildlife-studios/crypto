package crypto

import (
	"crypto/rand"
	"crypto/sha512"
	"crypto/subtle"
	"encoding/base64"
	"fmt"
	"strings"

	"golang.org/x/crypto/argon2"
	"golang.org/x/crypto/chacha20poly1305"
)

// InvalidEncodingError is the error thrown when trying to parse an
// Argon2 hash if the string provided does not conform to the reference
// implementation encoding.
// You can call Unwrap() to see specifically which part of the
// string is malformed.
type InvalidEncodingError struct {
	original error
}

func (e InvalidEncodingError) Error() string {
	return fmt.Sprintf("can't compare hashes because the saved hash is malformed: %s", e.original)
}

func (e InvalidEncodingError) Unwrap() error {
	return e.original
}

// XChacha is the cryptographic algorithm recommended at WLS to perform
// encryption.
//
// It is safe to call the methods of XChacha with a nil value. This will modify the pointer
// to point to valid XChacha struct as constructed by the NewXChacha() function.
type XChacha struct{}

// NewXChacha gives you a XChacha with which to encrypt your data.
func NewXChacha() *XChacha {
	return &XChacha{}
}

// Encrypt will convert a message to a ciphertext.
// The key must be stored safely, this generally means using Vault.
func (c *XChacha) Encrypt(msg []byte, key []byte) ([]byte, error) {
	if c == nil {
		c = NewXChacha()
	}

	if len(key) != 32 {
		return nil, fmt.Errorf("wrong key length. expected 32 bytes, got: %d", len(key))
	}
	aead, err := chacha20poly1305.NewX(key)
	if err != nil {
		return nil, err
	}
	// Select a random nonce, and leave capacity for the ciphertext.
	nonce := make([]byte, aead.NonceSize(), aead.NonceSize()+len(msg)+aead.Overhead())
	if _, err := rand.Read(nonce); err != nil {
		return nil, err
	}

	return aead.Seal(nonce, nonce, msg, nil), nil
}

// Decrypt converts a ciphertext back to the plaintext. It will fail
// if the key is not 32 bytes long, if the ciphertext has been tampered with
// or if the ciphertext is malformed.
func (c *XChacha) Decrypt(ciphertext []byte, key []byte) ([]byte, error) {
	if c == nil {
		c = NewXChacha()
	}

	if len(key) != 32 {
		return nil, fmt.Errorf("wrong key length. expected 32 bytes, got: %d", len(key))
	}
	aead, err := chacha20poly1305.NewX(key)
	if err != nil {
		return nil, err
	}

	if len(ciphertext) < aead.NonceSize() {
		return nil, fmt.Errorf("malformed ciphertext: it is shorter than the nonce")
	}
	nonce := ciphertext[:aead.NonceSize()]
	msg := ciphertext[aead.NonceSize():]

	// Decrypt the message and check it wasn't tampered with.
	return aead.Open(nil, nonce, msg, nil)
}

// SHA512 has hashing and comparing methods using the SHA2-512 algorithm.
// SHA512 should be used to hash random data.
// If you need to hash non-random data, please look at Argon2.
//
// It is safe to call the methods of SHA512 with a nil value. This will modify the pointer
// to point to valid SHA512 struct as constructed by the NewSHA512() function.
type SHA512 struct{}

// NewSHA512 will return a SHA512 struct.
// SHA512 should be used to hash random data.
// If you need to hash non-random data, please look at Argon2.
func NewSHA512() *SHA512 {
	return &SHA512{}
}

// Hash will give you a hash of your message of exactly 64 bytes using
// the SHA2 algorithm. This should be used to hash random, uniform data.
// Examples include UUIDs, random numbers, MAC addresses.
func (s *SHA512) Hash(msg []byte) []byte {
	if s == nil {
		s = NewSHA512()
	}
	h := sha512.Sum512(msg)
	return h[:]
}

// Compare a message with a hash. Will return true if SHA512(msg) is
// equal to the hash. Guarantees the comparison to be in constant time.
func (s *SHA512) Compare(msg []byte, hash []byte) bool {
	if s == nil {
		s = NewSHA512()
	}
	recreated := s.Hash(msg)
	return subtle.ConstantTimeCompare(hash, recreated) == 1
}

// Argon2 is the algorithm chosen as the Key Derivation Function for Wildlife Studios.
// Key Derivation Functions and are a subset of /ash functions which should be used to
// hash non-random data, such as passwords, IP addresses or geolocation.
//
// It is safe to call the methods of Argon2 with a nil value. This will modify the pointer
// to point to valid Argon2 struct as constructed by the NewArgon2() function.
type Argon2 struct {
	// Iterations is called T in bibliography
	Iterations uint32
	// MemoryKB is called M in bibliography
	MemoryKB      uint32
	Threads       uint8
	keyLen        uint32
	saltSizeBytes int8
}

// NewArgon2 will give you an Argon2 to hash your data. This constructor will set
// the recommended parameters for Argon2, but you can tweak Iterations, Memory and Threads
// to adjust them to your performance needs.
// Argon2 is the algorithm chosen as the Key Derivation Function for Wildlife Studios.
// Key Derivation Functions and are a subset of /ash functions which should be used to
// hash non-random data, such as passwords, IP addresses or geolocation.
func NewArgon2() *Argon2 {
	return &Argon2{
		Iterations:    1,
		MemoryKB:      64 * 1024,
		Threads:       4,
		keyLen:        32,
		saltSizeBytes: 16,
	}
}

func (a *Argon2) encode(hash []byte, salt []byte) string {
	// for some reason the guys at the reference implementation
	// do not use padding characters. why is anybodies' guess ¯\_(ツ)_/¯
	// https://github.com/P-H-C/phc-winner-argon2/
	b64Salt := base64.RawStdEncoding.EncodeToString(salt)
	b64Hash := base64.RawStdEncoding.EncodeToString(hash)

	format := "$argon2id$v=%d$m=%d,t=%d,p=%d$%s$%s"
	encoded := fmt.Sprintf(format, argon2.Version, a.MemoryKB, a.Iterations, a.Threads, b64Salt, b64Hash)
	return encoded
}

// Hash will give you a hash of your message encoded using the reference
// Argon2 encoding.
func (a *Argon2) Hash(msg []byte) (string, error) {
	if a == nil {
		a = NewArgon2()
	}
	salt := make([]byte, a.saltSizeBytes)
	if _, err := rand.Read(salt); err != nil {
		return "", err
	}
	hash := argon2.IDKey(msg, salt, a.Iterations, a.MemoryKB, a.Threads, a.keyLen)
	encoded := a.encode(hash, salt)
	return encoded, nil
}

// HashWithFixedSalt allows you to use Argon2 using a fixed salt.
// The salt must be exactly 16 bytes long.
// *WARNING* use only if you are using Argon2 to index encrypted data.
// Use different salts to index different columns.
func (a *Argon2) HashWithFixedSalt(msg []byte, salt []byte) (string, error) {
	if a == nil {
		a = NewArgon2()
	}
	if len(salt) != int(a.saltSizeBytes) {
		return "", fmt.Errorf("wrong salt size. expected %d, got %d", a.saltSizeBytes, len(salt))
	}
	hash := argon2.IDKey(msg, salt, a.Iterations, a.MemoryKB, a.Threads, a.keyLen)
	encoded := a.encode(hash, salt)
	return encoded, nil
}

// Compare a message with a hash. Will return true if Argon2(msg) is
// equal to the hash. Guarantees the comparison to be in constant time.
func (a *Argon2) Compare(msg []byte, saved string) (bool, error) {
	if a == nil {
		a = NewArgon2()
	}
	parts := strings.Split(saved, "$")
	argon := Argon2{}
	_, err := fmt.Sscanf(parts[3], "m=%d,t=%d,p=%d", &argon.MemoryKB, &argon.Iterations, &argon.Threads)
	if err != nil {
		return false, InvalidEncodingError{err}
	}

	salt, err := base64.RawStdEncoding.DecodeString(parts[4])
	if err != nil {
		return false, InvalidEncodingError{err}
	}

	old, err := base64.RawStdEncoding.DecodeString(parts[5])
	if err != nil {
		return false, InvalidEncodingError{err}
	}
	argon.keyLen = uint32(len(old))
	recreated := argon2.IDKey(msg, salt, argon.Iterations, argon.MemoryKB, argon.Threads, argon.keyLen)
	return subtle.ConstantTimeCompare(old, recreated) == 1, nil
}

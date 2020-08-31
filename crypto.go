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

func (InvalidEncodingError) Error() string {
	return "can't compare hashes because the saved hash is malformed"
}

func (e InvalidEncodingError) Unwrap() error {
	return e.original
}

// XChacha is the cryptographic algorithm recommended at WLS to perform
// encryption.
type XChacha struct{}

// NewXChacha gives you a XChacha with which to encrypt your data.
func NewXChacha() XChacha {
	return XChacha{}
}

// Encrypt will convert a message to a ciphertext.
// The key must be stored safely, this generally means using Vault.
func (c XChacha) Encrypt(msg []byte, key []byte) ([]byte, error) {
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

// Decrypt converts a base64-encoded ciphertext back to the plaintext.
// It will fail if the ciphertext is not well-formed padded base64,
// if the ciphertext is too short or if the ciphertext has been tampered with.
// The hexkey is expected to be a hexadecimal string of exactly 64 characters (32 bytes)
func (c XChacha) Decrypt(ciphertext []byte, key []byte) ([]byte, error) {
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
type SHA512 struct{}

// NewSHA512 will return a SHA512 struct.
func NewSHA512() SHA512 {
	return SHA512{}
}

// Hash will give you a hash of your message of exactly 64 bytes using
// the SHA2 algorithm. This should be used to hash random, uniform data.
// Examples include UUIDs, random numbers, MAC addresses.
func (SHA512) Hash(msg []byte) []byte {
	h := sha512.Sum512(msg)
	return h[:]
}

// Compare a message with a hash. Will return true if SHA512(msg) is
// equal to the hash. Guarantees the comparison to be in constant time.
func (s SHA512) Compare(msg []byte, hash []byte) bool {
	recreated := s.Hash(msg)
	return subtle.ConstantTimeCompare(hash, recreated) == 1
}

// Argon2 is the algorithm chosen as the Key Derivation Function for Wildlife Studios.
// Key Derivation Functions and are a subset of /ash functions which should be used to
// hash non-random data, such as passwords, IP addresses or geolocation.
type Argon2 struct {
	times    uint32
	memory   uint32
	threads  uint8
	keyLen   uint32
	saltSize int8
}

// NewArgon2 will give you an Argon2 to hash your data.
func NewArgon2() Argon2 {
	return Argon2{
		times:    1,
		memory:   64 * 1024,
		threads:  4,
		keyLen:   32,
		saltSize: 16,
	}
}

func (a Argon2) encode(hash []byte, salt []byte) string {
	// for some reason the guys at the reference implementation
	// do not use padding characters. why is anybodies' guess ¯\_(ツ)_/¯
	// https://github.com/P-H-C/phc-winner-argon2/
	b64Salt := base64.RawStdEncoding.EncodeToString(salt)
	b64Hash := base64.RawStdEncoding.EncodeToString(hash)

	format := "$argon2id$v=%d$m=%d,t=%d,p=%d$%s$%s"
	encoded := fmt.Sprintf(format, argon2.Version, a.memory, a.times, a.threads, b64Salt, b64Hash)
	return encoded
}

// Hash will give you a hash of your message encoded using the reference
// Argon2 encoding.
func (a Argon2) Hash(msg []byte) (string, error) {
	salt := make([]byte, a.saltSize)
	if _, err := rand.Read(salt); err != nil {
		return "", err
	}
	hash := argon2.IDKey(msg, salt, a.times, a.memory, a.threads, a.keyLen)
	encoded := a.encode(hash, salt)
	return encoded, nil
}

// Compare a message with a hash. Will return true if Argon2(msg) is
// equal to the hash. Guarantees the comparison to be in constant time.
func (Argon2) Compare(msg []byte, saved string) (bool, error) {
	parts := strings.Split(saved, "$")
	argon := Argon2{}
	_, err := fmt.Sscanf(parts[3], "m=%d,t=%d,p=%d", &argon.memory, &argon.times, &argon.threads)
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
	recreated := argon2.IDKey(msg, salt, argon.times, argon.memory, argon.threads, argon.keyLen)
	return subtle.ConstantTimeCompare(old, recreated) == 1, nil
}

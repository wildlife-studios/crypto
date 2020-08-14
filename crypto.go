package main

import (
	"crypto/rand"
	"crypto/sha512"
	"crypto/subtle"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"strings"

	"golang.org/x/crypto/argon2"
	"golang.org/x/crypto/chacha20poly1305"
)

// CantGetRandomError is the error returned if the system can't cant
// enough random bytes for some reason. You can inspect the original
// errow with Unwrap() if you need to know why.
type CantGetRandomError struct {
	original error
}

func (CantGetRandomError) Error() string {
	return "could not fill buffer with random data"
}

func (e CantGetRandomError) Unwrap() error {
	return e.original
}

type InvalidEncodingError struct {
	original error
}

func (InvalidEncodingError) Error() string {
	return "can't compare hashes because the saved hash is malformed"
}

func (e InvalidEncodingError) Unwrap() error {
	return e.original
}

// Ciphertext is an encrypted slice of bytes
type Ciphertext []byte

// Bytes returns the raw bytes of the ciphertext
func (c Ciphertext) Bytes() []byte { return c }

// Encode will return a padded-base64 version of the ciphertext
func (c Ciphertext) Encode() string { return base64.StdEncoding.EncodeToString(c) }

// XChacha is the cryptographic algorithm recommended at WLS to perform
// encryption.
type Chacha struct{}

// Gives you a Cacha with which to encrypt your data.
func MakeChacha() Chacha {
	return Chacha{}
}

// newKey will give you a new key to use with our cipher.
func (Chacha) newKey() ([]byte, error) {
	key := make([]byte, chacha20poly1305.KeySize)
	_, err := rand.Read(key)
	return key, err
}

// ReadKey will return a byte array from a hexadecimal string.
// Utility function so you can store a hexstring in a JSON in
// Vault and pass it to this function to get it formatted
// the way Chacha likes it.
func (Chacha) ReadKey(hexadecimal string) ([32]byte, error) {
	var key [32]byte
	k, err := hex.DecodeString(hexadecimal)
	copy(key[:], k)
	return key, err
}

// Encrypt will convert a message to a ciphertext which can't be read
// unless the reader has the key.
// The key must be stored safely, this generally means using Vault.
// In any case, the key must be exactly 32 bytes long. If it is not this
// will return an error in runtime.
func (Chacha) Encrypt(msg []byte, key []byte) (Ciphertext, error) {
	aead, err := chacha20poly1305.NewX(key)
	if err != nil {
		return Ciphertext(nil), err
	}

	// Select a random nonce, and leave capacity for the ciphertext.
	nonce := make([]byte, aead.NonceSize(), aead.NonceSize()+len(msg)+aead.Overhead())
	if _, err := rand.Read(nonce); err != nil {
		return Ciphertext(nil), err
	}

	encryptedMsg := aead.Seal(nonce, nonce, msg, nil)
	return Ciphertext(encryptedMsg), nil
}

// Decrypt converts a base64-encoded ciphertext back to the plaintext.
// It will fail if the ciphertext is not correctly with padded base64,
// if the ciphertext is too short or if the ciphertext has been tampered with.
func (c Chacha) Decrypt(ciphertext string, key []byte) ([]byte, error) {
	cipherBytes, err := base64.StdEncoding.DecodeString(ciphertext)
	if err != nil {
		return nil, errors.New("ciphertext not in base64")
	}
	aead, err := chacha20poly1305.NewX(key)
	if err != nil {
		return nil, err
	}

	if len(cipherBytes) < aead.NonceSize() {
		return nil, errors.New("ciphertext too short")
	}
	nonce := cipherBytes[:aead.NonceSize()]
	msg := cipherBytes[aead.NonceSize():]

	// Decrypt the message and check it wasn't tampered with.
	return aead.Open(nil, nonce, msg, nil)
}

// SHAHas represents a SHA2 hash
type SHAHash []byte

// Bytes returns the raw bytes of the hash
func (h SHAHash) Bytes() []byte { return h }

// Encode returns a padded-base64 version of the hash.
func (h SHAHash) Encode() string { return base64.StdEncoding.EncodeToString(h[:]) }

// SHA512 has hashing and comparing methods using the SHA2-512 algorithm.
// SHA512 should be used to hash random data.
// If you need to hash non-random data, please look at Argon2.
type SHA512 struct{}

// MakeSHA512 will return a SHA512 struct.
func MakeSHA512() SHA512 {
	return SHA512{}
}

// Hash will give you a hash of your message of exactly 64 bytes using
// the SHA2 algorithm. This should be used to hash random, uniform data.
// Examples include UUIDs, random numbers, MAC addresses.
func (SHA512) Hash(msg []byte) SHAHash {
	h := sha512.Sum512(msg)
	return SHAHash(h[:])
}

// Compare a msg with a saved base64-encoded hash. Will err if the saved
// string is not in base64.
func (s SHA512) Compare(msg []byte, saved string) (bool, error) {
	recreated := s.Hash(msg).Bytes()
	old, err := base64.StdEncoding.DecodeString(saved)
	if err != nil {
		return false, InvalidEncodingError{err}
	}
	return subtle.ConstantTimeCompare(old, recreated) == 1, nil
}

// Argon2Hash is a string which contains the raw hash and metadata
// of the Argon2 KDF.
type Argon2Hash string

// Bytes returns the Argon2-encoded hash and metadata as raw bytes.
// The bytes are guaranteed to be valid UTF-8 and are just the bytes representation
// of the string returned by Encode()
func (h Argon2Hash) Bytes() []byte { return []byte(h) }

// Encode returns Argon2 hash as a string following the reference encoding
// $argon2<T>$v=<num>$m=<num>,t=<num>,p=<num>$non-padded-base64(salt)$non-padded-base64(hash)
func (h Argon2Hash) Encode() string { return string(h) }

// Argon2 is the algorithm chosen as the KDF for WLS.
// KDF stands for Key Derivation Functions and are a subset of
// hash functions which should be used to hash non-random data,
// such as passwords, IP addresses or geolocation.
type Argon2 struct {
	times, memory uint32
	threads       uint8
	keyLen        uint32
	saltSize      int8
}

// MakeArgon2 will give you an Argon2 struct with secure parameters.
// If you need to hash non-random data and you are not happy with
// the performance these parameters give you, please post in the #security-public
// Slack channel.
func MakeArgon2() Argon2 {
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
	// do not use padding characters. why is anybodies guess.
	// https://github.com/P-H-C/phc-winner-argon2/
	b64Salt := base64.RawStdEncoding.EncodeToString(salt)
	b64Hash := base64.RawStdEncoding.EncodeToString(hash)

	format := "$argon2id$v=%d$m=%d,t=%d,p=%d$%s$%s"
	encoded := fmt.Sprintf(format, argon2.Version, a.memory, a.times, a.threads, b64Salt, b64Hash)
	return encoded
}

// Hash will give you a hash of your message encoded using the reference
// Argon2 encoding.
func (a Argon2) Hash(txt []byte) (Argon2Hash, error) {
	salt := make([]byte, a.saltSize)
	if _, err := rand.Read(salt); err != nil {
		return Argon2Hash(""), CantGetRandomError{err}
	}
	hash := argon2.IDKey(txt, salt, a.times, a.memory, a.threads, a.keyLen)
	encoded := a.encode(hash, salt)
	return Argon2Hash(encoded), nil
}

func (a Argon2) hash(txt []byte, salt []byte) []byte {
	hash := argon2.IDKey(txt, salt, a.times, a.memory, a.threads, a.keyLen)
	return hash
}

// Compare will return True when the msg results in the same hash than the
// saved hash. The saved string must have been encoded using the reference
// Argon2 encoding.
func (a Argon2) Compare(msg []byte, saved string) (bool, error) {
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
	recreated := argon.hash(msg, salt)

	return subtle.ConstantTimeCompare(old, recreated) == 1, nil
}

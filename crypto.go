package main

import (
	"crypto/rand"
	"crypto/sha512"
	"encoding/base64"
	"errors"

	"golang.org/x/crypto/argon2"
	"golang.org/x/crypto/chacha20poly1305"
)

type Ciphertext []byte

func (c Ciphertext) Bytes() []byte  { return c }
func (c Ciphertext) Base64() string { return base64.StdEncoding.EncodeToString(c) }

// Cipher provides methods to encrypt/decrypt information.
type Chacha struct{}

// NewKey will give you a new key to use with our cipher.
func (Chacha) NewKey() ([]byte, error) {
	key := make([]byte, chacha20poly1305.KeySize)
	_, err := rand.Read(key)
	return key, err
}

// Encrypt will convert a message to a ciphertext which can't be read
// unless the reader has the key.
// The key must be stored safely, this generally means using Vault.
// You can get a new key using the Chacha.NewKey() method.
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

// Decrypt takes a ciphertext and will convert it back to a simple byte slice
// provided you have the correct key.
func (Chacha) Decrypt(c Ciphertext, key []byte) ([]byte, error) {
	aead, err := chacha20poly1305.NewX(key)
	if err != nil {
		return nil, err
	}

	cipherBytes := c.Bytes()
	if len(cipherBytes) < aead.NonceSize() {
		panic("ciphertext too short")
	}
	nonce := cipherBytes[:aead.NonceSize()]
	msg := cipherBytes[aead.NonceSize():]

	// Decrypt the message and check it wasn't tampered with.
	return aead.Open(nil, nonce, msg, nil)
}

type Hash512 [64]byte

func (c Hash512) Bytes() [64]byte { return c }
func (c Hash512) Base64() string  { return base64.StdEncoding.EncodeToString(c[:]) }

type SHA512 struct{}

// Hash will give you a hash of your message of exactly 64 bytes using
// the SHA2 algorithm. This should be used to hash random, uniform data.
// Examples include UUIDs, random numbers, MAC addresses.
func (SHA512) Hash(msg []byte) Hash512 {
	return Hash512(sha512.Sum512(msg))
}

type Hash256 [32]byte

func (c Hash256) Bytes() [32]byte { return c }
func (c Hash256) Base64() string  { return base64.StdEncoding.EncodeToString(c[:]) }

type Argon2 struct{}

// Hash will give you a hash of your message of exactly 32 bytes using
// the Argon2 KDF. This should be used to hash non random data.
// Examples include user passwords, IPs, geolocations.
// Keep in mind this function is ~5 orders of magnitude slower than
// SHA512. A Macbook can process only 73 of these per second.
// If you can't afford such an slow algorithm for non random data,
// do NOT use SHA512, contact the application security team at #security-public
// instead.
func (Argon2) Hash(txt []byte, salt []byte) (Hash256, error) {
	var arr [32]byte
	h := argon2.IDKey(txt, salt, 1, 64*1024, 4, 32)
	amount := copy(arr[:], h)
	if amount != 32 {
		return arr, errors.New("did not copy entire hash into memory")
	}
	return Hash256(arr), nil
}

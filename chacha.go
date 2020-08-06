package main

import (
	"crypto/rand"
	"encoding/base64"

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

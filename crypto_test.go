package main

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/base64"
	"testing"
)

func BenchmarkSHA512With16Bytes(b *testing.B) {
	b.ReportAllocs()
	message := []byte("YELLOW SUBMARINE")
	for n := 0; n < b.N; n++ {
		SHA512{}.Hash(message)
	}
}

func BenchmarkSHA512With32Bytes(b *testing.B) {
	b.ReportAllocs()
	message := []byte("SO LONG THANKS FOR ALL THE FISH!")
	for n := 0; n < b.N; n++ {
		SHA512{}.Hash(message)
	}
}

func BenchmarkSHA512With64Bytes(b *testing.B) {
	b.ReportAllocs()
	message := []byte("Look at your body - A head full of false imaginings - Dhammapada")
	for n := 0; n < b.N; n++ {
		SHA512{}.Hash(message)
	}
}

func BenchmarkSHA512With128Bytes(b *testing.B) {
	b.ReportAllocs()
	// had to add a space at the end :(
	// also note that naive is non ascii so it uses 2 bytes
	message := []byte("As a general rule, people, even the wicked, are much more naïve and simple-hearted than we suppose. And we ourselves are, too. ")
	for n := 0; n < b.N; n++ {
		SHA512{}.Hash(message)
	}

}

func BenchmarkChachaEncryption(t *testing.B) {
	t.ReportAllocs()
	message := "123e4567-e89b-12d3-a456-426614174000"
	cipher := Chacha{}
	bytes := []byte(message)
	key, _ := cipher.NewKey()
	for n := 0; n < t.N; n++ {
		cipher.Encrypt(bytes, key)
	}
}

func BenchmarkChachaDecryption(t *testing.B) {
	t.ReportAllocs()
	message := "123e4567-e89b-12d3-a456-426614174000"
	bytes := []byte(message)
	cipher := Chacha{}
	key, _ := cipher.NewKey()
	ciphertext, err := cipher.Encrypt(bytes, key)
	if err != nil {
		panic(err)
	}
	for n := 0; n < t.N; n++ {
		cipher.Decrypt(ciphertext, key)
	}
}

func BenchmarkAESEncryption(t *testing.B) {
	t.ReportAllocs()
	message := "123e4567-e89b-12d3-a456-426614174000"
	bytes := []byte(message)
	cipher := Chacha{}
	key, _ := cipher.NewKey()
	for n := 0; n < t.N; n++ {
		encryptAES(bytes, key)
	}
}

func BenchmarkAESDecryption(t *testing.B) {
	t.ReportAllocs()
	message := "123e4567-e89b-12d3-a456-426614174000"
	bytes := []byte(message)
	cipher := Chacha{}
	key, _ := cipher.NewKey()
	ciphertext, err := encryptAES(bytes, key)
	if err != nil {
		panic(err)
	}
	for n := 0; n < t.N; n++ {
		decryptAES(ciphertext, key)
	}
}

// encryptAES provides AES GCM encryption to be a standard against
// which we can compare other encryption algorithms
func encryptAES(msg []byte, key []byte) (string, error) {
	AESCipher, err := aes.NewCipher(key)
	if err != nil {
		return "", err
	}
	nonce := make([]byte, 12)
	if _, err := rand.Read(nonce); err != nil {
		return "", err
	}
	gcm, err := cipher.NewGCM(AESCipher)
	encryptedMsg := gcm.Seal(nonce, nonce, msg, nil)
	return base64.StdEncoding.EncodeToString(encryptedMsg), nil
}

// decryptAES provides AES GCM decryption to be a standard against
// which we can compare other decryption algorithms
func decryptAES(encrypted string, key []byte) ([]byte, error) {
	msg, _ := base64.StdEncoding.DecodeString(encrypted)
	AESCipher, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	gcm, err := cipher.NewGCM(AESCipher)
	nonce := msg[:gcm.NonceSize()]
	ciphertext := msg[gcm.NonceSize():]
	plaintext, err := gcm.Open(nonce, nonce, ciphertext, nil)
	return plaintext, err
}

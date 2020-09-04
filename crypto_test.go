package crypto

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/base64"
	"testing"

	"golang.org/x/crypto/chacha20poly1305"
)

func TestComparingArgon2Works(t *testing.T) {
	argon2 := NewArgon2()
	text := []byte("you should say nothing mortal")
	hash, err := argon2.Hash(text)
	if err != nil {
		t.Errorf("could not has with argon. err: %s", err)
	}
	equal, err := argon2.Compare(text, hash)
	if err != nil || !equal {
		t.Errorf("did not deem the messages as equals. err: %s", err)
	}
	anotherText := []byte("on my window pane")
	equal, err = argon2.Compare(anotherText, hash)
	if err != nil || equal {
		t.Errorf("deemed messages as equals. err: %s", err)
	}

}

func TestComparingSHA512Works(t *testing.T) {
	sha512 := NewSHA512()
	text := []byte("you should say nothing mortal")
	hash := sha512.Hash(text)
	equal := sha512.Compare(text, hash)
	if !equal {
		t.Errorf("did not deem the messages as equals")
	}
	anotherText := []byte("on my window pane")
	equal = sha512.Compare(anotherText, hash)
	if equal {
		t.Errorf("deemed messages as equals")
	}
}

func TestEncryptAndDecryptWork(t *testing.T) {
	chacha, key := getMeSomeXChacha(t)
	text := []byte("something almost, but not quite entirely unlike tea")
	ciphertext, err := chacha.Encrypt(text, key)
	if err != nil {
		t.Error(err)
	}
	plain, err := chacha.Decrypt(ciphertext, key)
	if err != nil {
		t.Error(err)
	}
	if bytes.Compare(plain, text) != 0 {
		t.Errorf("decrypting the cipher text did not result in plain text")
	}
}

func TestModifyingCipherTextWithXXChachaFails(t *testing.T) {
	chacha, key := getMeSomeXChacha(t)
	ciphertext, err := chacha.Encrypt([]byte("Nothing going to change"), key)
	if err != nil {
		t.Error(err)
	}

	// tamper with it
	ciphertext[1] = byte(0xDE)
	ciphertext[2] = byte(0xAD)
	ciphertext[3] = byte(0xBE)
	ciphertext[4] = byte(0xEF)
	_, err = chacha.Decrypt(ciphertext, key)
	if err == nil {
		t.Errorf("did not detect tampering")
	}
}

func BenchmarkArgon2With16Bytes(b *testing.B) {
	b.ReportAllocs()
	message := []byte("YELLOW SUBMARINE")
	argon2 := NewArgon2()
	for n := 0; n < b.N; n++ {
		argon2.Hash(message)
	}
}

func BenchmarkSHA512With16Bytes(b *testing.B) {
	b.ReportAllocs()
	message := []byte("YELLOW SUBMARINE")
	sha512 := NewSHA512()
	for n := 0; n < b.N; n++ {
		sha512.Hash(message)
	}
}

func BenchmarkSHA512With32Bytes(b *testing.B) {
	b.ReportAllocs()
	message := []byte("SO LONG THANKS FOR ALL THE FISH!")
	sha512 := NewSHA512()
	for n := 0; n < b.N; n++ {
		sha512.Hash(message)
	}
}

func BenchmarkSHA512With64Bytes(b *testing.B) {
	b.ReportAllocs()
	message := []byte("Look at your body - A head full of false imaginings - Dhammapada")
	sha512 := NewSHA512()
	for n := 0; n < b.N; n++ {
		sha512.Hash(message)
	}
}

func BenchmarkSHA512With128Bytes(b *testing.B) {
	b.ReportAllocs()
	// had to add a space at the end :(
	// also note that naive is non ascii so it uses 2 bytes
	message := []byte("As a general rule, people, even the wicked, are much more naïve and simple-hearted than we suppose. And we ourselves are, too. ")
	sha512 := NewSHA512()
	for n := 0; n < b.N; n++ {
		sha512.Hash(message)
	}
}

func BenchmarkXChachaEncryption(t *testing.B) {
	t.ReportAllocs()
	message := "123e4567-e89b-12d3-a456-426614174000"
	bytes := []byte(message)
	cipher, key := getMeSomeXChacha(nil)
	for n := 0; n < t.N; n++ {
		cipher.Encrypt(bytes, key)
	}
}

func BenchmarkXChachaDecryption(t *testing.B) {
	t.ReportAllocs()
	message := "123e4567-e89b-12d3-a456-426614174000"
	bytes := []byte(message)
	cipher, key := getMeSomeXChacha(nil)
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
	key, _ := newXChachaKey()
	for n := 0; n < t.N; n++ {
		encryptAES(bytes, key)
	}
}

func BenchmarkAESDecryption(t *testing.B) {
	t.ReportAllocs()
	message := "123e4567-e89b-12d3-a456-426614174000"
	bytes := []byte(message)
	key, _ := newXChachaKey()
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

// getMeSomeXChacha returns a new *XChacha instance and a key
// Panics if t == nil.
func getMeSomeXChacha(t *testing.T) (*XChacha, []byte) {
	if t != nil {
		t.Helper()
	}
	chacha := NewXChacha()
	key, err := newXChachaKey()
	if err != nil {
		t.Error(err)
	}
	return chacha, key
}

// newXChachaKey will give you a new key to use with our cipher.
func newXChachaKey() ([]byte, error) {
	key := make([]byte, chacha20poly1305.KeySize)
	_, err := rand.Read(key)
	return key, err
}

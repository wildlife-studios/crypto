
package crypto // import "git.topfreegames.com/security/crypto"


TYPES

type Argon2 struct {
	// Has unexported fields.
}
    Argon2 is the algorithm chosen as the Key Derivation Function for Wildlife
    Studios. Key Derivation Functions and are a subset of /ash functions which
    should be used to hash non-random data, such as passwords, IP addresses or
    geolocation.

    It is safe to call the methods of Argon2 with a nil value. This will modify
    the pointer to point to valid Argon2 struct as constructed by the
    NewArgon2() function.

func NewArgon2() *Argon2
    NewArgon2 will give you an Argon2 to hash your data. Argon2 is the algorithm
    chosen as the Key Derivation Function for Wildlife Studios. Key Derivation
    Functions and are a subset of /ash functions which should be used to hash
    non-random data, such as passwords, IP addresses or geolocation.

func (a *Argon2) Compare(msg []byte, saved string) (bool, error)
    Compare a message with a hash. Will return true if Argon2(msg) is equal to
    the hash. Guarantees the comparison to be in constant time.

func (a *Argon2) Hash(msg []byte) (string, error)
    Hash will give you a hash of your message encoded using the reference Argon2
    encoding.

type InvalidEncodingError struct {
	// Has unexported fields.
}
    InvalidEncodingError is the error thrown when trying to parse an Argon2 hash
    if the string provided does not conform to the reference implementation
    encoding. You can call Unwrap() to see specifically which part of the string
    is malformed.

func (e InvalidEncodingError) Error() string

func (e InvalidEncodingError) Unwrap() error

type SHA512 struct{}
    SHA512 has hashing and comparing methods using the SHA2-512 algorithm.
    SHA512 should be used to hash random data. If you need to hash non-random
    data, please look at Argon2.

    It is safe to call the methods of SHA512 with a nil value. This will modify
    the pointer to point to valid SHA512 struct as constructed by the
    NewSHA512() function.

func NewSHA512() *SHA512
    NewSHA512 will return a SHA512 struct. SHA512 should be used to hash random
    data. If you need to hash non-random data, please look at Argon2.

func (s *SHA512) Compare(msg []byte, hash []byte) bool
    Compare a message with a hash. Will return true if SHA512(msg) is equal to
    the hash. Guarantees the comparison to be in constant time.

func (s *SHA512) Hash(msg []byte) []byte
    Hash will give you a hash of your message of exactly 64 bytes using the SHA2
    algorithm. This should be used to hash random, uniform data. Examples
    include UUIDs, random numbers, MAC addresses.

type XChacha struct{}
    XChacha is the cryptographic algorithm recommended at WLS to perform
    encryption.

    It is safe to call the methods of XChacha with a nil value. This will modify
    the pointer to point to valid XChacha struct as constructed by the
    NewXChacha() function.

func NewXChacha() *XChacha
    NewXChacha gives you a XChacha with which to encrypt your data.

func (c *XChacha) Decrypt(ciphertext []byte, key []byte) ([]byte, error)
    Decrypt converts a ciphertext back to the plaintext. It will fail if the key
    is not 32 bytes long, if the ciphertext has been tampered with or if the
    ciphertext is malformed.

func (c *XChacha) Encrypt(msg []byte, key []byte) ([]byte, error)
    Encrypt will convert a message to a ciphertext. The key must be stored
    safely, this generally means using Vault.


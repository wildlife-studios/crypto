# Crypto

This repository holds the security crypto library for Wildlife.

You can read more about our [Cryptography recommendations at our Wiki](https://wiki.wildlifestudios.com/display/SPCNPRVCY/How+to+Store+Private+Data)

## How to use
There are three use cases.

* Encryption
* Hashing random data such as tokens and UUIDs
* Hashing non random data such as IPs and passwords

### How do I encrypt/decrypt data?
You should first generate a secret key and store it in Vault. The key must be 32 bytes long and for ease of use you can store it as a string.

This little snippet should provide you with a nice JSON with a key to put in Vault:
```
python3 -c 'import secrets;r=secrets.token_hex(32);print(f"{{\"key\": \"{r}\"}}")'
```

Then, in your application, you can use `crypto`
```
import "git.topfreegames.com/security/crypto"

var cipher = crypto.NewXChacha()

func EncryptAndStore(id, msg string, storage Storager, vault Vaulter) error {
     // get the key from vault
     // if possible, leave the key in the stack, but if performance
     // obliges, you can do this one and leave it as a constant
     key, err := vault.GetKey()
     if err != nil {
          return errors.New("could not read key")
     }
     // encrypt!
     ciphertext, err := cipher.Encrypt(msg, key)
     if err != nil {
          return errors.New("could not encrypt")
     }
     // store the base64 encoded
     storage.Save(id, ciphertext)
}


func Retrieve(id string, storage Storager, vault Vaulter) (string, error) {
     // get the key from vault
     // if possible, leave the key in the stack, but if performance
     // obliges, you can do this one and leave it as a constant
     key, err := vault.GetKey()
     if err != nil {
          return "", errors.New("could not read key")
     }
     ciphertext := storage.Retrieve(id)
     plaintext, err := cipher.Decrypt(ciphertext, key)
     if err != nil {
          return "", errors.New("could not decrypt")
     }
     return plaintext, err
}
```

### How do I hash data?

#### I promise, promise, promise my data is random

Then just use SHA512. It is fast and simple.

```
import "git.topfreegames.com/security/crypto"

var sha512 = crypto.NewSHA512()

func HashToken(user, token string, storage Storager)  {
     hash := sha512.Hash(msg)
     storage.Save(user, hash)
}

func CompareToken(user, token string, storage Storager) (bool, error) {
     saved := storage.Retrieve(user)
     return sha512.Compare([]byte(token), saved)
}
```

### I'm not so sure my data is random
If you are storing things like passwords, IPs, geolocation and the like and you don't need to retrieve
the original values, you can use `Argon2`.

The password use case is obvious, but you may also be building a fingerpriting service which is based on the IPs
of the users.


```
import "git.topfreegames.com/security/crypto"

var argon2 = crypto.NewArgon2()

func HashPassword(user, token string, storage Storager)  {
     hash := argon2.Hash(msg)
     storage.Save(user, hash)
}

func ComparePassword(user, token string, storage Storager) (bool, error) {
     saved := storage.Retrieve(user)
     return sha512.Compare([]byte(token), saved)
}
```

### I need to encrypted data on my DB

Due to the internals of most encryption algorithms, the output of an encrypt function is generally non-deterministic. 
This means that Encrypt(“my message”, “my key”) will yield different results when called several times.

To index encrypted data, one strategy is to use a *blind index*. Create a new column and store the hashes of data
there. You can use the index to find the encrypted data, and decrypt it as necessary in your app.

As in other instances when you need hash functions, you need to check if your data is random.

If your data is random, use `SHA512` as described above.
If your data is not random, use `Argon2` but use the `HashWithFixedSalt` method and provide a salt yourself.


## Benchmarks
```
BenchmarkArgon2With16Bytes-12     	      73	  17387010 ns/op	67118640 B/op	      50 allocs/op
BenchmarkSHA512With16Bytes-12     	 4869639	       239 ns/op	       0 B/op	       0 allocs/op
BenchmarkSHA512With32Bytes-12     	 5005380	       240 ns/op	       0 B/op	       0 allocs/op
BenchmarkSHA512With64Bytes-12     	 4914045	       237 ns/op	       0 B/op	       0 allocs/op
BenchmarkSHA512With128Bytes-12    	 2746240	       435 ns/op	       0 B/op	       0 allocs/op
BenchmarkChachaEncryption-12      	 3179156	       376 ns/op	     112 B/op	       2 allocs/op
BenchmarkChachaDecryption-12      	 1860862	       645 ns/op	     496 B/op	       6 allocs/op
```

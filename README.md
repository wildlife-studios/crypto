# Crypto

This repository holds the security crypto library for Wildlife.

You can read more about our (Cryptography recommendations at our Wiki)[https://wiki.wildlifestudios.com/display/SPCNPRVCY/How+to+Store+Private+Data]

## How to use
The library has extensive documentation. There are three use cases.

* Encryption
* Hashing random data such as tokens and UUIDs
* Hashing non random data such as IPs and passwords

Every type returned by the library has both a `Bytes()` and an `Encode()` method.

You should mostly use the `Encode()` method to save the information to a permanent storage.
`Bytes()` should only be used if you need to manually encode the bytes to keep backward compatibility.


### How do I encrypt/decrypt data?
You should first generate a secret key and store it in Vault. The key must be 32 bytes long and for ease of use you can store it as a string.

This little snippet should provide you with a nice JSON with a key to put in Vault:
```
python3 -c 'import secrets;r=secrets.token_hex(32);print(f"{{\"key\": \"{r}\"}}")'
```

Then, in your application, you can use `crypto`
```
import "git.topfreegames.com/security/crypto"

var cipher = crypto.MakeChacha()

func EncryptAndStore(id, msg string, storage Storager, vault Vaulter) error {
     // get the key from vault and parse it with the cipher
     // if possible, leave the key in the stack, but if performance
     // obliges, you can do this one and leave it as a constant
     key, err := cipher.ReadKey(vault.GetKey())
     if err != nil {
          return errors.New("could not read key")
     }
     // encrypt
     ciphertext, err := cipher.Encrypt(msg, key)
     if err != nil {
          return errors.New("could not encrypt")
     }
     // store the base64 encoded
     storage.Save(id, ciphertext.Encode())
}


func Retrieve(id string, storage Storager, vault Vaulter) (string, error) {
     // get the key from vault and parse it with the cipher
     // if possible, leave the key in the stack, but if performance
     // obliges, you can do this one and leave it as a constant
     key, err := cipher.ReadKey(vault.GetKey())
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

The just use SHA512. It is fast and simple.

```
import "git.topfreegames.com/security/crypto"

var sha512 = crypto.MakeSHA512()

func HashToken(user, token string, storage Storager)  {
     hash := sha512.Hash(msg)
     storage.Save(user, hash.Encode())
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

var argon2 = crypto.MakeSHA512()

func HashPasswoed(user, token string, storage Storager)  {
     hash := argon2.Hash(msg)
     storage.Save(user, hash.Encode())
}

func ComparePassword(user, token string, storage Storager) (bool, error) {
     saved := storage.Retrieve(user)
     return sha512.Compare([]byte(token), saved)
}
```
package main

import (
	"crypto/sha512"
	"encoding/base64"
)

type Hash512 [64]byte

func (c Hash512) Bytes() [64]byte { return c }
func (c Hash512) Base64() string  { return base64.StdEncoding.EncodeToString(c[:]) }

type SHA512 struct{}

func (SHA512) Hash(msg []byte) Hash512 {
	return Hash512(sha512.Sum512(msg))
}

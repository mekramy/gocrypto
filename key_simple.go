package gocrypto

import (
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
)

type SimpleLength int

const (
	Simple16 SimpleLength = 16
	Simple24 SimpleLength = 24
	Simple32 SimpleLength = 32
)

// NewSimpleKey generate new random key.
func NewSimpleKey(length SimpleLength) (SimpleKey, error) {
	key := make(SimpleKey, length)
	_, err := rand.Read(key)
	if err != nil {
		return nil, err
	}
	return key, nil
}

// SimpleKey implementation of the Key interface for simple keys.
type SimpleKey []byte

// Bytes returns the key as a byte slice.
func (k SimpleKey) Bytes() []byte {
	return k
}

// Hex returns the key as a hex string.
func (k SimpleKey) Hex() string {
	return hex.EncodeToString(k)
}

// Base64 returns the key as a base64 string.
func (k SimpleKey) Base64() string {
	return base64.StdEncoding.EncodeToString(k)
}

// String implement fmt.Stringer interface.
func (k SimpleKey) String() string {
	return k.Hex()
}

package gocrypto

import (
	"crypto/hmac"
	"fmt"
)

type hmacHasher struct {
	key  []byte
	algo HashingAlgo
}

func (h hmacHasher) Hash(data []byte) ([]byte, error) {
	if len(h.key) == 0 || string(h.key) == "" {
		return nil, fmt.Errorf("empty key passed to hasher")
	}

	constructor := HashingInstance(h.algo)
	if constructor == nil {
		return nil, fmt.Errorf("invalid hash algo passed to hasher")
	}

	hasher := hmac.New(constructor, h.key)
	_, err := hasher.Write([]byte(data))
	if err != nil {
		return nil, err
	}

	return base64Encode(hasher.Sum(nil))
}

func (h hmacHasher) Validate(hash, data []byte) (bool, error) {
	newHash, err := h.Hash(data)
	if err != nil {
		return false, err
	}

	return hmac.Equal(hash, newHash), nil
}

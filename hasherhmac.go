package gocrypto

import (
	"crypto/hmac"
	"fmt"
)

type hmacHasher struct {
	key  []byte
	algo HashingAlgo
}

func (driver hmacHasher) Hash(data []byte) ([]byte, error) {
	if len(driver.key) == 0 || string(driver.key) == "" {
		return nil, fmt.Errorf("empty key passed to hasher")
	}

	constructor := HashingInstance(driver.algo)
	if constructor == nil {
		return nil, fmt.Errorf("invalid hash algo passed to hasher")
	}

	hasher := hmac.New(constructor, driver.key)
	_, err := hasher.Write([]byte(data))
	if err != nil {
		return nil, err
	}

	return base64Encode(hasher.Sum(nil))
}

func (driver hmacHasher) Validate(hash, data []byte) (bool, error) {
	newHash, err := driver.Hash(data)
	if err != nil {
		return false, err
	}

	return hmac.Equal(hash, newHash), nil
}

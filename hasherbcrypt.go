package gocrypto

import (
	"golang.org/x/crypto/bcrypt"
)

type bcryptHasher struct {
	cost int
}

func (b bcryptHasher) Hash(data []byte) ([]byte, error) {
	encrypted, err := bcrypt.GenerateFromPassword(data, b.cost)
	if err != nil {
		return nil, err
	}

	return base64Encode(encrypted)
}

func (b bcryptHasher) Validate(hash, data []byte) (bool, error) {
	raw, err := base64Decode(hash)
	if err != nil {
		return false, err
	}
	err = bcrypt.CompareHashAndPassword(raw, data)
	return err == nil, nil
}

package gocrypto

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/rand"
	"fmt"
	"io"
)

type symmetricDriver struct {
	key    SimpleKey
	signer HashingAlgo
}

func (s symmetricDriver) Sign(data []byte) ([]byte, error) {
	constructor := HashingInstance(s.signer)
	if constructor == nil {
		return nil, fmt.Errorf("invalid hash algo passed to driver")
	}

	hasher := hmac.New(constructor, s.key)
	_, err := hasher.Write(data)
	if err != nil {
		return nil, err
	}

	return hasher.Sum(nil), nil
}

func (s symmetricDriver) ValidateSignature(data []byte, signature []byte) (bool, error) {
	constructor := HashingInstance(s.signer)
	if constructor == nil {
		return false, fmt.Errorf("invalid hash algo passed to driver")
	}

	hasher := hmac.New(constructor, s.key)
	_, err := hasher.Write(data)
	if err != nil {
		return false, err
	}

	return hmac.Equal(signature, hasher.Sum(nil)), nil
}

func (s symmetricDriver) Encrypt(data []byte) ([]byte, error) {
	block, err := aes.NewCipher(s.key)
	if err != nil {
		return nil, err
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}

	nonce := make([]byte, gcm.NonceSize())
	_, err = io.ReadFull(rand.Reader, nonce)
	if err != nil {
		return nil, err
	}

	return gcm.Seal(nonce, nonce, data, nil), nil
}

func (s symmetricDriver) Decrypt(data []byte) ([]byte, error) {
	block, err := aes.NewCipher(s.key)
	if err != nil {
		return nil, err
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}

	nonce, ciphertext := data[:gcm.NonceSize()], data[gcm.NonceSize():]

	result, err := gcm.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		return nil, err
	}

	return result, nil

}

func (s symmetricDriver) EncryptBase64(data []byte) (string, error) {
	raw, err := s.Encrypt(data)
	if err != nil {
		return "", err
	}

	encoded, err := base64Encode(raw)
	return string(encoded), nil
}

func (s symmetricDriver) DecryptBase64(encrypted string) ([]byte, error) {
	raw, err := base64Decode([]byte(encrypted))
	if err != nil {
		return nil, err
	}

	return s.Decrypt(raw)
}

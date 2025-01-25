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

func (driver symmetricDriver) Sign(data []byte) ([]byte, error) {
	constructor := HashingInstance(driver.signer)
	if constructor == nil {
		return nil, fmt.Errorf("invalid hash algo passed to driver")
	}

	hasher := hmac.New(constructor, driver.key)
	_, err := hasher.Write(data)
	if err != nil {
		return nil, err
	}

	return hasher.Sum(nil), nil
}

func (driver symmetricDriver) ValidateSignature(data []byte, signature []byte) (bool, error) {
	constructor := HashingInstance(driver.signer)
	if constructor == nil {
		return false, fmt.Errorf("invalid hash algo passed to driver")
	}

	hasher := hmac.New(constructor, driver.key)
	_, err := hasher.Write(data)
	if err != nil {
		return false, err
	}

	return hmac.Equal(signature, hasher.Sum(nil)), nil
}

func (driver symmetricDriver) Encrypt(data []byte) ([]byte, error) {
	block, err := aes.NewCipher(driver.key)
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

func (driver symmetricDriver) Decrypt(data []byte) ([]byte, error) {
	block, err := aes.NewCipher(driver.key)
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

func (driver symmetricDriver) EncryptBase64(data []byte) (string, error) {
	raw, err := driver.Encrypt(data)
	if err != nil {
		return "", err
	}

	encoded, err := base64Encode(raw)
	return string(encoded), nil
}

func (driver symmetricDriver) DecryptBase64(encrypted string) ([]byte, error) {
	raw, err := base64Decode([]byte(encrypted))
	if err != nil {
		return nil, err
	}

	return driver.Decrypt(raw)
}

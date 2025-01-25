package gocrypto

import (
	"crypto/rand"
	"crypto/rsa"
	"fmt"
)

type asymmetricDriver struct {
	key       *RSAKey
	publicKey *rsa.PublicKey
	signer    HashingAlgo
}

func (driver asymmetricDriver) PublicKey() *rsa.PublicKey {
	if driver.publicKey != nil {
		return driver.publicKey
	} else if driver.key != nil {
		return driver.key.PublicKey()
	}
	return nil
}

func (driver asymmetricDriver) Sign(data []byte) ([]byte, error) {
	if driver.key == nil {
		return nil, fmt.Errorf("no private key passed to driver")
	}

	constructor := HashingInstance(driver.signer)
	if constructor == nil {
		return nil, fmt.Errorf("invalid hash algo passed to driver")
	}

	hasher := constructor()
	_, err := hasher.Write(data)
	if err != nil {
		return nil, err
	}

	signature, err := rsa.SignPKCS1v15(
		rand.Reader, driver.key.PrivateKey(),
		HashingAlg(driver.signer), hasher.Sum(nil),
	)
	if err != nil {
		return nil, err
	}
	return signature, nil
}

func (driver asymmetricDriver) ValidateSignature(data []byte, signature []byte) (bool, error) {
	constructor := HashingInstance(driver.signer)
	if constructor == nil {
		return false, fmt.Errorf("invalid hash algo passed to driver")
	}

	hasher := constructor()
	_, err := hasher.Write(data)
	if err != nil {
		return false, err
	}

	err = rsa.VerifyPKCS1v15(
		driver.PublicKey(), HashingAlg(driver.signer),
		hasher.Sum(nil), signature,
	)
	if err != nil {
		return false, err
	}
	return true, nil
}

func (driver asymmetricDriver) Encrypt(data []byte) ([]byte, error) {
	constructor := HashingInstance(driver.signer)
	if constructor == nil {
		return nil, fmt.Errorf("invalid hash algo passed to driver")
	}

	encrypted, err := rsa.EncryptOAEP(
		constructor(), rand.Reader,
		driver.PublicKey(), data, nil,
	)
	if err != nil {
		return nil, err
	}

	return encrypted, nil
}

func (driver asymmetricDriver) Decrypt(data []byte) ([]byte, error) {
	if driver.key == nil {
		return nil, fmt.Errorf("no private key passed to driver")
	}

	constructor := HashingInstance(driver.signer)
	if constructor == nil {
		return nil, fmt.Errorf("invalid hash algo passed to driver")
	}

	decrypted, err := rsa.DecryptOAEP(
		constructor(), rand.Reader,
		driver.key.PrivateKey(), data, nil,
	)
	if err != nil {
		return nil, err
	}

	return decrypted, nil
}

func (driver asymmetricDriver) EncryptBase64(data []byte) (string, error) {
	raw, err := driver.Encrypt(data)
	if err != nil {
		return "", err
	}

	encoded, err := base64Encode(raw)
	return string(encoded), nil
}

func (driver asymmetricDriver) DecryptBase64(encrypted string) ([]byte, error) {
	raw, err := base64Decode([]byte(encrypted))
	if err != nil {
		return nil, err
	}

	return driver.Decrypt(raw)
}

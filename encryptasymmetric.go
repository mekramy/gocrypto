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

func (a asymmetricDriver) PublicKey() *rsa.PublicKey {
	if a.publicKey != nil {
		return a.publicKey
	} else if a.key != nil {
		return a.key.PublicKey()
	}
	return nil
}

func (a asymmetricDriver) Sign(data []byte) ([]byte, error) {
	if a.key == nil {
		return nil, fmt.Errorf("no private key passed to driver")
	}

	constructor := HashingInstance(a.signer)
	if constructor == nil {
		return nil, fmt.Errorf("invalid hash algo passed to driver")
	}

	hasher := constructor()
	_, err := hasher.Write(data)
	if err != nil {
		return nil, err
	}

	signature, err := rsa.SignPKCS1v15(
		rand.Reader, a.key.PrivateKey(),
		HashingAlg(a.signer), hasher.Sum(nil),
	)
	if err != nil {
		return nil, err
	}
	return signature, nil
}

func (a asymmetricDriver) ValidateSignature(data []byte, signature []byte) (bool, error) {
	constructor := HashingInstance(a.signer)
	if constructor == nil {
		return false, fmt.Errorf("invalid hash algo passed to driver")
	}

	hasher := constructor()
	_, err := hasher.Write(data)
	if err != nil {
		return false, err
	}

	err = rsa.VerifyPKCS1v15(
		a.PublicKey(), HashingAlg(a.signer),
		hasher.Sum(nil), signature,
	)
	if err != nil {
		return false, err
	}
	return true, nil
}

func (a asymmetricDriver) Encrypt(data []byte) ([]byte, error) {
	constructor := HashingInstance(a.signer)
	if constructor == nil {
		return nil, fmt.Errorf("invalid hash algo passed to driver")
	}

	encrypted, err := rsa.EncryptOAEP(
		constructor(), rand.Reader,
		a.PublicKey(), data, nil,
	)
	if err != nil {
		return nil, err
	}

	return encrypted, nil
}

func (a asymmetricDriver) Decrypt(data []byte) ([]byte, error) {
	if a.key == nil {
		return nil, fmt.Errorf("no private key passed to driver")
	}

	constructor := HashingInstance(a.signer)
	if constructor == nil {
		return nil, fmt.Errorf("invalid hash algo passed to driver")
	}

	decrypted, err := rsa.DecryptOAEP(
		constructor(), rand.Reader,
		a.key.PrivateKey(), data, nil,
	)
	if err != nil {
		return nil, err
	}

	return decrypted, nil
}

func (a asymmetricDriver) EncryptBase64(data []byte) (string, error) {
	raw, err := a.Encrypt(data)
	if err != nil {
		return "", err
	}

	encoded, err := base64Encode(raw)
	return string(encoded), nil
}

func (a asymmetricDriver) DecryptBase64(encrypted string) ([]byte, error) {
	raw, err := base64Decode([]byte(encrypted))
	if err != nil {
		return nil, err
	}

	return a.Decrypt(raw)
}

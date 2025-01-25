package gocrypto

import "crypto/rsa"

// Encrypt interface for encrption.
type Encrypt interface {
	// Sign data.
	Sign(data []byte) ([]byte, error)
	// ValidateSignature validates the signature.
	ValidateSignature(data []byte, signature []byte) (bool, error)
	// Encrypt data.
	Encrypt(data []byte) ([]byte, error)
	// Decrypt data.
	Decrypt(data []byte) ([]byte, error)
	// EncryptBase64 encrypt data and encode it to base64 string.
	EncryptBase64(data []byte) (string, error)
	// DecryptBase64 decode base64 string and decrypt it.
	DecryptBase64(encrypted string) ([]byte, error)
}

// NewSymmetric creates a new symmetric encryption driver.
func NewSymmetric(key SimpleKey, signer HashingAlgo) Encrypt {
	driver := new(symmetricDriver)
	driver.key = key
	driver.signer = signer
	return driver
}

// NewAsymmetric creates a new asymmetric encryption driver.
func NewAsymmetric(key RSAKey, signer HashingAlgo) Encrypt {
	driver := new(asymmetricDriver)
	driver.key = &key
	driver.signer = signer
	return driver
}

// NewAsymmetricClient creates a new asymmetric encryption driver from public key.
func NewAsymmetricClient(public *rsa.PublicKey, signer HashingAlgo) Encrypt {
	driver := new(asymmetricDriver)
	driver.publicKey = public
	driver.signer = signer
	return driver
}

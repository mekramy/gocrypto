package gocrypto

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
)

type RSALength int

const (
	RSA1024 RSALength = 1024 // Not recommended for security as it's considered weak and can potentially be broken by modern computational capabilities.
	RSA2048 RSALength = 2048 // The minimum recommended size for modern applications. It provides a good balance between security and performance.
	RSA3072 RSALength = 3072 // Offers stronger security for scenarios where 2048 bits might not suffice, such as for long-term data protection.
	RSA4096 RSALength = 4096 // Extremely secure, but with significantly slower performance. Often used for highly sensitive data.
)

// NewRSAKey generates a new RSA key with the given key size.
func NewRSAKey(length RSALength) (*RSAKey, error) {
	key, err := rsa.GenerateKey(rand.Reader, int(length))
	if err != nil {
		return nil, err
	}
	return &RSAKey{key}, nil
}

// RSAKey implementation of the Key interface for RSA keys.
type RSAKey struct {
	key *rsa.PrivateKey
}

// PrivateKey returns the private key.
func (k *RSAKey) PrivateKey() *rsa.PrivateKey {
	return k.key
}

// PrivateKeyBytes returns the private key in PKCS #1 or PKCS #8 format.
// PKCS #1 is not recommended for security as it's considered weak and
// can potentially be broken by modern computational capabilities.
func (k *RSAKey) PrivateKeyBytes(usePKCS8 bool) ([]byte, error) {
	if usePKCS8 {
		return x509.MarshalPKCS8PrivateKey(k.key)
	}
	return x509.MarshalPKCS1PrivateKey(k.key), nil
}

// PrivateKeyPEM returns the private key in PKCS #1 or PKCS #8 PEM-encoded format.
// PKCS #1 is not recommended for security as it's considered weak and
// can potentially be broken by modern computational capabilities.
func (k *RSAKey) PrivateKeyPEM(usePKCS8 bool) ([]byte, error) {
	if usePKCS8 {
		privateKeyPEM, err := x509.MarshalPKCS8PrivateKey(k.key)
		if err != nil {
			return nil, err
		}
		return pem.EncodeToMemory(&pem.Block{
			Type:  "PRIVATE KEY",
			Bytes: privateKeyPEM,
		}), nil
	} else {
		privateKeyPEM := x509.MarshalPKCS1PrivateKey(k.key)
		return pem.EncodeToMemory(&pem.Block{
			Type:  "RSA PRIVATE KEY",
			Bytes: privateKeyPEM,
		}), nil
	}
}

// PublicKey returns the public key.
func (k *RSAKey) PublicKey() *rsa.PublicKey {
	return &k.key.PublicKey
}

// PublicKeyBytes returns the public key in PKIX or PKCS #1 format.
// PKCS #1 is not recommended for security as it's considered weak and
// can potentially be broken by modern computational capabilities.
func (k *RSAKey) PublicKeyBytes(usePKCS8 bool) ([]byte, error) {
	if usePKCS8 {
		return x509.MarshalPKIXPublicKey(&k.key.PublicKey)
	} else {
		return x509.MarshalPKCS1PublicKey(&k.key.PublicKey), nil
	}
}

// PublicKeyPEM returns the public key in PKIX or PKCS #1 PEM-encoded format.
// PKCS #1 is not recommended for security as it's considered weak and
// can potentially be broken by modern computational capabilities.
func (k *RSAKey) PublicKeyPEM(usePKCS8 bool) ([]byte, error) {
	if usePKCS8 {
		publicKeyPEM, err := x509.MarshalPKIXPublicKey(&k.key.PublicKey)
		if err != nil {
			return nil, err
		}
		return pem.EncodeToMemory(&pem.Block{
			Type:  "PUBLIC KEY",
			Bytes: publicKeyPEM,
		}), nil
	} else {
		publicKeyPEM := x509.MarshalPKCS1PublicKey(&k.key.PublicKey)
		return pem.EncodeToMemory(&pem.Block{
			Type:  "RSA PUBLIC KEY",
			Bytes: publicKeyPEM,
		}), nil
	}
}

// IssueCertificateBytes issue a self-signed certificate in DER format.
func (k *RSAKey) IssueCertificateBytes(subject pkix.Name, algo x509.SignatureAlgorithm, options *x509.Certificate) ([]byte, error) {
	// Create a new certificate template
	if options == nil {
		options = &x509.Certificate{}
	}
	options.Subject = subject
	options.SignatureAlgorithm = algo

	// Generate the certificate
	certDER, err := x509.CreateCertificate(rand.Reader, options, options, &k.key.PublicKey, k.key)
	if err != nil {
		return nil, err
	}
	return certDER, nil
}

// IssueCertificatePEM issue a self-signed certificate in PEM format.
func (k *RSAKey) IssueCertificatePEM(subject pkix.Name, algo x509.SignatureAlgorithm, options *x509.Certificate) ([]byte, error) {
	certDER, err := k.IssueCertificateBytes(subject, algo, options)
	if err != nil {
		return nil, err
	}
	return pem.EncodeToMemory(&pem.Block{
		Type:  "CERTIFICATE",
		Bytes: certDER,
	}), nil
}

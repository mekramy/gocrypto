package gocrypto

import (
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
)

// ParsePrivateKey parses an RSA private key from PKCS #1 or PKCS #8 format.
// If isPEM is true, it will attempt to decode the key as PEM.
func ParsePrivateKey(key []byte, isPEM bool) (*RSAKey, error) {
	var raw []byte

	// Decode the PEM block
	if isPEM {
		block, _ := pem.Decode(key)
		if block == nil {
			return nil, errors.New("failed to decode PEM block")
		}
		raw = make([]byte, len(block.Bytes))
		copy(raw, block.Bytes)
	} else {
		raw = make([]byte, len(key))
		copy(raw, key)
	}

	// Parse the key PKCS #1
	private, err := x509.ParsePKCS1PrivateKey(raw)
	if err == nil {
		return &RSAKey{key: private}, nil
	}

	// If not PKCS #1, try parsing as PKCS #8
	parsed, err := x509.ParsePKCS8PrivateKey(raw)
	if err != nil {
		return nil, err
	} else if private, ok := parsed.(*rsa.PrivateKey); !ok {
		return nil, fmt.Errorf("failed to parse RSA private key")
	} else {
		return &RSAKey{key: private}, nil
	}
}

// ParsePublicKey parses an RSA public key from PKIX or PKCS #1 format.
// If isPEM is true, it will attempt to decode the key as PEM.
func ParsePublicKey(key []byte, isPEM bool) (*rsa.PublicKey, error) {
	var raw []byte

	// Decode the PEM block
	if isPEM {
		block, _ := pem.Decode(key)
		if block == nil {
			return nil, errors.New("failed to decode PEM block")
		}
		raw = make([]byte, len(block.Bytes))
		copy(raw, block.Bytes)
	} else {
		raw = make([]byte, len(key))
		copy(raw, key)
	}

	public, err := x509.ParsePKCS1PublicKey(raw)
	if err == nil {
		return public, nil
	}

	// Parse the key
	parsed, err := x509.ParsePKIXPublicKey(raw)
	if err != nil {
		return nil, err
	} else if public, ok := parsed.(*rsa.PublicKey); !ok {
		return nil, fmt.Errorf("failed to parse RSA public key")
	} else {
		return public, nil
	}
}

// ParseCertificateRequest parses an x509 certificate request from CSR.
// If isPEM is true, it will attempt to decode the CSR as PEM.
func ParseCertificateRequest(csr []byte, isPEM bool) (*x509.CertificateRequest, error) {
	var raw []byte

	// Decode the PEM block
	if isPEM {
		block, _ := pem.Decode(csr)
		if block == nil {
			return nil, errors.New("failed to decode PEM block")
		}
		raw = make([]byte, len(block.Bytes))
		copy(raw, block.Bytes)
	} else {
		raw = make([]byte, len(csr))
		copy(raw, csr)
	}

	// Parse the Certificate Signing Request
	request, err := x509.ParseCertificateRequest(raw)
	if err != nil {
		return nil, err
	}

	return request, nil
}

// ParseCertificate parses an x509 certificate from CSR.
// If isPEM is true, it will attempt to decode the CSR as PEM.
func ParseCertificate(csr []byte, isPEM bool) (*x509.Certificate, error) {
	var raw []byte

	// Decode the PEM block
	if isPEM {
		block, _ := pem.Decode(csr)
		if block == nil {
			return nil, errors.New("failed to decode PEM block")
		}
		raw = make([]byte, len(block.Bytes))
		copy(raw, block.Bytes)
	} else {
		raw = make([]byte, len(csr))
		copy(raw, csr)
	}

	// Parse the certificate
	cert, err := x509.ParseCertificate(raw)
	if err != nil {
		return nil, err
	}

	return cert, nil
}

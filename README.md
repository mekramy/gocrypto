# GoCrypto

GoCrypto is a Go library that provides various cryptographic functionalities including **hashing**, **encryption**, and **key management**. This library supports both _symmetric_ and _asymmetric_ encryption, as well as various _hashing_ algorithms.

## Installation

To install GoCrypto, use the following command:

```sh
go get github.com/mekramy/gocrypto
```

## Usage

### Hashing

GoCrypto provides interfaces and implementations for hashing data using various algorithms.

#### Hasher Interface

Hasher Generate hash from data and password. For security usecase like password use **argon2** or **bcrypt** driver.

```go
type Hasher interface {
    Hash(data []byte) ([]byte, error)
    Validate(hash, data []byte) (bool, error)
}
```

#### Argon2 Hasher

Generate new argon2 hash driver (recommended for password). Pass 0 for parameter to use defaults.

```go
hasher := gocrypto.NewArgon2Hasher(0, 0, 0, 0, 0)
hash, err := hasher.Hash([]byte("password"))
isValid, err := hasher.Validate(hash, []byte("password"))
```

#### Bcrypt Hasher

Generate new bcrypt hash driver (alternative for password). Pass 0 for parameter to use defaults.

```go
hasher := gocrypto.NewBcryptHasher(0)
hash, err := hasher.Hash([]byte("password"))
isValid, err := hasher.Validate(hash, []byte("password"))
```

#### HMac Hasher

Generate new Hmac hash driver (recommended for message sign).

```go
hasher := gocrypto.HMacHasher([]byte("key"), gocrypto.MD5)
hash, err := hasher.Hash([]byte("message"))
isValid, err := hasher.Validate(hash, []byte("message"))
```

### Encryption

GoCrypto provides interfaces and implementations for encrypting and decrypting data.

#### Encrypt Interface

```go
type Encrypt interface {
    Sign(data []byte) ([]byte, error)
    ValidateSignature(data []byte, signature []byte) (bool, error)
    Encrypt(data []byte) ([]byte, error)
    Decrypt(data []byte) ([]byte, error)
    EncryptBase64(data []byte) (string, error)
    DecryptBase64(encrypted string) ([]byte, error)
}
```

#### Symmetric Encryption

```go
key, _ := gocrypto.NewSimpleKey(gocrypto.Simple32)
encryptor := gocrypto.NewSymmetric(key, gocrypto.SHA256)
encrypted, err := encryptor.Encrypt([]byte("message"))
decrypted, err := encryptor.Decrypt(encrypted)
```

#### Asymmetric Encryption

```go
key, _ := gocrypto.NewRSAKey(gocrypto.RSA2048)
encryptor := gocrypto.NewAsymmetric(*key, gocrypto.SHA256)
encrypted, err := encryptor.Encrypt([]byte("message"))
decrypted, err := encryptor.Decrypt(encrypted)
```

### Key Management

GoCrypto provides functionalities for generating and managing cryptographic keys.

#### Simple Key

```go
key, err := gocrypto.NewSimpleKey(gocrypto.Simple32)
fmt.Println(key.Hex())
fmt.Println(key.Base64())
```

#### RSA Key

```go
key, err := gocrypto.NewRSAKey(gocrypto.RSA2048)
privateKeyPEM, err := key.PrivateKeyPEM(false)
publicKeyPEM, err := key.PublicKeyPEM(false)
```

### Utility Functions

GoCrypto provides utility functions for parsing keys and certificates.

#### Parse Private Key

```go
privateKey, err := gocrypto.ParsePrivateKey(pemEncodedKey, true)
```

#### Parse Public Key

```go
publicKey, err := gocrypto.ParsePublicKey(pemEncodedKey, true)
```

#### Parse Certificate Request

```go
csr, err := gocrypto.ParseCertificateRequest(pemEncodedCSR, true)
```

#### Parse Certificate

```go
cert, err := gocrypto.ParseCertificate(pemEncodedCert, true)
```

### Hashing Algorithms

GoCrypto support following hashing algorithms for signing.

- `MD5`: MD5 (not recommended for security)
- `SHA1`: SHA1 (not recommended for security)
- `SHA224`: SHA2 224 bit
- `SHA256`: SHA2 256 bit (recommended)
- `SHA384`: SHA2 384 bit
- `SHA512`: SHA2 512 bit
- `SHA3224`:SHA3 224 bit
- `SHA3256`:SHA3 256 bit
- `SHA3384`:SHA3 384 bit
- `SHA3512`:SHA3 512 bit

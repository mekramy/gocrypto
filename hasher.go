package gocrypto

import (
	"runtime"

	"golang.org/x/crypto/bcrypt"
)

// Hasher Generate hash from data and password.
// For security usecase like password use argon2 or bcrypt driver.
type Hasher interface {
	// Hash Generate hash from data.
	Hash(data []byte) ([]byte, error)
	// Validate compares a hashed data with its possible plaintext equivalent.
	Validate(hash, data []byte) (bool, error)
}

// NewArgon2Hasher generate new argon2 hash driver (recommended for password).
// Pass 0 for parameter to use defaults.
func NewArgon2Hasher(
	saltLength uint32, keyLength uint32,
	memory uint32, iterations uint32, parallelism uint8,
) Hasher {
	driver := new(argon2Hasher)
	driver.memory = valueOf(memory, 64*1024)
	driver.iterations = valueOf(iterations, 1)
	driver.parallelism = valueOf(parallelism, uint8(runtime.NumCPU()))
	driver.saltLength = valueOf(saltLength, 16)
	driver.keyLength = valueOf(keyLength, 32)
	return driver
}

// NewBcryptHasher generate new bcrypt hash driver (alternative for password).
// Pass 0 for parameter to use defaults.
func NewBcryptHasher(cost int) Hasher {
	driver := new(bcryptHasher)
	if cost < bcrypt.MinCost || cost > bcrypt.MaxCost {
		driver.cost = bcrypt.DefaultCost
	} else {
		driver.cost = cost
	}
	return driver
}

// HMacHasher generate new Hmac hash driver (recommended for message sign).
func HMacHasher(key []byte, algo HashingAlgo) Hasher {
	driver := new(hmacHasher)
	driver.key = key
	driver.algo = algo
	return driver
}

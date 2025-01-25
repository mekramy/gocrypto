package gocrypto

import (
	"crypto/subtle"
	"fmt"
	"strings"

	"golang.org/x/crypto/argon2"
)

type argon2Hasher struct {
	memory      uint32
	iterations  uint32
	parallelism uint8
	saltLength  uint32
	keyLength   uint32
}

func (driver argon2Hasher) Hash(data []byte) ([]byte, error) {
	salt, err := NewSimpleKey(SimpleLength(driver.saltLength))
	if err != nil {
		return nil, err
	}

	key := argon2.IDKey(
		data, salt,
		driver.iterations, driver.memory,
		driver.parallelism, driver.keyLength,
	)

	encodedSalt, _ := base64Encode(salt)
	encodedKey, _ := base64Encode(key)
	return base64Encode(
		[]byte(
			fmt.Sprintf(
				"%s#%d$%d$%d$%d#%s",
				string(encodedSalt), argon2.Version, driver.memory,
				driver.iterations, driver.parallelism, string(encodedKey),
			),
		),
	)
}

func (driver argon2Hasher) Validate(hash, data []byte) (bool, error) {
	salt, key, _, _, _, _, err := driver.decodeHash(hash)
	if err != nil {
		return false, err
	}

	otherKey := argon2.IDKey(
		data, salt,
		driver.iterations, driver.memory,
		driver.parallelism, driver.keyLength,
	)

	// Check that the contents of the hashed passwords are identical. Note
	// that we are using the subtle.ConstantTimeCompare() function for this
	// to help prevent timing attacks.
	if subtle.ConstantTimeCompare(key, otherKey) == 1 {
		return true, nil
	}
	return false, nil
}

// decodeHash Decode hash and extract args
// returns salt, key, version, memory, iterations, parallelism and error
func (driver argon2Hasher) decodeHash(hash []byte) ([]byte, []byte, int, uint32, uint32, uint8, error) {
	// Decode
	raw, err := base64Decode(hash)
	if err != nil {
		return nil, nil, 0, 0, 0, 0, fmt.Errorf("invalid password hash")
	}

	// Extract parts
	parts := strings.Split(string(raw), "#")
	if len(parts) != 3 {
		return nil, nil, 0, 0, 0, 0, fmt.Errorf("invalid password hash")
	}

	// Parse salt
	salt, err := base64Decode([]byte(parts[0]))
	if err != nil {
		return nil, nil, 0, 0, 0, 0, fmt.Errorf("invalid password hash")
	}

	// Parse and validate version
	var version int
	var memory int
	var iterations int
	var parallelism int
	_, err = fmt.Sscanf(parts[1], "%d$%d$%d$%d", &version, &memory, &iterations, &parallelism)
	if err != nil {
		return nil, nil, 0, 0, 0, 0, fmt.Errorf("invalid password hash")
	}

	if version != argon2.Version {
		return nil, nil, 0, 0, 0, 0, fmt.Errorf("incompatible version of argon2")
	}

	// Parse key
	key, err := base64Decode([]byte(parts[2]))
	if err != nil {
		return nil, nil, 0, 0, 0, 0, fmt.Errorf("invalid password hash")
	}

	// return final result
	return salt, key, version, uint32(memory), uint32(iterations), uint8(parallelism), nil
}

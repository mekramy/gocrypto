package gocrypto_test

import (
	"testing"

	"github.com/mekramy/gocrypto"
)

func TestArgon2(t *testing.T) {
	password := []byte("pass12341fadsfasf@!#@$")

	hasher := gocrypto.NewArgon2Hasher(0, 0, 0, 0, 0)
	hashed, err := hasher.Hash(password)
	if err != nil {
		t.Fatal(err)
	}

	same, err := hasher.Validate(hashed, password)
	if err != nil {
		t.Fatal(err)
	} else if !same {
		t.Error("validate failed")
	}
}

func TestBCrypt(t *testing.T) {
	password := []byte("pass12341fadsfasf@!#@$")

	hasher := gocrypto.NewBcryptHasher(0)
	hashed, err := hasher.Hash(password)
	if err != nil {
		t.Fatal(err)
	}

	same, err := hasher.Validate(hashed, password)
	if err != nil {
		t.Fatal(err)
	} else if !same {
		t.Error("validate failed")
	}
}

func TestHMac(t *testing.T) {
	password := []byte("pass12341fadsfasf@!#@$")
	algos := []gocrypto.HashingAlgo{
		gocrypto.MD5, gocrypto.SHA1,

		gocrypto.SHA224, gocrypto.SHA256,
		gocrypto.SHA384, gocrypto.SHA512,

		gocrypto.SHA3224, gocrypto.SHA3256,
		gocrypto.SHA3384, gocrypto.SHA3512,
	}

	// Generate random key
	key, err := gocrypto.NewSimpleKey(gocrypto.Simple32)
	if err != nil {
		t.Fatal(err)
	}

	// Test all algos
	for _, algo := range algos {
		t.Run(string(algo), func(t *testing.T) {
			hasher := gocrypto.HMacHasher(key, algo)
			hashed, err := hasher.Hash(password)
			if err != nil {
				t.Fatal(err)
			}

			same, err := hasher.Validate(hashed, password)
			if err != nil {
				t.Fatal(err)
			} else if !same {
				t.Error("validate failed")
			}
		})
	}

}

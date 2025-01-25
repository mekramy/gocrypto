package gocrypto_test

import (
	"bytes"
	"testing"

	"github.com/mekramy/gocrypto"
)

func TestEncrpt(t *testing.T) {
	data := []byte("my name is John doe")

	t.Run("Symmetric", func(t *testing.T) {
		key, err := gocrypto.NewSimpleKey(gocrypto.Simple32)
		if err != nil {
			t.Fatal(err)
		}

		driver := gocrypto.NewSymmetric(key, gocrypto.SHA256)

		// Encrypt
		encrypted, err := driver.EncryptBase64(data)
		if err != nil {
			t.Fatal(err)
		}

		// Decrypt
		raw, err := driver.DecryptBase64(encrypted)
		if err != nil {
			t.Fatal(err)
		} else if !bytes.Equal(raw, data) {
			t.Fatal("decrypted data invalid")
		}
	})

	t.Run("Asymmetric", func(t *testing.T) {
		key, err := gocrypto.NewRSAKey(gocrypto.RSA2048)
		if err != nil {
			t.Fatal(err)
		}

		driver := gocrypto.NewAsymmetric(*key, gocrypto.SHA256)

		// Encrypt
		encrypted, err := driver.EncryptBase64(data)
		if err != nil {
			t.Fatal(err)
		}

		// Decrypt
		raw, err := driver.DecryptBase64(encrypted)
		if err != nil {
			t.Fatal(err)
		} else if !bytes.Equal(raw, data) {
			t.Fatal("decrypted data invalid")
		}
	})

}

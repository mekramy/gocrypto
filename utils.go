package gocrypto

import (
	"encoding/base64"
)

func valueOf[T comparable](value, fallback T) T {
	var def T
	if value == def {
		return fallback
	}
	return value
}

func base64Encode(data []byte) ([]byte, error) {
	res := make([]byte, base64.StdEncoding.EncodedLen(len(data)))
	base64.StdEncoding.Encode(res, data)
	return res, nil
}

func base64Decode(data []byte) ([]byte, error) {
	res := make([]byte, base64.StdEncoding.DecodedLen(len(data)))
	n, err := base64.StdEncoding.Decode(res, data)
	if err != nil {
		return nil, err
	}
	return res[:n], nil
}

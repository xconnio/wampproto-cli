package wampprotocli

import (
	"encoding/base64"
	"encoding/hex"
)

func HexToBase64(hexStr string) (string, error) {
	bytes, err := hex.DecodeString(hexStr)
	if err != nil {
		return "", err
	}

	base64Str := base64.StdEncoding.EncodeToString(bytes)
	return base64Str, nil
}

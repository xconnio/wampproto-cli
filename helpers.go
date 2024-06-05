package wampprotocli

import (
	"encoding/base64"
	"encoding/hex"
	"fmt"
)

func HexToBase64(hexStr string) (string, error) {
	bytes, err := hex.DecodeString(hexStr)
	if err != nil {
		return "", err
	}

	base64Str := base64.StdEncoding.EncodeToString(bytes)
	return base64Str, nil
}

func DecodeHexOrBase64(str string) ([]byte, error) {
	bytes, err := hex.DecodeString(str)
	if err == nil {
		return bytes, nil
	}

	bytes, err = base64.StdEncoding.DecodeString(str)
	if err == nil {
		return bytes, nil
	}

	return nil, fmt.Errorf("must be in either hexadecimal or base64 format")
}

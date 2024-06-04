package wampprotocli_test

import (
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/xconnio/wampproto-cli"
)

func TestHexToBase64(t *testing.T) {
	t.Run("TestValidHexStrings", func(t *testing.T) {
		for base64Str, hexStr := range map[string]string{
			"SGVsbG8gV29ybGQ=": "48656c6c6f20576f726c64",
			"Zm9v":             "666f6f",
			"":                 "",
		} {
			result, err := wampprotocli.HexToBase64(hexStr)
			wampprotocli.NoErrorEqual(t, err, base64Str, result)
		}
	})

	t.Run("TestInvalidHexStrings", func(t *testing.T) {
		for _, rawStr := range []string{
			"Hello",
			"invalidHex",
		} {
			_, err := wampprotocli.HexToBase64(rawStr)
			require.Error(t, err)
		}
	})
}

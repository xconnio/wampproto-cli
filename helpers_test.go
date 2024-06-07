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

func TestDecodeHexOrBase64(t *testing.T) {
	t.Run("ValidHexString", func(t *testing.T) {
		_, err := wampprotocli.DecodeHexOrBase64("48656c6c6f20576f726c64")
		require.NoError(t, err)
	})

	t.Run("ValidBase64String", func(t *testing.T) {
		_, err := wampprotocli.DecodeHexOrBase64("SGVsbG8gV29ybGQ=")
		require.NoError(t, err)
	})

	t.Run("InvalidString", func(t *testing.T) {
		_, err := wampprotocli.DecodeHexOrBase64("invalidString")
		require.EqualError(t, err, "must be in either hexadecimal or base64 format")
	})
}

func TestStringsToTypedList(t *testing.T) {
	var input = []string{"false", "789", "45.67", `{"a": true, "b": "c"}`, `[{"x": true}, {"y": false}]`, "world",
		`["hello", true]`}
	var expected = []any{false, 789, 45.67, map[string]any{"a": true, "b": "c"}, []map[string]any{{"x": true},
		{"y": false}}, "world", []any{"hello", true}}

	result := wampprotocli.StringsToTypedList(input)
	require.Equal(t, expected, result)
}

func TestStringMapToTypedMap(t *testing.T) {
	var input = map[string]string{
		"float":   "45.67",
		"bool":    "true",
		"json":    `{"key": "value"}`,
		"list":    `["a", true, 1.2]`,
		"string":  "hello",
		"mapList": `[{"x": true}, {"y": false}]`,
	}
	var expected = map[string]any{
		"float":   45.67,
		"bool":    true,
		"json":    map[string]any{"key": "value"},
		"list":    []any{"a", true, 1.2},
		"string":  "hello",
		"mapList": []map[string]any{{"x": true}, {"y": false}},
	}

	result := wampprotocli.StringMapToTypedMap(input)
	require.Equal(t, expected, result)
}

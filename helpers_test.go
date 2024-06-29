package wampprotocli_test

import (
	"encoding/base64"
	"encoding/hex"
	"testing"

	"github.com/stretchr/testify/require"

	wampprotocli "github.com/xconnio/wampproto-cli"
	"github.com/xconnio/wampproto-go/serializers"
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

func TestFormatOutput(t *testing.T) {
	var hexInput = "48656c6c6f" // "Hello" in hex

	t.Run("HexFormat", func(t *testing.T) {
		output, err := wampprotocli.FormatOutput(wampprotocli.HexFormat, hexInput)
		wampprotocli.NoErrorEqual(t, err, hexInput, output)
	})

	t.Run("Base64Format", func(t *testing.T) {
		expectedBase64 := base64.StdEncoding.EncodeToString([]byte("Hello"))
		output, err := wampprotocli.FormatOutput(wampprotocli.Base64Format, hexInput)
		wampprotocli.NoErrorEqual(t, err, expectedBase64, output)
	})

	t.Run("InvalidFormat", func(t *testing.T) {
		_, err := wampprotocli.FormatOutput("invalid", "48656c6c6f")
		require.Error(t, err)
	})
}

func TestFormatOutputBytes(t *testing.T) {
	var bytesInput = []byte("Hello")

	t.Run("HexFormat", func(t *testing.T) {
		expectedHex := hex.EncodeToString(bytesInput)
		output, err := wampprotocli.FormatOutputBytes(wampprotocli.HexFormat, bytesInput)
		wampprotocli.NoErrorEqual(t, err, expectedHex, output)
	})

	t.Run("Base64Format", func(t *testing.T) {
		expectedBase64 := base64.StdEncoding.EncodeToString(bytesInput)
		output, err := wampprotocli.FormatOutputBytes(wampprotocli.Base64Format, bytesInput)
		wampprotocli.NoErrorEqual(t, err, expectedBase64, output)
	})

	t.Run("InvalidFormat", func(t *testing.T) {
		_, err := wampprotocli.FormatOutputBytes("invalid", []byte("Hello"))
		require.Error(t, err)
	})
}

func TestSerializerByName(t *testing.T) {
	t.Run("JSONSerializer", func(t *testing.T) {
		serializer := wampprotocli.SerializerByName(wampprotocli.JsonSerializer)
		require.IsType(t, &serializers.JSONSerializer{}, serializer)
	})

	t.Run("CBORSerializer", func(t *testing.T) {
		serializer := wampprotocli.SerializerByName(wampprotocli.CborSerializer)
		require.IsType(t, &serializers.CBORSerializer{}, serializer)
	})

	t.Run("MsgPackSerializer", func(t *testing.T) {
		serializer := wampprotocli.SerializerByName(wampprotocli.MsgpackSerializer)
		require.IsType(t, &serializers.MsgPackSerializer{}, serializer)
	})

	t.Run("InvalidSerializer", func(t *testing.T) {
		serializer := wampprotocli.SerializerByName("invalid")
		require.Nil(t, serializer)
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

func TestUpdateArgsKwArgsIfEmpty(t *testing.T) {
	t.Run("EmptyArgumentsAndKwargs", func(t *testing.T) {
		args := []any{}
		kwargs := map[string]any{}

		updatedArgs, updatedKwargs := wampprotocli.UpdateArgsKwArgsIfEmpty(args, kwargs)
		require.Nil(t, updatedArgs)
		require.Nil(t, updatedKwargs)
	})

	t.Run("EmptyArgs", func(t *testing.T) {
		args := []any{}
		kwargs := map[string]any{"key": "value"}

		updatedArgs, updatedKwargs := wampprotocli.UpdateArgsKwArgsIfEmpty(args, kwargs)
		require.Equal(t, args, updatedArgs)
		require.Equal(t, kwargs, updatedKwargs)
	})

	t.Run("EmptyKwargs", func(t *testing.T) {
		args := []any{1, 2, 3}
		kwargs := map[string]any{}

		updatedArgs, updatedKwargs := wampprotocli.UpdateArgsKwArgsIfEmpty(args, kwargs)
		wampprotocli.NilEqual(t, updatedKwargs, args, updatedArgs)
	})

	t.Run("NonEmptyArgumentsAndKwargs", func(t *testing.T) {
		args := []any{1, 2, 3}
		kwargs := map[string]any{"key": "value"}

		updatedArgs, updatedKwargs := wampprotocli.UpdateArgsKwArgsIfEmpty(args, kwargs)
		require.Equal(t, args, updatedArgs)
		require.Equal(t, kwargs, updatedKwargs)
	})
}

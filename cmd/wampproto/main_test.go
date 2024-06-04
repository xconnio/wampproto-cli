package main_test

import (
	"encoding/base64"
	"encoding/hex"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/xconnio/wampproto-cli/cmd/wampproto"
)

func TestRunGenerateChallenge(t *testing.T) {
	const cryptoSignChallengeLen = 32

	t.Run("OutputHex", func(t *testing.T) {
		command := []string{"cmd", "auth", "cryptosign", "generate-challenge", "--output", "hex"}
		output, err := main.Run(command)
		require.NoError(t, err)

		outputBytes, err := hex.DecodeString(output)
		require.NoError(t, err)
		require.Len(t, outputBytes, cryptoSignChallengeLen)
	})

	t.Run("OutputBase64", func(t *testing.T) {
		command := []string{"cmd", "auth", "cryptosign", "generate-challenge", "--output", "base64"}
		output, err := main.Run(command)
		require.NoError(t, err)

		outputBytes, err := base64.StdEncoding.DecodeString(output)
		require.NoError(t, err)
		require.Len(t, outputBytes, cryptoSignChallengeLen)
	})
}

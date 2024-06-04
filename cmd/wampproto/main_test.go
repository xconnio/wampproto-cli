package main_test

import (
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/xconnio/wampproto-cli"
	"github.com/xconnio/wampproto-cli/cmd/wampproto"
)

func TestRunGenerateChallenge(t *testing.T) {
	const cryptoSignChallengeLen = 32

	t.Run("OutputHex", func(t *testing.T) {
		command := []string{"cmd", "auth", "cryptosign", "generate-challenge", "--output", "hex"}
		output, err := main.Run(command)
		require.NoError(t, err)

		outputBytes, err := hex.DecodeString(output)
		wampprotocli.NoErrorLen(t, err, outputBytes, cryptoSignChallengeLen)
	})

	t.Run("OutputBase64", func(t *testing.T) {
		command := []string{"cmd", "auth", "cryptosign", "generate-challenge", "--output", "base64"}
		output, err := main.Run(command)
		require.NoError(t, err)

		outputBytes, err := base64.StdEncoding.DecodeString(output)
		wampprotocli.NoErrorLen(t, err, outputBytes, cryptoSignChallengeLen)
	})
}

func TestRunSignCryptoSignChallenge(t *testing.T) {
	const (
		signedChallengeLen = 96

		testChallenge        = "4bb64ae4ddf4e7d841f9194fd0771b81bbf9c90bac56b369dd5d73a311dba699"
		testBase64PrivateKey = "3Tp4+gHrRutOd2BqUxkrZL1CZq4qnbkDPkqPpxRpYu7gdFIbNZtgIuf6MUz4EUfcIQ4BTY9otdDB6GLmoDXlZA=="
		testHexPrivateKey    = "218319f062aacc0f5817728ae61d0605cd816780f0cf21c74126111a4f6d284d"
	)

	t.Run("OutputHex", func(t *testing.T) {
		command := fmt.Sprintf("cmd auth cryptosign sign-challenge --challenge %s --private-key %s --output hex",
			testChallenge, testHexPrivateKey)
		output, err := main.Run(strings.Split(command, " "))
		require.NoError(t, err)

		outputBytes, err := hex.DecodeString(output)
		wampprotocli.NoErrorLen(t, err, outputBytes, signedChallengeLen)
	})

	t.Run("OutputBase64", func(t *testing.T) {
		command := fmt.Sprintf("cmd auth cryptosign sign-challenge --challenge %s --private-key %s --output base64",
			testChallenge, testHexPrivateKey)
		output, err := main.Run(strings.Split(command, " "))
		require.NoError(t, err)

		outputBytes, err := base64.StdEncoding.DecodeString(output)
		wampprotocli.NoErrorLen(t, err, outputBytes, signedChallengeLen)
	})

	t.Run("Base64PrivateKey", func(t *testing.T) {
		command := fmt.Sprintf("cmd auth cryptosign sign-challenge --challenge %s --private-key %s --output hex",
			testChallenge, testBase64PrivateKey)
		output, err := main.Run(strings.Split(command, " "))
		require.NoError(t, err)

		outputBytes, err := hex.DecodeString(output)
		wampprotocli.NoErrorLen(t, err, outputBytes, signedChallengeLen)
	})

	t.Run("InvalidPrivateKey", func(t *testing.T) {
		command := fmt.Sprintf("cmd auth cryptosign sign-challenge --challenge %s --private-key %s --output hex",
			testChallenge, "mcbhagcakjhfcvsjvcjhvcjhv")
		_, err := main.Run(strings.Split(command, " "))
		require.Error(t, err)
	})
}

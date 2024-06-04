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

func TestRunVerifyCryptoSignSignature(t *testing.T) {
	const (
		testSignature = "34806bbdefe1d37c495d4f2c0d27d334155ab2cb244779ea2bddae92b4f3382036b9b519f3285e68a87f7468" +
			"8cbf20ed72dbbaae2381e8a3cf023127bf24d1004bb64ae4ddf4e7d841f9194fd0771b81bbf9c90bac56b369dd5d73a311dba699"
		testBase64PublicKey = "Ta9P/tQjNoYGK1BMKbjvdtRglZF3IvPt6X+fBQ6HIAU="
		testHexPublicKey    = "4daf4ffed4233686062b504c29b8ef76d46095917722f3ede97f9f050e872005"
	)

	t.Run("HexPublicKey", func(t *testing.T) {
		command := fmt.Sprintf("cmd auth cryptosign verify-signature --signature %s --public-key %s",
			testSignature, testHexPublicKey)
		output, err := main.Run(strings.Split(command, " "))
		wampprotocli.NoErrorEqual(t, err, "Signature verified successfully", output)

	})

	t.Run("Base64PublicKey", func(t *testing.T) {
		command := fmt.Sprintf("cmd auth cryptosign verify-signature --signature %s --public-key %s",
			testSignature, testBase64PublicKey)
		output, err := main.Run(strings.Split(command, " "))
		wampprotocli.NoErrorEqual(t, err, "Signature verified successfully", output)
	})

	t.Run("InvalidPublicKey", func(t *testing.T) {
		command := fmt.Sprintf("cmd auth cryptosign verify-signature --signature %s --public-key %s",
			testSignature, "ivalidPubKey")
		_, err := main.Run(strings.Split(command, " "))
		require.EqualError(t, err, "invalid public-key: must be of length 32")
	})

	t.Run("BadSignature", func(t *testing.T) {
		command := fmt.Sprintf("cmd auth cryptosign verify-signature --signature %s --public-key %s",
			"34806bbdefe1d37c495d4f2c0d27d334155ab2cb244779ea2bddae92b4f3382036b9b519f3285e68a87f7468"+
				"8cbf20ed72dbbaae2381e8a3cf023127bf24d1004bb64ae4ddf4e7d841f9194fd0771b81bbf9c90bac56b369dd5d73a311dba691",
			testBase64PublicKey)
		output, err := main.Run(strings.Split(command, " "))
		wampprotocli.NoErrorEqual(t, err, "Signature verification failed", output)
	})
}

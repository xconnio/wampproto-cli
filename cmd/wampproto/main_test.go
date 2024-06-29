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
		command := fmt.Sprintf("cmd auth cryptosign sign-challenge %s %s --output hex",
			testChallenge, testHexPrivateKey)
		output, err := main.Run(strings.Split(command, " "))
		require.NoError(t, err)

		outputBytes, err := hex.DecodeString(output)
		wampprotocli.NoErrorLen(t, err, outputBytes, signedChallengeLen)
	})

	t.Run("OutputBase64", func(t *testing.T) {
		command := fmt.Sprintf("cmd auth cryptosign sign-challenge %s %s --output base64",
			testChallenge, testHexPrivateKey)
		output, err := main.Run(strings.Split(command, " "))
		require.NoError(t, err)

		outputBytes, err := base64.StdEncoding.DecodeString(output)
		wampprotocli.NoErrorLen(t, err, outputBytes, signedChallengeLen)
	})

	t.Run("Base64PrivateKey", func(t *testing.T) {
		command := fmt.Sprintf("cmd auth cryptosign sign-challenge %s %s --output hex",
			testChallenge, testBase64PrivateKey)
		output, err := main.Run(strings.Split(command, " "))
		require.NoError(t, err)

		outputBytes, err := hex.DecodeString(output)
		wampprotocli.NoErrorLen(t, err, outputBytes, signedChallengeLen)
	})

	t.Run("InvalidPrivateKey", func(t *testing.T) {
		command := fmt.Sprintf("cmd auth cryptosign sign-challenge %s %s --output hex",
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
		command := fmt.Sprintf("cmd auth cryptosign verify-signature %s %s", testSignature, testHexPublicKey)
		output, err := main.Run(strings.Split(command, " "))
		wampprotocli.NoErrorEqual(t, err, "Signature verified successfully", output)
	})

	t.Run("Base64PublicKey", func(t *testing.T) {
		command := fmt.Sprintf("cmd auth cryptosign verify-signature %s %s", testSignature, testBase64PublicKey)
		output, err := main.Run(strings.Split(command, " "))
		wampprotocli.NoErrorEqual(t, err, "Signature verified successfully", output)
	})

	t.Run("InvalidPublicKey", func(t *testing.T) {
		command := fmt.Sprintf("cmd auth cryptosign verify-signature %s %s", testSignature, "ivalidPubKey")
		_, err := main.Run(strings.Split(command, " "))
		require.EqualError(t, err, "invalid public-key: must be of length 32")
	})

	t.Run("BadSignature", func(t *testing.T) {
		command := fmt.Sprintf("cmd auth cryptosign verify-signature %s %s",
			"34806bbdefe1d37c495d4f2c0d27d334155ab2cb244779ea2bddae92b4f3382036b9b519f3285e68a87f7468"+
				"8cbf20ed72dbbaae2381e8a3cf023127bf24d1004bb64ae4ddf4e7d841f9194fd0771b81bbf9c90bac56b369dd5d73a311dba691",
			testBase64PublicKey)
		_, err := main.Run(strings.Split(command, " "))
		require.EqualError(t, err, "signature verification failed")
	})
}

func TestGenerateCryptoSignKeypair(t *testing.T) {
	const publicPrivateKeyLen = 32

	extractKeys := func(output string) (string, string) {
		before, after, found := strings.Cut(output, "\n")
		require.True(t, found)

		publicKey, found := strings.CutPrefix(before, "Public Key: ")
		require.True(t, found)
		privateKey, found := strings.CutPrefix(after, "Private Key: ")
		require.True(t, found)

		return publicKey, privateKey
	}

	t.Run("OutputHex", func(t *testing.T) {
		command := "cmd auth cryptosign keygen --output hex"
		output, err := main.Run(strings.Split(command, " "))
		require.NoError(t, err)

		publicKey, privateKey := extractKeys(output)

		publicKeyBytes, err := hex.DecodeString(publicKey)
		wampprotocli.NoErrorLen(t, err, publicKeyBytes, publicPrivateKeyLen)

		privateKeyBytes, err := hex.DecodeString(privateKey)
		wampprotocli.NoErrorLen(t, err, privateKeyBytes, publicPrivateKeyLen)
	})

	t.Run("OutputBase64", func(t *testing.T) {
		command := "cmd auth cryptosign keygen --output base64"
		output, err := main.Run(strings.Split(command, " "))
		require.NoError(t, err)

		publicKey, privateKey := extractKeys(output)

		publicKeyBytes, err := base64.StdEncoding.DecodeString(publicKey)
		wampprotocli.NoErrorLen(t, err, publicKeyBytes, publicPrivateKeyLen)

		privateKeyBytes, err := base64.StdEncoding.DecodeString(strings.TrimSpace(privateKey))
		wampprotocli.NoErrorLen(t, err, privateKeyBytes, publicPrivateKeyLen)
	})

	t.Run("TestGetPublicKey", func(t *testing.T) {
		const (
			testPublicKey  = "58fda9f9f04539dde555a3e330f416c6e93506c2684d014a66f9d7175da72288"
			testPrivateKey = "a67b4a69b248f9d140f8a882015d58bd8e184529c7dd4cfe3e8589aec38d94e3"

			testPublicKeyBase64  = "WP2p+fBFOd3lVaPjMPQWxuk1BsJoTQFKZvnXF12nIog="
			testPrivateKeyBase64 = "pntKabJI+dFA+KiCAV1YvY4YRSnH3Uz+PoWJrsONlOM="
		)

		t.Run("OutputHex", func(t *testing.T) {
			command := fmt.Sprintf("wampproto auth cryptosign get-pubkey %s --output hex", testPrivateKey)
			output, err := main.Run(strings.Split(command, " "))
			require.NoError(t, err)

			require.Equal(t, testPublicKey, output)
		})

		t.Run("OutputBase64", func(t *testing.T) {
			command := fmt.Sprintf("wampproto auth cryptosign get-pubkey %s --output base64", testPrivateKey)
			output, err := main.Run(strings.Split(command, " "))
			require.NoError(t, err)

			require.Equal(t, testPublicKeyBase64, output)
		})

		t.Run("Base64PrivateKey", func(t *testing.T) {
			command := fmt.Sprintf("wampproto auth cryptosign get-pubkey %s --output hex", testPrivateKeyBase64)
			output, err := main.Run(strings.Split(command, " "))
			require.NoError(t, err)

			require.Equal(t, testPublicKey, output)
		})

		t.Run("InvalidPrivateKeyFormat", func(t *testing.T) {
			command := "wampproto auth cryptosign get-pubkey invalidString --output base64"
			_, err := main.Run(strings.Split(command, " "))
			require.EqualError(t, err, "invalid private-key: must be in either hexadecimal or base64 format")
		})

		t.Run("InvalidPrivateKey", func(t *testing.T) {
			command := "wampproto auth cryptosign get-pubkey 48656c6c6f20576f726c64 --output base64"

			require.Panics(t, func() {
				_, _ = main.Run(strings.Split(command, " "))
			})
		})
	})
}

func testMessageCommand(t *testing.T, command string) {
	t.Run("OutputHex", func(t *testing.T) {
		output, err := main.Run(strings.Split(command, " "))
		require.NoError(t, err)

		_, err = hex.DecodeString(output)
		require.NoError(t, err)
	})

	t.Run("OutputBase64", func(t *testing.T) {
		output, err := main.Run(strings.Split(command+" --output base64", " "))
		require.NoError(t, err)

		_, err = base64.StdEncoding.DecodeString(output)
		require.NoError(t, err)
	})

	t.Run("CBORSerializer", func(t *testing.T) {
		output, err := main.Run(strings.Split(command+" --serializer cbor", " "))
		require.NoError(t, err)

		_, err = hex.DecodeString(output)
		require.NoError(t, err)
	})

	t.Run("MsgPackSerializer", func(t *testing.T) {
		output, err := main.Run(strings.Split(command+" --serializer msgpack", " "))
		require.NoError(t, err)

		_, err = hex.DecodeString(output)
		require.NoError(t, err)
	})

	t.Run("ProtobufSerailizer", func(t *testing.T) {
		output, err := main.Run(strings.Split(command+" --serializer protobuf", " "))
		require.NoError(t, err)

		_, err = hex.DecodeString(output)
		require.NoError(t, err)
	})
}

func TestHelloMessage(t *testing.T) {
	var command = "wampproto message hello realm1 anonymous ticket wampcra --authid 1 -e abc:xyz --authextra foo:bar " +
		"--roles caller:true -r callee:false"

	testMessageCommand(t, command)

	t.Run("NoAuthExtraNoRoles", func(t *testing.T) {
		var cmd = "wampproto message hello realm1 anonymous ticket wampcra"
		output, err := main.Run(strings.Split(cmd, " "))
		require.NoError(t, err)

		_, err = hex.DecodeString(output)
		require.NoError(t, err)
	})
}

func TestWelcomeMessage(t *testing.T) {
	var command = "wampproto message welcome 1 -d foo:bar -d 123:true"

	testMessageCommand(t, command)

	t.Run("NoDetails", func(t *testing.T) {
		var cmd = "wampproto message welcome 1"
		output, err := main.Run(strings.Split(cmd, " "))
		require.NoError(t, err)

		_, err = hex.DecodeString(output)
		require.NoError(t, err)
	})
}

func TestChallengeMessage(t *testing.T) {
	var command = "wampproto message challenge wampcra -e challenge:bar -e foo:true"

	testMessageCommand(t, command)

	t.Run("NoExtra", func(t *testing.T) {
		var cmd = "wampproto message challenge cryptosign"
		output, err := main.Run(strings.Split(cmd, " "))
		require.NoError(t, err)

		_, err = hex.DecodeString(output)
		require.NoError(t, err)
	})
}

func TestAuthenticateCommand(t *testing.T) {
	var command = "wampproto message authenticate abc -e abc:123 -e foo:bar"

	testMessageCommand(t, command)

	t.Run("NoExtra", func(t *testing.T) {
		var cmd = "wampproto message authenticate abc"
		output, err := main.Run(strings.Split(cmd, " "))
		require.NoError(t, err)

		_, err = hex.DecodeString(output)
		require.NoError(t, err)
	})
}

func TestAbortCommand(t *testing.T) {
	var command = "wampproto message abort noreason abc 123 true -d abc:123 -k foo:bar"

	testMessageCommand(t, command)

	t.Run("NoArgsKwargsDetails", func(t *testing.T) {
		var cmd = "wampproto message abort noreason"
		output, err := main.Run(strings.Split(cmd, " "))
		require.NoError(t, err)

		_, err = hex.DecodeString(output)
		require.NoError(t, err)
	})
}

func TestCallMessage(t *testing.T) {
	var command = "wampproto message call 1 io.xconn.test abc -k key:value abc=123"

	testMessageCommand(t, command)

	t.Run("NoArgsKwargs", func(t *testing.T) {
		var cmd = "wampproto message call 1 io.xconn.test"
		output, err := main.Run(strings.Split(cmd, " "))
		require.NoError(t, err)

		_, err = hex.DecodeString(output)
		require.NoError(t, err)
	})
}

func TestResultMessage(t *testing.T) {
	var command = "wampproto message result 1"

	testMessageCommand(t, command)

	t.Run("WithArgsKwargsDetails", func(t *testing.T) {
		var cmd = command + " abc def --details abc=def -k key:value abc=123"
		output, err := main.Run(strings.Split(cmd, " "))
		require.NoError(t, err)

		_, err = hex.DecodeString(output)
		require.NoError(t, err)
	})
}

func TestRegisterMessage(t *testing.T) {
	var command = "wampproto message register 1 io.xconn.test"

	testMessageCommand(t, command)

	t.Run("WithOptions", func(t *testing.T) {
		var cmd = command + " -o invoke=roundrobin"
		output, err := main.Run(strings.Split(cmd, " "))
		require.NoError(t, err)

		_, err = hex.DecodeString(output)
		require.NoError(t, err)
	})
}

func TestRegisteredMessage(t *testing.T) {
	var command = "wampproto message registered 1 1"

	testMessageCommand(t, command)
}

func TestInvocationMessage(t *testing.T) {
	var command = "wampproto message invocation 1 1"

	testMessageCommand(t, command)

	t.Run("WithArgsKwargsDetails", func(t *testing.T) {
		var cmd = command + " abc def --details abc=def -k key:value abc=123"
		output, err := main.Run(strings.Split(cmd, " "))
		require.NoError(t, err)

		_, err = hex.DecodeString(output)
		require.NoError(t, err)
	})
}

func TestYieldMessage(t *testing.T) {
	var command = "wampproto message yield 1"

	testMessageCommand(t, command)

	t.Run("WithArgsKwargsOptions", func(t *testing.T) {
		var cmd = command + " abc def -o abc=def -k key:value abc=123"
		output, err := main.Run(strings.Split(cmd, " "))
		require.NoError(t, err)

		_, err = hex.DecodeString(output)
		require.NoError(t, err)
	})
}

func TestUnRegisterMessage(t *testing.T) {
	var command = "wampproto message unregister 1 1"

	testMessageCommand(t, command)
}

func TestUnRegisteredMessage(t *testing.T) {
	var command = "wampproto message unregistered 1"

	testMessageCommand(t, command)
}

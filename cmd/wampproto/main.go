package main

import (
	"crypto/ed25519"
	"fmt"
	"log"
	"os"

	"github.com/alecthomas/kingpin/v2"

	"github.com/xconnio/wampproto-cli"
	"github.com/xconnio/wampproto-go/auth"
	"github.com/xconnio/wampproto-go/messages"
)

const (
	versionString = "0.1.0"
)

type cmd struct {
	parsedCommand string

	output *string

	auth *kingpin.CmdClause
	*CryptoSign

	message    *kingpin.CmdClause
	serializer *string
	*Call
}

func parseCmd(args []string) (*cmd, error) {
	app := kingpin.New(args[0], "A tool for testing interoperability between different wampproto implementations.")
	app.Version(versionString).VersionFlag.Short('v')

	authCommand := app.Command("auth", "Authentication commands.")

	cryptoSignCommand := authCommand.Command("cryptosign", "Commands for cryptosign authentication.")
	signChallengeCommand := cryptoSignCommand.Command("sign-challenge", "Sign a cryptosign challenge.")
	verifySignatureCommand := cryptoSignCommand.Command("verify-signature", "Verify a cryptosign challenge.")
	getPubKeyCommand := cryptoSignCommand.Command("get-pubkey",
		"Retrieve the ed25519 public key associated with the provided private key.")

	messageCommand := app.Command("message", "Wampproto messages.")
	callCommand := messageCommand.Command("call", "Call message.")
	c := &cmd{
		output: app.Flag("output", "Format of the output.").Default("hex").
			Enum(wampprotocli.HexFormat, wampprotocli.Base64Format),

		auth: authCommand,

		CryptoSign: &CryptoSign{
			cryptosign:        cryptoSignCommand,
			generateChallenge: cryptoSignCommand.Command("generate-challenge", "Generate a cryptosign challenge."),

			signChallenge: signChallengeCommand,
			challenge:     signChallengeCommand.Flag("challenge", "Challenge to sign.").Required().String(),
			privateKey:    signChallengeCommand.Flag("private-key", "Private key to sign challenge.").Required().String(),

			verifySignature: verifySignatureCommand,
			signature:       verifySignatureCommand.Flag("signature", "Signature to verify.").Required().String(),
			publicKey:       verifySignatureCommand.Flag("public-key", "Public key to verify signature.").Required().String(),

			generateKeyPair: cryptoSignCommand.Command("keygen", "Generate a WAMP cryptosign ed25519 keypair."),

			getPublicKey: getPubKeyCommand,
			privateKeyFlag: getPubKeyCommand.Flag("private-key",
				"The ed25519 private key to derive the corresponding public key.").Required().String(),
		},

		message: messageCommand,
		serializer: messageCommand.Flag("serializer", "Serializer to use.").Default(wampprotocli.JsonSerializer).
			Enum(wampprotocli.JsonSerializer, wampprotocli.CborSerializer, wampprotocli.MsgpackSerializer),

		Call: &Call{
			call:          callCommand,
			callRequestID: callCommand.Arg("request-id", "Call request ID.").Required().Int64(),
			callURI:       callCommand.Arg("procedure", "Procedure to call.").Required().String(),
			callArgs:      callCommand.Arg("args", "Arguments for the call.").Strings(),
			callKwargs:    callCommand.Flag("kwargs", "Keyword argument for the call.").Short('k').StringMap(),
			callOption:    callCommand.Flag("option", "Call options.").Short('o').StringMap(),
		},
	}

	parsedCommand, err := app.Parse(args[1:])
	if err != nil {
		return nil, err
	}
	c.parsedCommand = parsedCommand

	return c, nil
}

func Run(args []string) (string, error) {
	c, err := parseCmd(args)
	if err != nil {
		return "", err
	}

	switch c.parsedCommand {
	case c.generateChallenge.FullCommand():
		challenge, err := auth.GenerateCryptoSignChallenge()
		if err != nil {
			return "", err
		}

		return wampprotocli.FormatOutput(*c.output, challenge)

	case c.signChallenge.FullCommand():
		privateKeyBytes, err := wampprotocli.DecodeHexOrBase64(*c.privateKey)
		if err != nil {
			return "", fmt.Errorf("invalid private-key: %s", err.Error())
		}

		if len(privateKeyBytes) != 32 && len(privateKeyBytes) != 64 {
			return "", fmt.Errorf("invalid private-key: must be of length 32 or 64")
		}

		if len(privateKeyBytes) == 32 {
			privateKeyBytes = ed25519.NewKeyFromSeed(privateKeyBytes)
		}

		signedChallenge, err := auth.SignCryptoSignChallenge(*c.challenge, privateKeyBytes)
		if err != nil {
			return "", err
		}

		return wampprotocli.FormatOutput(*c.output, signedChallenge)

	case c.verifySignature.FullCommand():
		publicKeyBytes, err := wampprotocli.DecodeHexOrBase64(*c.publicKey)
		if err != nil {
			return "", fmt.Errorf("invalid public-key: %s", err.Error())
		}

		if len(publicKeyBytes) != 32 {
			return "", fmt.Errorf("invalid public-key: must be of length 32")
		}

		isVerified, err := auth.VerifyCryptoSignSignature(*c.signature, publicKeyBytes)
		if err != nil {
			return "", err
		}

		if isVerified {
			return "Signature verified successfully", nil
		}

		return "", fmt.Errorf("signature verification failed")

	case c.generateKeyPair.FullCommand():
		publicKey, privateKey, err := auth.GenerateCryptoSignKeyPair()
		if err != nil {
			return "", err
		}

		formatedPubKey, err := wampprotocli.FormatOutput(*c.output, publicKey)
		if err != nil {
			return "", err
		}

		formatedPriKey, err := wampprotocli.FormatOutput(*c.output, privateKey)
		if err != nil {
			return "", err
		}

		return fmt.Sprintf("Public Key: %s\nPrivate Key: %s", formatedPubKey, formatedPriKey), nil

	case c.getPublicKey.FullCommand():
		privateKeyBytes, err := wampprotocli.DecodeHexOrBase64(*c.privateKeyFlag)
		if err != nil {
			return "", fmt.Errorf("invalid private-key: %s", err.Error())
		}

		publicKeyBytes := ed25519.NewKeyFromSeed(privateKeyBytes).Public().(ed25519.PublicKey)

		return wampprotocli.FormatOutputBytes(*c.output, publicKeyBytes)

	case c.call.FullCommand():
		var (
			options   = wampprotocli.StringMapToTypedMap(*c.callOption)
			arguments = wampprotocli.StringsToTypedList(*c.callArgs)
			kwargs    = wampprotocli.StringMapToTypedMap(*c.callKwargs)

			serializer = wampprotocli.SerializerByName(*c.serializer)
		)
		callMessage := messages.NewCall(*c.callRequestID, options, *c.callURI, arguments, kwargs)

		serializedMessage, err := serializer.Serialize(callMessage)
		if err != nil {
			return "", err
		}

		return wampprotocli.FormatOutputBytes(*c.output, serializedMessage)
	}

	return "", nil
}

func main() {
	output, err := Run(os.Args)
	if err != nil {
		log.Fatalln(err)
	}

	fmt.Println(output)
}

package main

import (
	"crypto/ed25519"
	"encoding/hex"
	"fmt"
	"log"
	"os"

	"github.com/alecthomas/kingpin/v2"

	"github.com/xconnio/wampproto-cli"
	"github.com/xconnio/wampproto-go/auth"
)

const (
	versionString = "0.1.0"

	HexFormat    = "hex"
	Base64Format = "base64"
)

type cmd struct {
	parsedCommand string

	output *string

	auth *kingpin.CmdClause

	cryptosign *kingpin.CmdClause

	generateChallenge *kingpin.CmdClause

	signChallenge *kingpin.CmdClause
	challenge     *string
	privateKey    *string

	verifySignature *kingpin.CmdClause
	signature       *string
	publicKey       *string

	generateKeyPair *kingpin.CmdClause

	getPublicKey   *kingpin.CmdClause
	privateKeyFlag *string
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
	c := &cmd{
		output: app.Flag("output", "Format of the output.").Default("hex").Enum(HexFormat, Base64Format),

		auth: authCommand,

		cryptosign: cryptoSignCommand,

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

		return formatOutput(*c.output, challenge)

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

		return formatOutput(*c.output, signedChallenge)

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

		return "Signature verification failed", nil

	case c.generateKeyPair.FullCommand():
		publicKey, privateKey, err := auth.GenerateCryptoSignKeyPair()
		if err != nil {
			return "", err
		}

		formatedPubKey, err := formatOutput(*c.output, publicKey)
		if err != nil {
			return "", err
		}

		formatedPriKey, err := formatOutput(*c.output, privateKey)
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

		return formatOutput(*c.output, hex.EncodeToString(publicKeyBytes))
	}

	return "", nil
}

func formatOutput(outputFormat, outputString string) (string, error) {
	switch outputFormat {
	case HexFormat:
		return outputString, nil

	case Base64Format:
		base64Str, err := wampprotocli.HexToBase64(outputString)
		if err != nil {
			return "", err
		}

		return base64Str, err

	default:
		return "", fmt.Errorf("invalid output format")
	}
}

func main() {
	output, err := Run(os.Args)
	if err != nil {
		log.Fatalln(err)
	}

	fmt.Println(output)
}

package main

import (
	"crypto/ed25519"
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
}

func parseCmd(args []string) (*cmd, error) {
	app := kingpin.New(args[0], "A tool for testing interoperability between different wampproto implementations.")
	app.Version(versionString).VersionFlag.Short('v')

	authCommand := app.Command("auth", "Authentication commands.")

	cryptoSignCommand := authCommand.Command("cryptosign", "Commands for cryptosign authentication.")
	signChallengeCommand := cryptoSignCommand.Command("sign-challenge", "Sign a cryptosign challenge.")
	c := &cmd{
		output: app.Flag("output", "Format of the output.").Default("hex").Enum(HexFormat, Base64Format),

		auth: authCommand,

		cryptosign: cryptoSignCommand,

		generateChallenge: cryptoSignCommand.Command("generate-challenge", "Generate a cryptosign challenge."),

		signChallenge: signChallengeCommand,
		challenge:     signChallengeCommand.Flag("challenge", "Challenge to sign.").Required().String(),
		privateKey:    signChallengeCommand.Flag("private-key", "Private key to sign challenge.").Required().String(),
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

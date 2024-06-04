package main

import (
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

	auth              *kingpin.CmdClause
	cryptosign        *kingpin.CmdClause
	generateChallenge *kingpin.CmdClause
}

func parseCmd(args []string) (*cmd, error) {
	app := kingpin.New(args[0], "A tool for testing interoperability between different wampproto implementations.")
	app.Version(versionString).VersionFlag.Short('v')

	authCommand := app.Command("auth", "Authentication commands.")

	cryptoSignCommand := authCommand.Command("cryptosign", "Commands for cryptosign authentication.")

	c := &cmd{
		output: app.Flag("output", "Format of the output.").Default("hex").Enum(HexFormat, Base64Format),

		auth: authCommand,

		cryptosign: cryptoSignCommand,

		generateChallenge: cryptoSignCommand.Command("generate-challenge", "Generate a cryptosign challenge."),
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

		switch *c.output {
		case HexFormat:
			return challenge, nil

		case Base64Format:
			base64Str, err := wampprotocli.HexToBase64(challenge)
			if err != nil {
				return "", err
			}

			return base64Str, err
		}

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

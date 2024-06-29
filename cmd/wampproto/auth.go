package main

import "github.com/alecthomas/kingpin/v2"

type CryptoSign struct {
	cryptosign *kingpin.CmdClause

	generateChallenge *kingpin.CmdClause

	signChallenge       *kingpin.CmdClause
	cryptoSignChallenge *string
	privateKey          *string

	verifySignature     *kingpin.CmdClause
	cryptoSignSignature *string
	publicKey           *string

	generateKeyPair *kingpin.CmdClause

	getPublicKey   *kingpin.CmdClause
	privateKeyFlag *string
}

type CRA struct {
	cra *kingpin.CmdClause

	generateCRAChallenge *kingpin.CmdClause
	craSessionID         *int64
	craAuthID            *string
	craAuthRole          *string
	craProvider          *string

	deriveKey *kingpin.CmdClause
	salt      *string
	secret    *string
	iteration *int
	keylen    *int

	signCRAChallenge *kingpin.CmdClause
	craChallenge     *string
	craKey           *string
}

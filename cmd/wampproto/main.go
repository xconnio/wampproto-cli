package main

import (
	"crypto/ed25519"
	"fmt"
	"log"
	"os"

	"github.com/alecthomas/kingpin/v2"

	wampprotocli "github.com/xconnio/wampproto-cli"
	"github.com/xconnio/wampproto-go/auth"
	"github.com/xconnio/wampproto-go/messages"
	"github.com/xconnio/wampproto-go/serializers"
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
	*Hello
	*Welcome
	*Challenge
	*Authenticate
	*Abort
	*Error
	*Interrupt
	*Cancel
	*GoodBye
	*Call
	*Result
	*Register
	*Registered
	*Invocation
	*Yield
	*UnRegister
	*UnRegistered
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
	helloCommand := messageCommand.Command("hello", "Hello message.")
	welcomeCommand := messageCommand.Command("welcome", "Welcome message.")
	challengeCommand := messageCommand.Command("challenge", "Challenge message.")
	authenticateCommand := messageCommand.Command("authenticate", "Authenticate message.")
	abortCommand := messageCommand.Command("abort", "Abort message.")
	errorCommand := messageCommand.Command("error", "Error message.")
	cancelCommand := messageCommand.Command("cancel", "Cancel message.")
	interruptCommand := messageCommand.Command("interrupt", "Interrupt message.")
	goodByeCommand := messageCommand.Command("goodbye", "Goodbye message.")
	callCommand := messageCommand.Command("call", "Call message.")
	resultCommand := messageCommand.Command("result", "Result messages.")
	registerCommand := messageCommand.Command("register", "Register message.")
	registeredCommand := messageCommand.Command("registered", "Registered message.")
	invocationCommand := messageCommand.Command("invocation", "Invocation message.")
	yieldCommand := messageCommand.Command("yield", "Yield message.")
	UnRegisterCommand := messageCommand.Command("unregister", "Unregister message.")
	UnRegisteredCommand := messageCommand.Command("unregistered", "Unregistered message.")
	c := &cmd{
		output: app.Flag("output", "Format of the output.").Default("hex").
			Enum(wampprotocli.HexFormat, wampprotocli.Base64Format),

		auth: authCommand,

		CryptoSign: &CryptoSign{
			cryptosign:        cryptoSignCommand,
			generateChallenge: cryptoSignCommand.Command("generate-challenge", "Generate a cryptosign challenge."),

			signChallenge:       signChallengeCommand,
			cryptoSignChallenge: signChallengeCommand.Arg("challenge", "Challenge to sign.").Required().String(),
			privateKey:          signChallengeCommand.Arg("private-key", "Private key to sign challenge.").Required().String(),

			verifySignature:     verifySignatureCommand,
			cryptoSignSignature: verifySignatureCommand.Arg("signature", "Signature to verify.").Required().String(),
			publicKey:           verifySignatureCommand.Arg("public-key", "Public key to verify signature.").Required().String(),

			generateKeyPair: cryptoSignCommand.Command("keygen", "Generate a WAMP cryptosign ed25519 keypair."),

			getPublicKey: getPubKeyCommand,
			privateKeyFlag: getPubKeyCommand.Arg("private-key",
				"The ed25519 private key to derive the corresponding public key.").Required().String(),
		},

		message: messageCommand,
		serializer: messageCommand.Flag("serializer", "Serializer to use.").Default(wampprotocli.JsonSerializer).
			Enum(wampprotocli.JsonSerializer, wampprotocli.CborSerializer, wampprotocli.MsgpackSerializer,
				wampprotocli.ProtobufSerializer),

		Hello: &Hello{
			hello: helloCommand,
			realm: helloCommand.Arg("realm", "The WAMP realm.").Required().String(),
			authMethods: helloCommand.Arg("authmethods", "The authentication methods").Default(wampprotocli.Anonymous).
				Enums(wampprotocli.Anonymous, wampprotocli.Ticket, wampprotocli.WAMPCra, wampprotocli.CryptoSign),
			authID:    helloCommand.Flag("authid", "The authid.").Default("").String(),
			authExtra: helloCommand.Flag("authextra", "Additional authentication data.").Short('e').StringMap(),
			roles:     helloCommand.Flag("roles", "Client roles.").Short('r').StringMap(),
		},

		Welcome: &Welcome{
			welcome:        welcomeCommand,
			sessionID:      welcomeCommand.Arg("session-id", "WAMP session ID.").Required().Int64(),
			welcomeDetails: welcomeCommand.Flag("detail", "Welcome details.").Short('d').StringMap(),
		},

		Challenge: &Challenge{
			challenge: challengeCommand,
			authMethod: challengeCommand.Arg("authmethod", "The authentication method.").Required().
				Enum(wampprotocli.Anonymous, wampprotocli.Ticket, wampprotocli.WAMPCra, wampprotocli.CryptoSign),
			challengeExtra: challengeCommand.Flag("extra", "Additional challenge data.").Short('e').StringMap(),
		},

		Authenticate: &Authenticate{
			authenticate:      authenticateCommand,
			signature:         authenticateCommand.Arg("signature", "Signature to authenticate.").Required().String(),
			authenticateExtra: authenticateCommand.Flag("extra", "Additional authentication data.").Short('e').StringMap(),
		},

		Abort: &Abort{
			abort:        abortCommand,
			abortReason:  abortCommand.Arg("reason", "Reason to abort.").Required().String(),
			abortDetails: abortCommand.Flag("detail", "Additional abort data.").Short('d').StringMap(),
			abortArgs:    abortCommand.Arg("args", "Arguments of abort").Strings(),
			abortKwArgs:  abortCommand.Flag("kwargs", "Keyword arguments of abort").Short('k').StringMap(),
		},

		Error: &Error{
			error:       errorCommand,
			messageType: errorCommand.Arg("message-type", "The ID of message associated with the error.").Required().Int64(),
			errorRequestID: errorCommand.Arg("request-id", "The ID of the request that resulted in the error").
				Required().Int64(),
			errorDetails: errorCommand.Flag("detail", "Additional error data.").Short('d').StringMap(),
			errorUri:     errorCommand.Arg("uri", "Error URI.").Required().String(),
			errorArgs:    errorCommand.Arg("args", "Arguments of error.").Strings(),
			errorKwArgs:  errorCommand.Flag("kwargs", "Keyword arguments of error.").Short('k').StringMap(),
		},

		Cancel: &Cancel{
			cancel:          cancelCommand,
			cancelRequestID: cancelCommand.Arg("request-id", "The ID of request to cancel.").Required().Int64(),
			cancelOptions:   cancelCommand.Flag("options", "Cancel options.").Short('o').StringMap(),
		},

		Interrupt: &Interrupt{
			interrupt:          interruptCommand,
			interruptRequestID: interruptCommand.Arg("request-id", "The ID of request to interrupt.").Required().Int64(),
			interruptOptions:   interruptCommand.Flag("options", "Interrupt options.").Short('o').StringMap(),
		},

		GoodBye: &GoodBye{
			goodBye:        goodByeCommand,
			goodByeReason:  goodByeCommand.Arg("reason", "GoodBye reason.").Required().String(),
			goodByeDetails: goodByeCommand.Flag("detail", "GoodBye details.").Short('d').StringMap(),
		},

		Call: &Call{
			call:          callCommand,
			callRequestID: callCommand.Arg("request-id", "Call request ID.").Required().Int64(),
			callURI:       callCommand.Arg("procedure", "Procedure to call.").Required().String(),
			callArgs:      callCommand.Arg("args", "Arguments for the call.").Strings(),
			callKwargs:    callCommand.Flag("kwargs", "Keyword argument for the call.").Short('k').StringMap(),
			callOption:    callCommand.Flag("option", "Call options.").Short('o').StringMap(),
		},

		Result: &Result{
			result:          resultCommand,
			resultRequestID: resultCommand.Arg("request-id", "Result request ID.").Required().Int64(),
			resultDetails:   resultCommand.Flag("detail", "Result details.").Short('d').StringMap(),
			resultArgs:      resultCommand.Arg("args", "Result Arguments").Strings(),
			resultKwargs:    resultCommand.Flag("kwargs", "Result KW Arguments.").Short('k').StringMap(),
		},

		Register: &Register{
			register:     registerCommand,
			regRequestID: registerCommand.Arg("request-id", "Request request ID.").Required().Int64(),
			regProcedure: registerCommand.Arg("procedure", "Procedure to register.").Required().String(),
			regOptions:   registerCommand.Flag("option", "Register options.").Short('o').StringMap(),
		},

		Registered: &Registered{
			registered:          registeredCommand,
			registeredRequestID: registeredCommand.Arg("request-id", "Registered request ID.").Required().Int64(),
			registrationID:      registeredCommand.Arg("registration-id", "Registration ID.").Required().Int64(),
		},

		Invocation: &Invocation{
			invocation:        invocationCommand,
			invRequestID:      invocationCommand.Arg("request-id", "Invocation request ID.").Required().Int64(),
			invRegistrationID: invocationCommand.Arg("registration-id", "Invocation registration ID.").Required().Int64(),
			invDetails:        invocationCommand.Flag("detail", "Invocation details.").Short('d').StringMap(),
			invArgs:           invocationCommand.Arg("args", "Invocation arguments.").Strings(),
			invKwArgs:         invocationCommand.Flag("kwargs", "Invocation KW arguments.").Short('k').StringMap(),
		},

		Yield: &Yield{
			yield:          yieldCommand,
			yieldRequestID: yieldCommand.Arg("request-id", "Yield request ID.").Required().Int64(),
			yieldOptions:   yieldCommand.Flag("option", "Yield options.").Short('o').StringMap(),
			yieldArgs:      yieldCommand.Arg("args", "Yield arguments.").Strings(),
			yieldKwArgs:    yieldCommand.Flag("kwargs", "Yield KW arguments.").Short('k').StringMap(),
		},

		UnRegister: &UnRegister{
			unRegister:          UnRegisterCommand,
			unRegRequestID:      UnRegisterCommand.Arg("request-id", "UnRegister request ID.").Required().Int64(),
			unRegRegistrationID: UnRegisterCommand.Arg("registration-id", "UnRegister registration ID.").Required().Int64(),
		},

		UnRegistered: &UnRegistered{
			unRegistered:          UnRegisteredCommand,
			UnRegisteredRequestID: UnRegisteredCommand.Arg("request-id", "UnRegistered request ID.").Required().Int64(),
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

		signedChallenge, err := auth.SignCryptoSignChallenge(*c.cryptoSignChallenge, privateKeyBytes)
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

		isVerified, err := auth.VerifyCryptoSignSignature(*c.cryptoSignSignature, publicKeyBytes)
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

	case c.hello.FullCommand():
		var (
			authExtra = wampprotocli.StringMapToTypedMap(*c.authExtra)
			roles     = wampprotocli.StringMapToTypedMap(*c.roles)

			serializer = wampprotocli.SerializerByName(*c.serializer)
		)

		helloMessage := messages.NewHello(*c.realm, *c.authID, authExtra, roles, *c.authMethods)

		return serializeMessageAndOutput(serializer, helloMessage, *c.output)

	case c.welcome.FullCommand():
		var (
			details = wampprotocli.StringMapToTypedMap(*c.welcomeDetails)

			serializer = wampprotocli.SerializerByName(*c.serializer)
		)

		welcomeMessage := messages.NewWelcome(*c.sessionID, details)

		return serializeMessageAndOutput(serializer, welcomeMessage, *c.output)

	case c.challenge.FullCommand():
		var (
			challengeExtra = wampprotocli.StringMapToTypedMap(*c.challengeExtra)

			serializer = wampprotocli.SerializerByName(*c.serializer)
		)

		challengeMessage := messages.NewChallenge(*c.authMethod, challengeExtra)

		return serializeMessageAndOutput(serializer, challengeMessage, *c.output)

	case c.authenticate.FullCommand():
		var (
			authenticateExtra = wampprotocli.StringMapToTypedMap(*c.authenticateExtra)

			serializer = wampprotocli.SerializerByName(*c.serializer)
		)

		authenticateMessage := messages.NewAuthenticate(*c.signature, authenticateExtra)

		return serializeMessageAndOutput(serializer, authenticateMessage, *c.output)

	case c.abort.FullCommand():
		var (
			abortDetails = wampprotocli.StringMapToTypedMap(*c.abortDetails)
			abortArgs    = wampprotocli.StringsToTypedList(*c.abortArgs)
			abortKwargs  = wampprotocli.StringMapToTypedMap(*c.abortKwArgs)

			serializer = wampprotocli.SerializerByName(*c.serializer)
		)

		abortMessage := messages.NewAbort(abortDetails, *c.abortReason, abortArgs, abortKwargs)

		return serializeMessageAndOutput(serializer, abortMessage, *c.output)

	case c.error.FullCommand():
		var (
			errorDetails = wampprotocli.StringMapToTypedMap(*c.errorDetails)
			errorArgs    = wampprotocli.StringsToTypedList(*c.errorArgs)
			errorKwargs  = wampprotocli.StringMapToTypedMap(*c.errorKwArgs)

			serializer = wampprotocli.SerializerByName(*c.serializer)
		)

		errorMessage := messages.NewError(*c.messageType, *c.errorRequestID, errorDetails, *c.errorUri, errorArgs,
			errorKwargs)

		return serializeMessageAndOutput(serializer, errorMessage, *c.output)

	case c.cancel.FullCommand():
		var (
			cancelOptions = wampprotocli.StringMapToTypedMap(*c.cancelOptions)

			serializer = wampprotocli.SerializerByName(*c.serializer)
		)

		cancelMessage := messages.NewCancel(*c.sessionID, cancelOptions)

		return serializeMessageAndOutput(serializer, cancelMessage, *c.output)

	case c.interrupt.FullCommand():
		var (
			interruptOptions = wampprotocli.StringMapToTypedMap(*c.interruptOptions)

			serializer = wampprotocli.SerializerByName(*c.serializer)
		)

		interruptMessage := messages.NewInterrupt(*c.sessionID, interruptOptions)

		return serializeMessageAndOutput(serializer, interruptMessage, *c.output)

	case c.goodBye.FullCommand():
		var (
			goodByeDetails = wampprotocli.StringMapToTypedMap(*c.goodByeDetails)

			serializer = wampprotocli.SerializerByName(*c.serializer)
		)
		goodByeMessage := messages.NewGoodBye(*c.goodByeReason, goodByeDetails)

		return serializeMessageAndOutput(serializer, goodByeMessage, *c.output)

	case c.call.FullCommand():
		var (
			options   = wampprotocli.StringMapToTypedMap(*c.callOption)
			arguments = wampprotocli.StringsToTypedList(*c.callArgs)
			kwargs    = wampprotocli.StringMapToTypedMap(*c.callKwargs)

			serializer = wampprotocli.SerializerByName(*c.serializer)
		)

		arguments, kwargs = wampprotocli.UpdateArgsKwArgsIfEmpty(arguments, kwargs)

		callMessage := messages.NewCall(*c.callRequestID, options, *c.callURI, arguments, kwargs)

		return serializeMessageAndOutput(serializer, callMessage, *c.output)

	case c.result.FullCommand():
		var (
			details   = wampprotocli.StringMapToTypedMap(*c.resultDetails)
			arguments = wampprotocli.StringsToTypedList(*c.resultArgs)
			kwargs    = wampprotocli.StringMapToTypedMap(*c.resultKwargs)

			serializer = wampprotocli.SerializerByName(*c.serializer)
		)

		arguments, kwargs = wampprotocli.UpdateArgsKwArgsIfEmpty(arguments, kwargs)

		resultMessage := messages.NewResult(*c.resultRequestID, details, arguments, kwargs)

		return serializeMessageAndOutput(serializer, resultMessage, *c.output)

	case c.register.FullCommand():
		var (
			options    = wampprotocli.StringMapToTypedMap(*c.regOptions)
			serializer = wampprotocli.SerializerByName(*c.serializer)
		)

		regMessage := messages.NewRegister(*c.regRequestID, options, *c.regProcedure)

		return serializeMessageAndOutput(serializer, regMessage, *c.output)

	case c.registered.FullCommand():
		var serializer = wampprotocli.SerializerByName(*c.serializer)

		registeredCmd := messages.NewRegistered(*c.registeredRequestID, *c.registrationID)

		return serializeMessageAndOutput(serializer, registeredCmd, *c.output)

	case c.invocation.FullCommand():
		var (
			details   = wampprotocli.StringMapToTypedMap(*c.invDetails)
			arguments = wampprotocli.StringsToTypedList(*c.invArgs)
			kwargs    = wampprotocli.StringMapToTypedMap(*c.invKwArgs)

			serializer = wampprotocli.SerializerByName(*c.serializer)
		)

		arguments, kwargs = wampprotocli.UpdateArgsKwArgsIfEmpty(arguments, kwargs)

		invocationMessage := messages.NewInvocation(*c.invRequestID, *c.invRegistrationID, details, arguments, kwargs)

		return serializeMessageAndOutput(serializer, invocationMessage, *c.output)

	case c.yield.FullCommand():
		var (
			options   = wampprotocli.StringMapToTypedMap(*c.yieldOptions)
			arguments = wampprotocli.StringsToTypedList(*c.yieldArgs)
			kwargs    = wampprotocli.StringMapToTypedMap(*c.yieldKwArgs)

			serializer = wampprotocli.SerializerByName(*c.serializer)
		)

		arguments, kwargs = wampprotocli.UpdateArgsKwArgsIfEmpty(arguments, kwargs)

		yieldMessage := messages.NewYield(*c.yieldRequestID, options, arguments, kwargs)

		return serializeMessageAndOutput(serializer, yieldMessage, *c.output)

	case c.unRegister.FullCommand():
		var serializer = wampprotocli.SerializerByName(*c.serializer)

		unRegisterMessage := messages.NewUnRegister(*c.registeredRequestID, *c.unRegRegistrationID)

		return serializeMessageAndOutput(serializer, unRegisterMessage, *c.output)

	case c.unRegistered.FullCommand():
		var serializer = wampprotocli.SerializerByName(*c.serializer)

		unRegisteredMessage := messages.NewUnRegistered(*c.UnRegisteredRequestID)

		return serializeMessageAndOutput(serializer, unRegisteredMessage, *c.output)
	}

	return "", nil
}

func serializeMessageAndOutput(serializer serializers.Serializer, message messages.Message,
	outputFormat string) (string, error) {
	serializedMessage, err := serializer.Serialize(message)
	if err != nil {
		return "", err
	}

	return wampprotocli.FormatOutputBytes(outputFormat, serializedMessage)
}

func main() {
	output, err := Run(os.Args)
	if err != nil {
		log.Fatalln(err)
	}

	fmt.Println(output)
}

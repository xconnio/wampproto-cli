package main

import (
	"github.com/alecthomas/kingpin/v2"
)

type Hello struct {
	hello       *kingpin.CmdClause
	realm       *string
	authID      *string
	authMethods *[]string
	authExtra   *map[string]string
	roles       *map[string]string
}

type Welcome struct {
	welcome           *kingpin.CmdClause
	sessionID         *uint64
	welcomeRoles      *map[string]string
	welcomeAuthid     *string
	welcomeAuthRole   *string
	welcomeAuthMethod *string
	welcomeAuthExtra  *map[string]string
}

type Challenge struct {
	challenge      *kingpin.CmdClause
	authMethod     *string
	challengeExtra *map[string]string
}

type Authenticate struct {
	authenticate      *kingpin.CmdClause
	signature         *string
	authenticateExtra *map[string]string
}

type Abort struct {
	abort        *kingpin.CmdClause
	abortDetails *map[string]string
	abortReason  *string
	abortArgs    *[]string
	abortKwArgs  *map[string]string
}

type Error struct {
	error          *kingpin.CmdClause
	messageType    *uint64
	errorRequestID *uint64
	errorDetails   *map[string]string
	errorUri       *string
	errorArgs      *[]string
	errorKwArgs    *map[string]string
}

type Cancel struct {
	cancel          *kingpin.CmdClause
	cancelRequestID *uint64
	cancelOptions   *map[string]string
}

type Interrupt struct {
	interrupt          *kingpin.CmdClause
	interruptRequestID *uint64
	interruptOptions   *map[string]string
}

type GoodBye struct {
	goodBye        *kingpin.CmdClause
	goodByeReason  *string
	goodByeDetails *map[string]string
}

type Call struct {
	call          *kingpin.CmdClause
	callRequestID *uint64
	callURI       *string
	callArgs      *[]string
	callKwargs    *map[string]string
	callOption    *map[string]string
}

type Result struct {
	result          *kingpin.CmdClause
	resultRequestID *uint64
	resultDetails   *map[string]string
	resultArgs      *[]string
	resultKwargs    *map[string]string
}

type Register struct {
	register     *kingpin.CmdClause
	regRequestID *uint64
	regProcedure *string
	regOptions   *map[string]string
}

type Registered struct {
	registered          *kingpin.CmdClause
	registeredRequestID *uint64
	registrationID      *uint64
}

type Invocation struct {
	invocation        *kingpin.CmdClause
	invRequestID      *uint64
	invRegistrationID *uint64
	invDetails        *map[string]string
	invArgs           *[]string
	invKwArgs         *map[string]string
}

type Yield struct {
	yield          *kingpin.CmdClause
	yieldRequestID *uint64
	yieldOptions   *map[string]string
	yieldArgs      *[]string
	yieldKwArgs    *map[string]string
}

type UnRegister struct {
	unRegister          *kingpin.CmdClause
	unRegRequestID      *uint64
	unRegRegistrationID *uint64
}

type UnRegistered struct {
	unRegistered          *kingpin.CmdClause
	UnRegisteredRequestID *uint64
}

type Subscribe struct {
	subscribe          *kingpin.CmdClause
	subscribeRequestID *uint64
	subscribeTopic     *string
	subscribeOptions   *map[string]string
}

type Subscribed struct {
	subscribed          *kingpin.CmdClause
	subscribedRequestID *uint64
	subscriptionID      *uint64
}

type Publish struct {
	publish          *kingpin.CmdClause
	publishRequestID *uint64
	publishTopic     *string
	publishOptions   *map[string]string
	publishArgs      *[]string
	publishKwArgs    *map[string]string
}

type Published struct {
	published          *kingpin.CmdClause
	publishedRequestID *uint64
	publicationID      *uint64
}

type Event struct {
	event               *kingpin.CmdClause
	eventSubscriptionID *uint64
	eventPublicationID  *uint64
	eventDetails        *map[string]string
	eventArgs           *[]string
	eventKwArgs         *map[string]string
}

type UnSubscribe struct {
	unSubscribe               *kingpin.CmdClause
	unSubscribeRequestID      *uint64
	unSubscribeSubscriptionID *uint64
}

type UnSubscribed struct {
	unSubscribed          *kingpin.CmdClause
	unSubscribedRequestID *uint64
}

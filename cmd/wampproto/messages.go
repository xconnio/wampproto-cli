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
	sessionID         *int64
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
	messageType    *int64
	errorRequestID *int64
	errorDetails   *map[string]string
	errorUri       *string
	errorArgs      *[]string
	errorKwArgs    *map[string]string
}

type Cancel struct {
	cancel          *kingpin.CmdClause
	cancelRequestID *int64
	cancelOptions   *map[string]string
}

type Interrupt struct {
	interrupt          *kingpin.CmdClause
	interruptRequestID *int64
	interruptOptions   *map[string]string
}

type GoodBye struct {
	goodBye        *kingpin.CmdClause
	goodByeReason  *string
	goodByeDetails *map[string]string
}

type Call struct {
	call          *kingpin.CmdClause
	callRequestID *int64
	callURI       *string
	callArgs      *[]string
	callKwargs    *map[string]string
	callOption    *map[string]string
}

type Result struct {
	result          *kingpin.CmdClause
	resultRequestID *int64
	resultDetails   *map[string]string
	resultArgs      *[]string
	resultKwargs    *map[string]string
}

type Register struct {
	register     *kingpin.CmdClause
	regRequestID *int64
	regProcedure *string
	regOptions   *map[string]string
}

type Registered struct {
	registered          *kingpin.CmdClause
	registeredRequestID *int64
	registrationID      *int64
}

type Invocation struct {
	invocation        *kingpin.CmdClause
	invRequestID      *int64
	invRegistrationID *int64
	invDetails        *map[string]string
	invArgs           *[]string
	invKwArgs         *map[string]string
}

type Yield struct {
	yield          *kingpin.CmdClause
	yieldRequestID *int64
	yieldOptions   *map[string]string
	yieldArgs      *[]string
	yieldKwArgs    *map[string]string
}

type UnRegister struct {
	unRegister          *kingpin.CmdClause
	unRegRequestID      *int64
	unRegRegistrationID *int64
}

type UnRegistered struct {
	unRegistered          *kingpin.CmdClause
	UnRegisteredRequestID *int64
}

type Subscribe struct {
	subscribe          *kingpin.CmdClause
	subscribeRequestID *int64
	subscribeTopic     *string
	subscribeOptions   *map[string]string
}

type Subscribed struct {
	subscribed          *kingpin.CmdClause
	subscribedRequestID *int64
	subscriptionID      *int64
}

type Publish struct {
	publish          *kingpin.CmdClause
	publishRequestID *int64
	publishTopic     *string
	publishOptions   *map[string]string
	publishArgs      *[]string
	publishKwArgs    *map[string]string
}

type Published struct {
	published          *kingpin.CmdClause
	publishedRequestID *int64
	publicationID      *int64
}

type Event struct {
	event               *kingpin.CmdClause
	eventSubscriptionID *int64
	eventPublicationID  *int64
	eventDetails        *map[string]string
	eventArgs           *[]string
	eventKwArgs         *map[string]string
}

type UnSubscribe struct {
	unSubscribe               *kingpin.CmdClause
	unSubscribeRequestID      *int64
	unSubscribeSubscriptionID *int64
}

type UnSubscribed struct {
	unSubscribed          *kingpin.CmdClause
	unSubscribedRequestID *int64
}

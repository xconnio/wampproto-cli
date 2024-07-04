# wampproto

A tool for testing interoperability between different wampproto implementations.

## CLI

The command-line interface overview:

```shell
muzzammil@OfficePC:~$ wampproto --help-long
usage: wampproto [<flags>] <command> [<args> ...]

A tool for testing interoperability between different wampproto implementations.

Flags:
      --[no-]help     Show context-sensitive help (also try --help-long and --help-man).
  -v, --[no-]version  Show application version.
      --output=raw    Format of the output.

Commands:
help [<command>...]
    Show help.


auth cryptosign sign-challenge <challenge> <private-key>
    Sign a cryptosign challenge.


auth cryptosign verify-signature <signature> <public-key>
    Verify a cryptosign challenge.


auth cryptosign get-pubkey <private-key>
    Retrieve the ed25519 public key associated with the provided private key.


auth cryptosign generate-challenge
    Generate a cryptosign challenge.


auth cryptosign keygen
    Generate a WAMP cryptosign ed25519 keypair.


auth cra generate-challenge <session-id> <authid> <authrole> <provider>
    Generate a CRA challenge.


auth cra derive-key [<flags>] <salt> <secret>
    Derive CRA Key.

    -i, --iteration=ITERATION  Iteration count.
    -l, --keylen=KEYLEN        Key length.

auth cra sign-challenge <challenge> <key>
    Sign a CRA challenge.


auth cra verify-signature <challenge> <signature> <key>
    Verify a CRA signature.


message hello [<flags>] <realm> [<authmethods>...]
    Hello message.

        --authid=""                The authid.
    -e, --authextra=AUTHEXTRA ...  Additional authentication data.
    -r, --roles=ROLES ...          Client roles.

message welcome [<flags>] <session-id>
    Welcome message.

        --roles=ROLES ...          Client roles.
        --authid=AUTHID            Client authid.
        --authrole=AUTHROLE        Client authrole.
        --authmethod=AUTHMETHOD    Client authmethod.
    -e, --authextra=AUTHEXTRA ...  Additional authentication data.

message challenge [<flags>] <authmethod>
    Challenge message.

    -e, --extra=EXTRA ...  Additional challenge data.

message authenticate [<flags>] <signature>
    Authenticate message.

    -e, --extra=EXTRA ...  Additional authentication data.

message abort [<flags>] <reason> [<args>...]
    Abort message.

    -d, --detail=DETAIL ...  Additional abort data.
    -k, --kwarg=KWARG ...    Keyword arguments of abort

message error [<flags>] <message-type> <request-id> <uri> [<args>...]
    Error message.

    -d, --detail=DETAIL ...  Additional error data.
    -k, --kwarg=KWARG ...    Keyword arguments of error.

message cancel [<flags>] <request-id>
    Cancel message.

    -o, --option=OPTION ...  Cancel options.

message interrupt [<flags>] <request-id>
    Interrupt message.

    -o, --option=OPTION ...  Interrupt options.

message goodbye [<flags>] <reason>
    Goodbye message.

    -d, --detail=DETAIL ...  GoodBye details.

message call [<flags>] <request-id> <procedure> [<args>...]
    Call message.

    -k, --kwarg=KWARG ...    Keyword argument for the call.
    -o, --option=OPTION ...  Call options.

message result [<flags>] <request-id> [<args>...]
    Result messages.

    -d, --detail=DETAIL ...  Result details.
    -k, --kwarg=KWARG ...    Result KW Arguments.

message register [<flags>] <request-id> <procedure>
    Register message.

    -o, --option=OPTION ...  Register options.

message registered <request-id> <registration-id>
    Registered message.


message invocation [<flags>] <request-id> <registration-id> [<args>...]
    Invocation message.

    -d, --detail=DETAIL ...  Invocation details.
    -k, --kwarg=KWARG ...    Invocation KW arguments.

message yield [<flags>] <request-id> [<args>...]
    Yield message.

    -o, --option=OPTION ...  Yield options.
    -k, --kwarg=KWARG ...    Yield KW arguments.

message unregister <request-id> <registration-id>
    Unregister message.


message unregistered <request-id>
    Unregistered message.


message subscribe [<flags>] <request-id> <topic>
    Subscribe message.

    -o, --option=OPTION ...  Subscribe options.

message subscribed <request-id> <subscription-id>
    Subscribed message.


message publish [<flags>] <request-id> <topic> [<args>...]
    Publish message.

    -o, --option=OPTION ...  Publish options.
    -k, --kwarg=KWARG ...    Publish Keyword arguments.

message published <request-id> <publication-id>
    Published message.


message event [<flags>] <subscription-id> <publication-id> [<args>...]
    Event message.

    -d, --detail=DETAIL ...  Event details.
    -k, --kwarg=KWARG ...    Event Keyword arguments.

message unsubscribe <request-id> <subscription-id>
    Unsubscribe message.


message unsubscribed <request-id>
    Unsubscribed message.
```

## Installation

```shell
sudo snap install wampproto
```

## Building the Project

```shell
git clone git@github.com:/xconnio/wampproto-cli.git
cd wampproto-cli
make build
```
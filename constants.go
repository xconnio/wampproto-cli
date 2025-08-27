package wampprotocli

const (
	RawFormat    = "raw"
	HexFormat    = "hex"
	Base64Format = "base64"

	JsonSerializer      = "json"
	CborSerializer      = "cbor"
	MsgpackSerializer   = "msgpack"
	ProtobufSerializer  = "protobuf"
	CapnprotoSerializer = "capnproto"

	Anonymous  = "anonymous"
	Ticket     = "ticket"
	WAMPCra    = "wampcra"
	CryptoSign = "cryptosign"
)

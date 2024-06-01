package main

import (
	"encoding/hex"
	"log"

	"github.com/xconnio/wampproto-go/messages"
	"github.com/xconnio/wampproto-go/serializers"
)

func main() {
	hello := messages.NewHello("realm1", "test", nil, nil, []string{"anonymous"})
	serializer := &serializers.MsgPackSerializer{}
	data, err := serializer.Serialize(hello)
	if err != nil {
		panic(err)
	}

	log.Println("HELLO", hex.EncodeToString(data))
}

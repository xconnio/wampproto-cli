build:
	go build ./cmd/wampproto

test:
	go test -count=1 ./... -v

lint:
	golangci-lint run
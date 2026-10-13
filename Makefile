.PHONY: test build

test:
	go test ./...

build:
	go build ./cmd/pqtunneld ./cmd/pqtunnel-client ./cmd/pqtunnel-pki

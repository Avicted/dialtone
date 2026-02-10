SHELL := /bin/sh

.PHONY: fmt vet test coverage build build-client build-all

fmt:
	go fmt ./...

vet:
	go vet ./...

test:
	go test ./...

coverage:
	go test ./... -covermode=atomic -coverpkg=./... -coverprofile=coverage.out
	go tool cover -func=coverage.out

build:
	go build -o ./bin/server ./cmd/server

build-client:
	go build -o ./bin/client ./cmd/client

build-all: build build-client

SHELL := /bin/sh

.PHONY: fmt vet test build build-client build-all

fmt:
	go fmt ./...

vet:
	go vet ./...

test:
	go test ./...

build:
	go build ./cmd/server

build-client:
	go build ./cmd/client

build-all: build build-client

SHELL := /bin/sh

.PHONY: fmt vet test build

fmt:
	go fmt ./...

vet:
	go vet ./...

test:
	go test ./...

build:
	go build ./cmd/server

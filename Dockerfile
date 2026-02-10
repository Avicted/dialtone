FROM golang:1.22-alpine AS builder

WORKDIR /src

RUN apk add --no-cache ca-certificates

COPY go.mod go.sum ./
RUN go mod download

COPY . .

RUN CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -o /out/dialtone-server ./cmd/server

FROM alpine:3.20

RUN apk add --no-cache ca-certificates && \
	adduser -D -H -u 10001 -s /sbin/nologin dialtone

COPY --from=builder /out/dialtone-server /usr/local/bin/dialtone-server

USER 10001
EXPOSE 8080

ENTRYPOINT ["/usr/local/bin/dialtone-server"]

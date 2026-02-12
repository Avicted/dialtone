//go:build windows

package ipc

import (
	"net"
	"os"

	"github.com/Microsoft/go-winio"
)

func Listen(addr string) (net.Listener, error) {
	if addr == "" {
		return nil, os.ErrInvalid
	}
	return winio.ListenPipe(addr, nil)
}

func Dial(addr string) (net.Conn, error) {
	if addr == "" {
		return nil, os.ErrInvalid
	}
	return winio.DialPipe(addr, nil)
}

//go:build !windows

package ipc

import (
	"net"
	"os"
)

func Listen(addr string) (net.Listener, error) {
	if addr == "" {
		return nil, os.ErrInvalid
	}
	_ = os.Remove(addr)
	return net.Listen("unix", addr)
}

func Dial(addr string) (net.Conn, error) {
	if addr == "" {
		return nil, os.ErrInvalid
	}
	return net.Dial("unix", addr)
}

package main

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"log"
	"net"
	"sync"

	"github.com/Avicted/dialtone/internal/ipc"
)

type ipcServer struct {
	addr  string
	mu    sync.Mutex
	ln    net.Listener
	conns map[net.Conn]*ipcConn
	h     ipcHandler
}

type ipcHandler func(ctx context.Context, msg ipc.Message) (ipc.Message, error)

type ipcConn struct {
	conn net.Conn
	enc  *json.Encoder
	mu   sync.Mutex
}

func (c *ipcConn) send(msg ipc.Message) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.enc.Encode(msg)
}

func newIPCServer(addr string, handler ipcHandler) *ipcServer {
	return &ipcServer{addr: addr, h: handler}
}

func (s *ipcServer) Run(ctx context.Context) error {
	ln, err := ipc.Listen(s.addr)
	if err != nil {
		return err
	}
	s.mu.Lock()
	s.ln = ln
	if s.conns == nil {
		s.conns = make(map[net.Conn]*ipcConn)
	}
	s.mu.Unlock()

	go func() {
		<-ctx.Done()
		_ = s.Close()
	}()

	for {
		conn, err := ln.Accept()
		if err != nil {
			if ctx.Err() != nil || errors.Is(err, net.ErrClosed) {
				return nil
			}
			return err
		}
		go s.handleConn(ctx, conn)
	}
}

func (s *ipcServer) Close() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.ln != nil {
		_ = s.ln.Close()
		s.ln = nil
	}
	for conn := range s.conns {
		_ = conn.Close()
	}
	s.conns = make(map[net.Conn]*ipcConn)
	return nil
}

func (s *ipcServer) Broadcast(msg ipc.Message) {
	s.mu.Lock()
	conns := make([]*ipcConn, 0, len(s.conns))
	for _, conn := range s.conns {
		conns = append(conns, conn)
	}
	s.mu.Unlock()
	for _, conn := range conns {
		_ = conn.send(msg)
	}
}

func (s *ipcServer) handleConn(ctx context.Context, conn net.Conn) {
	enc := ipc.NewEncoder(conn)
	dec := ipc.NewDecoder(conn)
	state := &ipcConn{conn: conn, enc: enc}

	s.trackConn(state)
	_ = state.send(ipc.Message{Event: ipc.EventVoiceReady})

	for {
		var msg ipc.Message
		if err := dec.Decode(&msg); err != nil {
			if !errors.Is(err, io.EOF) && !errors.Is(err, net.ErrClosed) {
				log.Printf("ipc decode error: %v", err)
			}
			break
		}
		if msg.Cmd == "" {
			continue
		}
		s.handleCommand(ctx, msg, state)
	}

	s.untrackConn(conn)
	_ = conn.Close()
}

func (s *ipcServer) handleCommand(ctx context.Context, msg ipc.Message, state *ipcConn) {
	if s.h == nil {
		s.sendError(state, "ipc handler unavailable")
		return
	}
	resp, err := s.h(ctx, msg)
	if err != nil {
		s.sendError(state, err.Error())
		return
	}
	if resp.Event == "" {
		return
	}
	_ = state.send(resp)
}

func (s *ipcServer) sendError(state *ipcConn, message string) {
	_ = state.send(ipc.Message{Event: ipc.EventError, Error: message})
}

func (s *ipcServer) trackConn(state *ipcConn) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.conns == nil {
		s.conns = make(map[net.Conn]*ipcConn)
	}
	s.conns[state.conn] = state
}

func (s *ipcServer) untrackConn(conn net.Conn) {
	s.mu.Lock()
	defer s.mu.Unlock()
	delete(s.conns, conn)
}

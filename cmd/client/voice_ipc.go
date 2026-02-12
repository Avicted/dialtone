package main

import (
	"encoding/json"
	"fmt"
	"net"
	"runtime"
	"sync"

	"github.com/Avicted/dialtone/internal/ipc"
)

type voiceIPC struct {
	addr string
	mu   sync.Mutex
	conn net.Conn
	enc  *json.Encoder
	dec  *json.Decoder
}

func newVoiceIPC(addr string) *voiceIPC {
	return &voiceIPC{addr: addr}
}

func (v *voiceIPC) send(msg ipc.Message) error {
	v.mu.Lock()
	defer v.mu.Unlock()
	if err := v.ensureConnLocked(); err != nil {
		return err
	}
	if err := v.enc.Encode(msg); err != nil {
		v.resetLocked()
		return err
	}
	return nil
}

func (v *voiceIPC) readLoop(ch chan<- ipc.Message) {
	defer close(ch)
	if err := v.ensureConn(); err != nil {
		ch <- ipc.Message{Event: ipc.EventError, Error: err.Error()}
		return
	}
	v.mu.Lock()
	dec := v.dec
	v.mu.Unlock()
	if dec == nil {
		ch <- ipc.Message{Event: ipc.EventError, Error: "voice ipc decoder not available"}
		return
	}
	for {
		var msg ipc.Message
		if err := dec.Decode(&msg); err != nil {
			v.reset()
			ch <- ipc.Message{Event: ipc.EventError, Error: err.Error()}
			return
		}
		ch <- msg
	}
}

func (v *voiceIPC) reset() {
	v.mu.Lock()
	defer v.mu.Unlock()
	v.resetLocked()
}

func (v *voiceIPC) ensureConn() error {
	v.mu.Lock()
	defer v.mu.Unlock()
	return v.ensureConnLocked()
}

func (v *voiceIPC) ensureConnLocked() error {
	if v.addr == "" {
		return fmt.Errorf("voice ipc address is empty")
	}
	if v.conn == nil {
		conn, err := ipc.Dial(v.addr)
		if err != nil {
			return err
		}
		v.conn = conn
		v.enc = ipc.NewEncoder(conn)
		v.dec = ipc.NewDecoder(conn)
	}
	if v.enc == nil || v.dec == nil {
		return fmt.Errorf("voice ipc encoder not available")
	}
	return nil
}

func (v *voiceIPC) resetLocked() {
	if v.conn != nil {
		_ = v.conn.Close()
	}
	v.conn = nil
	v.enc = nil
	v.dec = nil
}

func defaultVoiceIPCAddr() string {
	if runtime.GOOS == "windows" {
		return `\\.\pipe\dialtone-voice`
	}
	return "/tmp/dialtone-voice.sock"
}

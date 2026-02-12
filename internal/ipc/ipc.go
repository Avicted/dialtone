package ipc

import "encoding/json"

const (
	CommandVoiceJoin  = "voice_join"
	CommandVoiceLeave = "voice_leave"
	CommandMute       = "mute"
	CommandUnmute     = "unmute"
	CommandIdentify   = "identify"
	CommandPing       = "ping"

	EventVoiceReady     = "voice_ready"
	EventVoiceConnected = "voice_connected"
	EventVoiceMembers   = "voice_members"
	EventUserSpeaking   = "user_speaking"
	EventInfo           = "info"
	EventError          = "error"
	EventPong           = "pong"
)

type Message struct {
	Cmd    string   `json:"cmd,omitempty"`
	Event  string   `json:"event,omitempty"`
	Room   string   `json:"room,omitempty"`
	User   string   `json:"user,omitempty"`
	Users  []string `json:"users,omitempty"`
	Active bool     `json:"active,omitempty"`
	Error  string   `json:"error,omitempty"`
}

func NewDecoder(r interface{ Read([]byte) (int, error) }) *json.Decoder {
	return json.NewDecoder(r)
}

func NewEncoder(w interface{ Write([]byte) (int, error) }) *json.Encoder {
	return json.NewEncoder(w)
}

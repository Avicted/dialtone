package message

import (
	"context"
	"time"

	"github.com/Avicted/dialtone/internal/user"
)

// BroadcastMessage is a message sent to all connected clients.
type BroadcastMessage struct {
	ID              ID
	SenderID        user.ID
	SenderNameEnc   string
	SenderPublicKey string
	Body            string
	Envelopes       map[string]string
	SentAt          time.Time
}

// BroadcastRepository persists and retrieves broadcast messages.
type BroadcastRepository interface {
	Save(ctx context.Context, msg BroadcastMessage) error
	ListRecent(ctx context.Context, limit int) ([]BroadcastMessage, error)
}

package message

import (
	"context"
	"time"

	"github.com/Avicted/dialtone/internal/device"
	"github.com/Avicted/dialtone/internal/user"
)

type ID string

type Message struct {
	ID                ID
	SenderID          user.ID
	RecipientID       user.ID
	RecipientDeviceID device.ID
	Ciphertext        []byte
	SentAt            time.Time
}

type Repository interface {
	Save(ctx context.Context, msg Message) error
	ListForRecipientDevice(ctx context.Context, deviceID device.ID, limit int) ([]Message, error)
}

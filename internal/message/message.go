package message

import "time"

type ID string

type Message struct {
	ID          ID
	SenderID    string
	RecipientID string
	Ciphertext  []byte
	SentAt      time.Time
}

type Repository interface {
	Save(msg Message) error
}

package outbox

import "time"

type Event struct {
	EventID       string
	AggregateType string
	AggregateID   string
	EventType     string
	Topic         string // 🔥 NEW
	Payload       []byte
	Headers       map[string]string
	Status        string
	RetryCount    int
	CreatedAt     time.Time
	ProcessedAt   *time.Time
}

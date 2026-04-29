package service

// Kafka topics for accounting module outbox events
// All accounting events go to a single topic for simplicity.
const (
	TopicAccountingEvents = "accounting-events"
)

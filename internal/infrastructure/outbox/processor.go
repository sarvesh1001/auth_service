package outbox

import (
	"context"
	"time"

	"auth-service/internal/client"

	"go.uber.org/zap"
)

type Processor struct {
	repo      Repository
	producer  *client.KafkaProducer
	logger    *zap.Logger
	batchSize int
	topic     string // single topic for all events
}

// NewProcessor creates a new outbox processor.
// topic: the Kafka topic to publish all events to (e.g., "academics-events").
func NewProcessor(repo Repository, producer *client.KafkaProducer, logger *zap.Logger, topic string) *Processor {
	return &Processor{
		repo:      repo,
		producer:  producer,
		logger:    logger,
		batchSize: 50,
		topic:     topic,
	}
}

// Start begins polling the outbox table and publishing events.
func (p *Processor) Start(ctx context.Context) {
	ticker := time.NewTicker(2 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-ticker.C:
			p.processBatch(ctx)
		case <-ctx.Done():
			return
		}
	}
}

func (p *Processor) processBatch(ctx context.Context) {
	events, err := p.repo.FetchPending(ctx, p.batchSize)
	if err != nil {
		p.logger.Error("failed to fetch outbox events", zap.Error(err))
		return
	}

	for _, e := range events {
		// Prepare headers: include event type, aggregate type, etc.
		headers := make(map[string]string)
		if e.Headers != nil {
			// Copy existing headers if any
			for k, v := range e.Headers {
				headers[k] = v
			}
		}
		// Add event type header (required by consumer)
		headers["event_type"] = e.EventType
		if e.AggregateType != "" {
			headers["aggregate_type"] = e.AggregateType
		}
		if e.AggregateID != "" {
			headers["aggregate_id"] = e.AggregateID
		}

		err := p.producer.ProduceMessage(
			ctx,
			p.topic,               // single topic
			[]byte(e.AggregateID), // message key (optional)
			e.Payload,
			headers,
		)

		if err != nil {
			p.logger.Error("failed to publish event",
				zap.String("event_id", e.EventID),
				zap.String("event_type", e.EventType),
				zap.Error(err),
			)
			// Increment retry count
			_ = p.repo.MarkFailed(ctx, e.EventID, e.RetryCount+1)
			continue
		}

		// Mark as processed
		_ = p.repo.MarkProcessed(ctx, e.EventID)
	}
}

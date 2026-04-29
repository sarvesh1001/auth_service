package outbox

import (
	"context"
	"time"

	"auth-service/internal/client"

	"go.uber.org/zap"
)

// Processor publishes outbox events to Kafka using topic from DB.
type Processor struct {
	repo      Repository
	producer  *client.KafkaProducer
	logger    *zap.Logger
	batchSize int
}

func NewProcessor(
	repo Repository,
	producer *client.KafkaProducer,
	logger *zap.Logger,
) *Processor {
	return &Processor{
		repo:      repo,
		producer:  producer,
		logger:    logger,
		batchSize: 50,
	}
}

// Start polling loop
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

		// 🔥 USE topic from DB (NO routing logic)
		topic := e.Topic

		// Prepare headers
		headers := make(map[string]string)
		if e.Headers != nil {
			for k, v := range e.Headers {
				headers[k] = v
			}
		}

		headers["event_id"] = e.EventID
		headers["event_type"] = e.EventType

		if e.AggregateType != "" {
			headers["aggregate_type"] = e.AggregateType
		}
		if e.AggregateID != "" {
			headers["aggregate_id"] = e.AggregateID
		}

		err := p.producer.ProduceMessage(
			ctx,
			topic,
			[]byte(e.AggregateID), // partition key
			e.Payload,
			headers,
		)

		if err != nil {
			p.logger.Error("failed to publish event",
				zap.String("event_id", e.EventID),
				zap.String("topic", topic),
				zap.String("event_type", e.EventType),
				zap.Error(err),
			)

			_ = p.repo.MarkFailed(ctx, e.EventID, e.RetryCount+1)
			continue
		}

		_ = p.repo.MarkProcessed(ctx, e.EventID)
	}
}

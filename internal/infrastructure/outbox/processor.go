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
	logger := p.logger.With(zap.String("component", "outbox_processor"))
	logger.Info("Outbox processor started, polling every 2 seconds")

	if p.producer == nil {
		logger.Error("❌ Kafka producer is nil – outbox processor will not function")
		return
	}

	var lastProcessed time.Time
	ticker := time.NewTicker(2 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-ticker.C:
			p.processBatch(ctx, &lastProcessed)
		case <-ctx.Done():
			logger.Info("Outbox processor stopped (context cancelled)")
			return
		}
	}
}

func (p *Processor) processBatch(ctx context.Context, lastProcessed *time.Time) {
	logger := p.logger.With(zap.String("component", "outbox_processor"))

	if p.producer == nil {
		logger.Error("Producer is nil, cannot process events")
		return
	}

	events, err := p.repo.FetchPending(ctx, p.batchSize)
	if err != nil {
		logger.Error("Failed to fetch outbox events", zap.Error(err))
		return
	}

	// No events: do nothing and don't log.
	if len(events) == 0 {
		return
	}

	*lastProcessed = time.Now()

	logger.Info("Processing outbox events batch", zap.Int("count", len(events)))

	for i, e := range events {
		eventLogger := logger.With(
			zap.String("event_id", e.EventID),
			zap.String("event_type", e.EventType),
			zap.String("topic", e.Topic),
			zap.Int("retry_count", e.RetryCount),
			zap.Int("batch_index", i),
			zap.String("aggregate_id", e.AggregateID),
		)

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

		if e.Topic == "" {
			eventLogger.Error("Event has empty topic, cannot publish")
			if e.RetryCount >= 3 {
				_ = p.repo.MarkFailed(ctx, e.EventID, e.RetryCount+1)
			}
			continue
		}

		err := p.producer.ProduceMessage(ctx, e.Topic, []byte(e.AggregateID), e.Payload, headers)
		if err != nil {
			eventLogger.Error("Failed to publish event", zap.Error(err))
			_ = p.repo.MarkFailed(ctx, e.EventID, e.RetryCount+1)
			continue
		}

		if err := p.repo.MarkProcessed(ctx, e.EventID); err != nil {
			eventLogger.Error("Failed to mark event as processed", zap.Error(err))
			// leave pending – retry later
			continue
		}

		eventLogger.Info("Event published and marked processed")
	}
}

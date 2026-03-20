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
}

func NewProcessor(repo Repository, producer *client.KafkaProducer, logger *zap.Logger) *Processor {
	return &Processor{
		repo:      repo,
		producer:  producer,
		logger:    logger,
		batchSize: 50,
	}
}

func (p *Processor) Start(ctx context.Context) {
	ticker := time.NewTicker(2 * time.Second)

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
		err := p.producer.ProduceMessage(
			ctx,
			e.EventType, // topic = event type (or map)
			[]byte(e.AggregateID),
			e.Payload,
			e.Headers,
		)

		if err != nil {
			p.logger.Error("failed to publish event",
				zap.String("event_id", e.EventID),
				zap.Error(err),
			)

			_ = p.repo.MarkFailed(ctx, e.EventID, e.RetryCount+1)
			continue
		}

		_ = p.repo.MarkProcessed(ctx, e.EventID)
	}
}

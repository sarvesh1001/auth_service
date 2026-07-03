package outbox

import (
	"context"
	"encoding/json"
	"time"

	"github.com/google/uuid"
	"go.uber.org/zap"

	"auth-service/internal/attendance/repository"
)

type BatchOutboxProcessor struct {
	outboxRepo repository.OutboxRepository
	kafka      KafkaProducer
	logger     *zap.Logger
	batchSize  int
	interval   time.Duration
	stopChan   chan struct{}
	isRunning  bool
}

func NewBatchOutboxProcessor(
	outboxRepo repository.OutboxRepository,
	kafka KafkaProducer,
	logger *zap.Logger,
	batchSize int,
	interval time.Duration,
) *BatchOutboxProcessor {
	return &BatchOutboxProcessor{
		outboxRepo: outboxRepo,
		kafka:      kafka,
		logger:     logger,
		batchSize:  batchSize,
		interval:   interval,
		stopChan:   make(chan struct{}),
	}
}

func (p *BatchOutboxProcessor) Start(ctx context.Context) {
	ticker := time.NewTicker(p.interval)
	defer ticker.Stop()
	p.logger.Info("Batch outbox processor started")
	p.isRunning = true

	for {
		select {
		case <-ctx.Done():
			p.logger.Info("Batch outbox processor stopped via context")
			p.isRunning = false
			return
		case <-p.stopChan:
			p.logger.Info("Batch outbox processor stopped")
			p.isRunning = false
			return
		case <-ticker.C:
			p.processOnce(ctx)
		}
	}
}

func (p *BatchOutboxProcessor) processOnce(ctx context.Context) {
	events, err := p.outboxRepo.FetchUnprocessed(ctx, p.batchSize)
	if err != nil {
		p.logger.Error("Failed to fetch outbox events", zap.Error(err))
		return
	}
	if len(events) == 0 {
		return
	}

	var processed []uuid.UUID
	for _, evt := range events {
		if err := p.publishOne(ctx, evt); err != nil {
			_ = p.outboxRepo.MarkFailed(ctx, evt.EventID, err.Error())
			continue
		}
		processed = append(processed, evt.EventID)
	}

	if len(processed) > 0 {
		if err := p.outboxRepo.MarkProcessed(ctx, processed); err != nil {
			p.logger.Error("Failed to mark outbox events processed", zap.Error(err))
		}
	}
}

func (p *BatchOutboxProcessor) publishOne(ctx context.Context, evt *repository.OutboxEvent) error {
	message := map[string]interface{}{
		"event_type":   evt.EventType,
		"aggregate_id": evt.AggregateID,
		"payload":      json.RawMessage(evt.Payload),
		"created_at":   evt.CreatedAt,
	}
	value, err := json.Marshal(message)
	if err != nil {
		return err
	}

	const topic = "attendance.events" // or use evt.Topic if per-event
	err = p.kafka.ProduceMessage(
		ctx,
		topic,
		[]byte(evt.AggregateID.String()),
		value,
		map[string]string{
			"event_type": evt.EventType,
			"source":     "attendance-batch",
		},
	)
	if err != nil {
		p.logger.Error("Kafka publish failed",
			zap.String("topic", topic),
			zap.String("event_type", evt.EventType),
			zap.String("event_id", evt.EventID.String()),
			zap.Error(err),
		)
		return err
	}
	p.logger.Debug("Outbox event published",
		zap.String("event_id", evt.EventID.String()),
		zap.String("event_type", evt.EventType),
	)
	return nil
}

func (p *BatchOutboxProcessor) Stop() {
	if p.isRunning {
		close(p.stopChan)
		p.isRunning = false
	}
}

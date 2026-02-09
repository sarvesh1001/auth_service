package service

import (
	"context"
	"encoding/json"
	"time"

	"auth-service/internal/hr/repository"

	"github.com/google/uuid"
	"go.uber.org/zap"
)

type AttendanceBatchOutboxProcessor struct {
	outboxRepo repository.AttendanceBatchOutboxRepository
	kafka      KafkaProducer
	logger     *zap.Logger
	batchSize  int
	interval   time.Duration
}

type KafkaProducer interface {
	ProduceMessage(
		ctx context.Context,
		topic string,
		key []byte,
		value []byte,
		headers map[string]string,
	) error
}

func NewAttendanceBatchOutboxProcessor(
	outboxRepo repository.AttendanceBatchOutboxRepository,
	kafka KafkaProducer,
	logger *zap.Logger,
	batchSize int,
	interval time.Duration,
) *AttendanceBatchOutboxProcessor {
	return &AttendanceBatchOutboxProcessor{
		outboxRepo: outboxRepo,
		kafka:      kafka,
		logger:     logger,
		batchSize:  batchSize,
		interval:   interval,
	}
}

// ============================================
// START LOOP
// ============================================

func (p *AttendanceBatchOutboxProcessor) Start(ctx context.Context) {
	ticker := time.NewTicker(p.interval)
	defer ticker.Stop()

	p.logger.Info("Attendance batch outbox processor started")

	for {
		select {
		case <-ctx.Done():
			p.logger.Info("Attendance batch outbox processor stopped")
			return
		case <-ticker.C:
			p.processOnce(ctx)
		}
	}
}

// ============================================
// SINGLE POLL CYCLE
// ============================================

func (p *AttendanceBatchOutboxProcessor) processOnce(ctx context.Context) {
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
			_ = p.outboxRepo.MarkFailed(ctx, evt.OutboxID, err.Error())
			continue
		}
		processed = append(processed, evt.OutboxID)
	}

	if err := p.outboxRepo.MarkProcessed(ctx, processed); err != nil {
		p.logger.Error("Failed to mark outbox events processed", zap.Error(err))
	}
}

// ============================================
// PUBLISH SINGLE EVENT (FIXED)
// ============================================

func (p *AttendanceBatchOutboxProcessor) publishOne(
	ctx context.Context,
	evt *repository.AttendanceBatchOutbox,
) error {

	// Wrap payload with metadata (best practice)
	message := map[string]interface{}{
		"event_type":   evt.EventType,
		"aggregate_id": evt.AggregateID,
		"payload":      evt.Payload,
		"created_at":   evt.CreatedAt,
	}

	value, err := json.Marshal(message)
	if err != nil {
		return err
	}

	// ✅ FIX: single stable topic
	const topic = "attendance.events"

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
		p.logger.Error(
			"Kafka publish failed",
			zap.String("topic", topic),
			zap.String("event_type", evt.EventType),
			zap.String("outbox_id", evt.OutboxID.String()),
			zap.Error(err),
		)
		return err
	}

	p.logger.Debug(
		"Outbox event published",
		zap.String("topic", topic),
		zap.String("event_type", evt.EventType),
		zap.String("outbox_id", evt.OutboxID.String()),
	)

	return nil
}

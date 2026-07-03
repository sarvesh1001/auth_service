package outbox

import (
	"context"
	"encoding/json"
	"fmt"
	"time"

	"github.com/google/uuid"
	"go.uber.org/zap"

	"auth-service/internal/attendance/repository"
)

type KafkaProducer interface {
	ProduceMessage(ctx context.Context, topic string, key []byte, value []byte, headers map[string]string) error
}

type OutboxService struct {
	outboxRepo   repository.OutboxRepository
	kafka        KafkaProducer
	logger       *zap.Logger
	batchSize    int
	pollInterval time.Duration
	topicName    string
	stopChan     chan struct{}
	isRunning    bool
}

func NewOutboxService(
	outboxRepo repository.OutboxRepository,
	kafka KafkaProducer,
	logger *zap.Logger,
	batchSize int,
	pollInterval time.Duration,
	topicName string,
) *OutboxService {
	return &OutboxService{
		outboxRepo:   outboxRepo,
		kafka:        kafka,
		logger:       logger,
		batchSize:    batchSize,
		pollInterval: pollInterval,
		topicName:    topicName,
		stopChan:     make(chan struct{}),
	}
}

func (s *OutboxService) Start(ctx context.Context) error {
	s.logger.Info("Starting outbox service",
		zap.String("topic", s.topicName),
		zap.Int("batch_size", s.batchSize),
		zap.Duration("poll_interval", s.pollInterval),
	)
	s.isRunning = true
	ticker := time.NewTicker(s.pollInterval)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			s.logger.Info("Outbox service stopped via context")
			s.isRunning = false
			return nil
		case <-s.stopChan:
			s.logger.Info("Outbox service stopped")
			s.isRunning = false
			return nil
		case <-ticker.C:
			if err := s.processBatch(ctx); err != nil {
				s.logger.Error("Failed to process outbox batch", zap.Error(err))
			}
		}
	}
}

func (s *OutboxService) processBatch(ctx context.Context) error {
	events, err := s.outboxRepo.FetchUnprocessed(ctx, s.batchSize)
	if err != nil {
		return fmt.Errorf("fetch unprocessed: %w", err)
	}
	if len(events) == 0 {
		return nil
	}

	var processedIDs []uuid.UUID
	for _, evt := range events {
		// Build Kafka message
		msg := map[string]interface{}{
			"event_id":     evt.EventID,
			"aggregate_id": evt.AggregateID,
			"event_type":   evt.EventType,
			"payload":      json.RawMessage(evt.Payload),
			"created_at":   evt.CreatedAt,
		}
		data, err := json.Marshal(msg)
		if err != nil {
			s.logger.Error("marshal outbox event", zap.String("event_id", evt.EventID.String()), zap.Error(err))
			continue
		}
		// Publish
		err = s.kafka.ProduceMessage(
			ctx,
			s.topicName,
			[]byte(evt.AggregateID.String()),
			data,
			map[string]string{
				"event_type": evt.EventType,
				"source":     "attendance",
			},
		)
		if err != nil {
			s.logger.Error("kafka produce failed", zap.String("event_id", evt.EventID.String()), zap.Error(err))
			_ = s.outboxRepo.MarkFailed(ctx, evt.EventID, err.Error())
			continue
		}
		processedIDs = append(processedIDs, evt.EventID)
	}

	if len(processedIDs) > 0 {
		if err := s.outboxRepo.MarkProcessed(ctx, processedIDs); err != nil {
			return fmt.Errorf("mark processed: %w", err)
		}
		s.logger.Info("Processed outbox batch", zap.Int("count", len(processedIDs)))
	}
	return nil
}

func (s *OutboxService) Stop() {
	if s.isRunning {
		close(s.stopChan)
		s.isRunning = false
		s.logger.Info("Outbox service stopping...")
	}
}

func (s *OutboxService) HealthCheck(ctx context.Context) error {
	if err := s.outboxRepo.HealthCheck(ctx); err != nil {
		return fmt.Errorf("outbox repo health: %w", err)
	}
	if s.kafka == nil {
		return fmt.Errorf("kafka producer not initialized")
	}
	count, err := s.outboxRepo.CountUnprocessed(ctx)
	if err != nil {
		return fmt.Errorf("count unprocessed: %w", err)
	}
	if count > 1000 {
		s.logger.Warn("Large outbox backlog", zap.Int64("pending", count))
	}
	return nil
}

package outbox

import (
	"context"
	"encoding/json"
	"fmt"
	"sync"
	"time"

	"github.com/google/uuid"
	"go.uber.org/zap"

	"auth-service/internal/attendance/repository"
)

type KafkaProducer interface {
	ProduceMessage(ctx context.Context, topic string, key []byte, value []byte, headers map[string]string) error
}

// OutboxService polls the outbox table and publishes events to Kafka.
//
// Lifecycle is safe against:
//   - calling Stop() multiple times
//   - calling Stop() before Start()
//   - Start -> Stop -> Start (a new run creates a fresh cancel func)
//
// FIX (Tier 1): the previous implementation closed a channel that was
// created once in the constructor and guarded by a plain bool. That led to
// panics on the second Stop() and to a data race between the loop goroutine
// and Stop() callers. Replaced with a mutex-guarded context.CancelFunc.
type OutboxService struct {
	outboxRepo   repository.OutboxRepository
	kafka        KafkaProducer
	logger       *zap.Logger
	batchSize    int
	pollInterval time.Duration
	topicName    string

	mu       sync.Mutex
	running  bool
	cancelFn context.CancelFunc
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
	}
}

// IsRunning reports whether the service loop is currently active.
func (s *OutboxService) IsRunning() bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.running
}

func (s *OutboxService) Start(ctx context.Context) error {
	s.mu.Lock()
	if s.running {
		s.mu.Unlock()
		return fmt.Errorf("outbox service already running")
	}
	runCtx, cancel := context.WithCancel(ctx)
	s.cancelFn = cancel
	s.running = true
	s.mu.Unlock()

	s.logger.Info("Starting outbox service",
		zap.String("topic", s.topicName),
		zap.Int("batch_size", s.batchSize),
		zap.Duration("poll_interval", s.pollInterval),
	)

	defer func() {
		s.mu.Lock()
		s.running = false
		s.cancelFn = nil
		s.mu.Unlock()
		cancel()
	}()

	ticker := time.NewTicker(s.pollInterval)
	defer ticker.Stop()

	for {
		select {
		case <-runCtx.Done():
			s.logger.Info("Outbox service stopped via context")
			return nil
		case <-ticker.C:
			if err := s.processBatch(runCtx); err != nil {
				s.logger.Error("Failed to process outbox batch", zap.Error(err))
			}
		}
	}
}

// Stop requests the running loop to exit. Safe to call multiple times and
// safe to call when the service is not running.
func (s *OutboxService) Stop() {
	s.mu.Lock()
	cancel := s.cancelFn
	s.mu.Unlock()

	if cancel == nil {
		return
	}
	s.logger.Info("Outbox service stopping...")
	cancel()
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
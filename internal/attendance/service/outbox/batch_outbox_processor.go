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

// BatchOutboxProcessor is a lightweight alternative to OutboxService.
//
// NOTE: Do NOT wire both this and OutboxService against the same outbox
// table at the same time — they will race and double-publish. Pick one.
// The two are kept separate only so different deployments can choose.
type BatchOutboxProcessor struct {
	outboxRepo repository.OutboxRepository
	kafka      KafkaProducer
	logger     *zap.Logger
	batchSize  int
	interval   time.Duration
	topicName  string

	mu       sync.Mutex
	running  bool
	cancelFn context.CancelFunc
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
		topicName:  "attendance.events",
	}
}

func (p *BatchOutboxProcessor) IsRunning() bool {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.running
}

func (p *BatchOutboxProcessor) Start(ctx context.Context) {
	p.mu.Lock()
	if p.running {
		p.mu.Unlock()
		p.logger.Warn("Batch outbox processor already running; ignoring Start")
		return
	}
	runCtx, cancel := context.WithCancel(ctx)
	p.cancelFn = cancel
	p.running = true
	p.mu.Unlock()

	p.logger.Info("Batch outbox processor started")

	defer func() {
		p.mu.Lock()
		p.running = false
		p.cancelFn = nil
		p.mu.Unlock()
		cancel()
	}()

	ticker := time.NewTicker(p.interval)
	defer ticker.Stop()

	for {
		select {
		case <-runCtx.Done():
			p.logger.Info("Batch outbox processor stopped via context")
			return
		case <-ticker.C:
			p.processOnce(runCtx)
		}
	}
}

// Stop is idempotent and safe against concurrent calls.
func (p *BatchOutboxProcessor) Stop() {
	p.mu.Lock()
	cancel := p.cancelFn
	p.mu.Unlock()

	if cancel == nil {
		return
	}
	p.logger.Info("Batch outbox processor stopping...")
	cancel()
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
		"event_id":     evt.EventID,
		"event_type":   evt.EventType,
		"aggregate_id": evt.AggregateID,
		"payload":      json.RawMessage(evt.Payload),
		"created_at":   evt.CreatedAt,
	}
	value, err := json.Marshal(message)
	if err != nil {
		return fmt.Errorf("marshal outbox event: %w", err)
	}

	err = p.kafka.ProduceMessage(
		ctx,
		p.topicName,
		[]byte(evt.AggregateID.String()),
		value,
		map[string]string{
			"event_type": evt.EventType,
			"source":     "attendance-batch",
		},
	)
	if err != nil {
		p.logger.Error("Kafka publish failed",
			zap.String("topic", p.topicName),
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
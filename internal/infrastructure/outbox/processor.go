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

	// For monitoring: track last time events were processed
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

	logger.Debug("Fetching pending outbox events")
	events, err := p.repo.FetchPending(ctx, p.batchSize)
	if err != nil {
		logger.Error("Failed to fetch outbox events",
			zap.Error(err),
			zap.Duration("query_timeout", 5*time.Second), // placeholder
		)
		return
	}

	if len(events) == 0 {
		// Log warning if no events for a long time (e.g., >1 minute)
		if !lastProcessed.IsZero() && time.Since(*lastProcessed) > 1*time.Minute {
			logger.Warn("No pending events for over 1 minute – outbox may be empty or processor may be stuck")
		}
		logger.Debug("No pending events")
		return
	}

	// Reset last processed time when we have events
	*lastProcessed = time.Now()

	logger.Info("Processing outbox events batch",
		zap.Int("count", len(events)),
		zap.Duration("since_last_batch", time.Since(*lastProcessed)),
	)

	for i, e := range events {
		eventLogger := logger.With(
			zap.String("event_id", e.EventID),
			zap.String("event_type", e.EventType),
			zap.String("topic", e.Topic),
			zap.Int("retry_count", e.RetryCount),
			zap.Int("batch_index", i),
			zap.String("aggregate_id", e.AggregateID),
		)

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

		eventLogger.Info("Publishing event to Kafka",
			zap.Int("payload_size", len(e.Payload)),
			zap.String("partition_key", e.AggregateID),
		)

		// ✅ CRITICAL: Check if topic is empty
		if e.Topic == "" {
			eventLogger.Error("❌ Event has empty topic, cannot publish",
				zap.String("event_id", e.EventID),
			)
			// Move to failed state after a few retries
			if e.RetryCount >= 3 {
				eventLogger.Error("Retry limit reached for empty topic, moving to failed state")
				if markErr := p.repo.MarkFailed(ctx, e.EventID, e.RetryCount+1); markErr != nil {
					eventLogger.Error("Failed to mark event as failed", zap.Error(markErr))
				}
			}
			continue
		}

		err := p.producer.ProduceMessage(
			ctx,
			e.Topic,
			[]byte(e.AggregateID), // partition key
			e.Payload,
			headers,
		)

		if err != nil {
			eventLogger.Error("❌ Failed to publish event to Kafka",
				zap.Error(err),
				zap.String("topic", e.Topic),
			)

			// Check if it's a retryable error (e.g., network timeout, broker down)
			// We'll just increment retry count and let it retry
			if markErr := p.repo.MarkFailed(ctx, e.EventID, e.RetryCount+1); markErr != nil {
				eventLogger.Error("Failed to mark event as failed",
					zap.Error(markErr),
					zap.String("error_type", "mark_failed_failure"),
				)
			} else {
				eventLogger.Warn("Event marked as failed, will retry later",
					zap.Int("new_retry_count", e.RetryCount+1),
				)
			}
			continue
		}

		eventLogger.Info("✅ Event published successfully, marking as processed")

		if markErr := p.repo.MarkProcessed(ctx, e.EventID); markErr != nil {
			// ❌ CRITICAL: This is the error we've been seeing – mark processed fails
			eventLogger.Error("❌❌❌ CRITICAL: Failed to mark event as processed (event will remain pending and be retried)",
				zap.Error(markErr),
				zap.String("event_id", e.EventID),
				zap.String("event_type", e.EventType),
				zap.String("error_type", "mark_processed_failure"),
				zap.String("possible_causes", "DB connection timeout, lock contention, deadlock, or constraint violation"),
			)
			// DO NOT mark as failed – let the event stay pending for the next poll.
			// The error could be transient (e.g., DB timeout), and we want to retry.
			// We'll just log it and continue to the next event.
			// If this happens repeatedly, we might need to add an exponential backoff.
			continue
		}

		eventLogger.Info("✅ Event published and marked processed successfully")
	}

	logger.Debug("Finished processing batch")
}

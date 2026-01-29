package consumer

import (
	"context"
	"encoding/json"
	"fmt"
	"time"

	"auth-service/internal/client"
	"auth-service/internal/hr/service"

	"github.com/google/uuid"
	"go.uber.org/zap"
)

type AttendanceResolutionConsumer struct {
	kafkaConsumer     *client.KafkaConsumer
	resolutionService service.AttendanceResolutionService
	logger            *zap.Logger
}

func NewAttendanceResolutionConsumer(
	kafkaConsumer *client.KafkaConsumer,
	resolutionService service.AttendanceResolutionService,
	logger *zap.Logger,
) *AttendanceResolutionConsumer {
	return &AttendanceResolutionConsumer{
		kafkaConsumer:     kafkaConsumer,
		resolutionService: resolutionService,
		logger:            logger,
	}
}

func (c *AttendanceResolutionConsumer) Start(ctx context.Context) error {
	c.logger.Info("Starting attendance resolution consumer",
		zap.String("topic", c.kafkaConsumer.Reader.Config().Topic),
	)

	for {
		select {
		case <-ctx.Done():
			c.logger.Info("Attendance resolution consumer stopped via context")
			return nil
		default:
			if err := c.consumeMessage(ctx); err != nil {
				c.logger.Error("Failed to consume message", zap.Error(err))
				time.Sleep(1 * time.Second)
			}
		}
	}
}

func (c *AttendanceResolutionConsumer) consumeMessage(ctx context.Context) error {
	msg, err := c.kafkaConsumer.ConsumeMessage(ctx)
	if err != nil {
		return fmt.Errorf("failed to consume message: %w", err)
	}

	c.logger.Debug("Received attendance outbox message",
		zap.String("topic", msg.Topic),
		zap.Int64("offset", msg.Offset),
		zap.Int("partition", msg.Partition),
		zap.Time("time", msg.Time),
	)

	// Parse outbox message
	var message struct {
		OutboxID    string          `json:"outbox_id"`
		AggregateID string          `json:"aggregate_id"`
		Payload     json.RawMessage `json:"payload"`
		CreatedAt   time.Time       `json:"created_at"`
	}

	if err := json.Unmarshal(msg.Value, &message); err != nil {
		c.logger.Error("Failed to unmarshal message",
			zap.Error(err),
			zap.ByteString("value", msg.Value),
		)

		// Commit malformed message to avoid infinite loop
		_ = c.kafkaConsumer.CommitMessage(ctx, msg)
		return fmt.Errorf("failed to unmarshal message: %w", err)
	}

	// Extract payload
	var payload struct {
		EventID string `json:"event_id"`
	}

	if err := json.Unmarshal(message.Payload, &payload); err != nil {
		c.logger.Error("Failed to unmarshal payload",
			zap.Error(err),
			zap.String("outbox_id", message.OutboxID),
		)

		_ = c.kafkaConsumer.CommitMessage(ctx, msg)
		return fmt.Errorf("failed to unmarshal payload: %w", err)
	}

	c.logger.Info("Processing attendance event for resolution",
		zap.String("event_id", payload.EventID),
		zap.String("outbox_id", message.OutboxID),
	)

	// Convert event_id → uuid.UUID
	eventUUID, err := uuid.Parse(payload.EventID)
	if err != nil {
		c.logger.Error("Invalid event_id UUID",
			zap.String("event_id", payload.EventID),
			zap.String("outbox_id", message.OutboxID),
			zap.Error(err),
		)

		// Commit invalid UUID message (poison message)
		_ = c.kafkaConsumer.CommitMessage(ctx, msg)
		return fmt.Errorf("invalid event_id uuid: %w", err)
	}

	// Call resolution service
	if err := c.resolutionService.ResolveEvent(ctx, eventUUID); err != nil {
		c.logger.Error("Failed to resolve attendance event",
			zap.String("event_id", payload.EventID),
			zap.Error(err),
		)

		// Do NOT commit → retry allowed
		return fmt.Errorf("failed to resolve event %s: %w", payload.EventID, err)
	}

	// Commit Kafka message after successful resolution
	if err := c.kafkaConsumer.CommitMessage(ctx, msg); err != nil {
		c.logger.Error("Failed to commit message",
			zap.String("event_id", payload.EventID),
			zap.Error(err),
		)
		return fmt.Errorf("failed to commit message: %w", err)
	}

	c.logger.Info("Successfully processed attendance event",
		zap.String("event_id", payload.EventID),
		zap.String("outbox_id", message.OutboxID),
		zap.Int64("offset", msg.Offset),
	)

	return nil
}

func (c *AttendanceResolutionConsumer) Stop() error {
	if c.kafkaConsumer != nil {
		return c.kafkaConsumer.Close()
	}
	return nil
}

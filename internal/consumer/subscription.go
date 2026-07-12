package consumer

import (
	"context"
	"fmt"
	"time"

	"github.com/segmentio/kafka-go"
	"go.uber.org/zap"

	"auth-service/internal/client"
)

// SubscriptionAnalyticsService defines the interface for processing subscription events.
type SubscriptionAnalyticsService interface {
	ProcessSubscriptionEvent(ctx context.Context, eventType string, payload []byte) error
}

// SubscriptionConsumer consumes events from "subscription-events" and forwards them to the analytics service.
type SubscriptionConsumer struct {
	analyticsSvc SubscriptionAnalyticsService
	logger       *zap.Logger
	consumer     *client.KafkaConsumer
	topic        string
	maxRetries   int
	producer     *kafka.Writer
}

// NewSubscriptionConsumer creates a new consumer for subscription events.
func NewSubscriptionConsumer(
	analyticsSvc SubscriptionAnalyticsService,
	logger *zap.Logger,
	consumer *client.KafkaConsumer,
	topic string,
	brokers []string,
) *SubscriptionConsumer {
	return &SubscriptionConsumer{
		analyticsSvc: analyticsSvc,
		logger:       logger.Named("subscription_consumer"),
		consumer:     consumer,
		topic:        topic,
		maxRetries:   3,
		producer: &kafka.Writer{
			Addr:         kafka.TCP(brokers...),
			Balancer:     &kafka.LeastBytes{},
			RequiredAcks: kafka.RequireOne,
			Async:        false,
		},
	}
}

// Start consumes messages from Kafka indefinitely.
func (c *SubscriptionConsumer) Start(ctx context.Context) {
	c.logger.Info("starting subscription consumer", zap.String("topic", c.topic))
	for {
		msg, err := c.consumer.ConsumeMessage(ctx)
		if err != nil {
			if ctx.Err() != nil {
				return
			}
			c.logger.Error("failed to consume message", zap.Error(err))
			continue
		}

		eventType := c.extractHeader(msg, "event_type")
		eventID := c.extractHeader(msg, "event_id")
		logger := c.logger.With(
			zap.String("event_type", eventType),
			zap.String("event_id", eventID),
			zap.Int64("offset", msg.Offset),
			zap.String("topic", msg.Topic),
		)

		if eventType == "" {
			logger.Warn("missing event_type header, skipping")
			_ = c.consumer.CommitMessage(ctx, msg)
			continue
		}

		if eventID == "" {
			logger.Warn("missing event_id header, skipping")
			_ = c.consumer.CommitMessage(ctx, msg)
			continue
		}

		logger.Debug("processing subscription event", zap.Int("payload_size", len(msg.Value)))

		err = c.analyticsSvc.ProcessSubscriptionEvent(ctx, eventType, msg.Value)
		if err != nil {
			logger.Error("failed to process subscription event", zap.Error(err))

			retryCount := c.extractRetry(msg)
			if retryCount < c.maxRetries {
				logger.Info("publishing retry", zap.Int("next_retry", retryCount+1))
				if pubErr := c.publishRetry(ctx, msg, retryCount+1); pubErr != nil {
					logger.Error("failed to publish retry", zap.Error(pubErr))
				}
			} else {
				logger.Error("max retries exceeded, sending to DLQ")
				if dlqErr := c.sendToDLQ(ctx, msg, err); dlqErr != nil {
					logger.Error("failed to send to DLQ", zap.Error(dlqErr))
				}
			}
			_ = c.consumer.CommitMessage(ctx, msg)
			continue
		}

		logger.Info("subscription event processed successfully")
		if err := c.consumer.CommitMessage(ctx, msg); err != nil {
			logger.Error("failed to commit Kafka message", zap.Error(err))
		}
	}
}

// extractHeader returns the value of a specific header key.
func (c *SubscriptionConsumer) extractHeader(msg *kafka.Message, key string) string {
	for _, h := range msg.Headers {
		if h.Key == key {
			return string(h.Value)
		}
	}
	return ""
}

// extractRetry reads retry_count from headers.
func (c *SubscriptionConsumer) extractRetry(msg *kafka.Message) int {
	val := c.extractHeader(msg, "retry_count")
	var count int
	fmt.Sscanf(val, "%d", &count)
	return count
}

// publishRetry sends the message back to the same topic with an incremented retry count.
func (c *SubscriptionConsumer) publishRetry(ctx context.Context, original *kafka.Message, newRetry int) error {
	headers := make([]kafka.Header, 0, len(original.Headers)+1)
	found := false
	for _, h := range original.Headers {
		if h.Key == "retry_count" {
			headers = append(headers, kafka.Header{
				Key:   "retry_count",
				Value: []byte(fmt.Sprintf("%d", newRetry)),
			})
			found = true
		} else {
			headers = append(headers, h)
		}
	}
	if !found {
		headers = append(headers, kafka.Header{
			Key:   "retry_count",
			Value: []byte(fmt.Sprintf("%d", newRetry)),
		})
	}
	retryMsg := kafka.Message{
		Topic:   original.Topic,
		Key:     original.Key,
		Value:   original.Value,
		Headers: headers,
		Time:    time.Now(),
	}
	return c.producer.WriteMessages(ctx, retryMsg)
}

// sendToDLQ forwards the failed message to the dead‑letter queue.
func (c *SubscriptionConsumer) sendToDLQ(ctx context.Context, original *kafka.Message, processErr error) error {
	dlqTopic := original.Topic + ".dlq"
	headers := append(original.Headers,
		kafka.Header{Key: "error", Value: []byte(processErr.Error())},
		kafka.Header{Key: "failed_at", Value: []byte(time.Now().Format(time.RFC3339))},
	)
	dlqMsg := kafka.Message{
		Topic:   dlqTopic,
		Key:     original.Key,
		Value:   original.Value,
		Headers: headers,
		Time:    time.Now(),
	}
	return c.producer.WriteMessages(ctx, dlqMsg)
}

// Close shuts down the consumer and its internal producer.
func (c *SubscriptionConsumer) Close() error {
	if err := c.consumer.Close(); err != nil {
		c.logger.Error("failed to close consumer", zap.Error(err))
	}
	return c.producer.Close()
}

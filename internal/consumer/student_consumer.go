// File: internal/consumer/student_consumer.go
package consumer

import (
	"context"
	"encoding/json"
	"fmt"
	"time"

	"github.com/segmentio/kafka-go"
	"go.uber.org/zap"

	"auth-service/internal/academics/models"
	"auth-service/internal/client"
	"auth-service/internal/util"
)

// StudentConsumer consumes student-related events from Kafka,
// applies retry logic, and sends permanently failed messages to a DLQ.
type StudentConsumer struct {
	kafkaConsumers map[string]*client.KafkaConsumer
	logger         *zap.Logger
	maxRetries     int
	producer       *kafka.Writer // for retries and DLQ
}

// NewStudentConsumer creates a new StudentConsumer.
// It expects a map of topic → KafkaConsumer and uses the same brokers for producing.
func NewStudentConsumer(
	kafkaConsumers map[string]*client.KafkaConsumer,
	brokers []string,
) *StudentConsumer {
	logger := util.Get().Named("student_consumer")

	// Extract topics for logging
	topics := make([]string, 0, len(kafkaConsumers))
	for t := range kafkaConsumers {
		topics = append(topics, t)
	}

	// Create a shared Kafka writer for producing retry/DLQ messages
	producer := &kafka.Writer{
		Addr:         kafka.TCP(brokers...),
		Balancer:     &kafka.LeastBytes{},
		RequiredAcks: kafka.RequireOne,
		Async:        false, // synchronous for reliability
	}

	logger.Info("Student consumer initialized",
		zap.Strings("topics", topics),
		zap.Int("topic_count", len(topics)),
		zap.Int("max_retries", 3),
	)

	return &StudentConsumer{
		kafkaConsumers: kafkaConsumers,
		logger:         logger,
		maxRetries:     3,
		producer:       producer,
	}
}

// Start begins consuming from all assigned topics.
func (c *StudentConsumer) Start(ctx context.Context) error {
	c.logger.Info("Student consumer started")

	for topic, kc := range c.kafkaConsumers {
		go c.consumeTopic(ctx, topic, kc)
	}

	<-ctx.Done()
	c.logger.Info("Student consumer stopped")
	return ctx.Err()
}

// consumeTopic runs the consumption loop for a single topic.
func (c *StudentConsumer) consumeTopic(
	ctx context.Context,
	topic string,
	kc *client.KafkaConsumer,
) {
	c.logger.Info("started topic consumer", zap.String("topic", topic))

	for {
		msg, err := kc.ConsumeMessage(ctx)
		if err != nil {
			if ctx.Err() != nil {
				return
			}
			c.logger.Error("failed to consume message",
				zap.String("topic", topic),
				zap.Error(err),
			)
			time.Sleep(time.Second)
			continue
		}

		// Extract event type and retry count
		eventType := c.extractEventType(msg)
		retryCount := c.getRetryCount(msg)

		// Process the event
		err = c.handleEvent(ctx, eventType, msg.Value)
		if err != nil {
			c.logger.Error("event processing failed",
				zap.String("event_type", eventType),
				zap.Int("retry", retryCount),
				zap.Error(err),
			)

			if retryCount < c.maxRetries {
				// Retry: publish a new message with incremented retry count
				c.logger.Warn("retrying event",
					zap.String("event_type", eventType),
					zap.Int("attempt", retryCount+1),
				)
				if pubErr := c.publishRetry(ctx, msg, retryCount+1); pubErr != nil {
					c.logger.Error("failed to publish retry message", zap.Error(pubErr))
					// Continue without committing – the original message will be redelivered by Kafka.
					// To avoid infinite loop, we could also move to DLQ after a second layer of failures,
					// but here we keep it simple: if we can't publish the retry, we rely on Kafka redelivery.
					continue
				}
			} else {
				// Max retries exceeded → send to DLQ
				c.logger.Error("max retries exceeded, sending to DLQ",
					zap.String("event_type", eventType),
				)
				if dlqErr := c.sendToDLQ(ctx, msg, err); dlqErr != nil {
					c.logger.Error("failed to send message to DLQ", zap.Error(dlqErr))
					// Continue without committing – the message will be retried again (potentially forever).
					// To avoid this, you could add a dead‑letter counter header or move to an alert.
					continue
				}
			}

			// Commit the original message after successful retry publication or DLQ send.
			// This removes it from the main topic.
			if commitErr := kc.CommitMessage(ctx, msg); commitErr != nil {
				c.logger.Error("failed to commit original message",
					zap.String("topic", topic),
					zap.Error(commitErr),
				)
			}
			continue
		}

		// Success – commit immediately
		if err := kc.CommitMessage(ctx, msg); err != nil {
			c.logger.Error("failed to commit message",
				zap.String("topic", topic),
				zap.Error(err),
			)
		}
	}
}

// handleEvent routes the event to the appropriate handler.
func (c *StudentConsumer) handleEvent(ctx context.Context, eventType string, payload []byte) error {
	switch eventType {
	case "student.created":
		return c.handleStudentCreated(ctx, payload)
	case "student.updated":
		return c.handleStudentUpdated(ctx, payload)
	case "student.deleted":
		return c.handleStudentDeleted(ctx, payload)
	case "student.promoted":
		return c.handleStudentPromoted(ctx, payload)
	default:
		c.logger.Warn("unknown event type", zap.String("event_type", eventType))
		return nil
	}
}

// ----- Event handlers (stubs – extend as needed) -----

func (c *StudentConsumer) handleStudentCreated(ctx context.Context, payload []byte) error {
	var student models.Student
	if err := json.Unmarshal(payload, &student); err != nil {
		return err
	}
	c.logger.Info("student created event",
		zap.String("student_id", student.StudentID.String()),
		zap.String("name", student.FirstName+" "+student.LastName),
	)
	// Add business logic here
	return nil
}

func (c *StudentConsumer) handleStudentUpdated(ctx context.Context, payload []byte) error {
	var data map[string]interface{}
	if err := json.Unmarshal(payload, &data); err != nil {
		return err
	}
	c.logger.Info("student updated event")
	return nil
}

func (c *StudentConsumer) handleStudentDeleted(ctx context.Context, payload []byte) error {
	var data map[string]interface{}
	if err := json.Unmarshal(payload, &data); err != nil {
		return err
	}
	c.logger.Info("student deleted event")
	return nil
}

func (c *StudentConsumer) handleStudentPromoted(ctx context.Context, payload []byte) error {
	var data map[string]interface{}
	if err := json.Unmarshal(payload, &data); err != nil {
		return err
	}
	c.logger.Info("student promoted event")
	return nil
}

// ----- Helpers -----

// extractEventType retrieves the "event_type" header.
func (c *StudentConsumer) extractEventType(msg *kafka.Message) string {
	for _, h := range msg.Headers {
		if h.Key == "event_type" {
			return string(h.Value)
		}
	}
	return ""
}

// getRetryCount reads the "retry_count" header, defaulting to 0.
func (c *StudentConsumer) getRetryCount(msg *kafka.Message) int {
	for _, h := range msg.Headers {
		if h.Key == "retry_count" {
			var count int
			fmt.Sscanf(string(h.Value), "%d", &count)
			return count
		}
	}
	return 0
}

// publishRetry produces a new message to the same topic with an incremented retry_count.
func (c *StudentConsumer) publishRetry(ctx context.Context, original *kafka.Message, newRetryCount int) error {
	// Copy headers and add/update retry_count
	headers := make([]kafka.Header, 0, len(original.Headers)+1)
	found := false
	for _, h := range original.Headers {
		if h.Key == "retry_count" {
			headers = append(headers, kafka.Header{
				Key:   "retry_count",
				Value: []byte(fmt.Sprintf("%d", newRetryCount)),
			})
			found = true
		} else {
			headers = append(headers, h)
		}
	}
	if !found {
		headers = append(headers, kafka.Header{
			Key:   "retry_count",
			Value: []byte(fmt.Sprintf("%d", newRetryCount)),
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

// sendToDLQ publishes the message to <original-topic>.dlq with error information.
func (c *StudentConsumer) sendToDLQ(ctx context.Context, original *kafka.Message, processErr error) error {
	dlqTopic := original.Topic + ".dlq"

	// Add error details as headers
	headers := append(original.Headers,
		kafka.Header{
			Key:   "error",
			Value: []byte(processErr.Error()),
		},
		kafka.Header{
			Key:   "failed_at",
			Value: []byte(time.Now().Format(time.RFC3339)),
		},
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

// Close shuts down the consumer and the internal producer.
func (c *StudentConsumer) Close() error {
	c.logger.Info("closing student consumer")

	// Close all Kafka consumers
	for topic, kc := range c.kafkaConsumers {
		c.logger.Info("closing kafka consumer", zap.String("topic", topic))
		if err := kc.Close(); err != nil {
			c.logger.Error("failed to close kafka consumer", zap.Error(err))
		}
	}

	// Close the producer
	if err := c.producer.Close(); err != nil {
		c.logger.Error("failed to close producer", zap.Error(err))
	}

	return nil
}

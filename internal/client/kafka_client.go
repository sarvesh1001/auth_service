// File: internal/client/kafka_client.go (FIXED - Manual Commit Control)
// ✅ CRITICAL FIX: Changed from auto-commit ReadMessage to manual FetchMessage + CommitMessages

package client

import (
	"context"
	"fmt"
	"time"

	"github.com/segmentio/kafka-go"
	"go.uber.org/zap"

	"auth-service/internal/config"
	"auth-service/internal/util"
)

type KafkaProducer struct {
	Writer *kafka.Writer
	config *config.Config
	logger *zap.Logger
}

type KafkaConsumer struct {
	Reader *kafka.Reader
	config *config.Config
	logger *zap.Logger
}

func NewKafkaProducer(cfg *config.Config, logger *zap.Logger) (*KafkaProducer, error) {
	kafkaConfig := cfg.Kafka

	writer := &kafka.Writer{
		Addr:         kafka.TCP(kafkaConfig.Brokers...),
		Balancer:     &kafka.LeastBytes{},
		MaxAttempts:  3,
		BatchSize:    100,
		BatchBytes:   1048576,
		BatchTimeout: 10 * time.Millisecond,
		RequiredAcks: kafka.RequireOne,
		Async:        false,
		Completion: func(messages []kafka.Message, err error) {
			if err != nil {
				logger.Error("failed to write kafka messages",
					zap.Error(err),
					zap.Int("message_count", len(messages)),
				)
			}
		},
	}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	if err := healthCheckKafka(ctx, kafkaConfig.Brokers[0]); err != nil {
		return nil, fmt.Errorf("failed to connect to Kafka brokers: %w", err)
	}

	util.Get().Info("Kafka producer initialized",
		zap.Strings("brokers", kafkaConfig.Brokers),
	)

	return &KafkaProducer{
		Writer: writer,
		config: cfg,
		logger: logger,
	}, nil
}

func NewKafkaConsumer(cfg *config.Config, topic string, groupID string, logger *zap.Logger) (*KafkaConsumer, error) {
	kafkaConfig := cfg.Kafka

	reader := kafka.NewReader(kafka.ReaderConfig{
		Brokers:        kafkaConfig.Brokers,
		Topic:          topic,
		GroupID:        groupID,
		MinBytes:       10e3,
		MaxBytes:       10e6,
		CommitInterval: 0, // ✅ CRITICAL: Disable auto-commit, we'll commit manually
		StartOffset:    kafka.FirstOffset,
		MaxWait:        5 * time.Second,
		ReadBackoffMin: 100 * time.Millisecond,
		ReadBackoffMax: 1 * time.Second,
	})

	logger.Info("Kafka consumer initialized with manual commit",
		zap.Strings("brokers", kafkaConfig.Brokers),
		zap.String("topic", topic),
		zap.String("group_id", groupID),
	)

	return &KafkaConsumer{
		Reader: reader,
		config: cfg,
		logger: logger,
	}, nil
}

func (p *KafkaProducer) Close() error {
	if p.Writer != nil {
		err := p.Writer.Close()
		if err != nil {
			p.logger.Error("failed to close Kafka producer", zap.Error(err))
			return err
		}
		p.logger.Info("Kafka producer closed")
	}
	return nil
}

func (c *KafkaConsumer) Close() error {
	if c.Reader != nil {
		err := c.Reader.Close()
		if err != nil {
			c.logger.Error("failed to close Kafka consumer", zap.Error(err))
			return err
		}
		c.logger.Info("Kafka consumer closed")
	}
	return nil
}

func (p *KafkaProducer) ProduceMessage(ctx context.Context, topic string, key, value []byte, headers map[string]string) error {
	msg := kafka.Message{
		Topic: topic,
		Key:   key,
		Value: value,
	}

	for k, v := range headers {
		msg.Headers = append(msg.Headers, kafka.Header{
			Key:   k,
			Value: []byte(v),
		})
	}

	if err := p.Writer.WriteMessages(ctx, msg); err != nil {
		return fmt.Errorf("failed to write kafka message: %w", err)
	}

	p.logger.Debug("Produced kafka message",
		zap.String("topic", topic),
		zap.ByteString("key", key),
		zap.Int("value_size", len(value)),
	)

	return nil
}

// ✅ CRITICAL FIX: Changed from ReadMessage (auto-commit) to FetchMessage (manual commit)
func (c *KafkaConsumer) ConsumeMessage(ctx context.Context) (*kafka.Message, error) {
	msg, err := c.Reader.FetchMessage(ctx) // Fetch WITHOUT committing
	if err != nil {
		return nil, fmt.Errorf("failed to fetch kafka message: %w", err)
	}

	c.logger.Debug("Fetched kafka message (not yet committed)",
		zap.String("topic", msg.Topic),
		zap.ByteString("key", msg.Key),
		zap.Int("value_size", len(msg.Value)),
		zap.Int64("offset", msg.Offset),
		zap.Time("time", msg.Time),
	)

	return &msg, nil
}

// ✅ NEW: Explicit commit method - call ONLY after successful processing
func (c *KafkaConsumer) CommitMessage(ctx context.Context, msg *kafka.Message) error {
	if msg == nil {
		return fmt.Errorf("cannot commit nil message")
	}

	if err := c.Reader.CommitMessages(ctx, *msg); err != nil {
		return fmt.Errorf("failed to commit kafka message: %w", err)
	}

	c.logger.Debug("Committed kafka message",
		zap.String("topic", msg.Topic),
		zap.Int64("offset", msg.Offset),
		zap.Int("partition", msg.Partition),
	)

	return nil
}

// ✅ NEW: Batch commit for efficiency
func (c *KafkaConsumer) CommitMessages(ctx context.Context, msgs ...*kafka.Message) error {
	if len(msgs) == 0 {
		return nil
	}

	// Convert to value slice for CommitMessages
	valueMsgs := make([]kafka.Message, len(msgs))
	for i, msg := range msgs {
		if msg == nil {
			continue
		}
		valueMsgs[i] = *msg
	}

	if err := c.Reader.CommitMessages(ctx, valueMsgs...); err != nil {
		return fmt.Errorf("failed to commit %d messages: %w", len(msgs), err)
	}

	c.logger.Debug("Committed message batch",
		zap.Int("count", len(msgs)),
	)

	return nil
}

func (p *KafkaProducer) HealthCheck(ctx context.Context) error {
	return healthCheckKafka(ctx, p.config.Kafka.Brokers[0])
}

func healthCheckKafka(ctx context.Context, broker string) error {
	dialer := &kafka.Dialer{
		Timeout:   5 * time.Second,
		DualStack: true,
	}

	conn, err := dialer.DialContext(ctx, "tcp", broker)
	if err != nil {
		return fmt.Errorf("failed to connect to kafka broker: %w", err)
	}
	defer conn.Close()

	_, err = conn.ReadPartitions()
	if err != nil {
		return fmt.Errorf("failed to read Kafka partitions: %w", err)
	}

	return nil
}

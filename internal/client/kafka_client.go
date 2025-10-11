package client

import (
    "context"
    "crypto/tls"
    "fmt"
    "time"

    "github.com/segmentio/kafka-go"
    "go.uber.org/zap"

    "auth-service/internal/config"
    "auth-service/internal/util"
)

type KafkaProducer struct {
    Writer *kafka.Writer
    config *config.KafkaConfig
    logger *zap.Logger
}

type KafkaConsumer struct {
    Reader *kafka.Reader
    config *config.KafkaConfig
    logger *zap.Logger
}
func NewKafkaProducer(cfg *config.Config, logger *zap.Logger) (*KafkaProducer, error) {
    kafkaConfig := cfg.Kafka

    writer := &kafka.Writer{
        Addr:         kafka.TCP(kafkaConfig.Brokers...),
        Balancer:     &kafka.LeastBytes{},
        MaxAttempts:  3,
        BatchSize:    100,
        BatchBytes:   1048576, // 1MB
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

    // Manually perform a TLS dial to test connectivity in HealthCheck
    ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
    defer cancel()

    // We don't specify TLS here (dial over plain TCP, or implement custom Dialer outside Kafka Writer)
    // Just connection test by writing a test message, expecting fail if topic missing
    err := writer.WriteMessages(ctx, kafka.Message{
        Topic: "health-check",
        Key:   []byte("test"),
        Value: []byte("health check message"),
    })

    if err != nil && !isConnectivityError(err) {
        return nil, fmt.Errorf("failed to connect to Kafka brokers: %w", err)
    }

    util.Info("Kafka producer initialized without Dialer (TLS not set on Writer)",
        zap.Strings("brokers", kafkaConfig.Brokers),
    )

    return &KafkaProducer{
        Writer: writer,
        config: &kafkaConfig,
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
        CommitInterval: time.Second,
        StartOffset:    kafka.FirstOffset,
        MaxWait:        5 * time.Second,
        ReadBackoffMin: 100 * time.Millisecond,
        ReadBackoffMax: 1 * time.Second,
    })

    util.Get().Info("Kafka consumer initialized",
        zap.Strings("brokers", kafkaConfig.Brokers),
        zap.String("topic", topic),
        zap.String("group_id", groupID),
    )

    return &KafkaConsumer{
        Reader: reader,
        config: &kafkaConfig,
        logger: util.Get(),
    }, nil
}

func (p *KafkaProducer) Close() error {
    if p.Writer != nil {
        err := p.Writer.Close()
        if err != nil {
            util.Get().Error("failed to close Kafka producer", zap.Error(err))
            return err
        }
        util.Get().Info("Kafka producer closed")
    }
    return nil
}

func (c *KafkaConsumer) Close() error {
    if c.Reader != nil {
        err := c.Reader.Close()
        if err != nil {
            util.Get().Error("failed to close Kafka consumer", zap.Error(err))
            return err
        }
        util.Get().Info("Kafka consumer closed")
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

    util.Get().Debug("Produced kafka message",
        zap.String("topic", topic),
        zap.ByteString("key", key),
        zap.Int("value_size", len(value)),
    )

    return nil
}

func (c *KafkaConsumer) ConsumeMessage(ctx context.Context) (*kafka.Message, error) {
    msg, err := c.Reader.ReadMessage(ctx)
    if err != nil {
        return nil, fmt.Errorf("failed to read kafka message: %w", err)
    }

    util.Get().Debug("Consumed kafka message",
        zap.String("topic", msg.Topic),
        zap.ByteString("key", msg.Key),
        zap.Int("value_size", len(msg.Value)),
        zap.Time("time", msg.Time),
    )

    return &msg, nil
}
func (p *KafkaProducer) HealthCheck(ctx context.Context) error {
    dialer := &kafka.Dialer{
        TLS: &tls.Config{
            InsecureSkipVerify: config.Get().IsDevelopment(),
        },
        Timeout:   5 * time.Second,
        DualStack: true,
    }

    conn, err := dialer.DialContext(ctx, "tcp", p.config.Brokers[0])
    if err != nil {
        return fmt.Errorf("failed to connect to kafka broker (TLS dialer): %w", err)
    }
    defer conn.Close()

    _, err = conn.ReadPartitions()
    if err != nil {
        return fmt.Errorf("failed to read Kafka partitions: %w", err)
    }
    return nil
}

func isConnectivityError(err error) bool {
    return err != nil &&
        (err.Error() == "leader not available" ||
            err.Error() == "topic authorization failed" ||
            err.Error() == "unknown topic or partition")
}

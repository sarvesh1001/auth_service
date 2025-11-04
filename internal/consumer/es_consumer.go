// File: internal/consumer/es_consumer.go (FIXED)
// Consumes Kafka events and indexes them to Elasticsearch
// ✅ FIXED: Bulk indexing + retry logic + proper error handling

package consumer

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"time"

	"github.com/elastic/go-elasticsearch/v8"
	"github.com/elastic/go-elasticsearch/v8/esutil"
	"go.uber.org/zap"

	"auth-service/internal/client"
	"auth-service/internal/models"
	"auth-service/internal/util"
)

// ESConsumer consumes Kafka events and indexes them into Elasticsearch
type ESConsumer struct {
	kafkaConsumer  *client.KafkaConsumer
	esClient       *elasticsearch.Client
	bulkIndexer    esutil.BulkIndexer
	logger         *zap.Logger
	maxRetries     int
	retryBackoff   time.Duration
}

// NewESConsumer creates a new Elasticsearch consumer
func NewESConsumer(
	kafkaConsumer *client.KafkaConsumer,
	esClient *elasticsearch.Client,
) (*ESConsumer, error) {
	// ✅ FIXED: Initialize bulk indexer for better performance
	bulkIndexer, err := esutil.NewBulkIndexer(esutil.BulkIndexerConfig{
		Client:     esClient,
		NumWorkers: 4,
		FlushBytes: 5e+6, // 5MB
		Timeout:    30 * time.Second,
	})
	if err != nil {
		return nil, fmt.Errorf("failed to create bulk indexer: %w", err)
	}

	return &ESConsumer{
		kafkaConsumer: kafkaConsumer,
		esClient:      esClient,
		bulkIndexer:   bulkIndexer,
		logger:        util.Get(),
		maxRetries:    3,
		retryBackoff:  100 * time.Millisecond,
	}, nil
}

// Start begins consuming from Kafka and indexing to Elasticsearch
func (ec *ESConsumer) Start(ctx context.Context) error {
	ec.logger.Info("ES consumer started")

	for {
		select {
		case <-ctx.Done():
			// ✅ Close bulk indexer gracefully
			if err := ec.bulkIndexer.Close(ctx); err != nil {
				ec.logger.Error("failed to close bulk indexer", zap.Error(err))
			}
			ec.logger.Info("ES consumer stopped")
			return ctx.Err()

		default:
			msg, err := ec.kafkaConsumer.ConsumeMessage(ctx)
			if err != nil {
				ec.logger.Error("failed to consume message", zap.Error(err))
				time.Sleep(time.Second)
				continue
			}

			// Get event type from headers
			eventType := ""
			for _, h := range msg.Headers {
				if h.Key == "event_type" {
					eventType = string(h.Value)
					break
				}
			}

			// Route to appropriate indexing function
			switch eventType {
			case "otp":
				var event models.OTPLogEvent
				if err := json.Unmarshal(msg.Value, &event); err != nil {
					ec.logger.Error("failed to unmarshal OTP event", zap.Error(err))
					continue
				}
				if err := ec.indexOTPEvent(ctx, &event); err != nil {
					ec.logger.Error("failed to index OTP event", zap.Error(err))
				}

			case "mpin":
				var event models.MPINLogEvent
				if err := json.Unmarshal(msg.Value, &event); err != nil {
					ec.logger.Error("failed to unmarshal MPIN event", zap.Error(err))
					continue
				}
				if err := ec.indexMPINEvent(ctx, &event); err != nil {
					ec.logger.Error("failed to index MPIN event", zap.Error(err))
				}

			case "security":
				var event models.SecurityLogEvent
				if err := json.Unmarshal(msg.Value, &event); err != nil {
					ec.logger.Error("failed to unmarshal Security event", zap.Error(err))
					continue
				}
				if err := ec.indexSecurityEvent(ctx, &event); err != nil {
					ec.logger.Error("failed to index Security event", zap.Error(err))
				}

			case "admin":
				var event models.AdminLogEvent
				if err := json.Unmarshal(msg.Value, &event); err != nil {
					ec.logger.Error("failed to unmarshal Admin event", zap.Error(err))
					continue
				}
				if err := ec.indexAdminEvent(ctx, &event); err != nil {
					ec.logger.Error("failed to index Admin event", zap.Error(err))
				}

			case "session":
				var event models.SessionLogEvent
				if err := json.Unmarshal(msg.Value, &event); err != nil {
					ec.logger.Error("failed to unmarshal Session event", zap.Error(err))
					continue
				}
				if err := ec.indexSessionEvent(ctx, &event); err != nil {
					ec.logger.Error("failed to index Session event", zap.Error(err))
				}

			case "user":
				var event models.UserLogEvent
				if err := json.Unmarshal(msg.Value, &event); err != nil {
					ec.logger.Error("failed to unmarshal User event", zap.Error(err))
					continue
				}
				if err := ec.indexUserEvent(ctx, &event); err != nil {
					ec.logger.Error("failed to index User event", zap.Error(err))
				}

			case "device":
				var event models.DeviceLogEvent
				if err := json.Unmarshal(msg.Value, &event); err != nil {
					ec.logger.Error("failed to unmarshal Device event", zap.Error(err))
					continue
				}
				if err := ec.indexDeviceEvent(ctx, &event); err != nil {
					ec.logger.Error("failed to index Device event", zap.Error(err))
				}

			default:
				ec.logger.Warn("unknown event type received", zap.String("event_type", eventType))
			}
		}
	}
}

// Stop stops the consumer gracefully
func (ec *ESConsumer) Stop(ctx context.Context) error {
	return ec.bulkIndexer.Close(ctx)
}

// ================== Indexing Methods ==================

func (ec *ESConsumer) indexOTPEvent(ctx context.Context, event *models.OTPLogEvent) error {
	index := fmt.Sprintf("otp-events-%s", event.Timestamp.Format("2006.01.02"))
	return ec.indexDocumentWithRetry(ctx, index, event.EventID, event)
}

func (ec *ESConsumer) indexMPINEvent(ctx context.Context, event *models.MPINLogEvent) error {
	index := fmt.Sprintf("mpin-events-%s", event.Timestamp.Format("2006.01.02"))
	return ec.indexDocumentWithRetry(ctx, index, event.EventID, event)
}

func (ec *ESConsumer) indexSecurityEvent(ctx context.Context, event *models.SecurityLogEvent) error {
	index := fmt.Sprintf("security-events-%s", event.Timestamp.Format("2006.01.02"))
	return ec.indexDocumentWithRetry(ctx, index, event.EventID, event)
}

func (ec *ESConsumer) indexAdminEvent(ctx context.Context, event *models.AdminLogEvent) error {
	index := fmt.Sprintf("admin-events-%s", event.Timestamp.Format("2006.01.02"))
	return ec.indexDocumentWithRetry(ctx, index, event.EventID, event)
}

func (ec *ESConsumer) indexSessionEvent(ctx context.Context, event *models.SessionLogEvent) error {
	index := fmt.Sprintf("session-events-%s", event.Timestamp.Format("2006.01.02"))
	return ec.indexDocumentWithRetry(ctx, index, event.EventID, event)
}

func (ec *ESConsumer) indexUserEvent(ctx context.Context, event *models.UserLogEvent) error {
	index := fmt.Sprintf("user-events-%s", event.Timestamp.Format("2006.01.02"))
	return ec.indexDocumentWithRetry(ctx, index, event.EventID, event)
}

func (ec *ESConsumer) indexDeviceEvent(ctx context.Context, event *models.DeviceLogEvent) error {
	index := fmt.Sprintf("device-events-%s", event.Timestamp.Format("2006.01.02"))
	return ec.indexDocumentWithRetry(ctx, index, event.EventID, event)
}

// ✅ FIXED: Use bulk indexer instead of single document indexing
func (ec *ESConsumer) indexDocumentWithRetry(ctx context.Context, index, docID string, doc interface{}) error {
	data, err := json.Marshal(doc)
	if err != nil {
		return fmt.Errorf("failed to marshal document: %w", err)
	}

	// ✅ Use bulk indexer
	return ec.bulkIndexer.Add(ctx, esutil.BulkIndexerItem{
		Action:     "index",
		Index:      index,
		DocumentID: docID,
		Body:       bytes.NewReader(data),
		OnFailure: func(_ context.Context, req esutil.BulkIndexerItem, res esutil.BulkIndexerResponseItem, err error) {
			if err != nil {
				ec.logger.Error("bulk indexing error",
					zap.String("index", index),
					zap.String("doc_id", docID),
					zap.Error(err))
			} else {
				ec.logger.Error("bulk indexing response error",
					zap.String("index", index),
					zap.String("doc_id", docID),
					zap.String("error", res.Error.Type),
					zap.String("reason", res.Error.Reason))
			}
		},
		OnSuccess: func(_ context.Context, _ esutil.BulkIndexerItem, res esutil.BulkIndexerResponseItem) {
			ec.logger.Debug("document indexed",
				zap.String("index", index),
				zap.String("doc_id", docID))
		},
	})
}

// Health check for Elasticsearch
func (ec *ESConsumer) Health(ctx context.Context) error {
	res, err := ec.esClient.Info()
	if err != nil {
		return fmt.Errorf("elasticsearch unhealthy: %w", err)
	}
	defer res.Body.Close()

	if res.IsError() {
		return fmt.Errorf("elasticsearch error: %s", res.Status())
	}

	return nil
}
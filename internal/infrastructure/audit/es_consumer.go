// File: internal/infrastructure/audit/es_consumer.go
package audit

import (
	"context"
	"encoding/json"
	"fmt"

	"github.com/segmentio/kafka-go"
	"go.uber.org/zap"

	"auth-service/internal/client"
)

// AuditESConsumer consumes audit events from Kafka and indexes them to Elasticsearch.
type AuditESConsumer struct {
	consumer    *client.KafkaConsumer
	esClient    *client.ESClient
	logger      *zap.Logger
	topic       string
	maxRetries  int
	environment string
}

// NewAuditESConsumer creates a new consumer for audit events to Elasticsearch.
func NewAuditESConsumer(
	consumer *client.KafkaConsumer,
	esClient *client.ESClient,
	logger *zap.Logger,
	environment string,
) *AuditESConsumer {
	return &AuditESConsumer{
		consumer:    consumer,
		esClient:    esClient,
		logger:      logger.Named("audit_es_consumer"),
		topic:       "audit-logs",
		maxRetries:  3,
		environment: environment,
	}
}

// Start consumes messages from Kafka and indexes them to Elasticsearch.
func (c *AuditESConsumer) Start(ctx context.Context) {
	c.logger.Info("starting audit ES consumer", zap.String("topic", c.topic))
	for {
		msg, err := c.consumer.ConsumeMessage(ctx)
		if err != nil {
			if ctx.Err() != nil {
				return
			}
			c.logger.Error("failed to consume message", zap.Error(err))
			continue
		}

		// Extract audit_id from headers
		auditIDHeader := c.extractHeader(msg, "audit_id")
		logger := c.logger.With(
			zap.String("audit_id_header", auditIDHeader),
			zap.Int64("offset", msg.Offset),
			zap.String("topic", msg.Topic),
		)

		if auditIDHeader == "" {
			logger.Warn("missing audit_id header, skipping")
			_ = c.consumer.CommitMessage(ctx, msg)
			continue
		}

		logger.Debug("processing audit event for ES", zap.Int("payload_size", len(msg.Value)))

		// ✅ FIXED: Unmarshal into AuditLog (not AuditLogEvent)
		var auditLog AuditLog
		if err := json.Unmarshal(msg.Value, &auditLog); err != nil {
			logger.Error("failed to unmarshal audit log", zap.Error(err))
			_ = c.consumer.CommitMessage(ctx, msg)
			continue
		}

		// Index to Elasticsearch
		if err := c.indexAuditLog(ctx, &auditLog); err != nil {
			logger.Error("failed to index audit log to ES", zap.Error(err))
			_ = c.consumer.CommitMessage(ctx, msg)
			continue
		}

		logger.Info("audit event indexed to Elasticsearch",
			zap.String("audit_id", auditLog.AuditID.String()),
			zap.String("module", auditLog.Module),
			zap.String("action", auditLog.Action),
		)
		if err := c.consumer.CommitMessage(ctx, msg); err != nil {
			logger.Error("failed to commit Kafka message", zap.Error(err))
		}
	}
}

// indexAuditLog prepares the document and indexes it to Elasticsearch.
func (c *AuditESConsumer) indexAuditLog(ctx context.Context, log *AuditLog) error {
	docID := log.AuditID.String()
	if docID == "" {
		return fmt.Errorf("missing audit_id")
	}

	// Index by creation date
	index := fmt.Sprintf("audit-%s", log.CreatedAt.Format("2006.01.02"))

	// Build the document
	doc := map[string]interface{}{
		"audit_id":     log.AuditID,
		"company_id":   log.CompanyID,
		"module":       log.Module,
		"action":       log.Action,
		"entity_type":  log.EntityType,
		"entity_id":    log.EntityID,
		"actor_type":   log.ActorType,
		"actor_id":     log.ActorID,
		"created_at":   log.CreatedAt,
		"environment":  c.environment,
		"service_name": "auth-service",
	}

	// Add optional JSON fields if present
	if len(log.BeforeState) > 0 {
		var before interface{}
		if err := json.Unmarshal(log.BeforeState, &before); err == nil {
			doc["before_state"] = before
		}
	}
	if len(log.AfterState) > 0 {
		var after interface{}
		if err := json.Unmarshal(log.AfterState, &after); err == nil {
			doc["after_state"] = after
		}
	}
	if len(log.Metadata) > 0 {
		var meta interface{}
		if err := json.Unmarshal(log.Metadata, &meta); err == nil {
			doc["metadata"] = meta
		}
	}

	_, err := c.esClient.IndexDocument(index, docID, doc)
	return err
}

// extractHeader returns the value of a specific header key.
func (c *AuditESConsumer) extractHeader(msg *kafka.Message, key string) string {
	for _, h := range msg.Headers {
		if h.Key == key {
			return string(h.Value)
		}
	}
	return ""
}

// Close shuts down the consumer.
func (c *AuditESConsumer) Close() error {
	return c.consumer.Close()
}

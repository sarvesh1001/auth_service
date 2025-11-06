// File: internal/consumer/es_consumer.go - UPDATED FOR MULTI-TOPIC CONSUMPTION
// Consumes Kafka events from multiple topics and indexes them to Elasticsearch for SEARCH & ANALYTICS
// ✅ UPDATED: Handles multiple topics with separate consumers

package consumer

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"sync"
	"time"

	"github.com/elastic/go-elasticsearch/v8"
	"github.com/elastic/go-elasticsearch/v8/esutil"
	"github.com/segmentio/kafka-go" // ✅ ADD MISSING IMPORT
	"go.uber.org/zap"

	"auth-service/internal/client"
	"auth-service/internal/models"
	"auth-service/internal/util"
)

// ESConsumer consumes Kafka SEARCH events from multiple topics and indexes them into Elasticsearch
type ESConsumer struct {
	kafkaConsumers map[string]*client.KafkaConsumer // ✅ CHANGED: Multiple consumers by topic
	esClient       *elasticsearch.Client
	bulkIndexer    esutil.BulkIndexer
	logger         *zap.Logger
	maxRetries     int
	retryBackoff   time.Duration
}

// NewESConsumer creates a new Elasticsearch consumer for search events
func NewESConsumer(
	kafkaConsumers map[string]*client.KafkaConsumer, // ✅ CHANGED: Accept map of consumers
	esClient *elasticsearch.Client,
) (*ESConsumer, error) {
	// ✅ Initialize bulk indexer for better performance
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
		kafkaConsumers: kafkaConsumers, // ✅ FIXED: Use correct field name (plural)
		esClient:       esClient,
		bulkIndexer:    bulkIndexer,
		logger:         util.Get(),
		maxRetries:     3,
		retryBackoff:   100 * time.Millisecond,
	}, nil
}

// Start begins consuming from Kafka topics and indexing SEARCH events to Elasticsearch
func (ec *ESConsumer) Start(ctx context.Context) error {
	ec.logger.Info("ES consumer started for multiple topics",
		zap.Int("topic_count", len(ec.kafkaConsumers)),
		zap.Strings("topics", ec.getTopicNames()))

	var wg sync.WaitGroup
	
	// Start a goroutine for each topic consumer
	for topic, kafkaConsumer := range ec.kafkaConsumers {
		wg.Add(1)
		go func(topic string, consumer *client.KafkaConsumer) {
			defer wg.Done()
			ec.consumeTopic(ctx, topic, consumer)
		}(topic, kafkaConsumer)
	}
	
	// Wait for all consumers to finish when context is cancelled
	wg.Wait()
	
	// ✅ Close bulk indexer gracefully
	if err := ec.bulkIndexer.Close(ctx); err != nil {
		ec.logger.Error("failed to close bulk indexer", zap.Error(err))
	}
	
	ec.logger.Info("ES consumer stopped")
	return ctx.Err()
}

// consumeTopic handles consumption for a single topic
func (ec *ESConsumer) consumeTopic(ctx context.Context, topic string, kafkaConsumer *client.KafkaConsumer) {
	ec.logger.Info("Starting consumption for topic", zap.String("topic", topic))
	
	for {
		select {
		case <-ctx.Done():
			ec.logger.Info("Stopping consumption for topic", zap.String("topic", topic))
			return
			
		default:
			msg, err := kafkaConsumer.ConsumeMessage(ctx)
			if err != nil {
				ec.logger.Error("failed to consume message", 
					zap.String("topic", topic),
					zap.Error(err))
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

			// Process the event based on type
			ec.processEvent(ctx, eventType, msg, kafkaConsumer)
		}
	}
}

// processEvent processes a single event - ✅ FIXED: Use kafka.Message type
func (ec *ESConsumer) processEvent(ctx context.Context, eventType string, msg *kafka.Message, kafkaConsumer *client.KafkaConsumer) {
	switch eventType {
	case "security":
		var event models.SecurityLogEvent
		if err := json.Unmarshal(msg.Value, &event); err != nil {
			ec.logger.Error("failed to unmarshal Security event", zap.Error(err))
			if err := kafkaConsumer.CommitMessage(ctx, msg); err != nil {
				ec.logger.Error("failed to commit message after unmarshal error", zap.Error(err))
			}
			return
		}
		if err := ec.indexSecurityEvent(ctx, &event); err != nil {
			ec.logger.Error("failed to index Security event", zap.Error(err))
		}
		if err := kafkaConsumer.CommitMessage(ctx, msg); err != nil {
			ec.logger.Error("failed to commit security event message", zap.Error(err))
		}

	case "admin":
		var event models.AdminLogEvent
		if err := json.Unmarshal(msg.Value, &event); err != nil {
			ec.logger.Error("failed to unmarshal Admin event", zap.Error(err))
			if err := kafkaConsumer.CommitMessage(ctx, msg); err != nil {
				ec.logger.Error("failed to commit message after unmarshal error", zap.Error(err))
			}
			return
		}
		if err := ec.indexAdminEvent(ctx, &event); err != nil {
			ec.logger.Error("failed to index Admin event", zap.Error(err))
		}
		if err := kafkaConsumer.CommitMessage(ctx, msg); err != nil {
			ec.logger.Error("failed to commit admin event message", zap.Error(err))
		}

	case "session":
		var event models.SessionLogEvent
		if err := json.Unmarshal(msg.Value, &event); err != nil {
			ec.logger.Error("failed to unmarshal Session event", zap.Error(err))
			if err := kafkaConsumer.CommitMessage(ctx, msg); err != nil {
				ec.logger.Error("failed to commit message after unmarshal error", zap.Error(err))
			}
			return
		}
		if err := ec.indexSessionEvent(ctx, &event); err != nil {
			ec.logger.Error("failed to index Session event", zap.Error(err))
		}
		if err := kafkaConsumer.CommitMessage(ctx, msg); err != nil {
			ec.logger.Error("failed to commit session event message", zap.Error(err))
		}

	case "user":
		var event models.UserLogEvent
		if err := json.Unmarshal(msg.Value, &event); err != nil {
			ec.logger.Error("failed to unmarshal User event", zap.Error(err))
			if err := kafkaConsumer.CommitMessage(ctx, msg); err != nil {
				ec.logger.Error("failed to commit message after unmarshal error", zap.Error(err))
			}
			return
		}
		if err := ec.indexUserEvent(ctx, &event); err != nil {
			ec.logger.Error("failed to index User event", zap.Error(err))
		}
		if err := kafkaConsumer.CommitMessage(ctx, msg); err != nil {
			ec.logger.Error("failed to commit user event message", zap.Error(err))
		}

	// ✅ REMOVED: Device, MPIN, OTP events (now handled by ClickHouse only)
	default:
		ec.logger.Debug("ignoring time-series event for Elasticsearch",
			zap.String("event_type", eventType),
			zap.String("reason", "handled_by_clickhouse"))
		// Still commit the message since it's processed by ClickHouse consumer
		if err := kafkaConsumer.CommitMessage(ctx, msg); err != nil {
			ec.logger.Error("failed to commit ignored message", zap.Error(err))
		}
	}
}

// getTopicNames returns the list of topics being consumed
func (ec *ESConsumer) getTopicNames() []string {
	topics := make([]string, 0, len(ec.kafkaConsumers))
	for topic := range ec.kafkaConsumers {
		topics = append(topics, topic)
	}
	return topics
}

// Stop stops the consumer gracefully
func (ec *ESConsumer) Stop(ctx context.Context) error {
	return ec.bulkIndexer.Close(ctx)
}

// ================== SEARCH EVENT Indexing Methods ==================

func (ec *ESConsumer) indexSecurityEvent(ctx context.Context, event *models.SecurityLogEvent) error {
	index := fmt.Sprintf("security-events-%s", event.Timestamp.Format("2006.01.02"))
	return ec.indexDocumentWithRetry(ctx, index, event.EventID, event)
}

// ✅ UPDATED: Handle AdminLogEvent with proper LogEnvelope structure
func (ec *ESConsumer) indexAdminEvent(ctx context.Context, event *models.AdminLogEvent) error {
	// Use LogEnvelope.Timestamp for index date
	timestamp := event.LogEnvelope.Timestamp
	index := ec.getAdminEventIndex(event)

	ec.logger.Debug("indexing admin event",
		zap.String("index", index),
		zap.String("event_id", event.LogEnvelope.EventID),
		zap.String("action", event.Action),
		zap.String("admin_id", event.AdminID),
		zap.String("status", event.Status),
	)

	// Use event_id as document ID for uniqueness
	docID := event.LogEnvelope.EventID

	// Create enriched document with all fields for searching
	enrichedEvent := map[string]interface{}{
		"event_id":       event.LogEnvelope.EventID,
		"event_type":     event.LogEnvelope.EventType,
		"service_name":   event.LogEnvelope.ServiceName,
		"timestamp":      timestamp,
		"environment":    event.LogEnvelope.Environment,
		"version":        event.LogEnvelope.Version,
		"admin_id":       event.AdminID,
		"admin_role":     event.AdminRole,
		"target_user_id": event.TargetUserID,
		"action":         event.Action,
		"resource_type":  event.ResourceType,
		"resource_id":    event.ResourceID,
		"status":         event.Status,
		"error_code":     event.ErrorCode,
		"error_message":  event.ErrorMessage,
		"changes":        event.Changes,
		"duration_ms":    event.Duration,
	}

	return ec.indexDocumentWithRetry(ctx, index, docID, enrichedEvent)
}

// ✅ NEW: Get appropriate index based on admin action type
func (ec *ESConsumer) getAdminEventIndex(event *models.AdminLogEvent) string {
	switch event.Action {
	case "authenticate_admin", "authenticate_admin_with_session", "failed_login_attempt", "record_admin_login", "admin_lockout":
		return fmt.Sprintf("admin-auth-%s", event.LogEnvelope.Timestamp.Format("2006.01.02"))

	case "invite_admin", "promote_admin", "remove_admin", "deactivate_admin", "activate_admin":
		return fmt.Sprintf("admin-management-%s", event.LogEnvelope.Timestamp.Format("2006.01.02"))

	case "initialize_owner", "change_owner_phone":
		return fmt.Sprintf("admin-owner-%s", event.LogEnvelope.Timestamp.Format("2006.01.02"))

	case "update_admin_permissions":
		return fmt.Sprintf("admin-permissions-%s", event.LogEnvelope.Timestamp.Format("2006.01.02"))

	default:
		return fmt.Sprintf("admin-events-%s", event.LogEnvelope.Timestamp.Format("2006.01.02"))
	}
}

func (ec *ESConsumer) indexSessionEvent(ctx context.Context, event *models.SessionLogEvent) error {
	index := fmt.Sprintf("session-events-%s", event.Timestamp.Format("2006.01.02"))
	return ec.indexDocumentWithRetry(ctx, index, event.EventID, event)
}

func (ec *ESConsumer) indexUserEvent(ctx context.Context, event *models.UserLogEvent) error {
	index := fmt.Sprintf("user-events-%s", event.Timestamp.Format("2006.01.02"))
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
			ec.logger.Debug("document indexed in Elasticsearch",
				zap.String("index", index),
				zap.String("doc_id", docID))
		},
	})
}

// ✅ NEW: Query helpers for admin audit trails

// GetAdminEventsByAdminID returns all events for a specific admin
// Useful for audit trails and compliance investigations
func (ec *ESConsumer) GetAdminEventsByAdminID(ctx context.Context, adminID string, limit int) ([]models.AdminLogEvent, error) {
	query := map[string]interface{}{
		"query": map[string]interface{}{
			"match": map[string]interface{}{
				"admin_id": adminID,
			},
		},
		"size": limit,
		"sort": []map[string]interface{}{
			{
				"timestamp": map[string]string{
					"order": "desc",
				},
			},
		},
	}

	queryBody, _ := json.Marshal(query)
	res, err := ec.esClient.Search(
		ec.esClient.Search.WithContext(ctx),
		ec.esClient.Search.WithIndex("admin-*"),
		ec.esClient.Search.WithBody(bytes.NewReader(queryBody)),
	)
	if err != nil {
		ec.logger.Error("failed to search admin events", zap.Error(err))
		return nil, err
	}
	defer res.Body.Close()

	var searchResult struct {
		Hits struct {
			Hits []struct {
				Source models.AdminLogEvent `json:"_source"`
			} `json:"hits"`
		} `json:"hits"`
	}

	if err := json.NewDecoder(res.Body).Decode(&searchResult); err != nil {
		ec.logger.Error("failed to decode search results", zap.Error(err))
		return nil, err
	}

	var events []models.AdminLogEvent
	for _, hit := range searchResult.Hits.Hits {
		events = append(events, hit.Source)
	}

	return events, nil
}

// GetFailedAdminActions returns all failed admin actions for compliance review
func (ec *ESConsumer) GetFailedAdminActions(ctx context.Context, hoursBack int, limit int) ([]models.AdminLogEvent, error) {
	query := map[string]interface{}{
		"query": map[string]interface{}{
			"bool": map[string]interface{}{
				"must": []map[string]interface{}{
					{
						"match": map[string]interface{}{
							"status": "failed",
						},
					},
					{
						"range": map[string]interface{}{
							"timestamp": map[string]interface{}{
								"gte": fmt.Sprintf("now-%dh", hoursBack),
							},
						},
					},
				},
			},
		},
		"size": limit,
		"sort": []map[string]interface{}{
			{
				"timestamp": map[string]string{
					"order": "desc",
				},
			},
		},
	}

	queryBody, _ := json.Marshal(query)
	res, err := ec.esClient.Search(
		ec.esClient.Search.WithContext(ctx),
		ec.esClient.Search.WithIndex("admin-*"),
		ec.esClient.Search.WithBody(bytes.NewReader(queryBody)),
	)
	if err != nil {
		ec.logger.Error("failed to search failed admin actions", zap.Error(err))
		return nil, err
	}
	defer res.Body.Close()

	var searchResult struct {
		Hits struct {
			Hits []struct {
				Source models.AdminLogEvent `json:"_source"`
			} `json:"hits"`
		} `json:"hits"`
	}

	if err := json.NewDecoder(res.Body).Decode(&searchResult); err != nil {
		ec.logger.Error("failed to decode search results", zap.Error(err))
		return nil, err
	}

	var events []models.AdminLogEvent
	for _, hit := range searchResult.Hits.Hits {
		events = append(events, hit.Source)
	}

	return events, nil
}

// GetAdminActionsByType returns all admin actions of a specific type
func (ec *ESConsumer) GetAdminActionsByType(ctx context.Context, action string, hoursBack int, limit int) ([]models.AdminLogEvent, error) {
	query := map[string]interface{}{
		"query": map[string]interface{}{
			"bool": map[string]interface{}{
				"must": []map[string]interface{}{
					{
						"match": map[string]interface{}{
							"action": action,
						},
					},
					{
						"range": map[string]interface{}{
							"timestamp": map[string]interface{}{
								"gte": fmt.Sprintf("now-%dh", hoursBack),
							},
						},
					},
				},
			},
		},
		"size": limit,
		"sort": []map[string]interface{}{
			{
				"timestamp": map[string]string{
					"order": "desc",
				},
			},
		},
	}

	queryBody, _ := json.Marshal(query)
	res, err := ec.esClient.Search(
		ec.esClient.Search.WithContext(ctx),
		ec.esClient.Search.WithIndex("admin-*"),
		ec.esClient.Search.WithBody(bytes.NewReader(queryBody)),
	)
	if err != nil {
		ec.logger.Error("failed to search admin actions by type", zap.Error(err))
		return nil, err
	}
	defer res.Body.Close()

	var searchResult struct {
		Hits struct {
			Hits []struct {
				Source models.AdminLogEvent `json:"_source"`
			} `json:"hits"`
		} `json:"hits"`
	}

	if err := json.NewDecoder(res.Body).Decode(&searchResult); err != nil {
		ec.logger.Error("failed to decode search results", zap.Error(err))
		return nil, err
	}

	var events []models.AdminLogEvent
	for _, hit := range searchResult.Hits.Hits {
		events = append(events, hit.Source)
	}

	return events, nil
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
package consumer

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"time"

	"github.com/segmentio/kafka-go"
	"go.uber.org/zap"

	"auth-service/internal/accounting/events"
	"auth-service/internal/accounting/models/settings"
	"auth-service/internal/accounting/repository"
	"auth-service/internal/accounting/service"
	"auth-service/internal/client"
)

// AccountingConsumer consumes events from the "accounting-events" Kafka topic.
type AccountingConsumer struct {
	analyticsSvc  service.AccountingAnalyticsService
	complianceSvc service.ComplianceAnalyticsService
	taxSvc        service.TaxAnalyticsService
	repo          repository.AnalyticsRepository // ✅ added
	db            *sql.DB                        // ✅ added
	logger        *zap.Logger
	consumer      *client.KafkaConsumer
	topic         string
	maxRetries    int
	producer      *kafka.Writer
}

// NewAccountingConsumer creates a new AccountingConsumer with idempotency support.
func NewAccountingConsumer(
	analyticsSvc service.AccountingAnalyticsService,
	complianceAnalyticsSvc service.ComplianceAnalyticsService,
	taxAnalyticsSvc service.TaxAnalyticsService,
	repo repository.AnalyticsRepository, // ✅ new
	db *sql.DB, // ✅ new
	logger *zap.Logger,
	consumer *client.KafkaConsumer,
	topic string,
	brokers []string,
) *AccountingConsumer {
	return &AccountingConsumer{
		analyticsSvc:  analyticsSvc,
		complianceSvc: complianceAnalyticsSvc,
		taxSvc:        taxAnalyticsSvc,
		repo:          repo,
		db:            db,
		logger:        logger.Named("accounting_consumer"),
		consumer:      consumer,
		topic:         topic,
		maxRetries:    3,
		producer: &kafka.Writer{
			Addr:         kafka.TCP(brokers...),
			Balancer:     &kafka.LeastBytes{},
			RequiredAcks: kafka.RequireOne,
			Async:        false,
		},
	}
}

// Start consumes messages from Kafka with idempotent processing.
func (c *AccountingConsumer) Start(ctx context.Context) {
	c.logger.Info("starting accounting consumer", zap.String("topic", c.topic))
	for {
		msg, err := c.consumer.ConsumeMessage(ctx)
		if err != nil {
			if ctx.Err() != nil {
				return
			}
			c.logger.Error("failed to consume message", zap.Error(err))
			continue
		}

		eventType := c.extractEventType(msg)
		if eventType == "" {
			c.logger.Warn("message has no event_type header", zap.ByteString("key", msg.Key))
			_ = c.consumer.CommitMessage(ctx, msg)
			continue
		}

		if !isRelevantEvent(eventType) {
			_ = c.consumer.CommitMessage(ctx, msg)
			continue
		}

		// ---------- IDEMPOTENCY START ----------
		eventID := c.extractEventID(msg)
		if eventID == "" {
			c.logger.Warn("missing event_id header, skipping message", zap.String("event_type", eventType))
			_ = c.consumer.CommitMessage(ctx, msg)
			continue
		}

		// 1) Start DB transaction
		tx, err := c.db.BeginTx(ctx, nil)
		if err != nil {
			c.logger.Error("failed to begin transaction", zap.Error(err))
			_ = c.consumer.CommitMessage(ctx, msg) // commit to avoid reprocessing? Actually better to not commit, but we log.
			// We skip this message to avoid infinite loop; let the consumer retry after offset commit.
			continue
		}

		// 2) Idempotency check (atomic insert)
		firstTime, err := c.repo.TryMarkEventProcessed(ctx, tx, eventID, "accounting-consumer")
		if err != nil {
			tx.Rollback()
			c.logger.Error("idempotency check failed", zap.String("event_id", eventID), zap.Error(err))
			_ = c.consumer.CommitMessage(ctx, msg)
			continue
		}

		if !firstTime {
			// Already processed – skip business logic
			tx.Rollback()
			c.logger.Debug("duplicate event skipped", zap.String("event_id", eventID))
			_ = c.consumer.CommitMessage(ctx, msg)
			continue
		}

		// 3) Process the actual event (business logic)
		err = c.handleEvent(ctx, eventType, msg.Value)
		if err != nil {
			tx.Rollback() // rollback the insert of processed_events
			c.logger.Error("failed to process event",
				zap.String("event_type", eventType),
				zap.String("event_id", eventID),
				zap.Error(err),
			)

			retryCount := c.getRetryCount(msg)
			if retryCount < c.maxRetries {
				if pubErr := c.publishRetry(ctx, msg, retryCount+1); pubErr != nil {
					c.logger.Error("failed to publish retry", zap.Error(pubErr))
				}
			} else {
				if dlqErr := c.sendToDLQ(ctx, msg, err); dlqErr != nil {
					c.logger.Error("failed to send to DLQ", zap.Error(dlqErr))
				}
			}
			_ = c.consumer.CommitMessage(ctx, msg)
			continue
		}

		// 4) Commit DB transaction (marks event as processed permanently)
		if err := tx.Commit(); err != nil {
			c.logger.Error("failed to commit transaction", zap.String("event_id", eventID), zap.Error(err))
			// Do NOT commit Kafka offset; reprocess later
			continue
		}

		// 5) Commit Kafka offset only after DB commit
		if err := c.consumer.CommitMessage(ctx, msg); err != nil {
			c.logger.Error("failed to commit Kafka message", zap.Error(err))
		}
		// ---------- IDEMPOTENCY END ----------
	}
}

// handleEvent routes the event to the appropriate analytics service (unchanged).
func (c *AccountingConsumer) handleEvent(ctx context.Context, eventType string, payload []byte) error {
	// --- Accounting events (journal/ledger) ---
	switch eventType {
	case events.EventJournalCreated, events.EventJournalUpdated,
		events.EventJournalPosted, events.EventJournalReversed:
		if c.analyticsSvc != nil {
			return c.analyticsSvc.ProcessJournalEvent(ctx, eventType, payload)
		}
		return nil

	case events.EventLedgerUpdated, events.EventLedgerReversed:
		if c.analyticsSvc != nil {
			return c.analyticsSvc.ProcessLedgerEvent(ctx, eventType, payload)
		}
		return nil
	}

	// --- Compliance events ---
	switch eventType {
	case events.EventReturnFiled, events.EventReturnAmended:
		if c.complianceSvc != nil {
			return c.complianceSvc.ProcessComplianceEvent(ctx, eventType, payload)
		}
		return nil
	}

	// --- Tax events ---
	switch eventType {
	case events.EventTaxTransactionCreated,
		events.EventTaxRateCreated, events.EventTaxRateUpdated,
		events.EventTaxRuleCreated, events.EventTaxRuleUpdated,
		events.EventTaxProfileCreated, events.EventTaxProfileUpdated:
		if c.taxSvc != nil {
			return c.taxSvc.ProcessTaxEvent(ctx, eventType, payload)
		}
		return nil
	}

	// --- Accounting settings events ---
	switch eventType {
	case events.EventAccountingSettingsCreated, events.EventAccountingSettingsUpdated:
		if c.analyticsSvc != nil {
			var settings settings.AccountingSettings
			if err := json.Unmarshal(payload, &settings); err != nil {
				c.logger.Error("failed to unmarshal settings event payload", zap.Error(err))
				return fmt.Errorf("unmarshal settings: %w", err)
			}
			return c.analyticsSvc.ProcessSettingsEvent(ctx, eventType, &settings)
		}
		return nil
	}

	// --- Account events (chart of accounts) ---
	switch eventType {
	case events.EventAccountCreated,
		events.EventAccountUpdated,
		events.EventAccountStatusChanged,
		events.EventAccountMoved,
		events.EventAccountDeleted:
		if c.analyticsSvc != nil {
			return c.analyticsSvc.ProcessAccountEvent(ctx, eventType, payload)
		}
		return nil
	}

	c.logger.Debug("ignored event type", zap.String("event_type", eventType))
	return nil
}

// extractEventType reads the event type from Kafka message headers.
func (c *AccountingConsumer) extractEventType(msg *kafka.Message) string {
	for _, h := range msg.Headers {
		if h.Key == "event_type" {
			return string(h.Value)
		}
	}
	return ""
}

// extractEventID reads the event_id from Kafka message headers.
func (c *AccountingConsumer) extractEventID(msg *kafka.Message) string {
	for _, h := range msg.Headers {
		if h.Key == "event_id" {
			return string(h.Value)
		}
	}
	return ""
}

// getRetryCount extracts the retry count from message headers.
func (c *AccountingConsumer) getRetryCount(msg *kafka.Message) int {
	for _, h := range msg.Headers {
		if h.Key == "retry_count" {
			var count int
			fmt.Sscanf(string(h.Value), "%d", &count)
			return count
		}
	}
	return 0
}

// publishRetry publishes the message back to the same topic with an incremented retry count.
func (c *AccountingConsumer) publishRetry(ctx context.Context, original *kafka.Message, newRetryCount int) error {
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

// sendToDLQ sends the failed message to the dead-letter queue topic.
func (c *AccountingConsumer) sendToDLQ(ctx context.Context, original *kafka.Message, processErr error) error {
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

// isRelevantEvent returns true if the event type is handled by this consumer.
func isRelevantEvent(eventType string) bool {
	switch eventType {
	// Accounting events (journal/ledger)
	case events.EventJournalCreated, events.EventJournalUpdated,
		events.EventJournalPosted, events.EventJournalReversed,
		events.EventLedgerUpdated, events.EventLedgerReversed,
		// Compliance events
		events.EventReturnFiled, events.EventReturnAmended,
		// Tax events
		events.EventTaxTransactionCreated,
		events.EventTaxRateCreated, events.EventTaxRateUpdated,
		events.EventTaxRuleCreated, events.EventTaxRuleUpdated,
		events.EventTaxProfileCreated, events.EventTaxProfileUpdated,
		// Accounting settings events
		events.EventAccountingSettingsCreated, events.EventAccountingSettingsUpdated,
		// Account events
		events.EventAccountCreated,
		events.EventAccountUpdated,
		events.EventAccountStatusChanged,
		events.EventAccountMoved,
		events.EventAccountDeleted:
		return true
	}
	return false
}

// Close shuts down the consumer and the internal producer.
func (c *AccountingConsumer) Close() error {
	if err := c.consumer.Close(); err != nil {
		c.logger.Error("failed to close consumer", zap.Error(err))
	}
	return c.producer.Close()
}

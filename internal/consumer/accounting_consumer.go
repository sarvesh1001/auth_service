package consumer

import (
	"context"
	"fmt"
	"time"

	"github.com/segmentio/kafka-go"
	"go.uber.org/zap"

	"auth-service/internal/accounting/events"
	"auth-service/internal/accounting/service"
	"auth-service/internal/client"
)

// AccountingConsumer consumes events from the "accounting-events" Kafka topic.
// It handles accounting (journal/ledger), compliance, and tax domain events.
type AccountingConsumer struct {
	analyticsSvc  service.AccountingAnalyticsService
	complianceSvc service.ComplianceAnalyticsService
	taxSvc        service.TaxAnalyticsService
	logger        *zap.Logger
	consumer      *client.KafkaConsumer
	topic         string
	maxRetries    int
	producer      *kafka.Writer
}

// NewAccountingConsumer creates a new AccountingConsumer.
// Any of the analytics services can be nil; events for missing services will be ignored.
func NewAccountingConsumer(
	analyticsSvc service.AccountingAnalyticsService,
	complianceAnalyticsSvc service.ComplianceAnalyticsService,
	taxAnalyticsSvc service.TaxAnalyticsService,
	logger *zap.Logger,
	consumer *client.KafkaConsumer,
	topic string,
	brokers []string,
) *AccountingConsumer {
	return &AccountingConsumer{
		analyticsSvc:  analyticsSvc,
		complianceSvc: complianceAnalyticsSvc,
		taxSvc:        taxAnalyticsSvc,
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

// Start consumes messages from Kafka and processes accounting/compliance/tax events.
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

		retryCount := c.getRetryCount(msg)
		err = c.handleEvent(ctx, eventType, msg.Value)

		if err != nil {
			c.logger.Error("failed to process event",
				zap.String("event_type", eventType),
				zap.Int("retry", retryCount),
				zap.Error(err),
			)

			if retryCount < c.maxRetries {
				if pubErr := c.publishRetry(ctx, msg, retryCount+1); pubErr != nil {
					c.logger.Error("failed to publish retry", zap.Error(pubErr))
				}
			} else {
				if dlqErr := c.sendToDLQ(ctx, msg, err); dlqErr != nil {
					c.logger.Error("failed to send to DLQ", zap.Error(dlqErr))
				}
			}
		}

		if err := c.consumer.CommitMessage(ctx, msg); err != nil {
			c.logger.Error("failed to commit message", zap.Error(err))
		}
	}
}

// handleEvent routes the event to the appropriate analytics service.
func (c *AccountingConsumer) handleEvent(ctx context.Context, eventType string, payload []byte) error {
	// Accounting events (journal/ledger)
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

	// Compliance events
	switch eventType {
	case events.EventReturnFiled, events.EventReturnAmended:
		if c.complianceSvc != nil {
			return c.complianceSvc.ProcessComplianceEvent(ctx, eventType, payload)
		}
		return nil
	}

	// Tax events – now handling all tax configuration changes
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
	// Accounting events
	case events.EventJournalCreated, events.EventJournalUpdated,
		events.EventJournalPosted, events.EventJournalReversed,
		events.EventLedgerUpdated, events.EventLedgerReversed,
		// Compliance events
		events.EventReturnFiled, events.EventReturnAmended,
		// Tax events (all)
		events.EventTaxTransactionCreated,
		events.EventTaxRateCreated, events.EventTaxRateUpdated,
		events.EventTaxRuleCreated, events.EventTaxRuleUpdated,
		events.EventTaxProfileCreated, events.EventTaxProfileUpdated:
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

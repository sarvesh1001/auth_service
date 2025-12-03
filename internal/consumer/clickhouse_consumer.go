// File: internal/consumer/clickhouse_consumer.go - MULTI-TOPIC VERSION (FIXED)
// ClickHouse consumer for time-series analytics with support for multiple Kafka topics
// ✅ COMPAT: Uses internal ClickHouse client (client.ClickHouseClient) and driver.Conn
// ✅ FIXED: PrepareBatch calls use cc.chClient.Conn().PrepareBatch(...) via the client

package consumer

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"sync"
	"time"

	"github.com/segmentio/kafka-go"
	"go.uber.org/zap"

	"auth-service/internal/client"
	"auth-service/internal/models"
	"auth-service/internal/util"
)

// MessageBatch tracks events and their Kafka messages for atomic processing
type MessageBatch struct {
	events   interface{}      // []*EventType
	messages []*kafka.Message // Corresponding Kafka messages
}

// ClickHouseConsumer consumes multiple Kafka topics and inserts to ClickHouse for time-series analytics
type ClickHouseConsumer struct {
	kafkaConsumers map[string]*client.KafkaConsumer // topic -> consumer
	chClient       *client.ClickHouseClient
	logger         *zap.Logger
	batchSize      int
	batchTimeout   time.Duration
	maxBatchBytes  int // Memory limit for batches
	mu             sync.RWMutex
	activeTopics   map[string]bool // Track active topics
}

// NewClickHouseConsumer creates a new multi-topic ClickHouse consumer optimized for time-series events
func NewClickHouseConsumer(
	kafkaConsumers map[string]*client.KafkaConsumer, // ✅ Accepts map of topic -> consumer
	chClient *client.ClickHouseClient,
	batchSize int,
	batchTimeout time.Duration,
) *ClickHouseConsumer {
	logger := util.Get()

	// Extract and sort topic list for consistent logging
	topicList := make([]string, 0, len(kafkaConsumers))
	for topic := range kafkaConsumers {
		topicList = append(topicList, topic)
	}

	// ✅ Log multi-topic consumer initialization with optimization details
	logger.Info("ClickHouse multi-topic consumer initialized (OPTIMIZED FOR TIME-SERIES)",
		zap.Strings("topics", topicList),
		zap.Int("topic_count", len(kafkaConsumers)),
		zap.Int("batch_size", batchSize),
		zap.Duration("batch_timeout", batchTimeout),
		zap.String("mode", "manual-commit"),
		zap.String("events_handled", "Device, MPIN, OTP, Security, SecurityRisk"),
	)

	return &ClickHouseConsumer{
		kafkaConsumers: kafkaConsumers,
		chClient:       chClient,
		logger:         logger,
		batchSize:      batchSize,
		batchTimeout:   batchTimeout,
		maxBatchBytes:  10 * 1024 * 1024, // 10MB default
		activeTopics:   make(map[string]bool),
	}
}

// SetMaxBatchBytes allows configuration of max batch memory
func (cc *ClickHouseConsumer) SetMaxBatchBytes(bytes int) {
	cc.maxBatchBytes = bytes
}

// Start begins consuming from multiple Kafka topics with independent batching
func (cc *ClickHouseConsumer) Start(ctx context.Context) error {
	cc.logger.Info("ClickHouse multi-topic consumer started (Time-Series Optimized)",
		zap.Int("topic_count", len(cc.kafkaConsumers)),
		zap.Int("batch_size", cc.batchSize),
		zap.String("events", "Device, MPIN, OTP, Security, SecurityRisk"),
	)

	// ✅ Start independent consumer goroutine for each topic
	var wg sync.WaitGroup
	for topic, kafkaConsumer := range cc.kafkaConsumers {
		wg.Add(1)
		go func(topicName string, consumer *client.KafkaConsumer) {
			defer wg.Done()
			cc.consumeTopic(ctx, topicName, consumer)
		}(topic, kafkaConsumer)
	}

	// ✅ Wait for context cancellation
	<-ctx.Done()
	cc.logger.Info("ClickHouse multi-topic consumer shutdown initiated")

	// ✅ Wait for all consumer goroutines to finish gracefully
	wg.Wait()
	cc.logger.Info("ClickHouse multi-topic consumer stopped gracefully")
	return ctx.Err()
}

func (cc *ClickHouseConsumer) consumeTopic(ctx context.Context, topic string, kafkaConsumer *client.KafkaConsumer) {
	cc.logger.Info("topic consumer started",
		zap.String("topic", topic),
		zap.Int("batch_size", cc.batchSize),
	)

	cc.mu.Lock()
	cc.activeTopics[topic] = true
	cc.mu.Unlock()

	defer func() {
		cc.mu.Lock()
		delete(cc.activeTopics, topic)
		cc.mu.Unlock()
		cc.logger.Info("topic consumer stopped", zap.String("topic", topic))
	}()

	otpBatch := MessageBatch{events: make([]*models.OTPLogEvent, 0, cc.batchSize)}
	mpinBatch := MessageBatch{events: make([]*models.MPINLogEvent, 0, cc.batchSize)}
	securityBatch := MessageBatch{events: make([]*models.SecurityLogEvent, 0, cc.batchSize)}
	deviceBatch := MessageBatch{events: make([]*models.DeviceLogEvent, 0, cc.batchSize)}
	securityRiskBatch := MessageBatch{events: make([]*models.SecurityEvent, 0, cc.batchSize)}

	otpBatchBytes := 0
	mpinBatchBytes := 0
	securityBatchBytes := 0
	deviceBatchBytes := 0
	securityRiskBatchBytes := 0

	ticker := time.NewTicker(cc.batchTimeout)
	defer ticker.Stop()

	for {
		// -----------------------------------------
		// ❗ BLOCKING select — no default case
		// -----------------------------------------
		select {
		case <-ctx.Done():
			shutdownCtx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
			defer cancel()

			cc.flushAndCommitAll(shutdownCtx, topic,
				&otpBatch, &mpinBatch, &securityBatch, &deviceBatch, &securityRiskBatch)

			cc.logger.Info("topic consumer stopped", zap.String("topic", topic))
			return

		case <-ticker.C:
			cc.flushAndCommitAll(ctx, topic,
				&otpBatch, &mpinBatch, &securityBatch, &deviceBatch, &securityRiskBatch)

			otpBatch = MessageBatch{events: make([]*models.OTPLogEvent, 0, cc.batchSize)}
			mpinBatch = MessageBatch{events: make([]*models.MPINLogEvent, 0, cc.batchSize)}
			securityBatch = MessageBatch{events: make([]*models.SecurityLogEvent, 0, cc.batchSize)}
			deviceBatch = MessageBatch{events: make([]*models.DeviceLogEvent, 0, cc.batchSize)}
			securityRiskBatch = MessageBatch{events: make([]*models.SecurityEvent, 0, cc.batchSize)}

			otpBatchBytes = 0
			mpinBatchBytes = 0
			securityBatchBytes = 0
			deviceBatchBytes = 0
			securityRiskBatchBytes = 0
		}

		// -------------------------------------------------------
		// ❗ BLOCKING KAFKA READ — placed OUTSIDE the select
		// -------------------------------------------------------
		msg, err := kafkaConsumer.ConsumeMessage(ctx)
		if err != nil {
			if err == context.Canceled {
				return
			}

			cc.logger.Error("failed to consume message",
				zap.String("topic", topic),
				zap.Error(err),
			)

			time.Sleep(time.Second)
			continue
		}

		// -------------------------
		// EVENT TYPE EXTRACTION
		// -------------------------
		eventType := ""
		for _, h := range msg.Headers {
			if h.Key == "event_type" {
				eventType = string(h.Value)
				break
			}
		}

		// -------------------------
		// PROCESS MESSAGE BY TYPE
		// -------------------------
		switch eventType {

		case "otp":
			var e models.OTPLogEvent
			if err := json.Unmarshal(msg.Value, &e); err != nil {
				cc.logger.Error("unmarshal OTP failed",
					zap.String("topic", topic),
					zap.Error(err),
				)
				continue
			}

			e.ErrorMessage = cc.sanitizeString(e.ErrorMessage, 500)
			e.Purpose = cc.sanitizeString(e.Purpose, 100)

			events := otpBatch.events.([]*models.OTPLogEvent)
			otpBatch.events = append(events, &e)
			otpBatch.messages = append(otpBatch.messages, msg)
			otpBatchBytes += len(msg.Value)

			if len(events) >= cc.batchSize || otpBatchBytes >= cc.maxBatchBytes {
				cc.flushAndCommitOTPBatch(ctx, topic, &otpBatch)
				otpBatch = MessageBatch{events: make([]*models.OTPLogEvent, 0, cc.batchSize)}
				otpBatchBytes = 0
			}

		case "mpin":
			var e models.MPINLogEvent
			if err := json.Unmarshal(msg.Value, &e); err != nil {
				cc.logger.Error("unmarshal MPIN failed",
					zap.String("topic", topic),
					zap.Error(err),
				)
				continue
			}

			e.ErrorMessage = cc.sanitizeString(e.ErrorMessage, 500)
			e.FailureReason = cc.sanitizeString(e.FailureReason, 200)

			events := mpinBatch.events.([]*models.MPINLogEvent)
			mpinBatch.events = append(events, &e)
			mpinBatch.messages = append(mpinBatch.messages, msg)
			mpinBatchBytes += len(msg.Value)

			if len(events) >= cc.batchSize || mpinBatchBytes >= cc.maxBatchBytes {
				cc.flushAndCommitMPINBatch(ctx, topic, &mpinBatch)
				mpinBatch = MessageBatch{events: make([]*models.MPINLogEvent, 0, cc.batchSize)}
				mpinBatchBytes = 0
			}

		case "security":
			var e models.SecurityLogEvent
			if err := json.Unmarshal(msg.Value, &e); err != nil {
				cc.logger.Error("unmarshal Security failed",
					zap.String("topic", topic),
					zap.Error(err),
				)
				continue
			}

			e.Reason = cc.sanitizeString(e.Reason, 500)

			events := securityBatch.events.([]*models.SecurityLogEvent)
			securityBatch.events = append(events, &e)
			securityBatch.messages = append(securityBatch.messages, msg)
			securityBatchBytes += len(msg.Value)

			if len(events) >= cc.batchSize || securityBatchBytes >= cc.maxBatchBytes {
				cc.flushAndCommitSecurityBatch(ctx, topic, &securityBatch)
				securityBatch = MessageBatch{events: make([]*models.SecurityLogEvent, 0, cc.batchSize)}
				securityBatchBytes = 0
			}

		case "device":
			var e models.DeviceLogEvent
			if err := json.Unmarshal(msg.Value, &e); err != nil {
				cc.logger.Error("unmarshal Device failed",
					zap.String("topic", topic),
					zap.Error(err),
				)
				continue
			}

			e.ErrorMessage = cc.sanitizeString(e.ErrorMessage, 500)

			events := deviceBatch.events.([]*models.DeviceLogEvent)
			deviceBatch.events = append(events, &e)
			deviceBatch.messages = append(deviceBatch.messages, msg)
			deviceBatchBytes += len(msg.Value)

			if len(events) >= cc.batchSize || deviceBatchBytes >= cc.maxBatchBytes {
				cc.flushAndCommitDeviceBatch(ctx, topic, &deviceBatch)
				deviceBatch = MessageBatch{events: make([]*models.DeviceLogEvent, 0, cc.batchSize)}
				deviceBatchBytes = 0
			}

		case "security_risk":
			var e models.SecurityEvent
			if err := json.Unmarshal(msg.Value, &e); err != nil {
				cc.logger.Error("unmarshal Security Risk failed",
					zap.String("topic", topic),
					zap.Error(err),
				)
				continue
			}

			e.UserAgent = cc.sanitizeString(e.UserAgent, 500)

			events := securityRiskBatch.events.([]*models.SecurityEvent)
			securityRiskBatch.events = append(events, &e)
			securityRiskBatch.messages = append(securityRiskBatch.messages, msg)
			securityRiskBatchBytes += len(msg.Value)

			if len(events) >= cc.batchSize || securityRiskBatchBytes >= cc.maxBatchBytes {
				cc.flushAndCommitSecurityRiskBatch(ctx, topic, &securityRiskBatch)
				securityRiskBatch = MessageBatch{events: make([]*models.SecurityEvent, 0, cc.batchSize)}
				securityRiskBatchBytes = 0
			}

		default:
			if cc.isTimeSeriesEvent(eventType) {
				cc.logger.Warn("unknown time-series event type",
					zap.String("topic", topic),
					zap.String("event_type", eventType),
				)
			}
		}
	}
}

// ======== Batch Flush & Commit Helpers ========

// ✅ FIXED: Flush and commit all time-series event batches atomically with topic context
func (cc *ClickHouseConsumer) flushAndCommitAll(
	ctx context.Context,
	topic string,
	otp *MessageBatch,
	mpin *MessageBatch,
	security *MessageBatch,
	device *MessageBatch,
	securityRisk *MessageBatch, // ✅ NEW: Security risk batch
) {
	if err := cc.flushAndCommitOTPBatch(ctx, topic, otp); err != nil {
		cc.logger.Error("OTP batch flush failed", zap.String("topic", topic), zap.Error(err))
	}
	if err := cc.flushAndCommitMPINBatch(ctx, topic, mpin); err != nil {
		cc.logger.Error("MPIN batch flush failed", zap.String("topic", topic), zap.Error(err))
	}
	if err := cc.flushAndCommitSecurityBatch(ctx, topic, security); err != nil {
		cc.logger.Error("Security batch flush failed", zap.String("topic", topic), zap.Error(err))
	}
	if err := cc.flushAndCommitDeviceBatch(ctx, topic, device); err != nil {
		cc.logger.Error("Device batch flush failed", zap.String("topic", topic), zap.Error(err))
	}
	// ✅ NEW: Security risk batch
	if err := cc.flushAndCommitSecurityRiskBatch(ctx, topic, securityRisk); err != nil {
		cc.logger.Error("Security Risk batch flush failed", zap.String("topic", topic), zap.Error(err))
	}
}

// ✅ NEW: Security Risk Events - Flush to ClickHouse, THEN commit to Kafka
func (cc *ClickHouseConsumer) flushAndCommitSecurityRiskBatch(ctx context.Context, topic string, batch *MessageBatch) error {
	if batch == nil || len(batch.messages) == 0 {
		return nil
	}

	// ✅ FIXED: Use pointer type assertion
	events := batch.events.([]*models.SecurityEvent)
	if len(events) == 0 {
		return nil
	}

	// Step 1: Flush to ClickHouse
	if err := cc.flushSecurityRiskBatch(ctx, events); err != nil {
		cc.logger.Error("Security Risk flush to ClickHouse failed",
			zap.String("topic", topic),
			zap.Error(err),
			zap.Int("batch_size", len(events)),
		)
		return err // Don't commit on failure
	}

	// Step 2: ONLY commit after successful ClickHouse write
	for i, msg := range batch.messages {
		if err := cc.kafkaConsumers[topic].CommitMessage(ctx, msg); err != nil {
			cc.logger.Error("failed to commit Security Risk message",
				zap.String("topic", topic),
				zap.Error(err),
				zap.Int("index", i),
				zap.Int64("offset", msg.Offset),
			)
			// Continue committing other messages
		}
	}

	cc.logger.Info("Security Risk batch flushed and committed",
		zap.String("topic", topic),
		zap.Int("count", len(events)),
	)
	return nil
}

// ✅ FIXED: OTP Logs - Flush to ClickHouse, THEN commit to Kafka
func (cc *ClickHouseConsumer) flushAndCommitOTPBatch(ctx context.Context, topic string, batch *MessageBatch) error {
	if batch == nil || len(batch.messages) == 0 {
		return nil
	}

	// ✅ FIXED: Use pointer type assertion
	events := batch.events.([]*models.OTPLogEvent)
	if len(events) == 0 {
		return nil
	}

	// Step 1: Flush to ClickHouse
	if err := cc.flushOTPBatch(ctx, events); err != nil {
		cc.logger.Error("OTP flush to ClickHouse failed",
			zap.String("topic", topic),
			zap.Error(err),
			zap.Int("batch_size", len(events)),
		)
		return err // Don't commit on failure
	}

	// Step 2: ONLY commit after successful ClickHouse write
	for i, msg := range batch.messages {
		if err := cc.kafkaConsumers[topic].CommitMessage(ctx, msg); err != nil {
			cc.logger.Error("failed to commit OTP message",
				zap.String("topic", topic),
				zap.Error(err),
				zap.Int("index", i),
				zap.Int64("offset", msg.Offset),
			)
			// Continue committing other messages
		}
	}

	cc.logger.Info("OTP batch flushed and committed",
		zap.String("topic", topic),
		zap.Int("count", len(events)),
	)
	return nil
}

// ✅ FIXED: MPIN Logs - Flush to ClickHouse, THEN commit to Kafka
func (cc *ClickHouseConsumer) flushAndCommitMPINBatch(ctx context.Context, topic string, batch *MessageBatch) error {
	if batch == nil || len(batch.messages) == 0 {
		return nil
	}

	// ✅ FIXED: Use pointer type assertion
	events := batch.events.([]*models.MPINLogEvent)
	if len(events) == 0 {
		return nil
	}

	// Step 1: Flush to ClickHouse
	if err := cc.flushMPINBatch(ctx, events); err != nil {
		cc.logger.Error("MPIN flush to ClickHouse failed",
			zap.String("topic", topic),
			zap.Error(err),
			zap.Int("batch_size", len(events)),
		)
		return err
	}

	// Step 2: ONLY commit after successful ClickHouse write
	for i, msg := range batch.messages {
		if err := cc.kafkaConsumers[topic].CommitMessage(ctx, msg); err != nil {
			cc.logger.Error("failed to commit MPIN message",
				zap.String("topic", topic),
				zap.Error(err),
				zap.Int("index", i),
				zap.Int64("offset", msg.Offset),
			)
		}
	}

	cc.logger.Info("MPIN batch flushed and committed",
		zap.String("topic", topic),
		zap.Int("count", len(events)),
	)
	return nil
}

// ✅ FIXED: Security Logs - Flush to ClickHouse, THEN commit to Kafka
func (cc *ClickHouseConsumer) flushAndCommitSecurityBatch(ctx context.Context, topic string, batch *MessageBatch) error {
	if batch == nil || len(batch.messages) == 0 {
		return nil
	}

	// ✅ FIXED: Use pointer type assertion
	events := batch.events.([]*models.SecurityLogEvent)
	if len(events) == 0 {
		return nil
	}

	// Step 1: Flush to ClickHouse
	if err := cc.flushSecurityBatch(ctx, events); err != nil {
		cc.logger.Error("Security flush to ClickHouse failed",
			zap.String("topic", topic),
			zap.Error(err),
			zap.Int("batch_size", len(events)),
		)
		return err
	}

	// Step 2: ONLY commit after successful ClickHouse write
	for i, msg := range batch.messages {
		if err := cc.kafkaConsumers[topic].CommitMessage(ctx, msg); err != nil {
			cc.logger.Error("failed to commit Security message",
				zap.String("topic", topic),
				zap.Error(err),
				zap.Int("index", i),
				zap.Int64("offset", msg.Offset),
			)
		}
	}

	cc.logger.Info("Security batch flushed and committed",
		zap.String("topic", topic),
		zap.Int("count", len(events)),
	)
	return nil
}

// ✅ FIXED: Device Logs - Flush to ClickHouse, THEN commit to Kafka
func (cc *ClickHouseConsumer) flushAndCommitDeviceBatch(ctx context.Context, topic string, batch *MessageBatch) error {
	if batch == nil || len(batch.messages) == 0 {
		return nil
	}

	// ✅ FIXED: Use pointer type assertion
	events := batch.events.([]*models.DeviceLogEvent)
	if len(events) == 0 {
		return nil
	}

	// Step 1: Flush to ClickHouse
	if err := cc.flushDeviceBatch(ctx, events); err != nil {
		cc.logger.Error("Device flush to ClickHouse failed",
			zap.String("topic", topic),
			zap.Error(err),
			zap.Int("batch_size", len(events)),
		)
		return err // Don't commit on failure - Kafka will redeliver
	}

	// Step 2: ONLY commit after successful ClickHouse write
	for i, msg := range batch.messages {
		if err := cc.kafkaConsumers[topic].CommitMessage(ctx, msg); err != nil {
			cc.logger.Error("failed to commit Device message",
				zap.String("topic", topic),
				zap.Error(err),
				zap.Int("index", i),
				zap.Int64("offset", msg.Offset),
			)
			// Continue committing other messages
		}
	}

	cc.logger.Info("Device batch flushed and committed",
		zap.String("topic", topic),
		zap.Int("count", len(events)),
	)
	return nil
}

// ======== ClickHouse Batch Insert Helpers ========

// ✅ FIXED: Accept pointer slices
func (cc *ClickHouseConsumer) flushOTPBatch(ctx context.Context, batch []*models.OTPLogEvent) error {
	if len(batch) == 0 {
		return nil
	}

	query := `INSERT INTO auth_analytics.otp_events (
		event_id, event_type, timestamp, user_id, phone_number, status,
		attempt_number, attempts_left, error_code, error_message, ip_address,
		device_id, purpose, otp_provider, duration_ms, environment, version, message, service_name
	) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`

	batch_, err := cc.chClient.Conn().PrepareBatch(ctx, query)
	if err != nil {
		return fmt.Errorf("failed to prepare OTP batch: %w", err)
	}

	for _, e := range batch {
		if err := batch_.Append(
			e.EventID, e.EventType, e.Timestamp,
			e.UserID, e.PhoneNumber, e.Status,
			e.AttemptNumber, e.AttemptsLeft,
			e.ErrorCode, e.ErrorMessage, e.IPAddress,
			e.DeviceID, e.Purpose, e.OTPProvider, e.Duration,
			e.Environment, e.Version, e.Message, e.ServiceName,
		); err != nil {
			return fmt.Errorf("failed to append OTP row: %w", err)
		}
	}

	if err := batch_.Send(); err != nil {
		return fmt.Errorf("failed to send OTP batch: %w", err)
	}

	cc.logger.Debug("OTP batch flushed to ClickHouse", zap.Int("count", len(batch)))
	return nil
}

// ✅ FIXED: Accept pointer slices
func (cc *ClickHouseConsumer) flushMPINBatch(ctx context.Context, batch []*models.MPINLogEvent) error {
	if len(batch) == 0 {
		return nil
	}

	query := `INSERT INTO auth_analytics.mpin_events (
		event_id, event_type, timestamp, user_id, status, attempts, attempts_left,
		is_locked, error_code, error_message, device_id, device_trust, duration_ms, failure_reason,
		environment, version, message, service_name
	) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`

	batch_, err := cc.chClient.Conn().PrepareBatch(ctx, query)
	if err != nil {
		return fmt.Errorf("failed to prepare MPIN batch: %w", err)
	}

	for _, e := range batch {
		locked := uint8(0)
		if e.IsLocked {
			locked = 1
		}

		if err := batch_.Append(
			e.EventID, e.EventType, e.Timestamp,
			e.UserID, e.Status, e.Attempts, e.AttemptsLeft, locked,
			e.ErrorCode, e.ErrorMessage, e.DeviceID, e.DeviceTrust, e.Duration, e.FailureReason,
			e.Environment, e.Version, e.Message, e.ServiceName,
		); err != nil {
			return fmt.Errorf("failed to append MPIN row: %w", err)
		}
	}

	if err := batch_.Send(); err != nil {
		return fmt.Errorf("failed to send MPIN batch: %w", err)
	}

	cc.logger.Debug("MPIN batch flushed to ClickHouse", zap.Int("count", len(batch)))
	return nil
}

// ✅ FIXED: Accept pointer slices
func (cc *ClickHouseConsumer) flushSecurityBatch(ctx context.Context, batch []*models.SecurityLogEvent) error {
	if len(batch) == 0 {
		return nil
	}

	query := `INSERT INTO auth_analytics.security_events (
		event_id, event_type, timestamp, user_id, event_category, severity,
		ip_address, device_id, action, risk_score, reason,
		environment, version, message, service_name
	) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`

	batch_, err := cc.chClient.Conn().PrepareBatch(ctx, query)
	if err != nil {
		return fmt.Errorf("failed to prepare Security batch: %w", err)
	}

	for _, e := range batch {
		if err := batch_.Append(
			e.EventID, e.EventType, e.Timestamp,
			e.UserID, e.EventCategory, e.Severity, e.IPAddress, e.DeviceID, e.Action,
			e.RiskScore, e.Reason,
			e.Environment, e.Version, e.Message, e.ServiceName,
		); err != nil {
			return fmt.Errorf("failed to append Security row: %w", err)
		}
	}

	if err := batch_.Send(); err != nil {
		return fmt.Errorf("failed to send Security batch: %w", err)
	}

	cc.logger.Debug("Security batch flushed to ClickHouse", zap.Int("count", len(batch)))
	return nil
}

// ✅ FIXED: Accept pointer slices
func (cc *ClickHouseConsumer) flushDeviceBatch(ctx context.Context, batch []*models.DeviceLogEvent) error {
	if len(batch) == 0 {
		return nil
	}

	query := `INSERT INTO auth_analytics.device_events (
		event_id, event_type, timestamp, user_id, device_id, action,
		status, bind_token, error_code, error_message, ip_address, session_id, duration_ms,
		environment, version, message, service_name
	) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`

	batch_, err := cc.chClient.Conn().PrepareBatch(ctx, query)
	if err != nil {
		return fmt.Errorf("failed to prepare Device batch: %w", err)
	}

	for _, e := range batch {
		if err := batch_.Append(
			e.EventID, e.EventType, e.Timestamp,
			e.UserID, e.DeviceID, e.Action, e.Status, e.BindToken,
			e.ErrorCode, e.ErrorMessage, e.IPAddress, e.SessionID, e.Duration,
			e.Environment, e.Version, e.Message, e.ServiceName,
		); err != nil {
			return fmt.Errorf("failed to append Device row: %w", err)
		}
	}

	if err := batch_.Send(); err != nil {
		return fmt.Errorf("failed to send Device batch: %w", err)
	}

	cc.logger.Debug("Device batch flushed to ClickHouse", zap.Int("count", len(batch)))
	return nil
}

// ✅ NEW: Security Risk Events - Bot Protection, IP Reputation, Risk Scoring
func (cc *ClickHouseConsumer) flushSecurityRiskBatch(ctx context.Context, batch []*models.SecurityEvent) error {
	if len(batch) == 0 {
		return nil
	}

	query := `INSERT INTO auth_analytics.security_risk_events (
		event_id, event_type, timestamp, phone_number, ip_address, device_id, user_agent,
		risk_score, event_type_detail, reasons, action_taken,
		environment, version, message, service_name
	) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`

	batch_, err := cc.chClient.Conn().PrepareBatch(ctx, query)
	if err != nil {
		return fmt.Errorf("failed to prepare Security Risk batch: %w", err)
	}

	for _, e := range batch {
		if err := batch_.Append(
			e.EventID, e.EventType, e.Timestamp,
			e.PhoneNumber, e.IPAddress, e.DeviceID, e.UserAgent,
			e.RiskScore, e.EventType, e.Reasons, e.ActionTaken,
			e.Environment, e.Version, e.Message, e.ServiceName,
		); err != nil {
			return fmt.Errorf("failed to append Security Risk row: %w", err)
		}
	}

	if err := batch_.Send(); err != nil {
		return fmt.Errorf("failed to send Security Risk batch: %w", err)
	}

	cc.logger.Debug("Security Risk batch flushed to ClickHouse", zap.Int("count", len(batch)))
	return nil
}

// ======== Utility Methods ========

// Health check - verify ClickHouse connection
func (cc *ClickHouseConsumer) Health(ctx context.Context) error {
	return cc.chClient.HealthCheck(ctx)
}

// GetActiveTopics returns list of currently active consumer topics
func (cc *ClickHouseConsumer) GetActiveTopics() []string {
	cc.mu.RLock()
	defer cc.mu.RUnlock()

	topics := make([]string, 0, len(cc.activeTopics))
	for topic := range cc.activeTopics {
		topics = append(topics, topic)
	}
	return topics
}

// ✅ Input sanitization to prevent SQL injection
func (cc *ClickHouseConsumer) sanitizeString(s string, maxLen int) string {
	// Trim to max length
	if len(s) > maxLen {
		s = s[:maxLen]
	}

	// Replace dangerous characters
	s = strings.ReplaceAll(s, "'", "''")
	s = strings.ReplaceAll(s, "\\", "\\\\")
	s = strings.ReplaceAll(s, "\x00", "")

	return s
}

// ✅ Check if event type is a time-series event
func (cc *ClickHouseConsumer) isTimeSeriesEvent(eventType string) bool {
	timeSeriesEvents := map[string]bool{
		"otp":           true,
		"mpin":          true,
		"security":      true,
		"device":        true,
		"security_risk": true, // ✅ NEW: Security risk events
	}
	return timeSeriesEvents[eventType]
}

func (cc *ClickHouseConsumer) Close() error {
	cc.logger.Info("closing ClickHouse consumer...")

	for topic, kc := range cc.kafkaConsumers {
		cc.logger.Info("closing kafka consumer for topic", zap.String("topic", topic))
		if err := kc.Close(); err != nil {
			cc.logger.Error("failed to close kafka consumer", zap.Error(err))
		}
	}

	cc.logger.Info("ClickHouse consumer closed")
	return nil
}

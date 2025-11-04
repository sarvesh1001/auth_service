// File: internal/consumer/clickhouse_consumer.go (FIXED)
// Consumes Kafka events and writes to ClickHouse for analytics
// ✅ CRITICAL FIX: Manual commit ONLY after successful ClickHouse write

package consumer

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"github.com/ClickHouse/clickhouse-go/v2"
	"github.com/segmentio/kafka-go"
	"go.uber.org/zap"

	"auth-service/internal/client"
	"auth-service/internal/models"
	"auth-service/internal/util"
)

// MessageBatch tracks events and their Kafka messages for atomic processing
type MessageBatch struct {
	events   interface{}     // []EventType
	messages []*kafka.Message // Corresponding Kafka messages
}

// ClickHouseConsumer consumes Kafka events and inserts to ClickHouse
type ClickHouseConsumer struct {
	kafkaConsumer *client.KafkaConsumer
	chClient      clickhouse.Conn
	logger        *zap.Logger
	batchSize     int
	batchTimeout  time.Duration
	maxBatchBytes int // NEW: Memory limit for batches
}

// NewClickHouseConsumer creates a new ClickHouse consumer
func NewClickHouseConsumer(
	kafkaConsumer *client.KafkaConsumer,
	chClient clickhouse.Conn,
	batchSize int,
	batchTimeout time.Duration,
) *ClickHouseConsumer {
	logger := util.Get()

	// ✅ Log consumer initialization with group ID
	logger.Info("ClickHouse consumer initialized",
		zap.String("batch_size", fmt.Sprintf("%d", batchSize)),
		zap.Duration("batch_timeout", batchTimeout),
		zap.String("mode", "manual-commit"),
	)

	return &ClickHouseConsumer{
		kafkaConsumer: kafkaConsumer,
		chClient:      chClient,
		logger:        logger,
		batchSize:     batchSize,
		batchTimeout:  batchTimeout,
		maxBatchBytes: 10 * 1024 * 1024, // 10MB default
	}
}

// SetMaxBatchBytes allows configuration of max batch memory
func (cc *ClickHouseConsumer) SetMaxBatchBytes(bytes int) {
	cc.maxBatchBytes = bytes
}

// Start begins consuming from Kafka and batching inserts to ClickHouse
func (cc *ClickHouseConsumer) Start(ctx context.Context) error {
	cc.logger.Info("ClickHouse consumer started", zap.Int("batch_size", cc.batchSize))

	// Initialize message batch tracking
	otpBatch := MessageBatch{events: make([]models.OTPLogEvent, 0, cc.batchSize)}
	mpinBatch := MessageBatch{events: make([]models.MPINLogEvent, 0, cc.batchSize)}
	securityBatch := MessageBatch{events: make([]models.SecurityLogEvent, 0, cc.batchSize)}
	adminBatch := MessageBatch{events: make([]models.AdminLogEvent, 0, cc.batchSize)}
	sessionBatch := MessageBatch{events: make([]models.SessionLogEvent, 0, cc.batchSize)}
	userBatch := MessageBatch{events: make([]models.UserLogEvent, 0, cc.batchSize)}
	deviceBatch := MessageBatch{events: make([]models.DeviceLogEvent, 0, cc.batchSize)}

	otpBatchBytes := 0
	mpinBatchBytes := 0
	securityBatchBytes := 0
	adminBatchBytes := 0
	sessionBatchBytes := 0
	userBatchBytes := 0
	deviceBatchBytes := 0

	ticker := time.NewTicker(cc.batchTimeout)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			// ✅ FIXED: Use background context with timeout for graceful shutdown
			shutdownCtx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
			defer cancel()

			cc.flushAndCommitAll(shutdownCtx, &otpBatch, &mpinBatch, &securityBatch, &adminBatch, &sessionBatch, &userBatch, &deviceBatch)
			cc.logger.Info("ClickHouse consumer stopped gracefully")
			return ctx.Err()

		case <-ticker.C:
			// Flush and commit all batches on timeout
			cc.flushAndCommitAll(ctx, &otpBatch, &mpinBatch, &securityBatch, &adminBatch, &sessionBatch, &userBatch, &deviceBatch)

			// Reset batches
			otpBatch = MessageBatch{events: make([]models.OTPLogEvent, 0, cc.batchSize)}
			mpinBatch = MessageBatch{events: make([]models.MPINLogEvent, 0, cc.batchSize)}
			securityBatch = MessageBatch{events: make([]models.SecurityLogEvent, 0, cc.batchSize)}
			adminBatch = MessageBatch{events: make([]models.AdminLogEvent, 0, cc.batchSize)}
			sessionBatch = MessageBatch{events: make([]models.SessionLogEvent, 0, cc.batchSize)}
			userBatch = MessageBatch{events: make([]models.UserLogEvent, 0, cc.batchSize)}
			deviceBatch = MessageBatch{events: make([]models.DeviceLogEvent, 0, cc.batchSize)}

			otpBatchBytes = 0
			mpinBatchBytes = 0
			securityBatchBytes = 0
			adminBatchBytes = 0
			sessionBatchBytes = 0
			userBatchBytes = 0
			deviceBatchBytes = 0

		default:
			msg, err := cc.kafkaConsumer.ConsumeMessage(ctx)
			if err != nil {
				cc.logger.Error("failed to consume message", zap.Error(err))
				time.Sleep(time.Second)
				continue
			}

			eventType := ""
			for _, h := range msg.Headers {
				if h.Key == "event_type" {
					eventType = string(h.Value)
					break
				}
			}

			switch eventType {
			case "otp":
				var e models.OTPLogEvent
				if err := json.Unmarshal(msg.Value, &e); err != nil {
					cc.logger.Error("unmarshal OTP failed", zap.Error(err))
					continue
				}

				// ✅ Sanitize input
				e.ErrorMessage = cc.sanitizeString(e.ErrorMessage, 500)
				e.Purpose = cc.sanitizeString(e.Purpose, 100)

				events := otpBatch.events.([]models.OTPLogEvent)
				otpBatch.events = append(events, e)
				otpBatch.messages = append(otpBatch.messages, msg)
				otpBatchBytes += len(msg.Value)

				if len(events) >= cc.batchSize || otpBatchBytes >= cc.maxBatchBytes {
					if err := cc.flushAndCommitOTPBatch(ctx, &otpBatch); err != nil {
						cc.logger.Error("failed OTP batch insert", zap.Error(err), zap.Int("batch_size", len(events)))
					}
					otpBatch = MessageBatch{events: make([]models.OTPLogEvent, 0, cc.batchSize)}
					otpBatchBytes = 0
				}

			case "mpin":
				var e models.MPINLogEvent
				if err := json.Unmarshal(msg.Value, &e); err != nil {
					cc.logger.Error("unmarshal MPIN failed", zap.Error(err))
					continue
				}

				// ✅ Sanitize input
				e.ErrorMessage = cc.sanitizeString(e.ErrorMessage, 500)
				e.FailureReason = cc.sanitizeString(e.FailureReason, 200)

				events := mpinBatch.events.([]models.MPINLogEvent)
				mpinBatch.events = append(events, e)
				mpinBatch.messages = append(mpinBatch.messages, msg)
				mpinBatchBytes += len(msg.Value)

				if len(events) >= cc.batchSize || mpinBatchBytes >= cc.maxBatchBytes {
					if err := cc.flushAndCommitMPINBatch(ctx, &mpinBatch); err != nil {
						cc.logger.Error("failed MPIN batch insert", zap.Error(err), zap.Int("batch_size", len(events)))
					}
					mpinBatch = MessageBatch{events: make([]models.MPINLogEvent, 0, cc.batchSize)}
					mpinBatchBytes = 0
				}

			case "security":
				var e models.SecurityLogEvent
				if err := json.Unmarshal(msg.Value, &e); err != nil {
					cc.logger.Error("unmarshal Security failed", zap.Error(err))
					continue
				}

				// ✅ Sanitize input
				e.Reason = cc.sanitizeString(e.Reason, 500)

				events := securityBatch.events.([]models.SecurityLogEvent)
				securityBatch.events = append(events, e)
				securityBatch.messages = append(securityBatch.messages, msg)
				securityBatchBytes += len(msg.Value)

				if len(events) >= cc.batchSize || securityBatchBytes >= cc.maxBatchBytes {
					if err := cc.flushAndCommitSecurityBatch(ctx, &securityBatch); err != nil {
						cc.logger.Error("failed Security batch insert", zap.Error(err), zap.Int("batch_size", len(events)))
					}
					securityBatch = MessageBatch{events: make([]models.SecurityLogEvent, 0, cc.batchSize)}
					securityBatchBytes = 0
				}

			case "admin":
				var e models.AdminLogEvent
				if err := json.Unmarshal(msg.Value, &e); err != nil {
					cc.logger.Error("unmarshal Admin failed", zap.Error(err))
					continue
				}

				events := adminBatch.events.([]models.AdminLogEvent)
				adminBatch.events = append(events, e)
				adminBatch.messages = append(adminBatch.messages, msg)
				adminBatchBytes += len(msg.Value)

				if len(events) >= cc.batchSize || adminBatchBytes >= cc.maxBatchBytes {
					if err := cc.flushAndCommitAdminBatch(ctx, &adminBatch); err != nil {
						cc.logger.Error("failed Admin batch insert", zap.Error(err), zap.Int("batch_size", len(events)))
					}
					adminBatch = MessageBatch{events: make([]models.AdminLogEvent, 0, cc.batchSize)}
					adminBatchBytes = 0
				}

			case "session":
				var e models.SessionLogEvent
				if err := json.Unmarshal(msg.Value, &e); err != nil {
					cc.logger.Error("unmarshal Session failed", zap.Error(err))
					continue
				}

				events := sessionBatch.events.([]models.SessionLogEvent)
				sessionBatch.events = append(events, e)
				sessionBatch.messages = append(sessionBatch.messages, msg)
				sessionBatchBytes += len(msg.Value)

				if len(events) >= cc.batchSize || sessionBatchBytes >= cc.maxBatchBytes {
					if err := cc.flushAndCommitSessionBatch(ctx, &sessionBatch); err != nil {
						cc.logger.Error("failed Session batch insert", zap.Error(err), zap.Int("batch_size", len(events)))
					}
					sessionBatch = MessageBatch{events: make([]models.SessionLogEvent, 0, cc.batchSize)}
					sessionBatchBytes = 0
				}

			case "user":
				var e models.UserLogEvent
				if err := json.Unmarshal(msg.Value, &e); err != nil {
					cc.logger.Error("unmarshal User failed", zap.Error(err))
					continue
				}

				events := userBatch.events.([]models.UserLogEvent)
				userBatch.events = append(events, e)
				userBatch.messages = append(userBatch.messages, msg)
				userBatchBytes += len(msg.Value)

				if len(events) >= cc.batchSize || userBatchBytes >= cc.maxBatchBytes {
					if err := cc.flushAndCommitUserBatch(ctx, &userBatch); err != nil {
						cc.logger.Error("failed User batch insert", zap.Error(err), zap.Int("batch_size", len(events)))
					}
					userBatch = MessageBatch{events: make([]models.UserLogEvent, 0, cc.batchSize)}
					userBatchBytes = 0
				}

			case "device":
				var e models.DeviceLogEvent
				if err := json.Unmarshal(msg.Value, &e); err != nil {
					cc.logger.Error("unmarshal Device failed", zap.Error(err))
					continue
				}

				// ✅ Sanitize input
				e.ErrorMessage = cc.sanitizeString(e.ErrorMessage, 500)

				events := deviceBatch.events.([]models.DeviceLogEvent)
				deviceBatch.events = append(events, e)
				deviceBatch.messages = append(deviceBatch.messages, msg)
				deviceBatchBytes += len(msg.Value)

				if len(events) >= cc.batchSize || deviceBatchBytes >= cc.maxBatchBytes {
					if err := cc.flushAndCommitDeviceBatch(ctx, &deviceBatch); err != nil {
						cc.logger.Error("failed Device batch insert", zap.Error(err), zap.Int("batch_size", len(events)))
					}
					deviceBatch = MessageBatch{events: make([]models.DeviceLogEvent, 0, cc.batchSize)}
					deviceBatchBytes = 0
				}

			default:
				cc.logger.Warn("unknown event type", zap.String("event_type", eventType))
			}
		}
	}
}

//
// ======== Batch Flush & Commit Helpers ========
//

// ✅ NEW: Flush and commit all event batches atomically
func (cc *ClickHouseConsumer) flushAndCommitAll(
	ctx context.Context,
	otp *MessageBatch,
	mpin *MessageBatch,
	security *MessageBatch,
	admin *MessageBatch,
	session *MessageBatch,
	user *MessageBatch,
	device *MessageBatch,
) {
	if err := cc.flushAndCommitOTPBatch(ctx, otp); err != nil {
		cc.logger.Error("OTP batch flush failed", zap.Error(err))
	}
	if err := cc.flushAndCommitMPINBatch(ctx, mpin); err != nil {
		cc.logger.Error("MPIN batch flush failed", zap.Error(err))
	}
	if err := cc.flushAndCommitSecurityBatch(ctx, security); err != nil {
		cc.logger.Error("Security batch flush failed", zap.Error(err))
	}
	if err := cc.flushAndCommitAdminBatch(ctx, admin); err != nil {
		cc.logger.Error("Admin batch flush failed", zap.Error(err))
	}
	if err := cc.flushAndCommitSessionBatch(ctx, session); err != nil {
		cc.logger.Error("Session batch flush failed", zap.Error(err))
	}
	if err := cc.flushAndCommitUserBatch(ctx, user); err != nil {
		cc.logger.Error("User batch flush failed", zap.Error(err))
	}
	if err := cc.flushAndCommitDeviceBatch(ctx, device); err != nil {
		cc.logger.Error("Device batch flush failed", zap.Error(err))
	}
}

// ✅ FIXED: OTP Logs - Flush to ClickHouse, THEN commit to Kafka
func (cc *ClickHouseConsumer) flushAndCommitOTPBatch(ctx context.Context, batch *MessageBatch) error {
	if batch == nil || len(batch.messages) == 0 {
		return nil
	}

	events := batch.events.([]models.OTPLogEvent)
	if len(events) == 0 {
		return nil
	}

	// Step 1: Flush to ClickHouse
	if err := cc.flushOTPBatch(ctx, events); err != nil {
		cc.logger.Error("OTP flush to ClickHouse failed", zap.Error(err), zap.Int("batch_size", len(events)))
		return err // Don't commit on failure
	}

	// Step 2: ONLY commit after successful ClickHouse write
	for i, msg := range batch.messages {
		if err := cc.kafkaConsumer.CommitMessage(ctx, msg); err != nil {
			cc.logger.Error("failed to commit OTP message",
				zap.Error(err),
				zap.Int("index", i),
				zap.Int64("offset", msg.Offset),
			)
			// Continue committing other messages
		}
	}

	cc.logger.Info("OTP batch flushed and committed", zap.Int("count", len(events)))
	return nil
}

// ✅ FIXED: MPIN Logs - Flush to ClickHouse, THEN commit to Kafka
func (cc *ClickHouseConsumer) flushAndCommitMPINBatch(ctx context.Context, batch *MessageBatch) error {
	if batch == nil || len(batch.messages) == 0 {
		return nil
	}

	events := batch.events.([]models.MPINLogEvent)
	if len(events) == 0 {
		return nil
	}

	// Step 1: Flush to ClickHouse
	if err := cc.flushMPINBatch(ctx, events); err != nil {
		cc.logger.Error("MPIN flush to ClickHouse failed", zap.Error(err), zap.Int("batch_size", len(events)))
		return err
	}

	// Step 2: ONLY commit after successful ClickHouse write
	for i, msg := range batch.messages {
		if err := cc.kafkaConsumer.CommitMessage(ctx, msg); err != nil {
			cc.logger.Error("failed to commit MPIN message",
				zap.Error(err),
				zap.Int("index", i),
				zap.Int64("offset", msg.Offset),
			)
		}
	}

	cc.logger.Info("MPIN batch flushed and committed", zap.Int("count", len(events)))
	return nil
}

// ✅ FIXED: Security Logs - Flush to ClickHouse, THEN commit to Kafka
func (cc *ClickHouseConsumer) flushAndCommitSecurityBatch(ctx context.Context, batch *MessageBatch) error {
	if batch == nil || len(batch.messages) == 0 {
		return nil
	}

	events := batch.events.([]models.SecurityLogEvent)
	if len(events) == 0 {
		return nil
	}

	// Step 1: Flush to ClickHouse
	if err := cc.flushSecurityBatch(ctx, events); err != nil {
		cc.logger.Error("Security flush to ClickHouse failed", zap.Error(err), zap.Int("batch_size", len(events)))
		return err
	}

	// Step 2: ONLY commit after successful ClickHouse write
	for i, msg := range batch.messages {
		if err := cc.kafkaConsumer.CommitMessage(ctx, msg); err != nil {
			cc.logger.Error("failed to commit Security message",
				zap.Error(err),
				zap.Int("index", i),
				zap.Int64("offset", msg.Offset),
			)
		}
	}

	cc.logger.Info("Security batch flushed and committed", zap.Int("count", len(events)))
	return nil
}

// ✅ FIXED: Admin Logs - Flush to ClickHouse, THEN commit to Kafka
func (cc *ClickHouseConsumer) flushAndCommitAdminBatch(ctx context.Context, batch *MessageBatch) error {
	if batch == nil || len(batch.messages) == 0 {
		return nil
	}

	events := batch.events.([]models.AdminLogEvent)
	if len(events) == 0 {
		return nil
	}

	// Step 1: Flush to ClickHouse
	if err := cc.flushAdminBatch(ctx, events); err != nil {
		cc.logger.Error("Admin flush to ClickHouse failed", zap.Error(err), zap.Int("batch_size", len(events)))
		return err
	}

	// Step 2: ONLY commit after successful ClickHouse write
	for i, msg := range batch.messages {
		if err := cc.kafkaConsumer.CommitMessage(ctx, msg); err != nil {
			cc.logger.Error("failed to commit Admin message",
				zap.Error(err),
				zap.Int("index", i),
				zap.Int64("offset", msg.Offset),
			)
		}
	}

	cc.logger.Info("Admin batch flushed and committed", zap.Int("count", len(events)))
	return nil
}

// ✅ FIXED: Session Logs - Flush to ClickHouse, THEN commit to Kafka
func (cc *ClickHouseConsumer) flushAndCommitSessionBatch(ctx context.Context, batch *MessageBatch) error {
	if batch == nil || len(batch.messages) == 0 {
		return nil
	}

	events := batch.events.([]models.SessionLogEvent)
	if len(events) == 0 {
		return nil
	}

	// Step 1: Flush to ClickHouse
	if err := cc.flushSessionBatch(ctx, events); err != nil {
		cc.logger.Error("Session flush to ClickHouse failed", zap.Error(err), zap.Int("batch_size", len(events)))
		return err
	}

	// Step 2: ONLY commit after successful ClickHouse write
	for i, msg := range batch.messages {
		if err := cc.kafkaConsumer.CommitMessage(ctx, msg); err != nil {
			cc.logger.Error("failed to commit Session message",
				zap.Error(err),
				zap.Int("index", i),
				zap.Int64("offset", msg.Offset),
			)
		}
	}

	cc.logger.Info("Session batch flushed and committed", zap.Int("count", len(events)))
	return nil
}

// ✅ FIXED: User Logs - Flush to ClickHouse, THEN commit to Kafka
func (cc *ClickHouseConsumer) flushAndCommitUserBatch(ctx context.Context, batch *MessageBatch) error {
	if batch == nil || len(batch.messages) == 0 {
		return nil
	}

	events := batch.events.([]models.UserLogEvent)
	if len(events) == 0 {
		return nil
	}

	// Step 1: Flush to ClickHouse
	if err := cc.flushUserBatch(ctx, events); err != nil {
		cc.logger.Error("User flush to ClickHouse failed", zap.Error(err), zap.Int("batch_size", len(events)))
		return err
	}

	// Step 2: ONLY commit after successful ClickHouse write
	for i, msg := range batch.messages {
		if err := cc.kafkaConsumer.CommitMessage(ctx, msg); err != nil {
			cc.logger.Error("failed to commit User message",
				zap.Error(err),
				zap.Int("index", i),
				zap.Int64("offset", msg.Offset),
			)
		}
	}

	cc.logger.Info("User batch flushed and committed", zap.Int("count", len(events)))
	return nil
}

// ✅ FIXED: Device Logs - Flush to ClickHouse, THEN commit to Kafka
func (cc *ClickHouseConsumer) flushAndCommitDeviceBatch(ctx context.Context, batch *MessageBatch) error {
	if batch == nil || len(batch.messages) == 0 {
		return nil
	}

	events := batch.events.([]models.DeviceLogEvent)
	if len(events) == 0 {
		return nil
	}

	// Step 1: Flush to ClickHouse
	if err := cc.flushDeviceBatch(ctx, events); err != nil {
		cc.logger.Error("Device flush to ClickHouse failed", zap.Error(err), zap.Int("batch_size", len(events)))
		return err // Don't commit on failure - Kafka will redeliver
	}

	// Step 2: ONLY commit after successful ClickHouse write
	for i, msg := range batch.messages {
		if err := cc.kafkaConsumer.CommitMessage(ctx, msg); err != nil {
			cc.logger.Error("failed to commit Device message",
				zap.Error(err),
				zap.Int("index", i),
				zap.Int64("offset", msg.Offset),
			)
			// Continue committing other messages
		}
	}

	cc.logger.Info("Device batch flushed and committed", zap.Int("count", len(events)))
	return nil
}

//
// ======== ClickHouse Batch Insert Helpers ========
//

// flushOTPBatch writes OTP events to ClickHouse
func (cc *ClickHouseConsumer) flushOTPBatch(ctx context.Context, batch []models.OTPLogEvent) error {
	if len(batch) == 0 {
		return nil
	}

	query := `INSERT INTO auth_analytics.otp_events (
		event_id, event_type, timestamp, user_id, phone_number, status,
		attempt_number, attempts_left, error_code, error_message, ip_address,
		device_id, purpose, otp_provider, duration_ms
	)`

	batch_, err := cc.chClient.PrepareBatch(ctx, query)
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

// flushMPINBatch writes MPIN events to ClickHouse
func (cc *ClickHouseConsumer) flushMPINBatch(ctx context.Context, batch []models.MPINLogEvent) error {
	if len(batch) == 0 {
		return nil
	}

	query := `INSERT INTO auth_analytics.mpin_events (
		event_id, event_type, timestamp, user_id, status, attempts, attempts_left,
		is_locked, error_code, error_message, device_id, device_trust, duration_ms, failure_reason
	)`

	batch_, err := cc.chClient.PrepareBatch(ctx, query)
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

// flushSecurityBatch writes Security events to ClickHouse
func (cc *ClickHouseConsumer) flushSecurityBatch(ctx context.Context, batch []models.SecurityLogEvent) error {
	if len(batch) == 0 {
		return nil
	}

	query := `INSERT INTO auth_analytics.security_events (
		event_id, event_type, timestamp, user_id, event_category, severity,
		ip_address, device_id, action, risk_score, reason
	)`

	batch_, err := cc.chClient.PrepareBatch(ctx, query)
	if err != nil {
		return fmt.Errorf("failed to prepare Security batch: %w", err)
	}

	for _, e := range batch {
		if err := batch_.Append(
			e.EventID, e.EventType, e.Timestamp,
			e.UserID, e.EventCategory, e.Severity, e.IPAddress, e.DeviceID, e.Action,
			e.RiskScore, e.Reason,
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

// flushAdminBatch writes Admin events to ClickHouse
func (cc *ClickHouseConsumer) flushAdminBatch(ctx context.Context, batch []models.AdminLogEvent) error {
	if len(batch) == 0 {
		return nil
	}

	query := `INSERT INTO auth_analytics.admin_events (
		event_id, event_type, timestamp, admin_id, admin_role, target_user_id,
		action, resource_type, resource_id, status, error_code, duration_ms
	)`

	batch_, err := cc.chClient.PrepareBatch(ctx, query)
	if err != nil {
		return fmt.Errorf("failed to prepare Admin batch: %w", err)
	}

	for _, e := range batch {
		if err := batch_.Append(
			e.EventID, e.EventType, e.Timestamp,
			e.AdminID, e.AdminRole, e.TargetUserID, e.Action, e.ResourceType,
			e.ResourceID, e.Status, e.ErrorCode, e.Duration,
		); err != nil {
			return fmt.Errorf("failed to append Admin row: %w", err)
		}
	}

	if err := batch_.Send(); err != nil {
		return fmt.Errorf("failed to send Admin batch: %w", err)
	}

	cc.logger.Debug("Admin batch flushed to ClickHouse", zap.Int("count", len(batch)))
	return nil
}

// flushSessionBatch writes Session events to ClickHouse
func (cc *ClickHouseConsumer) flushSessionBatch(ctx context.Context, batch []models.SessionLogEvent) error {
	if len(batch) == 0 {
		return nil
	}

	query := `INSERT INTO auth_analytics.session_events (
		event_id, event_type, timestamp, user_id, session_id, status,
		device_id, ip_address, session_type, ttl_seconds, error_code
	)`

	batch_, err := cc.chClient.PrepareBatch(ctx, query)
	if err != nil {
		return fmt.Errorf("failed to prepare Session batch: %w", err)
	}

	for _, e := range batch {
		if err := batch_.Append(
			e.EventID, e.EventType, e.Timestamp,
			e.UserID, e.SessionID, e.Status, e.DeviceID, e.IPAddress,
			e.SessionType, e.TTL, e.ErrorCode,
		); err != nil {
			return fmt.Errorf("failed to append Session row: %w", err)
		}
	}

	if err := batch_.Send(); err != nil {
		return fmt.Errorf("failed to send Session batch: %w", err)
	}

	cc.logger.Debug("Session batch flushed to ClickHouse", zap.Int("count", len(batch)))
	return nil
}

// flushUserBatch writes User events to ClickHouse
func (cc *ClickHouseConsumer) flushUserBatch(ctx context.Context, batch []models.UserLogEvent) error {
	if len(batch) == 0 {
		return nil
	}

	query := `INSERT INTO auth_analytics.user_events (
		event_id, event_type, timestamp, user_id, action, phone_number,
		status, device_id, error_code, duration_ms
	)`

	batch_, err := cc.chClient.PrepareBatch(ctx, query)
	if err != nil {
		return fmt.Errorf("failed to prepare User batch: %w", err)
	}

	for _, e := range batch {
		if err := batch_.Append(
			e.EventID, e.EventType, e.Timestamp,
			e.UserID, e.Action, e.PhoneNumber, e.Status, e.DeviceID,
			e.ErrorCode, e.Duration,
		); err != nil {
			return fmt.Errorf("failed to append User row: %w", err)
		}
	}

	if err := batch_.Send(); err != nil {
		return fmt.Errorf("failed to send User batch: %w", err)
	}

	cc.logger.Debug("User batch flushed to ClickHouse", zap.Int("count", len(batch)))
	return nil
}

// flushDeviceBatch writes Device events to ClickHouse
func (cc *ClickHouseConsumer) flushDeviceBatch(ctx context.Context, batch []models.DeviceLogEvent) error {
	if len(batch) == 0 {
		return nil
	}

	query := `INSERT INTO auth_analytics.device_events (
		event_id, event_type, timestamp, user_id, device_id, action,
		status, bind_token, error_code, error_message, ip_address, session_id, duration_ms
	)`

	batch_, err := cc.chClient.PrepareBatch(ctx, query)
	if err != nil {
		return fmt.Errorf("failed to prepare Device batch: %w", err)
	}

	for _, e := range batch {
		if err := batch_.Append(
			e.EventID, e.EventType, e.Timestamp,
			e.UserID, e.DeviceID, e.Action, e.Status, e.BindToken,
			e.ErrorCode, e.ErrorMessage, e.IPAddress, e.SessionID, e.Duration,
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

// Health check
func (cc *ClickHouseConsumer) Health(ctx context.Context) error {
	if err := cc.chClient.Ping(ctx); err != nil {
		return fmt.Errorf("clickhouse unhealthy: %w", err)
	}
	return nil
}

// ✅ NEW: Input sanitization to prevent SQL injection
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

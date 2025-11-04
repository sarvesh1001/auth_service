// File: internal/consumer/clickhouse_consumer.go (FIXED)
// Consumes Kafka events and writes to ClickHouse for analytics
// ✅ CRITICAL FIX: Uses prepared statements instead of string concatenation

package consumer

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"github.com/ClickHouse/clickhouse-go/v2"
	"go.uber.org/zap"

	"auth-service/internal/client"
	"auth-service/internal/models"
	"auth-service/internal/util"
)

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
	return &ClickHouseConsumer{
		kafkaConsumer: kafkaConsumer,
		chClient:      chClient,
		logger:        util.Get(),
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

	otpBatch := make([]models.OTPLogEvent, 0, cc.batchSize)
	mpinBatch := make([]models.MPINLogEvent, 0, cc.batchSize)
	securityBatch := make([]models.SecurityLogEvent, 0, cc.batchSize)
	adminBatch := make([]models.AdminLogEvent, 0, cc.batchSize)
	sessionBatch := make([]models.SessionLogEvent, 0, cc.batchSize)
	userBatch := make([]models.UserLogEvent, 0, cc.batchSize)
	deviceBatch := make([]models.DeviceLogEvent, 0, cc.batchSize)

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
			
			cc.flushAll(shutdownCtx, otpBatch, mpinBatch, securityBatch, adminBatch, sessionBatch, userBatch, deviceBatch)
			cc.logger.Info("ClickHouse consumer stopped gracefully")
			return ctx.Err()

		case <-ticker.C:
			cc.flushAll(ctx, otpBatch, mpinBatch, securityBatch, adminBatch, sessionBatch, userBatch, deviceBatch)
			otpBatch = otpBatch[:0]
			mpinBatch = mpinBatch[:0]
			securityBatch = securityBatch[:0]
			adminBatch = adminBatch[:0]
			sessionBatch = sessionBatch[:0]
			userBatch = userBatch[:0]
			deviceBatch = deviceBatch[:0]
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
				
				otpBatch = append(otpBatch, e)
				otpBatchBytes += len(msg.Value)
				
				if len(otpBatch) >= cc.batchSize || otpBatchBytes >= cc.maxBatchBytes {
					if err := cc.flushOTPBatch(ctx, otpBatch); err != nil {
						cc.logger.Error("failed OTP batch insert", zap.Error(err), zap.Int("batch_size", len(otpBatch)))
					}
					otpBatch = otpBatch[:0]
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
				
				mpinBatch = append(mpinBatch, e)
				mpinBatchBytes += len(msg.Value)
				
				if len(mpinBatch) >= cc.batchSize || mpinBatchBytes >= cc.maxBatchBytes {
					if err := cc.flushMPINBatch(ctx, mpinBatch); err != nil {
						cc.logger.Error("failed MPIN batch insert", zap.Error(err), zap.Int("batch_size", len(mpinBatch)))
					}
					mpinBatch = mpinBatch[:0]
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
				
				securityBatch = append(securityBatch, e)
				securityBatchBytes += len(msg.Value)
				
				if len(securityBatch) >= cc.batchSize || securityBatchBytes >= cc.maxBatchBytes {
					if err := cc.flushSecurityBatch(ctx, securityBatch); err != nil {
						cc.logger.Error("failed Security batch insert", zap.Error(err), zap.Int("batch_size", len(securityBatch)))
					}
					securityBatch = securityBatch[:0]
					securityBatchBytes = 0
				}

			case "admin":
				var e models.AdminLogEvent
				if err := json.Unmarshal(msg.Value, &e); err != nil {
					cc.logger.Error("unmarshal Admin failed", zap.Error(err))
					continue
				}
				
				adminBatch = append(adminBatch, e)
				adminBatchBytes += len(msg.Value)
				
				if len(adminBatch) >= cc.batchSize || adminBatchBytes >= cc.maxBatchBytes {
					if err := cc.flushAdminBatch(ctx, adminBatch); err != nil {
						cc.logger.Error("failed Admin batch insert", zap.Error(err), zap.Int("batch_size", len(adminBatch)))
					}
					adminBatch = adminBatch[:0]
					adminBatchBytes = 0
				}

			case "session":
				var e models.SessionLogEvent
				if err := json.Unmarshal(msg.Value, &e); err != nil {
					cc.logger.Error("unmarshal Session failed", zap.Error(err))
					continue
				}
				
				sessionBatch = append(sessionBatch, e)
				sessionBatchBytes += len(msg.Value)
				
				if len(sessionBatch) >= cc.batchSize || sessionBatchBytes >= cc.maxBatchBytes {
					if err := cc.flushSessionBatch(ctx, sessionBatch); err != nil {
						cc.logger.Error("failed Session batch insert", zap.Error(err), zap.Int("batch_size", len(sessionBatch)))
					}
					sessionBatch = sessionBatch[:0]
					sessionBatchBytes = 0
				}

			case "user":
				var e models.UserLogEvent
				if err := json.Unmarshal(msg.Value, &e); err != nil {
					cc.logger.Error("unmarshal User failed", zap.Error(err))
					continue
				}
				
				userBatch = append(userBatch, e)
				userBatchBytes += len(msg.Value)
				
				if len(userBatch) >= cc.batchSize || userBatchBytes >= cc.maxBatchBytes {
					if err := cc.flushUserBatch(ctx, userBatch); err != nil {
						cc.logger.Error("failed User batch insert", zap.Error(err), zap.Int("batch_size", len(userBatch)))
					}
					userBatch = userBatch[:0]
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
				
				deviceBatch = append(deviceBatch, e)
				deviceBatchBytes += len(msg.Value)
				
				if len(deviceBatch) >= cc.batchSize || deviceBatchBytes >= cc.maxBatchBytes {
					if err := cc.flushDeviceBatch(ctx, deviceBatch); err != nil {
						cc.logger.Error("failed Device batch insert", zap.Error(err), zap.Int("batch_size", len(deviceBatch)))
					}
					deviceBatch = deviceBatch[:0]
					deviceBatchBytes = 0
				}

			default:
				cc.logger.Warn("unknown event type", zap.String("event_type", eventType))
			}
		}
	}
}

//
// ======== Batch Flush Helpers ========
//

// Flush all event batches
func (cc *ClickHouseConsumer) flushAll(
	ctx context.Context,
	otp []models.OTPLogEvent,
	mpin []models.MPINLogEvent,
	security []models.SecurityLogEvent,
	admin []models.AdminLogEvent,
	session []models.SessionLogEvent,
	user []models.UserLogEvent,
	device []models.DeviceLogEvent,
) {
	if err := cc.flushOTPBatch(ctx, otp); err != nil {
		cc.logger.Error("OTP batch flush failed", zap.Error(err))
	}
	if err := cc.flushMPINBatch(ctx, mpin); err != nil {
		cc.logger.Error("MPIN batch flush failed", zap.Error(err))
	}
	if err := cc.flushSecurityBatch(ctx, security); err != nil {
		cc.logger.Error("Security batch flush failed", zap.Error(err))
	}
	if err := cc.flushAdminBatch(ctx, admin); err != nil {
		cc.logger.Error("Admin batch flush failed", zap.Error(err))
	}
	if err := cc.flushSessionBatch(ctx, session); err != nil {
		cc.logger.Error("Session batch flush failed", zap.Error(err))
	}
	if err := cc.flushUserBatch(ctx, user); err != nil {
		cc.logger.Error("User batch flush failed", zap.Error(err))
	}
	if err := cc.flushDeviceBatch(ctx, device); err != nil {
		cc.logger.Error("Device batch flush failed", zap.Error(err))
	}
}

// ✅ FIXED: OTP Logs - Uses prepared batch inserts
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

	cc.logger.Debug("OTP batch flushed", zap.Int("count", len(batch)))
	return nil
}

// ✅ FIXED: MPIN Logs - Uses prepared batch inserts
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

	cc.logger.Debug("MPIN batch flushed", zap.Int("count", len(batch)))
	return nil
}

// ✅ FIXED: Security Logs - Uses prepared batch inserts
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

	cc.logger.Debug("Security batch flushed", zap.Int("count", len(batch)))
	return nil
}

// ✅ FIXED: Admin Logs - Uses prepared batch inserts
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

	cc.logger.Debug("Admin batch flushed", zap.Int("count", len(batch)))
	return nil
}

// ✅ FIXED: Session Logs - Uses prepared batch inserts
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

	cc.logger.Debug("Session batch flushed", zap.Int("count", len(batch)))
	return nil
}

// ✅ FIXED: User Logs - Uses prepared batch inserts
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

	cc.logger.Debug("User batch flushed", zap.Int("count", len(batch)))
	return nil
}

// ✅ FIXED: Device Logs - Uses prepared batch inserts
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

	cc.logger.Debug("Device batch flushed", zap.Int("count", len(batch)))
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
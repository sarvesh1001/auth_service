// File: internal/service/log_producer.go
// Produces operational events to Kafka topics for metrics and monitoring.
// Note: Audit events (business actions) are produced separately via the AuditService.
// This producer handles high‑volume operational logs: MPIN, OTP, Device, Security, SecurityRisk.

package service

import (
	"context"
	"encoding/json"
	"fmt"
	"time"

	"github.com/google/uuid"
	"go.uber.org/zap"

	"auth-service/internal/client"
	"auth-service/internal/models"
	"auth-service/internal/util"
)

// LogProducerService handles production of operational events to Kafka.
type LogProducerService struct {
	kafkaProducer *client.KafkaProducer
	logger        *zap.Logger
	environment   string
	version       string
}

// NewLogProducerService creates a new log producer service.
func NewLogProducerService(
	kafkaProducer *client.KafkaProducer,
	environment string,
	version string,
) *LogProducerService {
	return &LogProducerService{
		kafkaProducer: kafkaProducer,
		logger:        util.Get(),
		environment:   environment,
		version:       version,
	}
}

// ================== SECURITY RISK EVENTS ==================
// ProduceSecurityRiskEvent sends security risk events for bot protection, IP reputation, and risk scoring.
func (lps *LogProducerService) ProduceSecurityRiskEvent(ctx context.Context, event *models.SecurityEvent) error {
	if event == nil {
		return fmt.Errorf("event is nil")
	}

	// Set common fields if not already set
	if event.EventID == "" {
		event.EventID = uuid.New().String()
	}
	if event.EventType == "" {
		event.EventType = "security_risk"
	}
	if event.Timestamp.IsZero() {
		event.Timestamp = time.Now().UTC()
	}
	if event.Environment == "" {
		event.Environment = lps.environment
	}
	if event.Version == "" {
		event.Version = lps.version
	}
	if event.ServiceName == "" {
		event.ServiceName = "auth-service"
	}

	data, err := json.Marshal(event)
	if err != nil {
		lps.logger.Error("failed to marshal Security Risk event", zap.Error(err))
		return err
	}

	headers := map[string]string{
		"event_type":   "security_risk",
		"phone_number": event.PhoneNumber,
		"action_taken": event.ActionTaken,
	}

	err = lps.kafkaProducer.ProduceMessage(ctx, "security-events", []byte(event.PhoneNumber), data, headers)
	if err != nil {
		lps.logger.Error("failed to produce Security Risk event", zap.Error(err))
		return err
	}

	lps.logger.Debug("Security Risk event produced",
		zap.String("phone_number", event.PhoneNumber),
		zap.Int("risk_score", event.RiskScore),
		zap.String("action_taken", event.ActionTaken),
	)
	return nil
}

// ================== OTP EVENTS ==================
// ProduceOTPEvent sends OTP lifecycle events (send, verify, failure, etc.)
func (lps *LogProducerService) ProduceOTPEvent(ctx context.Context, event *models.OTPLogEvent) error {
	if event == nil {
		return fmt.Errorf("event is nil")
	}

	event.EventID = uuid.New().String()
	event.EventType = "otp"
	event.Timestamp = time.Now().UTC()

	data, err := json.Marshal(event)
	if err != nil {
		lps.logger.Error("failed to marshal OTP event", zap.Error(err))
		return err
	}

	headers := map[string]string{
		"event_type": "otp",
		"user_id":    event.UserID,
		"status":     event.Status,
	}

	err = lps.kafkaProducer.ProduceMessage(ctx, "otp-events", []byte(event.UserID), data, headers)
	if err != nil {
		lps.logger.Error("failed to produce OTP event", zap.Error(err))
		return err
	}

	lps.logger.Debug("OTP event produced", zap.String("user_id", event.UserID))
	return nil
}

// ================== MPIN EVENTS ==================
// ProduceMPINEvent sends MPIN authentication attempts (setup, verify, change, lockout, etc.)
func (lps *LogProducerService) ProduceMPINEvent(ctx context.Context, event *models.MPINLogEvent) error {
	if event == nil {
		return fmt.Errorf("event is nil")
	}

	event.EventID = uuid.New().String()
	event.EventType = "mpin"
	event.Timestamp = time.Now().UTC()

	data, err := json.Marshal(event)
	if err != nil {
		lps.logger.Error("failed to marshal MPIN event", zap.Error(err))
		return err
	}

	headers := map[string]string{
		"event_type": "mpin",
		"user_id":    event.UserID,
		"status":     event.Status,
	}

	err = lps.kafkaProducer.ProduceMessage(ctx, "mpin-events", []byte(event.UserID), data, headers)
	if err != nil {
		lps.logger.Error("failed to produce MPIN event", zap.Error(err))
		return err
	}

	lps.logger.Debug("MPIN event produced", zap.String("user_id", event.UserID))
	return nil
}

// ================== SECURITY EVENTS ==================
// ProduceSecurityEvent sends security alerts (suspicious IP, brute‑force, anomaly detection)
func (lps *LogProducerService) ProduceSecurityEvent(ctx context.Context, event *models.SecurityLogEvent) error {
	if event == nil {
		return fmt.Errorf("event is nil")
	}

	event.EventID = uuid.New().String()
	event.EventType = "security"
	event.Timestamp = time.Now().UTC()

	data, err := json.Marshal(event)
	if err != nil {
		lps.logger.Error("failed to marshal Security event", zap.Error(err))
		return err
	}

	headers := map[string]string{
		"event_type": "security",
		"user_id":    event.UserID,
	}

	err = lps.kafkaProducer.ProduceMessage(ctx, "security-events", []byte(event.UserID), data, headers)
	if err != nil {
		lps.logger.Error("failed to produce Security event", zap.Error(err))
		return err
	}

	lps.logger.Debug("Security event produced", zap.String("user_id", event.UserID))
	return nil
}

// ================== DEVICE EVENTS ==================
// ProduceDeviceEvent sends device lifecycle events (bind, trust, block, etc.)
func (lps *LogProducerService) ProduceDeviceEvent(ctx context.Context, event *models.DeviceLogEvent) error {
	if event == nil {
		return fmt.Errorf("event is nil")
	}

	event.EventID = uuid.New().String()
	event.EventType = "device"
	event.Timestamp = time.Now().UTC()

	data, err := json.Marshal(event)
	if err != nil {
		lps.logger.Error("failed to marshal Device event", zap.Error(err))
		return err
	}

	headers := map[string]string{
		"event_type": "device",
		"user_id":    event.UserID,
		"device_id":  event.DeviceID,
		"status":     event.Status,
	}

	err = lps.kafkaProducer.ProduceMessage(ctx, "device-events", []byte(event.UserID), data, headers)
	if err != nil {
		lps.logger.Error("failed to produce Device event", zap.Error(err))
		return err
	}

	lps.logger.Debug("Device event produced", zap.String("user_id", event.UserID))
	return nil
}

// ================== CLOSE PRODUCER ==================
// Close shuts down the underlying Kafka producer.
func (lps *LogProducerService) Close() error {
	if lps.kafkaProducer != nil {
		return lps.kafkaProducer.Close()
	}
	return nil
}

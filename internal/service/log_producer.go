// File: internal/service/log_producer.go
// Produces events to Kafka topics for log aggregation

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

// LogProducerService handles Kafka event production
type LogProducerService struct {
	kafkaProducer *client.KafkaProducer
	logger        *zap.Logger
	environment   string
	version       string
}

// NewLogProducerService creates a new log producer service
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

// ================== OTP EVENTS ==================
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

	lps.logger.Debug("✅ OTP event produced", zap.String("user_id", event.UserID))
	return nil
}

// ================== MPIN EVENTS ==================
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

	lps.logger.Debug("✅ MPIN event produced", zap.String("user_id", event.UserID))
	return nil
}

// ================== SECURITY EVENTS ==================
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

	lps.logger.Debug("✅ Security event produced", zap.String("user_id", event.UserID))
	return nil
}

// ================== ADMIN EVENTS ==================
func (lps *LogProducerService) ProduceAdminEvent(ctx context.Context, event *models.AdminLogEvent) error {
	if event == nil {
		return fmt.Errorf("event is nil")
	}

	event.EventID = uuid.New().String()
	event.EventType = "admin"
	event.Timestamp = time.Now().UTC()

	data, err := json.Marshal(event)
	if err != nil {
		lps.logger.Error("failed to marshal Admin event", zap.Error(err))
		return err
	}

	headers := map[string]string{
		"event_type": "admin",
		"admin_id":   event.AdminID,
		"action":     event.Action,
		"status":     event.Status,
	}

	err = lps.kafkaProducer.ProduceMessage(ctx, "admin-events", []byte(event.AdminID), data, headers)
	if err != nil {
		lps.logger.Error("failed to produce Admin event", zap.Error(err))
		return err
	}

	lps.logger.Debug("✅ Admin event produced", zap.String("admin_id", event.AdminID))
	return nil
}

// ================== SESSION EVENTS ==================
func (lps *LogProducerService) ProduceSessionEvent(ctx context.Context, event *models.SessionLogEvent) error {
	if event == nil {
		return fmt.Errorf("event is nil")
	}

	event.EventID = uuid.New().String()
	event.EventType = "session"
	event.Timestamp = time.Now().UTC()

	data, err := json.Marshal(event)
	if err != nil {
		lps.logger.Error("failed to marshal Session event", zap.Error(err))
		return err
	}

	headers := map[string]string{
		"event_type":   "session",
		"user_id":      event.UserID,
		"session_type": event.SessionType,
	}

	err = lps.kafkaProducer.ProduceMessage(ctx, "session-events", []byte(event.UserID), data, headers)
	if err != nil {
		lps.logger.Error("failed to produce Session event", zap.Error(err))
		return err
	}

	lps.logger.Debug("✅ Session event produced", zap.String("user_id", event.UserID))
	return nil
}

// ================== USER EVENTS ==================
func (lps *LogProducerService) ProduceUserEvent(ctx context.Context, event *models.UserLogEvent) error {
	if event == nil {
		return fmt.Errorf("event is nil")
	}

	event.EventID = uuid.New().String()
	event.EventType = "user"
	event.Timestamp = time.Now().UTC()

	data, err := json.Marshal(event)
	if err != nil {
		lps.logger.Error("failed to marshal User event", zap.Error(err))
		return err
	}

	headers := map[string]string{
		"event_type": "user",
		"user_id":    event.UserID,
		"action":     event.Action,
	}

	err = lps.kafkaProducer.ProduceMessage(ctx, "user-events", []byte(event.UserID), data, headers)
	if err != nil {
		lps.logger.Error("failed to produce User event", zap.Error(err))
		return err
	}

	lps.logger.Debug("✅ User event produced", zap.String("user_id", event.UserID))
	return nil
}

// ================== DEVICE EVENTS ==================
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

	lps.logger.Debug("✅ Device event produced", zap.String("user_id", event.UserID))
	return nil
}

// ================== CLOSE PRODUCER ==================
func (lps *LogProducerService) Close() error {
	if lps.kafkaProducer != nil {
		return lps.kafkaProducer.Close()
	}
	return nil
}

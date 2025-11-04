// File: internal/service/device_service.go
package service

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"time"

	"auth-service/internal/config"
	"auth-service/internal/models"
	"auth-service/internal/repository/scylla"
	"auth-service/internal/util"

	"github.com/google/uuid"
	"go.uber.org/zap"
)

// DeviceService handles device management business logic
type DeviceService struct {
	deviceRepo   scylla.DeviceRepository
	historyRepo  *scylla.DeviceHistoryRepositoryImpl
	distCache    *DistributedCache
	logProducer  *LogProducerService
	config       config.Config
	logger       *zap.Logger
}

// NewDeviceService creates a new device service
func NewDeviceService(
	deviceRepo scylla.DeviceRepository,
	distCache *DistributedCache,
	config config.Config,
	logger *zap.Logger,
) *DeviceService {
	return &DeviceService{
		deviceRepo: deviceRepo,
		distCache:  distCache,
		config:     config,
		logger:     logger,
	}
}

// SetHistoryRepository sets the history repository for tracking device binding changes
func (s *DeviceService) SetHistoryRepository(historyRepo *scylla.DeviceHistoryRepositoryImpl) {
	s.historyRepo = historyRepo
}

// SetLogProducerService sets the log producer service
func (s *DeviceService) SetLogProducerService(logProducer *LogProducerService) {
	s.logProducer = logProducer
}

// Request/Response types

type BindDeviceRequest struct {
	UserID    uuid.UUID `json:"user_id" validate:"required"`
	DeviceID  string    `json:"device_id" validate:"required"`
	IPAddress string    `json:"ip_address,omitempty"`
	UserAgent string    `json:"user_agent,omitempty"`
}

type BindDeviceResponse struct {
	BindToken string    `json:"bind_token"`
	BoundAt   time.Time `json:"bound_at"`
	Success   bool      `json:"success"`
}

type ValidateDeviceRequest struct {
	UserID    uuid.UUID `json:"user_id" validate:"required"`
	DeviceID  string    `json:"device_id" validate:"required"`
	BindToken string    `json:"bind_token" validate:"required"`
	IPAddress string    `json:"ip_address,omitempty"`
}

type ValidateDeviceResponse struct {
	IsValid bool   `json:"is_valid"`
	Message string `json:"message,omitempty"`
}

// BindDevice creates a device binding with a generated token
func (s *DeviceService) BindDevice(
	ctx context.Context,
	req BindDeviceRequest,
) (*BindDeviceResponse, error) {
	startTime := time.Now()

	// Generate cryptographically secure bind token
	bindToken, err := s.generateBindToken()
	if err != nil {
		// ✅ Log failure event
		if s.logProducer != nil {
			event := &models.DeviceLogEvent{
				UserID:       req.UserID.String(),
				DeviceID:     req.DeviceID,
				Action:       "bind",
				Status:       "failed",
				ErrorCode:    "TOKEN_GENERATION_FAILED",
				ErrorMessage: err.Error(),
				IPAddress:    req.IPAddress,
				Duration:     int64(time.Since(startTime).Milliseconds()),
			}
			_ = s.logProducer.ProduceDeviceEvent(ctx, event)
		}
		return nil, fmt.Errorf("failed to generate bind token: %w", err)
	}

	// Bind device in repository
	if err := s.deviceRepo.BindUserDevice(ctx, req.UserID, req.DeviceID, bindToken); err != nil {
		// ✅ Log failure event
		if s.logProducer != nil {
			event := &models.DeviceLogEvent{
				UserID:       req.UserID.String(),
				DeviceID:     req.DeviceID,
				Action:       "bind",
				Status:       "failed",
				ErrorCode:    "BIND_FAILED",
				ErrorMessage: err.Error(),
				IPAddress:    req.IPAddress,
				Duration:     int64(time.Since(startTime).Milliseconds()),
			}
			_ = s.logProducer.ProduceDeviceEvent(ctx, event)
		}
		return nil, fmt.Errorf("failed to bind device: %w", err)
	}

	// Record in history
	if s.historyRepo != nil {
		if err := s.historyRepo.RecordBinding(ctx, req.UserID, req.DeviceID, nil, bindToken, "bind"); err != nil {
			s.logger.Warn("Failed to record binding in history",
				util.ErrorField(err),
				util.String("user_id", req.UserID.String()),
				util.String("device_id", req.DeviceID))
			// Don't fail the request if history recording fails
		}
	}

	// ✅ Log success event
	if s.logProducer != nil {
		event := &models.DeviceLogEvent{
			UserID:    req.UserID.String(),
			DeviceID:  req.DeviceID,
			Action:    "bind",
			Status:    "success",
			BindToken: bindToken,
			IPAddress: req.IPAddress,
			Duration:  int64(time.Since(startTime).Milliseconds()),
		}
		_ = s.logProducer.ProduceDeviceEvent(ctx, event)
	}

	// Invalidate cache
	if s.distCache != nil {
		cacheKey := fmt.Sprintf("device:%s", req.UserID.String())
		s.distCache.DeleteKey(ctx, cacheKey)
	}

	s.logger.Info("Device bound successfully",
		util.String("user_id", req.UserID.String()),
		util.String("device_id", req.DeviceID),
		util.String("ip_address", req.IPAddress),
		util.Duration("duration", time.Since(startTime)))

	return &BindDeviceResponse{
		BindToken: bindToken,
		BoundAt:   time.Now().UTC(),
		Success:   true,
	}, nil
}

// GetActiveDevice retrieves the active device for a user (with caching)
func (s *DeviceService) GetActiveDevice(
	ctx context.Context,
	userID uuid.UUID,
) (*models.UserActiveDevice, error) {
	// Try cache first
	if s.distCache != nil {
		cacheKey := fmt.Sprintf("device:%s", userID.String())
		var cachedDevice models.UserActiveDevice
		if err := s.distCache.Get(ctx, cacheKey, &cachedDevice); err == nil {
			s.logger.Debug("Device cache hit", util.String("user_id", userID.String()))
			return &cachedDevice, nil
		}
	}

	// Cache miss - fetch from database
	device, err := s.deviceRepo.GetActiveDevice(ctx, userID)
	if err != nil {
		return nil, err
	}

	// Cache the result
	if device != nil && s.distCache != nil {
		cacheKey := fmt.Sprintf("device:%s", userID.String())
		s.distCache.SetWithExpiry(ctx, cacheKey, device, 5*time.Minute)
	}

	return device, nil
}

// UnbindDevice removes a device binding
func (s *DeviceService) UnbindDevice(ctx context.Context, userID uuid.UUID, ipAddress string) error {
	startTime := time.Now()

	// Get device before unbinding for history
	device, err := s.deviceRepo.GetActiveDevice(ctx, userID)
	if err != nil {
		// ✅ Log failure event
		if s.logProducer != nil {
			event := &models.DeviceLogEvent{
				UserID:       userID.String(),
				Action:       "unbind",
				Status:       "failed",
				ErrorCode:    "GET_DEVICE_FAILED",
				ErrorMessage: err.Error(),
				IPAddress:    ipAddress,
				Duration:     int64(time.Since(startTime).Milliseconds()),
			}
			_ = s.logProducer.ProduceDeviceEvent(ctx, event)
		}
		return fmt.Errorf("failed to get active device: %w", err)
	}

	if err := s.deviceRepo.UnbindUserDevice(ctx, userID); err != nil {
		// ✅ Log failure event
		if s.logProducer != nil && device != nil {
			event := &models.DeviceLogEvent{
				UserID:       userID.String(),
				DeviceID:     device.DeviceID,
				Action:       "unbind",
				Status:       "failed",
				ErrorCode:    "UNBIND_FAILED",
				ErrorMessage: err.Error(),
				IPAddress:    ipAddress,
				Duration:     int64(time.Since(startTime).Milliseconds()),
			}
			_ = s.logProducer.ProduceDeviceEvent(ctx, event)
		}
		return fmt.Errorf("failed to unbind device: %w", err)
	}

	// Record unbind in history
	if device != nil && s.historyRepo != nil {
		if err := s.historyRepo.RecordBinding(ctx, userID, device.DeviceID, nil, device.BindToken, "unbind"); err != nil {
			s.logger.Warn("Failed to record unbind in history",
				util.ErrorField(err),
				util.String("user_id", userID.String()),
				util.String("device_id", device.DeviceID))
		}
	}

	// ✅ Log success event
	if s.logProducer != nil && device != nil {
		event := &models.DeviceLogEvent{
			UserID:    userID.String(),
			DeviceID:  device.DeviceID,
			Action:    "unbind",
			Status:    "success",
			IPAddress: ipAddress,
			Duration:  int64(time.Since(startTime).Milliseconds()),
		}
		_ = s.logProducer.ProduceDeviceEvent(ctx, event)
	}

	// Invalidate cache
	if s.distCache != nil {
		cacheKey := fmt.Sprintf("device:%s", userID.String())
		s.distCache.DeleteKey(ctx, cacheKey)
	}

	s.logger.Info("Device unbound successfully", 
		util.String("user_id", userID.String()),
		util.String("ip_address", ipAddress))
	return nil
}

// UpdateDeviceSession updates the session ID for a device
func (s *DeviceService) UpdateDeviceSession(
	ctx context.Context,
	userID, sessionID uuid.UUID,
	ipAddress string,
) error {
	startTime := time.Now()

	if err := s.deviceRepo.UpdateDeviceSession(ctx, userID, sessionID); err != nil {
		// ✅ Log failure event
		if s.logProducer != nil {
			event := &models.DeviceLogEvent{
				UserID:       userID.String(),
				Action:       "update_session",
				Status:       "failed",
				ErrorCode:    "UPDATE_SESSION_FAILED",
				ErrorMessage: err.Error(),
				IPAddress:    ipAddress,
				Duration:     int64(time.Since(startTime).Milliseconds()),
			}
			_ = s.logProducer.ProduceDeviceEvent(ctx, event)
		}
		return fmt.Errorf("failed to update device session: %w", err)
	}

	// ✅ Log success event
	if s.logProducer != nil {
		event := &models.DeviceLogEvent{
			UserID:    userID.String(),
			Action:    "update_session",
			Status:    "success",
			SessionID: sessionID.String(),
			IPAddress: ipAddress,
			Duration:  int64(time.Since(startTime).Milliseconds()),
		}
		_ = s.logProducer.ProduceDeviceEvent(ctx, event)
	}

	// Invalidate cache
	if s.distCache != nil {
		cacheKey := fmt.Sprintf("device:%s", userID.String())
		s.distCache.DeleteKey(ctx, cacheKey)
	}

	return nil
}

// ValidateDevice validates a device binding
func (s *DeviceService) ValidateDevice(
	ctx context.Context,
	req ValidateDeviceRequest,
) (*ValidateDeviceResponse, error) {
	startTime := time.Now()

	isValid, err := s.deviceRepo.ValidateDeviceBinding(
		ctx,
		req.UserID,
		req.DeviceID,
		req.BindToken,
	)

	response := &ValidateDeviceResponse{
		IsValid: isValid,
	}

	if err != nil {
		// ✅ Log failure event
		if s.logProducer != nil {
			event := &models.DeviceLogEvent{
				UserID:       req.UserID.String(),
				DeviceID:     req.DeviceID,
				Action:       "validate",
				Status:       "failed",
				ErrorCode:    "VALIDATION_ERROR",
				ErrorMessage: err.Error(),
				IPAddress:    req.IPAddress,
				Duration:     int64(time.Since(startTime).Milliseconds()),
			}
			_ = s.logProducer.ProduceDeviceEvent(ctx, event)
		}
		return nil, fmt.Errorf("failed to validate device: %w", err)
	}

	if !isValid {
		response.Message = "Invalid device binding"
		// ✅ Log validation failure
		if s.logProducer != nil {
			event := &models.DeviceLogEvent{
				UserID:    req.UserID.String(),
				DeviceID:  req.DeviceID,
				Action:    "validate",
				Status:    "failed",
				ErrorCode: "INVALID_BINDING",
				IPAddress: req.IPAddress,
				Duration:  int64(time.Since(startTime).Milliseconds()),
			}
			_ = s.logProducer.ProduceDeviceEvent(ctx, event)
		}
	} else {
		// ✅ Log validation success
		if s.logProducer != nil {
			event := &models.DeviceLogEvent{
				UserID:    req.UserID.String(),
				DeviceID:  req.DeviceID,
				Action:    "validate",
				Status:    "success",
				IPAddress: req.IPAddress,
				Duration:  int64(time.Since(startTime).Milliseconds()),
			}
			_ = s.logProducer.ProduceDeviceEvent(ctx, event)
		}
	}

	return response, nil
}

// GetDeviceBindingHistory retrieves device history from history table
func (s *DeviceService) GetDeviceBindingHistory(
	ctx context.Context,
	userID uuid.UUID,
	limit int,
) ([]*models.UserActiveDevice, error) {
	// Use history table if available
	if s.historyRepo != nil {
		return s.historyRepo.GetBindingHistory(ctx, userID, limit)
	}

	// Fallback to current device
	device, err := s.deviceRepo.GetActiveDevice(ctx, userID)
	if err != nil {
		return nil, err
	}

	if device == nil {
		return []*models.UserActiveDevice{}, nil
	}

	return []*models.UserActiveDevice{device}, nil
}

// GetUsersByDevice finds all users for a device
func (s *DeviceService) GetUsersByDevice(
	ctx context.Context,
	deviceID string,
) ([]*models.UserActiveDevice, error) {
	// Use history table if available (faster with materialized view)
	if s.historyRepo != nil {
		return s.historyRepo.GetUsersByDeviceFromHistory(ctx, deviceID)
	}

	// Fallback to main repository
	return s.deviceRepo.GetUsersByDevice(ctx, deviceID)
}

// CleanupOrphanedDevices removes old device bindings
func (s *DeviceService) CleanupOrphanedDevices(
	ctx context.Context,
	olderThan time.Duration,
) (int, error) {
	startTime := time.Now()

	cutoffTime := time.Now().Add(-olderThan)
	count, err := s.deviceRepo.CleanupOrphanedDevices(ctx, cutoffTime)
	if err != nil {
		// ✅ Log failure event
		if s.logProducer != nil {
			event := &models.DeviceLogEvent{
				Action:       "cleanup_orphaned",
				Status:       "failed",
				ErrorCode:    "CLEANUP_FAILED",
				ErrorMessage: err.Error(),
				Duration:     int64(time.Since(startTime).Milliseconds()),
			}
			_ = s.logProducer.ProduceDeviceEvent(ctx, event)
		}
		return 0, fmt.Errorf("failed to cleanup orphaned devices: %w", err)
	}

	// ✅ Log success event
	if s.logProducer != nil && count > 0 {
		event := &models.DeviceLogEvent{
			Action:   "cleanup_orphaned",
			Status:   "success",
			Duration: int64(time.Since(startTime).Milliseconds()),
		}
		_ = s.logProducer.ProduceDeviceEvent(ctx, event)
	}

	s.logger.Info("Cleaned up orphaned devices",
		util.Int("count", count),
		util.Duration("older_than", olderThan))

	return count, nil
}

// HealthCheck checks service health
func (s *DeviceService) HealthCheck(ctx context.Context) error {
	if err := s.deviceRepo.HealthCheck(ctx); err != nil {
		return err
	}

	if s.historyRepo != nil {
		if err := s.historyRepo.HealthCheck(ctx); err != nil {
			return err
		}
	}

	return nil
}

// GetServiceStats returns service statistics
func (s *DeviceService) GetServiceStats(ctx context.Context) (map[string]interface{}, error) {
	return s.deviceRepo.GetRepositoryStats(ctx)
}

// generateBindToken generates a cryptographically secure bind token
func (s *DeviceService) generateBindToken() (string, error) {
	b := make([]byte, 32) // 256 bits
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return base64.URLEncoding.EncodeToString(b), nil
}
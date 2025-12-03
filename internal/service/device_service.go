// File: internal/service/device_service.go
package service

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"net"
	"strings"
	"time"

	"auth-service/internal/config"
	"auth-service/internal/models"
	"auth-service/internal/repository/scylla"
	"auth-service/internal/util"

	"github.com/google/uuid"
	"go.uber.org/zap"
)

// DeviceService handles device management and trust business logic
type DeviceService struct {
	deviceRepo           scylla.DeviceRepository
	deviceTrustRepo      scylla.DeviceTrustRepository
	adminDeviceTrustRepo scylla.AdminDeviceTrustRepository
	historyRepo          *scylla.DeviceHistoryRepositoryImpl
	distCache            *DistributedCache
	logProducer          *LogProducerService
	config               config.Config
	logger               *zap.Logger
}

// NewDeviceService creates a new device service
func NewDeviceService(
	deviceRepo scylla.DeviceRepository,
	deviceTrustRepo scylla.DeviceTrustRepository,
	adminDeviceTrustRepo scylla.AdminDeviceTrustRepository,
	distCache *DistributedCache,
	config config.Config,
	logger *zap.Logger,
) *DeviceService {
	return &DeviceService{
		deviceRepo:           deviceRepo,
		deviceTrustRepo:      deviceTrustRepo,
		adminDeviceTrustRepo: adminDeviceTrustRepo,
		distCache:            distCache,
		config:               config,
		logger:               logger,
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

type DeviceTrustRequest struct {
	UserID            uuid.UUID                `json:"user_id" validate:"required"`
	DeviceID          string                   `json:"device_id" validate:"required"`
	TrustStatus       models.DeviceTrustStatus `json:"trust_status" validate:"required"`
	DeviceFingerprint string                   `json:"device_fingerprint"`
	OSVersion         string                   `json:"os_version"`
	AppVersion        string                   `json:"app_version"`
	IPAddress         string                   `json:"ip_address"`
	UserAgent         string                   `json:"user_agent"`
	DeviceModel       string                   `json:"device_model"`
}

type DeviceTrustResponse struct {
	Success    bool                     `json:"success"`
	TrustLevel *models.DeviceTrustLevel `json:"trust_level,omitempty"`
	RiskScore  int                      `json:"risk_score"`
	IsBlocked  bool                     `json:"is_blocked"`
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
		}
	}

	// Create initial device trust level
	trustLevel := &models.DeviceTrustLevel{
		UserID:      req.UserID,
		DeviceID:    req.DeviceID,
		TrustStatus: models.TrustStatusUntrusted,
		RiskScore:   0,
		IsBlocked:   false,
	}

	if err := s.deviceTrustRepo.SetDeviceTrustLevel(ctx, req.UserID, req.DeviceID, trustLevel); err != nil {
		s.logger.Warn("Failed to set initial device trust level",
			util.ErrorField(err),
			util.String("user_id", req.UserID.String()),
			util.String("device_id", req.DeviceID))
	}

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
	startTime := time.Now()

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
		if s.logProducer != nil {
			event := &models.DeviceLogEvent{
				UserID:       userID.String(),
				Action:       "get_active_device",
				Status:       "failed",
				ErrorCode:    "GET_DEVICE_FAILED",
				ErrorMessage: err.Error(),
				Duration:     int64(time.Since(startTime).Milliseconds()),
			}
			_ = s.logProducer.ProduceDeviceEvent(ctx, event)
		}
		return nil, fmt.Errorf("failed to get active device: %w", err)
	}

	// Cache the result
	if device != nil && s.distCache != nil {
		cacheKey := fmt.Sprintf("device:%s", userID.String())
		s.distCache.SetWithExpiry(ctx, cacheKey, device, 5*time.Minute)
	}

	if s.logProducer != nil && device != nil {
		event := &models.DeviceLogEvent{
			UserID:   userID.String(),
			DeviceID: device.DeviceID,
			Action:   "get_active_device",
			Status:   "success",
			Duration: int64(time.Since(startTime).Milliseconds()),
		}
		_ = s.logProducer.ProduceDeviceEvent(ctx, event)
	}

	return device, nil
}

// UnbindDevice removes a device binding
func (s *DeviceService) UnbindDevice(ctx context.Context, userID uuid.UUID, ipAddress string) error {
	startTime := time.Now()

	// Get device before unbinding for history
	device, err := s.deviceRepo.GetActiveDevice(ctx, userID)
	if err != nil {
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
	startTime := time.Now()

	// Use history table if available
	if s.historyRepo != nil {
		history, err := s.historyRepo.GetBindingHistory(ctx, userID, limit)
		if err != nil {
			if s.logProducer != nil {
				event := &models.DeviceLogEvent{
					UserID:       userID.String(),
					Action:       "get_binding_history",
					Status:       "failed",
					ErrorCode:    "GET_HISTORY_FAILED",
					ErrorMessage: err.Error(),
					Duration:     int64(time.Since(startTime).Milliseconds()),
				}
				_ = s.logProducer.ProduceDeviceEvent(ctx, event)
			}
			return nil, fmt.Errorf("failed to get binding history: %w", err)
		}

		if s.logProducer != nil {
			event := &models.DeviceLogEvent{
				UserID:   userID.String(),
				Action:   "get_binding_history",
				Status:   "success",
				Duration: int64(time.Since(startTime).Milliseconds()),
			}
			_ = s.logProducer.ProduceDeviceEvent(ctx, event)
		}

		return history, nil
	}

	// Fallback to current device
	device, err := s.deviceRepo.GetActiveDevice(ctx, userID)
	if err != nil {
		if s.logProducer != nil {
			event := &models.DeviceLogEvent{
				UserID:       userID.String(),
				Action:       "get_binding_history",
				Status:       "failed",
				ErrorCode:    "GET_DEVICE_FAILED",
				ErrorMessage: err.Error(),
				Duration:     int64(time.Since(startTime).Milliseconds()),
			}
			_ = s.logProducer.ProduceDeviceEvent(ctx, event)
		}
		return nil, fmt.Errorf("failed to get active device: %w", err)
	}

	if device == nil {
		return []*models.UserActiveDevice{}, nil
	}

	if s.logProducer != nil {
		event := &models.DeviceLogEvent{
			UserID:   userID.String(),
			Action:   "get_binding_history",
			Status:   "success",
			Duration: int64(time.Since(startTime).Milliseconds()),
		}
		_ = s.logProducer.ProduceDeviceEvent(ctx, event)
	}

	return []*models.UserActiveDevice{device}, nil
}

// GetUsersByDevice finds all users for a device
func (s *DeviceService) GetUsersByDevice(
	ctx context.Context,
	deviceID string,
) ([]*models.UserActiveDevice, error) {
	startTime := time.Now()

	// Use history table if available (faster with materialized view)
	if s.historyRepo != nil {
		users, err := s.historyRepo.GetUsersByDeviceFromHistory(ctx, deviceID)
		if err != nil {
			if s.logProducer != nil {
				event := &models.DeviceLogEvent{
					DeviceID:     deviceID,
					Action:       "get_users_by_device",
					Status:       "failed",
					ErrorCode:    "GET_USERS_FAILED",
					ErrorMessage: err.Error(),
					Duration:     int64(time.Since(startTime).Milliseconds()),
				}
				_ = s.logProducer.ProduceDeviceEvent(ctx, event)
			}
			return nil, fmt.Errorf("failed to get users by device from history: %w", err)
		}

		if s.logProducer != nil {
			event := &models.DeviceLogEvent{
				DeviceID: deviceID,
				Action:   "get_users_by_device",
				Status:   "success",
				Duration: int64(time.Since(startTime).Milliseconds()),
			}
			_ = s.logProducer.ProduceDeviceEvent(ctx, event)
		}

		return users, nil
	}

	// Fallback to main repository
	users, err := s.deviceRepo.GetUsersByDevice(ctx, deviceID)
	if err != nil {
		if s.logProducer != nil {
			event := &models.DeviceLogEvent{
				DeviceID:     deviceID,
				Action:       "get_users_by_device",
				Status:       "failed",
				ErrorCode:    "GET_USERS_FAILED",
				ErrorMessage: err.Error(),
				Duration:     int64(time.Since(startTime).Milliseconds()),
			}
			_ = s.logProducer.ProduceDeviceEvent(ctx, event)
		}
		return nil, fmt.Errorf("failed to get users by device: %w", err)
	}

	if s.logProducer != nil {
		event := &models.DeviceLogEvent{
			DeviceID: deviceID,
			Action:   "get_users_by_device",
			Status:   "success",
			Duration: int64(time.Since(startTime).Milliseconds()),
		}
		_ = s.logProducer.ProduceDeviceEvent(ctx, event)
	}

	return users, nil
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

	if s.logProducer != nil {
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
	startTime := time.Now()

	if err := s.deviceRepo.HealthCheck(ctx); err != nil {
		if s.logProducer != nil {
			event := &models.DeviceLogEvent{
				Action:       "health_check",
				Status:       "failed",
				ErrorCode:    "DEVICE_REPO_HEALTH_FAILED",
				ErrorMessage: err.Error(),
				Duration:     int64(time.Since(startTime).Milliseconds()),
			}
			_ = s.logProducer.ProduceDeviceEvent(ctx, event)
		}
		return fmt.Errorf("device repository health check failed: %w", err)
	}

	if s.deviceTrustRepo != nil {
		if err := s.deviceTrustRepo.HealthCheck(ctx); err != nil {
			if s.logProducer != nil {
				event := &models.DeviceLogEvent{
					Action:       "health_check",
					Status:       "failed",
					ErrorCode:    "TRUST_REPO_HEALTH_FAILED",
					ErrorMessage: err.Error(),
					Duration:     int64(time.Since(startTime).Milliseconds()),
				}
				_ = s.logProducer.ProduceDeviceEvent(ctx, event)
			}
			return fmt.Errorf("device trust repository health check failed: %w", err)
		}
	}

	if s.historyRepo != nil {
		if err := s.historyRepo.HealthCheck(ctx); err != nil {
			if s.logProducer != nil {
				event := &models.DeviceLogEvent{
					Action:       "health_check",
					Status:       "failed",
					ErrorCode:    "HISTORY_REPO_HEALTH_FAILED",
					ErrorMessage: err.Error(),
					Duration:     int64(time.Since(startTime).Milliseconds()),
				}
				_ = s.logProducer.ProduceDeviceEvent(ctx, event)
			}
			return fmt.Errorf("history repository health check failed: %w", err)
		}
	}

	if s.logProducer != nil {
		event := &models.DeviceLogEvent{
			Action:   "health_check",
			Status:   "success",
			Duration: int64(time.Since(startTime).Milliseconds()),
		}
		_ = s.logProducer.ProduceDeviceEvent(ctx, event)
	}

	return nil
}

// GetServiceStats returns service statistics
func (s *DeviceService) GetServiceStats(ctx context.Context) (map[string]interface{}, error) {
	startTime := time.Now()

	stats, err := s.deviceRepo.GetRepositoryStats(ctx)
	if err != nil {
		if s.logProducer != nil {
			event := &models.DeviceLogEvent{
				Action:       "get_service_stats",
				Status:       "failed",
				ErrorCode:    "GET_STATS_FAILED",
				ErrorMessage: err.Error(),
				Duration:     int64(time.Since(startTime).Milliseconds()),
			}
			_ = s.logProducer.ProduceDeviceEvent(ctx, event)
		}
		return nil, fmt.Errorf("failed to get service stats: %w", err)
	}

	if s.logProducer != nil {
		event := &models.DeviceLogEvent{
			Action:   "get_service_stats",
			Status:   "success",
			Duration: int64(time.Since(startTime).Milliseconds()),
		}
		_ = s.logProducer.ProduceDeviceEvent(ctx, event)
	}

	return stats, nil
}

// IsDeviceTrusted checks if a device is trusted for a user
func (s *DeviceService) IsDeviceTrusted(ctx context.Context, userID uuid.UUID, deviceID string) (bool, error) {
	startTime := time.Now()

	// Get active device for user
	activeDevice, err := s.deviceRepo.GetActiveDevice(ctx, userID)
	if err != nil {
		s.logger.Warn("Failed to get active device for trust check",
			util.String("user_id", userID.String()),
			util.String("device_id", deviceID),
			util.ErrorField(err))
		return false, err
	}

	if activeDevice == nil {
		return false, nil
	}

	isTrusted := activeDevice.DeviceID == deviceID

	s.logger.Debug("Device trust check completed",
		util.String("user_id", userID.String()),
		util.String("device_id", deviceID),
		util.Bool("is_trusted", isTrusted),
		util.Duration("duration", time.Since(startTime)))

	return isTrusted, nil
}

// ===============================
// Device Trust Management Methods
// ===============================

// GetDeviceTrustLevel retrieves the trust level for a device
func (s *DeviceService) GetDeviceTrustLevel(
	ctx context.Context,
	userID uuid.UUID,
	deviceID string,
) (*DeviceTrustResponse, error) {
	startTime := time.Now()

	trustLevel, err := s.deviceTrustRepo.GetDeviceTrustLevel(ctx, userID, deviceID)
	if err != nil {
		if s.logProducer != nil {
			event := &models.DeviceLogEvent{
				UserID:       userID.String(),
				DeviceID:     deviceID,
				Action:       "get_trust_level",
				Status:       "failed",
				ErrorCode:    "GET_TRUST_FAILED",
				ErrorMessage: err.Error(),
				Duration:     int64(time.Since(startTime).Milliseconds()),
			}
			_ = s.logProducer.ProduceDeviceEvent(ctx, event)
		}
		return nil, fmt.Errorf("failed to get device trust level: %w", err)
	}

	if s.logProducer != nil {
		event := &models.DeviceLogEvent{
			UserID:   userID.String(),
			DeviceID: deviceID,
			Action:   "get_trust_level",
			Status:   "success",
			Duration: int64(time.Since(startTime).Milliseconds()),
		}
		_ = s.logProducer.ProduceDeviceEvent(ctx, event)
	}

	return &DeviceTrustResponse{
		Success:    true,
		TrustLevel: trustLevel,
		RiskScore:  trustLevel.RiskScore,
		IsBlocked:  trustLevel.IsBlocked,
	}, nil
}

// SetDeviceTrustLevel updates the trust level for a device
func (s *DeviceService) SetDeviceTrustLevel(
	ctx context.Context,
	req DeviceTrustRequest,
) (*DeviceTrustResponse, error) {
	startTime := time.Now()

	// Calculate IP subnet and location hash
	ipSubnet := s.extractIPSubnet(req.IPAddress)
	locationHash := s.hashLocation(req.IPAddress, req.UserAgent)

	trustLevel := &models.DeviceTrustLevel{
		UserID:            req.UserID,
		DeviceID:          req.DeviceID,
		TrustStatus:       req.TrustStatus,
		DeviceFingerprint: req.DeviceFingerprint,
		OSVersion:         req.OSVersion,
		AppVersion:        req.AppVersion,
		LastIPAddress:     req.IPAddress,
		LastIPSubnet:      ipSubnet,
		LastLocationHash:  locationHash,
		UserAgent:         req.UserAgent,
		DeviceModel:       req.DeviceModel,
		RiskScore:         s.calculateRiskScore(req.TrustStatus),
		IsBlocked:         false,
	}

	if err := s.deviceTrustRepo.SetDeviceTrustLevel(ctx, req.UserID, req.DeviceID, trustLevel); err != nil {
		if s.logProducer != nil {
			event := &models.DeviceLogEvent{
				UserID:       req.UserID.String(),
				DeviceID:     req.DeviceID,
				Action:       "set_trust_level",
				Status:       "failed",
				ErrorCode:    "SET_TRUST_FAILED",
				ErrorMessage: err.Error(),
				IPAddress:    req.IPAddress,
				Duration:     int64(time.Since(startTime).Milliseconds()),
			}
			_ = s.logProducer.ProduceDeviceEvent(ctx, event)
		}
		return nil, fmt.Errorf("failed to set device trust level: %w", err)
	}

	if s.logProducer != nil {
		event := &models.DeviceLogEvent{
			UserID:    req.UserID.String(),
			DeviceID:  req.DeviceID,
			Action:    "set_trust_level",
			Status:    "success",
			IPAddress: req.IPAddress,
			Duration:  int64(time.Since(startTime).Milliseconds()),
		}
		_ = s.logProducer.ProduceDeviceEvent(ctx, event)
	}

	s.logger.Info("Device trust level updated",
		util.String("user_id", req.UserID.String()),
		util.String("device_id", req.DeviceID),
		util.String("trust_status", string(req.TrustStatus)),
		util.Int("risk_score", trustLevel.RiskScore))

	return &DeviceTrustResponse{
		Success:    true,
		TrustLevel: trustLevel,
		RiskScore:  trustLevel.RiskScore,
		IsBlocked:  trustLevel.IsBlocked,
	}, nil
}

// MarkSuccessfulLogin updates device trust after successful login
func (s *DeviceService) MarkSuccessfulLogin(
	ctx context.Context,
	userID uuid.UUID,
	deviceID string,
	ipAddress string,
	userAgent string,
	deviceFingerprint string,
) error {
	startTime := time.Now()

	ipSubnet := s.extractIPSubnet(ipAddress)
	locationHash := s.hashLocation(ipAddress, userAgent)

	trustLevel := &models.DeviceTrustLevel{
		UserID:            userID,
		DeviceID:          deviceID,
		LastIPAddress:     ipAddress,
		LastIPSubnet:      ipSubnet,
		LastLocationHash:  locationHash,
		UserAgent:         userAgent,
		DeviceFingerprint: deviceFingerprint,
		RiskScore:         0, // Will be calculated by the repository
	}

	if err := s.deviceTrustRepo.MarkSuccessfulLogin(ctx, userID, deviceID, trustLevel); err != nil {
		if s.logProducer != nil {
			event := &models.DeviceLogEvent{
				UserID:       userID.String(),
				DeviceID:     deviceID,
				Action:       "mark_successful_login",
				Status:       "failed",
				ErrorCode:    "MARK_LOGIN_FAILED",
				ErrorMessage: err.Error(),
				IPAddress:    ipAddress,
				Duration:     int64(time.Since(startTime).Milliseconds()),
			}
			_ = s.logProducer.ProduceDeviceEvent(ctx, event)
		}
		return fmt.Errorf("failed to mark successful login: %w", err)
	}

	if s.logProducer != nil {
		event := &models.DeviceLogEvent{
			UserID:    userID.String(),
			DeviceID:  deviceID,
			Action:    "mark_successful_login",
			Status:    "success",
			IPAddress: ipAddress,
			Duration:  int64(time.Since(startTime).Milliseconds()),
		}
		_ = s.logProducer.ProduceDeviceEvent(ctx, event)
	}

	s.logger.Info("Successful login marked for device",
		util.String("user_id", userID.String()),
		util.String("device_id", deviceID),
		util.String("ip_address", ipAddress))

	return nil
}

// BlockDevice blocks a device for a user
func (s *DeviceService) BlockDevice(ctx context.Context, userID uuid.UUID, deviceID string) error {
	startTime := time.Now()

	if err := s.deviceTrustRepo.BlockDevice(ctx, userID, deviceID); err != nil {
		if s.logProducer != nil {
			event := &models.DeviceLogEvent{
				UserID:       userID.String(),
				DeviceID:     deviceID,
				Action:       "block_device",
				Status:       "failed",
				ErrorCode:    "BLOCK_DEVICE_FAILED",
				ErrorMessage: err.Error(),
				Duration:     int64(time.Since(startTime).Milliseconds()),
			}
			_ = s.logProducer.ProduceDeviceEvent(ctx, event)
		}
		return fmt.Errorf("failed to block device: %w", err)
	}

	if s.logProducer != nil {
		event := &models.DeviceLogEvent{
			UserID:   userID.String(),
			DeviceID: deviceID,
			Action:   "block_device",
			Status:   "success",
			Duration: int64(time.Since(startTime).Milliseconds()),
		}
		_ = s.logProducer.ProduceDeviceEvent(ctx, event)
	}

	s.logger.Warn("Device blocked",
		util.String("user_id", userID.String()),
		util.String("device_id", deviceID))

	return nil
}

// GetUserDevices retrieves all devices for a user
func (s *DeviceService) GetUserDevices(ctx context.Context, userID uuid.UUID) ([]*models.DeviceTrustLevel, error) {
	startTime := time.Now()

	devices, err := s.deviceTrustRepo.GetUserDevices(ctx, userID)
	if err != nil {
		if s.logProducer != nil {
			event := &models.DeviceLogEvent{
				UserID:       userID.String(),
				Action:       "get_user_devices",
				Status:       "failed",
				ErrorCode:    "GET_DEVICES_FAILED",
				ErrorMessage: err.Error(),
				Duration:     int64(time.Since(startTime).Milliseconds()),
			}
			_ = s.logProducer.ProduceDeviceEvent(ctx, event)
		}
		return nil, fmt.Errorf("failed to get user devices: %w", err)
	}

	if s.logProducer != nil {
		event := &models.DeviceLogEvent{
			UserID:   userID.String(),
			Action:   "get_user_devices",
			Status:   "success",
			Duration: int64(time.Since(startTime).Milliseconds()),
		}
		_ = s.logProducer.ProduceDeviceEvent(ctx, event)
	}

	return devices, nil
}

// UpdateDeviceRiskScore updates the risk score for a device
func (s *DeviceService) UpdateDeviceRiskScore(
	ctx context.Context,
	userID uuid.UUID,
	deviceID string,
	riskScore int,
) error {
	startTime := time.Now()

	if err := s.deviceTrustRepo.UpdateDeviceRiskScore(ctx, userID, deviceID, riskScore); err != nil {
		if s.logProducer != nil {
			event := &models.DeviceLogEvent{
				UserID:       userID.String(),
				DeviceID:     deviceID,
				Action:       "update_risk_score",
				Status:       "failed",
				ErrorCode:    "UPDATE_RISK_FAILED",
				ErrorMessage: err.Error(),
				Duration:     int64(time.Since(startTime).Milliseconds()),
			}
			_ = s.logProducer.ProduceDeviceEvent(ctx, event)
		}
		return fmt.Errorf("failed to update device risk score: %w", err)
	}

	if s.logProducer != nil {
		event := &models.DeviceLogEvent{
			UserID:   userID.String(),
			DeviceID: deviceID,
			Action:   "update_risk_score",
			Status:   "success",
			Duration: int64(time.Since(startTime).Milliseconds()),
		}
		_ = s.logProducer.ProduceDeviceEvent(ctx, event)
	}

	s.logger.Debug("Device risk score updated",
		util.String("user_id", userID.String()),
		util.String("device_id", deviceID),
		util.Int("risk_score", riskScore))

	return nil
}

// ===============================
// Admin Device Trust Methods
// ===============================

// GetAdminDeviceTrustLevel retrieves trust level for admin device
func (s *DeviceService) GetAdminDeviceTrustLevel(
	ctx context.Context,
	adminID uuid.UUID,
	deviceID string,
) (*DeviceTrustResponse, error) {
	startTime := time.Now()

	trustLevel, err := s.adminDeviceTrustRepo.GetAdminDeviceTrustLevel(ctx, adminID, deviceID)
	if err != nil {
		if s.logProducer != nil {
			event := &models.DeviceLogEvent{
				UserID:       adminID.String(),
				DeviceID:     deviceID,
				Action:       "get_admin_trust_level",
				Status:       "failed",
				ErrorCode:    "GET_ADMIN_TRUST_FAILED",
				ErrorMessage: err.Error(),
				Duration:     int64(time.Since(startTime).Milliseconds()),
			}
			_ = s.logProducer.ProduceDeviceEvent(ctx, event)
		}
		return nil, fmt.Errorf("failed to get admin device trust level: %w", err)
	}

	if s.logProducer != nil {
		event := &models.DeviceLogEvent{
			UserID:   adminID.String(),
			DeviceID: deviceID,
			Action:   "get_admin_trust_level",
			Status:   "success",
			Duration: int64(time.Since(startTime).Milliseconds()),
		}
		_ = s.logProducer.ProduceDeviceEvent(ctx, event)
	}

	return &DeviceTrustResponse{
		Success:    true,
		TrustLevel: trustLevel,
		RiskScore:  trustLevel.RiskScore,
		IsBlocked:  trustLevel.IsBlocked,
	}, nil
}

// MarkAdminSuccessfulLogin updates admin device trust after successful login
func (s *DeviceService) MarkAdminSuccessfulLogin(
	ctx context.Context,
	adminID uuid.UUID,
	deviceID string,
	ipAddress string,
	userAgent string,
	deviceFingerprint string,
) error {
	startTime := time.Now()

	ipSubnet := s.extractIPSubnet(ipAddress)
	locationHash := s.hashLocation(ipAddress, userAgent)

	trustLevel := &models.DeviceTrustLevel{
		UserID:            adminID,
		DeviceID:          deviceID,
		LastIPAddress:     ipAddress,
		LastIPSubnet:      ipSubnet,
		LastLocationHash:  locationHash,
		UserAgent:         userAgent,
		DeviceFingerprint: deviceFingerprint,
		RiskScore:         0,
	}

	if err := s.adminDeviceTrustRepo.MarkAdminSuccessfulLogin(ctx, adminID, deviceID, trustLevel); err != nil {
		if s.logProducer != nil {
			event := &models.DeviceLogEvent{
				UserID:       adminID.String(),
				DeviceID:     deviceID,
				Action:       "mark_admin_successful_login",
				Status:       "failed",
				ErrorCode:    "MARK_ADMIN_LOGIN_FAILED",
				ErrorMessage: err.Error(),
				IPAddress:    ipAddress,
				Duration:     int64(time.Since(startTime).Milliseconds()),
			}
			_ = s.logProducer.ProduceDeviceEvent(ctx, event)
		}
		return fmt.Errorf("failed to mark admin successful login: %w", err)
	}

	if s.logProducer != nil {
		event := &models.DeviceLogEvent{
			UserID:    adminID.String(),
			DeviceID:  deviceID,
			Action:    "mark_admin_successful_login",
			Status:    "success",
			IPAddress: ipAddress,
			Duration:  int64(time.Since(startTime).Milliseconds()),
		}
		_ = s.logProducer.ProduceDeviceEvent(ctx, event)
	}

	s.logger.Info("Successful login marked for admin device",
		util.String("admin_id", adminID.String()),
		util.String("device_id", deviceID),
		util.String("ip_address", ipAddress))

	return nil
}

// BlockAdminDevice blocks an admin device
func (s *DeviceService) BlockAdminDevice(ctx context.Context, adminID uuid.UUID, deviceID string) error {
	startTime := time.Now()

	if err := s.adminDeviceTrustRepo.BlockAdminDevice(ctx, adminID, deviceID); err != nil {
		if s.logProducer != nil {
			event := &models.DeviceLogEvent{
				UserID:       adminID.String(),
				DeviceID:     deviceID,
				Action:       "block_admin_device",
				Status:       "failed",
				ErrorCode:    "BLOCK_ADMIN_DEVICE_FAILED",
				ErrorMessage: err.Error(),
				Duration:     int64(time.Since(startTime).Milliseconds()),
			}
			_ = s.logProducer.ProduceDeviceEvent(ctx, event)
		}
		return fmt.Errorf("failed to block admin device: %w", err)
	}

	if s.logProducer != nil {
		event := &models.DeviceLogEvent{
			UserID:   adminID.String(),
			DeviceID: deviceID,
			Action:   "block_admin_device",
			Status:   "success",
			Duration: int64(time.Since(startTime).Milliseconds()),
		}
		_ = s.logProducer.ProduceDeviceEvent(ctx, event)
	}

	s.logger.Warn("Admin device blocked",
		util.String("admin_id", adminID.String()),
		util.String("device_id", deviceID))

	return nil
}

// ===============================
// Helper Methods
// ===============================

// generateBindToken generates a cryptographically secure bind token
func (s *DeviceService) generateBindToken() (string, error) {
	b := make([]byte, 32) // 256 bits
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return base64.URLEncoding.EncodeToString(b), nil
}

// extractIPSubnet extracts /24 subnet from IP address
func (s *DeviceService) extractIPSubnet(ipAddress string) string {
	if ipAddress == "" {
		return ""
	}

	ip := net.ParseIP(ipAddress)
	if ip == nil {
		return ""
	}

	if ip.To4() != nil {
		// IPv4: extract /24 subnet
		ip = ip.To4()
		return fmt.Sprintf("%d.%d.%d.0/24", ip[0], ip[1], ip[2])
	}

	// IPv6: extract /64 subnet (first 64 bits)
	return fmt.Sprintf("%s/64", ip.Mask(net.CIDRMask(64, 128)).String())
}

// hashLocation creates a location hash from IP and UserAgent
func (s *DeviceService) hashLocation(ipAddress, userAgent string) string {
	if ipAddress == "" && userAgent == "" {
		return ""
	}

	// Simple hash combining IP subnet and user agent characteristics
	locationData := s.extractIPSubnet(ipAddress) + "|" + s.extractUserAgentFeatures(userAgent)
	return util.HashString(locationData)
}

// extractUserAgentFeatures extracts key features from UserAgent
func (s *DeviceService) extractUserAgentFeatures(userAgent string) string {
	if userAgent == "" {
		return ""
	}

	features := []string{}

	// Extract browser/device type
	if strings.Contains(strings.ToLower(userAgent), "mobile") {
		features = append(features, "mobile")
	} else {
		features = append(features, "desktop")
	}

	// Extract OS family
	switch {
	case strings.Contains(strings.ToLower(userAgent), "windows"):
		features = append(features, "windows")
	case strings.Contains(strings.ToLower(userAgent), "mac os"):
		features = append(features, "macos")
	case strings.Contains(strings.ToLower(userAgent), "linux"):
		features = append(features, "linux")
	case strings.Contains(strings.ToLower(userAgent), "android"):
		features = append(features, "android")
	case strings.Contains(strings.ToLower(userAgent), "ios"):
		features = append(features, "ios")
	}

	return strings.Join(features, "|")
}

// calculateRiskScore calculates risk score based on trust status
func (s *DeviceService) calculateRiskScore(trustStatus models.DeviceTrustStatus) int {
	switch trustStatus {
	case models.TrustStatusPrimary:
		return 10
	case models.TrustStatusTrusted:
		return 30
	case models.TrustStatusUntrusted:
		return 70
	default:
		return 50
	}
}

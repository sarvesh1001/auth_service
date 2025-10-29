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
	historyRepo  *scylla.DeviceHistoryRepositoryImpl // ✅ ADD THIS
	distCache    *DistributedCache
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

// Request/Response types

type BindDeviceRequest struct {
	UserID   uuid.UUID `json:"user_id" validate:"required"`
	DeviceID string    `json:"device_id" validate:"required"`
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
		return nil, fmt.Errorf("failed to generate bind token: %w", err)
	}

	// Bind device in repository
	if err := s.deviceRepo.BindUserDevice(ctx, req.UserID, req.DeviceID, bindToken); err != nil {
		return nil, fmt.Errorf("failed to bind device: %w", err)
	}

	// Record in history ✅ ADD THIS
	if s.historyRepo != nil {
		if err := s.historyRepo.RecordBinding(ctx, req.UserID, req.DeviceID, nil, bindToken, "bind"); err != nil {
			s.logger.Warn("Failed to record binding in history",
				util.ErrorField(err),
				util.String("user_id", req.UserID.String()),
				util.String("device_id", req.DeviceID))
			// Don't fail the request if history recording fails
		}
	}

	// Invalidate cache
	if s.distCache != nil {
		cacheKey := fmt.Sprintf("device:%s", req.UserID.String())
		s.distCache.DeleteKey(ctx, cacheKey)
	}

	s.logger.Info("Device bound successfully",
		util.String("user_id", req.UserID.String()),
		util.String("device_id", req.DeviceID),
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
func (s *DeviceService) UnbindDevice(ctx context.Context, userID uuid.UUID) error {
	// Get device before unbinding for history ✅ ADD THIS
	device, err := s.deviceRepo.GetActiveDevice(ctx, userID)
	if err != nil {
		return fmt.Errorf("failed to get active device: %w", err)
	}

	if err := s.deviceRepo.UnbindUserDevice(ctx, userID); err != nil {
		return fmt.Errorf("failed to unbind device: %w", err)
	}

	// Record unbind in history ✅ ADD THIS
	if device != nil && s.historyRepo != nil {
		if err := s.historyRepo.RecordBinding(ctx, userID, device.DeviceID, nil, device.BindToken, "unbind"); err != nil {
			s.logger.Warn("Failed to record unbind in history",
				util.ErrorField(err),
				util.String("user_id", userID.String()),
				util.String("device_id", device.DeviceID))
			// Don't fail the request if history recording fails
		}
	}

	// Invalidate cache
	if s.distCache != nil {
		cacheKey := fmt.Sprintf("device:%s", userID.String())
		s.distCache.DeleteKey(ctx, cacheKey)
	}

	s.logger.Info("Device unbound successfully", util.String("user_id", userID.String()))
	return nil
}

// UpdateDeviceSession updates the session ID for a device
func (s *DeviceService) UpdateDeviceSession(
	ctx context.Context,
	userID, sessionID uuid.UUID,
) error {
	if err := s.deviceRepo.UpdateDeviceSession(ctx, userID, sessionID); err != nil {
		return fmt.Errorf("failed to update device session: %w", err)
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
	isValid, err := s.deviceRepo.ValidateDeviceBinding(
		ctx,
		req.UserID,
		req.DeviceID,
		req.BindToken,
	)

	if err != nil {
		return nil, fmt.Errorf("failed to validate device: %w", err)
	}

	response := &ValidateDeviceResponse{
		IsValid: isValid,
	}

	if !isValid {
		response.Message = "Invalid device binding"
	}

	return response, nil
}

// GetDeviceBindingHistory retrieves device history from history table ✅ UPDATED
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

// GetUsersByDevice finds all users for a device ✅ UPDATED
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
	cutoffTime := time.Now().Add(-olderThan)
	count, err := s.deviceRepo.CleanupOrphanedDevices(ctx, cutoffTime)
	if err != nil {
		return 0, fmt.Errorf("failed to cleanup orphaned devices: %w", err)
	}

	s.logger.Info("Cleaned up orphaned devices",
		util.Int("count", count),
		util.Duration("older_than", olderThan))

	return count, nil
}

// HealthCheck checks service health ✅ UPDATED
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

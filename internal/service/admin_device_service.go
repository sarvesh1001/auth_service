

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

// AdminDeviceService handles admin device management business logic
type AdminDeviceService struct {
	deviceRepo      *scylla.AdminDeviceRepositoryImpl
	historyRepo     *scylla.AdminDeviceHistoryRepositoryImpl // ✅ Changed from AdminDeviceTrustRepository
	trustRepo       scylla.AdminDeviceTrustRepository
	mpinRepo        *scylla.AdminMPINRepositoryImpl
	distCache       *DistributedCache
	logProducer     *LogProducerService
	config          config.Config
	logger          *zap.Logger
}

// NewAdminDeviceService creates a new admin device service
func NewAdminDeviceService(
	deviceRepo *scylla.AdminDeviceRepositoryImpl,
	trustRepo scylla.AdminDeviceTrustRepository,
	mpinRepo *scylla.AdminMPINRepositoryImpl,
	distCache *DistributedCache,
	config config.Config,
	logger *zap.Logger,
) *AdminDeviceService {
	return &AdminDeviceService{
		deviceRepo: deviceRepo,
		trustRepo:  trustRepo,
		mpinRepo:   mpinRepo,
		distCache:  distCache,
		config:     config,
		logger:     logger,
	}
}

// SetHistoryRepository sets the history repository for tracking admin device binding changes
func (s *AdminDeviceService) SetHistoryRepository(historyRepo *scylla.AdminDeviceHistoryRepositoryImpl) {
	s.historyRepo = historyRepo
}

// SetLogProducerService sets the log producer service
func (s *AdminDeviceService) SetLogProducerService(logProducer *LogProducerService) {
	s.logProducer = logProducer
}

// Request/Response types (similar to user device service)

type AdminBindDeviceRequest struct {
	AdminID   uuid.UUID `json:"admin_id" validate:"required"`
	DeviceID  string    `json:"device_id" validate:"required"`
	IPAddress string    `json:"ip_address,omitempty"`
	UserAgent string    `json:"user_agent,omitempty"`
}

type AdminBindDeviceResponse struct {
	BindToken string    `json:"bind_token"`
	BoundAt   time.Time `json:"bound_at"`
	Success   bool      `json:"success"`
}

type AdminValidateDeviceRequest struct {
	AdminID   uuid.UUID `json:"admin_id" validate:"required"`
	DeviceID  string    `json:"device_id" validate:"required"`
	BindToken string    `json:"bind_token" validate:"required"`
	IPAddress string    `json:"ip_address,omitempty"`
}

type AdminValidateDeviceResponse struct {
	IsValid bool   `json:"is_valid"`
	Message string `json:"message,omitempty"`
}

// BindDevice creates an admin device binding with a generated token
func (s *AdminDeviceService) BindDevice(
	ctx context.Context,
	req AdminBindDeviceRequest,
) (*AdminBindDeviceResponse, error) {
	startTime := time.Now()

	// Generate cryptographically secure bind token
	bindToken, err := s.generateBindToken()
	if err != nil {
		// ✅ Log failure event
		if s.logProducer != nil {
			event := &models.DeviceLogEvent{
				UserID:       req.AdminID.String(),
				DeviceID:     req.DeviceID,
				Action:       "admin_bind",
				Status:       "failed",
				ErrorCode:    "TOKEN_GENERATION_FAILED",
				ErrorMessage: err.Error(),
				IPAddress:    req.IPAddress,
				Duration:     int64(time.Since(startTime).Milliseconds()),
			}
			_ = s.logProducer.ProduceDeviceEvent(ctx, event)
		}
		return nil, fmt.Errorf("failed to generate admin bind token: %w", err)
	}

	// Bind device in repository
	if err := s.deviceRepo.BindAdminDevice(ctx, req.AdminID, req.DeviceID, bindToken); err != nil {
		// ✅ Log failure event
		if s.logProducer != nil {
			event := &models.DeviceLogEvent{
				UserID:       req.AdminID.String(),
				DeviceID:     req.DeviceID,
				Action:       "admin_bind",
				Status:       "failed",
				ErrorCode:    "BIND_FAILED",
				ErrorMessage: err.Error(),
				IPAddress:    req.IPAddress,
				Duration:     int64(time.Since(startTime).Milliseconds()),
			}
			_ = s.logProducer.ProduceDeviceEvent(ctx, event)
		}
		return nil, fmt.Errorf("failed to bind admin device: %w", err)
	}

	// Record in history
	if s.historyRepo != nil {
		if err := s.historyRepo.RecordAdminBinding(ctx, req.AdminID, req.DeviceID, nil, bindToken, "bind"); err != nil {
			s.logger.Warn("Failed to record admin binding in history",
				util.ErrorField(err),
				util.String("admin_id", req.AdminID.String()),
				util.String("device_id", req.DeviceID))
			// Don't fail the request if history recording fails
		}
	}

	// Update device trust level
	if s.trustRepo != nil {
		if err := s.trustRepo.MarkAdminSuccessfulLogin(ctx, req.AdminID, req.DeviceID, req.IPAddress, req.UserAgent); err != nil {
			s.logger.Warn("Failed to update admin device trust level",
				util.ErrorField(err),
				util.String("admin_id", req.AdminID.String()),
				util.String("device_id", req.DeviceID))
		}
	}

	// ✅ Log success event
	if s.logProducer != nil {
		event := &models.DeviceLogEvent{
			UserID:    req.AdminID.String(),
			DeviceID:  req.DeviceID,
			Action:    "admin_bind",
			Status:    "success",
			BindToken: bindToken,
			IPAddress: req.IPAddress,
			Duration:  int64(time.Since(startTime).Milliseconds()),
		}
		_ = s.logProducer.ProduceDeviceEvent(ctx, event)
	}

	// Invalidate cache
	if s.distCache != nil {
		cacheKey := fmt.Sprintf("admin_device:%s", req.AdminID.String())
		s.distCache.DeleteKey(ctx, cacheKey)
	}

	s.logger.Info("Admin device bound successfully",
		util.String("admin_id", req.AdminID.String()),
		util.String("device_id", req.DeviceID),
		util.String("ip_address", req.IPAddress),
		util.Duration("duration", time.Since(startTime)))

	return &AdminBindDeviceResponse{
		BindToken: bindToken,
		BoundAt:   time.Now().UTC(),
		Success:   true,
	}, nil
}

// GetActiveDevice retrieves the active device for an admin (with caching)
func (s *AdminDeviceService) GetActiveDevice(
	ctx context.Context,
	adminID uuid.UUID,
) (*models.UserActiveDevice, error) {
	startTime := time.Now()

	// Try cache first
	if s.distCache != nil {
		cacheKey := fmt.Sprintf("admin_device:%s", adminID.String())
		var cachedDevice models.UserActiveDevice
		if err := s.distCache.Get(ctx, cacheKey, &cachedDevice); err == nil {
			s.logger.Debug("Admin device cache hit", util.String("admin_id", adminID.String()))
			return &cachedDevice, nil
		}
	}

	// Cache miss - fetch from database
	device, err := s.deviceRepo.GetAdminActiveDevice(ctx, adminID)
	if err != nil {
		// ✅ Log failure event
		if s.logProducer != nil {
			event := &models.DeviceLogEvent{
				UserID:       adminID.String(),
				Action:       "admin_get_active_device",
				Status:       "failed",
				ErrorCode:    "GET_DEVICE_FAILED",
				ErrorMessage: err.Error(),
				Duration:     int64(time.Since(startTime).Milliseconds()),
			}
			_ = s.logProducer.ProduceDeviceEvent(ctx, event)
		}
		return nil, fmt.Errorf("failed to get active admin device: %w", err)
	}

	// Cache the result
	if device != nil && s.distCache != nil {
		cacheKey := fmt.Sprintf("admin_device:%s", adminID.String())
		s.distCache.SetWithExpiry(ctx, cacheKey, device, 5*time.Minute)
	}

	// ✅ Log success event
	if s.logProducer != nil && device != nil {
		event := &models.DeviceLogEvent{
			UserID:    adminID.String(),
			DeviceID:  device.DeviceID,
			Action:    "admin_get_active_device",
			Status:    "success",
			Duration:  int64(time.Since(startTime).Milliseconds()),
		}
		_ = s.logProducer.ProduceDeviceEvent(ctx, event)
	}

	return device, nil
}

// UnbindDevice removes an admin device binding
func (s *AdminDeviceService) UnbindDevice(ctx context.Context, adminID uuid.UUID, ipAddress string) error {
	startTime := time.Now()

	// Get device before unbinding for history
	device, err := s.deviceRepo.GetAdminActiveDevice(ctx, adminID)
	if err != nil {
		// ✅ Log failure event
		if s.logProducer != nil {
			event := &models.DeviceLogEvent{
				UserID:       adminID.String(),
				Action:       "admin_unbind",
				Status:       "failed",
				ErrorCode:    "GET_DEVICE_FAILED",
				ErrorMessage: err.Error(),
				IPAddress:    ipAddress,
				Duration:     int64(time.Since(startTime).Milliseconds()),
			}
			_ = s.logProducer.ProduceDeviceEvent(ctx, event)
		}
		return fmt.Errorf("failed to get active admin device: %w", err)
	}

	if err := s.deviceRepo.UnbindAdminDevice(ctx, adminID); err != nil {
		// ✅ Log failure event
		if s.logProducer != nil && device != nil {
			event := &models.DeviceLogEvent{
				UserID:       adminID.String(),
				DeviceID:     device.DeviceID,
				Action:       "admin_unbind",
				Status:       "failed",
				ErrorCode:    "UNBIND_FAILED",
				ErrorMessage: err.Error(),
				IPAddress:    ipAddress,
				Duration:     int64(time.Since(startTime).Milliseconds()),
			}
			_ = s.logProducer.ProduceDeviceEvent(ctx, event)
		}
		return fmt.Errorf("failed to unbind admin device: %w", err)
	}

	// Record unbind in history
	if device != nil && s.historyRepo != nil {
		if err := s.historyRepo.RecordAdminBinding(ctx, adminID, device.DeviceID, nil, device.BindToken, "unbind"); err != nil {
			s.logger.Warn("Failed to record admin unbind in history",
				util.ErrorField(err),
				util.String("admin_id", adminID.String()),
				util.String("device_id", device.DeviceID))
		}
	}

	// ✅ Log success event
	if s.logProducer != nil && device != nil {
		event := &models.DeviceLogEvent{
			UserID:    adminID.String(),
			DeviceID:  device.DeviceID,
			Action:    "admin_unbind",
			Status:    "success",
			IPAddress: ipAddress,
			Duration:  int64(time.Since(startTime).Milliseconds()),
		}
		_ = s.logProducer.ProduceDeviceEvent(ctx, event)
	}

	// Invalidate cache
	if s.distCache != nil {
		cacheKey := fmt.Sprintf("admin_device:%s", adminID.String())
		s.distCache.DeleteKey(ctx, cacheKey)
	}

	s.logger.Info("Admin device unbound successfully", 
		util.String("admin_id", adminID.String()),
		util.String("ip_address", ipAddress))
	return nil
}

// UpdateDeviceSession updates the session ID for an admin device
func (s *AdminDeviceService) UpdateDeviceSession(
	ctx context.Context,
	adminID, sessionID uuid.UUID,
	ipAddress string,
) error {
	startTime := time.Now()

	if err := s.deviceRepo.UpdateAdminDeviceSession(ctx, adminID, sessionID); err != nil {
		// ✅ Log failure event
		if s.logProducer != nil {
			event := &models.DeviceLogEvent{
				UserID:       adminID.String(),
				Action:       "admin_update_session",
				Status:       "failed",
				ErrorCode:    "UPDATE_SESSION_FAILED",
				ErrorMessage: err.Error(),
				IPAddress:    ipAddress,
				Duration:     int64(time.Since(startTime).Milliseconds()),
			}
			_ = s.logProducer.ProduceDeviceEvent(ctx, event)
		}
		return fmt.Errorf("failed to update admin device session: %w", err)
	}

	// ✅ Log success event
	if s.logProducer != nil {
		event := &models.DeviceLogEvent{
			UserID:    adminID.String(),
			Action:    "admin_update_session",
			Status:    "success",
			SessionID: sessionID.String(),
			IPAddress: ipAddress,
			Duration:  int64(time.Since(startTime).Milliseconds()),
		}
		_ = s.logProducer.ProduceDeviceEvent(ctx, event)
	}

	// Invalidate cache
	if s.distCache != nil {
		cacheKey := fmt.Sprintf("admin_device:%s", adminID.String())
		s.distCache.DeleteKey(ctx, cacheKey)
	}

	return nil
}

// ValidateDevice validates an admin device binding
func (s *AdminDeviceService) ValidateDevice(
	ctx context.Context,
	req AdminValidateDeviceRequest,
) (*AdminValidateDeviceResponse, error) {
	startTime := time.Now()

	isValid, err := s.deviceRepo.ValidateAdminDeviceBinding(
		ctx,
		req.AdminID,
		req.DeviceID,
		req.BindToken,
	)

	response := &AdminValidateDeviceResponse{
		IsValid: isValid,
	}

	if err != nil {
		// ✅ Log failure event
		if s.logProducer != nil {
			event := &models.DeviceLogEvent{
				UserID:       req.AdminID.String(),
				DeviceID:     req.DeviceID,
				Action:       "admin_validate",
				Status:       "failed",
				ErrorCode:    "VALIDATION_ERROR",
				ErrorMessage: err.Error(),
				IPAddress:    req.IPAddress,
				Duration:     int64(time.Since(startTime).Milliseconds()),
			}
			_ = s.logProducer.ProduceDeviceEvent(ctx, event)
		}
		return nil, fmt.Errorf("failed to validate admin device: %w", err)
	}

	if !isValid {
		response.Message = "Invalid admin device binding"
		// ✅ Log validation failure
		if s.logProducer != nil {
			event := &models.DeviceLogEvent{
				UserID:    req.AdminID.String(),
				DeviceID:  req.DeviceID,
				Action:    "admin_validate",
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
				UserID:    req.AdminID.String(),
				DeviceID:  req.DeviceID,
				Action:    "admin_validate",
				Status:    "success",
				IPAddress: req.IPAddress,
				Duration:  int64(time.Since(startTime).Milliseconds()),
			}
			_ = s.logProducer.ProduceDeviceEvent(ctx, event)
		}
	}

	return response, nil
}

// GetDeviceBindingHistory retrieves admin device history from history table
func (s *AdminDeviceService) GetDeviceBindingHistory(
	ctx context.Context,
	adminID uuid.UUID,
	limit int,
) ([]*models.UserActiveDevice, error) {
	startTime := time.Now()

	// Use history table if available
	if s.historyRepo != nil {
		history, err := s.historyRepo.GetAdminBindingHistory(ctx, adminID, limit)
		if err != nil {
			// ✅ Log failure event
			if s.logProducer != nil {
				event := &models.DeviceLogEvent{
					UserID:       adminID.String(),
					Action:       "admin_get_binding_history",
					Status:       "failed",
					ErrorCode:    "GET_HISTORY_FAILED",
					ErrorMessage: err.Error(),
					Duration:     int64(time.Since(startTime).Milliseconds()),
				}
				_ = s.logProducer.ProduceDeviceEvent(ctx, event)
			}
			return nil, fmt.Errorf("failed to get admin binding history: %w", err)
		}

		// ✅ Log success event
		if s.logProducer != nil {
			event := &models.DeviceLogEvent{
				UserID:   adminID.String(),
				Action:   "admin_get_binding_history",
				Status:   "success",
				Duration: int64(time.Since(startTime).Milliseconds()),
			}
			_ = s.logProducer.ProduceDeviceEvent(ctx, event)
		}

		return history, nil
	}

	// Fallback to current device
	device, err := s.deviceRepo.GetAdminActiveDevice(ctx, adminID)
	if err != nil {
		// ✅ Log failure event
		if s.logProducer != nil {
			event := &models.DeviceLogEvent{
				UserID:       adminID.String(),
				Action:       "admin_get_binding_history",
				Status:       "failed",
				ErrorCode:    "GET_DEVICE_FAILED",
				ErrorMessage: err.Error(),
				Duration:     int64(time.Since(startTime).Milliseconds()),
			}
			_ = s.logProducer.ProduceDeviceEvent(ctx, event)
		}
		return nil, fmt.Errorf("failed to get active admin device: %w", err)
	}

	if device == nil {
		return []*models.UserActiveDevice{}, nil
	}

	// ✅ Log success event
	if s.logProducer != nil {
		event := &models.DeviceLogEvent{
			UserID:   adminID.String(),
			Action:   "admin_get_binding_history",
			Status:   "success",
			Duration: int64(time.Since(startTime).Milliseconds()),
		}
		_ = s.logProducer.ProduceDeviceEvent(ctx, event)
	}

	return []*models.UserActiveDevice{device}, nil
}

// GetAdminsByDevice finds all admins for a device
func (s *AdminDeviceService) GetAdminsByDevice(
	ctx context.Context,
	deviceID string,
) ([]*models.UserActiveDevice, error) {
	startTime := time.Now()

	// Use history table if available (faster with materialized view)
	if s.historyRepo != nil {
		admins, err := s.historyRepo.GetAdminRecentBindingsByDevice(ctx, deviceID, 50)
		if err != nil {
			// ✅ Log failure event
			if s.logProducer != nil {
				event := &models.DeviceLogEvent{
					DeviceID:     deviceID,
					Action:       "admin_get_admins_by_device",
					Status:       "failed",
					ErrorCode:    "GET_ADMINS_FAILED",
					ErrorMessage: err.Error(),
					Duration:     int64(time.Since(startTime).Milliseconds()),
				}
				_ = s.logProducer.ProduceDeviceEvent(ctx, event)
			}
			return nil, fmt.Errorf("failed to get admins by device from history: %w", err)
		}

		// ✅ Log success event
		if s.logProducer != nil {
			event := &models.DeviceLogEvent{
				DeviceID: deviceID,
				Action:   "admin_get_admins_by_device",
				Status:   "success",
				Duration: int64(time.Since(startTime).Milliseconds()),
			}
			_ = s.logProducer.ProduceDeviceEvent(ctx, event)
		}

		return admins, nil
	}

	// Fallback to main repository
	admins, err := s.deviceRepo.GetAdminsByDevice(ctx, deviceID)
	if err != nil {
		// ✅ Log failure event
		if s.logProducer != nil {
			event := &models.DeviceLogEvent{
				DeviceID:     deviceID,
				Action:       "admin_get_admins_by_device",
				Status:       "failed",
				ErrorCode:    "GET_ADMINS_FAILED",
				ErrorMessage: err.Error(),
				Duration:     int64(time.Since(startTime).Milliseconds()),
			}
			_ = s.logProducer.ProduceDeviceEvent(ctx, event)
		}
		return nil, fmt.Errorf("failed to get admins by device: %w", err)
	}

	// ✅ Log success event
	if s.logProducer != nil {
		event := &models.DeviceLogEvent{
			DeviceID: deviceID,
			Action:   "admin_get_admins_by_device",
			Status:   "success",
			Duration: int64(time.Since(startTime).Milliseconds()),
		}
		_ = s.logProducer.ProduceDeviceEvent(ctx, event)
	}

	return admins, nil
}

// CleanupOrphanedDevices removes old admin device bindings
func (s *AdminDeviceService) CleanupOrphanedDevices(
	ctx context.Context,
	olderThan time.Duration,
) (int, error) {
	startTime := time.Now()

	cutoffTime := time.Now().Add(-olderThan)
	count, err := s.deviceRepo.CleanupAdminOrphanedDevices(ctx, cutoffTime)
	if err != nil {
		// ✅ Log failure event
		if s.logProducer != nil {
			event := &models.DeviceLogEvent{
				Action:       "admin_cleanup_orphaned",
				Status:       "failed",
				ErrorCode:    "CLEANUP_FAILED",
				ErrorMessage: err.Error(),
				Duration:     int64(time.Since(startTime).Milliseconds()),
			}
			_ = s.logProducer.ProduceDeviceEvent(ctx, event)
		}
		return 0, fmt.Errorf("failed to cleanup orphaned admin devices: %w", err)
	}

	// ✅ Log success event
	if s.logProducer != nil {
		event := &models.DeviceLogEvent{
			Action:   "admin_cleanup_orphaned",
			Status:   "success",
			Duration: int64(time.Since(startTime).Milliseconds()),
		}
		_ = s.logProducer.ProduceDeviceEvent(ctx, event)
	}

	s.logger.Info("Cleaned up orphaned admin devices",
		util.Int("count", count),
		util.Duration("older_than", olderThan))

	return count, nil
}

// HealthCheck checks service health
func (s *AdminDeviceService) HealthCheck(ctx context.Context) error {
	startTime := time.Now()

	if err := s.deviceRepo.HealthCheck(ctx); err != nil {
		// ✅ Log failure event
		if s.logProducer != nil {
			event := &models.DeviceLogEvent{
				Action:       "admin_health_check",
				Status:       "failed",
				ErrorCode:    "DEVICE_REPO_HEALTH_FAILED",
				ErrorMessage: err.Error(),
				Duration:     int64(time.Since(startTime).Milliseconds()),
			}
			_ = s.logProducer.ProduceDeviceEvent(ctx, event)
		}
		return fmt.Errorf("admin device repository health check failed: %w", err)
	}

	if s.historyRepo != nil {
		if err := s.historyRepo.HealthCheck(ctx); err != nil {
			// ✅ Log failure event
			if s.logProducer != nil {
				event := &models.DeviceLogEvent{
					Action:       "admin_health_check",
					Status:       "failed",
					ErrorCode:    "HISTORY_REPO_HEALTH_FAILED",
					ErrorMessage: err.Error(),
					Duration:     int64(time.Since(startTime).Milliseconds()),
				}
				_ = s.logProducer.ProduceDeviceEvent(ctx, event)
			}
			return fmt.Errorf("admin history repository health check failed: %w", err)
		}
	}

	// ✅ Log success event
	if s.logProducer != nil {
		event := &models.DeviceLogEvent{
			Action:   "admin_health_check",
			Status:   "success",
			Duration: int64(time.Since(startTime).Milliseconds()),
		}
		_ = s.logProducer.ProduceDeviceEvent(ctx, event)
	}

	return nil
}

// GetServiceStats returns service statistics
func (s *AdminDeviceService) GetServiceStats(ctx context.Context) (map[string]interface{}, error) {
	startTime := time.Now()

	stats, err := s.deviceRepo.GetAdminRepositoryStats(ctx)
	if err != nil {
		// ✅ Log failure event
		if s.logProducer != nil {
			event := &models.DeviceLogEvent{
				Action:       "admin_get_service_stats",
				Status:       "failed",
				ErrorCode:    "GET_STATS_FAILED",
				ErrorMessage: err.Error(),
				Duration:     int64(time.Since(startTime).Milliseconds()),
			}
			_ = s.logProducer.ProduceDeviceEvent(ctx, event)
		}
		return nil, fmt.Errorf("failed to get admin service stats: %w", err)
	}

	// ✅ Log success event
	if s.logProducer != nil {
		event := &models.DeviceLogEvent{
			Action:   "admin_get_service_stats",
			Status:   "success",
			Duration: int64(time.Since(startTime).Milliseconds()),
		}
		_ = s.logProducer.ProduceDeviceEvent(ctx, event)
	}

	return stats, nil
}

// IsDeviceTrusted checks if a device is trusted for an admin
func (s *AdminDeviceService) IsDeviceTrusted(ctx context.Context, adminID uuid.UUID, deviceID string) (bool, error) {
	startTime := time.Now()

	// Get active device for admin
	activeDevice, err := s.deviceRepo.GetAdminActiveDevice(ctx, adminID)
	if err != nil {
		s.logger.Warn("Failed to get active device for admin trust check",
			util.String("admin_id", adminID.String()),
			util.String("device_id", deviceID),
			util.ErrorField(err))
		return false, err
	}

	if activeDevice == nil {
		return false, nil
	}

	isTrusted := activeDevice.DeviceID == deviceID

	s.logger.Debug("Admin device trust check completed",
		util.String("admin_id", adminID.String()),
		util.String("device_id", deviceID),
		util.Bool("is_trusted", isTrusted),
		util.Duration("duration", time.Since(startTime)))

	return isTrusted, nil
}

// GetDeviceTrustLevel retrieves trust level for an admin device
func (s *AdminDeviceService) GetDeviceTrustLevel(
	ctx context.Context,
	adminID uuid.UUID,
	deviceID string,
) (*models.DeviceTrustLevel, error) {
	if s.trustRepo == nil {
		return &models.DeviceTrustLevel{
			UserID:      adminID,
			DeviceID:    deviceID,
			TrustStatus: models.TrustStatusUntrusted,
			IsBlocked:   false,
		}, nil
	}

	return s.trustRepo.GetAdminDeviceTrustLevel(ctx, adminID, deviceID)
}

// BlockDevice blocks an admin device
func (s *AdminDeviceService) BlockDevice(ctx context.Context, adminID uuid.UUID, deviceID string) error {
	if s.trustRepo == nil {
		return fmt.Errorf("trust repository not available")
	}

	return s.trustRepo.BlockAdminDevice(ctx, adminID, deviceID)
}

// GetPrimaryDevice retrieves the primary trusted device for an admin
func (s *AdminDeviceService) GetPrimaryDevice(ctx context.Context, adminID uuid.UUID) (*models.DeviceTrustLevel, error) {
	if s.trustRepo == nil {
		return nil, fmt.Errorf("trust repository not available")
	}

	return s.trustRepo.GetAdminPrimaryDevice(ctx, adminID)
}

// UpdateMPINDeviceBinding updates the device binding for admin MPIN
func (s *AdminDeviceService) UpdateMPINDeviceBinding(ctx context.Context, adminID uuid.UUID, deviceID string) error {
	if s.mpinRepo == nil {
		return fmt.Errorf("MPIN repository not available")
	}

	return s.mpinRepo.UpdateAdminMPINDeviceBinding(ctx, adminID, deviceID)
}

// generateBindToken generates a cryptographically secure bind token
func (s *AdminDeviceService) generateBindToken() (string, error) {
	b := make([]byte, 32) // 256 bits
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return base64.URLEncoding.EncodeToString(b), nil
}
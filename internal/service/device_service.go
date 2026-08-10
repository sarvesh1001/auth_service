// File: internal/service/device_service.go
package service

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net"
	"strings"
	"time"

	"go.uber.org/zap"

	"auth-service/internal/config"
	appErrors "auth-service/internal/errors"
	"auth-service/internal/infrastructure/audit"
	"auth-service/internal/infrastructure/idempotency"
	"auth-service/internal/models"
	"auth-service/internal/repository/scylla"

	"github.com/google/uuid"
)

// DeviceService handles device management and trust business logic.
// It uses audit logging, idempotency, and Kafka event production.
type DeviceService struct {
	deviceRepo           scylla.DeviceRepository
	deviceTrustRepo      scylla.DeviceTrustRepository
	adminDeviceTrustRepo scylla.AdminDeviceTrustRepository
	historyRepo          *scylla.DeviceHistoryRepositoryImpl
	distCache            *DistributedCache
	logProducer          *LogProducerService
	auditService         *audit.AuditService
	idempotencyStore     idempotency.Store
	config               config.Config
}

// NewDeviceService creates a new device service.
func NewDeviceService(
	deviceRepo scylla.DeviceRepository,
	deviceTrustRepo scylla.DeviceTrustRepository,
	adminDeviceTrustRepo scylla.AdminDeviceTrustRepository,
	distCache *DistributedCache,
	config config.Config,
	auditService *audit.AuditService,
	idempotencyStore idempotency.Store,
	logProducer *LogProducerService,
) *DeviceService {
	return &DeviceService{
		deviceRepo:           deviceRepo,
		deviceTrustRepo:      deviceTrustRepo,
		adminDeviceTrustRepo: adminDeviceTrustRepo,
		distCache:            distCache,
		config:               config,
		auditService:         auditService,
		idempotencyStore:     idempotencyStore,
		logProducer:          logProducer,
	}
}

// SetHistoryRepository sets the history repository for tracking device binding changes.
func (s *DeviceService) SetHistoryRepository(historyRepo *scylla.DeviceHistoryRepositoryImpl) {
	s.historyRepo = historyRepo
}

// SetLogProducerService sets the log producer service (legacy, kept for backwards compatibility).
func (s *DeviceService) SetLogProducerService(logProducer *LogProducerService) {
	s.logProducer = logProducer
}

// ----- Request/Response Types -----

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

// ----- Core Methods -----

// BindDevice creates a device binding with a generated token.
func (s *DeviceService) BindDevice(
	ctx context.Context,
	req BindDeviceRequest,
) (*BindDeviceResponse, error) {
	startTime := time.Now()

	// Idempotency check
	idempKey, _ := ctx.Value("idempotency_key").(string)
	if idempKey == "" {
		idempKey = fmt.Sprintf("bind_device-%s-%s", req.UserID.String(), req.DeviceID)
	}
	var cachedResponse BindDeviceResponse
	if err := s.idempotencyStore.Get(ctx, nil, idempKey, &cachedResponse); err == nil && cachedResponse.Success {
		return &cachedResponse, nil
	}
	ip, _ := ctx.Value("ip_address").(string)
	if ip == "" {
		ip = req.IPAddress
	}

	// Generate bind token
	bindToken, err := s.generateBindToken()
	if err != nil {
		s.produceDeviceEvent(ctx, &models.DeviceLogEvent{
			UserID:       req.UserID.String(),
			DeviceID:     req.DeviceID,
			Action:       "bind",
			Status:       "failed",
			ErrorCode:    "TOKEN_GENERATION_FAILED",
			ErrorMessage: err.Error(),
			IPAddress:    ip,
			Duration:     int64(time.Since(startTime).Milliseconds()),
		})
		return nil, fmt.Errorf("%w: token generation failed", appErrors.ErrInternal)
	}

	// Bind device
	if err := s.deviceRepo.BindUserDevice(ctx, req.UserID, req.DeviceID, bindToken); err != nil {
		s.produceDeviceEvent(ctx, &models.DeviceLogEvent{
			UserID:       req.UserID.String(),
			DeviceID:     req.DeviceID,
			Action:       "bind",
			Status:       "failed",
			ErrorCode:    "BIND_FAILED",
			ErrorMessage: err.Error(),
			IPAddress:    ip,
			Duration:     int64(time.Since(startTime).Milliseconds()),
		})
		return nil, fmt.Errorf("%w: bind failed", appErrors.ErrInternal)
	}

	// Record history
	if s.historyRepo != nil {
		_ = s.historyRepo.RecordBinding(ctx, req.UserID, req.DeviceID, nil, bindToken, "bind")
	}

	// Create initial trust level
	trustLevel := &models.DeviceTrustLevel{
		UserID:      req.UserID,
		DeviceID:    req.DeviceID,
		TrustStatus: models.TrustStatusUntrusted,
		RiskScore:   0,
		IsBlocked:   false,
	}
	if s.deviceTrustRepo != nil {
		_ = s.deviceTrustRepo.SetDeviceTrustLevel(ctx, req.UserID, req.DeviceID, trustLevel)
	}

	// Invalidate cache
	if s.distCache != nil {
		cacheKey := fmt.Sprintf("device:%s", req.UserID.String())
		s.distCache.DeleteKey(ctx, cacheKey)
	}

	response := &BindDeviceResponse{
		BindToken: bindToken,
		BoundAt:   time.Now().UTC(),
		Success:   true,
	}

	// Kafka event
	s.produceDeviceEvent(ctx, &models.DeviceLogEvent{
		UserID:    req.UserID.String(),
		DeviceID:  req.DeviceID,
		Action:    "bind",
		Status:    "success",
		BindToken: bindToken,
		IPAddress: ip,
		Duration:  int64(time.Since(startTime).Milliseconds()),
	})

	// Audit log
	if s.auditService != nil {
		before, _ := json.Marshal(map[string]interface{}{"device_id": req.DeviceID, "user_id": req.UserID.String()})
		after, _ := json.Marshal(map[string]interface{}{"bind_token": bindToken, "bound_at": response.BoundAt})
		_ = s.auditService.LogAction(ctx, nil, nil, "device", "bind", "device_binding",
			nil, "user", &req.UserID, before, after, map[string]interface{}{
				"device_id":  req.DeviceID,
				"ip":         ip,
				"user_agent": req.UserAgent,
			})
	}

	// Store idempotency
	_ = s.idempotencyStore.Store(ctx, nil, idempKey, response)

	return response, nil
}

// GetActiveDevice retrieves the active device for a user (with caching).
func (s *DeviceService) GetActiveDevice(
	ctx context.Context,
	userID uuid.UUID,
) (*models.UserActiveDevice, error) {
	logger, _ := zap.NewDevelopment()
	defer logger.Sync()

	startTime := time.Now()

	// Try cache
	if s.distCache != nil {
		cacheKey := fmt.Sprintf("device:%s", userID.String())
		var cachedDevice models.UserActiveDevice
		if err := s.distCache.Get(ctx, cacheKey, &cachedDevice); err == nil {
			logger.Debug("Device cache hit",
				zap.String("user_id", userID.String()),
				zap.String("device_id", cachedDevice.DeviceID),
			)
			return &cachedDevice, nil
		}
		logger.Debug("Device cache miss", zap.String("user_id", userID.String()))
	}

	// Fetch from DB
	device, err := s.deviceRepo.GetActiveDevice(ctx, userID)
	if err != nil {
		logger.Error("GetActiveDevice DB error",
			zap.String("user_id", userID.String()),
			zap.Error(err),
		)
		s.produceDeviceEvent(ctx, &models.DeviceLogEvent{
			UserID:       userID.String(),
			Action:       "get_active_device",
			Status:       "failed",
			ErrorCode:    "GET_DEVICE_FAILED",
			ErrorMessage: err.Error(),
			Duration:     int64(time.Since(startTime).Milliseconds()),
		})
		return nil, fmt.Errorf("%w: %v", appErrors.ErrNotFound, err)
	}

	if device != nil {
		logger.Info("Active device retrieved from DB",
			zap.String("user_id", userID.String()),
			zap.String("device_id", device.DeviceID),
		)
		// Cache result
		if s.distCache != nil {
			cacheKey := fmt.Sprintf("device:%s", userID.String())
			s.distCache.SetWithExpiry(ctx, cacheKey, device, 5*time.Minute)
		}
	} else {
		logger.Warn("No active device found in DB",
			zap.String("user_id", userID.String()),
		)
	}

	if device != nil {
		s.produceDeviceEvent(ctx, &models.DeviceLogEvent{
			UserID:   userID.String(),
			DeviceID: device.DeviceID,
			Action:   "get_active_device",
			Status:   "success",
			Duration: int64(time.Since(startTime).Milliseconds()),
		})
	}

	// Audit
	if s.auditService != nil && device != nil {
		_ = s.auditService.LogAction(ctx, nil, nil, "device", "get_active", "device_binding",
			nil, "user", &userID, nil, nil, map[string]interface{}{
				"device_id": device.DeviceID,
			})
	}

	return device, nil
}

// UnbindDevice removes a device binding.
// UnbindDevice removes a device binding with idempotency, audit, and event logging.
func (s *DeviceService) UnbindDevice(ctx context.Context, userID uuid.UUID, ipAddress string) error {
	startTime := time.Now()

	// Idempotency
	idempKey, _ := ctx.Value("idempotency_key").(string)
	if idempKey == "" {
		idempKey = fmt.Sprintf("unbind_device-%s", userID.String())
	}
	var processed bool
	if err := s.idempotencyStore.Get(ctx, nil, idempKey, &processed); err == nil && processed {
		return nil
	}
	ip, _ := ctx.Value("ip_address").(string)
	if ip == "" {
		ip = ipAddress
	}

	// Get current device for audit and history
	device, err := s.deviceRepo.GetActiveDevice(ctx, userID)
	if err != nil && !isNotFoundError(err) {
		return fmt.Errorf("%w: failed to get device", appErrors.ErrInternal)
	}

	// Unbind
	if err := s.deviceRepo.UnbindUserDevice(ctx, userID); err != nil {
		deviceID := ""
		if device != nil {
			deviceID = device.DeviceID
		}
		s.produceDeviceEvent(ctx, &models.DeviceLogEvent{
			UserID:       userID.String(),
			DeviceID:     deviceID,
			Action:       "unbind",
			Status:       "failed",
			ErrorCode:    "UNBIND_FAILED",
			ErrorMessage: err.Error(),
			IPAddress:    ip,
			Duration:     int64(time.Since(startTime).Milliseconds()),
		})
		return fmt.Errorf("%w: unbind failed", appErrors.ErrInternal)
	}

	// Record history
	if device != nil && s.historyRepo != nil {
		_ = s.historyRepo.RecordBinding(ctx, userID, device.DeviceID, nil, device.BindToken, "unbind")
	}

	// Invalidate cache
	if s.distCache != nil {
		cacheKey := fmt.Sprintf("device:%s", userID.String())
		s.distCache.DeleteKey(ctx, cacheKey)
	}

	// Success event
	if device != nil {
		s.produceDeviceEvent(ctx, &models.DeviceLogEvent{
			UserID:    userID.String(),
			DeviceID:  device.DeviceID,
			Action:    "unbind",
			Status:    "success",
			IPAddress: ip,
			Duration:  int64(time.Since(startTime).Milliseconds()),
		})
	}

	// Audit
	if s.auditService != nil {
		var before []byte
		if device != nil {
			before, _ = json.Marshal(map[string]interface{}{
				"device_id":  device.DeviceID,
				"bind_token": device.BindToken,
			})
		}
		_ = s.auditService.LogAction(ctx, nil, nil, "device", "unbind", "device_binding",
			nil, "user", &userID, before, nil, map[string]interface{}{
				"ip": ip,
			})
	}

	_ = s.idempotencyStore.Store(ctx, nil, idempKey, true)
	return nil
}

// UpdateDeviceSession updates the session ID for a device.
func (s *DeviceService) UpdateDeviceSession(
	ctx context.Context,
	userID, sessionID uuid.UUID,
	ipAddress string,
) error {
	startTime := time.Now()

	// Idempotency
	idempKey, _ := ctx.Value("idempotency_key").(string)
	if idempKey == "" {
		idempKey = fmt.Sprintf("session-%s-%s", userID.String(), sessionID.String())
	}
	var processed bool
	if err := s.idempotencyStore.Get(ctx, nil, idempKey, &processed); err == nil && processed {
		return nil
	}
	ip, _ := ctx.Value("ip_address").(string)
	if ip == "" {
		ip = ipAddress
	}

	if err := s.deviceRepo.UpdateDeviceSession(ctx, userID, sessionID); err != nil {
		s.produceDeviceEvent(ctx, &models.DeviceLogEvent{
			UserID:       userID.String(),
			Action:       "update_session",
			Status:       "failed",
			ErrorCode:    "UPDATE_SESSION_FAILED",
			ErrorMessage: err.Error(),
			IPAddress:    ip,
			Duration:     int64(time.Since(startTime).Milliseconds()),
		})
		return fmt.Errorf("%w: %v", appErrors.ErrInternal, err)
	}

	s.produceDeviceEvent(ctx, &models.DeviceLogEvent{
		UserID:    userID.String(),
		Action:    "update_session",
		Status:    "success",
		SessionID: sessionID.String(),
		IPAddress: ip,
		Duration:  int64(time.Since(startTime).Milliseconds()),
	})

	// Invalidate cache
	if s.distCache != nil {
		cacheKey := fmt.Sprintf("device:%s", userID.String())
		s.distCache.DeleteKey(ctx, cacheKey)
	}

	if s.auditService != nil {
		_ = s.auditService.LogAction(ctx, nil, nil, "device", "update_session", "device_session",
			nil, "user", &userID, nil, nil, map[string]interface{}{
				"session_id": sessionID.String(),
				"ip":         ip,
			})
	}

	_ = s.idempotencyStore.Store(ctx, nil, idempKey, true)
	return nil
}

// ValidateDevice validates a device binding.
func (s *DeviceService) ValidateDevice(
	ctx context.Context,
	req ValidateDeviceRequest,
) (*ValidateDeviceResponse, error) {
	startTime := time.Now()

	// Idempotency
	idempKey, _ := ctx.Value("idempotency_key").(string)
	if idempKey == "" {
		idempKey = fmt.Sprintf("validate-%s-%s", req.UserID.String(), req.DeviceID)
	}
	var cached ValidateDeviceResponse
	if err := s.idempotencyStore.Get(ctx, nil, idempKey, &cached); err == nil {
		return &cached, nil
	}
	ip, _ := ctx.Value("ip_address").(string)
	if ip == "" {
		ip = req.IPAddress
	}

	isValid, err := s.deviceRepo.ValidateDeviceBinding(ctx, req.UserID, req.DeviceID, req.BindToken)
	if err != nil {
		s.produceDeviceEvent(ctx, &models.DeviceLogEvent{
			UserID:       req.UserID.String(),
			DeviceID:     req.DeviceID,
			Action:       "validate",
			Status:       "failed",
			ErrorCode:    "VALIDATION_ERROR",
			ErrorMessage: err.Error(),
			IPAddress:    ip,
			Duration:     int64(time.Since(startTime).Milliseconds()),
		})
		return nil, fmt.Errorf("%w: validation error", appErrors.ErrInternal)
	}

	response := &ValidateDeviceResponse{
		IsValid: isValid,
	}
	if !isValid {
		response.Message = "Invalid device binding"
	}

	s.produceDeviceEvent(ctx, &models.DeviceLogEvent{
		UserID:   req.UserID.String(),
		DeviceID: req.DeviceID,
		Action:   "validate",
		Status: func() string {
			if isValid {
				return "success"
			} else {
				return "failed"
			}
		}(),
		IPAddress: ip,
		Duration:  int64(time.Since(startTime).Milliseconds()),
	})

	if s.auditService != nil {
		_ = s.auditService.LogAction(ctx, nil, nil, "device", "validate", "device_binding",
			nil, "user", &req.UserID, nil, nil, map[string]interface{}{
				"device_id": req.DeviceID,
				"is_valid":  isValid,
				"ip":        ip,
			})
	}

	_ = s.idempotencyStore.Store(ctx, nil, idempKey, response)
	return response, nil
}

// GetDeviceBindingHistory retrieves device history from history table.
func (s *DeviceService) GetDeviceBindingHistory(
	ctx context.Context,
	userID uuid.UUID,
	limit int,
) ([]*models.UserActiveDevice, error) {
	startTime := time.Now()

	if s.historyRepo != nil {
		history, err := s.historyRepo.GetBindingHistory(ctx, userID, limit)
		if err != nil {
			s.produceDeviceEvent(ctx, &models.DeviceLogEvent{
				UserID:       userID.String(),
				Action:       "get_binding_history",
				Status:       "failed",
				ErrorCode:    "GET_HISTORY_FAILED",
				ErrorMessage: err.Error(),
				Duration:     int64(time.Since(startTime).Milliseconds()),
			})
			return nil, fmt.Errorf("%w: %v", appErrors.ErrNotFound, err)
		}
		s.produceDeviceEvent(ctx, &models.DeviceLogEvent{
			UserID:   userID.String(),
			Action:   "get_binding_history",
			Status:   "success",
			Duration: int64(time.Since(startTime).Milliseconds()),
		})
		if s.auditService != nil {
			_ = s.auditService.LogAction(ctx, nil, nil, "device", "get_history", "device_binding",
				nil, "user", &userID, nil, nil, map[string]interface{}{"limit": limit})
		}
		return history, nil
	}

	// Fallback to current device
	device, err := s.deviceRepo.GetActiveDevice(ctx, userID)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", appErrors.ErrNotFound, err)
	}
	if device == nil {
		return []*models.UserActiveDevice{}, nil
	}
	if s.auditService != nil {
		_ = s.auditService.LogAction(ctx, nil, nil, "device", "get_history", "device_binding",
			nil, "user", &userID, nil, nil, map[string]interface{}{"limit": limit})
	}
	return []*models.UserActiveDevice{device}, nil
}

// GetUsersByDevice finds all users for a device.
func (s *DeviceService) GetUsersByDevice(
	ctx context.Context,
	deviceID string,
) ([]*models.UserActiveDevice, error) {
	startTime := time.Now()

	var users []*models.UserActiveDevice
	var err error
	if s.historyRepo != nil {
		users, err = s.historyRepo.GetUsersByDeviceFromHistory(ctx, deviceID)
	} else {
		users, err = s.deviceRepo.GetUsersByDevice(ctx, deviceID)
	}
	if err != nil {
		s.produceDeviceEvent(ctx, &models.DeviceLogEvent{
			DeviceID:     deviceID,
			Action:       "get_users_by_device",
			Status:       "failed",
			ErrorCode:    "GET_USERS_FAILED",
			ErrorMessage: err.Error(),
			Duration:     int64(time.Since(startTime).Milliseconds()),
		})
		return nil, fmt.Errorf("%w: %v", appErrors.ErrNotFound, err)
	}
	s.produceDeviceEvent(ctx, &models.DeviceLogEvent{
		DeviceID: deviceID,
		Action:   "get_users_by_device",
		Status:   "success",
		Duration: int64(time.Since(startTime).Milliseconds()),
	})
	if s.auditService != nil {
		_ = s.auditService.LogAction(ctx, nil, nil, "device", "get_users_by_device", "device_binding",
			nil, "system", nil, nil, nil, map[string]interface{}{"device_id": deviceID})
	}
	return users, nil
}

// CleanupOrphanedDevices removes old device bindings.
func (s *DeviceService) CleanupOrphanedDevices(
	ctx context.Context,
	olderThan time.Duration,
) (int, error) {
	startTime := time.Now()

	cutoffTime := time.Now().Add(-olderThan)
	count, err := s.deviceRepo.CleanupOrphanedDevices(ctx, cutoffTime)
	if err != nil {
		s.produceDeviceEvent(ctx, &models.DeviceLogEvent{
			Action:       "cleanup_orphaned",
			Status:       "failed",
			ErrorCode:    "CLEANUP_FAILED",
			ErrorMessage: err.Error(),
			Duration:     int64(time.Since(startTime).Milliseconds()),
		})
		return 0, fmt.Errorf("%w: %v", appErrors.ErrInternal, err)
	}
	s.produceDeviceEvent(ctx, &models.DeviceLogEvent{
		Action:   "cleanup_orphaned",
		Status:   "success",
		Duration: int64(time.Since(startTime).Milliseconds()),
	})
	if s.auditService != nil {
		_ = s.auditService.LogAction(ctx, nil, nil, "device", "cleanup_orphaned", "system",
			nil, "system", nil, nil, nil, map[string]interface{}{
				"older_than": olderThan.String(),
				"count":      count,
			})
	}
	return count, nil
}

// HealthCheck checks service health.
func (s *DeviceService) HealthCheck(ctx context.Context) error {
	if err := s.deviceRepo.HealthCheck(ctx); err != nil {
		return fmt.Errorf("%w: device repo health failed", appErrors.ErrInternal)
	}
	if s.deviceTrustRepo != nil {
		if err := s.deviceTrustRepo.HealthCheck(ctx); err != nil {
			return fmt.Errorf("%w: trust repo health failed", appErrors.ErrInternal)
		}
	}
	if s.historyRepo != nil {
		if err := s.historyRepo.HealthCheck(ctx); err != nil {
			return fmt.Errorf("%w: history repo health failed", appErrors.ErrInternal)
		}
	}
	return nil
}

// GetServiceStats returns service statistics.
func (s *DeviceService) GetServiceStats(ctx context.Context) (map[string]interface{}, error) {
	stats, err := s.deviceRepo.GetRepositoryStats(ctx)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", appErrors.ErrInternal, err)
	}
	return stats, nil
}

// IsDeviceTrusted checks if a device is trusted for a user.
func (s *DeviceService) IsDeviceTrusted(ctx context.Context, userID uuid.UUID, deviceID string) (bool, error) {
	activeDevice, err := s.deviceRepo.GetActiveDevice(ctx, userID)
	if err != nil {
		return false, fmt.Errorf("%w: %v", appErrors.ErrNotFound, err)
	}
	if activeDevice == nil {
		return false, nil
	}
	return activeDevice.DeviceID == deviceID, nil
}

// ----- Device Trust Management -----

// GetDeviceTrustLevel retrieves the trust level for a device.
func (s *DeviceService) GetDeviceTrustLevel(
	ctx context.Context,
	userID uuid.UUID,
	deviceID string,
) (*DeviceTrustResponse, error) {
	trustLevel, err := s.deviceTrustRepo.GetDeviceTrustLevel(ctx, userID, deviceID)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", appErrors.ErrNotFound, err)
	}
	if s.auditService != nil {
		_ = s.auditService.LogAction(ctx, nil, nil, "device", "get_trust_level", "device_trust",
			nil, "user", &userID, nil, nil, map[string]interface{}{"device_id": deviceID})
	}
	return &DeviceTrustResponse{
		Success:    true,
		TrustLevel: trustLevel,
		RiskScore:  trustLevel.RiskScore,
		IsBlocked:  trustLevel.IsBlocked,
	}, nil
}

// SetDeviceTrustLevel updates the trust level for a device.
func (s *DeviceService) SetDeviceTrustLevel(
	ctx context.Context,
	req DeviceTrustRequest,
) (*DeviceTrustResponse, error) {
	startTime := time.Now()

	// Idempotency
	idempKey, _ := ctx.Value("idempotency_key").(string)
	if idempKey == "" {
		idempKey = fmt.Sprintf("trust-%s-%s", req.UserID.String(), req.DeviceID)
	}
	var cached DeviceTrustResponse
	if err := s.idempotencyStore.Get(ctx, nil, idempKey, &cached); err == nil && cached.Success {
		return &cached, nil
	}
	ip, _ := ctx.Value("ip_address").(string)
	if ip == "" {
		ip = req.IPAddress
	}

	ipSubnet := s.extractIPSubnet(ip)
	locationHash := s.hashLocation(ip, req.UserAgent)

	trustLevel := &models.DeviceTrustLevel{
		UserID:            req.UserID,
		DeviceID:          req.DeviceID,
		TrustStatus:       req.TrustStatus,
		DeviceFingerprint: req.DeviceFingerprint,
		OSVersion:         req.OSVersion,
		AppVersion:        req.AppVersion,
		LastIPAddress:     ip,
		LastIPSubnet:      ipSubnet,
		LastLocationHash:  locationHash,
		UserAgent:         req.UserAgent,
		DeviceModel:       req.DeviceModel,
		RiskScore:         s.calculateRiskScore(req.TrustStatus),
		IsBlocked:         false,
	}

	if err := s.deviceTrustRepo.SetDeviceTrustLevel(ctx, req.UserID, req.DeviceID, trustLevel); err != nil {
		s.produceDeviceEvent(ctx, &models.DeviceLogEvent{
			UserID:       req.UserID.String(),
			DeviceID:     req.DeviceID,
			Action:       "set_trust_level",
			Status:       "failed",
			ErrorCode:    "SET_TRUST_FAILED",
			ErrorMessage: err.Error(),
			IPAddress:    ip,
			Duration:     int64(time.Since(startTime).Milliseconds()),
		})
		return nil, fmt.Errorf("%w: %v", appErrors.ErrInternal, err)
	}

	response := &DeviceTrustResponse{
		Success:    true,
		TrustLevel: trustLevel,
		RiskScore:  trustLevel.RiskScore,
		IsBlocked:  trustLevel.IsBlocked,
	}

	s.produceDeviceEvent(ctx, &models.DeviceLogEvent{
		UserID:    req.UserID.String(),
		DeviceID:  req.DeviceID,
		Action:    "set_trust_level",
		Status:    "success",
		IPAddress: ip,
		Duration:  int64(time.Since(startTime).Milliseconds()),
	})

	if s.auditService != nil {
		before, _ := json.Marshal(map[string]interface{}{"trust_status": req.TrustStatus})
		after, _ := json.Marshal(map[string]interface{}{"trust_level": trustLevel})
		_ = s.auditService.LogAction(ctx, nil, nil, "device", "set_trust", "device_trust",
			nil, "user", &req.UserID, before, after, map[string]interface{}{
				"device_id": req.DeviceID,
				"ip":        ip,
			})
	}

	_ = s.idempotencyStore.Store(ctx, nil, idempKey, response)
	return response, nil
}

// MarkSuccessfulLogin updates device trust after successful login.
// 🔧 PRODUCTION FIX: Also binds the device to user_active_device so IsDeviceTrusted works.
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
		RiskScore:         0,
	}

	// 1. Update trust level
	if err := s.deviceTrustRepo.MarkSuccessfulLogin(ctx, userID, deviceID, trustLevel); err != nil {
		s.produceDeviceEvent(ctx, &models.DeviceLogEvent{
			UserID:       userID.String(),
			DeviceID:     deviceID,
			Action:       "mark_successful_login",
			Status:       "failed",
			ErrorCode:    "MARK_LOGIN_FAILED",
			ErrorMessage: err.Error(),
			IPAddress:    ipAddress,
			Duration:     int64(time.Since(startTime).Milliseconds()),
		})
		return fmt.Errorf("%w: %v", appErrors.ErrInternal, err)
	}

	// 2. Bind the device (insert/update user_active_device)
	bindToken, err := s.generateBindToken()
	if err != nil {
		s.produceDeviceEvent(ctx, &models.DeviceLogEvent{
			UserID:       userID.String(),
			DeviceID:     deviceID,
			Action:       "bind_device",
			Status:       "failed",
			ErrorCode:    "BIND_TOKEN_GENERATION_FAILED",
			ErrorMessage: err.Error(),
			IPAddress:    ipAddress,
			Duration:     int64(time.Since(startTime).Milliseconds()),
		})
		return fmt.Errorf("%w: bind token generation failed", appErrors.ErrInternal)
	}
	if err := s.deviceRepo.BindUserDevice(ctx, userID, deviceID, bindToken); err != nil {
		s.produceDeviceEvent(ctx, &models.DeviceLogEvent{
			UserID:       userID.String(),
			DeviceID:     deviceID,
			Action:       "bind_device",
			Status:       "failed",
			ErrorCode:    "BIND_DEVICE_FAILED",
			ErrorMessage: err.Error(),
			IPAddress:    ipAddress,
			Duration:     int64(time.Since(startTime).Milliseconds()),
		})
		return fmt.Errorf("%w: bind device failed", appErrors.ErrInternal)
	}

	// 3. Record history (if available)
	if s.historyRepo != nil {
		_ = s.historyRepo.RecordBinding(ctx, userID, deviceID, nil, bindToken, "bind")
	}

	// Success events and audit
	s.produceDeviceEvent(ctx, &models.DeviceLogEvent{
		UserID:    userID.String(),
		DeviceID:  deviceID,
		Action:    "mark_successful_login",
		Status:    "success",
		IPAddress: ipAddress,
		Duration:  int64(time.Since(startTime).Milliseconds()),
	})

	if s.auditService != nil {
		_ = s.auditService.LogAction(ctx, nil, nil, "device", "mark_login", "device_trust",
			nil, "user", &userID, nil, nil, map[string]interface{}{
				"device_id": deviceID,
				"ip":        ipAddress,
			})
	}
	return nil
}

// BlockDevice blocks a device for a user.
func (s *DeviceService) BlockDevice(ctx context.Context, userID uuid.UUID, deviceID string) error {
	startTime := time.Now()

	if err := s.deviceTrustRepo.BlockDevice(ctx, userID, deviceID); err != nil {
		s.produceDeviceEvent(ctx, &models.DeviceLogEvent{
			UserID:       userID.String(),
			DeviceID:     deviceID,
			Action:       "block_device",
			Status:       "failed",
			ErrorCode:    "BLOCK_DEVICE_FAILED",
			ErrorMessage: err.Error(),
			Duration:     int64(time.Since(startTime).Milliseconds()),
		})
		return fmt.Errorf("%w: %v", appErrors.ErrInternal, err)
	}

	s.produceDeviceEvent(ctx, &models.DeviceLogEvent{
		UserID:   userID.String(),
		DeviceID: deviceID,
		Action:   "block_device",
		Status:   "success",
		Duration: int64(time.Since(startTime).Milliseconds()),
	})

	if s.auditService != nil {
		_ = s.auditService.LogAction(ctx, nil, nil, "device", "block", "device_trust",
			nil, "user", &userID, nil, nil, map[string]interface{}{"device_id": deviceID})
	}
	return nil
}

// GetUserDevices retrieves all devices for a user.
func (s *DeviceService) GetUserDevices(ctx context.Context, userID uuid.UUID) ([]*models.DeviceTrustLevel, error) {
	devices, err := s.deviceTrustRepo.GetUserDevices(ctx, userID)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", appErrors.ErrNotFound, err)
	}
	if s.auditService != nil {
		_ = s.auditService.LogAction(ctx, nil, nil, "device", "get_user_devices", "device_trust",
			nil, "user", &userID, nil, nil, map[string]interface{}{"count": len(devices)})
	}
	return devices, nil
}

// UpdateDeviceRiskScore updates the risk score for a device.
func (s *DeviceService) UpdateDeviceRiskScore(
	ctx context.Context,
	userID uuid.UUID,
	deviceID string,
	riskScore int,
) error {
	if err := s.deviceTrustRepo.UpdateDeviceRiskScore(ctx, userID, deviceID, riskScore); err != nil {
		return fmt.Errorf("%w: %v", appErrors.ErrInternal, err)
	}
	if s.auditService != nil {
		_ = s.auditService.LogAction(ctx, nil, nil, "device", "update_risk", "device_trust",
			nil, "user", &userID, nil, nil, map[string]interface{}{
				"device_id":  deviceID,
				"risk_score": riskScore,
			})
	}
	return nil
}

// ----- Admin Device Trust Methods -----

// GetAdminDeviceTrustLevel retrieves trust level for admin device.
func (s *DeviceService) GetAdminDeviceTrustLevel(
	ctx context.Context,
	adminID uuid.UUID,
	deviceID string,
) (*DeviceTrustResponse, error) {
	trustLevel, err := s.adminDeviceTrustRepo.GetAdminDeviceTrustLevel(ctx, adminID, deviceID)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", appErrors.ErrNotFound, err)
	}
	if s.auditService != nil {
		_ = s.auditService.LogAction(ctx, nil, nil, "admin_device", "get_trust_level", "device_trust",
			&adminID, "admin", &adminID, nil, nil, map[string]interface{}{"device_id": deviceID})
	}
	return &DeviceTrustResponse{
		Success:    true,
		TrustLevel: trustLevel,
		RiskScore:  trustLevel.RiskScore,
		IsBlocked:  trustLevel.IsBlocked,
	}, nil
}

// MarkAdminSuccessfulLogin updates admin device trust after successful login.
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
		s.produceDeviceEvent(ctx, &models.DeviceLogEvent{
			UserID:       adminID.String(),
			DeviceID:     deviceID,
			Action:       "mark_admin_successful_login",
			Status:       "failed",
			ErrorCode:    "MARK_ADMIN_LOGIN_FAILED",
			ErrorMessage: err.Error(),
			IPAddress:    ipAddress,
			Duration:     int64(time.Since(startTime).Milliseconds()),
		})
		return fmt.Errorf("%w: %v", appErrors.ErrInternal, err)
	}

	s.produceDeviceEvent(ctx, &models.DeviceLogEvent{
		UserID:    adminID.String(),
		DeviceID:  deviceID,
		Action:    "mark_admin_successful_login",
		Status:    "success",
		IPAddress: ipAddress,
		Duration:  int64(time.Since(startTime).Milliseconds()),
	})

	if s.auditService != nil {
		_ = s.auditService.LogAction(ctx, nil, nil, "admin_device", "mark_login", "device_trust",
			&adminID, "admin", &adminID, nil, nil, map[string]interface{}{
				"device_id": deviceID,
				"ip":        ipAddress,
			})
	}
	return nil
}

// BlockAdminDevice blocks an admin device.
func (s *DeviceService) BlockAdminDevice(ctx context.Context, adminID uuid.UUID, deviceID string) error {
	startTime := time.Now()

	if err := s.adminDeviceTrustRepo.BlockAdminDevice(ctx, adminID, deviceID); err != nil {
		s.produceDeviceEvent(ctx, &models.DeviceLogEvent{
			UserID:       adminID.String(),
			DeviceID:     deviceID,
			Action:       "block_admin_device",
			Status:       "failed",
			ErrorCode:    "BLOCK_ADMIN_DEVICE_FAILED",
			ErrorMessage: err.Error(),
			Duration:     int64(time.Since(startTime).Milliseconds()),
		})
		return fmt.Errorf("%w: %v", appErrors.ErrInternal, err)
	}

	s.produceDeviceEvent(ctx, &models.DeviceLogEvent{
		UserID:   adminID.String(),
		DeviceID: deviceID,
		Action:   "block_admin_device",
		Status:   "success",
		Duration: int64(time.Since(startTime).Milliseconds()),
	})

	if s.auditService != nil {
		_ = s.auditService.LogAction(ctx, nil, nil, "admin_device", "block", "device_trust",
			&adminID, "admin", &adminID, nil, nil, map[string]interface{}{"device_id": deviceID})
	}
	return nil
}

// ----- Helper Methods -----

// generateBindToken generates a cryptographically secure bind token.
func (s *DeviceService) generateBindToken() (string, error) {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return base64.URLEncoding.EncodeToString(b), nil
}

// extractIPSubnet extracts /24 subnet from IP address.
func (s *DeviceService) extractIPSubnet(ipAddress string) string {
	if ipAddress == "" {
		return ""
	}
	ip := net.ParseIP(ipAddress)
	if ip == nil {
		return ""
	}
	if ip.To4() != nil {
		ip = ip.To4()
		return fmt.Sprintf("%d.%d.%d.0/24", ip[0], ip[1], ip[2])
	}
	return fmt.Sprintf("%s/64", ip.Mask(net.CIDRMask(64, 128)).String())
}

// hashLocation creates a location hash from IP and UserAgent.
func (s *DeviceService) hashLocation(ipAddress, userAgent string) string {
	if ipAddress == "" && userAgent == "" {
		return ""
	}
	// Using a simple hash; in production you might use a proper hashing function.
	locationData := s.extractIPSubnet(ipAddress) + "|" + s.extractUserAgentFeatures(userAgent)
	return fmt.Sprintf("%x", sha256.Sum256([]byte(locationData)))
}

// extractUserAgentFeatures extracts key features from UserAgent.
func (s *DeviceService) extractUserAgentFeatures(userAgent string) string {
	if userAgent == "" {
		return ""
	}
	features := []string{}
	lower := strings.ToLower(userAgent)
	if strings.Contains(lower, "mobile") {
		features = append(features, "mobile")
	} else {
		features = append(features, "desktop")
	}
	switch {
	case strings.Contains(lower, "windows"):
		features = append(features, "windows")
	case strings.Contains(lower, "mac os"):
		features = append(features, "macos")
	case strings.Contains(lower, "linux"):
		features = append(features, "linux")
	case strings.Contains(lower, "android"):
		features = append(features, "android")
	case strings.Contains(lower, "ios"):
		features = append(features, "ios")
	}
	return strings.Join(features, "|")
}

// calculateRiskScore calculates risk score based on trust status.
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

// produceDeviceEvent sends a DeviceLogEvent to Kafka (if logProducer is set).
func (s *DeviceService) produceDeviceEvent(ctx context.Context, event *models.DeviceLogEvent) {
	if s.logProducer != nil {
		_ = s.logProducer.ProduceDeviceEvent(ctx, event)
	}
}

// isNotFoundError checks if an error indicates "not found".
func isNotFoundError(err error) bool {
	return err != nil && strings.Contains(err.Error(), "not found")
}

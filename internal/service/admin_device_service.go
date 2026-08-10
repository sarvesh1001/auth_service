package service

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"time"

	"github.com/google/uuid"

	"auth-service/internal/config"
	appErrors "auth-service/internal/errors"
	"auth-service/internal/infrastructure/audit"
	"auth-service/internal/infrastructure/idempotency"
	"auth-service/internal/models"
	"auth-service/internal/repository/scylla"
)

// AdminDeviceService handles admin device binding, validation, and trust operations.
type AdminDeviceService struct {
	deviceRepo  scylla.AdminDeviceRepository
	historyRepo scylla.AdminDeviceHistoryRepository
	trustRepo   scylla.AdminDeviceTrustRepository
	mpinRepo    scylla.AdminMPINRepository
	distCache   *DistributedCache

	idempotencyStore idempotency.Store
	auditService     *audit.AuditService
	config           config.Config
	// logger removed
}

// NewAdminDeviceService creates a new AdminDeviceService (without logger).
func NewAdminDeviceService(
	deviceRepo scylla.AdminDeviceRepository,
	trustRepo scylla.AdminDeviceTrustRepository,
	mpinRepo scylla.AdminMPINRepository,
	distCache *DistributedCache,
	idempotencyStore idempotency.Store,
	auditService *audit.AuditService,
	config config.Config,
) *AdminDeviceService {
	return &AdminDeviceService{
		deviceRepo:       deviceRepo,
		trustRepo:        trustRepo,
		mpinRepo:         mpinRepo,
		distCache:        distCache,
		idempotencyStore: idempotencyStore,
		auditService:     auditService,
		config:           config,
	}
}

// SetHistoryRepository injects the history repository (optional).
func (s *AdminDeviceService) SetHistoryRepository(historyRepo scylla.AdminDeviceHistoryRepository) {
	s.historyRepo = historyRepo
}

// AdminBindDeviceRequest represents a request to bind a device to an admin.
type AdminBindDeviceRequest struct {
	AdminID           uuid.UUID `json:"admin_id" validate:"required"`
	DeviceID          string    `json:"device_id" validate:"required"`
	DeviceFingerprint string    `json:"device_fingerprint,omitempty"`
	OSVersion         string    `json:"os_version,omitempty"`
	AppVersion        string    `json:"app_version,omitempty"`
	IPAddress         string    `json:"ip_address,omitempty"`
	UserAgent         string    `json:"user_agent,omitempty"`
	DeviceModel       string    `json:"device_model,omitempty"`
}

// AdminBindDeviceResponse is the response for binding a device.
type AdminBindDeviceResponse struct {
	BindToken string    `json:"bind_token"`
	BoundAt   time.Time `json:"bound_at"`
	Success   bool      `json:"success"`
}

// AdminValidateDeviceRequest is used to validate a device binding.
type AdminValidateDeviceRequest struct {
	AdminID   uuid.UUID `json:"admin_id" validate:"required"`
	DeviceID  string    `json:"device_id" validate:"required"`
	BindToken string    `json:"bind_token" validate:"required"`
	IPAddress string    `json:"ip_address,omitempty"`
}

// AdminValidateDeviceResponse contains the validation result.
type AdminValidateDeviceResponse struct {
	IsValid bool   `json:"is_valid"`
	Message string `json:"message,omitempty"`
}

// BindDevice binds a new device to an admin with idempotency and audit.
func (s *AdminDeviceService) BindDevice(
	ctx context.Context,
	req AdminBindDeviceRequest,
) (*AdminBindDeviceResponse, error) {
	// Extract idempotency key and IP from context
	idempKey, _ := ctx.Value("idempotency_key").(string)
	if idempKey == "" {
		idempKey = uuid.New().String()
	}
	ip, _ := ctx.Value("ip_address").(string)
	if ip == "" && req.IPAddress != "" {
		ip = req.IPAddress
	}

	// Check idempotency
	var cachedResponse AdminBindDeviceResponse
	if err := s.idempotencyStore.Get(ctx, nil, idempKey, &cachedResponse); err == nil && cachedResponse.Success {
		// No logging; just return cached result
		return &cachedResponse, nil
	}

	bindToken, err := s.generateBindToken()
	if err != nil {
		return nil, fmt.Errorf("%w: token generation failed", appErrors.ErrInternal)
	}

	// Perform binding
	if err := s.deviceRepo.BindAdminDevice(ctx, req.AdminID, req.DeviceID, bindToken); err != nil {
		return nil, fmt.Errorf("%w: bind failed", appErrors.ErrInternal)
	}

	// Record history if available
	if s.historyRepo != nil {
		if err := s.historyRepo.RecordAdminBinding(ctx, req.AdminID, req.DeviceID, nil, bindToken, "bind"); err != nil {
			// Non‑critical; we don't fail the operation
		}
	}

	// Update trust level if available
	if s.trustRepo != nil {
		trustLevel := &models.DeviceTrustLevel{
			UserID:            req.AdminID,
			DeviceID:          req.DeviceID,
			TrustStatus:       models.TrustStatusTrusted,
			DeviceFingerprint: req.DeviceFingerprint,
			OSVersion:         req.OSVersion,
			AppVersion:        req.AppVersion,
			LastIPAddress:     ip,
			UserAgent:         req.UserAgent,
			DeviceModel:       req.DeviceModel,
			IsBlocked:         false,
			RiskScore:         0,
		}
		if err := s.trustRepo.MarkAdminSuccessfulLogin(ctx, req.AdminID, req.DeviceID, trustLevel); err != nil {
			// Non‑critical
		}
	}

	// Invalidate cache
	if s.distCache != nil {
		cacheKey := fmt.Sprintf("admin_device:%s", req.AdminID.String())
		s.distCache.DeleteKey(ctx, cacheKey)
	}

	response := &AdminBindDeviceResponse{
		BindToken: bindToken,
		BoundAt:   time.Now().UTC(),
		Success:   true,
	}

	// Store idempotency result
	if err := s.idempotencyStore.Store(ctx, nil, idempKey, response); err != nil {
		// Non‑critical; log might be elsewhere
	}

	// Audit log
	if s.auditService != nil {
		_ = s.auditService.LogAction(ctx, nil, nil, "admin_device", "bind_device", "admin",
			&req.AdminID, "admin", &req.AdminID, nil, nil, map[string]interface{}{
				"device_id":          req.DeviceID,
				"device_fingerprint": req.DeviceFingerprint,
				"ip_address":         ip,
				"bind_token":         bindToken,
			})
	}

	return response, nil
}

// GetActiveDevice retrieves the active device for an admin (with cache).
func (s *AdminDeviceService) GetActiveDevice(
	ctx context.Context,
	adminID uuid.UUID,
) (*models.UserActiveDevice, error) {
	if s.distCache != nil {
		cacheKey := fmt.Sprintf("admin_device:%s", adminID.String())
		var cachedDevice models.UserActiveDevice
		if err := s.distCache.Get(ctx, cacheKey, &cachedDevice); err == nil {
			return &cachedDevice, nil
		}
	}

	device, err := s.deviceRepo.GetAdminActiveDevice(ctx, adminID)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", appErrors.ErrNotFound, err)
	}

	if device != nil && s.distCache != nil {
		cacheKey := fmt.Sprintf("admin_device:%s", adminID.String())
		s.distCache.SetWithExpiry(ctx, cacheKey, device, 5*time.Minute)
	}

	if s.auditService != nil {
		_ = s.auditService.LogAction(ctx, nil, nil, "admin_device", "get_active_device", "admin",
			&adminID, "admin", &adminID, nil, nil, nil)
	}

	return device, nil
}

// UnbindDevice removes the active device binding for an admin (idempotent).
func (s *AdminDeviceService) UnbindDevice(ctx context.Context, adminID uuid.UUID, ipAddress string) error {
	idempKey, _ := ctx.Value("idempotency_key").(string)
	if idempKey == "" {
		idempKey = fmt.Sprintf("unbind-%s", adminID.String())
	}
	ip, _ := ctx.Value("ip_address").(string)
	if ip == "" {
		ip = ipAddress
	}

	// Check idempotency
	var processed bool
	if err := s.idempotencyStore.Get(ctx, nil, idempKey, &processed); err == nil && processed {
		return nil
	}

	// Get current device for audit before state
	device, err := s.deviceRepo.GetAdminActiveDevice(ctx, adminID)
	if err != nil && !errors.Is(err, appErrors.ErrNotFound) {
		return fmt.Errorf("%w: failed to get device", appErrors.ErrInternal)
	}

	// Perform unbind
	if err := s.deviceRepo.UnbindAdminDevice(ctx, adminID); err != nil {
		return fmt.Errorf("%w: unbind failed", appErrors.ErrInternal)
	}

	if device != nil && s.historyRepo != nil {
		if err := s.historyRepo.RecordAdminBinding(ctx, adminID, device.DeviceID, nil, device.BindToken, "unbind"); err != nil {
			// Non‑critical
		}
	}

	// Invalidate cache
	if s.distCache != nil {
		cacheKey := fmt.Sprintf("admin_device:%s", adminID.String())
		s.distCache.DeleteKey(ctx, cacheKey)
	}

	// Store idempotency marker
	if err := s.idempotencyStore.Store(ctx, nil, idempKey, true); err != nil {
		// Non‑critical
	}

	// Audit - prepare before state as JSON bytes
	var before []byte
	if device != nil {
		beforeMap := map[string]interface{}{
			"device_id":  device.DeviceID,
			"bind_token": device.BindToken,
		}
		before, _ = json.Marshal(beforeMap)
	}
	if s.auditService != nil {
		_ = s.auditService.LogAction(ctx, nil, nil, "admin_device", "unbind_device", "admin",
			&adminID, "admin", &adminID, before, nil, map[string]interface{}{
				"ip_address": ip,
			})
	}

	return nil
}

// UpdateDeviceSession updates the session ID for a device (idempotent).
func (s *AdminDeviceService) UpdateDeviceSession(
	ctx context.Context,
	adminID, sessionID uuid.UUID,
	ipAddress string,
) error {
	idempKey, _ := ctx.Value("idempotency_key").(string)
	if idempKey == "" {
		idempKey = fmt.Sprintf("session-%s-%s", adminID.String(), sessionID.String())
	}
	ip, _ := ctx.Value("ip_address").(string)
	if ip == "" {
		ip = ipAddress
	}

	var processed bool
	if err := s.idempotencyStore.Get(ctx, nil, idempKey, &processed); err == nil && processed {
		return nil
	}

	if err := s.deviceRepo.UpdateAdminDeviceSession(ctx, adminID, sessionID); err != nil {
		return fmt.Errorf("%w: %v", appErrors.ErrInternal, err)
	}

	// Invalidate cache
	if s.distCache != nil {
		cacheKey := fmt.Sprintf("admin_device:%s", adminID.String())
		s.distCache.DeleteKey(ctx, cacheKey)
	}

	if err := s.idempotencyStore.Store(ctx, nil, idempKey, true); err != nil {
		// Non‑critical
	}

	if s.auditService != nil {
		_ = s.auditService.LogAction(ctx, nil, nil, "admin_device", "update_session", "admin",
			&adminID, "admin", &adminID, nil, nil, map[string]interface{}{
				"session_id": sessionID.String(),
				"ip_address": ip,
			})
	}

	return nil
}

// ValidateDevice checks if a device binding is valid (idempotent).
func (s *AdminDeviceService) ValidateDevice(
	ctx context.Context,
	req AdminValidateDeviceRequest,
) (*AdminValidateDeviceResponse, error) {
	idempKey, _ := ctx.Value("idempotency_key").(string)
	if idempKey == "" {
		idempKey = fmt.Sprintf("validate-%s-%s", req.AdminID.String(), req.DeviceID)
	}
	ip, _ := ctx.Value("ip_address").(string)
	if ip == "" {
		ip = req.IPAddress
	}

	var cached AdminValidateDeviceResponse
	if err := s.idempotencyStore.Get(ctx, nil, idempKey, &cached); err == nil {
		return &cached, nil
	}

	isValid, err := s.deviceRepo.ValidateAdminDeviceBinding(ctx, req.AdminID, req.DeviceID, req.BindToken)
	if err != nil {
		return nil, fmt.Errorf("%w: validation error", appErrors.ErrInternal)
	}

	response := &AdminValidateDeviceResponse{
		IsValid: isValid,
	}
	if !isValid {
		response.Message = "Invalid admin device binding"
	}

	// Store idempotency result
	if err := s.idempotencyStore.Store(ctx, nil, idempKey, response); err != nil {
		// Non‑critical
	}

	if s.auditService != nil {
		status := "success"
		if !isValid {
			status = "failed"
		}
		_ = s.auditService.LogAction(ctx, nil, nil, "admin_device", "validate_device", "admin",
			&req.AdminID, "admin", &req.AdminID, nil, nil, map[string]interface{}{
				"device_id":  req.DeviceID,
				"is_valid":   isValid,
				"ip_address": ip,
				"status":     status,
			})
	}

	return response, nil
}

// GetDeviceBindingHistory retrieves binding history for an admin.
func (s *AdminDeviceService) GetDeviceBindingHistory(
	ctx context.Context,
	adminID uuid.UUID,
	limit int,
) ([]*models.UserActiveDevice, error) {
	if s.historyRepo != nil {
		history, err := s.historyRepo.GetAdminBindingHistory(ctx, adminID, limit)
		if err != nil {
			return nil, fmt.Errorf("%w: %v", appErrors.ErrNotFound, err)
		}
		if s.auditService != nil {
			_ = s.auditService.LogAction(ctx, nil, nil, "admin_device", "get_binding_history", "admin",
				&adminID, "admin", &adminID, nil, nil, map[string]interface{}{"limit": limit})
		}
		return history, nil
	}

	// Fallback: get active device only
	device, err := s.deviceRepo.GetAdminActiveDevice(ctx, adminID)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", appErrors.ErrNotFound, err)
	}
	if device == nil {
		return []*models.UserActiveDevice{}, nil
	}
	if s.auditService != nil {
		_ = s.auditService.LogAction(ctx, nil, nil, "admin_device", "get_binding_history", "admin",
			&adminID, "admin", &adminID, nil, nil, map[string]interface{}{"limit": limit})
	}
	return []*models.UserActiveDevice{device}, nil
}

// GetAdminsByDevice returns admins linked to a device.
func (s *AdminDeviceService) GetAdminsByDevice(
	ctx context.Context,
	deviceID string,
) ([]*models.UserActiveDevice, error) {
	var admins []*models.UserActiveDevice
	var err error
	if s.historyRepo != nil {
		admins, err = s.historyRepo.GetAdminRecentBindingsByDevice(ctx, deviceID, 50)
	} else {
		admins, err = s.deviceRepo.GetAdminsByDevice(ctx, deviceID)
	}
	if err != nil {
		return nil, fmt.Errorf("%w: %v", appErrors.ErrNotFound, err)
	}
	if s.auditService != nil {
		_ = s.auditService.LogAction(ctx, nil, nil, "admin_device", "get_admins_by_device", "device",
			nil, "system", nil, nil, nil, map[string]interface{}{"device_id": deviceID})
	}
	return admins, nil
}

// CleanupOrphanedDevices removes old unused device bindings.
func (s *AdminDeviceService) CleanupOrphanedDevices(
	ctx context.Context,
	olderThan time.Duration,
) (int, error) {
	cutoffTime := time.Now().Add(-olderThan)
	count, err := s.deviceRepo.CleanupAdminOrphanedDevices(ctx, cutoffTime)
	if err != nil {
		return 0, fmt.Errorf("%w: %v", appErrors.ErrInternal, err)
	}
	if s.auditService != nil {
		_ = s.auditService.LogAction(ctx, nil, nil, "admin_device", "cleanup_orphaned", "system",
			nil, "system", nil, nil, nil, map[string]interface{}{
				"older_than": olderThan.String(),
				"count":      count,
			})
	}
	return count, nil
}

// HealthCheck performs a health check on the underlying repositories.
func (s *AdminDeviceService) HealthCheck(ctx context.Context) error {
	if err := s.deviceRepo.HealthCheck(ctx); err != nil {
		return fmt.Errorf("%w: device repo health failed", appErrors.ErrInternal)
	}
	if s.historyRepo != nil {
		if err := s.historyRepo.HealthCheck(ctx); err != nil {
			return fmt.Errorf("%w: history repo health failed", appErrors.ErrInternal)
		}
	}
	return nil
}

// GetServiceStats returns statistics from the device repository.
func (s *AdminDeviceService) GetServiceStats(ctx context.Context) (map[string]interface{}, error) {
	stats, err := s.deviceRepo.GetAdminRepositoryStats(ctx)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", appErrors.ErrInternal, err)
	}
	return stats, nil
}

// IsDeviceTrusted checks if a device is trusted for an admin.
func (s *AdminDeviceService) IsDeviceTrusted(ctx context.Context, adminID uuid.UUID, deviceID string) (bool, error) {
	activeDevice, err := s.deviceRepo.GetAdminActiveDevice(ctx, adminID)
	if err != nil {
		return false, fmt.Errorf("%w: %v", appErrors.ErrNotFound, err)
	}
	if activeDevice == nil {
		return false, nil
	}
	return activeDevice.DeviceID == deviceID, nil
}

// GetDeviceTrustLevel returns the trust level for a device.
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

// BlockDevice blocks a device for an admin.
func (s *AdminDeviceService) BlockDevice(ctx context.Context, adminID uuid.UUID, deviceID string) error {
	if s.trustRepo == nil {
		return fmt.Errorf("%w: trust repository not available", appErrors.ErrInternal)
	}
	return s.trustRepo.BlockAdminDevice(ctx, adminID, deviceID)
}

// GetPrimaryDevice returns the primary device for an admin.
func (s *AdminDeviceService) GetPrimaryDevice(ctx context.Context, adminID uuid.UUID) (*models.DeviceTrustLevel, error) {
	if s.trustRepo == nil {
		return nil, fmt.Errorf("%w: trust repository not available", appErrors.ErrInternal)
	}
	return s.trustRepo.GetAdminPrimaryDevice(ctx, adminID)
}

// UpdateMPINDeviceBinding updates the MPIN device binding.
func (s *AdminDeviceService) UpdateMPINDeviceBinding(ctx context.Context, adminID uuid.UUID, deviceID string) error {
	if s.mpinRepo == nil {
		return fmt.Errorf("%w: MPIN repository not available", appErrors.ErrInternal)
	}
	return s.mpinRepo.UpdateAdminMPINDeviceBinding(ctx, adminID, deviceID)
}

// GetAdminDevices returns all devices for an admin.
func (s *AdminDeviceService) GetAdminDevices(ctx context.Context, adminID uuid.UUID) ([]*models.DeviceTrustLevel, error) {
	if s.trustRepo == nil {
		return nil, fmt.Errorf("%w: trust repository not available", appErrors.ErrInternal)
	}
	return s.trustRepo.GetAdminDevices(ctx, adminID)
}

// UpdateDeviceRiskScore updates the risk score for a device.
func (s *AdminDeviceService) UpdateDeviceRiskScore(ctx context.Context, adminID uuid.UUID, deviceID string, riskScore int) error {
	if s.trustRepo == nil {
		return fmt.Errorf("%w: trust repository not available", appErrors.ErrInternal)
	}
	return s.trustRepo.UpdateAdminDeviceRiskScore(ctx, adminID, deviceID, riskScore)
}

// RecordDataDeletion records a data deletion event.
func (s *AdminDeviceService) RecordDataDeletion(ctx context.Context, deletion *models.UserDataDeletion) error {
	if s.trustRepo == nil {
		return fmt.Errorf("%w: trust repository not available", appErrors.ErrInternal)
	}
	return s.trustRepo.RecordAdminDataDeletion(ctx, deletion)
}

// SetDeviceTrustLevel sets the trust level for a device.
func (s *AdminDeviceService) SetDeviceTrustLevel(
	ctx context.Context,
	adminID uuid.UUID,
	deviceID string,
	trust *models.DeviceTrustLevel,
) error {
	if s.trustRepo == nil {
		return fmt.Errorf("%w: trust repository not available", appErrors.ErrInternal)
	}
	return s.trustRepo.SetAdminDeviceTrustLevel(ctx, adminID, deviceID, trust)
}

// MarkAdminSuccessfulLogin updates trust level after successful login.
func (s *AdminDeviceService) MarkAdminSuccessfulLogin(
	ctx context.Context,
	adminID uuid.UUID,
	deviceID string,
	trustLevel *models.DeviceTrustLevel,
) error {
	if trustLevel.LastIPAddress != "" {
		if parsedIP := net.ParseIP(trustLevel.LastIPAddress); parsedIP == nil {
			// No logger; just clear invalid IP
			trustLevel.LastIPAddress = ""
		}
	}
	return s.trustRepo.MarkAdminSuccessfulLogin(ctx, adminID, deviceID, trustLevel)
}

// generateBindToken creates a secure random token.
func (s *AdminDeviceService) generateBindToken() (string, error) {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return base64.URLEncoding.EncodeToString(b), nil
}

// internal/service/admin_mpin_service.go
package service

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"net"
	"regexp"
	"sync"
	"time"

	"auth-service/internal/config"
	"auth-service/internal/encryption"
	"auth-service/internal/hashing"
	"auth-service/internal/models"
	"auth-service/internal/repository/scylla"
	"auth-service/internal/util"

	"github.com/google/uuid"
	"go.uber.org/zap"
)

var (
	ErrAdminMPINNotFound          = errors.New("admin MPIN not found")
	ErrAdminMPINInvalid           = errors.New("invalid admin MPIN")
	ErrAdminMPINLocked            = errors.New("admin MPIN is locked")
	ErrAdminMPINAlreadyExists     = errors.New("admin MPIN already exists")
	ErrAdminMPINTooWeak           = errors.New("admin MPIN is too weak")
	ErrAdminDeviceNotBound        = errors.New("device not bound to admin MPIN")
	ErrAdminDeviceNotTrusted      = errors.New("device is not trusted")
	ErrAdminMPINRateLimitExceeded = errors.New("MPIN rate limit exceeded")
	ErrAdminMPINAttemptsExceeded  = errors.New("maximum MPIN attempts exceeded")
)

const (
	AdminMPINMinLength        = 6
	AdminMPINMaxLength        = 8
	AdminMPINLockDuration     = 30 * time.Minute
	AdminMPINMaxAttempts      = 5
	AdminMPINVerifyRateLimit  = 5
	AdminMPINForgotRateLimit  = 3
	AdminMPINChangeRateLimit  = 5
	AdminMPINRateLimitWindow  = time.Minute
	AdminMPINForgotRateWindow = time.Hour
	AdminServiceVersion       = "v1.0.0"
	AdminMPINCacheDuration    = 5 * time.Minute
)

// Admin MPIN request/response structures
type AdminMPINSetupRequest struct {
	AdminID           uuid.UUID `json:"admin_id" validate:"required"`
	MPIN              string    `json:"mpin" validate:"required,min=6,max=8"`
	DeviceID          string    `json:"device_id" validate:"required"`
	IPAddress         string    `json:"ip_address"`
	DeviceFingerprint string    `json:"device_fingerprint"`
	UserAgent         string    `json:"user_agent"`
}

type AdminMPINVerifyRequest struct {
	AdminID           uuid.UUID `json:"admin_id" validate:"required"`
	MPIN              string    `json:"mpin" validate:"required"`
	DeviceID          string    `json:"device_id" validate:"required"`
	IPAddress         string    `json:"ip_address"`
	DeviceFingerprint string    `json:"device_fingerprint"`
	UserAgent         string    `json:"user_agent"` // ✅ ADDED USER AGENT
}

type AdminMPINVerifyResult struct {
	Verified       bool       `json:"verified"`
	FailedAttempts int        `json:"failed_attempts"`
	RemainingTries int        `json:"remaining_tries"`
	LockedUntil    *time.Time `json:"locked_until,omitempty"`
	Message        string     `json:"message"`
}

type AdminMPINChangeRequest struct {
	AdminID           uuid.UUID `json:"admin_id" validate:"required"`
	CurrentMPIN       string    `json:"current_mpin" validate:"required"`
	NewMPIN           string    `json:"new_mpin" validate:"required,min=6,max=8"`
	DeviceID          string    `json:"device_id" validate:"required"`
	IPAddress         string    `json:"ip_address"`
	DeviceFingerprint string    `json:"device_fingerprint"`
	UserAgent         string    `json:"user_agent"` // ✅ ADDED USER AGENT
}

type AdminMPINResetRequest struct {
	AdminID   uuid.UUID `json:"admin_id" validate:"required"`
	ResetBy   uuid.UUID `json:"reset_by" validate:"required"`
	Reason    string    `json:"reason" validate:"required"`
	IPAddress string    `json:"ip_address"`
	UserAgent string    `json:"user_agent"` // ✅ ADDED USER AGENT
}

type AdminMPINStatus struct {
	AdminID        uuid.UUID  `json:"admin_id"`
	Exists         bool       `json:"exists"`
	IsLocked       bool       `json:"is_locked"`
	FailedAttempts int        `json:"failed_attempts"`
	LockedUntil    *time.Time `json:"locked_until,omitempty"`
	LastChanged    *time.Time `json:"last_changed,omitempty"`
	DeviceID       string     `json:"device_id"`
}

type AdminMPINAdminChangeRequest struct {
	AdminID   uuid.UUID `json:"admin_id" validate:"required"`
	NewMPIN   string    `json:"new_mpin" validate:"required,min=6,max=8"`
	ChangedBy uuid.UUID `json:"changed_by" validate:"required"`
	Reason    string    `json:"reason,omitempty"`
	IPAddress string    `json:"ip_address"`
	UserAgent string    `json:"user_agent"` // ✅ ADDED USER AGENT
}

// Admin Forgot MPIN structures
type AdminMPINForgotRequest struct {
	PhoneNumber       string    `json:"phone_number" validate:"required"`
	AdminID           uuid.UUID `json:"admin_id"`
	DeviceID          string    `json:"device_id" validate:"required"`
	IPAddress         string    `json:"ip_address"`
	DeviceFingerprint string    `json:"device_fingerprint"`
	UserAgent         string    `json:"user_agent"`
}

type AdminMPINForgotWithOTPRequest struct {
	PhoneNumber       string    `json:"phone_number" validate:"required"`
	AdminID           uuid.UUID `json:"admin_id"`
	DeviceID          string    `json:"device_id" validate:"required"`
	NewMPIN           string    `json:"new_mpin" validate:"required,min=6,max=8"`
	OTPCode           string    `json:"otp_code" validate:"required,len=6"`
	IPAddress         string    `json:"ip_address"`
	DeviceFingerprint string    `json:"device_fingerprint"`
	UserAgent         string    `json:"user_agent,omitempty"`
}

// AdminMPINService handles all admin MPIN-related business logic
type AdminMPINService struct {
	mpinRepo        *scylla.AdminMPINRepositoryImpl
	adminRepo       scylla.AdminRepository
	deviceTrustRepo scylla.AdminDeviceTrustRepository
	otpService      *OTPService
	encryptionMgr   *encryption.EncryptionManager
	hasher          *hashing.Hasher
	config          *config.Config
	logger          *zap.Logger
	distCache       *DistributedCache
	logProducer     *LogProducerService
	cacheMutex      sync.RWMutex
}

func NewAdminMPINService(
	mpinRepo *scylla.AdminMPINRepositoryImpl,
	adminRepo scylla.AdminRepository,
	deviceTrustRepo scylla.AdminDeviceTrustRepository,
	otpService *OTPService,
	encryptionMgr *encryption.EncryptionManager,
	hasher *hashing.Hasher,
	cfg *config.Config,
	logger *zap.Logger,
	logProducer *LogProducerService,
) *AdminMPINService {
	return &AdminMPINService{
		mpinRepo:        mpinRepo,
		adminRepo:       adminRepo,
		deviceTrustRepo: deviceTrustRepo,
		hasher:          hasher,
		otpService:      otpService,
		config:          cfg,
		logger:          logger,
		encryptionMgr:   encryptionMgr,
		distCache:       nil,
		logProducer:     logProducer,
	}
}

// Helper function to hash device fingerprint
func (s *AdminMPINService) hashDeviceFingerprint(fingerprint string) string {
	if fingerprint == "" {
		return ""
	}
	hash := sha256.Sum256([]byte(fingerprint))
	return hex.EncodeToString(hash[:])
}

// Helper function to get subnet from IP address
func (s *AdminMPINService) getSubnet(ipAddress string) string {
	if ipAddress == "" {
		return ""
	}

	parsedIP := net.ParseIP(ipAddress)
	if parsedIP == nil {
		return ""
	}

	// For IPv4, use /24 subnet (first 3 octets)
	if ipv4 := parsedIP.To4(); ipv4 != nil {
		mask := net.CIDRMask(24, 32)
		maskedIP := ipv4.Mask(mask)
		return maskedIP.String()
	}

	// For IPv6, use /64 subnet (first 64 bits)
	if ipv6 := parsedIP.To16(); ipv6 != nil {
		mask := net.CIDRMask(64, 128)
		maskedIP := ipv6.Mask(mask)
		return maskedIP.String()
	}

	return ""
}

// Check if subnets match
func (s *AdminMPINService) isSubnetMatch(ip1, ip2 string) bool {
	if ip1 == "" || ip2 == "" {
		return true
	}

	subnet1 := s.getSubnet(ip1)
	subnet2 := s.getSubnet(ip2)

	if subnet1 == "" || subnet2 == "" {
		return true
	}

	return subnet1 == subnet2
}

// Enhanced device trust verification for MPIN operations
func (s *AdminMPINService) isDeviceTrusted(ctx context.Context, adminID uuid.UUID, deviceID, ipAddress, deviceFingerprint string) (bool, *models.DeviceTrustLevel, error) {
	trustLevel, err := s.deviceTrustRepo.GetAdminDeviceTrustLevel(ctx, adminID, deviceID)
	if err != nil {
		return false, nil, err
	}

	if trustLevel == nil {
		return false, nil, nil
	}

	// Check if device is blocked
	if trustLevel.IsBlocked {
		return false, trustLevel, nil
	}

	// Check trust status
	if trustLevel.TrustStatus != models.TrustStatusPrimary && trustLevel.TrustStatus != models.TrustStatusTrusted {
		return false, trustLevel, nil
	}

	// Check IP subnet mismatch
	if ipAddress != "" && trustLevel.LastIPAddress != "" && !s.isSubnetMatch(trustLevel.LastIPAddress, ipAddress) {
		s.logger.Warn("IP subnet mismatch for trusted device",
			util.String("admin_id", adminID.String()),
			util.String("device_id", deviceID),
			util.String("stored_ip", trustLevel.LastIPAddress),
			util.String("current_ip", ipAddress),
		)

		// Update risk score for subnet mismatch
		trustLevel.RiskScore += 15
		if err := s.deviceTrustRepo.SetAdminDeviceTrustLevel(ctx, adminID, deviceID, trustLevel); err != nil {
			s.logger.Warn("Failed to update risk score for subnet mismatch",
				util.ErrorField(err),
				util.String("admin_id", adminID.String()),
			)
		}
		return false, trustLevel, nil
	}

	// Check hashed device fingerprint
	hashedFingerprint := s.hashDeviceFingerprint(deviceFingerprint)
	if deviceFingerprint != "" && trustLevel.DeviceFingerprint != "" && trustLevel.DeviceFingerprint != hashedFingerprint {
		s.logger.Warn("Device fingerprint mismatch for trusted device",
			util.String("admin_id", adminID.String()),
			util.String("device_id", deviceID),
		)

		// Update risk score for fingerprint mismatch
		trustLevel.RiskScore += 10
		if err := s.deviceTrustRepo.SetAdminDeviceTrustLevel(ctx, adminID, deviceID, trustLevel); err != nil {
			s.logger.Warn("Failed to update risk score for fingerprint mismatch",
				util.ErrorField(err),
				util.String("admin_id", adminID.String()),
			)
		}
		return false, trustLevel, nil
	}

	return true, trustLevel, nil
}

// logAdminMPINEvent helper method
func (s *AdminMPINService) logAdminMPINEvent(ctx context.Context, event *models.MPINLogEvent) {
	if s.logProducer != nil {
		_ = s.logProducer.ProduceMPINEvent(ctx, event)
	}
}

func (s *AdminMPINService) SetDistributedCache(distCache *DistributedCache) {
	s.distCache = distCache
}

// Rate limiting methods with risk score updates
func (s *AdminMPINService) checkRateLimit(ctx context.Context, key string, limit int, window time.Duration) (bool, int) {
	if s.distCache == nil {
		return true, 0
	}

	allowed, retryAfter := s.distCache.AllowRate(ctx, key, limit, window)

	// Update risk score when rate limit is exceeded
	if !allowed {
		// Extract admin ID from key if possible
		if matches := regexp.MustCompile(`admin_mpin_[^:]+:([^:]+):`).FindStringSubmatch(key); len(matches) > 1 {
			if adminID, err := uuid.Parse(matches[1]); err == nil {
				go s.updateRiskScoreForRateLimit(ctx, adminID)
			}
		}
	}

	return allowed, retryAfter
}

// Update risk score for rate limit violations
func (s *AdminMPINService) updateRiskScoreForRateLimit(ctx context.Context, adminID uuid.UUID) {
	trustLevel, err := s.deviceTrustRepo.GetAdminDeviceTrustLevel(ctx, adminID, "")
	if err != nil || trustLevel == nil {
		return
	}

	trustLevel.RiskScore += 10
	if err := s.deviceTrustRepo.SetAdminDeviceTrustLevel(ctx, adminID, trustLevel.DeviceID, trustLevel); err != nil {
		s.logger.Warn("Failed to update risk score for rate limit",
			util.ErrorField(err),
			util.String("admin_id", adminID.String()),
		)
	}
}

// Update risk score for failed MPIN
func (s *AdminMPINService) updateRiskScoreForFailedMPIN(ctx context.Context, adminID uuid.UUID, deviceID string) {
	trustLevel, err := s.deviceTrustRepo.GetAdminDeviceTrustLevel(ctx, adminID, deviceID)
	if err != nil || trustLevel == nil {
		return
	}

	trustLevel.RiskScore += 10
	if err := s.deviceTrustRepo.SetAdminDeviceTrustLevel(ctx, adminID, deviceID, trustLevel); err != nil {
		s.logger.Warn("Failed to update risk score for failed MPIN",
			util.ErrorField(err),
			util.String("admin_id", adminID.String()),
		)
	}
}

// Update risk score for device mismatch
func (s *AdminMPINService) updateRiskScoreForDeviceMismatch(ctx context.Context, adminID uuid.UUID, deviceID string) {
	trustLevel, err := s.deviceTrustRepo.GetAdminDeviceTrustLevel(ctx, adminID, deviceID)
	if err != nil || trustLevel == nil {
		return
	}

	trustLevel.RiskScore += 10
	if err := s.deviceTrustRepo.SetAdminDeviceTrustLevel(ctx, adminID, deviceID, trustLevel); err != nil {
		s.logger.Warn("Failed to update risk score for device mismatch",
			util.ErrorField(err),
			util.String("admin_id", adminID.String()),
		)
	}
}

// Update risk score for OTP failures
func (s *AdminMPINService) updateRiskScoreForOTPFailure(ctx context.Context, adminID uuid.UUID, deviceID string) {
	trustLevel, err := s.deviceTrustRepo.GetAdminDeviceTrustLevel(ctx, adminID, deviceID)
	if err != nil || trustLevel == nil {
		return
	}

	trustLevel.RiskScore += 10
	if err := s.deviceTrustRepo.SetAdminDeviceTrustLevel(ctx, adminID, deviceID, trustLevel); err != nil {
		s.logger.Warn("Failed to update risk score for OTP failure",
			util.ErrorField(err),
			util.String("admin_id", adminID.String()),
		)
	}
}

func (s *AdminMPINService) validateAdminMPIN(mpin string) error {
	if len(mpin) < AdminMPINMinLength || len(mpin) > AdminMPINMaxLength {
		return fmt.Errorf("%w: admin MPIN must be between %d and %d digits", ErrInvalidInput, AdminMPINMinLength, AdminMPINMaxLength)
	}
	if matched, _ := regexp.MatchString(`^\d+$`, mpin); !matched {
		return fmt.Errorf("%w: admin MPIN must contain only digits", ErrInvalidInput)
	}
	if s.isAdminMPINWeak(mpin) {
		return ErrAdminMPINTooWeak
	}
	return nil
}

func (s *AdminMPINService) isAdminMPINWeak(mpin string) bool {
	if matched, _ := regexp.MatchString(`^(\d)\1+$`, mpin); matched {
		return true
	}
	if s.isSequential(mpin) {
		return true
	}
	weakAdminMPINs := []string{
		"123456", "000000", "111111", "222222", "333333", "444444",
		"555555", "666666", "777777", "888888", "999999", "112233",
		"123123", "654321", "121212", "131313", "123321",
	}
	for _, weak := range weakAdminMPINs {
		if mpin == weak {
			return true
		}
	}
	return false
}

func (s *AdminMPINService) isSequential(mpin string) bool {
	ascending := true
	descending := true
	for i := 1; i < len(mpin); i++ {
		if mpin[i] != mpin[i-1]+1 {
			ascending = false
		}
		if mpin[i] != mpin[i-1]-1 {
			descending = false
		}
	}
	return ascending || descending
}

// SetupAdminMPIN with hashed device fingerprint
func (s *AdminMPINService) SetupAdminMPIN(ctx context.Context, req *AdminMPINSetupRequest) error {
	startTime := time.Now()

	if s.hasher == nil {
		return fmt.Errorf("hasher service not available")
	}

	if !s.hasher.IsInitialized() {
		return fmt.Errorf("hasher not properly initialized - no pepper available")
	}

	s.logAdminMPINEvent(ctx, &models.MPINLogEvent{
		LogEnvelope: models.LogEnvelope{
			EventID:     uuid.New().String(),
			EventType:   string(models.LogEventTypeMPIN),
			ServiceName: "auth-service",
			Timestamp:   time.Now(),
			Environment: s.config.Environment,
			Version:     AdminServiceVersion,
			Level:       string(models.LogLevelInfo),
			Message:     "Admin MPIN setup initiated",
		},
		UserID:    req.AdminID.String(),
		Status:    "admin_setup_initiated",
		DeviceID:  req.DeviceID,
		UserAgent: req.UserAgent, // ✅ ADDED USER AGENT
	})

	if err := s.validateAdminMPIN(req.MPIN); err != nil {
		s.logAdminMPINEvent(ctx, &models.MPINLogEvent{
			LogEnvelope: models.LogEnvelope{
				EventID:     uuid.New().String(),
				EventType:   string(models.LogEventTypeMPIN),
				ServiceName: "auth-service",
				Timestamp:   time.Now(),
				Environment: s.config.Environment,
				Version:     AdminServiceVersion,
				Level:       string(models.LogLevelError),
				Message:     "Admin MPIN validation failed",
			},
			UserID:        req.AdminID.String(),
			Status:        "admin_setup_failed",
			DeviceID:      req.DeviceID,
			UserAgent:     req.UserAgent, // ✅ ADDED USER AGENT
			ErrorCode:     "VALIDATION_FAILED",
			ErrorMessage:  err.Error(),
			FailureReason: "admin_mpin_validation_failed",
		})
		return err
	}

	// Rate limiting for setup with risk score updates
	setupRateKey := fmt.Sprintf("admin_mpin_setup:%s:%s", req.AdminID.String(), req.DeviceID)
	if allowed, retryAfter := s.checkRateLimit(ctx, setupRateKey, 3, time.Hour); !allowed {
		s.logAdminMPINEvent(ctx, &models.MPINLogEvent{
			LogEnvelope: models.LogEnvelope{
				EventID:     uuid.New().String(),
				EventType:   string(models.LogEventTypeMPIN),
				ServiceName: "auth-service",
				Timestamp:   time.Now(),
				Environment: s.config.Environment,
				Version:     AdminServiceVersion,
				Level:       string(models.LogLevelWarning),
				Message:     "Admin MPIN setup rate limit exceeded",
			},
			UserID:       req.AdminID.String(),
			Status:       "admin_setup_rate_limited",
			DeviceID:     req.DeviceID,
			UserAgent:    req.UserAgent, // ✅ ADDED USER AGENT
			ErrorCode:    "RATE_LIMIT_EXCEEDED",
			AttemptsLeft: retryAfter,
		})
		return ErrAdminMPINRateLimitExceeded
	}

	admin, err := s.adminRepo.GetAdminByID(ctx, req.AdminID)
	if err != nil {
		s.logAdminMPINEvent(ctx, &models.MPINLogEvent{
			LogEnvelope: models.LogEnvelope{
				EventID:     uuid.New().String(),
				EventType:   string(models.LogEventTypeMPIN),
				ServiceName: "auth-service",
				Timestamp:   time.Now(),
				Environment: s.config.Environment,
				Version:     AdminServiceVersion,
				Level:       string(models.LogLevelError),
				Message:     "Admin not found for MPIN setup",
			},
			UserID:        req.AdminID.String(),
			Status:        "admin_setup_failed",
			DeviceID:      req.DeviceID,
			UserAgent:     req.UserAgent, // ✅ ADDED USER AGENT
			ErrorCode:     "ADMIN_NOT_FOUND",
			FailureReason: "admin_not_found",
		})
		return fmt.Errorf("%w: admin not found", ErrInvalidInput)
	}

	if !admin.IsActive {
		s.logAdminMPINEvent(ctx, &models.MPINLogEvent{
			LogEnvelope: models.LogEnvelope{
				EventID:     uuid.New().String(),
				EventType:   string(models.LogEventTypeMPIN),
				ServiceName: "auth-service",
				Timestamp:   time.Now(),
				Environment: s.config.Environment,
				Version:     AdminServiceVersion,
				Level:       string(models.LogLevelWarning),
				Message:     "Inactive admin attempted MPIN setup",
			},
			UserID:        req.AdminID.String(),
			Status:        "admin_setup_failed",
			DeviceID:      req.DeviceID,
			UserAgent:     req.UserAgent, // ✅ ADDED USER AGENT
			ErrorCode:     "ADMIN_INACTIVE",
			FailureReason: "admin_inactive",
		})
		return fmt.Errorf("admin account is inactive")
	}

	existingMPIN, err := s.mpinRepo.GetAdminMPINByAdminID(ctx, req.AdminID)
	if err == nil && existingMPIN != nil {
		s.logAdminMPINEvent(ctx, &models.MPINLogEvent{
			LogEnvelope: models.LogEnvelope{
				EventID:     uuid.New().String(),
				EventType:   string(models.LogEventTypeMPIN),
				ServiceName: "auth-service",
				Timestamp:   time.Now(),
				Environment: s.config.Environment,
				Version:     AdminServiceVersion,
				Level:       string(models.LogLevelWarning),
				Message:     "Admin MPIN already exists",
			},
			UserID:        req.AdminID.String(),
			Status:        "admin_setup_failed",
			DeviceID:      req.DeviceID,
			UserAgent:     req.UserAgent, // ✅ ADDED USER AGENT
			ErrorCode:     "ADMIN_MPIN_ALREADY_EXISTS",
			FailureReason: "admin_mpin_already_exists",
		})
		return ErrAdminMPINAlreadyExists
	}

	hashResult, err := s.hasher.HashMPIN(req.MPIN)
	if err != nil {
		s.logAdminMPINEvent(ctx, &models.MPINLogEvent{
			LogEnvelope: models.LogEnvelope{
				EventID:     uuid.New().String(),
				EventType:   string(models.LogEventTypeMPIN),
				ServiceName: "auth-service",
				Timestamp:   time.Now(),
				Environment: s.config.Environment,
				Version:     AdminServiceVersion,
				Level:       string(models.LogLevelError),
				Message:     "Failed to hash admin MPIN",
			},
			UserID:        req.AdminID.String(),
			Status:        "admin_setup_failed",
			DeviceID:      req.DeviceID,
			UserAgent:     req.UserAgent, // ✅ ADDED USER AGENT
			ErrorCode:     "HASHING_FAILED",
			ErrorMessage:  err.Error(),
			FailureReason: "hashing_failed",
		})
		return fmt.Errorf("failed to hash admin MPIN: %w", err)
	}

	now := time.Now().UTC()
	mpinCredential := &models.MPINCredential{
		UserID:         req.AdminID.String(),
		MPINHash:       hashResult.Hash,
		MPINSalt:       hashResult.Salt,
		PepperVersion:  hashResult.PepperVersion,
		HashAlgorithm:  hashResult.Algorithm,
		DeviceID:       req.DeviceID,
		LastChanged:    &now,
		FailedAttempts: 0,
		IsLocked:       false,
		LockedUntil:    nil,
	}

	if err := s.mpinRepo.CreateAdminMPIN(ctx, mpinCredential); err != nil {
		s.logAdminMPINEvent(ctx, &models.MPINLogEvent{
			LogEnvelope: models.LogEnvelope{
				EventID:     uuid.New().String(),
				EventType:   string(models.LogEventTypeMPIN),
				ServiceName: "auth-service",
				Timestamp:   time.Now(),
				Environment: s.config.Environment,
				Version:     AdminServiceVersion,
				Level:       string(models.LogLevelError),
				Message:     "Failed to create admin MPIN in repository",
			},
			UserID:        req.AdminID.String(),
			Status:        "admin_setup_failed",
			DeviceID:      req.DeviceID,
			UserAgent:     req.UserAgent, // ✅ ADDED USER AGENT
			ErrorCode:     "REPOSITORY_CREATE_FAILED",
			ErrorMessage:  err.Error(),
			FailureReason: "repository_create_failed",
		})
		return fmt.Errorf("failed to create admin MPIN: %w", err)
	}

	// Enhanced device trust setup with hashed fingerprint and IP
	trustLevel := &models.DeviceTrustLevel{
		UserID:            req.AdminID,
		DeviceID:          req.DeviceID,
		TrustStatus:       models.TrustStatusTrusted,
		DeviceFingerprint: s.hashDeviceFingerprint(req.DeviceFingerprint),
		LastIPAddress:     req.IPAddress,
		UserAgent:         req.UserAgent,
		IsBlocked:         false,
		RiskScore:         0,
	}

	if err := s.deviceTrustRepo.MarkAdminSuccessfulLogin(ctx, req.AdminID, req.DeviceID, trustLevel); err != nil {
		s.logger.Warn("Failed to set admin device trust level",
			util.ErrorField(err),
			util.String("admin_id", req.AdminID.String()),
			util.String("device_id", req.DeviceID),
		)
	}

	s.invalidateAdminMPINCache(ctx, req.AdminID)

	s.logAdminMPINEvent(ctx, &models.MPINLogEvent{
		LogEnvelope: models.LogEnvelope{
			EventID:     uuid.New().String(),
			EventType:   string(models.LogEventTypeMPIN),
			ServiceName: "auth-service",
			Timestamp:   time.Now(),
			Environment: s.config.Environment,
			Version:     AdminServiceVersion,
			Level:       string(models.LogLevelInfo),
			Message:     "Admin MPIN setup completed successfully",
		},
		UserID:    req.AdminID.String(),
		Status:    "admin_setup_completed",
		DeviceID:  req.DeviceID,
		UserAgent: req.UserAgent, // ✅ ADDED USER AGENT
		Duration:  int64(time.Since(startTime).Milliseconds()),
	})

	s.logger.Info("Admin MPIN setup completed",
		util.String("admin_id", req.AdminID.String()),
		util.String("device_id", req.DeviceID),
		util.String("user_agent", req.UserAgent), // ✅ ADDED USER AGENT
		util.Duration("duration", time.Since(startTime)),
	)
	return nil
}

// VerifyAdminMPIN with risk score updates for failures
func (s *AdminMPINService) VerifyAdminMPIN(ctx context.Context, req *AdminMPINVerifyRequest) (*AdminMPINVerifyResult, error) {
	startTime := time.Now()

	s.logAdminMPINEvent(ctx, &models.MPINLogEvent{
		LogEnvelope: models.LogEnvelope{
			EventID:     uuid.New().String(),
			EventType:   string(models.LogEventTypeMPIN),
			ServiceName: "auth-service",
			Timestamp:   time.Now(),
			Environment: s.config.Environment,
			Version:     AdminServiceVersion,
			Level:       string(models.LogLevelInfo),
			Message:     "Admin MPIN verification initiated",
		},
		UserID:    req.AdminID.String(),
		Status:    "admin_verification_initiated",
		DeviceID:  req.DeviceID,
		UserAgent: req.UserAgent, // ✅ ADDED USER AGENT
	})

	// Rate limiting for MPIN verification with risk score updates
	verifyRateKey := fmt.Sprintf("admin_mpin_verify:%s:%s", req.AdminID.String(), req.DeviceID)
	if allowed, retryAfter := s.checkRateLimit(ctx, verifyRateKey, AdminMPINVerifyRateLimit, AdminMPINRateLimitWindow); !allowed {
		s.logAdminMPINEvent(ctx, &models.MPINLogEvent{
			LogEnvelope: models.LogEnvelope{
				EventID:     uuid.New().String(),
				EventType:   string(models.LogEventTypeMPIN),
				ServiceName: "auth-service",
				Timestamp:   time.Now(),
				Environment: s.config.Environment,
				Version:     AdminServiceVersion,
				Level:       string(models.LogLevelWarning),
				Message:     "Admin MPIN verification rate limit exceeded",
			},
			UserID:       req.AdminID.String(),
			Status:       "admin_verification_rate_limited",
			DeviceID:     req.DeviceID,
			UserAgent:    req.UserAgent, // ✅ ADDED USER AGENT
			ErrorCode:    "RATE_LIMIT_EXCEEDED",
			AttemptsLeft: retryAfter,
		})
		return nil, ErrAdminMPINRateLimitExceeded
	}

	if err := s.validateAdminMPIN(req.MPIN); err != nil {
		s.logAdminMPINEvent(ctx, &models.MPINLogEvent{
			LogEnvelope: models.LogEnvelope{
				EventID:     uuid.New().String(),
				EventType:   string(models.LogEventTypeMPIN),
				ServiceName: "auth-service",
				Timestamp:   time.Now(),
				Environment: s.config.Environment,
				Version:     AdminServiceVersion,
				Level:       string(models.LogLevelError),
				Message:     "Admin MPIN validation failed",
			},
			UserID:        req.AdminID.String(),
			Status:        "admin_verification_failed",
			DeviceID:      req.DeviceID,
			UserAgent:     req.UserAgent, // ✅ ADDED USER AGENT
			ErrorCode:     "VALIDATION_FAILED",
			ErrorMessage:  err.Error(),
			FailureReason: "admin_mpin_validation_failed",
		})
		return nil, err
	}

	mpinCred, err := s.mpinRepo.ValidateAdminMPIN(ctx, req.AdminID, req.MPIN)
	if err != nil {
		if err.Error() == "MPIN not found for admin: "+req.AdminID.String() {
			s.logAdminMPINEvent(ctx, &models.MPINLogEvent{
				LogEnvelope: models.LogEnvelope{
					EventID:     uuid.New().String(),
					EventType:   string(models.LogEventTypeMPIN),
					ServiceName: "auth-service",
					Timestamp:   time.Now(),
					Environment: s.config.Environment,
					Version:     AdminServiceVersion,
					Level:       string(models.LogLevelWarning),
					Message:     "Admin MPIN not found for verification",
				},
				UserID:        req.AdminID.String(),
				Status:        "admin_verification_failed",
				DeviceID:      req.DeviceID,
				UserAgent:     req.UserAgent, // ✅ ADDED USER AGENT
				ErrorCode:     "ADMIN_MPIN_NOT_FOUND",
				FailureReason: "admin_mpin_not_found",
			})
			return nil, ErrAdminMPINNotFound
		}
		if err.Error() == "MPIN locked due to too many failed attempts" {
			result := &AdminMPINVerifyResult{
				Verified:       false,
				FailedAttempts: AdminMPINMaxAttempts,
				RemainingTries: 0,
				Message:        "Admin MPIN is locked due to too many failed attempts",
			}
			s.logAdminMPINEvent(ctx, &models.MPINLogEvent{
				LogEnvelope: models.LogEnvelope{
					EventID:     uuid.New().String(),
					EventType:   string(models.LogEventTypeMPIN),
					ServiceName: "auth-service",
					Timestamp:   time.Now(),
					Environment: s.config.Environment,
					Version:     AdminServiceVersion,
					Level:       string(models.LogLevelWarning),
					Message:     "Admin MPIN verification failed - locked",
				},
				UserID:        req.AdminID.String(),
				Status:        "admin_verification_failed",
				DeviceID:      req.DeviceID,
				UserAgent:     req.UserAgent, // ✅ ADDED USER AGENT
				Attempts:      AdminMPINMaxAttempts,
				AttemptsLeft:  0,
				IsLocked:      true,
				ErrorCode:     "ADMIN_MPIN_LOCKED",
				FailureReason: "admin_mpin_locked",
			})
			return result, ErrAdminMPINLocked
		}

		s.logAdminMPINEvent(ctx, &models.MPINLogEvent{
			LogEnvelope: models.LogEnvelope{
				EventID:     uuid.New().String(),
				EventType:   string(models.LogEventTypeMPIN),
				ServiceName: "auth-service",
				Timestamp:   time.Now(),
				Environment: s.config.Environment,
				Version:     AdminServiceVersion,
				Level:       string(models.LogLevelError),
				Message:     "Admin MPIN validation repository error",
			},
			UserID:        req.AdminID.String(),
			Status:        "admin_verification_failed",
			DeviceID:      req.DeviceID,
			UserAgent:     req.UserAgent, // ✅ ADDED USER AGENT
			ErrorCode:     "REPOSITORY_ERROR",
			ErrorMessage:  err.Error(),
			FailureReason: "repository_error",
		})
		return nil, err
	}

	if mpinCred.DeviceID != "" && req.DeviceID != "" && mpinCred.DeviceID != req.DeviceID {
		s.logAdminMPINEvent(ctx, &models.MPINLogEvent{
			LogEnvelope: models.LogEnvelope{
				EventID:     uuid.New().String(),
				EventType:   string(models.LogEventTypeMPIN),
				ServiceName: "auth-service",
				Timestamp:   time.Now(),
				Environment: s.config.Environment,
				Version:     AdminServiceVersion,
				Level:       string(models.LogLevelWarning),
				Message:     "Device mismatch during admin MPIN verification",
			},
			UserID:    req.AdminID.String(),
			Status:    "admin_device_mismatch",
			DeviceID:  req.DeviceID,
			UserAgent: req.UserAgent, // ✅ ADDED USER AGENT
		})
		s.logger.Warn("Device mismatch during admin MPIN verification",
			util.String("admin_id", req.AdminID.String()),
			util.String("expected_device", mpinCred.DeviceID),
			util.String("provided_device", req.DeviceID),
			util.String("user_agent", req.UserAgent), // ✅ ADDED USER AGENT
		)

		// Update risk score for device mismatch
		go s.updateRiskScoreForDeviceMismatch(ctx, req.AdminID, req.DeviceID)
	}

	hashResult := &hashing.HashResult{
		Hash:          mpinCred.MPINHash,
		Salt:          mpinCred.MPINSalt,
		PepperVersion: mpinCred.PepperVersion,
		Algorithm:     mpinCred.HashAlgorithm,
	}

	verified, err := s.hasher.VerifyMPIN(req.MPIN, hashResult)
	if err != nil {
		s.logAdminMPINEvent(ctx, &models.MPINLogEvent{
			LogEnvelope: models.LogEnvelope{
				EventID:     uuid.New().String(),
				EventType:   string(models.LogEventTypeMPIN),
				ServiceName: "auth-service",
				Timestamp:   time.Now(),
				Environment: s.config.Environment,
				Version:     AdminServiceVersion,
				Level:       string(models.LogLevelError),
				Message:     "Failed to verify admin MPIN hash",
			},
			UserID:        req.AdminID.String(),
			Status:        "admin_verification_failed",
			DeviceID:      req.DeviceID,
			UserAgent:     req.UserAgent, // ✅ ADDED USER AGENT
			ErrorCode:     "HASH_VERIFICATION_FAILED",
			ErrorMessage:  err.Error(),
			FailureReason: "hash_verification_failed",
		})
		return nil, fmt.Errorf("failed to verify admin MPIN: %w", err)
	}

	result := &AdminMPINVerifyResult{
		Verified:       verified,
		FailedAttempts: mpinCred.FailedAttempts,
		RemainingTries: max(0, AdminMPINMaxAttempts-mpinCred.FailedAttempts),
	}

	if verified {
		if err := s.mpinRepo.ResetAdminFailedAttempts(ctx, req.AdminID); err != nil {
			s.logger.Error("Failed to reset admin failed attempts",
				util.ErrorField(err),
				util.String("admin_id", req.AdminID.String()),
			)
		}
		result.Message = "Admin MPIN verified successfully"
		result.FailedAttempts = 0
		result.RemainingTries = AdminMPINMaxAttempts

		// Update device trust with hashed fingerprint and current IP
		trustLevel := &models.DeviceTrustLevel{
			UserID:            req.AdminID,
			DeviceID:          req.DeviceID,
			TrustStatus:       models.TrustStatusTrusted,
			DeviceFingerprint: s.hashDeviceFingerprint(req.DeviceFingerprint),
			LastIPAddress:     req.IPAddress,
			UserAgent:         req.UserAgent, // ✅ ADDED USER AGENT
			IsBlocked:         false,
			RiskScore:         0, // Reset risk score on successful verification
		}

		if err := s.deviceTrustRepo.MarkAdminSuccessfulLogin(ctx, req.AdminID, req.DeviceID, trustLevel); err != nil {
			s.logger.Warn("Failed to update admin device trust on successful login",
				util.ErrorField(err),
				util.String("admin_id", req.AdminID.String()),
			)
		}

		s.logAdminMPINEvent(ctx, &models.MPINLogEvent{
			LogEnvelope: models.LogEnvelope{
				EventID:     uuid.New().String(),
				EventType:   string(models.LogEventTypeMPIN),
				ServiceName: "auth-service",
				Timestamp:   time.Now(),
				Environment: s.config.Environment,
				Version:     AdminServiceVersion,
				Level:       string(models.LogLevelInfo),
				Message:     "Admin MPIN verified successfully",
			},
			UserID:       req.AdminID.String(),
			Status:       "admin_verification_successful",
			DeviceID:     req.DeviceID,
			UserAgent:    req.UserAgent, // ✅ ADDED USER AGENT
			Attempts:     0,
			AttemptsLeft: AdminMPINMaxAttempts,
			IsLocked:     false,
			Duration:     int64(time.Since(startTime).Milliseconds()),
		})
	} else {
		newFailedAttempts, err := s.mpinRepo.IncrementAdminFailedAttempts(ctx, req.AdminID)
		if err != nil {
			s.logger.Error("Failed to increment admin failed attempts",
				util.ErrorField(err),
				util.String("admin_id", req.AdminID.String()),
			)
		} else {
			result.FailedAttempts = newFailedAttempts
			result.RemainingTries = max(0, AdminMPINMaxAttempts-newFailedAttempts)
		}

		// Update risk score for failed MPIN verification
		go s.updateRiskScoreForFailedMPIN(ctx, req.AdminID, req.DeviceID)

		if result.RemainingTries == 0 {
			result.Message = "Admin MPIN is now locked due to too many failed attempts"
			lockUntil := time.Now().Add(AdminMPINLockDuration)
			result.LockedUntil = &lockUntil

			s.logAdminMPINEvent(ctx, &models.MPINLogEvent{
				LogEnvelope: models.LogEnvelope{
					EventID:     uuid.New().String(),
					EventType:   string(models.LogEventTypeMPIN),
					ServiceName: "auth-service",
					Timestamp:   time.Now(),
					Environment: s.config.Environment,
					Version:     AdminServiceVersion,
					Level:       string(models.LogLevelWarning),
					Message:     "Admin MPIN locked due to failed attempts",
				},
				UserID:       req.AdminID.String(),
				Status:       "admin_mpin_locked",
				DeviceID:     req.DeviceID,
				UserAgent:    req.UserAgent, // ✅ ADDED USER AGENT
				Attempts:     newFailedAttempts,
				AttemptsLeft: 0,
				IsLocked:     true,
				Duration:     int64(time.Since(startTime).Milliseconds()),
			})
		} else {
			result.Message = fmt.Sprintf("Invalid admin MPIN. %d attempts remaining", result.RemainingTries)

			s.logAdminMPINEvent(ctx, &models.MPINLogEvent{
				LogEnvelope: models.LogEnvelope{
					EventID:     uuid.New().String(),
					EventType:   string(models.LogEventTypeMPIN),
					ServiceName: "auth-service",
					Timestamp:   time.Now(),
					Environment: s.config.Environment,
					Version:     AdminServiceVersion,
					Level:       string(models.LogLevelWarning),
					Message:     "Admin MPIN verification failed",
				},
				UserID:       req.AdminID.String(),
				Status:       "admin_verification_failed",
				DeviceID:     req.DeviceID,
				UserAgent:    req.UserAgent, // ✅ ADDED USER AGENT
				Attempts:     newFailedAttempts,
				AttemptsLeft: result.RemainingTries,
				IsLocked:     false,
				Duration:     int64(time.Since(startTime).Milliseconds()),
			})
		}
	}

	s.logger.Info("Admin MPIN verification completed",
		util.String("admin_id", req.AdminID.String()),
		util.Bool("verified", verified),
		util.Int("failed_attempts", result.FailedAttempts),
		util.String("user_agent", req.UserAgent), // ✅ ADDED USER AGENT
		util.Duration("duration", time.Since(startTime)),
	)

	return result, nil
}

// ChangeAdminMPIN changes an admin's MPIN (requires old MPIN)
func (s *AdminMPINService) ChangeAdminMPIN(ctx context.Context, req *AdminMPINChangeRequest) error {
	startTime := time.Now()

	s.logAdminMPINEvent(ctx, &models.MPINLogEvent{
		LogEnvelope: models.LogEnvelope{
			EventID:     uuid.New().String(),
			EventType:   string(models.LogEventTypeMPIN),
			ServiceName: "auth-service",
			Timestamp:   time.Now(),
			Environment: s.config.Environment,
			Version:     AdminServiceVersion,
			Level:       string(models.LogLevelInfo),
			Message:     "Admin MPIN change initiated",
		},
		UserID:    req.AdminID.String(),
		Status:    "admin_change_initiated",
		DeviceID:  req.DeviceID,
		UserAgent: req.UserAgent, // ✅ ADDED USER AGENT
	})

	// Rate limiting for MPIN change with risk score updates
	changeRateKey := fmt.Sprintf("admin_mpin_change:%s:%s", req.AdminID.String(), req.DeviceID)
	if allowed, retryAfter := s.checkRateLimit(ctx, changeRateKey, AdminMPINChangeRateLimit, AdminMPINForgotRateWindow); !allowed {
		s.logAdminMPINEvent(ctx, &models.MPINLogEvent{
			LogEnvelope: models.LogEnvelope{
				EventID:     uuid.New().String(),
				EventType:   string(models.LogEventTypeMPIN),
				ServiceName: "auth-service",
				Timestamp:   time.Now(),
				Environment: s.config.Environment,
				Version:     AdminServiceVersion,
				Level:       string(models.LogLevelWarning),
				Message:     "Admin MPIN change rate limit exceeded",
			},
			UserID:       req.AdminID.String(),
			Status:       "admin_change_rate_limited",
			DeviceID:     req.DeviceID,
			UserAgent:    req.UserAgent, // ✅ ADDED USER AGENT
			ErrorCode:    "RATE_LIMIT_EXCEEDED",
			AttemptsLeft: retryAfter,
		})
		return ErrAdminMPINRateLimitExceeded
	}

	if err := s.validateAdminMPIN(req.NewMPIN); err != nil {
		s.logAdminMPINEvent(ctx, &models.MPINLogEvent{
			LogEnvelope: models.LogEnvelope{
				EventID:     uuid.New().String(),
				EventType:   string(models.LogEventTypeMPIN),
				ServiceName: "auth-service",
				Timestamp:   time.Now(),
				Environment: s.config.Environment,
				Version:     AdminServiceVersion,
				Level:       string(models.LogLevelError),
				Message:     "New admin MPIN validation failed",
			},
			UserID:        req.AdminID.String(),
			Status:        "admin_change_failed",
			DeviceID:      req.DeviceID,
			UserAgent:     req.UserAgent, // ✅ ADDED USER AGENT
			ErrorCode:     "VALIDATION_FAILED",
			ErrorMessage:  err.Error(),
			FailureReason: "new_admin_mpin_validation_failed",
		})
		return err
	}

	verifyReq := &AdminMPINVerifyRequest{
		AdminID:           req.AdminID,
		MPIN:              req.CurrentMPIN,
		DeviceID:          req.DeviceID,
		IPAddress:         req.IPAddress,
		DeviceFingerprint: req.DeviceFingerprint,
		UserAgent:         req.UserAgent, // ✅ ADDED USER AGENT
	}

	verifyResult, err := s.VerifyAdminMPIN(ctx, verifyReq)
	if err != nil {
		return err
	}

	if !verifyResult.Verified {
		s.logAdminMPINEvent(ctx, &models.MPINLogEvent{
			LogEnvelope: models.LogEnvelope{
				EventID:     uuid.New().String(),
				EventType:   string(models.LogEventTypeMPIN),
				ServiceName: "auth-service",
				Timestamp:   time.Now(),
				Environment: s.config.Environment,
				Version:     AdminServiceVersion,
				Level:       string(models.LogLevelWarning),
				Message:     "Current admin MPIN verification failed for change",
			},
			UserID:        req.AdminID.String(),
			Status:        "admin_change_failed",
			DeviceID:      req.DeviceID,
			UserAgent:     req.UserAgent, // ✅ ADDED USER AGENT
			ErrorCode:     "CURRENT_ADMIN_MPIN_INVALID",
			FailureReason: "current_admin_mpin_invalid",
		})
		return ErrAdminMPINInvalid
	}

	hashResult, err := s.hasher.HashMPIN(req.NewMPIN)
	if err != nil {
		s.logAdminMPINEvent(ctx, &models.MPINLogEvent{
			LogEnvelope: models.LogEnvelope{
				EventID:     uuid.New().String(),
				EventType:   string(models.LogEventTypeMPIN),
				ServiceName: "auth-service",
				Timestamp:   time.Now(),
				Environment: s.config.Environment,
				Version:     AdminServiceVersion,
				Level:       string(models.LogLevelError),
				Message:     "Failed to hash new admin MPIN",
			},
			UserID:        req.AdminID.String(),
			Status:        "admin_change_failed",
			DeviceID:      req.DeviceID,
			UserAgent:     req.UserAgent, // ✅ ADDED USER AGENT
			ErrorCode:     "HASHING_FAILED",
			ErrorMessage:  err.Error(),
			FailureReason: "hashing_failed",
		})
		return fmt.Errorf("failed to hash new admin MPIN: %w", err)
	}

	if err := s.mpinRepo.UpdateAdminMPIN(ctx, req.AdminID, hashResult.Hash, hashResult.Salt, hashResult.PepperVersion); err != nil {
		s.logAdminMPINEvent(ctx, &models.MPINLogEvent{
			LogEnvelope: models.LogEnvelope{
				EventID:     uuid.New().String(),
				EventType:   string(models.LogEventTypeMPIN),
				ServiceName: "auth-service",
				Timestamp:   time.Now(),
				Environment: s.config.Environment,
				Version:     AdminServiceVersion,
				Level:       string(models.LogLevelError),
				Message:     "Failed to update admin MPIN in repository",
			},
			UserID:        req.AdminID.String(),
			Status:        "admin_change_failed",
			DeviceID:      req.DeviceID,
			UserAgent:     req.UserAgent, // ✅ ADDED USER AGENT
			ErrorCode:     "REPOSITORY_UPDATE_FAILED",
			ErrorMessage:  err.Error(),
			FailureReason: "repository_update_failed",
		})
		return fmt.Errorf("failed to update admin MPIN: %w", err)
	}

	if err := s.mpinRepo.UpdateAdminMPINDeviceBinding(ctx, req.AdminID, req.DeviceID); err != nil {
		s.logger.Warn("Failed to update admin MPIN device binding",
			util.ErrorField(err),
			util.String("admin_id", req.AdminID.String()),
		)
	}

	s.invalidateAdminMPINCache(ctx, req.AdminID)

	s.logAdminMPINEvent(ctx, &models.MPINLogEvent{
		LogEnvelope: models.LogEnvelope{
			EventID:     uuid.New().String(),
			EventType:   string(models.LogEventTypeMPIN),
			ServiceName: "auth-service",
			Timestamp:   time.Now(),
			Environment: s.config.Environment,
			Version:     AdminServiceVersion,
			Level:       string(models.LogLevelInfo),
			Message:     "Admin MPIN changed successfully",
		},
		UserID:    req.AdminID.String(),
		Status:    "admin_change_completed",
		DeviceID:  req.DeviceID,
		UserAgent: req.UserAgent, // ✅ ADDED USER AGENT
		Duration:  int64(time.Since(startTime).Milliseconds()),
	})

	s.logger.Info("Admin MPIN changed successfully",
		util.String("admin_id", req.AdminID.String()),
		util.String("device_id", req.DeviceID),
		util.String("user_agent", req.UserAgent), // ✅ ADDED USER AGENT
		util.Duration("duration", time.Since(startTime)),
	)

	return nil
}

// ForgotAdminMPIN with device trust checks handled by MPIN service
func (s *AdminMPINService) ForgotAdminMPIN(ctx context.Context, req *AdminMPINForgotRequest) error {
	startTime := time.Now()

	s.logAdminMPINEvent(ctx, &models.MPINLogEvent{
		LogEnvelope: models.LogEnvelope{
			EventID:     uuid.New().String(),
			EventType:   string(models.LogEventTypeMPIN),
			ServiceName: "auth-service",
			Timestamp:   time.Now(),
			Environment: s.config.Environment,
			Version:     AdminServiceVersion,
			Level:       string(models.LogLevelInfo),
			Message:     "Forgot admin MPIN flow initiated",
		},
		UserID:    req.AdminID.String(),
		Status:    "admin_forgot_initiated",
		DeviceID:  req.DeviceID,
		UserAgent: req.UserAgent, // ✅ ADDED USER AGENT
	})

	// Rate limiting for forgot MPIN
	forgotRateKey := fmt.Sprintf("admin_mpin_forgot:%s:%s", req.AdminID.String(), req.DeviceID)
	if allowed, retryAfter := s.checkRateLimit(ctx, forgotRateKey, AdminMPINForgotRateLimit, AdminMPINForgotRateWindow); !allowed {
		s.logAdminMPINEvent(ctx, &models.MPINLogEvent{
			LogEnvelope: models.LogEnvelope{
				EventID:     uuid.New().String(),
				EventType:   string(models.LogEventTypeMPIN),
				ServiceName: "auth-service",
				Timestamp:   time.Now(),
				Environment: s.config.Environment,
				Version:     AdminServiceVersion,
				Level:       string(models.LogLevelWarning),
				Message:     "Admin MPIN forgot rate limit exceeded",
			},
			UserID:       req.AdminID.String(),
			Status:       "admin_forgot_rate_limited",
			DeviceID:     req.DeviceID,
			UserAgent:    req.UserAgent, // ✅ ADDED USER AGENT
			ErrorCode:    "RATE_LIMIT_EXCEEDED",
			AttemptsLeft: retryAfter,
		})
		return ErrAdminMPINRateLimitExceeded
	}

	// CHECK: Device trust handled by MPIN service
	isTrusted, trustLevel, err := s.isDeviceTrusted(ctx, req.AdminID, req.DeviceID, req.IPAddress, req.DeviceFingerprint)
	if err != nil {
		s.logAdminMPINEvent(ctx, &models.MPINLogEvent{
			LogEnvelope: models.LogEnvelope{
				EventID:     uuid.New().String(),
				EventType:   string(models.LogEventTypeMPIN),
				ServiceName: "auth-service",
				Timestamp:   time.Now(),
				Environment: s.config.Environment,
				Version:     AdminServiceVersion,
				Level:       string(models.LogLevelError),
				Message:     "Device trust check failed for forgot MPIN",
			},
			UserID:        req.AdminID.String(),
			Status:        "admin_forgot_failed",
			DeviceID:      req.DeviceID,
			UserAgent:     req.UserAgent, // ✅ ADDED USER AGENT
			ErrorCode:     "DEVICE_TRUST_CHECK_FAILED",
			ErrorMessage:  err.Error(),
			FailureReason: "device_trust_check_failed",
		})
		return fmt.Errorf("device trust check failed: %w", err)
	}

	if !isTrusted {
		// Update risk score for untrusted device attempting forgot MPIN
		if trustLevel != nil {
			trustLevel.RiskScore += 10
			if updateErr := s.deviceTrustRepo.SetAdminDeviceTrustLevel(ctx, req.AdminID, req.DeviceID, trustLevel); updateErr != nil {
				s.logger.Warn("Failed to update risk score for untrusted device",
					util.ErrorField(updateErr),
					util.String("admin_id", req.AdminID.String()),
				)
			}
		}

		s.logAdminMPINEvent(ctx, &models.MPINLogEvent{
			LogEnvelope: models.LogEnvelope{
				EventID:     uuid.New().String(),
				EventType:   string(models.LogEventTypeMPIN),
				ServiceName: "auth-service",
				Timestamp:   time.Now(),
				Environment: s.config.Environment,
				Version:     AdminServiceVersion,
				Level:       string(models.LogLevelWarning),
				Message:     "Untrusted device attempted forgot MPIN",
			},
			UserID:        req.AdminID.String(),
			Status:        "admin_forgot_failed",
			DeviceID:      req.DeviceID,
			UserAgent:     req.UserAgent, // ✅ ADDED USER AGENT
			ErrorCode:     "DEVICE_NOT_TRUSTED",
			FailureReason: "device_not_trusted",
		})
		return ErrAdminDeviceNotTrusted
	}

	// Send OTP for verification on trusted device
	admin, err := s.adminRepo.GetAdminByID(ctx, req.AdminID)
	if err != nil {
		s.logAdminMPINEvent(ctx, &models.MPINLogEvent{
			LogEnvelope: models.LogEnvelope{
				EventID:     uuid.New().String(),
				EventType:   string(models.LogEventTypeMPIN),
				ServiceName: "auth-service",
				Timestamp:   time.Now(),
				Environment: s.config.Environment,
				Version:     AdminServiceVersion,
				Level:       string(models.LogLevelError),
				Message:     "Admin not found for forgot MPIN",
			},
			UserID:        req.AdminID.String(),
			Status:        "admin_forgot_failed",
			DeviceID:      req.DeviceID,
			UserAgent:     req.UserAgent, // ✅ ADDED USER AGENT
			ErrorCode:     "ADMIN_NOT_FOUND",
			FailureReason: "admin_not_found",
		})
		return fmt.Errorf("admin not found: %w", err)
	}

	encryptedData := &encryption.EncryptedData{
		EncryptedValue: admin.PhoneEncrypted,
		EncryptedDEK:   admin.PhoneEncryptedDEK,
		KeyID:          admin.PhoneKeyID.String(),
		Version:        "v1",
		CreatedAt:      admin.AdminCreatedAt,
	}

	phoneNumber, err := s.encryptionMgr.DecryptField(ctx, encryptedData)
	if err != nil {
		s.logAdminMPINEvent(ctx, &models.MPINLogEvent{
			LogEnvelope: models.LogEnvelope{
				EventID:     uuid.New().String(),
				EventType:   string(models.LogEventTypeMPIN),
				ServiceName: "auth-service",
				Timestamp:   time.Now(),
				Environment: s.config.Environment,
				Version:     AdminServiceVersion,
				Level:       string(models.LogLevelError),
				Message:     "Failed to decrypt phone number for forgot MPIN",
			},
			UserID:        req.AdminID.String(),
			Status:        "admin_forgot_failed",
			DeviceID:      req.DeviceID,
			UserAgent:     req.UserAgent, // ✅ ADDED USER AGENT
			ErrorCode:     "PHONE_DECRYPTION_FAILED",
			ErrorMessage:  err.Error(),
			FailureReason: "phone_decryption_failed",
		})
		return fmt.Errorf("failed to decrypt admin phone number: %w", err)
	}

	// Send OTP for verification
	otpReq := &OTPSendRequest{
		PhoneNumber:       phoneNumber,
		Purpose:           "forgot_mpin",
		IPAddress:         req.IPAddress,
		DeviceID:          req.DeviceID,
		DeviceFingerprint: req.DeviceFingerprint,
		UserAgent:         req.UserAgent,
	}

	otpResp, err := s.otpService.SendOTP(ctx, otpReq)
	if err != nil {
		s.logAdminMPINEvent(ctx, &models.MPINLogEvent{
			LogEnvelope: models.LogEnvelope{
				EventID:     uuid.New().String(),
				EventType:   string(models.LogEventTypeMPIN),
				ServiceName: "auth-service",
				Timestamp:   time.Now(),
				Environment: s.config.Environment,
				Version:     AdminServiceVersion,
				Level:       string(models.LogLevelError),
				Message:     "Failed to send OTP for forgot MPIN",
			},
			UserID:        req.AdminID.String(),
			Status:        "admin_forgot_failed",
			DeviceID:      req.DeviceID,
			UserAgent:     req.UserAgent, // ✅ ADDED USER AGENT
			ErrorCode:     "OTP_SEND_FAILED",
			ErrorMessage:  err.Error(),
			FailureReason: "otp_send_failed",
		})
		return fmt.Errorf("failed to send OTP: %w", err)
	}

	if !otpResp.Success {
		s.logAdminMPINEvent(ctx, &models.MPINLogEvent{
			LogEnvelope: models.LogEnvelope{
				EventID:     uuid.New().String(),
				EventType:   string(models.LogEventTypeMPIN),
				ServiceName: "auth-service",
				Timestamp:   time.Now(),
				Environment: s.config.Environment,
				Version:     AdminServiceVersion,
				Level:       string(models.LogLevelError),
				Message:     "OTP send failed for forgot MPIN",
			},
			UserID:        req.AdminID.String(),
			Status:        "admin_forgot_failed",
			DeviceID:      req.DeviceID,
			UserAgent:     req.UserAgent, // ✅ ADDED USER AGENT
			ErrorCode:     "OTP_SEND_FAILED",
			ErrorMessage:  otpResp.Message,
			FailureReason: "otp_send_failed",
		})
		return fmt.Errorf("OTP send failed: %s", otpResp.Message)
	}

	s.logAdminMPINEvent(ctx, &models.MPINLogEvent{
		LogEnvelope: models.LogEnvelope{
			EventID:     uuid.New().String(),
			EventType:   string(models.LogEventTypeMPIN),
			ServiceName: "auth-service",
			Timestamp:   time.Now(),
			Environment: s.config.Environment,
			Version:     AdminServiceVersion,
			Level:       string(models.LogLevelInfo),
			Message:     "OTP sent for forgot MPIN on trusted device",
		},
		UserID:      req.AdminID.String(),
		Status:      "admin_forgot_otp_sent",
		DeviceID:    req.DeviceID,
		UserAgent:   req.UserAgent, // ✅ ADDED USER AGENT
		DeviceTrust: string(trustLevel.TrustStatus),
		Duration:    int64(time.Since(startTime).Milliseconds()),
	})

	s.logger.Info("OTP sent for admin forgot MPIN on trusted device",
		util.String("admin_id", req.AdminID.String()),
		util.String("device_id", req.DeviceID),
		util.String("user_agent", req.UserAgent), // ✅ ADDED USER AGENT
		util.String("trust_status", string(trustLevel.TrustStatus)),
	)

	return nil
}

// VerifyForgotAdminMPINOTP with device trust checks handled by MPIN service
func (s *AdminMPINService) VerifyForgotAdminMPINOTP(ctx context.Context, req *AdminMPINForgotWithOTPRequest) error {
	startTime := time.Now()

	s.logAdminMPINEvent(ctx, &models.MPINLogEvent{
		LogEnvelope: models.LogEnvelope{
			EventID:     uuid.New().String(),
			EventType:   string(models.LogEventTypeMPIN),
			ServiceName: "auth-service",
			Timestamp:   time.Now(),
			Environment: s.config.Environment,
			Version:     AdminServiceVersion,
			Level:       string(models.LogLevelInfo),
			Message:     "Forgot admin MPIN OTP verification initiated",
		},
		UserID:    req.AdminID.String(),
		Status:    "admin_forgot_otp_verification_initiated",
		DeviceID:  req.DeviceID,
		UserAgent: req.UserAgent,
	})

	// CHECK: Device trust handled by MPIN service
	isTrusted, trustLevel, err := s.isDeviceTrusted(ctx, req.AdminID, req.DeviceID, req.IPAddress, req.DeviceFingerprint)
	if err != nil {
		s.logAdminMPINEvent(ctx, &models.MPINLogEvent{
			LogEnvelope: models.LogEnvelope{
				EventID:     uuid.New().String(),
				EventType:   string(models.LogEventTypeMPIN),
				ServiceName: "auth-service",
				Timestamp:   time.Now(),
				Environment: s.config.Environment,
				Version:     AdminServiceVersion,
				Level:       string(models.LogLevelError),
				Message:     "Device trust check failed for forgot MPIN OTP",
			},
			UserID:        req.AdminID.String(),
			Status:        "admin_forgot_otp_verification_failed",
			DeviceID:      req.DeviceID,
			UserAgent:     req.UserAgent,
			ErrorCode:     "DEVICE_TRUST_CHECK_FAILED",
			ErrorMessage:  err.Error(),
			FailureReason: "device_trust_check_failed",
		})
		return fmt.Errorf("device trust check failed: %w", err)
	}

	if !isTrusted {
		// Update risk score for untrusted device attempting OTP verification
		if trustLevel != nil {
			trustLevel.RiskScore += 10
			if updateErr := s.deviceTrustRepo.SetAdminDeviceTrustLevel(ctx, req.AdminID, req.DeviceID, trustLevel); updateErr != nil {
				s.logger.Warn("Failed to update risk score for untrusted device in OTP verification",
					util.ErrorField(updateErr),
					util.String("admin_id", req.AdminID.String()),
				)
			}
		}

		s.logAdminMPINEvent(ctx, &models.MPINLogEvent{
			LogEnvelope: models.LogEnvelope{
				EventID:     uuid.New().String(),
				EventType:   string(models.LogEventTypeMPIN),
				ServiceName: "auth-service",
				Timestamp:   time.Now(),
				Environment: s.config.Environment,
				Version:     AdminServiceVersion,
				Level:       string(models.LogLevelWarning),
				Message:     "Untrusted device attempted forgot MPIN OTP verification",
			},
			UserID:        req.AdminID.String(),
			Status:        "admin_forgot_otp_verification_failed",
			DeviceID:      req.DeviceID,
			UserAgent:     req.UserAgent,
			ErrorCode:     "DEVICE_NOT_TRUSTED",
			FailureReason: "device_not_trusted",
		})
		return ErrAdminDeviceNotTrusted
	}

	if err := s.validateAdminMPIN(req.NewMPIN); err != nil {
		s.logAdminMPINEvent(ctx, &models.MPINLogEvent{
			LogEnvelope: models.LogEnvelope{
				EventID:     uuid.New().String(),
				EventType:   string(models.LogEventTypeMPIN),
				ServiceName: "auth-service",
				Timestamp:   time.Now(),
				Environment: s.config.Environment,
				Version:     AdminServiceVersion,
				Level:       string(models.LogLevelError),
				Message:     "MPIN validation failed for forgot admin MPIN OTP",
			},
			UserID:        req.AdminID.String(),
			Status:        "admin_forgot_otp_verification_failed",
			DeviceID:      req.DeviceID,
			UserAgent:     req.UserAgent,
			ErrorCode:     "VALIDATION_FAILED",
			ErrorMessage:  err.Error(),
			FailureReason: "admin_mpin_validation_failed",
		})
		return err
	}

	admin, err := s.adminRepo.GetAdminByID(ctx, req.AdminID)
	if err != nil {
		s.logAdminMPINEvent(ctx, &models.MPINLogEvent{
			LogEnvelope: models.LogEnvelope{
				EventID:     uuid.New().String(),
				EventType:   string(models.LogEventTypeMPIN),
				ServiceName: "auth-service",
				Timestamp:   time.Now(),
				Environment: s.config.Environment,
				Version:     AdminServiceVersion,
				Level:       string(models.LogLevelError),
				Message:     "Admin not found for forgot MPIN OTP verification",
			},
			UserID:        req.AdminID.String(),
			Status:        "admin_forgot_otp_verification_failed",
			DeviceID:      req.DeviceID,
			UserAgent:     req.UserAgent,
			ErrorCode:     "ADMIN_NOT_FOUND",
			FailureReason: "admin_not_found",
		})
		return fmt.Errorf("admin not found: %w", err)
	}

	encryptedData := &encryption.EncryptedData{
		EncryptedValue: admin.PhoneEncrypted,
		EncryptedDEK:   admin.PhoneEncryptedDEK,
		KeyID:          admin.PhoneKeyID.String(),
		Version:        "v1",
		CreatedAt:      admin.AdminCreatedAt,
	}

	phoneNumber, err := s.encryptionMgr.DecryptField(ctx, encryptedData)
	if err != nil {
		s.logAdminMPINEvent(ctx, &models.MPINLogEvent{
			LogEnvelope: models.LogEnvelope{
				EventID:     uuid.New().String(),
				EventType:   string(models.LogEventTypeMPIN),
				ServiceName: "auth-service",
				Timestamp:   time.Now(),
				Environment: s.config.Environment,
				Version:     AdminServiceVersion,
				Level:       string(models.LogLevelError),
				Message:     "Failed to decrypt phone number for forgot admin MPIN OTP verification",
			},
			UserID:        req.AdminID.String(),
			Status:        "admin_forgot_otp_verification_failed",
			DeviceID:      req.DeviceID,
			UserAgent:     req.UserAgent,
			ErrorCode:     "PHONE_DECRYPTION_FAILED",
			ErrorMessage:  err.Error(),
			FailureReason: "phone_decryption_failed",
		})
		return fmt.Errorf("failed to decrypt admin phone number: %w", err)
	}

	// ✅ UPDATED: Pass UserAgent to OTP verification
	otpVerifyReq := &OTPVerifyRequest{
		PhoneNumber:       phoneNumber,
		OTP:               req.OTPCode,
		Purpose:           "forgot_mpin",
		IPAddress:         req.IPAddress,
		DeviceID:          req.DeviceID,
		DeviceFingerprint: req.DeviceFingerprint,
		UserAgent:         req.UserAgent,
	}

	otpResp, err := s.otpService.VerifyOTP(ctx, otpVerifyReq)
	if err != nil {
		// Update risk score for OTP verification failure
		go s.updateRiskScoreForOTPFailure(ctx, req.AdminID, req.DeviceID)

		s.logAdminMPINEvent(ctx, &models.MPINLogEvent{
			LogEnvelope: models.LogEnvelope{
				EventID:     uuid.New().String(),
				EventType:   string(models.LogEventTypeMPIN),
				ServiceName: "auth-service",
				Timestamp:   time.Now(),
				Environment: s.config.Environment,
				Version:     AdminServiceVersion,
				Level:       string(models.LogLevelWarning),
				Message:     "OTP verification failed for forgot admin MPIN",
			},
			UserID:        req.AdminID.String(),
			Status:        "admin_forgot_otp_verification_failed",
			DeviceID:      req.DeviceID,
			UserAgent:     req.UserAgent,
			ErrorCode:     "OTP_VERIFICATION_FAILED",
			ErrorMessage:  err.Error(),
			FailureReason: "otp_verification_failed",
		})
		return fmt.Errorf("invalid OTP code")
	}

	if !otpResp.Success {
		// Update risk score for invalid OTP
		go s.updateRiskScoreForOTPFailure(ctx, req.AdminID, req.DeviceID)

		s.logAdminMPINEvent(ctx, &models.MPINLogEvent{
			LogEnvelope: models.LogEnvelope{
				EventID:     uuid.New().String(),
				EventType:   string(models.LogEventTypeMPIN),
				ServiceName: "auth-service",
				Timestamp:   time.Now(),
				Environment: s.config.Environment,
				Version:     AdminServiceVersion,
				Level:       string(models.LogLevelWarning),
				Message:     "Invalid OTP code for forgot admin MPIN",
			},
			UserID:        req.AdminID.String(),
			Status:        "admin_forgot_otp_verification_failed",
			DeviceID:      req.DeviceID,
			UserAgent:     req.UserAgent,
			ErrorCode:     "INVALID_OTP",
			FailureReason: "invalid_otp",
		})
		return fmt.Errorf("invalid OTP code")
	}

	hashResult, err := s.hasher.HashMPIN(req.NewMPIN)
	if err != nil {
		s.logAdminMPINEvent(ctx, &models.MPINLogEvent{
			LogEnvelope: models.LogEnvelope{
				EventID:     uuid.New().String(),
				EventType:   string(models.LogEventTypeMPIN),
				ServiceName: "auth-service",
				Timestamp:   time.Now(),
				Environment: s.config.Environment,
				Version:     AdminServiceVersion,
				Level:       string(models.LogLevelError),
				Message:     "Failed to hash MPIN for forgot admin MPIN OTP",
			},
			UserID:        req.AdminID.String(),
			Status:        "admin_forgot_otp_verification_failed",
			DeviceID:      req.DeviceID,
			UserAgent:     req.UserAgent,
			ErrorCode:     "HASHING_FAILED",
			ErrorMessage:  err.Error(),
			FailureReason: "hashing_failed",
		})
		return fmt.Errorf("failed to hash admin MPIN: %w", err)
	}

	if err := s.mpinRepo.UpdateAdminMPIN(ctx, req.AdminID, hashResult.Hash, hashResult.Salt, hashResult.PepperVersion); err != nil {
		s.logAdminMPINEvent(ctx, &models.MPINLogEvent{
			LogEnvelope: models.LogEnvelope{
				EventID:     uuid.New().String(),
				EventType:   string(models.LogEventTypeMPIN),
				ServiceName: "auth-service",
				Timestamp:   time.Now(),
				Environment: s.config.Environment,
				Version:     AdminServiceVersion,
				Level:       string(models.LogLevelError),
				Message:     "Failed to update MPIN for forgot admin MPIN OTP",
			},
			UserID:        req.AdminID.String(),
			Status:        "admin_forgot_otp_verification_failed",
			DeviceID:      req.DeviceID,
			UserAgent:     req.UserAgent,
			ErrorCode:     "MPIN_UPDATE_FAILED",
			ErrorMessage:  err.Error(),
			FailureReason: "mpin_update_failed",
		})
		return fmt.Errorf("failed to update admin MPIN: %w", err)
	}

	_ = s.mpinRepo.UnlockAdminMPIN(ctx, req.AdminID)

	// Update device trust with hashed fingerprint and current information
	updatedTrustLevel := &models.DeviceTrustLevel{
		UserID:            req.AdminID,
		DeviceID:          req.DeviceID,
		TrustStatus:       models.TrustStatusTrusted,
		DeviceFingerprint: s.hashDeviceFingerprint(req.DeviceFingerprint),
		LastIPAddress:     req.IPAddress,
		UserAgent:         req.UserAgent, // ✅ ADDED USER AGENT
		IsBlocked:         false,
		RiskScore:         0, // Reset risk score on successful reset
	}

	if err := s.deviceTrustRepo.SetAdminDeviceTrustLevel(ctx, req.AdminID, req.DeviceID, updatedTrustLevel); err != nil {
		s.logger.Warn("Failed to update admin device trust level",
			util.ErrorField(err),
			util.String("admin_id", req.AdminID.String()),
		)
	}

	s.invalidateAdminMPINCache(ctx, req.AdminID)

	s.logAdminMPINEvent(ctx, &models.MPINLogEvent{
		LogEnvelope: models.LogEnvelope{
			EventID:     uuid.New().String(),
			EventType:   string(models.LogEventTypeMPIN),
			ServiceName: "auth-service",
			Timestamp:   time.Now(),
			Environment: s.config.Environment,
			Version:     AdminServiceVersion,
			Level:       string(models.LogLevelInfo),
			Message:     "Admin MPIN reset via forgot with OTP verification completed",
		},
		UserID:      req.AdminID.String(),
		Status:      "admin_forgot_otp_verification_completed",
		DeviceID:    req.DeviceID,
		UserAgent:   req.UserAgent,
		DeviceTrust: string(trustLevel.TrustStatus),
		Duration:    int64(time.Since(startTime).Milliseconds()),
	})

	s.logger.Info("Admin MPIN reset via forgot with OTP verification on trusted device",
		util.String("admin_id", req.AdminID.String()),
		util.String("device_id", req.DeviceID),
		util.String("user_agent", req.UserAgent),
		util.String("trust_status", string(trustLevel.TrustStatus)),
	)

	return nil
}

// ChangeAdminMPINByAdmin changes admin MPIN by another admin (admin override)
func (s *AdminMPINService) ChangeAdminMPINByAdmin(ctx context.Context, req *AdminMPINAdminChangeRequest) error {
	startTime := time.Now()

	s.logAdminMPINEvent(ctx, &models.MPINLogEvent{
		LogEnvelope: models.LogEnvelope{
			EventID:     uuid.New().String(),
			EventType:   string(models.LogEventTypeMPIN),
			ServiceName: "auth-service",
			Timestamp:   time.Now(),
			Environment: s.config.Environment,
			Version:     AdminServiceVersion,
			Level:       string(models.LogLevelInfo),
			Message:     "Admin MPIN change by admin initiated",
		},
		UserID:    req.AdminID.String(),
		Status:    "admin_change_by_admin_initiated",
		UserAgent: req.UserAgent, // ✅ ADDED USER AGENT
	})

	if err := s.validateAdminMPIN(req.NewMPIN); err != nil {
		s.logAdminMPINEvent(ctx, &models.MPINLogEvent{
			LogEnvelope: models.LogEnvelope{
				EventID:     uuid.New().String(),
				EventType:   string(models.LogEventTypeMPIN),
				ServiceName: "auth-service",
				Timestamp:   time.Now(),
				Environment: s.config.Environment,
				Version:     AdminServiceVersion,
				Level:       string(models.LogLevelError),
				Message:     "New admin MPIN validation failed for admin change",
			},
			UserID:        req.AdminID.String(),
			Status:        "admin_change_by_admin_failed",
			UserAgent:     req.UserAgent, // ✅ ADDED USER AGENT
			ErrorCode:     "VALIDATION_FAILED",
			ErrorMessage:  err.Error(),
			FailureReason: "new_admin_mpin_validation_failed",
		})
		return err
	}

	admin, err := s.adminRepo.GetAdminByID(ctx, req.AdminID)
	if err != nil {
		s.logAdminMPINEvent(ctx, &models.MPINLogEvent{
			LogEnvelope: models.LogEnvelope{
				EventID:     uuid.New().String(),
				EventType:   string(models.LogEventTypeMPIN),
				ServiceName: "auth-service",
				Timestamp:   time.Now(),
				Environment: s.config.Environment,
				Version:     AdminServiceVersion,
				Level:       string(models.LogLevelError),
				Message:     "Admin not found for admin MPIN change",
			},
			UserID:        req.AdminID.String(),
			Status:        "admin_change_by_admin_failed",
			UserAgent:     req.UserAgent, // ✅ ADDED USER AGENT
			ErrorCode:     "ADMIN_NOT_FOUND",
			FailureReason: "admin_not_found",
		})
		return fmt.Errorf("admin not found: %w", err)
	}

	if !admin.IsActive {
		s.logAdminMPINEvent(ctx, &models.MPINLogEvent{
			LogEnvelope: models.LogEnvelope{
				EventID:     uuid.New().String(),
				EventType:   string(models.LogEventTypeMPIN),
				ServiceName: "auth-service",
				Timestamp:   time.Now(),
				Environment: s.config.Environment,
				Version:     AdminServiceVersion,
				Level:       string(models.LogLevelWarning),
				Message:     "Inactive admin for admin MPIN change",
			},
			UserID:        req.AdminID.String(),
			Status:        "admin_change_by_admin_failed",
			UserAgent:     req.UserAgent, // ✅ ADDED USER AGENT
			ErrorCode:     "ADMIN_INACTIVE",
			FailureReason: "admin_inactive",
		})
		return fmt.Errorf("admin account is inactive")
	}

	hashResult, err := s.hasher.HashMPIN(req.NewMPIN)
	if err != nil {
		s.logAdminMPINEvent(ctx, &models.MPINLogEvent{
			LogEnvelope: models.LogEnvelope{
				EventID:     uuid.New().String(),
				EventType:   string(models.LogEventTypeMPIN),
				ServiceName: "auth-service",
				Timestamp:   time.Now(),
				Environment: s.config.Environment,
				Version:     AdminServiceVersion,
				Level:       string(models.LogLevelError),
				Message:     "Failed to hash MPIN for admin change",
			},
			UserID:        req.AdminID.String(),
			Status:        "admin_change_by_admin_failed",
			UserAgent:     req.UserAgent, // ✅ ADDED USER AGENT
			ErrorCode:     "HASHING_FAILED",
			ErrorMessage:  err.Error(),
			FailureReason: "hashing_failed",
		})
		return fmt.Errorf("failed to hash admin MPIN: %w", err)
	}

	if err := s.mpinRepo.UpdateAdminMPIN(ctx, req.AdminID, hashResult.Hash, hashResult.Salt, hashResult.PepperVersion); err != nil {
		s.logAdminMPINEvent(ctx, &models.MPINLogEvent{
			LogEnvelope: models.LogEnvelope{
				EventID:     uuid.New().String(),
				EventType:   string(models.LogEventTypeMPIN),
				ServiceName: "auth-service",
				Timestamp:   time.Now(),
				Environment: s.config.Environment,
				Version:     AdminServiceVersion,
				Level:       string(models.LogLevelError),
				Message:     "Failed to update admin MPIN in repository for admin change",
			},
			UserID:        req.AdminID.String(),
			Status:        "admin_change_by_admin_failed",
			UserAgent:     req.UserAgent, // ✅ ADDED USER AGENT
			ErrorCode:     "REPOSITORY_UPDATE_FAILED",
			ErrorMessage:  err.Error(),
			FailureReason: "repository_update_failed",
		})
		return fmt.Errorf("failed to update admin MPIN: %w", err)
	}

	_ = s.mpinRepo.UnlockAdminMPIN(ctx, req.AdminID)

	s.invalidateAdminMPINCache(ctx, req.AdminID)

	s.logAdminMPINEvent(ctx, &models.MPINLogEvent{
		LogEnvelope: models.LogEnvelope{
			EventID:     uuid.New().String(),
			EventType:   string(models.LogEventTypeMPIN),
			ServiceName: "auth-service",
			Timestamp:   time.Now(),
			Environment: s.config.Environment,
			Version:     AdminServiceVersion,
			Level:       string(models.LogLevelWarning),
			Message:     "Admin MPIN changed by admin successfully",
		},
		UserID:    req.AdminID.String(),
		Status:    "admin_change_by_admin_completed",
		UserAgent: req.UserAgent, // ✅ ADDED USER AGENT
		Duration:  int64(time.Since(startTime).Milliseconds()),
	})

	s.logger.Warn("Admin MPIN changed by admin",
		util.String("admin_id", req.AdminID.String()),
		util.String("changed_by", req.ChangedBy.String()),
		util.String("reason", req.Reason),
		util.String("user_agent", req.UserAgent), // ✅ ADDED USER AGENT
		util.Duration("duration", time.Since(startTime)),
	)

	return nil
}

// ResetAdminMPIN resets admin MPIN (admin override - unlocks only)
func (s *AdminMPINService) ResetAdminMPIN(ctx context.Context, req *AdminMPINResetRequest) error {
	startTime := time.Now()

	s.logAdminMPINEvent(ctx, &models.MPINLogEvent{
		LogEnvelope: models.LogEnvelope{
			EventID:     uuid.New().String(),
			EventType:   string(models.LogEventTypeMPIN),
			ServiceName: "auth-service",
			Timestamp:   time.Now(),
			Environment: s.config.Environment,
			Version:     AdminServiceVersion,
			Level:       string(models.LogLevelInfo),
			Message:     "Admin MPIN reset initiated",
		},
		UserID:    req.AdminID.String(),
		Status:    "admin_reset_initiated",
		UserAgent: req.UserAgent, // ✅ ADDED USER AGENT
	})

	_, err := s.mpinRepo.GetAdminMPINByAdminID(ctx, req.AdminID)
	if err != nil {
		s.logAdminMPINEvent(ctx, &models.MPINLogEvent{
			LogEnvelope: models.LogEnvelope{
				EventID:     uuid.New().String(),
				EventType:   string(models.LogEventTypeMPIN),
				ServiceName: "auth-service",
				Timestamp:   time.Now(),
				Environment: s.config.Environment,
				Version:     AdminServiceVersion,
				Level:       string(models.LogLevelWarning),
				Message:     "Admin MPIN not found for reset",
			},
			UserID:        req.AdminID.String(),
			Status:        "admin_reset_failed",
			UserAgent:     req.UserAgent, // ✅ ADDED USER AGENT
			ErrorCode:     "ADMIN_MPIN_NOT_FOUND",
			FailureReason: "admin_mpin_not_found",
		})
		return ErrAdminMPINNotFound
	}

	if err := s.mpinRepo.UnlockAdminMPIN(ctx, req.AdminID); err != nil {
		s.logAdminMPINEvent(ctx, &models.MPINLogEvent{
			LogEnvelope: models.LogEnvelope{
				EventID:     uuid.New().String(),
				EventType:   string(models.LogEventTypeMPIN),
				ServiceName: "auth-service",
				Timestamp:   time.Now(),
				Environment: s.config.Environment,
				Version:     AdminServiceVersion,
				Level:       string(models.LogLevelError),
				Message:     "Failed to unlock admin MPIN for reset",
			},
			UserID:        req.AdminID.String(),
			Status:        "admin_reset_failed",
			UserAgent:     req.UserAgent, // ✅ ADDED USER AGENT
			ErrorCode:     "UNLOCK_FAILED",
			ErrorMessage:  err.Error(),
			FailureReason: "unlock_failed",
		})
		return fmt.Errorf("failed to unlock admin MPIN: %w", err)
	}

	s.invalidateAdminMPINCache(ctx, req.AdminID)

	s.logAdminMPINEvent(ctx, &models.MPINLogEvent{
		LogEnvelope: models.LogEnvelope{
			EventID:     uuid.New().String(),
			EventType:   string(models.LogEventTypeMPIN),
			ServiceName: "auth-service",
			Timestamp:   time.Now(),
			Environment: s.config.Environment,
			Version:     AdminServiceVersion,
			Level:       string(models.LogLevelWarning),
			Message:     "Admin MPIN reset by admin completed",
		},
		UserID:    req.AdminID.String(),
		Status:    "admin_reset_completed",
		UserAgent: req.UserAgent, // ✅ ADDED USER AGENT
		Duration:  int64(time.Since(startTime).Milliseconds()),
	})

	s.logger.Warn("Admin MPIN reset by admin",
		util.String("admin_id", req.AdminID.String()),
		util.String("reset_by", req.ResetBy.String()),
		util.String("reason", req.Reason),
		util.String("user_agent", req.UserAgent), // ✅ ADDED USER AGENT
		util.Duration("duration", time.Since(startTime)),
	)

	return nil
}

// UnlockAdminMPIN unlocks a locked admin MPIN
func (s *AdminMPINService) UnlockAdminMPIN(ctx context.Context, adminID uuid.UUID) error {
	s.logAdminMPINEvent(ctx, &models.MPINLogEvent{
		LogEnvelope: models.LogEnvelope{
			EventID:     uuid.New().String(),
			EventType:   string(models.LogEventTypeMPIN),
			ServiceName: "auth-service",
			Timestamp:   time.Now(),
			Environment: s.config.Environment,
			Version:     AdminServiceVersion,
			Level:       string(models.LogLevelInfo),
			Message:     "Admin MPIN unlock initiated",
		},
		UserID: adminID.String(),
		Status: "admin_unlock_initiated",
	})

	if err := s.mpinRepo.UnlockAdminMPIN(ctx, adminID); err != nil {
		s.logAdminMPINEvent(ctx, &models.MPINLogEvent{
			LogEnvelope: models.LogEnvelope{
				EventID:     uuid.New().String(),
				EventType:   string(models.LogEventTypeMPIN),
				ServiceName: "auth-service",
				Timestamp:   time.Now(),
				Environment: s.config.Environment,
				Version:     AdminServiceVersion,
				Level:       string(models.LogLevelError),
				Message:     "Failed to unlock admin MPIN",
			},
			UserID:        adminID.String(),
			Status:        "admin_unlock_failed",
			ErrorCode:     "UNLOCK_FAILED",
			ErrorMessage:  err.Error(),
			FailureReason: "unlock_failed",
		})
		return fmt.Errorf("failed to unlock admin MPIN: %w", err)
	}

	s.invalidateAdminMPINCache(ctx, adminID)

	s.logAdminMPINEvent(ctx, &models.MPINLogEvent{
		LogEnvelope: models.LogEnvelope{
			EventID:     uuid.New().String(),
			EventType:   string(models.LogEventTypeMPIN),
			ServiceName: "auth-service",
			Timestamp:   time.Now(),
			Environment: s.config.Environment,
			Version:     AdminServiceVersion,
			Level:       string(models.LogLevelInfo),
			Message:     "Admin MPIN unlocked successfully",
		},
		UserID: adminID.String(),
		Status: "admin_unlock_completed",
	})

	return nil
}

// GetAdminMPINStatus retrieves the status of an admin's MPIN
func (s *AdminMPINService) GetAdminMPINStatus(ctx context.Context, adminID uuid.UUID) (*AdminMPINStatus, error) {
	s.logger.Debug("🔍 GetAdminMPINStatus called",
		util.String("admin_id", adminID.String()))

	mpinCred, err := s.mpinRepo.GetAdminMPINByAdminID(ctx, adminID)
	if err != nil {
		s.logger.Error("❌ Error getting admin MPIN",
			util.ErrorField(err),
			util.String("admin_id", adminID.String()))
		return nil, err
	}

	if mpinCred == nil {
		s.logger.Debug("❌ No MPIN found - returning Exists: false",
			util.String("admin_id", adminID.String()))
		return &AdminMPINStatus{
			AdminID:        adminID,
			Exists:         false,
			IsLocked:       false,
			FailedAttempts: 0,
			LockedUntil:    nil,
			LastChanged:    nil,
			DeviceID:       "",
		}, nil
	}

	s.logger.Debug("✅ MPIN exists - returning Exists: true",
		util.String("admin_id", adminID.String()),
		util.Bool("is_locked", mpinCred.IsLocked))

	return &AdminMPINStatus{
		AdminID:        adminID,
		Exists:         true,
		IsLocked:       mpinCred.IsLocked,
		FailedAttempts: mpinCred.FailedAttempts,
		LockedUntil:    mpinCred.LockedUntil,
		LastChanged:    mpinCred.LastChanged,
		DeviceID:       mpinCred.DeviceID,
	}, nil
}

// UpdateAdminMPINDeviceBinding updates the device binding for an admin MPIN
func (s *AdminMPINService) UpdateAdminMPINDeviceBinding(ctx context.Context, adminID uuid.UUID, deviceID string) error {
	if err := s.mpinRepo.UpdateAdminMPINDeviceBinding(ctx, adminID, deviceID); err != nil {
		return fmt.Errorf("failed to update admin device binding: %w", err)
	}

	s.invalidateAdminMPINCache(ctx, adminID)

	return nil
}

// GetAdminMPINsByDevice retrieves all admin MPINs for a specific device
func (s *AdminMPINService) GetAdminMPINsByDevice(ctx context.Context, deviceID string) ([]*models.MPINCredential, error) {
	return s.mpinRepo.GetAdminMPINsByDevice(ctx, deviceID)
}

// GetAdminLockedMPINs retrieves locked admin MPINs
func (s *AdminMPINService) GetAdminLockedMPINs(ctx context.Context, limit int) ([]*models.MPINCredential, error) {
	return s.mpinRepo.GetAdminLockedMPINs(ctx, limit)
}

// CleanupAdminExpiredLocks cleans up expired MPIN locks
func (s *AdminMPINService) CleanupAdminExpiredLocks(ctx context.Context) (int, error) {
	return s.mpinRepo.CleanupAdminUnlockedMPINs(ctx)
}

// GetAdminMPINStats retrieves statistics about admin MPINs
func (s *AdminMPINService) GetAdminMPINStats(ctx context.Context) (map[string]interface{}, error) {
	stats, err := s.mpinRepo.GetAdminRepositoryStats(ctx)
	if err != nil {
		return nil, err
	}

	stats["service_constants"] = map[string]interface{}{
		"min_length":            AdminMPINMinLength,
		"max_length":            AdminMPINMaxLength,
		"max_attempts":          AdminMPINMaxAttempts,
		"lock_duration_minutes": int(AdminMPINLockDuration.Minutes()),
		"rate_limits": map[string]interface{}{
			"verify_per_minute": AdminMPINVerifyRateLimit,
			"forgot_per_hour":   AdminMPINForgotRateLimit,
			"change_per_hour":   AdminMPINChangeRateLimit,
		},
	}

	return stats, nil
}

// HealthCheck performs a health check on the service
func (s *AdminMPINService) HealthCheck(ctx context.Context) error {
	return s.mpinRepo.HealthCheck(ctx)
}

// invalidateAdminMPINCache invalidates the cache for a specific admin MPIN
func (s *AdminMPINService) invalidateAdminMPINCache(ctx context.Context, adminID uuid.UUID) {
	if s.distCache != nil {
		cacheKey := fmt.Sprintf("admin_mpin:%s", adminID.String())
		_ = s.distCache.Delete(ctx, cacheKey)
	}
}

// SetLogProducerService sets the log producer service
func (s *AdminMPINService) SetLogProducerService(logProducer *LogProducerService) {
	s.logProducer = logProducer
}

// DebugHasherStatus returns debug information about the hasher
func (s *AdminMPINService) DebugHasherStatus(ctx context.Context) map[string]interface{} {
	status := s.hasher.GetStatus()

	// Get sample admin MPIN credential to check pepper version
	adminID, _ := uuid.Parse("your-test-admin-id")
	mpinCred, err := s.mpinRepo.GetAdminMPINByAdminID(ctx, adminID)
	if err == nil {
		status["sample_admin_mpin_pepper_version"] = mpinCred.PepperVersion
		status["sample_admin_mpin_algorithm"] = mpinCred.HashAlgorithm
	}

	return status
}

// GetAdminDeviceRiskScore gets the current risk score for an admin device
func (s *AdminMPINService) GetAdminDeviceRiskScore(ctx context.Context, adminID uuid.UUID, deviceID string) (int, error) {
	trustLevel, err := s.deviceTrustRepo.GetAdminDeviceTrustLevel(ctx, adminID, deviceID)
	if err != nil {
		return 0, err
	}
	if trustLevel == nil {
		return 0, nil
	}
	return trustLevel.RiskScore, nil
}

// ResetAdminDeviceRiskScore resets the risk score for an admin device
func (s *AdminMPINService) ResetAdminDeviceRiskScore(ctx context.Context, adminID uuid.UUID, deviceID string) error {
	trustLevel, err := s.deviceTrustRepo.GetAdminDeviceTrustLevel(ctx, adminID, deviceID)
	if err != nil {
		return err
	}
	if trustLevel == nil {
		return nil
	}

	trustLevel.RiskScore = 0
	return s.deviceTrustRepo.SetAdminDeviceTrustLevel(ctx, adminID, deviceID, trustLevel)
}

// validateIPAddress validates an IP address
func (s *AdminMPINService) validateIPAddress(ip string) bool {
	if ip == "" {
		return false
	}
	return net.ParseIP(ip) != nil
}

// getValidatedIP returns a validated IP or empty string
func (s *AdminMPINService) getValidatedIP(ip string) string {
	if s.validateIPAddress(ip) {
		return ip
	}
	return ""
}

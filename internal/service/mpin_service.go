// internal/service/mpin_service.go
package service

import (
	"auth-service/internal/config"
	"auth-service/internal/encryption"
	"auth-service/internal/hashing"
	"auth-service/internal/models"
	"auth-service/internal/repository/postgres"
	"auth-service/internal/repository/scylla"
	"auth-service/internal/util"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"net"
	"regexp"
	"sync"
	"time"

	"github.com/google/uuid"
	"go.uber.org/zap"
)

var (
	ErrMPINNotFound          = errors.New("MPIN not found")
	ErrMPINInvalid           = errors.New("invalid MPIN")
	ErrMPINLocked            = errors.New("MPIN is locked")
	ErrMPINAlreadyExists     = errors.New("MPIN already exists")
	ErrMPINTooWeak           = errors.New("MPIN is too weak")
	ErrDeviceNotBound        = errors.New("device not bound to MPIN")
	ErrMPINRateLimitExceeded = errors.New("MPIN rate limit exceeded")
	ErrMPINAttemptsExceeded  = errors.New("maximum MPIN attempts exceeded")
	ErrDeviceNotTrusted      = errors.New("device is not trusted")
)

const (
	MPINMinLength        = 4
	MPINMaxLength        = 8
	MPINLockDuration     = 30 * time.Minute
	MPINMaxAttempts      = 5
	MPINVerifyRateLimit  = 5           // per minute
	MPINForgotRateLimit  = 3           // per hour
	MPINChangeRateLimit  = 5           // per hour
	MPINSetupRateLimit   = 3           // per hour
	MPINRateLimitWindow  = time.Minute // 1 minute window
	MPINForgotRateWindow = time.Hour   // 1 hour window
	MPINCacheDuration    = 5 * time.Minute
)

// MPIN request/response structures
type MPINSetupRequest struct {
    UserID            uuid.UUID `json:"user_id" validate:"required"`

    MPIN              string `json:"mpin" validate:"required,min=4,max=8"`
    DeviceID          string `json:"device_id" validate:"required"`
    IPAddress         string `json:"ip_address"`
    DeviceFingerprint string `json:"device_fingerprint"`
    UserAgent         string `json:"user_agent"`
}

type MPINVerifyRequest struct {
    UserID            uuid.UUID `json:"user_id" validate:"required"`
    MPIN              string `json:"mpin" validate:"required"`
    DeviceID          string `json:"device_id" validate:"required"`
    IPAddress         string `json:"ip_address"`
    DeviceFingerprint string `json:"device_fingerprint"`
    UserAgent         string `json:"user_agent"`
}

type MPINChangeRequest struct {
    UserID            uuid.UUID `json:"user_id" validate:"required"`
    CurrentMPIN       string `json:"current_mpin" validate:"required"`
    NewMPIN           string `json:"new_mpin" validate:"required,min=4,max=8"`
    DeviceID          string `json:"device_id" validate:"required"`
    IPAddress         string `json:"ip_address"`
    DeviceFingerprint string `json:"device_fingerprint"`
    UserAgent         string `json:"user_agent"`
}

type MPINResetRequest struct {
    UserID            uuid.UUID `json:"user_id" validate:"required"`
    ResetBy     uuid.UUID `json:"reset_by" validate:"required"`
    Reason      string    `json:"reason" validate:"required"`
    IPAddress   string    `json:"ip_address"`
    UserAgent   string    `json:"user_agent"`
}

type MPINAdminChangeRequest struct {
    UserID            uuid.UUID `json:"user_id" validate:"required"`
    NewMPIN     string    `json:"new_mpin" validate:"required,min=4,max=8"`
    AdminID     uuid.UUID `json:"admin_id" validate:"required"`
    Reason      string    `json:"reason,omitempty"`
    IPAddress   string    `json:"ip_address"`
    UserAgent   string    `json:"user_agent"`
}

type MPINForgotRequest struct {
    UserID            uuid.UUID `json:"user_id" validate:"required"`
    DeviceID          string `json:"device_id" validate:"required"`
    IPAddress         string `json:"ip_address"`
    DeviceFingerprint string `json:"device_fingerprint"`
    UserAgent         string `json:"user_agent"`
}

type MPINForgotWithOTPRequest struct {
    UserID            uuid.UUID `json:"user_id" validate:"required"`
    DeviceID          string `json:"device_id" validate:"required"`
    NewMPIN           string `json:"new_mpin" validate:"required,min=4,max=8"`
    OTPCode           string `json:"otp_code" validate:"required,len=6"`
    IPAddress         string `json:"ip_address"`
    DeviceFingerprint string `json:"device_fingerprint"`
    UserAgent         string `json:"user_agent"`
}

type MPINVerifyResult struct {
	Verified       bool       `json:"verified"`
	FailedAttempts int        `json:"failed_attempts"`
	RemainingTries int        `json:"remaining_tries"`
	LockedUntil    *time.Time `json:"locked_until,omitempty"`
	Message        string     `json:"message"`
}



type MPINStatus struct {
	UserID         uuid.UUID  `json:"user_id"`
	Exists         bool       `json:"exists"`
	IsLocked       bool       `json:"is_locked"`
	FailedAttempts int        `json:"failed_attempts"`
	LockedUntil    *time.Time `json:"locked_until,omitempty"`
	LastChanged    *time.Time `json:"last_changed,omitempty"`
	DeviceID       string     `json:"device_id"`
}




// MPINService handles all MPIN-related business logic with enhanced security
type MPINService struct {
	mpinRepo        scylla.MPINRepository
	userRepo        postgres.UserRepository
	deviceTrustRepo scylla.DeviceTrustRepository
	userOTPService  *UserOTPService // ✅ CHANGED: Use UserOTPService instead of OTPService
	encryptionMgr   *encryption.EncryptionManager
	hasher          *hashing.Hasher
	config          *config.Config
	logger          *zap.Logger
	distCache       *DistributedCache
	logProducer     *LogProducerService
	cacheMutex      sync.RWMutex
}

func NewMPINService(
	mpinRepo scylla.MPINRepository,
	userRepo postgres.UserRepository,
	deviceTrustRepo scylla.DeviceTrustRepository,
	userOTPService *UserOTPService, // ✅ CHANGED: Use UserOTPService instead of OTPService
	encryptionMgr *encryption.EncryptionManager,
	hasher *hashing.Hasher,
	cfg *config.Config,
	logger *zap.Logger,
	logProducer *LogProducerService,
) *MPINService {
	return &MPINService{
		mpinRepo:        mpinRepo,
		userRepo:        userRepo,
		deviceTrustRepo: deviceTrustRepo,
		hasher:          hasher,
		userOTPService:  userOTPService, // ✅ CHANGED
		config:          cfg,
		logger:          logger,
		encryptionMgr:   encryptionMgr,
		distCache:       nil,
		logProducer:     logProducer,
	}
}

// ✅ UPDATED: Helper function to hash device fingerprint
func (s *MPINService) hashDeviceFingerprint(fingerprint string) string {
	if fingerprint == "" {
		return ""
	}
	hash := sha256.Sum256([]byte(fingerprint))
	return hex.EncodeToString(hash[:])
}

// ✅ UPDATED: Helper function to get subnet from IP address
func (s *MPINService) getSubnet(ipAddress string) string {
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

// ✅ UPDATED: Check if subnets match
func (s *MPINService) isSubnetMatch(ip1, ip2 string) bool {
	if ip1 == "" || ip2 == "" {
		return true // If either IP is empty, consider it a match (no data to compare)
	}

	subnet1 := s.getSubnet(ip1)
	subnet2 := s.getSubnet(ip2)

	if subnet1 == "" || subnet2 == "" {
		return true
	}

	return subnet1 == subnet2
}

// ✅ NEW: Enhanced device trust verification for MPIN operations
func (s *MPINService) isDeviceTrusted(ctx context.Context, userID uuid.UUID, deviceID, ipAddress, deviceFingerprint string) (bool, *models.DeviceTrustLevel, error) {
	trustLevel, err := s.deviceTrustRepo.GetDeviceTrustLevel(ctx, userID, deviceID)
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
			util.String("user_id", userID.String()),
			util.String("device_id", deviceID),
			util.String("stored_ip", trustLevel.LastIPAddress),
			util.String("current_ip", ipAddress),
		)

		// Update risk score for subnet mismatch
		trustLevel.RiskScore += 15
		if err := s.deviceTrustRepo.UpdateRisk(ctx, trustLevel); err != nil {
			s.logger.Warn("Failed to update risk score for subnet mismatch",
				util.ErrorField(err),
				util.String("user_id", userID.String()),
			)
		}
		return false, trustLevel, nil
	}

	// Check hashed device fingerprint
	hashedFingerprint := s.hashDeviceFingerprint(deviceFingerprint)
	if deviceFingerprint != "" && trustLevel.DeviceFingerprint != "" && trustLevel.DeviceFingerprint != hashedFingerprint {
		s.logger.Warn("Device fingerprint mismatch for trusted device",
			util.String("user_id", userID.String()),
			util.String("device_id", deviceID),
		)

		// Update risk score for fingerprint mismatch
		trustLevel.RiskScore += 10
		if err := s.deviceTrustRepo.UpdateRisk(ctx, trustLevel); err != nil {
			s.logger.Warn("Failed to update risk score for fingerprint mismatch",
				util.ErrorField(err),
				util.String("user_id", userID.String()),
			)
		}
		return false, trustLevel, nil
	}

	return true, trustLevel, nil
}

// ✅ NEW: logMPINEvent helper method
func (s *MPINService) logMPINEvent(ctx context.Context, event *models.MPINLogEvent) {
	if s.logProducer != nil {
		_ = s.logProducer.ProduceMPINEvent(ctx, event)
	}
}

func (s *MPINService) SetDistributedCache(distCache *DistributedCache) {
	s.distCache = distCache
}

// ✅ NEW: Rate limiting methods with risk score updates
func (s *MPINService) checkRateLimit(ctx context.Context, key string, limit int, window time.Duration) (bool, int) {
	if s.distCache == nil {
		return true, 0
	}

	allowed, retryAfter := s.distCache.AllowRate(ctx, key, limit, window)

	// Update risk score when rate limit is exceeded
	if !allowed {
		// Extract user ID from key if possible
		if matches := regexp.MustCompile(`mpin_[^:]+:([^:]+):`).FindStringSubmatch(key); len(matches) > 1 {
			if userID, err := uuid.Parse(matches[1]); err == nil {
				go s.updateRiskScoreForRateLimit(ctx, userID)
			}
		}
	}

	return allowed, retryAfter
}

// ✅ NEW: Update risk score for rate limit violations
func (s *MPINService) updateRiskScoreForRateLimit(ctx context.Context, userID uuid.UUID) {
	trustLevel, err := s.deviceTrustRepo.GetDeviceTrustLevel(ctx, userID, "")
	if err != nil || trustLevel == nil {
		return
	}

	trustLevel.RiskScore += 10
	if err := s.deviceTrustRepo.UpdateRisk(ctx, trustLevel); err != nil {
		s.logger.Warn("Failed to update risk score for rate limit",
			util.ErrorField(err),
			util.String("user_id", userID.String()),
		)
	}
}

// ✅ NEW: Update risk score for failed MPIN
func (s *MPINService) updateRiskScoreForFailedMPIN(ctx context.Context, userID uuid.UUID, deviceID string) {
	trustLevel, err := s.deviceTrustRepo.GetDeviceTrustLevel(ctx, userID, deviceID)
	if err != nil || trustLevel == nil {
		return
	}

	trustLevel.RiskScore += 10
	if err := s.deviceTrustRepo.UpdateRisk(ctx, trustLevel); err != nil {
		s.logger.Warn("Failed to update risk score for failed MPIN",
			util.ErrorField(err),
			util.String("user_id", userID.String()),
		)
	}
}

// ✅ NEW: Update risk score for device mismatch
func (s *MPINService) updateRiskScoreForDeviceMismatch(ctx context.Context, userID uuid.UUID, deviceID string) {
	trustLevel, err := s.deviceTrustRepo.GetDeviceTrustLevel(ctx, userID, deviceID)
	if err != nil || trustLevel == nil {
		return
	}

	trustLevel.RiskScore += 10
	if err := s.deviceTrustRepo.UpdateRisk(ctx, trustLevel); err != nil {
		s.logger.Warn("Failed to update risk score for device mismatch",
			util.ErrorField(err),
			util.String("user_id", userID.String()),
		)
	}
}

// ✅ NEW: Update risk score for OTP failures
func (s *MPINService) updateRiskScoreForOTPFailure(ctx context.Context, userID uuid.UUID, deviceID string) {
	trustLevel, err := s.deviceTrustRepo.GetDeviceTrustLevel(ctx, userID, deviceID)
	if err != nil || trustLevel == nil {
		return
	}

	trustLevel.RiskScore += 10
	if err := s.deviceTrustRepo.UpdateRisk(ctx, trustLevel); err != nil {
		s.logger.Warn("Failed to update risk score for OTP failure",
			util.ErrorField(err),
			util.String("user_id", userID.String()),
		)
	}
}

func (s *MPINService) validateMPIN(mpin string) error {
	if len(mpin) < MPINMinLength || len(mpin) > MPINMaxLength {
		return fmt.Errorf("%w: MPIN must be between %d and %d digits", ErrInvalidInput, MPINMinLength, MPINMaxLength)
	}
	if matched, _ := regexp.MatchString(`^\d+$`, mpin); !matched {
		return fmt.Errorf("%w: MPIN must contain only digits", ErrInvalidInput)
	}
	if s.isMPINWeak(mpin) {
		return ErrMPINTooWeak
	}
	return nil
}

func (s *MPINService) isMPINWeak(mpin string) bool {
	if matched, _ := regexp.MatchString(`^(\d)\1+$`, mpin); matched {
		return true
	}
	if s.isSequential(mpin) {
		return true
	}
	weakMPINs := []string{"1234", "0000", "1111", "2222", "3333", "4444", "5555", "6666", "7777", "8888", "9999", "1122", "1212"}
	for _, weak := range weakMPINs {
		if mpin == weak {
			return true
		}
	}
	return false
}

func (s *MPINService) isSequential(mpin string) bool {
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

// ✅ UPDATED: SetupMPIN with hashed device fingerprint and enhanced logging
func (s *MPINService) SetupMPIN(ctx context.Context, req *MPINSetupRequest) error {
	startTime := time.Now()

	if s.hasher == nil {
		return fmt.Errorf("hasher service not available")
	}

	if !s.hasher.IsInitialized() {
		return fmt.Errorf("hasher not properly initialized - no pepper available")
	}

	s.logMPINEvent(ctx, &models.MPINLogEvent{
		LogEnvelope: models.LogEnvelope{
			EventID:     uuid.New().String(),
			EventType:   string(models.LogEventTypeMPIN),
			ServiceName: "auth-service",
			Timestamp:   time.Now(),
			Environment: s.config.Environment,
			Version:     ServiceVersion,
			Level:       string(models.LogLevelInfo),
			Message:     "MPIN setup initiated",
		},
		UserID:    req.UserID.String(),
		Status:    "setup_initiated",
		DeviceID:  req.DeviceID,
		UserAgent: req.UserAgent,
	})

	if err := s.validateMPIN(req.MPIN); err != nil {
		s.logMPINEvent(ctx, &models.MPINLogEvent{
			LogEnvelope: models.LogEnvelope{
				EventID:     uuid.New().String(),
				EventType:   string(models.LogEventTypeMPIN),
				ServiceName: "auth-service",
				Timestamp:   time.Now(),
				Environment: s.config.Environment,
				Version:     ServiceVersion,
				Level:       string(models.LogLevelError),
				Message:     "MPIN validation failed",
			},
			UserID:        req.UserID.String(),
			Status:        "setup_failed",
			DeviceID:      req.DeviceID,
			UserAgent:     req.UserAgent,
			ErrorCode:     "VALIDATION_FAILED",
			ErrorMessage:  err.Error(),
			FailureReason: "mpin_validation_failed",
		})
		return err
	}

	// ✅ NEW: Rate limiting for setup with risk score updates
	setupRateKey := fmt.Sprintf("mpin_setup:%s:%s", req.UserID.String(), req.DeviceID)
	if allowed, retryAfter := s.checkRateLimit(ctx, setupRateKey, MPINSetupRateLimit, MPINForgotRateWindow); !allowed {
		s.logMPINEvent(ctx, &models.MPINLogEvent{
			LogEnvelope: models.LogEnvelope{
				EventID:     uuid.New().String(),
				EventType:   string(models.LogEventTypeMPIN),
				ServiceName: "auth-service",
				Timestamp:   time.Now(),
				Environment: s.config.Environment,
				Version:     ServiceVersion,
				Level:       string(models.LogLevelWarning),
				Message:     "MPIN setup rate limit exceeded",
			},
			UserID:       req.UserID.String(),
			Status:       "setup_rate_limited",
			DeviceID:     req.DeviceID,
			UserAgent:    req.UserAgent,
			ErrorCode:    "RATE_LIMIT_EXCEEDED",
			AttemptsLeft: retryAfter,
		})
		return ErrMPINRateLimitExceeded
	}

	user, err := s.userRepo.GetUserByID(ctx, req.UserID)
	if err != nil {
		s.logMPINEvent(ctx, &models.MPINLogEvent{
			LogEnvelope: models.LogEnvelope{
				EventID:     uuid.New().String(),
				EventType:   string(models.LogEventTypeMPIN),
				ServiceName: "auth-service",
				Timestamp:   time.Now(),
				Environment: s.config.Environment,
				Version:     ServiceVersion,
				Level:       string(models.LogLevelError),
				Message:     "User not found for MPIN setup",
			},
			UserID:        req.UserID.String(),
			Status:        "setup_failed",
			DeviceID:      req.DeviceID,
			UserAgent:     req.UserAgent,
			ErrorCode:     "USER_NOT_FOUND",
			FailureReason: "user_not_found",
		})
		return fmt.Errorf("%w: user not found", ErrInvalidInput)
	}

	if !user.IsActive {
		s.logMPINEvent(ctx, &models.MPINLogEvent{
			LogEnvelope: models.LogEnvelope{
				EventID:     uuid.New().String(),
				EventType:   string(models.LogEventTypeMPIN),
				ServiceName: "auth-service",
				Timestamp:   time.Now(),
				Environment: s.config.Environment,
				Version:     ServiceVersion,
				Level:       string(models.LogLevelWarning),
				Message:     "Inactive user attempted MPIN setup",
			},
			UserID:        req.UserID.String(),
			Status:        "setup_failed",
			DeviceID:      req.DeviceID,
			UserAgent:     req.UserAgent,
			ErrorCode:     "USER_INACTIVE",
			FailureReason: "user_inactive",
		})
		return ErrUserBanned
	}

	existingMPIN, err := s.mpinRepo.GetMPINByUserID(ctx, req.UserID)
	if err == nil && existingMPIN != nil {
		s.logMPINEvent(ctx, &models.MPINLogEvent{
			LogEnvelope: models.LogEnvelope{
				EventID:     uuid.New().String(),
				EventType:   string(models.LogEventTypeMPIN),
				ServiceName: "auth-service",
				Timestamp:   time.Now(),
				Environment: s.config.Environment,
				Version:     ServiceVersion,
				Level:       string(models.LogLevelWarning),
				Message:     "MPIN already exists for user",
			},
			UserID:        req.UserID.String(),
			Status:        "setup_failed",
			DeviceID:      req.DeviceID,
			UserAgent:     req.UserAgent,
			ErrorCode:     "MPIN_ALREADY_EXISTS",
			FailureReason: "mpin_already_exists",
		})
		return ErrMPINAlreadyExists
	}

	hashResult, err := s.hasher.HashMPIN(req.MPIN)
	if err != nil {
		s.logMPINEvent(ctx, &models.MPINLogEvent{
			LogEnvelope: models.LogEnvelope{
				EventID:     uuid.New().String(),
				EventType:   string(models.LogEventTypeMPIN),
				ServiceName: "auth-service",
				Timestamp:   time.Now(),
				Environment: s.config.Environment,
				Version:     ServiceVersion,
				Level:       string(models.LogLevelError),
				Message:     "Failed to hash MPIN",
			},
			UserID:        req.UserID.String(),
			Status:        "setup_failed",
			DeviceID:      req.DeviceID,
			UserAgent:     req.UserAgent,
			ErrorCode:     "HASHING_FAILED",
			ErrorMessage:  err.Error(),
			FailureReason: "hashing_failed",
		})
		return fmt.Errorf("failed to hash MPIN: %w", err)
	}

	now := time.Now().UTC()
	mpinCredential := &models.MPINCredential{
		UserID:         req.UserID.String(),
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

	if err := s.mpinRepo.CreateMPIN(ctx, mpinCredential); err != nil {
		s.logMPINEvent(ctx, &models.MPINLogEvent{
			LogEnvelope: models.LogEnvelope{
				EventID:     uuid.New().String(),
				EventType:   string(models.LogEventTypeMPIN),
				ServiceName: "auth-service",
				Timestamp:   time.Now(),
				Environment: s.config.Environment,
				Version:     ServiceVersion,
				Level:       string(models.LogLevelError),
				Message:     "Failed to create MPIN in repository",
			},
			UserID:        req.UserID.String(),
			Status:        "setup_failed",
			DeviceID:      req.DeviceID,
			UserAgent:     req.UserAgent,
			ErrorCode:     "REPOSITORY_CREATE_FAILED",
			ErrorMessage:  err.Error(),
			FailureReason: "repository_create_failed",
		})
		return fmt.Errorf("failed to create MPIN: %w", err)
	}

	// ✅ UPDATED: Enhanced device trust setup with hashed fingerprint and IP
	trustLevel := &models.DeviceTrustLevel{
		UserID:            req.UserID,
		DeviceID:          req.DeviceID,
		TrustStatus:       models.TrustStatusTrusted,
		DeviceFingerprint: s.hashDeviceFingerprint(req.DeviceFingerprint),
		LastIPAddress:     req.IPAddress,
		UserAgent:         req.UserAgent,
		IsBlocked:         false,
		RiskScore:         0,
	}

	if err := s.deviceTrustRepo.MarkSuccessfulLogin(ctx, req.UserID, req.DeviceID, trustLevel); err != nil {
		s.logger.Warn("Failed to set device trust level",
			util.ErrorField(err),
			util.String("user_id", req.UserID.String()),
			util.String("device_id", req.DeviceID),
		)
	}

	s.invalidateMPINCache(ctx, req.UserID)

	s.logMPINEvent(ctx, &models.MPINLogEvent{
		LogEnvelope: models.LogEnvelope{
			EventID:     uuid.New().String(),
			EventType:   string(models.LogEventTypeMPIN),
			ServiceName: "auth-service",
			Timestamp:   time.Now(),
			Environment: s.config.Environment,
			Version:     ServiceVersion,
			Level:       string(models.LogLevelInfo),
			Message:     "MPIN setup completed successfully",
		},
		UserID:    req.UserID.String(),
		Status:    "setup_completed",
		DeviceID:  req.DeviceID,
		UserAgent: req.UserAgent,
		Duration:  int64(time.Since(startTime).Milliseconds()),
	})

	s.logger.Info("MPIN setup completed",
		util.String("user_id", req.UserID.String()),
		util.String("device_id", req.DeviceID),
		util.String("user_agent", req.UserAgent),
		util.Duration("duration", time.Since(startTime)),
	)
	return nil
}

// ✅ UPDATED: VerifyMPIN with risk score updates for failures and UserAgent
func (s *MPINService) VerifyMPIN(ctx context.Context, req *MPINVerifyRequest) (*MPINVerifyResult, error) {
	startTime := time.Now()

	s.logMPINEvent(ctx, &models.MPINLogEvent{
		LogEnvelope: models.LogEnvelope{
			EventID:     uuid.New().String(),
			EventType:   string(models.LogEventTypeMPIN),
			ServiceName: "auth-service",
			Timestamp:   time.Now(),
			Environment: s.config.Environment,
			Version:     ServiceVersion,
			Level:       string(models.LogLevelInfo),
			Message:     "MPIN verification initiated",
		},
		UserID:    req.UserID.String(),
		Status:    "verification_initiated",
		DeviceID:  req.DeviceID,
		UserAgent: req.UserAgent,
	})

	// ✅ NEW: Rate limiting for MPIN verification with risk score updates
	verifyRateKey := fmt.Sprintf("mpin_verify:%s:%s", req.UserID.String(), req.DeviceID)
	if allowed, retryAfter := s.checkRateLimit(ctx, verifyRateKey, MPINVerifyRateLimit, MPINRateLimitWindow); !allowed {
		s.logMPINEvent(ctx, &models.MPINLogEvent{
			LogEnvelope: models.LogEnvelope{
				EventID:     uuid.New().String(),
				EventType:   string(models.LogEventTypeMPIN),
				ServiceName: "auth-service",
				Timestamp:   time.Now(),
				Environment: s.config.Environment,
				Version:     ServiceVersion,
				Level:       string(models.LogLevelWarning),
				Message:     "MPIN verification rate limit exceeded",
			},
			UserID:       req.UserID.String(),
			Status:       "verification_rate_limited",
			DeviceID:     req.DeviceID,
			UserAgent:    req.UserAgent,
			ErrorCode:    "RATE_LIMIT_EXCEEDED",
			AttemptsLeft: retryAfter,
		})
		return nil, ErrMPINRateLimitExceeded
	}

	if err := s.validateMPIN(req.MPIN); err != nil {
		s.logMPINEvent(ctx, &models.MPINLogEvent{
			LogEnvelope: models.LogEnvelope{
				EventID:     uuid.New().String(),
				EventType:   string(models.LogEventTypeMPIN),
				ServiceName: "auth-service",
				Timestamp:   time.Now(),
				Environment: s.config.Environment,
				Version:     ServiceVersion,
				Level:       string(models.LogLevelError),
				Message:     "MPIN validation failed",
			},
			UserID:        req.UserID.String(),
			Status:        "verification_failed",
			DeviceID:      req.DeviceID,
			UserAgent:     req.UserAgent,
			ErrorCode:     "VALIDATION_FAILED",
			ErrorMessage:  err.Error(),
			FailureReason: "mpin_validation_failed",
		})
		return nil, err
	}

	mpinCred, err := s.mpinRepo.ValidateMPIN(ctx, req.UserID, req.MPIN)
	if err != nil {
		if err.Error() == "MPIN not found for user: "+req.UserID.String() {
			s.logMPINEvent(ctx, &models.MPINLogEvent{
				LogEnvelope: models.LogEnvelope{
					EventID:     uuid.New().String(),
					EventType:   string(models.LogEventTypeMPIN),
					ServiceName: "auth-service",
					Timestamp:   time.Now(),
					Environment: s.config.Environment,
					Version:     ServiceVersion,
					Level:       string(models.LogLevelWarning),
					Message:     "MPIN not found for verification",
				},
				UserID:        req.UserID.String(),
				Status:        "verification_failed",
				DeviceID:      req.DeviceID,
				UserAgent:     req.UserAgent,
				ErrorCode:     "MPIN_NOT_FOUND",
				FailureReason: "mpin_not_found",
			})
			return nil, ErrMPINNotFound
		}
		if err.Error() == "MPIN locked due to too many failed attempts" {
			result := &MPINVerifyResult{
				Verified:       false,
				FailedAttempts: MPINMaxAttempts,
				RemainingTries: 0,
				Message:        "MPIN is locked due to too many failed attempts",
			}
			s.logMPINEvent(ctx, &models.MPINLogEvent{
				LogEnvelope: models.LogEnvelope{
					EventID:     uuid.New().String(),
					EventType:   string(models.LogEventTypeMPIN),
					ServiceName: "auth-service",
					Timestamp:   time.Now(),
					Environment: s.config.Environment,
					Version:     ServiceVersion,
					Level:       string(models.LogLevelWarning),
					Message:     "MPIN verification failed - locked",
				},
				UserID:        req.UserID.String(),
				Status:        "verification_failed",
				DeviceID:      req.DeviceID,
				UserAgent:     req.UserAgent,
				Attempts:      MPINMaxAttempts,
				AttemptsLeft:  0,
				IsLocked:      true,
				ErrorCode:     "MPIN_LOCKED",
				FailureReason: "mpin_locked",
			})
			return result, ErrMPINLocked
		}

		s.logMPINEvent(ctx, &models.MPINLogEvent{
			LogEnvelope: models.LogEnvelope{
				EventID:     uuid.New().String(),
				EventType:   string(models.LogEventTypeMPIN),
				ServiceName: "auth-service",
				Timestamp:   time.Now(),
				Environment: s.config.Environment,
				Version:     ServiceVersion,
				Level:       string(models.LogLevelError),
				Message:     "MPIN validation repository error",
			},
			UserID:        req.UserID.String(),
			Status:        "verification_failed",
			DeviceID:      req.DeviceID,
			UserAgent:     req.UserAgent,
			ErrorCode:     "REPOSITORY_ERROR",
			ErrorMessage:  err.Error(),
			FailureReason: "repository_error",
		})
		return nil, err
	}

	// Device mismatch warning with risk score update
	if mpinCred.DeviceID != "" && req.DeviceID != "" && mpinCred.DeviceID != req.DeviceID {
		s.logMPINEvent(ctx, &models.MPINLogEvent{
			LogEnvelope: models.LogEnvelope{
				EventID:     uuid.New().String(),
				EventType:   string(models.LogEventTypeMPIN),
				ServiceName: "auth-service",
				Timestamp:   time.Now(),
				Environment: s.config.Environment,
				Version:     ServiceVersion,
				Level:       string(models.LogLevelWarning),
				Message:     "Device mismatch during MPIN verification",
			},
			UserID:    req.UserID.String(),
			Status:    "device_mismatch",
			DeviceID:  req.DeviceID,
			UserAgent: req.UserAgent,
		})
		s.logger.Warn("Device mismatch during MPIN verification",
			util.String("user_id", req.UserID.String()),
			util.String("expected_device", mpinCred.DeviceID),
			util.String("provided_device", req.DeviceID),
			util.String("user_agent", req.UserAgent),
		)

		// Update risk score for device mismatch
		go s.updateRiskScoreForDeviceMismatch(ctx, req.UserID, req.DeviceID)
	}

	hashResult := &hashing.HashResult{
		Hash:          mpinCred.MPINHash,
		Salt:          mpinCred.MPINSalt,
		PepperVersion: mpinCred.PepperVersion,
		Algorithm:     mpinCred.HashAlgorithm,
	}

	verified, err := s.hasher.VerifyMPIN(req.MPIN, hashResult)
	if err != nil {
		s.logMPINEvent(ctx, &models.MPINLogEvent{
			LogEnvelope: models.LogEnvelope{
				EventID:     uuid.New().String(),
				EventType:   string(models.LogEventTypeMPIN),
				ServiceName: "auth-service",
				Timestamp:   time.Now(),
				Environment: s.config.Environment,
				Version:     ServiceVersion,
				Level:       string(models.LogLevelError),
				Message:     "Failed to verify MPIN hash",
			},
			UserID:        req.UserID.String(),
			Status:        "verification_failed",
			DeviceID:      req.DeviceID,
			UserAgent:     req.UserAgent,
			ErrorCode:     "HASH_VERIFICATION_FAILED",
			ErrorMessage:  err.Error(),
			FailureReason: "hash_verification_failed",
		})
		return nil, fmt.Errorf("failed to verify MPIN: %w", err)
	}

	result := &MPINVerifyResult{
		Verified:       verified,
		FailedAttempts: mpinCred.FailedAttempts,
		RemainingTries: max(0, MPINMaxAttempts-mpinCred.FailedAttempts),
	}

	if verified {
		if err := s.mpinRepo.ResetFailedAttempts(ctx, req.UserID); err != nil {
			s.logger.Error("Failed to reset failed attempts",
				util.ErrorField(err),
				util.String("user_id", req.UserID.String()),
			)
		}
		result.Message = "MPIN verified successfully"
		result.FailedAttempts = 0
		result.RemainingTries = MPINMaxAttempts

		// ✅ UPDATED: Update device trust with hashed fingerprint and current IP
		trustLevel := &models.DeviceTrustLevel{
			UserID:            req.UserID,
			DeviceID:          req.DeviceID,
			TrustStatus:       models.TrustStatusTrusted,
			DeviceFingerprint: s.hashDeviceFingerprint(req.DeviceFingerprint),
			LastIPAddress:     req.IPAddress,
			UserAgent:         req.UserAgent,
			IsBlocked:         false,
			RiskScore:         0, // Reset risk score on successful verification
		}

		if err := s.deviceTrustRepo.MarkSuccessfulLogin(ctx, req.UserID, req.DeviceID, trustLevel); err != nil {
			s.logger.Warn("Failed to update device trust on successful login",
				util.ErrorField(err),
				util.String("user_id", req.UserID.String()),
			)
		}

		s.logMPINEvent(ctx, &models.MPINLogEvent{
			LogEnvelope: models.LogEnvelope{
				EventID:     uuid.New().String(),
				EventType:   string(models.LogEventTypeMPIN),
				ServiceName: "auth-service",
				Timestamp:   time.Now(),
				Environment: s.config.Environment,
				Version:     ServiceVersion,
				Level:       string(models.LogLevelInfo),
				Message:     "MPIN verified successfully",
			},
			UserID:       req.UserID.String(),
			Status:       "verification_successful",
			DeviceID:     req.DeviceID,
			UserAgent:    req.UserAgent,
			Attempts:     0,
			AttemptsLeft: MPINMaxAttempts,
			IsLocked:     false,
			Duration:     int64(time.Since(startTime).Milliseconds()),
		})
	} else {
		newFailedAttempts, err := s.mpinRepo.IncrementFailedAttempts(ctx, req.UserID)
		if err != nil {
			s.logger.Error("Failed to increment failed attempts",
				util.ErrorField(err),
				util.String("user_id", req.UserID.String()),
			)
		} else {
			result.FailedAttempts = newFailedAttempts
			result.RemainingTries = max(0, MPINMaxAttempts-newFailedAttempts)
		}

		// Update risk score for failed MPIN verification
		go s.updateRiskScoreForFailedMPIN(ctx, req.UserID, req.DeviceID)

		if result.RemainingTries == 0 {
			result.Message = "MPIN is now locked due to too many failed attempts"
			lockUntil := time.Now().Add(MPINLockDuration)
			result.LockedUntil = &lockUntil

			s.logMPINEvent(ctx, &models.MPINLogEvent{
				LogEnvelope: models.LogEnvelope{
					EventID:     uuid.New().String(),
					EventType:   string(models.LogEventTypeMPIN),
					ServiceName: "auth-service",
					Timestamp:   time.Now(),
					Environment: s.config.Environment,
					Version:     ServiceVersion,
					Level:       string(models.LogLevelWarning),
					Message:     "MPIN locked due to failed attempts",
				},
				UserID:       req.UserID.String(),
				Status:       "mpin_locked",
				DeviceID:     req.DeviceID,
				UserAgent:    req.UserAgent,
				Attempts:     newFailedAttempts,
				AttemptsLeft: 0,
				IsLocked:     true,
				Duration:     int64(time.Since(startTime).Milliseconds()),
			})
		} else {
			result.Message = fmt.Sprintf("Invalid MPIN. %d attempts remaining", result.RemainingTries)

			s.logMPINEvent(ctx, &models.MPINLogEvent{
				LogEnvelope: models.LogEnvelope{
					EventID:     uuid.New().String(),
					EventType:   string(models.LogEventTypeMPIN),
					ServiceName: "auth-service",
					Timestamp:   time.Now(),
					Environment: s.config.Environment,
					Version:     ServiceVersion,
					Level:       string(models.LogLevelWarning),
					Message:     "MPIN verification failed",
				},
				UserID:       req.UserID.String(),
				Status:       "verification_failed",
				DeviceID:     req.DeviceID,
				UserAgent:    req.UserAgent,
				Attempts:     newFailedAttempts,
				AttemptsLeft: result.RemainingTries,
				IsLocked:     false,
				Duration:     int64(time.Since(startTime).Milliseconds()),
			})
		}
	}

	s.logger.Info("MPIN verification completed",
		util.String("user_id", req.UserID.String()),
		util.Bool("verified", verified),
		util.Int("failed_attempts", result.FailedAttempts),
		util.String("user_agent", req.UserAgent),
		util.Duration("duration", time.Since(startTime)),
	)

	return result, nil
}

// ✅ UPDATED: ForgotMPIN with phone number parameter and device trust checks handled by MPIN service and UserAgent
func (s *MPINService) ForgotMPIN(ctx context.Context, req *MPINForgotRequest) error {
    startTime := time.Now()

    s.logMPINEvent(ctx, &models.MPINLogEvent{
        LogEnvelope: models.LogEnvelope{
            EventID:     uuid.New().String(),
            EventType:   string(models.LogEventTypeMPIN),
            ServiceName: "auth-service",
            Timestamp:   time.Now(),
            Environment: s.config.Environment,
            Version:     ServiceVersion,
            Level:       string(models.LogLevelInfo),
            Message:     "Forgot MPIN flow initiated",
        },
        UserID:    req.UserID.String(),
        Status:    "forgot_initiated",
        DeviceID:  req.DeviceID,
        UserAgent: req.UserAgent,
    })

    // ✅ FIXED: Use the UserID from request (passed by handler)
    user, err := s.userRepo.GetUserByID(ctx, req.UserID)
    if err != nil {
        s.logMPINEvent(ctx, &models.MPINLogEvent{
            LogEnvelope: models.LogEnvelope{
                EventID:     uuid.New().String(),
                EventType:   string(models.LogEventTypeMPIN),
                ServiceName: "auth-service",
                Timestamp:   time.Now(),
                Environment: s.config.Environment,
                Version:     ServiceVersion,
                Level:       string(models.LogLevelError),
                Message:     "User not found for forgot MPIN",
            },
            UserID:        req.UserID.String(),
            Status:        "forgot_failed",
            DeviceID:      req.DeviceID,
            UserAgent:     req.UserAgent,
            ErrorCode:     "USER_NOT_FOUND",
            FailureReason: "user_not_found",
        })
        return fmt.Errorf("user not found: %w", err)
    }

    // Decrypt phone number
    encryptedData := &encryption.EncryptedData{
        EncryptedValue: string(user.PhoneEncrypted),
        EncryptedDEK:   user.PhoneEncryptedDEK,
        KeyID:          user.PhoneKeyID.String(),
        Version:        "v1",
        CreatedAt:      user.CreatedAt,
    }

    phoneNumber, err := s.encryptionMgr.DecryptField(ctx, encryptedData)
    if err != nil {
        s.logMPINEvent(ctx, &models.MPINLogEvent{
            LogEnvelope: models.LogEnvelope{
                EventID:     uuid.New().String(),
                EventType:   string(models.LogEventTypeMPIN),
                ServiceName: "auth-service",
                Timestamp:   time.Now(),
                Environment: s.config.Environment,
                Version:     ServiceVersion,
                Level:       string(models.LogLevelError),
                Message:     "Failed to decrypt phone number for forgot MPIN",
            },
            UserID:        req.UserID.String(),
            Status:        "forgot_failed",
            DeviceID:      req.DeviceID,
            UserAgent:     req.UserAgent,
            ErrorCode:     "PHONE_DECRYPTION_FAILED",
            ErrorMessage:  err.Error(),
            FailureReason: "phone_decryption_failed",
        })
        return fmt.Errorf("failed to decrypt phone number: %w", err)
    }

    // ✅ UPDATED: Use UserOTPService instead of OTPService
    otpReq := &UserOTPSendRequest{
        PhoneNumber:       phoneNumber,
        Purpose:           "forgot_mpin",
        IPAddress:         req.IPAddress,
        DeviceID:          req.DeviceID,
        UserAgent:         req.UserAgent,
        DeviceFingerprint: req.DeviceFingerprint,
    }

    otpResp, err := s.userOTPService.UserSendOTP(ctx, otpReq)
    if err != nil {
        s.logMPINEvent(ctx, &models.MPINLogEvent{
            LogEnvelope: models.LogEnvelope{
                EventID:     uuid.New().String(),
                EventType:   string(models.LogEventTypeMPIN),
                ServiceName: "auth-service",
                Timestamp:   time.Now(),
                Environment: s.config.Environment,
                Version:     ServiceVersion,
                Level:       string(models.LogLevelError),
                Message:     "Failed to send OTP for forgot MPIN",
            },
            UserID:        req.UserID.String(),
            Status:        "forgot_failed",
            DeviceID:      req.DeviceID,
            UserAgent:     req.UserAgent,
            ErrorCode:     "OTP_SEND_FAILED",
            ErrorMessage:  err.Error(),
            FailureReason: "otp_send_failed",
        })
        return fmt.Errorf("failed to send OTP: %w", err)
    }

    if !otpResp.Success {
        s.logMPINEvent(ctx, &models.MPINLogEvent{
            LogEnvelope: models.LogEnvelope{
                EventID:     uuid.New().String(),
                EventType:   string(models.LogEventTypeMPIN),
                ServiceName: "auth-service",
                Timestamp:   time.Now(),
                Environment: s.config.Environment,
                Version:     ServiceVersion,
                Level:       string(models.LogLevelError),
                Message:     "OTP send failed for forgot MPIN",
            },
            UserID:        req.UserID.String(),
            Status:        "forgot_failed",
            DeviceID:      req.DeviceID,
            UserAgent:     req.UserAgent,
            ErrorCode:     "OTP_SEND_FAILED",
            ErrorMessage:  otpResp.Message,
            FailureReason: "otp_send_failed",
        })
        return fmt.Errorf("OTP send failed: %s", otpResp.Message)
    }

    s.logMPINEvent(ctx, &models.MPINLogEvent{
        LogEnvelope: models.LogEnvelope{
            EventID:     uuid.New().String(),
            EventType:   string(models.LogEventTypeMPIN),
            ServiceName: "auth-service",
            Timestamp:   time.Now(),
            Environment: s.config.Environment,
            Version:     ServiceVersion,
            Level:       string(models.LogLevelInfo),
            Message:     "OTP sent for forgot MPIN",
        },
        UserID:    req.UserID.String(),
        Status:    "forgot_otp_sent",
        DeviceID:  req.DeviceID,
        UserAgent: req.UserAgent,
        Duration:  int64(time.Since(startTime).Milliseconds()),
    })

    s.logger.Info("OTP sent for forgot MPIN",
        util.String("user_id", req.UserID.String()),
        util.String("device_id", req.DeviceID),
        util.String("user_agent", req.UserAgent),
    )

    return nil
}
// ✅ UPDATED: VerifyForgotMPINOTP with device trust checks handled by MPIN service and UserAgent
func (s *MPINService) VerifyForgotMPINOTP(ctx context.Context, req *MPINForgotWithOTPRequest) error {
	startTime := time.Now()

	s.logMPINEvent(ctx, &models.MPINLogEvent{
		LogEnvelope: models.LogEnvelope{
			EventID:     uuid.New().String(),
			EventType:   string(models.LogEventTypeMPIN),
			ServiceName: "auth-service",
			Timestamp:   time.Now(),
			Environment: s.config.Environment,
			Version:     ServiceVersion,
			Level:       string(models.LogLevelInfo),
			Message:     "Forgot MPIN OTP verification initiated",
		},
		UserID:    req.UserID.String(),
		Status:    "forgot_otp_verification_initiated",
		DeviceID:  req.DeviceID,
		UserAgent: req.UserAgent,
	})

	// ✅ UPDATED: Device trust handled by MPIN service
	isTrusted, trustLevel, err := s.isDeviceTrusted(ctx, req.UserID, req.DeviceID, req.IPAddress, req.DeviceFingerprint)
	if err != nil {
		s.logMPINEvent(ctx, &models.MPINLogEvent{
			LogEnvelope: models.LogEnvelope{
				EventID:     uuid.New().String(),
				EventType:   string(models.LogEventTypeMPIN),
				ServiceName: "auth-service",
				Timestamp:   time.Now(),
				Environment: s.config.Environment,
				Version:     ServiceVersion,
				Level:       string(models.LogLevelError),
				Message:     "Device trust check failed for forgot MPIN OTP",
			},
			UserID:        req.UserID.String(),
			Status:        "forgot_otp_verification_failed",
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
			if updateErr := s.deviceTrustRepo.UpdateRisk(ctx, trustLevel); updateErr != nil {
				s.logger.Warn("Failed to update risk score for untrusted device in OTP verification",
					util.ErrorField(updateErr),
					util.String("user_id", req.UserID.String()),
				)
			}
		}

		s.logMPINEvent(ctx, &models.MPINLogEvent{
			LogEnvelope: models.LogEnvelope{
				EventID:     uuid.New().String(),
				EventType:   string(models.LogEventTypeMPIN),
				ServiceName: "auth-service",
				Timestamp:   time.Now(),
				Environment: s.config.Environment,
				Version:     ServiceVersion,
				Level:       string(models.LogLevelWarning),
				Message:     "Untrusted device attempted forgot MPIN OTP verification",
			},
			UserID:        req.UserID.String(),
			Status:        "forgot_otp_verification_failed",
			DeviceID:      req.DeviceID,
			UserAgent:     req.UserAgent,
			ErrorCode:     "DEVICE_NOT_TRUSTED",
			FailureReason: "device_not_trusted",
		})
		return ErrDeviceNotTrusted
	}

	if err := s.validateMPIN(req.NewMPIN); err != nil {
		s.logMPINEvent(ctx, &models.MPINLogEvent{
			LogEnvelope: models.LogEnvelope{
				EventID:     uuid.New().String(),
				EventType:   string(models.LogEventTypeMPIN),
				ServiceName: "auth-service",
				Timestamp:   time.Now(),
				Environment: s.config.Environment,
				Version:     ServiceVersion,
				Level:       string(models.LogLevelError),
				Message:     "MPIN validation failed for forgot MPIN OTP",
			},
			UserID:        req.UserID.String(),
			Status:        "forgot_otp_verification_failed",
			DeviceID:      req.DeviceID,
			UserAgent:     req.UserAgent,
			ErrorCode:     "VALIDATION_FAILED",
			ErrorMessage:  err.Error(),
			FailureReason: "mpin_validation_failed",
		})
		return err
	}

	user, err := s.userRepo.GetUserByID(ctx, req.UserID)
	if err != nil {
		s.logMPINEvent(ctx, &models.MPINLogEvent{
			LogEnvelope: models.LogEnvelope{
				EventID:     uuid.New().String(),
				EventType:   string(models.LogEventTypeMPIN),
				ServiceName: "auth-service",
				Timestamp:   time.Now(),
				Environment: s.config.Environment,
				Version:     ServiceVersion,
				Level:       string(models.LogLevelError),
				Message:     "User not found for forgot MPIN OTP verification",
			},
			UserID:        req.UserID.String(),
			Status:        "forgot_otp_verification_failed",
			DeviceID:      req.DeviceID,
			UserAgent:     req.UserAgent,
			ErrorCode:     "USER_NOT_FOUND",
			FailureReason: "user_not_found",
		})
		return fmt.Errorf("user not found: %w", err)
	}

	// ✅ FIXED: Create proper EncryptedData struct
	encryptedData := &encryption.EncryptedData{
		EncryptedValue: string(user.PhoneEncrypted),
		EncryptedDEK:   user.PhoneEncryptedDEK,
		KeyID:          user.PhoneKeyID.String(),
		Version:        "v1",
		CreatedAt:      user.CreatedAt,
	}

	phoneNumber, err := s.encryptionMgr.DecryptField(ctx, encryptedData)
	if err != nil {
		s.logMPINEvent(ctx, &models.MPINLogEvent{
			LogEnvelope: models.LogEnvelope{
				EventID:     uuid.New().String(),
				EventType:   string(models.LogEventTypeMPIN),
				ServiceName: "auth-service",
				Timestamp:   time.Now(),
				Environment: s.config.Environment,
				Version:     ServiceVersion,
				Level:       string(models.LogLevelError),
				Message:     "Failed to decrypt phone number for forgot MPIN OTP verification",
			},
			UserID:        req.UserID.String(),
			Status:        "forgot_otp_verification_failed",
			DeviceID:      req.DeviceID,
			UserAgent:     req.UserAgent,
			ErrorCode:     "PHONE_DECRYPTION_FAILED",
			ErrorMessage:  err.Error(),
			FailureReason: "phone_decryption_failed",
		})
		return fmt.Errorf("failed to decrypt phone number: %w", err)
	}

	// ✅ UPDATED: Use UserOTPService instead of OTPService
	otpVerifyReq := &UserOTPVerifyRequest{
		PhoneNumber:       phoneNumber,
		OTP:               req.OTPCode,
		Purpose:           "forgot_mpin",
		IPAddress:         req.IPAddress,
		DeviceID:          req.DeviceID,
		DeviceFingerprint: req.DeviceFingerprint,
		UserAgent:         req.UserAgent,
	}

	otpResp, err := s.userOTPService.UserVerifyOTP(ctx, otpVerifyReq)
	if err != nil {
		// Update risk score for OTP verification failure
		go s.updateRiskScoreForOTPFailure(ctx, req.UserID, req.DeviceID)

		s.logMPINEvent(ctx, &models.MPINLogEvent{
			LogEnvelope: models.LogEnvelope{
				EventID:     uuid.New().String(),
				EventType:   string(models.LogEventTypeMPIN),
				ServiceName: "auth-service",
				Timestamp:   time.Now(),
				Environment: s.config.Environment,
				Version:     ServiceVersion,
				Level:       string(models.LogLevelWarning),
				Message:     "OTP verification failed for forgot MPIN",
			},
			UserID:        req.UserID.String(),
			Status:        "forgot_otp_verification_failed",
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
		go s.updateRiskScoreForOTPFailure(ctx, req.UserID, req.DeviceID)

		s.logMPINEvent(ctx, &models.MPINLogEvent{
			LogEnvelope: models.LogEnvelope{
				EventID:     uuid.New().String(),
				EventType:   string(models.LogEventTypeMPIN),
				ServiceName: "auth-service",
				Timestamp:   time.Now(),
				Environment: s.config.Environment,
				Version:     ServiceVersion,
				Level:       string(models.LogLevelWarning),
				Message:     "Invalid OTP code for forgot MPIN",
			},
			UserID:        req.UserID.String(),
			Status:        "forgot_otp_verification_failed",
			DeviceID:      req.DeviceID,
			UserAgent:     req.UserAgent,
			ErrorCode:     "INVALID_OTP",
			FailureReason: "invalid_otp",
		})
		return fmt.Errorf("invalid OTP code")
	}

	hashResult, err := s.hasher.HashMPIN(req.NewMPIN)
	if err != nil {
		s.logMPINEvent(ctx, &models.MPINLogEvent{
			LogEnvelope: models.LogEnvelope{
				EventID:     uuid.New().String(),
				EventType:   string(models.LogEventTypeMPIN),
				ServiceName: "auth-service",
				Timestamp:   time.Now(),
				Environment: s.config.Environment,
				Version:     ServiceVersion,
				Level:       string(models.LogLevelError),
				Message:     "Failed to hash MPIN for forgot MPIN OTP",
			},
			UserID:        req.UserID.String(),
			Status:        "forgot_otp_verification_failed",
			DeviceID:      req.DeviceID,
			UserAgent:     req.UserAgent,
			ErrorCode:     "HASHING_FAILED",
			ErrorMessage:  err.Error(),
			FailureReason: "hashing_failed",
		})
		return fmt.Errorf("failed to hash MPIN: %w", err)
	}

	if err := s.mpinRepo.UpdateMPIN(ctx, req.UserID, hashResult.Hash, hashResult.Salt, hashResult.PepperVersion); err != nil {
		s.logMPINEvent(ctx, &models.MPINLogEvent{
			LogEnvelope: models.LogEnvelope{
				EventID:     uuid.New().String(),
				EventType:   string(models.LogEventTypeMPIN),
				ServiceName: "auth-service",
				Timestamp:   time.Now(),
				Environment: s.config.Environment,
				Version:     ServiceVersion,
				Level:       string(models.LogLevelError),
				Message:     "Failed to update MPIN for forgot MPIN OTP",
			},
			UserID:        req.UserID.String(),
			Status:        "forgot_otp_verification_failed",
			DeviceID:      req.DeviceID,
			UserAgent:     req.UserAgent,
			ErrorCode:     "MPIN_UPDATE_FAILED",
			ErrorMessage:  err.Error(),
			FailureReason: "mpin_update_failed",
		})
		return fmt.Errorf("failed to update MPIN: %w", err)
	}

	_ = s.mpinRepo.UnlockMPIN(ctx, req.UserID)

	// ✅ UPDATED: Update device trust with hashed fingerprint and current information
	updatedTrustLevel := &models.DeviceTrustLevel{
		UserID:            req.UserID,
		DeviceID:          req.DeviceID,
		TrustStatus:       models.TrustStatusTrusted,
		DeviceFingerprint: s.hashDeviceFingerprint(req.DeviceFingerprint),
		LastIPAddress:     req.IPAddress,
		UserAgent:         req.UserAgent,
		IsBlocked:         false,
		RiskScore:         0, // Reset risk score on successful reset
	}

	if err := s.deviceTrustRepo.SetDeviceTrustLevel(ctx, req.UserID, req.DeviceID, updatedTrustLevel); err != nil {
		s.logger.Warn("Failed to update device trust level",
			util.ErrorField(err),
			util.String("user_id", req.UserID.String()),
		)
	}

	s.invalidateMPINCache(ctx, req.UserID)

	s.logMPINEvent(ctx, &models.MPINLogEvent{
		LogEnvelope: models.LogEnvelope{
			EventID:     uuid.New().String(),
			EventType:   string(models.LogEventTypeMPIN),
			ServiceName: "auth-service",
			Timestamp:   time.Now(),
			Environment: s.config.Environment,
			Version:     ServiceVersion,
			Level:       string(models.LogLevelInfo),
			Message:     "MPIN reset via forgot with OTP verification completed",
		},
		UserID:      req.UserID.String(),
		Status:      "forgot_otp_verification_completed",
		DeviceID:    req.DeviceID,
		UserAgent:   req.UserAgent,
		DeviceTrust: string(trustLevel.TrustStatus),
		Duration:    int64(time.Since(startTime).Milliseconds()),
	})

	s.logger.Info("MPIN reset via forgot with OTP verification on trusted device",
		util.String("user_id", req.UserID.String()),
		util.String("device_id", req.DeviceID),
		util.String("user_agent", req.UserAgent),
		util.String("trust_status", string(trustLevel.TrustStatus)),
	)

	return nil
}

// Helper function
func max(a, b int) int {
	if a > b {
		return a
	}
	return b
}

// ✅ NEW: SetLogProducerService sets Kafka log producer service
func (s *MPINService) SetLogProducerService(logProducer *LogProducerService) {
	s.logProducer = logProducer
}

// ✅ NEW: Helper method to invalidate MPIN cache
func (s *MPINService) invalidateMPINCache(ctx context.Context, userID uuid.UUID) {
	if s.distCache != nil {
		cacheKey := fmt.Sprintf("mpin:%s", userID.String())
		_ = s.distCache.Delete(ctx, cacheKey)
	}
}

// ✅ NEW: DebugHasherStatus for troubleshooting
func (s *MPINService) DebugHasherStatus(ctx context.Context) map[string]interface{} {
	status := s.hasher.GetStatus()

	// Get sample MPIN credential to check pepper version
	userID, _ := uuid.Parse("your-test-user-id") // Use a real user ID
	mpinCred, err := s.mpinRepo.GetMPINByUserID(ctx, userID)
	if err == nil {
		status["sample_mpin_pepper_version"] = mpinCred.PepperVersion
		status["sample_mpin_algorithm"] = mpinCred.HashAlgorithm
	}

	return status
}

// ✅ NEW: Method to get current risk score for a user device
func (s *MPINService) GetDeviceRiskScore(ctx context.Context, userID uuid.UUID, deviceID string) (int, error) {
	trustLevel, err := s.deviceTrustRepo.GetDeviceTrustLevel(ctx, userID, deviceID)
	if err != nil {
		return 0, err
	}
	if trustLevel == nil {
		return 0, nil
	}
	return trustLevel.RiskScore, nil
}

// ✅ NEW: Method to reset risk score for a user device
func (s *MPINService) ResetDeviceRiskScore(ctx context.Context, userID uuid.UUID, deviceID string) error {
	trustLevel, err := s.deviceTrustRepo.GetDeviceTrustLevel(ctx, userID, deviceID)
	if err != nil {
		return err
	}
	if trustLevel == nil {
		return nil
	}

	trustLevel.RiskScore = 0
	return s.deviceTrustRepo.UpdateRisk(ctx, trustLevel)
}

// ✅ COMPLETE: ChangeMPIN changes a user's MPIN (requires old MPIN) with UserAgent
func (s *MPINService) ChangeMPIN(ctx context.Context, req *MPINChangeRequest) error {
	startTime := time.Now()

	s.logMPINEvent(ctx, &models.MPINLogEvent{
		LogEnvelope: models.LogEnvelope{
			EventID:     uuid.New().String(),
			EventType:   string(models.LogEventTypeMPIN),
			ServiceName: "auth-service",
			Timestamp:   time.Now(),
			Environment: s.config.Environment,
			Version:     ServiceVersion,
			Level:       string(models.LogLevelInfo),
			Message:     "MPIN change initiated",
		},
		UserID:    req.UserID.String(),
		Status:    "change_initiated",
		DeviceID:  req.DeviceID,
		UserAgent: req.UserAgent,
	})

	// Rate limiting for MPIN change with risk score updates
	changeRateKey := fmt.Sprintf("mpin_change:%s:%s", req.UserID.String(), req.DeviceID)
	if allowed, retryAfter := s.checkRateLimit(ctx, changeRateKey, MPINChangeRateLimit, MPINForgotRateWindow); !allowed {
		s.logMPINEvent(ctx, &models.MPINLogEvent{
			LogEnvelope: models.LogEnvelope{
				EventID:     uuid.New().String(),
				EventType:   string(models.LogEventTypeMPIN),
				ServiceName: "auth-service",
				Timestamp:   time.Now(),
				Environment: s.config.Environment,
				Version:     ServiceVersion,
				Level:       string(models.LogLevelWarning),
				Message:     "MPIN change rate limit exceeded",
			},
			UserID:       req.UserID.String(),
			Status:       "change_rate_limited",
			DeviceID:     req.DeviceID,
			UserAgent:    req.UserAgent,
			ErrorCode:    "RATE_LIMIT_EXCEEDED",
			AttemptsLeft: retryAfter,
		})
		return ErrMPINRateLimitExceeded
	}

	if err := s.validateMPIN(req.NewMPIN); err != nil {
		s.logMPINEvent(ctx, &models.MPINLogEvent{
			LogEnvelope: models.LogEnvelope{
				EventID:     uuid.New().String(),
				EventType:   string(models.LogEventTypeMPIN),
				ServiceName: "auth-service",
				Timestamp:   time.Now(),
				Environment: s.config.Environment,
				Version:     ServiceVersion,
				Level:       string(models.LogLevelError),
				Message:     "New MPIN validation failed",
			},
			UserID:        req.UserID.String(),
			Status:        "change_failed",
			DeviceID:      req.DeviceID,
			UserAgent:     req.UserAgent,
			ErrorCode:     "VALIDATION_FAILED",
			ErrorMessage:  err.Error(),
			FailureReason: "new_mpin_validation_failed",
		})
		return err
	}

	verifyReq := &MPINVerifyRequest{
		UserID:            req.UserID,
		MPIN:              req.CurrentMPIN,
		DeviceID:          req.DeviceID,
		IPAddress:         req.IPAddress,
		DeviceFingerprint: req.DeviceFingerprint,
		UserAgent:         req.UserAgent,
	}

	verifyResult, err := s.VerifyMPIN(ctx, verifyReq)
	if err != nil {
		return err
	}

	if !verifyResult.Verified {
		s.logMPINEvent(ctx, &models.MPINLogEvent{
			LogEnvelope: models.LogEnvelope{
				EventID:     uuid.New().String(),
				EventType:   string(models.LogEventTypeMPIN),
				ServiceName: "auth-service",
				Timestamp:   time.Now(),
				Environment: s.config.Environment,
				Version:     ServiceVersion,
				Level:       string(models.LogLevelWarning),
				Message:     "Current MPIN verification failed for change",
			},
			UserID:        req.UserID.String(),
			Status:        "change_failed",
			DeviceID:      req.DeviceID,
			UserAgent:     req.UserAgent,
			ErrorCode:     "CURRENT_MPIN_INVALID",
			FailureReason: "current_mpin_invalid",
		})
		return ErrMPINInvalid
	}

	hashResult, err := s.hasher.HashMPIN(req.NewMPIN)
	if err != nil {
		s.logMPINEvent(ctx, &models.MPINLogEvent{
			LogEnvelope: models.LogEnvelope{
				EventID:     uuid.New().String(),
				EventType:   string(models.LogEventTypeMPIN),
				ServiceName: "auth-service",
				Timestamp:   time.Now(),
				Environment: s.config.Environment,
				Version:     ServiceVersion,
				Level:       string(models.LogLevelError),
				Message:     "Failed to hash new MPIN",
			},
			UserID:        req.UserID.String(),
			Status:        "change_failed",
			DeviceID:      req.DeviceID,
			UserAgent:     req.UserAgent,
			ErrorCode:     "HASHING_FAILED",
			ErrorMessage:  err.Error(),
			FailureReason: "hashing_failed",
		})
		return fmt.Errorf("failed to hash new MPIN: %w", err)
	}

	if err := s.mpinRepo.UpdateMPIN(ctx, req.UserID, hashResult.Hash, hashResult.Salt, hashResult.PepperVersion); err != nil {
		s.logMPINEvent(ctx, &models.MPINLogEvent{
			LogEnvelope: models.LogEnvelope{
				EventID:     uuid.New().String(),
				EventType:   string(models.LogEventTypeMPIN),
				ServiceName: "auth-service",
				Timestamp:   time.Now(),
				Environment: s.config.Environment,
				Version:     ServiceVersion,
				Level:       string(models.LogLevelError),
				Message:     "Failed to update MPIN in repository",
			},
			UserID:        req.UserID.String(),
			Status:        "change_failed",
			DeviceID:      req.DeviceID,
			UserAgent:     req.UserAgent,
			ErrorCode:     "REPOSITORY_UPDATE_FAILED",
			ErrorMessage:  err.Error(),
			FailureReason: "repository_update_failed",
		})
		return fmt.Errorf("failed to update MPIN: %w", err)
	}

	if err := s.mpinRepo.UpdateMPINDeviceBinding(ctx, req.UserID, req.DeviceID); err != nil {
		s.logger.Warn("Failed to update MPIN device binding",
			util.ErrorField(err),
			util.String("user_id", req.UserID.String()),
		)
	}

	s.invalidateMPINCache(ctx, req.UserID)

	s.logMPINEvent(ctx, &models.MPINLogEvent{
		LogEnvelope: models.LogEnvelope{
			EventID:     uuid.New().String(),
			EventType:   string(models.LogEventTypeMPIN),
			ServiceName: "auth-service",
			Timestamp:   time.Now(),
			Environment: s.config.Environment,
			Version:     ServiceVersion,
			Level:       string(models.LogLevelInfo),
			Message:     "MPIN changed successfully",
		},
		UserID:    req.UserID.String(),
		Status:    "change_completed",
		DeviceID:  req.DeviceID,
		UserAgent: req.UserAgent,
		Duration:  int64(time.Since(startTime).Milliseconds()),
	})

	s.logger.Info("MPIN changed successfully",
		util.String("user_id", req.UserID.String()),
		util.String("device_id", req.DeviceID),
		util.String("user_agent", req.UserAgent),
		util.Duration("duration", time.Since(startTime)),
	)

	return nil
}

// ✅ COMPLETE: ChangeMPINByAdmin changes user MPIN by admin (admin override) with UserAgent
func (s *MPINService) ChangeMPINByAdmin(ctx context.Context, req *MPINAdminChangeRequest) error {
	startTime := time.Now()

	s.logMPINEvent(ctx, &models.MPINLogEvent{
		LogEnvelope: models.LogEnvelope{
			EventID:     uuid.New().String(),
			EventType:   string(models.LogEventTypeMPIN),
			ServiceName: "auth-service",
			Timestamp:   time.Now(),
			Environment: s.config.Environment,
			Version:     ServiceVersion,
			Level:       string(models.LogLevelInfo),
			Message:     "Admin MPIN change initiated",
		},
		UserID:    req.UserID.String(),
		Status:    "admin_change_initiated",
		UserAgent: req.UserAgent,
	})

	if err := s.validateMPIN(req.NewMPIN); err != nil {
		s.logMPINEvent(ctx, &models.MPINLogEvent{
			LogEnvelope: models.LogEnvelope{
				EventID:     uuid.New().String(),
				EventType:   string(models.LogEventTypeMPIN),
				ServiceName: "auth-service",
				Timestamp:   time.Now(),
				Environment: s.config.Environment,
				Version:     ServiceVersion,
				Level:       string(models.LogLevelError),
				Message:     "New MPIN validation failed for admin change",
			},
			UserID:        req.UserID.String(),
			Status:        "admin_change_failed",
			UserAgent:     req.UserAgent,
			ErrorCode:     "VALIDATION_FAILED",
			ErrorMessage:  err.Error(),
			FailureReason: "new_mpin_validation_failed",
		})
		return err
	}

	user, err := s.userRepo.GetUserByID(ctx, req.UserID)
	if err != nil {
		s.logMPINEvent(ctx, &models.MPINLogEvent{
			LogEnvelope: models.LogEnvelope{
				EventID:     uuid.New().String(),
				EventType:   string(models.LogEventTypeMPIN),
				ServiceName: "auth-service",
				Timestamp:   time.Now(),
				Environment: s.config.Environment,
				Version:     ServiceVersion,
				Level:       string(models.LogLevelError),
				Message:     "User not found for admin MPIN change",
			},
			UserID:        req.UserID.String(),
			Status:        "admin_change_failed",
			UserAgent:     req.UserAgent,
			ErrorCode:     "USER_NOT_FOUND",
			FailureReason: "user_not_found",
		})
		return fmt.Errorf("user not found: %w", err)
	}

	if !user.IsActive {
		s.logMPINEvent(ctx, &models.MPINLogEvent{
			LogEnvelope: models.LogEnvelope{
				EventID:     uuid.New().String(),
				EventType:   string(models.LogEventTypeMPIN),
				ServiceName: "auth-service",
				Timestamp:   time.Now(),
				Environment: s.config.Environment,
				Version:     ServiceVersion,
				Level:       string(models.LogLevelWarning),
				Message:     "Inactive user for admin MPIN change",
			},
			UserID:        req.UserID.String(),
			Status:        "admin_change_failed",
			UserAgent:     req.UserAgent,
			ErrorCode:     "USER_INACTIVE",
			FailureReason: "user_inactive",
		})
		return fmt.Errorf("user account is inactive")
	}

	hashResult, err := s.hasher.HashMPIN(req.NewMPIN)
	if err != nil {
		s.logMPINEvent(ctx, &models.MPINLogEvent{
			LogEnvelope: models.LogEnvelope{
				EventID:     uuid.New().String(),
				EventType:   string(models.LogEventTypeMPIN),
				ServiceName: "auth-service",
				Timestamp:   time.Now(),
				Environment: s.config.Environment,
				Version:     ServiceVersion,
				Level:       string(models.LogLevelError),
				Message:     "Failed to hash MPIN for admin change",
			},
			UserID:        req.UserID.String(),
			Status:        "admin_change_failed",
			UserAgent:     req.UserAgent,
			ErrorCode:     "HASHING_FAILED",
			ErrorMessage:  err.Error(),
			FailureReason: "hashing_failed",
		})
		return fmt.Errorf("failed to hash MPIN: %w", err)
	}

	if err := s.mpinRepo.UpdateMPIN(ctx, req.UserID, hashResult.Hash, hashResult.Salt, hashResult.PepperVersion); err != nil {
		s.logMPINEvent(ctx, &models.MPINLogEvent{
			LogEnvelope: models.LogEnvelope{
				EventID:     uuid.New().String(),
				EventType:   string(models.LogEventTypeMPIN),
				ServiceName: "auth-service",
				Timestamp:   time.Now(),
				Environment: s.config.Environment,
				Version:     ServiceVersion,
				Level:       string(models.LogLevelError),
				Message:     "Failed to update MPIN in repository for admin change",
			},
			UserID:        req.UserID.String(),
			Status:        "admin_change_failed",
			UserAgent:     req.UserAgent,
			ErrorCode:     "REPOSITORY_UPDATE_FAILED",
			ErrorMessage:  err.Error(),
			FailureReason: "repository_update_failed",
		})
		return fmt.Errorf("failed to update MPIN: %w", err)
	}

	_ = s.mpinRepo.UnlockMPIN(ctx, req.UserID)

	s.invalidateMPINCache(ctx, req.UserID)

	s.logMPINEvent(ctx, &models.MPINLogEvent{
		LogEnvelope: models.LogEnvelope{
			EventID:     uuid.New().String(),
			EventType:   string(models.LogEventTypeMPIN),
			ServiceName: "auth-service",
			Timestamp:   time.Now(),
			Environment: s.config.Environment,
			Version:     ServiceVersion,
			Level:       string(models.LogLevelWarning),
			Message:     "MPIN changed by admin successfully",
		},
		UserID:    req.UserID.String(),
		Status:    "admin_change_completed",
		UserAgent: req.UserAgent,
		Duration:  int64(time.Since(startTime).Milliseconds()),
	})

	s.logger.Warn("MPIN changed by admin",
		util.String("user_id", req.UserID.String()),
		util.String("admin_id", req.AdminID.String()),
		util.String("user_agent", req.UserAgent),
		util.String("reason", req.Reason),
		util.Duration("duration", time.Since(startTime)),
	)

	return nil
}

// ✅ COMPLETE: ResetMPIN resets user MPIN (admin override - unlocks only) with UserAgent
func (s *MPINService) ResetMPIN(ctx context.Context, req *MPINResetRequest) error {
	startTime := time.Now()

	s.logMPINEvent(ctx, &models.MPINLogEvent{
		LogEnvelope: models.LogEnvelope{
			EventID:     uuid.New().String(),
			EventType:   string(models.LogEventTypeMPIN),
			ServiceName: "auth-service",
			Timestamp:   time.Now(),
			Environment: s.config.Environment,
			Version:     ServiceVersion,
			Level:       string(models.LogLevelInfo),
			Message:     "MPIN reset initiated",
		},
		UserID:    req.UserID.String(),
		Status:    "reset_initiated",
		UserAgent: req.UserAgent,
	})

	_, err := s.mpinRepo.GetMPINByUserID(ctx, req.UserID)
	if err != nil {
		s.logMPINEvent(ctx, &models.MPINLogEvent{
			LogEnvelope: models.LogEnvelope{
				EventID:     uuid.New().String(),
				EventType:   string(models.LogEventTypeMPIN),
				ServiceName: "auth-service",
				Timestamp:   time.Now(),
				Environment: s.config.Environment,
				Version:     ServiceVersion,
				Level:       string(models.LogLevelWarning),
				Message:     "MPIN not found for reset",
			},
			UserID:        req.UserID.String(),
			Status:        "reset_failed",
			UserAgent:     req.UserAgent,
			ErrorCode:     "MPIN_NOT_FOUND",
			FailureReason: "mpin_not_found",
		})
		return ErrMPINNotFound
	}

	if err := s.mpinRepo.UnlockMPIN(ctx, req.UserID); err != nil {
		s.logMPINEvent(ctx, &models.MPINLogEvent{
			LogEnvelope: models.LogEnvelope{
				EventID:     uuid.New().String(),
				EventType:   string(models.LogEventTypeMPIN),
				ServiceName: "auth-service",
				Timestamp:   time.Now(),
				Environment: s.config.Environment,
				Version:     ServiceVersion,
				Level:       string(models.LogLevelError),
				Message:     "Failed to unlock MPIN for reset",
			},
			UserID:        req.UserID.String(),
			Status:        "reset_failed",
			UserAgent:     req.UserAgent,
			ErrorCode:     "UNLOCK_FAILED",
			ErrorMessage:  err.Error(),
			FailureReason: "unlock_failed",
		})
		return fmt.Errorf("failed to unlock MPIN: %w", err)
	}

	s.invalidateMPINCache(ctx, req.UserID)

	s.logMPINEvent(ctx, &models.MPINLogEvent{
		LogEnvelope: models.LogEnvelope{
			EventID:     uuid.New().String(),
			EventType:   string(models.LogEventTypeMPIN),
			ServiceName: "auth-service",
			Timestamp:   time.Now(),
			Environment: s.config.Environment,
			Version:     ServiceVersion,
			Level:       string(models.LogLevelWarning),
			Message:     "MPIN reset by admin completed",
		},
		UserID:    req.UserID.String(),
		Status:    "reset_completed",
		UserAgent: req.UserAgent,
		Duration:  int64(time.Since(startTime).Milliseconds()),
	})

	s.logger.Warn("MPIN reset by admin",
		util.String("user_id", req.UserID.String()),
		util.String("reset_by", req.ResetBy.String()),
		util.String("user_agent", req.UserAgent),
		util.String("reason", req.Reason),
		util.Duration("duration", time.Since(startTime)),
	)

	return nil
}

// ✅ COMPLETE: UnlockMPIN unlocks a locked MPIN
func (s *MPINService) UnlockMPIN(ctx context.Context, userID uuid.UUID) error {
	s.logMPINEvent(ctx, &models.MPINLogEvent{
		LogEnvelope: models.LogEnvelope{
			EventID:     uuid.New().String(),
			EventType:   string(models.LogEventTypeMPIN),
			ServiceName: "auth-service",
			Timestamp:   time.Now(),
			Environment: s.config.Environment,
			Version:     ServiceVersion,
			Level:       string(models.LogLevelInfo),
			Message:     "MPIN unlock initiated",
		},
		UserID: userID.String(),
		Status: "unlock_initiated",
	})

	if err := s.mpinRepo.UnlockMPIN(ctx, userID); err != nil {
		s.logMPINEvent(ctx, &models.MPINLogEvent{
			LogEnvelope: models.LogEnvelope{
				EventID:     uuid.New().String(),
				EventType:   string(models.LogEventTypeMPIN),
				ServiceName: "auth-service",
				Timestamp:   time.Now(),
				Environment: s.config.Environment,
				Version:     ServiceVersion,
				Level:       string(models.LogLevelError),
				Message:     "Failed to unlock MPIN",
			},
			UserID:        userID.String(),
			Status:        "unlock_failed",
			ErrorCode:     "UNLOCK_FAILED",
			ErrorMessage:  err.Error(),
			FailureReason: "unlock_failed",
		})
		return fmt.Errorf("failed to unlock MPIN: %w", err)
	}

	s.invalidateMPINCache(ctx, userID)

	s.logMPINEvent(ctx, &models.MPINLogEvent{
		LogEnvelope: models.LogEnvelope{
			EventID:     uuid.New().String(),
			EventType:   string(models.LogEventTypeMPIN),
			ServiceName: "auth-service",
			Timestamp:   time.Now(),
			Environment: s.config.Environment,
			Version:     ServiceVersion,
			Level:       string(models.LogLevelInfo),
			Message:     "MPIN unlocked successfully",
		},
		UserID: userID.String(),
		Status: "unlock_completed",
	})

	return nil
}

// ✅ COMPLETE: GetMPINStatus gets MPIN status for a user
func (s *MPINService) GetMPINStatus(ctx context.Context, userID uuid.UUID) (*MPINStatus, error) {
	s.logger.Debug("🔍 GetMPINStatus called",
		util.String("user_id", userID.String()))

	mpinCred, err := s.mpinRepo.GetMPINByUserID(ctx, userID)
	if err != nil {
		s.logger.Error("❌ Error getting MPIN",
			util.ErrorField(err),
			util.String("user_id", userID.String()))
		return nil, err
	}

	if mpinCred == nil {
		s.logger.Debug("❌ No MPIN found - returning Exists: false",
			util.String("user_id", userID.String()))
		return &MPINStatus{
			UserID:         userID,
			Exists:         false,
			IsLocked:       false,
			FailedAttempts: 0,
			LockedUntil:    nil,
			LastChanged:    nil,
			DeviceID:       "",
		}, nil
	}

	s.logger.Debug("✅ MPIN exists - returning Exists: true",
		util.String("user_id", userID.String()),
		util.Bool("is_locked", mpinCred.IsLocked))

	return &MPINStatus{
		UserID:         userID,
		Exists:         true,
		IsLocked:       mpinCred.IsLocked,
		FailedAttempts: mpinCred.FailedAttempts,
		LockedUntil:    mpinCred.LockedUntil,
		LastChanged:    mpinCred.LastChanged,
		DeviceID:       mpinCred.DeviceID,
	}, nil
}

// ✅ COMPLETE: UpdateDeviceBinding updates device binding for MPIN
func (s *MPINService) UpdateDeviceBinding(ctx context.Context, userID uuid.UUID, deviceID string) error {
	if err := s.mpinRepo.UpdateMPINDeviceBinding(ctx, userID, deviceID); err != nil {
		return fmt.Errorf("failed to update device binding: %w", err)
	}

	s.invalidateMPINCache(ctx, userID)

	return nil
}

// ✅ COMPLETE: GetMPINsByDevice gets all MPINs associated with a device
func (s *MPINService) GetMPINsByDevice(ctx context.Context, deviceID string) ([]*models.MPINCredential, error) {
	return s.mpinRepo.GetMPINsByDevice(ctx, deviceID)
}

// ✅ COMPLETE: GetLockedMPINs gets locked MPIN credentials
func (s *MPINService) GetLockedMPINs(ctx context.Context, limit int) ([]*models.MPINCredential, error) {
	return s.mpinRepo.GetLockedMPINs(ctx, limit)
}

// ✅ COMPLETE: CleanupExpiredLocks cleans up expired MPIN locks
func (s *MPINService) CleanupExpiredLocks(ctx context.Context) (int, error) {
	return s.mpinRepo.CleanupUnlockedMPINs(ctx)
}

// ✅ COMPLETE: GetMPINStats gets MPIN service statistics
func (s *MPINService) GetMPINStats(ctx context.Context) (map[string]interface{}, error) {
	stats, err := s.mpinRepo.GetRepositoryStats(ctx)
	if err != nil {
		return nil, err
	}

	stats["service_constants"] = map[string]interface{}{
		"min_length":            MPINMinLength,
		"max_length":            MPINMaxLength,
		"max_attempts":          MPINMaxAttempts,
		"lock_duration_minutes": int(MPINLockDuration.Minutes()),
		"rate_limits": map[string]interface{}{
			"verify_per_minute": MPINVerifyRateLimit,
			"forgot_per_hour":   MPINForgotRateLimit,
			"change_per_hour":   MPINChangeRateLimit,
			"setup_per_hour":    MPINSetupRateLimit,
		},
	}

	return stats, nil
}

// ✅ COMPLETE: HealthCheck performs a health check on the service
func (s *MPINService) HealthCheck(ctx context.Context) error {
	return s.mpinRepo.HealthCheck(ctx)
}

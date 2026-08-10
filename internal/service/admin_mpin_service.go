package service

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"net"
	"regexp"
	"sync"
	"time"

	"github.com/google/uuid"

	"auth-service/internal/config"
	"auth-service/internal/encryption"
	appErrors "auth-service/internal/errors"
	"auth-service/internal/hashing"
	"auth-service/internal/infrastructure/audit"
	"auth-service/internal/infrastructure/idempotency"
	"auth-service/internal/models"
	"auth-service/internal/repository/postgres"
	"auth-service/internal/repository/scylla"
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

// ---- Request/Response structs ----

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
	UserAgent         string    `json:"user_agent"`
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
	UserAgent         string    `json:"user_agent"`
}

type AdminMPINResetRequest struct {
	AdminID   uuid.UUID `json:"admin_id" validate:"required"`
	ResetBy   uuid.UUID `json:"reset_by" validate:"required"`
	Reason    string    `json:"reason" validate:"required"`
	IPAddress string    `json:"ip_address"`
	UserAgent string    `json:"user_agent"`
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
	UserAgent string    `json:"user_agent"`
}

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

// ---- AdminMPINService ----

type AdminMPINService struct {
	mpinRepo        *scylla.AdminMPINRepositoryImpl
	adminRepo       postgres.AdminRepository
	deviceTrustRepo scylla.AdminDeviceTrustRepository
	otpService      *OTPService
	encryptionMgr   *encryption.EncryptionManager
	hasher          *hashing.Hasher
	config          *config.Config
	distCache       *DistributedCache
	logProducer     *LogProducerService

	idempotencyStore idempotency.Store
	auditService     *audit.AuditService

	cacheMutex sync.RWMutex
}

func NewAdminMPINService(
	mpinRepo *scylla.AdminMPINRepositoryImpl,
	adminRepo postgres.AdminRepository,
	deviceTrustRepo scylla.AdminDeviceTrustRepository,
	otpService *OTPService,
	encryptionMgr *encryption.EncryptionManager,
	hasher *hashing.Hasher,
	cfg *config.Config,
	logProducer *LogProducerService,
	idempotencyStore idempotency.Store,
	auditService *audit.AuditService,
) *AdminMPINService {
	return &AdminMPINService{
		mpinRepo:         mpinRepo,
		adminRepo:        adminRepo,
		deviceTrustRepo:  deviceTrustRepo,
		otpService:       otpService,
		encryptionMgr:    encryptionMgr,
		hasher:           hasher,
		config:           cfg,
		logProducer:      logProducer,
		idempotencyStore: idempotencyStore,
		auditService:     auditService,
	}
}

// ---- Helper methods ----

func (s *AdminMPINService) hashDeviceFingerprint(fingerprint string) string {
	if fingerprint == "" {
		return ""
	}
	hash := sha256.Sum256([]byte(fingerprint))
	return hex.EncodeToString(hash[:])
}

func (s *AdminMPINService) getSubnet(ipAddress string) string {
	if ipAddress == "" {
		return ""
	}
	parsedIP := net.ParseIP(ipAddress)
	if parsedIP == nil {
		return ""
	}
	if ipv4 := parsedIP.To4(); ipv4 != nil {
		mask := net.CIDRMask(24, 32)
		maskedIP := ipv4.Mask(mask)
		return maskedIP.String()
	}
	if ipv6 := parsedIP.To16(); ipv6 != nil {
		mask := net.CIDRMask(64, 128)
		maskedIP := ipv6.Mask(mask)
		return maskedIP.String()
	}
	return ""
}

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

// isDeviceTrusted – with extensive logging for debugging
func (s *AdminMPINService) isDeviceTrusted(ctx context.Context, adminID uuid.UUID, deviceID, ipAddress, deviceFingerprint string) (bool, *models.DeviceTrustLevel, error) {
	trustLevel, err := s.deviceTrustRepo.GetAdminDeviceTrustLevel(ctx, adminID, deviceID)
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
				Message:     "Device trust: repository error",
			},
			UserID:        adminID.String(),
			DeviceID:      deviceID,
			ErrorCode:     "DEVICE_TRUST_REPO_ERROR",
			ErrorMessage:  err.Error(),
			FailureReason: "repo_error",
		})
		return false, nil, err
	}
	if trustLevel == nil {
		s.logAdminMPINEvent(ctx, &models.MPINLogEvent{
			LogEnvelope: models.LogEnvelope{
				EventID:     uuid.New().String(),
				EventType:   string(models.LogEventTypeMPIN),
				ServiceName: "auth-service",
				Timestamp:   time.Now(),
				Environment: s.config.Environment,
				Version:     AdminServiceVersion,
				Level:       string(models.LogLevelWarning),
				Message:     "Device trust: no trust record found",
			},
			UserID:        adminID.String(),
			DeviceID:      deviceID,
			Status:        "trust_check_failed",
			FailureReason: "no_trust_record",
		})
		return false, nil, nil
	}
	if trustLevel.IsBlocked {
		s.logAdminMPINEvent(ctx, &models.MPINLogEvent{
			LogEnvelope: models.LogEnvelope{
				EventID:     uuid.New().String(),
				EventType:   string(models.LogEventTypeMPIN),
				ServiceName: "auth-service",
				Timestamp:   time.Now(),
				Environment: s.config.Environment,
				Version:     AdminServiceVersion,
				Level:       string(models.LogLevelWarning),
				Message:     "Device trust: device is blocked",
			},
			UserID:        adminID.String(),
			DeviceID:      deviceID,
			Status:        "trust_check_failed",
			FailureReason: "device_blocked",
		})
		return false, trustLevel, nil
	}
	if trustLevel.TrustStatus != models.TrustStatusPrimary && trustLevel.TrustStatus != models.TrustStatusTrusted {
		s.logAdminMPINEvent(ctx, &models.MPINLogEvent{
			LogEnvelope: models.LogEnvelope{
				EventID:     uuid.New().String(),
				EventType:   string(models.LogEventTypeMPIN),
				ServiceName: "auth-service",
				Timestamp:   time.Now(),
				Environment: s.config.Environment,
				Version:     AdminServiceVersion,
				Level:       string(models.LogLevelWarning),
				Message:     fmt.Sprintf("Device trust: status is %s (not Primary/Trusted)", trustLevel.TrustStatus),
			},
			UserID:        adminID.String(),
			DeviceID:      deviceID,
			Status:        "trust_check_failed",
			FailureReason: "untrusted_status",
		})
		return false, trustLevel, nil
	}
	if ipAddress != "" && trustLevel.LastIPAddress != "" && !s.isSubnetMatch(trustLevel.LastIPAddress, ipAddress) {
		trustLevel.RiskScore += 15
		if err := s.deviceTrustRepo.SetAdminDeviceTrustLevel(ctx, adminID, deviceID, trustLevel); err != nil {
			s.logAdminMPINEvent(ctx, &models.MPINLogEvent{
				LogEnvelope: models.LogEnvelope{
					EventID:     uuid.New().String(),
					EventType:   string(models.LogEventTypeMPIN),
					ServiceName: "auth-service",
					Timestamp:   time.Now(),
					Environment: s.config.Environment,
					Version:     AdminServiceVersion,
					Level:       string(models.LogLevelWarning),
					Message:     "Failed to update risk score for subnet mismatch",
				},
				UserID:       adminID.String(),
				Status:       "risk_update_failed",
				DeviceID:     deviceID,
				ErrorCode:    "RISK_UPDATE_FAILED",
				ErrorMessage: err.Error(),
			})
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
				Message:     fmt.Sprintf("Device trust: IP subnet mismatch (stored: %s, current: %s)", trustLevel.LastIPAddress, ipAddress),
			},
			UserID:        adminID.String(),
			DeviceID:      deviceID,
			Status:        "trust_check_failed",
			FailureReason: "ip_subnet_mismatch",
		})
		return false, trustLevel, nil
	}
	hashedFingerprint := s.hashDeviceFingerprint(deviceFingerprint)
	if deviceFingerprint != "" && trustLevel.DeviceFingerprint != "" && trustLevel.DeviceFingerprint != hashedFingerprint {
		trustLevel.RiskScore += 10
		if err := s.deviceTrustRepo.SetAdminDeviceTrustLevel(ctx, adminID, deviceID, trustLevel); err != nil {
			s.logAdminMPINEvent(ctx, &models.MPINLogEvent{
				LogEnvelope: models.LogEnvelope{
					EventID:     uuid.New().String(),
					EventType:   string(models.LogEventTypeMPIN),
					ServiceName: "auth-service",
					Timestamp:   time.Now(),
					Environment: s.config.Environment,
					Version:     AdminServiceVersion,
					Level:       string(models.LogLevelWarning),
					Message:     "Failed to update risk score for fingerprint mismatch",
				},
				UserID:       adminID.String(),
				Status:       "risk_update_failed",
				DeviceID:     deviceID,
				ErrorCode:    "RISK_UPDATE_FAILED",
				ErrorMessage: err.Error(),
			})
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
				Message:     "Device trust: fingerprint mismatch",
			},
			UserID:        adminID.String(),
			DeviceID:      deviceID,
			Status:        "trust_check_failed",
			FailureReason: "fingerprint_mismatch",
		})
		return false, trustLevel, nil
	}
	// All checks passed
	s.logAdminMPINEvent(ctx, &models.MPINLogEvent{
		LogEnvelope: models.LogEnvelope{
			EventID:     uuid.New().String(),
			EventType:   string(models.LogEventTypeMPIN),
			ServiceName: "auth-service",
			Timestamp:   time.Now(),
			Environment: s.config.Environment,
			Version:     AdminServiceVersion,
			Level:       string(models.LogLevelInfo),
			Message:     "Device trust: device is trusted",
		},
		UserID:   adminID.String(),
		DeviceID: deviceID,
		Status:   "trust_check_success",
	})
	return true, trustLevel, nil
}

// logAdminMPINEvent sends log event via Kafka
func (s *AdminMPINService) logAdminMPINEvent(ctx context.Context, event *models.MPINLogEvent) {
	if s.logProducer != nil {
		_ = s.logProducer.ProduceMPINEvent(ctx, event)
	}
}

// ---- Cache and rate limiting ----

func (s *AdminMPINService) SetDistributedCache(distCache *DistributedCache) {
	s.distCache = distCache
}

func (s *AdminMPINService) checkRateLimit(ctx context.Context, key string, limit int, window time.Duration) (bool, int) {
	if s.distCache == nil {
		return true, 0
	}
	allowed, retryAfter := s.distCache.AllowRate(ctx, key, limit, window)
	if !allowed {
		if matches := regexp.MustCompile(`admin_mpin_[^:]+:([^:]+):`).FindStringSubmatch(key); len(matches) > 1 {
			if adminID, err := uuid.Parse(matches[1]); err == nil {
				go s.updateRiskScoreForRateLimit(ctx, adminID)
			}
		}
	}
	return allowed, retryAfter
}

func (s *AdminMPINService) updateRiskScoreForRateLimit(ctx context.Context, adminID uuid.UUID) {
	trustLevel, err := s.deviceTrustRepo.GetAdminDeviceTrustLevel(ctx, adminID, "")
	if err != nil || trustLevel == nil {
		return
	}
	trustLevel.RiskScore += 10
	if err := s.deviceTrustRepo.SetAdminDeviceTrustLevel(ctx, adminID, trustLevel.DeviceID, trustLevel); err != nil {
		s.logAdminMPINEvent(ctx, &models.MPINLogEvent{
			LogEnvelope: models.LogEnvelope{
				EventID:     uuid.New().String(),
				EventType:   string(models.LogEventTypeMPIN),
				ServiceName: "auth-service",
				Timestamp:   time.Now(),
				Environment: s.config.Environment,
				Version:     AdminServiceVersion,
				Level:       string(models.LogLevelWarning),
				Message:     "Failed to update risk score for rate limit",
			},
			UserID:       adminID.String(),
			Status:       "risk_update_failed",
			ErrorCode:    "RISK_UPDATE_FAILED",
			ErrorMessage: err.Error(),
		})
	}
}

func (s *AdminMPINService) updateRiskScoreForFailedMPIN(ctx context.Context, adminID uuid.UUID, deviceID string) {
	trustLevel, err := s.deviceTrustRepo.GetAdminDeviceTrustLevel(ctx, adminID, deviceID)
	if err != nil || trustLevel == nil {
		return
	}
	trustLevel.RiskScore += 10
	if err := s.deviceTrustRepo.SetAdminDeviceTrustLevel(ctx, adminID, deviceID, trustLevel); err != nil {
		s.logAdminMPINEvent(ctx, &models.MPINLogEvent{
			LogEnvelope: models.LogEnvelope{
				EventID:     uuid.New().String(),
				EventType:   string(models.LogEventTypeMPIN),
				ServiceName: "auth-service",
				Timestamp:   time.Now(),
				Environment: s.config.Environment,
				Version:     AdminServiceVersion,
				Level:       string(models.LogLevelWarning),
				Message:     "Failed to update risk score for failed MPIN",
			},
			UserID:       adminID.String(),
			Status:       "risk_update_failed",
			DeviceID:     deviceID,
			ErrorCode:    "RISK_UPDATE_FAILED",
			ErrorMessage: err.Error(),
		})
	}
}

func (s *AdminMPINService) updateRiskScoreForDeviceMismatch(ctx context.Context, adminID uuid.UUID, deviceID string) {
	trustLevel, err := s.deviceTrustRepo.GetAdminDeviceTrustLevel(ctx, adminID, deviceID)
	if err != nil || trustLevel == nil {
		return
	}
	trustLevel.RiskScore += 10
	if err := s.deviceTrustRepo.SetAdminDeviceTrustLevel(ctx, adminID, deviceID, trustLevel); err != nil {
		s.logAdminMPINEvent(ctx, &models.MPINLogEvent{
			LogEnvelope: models.LogEnvelope{
				EventID:     uuid.New().String(),
				EventType:   string(models.LogEventTypeMPIN),
				ServiceName: "auth-service",
				Timestamp:   time.Now(),
				Environment: s.config.Environment,
				Version:     AdminServiceVersion,
				Level:       string(models.LogLevelWarning),
				Message:     "Failed to update risk score for device mismatch",
			},
			UserID:       adminID.String(),
			Status:       "risk_update_failed",
			DeviceID:     deviceID,
			ErrorCode:    "RISK_UPDATE_FAILED",
			ErrorMessage: err.Error(),
		})
	}
}

func (s *AdminMPINService) updateRiskScoreForOTPFailure(ctx context.Context, adminID uuid.UUID, deviceID string) {
	trustLevel, err := s.deviceTrustRepo.GetAdminDeviceTrustLevel(ctx, adminID, deviceID)
	if err != nil || trustLevel == nil {
		return
	}
	trustLevel.RiskScore += 10
	if err := s.deviceTrustRepo.SetAdminDeviceTrustLevel(ctx, adminID, deviceID, trustLevel); err != nil {
		s.logAdminMPINEvent(ctx, &models.MPINLogEvent{
			LogEnvelope: models.LogEnvelope{
				EventID:     uuid.New().String(),
				EventType:   string(models.LogEventTypeMPIN),
				ServiceName: "auth-service",
				Timestamp:   time.Now(),
				Environment: s.config.Environment,
				Version:     AdminServiceVersion,
				Level:       string(models.LogLevelWarning),
				Message:     "Failed to update risk score for OTP failure",
			},
			UserID:       adminID.String(),
			Status:       "risk_update_failed",
			DeviceID:     deviceID,
			ErrorCode:    "RISK_UPDATE_FAILED",
			ErrorMessage: err.Error(),
		})
	}
}

// ---- MPIN validation helpers ----

func (s *AdminMPINService) validateAdminMPIN(mpin string) error {
	if len(mpin) < AdminMPINMinLength || len(mpin) > AdminMPINMaxLength {
		return fmt.Errorf("%w: admin MPIN must be between %d and %d digits", appErrors.ErrInvalidInput, AdminMPINMinLength, AdminMPINMaxLength)
	}
	if matched, _ := regexp.MatchString(`^\d+$`, mpin); !matched {
		return fmt.Errorf("%w: admin MPIN must contain only digits", appErrors.ErrInvalidInput)
	}
	if s.isAdminMPINWeak(mpin) {
		return appErrors.ErrAdminMPINTooWeak
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

// ---- Public methods ----

// SetupAdminMPIN – sets up MPIN and creates device trust
func (s *AdminMPINService) SetupAdminMPIN(ctx context.Context, req *AdminMPINSetupRequest) error {
	startTime := time.Now()
	idempKey, _ := ctx.Value("idempotency_key").(string)
	if idempKey == "" {
		idempKey = fmt.Sprintf("admin_mpin_setup:%s:%s", req.AdminID.String(), req.DeviceID)
	}

	var done bool
	if err := s.idempotencyStore.Get(ctx, nil, idempKey, &done); err == nil && done {
		s.logAdminMPINEvent(ctx, &models.MPINLogEvent{
			LogEnvelope: models.LogEnvelope{
				EventID:     uuid.New().String(),
				EventType:   string(models.LogEventTypeMPIN),
				ServiceName: "auth-service",
				Timestamp:   time.Now(),
				Environment: s.config.Environment,
				Version:     AdminServiceVersion,
				Level:       string(models.LogLevelInfo),
				Message:     "Idempotent – admin MPIN setup already done",
			},
			UserID:   req.AdminID.String(),
			Status:   "admin_setup_idempotent",
			DeviceID: req.DeviceID,
		})
		return nil
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
		UserAgent: req.UserAgent,
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
			UserAgent:     req.UserAgent,
			ErrorCode:     "VALIDATION_FAILED",
			ErrorMessage:  err.Error(),
			FailureReason: "admin_mpin_validation_failed",
		})
		return err
	}

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
			UserAgent:    req.UserAgent,
			ErrorCode:    "RATE_LIMIT_EXCEEDED",
			AttemptsLeft: retryAfter,
		})
		return appErrors.ErrAdminMPINRateLimitExceeded
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
			UserAgent:     req.UserAgent,
			ErrorCode:     "ADMIN_NOT_FOUND",
			FailureReason: "admin_not_found",
		})
		return fmt.Errorf("%w: admin not found", appErrors.ErrInvalidInput)
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
			UserAgent:     req.UserAgent,
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
			UserAgent:     req.UserAgent,
			ErrorCode:     "ADMIN_MPIN_ALREADY_EXISTS",
			FailureReason: "admin_mpin_already_exists",
		})
		return appErrors.ErrAdminMPINAlreadyExists
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
			UserAgent:     req.UserAgent,
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
			UserAgent:     req.UserAgent,
			ErrorCode:     "REPOSITORY_CREATE_FAILED",
			ErrorMessage:  err.Error(),
			FailureReason: "repository_create_failed",
		})
		return fmt.Errorf("failed to create admin MPIN: %w", err)
	}

	// Establish device trust on setup
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
		s.logAdminMPINEvent(ctx, &models.MPINLogEvent{
			LogEnvelope: models.LogEnvelope{
				EventID:     uuid.New().String(),
				EventType:   string(models.LogEventTypeMPIN),
				ServiceName: "auth-service",
				Timestamp:   time.Now(),
				Environment: s.config.Environment,
				Version:     AdminServiceVersion,
				Level:       string(models.LogLevelWarning),
				Message:     "Failed to set admin device trust level during setup",
			},
			UserID:       req.AdminID.String(),
			Status:       "trust_update_failed",
			DeviceID:     req.DeviceID,
			ErrorCode:    "TRUST_UPDATE_FAILED",
			ErrorMessage: err.Error(),
		})
	} else {
		s.logAdminMPINEvent(ctx, &models.MPINLogEvent{
			LogEnvelope: models.LogEnvelope{
				EventID:     uuid.New().String(),
				EventType:   string(models.LogEventTypeMPIN),
				ServiceName: "auth-service",
				Timestamp:   time.Now(),
				Environment: s.config.Environment,
				Version:     AdminServiceVersion,
				Level:       string(models.LogLevelInfo),
				Message:     "Device trust record created during setup",
			},
			UserID:   req.AdminID.String(),
			DeviceID: req.DeviceID,
			Status:   "trust_created",
		})
	}

	s.invalidateAdminMPINCache(ctx, req.AdminID)

	if err := s.idempotencyStore.Store(ctx, nil, idempKey, true); err != nil {
		s.logAdminMPINEvent(ctx, &models.MPINLogEvent{
			LogEnvelope: models.LogEnvelope{
				EventID:     uuid.New().String(),
				EventType:   string(models.LogEventTypeMPIN),
				ServiceName: "auth-service",
				Timestamp:   time.Now(),
				Environment: s.config.Environment,
				Version:     AdminServiceVersion,
				Level:       string(models.LogLevelWarning),
				Message:     "Failed to store idempotency record",
			},
			UserID:       req.AdminID.String(),
			Status:       "idempotency_store_failed",
			DeviceID:     req.DeviceID,
			ErrorCode:    "IDEMPOTENCY_STORE_FAILED",
			ErrorMessage: err.Error(),
		})
	}

	if s.auditService != nil {
		_ = s.auditService.LogAction(ctx, nil, nil, "admin_mpin", "setup", "admin",
			&req.AdminID, "admin", &req.AdminID, nil, nil, map[string]interface{}{
				"device_id": req.DeviceID,
				"ip":        req.IPAddress,
			})
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
			Message:     "Admin MPIN setup completed successfully",
		},
		UserID:    req.AdminID.String(),
		Status:    "admin_setup_completed",
		DeviceID:  req.DeviceID,
		UserAgent: req.UserAgent,
		Duration:  int64(time.Since(startTime).Milliseconds()),
	})
	return nil
}

// VerifyAdminMPIN – ENFORCES device trust at the beginning
func (s *AdminMPINService) VerifyAdminMPIN(ctx context.Context, req *AdminMPINVerifyRequest) (*AdminMPINVerifyResult, error) {
	startTime := time.Now()
	idempKey, _ := ctx.Value("idempotency_key").(string)
	if idempKey == "" {
		idempKey = fmt.Sprintf("admin_mpin_verify:%s:%s", req.AdminID.String(), req.DeviceID)
	}

	var cachedResult AdminMPINVerifyResult
	if err := s.idempotencyStore.Get(ctx, nil, idempKey, &cachedResult); err == nil {
		s.logAdminMPINEvent(ctx, &models.MPINLogEvent{
			LogEnvelope: models.LogEnvelope{
				EventID:     uuid.New().String(),
				EventType:   string(models.LogEventTypeMPIN),
				ServiceName: "auth-service",
				Timestamp:   time.Now(),
				Environment: s.config.Environment,
				Version:     AdminServiceVersion,
				Level:       string(models.LogLevelInfo),
				Message:     "Idempotent – returning cached admin MPIN verification result",
			},
			UserID:   req.AdminID.String(),
			Status:   "admin_verification_idempotent",
			DeviceID: req.DeviceID,
		})
		return &cachedResult, nil
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
			Message:     "Admin MPIN verification initiated",
		},
		UserID:    req.AdminID.String(),
		Status:    "admin_verification_initiated",
		DeviceID:  req.DeviceID,
		UserAgent: req.UserAgent,
	})

	// ---- ★ NEW: Enforce device trust ----
	trusted, trustLevel, err := s.isDeviceTrusted(ctx, req.AdminID, req.DeviceID, req.IPAddress, req.DeviceFingerprint)
	if err != nil {
		return nil, fmt.Errorf("device trust check failed: %w", err)
	}
	if !trusted {
		s.logAdminMPINEvent(ctx, &models.MPINLogEvent{
			LogEnvelope: models.LogEnvelope{
				EventID:     uuid.New().String(),
				EventType:   string(models.LogEventTypeMPIN),
				ServiceName: "auth-service",
				Timestamp:   time.Now(),
				Environment: s.config.Environment,
				Version:     AdminServiceVersion,
				Level:       string(models.LogLevelWarning),
				Message:     "MPIN verification blocked: device not trusted",
			},
			UserID:        req.AdminID.String(),
			DeviceID:      req.DeviceID,
			Status:        "admin_verification_blocked_untrusted",
			FailureReason: "device_not_trusted",
		})
		return nil, appErrors.ErrDeviceNotTrusted
	}
	// ---- End of trust enforcement ----

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
			UserAgent:    req.UserAgent,
			ErrorCode:    "RATE_LIMIT_EXCEEDED",
			AttemptsLeft: retryAfter,
		})
		return nil, appErrors.ErrAdminMPINRateLimitExceeded
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
			UserAgent:     req.UserAgent,
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
				UserAgent:     req.UserAgent,
				ErrorCode:     "ADMIN_MPIN_NOT_FOUND",
				FailureReason: "admin_mpin_not_found",
			})
			return nil, appErrors.ErrAdminMPINNotFound
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
				UserAgent:     req.UserAgent,
				Attempts:      AdminMPINMaxAttempts,
				AttemptsLeft:  0,
				IsLocked:      true,
				ErrorCode:     "ADMIN_MPIN_LOCKED",
				FailureReason: "admin_mpin_locked",
			})
			return result, appErrors.ErrAdminMPINLocked
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
			UserAgent:     req.UserAgent,
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
			UserAgent: req.UserAgent,
		})
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
			UserAgent:     req.UserAgent,
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
			s.logAdminMPINEvent(ctx, &models.MPINLogEvent{
				LogEnvelope: models.LogEnvelope{
					EventID:     uuid.New().String(),
					EventType:   string(models.LogEventTypeMPIN),
					ServiceName: "auth-service",
					Timestamp:   time.Now(),
					Environment: s.config.Environment,
					Version:     AdminServiceVersion,
					Level:       string(models.LogLevelError),
					Message:     "Failed to reset admin failed attempts",
				},
				UserID:       req.AdminID.String(),
				Status:       "failed_attempts_reset_failed",
				DeviceID:     req.DeviceID,
				ErrorCode:    "RESET_FAILED",
				ErrorMessage: err.Error(),
			})
		}
		result.Message = "Admin MPIN verified successfully"
		result.FailedAttempts = 0
		result.RemainingTries = AdminMPINMaxAttempts

		// Update trust record (IP, fingerprint, etc.) on successful login
		trustLevel = &models.DeviceTrustLevel{
			UserID:            req.AdminID,
			DeviceID:          req.DeviceID,
			TrustStatus:       models.TrustStatusTrusted,
			DeviceFingerprint: s.hashDeviceFingerprint(req.DeviceFingerprint),
			LastIPAddress:     req.IPAddress,
			UserAgent:         req.UserAgent,
			IsBlocked:         false,
			RiskScore:         0,
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
				Message:     "Updating device trust on successful MPIN verification",
			},
			UserID:   req.AdminID.String(),
			DeviceID: req.DeviceID,
			Status:   "trust_update_attempt",
		})
		if err := s.deviceTrustRepo.MarkAdminSuccessfulLogin(ctx, req.AdminID, req.DeviceID, trustLevel); err != nil {
			s.logAdminMPINEvent(ctx, &models.MPINLogEvent{
				LogEnvelope: models.LogEnvelope{
					EventID:     uuid.New().String(),
					EventType:   string(models.LogEventTypeMPIN),
					ServiceName: "auth-service",
					Timestamp:   time.Now(),
					Environment: s.config.Environment,
					Version:     AdminServiceVersion,
					Level:       string(models.LogLevelWarning),
					Message:     "Failed to update admin device trust on successful login",
				},
				UserID:       req.AdminID.String(),
				Status:       "trust_update_failed",
				DeviceID:     req.DeviceID,
				ErrorCode:    "TRUST_UPDATE_FAILED",
				ErrorMessage: err.Error(),
			})
		} else {
			s.logAdminMPINEvent(ctx, &models.MPINLogEvent{
				LogEnvelope: models.LogEnvelope{
					EventID:     uuid.New().String(),
					EventType:   string(models.LogEventTypeMPIN),
					ServiceName: "auth-service",
					Timestamp:   time.Now(),
					Environment: s.config.Environment,
					Version:     AdminServiceVersion,
					Level:       string(models.LogLevelInfo),
					Message:     "Device trust updated successfully on MPIN login",
				},
				UserID:   req.AdminID.String(),
				DeviceID: req.DeviceID,
				Status:   "trust_update_success",
			})
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
			UserAgent:    req.UserAgent,
			Attempts:     0,
			AttemptsLeft: AdminMPINMaxAttempts,
			IsLocked:     false,
			Duration:     int64(time.Since(startTime).Milliseconds()),
		})
	} else {
		newFailedAttempts, err := s.mpinRepo.IncrementAdminFailedAttempts(ctx, req.AdminID)
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
					Message:     "Failed to increment admin failed attempts",
				},
				UserID:       req.AdminID.String(),
				Status:       "failed_attempts_increment_failed",
				DeviceID:     req.DeviceID,
				ErrorCode:    "INCREMENT_FAILED",
				ErrorMessage: err.Error(),
			})
		} else {
			result.FailedAttempts = newFailedAttempts
			result.RemainingTries = max(0, AdminMPINMaxAttempts-newFailedAttempts)
		}
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
				UserAgent:    req.UserAgent,
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
				UserAgent:    req.UserAgent,
				Attempts:     newFailedAttempts,
				AttemptsLeft: result.RemainingTries,
				IsLocked:     false,
				Duration:     int64(time.Since(startTime).Milliseconds()),
			})
		}
	}

	if err := s.idempotencyStore.Store(ctx, nil, idempKey, result); err != nil {
		s.logAdminMPINEvent(ctx, &models.MPINLogEvent{
			LogEnvelope: models.LogEnvelope{
				EventID:     uuid.New().String(),
				EventType:   string(models.LogEventTypeMPIN),
				ServiceName: "auth-service",
				Timestamp:   time.Now(),
				Environment: s.config.Environment,
				Version:     AdminServiceVersion,
				Level:       string(models.LogLevelWarning),
				Message:     "Failed to store idempotency record for verification",
			},
			UserID:       req.AdminID.String(),
			Status:       "idempotency_store_failed",
			DeviceID:     req.DeviceID,
			ErrorCode:    "IDEMPOTENCY_STORE_FAILED",
			ErrorMessage: err.Error(),
		})
	}

	if s.auditService != nil {
		metadata := map[string]interface{}{
			"device_id":    req.DeviceID,
			"ip":           req.IPAddress,
			"verified":     verified,
			"attempts":     result.FailedAttempts,
			"remaining":    result.RemainingTries,
			"locked_until": result.LockedUntil,
		}
		if !verified && result.RemainingTries == 0 {
			metadata["locked"] = true
		}
		_ = s.auditService.LogAction(ctx, nil, nil, "admin_mpin", "verify", "admin",
			&req.AdminID, "admin", &req.AdminID, nil, nil, metadata)
	}

	return result, nil
}

// ChangeAdminMPIN – unchanged (already uses VerifyAdminMPIN which enforces trust)
func (s *AdminMPINService) ChangeAdminMPIN(ctx context.Context, req *AdminMPINChangeRequest) error {
	startTime := time.Now()
	idempKey, _ := ctx.Value("idempotency_key").(string)
	if idempKey == "" {
		idempKey = fmt.Sprintf("admin_mpin_change:%s:%s", req.AdminID.String(), req.DeviceID)
	}
	var done bool
	if err := s.idempotencyStore.Get(ctx, nil, idempKey, &done); err == nil && done {
		s.logAdminMPINEvent(ctx, &models.MPINLogEvent{
			LogEnvelope: models.LogEnvelope{
				EventID:     uuid.New().String(),
				EventType:   string(models.LogEventTypeMPIN),
				ServiceName: "auth-service",
				Timestamp:   time.Now(),
				Environment: s.config.Environment,
				Version:     AdminServiceVersion,
				Level:       string(models.LogLevelInfo),
				Message:     "Idempotent – admin MPIN change already done",
			},
			UserID:   req.AdminID.String(),
			Status:   "admin_change_idempotent",
			DeviceID: req.DeviceID,
		})
		return nil
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
			Message:     "Admin MPIN change initiated",
		},
		UserID:    req.AdminID.String(),
		Status:    "admin_change_initiated",
		DeviceID:  req.DeviceID,
		UserAgent: req.UserAgent,
	})

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
			UserAgent:    req.UserAgent,
			ErrorCode:    "RATE_LIMIT_EXCEEDED",
			AttemptsLeft: retryAfter,
		})
		return appErrors.ErrAdminMPINRateLimitExceeded
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
			UserAgent:     req.UserAgent,
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
		UserAgent:         req.UserAgent,
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
			UserAgent:     req.UserAgent,
			ErrorCode:     "CURRENT_ADMIN_MPIN_INVALID",
			FailureReason: "current_admin_mpin_invalid",
		})
		return appErrors.ErrAdminMPINInvalid
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
			UserAgent:     req.UserAgent,
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
			UserAgent:     req.UserAgent,
			ErrorCode:     "REPOSITORY_UPDATE_FAILED",
			ErrorMessage:  err.Error(),
			FailureReason: "repository_update_failed",
		})
		return fmt.Errorf("failed to update admin MPIN: %w", err)
	}

	if err := s.mpinRepo.UpdateAdminMPINDeviceBinding(ctx, req.AdminID, req.DeviceID); err != nil {
		s.logAdminMPINEvent(ctx, &models.MPINLogEvent{
			LogEnvelope: models.LogEnvelope{
				EventID:     uuid.New().String(),
				EventType:   string(models.LogEventTypeMPIN),
				ServiceName: "auth-service",
				Timestamp:   time.Now(),
				Environment: s.config.Environment,
				Version:     AdminServiceVersion,
				Level:       string(models.LogLevelWarning),
				Message:     "Failed to update admin MPIN device binding",
			},
			UserID:       req.AdminID.String(),
			Status:       "device_binding_update_failed",
			DeviceID:     req.DeviceID,
			ErrorCode:    "BINDING_UPDATE_FAILED",
			ErrorMessage: err.Error(),
		})
	}

	s.invalidateAdminMPINCache(ctx, req.AdminID)

	if err := s.idempotencyStore.Store(ctx, nil, idempKey, true); err != nil {
		s.logAdminMPINEvent(ctx, &models.MPINLogEvent{
			LogEnvelope: models.LogEnvelope{
				EventID:     uuid.New().String(),
				EventType:   string(models.LogEventTypeMPIN),
				ServiceName: "auth-service",
				Timestamp:   time.Now(),
				Environment: s.config.Environment,
				Version:     AdminServiceVersion,
				Level:       string(models.LogLevelWarning),
				Message:     "Failed to store idempotency record for change",
			},
			UserID:       req.AdminID.String(),
			Status:       "idempotency_store_failed",
			DeviceID:     req.DeviceID,
			ErrorCode:    "IDEMPOTENCY_STORE_FAILED",
			ErrorMessage: err.Error(),
		})
	}

	if s.auditService != nil {
		_ = s.auditService.LogAction(ctx, nil, nil, "admin_mpin", "change", "admin",
			&req.AdminID, "admin", &req.AdminID, nil, nil, map[string]interface{}{
				"device_id": req.DeviceID,
				"ip":        req.IPAddress,
			})
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
			Message:     "Admin MPIN changed successfully",
		},
		UserID:    req.AdminID.String(),
		Status:    "admin_change_completed",
		DeviceID:  req.DeviceID,
		UserAgent: req.UserAgent,
		Duration:  int64(time.Since(startTime).Milliseconds()),
	})
	return nil
}

// ForgotAdminMPIN – device trust check REMOVED (recovery relies on OTP)
func (s *AdminMPINService) ForgotAdminMPIN(ctx context.Context, req *AdminMPINForgotRequest) error {
	startTime := time.Now()
	idempKey, _ := ctx.Value("idempotency_key").(string)
	if idempKey == "" {
		idempKey = fmt.Sprintf("admin_mpin_forgot:%s:%s", req.AdminID.String(), req.DeviceID)
	}
	var done bool
	if err := s.idempotencyStore.Get(ctx, nil, idempKey, &done); err == nil && done {
		s.logAdminMPINEvent(ctx, &models.MPINLogEvent{
			LogEnvelope: models.LogEnvelope{
				EventID:     uuid.New().String(),
				EventType:   string(models.LogEventTypeMPIN),
				ServiceName: "auth-service",
				Timestamp:   time.Now(),
				Environment: s.config.Environment,
				Version:     AdminServiceVersion,
				Level:       string(models.LogLevelInfo),
				Message:     "Idempotent – forgot MPIN OTP already sent",
			},
			UserID:   req.AdminID.String(),
			Status:   "admin_forgot_idempotent",
			DeviceID: req.DeviceID,
		})
		return nil
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
			Message:     "Forgot admin MPIN flow initiated (device trust check SKIPPED)",
		},
		UserID:    req.AdminID.String(),
		Status:    "admin_forgot_initiated",
		DeviceID:  req.DeviceID,
		UserAgent: req.UserAgent,
	})

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
			UserAgent:    req.UserAgent,
			ErrorCode:    "RATE_LIMIT_EXCEEDED",
			AttemptsLeft: retryAfter,
		})
		return appErrors.ErrAdminMPINRateLimitExceeded
	}

	// ❌ Device trust check removed – recovery relies solely on OTP

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
			UserAgent:     req.UserAgent,
			ErrorCode:     "ADMIN_NOT_FOUND",
			FailureReason: "admin_not_found",
		})
		return fmt.Errorf("admin not found: %w", err)
	}

	encryptedData := &encryption.EncryptedData{
		EncryptedValue: string(admin.PhoneEncrypted),
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
			UserAgent:     req.UserAgent,
			ErrorCode:     "PHONE_DECRYPTION_FAILED",
			ErrorMessage:  err.Error(),
			FailureReason: "phone_decryption_failed",
		})
		return fmt.Errorf("failed to decrypt admin phone number: %w", err)
	}

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
			UserAgent:     req.UserAgent,
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
			UserAgent:     req.UserAgent,
			ErrorCode:     "OTP_SEND_FAILED",
			ErrorMessage:  otpResp.Message,
			FailureReason: "otp_send_failed",
		})
		return fmt.Errorf("OTP send failed: %s", otpResp.Message)
	}

	if err := s.idempotencyStore.Store(ctx, nil, idempKey, true); err != nil {
		s.logAdminMPINEvent(ctx, &models.MPINLogEvent{
			LogEnvelope: models.LogEnvelope{
				EventID:     uuid.New().String(),
				EventType:   string(models.LogEventTypeMPIN),
				ServiceName: "auth-service",
				Timestamp:   time.Now(),
				Environment: s.config.Environment,
				Version:     AdminServiceVersion,
				Level:       string(models.LogLevelWarning),
				Message:     "Failed to store idempotency record for forgot",
			},
			UserID:       req.AdminID.String(),
			Status:       "idempotency_store_failed",
			DeviceID:     req.DeviceID,
			ErrorCode:    "IDEMPOTENCY_STORE_FAILED",
			ErrorMessage: err.Error(),
		})
	}

	if s.auditService != nil {
		_ = s.auditService.LogAction(ctx, nil, nil, "admin_mpin", "forgot_otp_sent", "admin",
			&req.AdminID, "admin", &req.AdminID, nil, nil, map[string]interface{}{
				"device_id": req.DeviceID,
				"ip":        req.IPAddress,
			})
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
			Message:     "OTP sent for forgot MPIN (device trust check bypassed)",
		},
		UserID:    req.AdminID.String(),
		Status:    "admin_forgot_otp_sent",
		DeviceID:  req.DeviceID,
		UserAgent: req.UserAgent,
		Duration:  int64(time.Since(startTime).Milliseconds()),
	})
	return nil
}

// VerifyForgotAdminMPINOTP – device trust check REMOVED, but trust is SET after OTP success
func (s *AdminMPINService) VerifyForgotAdminMPINOTP(ctx context.Context, req *AdminMPINForgotWithOTPRequest) error {
	startTime := time.Now()
	idempKey, _ := ctx.Value("idempotency_key").(string)
	if idempKey == "" {
		idempKey = fmt.Sprintf("admin_mpin_forgot_otp:%s:%s", req.AdminID.String(), req.DeviceID)
	}
	var done bool
	if err := s.idempotencyStore.Get(ctx, nil, idempKey, &done); err == nil && done {
		s.logAdminMPINEvent(ctx, &models.MPINLogEvent{
			LogEnvelope: models.LogEnvelope{
				EventID:     uuid.New().String(),
				EventType:   string(models.LogEventTypeMPIN),
				ServiceName: "auth-service",
				Timestamp:   time.Now(),
				Environment: s.config.Environment,
				Version:     AdminServiceVersion,
				Level:       string(models.LogLevelInfo),
				Message:     "Idempotent – forgot MPIN OTP verification already done",
			},
			UserID:   req.AdminID.String(),
			Status:   "admin_forgot_otp_idempotent",
			DeviceID: req.DeviceID,
		})
		return nil
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
			Message:     "Forgot admin MPIN OTP verification initiated (device trust check SKIPPED)",
		},
		UserID:    req.AdminID.String(),
		Status:    "admin_forgot_otp_verification_initiated",
		DeviceID:  req.DeviceID,
		UserAgent: req.UserAgent,
	})

	// ❌ Device trust check removed – OTP verification is the sole proof

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
		EncryptedValue: string(admin.PhoneEncrypted),
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

	// ✅ Trust is established here – the device becomes Trusted after successful OTP reset
	updatedTrustLevel := &models.DeviceTrustLevel{
		UserID:            req.AdminID,
		DeviceID:          req.DeviceID,
		TrustStatus:       models.TrustStatusTrusted,
		DeviceFingerprint: s.hashDeviceFingerprint(req.DeviceFingerprint),
		LastIPAddress:     req.IPAddress,
		UserAgent:         req.UserAgent,
		IsBlocked:         false,
		RiskScore:         0,
	}
	if err := s.deviceTrustRepo.SetAdminDeviceTrustLevel(ctx, req.AdminID, req.DeviceID, updatedTrustLevel); err != nil {
		s.logAdminMPINEvent(ctx, &models.MPINLogEvent{
			LogEnvelope: models.LogEnvelope{
				EventID:     uuid.New().String(),
				EventType:   string(models.LogEventTypeMPIN),
				ServiceName: "auth-service",
				Timestamp:   time.Now(),
				Environment: s.config.Environment,
				Version:     AdminServiceVersion,
				Level:       string(models.LogLevelWarning),
				Message:     "Failed to update admin device trust level after OTP reset",
			},
			UserID:       req.AdminID.String(),
			Status:       "trust_update_failed",
			DeviceID:     req.DeviceID,
			ErrorCode:    "TRUST_UPDATE_FAILED",
			ErrorMessage: err.Error(),
		})
	} else {
		s.logAdminMPINEvent(ctx, &models.MPINLogEvent{
			LogEnvelope: models.LogEnvelope{
				EventID:     uuid.New().String(),
				EventType:   string(models.LogEventTypeMPIN),
				ServiceName: "auth-service",
				Timestamp:   time.Now(),
				Environment: s.config.Environment,
				Version:     AdminServiceVersion,
				Level:       string(models.LogLevelInfo),
				Message:     "Device trust set to Trusted after successful OTP reset",
			},
			UserID:   req.AdminID.String(),
			DeviceID: req.DeviceID,
			Status:   "trust_established_after_otp",
		})
	}

	s.invalidateAdminMPINCache(ctx, req.AdminID)

	if err := s.idempotencyStore.Store(ctx, nil, idempKey, true); err != nil {
		s.logAdminMPINEvent(ctx, &models.MPINLogEvent{
			LogEnvelope: models.LogEnvelope{
				EventID:     uuid.New().String(),
				EventType:   string(models.LogEventTypeMPIN),
				ServiceName: "auth-service",
				Timestamp:   time.Now(),
				Environment: s.config.Environment,
				Version:     AdminServiceVersion,
				Level:       string(models.LogLevelWarning),
				Message:     "Failed to store idempotency record for forgot OTP verification",
			},
			UserID:       req.AdminID.String(),
			Status:       "idempotency_store_failed",
			DeviceID:     req.DeviceID,
			ErrorCode:    "IDEMPOTENCY_STORE_FAILED",
			ErrorMessage: err.Error(),
		})
	}

	if s.auditService != nil {
		_ = s.auditService.LogAction(ctx, nil, nil, "admin_mpin", "forgot_otp_verified", "admin",
			&req.AdminID, "admin", &req.AdminID, nil, nil, map[string]interface{}{
				"device_id": req.DeviceID,
				"ip":        req.IPAddress,
			})
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
			Message:     "Admin MPIN reset via forgot with OTP verification completed",
		},
		UserID:    req.AdminID.String(),
		Status:    "admin_forgot_otp_verification_completed",
		DeviceID:  req.DeviceID,
		UserAgent: req.UserAgent,
		Duration:  int64(time.Since(startTime).Milliseconds()),
	})
	return nil
}

// ---- Admin‑initiated changes ----

func (s *AdminMPINService) ChangeAdminMPINByAdmin(ctx context.Context, req *AdminMPINAdminChangeRequest) error {
	startTime := time.Now()
	idempKey, _ := ctx.Value("idempotency_key").(string)
	if idempKey == "" {
		idempKey = fmt.Sprintf("admin_mpin_admin_change:%s", req.AdminID.String())
	}
	var done bool
	if err := s.idempotencyStore.Get(ctx, nil, idempKey, &done); err == nil && done {
		s.logAdminMPINEvent(ctx, &models.MPINLogEvent{
			LogEnvelope: models.LogEnvelope{
				EventID:     uuid.New().String(),
				EventType:   string(models.LogEventTypeMPIN),
				ServiceName: "auth-service",
				Timestamp:   time.Now(),
				Environment: s.config.Environment,
				Version:     AdminServiceVersion,
				Level:       string(models.LogLevelInfo),
				Message:     "Idempotent – admin MPIN change by admin already done",
			},
			UserID: req.AdminID.String(),
			Status: "admin_change_by_admin_idempotent",
		})
		return nil
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
			Message:     "Admin MPIN change by admin initiated",
		},
		UserID:    req.AdminID.String(),
		Status:    "admin_change_by_admin_initiated",
		UserAgent: req.UserAgent,
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
			UserAgent:     req.UserAgent,
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
			UserAgent:     req.UserAgent,
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
			UserAgent:     req.UserAgent,
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
				Message:     "Failed to update admin MPIN in repository for admin change",
			},
			UserID:        req.AdminID.String(),
			Status:        "admin_change_by_admin_failed",
			UserAgent:     req.UserAgent,
			ErrorCode:     "REPOSITORY_UPDATE_FAILED",
			ErrorMessage:  err.Error(),
			FailureReason: "repository_update_failed",
		})
		return fmt.Errorf("failed to update admin MPIN: %w", err)
	}
	_ = s.mpinRepo.UnlockAdminMPIN(ctx, req.AdminID)
	s.invalidateAdminMPINCache(ctx, req.AdminID)

	if err := s.idempotencyStore.Store(ctx, nil, idempKey, true); err != nil {
		s.logAdminMPINEvent(ctx, &models.MPINLogEvent{
			LogEnvelope: models.LogEnvelope{
				EventID:     uuid.New().String(),
				EventType:   string(models.LogEventTypeMPIN),
				ServiceName: "auth-service",
				Timestamp:   time.Now(),
				Environment: s.config.Environment,
				Version:     AdminServiceVersion,
				Level:       string(models.LogLevelWarning),
				Message:     "Failed to store idempotency record for admin change",
			},
			UserID:       req.AdminID.String(),
			Status:       "idempotency_store_failed",
			ErrorCode:    "IDEMPOTENCY_STORE_FAILED",
			ErrorMessage: err.Error(),
		})
	}

	if s.auditService != nil {
		_ = s.auditService.LogAction(ctx, nil, nil, "admin_mpin", "change_by_admin", "admin",
			&req.AdminID, "admin", &req.ChangedBy, nil, nil, map[string]interface{}{
				"reason": req.Reason,
				"ip":     req.IPAddress,
			})
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
			Message:     "Admin MPIN changed by admin successfully",
		},
		UserID:    req.AdminID.String(),
		Status:    "admin_change_by_admin_completed",
		UserAgent: req.UserAgent,
		Duration:  int64(time.Since(startTime).Milliseconds()),
	})
	return nil
}

func (s *AdminMPINService) ResetAdminMPIN(ctx context.Context, req *AdminMPINResetRequest) error {
	startTime := time.Now()
	idempKey, _ := ctx.Value("idempotency_key").(string)
	if idempKey == "" {
		idempKey = fmt.Sprintf("admin_mpin_reset:%s", req.AdminID.String())
	}
	var done bool
	if err := s.idempotencyStore.Get(ctx, nil, idempKey, &done); err == nil && done {
		s.logAdminMPINEvent(ctx, &models.MPINLogEvent{
			LogEnvelope: models.LogEnvelope{
				EventID:     uuid.New().String(),
				EventType:   string(models.LogEventTypeMPIN),
				ServiceName: "auth-service",
				Timestamp:   time.Now(),
				Environment: s.config.Environment,
				Version:     AdminServiceVersion,
				Level:       string(models.LogLevelInfo),
				Message:     "Idempotent – admin MPIN reset already done",
			},
			UserID: req.AdminID.String(),
			Status: "admin_reset_idempotent",
		})
		return nil
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
			Message:     "Admin MPIN reset initiated",
		},
		UserID:    req.AdminID.String(),
		Status:    "admin_reset_initiated",
		UserAgent: req.UserAgent,
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
			UserAgent:     req.UserAgent,
			ErrorCode:     "ADMIN_MPIN_NOT_FOUND",
			FailureReason: "admin_mpin_not_found",
		})
		return appErrors.ErrAdminMPINNotFound
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
			UserAgent:     req.UserAgent,
			ErrorCode:     "UNLOCK_FAILED",
			ErrorMessage:  err.Error(),
			FailureReason: "unlock_failed",
		})
		return fmt.Errorf("failed to unlock admin MPIN: %w", err)
	}

	s.invalidateAdminMPINCache(ctx, req.AdminID)

	if err := s.idempotencyStore.Store(ctx, nil, idempKey, true); err != nil {
		s.logAdminMPINEvent(ctx, &models.MPINLogEvent{
			LogEnvelope: models.LogEnvelope{
				EventID:     uuid.New().String(),
				EventType:   string(models.LogEventTypeMPIN),
				ServiceName: "auth-service",
				Timestamp:   time.Now(),
				Environment: s.config.Environment,
				Version:     AdminServiceVersion,
				Level:       string(models.LogLevelWarning),
				Message:     "Failed to store idempotency record for reset",
			},
			UserID:       req.AdminID.String(),
			Status:       "idempotency_store_failed",
			ErrorCode:    "IDEMPOTENCY_STORE_FAILED",
			ErrorMessage: err.Error(),
		})
	}

	if s.auditService != nil {
		_ = s.auditService.LogAction(ctx, nil, nil, "admin_mpin", "reset", "admin",
			&req.AdminID, "admin", &req.ResetBy, nil, nil, map[string]interface{}{
				"reason": req.Reason,
				"ip":     req.IPAddress,
			})
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
			Message:     "Admin MPIN reset by admin completed",
		},
		UserID:    req.AdminID.String(),
		Status:    "admin_reset_completed",
		UserAgent: req.UserAgent,
		Duration:  int64(time.Since(startTime).Milliseconds()),
	})
	return nil
}

func (s *AdminMPINService) UnlockAdminMPIN(ctx context.Context, adminID uuid.UUID) error {
	idempKey, _ := ctx.Value("idempotency_key").(string)
	if idempKey == "" {
		idempKey = fmt.Sprintf("admin_mpin_unlock:%s", adminID.String())
	}
	var done bool
	if err := s.idempotencyStore.Get(ctx, nil, idempKey, &done); err == nil && done {
		s.logAdminMPINEvent(ctx, &models.MPINLogEvent{
			LogEnvelope: models.LogEnvelope{
				EventID:     uuid.New().String(),
				EventType:   string(models.LogEventTypeMPIN),
				ServiceName: "auth-service",
				Timestamp:   time.Now(),
				Environment: s.config.Environment,
				Version:     AdminServiceVersion,
				Level:       string(models.LogLevelInfo),
				Message:     "Idempotent – admin MPIN unlock already done",
			},
			UserID: adminID.String(),
			Status: "admin_unlock_idempotent",
		})
		return nil
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

	if err := s.idempotencyStore.Store(ctx, nil, idempKey, true); err != nil {
		s.logAdminMPINEvent(ctx, &models.MPINLogEvent{
			LogEnvelope: models.LogEnvelope{
				EventID:     uuid.New().String(),
				EventType:   string(models.LogEventTypeMPIN),
				ServiceName: "auth-service",
				Timestamp:   time.Now(),
				Environment: s.config.Environment,
				Version:     AdminServiceVersion,
				Level:       string(models.LogLevelWarning),
				Message:     "Failed to store idempotency record for unlock",
			},
			UserID:       adminID.String(),
			Status:       "idempotency_store_failed",
			ErrorCode:    "IDEMPOTENCY_STORE_FAILED",
			ErrorMessage: err.Error(),
		})
	}

	if s.auditService != nil {
		_ = s.auditService.LogAction(ctx, nil, nil, "admin_mpin", "unlock", "admin",
			&adminID, "system", nil, nil, nil, nil)
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
			Message:     "Admin MPIN unlocked successfully",
		},
		UserID: adminID.String(),
		Status: "admin_unlock_completed",
	})
	return nil
}

// ---- Read‑only methods ----

func (s *AdminMPINService) GetAdminMPINStatus(ctx context.Context, adminID uuid.UUID) (*AdminMPINStatus, error) {
	mpinCred, err := s.mpinRepo.GetAdminMPINByAdminID(ctx, adminID)
	if err != nil {
		return nil, err
	}
	if mpinCred == nil {
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

func (s *AdminMPINService) UpdateAdminMPINDeviceBinding(ctx context.Context, adminID uuid.UUID, deviceID string) error {
	if err := s.mpinRepo.UpdateAdminMPINDeviceBinding(ctx, adminID, deviceID); err != nil {
		return fmt.Errorf("failed to update admin device binding: %w", err)
	}
	s.invalidateAdminMPINCache(ctx, adminID)
	return nil
}

func (s *AdminMPINService) GetAdminMPINsByDevice(ctx context.Context, deviceID string) ([]*models.MPINCredential, error) {
	return s.mpinRepo.GetAdminMPINsByDevice(ctx, deviceID)
}

func (s *AdminMPINService) GetAdminLockedMPINs(ctx context.Context, limit int) ([]*models.MPINCredential, error) {
	return s.mpinRepo.GetAdminLockedMPINs(ctx, limit)
}

func (s *AdminMPINService) CleanupAdminExpiredLocks(ctx context.Context) (int, error) {
	return s.mpinRepo.CleanupAdminUnlockedMPINs(ctx)
}

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

func (s *AdminMPINService) HealthCheck(ctx context.Context) error {
	return s.mpinRepo.HealthCheck(ctx)
}

func (s *AdminMPINService) invalidateAdminMPINCache(ctx context.Context, adminID uuid.UUID) {
	if s.distCache != nil {
		cacheKey := fmt.Sprintf("admin_mpin:%s", adminID.String())
		_ = s.distCache.Delete(ctx, cacheKey)
	}
}

func (s *AdminMPINService) SetLogProducerService(logProducer *LogProducerService) {
	s.logProducer = logProducer
}

func (s *AdminMPINService) DebugHasherStatus(ctx context.Context) map[string]interface{} {
	status := s.hasher.GetStatus()
	return status
}

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

func (s *AdminMPINService) validateIPAddress(ip string) bool {
	if ip == "" {
		return false
	}
	return net.ParseIP(ip) != nil
}

// AdminMPINService.go

// CheckAdminDeviceTrust checks if a device is trusted for an admin.
// Returns (trusted, trustLevel, error).
func (s *AdminMPINService) CheckAdminDeviceTrust(
	ctx context.Context,
	adminID uuid.UUID,
	deviceID string,
	ipAddress string,
	deviceFingerprint string,
) (bool, *models.DeviceTrustLevel, error) {
	return s.isDeviceTrusted(ctx, adminID, deviceID, ipAddress, deviceFingerprint)
}

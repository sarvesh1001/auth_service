// internal/service/mpin_service.go - UPDATED WITH KAFKA LOGGING

package service

import (
	"auth-service/internal/config"
	"auth-service/internal/encryption"
	"auth-service/internal/hashing"
	"auth-service/internal/models"
	"auth-service/internal/repository/scylla"
	"auth-service/internal/util"
	"context"
	"errors"
	"fmt"
	"regexp"
	"time"

	"github.com/google/uuid"
	"go.uber.org/zap"
)

var (
	ErrMPINNotFound      = errors.New("MPIN not found")
	ErrMPINInvalid       = errors.New("invalid MPIN")
	ErrMPINLocked        = errors.New("MPIN is locked")
	ErrMPINAlreadyExists = errors.New("MPIN already exists")
	ErrMPINTooWeak       = errors.New("MPIN is too weak")
	ErrDeviceNotBound    = errors.New("device not bound to MPIN")
)

const (
	MPINMinLength    = 4
	MPINMaxLength    = 8
	MPINLockDuration = 30 * time.Second
	MPINMaxAttempts  = 5
	ServiceVersion   = "v1.0.0" // ✅ FIXED: Use constant version

)

// MPINService handles all MPIN-related business logic
type MPINService struct {
	mpinRepo        scylla.MPINRepository
	userRepo        scylla.UserRepository
	deviceTrustRepo scylla.DeviceTrustRepository
	otpService      *OTPService
	encryptionMgr   *encryption.EncryptionManager
	hasher          *hashing.Hasher
	config          *config.Config
	logger          *zap.Logger
	distCache       *DistributedCache
	logProducer     *LogProducerService // ✅ NEW: Kafka log producer
}

// MPIN request/response structures
type MPINSetupRequest struct {
	UserID   uuid.UUID `json:"user_id" validate:"required"`
	MPIN     string    `json:"mpin" validate:"required,min=4,max=8"`
	DeviceID string    `json:"device_id" validate:"required"`
}

type MPINVerifyRequest struct {
	UserID   uuid.UUID `json:"user_id" validate:"required"`
	MPIN     string    `json:"mpin" validate:"required"`
	DeviceID string    `json:"device_id" validate:"required"`
}

type MPINVerifyResult struct {
	Verified       bool       `json:"verified"`
	FailedAttempts int        `json:"failed_attempts"`
	RemainingTries int        `json:"remaining_tries"`
	LockedUntil    *time.Time `json:"locked_until,omitempty"`
	Message        string     `json:"message"`
}

type MPINChangeRequest struct {
	UserID      uuid.UUID `json:"user_id" validate:"required"`
	CurrentMPIN string    `json:"current_mpin" validate:"required"`
	NewMPIN     string    `json:"new_mpin" validate:"required,min=4,max=8"`
	DeviceID    string    `json:"device_id" validate:"required"`
}

type MPINResetRequest struct {
	UserID  uuid.UUID `json:"user_id" validate:"required"`
	ResetBy uuid.UUID `json:"reset_by" validate:"required"`
	Reason  string    `json:"reason" validate:"required"`
}

// Request for Forgot MPIN with OTP
type MPINForgotWithOTPRequest struct {
	UserID   uuid.UUID `json:"user_id" validate:"required"`
	DeviceID string    `json:"device_id" validate:"required"`
	NewMPIN  string    `json:"new_mpin" validate:"required,min=4,max=8"`
	OTPCode  string    `json:"otp_code" validate:"required,len=6"`
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

// ✅ NEW: Admin MPIN change request
type MPINAdminChangeRequest struct {
	UserID  uuid.UUID `json:"user_id" validate:"required"`
	NewMPIN string    `json:"new_mpin" validate:"required,min=4,max=8"`
	AdminID uuid.UUID `json:"admin_id" validate:"required"`
	Reason  string    `json:"reason,omitempty"`
}

// ✅ NEW: Forgot MPIN Request (NO current MPIN needed)
type MPINForgotRequest struct {
	UserID   uuid.UUID `json:"user_id" validate:"required"`
	DeviceID string    `json:"device_id" validate:"required"`
	NewMPIN  string    `json:"new_mpin" validate:"required,min=4,max=8"`
}

func NewMPINService(
	mpinRepo scylla.MPINRepository,
	userRepo scylla.UserRepository,
	deviceTrustRepo scylla.DeviceTrustRepository,
	otpService *OTPService,
	encryptionMgr *encryption.EncryptionManager,
	hasher *hashing.Hasher,
	cfg *config.Config,
	logger *zap.Logger,
	logProducer *LogProducerService, // ✅ NEW: Accept log producer
) *MPINService {
	return &MPINService{
		mpinRepo:        mpinRepo,
		userRepo:        userRepo,
		deviceTrustRepo: deviceTrustRepo,
		hasher:          hasher,
		otpService:      otpService,
		config:          cfg,
		logger:          logger,
		encryptionMgr:   encryptionMgr,
		distCache:       nil,
		logProducer:     logProducer, // ✅ NEW: Store log producer
	}
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

func (s *MPINService) SetupMPIN(ctx context.Context, req *MPINSetupRequest) error {
	startTime := time.Now()

	if s.hasher == nil {
		return fmt.Errorf("hasher service not available")
	}

	// ✅ ADD: More specific check
	if !s.hasher.IsInitialized() {
		return fmt.Errorf("hasher not properly initialized - no pepper available")
	}

	// ✅ NEW: Log MPIN setup attempt
	s.logMPINEvent(ctx, &models.MPINLogEvent{
		LogEnvelope: models.LogEnvelope{
			EventID:     uuid.New().String(),
			EventType:   string(models.LogEventTypeMPIN),
			ServiceName: "auth-service",
			Timestamp:   time.Now(),
			Environment: s.config.Environment,
			Version:     ServiceVersion, // ✅ FIXED: Use constant

			Level:   string(models.LogLevelInfo),
			Message: "MPIN setup initiated",
		},
		UserID:   req.UserID.String(),
		Status:   "setup_initiated",
		DeviceID: req.DeviceID,
	})

	if err := s.validateMPIN(req.MPIN); err != nil {
		// ✅ NEW: Log validation failure
		s.logMPINEvent(ctx, &models.MPINLogEvent{
			LogEnvelope: models.LogEnvelope{
				EventID:     uuid.New().String(),
				EventType:   string(models.LogEventTypeMPIN),
				ServiceName: "auth-service",
				Timestamp:   time.Now(),
				Environment: s.config.Environment,
				Version:     ServiceVersion, // ✅ FIXED: Use constant

				Level:   string(models.LogLevelError),
				Message: "MPIN validation failed",
			},
			UserID:        req.UserID.String(),
			Status:        "setup_failed",
			DeviceID:      req.DeviceID,
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
				Version:     ServiceVersion, // ✅ FIXED: Use constant

				Level:   string(models.LogLevelError),
				Message: "User not found for MPIN setup",
			},
			UserID:        req.UserID.String(),
			Status:        "setup_failed",
			DeviceID:      req.DeviceID,
			ErrorCode:     "USER_NOT_FOUND",
			FailureReason: "user_not_found",
		})
		return fmt.Errorf("%w: user not found", ErrInvalidInput)
	}

	if user.IsBanned {
		s.logMPINEvent(ctx, &models.MPINLogEvent{
			LogEnvelope: models.LogEnvelope{
				EventID:     uuid.New().String(),
				EventType:   string(models.LogEventTypeMPIN),
				ServiceName: "auth-service",
				Timestamp:   time.Now(),
				Environment: s.config.Environment,
				Version:     ServiceVersion, // ✅ FIXED: Use constant

				Level:   string(models.LogLevelWarning),
				Message: "Banned user attempted MPIN setup",
			},
			UserID:        req.UserID.String(),
			Status:        "setup_failed",
			DeviceID:      req.DeviceID,
			ErrorCode:     "USER_BANNED",
			FailureReason: "user_banned",
		})
		return ErrUserBanned
	}

	if user.IsBlocked {
		s.logMPINEvent(ctx, &models.MPINLogEvent{
			LogEnvelope: models.LogEnvelope{
				EventID:     uuid.New().String(),
				EventType:   string(models.LogEventTypeMPIN),
				ServiceName: "auth-service",
				Timestamp:   time.Now(),
				Environment: s.config.Environment,
				Version:     ServiceVersion, // ✅ FIXED: Use constant

				Level:   string(models.LogLevelWarning),
				Message: "Blocked user attempted MPIN setup",
			},
			UserID:        req.UserID.String(),
			Status:        "setup_failed",
			DeviceID:      req.DeviceID,
			ErrorCode:     "USER_BLOCKED",
			FailureReason: "user_blocked",
		})
		return ErrUserBlocked
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
				Version:     ServiceVersion, // ✅ FIXED: Use constant

				Level:   string(models.LogLevelWarning),
				Message: "MPIN already exists for user",
			},
			UserID:        req.UserID.String(),
			Status:        "setup_failed",
			DeviceID:      req.DeviceID,
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
				Version:     ServiceVersion, // ✅ FIXED: Use constant

				Level:   string(models.LogLevelError),
				Message: "Failed to hash MPIN",
			},
			UserID:        req.UserID.String(),
			Status:        "setup_failed",
			DeviceID:      req.DeviceID,
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
				Version:     ServiceVersion, // ✅ FIXED: Use constant

				Level:   string(models.LogLevelError),
				Message: "Failed to create MPIN in repository",
			},
			UserID:        req.UserID.String(),
			Status:        "setup_failed",
			DeviceID:      req.DeviceID,
			ErrorCode:     "REPOSITORY_CREATE_FAILED",
			ErrorMessage:  err.Error(),
			FailureReason: "repository_create_failed",
		})
		return fmt.Errorf("failed to create MPIN: %w", err)
	}

	if err := s.deviceTrustRepo.SetDeviceTrustLevel(ctx, req.UserID, req.DeviceID, models.TrustStatusPrimary); err != nil {
		s.logger.Error("Failed to set primary device trust level",
			util.ErrorField(err),
			util.String("user_id", req.UserID.String()),
			util.String("device_id", req.DeviceID),
		)
	}

	if s.distCache != nil {
		cacheKey := fmt.Sprintf("mpin:%s", req.UserID.String())
		_ = s.distCache.Delete(ctx, cacheKey)
	}

	// ✅ NEW: Log successful MPIN setup
	s.logMPINEvent(ctx, &models.MPINLogEvent{
		LogEnvelope: models.LogEnvelope{
			EventID:     uuid.New().String(),
			EventType:   string(models.LogEventTypeMPIN),
			ServiceName: "auth-service",
			Timestamp:   time.Now(),
			Environment: s.config.Environment,
			Version:     ServiceVersion, // ✅ FIXED: Use constant

			Level:   string(models.LogLevelInfo),
			Message: "MPIN setup completed successfully",
		},
		UserID:   req.UserID.String(),
		Status:   "setup_completed",
		DeviceID: req.DeviceID,
		Duration: int64(time.Since(startTime).Milliseconds()),
	})

	s.logger.Info("MPIN setup completed",
		util.String("user_id", req.UserID.String()),
		util.String("device_id", req.DeviceID),
		util.Duration("duration", time.Since(startTime)),
	)
	return nil
}

// ✅ CORRECTED: SendForgotMPINOTP - Sends OTP for forgot MPIN flow
func (s *MPINService) SendForgotMPINOTP(ctx context.Context, userID uuid.UUID) (string, error) {
	startTime := time.Now()

	// ✅ NEW: Log OTP send initiation
	s.logMPINEvent(ctx, &models.MPINLogEvent{
		LogEnvelope: models.LogEnvelope{
			EventID:     uuid.New().String(),
			EventType:   string(models.LogEventTypeMPIN),
			ServiceName: "auth-service",
			Timestamp:   time.Now(),
			Environment: s.config.Environment,
			Version:     ServiceVersion, // ✅ FIXED: Use constant

			Level:   string(models.LogLevelInfo),
			Message: "Forgot MPIN OTP send initiated",
		},
		UserID: userID.String(),
		Status: "forgot_otp_initiated",
	})

	// Fetch user from database
	user, err := s.userRepo.GetUserByID(ctx, userID)
	if err != nil {
		s.logMPINEvent(ctx, &models.MPINLogEvent{
			LogEnvelope: models.LogEnvelope{
				EventID:     uuid.New().String(),
				EventType:   string(models.LogEventTypeMPIN),
				ServiceName: "auth-service",
				Timestamp:   time.Now(),
				Environment: s.config.Environment,
				Version:     ServiceVersion, // ✅ FIXED: Use constant

				Level:   string(models.LogLevelError),
				Message: "User not found for forgot MPIN OTP",
			},
			UserID:        userID.String(),
			Status:        "forgot_otp_failed",
			ErrorCode:     "USER_NOT_FOUND",
			FailureReason: "user_not_found",
		})
		return "", fmt.Errorf("user not found: %w", err)
	}

	// Check if user is banned
	if user.IsBanned {
		s.logMPINEvent(ctx, &models.MPINLogEvent{
			LogEnvelope: models.LogEnvelope{
				EventID:     uuid.New().String(),
				EventType:   string(models.LogEventTypeMPIN),
				ServiceName: "auth-service",
				Timestamp:   time.Now(),
				Environment: s.config.Environment,
				Version:     ServiceVersion, // ✅ FIXED: Use constant

				Level:   string(models.LogLevelWarning),
				Message: "Banned user attempted forgot MPIN OTP",
			},
			UserID:        userID.String(),
			Status:        "forgot_otp_failed",
			ErrorCode:     "USER_BANNED",
			FailureReason: "user_banned",
		})
		return "", ErrUserBanned
	}

	// ✅ FIXED: Create pointer to EncryptedData struct
	encryptedData := &encryption.EncryptedData{
		EncryptedValue: user.PhoneEncrypted,
		EncryptedDEK:   user.PhoneEncryptedDEK,
		KeyID:          user.PhoneKeyID.String(),
		Version:        "v1",
		CreatedAt:      user.CreatedAt,
	}

	s.logger.Info("DecryptField debug",
		util.String("EncryptedValue", user.PhoneEncrypted),
		util.String("EncryptedDEK", user.PhoneEncryptedDEK),
		util.String("KeyID", user.PhoneKeyID.String()),
		util.String("UserID", userID.String()),
	)

	// ✅ FIXED: Pass pointer directly (already a pointer from &)
	phoneNumber, err := s.encryptionMgr.DecryptField(ctx, encryptedData)
	if err != nil {
		s.logMPINEvent(ctx, &models.MPINLogEvent{
			LogEnvelope: models.LogEnvelope{
				EventID:     uuid.New().String(),
				EventType:   string(models.LogEventTypeMPIN),
				ServiceName: "auth-service",
				Timestamp:   time.Now(),
				Environment: s.config.Environment,
				Version:     ServiceVersion, // ✅ FIXED: Use constant

				Level:   string(models.LogLevelError),
				Message: "Failed to decrypt phone number for forgot MPIN OTP",
			},
			UserID:        userID.String(),
			Status:        "forgot_otp_failed",
			ErrorCode:     "PHONE_DECRYPTION_FAILED",
			ErrorMessage:  err.Error(),
			FailureReason: "phone_decryption_failed",
		})
		s.logger.Error("Failed to decrypt phone number",
			util.ErrorField(err),
			util.String("user_id", userID.String()),
		)
		return "", fmt.Errorf("failed to decrypt phone number: %w", err)
	}

	// Prepare OTP send request
	otpReq := &OTPSendRequest{
		PhoneNumber: phoneNumber,
		Purpose:     "forgot_mpin",
		DeviceID:    "",
	}

	// Send OTP via OTP service
	otpResp, err := s.otpService.SendOTP(ctx, otpReq)
	if err != nil {
		s.logMPINEvent(ctx, &models.MPINLogEvent{
			LogEnvelope: models.LogEnvelope{
				EventID:     uuid.New().String(),
				EventType:   string(models.LogEventTypeMPIN),
				ServiceName: "auth-service",
				Timestamp:   time.Now(),
				Environment: s.config.Environment,
				Version:     ServiceVersion, // ✅ FIXED: Use constant

				Level:   string(models.LogLevelError),
				Message: "OTP service error for forgot MPIN",
			},
			UserID:        userID.String(),
			Status:        "forgot_otp_failed",
			ErrorCode:     "OTP_SEND_FAILED",
			ErrorMessage:  err.Error(),
			FailureReason: "otp_send_failed",
		})
		s.logger.Error("OTP service error",
			util.ErrorField(err),
			util.String("user_id", userID.String()),
		)
		return "", err
	}

	if !otpResp.Success {
		s.logMPINEvent(ctx, &models.MPINLogEvent{
			LogEnvelope: models.LogEnvelope{
				EventID:     uuid.New().String(),
				EventType:   string(models.LogEventTypeMPIN),
				ServiceName: "auth-service",
				Timestamp:   time.Now(),
				Environment: s.config.Environment,
				Version:     ServiceVersion, // ✅ FIXED: Use constant

				Level:   string(models.LogLevelError),
				Message: "OTP send failed for forgot MPIN",
			},
			UserID:        userID.String(),
			Status:        "forgot_otp_failed",
			ErrorCode:     "OTP_SEND_FAILED",
			ErrorMessage:  otpResp.Message,
			FailureReason: "otp_send_failed",
		})
		return "", fmt.Errorf("failed to send OTP: %s", otpResp.Message)
	}

	// ✅ NEW: Log successful OTP send
	s.logMPINEvent(ctx, &models.MPINLogEvent{
		LogEnvelope: models.LogEnvelope{
			EventID:     uuid.New().String(),
			EventType:   string(models.LogEventTypeMPIN),
			ServiceName: "auth-service",
			Timestamp:   time.Now(),
			Environment: s.config.Environment,
			Version:     ServiceVersion, // ✅ FIXED: Use constant

			Level:   string(models.LogLevelInfo),
			Message: "Forgot MPIN OTP sent successfully",
		},
		UserID:   userID.String(),
		Status:   "forgot_otp_sent",
		Duration: int64(time.Since(startTime).Milliseconds()),
	})

	s.logger.Info("Forgot MPIN OTP sent successfully",
		util.String("user_id", userID.String()),
		util.String("phone", phoneNumber[len(phoneNumber)-4:]+"****"),
	)

	return "", nil
}

// ✅ CORRECTED: VerifyForgotMPINOTP - Verifies OTP and resets MPIN
func (s *MPINService) VerifyForgotMPINOTP(ctx context.Context, req *MPINForgotWithOTPRequest) error {
	startTime := time.Now()

	// ✅ NEW: Log OTP verification attempt
	s.logMPINEvent(ctx, &models.MPINLogEvent{
		LogEnvelope: models.LogEnvelope{
			EventID:     uuid.New().String(),
			EventType:   string(models.LogEventTypeMPIN),
			ServiceName: "auth-service",
			Timestamp:   time.Now(),
			Environment: s.config.Environment,
			Version:     ServiceVersion, // ✅ FIXED: Use constant

			Level:   string(models.LogLevelInfo),
			Message: "Forgot MPIN OTP verification initiated",
		},
		UserID:   req.UserID.String(),
		Status:   "forgot_otp_verification_initiated",
		DeviceID: req.DeviceID,
	})

	// Validate new MPIN
	if err := s.validateMPIN(req.NewMPIN); err != nil {
		s.logMPINEvent(ctx, &models.MPINLogEvent{
			LogEnvelope: models.LogEnvelope{
				EventID:     uuid.New().String(),
				EventType:   string(models.LogEventTypeMPIN),
				ServiceName: "auth-service",
				Timestamp:   time.Now(),
				Environment: s.config.Environment,
				Version:     ServiceVersion, // ✅ FIXED: Use constant

				Level:   string(models.LogLevelError),
				Message: "MPIN validation failed for forgot MPIN OTP",
			},
			UserID:        req.UserID.String(),
			Status:        "forgot_otp_verification_failed",
			DeviceID:      req.DeviceID,
			ErrorCode:     "VALIDATION_FAILED",
			ErrorMessage:  err.Error(),
			FailureReason: "mpin_validation_failed",
		})
		return err
	}

	// Fetch user from database
	user, err := s.userRepo.GetUserByID(ctx, req.UserID)
	if err != nil {
		s.logMPINEvent(ctx, &models.MPINLogEvent{
			LogEnvelope: models.LogEnvelope{
				EventID:     uuid.New().String(),
				EventType:   string(models.LogEventTypeMPIN),
				ServiceName: "auth-service",
				Timestamp:   time.Now(),
				Environment: s.config.Environment,
				Version:     ServiceVersion, // ✅ FIXED: Use constant

				Level:   string(models.LogLevelError),
				Message: "User not found for forgot MPIN OTP verification",
			},
			UserID:        req.UserID.String(),
			Status:        "forgot_otp_verification_failed",
			DeviceID:      req.DeviceID,
			ErrorCode:     "USER_NOT_FOUND",
			FailureReason: "user_not_found",
		})
		return fmt.Errorf("user not found: %w", err)
	}

	// ✅ FIXED: Create pointer to EncryptedData struct
	encryptedData := &encryption.EncryptedData{
		EncryptedValue: user.PhoneEncrypted,
		EncryptedDEK:   user.PhoneEncryptedDEK,
		KeyID:          user.PhoneKeyID.String(),
		Version:        "v1",
		CreatedAt:      user.CreatedAt,
	}

	// ✅ FIXED: Pass pointer directly (already a pointer from &)
	phoneNumber, err := s.encryptionMgr.DecryptField(ctx, encryptedData)
	if err != nil {
		s.logMPINEvent(ctx, &models.MPINLogEvent{
			LogEnvelope: models.LogEnvelope{
				EventID:     uuid.New().String(),
				EventType:   string(models.LogEventTypeMPIN),
				ServiceName: "auth-service",
				Timestamp:   time.Now(),
				Environment: s.config.Environment,
				Version:     ServiceVersion, // ✅ FIXED: Use constant

				Level:   string(models.LogLevelError),
				Message: "Failed to decrypt phone number for forgot MPIN OTP verification",
			},
			UserID:        req.UserID.String(),
			Status:        "forgot_otp_verification_failed",
			DeviceID:      req.DeviceID,
			ErrorCode:     "PHONE_DECRYPTION_FAILED",
			ErrorMessage:  err.Error(),
			FailureReason: "phone_decryption_failed",
		})
		s.logger.Error("Failed to decrypt phone number",
			util.ErrorField(err),
			util.String("user_id", req.UserID.String()),
		)
		return fmt.Errorf("failed to decrypt phone number: %w", err)
	}

	// Verify OTP
	otpVerifyReq := &OTPVerifyRequest{
		PhoneNumber: phoneNumber,
		OTP:         req.OTPCode,
		Purpose:     "forgot_mpin",
	}

	otpResp, err := s.otpService.VerifyOTP(ctx, otpVerifyReq)
	if err != nil {
		s.logMPINEvent(ctx, &models.MPINLogEvent{
			LogEnvelope: models.LogEnvelope{
				EventID:     uuid.New().String(),
				EventType:   string(models.LogEventTypeMPIN),
				ServiceName: "auth-service",
				Timestamp:   time.Now(),
				Environment: s.config.Environment,
				Version:     ServiceVersion, // ✅ FIXED: Use constant

				Level:   string(models.LogLevelWarning),
				Message: "OTP verification failed for forgot MPIN",
			},
			UserID:        req.UserID.String(),
			Status:        "forgot_otp_verification_failed",
			DeviceID:      req.DeviceID,
			ErrorCode:     "OTP_VERIFICATION_FAILED",
			ErrorMessage:  err.Error(),
			FailureReason: "otp_verification_failed",
		})
		s.logger.Warn("OTP verification failed",
			util.ErrorField(err),
			util.String("user_id", req.UserID.String()),
		)
		return fmt.Errorf("invalid OTP code")
	}

	if !otpResp.Success {
		s.logMPINEvent(ctx, &models.MPINLogEvent{
			LogEnvelope: models.LogEnvelope{
				EventID:     uuid.New().String(),
				EventType:   string(models.LogEventTypeMPIN),
				ServiceName: "auth-service",
				Timestamp:   time.Now(),
				Environment: s.config.Environment,
				Version:     ServiceVersion, // ✅ FIXED: Use constant

				Level:   string(models.LogLevelWarning),
				Message: "Invalid OTP code for forgot MPIN",
			},
			UserID:        req.UserID.String(),
			Status:        "forgot_otp_verification_failed",
			DeviceID:      req.DeviceID,
			ErrorCode:     "INVALID_OTP",
			FailureReason: "invalid_otp",
		})
		return fmt.Errorf("invalid OTP code")
	}

	// Get device trust level
	deviceTrust, err := s.deviceTrustRepo.GetDeviceTrustLevel(ctx, req.UserID, req.DeviceID)
	if err != nil {
		// Device is unknown, mark as untrusted
		deviceTrust = &models.DeviceTrustLevel{
			UserID:      req.UserID,
			DeviceID:    req.DeviceID,
			TrustStatus: models.TrustStatusUntrusted,
		}
	}

	// Get primary device for comparison
	primaryDevice, _ := s.deviceTrustRepo.GetPrimaryDevice(ctx, req.UserID)

	// Determine if device is trusted
	isTrustedDevice := deviceTrust.TrustStatus == models.TrustStatusPrimary ||
		deviceTrust.TrustStatus == models.TrustStatusTrusted

	// Check if data wipe should be triggered
	shouldWipeData := !isTrustedDevice && (primaryDevice != nil && primaryDevice.DeviceID != req.DeviceID)

	// Hash the new MPIN
	hashResult, err := s.hasher.HashMPIN(req.NewMPIN)
	if err != nil {
		s.logMPINEvent(ctx, &models.MPINLogEvent{
			LogEnvelope: models.LogEnvelope{
				EventID:     uuid.New().String(),
				EventType:   string(models.LogEventTypeMPIN),
				ServiceName: "auth-service",
				Timestamp:   time.Now(),
				Environment: s.config.Environment,
				Version:     ServiceVersion, // ✅ FIXED: Use constant

				Level:   string(models.LogLevelError),
				Message: "Failed to hash MPIN for forgot MPIN OTP",
			},
			UserID:        req.UserID.String(),
			Status:        "forgot_otp_verification_failed",
			DeviceID:      req.DeviceID,
			ErrorCode:     "HASHING_FAILED",
			ErrorMessage:  err.Error(),
			FailureReason: "hashing_failed",
		})
		s.logger.Error("Failed to hash MPIN",
			util.ErrorField(err),
			util.String("user_id", req.UserID.String()),
		)
		return fmt.Errorf("failed to hash MPIN: %w", err)
	}

	// Update MPIN in database
	if err := s.mpinRepo.UpdateMPIN(ctx, req.UserID, hashResult.Hash, hashResult.Salt, hashResult.PepperVersion); err != nil {
		s.logMPINEvent(ctx, &models.MPINLogEvent{
			LogEnvelope: models.LogEnvelope{
				EventID:     uuid.New().String(),
				EventType:   string(models.LogEventTypeMPIN),
				ServiceName: "auth-service",
				Timestamp:   time.Now(),
				Environment: s.config.Environment,
				Version:     ServiceVersion, // ✅ FIXED: Use constant

				Level:   string(models.LogLevelError),
				Message: "Failed to update MPIN for forgot MPIN OTP",
			},
			UserID:        req.UserID.String(),
			Status:        "forgot_otp_verification_failed",
			DeviceID:      req.DeviceID,
			ErrorCode:     "MPIN_UPDATE_FAILED",
			ErrorMessage:  err.Error(),
			FailureReason: "mpin_update_failed",
		})
		s.logger.Error("Failed to update MPIN",
			util.ErrorField(err),
			util.String("user_id", req.UserID.String()),
		)
		return fmt.Errorf("failed to update MPIN: %w", err)
	}

	// Unlock MPIN if it was locked
	_ = s.mpinRepo.UnlockMPIN(ctx, req.UserID)

	// Record data deletion if wipe is needed
	if shouldWipeData {
		s.logMPINEvent(ctx, &models.MPINLogEvent{
			LogEnvelope: models.LogEnvelope{
				EventID:     uuid.New().String(),
				EventType:   string(models.LogEventTypeMPIN),
				ServiceName: "auth-service",
				Timestamp:   time.Now(),
				Environment: s.config.Environment,
				Version:     ServiceVersion, // ✅ FIXED: Use constant

				Level:   string(models.LogLevelWarning),
				Message: "Data wipe triggered for forgot MPIN on untrusted device",
			},
			UserID:        req.UserID.String(),
			Status:        "data_wipe_triggered",
			DeviceID:      req.DeviceID,
			FailureReason: "untrusted_device_forgot_mpin",
		})

		s.logger.Warn("Data wipe triggered - forgot MPIN on new device",
			util.String("user_id", req.UserID.String()),
			util.String("device_id", req.DeviceID),
			util.String("trust_status", string(deviceTrust.TrustStatus)),
		)

		deletion := &models.UserDataDeletion{
			DeletionID:          uuid.New(),
			UserID:              req.UserID,
			DeviceID:            req.DeviceID,
			Reason:              "forgot_mpin_new_device",
			DeletedAt:           time.Now(),
			DataWipedCategories: []string{"session_tokens", "saved_data", "preferences"},
		}

		if err := s.deviceTrustRepo.RecordDataDeletion(ctx, deletion); err != nil {
			s.logger.Error("Failed to record data deletion",
				util.ErrorField(err),
				util.String("user_id", req.UserID.String()),
			)
		}
	}

	// Set device as trusted after successful OTP verification
	if err := s.deviceTrustRepo.SetDeviceTrustLevel(ctx, req.UserID, req.DeviceID, models.TrustStatusTrusted); err != nil {
		s.logger.Warn("Failed to set device trust level",
			util.ErrorField(err),
			util.String("user_id", req.UserID.String()),
		)
	}

	// Clear MPIN cache
	if s.distCache != nil {
		cacheKey := fmt.Sprintf("mpin:%s", req.UserID.String())
		_ = s.distCache.Delete(ctx, cacheKey)
	}

	// ✅ NEW: Log successful MPIN reset via OTP
	s.logMPINEvent(ctx, &models.MPINLogEvent{
		LogEnvelope: models.LogEnvelope{
			EventID:     uuid.New().String(),
			EventType:   string(models.LogEventTypeMPIN),
			ServiceName: "auth-service",
			Timestamp:   time.Now(),
			Environment: s.config.Environment,
			Version:     ServiceVersion, // ✅ FIXED: Use constant

			Level:   string(models.LogLevelInfo),
			Message: "MPIN reset via forgot with OTP verification completed",
		},
		UserID:      req.UserID.String(),
		Status:      "forgot_otp_verification_completed",
		DeviceID:    req.DeviceID,
		DeviceTrust: string(deviceTrust.TrustStatus),
		Duration:    int64(time.Since(startTime).Milliseconds()),
	})

	s.logger.Info("MPIN reset via forgot with OTP verification",
		util.String("user_id", req.UserID.String()),
		util.String("device_id", req.DeviceID),
		util.Bool("data_wiped", shouldWipeData),
		util.String("trust_status", string(deviceTrust.TrustStatus)),
	)

	return nil
}

// // ✅ UPDATED: VerifyMPIN with lenient device check and Kafka logging
// func (s *MPINService) VerifyMPIN(ctx context.Context, req *MPINVerifyRequest) (*MPINVerifyResult, error) {
//     startTime := time.Now()

//     // ✅ NEW: Log MPIN verification attempt
//     s.logMPINEvent(ctx, &models.MPINLogEvent{
//         LogEnvelope: models.LogEnvelope{
//             EventID:     uuid.New().String(),
//             EventType:   string(models.LogEventTypeMPIN),
//             ServiceName: "auth-service",
//             Timestamp:   time.Now(),
//             Environment: s.config.Environment,
//             Version:     ServiceVersion,       // ✅ FIXED: Use constant

//             Level:       string(models.LogLevelInfo),
//             Message:     "MPIN verification initiated",
//         },
//         UserID:   req.UserID.String(),
//         Status:   "verification_initiated",
//         DeviceID: req.DeviceID,
//     })

//     if err := s.validateMPIN(req.MPIN); err != nil {
//         s.logMPINEvent(ctx, &models.MPINLogEvent{
//             LogEnvelope: models.LogEnvelope{
//                 EventID:     uuid.New().String(),
//                 EventType:   string(models.LogEventTypeMPIN),
//                 ServiceName: "auth-service",
//                 Timestamp:   time.Now(),
//                 Environment: s.config.Environment,
//                 Version:     ServiceVersion,       // ✅ FIXED: Use constant

//                 Level:       string(models.LogLevelError),
//                 Message:     "MPIN validation failed",
//             },
//             UserID:        req.UserID.String(),
//             Status:        "verification_failed",
//             DeviceID:      req.DeviceID,
//             ErrorCode:     "VALIDATION_FAILED",
//             ErrorMessage:  err.Error(),
//             FailureReason: "mpin_validation_failed",
//         })
//         return nil, err
//     }

//     mpinCred, err := s.mpinRepo.ValidateMPIN(ctx, req.UserID, req.MPIN)
//     if err != nil {
//         if err.Error() == "MPIN not found for user: "+req.UserID.String() {
//             s.logMPINEvent(ctx, &models.MPINLogEvent{
//                 LogEnvelope: models.LogEnvelope{
//                     EventID:     uuid.New().String(),
//                     EventType:   string(models.LogEventTypeMPIN),
//                     ServiceName: "auth-service",
//                     Timestamp:   time.Now(),
//                     Environment: s.config.Environment,
//                     Version:     ServiceVersion,       // ✅ FIXED: Use constant

//                     Level:       string(models.LogLevelWarning),
//                     Message:     "MPIN not found for verification",
//                 },
//                 UserID:        req.UserID.String(),
//                 Status:        "verification_failed",
//                 DeviceID:      req.DeviceID,
//                 ErrorCode:     "MPIN_NOT_FOUND",
//                 FailureReason: "mpin_not_found",
//             })
//             return nil, ErrMPINNotFound
//         }
//         if err.Error() == "MPIN locked due to too many failed attempts" {
//             result := &MPINVerifyResult{
//                 Verified:       false,
//                 FailedAttempts: MPINMaxAttempts,
//                 RemainingTries: 0,
//                 Message:        "MPIN is locked due to too many failed attempts",
//             }
//             s.logMPINEvent(ctx, &models.MPINLogEvent{
//                 LogEnvelope: models.LogEnvelope{
//                     EventID:     uuid.New().String(),
//                     EventType:   string(models.LogEventTypeMPIN),
//                     ServiceName: "auth-service",
//                     Timestamp:   time.Now(),
//                     Environment: s.config.Environment,
//                     Version:     ServiceVersion,       // ✅ FIXED: Use constant

//                     Level:       string(models.LogLevelWarning),
//                     Message:     "MPIN verification failed - locked",
//                 },
//                 UserID:       req.UserID.String(),
//                 Status:       "verification_failed",
//                 DeviceID:     req.DeviceID,
//                 Attempts:     MPINMaxAttempts,
//                 AttemptsLeft: 0,
//                 IsLocked:     true,
//                 ErrorCode:    "MPIN_LOCKED",
//                 FailureReason: "mpin_locked",
//             })
//             return result, ErrMPINLocked
//         }

//         s.logMPINEvent(ctx, &models.MPINLogEvent{
//             LogEnvelope: models.LogEnvelope{
//                 EventID:     uuid.New().String(),
//                 EventType:   string(models.LogEventTypeMPIN),
//                 ServiceName: "auth-service",
//                 Timestamp:   time.Now(),
//                 Environment: s.config.Environment,
//                 Version:     ServiceVersion,       // ✅ FIXED: Use constant

//                 Level:       string(models.LogLevelError),
//                 Message:     "MPIN validation repository error",
//             },
//             UserID:        req.UserID.String(),
//             Status:        "verification_failed",
//             DeviceID:      req.DeviceID,
//             ErrorCode:     "REPOSITORY_ERROR",
//             ErrorMessage:  err.Error(),
//             FailureReason: "repository_error",
//         })
//         return nil, err
//     }

//     // ✅ UPDATED: Lenient device check - warn but allow verification
//     if mpinCred.DeviceID != "" && req.DeviceID != "" && mpinCred.DeviceID != req.DeviceID {
//         s.logMPINEvent(ctx, &models.MPINLogEvent{
//             LogEnvelope: models.LogEnvelope{
//                 EventID:     uuid.New().String(),
//                 EventType:   string(models.LogEventTypeMPIN),
//                 ServiceName: "auth-service",
//                 Timestamp:   time.Now(),
//                 Environment: s.config.Environment,
//                 Version:     ServiceVersion,       // ✅ FIXED: Use constant

//                 Level:       string(models.LogLevelWarning),
//                 Message:     "Device mismatch during MPIN verification",
//             },
//             UserID:   req.UserID.String(),
//             Status:   "device_mismatch",
//             DeviceID: req.DeviceID,
//         })
//         s.logger.Warn("Device mismatch during MPIN verification",
//             util.String("user_id", req.UserID.String()),
//             util.String("expected_device", mpinCred.DeviceID),
//             util.String("provided_device", req.DeviceID),
//         )
//         // Don't fail - allow verification to continue for untrusted device flow
//     }

//     hashResult := &hashing.HashResult{
//         Hash:          mpinCred.MPINHash,
//         Salt:          mpinCred.MPINSalt,
//         PepperVersion: mpinCred.PepperVersion,
//         Algorithm:     mpinCred.HashAlgorithm,
//     }

//     verified, err := s.hasher.VerifyMPIN(req.MPIN, hashResult)
//     if err != nil {
//         s.logMPINEvent(ctx, &models.MPINLogEvent{
//             LogEnvelope: models.LogEnvelope{
//                 EventID:     uuid.New().String(),
//                 EventType:   string(models.LogEventTypeMPIN),
//                 ServiceName: "auth-service",
//                 Timestamp:   time.Now(),
//                 Environment: s.config.Environment,
//                 Version:     ServiceVersion,       // ✅ FIXED: Use constant

//                 Level:       string(models.LogLevelError),
//                 Message:     "Failed to verify MPIN hash",
//             },
//             UserID:        req.UserID.String(),
//             Status:        "verification_failed",
//             DeviceID:      req.DeviceID,
//             ErrorCode:     "HASH_VERIFICATION_FAILED",
//             ErrorMessage:  err.Error(),
//             FailureReason: "hash_verification_failed",
//         })
//         return nil, fmt.Errorf("failed to verify MPIN: %w", err)
//     }

//     result := &MPINVerifyResult{
//         Verified:       verified,
//         FailedAttempts: mpinCred.FailedAttempts,
//         RemainingTries: max(0, MPINMaxAttempts-mpinCred.FailedAttempts),
//     }

//     if verified {
//         if err := s.mpinRepo.ResetFailedAttempts(ctx, req.UserID); err != nil {
//             s.logger.Error("Failed to reset failed attempts",
//                 util.ErrorField(err),
//                 util.String("user_id", req.UserID.String()),
//             )
//         }
//         result.Message = "MPIN verified successfully"
//         result.FailedAttempts = 0
//         result.RemainingTries = MPINMaxAttempts

//         // ✅ NEW: Log successful MPIN verification
//         s.logMPINEvent(ctx, &models.MPINLogEvent{
//             LogEnvelope: models.LogEnvelope{
//                 EventID:     uuid.New().String(),
//                 EventType:   string(models.LogEventTypeMPIN),
//                 ServiceName: "auth-service",
//                 Timestamp:   time.Now(),
//                 Environment: s.config.Environment,
//                 Version:     ServiceVersion,       // ✅ FIXED: Use constant

//                 Level:       string(models.LogLevelInfo),
//                 Message:     "MPIN verified successfully",
//             },
//             UserID:       req.UserID.String(),
//             Status:       "verification_successful",
//             DeviceID:     req.DeviceID,
//             Attempts:     0,
//             AttemptsLeft: MPINMaxAttempts,
//             IsLocked:     false,
//             Duration:     int64(time.Since(startTime).Milliseconds()),
//         })
//     } else {
//         newFailedAttempts, err := s.mpinRepo.IncrementFailedAttempts(ctx, req.UserID)
//         if err != nil {
//             s.logger.Error("Failed to increment failed attempts",
//                 util.ErrorField(err),
//                 util.String("user_id", req.UserID.String()),
//             )
//         } else {
//             result.FailedAttempts = newFailedAttempts
//             result.RemainingTries = max(0, MPINMaxAttempts-newFailedAttempts)
//         }

//         if result.RemainingTries == 0 {
//             result.Message = "MPIN is now locked due to too many failed attempts"
//             lockUntil := time.Now().Add(MPINLockDuration)
//             result.LockedUntil = &lockUntil

//             // ✅ NEW: Log MPIN lock event
//             s.logMPINEvent(ctx, &models.MPINLogEvent{
//                 LogEnvelope: models.LogEnvelope{
//                     EventID:     uuid.New().String(),
//                     EventType:   string(models.LogEventTypeMPIN),
//                     ServiceName: "auth-service",
//                     Timestamp:   time.Now(),
//                     Environment: s.config.Environment,
//                     Version:     ServiceVersion,       // ✅ FIXED: Use constant

//                     Level:       string(models.LogLevelWarning),
//                     Message:     "MPIN locked due to failed attempts",
//                 },
//                 UserID:       req.UserID.String(),
//                 Status:       "mpin_locked",
//                 DeviceID:     req.DeviceID,
//                 Attempts:     newFailedAttempts,
//                 AttemptsLeft: 0,
//                 IsLocked:     true,
//                 Duration:     int64(time.Since(startTime).Milliseconds()),
//             })
//         } else {
//             result.Message = fmt.Sprintf("Invalid MPIN. %d attempts remaining", result.RemainingTries)

//             // ✅ NEW: Log failed MPIN attempt
//             s.logMPINEvent(ctx, &models.MPINLogEvent{
//                 LogEnvelope: models.LogEnvelope{
//                     EventID:     uuid.New().String(),
//                     EventType:   string(models.LogEventTypeMPIN),
//                     ServiceName: "auth-service",
//                     Timestamp:   time.Now(),
//                     Environment: s.config.Environment,
//                     Version:     ServiceVersion,       // ✅ FIXED: Use constant

//                     Level:       string(models.LogLevelWarning),
//                     Message:     "MPIN verification failed",
//                 },
//                 UserID:       req.UserID.String(),
//                 Status:       "verification_failed",
//                 DeviceID:     req.DeviceID,
//                 Attempts:     newFailedAttempts,
//                 AttemptsLeft: result.RemainingTries,
//                 IsLocked:     false,
//                 Duration:     int64(time.Since(startTime).Milliseconds()),
//             })
//         }
//     }

//     s.logger.Info("MPIN verification completed",
//         util.String("user_id", req.UserID.String()),
//         util.Bool("verified", verified),
//         util.Int("failed_attempts", result.FailedAttempts),
//         util.Duration("duration", time.Since(startTime)),
//     )

//     return result, nil
// }

// ✅ FIXED: VerifyMPIN with CORRECT hash verification
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
		UserID:   req.UserID.String(),
		Status:   "verification_initiated",
		DeviceID: req.DeviceID,
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
			Status:        "verification_failed",
			DeviceID:      req.DeviceID,
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
			ErrorCode:     "REPOSITORY_ERROR",
			ErrorMessage:  err.Error(),
			FailureReason: "repository_error",
		})
		return nil, err
	}

	// Device mismatch warning (allow but log)
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
			UserID:   req.UserID.String(),
			Status:   "device_mismatch",
			DeviceID: req.DeviceID,
		})
		s.logger.Warn("Device mismatch during MPIN verification",
			util.String("user_id", req.UserID.String()),
			util.String("expected_device", mpinCred.DeviceID),
			util.String("provided_device", req.DeviceID),
		)
	}

	// ✅✅✅ CORRECT HASH VERIFICATION - Use your existing VerifyMPIN method
	hashResult := &hashing.HashResult{
		Hash:          mpinCred.MPINHash,      // Stored hash from database
		Salt:          mpinCred.MPINSalt,      // Stored salt from database
		PepperVersion: mpinCred.PepperVersion, // Stored pepper version from database
		Algorithm:     mpinCred.HashAlgorithm, // Stored algorithm from database
	}

	// This calls your hasher.VerifyMPIN which will:
	// 1. Hash the input MPIN with stored salt + correct pepper version
	// 2. Compare with stored hash
	// 3. Return true/false
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
		util.Duration("duration", time.Since(startTime)),
	)

	return result, nil
}

// ✅ UPDATED: ChangeMPIN with device trust, data wipe logic and Kafka logging
func (s *MPINService) ChangeMPIN(ctx context.Context, req *MPINChangeRequest) error {
	startTime := time.Now()

	// ✅ NEW: Log MPIN change attempt
	s.logMPINEvent(ctx, &models.MPINLogEvent{
		LogEnvelope: models.LogEnvelope{
			EventID:     uuid.New().String(),
			EventType:   string(models.LogEventTypeMPIN),
			ServiceName: "auth-service",
			Timestamp:   time.Now(),
			Environment: s.config.Environment,
			Version:     ServiceVersion, // ✅ FIXED: Use constant

			Level:   string(models.LogLevelInfo),
			Message: "MPIN change initiated",
		},
		UserID:   req.UserID.String(),
		Status:   "change_initiated",
		DeviceID: req.DeviceID,
	})

	if err := s.validateMPIN(req.NewMPIN); err != nil {
		s.logMPINEvent(ctx, &models.MPINLogEvent{
			LogEnvelope: models.LogEnvelope{
				EventID:     uuid.New().String(),
				EventType:   string(models.LogEventTypeMPIN),
				ServiceName: "auth-service",
				Timestamp:   time.Now(),
				Environment: s.config.Environment,
				Version:     ServiceVersion, // ✅ FIXED: Use constant

				Level:   string(models.LogLevelError),
				Message: "New MPIN validation failed",
			},
			UserID:        req.UserID.String(),
			Status:        "change_failed",
			DeviceID:      req.DeviceID,
			ErrorCode:     "VALIDATION_FAILED",
			ErrorMessage:  err.Error(),
			FailureReason: "new_mpin_validation_failed",
		})
		return err
	}

	// ✅ Get device trust level
	deviceTrust, err := s.deviceTrustRepo.GetDeviceTrustLevel(ctx, req.UserID, req.DeviceID)
	if err != nil {
		s.logger.Error("Failed to get device trust level",
			util.ErrorField(err),
			util.String("user_id", req.UserID.String()),
		)
		// Continue with untrusted status
		deviceTrust = &models.DeviceTrustLevel{
			UserID:      req.UserID,
			DeviceID:    req.DeviceID,
			TrustStatus: models.TrustStatusUntrusted,
		}
	}

	// ✅ Check if device is blocked
	if deviceTrust.IsBlocked {
		s.logMPINEvent(ctx, &models.MPINLogEvent{
			LogEnvelope: models.LogEnvelope{
				EventID:     uuid.New().String(),
				EventType:   string(models.LogEventTypeMPIN),
				ServiceName: "auth-service",
				Timestamp:   time.Now(),
				Environment: s.config.Environment,
				Version:     ServiceVersion, // ✅ FIXED: Use constant

				Level:   string(models.LogLevelWarning),
				Message: "Device blocked for MPIN change",
			},
			UserID:        req.UserID.String(),
			Status:        "change_failed",
			DeviceID:      req.DeviceID,
			ErrorCode:     "DEVICE_BLOCKED",
			FailureReason: "device_blocked",
		})
		return fmt.Errorf("device is blocked for security reasons")
	}

	// ✅ Get primary device for comparison
	primaryDevice, _ := s.deviceTrustRepo.GetPrimaryDevice(ctx, req.UserID)

	// ✅ Determine if this is a trusted device
	isTrustedDevice := deviceTrust.TrustStatus == models.TrustStatusPrimary ||
		deviceTrust.TrustStatus == models.TrustStatusTrusted

	// ✅ For untrusted devices, mark for data deletion
	shouldWipeData := !isTrustedDevice && (primaryDevice != nil && primaryDevice.DeviceID != req.DeviceID)

	// Verify current MPIN first
	verifyReq := &MPINVerifyRequest{
		UserID:   req.UserID,
		MPIN:     req.CurrentMPIN,
		DeviceID: req.DeviceID,
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
				Version:     ServiceVersion, // ✅ FIXED: Use constant

				Level:   string(models.LogLevelWarning),
				Message: "Current MPIN verification failed for change",
			},
			UserID:        req.UserID.String(),
			Status:        "change_failed",
			DeviceID:      req.DeviceID,
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
				Version:     ServiceVersion, // ✅ FIXED: Use constant

				Level:   string(models.LogLevelError),
				Message: "Failed to hash new MPIN",
			},
			UserID:        req.UserID.String(),
			Status:        "change_failed",
			DeviceID:      req.DeviceID,
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
				Version:     ServiceVersion, // ✅ FIXED: Use constant

				Level:   string(models.LogLevelError),
				Message: "Failed to update MPIN in repository",
			},
			UserID:        req.UserID.String(),
			Status:        "change_failed",
			DeviceID:      req.DeviceID,
			ErrorCode:     "REPOSITORY_UPDATE_FAILED",
			ErrorMessage:  err.Error(),
			FailureReason: "repository_update_failed",
		})
		return fmt.Errorf("failed to update MPIN: %w", err)
	}

	// ✅ If untrusted device, wipe sensitive data
	if shouldWipeData {
		s.logMPINEvent(ctx, &models.MPINLogEvent{
			LogEnvelope: models.LogEnvelope{
				EventID:     uuid.New().String(),
				EventType:   string(models.LogEventTypeMPIN),
				ServiceName: "auth-service",
				Timestamp:   time.Now(),
				Environment: s.config.Environment,
				Version:     ServiceVersion, // ✅ FIXED: Use constant

				Level:   string(models.LogLevelWarning),
				Message: "Data wipe triggered for MPIN change on untrusted device",
			},
			UserID:        req.UserID.String(),
			Status:        "data_wipe_triggered",
			DeviceID:      req.DeviceID,
			FailureReason: "untrusted_device_mpin_change",
		})

		s.logger.Warn("Data wipe triggered - untrusted device MPIN change",
			util.String("user_id", req.UserID.String()),
			util.String("device_id", req.DeviceID),
			util.String("trust_status", string(deviceTrust.TrustStatus)),
		)

		deletion := &models.UserDataDeletion{
			DeletionID:          uuid.New(),
			UserID:              req.UserID,
			DeviceID:            req.DeviceID,
			Reason:              "untrusted_device_mpin_change",
			DeletedAt:           time.Now(),
			DataWipedCategories: []string{"session_tokens", "saved_data", "preferences"},
		}

		if err := s.deviceTrustRepo.RecordDataDeletion(ctx, deletion); err != nil {
			s.logger.Error("Failed to record data deletion",
				util.ErrorField(err),
				util.String("user_id", req.UserID.String()),
			)
		}
	}

	// ✅ Update device trust level to trusted after successful MPIN change
	if deviceTrust.TrustStatus == models.TrustStatusUntrusted {
		_ = s.deviceTrustRepo.SetDeviceTrustLevel(ctx, req.UserID, req.DeviceID, models.TrustStatusTrusted)
	}

	if s.distCache != nil {
		cacheKey := fmt.Sprintf("mpin:%s", req.UserID.String())
		_ = s.distCache.Delete(ctx, cacheKey)
	}

	// ✅ NEW: Log successful MPIN change
	s.logMPINEvent(ctx, &models.MPINLogEvent{
		LogEnvelope: models.LogEnvelope{
			EventID:     uuid.New().String(),
			EventType:   string(models.LogEventTypeMPIN),
			ServiceName: "auth-service",
			Timestamp:   time.Now(),
			Environment: s.config.Environment,
			Version:     ServiceVersion, // ✅ FIXED: Use constant

			Level:   string(models.LogLevelInfo),
			Message: "MPIN changed successfully",
		},
		UserID:      req.UserID.String(),
		Status:      "change_completed",
		DeviceID:    req.DeviceID,
		DeviceTrust: string(deviceTrust.TrustStatus),
		Duration:    int64(time.Since(startTime).Milliseconds()),
	})

	s.logger.Info("MPIN changed successfully",
		util.String("user_id", req.UserID.String()),
		util.String("device_id", req.DeviceID),
		util.Bool("data_wiped", shouldWipeData),
		util.String("trust_status", string(deviceTrust.TrustStatus)),
		util.Duration("duration", time.Since(startTime)),
	)

	return nil
}

// ✅ NEW: Admin MPIN change (bypasses lock and device checks) with Kafka logging
func (s *MPINService) ChangeMPINAdmin(ctx context.Context, req *MPINAdminChangeRequest) error {
	startTime := time.Now()

	// ✅ NEW: Log admin MPIN change attempt
	s.logMPINEvent(ctx, &models.MPINLogEvent{
		LogEnvelope: models.LogEnvelope{
			EventID:     uuid.New().String(),
			EventType:   string(models.LogEventTypeMPIN),
			ServiceName: "auth-service",
			Timestamp:   time.Now(),
			Environment: s.config.Environment,
			Version:     ServiceVersion, // ✅ FIXED: Use constant

			Level:   string(models.LogLevelInfo),
			Message: "Admin MPIN change initiated",
		},
		UserID: req.UserID.String(),
		Status: "admin_change_initiated",
	})

	if err := s.validateMPIN(req.NewMPIN); err != nil {
		s.logMPINEvent(ctx, &models.MPINLogEvent{
			LogEnvelope: models.LogEnvelope{
				EventID:     uuid.New().String(),
				EventType:   string(models.LogEventTypeMPIN),
				ServiceName: "auth-service",
				Timestamp:   time.Now(),
				Environment: s.config.Environment,
				Version:     ServiceVersion, // ✅ FIXED: Use constant

				Level:   string(models.LogLevelError),
				Message: "New MPIN validation failed for admin change",
			},
			UserID:        req.UserID.String(),
			Status:        "admin_change_failed",
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
				Version:     ServiceVersion, // ✅ FIXED: Use constant

				Level:   string(models.LogLevelError),
				Message: "User not found for admin MPIN change",
			},
			UserID:        req.UserID.String(),
			Status:        "admin_change_failed",
			ErrorCode:     "USER_NOT_FOUND",
			FailureReason: "user_not_found",
		})
		return fmt.Errorf("user not found: %w", err)
	}

	if user.IsBanned {
		s.logMPINEvent(ctx, &models.MPINLogEvent{
			LogEnvelope: models.LogEnvelope{
				EventID:     uuid.New().String(),
				EventType:   string(models.LogEventTypeMPIN),
				ServiceName: "auth-service",
				Timestamp:   time.Now(),
				Environment: s.config.Environment,
				Version:     ServiceVersion, // ✅ FIXED: Use constant

				Level:   string(models.LogLevelWarning),
				Message: "Banned user for admin MPIN change",
			},
			UserID:        req.UserID.String(),
			Status:        "admin_change_failed",
			ErrorCode:     "USER_BANNED",
			FailureReason: "user_banned",
		})
		return ErrUserBanned
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
				Version:     ServiceVersion, // ✅ FIXED: Use constant

				Level:   string(models.LogLevelError),
				Message: "Failed to hash MPIN for admin change",
			},
			UserID:        req.UserID.String(),
			Status:        "admin_change_failed",
			ErrorCode:     "HASHING_FAILED",
			ErrorMessage:  err.Error(),
			FailureReason: "hashing_failed",
		})
		return fmt.Errorf("failed to hash MPIN: %w", err)
	}

	// ✅ Admin bypass - ignore lock status, update directly
	if err := s.mpinRepo.UpdateMPIN(ctx, req.UserID, hashResult.Hash, hashResult.Salt, hashResult.PepperVersion); err != nil {
		s.logMPINEvent(ctx, &models.MPINLogEvent{
			LogEnvelope: models.LogEnvelope{
				EventID:     uuid.New().String(),
				EventType:   string(models.LogEventTypeMPIN),
				ServiceName: "auth-service",
				Timestamp:   time.Now(),
				Environment: s.config.Environment,
				Version:     ServiceVersion, // ✅ FIXED: Use constant

				Level:   string(models.LogLevelError),
				Message: "Failed to update MPIN in repository for admin change",
			},
			UserID:        req.UserID.String(),
			Status:        "admin_change_failed",
			ErrorCode:     "REPOSITORY_UPDATE_FAILED",
			ErrorMessage:  err.Error(),
			FailureReason: "repository_update_failed",
		})
		return fmt.Errorf("failed to update MPIN: %w", err)
	}

	// ✅ Also unlock if locked
	_ = s.mpinRepo.UnlockMPIN(ctx, req.UserID)

	if s.distCache != nil {
		cacheKey := fmt.Sprintf("mpin:%s", req.UserID.String())
		_ = s.distCache.Delete(ctx, cacheKey)
	}

	// ✅ NEW: Log successful admin MPIN change
	s.logMPINEvent(ctx, &models.MPINLogEvent{
		LogEnvelope: models.LogEnvelope{
			EventID:     uuid.New().String(),
			EventType:   string(models.LogEventTypeMPIN),
			ServiceName: "auth-service",
			Timestamp:   time.Now(),
			Environment: s.config.Environment,
			Version:     ServiceVersion, // ✅ FIXED: Use constant

			Level:   string(models.LogLevelWarning),
			Message: "MPIN changed by admin successfully",
		},
		UserID:   req.UserID.String(),
		Status:   "admin_change_completed",
		Duration: int64(time.Since(startTime).Milliseconds()),
	})

	s.logger.Warn("MPIN changed by admin",
		util.String("user_id", req.UserID.String()),
		util.String("admin_id", req.AdminID.String()),
		util.String("reason", req.Reason),
		util.Duration("duration", time.Since(startTime)),
	)

	return nil
}

// ResetMPIN resets user's MPIN (admin operation) with Kafka logging
func (s *MPINService) ResetMPIN(ctx context.Context, req *MPINResetRequest) error {
	startTime := time.Now()

	// ✅ NEW: Log MPIN reset attempt
	s.logMPINEvent(ctx, &models.MPINLogEvent{
		LogEnvelope: models.LogEnvelope{
			EventID:     uuid.New().String(),
			EventType:   string(models.LogEventTypeMPIN),
			ServiceName: "auth-service",
			Timestamp:   time.Now(),
			Environment: s.config.Environment,
			Version:     ServiceVersion, // ✅ FIXED: Use constant

			Level:   string(models.LogLevelInfo),
			Message: "MPIN reset initiated",
		},
		UserID: req.UserID.String(),
		Status: "reset_initiated",
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
				Version:     ServiceVersion, // ✅ FIXED: Use constant

				Level:   string(models.LogLevelWarning),
				Message: "MPIN not found for reset",
			},
			UserID:        req.UserID.String(),
			Status:        "reset_failed",
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
				Version:     ServiceVersion, // ✅ FIXED: Use constant

				Level:   string(models.LogLevelError),
				Message: "Failed to unlock MPIN for reset",
			},
			UserID:        req.UserID.String(),
			Status:        "reset_failed",
			ErrorCode:     "UNLOCK_FAILED",
			ErrorMessage:  err.Error(),
			FailureReason: "unlock_failed",
		})
		return fmt.Errorf("failed to unlock MPIN: %w", err)
	}

	if s.distCache != nil {
		cacheKey := fmt.Sprintf("mpin:%s", req.UserID.String())
		_ = s.distCache.Delete(ctx, cacheKey)
	}

	// ✅ NEW: Log successful MPIN reset
	s.logMPINEvent(ctx, &models.MPINLogEvent{
		LogEnvelope: models.LogEnvelope{
			EventID:     uuid.New().String(),
			EventType:   string(models.LogEventTypeMPIN),
			ServiceName: "auth-service",
			Timestamp:   time.Now(),
			Environment: s.config.Environment,
			Version:     ServiceVersion, // ✅ FIXED: Use constant

			Level:   string(models.LogLevelWarning),
			Message: "MPIN reset by admin completed",
		},
		UserID:   req.UserID.String(),
		Status:   "reset_completed",
		Duration: int64(time.Since(startTime).Milliseconds()),
	})

	s.logger.Warn("MPIN reset by admin",
		util.String("user_id", req.UserID.String()),
		util.String("reset_by", req.ResetBy.String()),
		util.String("reason", req.Reason),
		util.Duration("duration", time.Since(startTime)),
	)

	return nil
}

// UnlockMPIN unlocks a locked MPIN with Kafka logging
func (s *MPINService) UnlockMPIN(ctx context.Context, userID uuid.UUID) error {
	// ✅ NEW: Log MPIN unlock attempt
	s.logMPINEvent(ctx, &models.MPINLogEvent{
		LogEnvelope: models.LogEnvelope{
			EventID:     uuid.New().String(),
			EventType:   string(models.LogEventTypeMPIN),
			ServiceName: "auth-service",
			Timestamp:   time.Now(),
			Environment: s.config.Environment,
			Version:     ServiceVersion, // ✅ FIXED: Use constant

			Level:   string(models.LogLevelInfo),
			Message: "MPIN unlock initiated",
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
				Version:     ServiceVersion, // ✅ FIXED: Use constant

				Level:   string(models.LogLevelError),
				Message: "Failed to unlock MPIN",
			},
			UserID:        userID.String(),
			Status:        "unlock_failed",
			ErrorCode:     "UNLOCK_FAILED",
			ErrorMessage:  err.Error(),
			FailureReason: "unlock_failed",
		})
		return fmt.Errorf("failed to unlock MPIN: %w", err)
	}

	if s.distCache != nil {
		cacheKey := fmt.Sprintf("mpin:%s", userID.String())
		_ = s.distCache.Delete(ctx, cacheKey)
	}

	// ✅ NEW: Log successful MPIN unlock
	s.logMPINEvent(ctx, &models.MPINLogEvent{
		LogEnvelope: models.LogEnvelope{
			EventID:     uuid.New().String(),
			EventType:   string(models.LogEventTypeMPIN),
			ServiceName: "auth-service",
			Timestamp:   time.Now(),
			Environment: s.config.Environment,
			Version:     ServiceVersion, // ✅ FIXED: Use constant

			Level:   string(models.LogLevelInfo),
			Message: "MPIN unlocked successfully",
		},
		UserID: userID.String(),
		Status: "unlock_completed",
	})

	return nil
}

// GetMPINStatus gets MPIN status for a user
func (s *MPINService) GetMPINStatus(ctx context.Context, userID uuid.UUID) (*MPINStatus, error) {
	mpinCred, err := s.mpinRepo.GetMPINByUserID(ctx, userID)
	if err != nil {
		if err.Error() == "MPIN not found for user: "+userID.String() {
			return &MPINStatus{
				UserID: userID,
				Exists: false,
			}, nil
		}
		return nil, err
	}

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

// UpdateDeviceBinding updates device binding for MPIN
func (s *MPINService) UpdateDeviceBinding(ctx context.Context, userID uuid.UUID, deviceID string) error {
	if err := s.mpinRepo.UpdateMPINDeviceBinding(ctx, userID, deviceID); err != nil {
		return fmt.Errorf("failed to update device binding: %w", err)
	}

	if s.distCache != nil {
		cacheKey := fmt.Sprintf("mpin:%s", userID.String())
		_ = s.distCache.Delete(ctx, cacheKey)
	}

	return nil
}

// GetMPINsByDevice gets all MPINs associated with a device
func (s *MPINService) GetMPINsByDevice(ctx context.Context, deviceID string) ([]*models.MPINCredential, error) {
	return s.mpinRepo.GetMPINsByDevice(ctx, deviceID)
}

// GetLockedMPINs gets locked MPIN credentials
func (s *MPINService) GetLockedMPINs(ctx context.Context, limit int) ([]*models.MPINCredential, error) {
	return s.mpinRepo.GetLockedMPINs(ctx, limit)
}

// CleanupExpiredLocks cleans up expired MPIN locks
func (s *MPINService) CleanupExpiredLocks(ctx context.Context) (int, error) {
	return s.mpinRepo.CleanupUnlockedMPINs(ctx)
}

// GetMPINStats gets MPIN service statistics
func (s *MPINService) GetMPINStats(ctx context.Context) (map[string]interface{}, error) {
	stats, err := s.mpinRepo.GetRepositoryStats(ctx)
	if err != nil {
		return nil, err
	}

	stats["service_constants"] = map[string]interface{}{
		"min_length":            MPINMinLength,
		"max_length":            MPINMaxLength,
		"max_attempts":          MPINMaxAttempts,
		"lock_duration_seconds": int(MPINLockDuration.Seconds()),
	}

	return stats, nil
}

// HealthCheck performs a health check on the service
func (s *MPINService) HealthCheck(ctx context.Context) error {
	return s.mpinRepo.HealthCheck(ctx)
}

// ✅ NEW: ForgotMPIN allows user to reset MPIN on trusted device with Kafka logging
func (s *MPINService) ForgotMPIN(ctx context.Context, req *MPINForgotRequest) error {
	startTime := time.Now()

	// ✅ NEW: Log forgot MPIN attempt
	s.logMPINEvent(ctx, &models.MPINLogEvent{
		LogEnvelope: models.LogEnvelope{
			EventID:     uuid.New().String(),
			EventType:   string(models.LogEventTypeMPIN),
			ServiceName: "auth-service",
			Timestamp:   time.Now(),
			Environment: s.config.Environment,
			Version:     ServiceVersion, // ✅ FIXED: Use constant

			Level:   string(models.LogLevelInfo),
			Message: "Forgot MPIN flow initiated",
		},
		UserID:   req.UserID.String(),
		Status:   "forgot_initiated",
		DeviceID: req.DeviceID,
	})

	if err := s.validateMPIN(req.NewMPIN); err != nil {
		s.logMPINEvent(ctx, &models.MPINLogEvent{
			LogEnvelope: models.LogEnvelope{
				EventID:     uuid.New().String(),
				EventType:   string(models.LogEventTypeMPIN),
				ServiceName: "auth-service",
				Timestamp:   time.Now(),
				Environment: s.config.Environment,
				Version:     ServiceVersion, // ✅ FIXED: Use constant

				Level:   string(models.LogLevelError),
				Message: "New MPIN validation failed for forgot flow",
			},
			UserID:        req.UserID.String(),
			Status:        "forgot_failed",
			DeviceID:      req.DeviceID,
			ErrorCode:     "VALIDATION_FAILED",
			ErrorMessage:  err.Error(),
			FailureReason: "new_mpin_validation_failed",
		})
		return err
	}

	// Check if MPIN exists
	_, err := s.mpinRepo.GetMPINByUserID(ctx, req.UserID)
	if err != nil {
		s.logMPINEvent(ctx, &models.MPINLogEvent{
			LogEnvelope: models.LogEnvelope{
				EventID:     uuid.New().String(),
				EventType:   string(models.LogEventTypeMPIN),
				ServiceName: "auth-service",
				Timestamp:   time.Now(),
				Environment: s.config.Environment,
				Version:     ServiceVersion, // ✅ FIXED: Use constant

				Level:   string(models.LogLevelWarning),
				Message: "MPIN not found for forgot flow",
			},
			UserID:        req.UserID.String(),
			Status:        "forgot_failed",
			DeviceID:      req.DeviceID,
			ErrorCode:     "MPIN_NOT_FOUND",
			FailureReason: "mpin_not_found",
		})
		return ErrMPINNotFound
	}

	// Get device trust level
	deviceTrust, err := s.deviceTrustRepo.GetDeviceTrustLevel(ctx, req.UserID, req.DeviceID)
	if err != nil {
		deviceTrust = &models.DeviceTrustLevel{
			UserID:      req.UserID,
			DeviceID:    req.DeviceID,
			TrustStatus: models.TrustStatusUntrusted,
		}
	}

	// Check if device is blocked
	if deviceTrust.IsBlocked {
		s.logMPINEvent(ctx, &models.MPINLogEvent{
			LogEnvelope: models.LogEnvelope{
				EventID:     uuid.New().String(),
				EventType:   string(models.LogEventTypeMPIN),
				ServiceName: "auth-service",
				Timestamp:   time.Now(),
				Environment: s.config.Environment,
				Version:     ServiceVersion, // ✅ FIXED: Use constant

				Level:   string(models.LogLevelWarning),
				Message: "Device blocked for forgot MPIN",
			},
			UserID:        req.UserID.String(),
			Status:        "forgot_failed",
			DeviceID:      req.DeviceID,
			ErrorCode:     "DEVICE_BLOCKED",
			FailureReason: "device_blocked",
		})
		return fmt.Errorf("device is blocked for security reasons")
	}

	// Determine if device is trusted
	isTrustedDevice := deviceTrust.TrustStatus == models.TrustStatusPrimary ||
		deviceTrust.TrustStatus == models.TrustStatusTrusted

	// ✅ KEY CHANGE: For untrusted devices, require OTP verification
	if !isTrustedDevice {
		s.logMPINEvent(ctx, &models.MPINLogEvent{
			LogEnvelope: models.LogEnvelope{
				EventID:     uuid.New().String(),
				EventType:   string(models.LogEventTypeMPIN),
				ServiceName: "auth-service",
				Timestamp:   time.Now(),
				Environment: s.config.Environment,
				Version:     ServiceVersion, // ✅ FIXED: Use constant

				Level:   string(models.LogLevelWarning),
				Message: "OTP verification required for untrusted device in forgot MPIN",
			},
			UserID:        req.UserID.String(),
			Status:        "forgot_failed",
			DeviceID:      req.DeviceID,
			ErrorCode:     "OTP_VERIFICATION_REQUIRED",
			FailureReason: "otp_verification_required",
		})
		return fmt.Errorf("OTP verification required for untrusted device - use VerifyForgotMPINOTP endpoint")
	}

	// Proceed only for trusted devices
	hashResult, err := s.hasher.HashMPIN(req.NewMPIN)
	if err != nil {
		s.logMPINEvent(ctx, &models.MPINLogEvent{
			LogEnvelope: models.LogEnvelope{
				EventID:     uuid.New().String(),
				EventType:   string(models.LogEventTypeMPIN),
				ServiceName: "auth-service",
				Timestamp:   time.Now(),
				Environment: s.config.Environment,
				Version:     ServiceVersion, // ✅ FIXED: Use constant

				Level:   string(models.LogLevelError),
				Message: "Failed to hash MPIN for forgot flow",
			},
			UserID:        req.UserID.String(),
			Status:        "forgot_failed",
			DeviceID:      req.DeviceID,
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
				Version:     ServiceVersion, // ✅ FIXED: Use constant

				Level:   string(models.LogLevelError),
				Message: "Failed to update MPIN for forgot flow",
			},
			UserID:        req.UserID.String(),
			Status:        "forgot_failed",
			DeviceID:      req.DeviceID,
			ErrorCode:     "REPOSITORY_UPDATE_FAILED",
			ErrorMessage:  err.Error(),
			FailureReason: "repository_update_failed",
		})
		return fmt.Errorf("failed to update MPIN: %w", err)
	}

	_ = s.mpinRepo.UnlockMPIN(ctx, req.UserID)

	if s.distCache != nil {
		cacheKey := fmt.Sprintf("mpin:%s", req.UserID.String())
		_ = s.distCache.Delete(ctx, cacheKey)
	}

	// ✅ NEW: Log successful forgot MPIN
	s.logMPINEvent(ctx, &models.MPINLogEvent{
		LogEnvelope: models.LogEnvelope{
			EventID:     uuid.New().String(),
			EventType:   string(models.LogEventTypeMPIN),
			ServiceName: "auth-service",
			Timestamp:   time.Now(),
			Environment: s.config.Environment,
			Version:     ServiceVersion, // ✅ FIXED: Use constant

			Level:   string(models.LogLevelInfo),
			Message: "MPIN reset via forgot flow completed",
		},
		UserID:      req.UserID.String(),
		Status:      "forgot_completed",
		DeviceID:    req.DeviceID,
		DeviceTrust: string(deviceTrust.TrustStatus),
		Duration:    int64(time.Since(startTime).Milliseconds()),
	})

	s.logger.Info("MPIN reset via forgot flow on trusted device",
		util.String("user_id", req.UserID.String()),
		util.String("device_id", req.DeviceID),
		util.String("device_trust_status", string(deviceTrust.TrustStatus)),
		util.Duration("duration", time.Since(startTime)),
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

// Add to your MPIN service
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
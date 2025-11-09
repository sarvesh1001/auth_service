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
	"sync"
	"time"
	"github.com/google/uuid"
	"go.uber.org/zap"
)

var (
	ErrAdminMPINNotFound      = errors.New("admin MPIN not found")
	ErrAdminMPINInvalid       = errors.New("invalid admin MPIN")
	ErrAdminMPINLocked        = errors.New("admin MPIN is locked")
	ErrAdminMPINAlreadyExists = errors.New("admin MPIN already exists")
	ErrAdminMPINTooWeak       = errors.New("admin MPIN is too weak")
	ErrAdminDeviceNotBound    = errors.New("device not bound to admin MPIN")
)

const (
	AdminMPINMinLength    = 6
	AdminMPINMaxLength    = 8
	AdminMPINLockDuration = 30 * time.Minute
	AdminMPINMaxAttempts  = 5
	AdminServiceVersion   = "v1.0.0"
)

// Admin MPIN request/response structures
type AdminMPINSetupRequest struct {
	AdminID  uuid.UUID `json:"admin_id" validate:"required"`
	MPIN     string    `json:"mpin" validate:"required,min=6,max=8"`
	DeviceID string    `json:"device_id" validate:"required"`
}

type AdminMPINVerifyRequest struct {
	AdminID  uuid.UUID `json:"admin_id" validate:"required"`
	MPIN     string    `json:"mpin" validate:"required"`
	DeviceID string    `json:"device_id" validate:"required"`
}

type AdminMPINVerifyResult struct {
	Verified       bool       `json:"verified"`
	FailedAttempts int        `json:"failed_attempts"`
	RemainingTries int        `json:"remaining_tries"`
	LockedUntil    *time.Time `json:"locked_until,omitempty"`
	Message        string     `json:"message"`
}

type AdminMPINChangeRequest struct {
	AdminID    uuid.UUID `json:"admin_id" validate:"required"`
	CurrentMPIN string   `json:"current_mpin" validate:"required"`
	NewMPIN    string    `json:"new_mpin" validate:"required,min=6,max=8"`
	DeviceID   string    `json:"device_id" validate:"required"`
}

type AdminMPINResetRequest struct {
	AdminID uuid.UUID `json:"admin_id" validate:"required"`
	ResetBy uuid.UUID `json:"reset_by" validate:"required"`
	Reason  string    `json:"reason" validate:"required"`
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
}

// Admin Forgot MPIN structures
type AdminMPINForgotRequest struct {
	AdminID  uuid.UUID `json:"admin_id" validate:"required"`
	DeviceID string    `json:"device_id" validate:"required"`
	NewMPIN  string    `json:"new_mpin" validate:"required,min=6,max=8"`
}

type AdminMPINForgotWithOTPRequest struct {
	AdminID  uuid.UUID `json:"admin_id" validate:"required"`
	DeviceID string    `json:"device_id" validate:"required"`
	NewMPIN  string    `json:"new_mpin" validate:"required,min=6,max=8"`
	OTPCode  string    `json:"otp_code" validate:"required,len=6"`
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

// logAdminMPINEvent helper method
func (s *AdminMPINService) logAdminMPINEvent(ctx context.Context, event *models.MPINLogEvent) {
	if s.logProducer != nil {
		_ = s.logProducer.ProduceMPINEvent(ctx, event)
	}
}

func (s *AdminMPINService) SetDistributedCache(distCache *DistributedCache) {
	s.distCache = distCache
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

// SetupAdminMPIN creates a new admin MPIN
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
		UserID:   req.AdminID.String(),
		Status:   "admin_setup_initiated",
		DeviceID: req.DeviceID,
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
				Message:     "Admin not found for MPIN setup",
			},
			UserID:        req.AdminID.String(),
			Status:        "admin_setup_failed",
			DeviceID:      req.DeviceID,
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
			ErrorCode:     "REPOSITORY_CREATE_FAILED",
			ErrorMessage:  err.Error(),
			FailureReason: "repository_create_failed",
		})
		return fmt.Errorf("failed to create admin MPIN: %w", err)
	}

	if err := s.deviceTrustRepo.MarkAdminSuccessfulLogin(ctx, req.AdminID, req.DeviceID, "", ""); err != nil {
		s.logger.Warn("Failed to set admin device trust level",
			util.ErrorField(err),
			util.String("admin_id", req.AdminID.String()),
			util.String("device_id", req.DeviceID),
		)
	}

	s.invalidateAdminMPINCache(ctx, req.AdminID) // ✅ Added ctx parameter

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
		UserID:   req.AdminID.String(),
		Status:   "admin_setup_completed",
		DeviceID: req.DeviceID,
		Duration: int64(time.Since(startTime).Milliseconds()),
	})

	s.logger.Info("Admin MPIN setup completed",
		util.String("admin_id", req.AdminID.String()),
		util.String("device_id", req.DeviceID),
		util.Duration("duration", time.Since(startTime)),
	)
	return nil
}

// VerifyAdminMPIN verifies an admin MPIN
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
		UserID:   req.AdminID.String(),
		Status:   "admin_verification_initiated",
		DeviceID: req.DeviceID,
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
			Status:        "admin_verification_failed",
			DeviceID:      req.DeviceID,
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
			UserID:   req.AdminID.String(),
			Status:   "admin_device_mismatch",
			DeviceID: req.DeviceID,
		})
		s.logger.Warn("Device mismatch during admin MPIN verification",
			util.String("admin_id", req.AdminID.String()),
			util.String("expected_device", mpinCred.DeviceID),
			util.String("provided_device", req.DeviceID),
		)
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

		if err := s.deviceTrustRepo.MarkAdminSuccessfulLogin(ctx, req.AdminID, req.DeviceID, "", ""); err != nil {
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
		util.Duration("duration", time.Since(startTime)),
	)

	return result, nil
}

// ChangeAdminMPIN changes an admin's MPIN
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
		UserID:   req.AdminID.String(),
		Status:   "admin_change_initiated",
		DeviceID: req.DeviceID,
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
				Message:     "New admin MPIN validation failed",
			},
			UserID:        req.AdminID.String(),
			Status:        "admin_change_failed",
			DeviceID:      req.DeviceID,
			ErrorCode:     "VALIDATION_FAILED",
			ErrorMessage:  err.Error(),
			FailureReason: "new_admin_mpin_validation_failed",
		})
		return err
	}

	verifyReq := &AdminMPINVerifyRequest{
		AdminID:  req.AdminID,
		MPIN:     req.CurrentMPIN,
		DeviceID: req.DeviceID,
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

	s.invalidateAdminMPINCache(ctx, req.AdminID) // ✅ Added ctx parameter

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
		UserID:   req.AdminID.String(),
		Status:   "admin_change_completed",
		DeviceID: req.DeviceID,
		Duration: int64(time.Since(startTime).Milliseconds()),
	})

	s.logger.Info("Admin MPIN changed successfully",
		util.String("admin_id", req.AdminID.String()),
		util.String("device_id", req.DeviceID),
		util.Duration("duration", time.Since(startTime)),
	)

	return nil
}

// ChangeAdminMPINByAdmin changes an admin's MPIN by another admin
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
		UserID: req.AdminID.String(),
		Status: "admin_change_by_admin_initiated",
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
			ErrorCode:     "REPOSITORY_UPDATE_FAILED",
			ErrorMessage:  err.Error(),
			FailureReason: "repository_update_failed",
		})
		return fmt.Errorf("failed to update admin MPIN: %w", err)
	}

	_ = s.mpinRepo.UnlockAdminMPIN(ctx, req.AdminID)

	s.invalidateAdminMPINCache(ctx, req.AdminID) // ✅ Added ctx parameter

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
		UserID:   req.AdminID.String(),
		Status:   "admin_change_by_admin_completed",
		Duration: int64(time.Since(startTime).Milliseconds()),
	})

	s.logger.Warn("Admin MPIN changed by admin",
		util.String("admin_id", req.AdminID.String()),
		util.String("changed_by", req.ChangedBy.String()),
		util.String("reason", req.Reason),
		util.Duration("duration", time.Since(startTime)),
	)

	return nil
}

// ResetAdminMPIN resets admin MPIN
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
		UserID: req.AdminID.String(),
		Status: "admin_reset_initiated",
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
			ErrorCode:     "UNLOCK_FAILED",
			ErrorMessage:  err.Error(),
			FailureReason: "unlock_failed",
		})
		return fmt.Errorf("failed to unlock admin MPIN: %w", err)
	}

	s.invalidateAdminMPINCache(ctx, req.AdminID) // ✅ Added ctx parameter

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
		UserID:   req.AdminID.String(),
		Status:   "admin_reset_completed",
		Duration: int64(time.Since(startTime).Milliseconds()),
	})

	s.logger.Warn("Admin MPIN reset by admin",
		util.String("admin_id", req.AdminID.String()),
		util.String("reset_by", req.ResetBy.String()),
		util.String("reason", req.Reason),
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

// GetAdminMPINStatus gets admin MPIN status
func (s *AdminMPINService) GetAdminMPINStatus(ctx context.Context, adminID uuid.UUID) (*AdminMPINStatus, error) {
	mpinCred, err := s.mpinRepo.GetAdminMPINByAdminID(ctx, adminID)
	if err != nil {
		if err.Error() == "MPIN not found for admin: "+adminID.String() {
			return &AdminMPINStatus{
				AdminID: adminID,
				Exists:  false,
			}, nil
		}
		return nil, err
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

// UpdateAdminMPINDeviceBinding updates device binding for admin MPIN
func (s *AdminMPINService) UpdateAdminMPINDeviceBinding(ctx context.Context, adminID uuid.UUID, deviceID string) error {
	if err := s.mpinRepo.UpdateAdminMPINDeviceBinding(ctx, adminID, deviceID); err != nil {
		return fmt.Errorf("failed to update admin device binding: %w", err)
	}

	s.invalidateAdminMPINCache(ctx, adminID)

	return nil
}

// GetAdminMPINsByDevice gets all admin MPINs associated with a device
func (s *AdminMPINService) GetAdminMPINsByDevice(ctx context.Context, deviceID string) ([]*models.MPINCredential, error) {
	return s.mpinRepo.GetAdminMPINsByDevice(ctx, deviceID)
}

// GetAdminLockedMPINs gets locked admin MPIN credentials
func (s *AdminMPINService) GetAdminLockedMPINs(ctx context.Context, limit int) ([]*models.MPINCredential, error) {
	return s.mpinRepo.GetAdminLockedMPINs(ctx, limit)
}

// CleanupAdminExpiredLocks cleans up expired admin MPIN locks
func (s *AdminMPINService) CleanupAdminExpiredLocks(ctx context.Context) (int, error) {
	return s.mpinRepo.CleanupAdminUnlockedMPINs(ctx)
}

// GetAdminMPINStats gets admin MPIN service statistics
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
	}

	return stats, nil
}

// HealthCheck performs a health check on the admin MPIN service
func (s *AdminMPINService) HealthCheck(ctx context.Context) error {
	return s.mpinRepo.HealthCheck(ctx)
}

// SendForgotAdminMPINOTP sends OTP for forgot admin MPIN flow
func (s *AdminMPINService) SendForgotAdminMPINOTP(ctx context.Context, adminID uuid.UUID) (string, error) {
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
			Message:     "Forgot admin MPIN OTP send initiated",
		},
		UserID: adminID.String(),
		Status: "admin_forgot_otp_initiated",
	})

	admin, err := s.adminRepo.GetAdminByID(ctx, adminID)
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
				Message:     "Admin not found for forgot MPIN OTP",
			},
			UserID:        adminID.String(),
			Status:        "admin_forgot_otp_failed",
			ErrorCode:     "ADMIN_NOT_FOUND",
			FailureReason: "admin_not_found",
		})
		return "", fmt.Errorf("admin not found: %w", err)
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
				Message:     "Inactive admin attempted forgot MPIN OTP",
			},
			UserID:        adminID.String(),
			Status:        "admin_forgot_otp_failed",
			ErrorCode:     "ADMIN_INACTIVE",
			FailureReason: "admin_inactive",
		})
		return "", fmt.Errorf("admin account is inactive")
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
				Message:     "Failed to decrypt phone number for forgot admin MPIN OTP",
			},
			UserID:        adminID.String(),
			Status:        "admin_forgot_otp_failed",
			ErrorCode:     "PHONE_DECRYPTION_FAILED",
			ErrorMessage:  err.Error(),
			FailureReason: "phone_decryption_failed",
		})
		s.logger.Error("Failed to decrypt admin phone number",
			util.ErrorField(err),
			util.String("admin_id", adminID.String()),
		)
		return "", fmt.Errorf("failed to decrypt admin phone number: %w", err)
	}

	otpReq := &OTPSendRequest{
		PhoneNumber: phoneNumber,
		Purpose:     "forgot_admin_mpin",
		DeviceID:    "",
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
				Message:     "OTP service error for forgot admin MPIN",
			},
			UserID:        adminID.String(),
			Status:        "admin_forgot_otp_failed",
			ErrorCode:     "OTP_SEND_FAILED",
			ErrorMessage:  err.Error(),
			FailureReason: "otp_send_failed",
		})
		s.logger.Error("OTP service error for admin",
			util.ErrorField(err),
			util.String("admin_id", adminID.String()),
		)
		return "", err
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
				Message:     "OTP send failed for forgot admin MPIN",
			},
			UserID:        adminID.String(),
			Status:        "admin_forgot_otp_failed",
			ErrorCode:     "OTP_SEND_FAILED",
			ErrorMessage:  otpResp.Message,
			FailureReason: "otp_send_failed",
		})
		return "", fmt.Errorf("failed to send OTP: %s", otpResp.Message)
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
			Message:     "Forgot admin MPIN OTP sent successfully",
		},
		UserID:   adminID.String(),
		Status:   "admin_forgot_otp_sent",
		Duration: int64(time.Since(startTime).Milliseconds()),
	})

	s.logger.Info("Forgot admin MPIN OTP sent successfully",
		util.String("admin_id", adminID.String()),
		util.String("phone", phoneNumber[len(phoneNumber)-4:]+"****"),
	)

	return "", nil
}

// VerifyForgotAdminMPINOTP verifies OTP and resets admin MPIN
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
		UserID:   req.AdminID.String(),
		Status:   "admin_forgot_otp_verification_initiated",
		DeviceID: req.DeviceID,
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
				Message:     "MPIN validation failed for forgot admin MPIN OTP",
			},
			UserID:        req.AdminID.String(),
			Status:        "admin_forgot_otp_verification_failed",
			DeviceID:      req.DeviceID,
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
			ErrorCode:     "PHONE_DECRYPTION_FAILED",
			ErrorMessage:  err.Error(),
			FailureReason: "phone_decryption_failed",
		})
		s.logger.Error("Failed to decrypt admin phone number",
			util.ErrorField(err),
			util.String("admin_id", req.AdminID.String()),
		)
		return fmt.Errorf("failed to decrypt admin phone number: %w", err)
	}

	otpVerifyReq := &OTPVerifyRequest{
		PhoneNumber: phoneNumber,
		OTP:         req.OTPCode,
		Purpose:     "forgot_admin_mpin",
	}

	otpResp, err := s.otpService.VerifyOTP(ctx, otpVerifyReq)
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
				Message:     "OTP verification failed for forgot admin MPIN",
			},
			UserID:        req.AdminID.String(),
			Status:        "admin_forgot_otp_verification_failed",
			DeviceID:      req.DeviceID,
			ErrorCode:     "OTP_VERIFICATION_FAILED",
			ErrorMessage:  err.Error(),
			FailureReason: "otp_verification_failed",
		})
		s.logger.Warn("OTP verification failed for admin",
			util.ErrorField(err),
			util.String("admin_id", req.AdminID.String()),
		)
		return fmt.Errorf("invalid OTP code")
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
				Level:       string(models.LogLevelWarning),
				Message:     "Invalid OTP code for forgot admin MPIN",
			},
			UserID:        req.AdminID.String(),
			Status:        "admin_forgot_otp_verification_failed",
			DeviceID:      req.DeviceID,
			ErrorCode:     "INVALID_OTP",
			FailureReason: "invalid_otp",
		})
		return fmt.Errorf("invalid OTP code")
	}

	deviceTrust, err := s.deviceTrustRepo.GetAdminDeviceTrustLevel(ctx, req.AdminID, req.DeviceID)
	if err != nil {
		deviceTrust = &models.DeviceTrustLevel{
			UserID:      req.AdminID,
			DeviceID:    req.DeviceID,
			TrustStatus: models.TrustStatusUntrusted,
		}
	}

	primaryDevice, _ := s.deviceTrustRepo.GetAdminPrimaryDevice(ctx, req.AdminID)

	isTrustedDevice := deviceTrust.TrustStatus == models.TrustStatusPrimary ||
		deviceTrust.TrustStatus == models.TrustStatusTrusted

	shouldWipeData := !isTrustedDevice && (primaryDevice != nil && primaryDevice.DeviceID != req.DeviceID)

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
			ErrorCode:     "HASHING_FAILED",
			ErrorMessage:  err.Error(),
			FailureReason: "hashing_failed",
		})
		s.logger.Error("Failed to hash admin MPIN",
			util.ErrorField(err),
			util.String("admin_id", req.AdminID.String()),
		)
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
			ErrorCode:     "MPIN_UPDATE_FAILED",
			ErrorMessage:  err.Error(),
			FailureReason: "mpin_update_failed",
		})
		s.logger.Error("Failed to update admin MPIN",
			util.ErrorField(err),
			util.String("admin_id", req.AdminID.String()),
		)
		return fmt.Errorf("failed to update admin MPIN: %w", err)
	}

	_ = s.mpinRepo.UnlockAdminMPIN(ctx, req.AdminID)

	if shouldWipeData {
		s.logAdminMPINEvent(ctx, &models.MPINLogEvent{
			LogEnvelope: models.LogEnvelope{
				EventID:     uuid.New().String(),
				EventType:   string(models.LogEventTypeMPIN),
				ServiceName: "auth-service",
				Timestamp:   time.Now(),
				Environment: s.config.Environment,
				Version:     AdminServiceVersion,
				Level:       string(models.LogLevelWarning),
				Message:     "Data wipe triggered for forgot admin MPIN on untrusted device",
			},
			UserID:        req.AdminID.String(),
			Status:        "admin_data_wipe_triggered",
			DeviceID:      req.DeviceID,
			FailureReason: "untrusted_device_forgot_admin_mpin",
		})

		s.logger.Warn("Data wipe triggered - forgot admin MPIN on new device",
			util.String("admin_id", req.AdminID.String()),
			util.String("device_id", req.DeviceID),
			util.String("trust_status", string(deviceTrust.TrustStatus)),
		)

		deletion := &models.UserDataDeletion{
			DeletionID:          uuid.New(),
			UserID:              req.AdminID,
			DeviceID:            req.DeviceID,
			Reason:              "forgot_admin_mpin_new_device",
			DeletedAt:           time.Now(),
			DataWipedCategories: []string{"session_tokens", "saved_data", "preferences"},
		}

		if err := s.deviceTrustRepo.RecordAdminDataDeletion(ctx, deletion); err != nil {
			s.logger.Error("Failed to record admin data deletion",
				util.ErrorField(err),
				util.String("admin_id", req.AdminID.String()),
			)
		}
	}

	if err := s.deviceTrustRepo.SetAdminDeviceTrustLevel(ctx, req.AdminID, req.DeviceID, models.TrustStatusTrusted); err != nil {
		s.logger.Warn("Failed to set admin device trust level",
			util.ErrorField(err),
			util.String("admin_id", req.AdminID.String()),
		)
	}

	s.invalidateAdminMPINCache(ctx, req.AdminID) // ✅ Added ctx parameter

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
		DeviceTrust: string(deviceTrust.TrustStatus),
		Duration:    int64(time.Since(startTime).Milliseconds()),
	})

	s.logger.Info("Admin MPIN reset via forgot with OTP verification",
		util.String("admin_id", req.AdminID.String()),
		util.String("device_id", req.DeviceID),
		util.Bool("data_wiped", shouldWipeData),
		util.String("trust_status", string(deviceTrust.TrustStatus)),
	)

	return nil
}

// ForgotAdminMPIN allows admin to reset MPIN on trusted device
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
		UserID:   req.AdminID.String(),
		Status:   "admin_forgot_initiated",
		DeviceID: req.DeviceID,
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
				Message:     "New MPIN validation failed for forgot admin flow",
			},
			UserID:        req.AdminID.String(),
			Status:        "admin_forgot_failed",
			DeviceID:      req.DeviceID,
			ErrorCode:     "VALIDATION_FAILED",
			ErrorMessage:  err.Error(),
			FailureReason: "new_admin_mpin_validation_failed",
		})
		return err
	}

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
				Message:     "Admin MPIN not found for forgot flow",
			},
			UserID:        req.AdminID.String(),
			Status:        "admin_forgot_failed",
			DeviceID:      req.DeviceID,
			ErrorCode:     "ADMIN_MPIN_NOT_FOUND",
			FailureReason: "admin_mpin_not_found",
		})
		return ErrAdminMPINNotFound
	}

	deviceTrust, err := s.deviceTrustRepo.GetAdminDeviceTrustLevel(ctx, req.AdminID, req.DeviceID)
	if err != nil {
		deviceTrust = &models.DeviceTrustLevel{
			UserID:      req.AdminID,
			DeviceID:    req.DeviceID,
			TrustStatus: models.TrustStatusUntrusted,
		}
	}

	if deviceTrust.IsBlocked {
		s.logAdminMPINEvent(ctx, &models.MPINLogEvent{
			LogEnvelope: models.LogEnvelope{
				EventID:     uuid.New().String(),
				EventType:   string(models.LogEventTypeMPIN),
				ServiceName: "auth-service",
				Timestamp:   time.Now(),
				Environment: s.config.Environment,
				Version:     AdminServiceVersion,
				Level:       string(models.LogLevelWarning),
				Message:     "Device blocked for forgot admin MPIN",
			},
			UserID:        req.AdminID.String(),
			Status:        "admin_forgot_failed",
			DeviceID:      req.DeviceID,
			ErrorCode:     "DEVICE_BLOCKED",
			FailureReason: "device_blocked",
		})
		return fmt.Errorf("device is blocked for security reasons")
	}

	isTrustedDevice := deviceTrust.TrustStatus == models.TrustStatusPrimary ||
		deviceTrust.TrustStatus == models.TrustStatusTrusted

	if !isTrustedDevice {
		s.logAdminMPINEvent(ctx, &models.MPINLogEvent{
			LogEnvelope: models.LogEnvelope{
				EventID:     uuid.New().String(),
				EventType:   string(models.LogEventTypeMPIN),
				ServiceName: "auth-service",
				Timestamp:   time.Now(),
				Environment: s.config.Environment,
				Version:     AdminServiceVersion,
				Level:       string(models.LogLevelWarning),
				Message:     "OTP verification required for untrusted device in forgot admin MPIN",
			},
			UserID:        req.AdminID.String(),
			Status:        "admin_forgot_failed",
			DeviceID:      req.DeviceID,
			ErrorCode:     "OTP_VERIFICATION_REQUIRED",
			FailureReason: "otp_verification_required",
		})
		return fmt.Errorf("OTP verification required for untrusted device - use VerifyForgotAdminMPINOTP endpoint")
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
				Message:     "Failed to hash MPIN for forgot admin flow",
			},
			UserID:        req.AdminID.String(),
			Status:        "admin_forgot_failed",
			DeviceID:      req.DeviceID,
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
				Message:     "Failed to update MPIN for forgot admin flow",
			},
			UserID:        req.AdminID.String(),
			Status:        "admin_forgot_failed",
			DeviceID:      req.DeviceID,
			ErrorCode:     "REPOSITORY_UPDATE_FAILED",
			ErrorMessage:  err.Error(),
			FailureReason: "repository_update_failed",
		})
		return fmt.Errorf("failed to update admin MPIN: %w", err)
	}

	_ = s.mpinRepo.UnlockAdminMPIN(ctx, req.AdminID)

	s.invalidateAdminMPINCache(ctx, req.AdminID) // ✅ Added ctx parameter

	s.logAdminMPINEvent(ctx, &models.MPINLogEvent{
		LogEnvelope: models.LogEnvelope{
			EventID:     uuid.New().String(),
			EventType:   string(models.LogEventTypeMPIN),
			ServiceName: "auth-service",
			Timestamp:   time.Now(),
			Environment: s.config.Environment,
			Version:     AdminServiceVersion,
			Level:       string(models.LogLevelInfo),
			Message:     "Admin MPIN reset via forgot flow completed",
		},
		UserID:      req.AdminID.String(),
		Status:      "admin_forgot_completed",
		DeviceID:    req.DeviceID,
		DeviceTrust: string(deviceTrust.TrustStatus),
		Duration:    int64(time.Since(startTime).Milliseconds()),
	})

	s.logger.Info("Admin MPIN reset via forgot flow on trusted device",
		util.String("admin_id", req.AdminID.String()),
		util.String("device_id", req.DeviceID),
		util.String("device_trust_status", string(deviceTrust.TrustStatus)),
		util.Duration("duration", time.Since(startTime)),
	)

	return nil
}

func (s *AdminMPINService) invalidateAdminMPINCache(ctx context.Context, adminID uuid.UUID) {
    if s.distCache != nil {
        cacheKey := fmt.Sprintf("admin_mpin:%s", adminID.String())
        _ = s.distCache.Delete(ctx, cacheKey)
    }
}



// SetLogProducerService sets Kafka log producer service
func (s *AdminMPINService) SetLogProducerService(logProducer *LogProducerService) {
	s.logProducer = logProducer
}

// DebugHasherStatus returns hasher status for debugging
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
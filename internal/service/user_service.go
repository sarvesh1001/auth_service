package service

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"strings"
	"sync"
	"time"

	"auth-service/internal/bucketing"
	"auth-service/internal/encryption"
	"auth-service/internal/hashing"
	"auth-service/internal/models"
	"auth-service/internal/repository/scylla"
	"auth-service/internal/util"

	lru "github.com/hashicorp/golang-lru/v2"
	"github.com/google/uuid"
	"go.uber.org/zap"
	"golang.org/x/sync/errgroup"
)

var (
	ErrUserNotFound      = errors.New("user not found")
	ErrInvalidInput      = errors.New("invalid input")
	ErrUserAlreadyExists = errors.New("user already exists")
	ErrPermissionDenied  = errors.New("permission denied")
	ErrUserBanned        = errors.New("user is banned")
	ErrUserBlocked       = errors.New("user is blocked")
	ErrKYCRequired       = errors.New("KYC verification required")
)

const (
	DefaultBatchSize   = 100
	MaxBatchSize       = 500
	MaxConcurrentBatch = 10
)

type UserService struct {
	userRepo        scylla.UserRepository
	hasher          *hashing.Hasher
	encryptionMgr   *encryption.EncryptionManager
	bucketingMgr    *bucketing.BucketingManager
	logger          *zap.Logger
	localCache      *lru.Cache[uuid.UUID, *models.User]
	phoneCache      *lru.Cache[string, uuid.UUID]
	distCache       *DistributedCache
	rateLimiter     *RateLimiter
	validationMutex sync.RWMutex
	logProducer     *LogProducerService
}

type RateLimiter struct {
	loginAttempts *sync.Map
	mpinAttempts  *sync.Map
	mutex         sync.RWMutex
}

// ✅ ENHANCED: UserCreateRequest with strict validation - no company fields
type UserCreateRequest struct {
	PhoneNumber       string `json:"phone_number" validate:"required"`
	DeviceID          string `json:"device_id" validate:"required"`
	DeviceFingerprint string `json:"device_fingerprint" validate:"required"`
	DataRegion        string `json:"data_region" validate:"required"`
	ConsentAgreed     bool   `json:"consent_agreed"`
	ConsentVersion    string `json:"consent_version" validate:"required"`
}

type UserUpdateRequest struct {
	DeviceID          *string `json:"device_id,omitempty"`
	DeviceFingerprint *string `json:"device_fingerprint,omitempty"`
	ProfileServiceID  *string `json:"profile_service_id,omitempty"`
	DataRegion        *string `json:"data_region,omitempty"`
}

type KYCUpdateRequest struct {
	UserID     uuid.UUID `json:"user_id" validate:"required"`
	Status     string    `json:"status" validate:"required,oneof=pending verified rejected expired"`
	Level      string    `json:"level" validate:"required,oneof=basic advanced premium"`
	Reason     string    `json:"reason,omitempty"`
	VerifiedBy uuid.UUID `json:"verified_by" validate:"required"`
}

type BanUserRequest struct {
	UserID   uuid.UUID `json:"user_id" validate:"required"`
	BannedBy uuid.UUID `json:"banned_by" validate:"required"`
	Reason   string    `json:"reason" validate:"required,min=10,max=500"`
}

func NewUserService(
	userRepo scylla.UserRepository,
	hasher *hashing.Hasher,
	encryptionMgr *encryption.EncryptionManager,
	bucketingMgr *bucketing.BucketingManager,
	logger *zap.Logger,
) *UserService {
	userCache, _ := lru.New[uuid.UUID, *models.User](1_000_000)
	phoneCache, _ := lru.New[string, uuid.UUID](1_000_000)

	return &UserService{
		userRepo:      userRepo,
		hasher:        hasher,
		encryptionMgr: encryptionMgr,
		bucketingMgr:  bucketingMgr,
		logger:        logger,
		localCache:    userCache,
		phoneCache:    phoneCache,
		rateLimiter:   &RateLimiter{loginAttempts: &sync.Map{}, mpinAttempts: &sync.Map{}},
	}
}

func NewUserServiceWithCache(
	userRepo scylla.UserRepository,
	hasher *hashing.Hasher,
	encryptionMgr *encryption.EncryptionManager,
	bucketingMgr *bucketing.BucketingManager,
	distCache *DistributedCache,
	logger *zap.Logger,
) *UserService {
	service := NewUserService(userRepo, hasher, encryptionMgr, bucketingMgr, logger)
	service.distCache = distCache
	return service
}

func (s *UserService) SetLogProducerService(logProducer *LogProducerService) { 
	s.logProducer = logProducer 
}

func (s *UserService) SetDistributedCache(distCache *DistributedCache) { 
	s.distCache = distCache 
}

func (s *UserService) logUserEvent(ctx context.Context, event *models.UserLogEvent) {
	if s.logProducer != nil {
		_ = s.logProducer.ProduceUserEvent(ctx, event)
	}
}

func (s *UserService) GeneratePhoneHash(phoneNumber string) string {
	normalized := strings.NewReplacer(" ", "", "-", "", "(", "", ")", "").Replace(phoneNumber)
	hash := sha256.Sum256([]byte(normalized))
	return hex.EncodeToString(hash[:])
}

func (s *UserService) GetUserByPhone(ctx context.Context, phoneNumber string) (*models.User, error) {
	phoneHash := s.GeneratePhoneHash(phoneNumber)

	if userID, ok := s.phoneCache.Get(phoneHash); ok {
		return s.GetUserByID(ctx, userID)
	}

	if s.distCache != nil {
		userID, err := s.distCache.GetUserByPhone(ctx, phoneHash)
		if err == nil && userID != uuid.Nil {
			s.phoneCache.Add(phoneHash, userID)
			return s.GetUserByID(ctx, userID)
		}
	}

	user, err := s.userRepo.GetUserByPhoneHash(ctx, phoneHash)
	if err != nil {
		return nil, fmt.Errorf("phone number not registered yet")
	}

	// if user.CompanyID != uuid.Nil && user.UserRoleLevel == "" {
	// 	s.logger.Warn("User has company but no role level",
	// 		util.String("user_id", user.UserID.String()),
	// 		util.String("company_id", user.CompanyID.String()))
	// }

	s.cacheUser(ctx, user)
	s.cachePhoneMapping(ctx, phoneHash, user.UserID)
	return user, nil
}

// ✅ STRICT: CreateUser - only creates basic user, no company association
func (s *UserService) CreateUser(ctx context.Context, req *UserCreateRequest) (*models.User, error) {
	startTime := time.Now()

	if err := s.validateCreateRequest(req); err != nil {
		return nil, fmt.Errorf("%w: %v", ErrInvalidInput, err)
	}

	phoneHash := s.GeneratePhoneHash(req.PhoneNumber)

	// ✅ STRICT: Check if user already exists
	existingUser, err := s.userRepo.GetUserByPhoneHash(ctx, phoneHash)
	if err == nil && existingUser != nil {
		return nil, ErrUserAlreadyExists
	}

	userID := uuid.New()

	encryptedPhone, err := s.encryptionMgr.EncryptField(ctx, req.PhoneNumber, "phone")
	if err != nil {
		s.logUserEvent(ctx, &models.UserLogEvent{
			LogEnvelope: models.LogEnvelope{
				EventID:     uuid.New().String(),
				EventType:   "user",
				ServiceName: "auth-service",
				Timestamp:   time.Now(),
				Environment: "production",
				Version:     "v1.0.0",
				Level:       "error",
				Message:     "Failed to encrypt phone during user creation",
			},
			UserID:      userID.String(),
			Action:      "create_user",
			PhoneNumber: req.PhoneNumber,
			Status:      "failed",
			ErrorCode:   "PHONE_ENCRYPTION_FAILED",
			Duration:    int64(time.Since(startTime).Milliseconds()),
		})
		return nil, fmt.Errorf("failed to encrypt phone: %w", err)
	}
	
	s.logger.Info("Encrypted phone debug",
		util.String("EncryptedValue", encryptedPhone.EncryptedValue),
		util.String("EncryptedDEK", encryptedPhone.EncryptedDEK),
		util.String("KeyID", encryptedPhone.KeyID),
		util.String("UserID", userID.String()),
	)

	keyID, err := uuid.Parse(encryptedPhone.KeyID)
	if err != nil {
		return nil, fmt.Errorf("failed to parse key ID: %w", err)
	}

	now := time.Now().UTC()
	user := &models.User{
		UserBucket:        s.bucketingMgr.GetUserBucket(userID),
		UserID:            userID,
		PhoneHash:         phoneHash,
		PhoneEncrypted:    encryptedPhone.EncryptedValue,
		PhoneKeyID:        keyID,
		PhoneEncryptedDEK: encryptedPhone.EncryptedDEK,
		DeviceID:          req.DeviceID,
		DeviceFingerprint: req.DeviceFingerprint,
		KYCStatus:         "pending",
		KYCLevel:          "basic",
		KYCVerifiedAt:     nil,
		KYCVerifiedBy:     uuid.Nil,
		ProfileServiceID:  uuid.Nil,
		IsVerified:        false,
		IsBlocked:         false,
		IsBanned:          false,
		BannedBy:          uuid.Nil,
		BannedReason:      "",
		BannedAt:          nil,
		CreatedAt:         now,
		LastLogin:         nil,
		UpdatedAt:         &now,
		ConsentAgreed:     req.ConsentAgreed,
		ConsentVersion:    req.ConsentVersion,
		DataRegion:        req.DataRegion,
		CompanyID:         uuid.Nil, // ✅ STRICT: No company association initially
		// UserRoleLevel:     models.UserRoleLevelNone, // ✅ STRICT: No role initially
	}

	if err := s.userRepo.CreateUser(ctx, user); err != nil {
		s.logUserEvent(ctx, &models.UserLogEvent{
			LogEnvelope: models.LogEnvelope{
				EventID:     uuid.New().String(),
				EventType:   "user",
				ServiceName: "auth-service",
				Timestamp:   time.Now(),
				Environment: "production",
				Version:     "v1.0.0",
				Level:       "error",
				Message:     "Failed to create user in database",
			},
			UserID:      userID.String(),
			Action:      "create_user",
			PhoneNumber: req.PhoneNumber,
			Status:      "failed",
			ErrorCode:   "CREATE_USER_FAILED",
			Duration:    int64(time.Since(startTime).Milliseconds()),
		})
		return nil, fmt.Errorf("failed to create user: %w", err)
	}

	s.cacheUser(ctx, user)
	s.cachePhoneMapping(ctx, phoneHash, userID)

	s.logUserEvent(ctx, &models.UserLogEvent{
		LogEnvelope: models.LogEnvelope{
			EventID:     uuid.New().String(),
			EventType:   "user",
			ServiceName: "auth-service",
			Timestamp:   time.Now(),
			Environment: "production",
			Version:     "v1.0.0",
			Level:       "info",
			Message:     "User created successfully",
		},
		UserID:      userID.String(),
		Action:      "create_user",
		PhoneNumber: req.PhoneNumber,
		Status:      "success",
		DeviceID:    req.DeviceID,
		Changes: map[string]interface{}{
			"data_region":     req.DataRegion,
			"consent_agreed":  req.ConsentAgreed,
			"consent_version": req.ConsentVersion,
		},
		Duration: int64(time.Since(startTime).Milliseconds()),
	})

	s.logger.Info("User created successfully",
		util.String("user_id", userID.String()),
		util.String("phone_hash", phoneHash),
		util.Int("user_bucket", user.UserBucket),
		util.Duration("duration", time.Since(startTime)),
	)

	return user, nil
}

func (s *UserService) GetUserByID(ctx context.Context, userID uuid.UUID) (*models.User, error) {
	if user, ok := s.localCache.Get(userID); ok {
		return user, nil
	}

	if s.distCache != nil {
		user, err := s.distCache.GetUser(ctx, userID)
		if err == nil && user != nil {
			s.localCache.Add(userID, user)
			return user, nil
		}
	}

	user, err := s.userRepo.GetUserByID(ctx, userID)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrUserNotFound, err)
	}

	if user.IsBanned {
		return nil, ErrUserBanned
	}
	if user.IsBlocked {
		return nil, ErrUserBlocked
	}

	s.cacheUser(ctx, user)
	return user, nil
}

// // ✅ FIXED: Update user role level - use UpdateUserCompany instead
// func (s *UserService) UpdateUserRoleLevel(ctx context.Context, userID uuid.UUID, roleLevel string) error {
// 	startTime := time.Now()
// 	user, err := s.GetUserByID(ctx, userID)
// 	if err != nil {
// 		return err
// 	}

// 	validRoles := map[string]bool{
// 		models.UserRoleLevelOwner:    true,
// 		models.UserRoleLevelManager:  true,
// 		models.UserRoleLevelEmployee: true,
// 		models.UserRoleLevelViewer:   true,
// 		models.UserRoleLevelNone:     true,
// 	}

// 	if !validRoles[roleLevel] {
// 		return fmt.Errorf("invalid role level: %s", roleLevel)
// 	}

// 	// FIXED: Use UpdateUserCompany to update both company and role
//     if err := s.userRepo.UpdateUserCompanyAndRole(ctx, userID, user.CompanyID, roleLevel); err != nil {
// 		s.logUserEvent(ctx, &models.UserLogEvent{
// 			LogEnvelope: models.LogEnvelope{
// 				EventID:     uuid.New().String(),
// 				EventType:   "user",
// 				ServiceName: "auth-service",
// 				Timestamp:   time.Now(),
// 				Environment: "production",
// 				Version:     "v1.0.0",
// 				Level:       "error",
// 				Message:     "Failed to update user role level",
// 			},
// 			UserID:    userID.String(),
// 			Action:    "update_user_role_level",
// 			Status:    "failed",
// 			ErrorCode: "UPDATE_ROLE_LEVEL_FAILED",
// 			Duration:  int64(time.Since(startTime).Milliseconds()),
// 		})
// 		return fmt.Errorf("failed to update user role level: %w", err)
// 	}

// 	s.logUserEvent(ctx, &models.UserLogEvent{
// 		LogEnvelope: models.LogEnvelope{
// 			EventID:     uuid.New().String(),
// 			EventType:   "user",
// 			ServiceName: "auth-service",
// 			Timestamp:   time.Now(),
// 			Environment: "production",
// 			Version:     "v1.0.0",
// 			Level:       "info",
// 			Message:     "User role level updated successfully",
// 		},
// 		UserID:   userID.String(),
// 		Action:   "update_user_role_level",
// 		Status:   "success",
// 		Changes: map[string]interface{}{
// 			"old_role_level": user.UserRoleLevel,
// 			"new_role_level": roleLevel,
// 		},
// 		Duration: int64(time.Since(startTime).Milliseconds()),
// 	})

// 	s.logger.Info("User role level updated",
// 		util.String("user_id", userID.String()),
// 		util.String("company_id", user.CompanyID.String()),
// 		util.String("new_role_level", roleLevel),
// 	)

// 	user.UserRoleLevel = roleLevel
// 	s.invalidateUserCache(ctx, userID)
// 	s.cacheUser(ctx, user)
// 	return nil
// }

// // ✅ FIXED: Internal method for company service to update user company and role - use UpdateUserCompany
// func (s *UserService) UpdateUserCompanyAndRole(ctx context.Context, userID uuid.UUID, companyID uuid.UUID, roleLevel string) error {
// 	startTime := time.Now()
	
// 	user, err := s.GetUserByID(ctx, userID)
// 	if err != nil {
// 		return err
// 	}

// 	validRoles := map[string]bool{
// 		models.UserRoleLevelOwner:    true,
// 		models.UserRoleLevelManager:  true,
// 		models.UserRoleLevelEmployee: true,
// 		models.UserRoleLevelViewer:   true,
// 		models.UserRoleLevelNone:     true,
// 	}

// 	if !validRoles[roleLevel] {
// 		return fmt.Errorf("invalid role level: %s", roleLevel)
// 	}

// 	// FIXED: Use UpdateUserCompany instead of UpdateUserCompanyAndRole
//     if err := s.userRepo.UpdateUserCompanyAndRole(ctx, userID, companyID, roleLevel); err != nil {
// 		s.logUserEvent(ctx, &models.UserLogEvent{
// 			LogEnvelope: models.LogEnvelope{
// 				EventID:     uuid.New().String(),
// 				EventType:   "user",
// 				ServiceName: "auth-service",
// 				Timestamp:   time.Now(),
// 				Environment: "production",
// 				Version:     "v1.0.0",
// 				Level:       "error",
// 				Message:     "Failed to update user company and role",
// 			},
// 			UserID:    userID.String(),
// 			Action:    "update_user_company_role",
// 			Status:    "failed",
// 			ErrorCode: "UPDATE_COMPANY_ROLE_FAILED",
// 			Duration:  int64(time.Since(startTime).Milliseconds()),
// 		})
// 		return fmt.Errorf("failed to update user company and role: %w", err)
// 	}

// 	s.logUserEvent(ctx, &models.UserLogEvent{
// 		LogEnvelope: models.LogEnvelope{
// 			EventID:     uuid.New().String(),
// 			EventType:   "user",
// 			ServiceName: "auth-service",
// 			Timestamp:   time.Now(),
// 			Environment: "production",
// 			Version:     "v1.0.0",
// 			Level:       "info",
// 			Message:     "User company and role updated successfully",
// 		},
// 		UserID:   userID.String(),
// 		Action:   "update_user_company_role",
// 		Status:   "success",
// 		Changes: map[string]interface{}{
// 			"old_company_id": user.CompanyID.String(),
// 			"new_company_id": companyID.String(),
// 			"old_role_level": user.UserRoleLevel,
// 			"new_role_level": roleLevel,
// 		},
// 		Duration: int64(time.Since(startTime).Milliseconds()),
// 	})

// 	s.logger.Info("User company and role updated",
// 		util.String("user_id", userID.String()),
// 		util.String("company_id", companyID.String()),
// 		util.String("role_level", roleLevel),
// 	)

// 	user.CompanyID = companyID
// 	user.UserRoleLevel = roleLevel
// 	s.invalidateUserCache(ctx, userID)
// 	s.cacheUser(ctx, user)
// 	return nil
// }

// ✅ NEW: Get users by company
func (s *UserService) GetUsersByCompany(ctx context.Context, companyID uuid.UUID, limit int) ([]*models.User, error) {
	return s.userRepo.GetUsersByCompany(ctx, companyID, limit)
}

func (s *UserService) UpdateUser(ctx context.Context, userID uuid.UUID, req *UserUpdateRequest) (*models.User, error) {
	startTime := time.Now()

	user, err := s.GetUserByID(ctx, userID)
	if err != nil {
		return nil, err
	}

	changes := make(map[string]interface{})
	
	if req.DeviceID != nil && *req.DeviceID != user.DeviceID {
		changes["device_id"] = map[string]interface{}{
			"old": user.DeviceID,
			"new": *req.DeviceID,
		}
		user.DeviceID = *req.DeviceID
	}
	if req.DeviceFingerprint != nil && *req.DeviceFingerprint != user.DeviceFingerprint {
		changes["device_fingerprint"] = map[string]interface{}{
			"old": user.DeviceFingerprint,
			"new": *req.DeviceFingerprint,
		}
		user.DeviceFingerprint = *req.DeviceFingerprint
	}
	if req.ProfileServiceID != nil {
		profileID, err := uuid.Parse(*req.ProfileServiceID)
		if err != nil {
			return nil, fmt.Errorf("invalid profile service ID format: %w", err)
		}
		changes["profile_service_id"] = map[string]interface{}{
			"old": user.ProfileServiceID,
			"new": profileID,
		}
		user.ProfileServiceID = profileID
	}
	if req.DataRegion != nil && *req.DataRegion != user.DataRegion {
		changes["data_region"] = map[string]interface{}{
			"old": user.DataRegion,
			"new": *req.DataRegion,
		}
		user.DataRegion = *req.DataRegion
	}

	now := time.Now().UTC()
	user.UpdatedAt = &now

	if err := s.userRepo.UpdateUser(ctx, user); err != nil {
		s.logUserEvent(ctx, &models.UserLogEvent{
			LogEnvelope: models.LogEnvelope{
				EventID:     uuid.New().String(),
				EventType:   "user",
				ServiceName: "auth-service",
				Timestamp:   time.Now(),
				Environment: "production",
				Version:     "v1.0.0",
				Level:       "error",
				Message:     "Failed to update user in database",
			},
			UserID:   userID.String(),
			Action:   "update_user",
			Status:   "failed",
			ErrorCode: "UPDATE_USER_FAILED",
			Changes:  changes,
			Duration: int64(time.Since(startTime).Milliseconds()),
		})
		return nil, fmt.Errorf("failed to update user: %w", err)
	}

	s.invalidateUserCache(ctx, userID)
	s.cacheUser(ctx, user)

	s.logUserEvent(ctx, &models.UserLogEvent{
		LogEnvelope: models.LogEnvelope{
			EventID:     uuid.New().String(),
			EventType:   "user",
			ServiceName: "auth-service",
			Timestamp:   time.Now(),
			Environment: "production",
			Version:     "v1.0.0",
			Level:       "info",
			Message:     "User updated successfully",
		},
		UserID:   userID.String(),
		Action:   "update_user",
		Status:   "success",
		Changes:  changes,
		Duration: int64(time.Since(startTime).Milliseconds()),
	})

	s.logger.Info("User updated successfully",
		util.String("user_id", userID.String()),
		util.Any("updates", req),
	)

	return user, nil
}

func (s *UserService) UpdateUserProfile(ctx context.Context, userID uuid.UUID, profileServiceID uuid.UUID) error {
	startTime := time.Now()

	user, err := s.GetUserByID(ctx, userID)
	if err != nil {
		return err
	}

	if err := s.userRepo.UpdateUserProfile(ctx, userID, profileServiceID); err != nil {
		s.logUserEvent(ctx, &models.UserLogEvent{
			LogEnvelope: models.LogEnvelope{
				EventID:     uuid.New().String(),
				EventType:   "user",
				ServiceName: "auth-service",
				Timestamp:   time.Now(),
				Environment: "production",
				Version:     "v1.0.0",
				Level:       "error",
				Message:     "Failed to update user profile in database",
			},
			UserID:   userID.String(),
			Action:   "update_user_profile",
			Status:   "failed",
			ErrorCode: "UPDATE_PROFILE_FAILED",
			Duration: int64(time.Since(startTime).Milliseconds()),
		})
		return fmt.Errorf("failed to update user profile: %w", err)
	}

	user.ProfileServiceID = profileServiceID
	now := time.Now().UTC()
	user.UpdatedAt = &now
	
	s.invalidateUserCache(ctx, userID)
	s.cacheUser(ctx, user)

	s.logUserEvent(ctx, &models.UserLogEvent{
		LogEnvelope: models.LogEnvelope{
			EventID:     uuid.New().String(),
			EventType:   "user",
			ServiceName: "auth-service",
			Timestamp:   time.Now(),
			Environment: "production",
			Version:     "v1.0.0",
			Level:       "info",
			Message:     "User profile updated successfully",
		},
		UserID:   userID.String(),
		Action:   "update_user_profile",
		Status:   "success",
		Changes: map[string]interface{}{
			"profile_service_id": profileServiceID.String(),
		},
		Duration: int64(time.Since(startTime).Milliseconds()),
	})

	return nil
}

func (s *UserService) UpdateUserStatus(ctx context.Context, userID uuid.UUID, isVerified, isBlocked, isBanned bool) error {
	startTime := time.Now()

	user, err := s.GetUserByID(ctx, userID)
	if err != nil {
		return err
	}

	if err := s.validateStatusTransition(user, isVerified, isBlocked, isBanned); err != nil {
		return err
	}

	if err := s.userRepo.UpdateUserStatus(ctx, userID, isVerified, isBlocked, isBanned); err != nil {
		s.logUserEvent(ctx, &models.UserLogEvent{
			LogEnvelope: models.LogEnvelope{
				EventID:     uuid.New().String(),
				EventType:   "user",
				ServiceName: "auth-service",
				Timestamp:   time.Now(),
				Environment: "production",
				Version:     "v1.0.0",
				Level:       "error",
				Message:     "Failed to update user status in database",
			},
			UserID:   userID.String(),
			Action:   "update_user_status",
			Status:   "failed",
			ErrorCode: "UPDATE_STATUS_FAILED",
			Duration: int64(time.Since(startTime).Milliseconds()),
		})
		return fmt.Errorf("failed to update user status: %w", err)
	}

	oldVerified := user.IsVerified
	oldBlocked := user.IsBlocked
	oldBanned := user.IsBanned

	user.IsVerified = isVerified
	user.IsBlocked = isBlocked
	user.IsBanned = isBanned
	now := time.Now().UTC()
	user.UpdatedAt = &now
	
	s.invalidateUserCache(ctx, userID)
	s.cacheUser(ctx, user)

	s.logUserEvent(ctx, &models.UserLogEvent{
		LogEnvelope: models.LogEnvelope{
			EventID:     uuid.New().String(),
			EventType:   "user",
			ServiceName: "auth-service",
			Timestamp:   time.Now(),
			Environment: "production",
			Version:     "v1.0.0",
			Level:       "info",
			Message:     "User status updated successfully",
		},
		UserID:   userID.String(),
		Action:   "update_user_status",
		Status:   "success",
		Changes: map[string]interface{}{
			"is_verified": map[string]interface{}{"old": oldVerified, "new": isVerified},
			"is_blocked":  map[string]interface{}{"old": oldBlocked, "new": isBlocked},
			"is_banned":   map[string]interface{}{"old": oldBanned, "new": isBanned},
		},
		Duration: int64(time.Since(startTime).Milliseconds()),
	})

	s.logger.Info("User status updated",
		util.String("user_id", userID.String()),
		util.Bool("verified", isVerified),
		util.Bool("blocked", isBlocked),
		util.Bool("banned", isBanned),
	)

	return nil
}

func (s *UserService) UpdateLastLogin(ctx context.Context, userID uuid.UUID) error {
	startTime := time.Now()

	user, err := s.GetUserByID(ctx, userID)
	if err != nil {
		return err
	}

	now := time.Now().UTC()
	if err := s.userRepo.UpdateLastLogin(ctx, userID, now); err != nil {
		return fmt.Errorf("failed to update last login: %w", err)
	}

	user.LastLogin = &now
	s.cacheUser(ctx, user)

	s.logUserEvent(ctx, &models.UserLogEvent{
		LogEnvelope: models.LogEnvelope{
			EventID:     uuid.New().String(),
			EventType:   "user",
			ServiceName: "auth-service",
			Timestamp:   time.Now(),
			Environment: "production",
			Version:     "v1.0.0",
			Level:       "info",
			Message:     "User last login updated",
		},
		UserID:   userID.String(),
		Action:   "update_last_login",
		Status:   "success",
		Duration: int64(time.Since(startTime).Milliseconds()),
	})

	return nil
}

func (s *UserService) CreateUsersBatch(ctx context.Context, requests []*UserCreateRequest) ([]*models.User, error) {
	if len(requests) == 0 {
		return []*models.User{}, nil
	}

	for i, req := range requests {
		if err := s.validateCreateRequest(req); err != nil {
			return nil, fmt.Errorf("invalid request at index %d: %w", i, err)
		}
	}

	phoneHashes := make(map[string]bool, len(requests))
	for _, req := range requests {
		phoneHash := s.GeneratePhoneHash(req.PhoneNumber)
		if phoneHashes[phoneHash] {
			return nil, fmt.Errorf("duplicate phone number in batch: %s", req.PhoneNumber)
		}
		phoneHashes[phoneHash] = true
	}

	users := make([]*models.User, 0, len(requests))
	var mu sync.Mutex
	g, gctx := errgroup.WithContext(ctx)
	g.SetLimit(MaxConcurrentBatch)

	for i := 0; i < len(requests); i += DefaultBatchSize {
		batchStart := i
		batchEnd := min(i+DefaultBatchSize, len(requests))
		batchRequests := requests[batchStart:batchEnd]

		g.Go(func() error {
			batchUsers, err := s.processUserBatch(gctx, batchRequests)
			if err != nil {
				return err
			}

			mu.Lock()
			users = append(users, batchUsers...)
			mu.Unlock()

			return nil
		})
	}

	if err := g.Wait(); err != nil {
		return nil, fmt.Errorf("batch creation failed: %w", err)
	}

	s.logger.Info("Batch user creation completed",
		util.Int("users_created", len(users)),
		util.Int("batch_count", (len(requests)+DefaultBatchSize-1)/DefaultBatchSize),
	)

	return users, nil
}

func (s *UserService) processUserBatch(ctx context.Context, requests []*UserCreateRequest) ([]*models.User, error) {
	users := make([]*models.User, 0, len(requests))

	for _, req := range requests {
		user, err := s.CreateUser(ctx, req)
		if err != nil {
			s.logger.Error("Failed to create user in batch",
				util.ErrorField(err),
				util.String("phone", req.PhoneNumber),
			)
			continue
		}
		users = append(users, user)
	}

	return users, nil
}

func (s *UserService) GetUsersByIDBatch(ctx context.Context, userIDs []uuid.UUID) ([]*models.User, error) {
	if len(userIDs) == 0 {
		return []*models.User{}, nil
	}

	cachedUsers := make([]*models.User, 0, len(userIDs))
	missingIDs := make([]uuid.UUID, 0)

	for _, userID := range userIDs {
		if user, ok := s.localCache.Get(userID); ok {
			cachedUsers = append(cachedUsers, user)
		} else {
			missingIDs = append(missingIDs, userID)
		}
	}

	if len(missingIDs) == 0 {
		return cachedUsers, nil
	}

	fetchedUsers, err := s.userRepo.GetUsersByIDBatch(ctx, missingIDs)
	if err != nil {
		return nil, fmt.Errorf("failed to fetch users batch: %w", err)
	}

	for _, user := range fetchedUsers {
		s.cacheUser(ctx, user)
	}

	allUsers := append(cachedUsers, fetchedUsers...)
	return allUsers, nil
}

func (s *UserService) UpdateUsersBatch(ctx context.Context, updates map[uuid.UUID]*UserUpdateRequest) ([]*models.User, error) {
	if len(updates) == 0 {
		return []*models.User{}, nil
	}

	updatedUsers := make([]*models.User, 0, len(updates))
	var mu sync.Mutex
	g, gctx := errgroup.WithContext(ctx)
	g.SetLimit(5)

	for userID, req := range updates {
		userID := userID
		req := req

		g.Go(func() error {
			user, err := s.UpdateUser(gctx, userID, req)
			if err != nil {
				s.logger.Warn("Failed to update user in batch",
					util.ErrorField(err),
					util.String("user_id", userID.String()),
				)
				return nil
			}

			mu.Lock()
			updatedUsers = append(updatedUsers, user)
			mu.Unlock()

			return nil
		})
	}

	if err := g.Wait(); err != nil {
		return nil, fmt.Errorf("batch update failed: %w", err)
	}

	return updatedUsers, nil
}

func (s *UserService) UpdateKYCStatus(ctx context.Context, req *KYCUpdateRequest) error {
	startTime := time.Now()

	user, err := s.GetUserByID(ctx, req.UserID)
	if err != nil {
		return err
	}

	if err := s.validateKYCStatusTransition(user.KYCStatus, req.Status); err != nil {
		return err
	}

	now := time.Now().UTC()
	if err := s.userRepo.UpdateKYCStatus(ctx, req.UserID, req.Status, req.Level, req.VerifiedBy); err != nil {
		s.logUserEvent(ctx, &models.UserLogEvent{
			LogEnvelope: models.LogEnvelope{
				EventID:     uuid.New().String(),
				EventType:   "user",
				ServiceName: "auth-service",
				Timestamp:   time.Now(),
				Environment: "production",
				Version:     "v1.0.0",
				Level:       "error",
				Message:     "Failed to update KYC status in database",
			},
			UserID:      req.UserID.String(),
			Action:      "update_kyc_status",
			Status:      "failed",
			ErrorCode:   "UPDATE_KYC_FAILED",
			Duration:    int64(time.Since(startTime).Milliseconds()),
		})
		return fmt.Errorf("failed to update KYC status: %w", err)
	}

	oldStatus := user.KYCStatus
	oldLevel := user.KYCLevel

	user.KYCStatus = req.Status
	user.KYCLevel = req.Level
	user.KYCVerifiedAt = &now
	user.KYCVerifiedBy = req.VerifiedBy
	user.UpdatedAt = &now

	if req.Status == "verified" {
		user.IsVerified = true
	}

	s.invalidateUserCache(ctx, req.UserID)
	s.cacheUser(ctx, user)

	s.logUserEvent(ctx, &models.UserLogEvent{
		LogEnvelope: models.LogEnvelope{
			EventID:     uuid.New().String(),
			EventType:   "user",
			ServiceName: "auth-service",
			Timestamp:   time.Now(),
			Environment: "production",
			Version:     "v1.0.0",
			Level:       "info",
			Message:     "KYC status updated successfully",
		},
		UserID:   req.UserID.String(),
		Action:   "update_kyc_status",
		Status:   "success",
		Changes: map[string]interface{}{
			"old_status": oldStatus,
			"new_status": req.Status,
			"old_level":  oldLevel,
			"new_level":  req.Level,
			"verified_by": req.VerifiedBy.String(),
		},
		Duration: int64(time.Since(startTime).Milliseconds()),
	})

	s.logger.Info("KYC status updated",
		util.String("user_id", req.UserID.String()),
		util.String("status", req.Status),
		util.String("level", req.Level),
		util.String("verified_by", req.VerifiedBy.String()),
	)

	return nil
}

func (s *UserService) GetUsersByKYCStatus(ctx context.Context, status string, limit int, pageToken string) ([]*models.User, string, error) {
	if limit <= 0 || limit > 1000 {
		limit = 100
	}

	var pageState []byte
	if pageToken != "" {
		var err error
		pageState, err = hex.DecodeString(pageToken)
		if err != nil {
			return nil, "", fmt.Errorf("invalid page token: %w", err)
		}
	}

	users, nextPageState, err := s.userRepo.GetUsersByKYCStatus(ctx, status, limit, pageState)
	if err != nil {
		return nil, "", fmt.Errorf("failed to get users by KYC status: %w", err)
	}

	nextPageToken := ""
	if len(nextPageState) > 0 {
		nextPageToken = hex.EncodeToString(nextPageState)
	}

	return users, nextPageToken, nil
}

func (s *UserService) UpdateUserConsent(ctx context.Context, userID uuid.UUID, agreed bool, version string) error {
	startTime := time.Now()

	user, err := s.GetUserByID(ctx, userID)
	if err != nil {
		return err
	}

	oldAgreed := user.ConsentAgreed
	oldVersion := user.ConsentVersion

	if err := s.userRepo.UpdateUserConsent(ctx, userID, agreed, version); err != nil {
		s.logUserEvent(ctx, &models.UserLogEvent{
			LogEnvelope: models.LogEnvelope{
				EventID:     uuid.New().String(),
				EventType:   "user",
				ServiceName: "auth-service",
				Timestamp:   time.Now(),
				Environment: "production",
				Version:     "v1.0.0",
				Level:       "error",
				Message:     "Failed to update user consent in database",
			},
			UserID:   userID.String(),
			Action:   "update_user_consent",
			Status:   "failed",
			ErrorCode: "UPDATE_CONSENT_FAILED",
			Duration: int64(time.Since(startTime).Milliseconds()),
		})
		return fmt.Errorf("failed to update user consent: %w", err)
	}

	user.ConsentAgreed = agreed
	user.ConsentVersion = version
	now := time.Now().UTC()
	user.UpdatedAt = &now
	
	s.invalidateUserCache(ctx, userID)
	s.cacheUser(ctx, user)

	s.logUserEvent(ctx, &models.UserLogEvent{
		LogEnvelope: models.LogEnvelope{
			EventID:     uuid.New().String(),
			EventType:   "user",
			ServiceName: "auth-service",
			Timestamp:   time.Now(),
			Environment: "production",
			Version:     "v1.0.0",
			Level:       "info",
			Message:     "User consent updated successfully",
		},
		UserID:   userID.String(),
		Action:   "update_user_consent",
		Status:   "success",
		Changes: map[string]interface{}{
			"consent_agreed":   map[string]interface{}{"old": oldAgreed, "new": agreed},
			"consent_version": map[string]interface{}{"old": oldVersion, "new": version},
		},
		Duration: int64(time.Since(startTime).Milliseconds()),
	})

	return nil
}

func (s *UserService) BanUser(ctx context.Context, req *BanUserRequest) error {
	startTime := time.Now()

	user, err := s.GetUserByID(ctx, req.UserID)
	if err != nil {
		return err
	}

	if user.IsBanned {
		return fmt.Errorf("user is already banned")
	}

	if err := s.userRepo.BanUser(ctx, req.UserID, req.BannedBy, req.Reason); err != nil {
		s.logUserEvent(ctx, &models.UserLogEvent{
			LogEnvelope: models.LogEnvelope{
				EventID:     uuid.New().String(),
				EventType:   "user",
				ServiceName: "auth-service",
				Timestamp:   time.Now(),
				Environment: "production",
				Version:     "v1.0.0",
				Level:       "error",
				Message:     "Failed to ban user in database",
			},
			UserID:      req.UserID.String(),
			Action:      "ban_user",
			Status:      "failed",
			ErrorCode:   "BAN_USER_FAILED",
			Duration:    int64(time.Since(startTime).Milliseconds()),
		})
		return fmt.Errorf("failed to ban user: %w", err)
	}

	user.IsBanned = true
	user.BannedBy = req.BannedBy
	user.BannedReason = req.Reason
	now := time.Now().UTC()
	user.BannedAt = &now
	user.UpdatedAt = &now
	
	s.invalidateUserCache(ctx, req.UserID)
	s.cacheUser(ctx, user)

	s.logUserEvent(ctx, &models.UserLogEvent{
		LogEnvelope: models.LogEnvelope{
			EventID:     uuid.New().String(),
			EventType:   "user",
			ServiceName: "auth-service",
			Timestamp:   time.Now(),
			Environment: "production",
			Version:     "v1.0.0",
			Level:       "warning",
			Message:     "User banned successfully",
		},
		UserID:   req.UserID.String(),
		Action:   "ban_user",
		Status:   "success",
		Changes: map[string]interface{}{
			"banned_by":   req.BannedBy.String(),
			"banned_reason": req.Reason,
			"banned_at":   now,
		},
		Duration: int64(time.Since(startTime).Milliseconds()),
	})

	s.logger.Warn("User banned",
		util.String("user_id", req.UserID.String()),
		util.String("banned_by", req.BannedBy.String()),
		util.String("reason", req.Reason),
	)

	return nil
}

func (s *UserService) UnbanUser(ctx context.Context, userID uuid.UUID) error {
	startTime := time.Now()

	user, err := s.GetUserByID(ctx, userID)
	if err != nil {
		return err
	}

	if !user.IsBanned {
		return fmt.Errorf("user is not banned")
	}

	if err := s.userRepo.UnbanUser(ctx, userID); err != nil {
		s.logUserEvent(ctx, &models.UserLogEvent{
			LogEnvelope: models.LogEnvelope{
				EventID:     uuid.New().String(),
				EventType:   "user",
				ServiceName: "auth-service",
				Timestamp:   time.Now(),
				Environment: "production",
				Version:     "v1.0.0",
				Level:       "error",
				Message:     "Failed to unban user in database",
			},
			UserID:   userID.String(),
			Action:   "unban_user",
			Status:   "failed",
			ErrorCode: "UNBAN_USER_FAILED",
			Duration: int64(time.Since(startTime).Milliseconds()),
		})
		return fmt.Errorf("failed to unban user: %w", err)
	}

	user.IsBanned = false
	user.BannedBy = uuid.Nil
	user.BannedReason = ""
	user.BannedAt = nil
	now := time.Now().UTC()
	user.UpdatedAt = &now
	
	s.invalidateUserCache(ctx, userID)
	s.cacheUser(ctx, user)

	s.logUserEvent(ctx, &models.UserLogEvent{
		LogEnvelope: models.LogEnvelope{
			EventID:     uuid.New().String(),
			EventType:   "user",
			ServiceName: "auth-service",
			Timestamp:   time.Now(),
			Environment: "production",
			Version:     "v1.0.0",
			Level:       "info",
			Message:     "User unbanned successfully",
		},
		UserID:   userID.String(),
		Action:   "unban_user",
		Status:   "success",
		Duration: int64(time.Since(startTime).Milliseconds()),
	})

	s.logger.Info("User unbanned",
		util.String("user_id", userID.String()),
	)

	return nil
}

func (s *UserService) GetBannedUsers(ctx context.Context, limit int, pageToken string) ([]*models.User, string, error) {
	if limit <= 0 || limit > 1000 {
		limit = 100
	}

	var pageState []byte
	if pageToken != "" {
		var err error
		pageState, err = hex.DecodeString(pageToken)
		if err != nil {
			return nil, "", fmt.Errorf("invalid page token: %w", err)
		}
	}

	users, nextPageState, err := s.userRepo.GetBannedUsers(ctx, limit, pageState)
	if err != nil {
		return nil, "", fmt.Errorf("failed to get banned users: %w", err)
	}

	nextPageToken := ""
	if len(nextPageState) > 0 {
		nextPageToken = hex.EncodeToString(nextPageState)
	}

	return users, nextPageToken, nil
}

func (s *UserService) cacheUser(ctx context.Context, user *models.User) {
	s.localCache.Add(user.UserID, user)

	if s.distCache != nil {
		if err := s.distCache.SetUser(ctx, user); err != nil {
			s.logger.Warn("Failed to cache user in Redis",
				util.ErrorField(err),
				util.String("user_id", user.UserID.String()))
		}
	}
}

func (s *UserService) cachePhoneMapping(ctx context.Context, phoneHash string, userID uuid.UUID) {
	s.phoneCache.Add(phoneHash, userID)

	if s.distCache != nil {
		if err := s.distCache.SetPhoneMapping(ctx, phoneHash, userID); err != nil {
			s.logger.Warn("Failed to cache phone mapping in Redis",
				util.ErrorField(err),
				util.String("phone_hash", phoneHash))
		}
	}
}

func (s *UserService) invalidateUserCache(ctx context.Context, userID uuid.UUID) {
	s.localCache.Remove(userID)

	if s.distCache != nil {
		if err := s.distCache.InvalidateUser(ctx, userID); err != nil {
			s.logger.Warn("Failed to invalidate user in Redis",
				util.ErrorField(err),
				util.String("user_id", userID.String()))
		}
	}
}

// ✅ ENHANCED: validateCreateRequest - removes company validation for basic user creation
func (s *UserService) validateCreateRequest(req *UserCreateRequest) error {
	if req.PhoneNumber == "" {
		return fmt.Errorf("phone number is required")
	}
	if len(req.PhoneNumber) < 10 || len(req.PhoneNumber) > 15 {
		return fmt.Errorf("phone number must be between 10 and 15 characters")
	}
	if req.DeviceID == "" {
		return fmt.Errorf("device ID is required")
	}
	if req.DeviceFingerprint == "" {
		return fmt.Errorf("device fingerprint is required")
	}
	if req.DataRegion == "" {
		return fmt.Errorf("data region is required")
	}
	if req.ConsentAgreed && req.ConsentVersion == "" {
		return fmt.Errorf("consent version is required when consent is agreed")
	}
	
	return nil
}

func (s *UserService) validateStatusTransition(user *models.User, isVerified, isBlocked, isBanned bool) error {
	if user.IsBanned && !isBanned {
		return fmt.Errorf("cannot unban user via status update, use UnbanUser method")
	}

	if !user.IsBanned && isBanned {
		return fmt.Errorf("cannot ban user via status update, use BanUser method")
	}

	return nil
}

func (s *UserService) validateKYCStatusTransition(currentStatus, newStatus string) error {
	validTransitions := map[string][]string{
		"pending":  {"verified", "rejected", "expired"},
		"verified": {"expired", "rejected"},
		"rejected": {"pending", "verified"},
		"expired":  {"pending", "verified"},
	}

	allowed, exists := validTransitions[currentStatus]
	if !exists {
		return fmt.Errorf("invalid current KYC status: %s", currentStatus)
	}

	for _, status := range allowed {
		if status == newStatus {
			return nil
		}
	}

	return fmt.Errorf("invalid KYC status transition: %s -> %s", currentStatus, newStatus)
}

func (s *UserService) HealthCheck(ctx context.Context) error {
	if err := s.userRepo.HealthCheck(ctx); err != nil {
		return fmt.Errorf("user repository health check failed: %w", err)
	}
	return nil
}

func (s *UserService) GetServiceStats(ctx context.Context) (map[string]interface{}, error) {
	repoStats, err := s.userRepo.GetRepositoryStats(ctx)
	if err != nil {
		return nil, err
	}

	stats := map[string]interface{}{
		"local_cache_size":  s.localCache.Len(),
		"phone_cache_size":  s.phoneCache.Len(),
		"local_cache_cap":   1_000_000,
		"phone_cache_cap":   1_000_000,
		"has_redis_cache":   s.distCache != nil,
		"repository":        repoStats,
		"timestamp":         time.Now().UTC(),
	}

	return stats, nil
}

func (s *UserService) Cleanup() {
	s.localCache.Purge()
	s.phoneCache.Purge()
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}
// ✅ NEW: CreateUserForCompanyOwner creates a user specifically for company ownership
func (s *UserService) CreateUserForCompanyOwner(ctx context.Context, phone, dataRegion string) (*models.User, error) {
    startTime := time.Now()

    // Validate basic inputs
    if phone == "" {
        return nil, fmt.Errorf("phone number is required")
    }
    if dataRegion == "" {
        return nil, fmt.Errorf("data region is required")
    }

    phoneHash := s.GeneratePhoneHash(phone)

    // Check if user already exists
    existingUser, err := s.userRepo.GetUserByPhoneHash(ctx, phoneHash)
    if err == nil && existingUser != nil {
        return existingUser, nil // Return existing user
    }

    userID := uuid.New()

    encryptedPhone, err := s.encryptionMgr.EncryptField(ctx, phone, "phone")
    if err != nil {
        s.logUserEvent(ctx, &models.UserLogEvent{
            LogEnvelope: models.LogEnvelope{
                EventID:     uuid.New().String(),
                EventType:   "user",
                ServiceName: "auth-service",
                Timestamp:   time.Now(),
                Environment: "production",
                Version:     "v1.0.0",
                Level:       "error",
                Message:     "Failed to encrypt phone during company owner user creation",
            },
            UserID:      userID.String(),
            Action:      "create_company_owner_user",
            PhoneNumber: phone,
            Status:      "failed",
            ErrorCode:   "PHONE_ENCRYPTION_FAILED",
            Duration:    int64(time.Since(startTime).Milliseconds()),
        })
        return nil, fmt.Errorf("failed to encrypt phone: %w", err)
    }

    keyID, err := uuid.Parse(encryptedPhone.KeyID)
    if err != nil {
        return nil, fmt.Errorf("failed to parse key ID: %w", err)
    }

    now := time.Now().UTC()
    user := &models.User{
        UserBucket:        s.bucketingMgr.GetUserBucket(userID),
        UserID:            userID,
        PhoneHash:         phoneHash,
        PhoneEncrypted:    encryptedPhone.EncryptedValue,
        PhoneKeyID:        keyID,
        PhoneEncryptedDEK: encryptedPhone.EncryptedDEK,
        DeviceID:          "company-owner-admin", // Special identifier for admin-created company owners
        DeviceFingerprint: "company-owner-admin",
        KYCStatus:         "pending",
        KYCLevel:          "basic",
        KYCVerifiedAt:     nil,
        KYCVerifiedBy:     uuid.Nil,
        ProfileServiceID:  uuid.Nil,
        IsVerified:        false,
        IsBlocked:         false,
        IsBanned:          false,
        BannedBy:          uuid.Nil,
        BannedReason:      "",
        BannedAt:          nil,
        CreatedAt:         now,
        LastLogin:         nil,
        UpdatedAt:         &now,
        ConsentAgreed:     true, // Company owners automatically consent
        ConsentVersion:    "v1.0",
        DataRegion:        dataRegion,
        CompanyID:         uuid.Nil, // Will be set when company is created
        // UserRoleLevel:     models.UserRoleLevelNone, // Will be updated to owner
    }

    if err := s.userRepo.CreateUser(ctx, user); err != nil {
        s.logUserEvent(ctx, &models.UserLogEvent{
            LogEnvelope: models.LogEnvelope{
                EventID:     uuid.New().String(),
                EventType:   "user",
                ServiceName: "auth-service",
                Timestamp:   time.Now(),
                Environment: "production",
                Version:     "v1.0.0",
                Level:       "error",
                Message:     "Failed to create company owner user in database",
            },
            UserID:      userID.String(),
            Action:      "create_company_owner_user",
            PhoneNumber: phone,
            Status:      "failed",
            ErrorCode:   "CREATE_USER_FAILED",
            Duration:    int64(time.Since(startTime).Milliseconds()),
        })
        return nil, fmt.Errorf("failed to create user: %w", err)
    }

    s.cacheUser(ctx, user)
    s.cachePhoneMapping(ctx, phoneHash, userID)

    s.logUserEvent(ctx, &models.UserLogEvent{
        LogEnvelope: models.LogEnvelope{
            EventID:     uuid.New().String(),
            EventType:   "user",
            ServiceName: "auth-service",
            Timestamp:   time.Now(),
            Environment: "production",
            Version:     "v1.0.0",
            Level:       "info",
            Message:     "Company owner user created successfully",
        },
        UserID:      userID.String(),
        Action:      "create_company_owner_user",
        PhoneNumber: phone,
        Status:      "success",
        Changes: map[string]interface{}{
            "data_region":     dataRegion,
            "consent_agreed":  true,
            "consent_version": "v1.0",
            "purpose":         "company_owner",
        },
        Duration: int64(time.Since(startTime).Milliseconds()),
    })

    s.logger.Info("Company owner user created successfully",
        util.String("user_id", userID.String()),
        util.String("phone_hash", phoneHash),
        util.Int("user_bucket", user.UserBucket),
        util.Duration("duration", time.Since(startTime)),
    )

    return user, nil
}


// ✅ NEW: Update only company ID, not role level
func (s *UserService) UpdateUserCompany(ctx context.Context, userID uuid.UUID, companyID uuid.UUID) error {
    startTime := time.Now()
    
    user, err := s.GetUserByID(ctx, userID)
    if err != nil {
        return err
    }

    // Update only the company ID
    if err := s.userRepo.UpdateUserCompany(ctx, userID, companyID); err != nil {
        s.logUserEvent(ctx, &models.UserLogEvent{
            LogEnvelope: models.LogEnvelope{
                EventID:     uuid.New().String(),
                EventType:   "user",
                ServiceName: "auth-service",
                Timestamp:   time.Now(),
                Environment: "production",
                Version:     "v1.0.0",
                Level:       "error",
                Message:     "Failed to update user company",
            },
            UserID:    userID.String(),
            Action:    "update_user_company",
            Status:    "failed",
            ErrorCode: "UPDATE_COMPANY_FAILED",
            Duration:  int64(time.Since(startTime).Milliseconds()),
        })
        return fmt.Errorf("failed to update user company: %w", err)
    }

    s.logUserEvent(ctx, &models.UserLogEvent{
        LogEnvelope: models.LogEnvelope{
            EventID:     uuid.New().String(),
            EventType:   "user",
            ServiceName: "auth-service",
            Timestamp:   time.Now(),
            Environment: "production",
            Version:     "v1.0.0",
            Level:       "info",
            Message:     "User company updated successfully",
        },
        UserID:   userID.String(),
        Action:   "update_user_company",
        Status:   "success",
        Changes: map[string]interface{}{
            "old_company_id": user.CompanyID.String(),
            "new_company_id": companyID.String(),
        },
        Duration: int64(time.Since(startTime).Milliseconds()),
    })

    s.logger.Info("User company updated",
        util.String("user_id", userID.String()),
        util.String("company_id", companyID.String()),
    )

    user.CompanyID = companyID
    s.invalidateUserCache(ctx, userID)
    s.cacheUser(ctx, user)
    return nil
}
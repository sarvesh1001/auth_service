// internal/service/user_service.go
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

	"auth-service/internal/encryption"
	"auth-service/internal/hashing"
	"auth-service/internal/models"
	"auth-service/internal/repository/postgres"
	"auth-service/internal/util"

	"github.com/google/uuid"
	lru "github.com/hashicorp/golang-lru/v2"
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
	userRepo      postgres.UserRepository
	hasher        *hashing.Hasher
	encryptionMgr *encryption.EncryptionManager
	logger        *zap.Logger
	localCache    *lru.Cache[uuid.UUID, *models.User]
	phoneCache    *lru.Cache[string, uuid.UUID]
	distCache     *DistributedCache
	rateLimiter   *RateLimiter
	logProducer   *LogProducerService
}

type RateLimiter struct {
	loginAttempts *sync.Map
	mpinAttempts  *sync.Map
	mutex         sync.RWMutex
}

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
type EncryptedData struct {
	EncryptedData string
	EncryptedDEK  string
	KeyID         string
}
type KYCUpdateRequest struct {
	UserID     uuid.UUID `json:"user_id" validate:"required"`
	Status     string    `json:"status" validate:"required,oneof=pending verified rejected expired under_review"`
	Level      string    `json:"level" validate:"required,oneof=basic advanced full"`
	Reason     string    `json:"reason,omitempty"`
	VerifiedBy uuid.UUID `json:"verified_by" validate:"required"`
}

type BanUserRequest struct {
	UserID   uuid.UUID `json:"user_id" validate:"required"`
	BannedBy uuid.UUID `json:"banned_by" validate:"required"`
	Reason   string    `json:"reason" validate:"required,min=10,max=500"`
}

func NewUserService(
	userRepo postgres.UserRepository,
	hasher *hashing.Hasher,
	encryptionMgr *encryption.EncryptionManager,
	logger *zap.Logger,
) *UserService {
	userCache, _ := lru.New[uuid.UUID, *models.User](1_000_000)
	phoneCache, _ := lru.New[string, uuid.UUID](1_000_000)

	return &UserService{
		userRepo:      userRepo,
		hasher:        hasher,
		encryptionMgr: encryptionMgr,
		logger:        logger,
		localCache:    userCache,
		phoneCache:    phoneCache,
		rateLimiter:   &RateLimiter{loginAttempts: &sync.Map{}, mpinAttempts: &sync.Map{}},
	}
}

func NewUserServiceWithCache(
	userRepo postgres.UserRepository,
	hasher *hashing.Hasher,
	encryptionMgr *encryption.EncryptionManager,
	distCache *DistributedCache,
	logger *zap.Logger,
) *UserService {
	service := NewUserService(userRepo, hasher, encryptionMgr, logger)
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

	s.cacheUser(ctx, user)
	s.cachePhoneMapping(ctx, phoneHash, user.UserID)
	return user, nil
}

// DecryptPhoneNumber decrypts the user's phone number - FIXED VERSION
func (s *UserService) DecryptPhoneNumber(ctx context.Context, user *models.User) (string, error) {
	if len(user.PhoneEncrypted) == 0 {
		return "", fmt.Errorf("no encrypted phone data available")
	}

	// ✅ CORRECT: Create proper encrypted data structure
	encryptedData := &encryption.EncryptedData{
		EncryptedValue: string(user.PhoneEncrypted),
		EncryptedDEK:   user.PhoneEncryptedDEK,
		KeyID:          user.PhoneKeyID.String(),
	}

	// ✅ Use DecryptField
	return s.encryptionMgr.DecryptField(ctx, encryptedData)
}

// ReencryptPhoneNumber re-encrypts the phone number with a new key - FIXED VERSION
func (s *UserService) ReencryptPhoneNumber(ctx context.Context, userID uuid.UUID) error {
	user, err := s.GetUserByID(ctx, userID)
	if err != nil {
		return err
	}

	// Decrypt current phone number
	phoneNumber, err := s.DecryptPhoneNumber(ctx, user)
	if err != nil {
		return fmt.Errorf("failed to decrypt phone number: %w", err)
	}

	// Re-encrypt with new key
	encryptedPhone, err := s.encryptionMgr.EncryptField(ctx, phoneNumber, "phone")
	if err != nil {
		return fmt.Errorf("failed to re-encrypt phone number: %w", err)
	}

	keyID, err := uuid.Parse(encryptedPhone.KeyID)
	if err != nil {
		return fmt.Errorf("failed to parse key ID: %w", err)
	}

	// ✅ FIXED: Use UpdateUserFields to update all encrypted fields
	fields := map[string]interface{}{
		"phone_encrypted":     []byte(encryptedPhone.EncryptedValue),
		"phone_key_id":        keyID,
		"phone_encrypted_dek": encryptedPhone.EncryptedDEK,
		"updated_at":          time.Now().UTC(),
	}

	if err := s.userRepo.UpdateUserFields(ctx, userID, fields); err != nil {
		return fmt.Errorf("failed to update user with re-encrypted phone: %w", err)
	}

	s.invalidateUserCache(ctx, userID)
	s.logger.Info("Phone number re-encrypted successfully",
		util.String("user_id", userID.String()),
	)

	return nil
}

// CreateUser creates a new user with encrypted phone number
func (s *UserService) CreateUser(ctx context.Context, req *UserCreateRequest) (*models.User, error) {
	startTime := time.Now()

	if err := s.validateCreateRequest(req); err != nil {
		return nil, fmt.Errorf("%w: %v", ErrInvalidInput, err)
	}

	phoneHash := s.GeneratePhoneHash(req.PhoneNumber)

	existingUser, err := s.userRepo.GetUserByPhoneHash(ctx, phoneHash)
	if err == nil && existingUser != nil {
		return nil, ErrUserAlreadyExists
	}

	userID := uuid.New()

	// ✅ FIXED: Use correct encryption method and struct
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

	keyID, err := uuid.Parse(encryptedPhone.KeyID)
	if err != nil {
		return nil, fmt.Errorf("failed to parse key ID: %w", err)
	}

	now := time.Now().UTC()
	user := &models.User{
		UserID:            userID,
		PhoneHash:         phoneHash,
		PhoneEncrypted:    []byte(encryptedPhone.EncryptedValue),
		PhoneKeyID:        keyID,
		PhoneEncryptedDEK: encryptedPhone.EncryptedDEK, // ✅ This is set
		DeviceID:          req.DeviceID,
		DeviceFingerprint: req.DeviceFingerprint,
		KYCStatus:         models.KYCStatusPending,
		KYCLevel:          models.KYCLevelBasic,
		KYCVerifiedAt:     nil,
		IsVerified:        false,
		IsActive:          true,
		DataRegion:        req.DataRegion,
		CreatedAt:         now,
		UpdatedAt:         now,
		LastLogin:         nil,
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
		util.Duration("duration", time.Since(startTime)),
	)

	return user, nil
}

// CreateUserForCompanyOwner creates a user for a company owner
func (s *UserService) CreateUserForCompanyOwner(ctx context.Context, phone, dataRegion string) (*models.User, error) {
	startTime := time.Now()

	if phone == "" {
		return nil, fmt.Errorf("phone number is required")
	}
	if dataRegion == "" {
		return nil, fmt.Errorf("data region is required")
	}

	phoneHash := s.GeneratePhoneHash(phone)

	existingUser, err := s.userRepo.GetUserByPhoneHash(ctx, phoneHash)
	if err == nil && existingUser != nil {
		return existingUser, nil
	}

	userID := uuid.New()

	// ✅ FIXED: Use correct encrypt method
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
		UserID:            userID,
		PhoneHash:         phoneHash,
		PhoneEncrypted:    []byte(encryptedPhone.EncryptedValue),
		PhoneKeyID:        keyID,
		PhoneEncryptedDEK: encryptedPhone.EncryptedDEK, // ✅ This is set
		DeviceID:          "company-owner-admin",
		DeviceFingerprint: "company-owner-admin",
		KYCStatus:         models.KYCStatusPending,
		KYCLevel:          models.KYCLevelBasic,
		KYCVerifiedAt:     nil,
		IsVerified:        false,
		IsActive:          true,
		DataRegion:        dataRegion,
		CreatedAt:         now,
		UpdatedAt:         now,
		LastLogin:         nil,
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
			"data_region": dataRegion,
			"purpose":     "company_owner",
		},
		Duration: int64(time.Since(startTime).Milliseconds()),
	})

	s.logger.Info("Company owner user created successfully",
		util.String("user_id", userID.String()),
		util.String("phone_hash", phoneHash),
		util.Duration("duration", time.Since(startTime)),
	)

	return user, nil
}

func (s *UserService) GetUserByID(ctx context.Context, userID uuid.UUID) (*models.User, error) {
	if user, ok := s.localCache.Get(userID); ok {
		// ✅ Optional: Validate that encrypted data is complete
		if err := s.validateUserEncryptionData(user); err != nil {
			s.logger.Warn("User encryption data incomplete in cache",
				util.String("user_id", userID.String()),
				util.ErrorField(err))
			// Continue to fetch from database
		} else {
			return user, nil
		}
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

	if !user.IsActive {
		return nil, fmt.Errorf("user account is inactive")
	}

	s.cacheUser(ctx, user)
	return user, nil
}

// Helper method to validate encryption data
func (s *UserService) validateUserEncryptionData(user *models.User) error {
	if len(user.PhoneEncrypted) == 0 {
		return fmt.Errorf("phone encrypted data is empty")
	}
	if user.PhoneKeyID == uuid.Nil {
		return fmt.Errorf("phone key ID is empty")
	}
	if user.PhoneEncryptedDEK == "" {
		return fmt.Errorf("phone encrypted DEK is empty")
	}
	return nil
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
	if req.DataRegion != nil && *req.DataRegion != user.DataRegion {
		changes["data_region"] = map[string]interface{}{
			"old": user.DataRegion,
			"new": *req.DataRegion,
		}
		user.DataRegion = *req.DataRegion
	}

	user.UpdatedAt = time.Now().UTC()

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
			UserID:    userID.String(),
			Action:    "update_user",
			Status:    "failed",
			ErrorCode: "UPDATE_USER_FAILED",
			Changes:   changes,
			Duration:  int64(time.Since(startTime).Milliseconds()),
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

func (s *UserService) UpdateUserStatus(ctx context.Context, userID uuid.UUID, isVerified, isActive bool) error {
	startTime := time.Now()

	user, err := s.GetUserByID(ctx, userID)
	if err != nil {
		return err
	}

	if err := s.userRepo.UpdateUserStatus(ctx, userID, isVerified, isActive); err != nil {
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
			UserID:    userID.String(),
			Action:    "update_user_status",
			Status:    "failed",
			ErrorCode: "UPDATE_STATUS_FAILED",
			Duration:  int64(time.Since(startTime).Milliseconds()),
		})
		return fmt.Errorf("failed to update user status: %w", err)
	}

	oldVerified := user.IsVerified
	oldActive := user.IsActive

	user.IsVerified = isVerified
	user.IsActive = isActive
	user.UpdatedAt = time.Now().UTC()

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
		UserID: userID.String(),
		Action: "update_user_status",
		Status: "success",
		Changes: map[string]interface{}{
			"is_verified": map[string]interface{}{"old": oldVerified, "new": isVerified},
			"is_active":   map[string]interface{}{"old": oldActive, "new": isActive},
		},
		Duration: int64(time.Since(startTime).Milliseconds()),
	})

	s.logger.Info("User status updated",
		util.String("user_id", userID.String()),
		util.Bool("verified", isVerified),
		util.Bool("active", isActive),
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

func (s *UserService) UpdateKYCStatus(ctx context.Context, req *KYCUpdateRequest) error {
	startTime := time.Now()

	user, err := s.GetUserByID(ctx, req.UserID)
	if err != nil {
		return err
	}

	if err := s.validateKYCStatusTransition(user.KYCStatus, req.Status); err != nil {
		return err
	}

	// FIXED: Use UpdateUserFields instead of UpdateKYCStatus with wrong parameters
	now := time.Now().UTC()
	fields := map[string]interface{}{
		"kyc_status":      req.Status,
		"kyc_level":       req.Level,
		"kyc_verified_at": &now,
		"updated_at":      now,
	}

	if req.Status == models.KYCStatusVerified {
		fields["is_verified"] = true
	}

	if err := s.userRepo.UpdateUserFields(ctx, req.UserID, fields); err != nil {
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
			UserID:    req.UserID.String(),
			Action:    "update_kyc_status",
			Status:    "failed",
			ErrorCode: "UPDATE_KYC_FAILED",
			Duration:  int64(time.Since(startTime).Milliseconds()),
		})
		return fmt.Errorf("failed to update KYC status: %w", err)
	}

	oldStatus := user.KYCStatus
	oldLevel := user.KYCLevel

	user.KYCStatus = req.Status
	user.KYCLevel = req.Level
	user.KYCVerifiedAt = &now
	user.UpdatedAt = now

	if req.Status == models.KYCStatusVerified {
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
		UserID: req.UserID.String(),
		Action: "update_kyc_status",
		Status: "success",
		Changes: map[string]interface{}{
			"old_status":  oldStatus,
			"new_status":  req.Status,
			"old_level":   oldLevel,
			"new_level":   req.Level,
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

func (s *UserService) GetUsersByKYCStatus(ctx context.Context, status string, limit, offset int) ([]*models.User, int, error) {
	if limit <= 0 || limit > 1000 {
		limit = 100
	}
	if offset < 0 {
		offset = 0
	}

	return s.userRepo.GetUsersByKYCStatus(ctx, status, limit, offset)
}

// ============================================================================
// CACHE METHODS - FIXED
// ============================================================================

func (s *UserService) cacheUser(ctx context.Context, user *models.User) {
	// ✅ Validate we have complete encryption data before caching
	if err := s.validateUserEncryptionData(user); err != nil {
		s.logger.Warn("Not caching user with incomplete encryption data",
			util.String("user_id", user.UserID.String()),
			util.ErrorField(err))
		return
	}

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

// ============================================================================
// VALIDATION METHODS
// ============================================================================

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

func (s *UserService) validateKYCStatusTransition(currentStatus, newStatus string) error {
	validTransitions := map[string][]string{
		models.KYCStatusPending:     {models.KYCStatusVerified, models.KYCStatusRejected, models.KYCStatusUnderReview},
		models.KYCStatusVerified:    {models.KYCStatusExpired, models.KYCStatusRejected},
		models.KYCStatusRejected:    {models.KYCStatusPending, models.KYCStatusVerified},
		models.KYCStatusUnderReview: {models.KYCStatusVerified, models.KYCStatusRejected},
		models.KYCStatusExpired:     {models.KYCStatusPending, models.KYCStatusVerified},
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

// ============================================================================
// HEALTH & STATS
// ============================================================================

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
		"local_cache_size": s.localCache.Len(),
		"phone_cache_size": s.phoneCache.Len(),
		"local_cache_cap":  1_000_000,
		"phone_cache_cap":  1_000_000,
		"has_redis_cache":  s.distCache != nil,
		"repository":       repoStats,
		"timestamp":        time.Now().UTC(),
	}

	return stats, nil
}

func (s *UserService) Cleanup() {
	s.localCache.Purge()
	s.phoneCache.Purge()
}

// ============================================================================
// UTILITY FUNCTIONS
// ============================================================================

// ============================================================================
// NEW SERVICE METHODS
// ============================================================================

// SoftDeleteUser soft deletes a user by marking as inactive
func (s *UserService) SoftDeleteUser(ctx context.Context, userID uuid.UUID, reason string) error {
	startTime := time.Now()

	user, err := s.GetUserByID(ctx, userID)
	if err != nil {
		return err
	}

	if err := s.userRepo.SoftDeleteUser(ctx, userID); err != nil {
		s.logUserEvent(ctx, &models.UserLogEvent{
			LogEnvelope: models.LogEnvelope{
				EventID:     uuid.New().String(),
				EventType:   "user",
				ServiceName: "auth-service",
				Timestamp:   time.Now(),
				Environment: "production",
				Version:     "v1.0.0",
				Level:       "error",
				Message:     "Failed to soft delete user",
			},
			UserID:    userID.String(),
			Action:    "soft_delete_user",
			Status:    "failed",
			ErrorCode: "SOFT_DELETE_FAILED",
			Duration:  int64(time.Since(startTime).Milliseconds()),
		})
		return fmt.Errorf("failed to soft delete user: %w", err)
	}

	s.invalidateUserCache(ctx, userID)

	s.logUserEvent(ctx, &models.UserLogEvent{
		LogEnvelope: models.LogEnvelope{
			EventID:     uuid.New().String(),
			EventType:   "user",
			ServiceName: "auth-service",
			Timestamp:   time.Now(),
			Environment: "production",
			Version:     "v1.0.0",
			Level:       "info",
			Message:     "User soft deleted successfully",
		},
		UserID: userID.String(),
		Action: "soft_delete_user",
		Status: "success",
		Changes: map[string]interface{}{
			"old_is_active": user.IsActive,
			"new_is_active": false,
			"reason":        reason,
		},
		Duration: int64(time.Since(startTime).Milliseconds()),
	})

	return nil
}

// ReactivateUser reactivates a soft-deleted user
func (s *UserService) ReactivateUser(ctx context.Context, userID uuid.UUID) error {
	startTime := time.Now()

	user, err := s.GetUserByID(ctx, userID)
	if err != nil {
		return err
	}

	if err := s.userRepo.ReactivateUser(ctx, userID); err != nil {
		s.logUserEvent(ctx, &models.UserLogEvent{
			LogEnvelope: models.LogEnvelope{
				EventID:     uuid.New().String(),
				EventType:   "user",
				ServiceName: "auth-service",
				Timestamp:   time.Now(),
				Environment: "production",
				Version:     "v1.0.0",
				Level:       "error",
				Message:     "Failed to reactivate user",
			},
			UserID:    userID.String(),
			Action:    "reactivate_user",
			Status:    "failed",
			ErrorCode: "REACTIVATE_FAILED",
			Duration:  int64(time.Since(startTime).Milliseconds()),
		})
		return fmt.Errorf("failed to reactivate user: %w", err)
	}

	s.invalidateUserCache(ctx, userID)

	s.logUserEvent(ctx, &models.UserLogEvent{
		LogEnvelope: models.LogEnvelope{
			EventID:     uuid.New().String(),
			EventType:   "user",
			ServiceName: "auth-service",
			Timestamp:   time.Now(),
			Environment: "production",
			Version:     "v1.0.0",
			Level:       "info",
			Message:     "User reactivated successfully",
		},
		UserID: userID.String(),
		Action: "reactivate_user",
		Status: "success",
		Changes: map[string]interface{}{
			"old_is_active": user.IsActive,
			"new_is_active": true,
		},
		Duration: int64(time.Since(startTime).Milliseconds()),
	})

	return nil
}

// SearchUsers searches users with various filters
func (s *UserService) SearchUsers(ctx context.Context, filters map[string]interface{}, limit, offset int) ([]*models.User, int, error) {
	if limit <= 0 || limit > 1000 {
		limit = 100
	}
	if offset < 0 {
		offset = 0
	}

	users, totalCount, err := s.userRepo.SearchUsers(ctx, filters, limit, offset)
	if err != nil {
		return nil, 0, fmt.Errorf("failed to search users: %w", err)
	}

	// Cache the found users
	for _, user := range users {
		s.cacheUser(ctx, user)
	}

	return users, totalCount, nil
}

// GetRecentlyActiveUsers gets users active since the given time
func (s *UserService) GetRecentlyActiveUsers(ctx context.Context, since time.Time, limit int) ([]*models.User, error) {
	if limit <= 0 || limit > 1000 {
		limit = 100
	}

	users, err := s.userRepo.GetRecentlyActiveUsers(ctx, since, limit)
	if err != nil {
		return nil, fmt.Errorf("failed to get recently active users: %w", err)
	}

	// Cache the found users
	for _, user := range users {
		s.cacheUser(ctx, user)
	}

	return users, nil
}

// GetInactiveUsersSince gets users inactive since the given time
func (s *UserService) GetInactiveUsersSince(ctx context.Context, since time.Time, limit int) ([]*models.User, error) {
	if limit <= 0 || limit > 1000 {
		limit = 100
	}

	users, err := s.userRepo.GetInactiveUsersSince(ctx, since, limit)
	if err != nil {
		return nil, fmt.Errorf("failed to get inactive users: %w", err)
	}

	return users, nil
}

// RecordLoginAttempt records a user login attempt
func (s *UserService) RecordLoginAttempt(ctx context.Context, userID uuid.UUID, success bool, ip, userAgent string) error {
	if err := s.userRepo.RecordLoginAttempt(ctx, userID, success, ip, userAgent); err != nil {
		s.logger.Warn("Failed to record login attempt",
			util.String("user_id", userID.String()),
			util.ErrorField(err))
		return fmt.Errorf("failed to record login attempt: %w", err)
	}

	// Update last login if successful
	if success {
		if err := s.UpdateLastLogin(ctx, userID); err != nil {
			s.logger.Warn("Failed to update last login after successful attempt",
				util.String("user_id", userID.String()),
				util.ErrorField(err))
		}
	}

	return nil
}

// GetRecentLoginAttempts gets recent login attempts for a user
func (s *UserService) GetRecentLoginAttempts(ctx context.Context, userID uuid.UUID, limit int) ([]models.LoginAttempt, error) {
	if limit <= 0 || limit > 100 {
		limit = 50
	}

	attempts, err := s.userRepo.GetRecentLoginAttempts(ctx, userID, limit)
	if err != nil {
		return nil, fmt.Errorf("failed to get recent login attempts: %w", err)
	}

	return attempts, nil
}

// GetUserGrowthMetrics gets comprehensive user growth metrics
func (s *UserService) GetUserGrowthMetrics(ctx context.Context, since time.Time) (map[string]interface{}, error) {
	metrics, err := s.userRepo.GetUserGrowthMetrics(ctx, since)
	if err != nil {
		return nil, fmt.Errorf("failed to get user growth metrics: %w", err)
	}

	return metrics, nil
}

// GetUserActivityStats gets user activity statistics
func (s *UserService) GetUserActivityStats(ctx context.Context, since time.Time) (map[string]interface{}, error) {
	stats, err := s.userRepo.GetUserActivityStats(ctx, since)
	if err != nil {
		return nil, fmt.Errorf("failed to get user activity stats: %w", err)
	}

	return stats, nil
}

// GetKYCDistribution gets KYC status distribution
func (s *UserService) GetKYCDistribution(ctx context.Context) (map[string]int, error) {
	distribution, err := s.userRepo.GetKYCDistribution(ctx)
	if err != nil {
		return nil, fmt.Errorf("failed to get KYC distribution: %w", err)
	}

	return distribution, nil
}

// GetActiveUserCountsByRegion gets active user counts by region
func (s *UserService) GetActiveUserCountsByRegion(ctx context.Context) (map[string]int, error) {
	counts, err := s.userRepo.GetActiveUserCountsByRegion(ctx)
	if err != nil {
		return nil, fmt.Errorf("failed to get active user counts by region: %w", err)
	}

	return counts, nil
}

// AddUserDevice adds a new device for a user
func (s *UserService) AddUserDevice(ctx context.Context, device *models.UserDevice) error {
	if err := s.userRepo.AddUserDevice(ctx, device); err != nil {
		return fmt.Errorf("failed to add user device: %w", err)
	}

	s.logger.Info("User device added",
		util.String("user_id", device.UserID.String()),
		util.String("device_id", device.DeviceID))

	return nil
}

// GetUserDevices gets all devices for a user
func (s *UserService) GetUserDevices(ctx context.Context, userID uuid.UUID) ([]models.UserDevice, error) {
	devices, err := s.userRepo.GetUserDevices(ctx, userID)
	if err != nil {
		return nil, fmt.Errorf("failed to get user devices: %w", err)
	}

	return devices, nil
}

// RemoveUserDevice removes a device from a user
func (s *UserService) RemoveUserDevice(ctx context.Context, userID uuid.UUID, deviceID string) error {
	if err := s.userRepo.RemoveUserDevice(ctx, userID, deviceID); err != nil {
		return fmt.Errorf("failed to remove user device: %w", err)
	}

	s.logger.Info("User device removed",
		util.String("user_id", userID.String()),
		util.String("device_id", deviceID))

	return nil
}

// ArchiveInactiveUsers archives users inactive since before the given date
func (s *UserService) ArchiveInactiveUsers(ctx context.Context, before time.Time) (int, error) {
	count, err := s.userRepo.ArchiveInactiveUsers(ctx, before)
	if err != nil {
		return 0, fmt.Errorf("failed to archive inactive users: %w", err)
	}

	s.logger.Info("Inactive users archived",
		util.Int("count", count),
		util.Time("inactive_since", before))

	return count, nil
}

// UpdateUserFields updates specific fields of a user
func (s *UserService) UpdateUserFields(ctx context.Context, userID uuid.UUID, fields map[string]interface{}) error {
	startTime := time.Now()

	if err := s.userRepo.UpdateUserFields(ctx, userID, fields); err != nil {
		s.logUserEvent(ctx, &models.UserLogEvent{
			LogEnvelope: models.LogEnvelope{
				EventID:     uuid.New().String(),
				EventType:   "user",
				ServiceName: "auth-service",
				Timestamp:   time.Now(),
				Environment: "production",
				Version:     "v1.0.0",
				Level:       "error",
				Message:     "Failed to update user fields",
			},
			UserID:    userID.String(),
			Action:    "update_user_fields",
			Status:    "failed",
			ErrorCode: "UPDATE_FIELDS_FAILED",
			Duration:  int64(time.Since(startTime).Milliseconds()),
		})
		return fmt.Errorf("failed to update user fields: %w", err)
	}

	s.invalidateUserCache(ctx, userID)

	s.logUserEvent(ctx, &models.UserLogEvent{
		LogEnvelope: models.LogEnvelope{
			EventID:     uuid.New().String(),
			EventType:   "user",
			ServiceName: "auth-service",
			Timestamp:   time.Now(),
			Environment: "production",
			Version:     "v1.0.0",
			Level:       "info",
			Message:     "User fields updated successfully",
		},
		UserID:   userID.String(),
		Action:   "update_user_fields",
		Status:   "success",
		Changes:  fields,
		Duration: int64(time.Since(startTime).Milliseconds()),
	})

	return nil
}

// GetUserByDeviceFingerprint gets a user by device fingerprint
func (s *UserService) GetUserByDeviceFingerprint(ctx context.Context, fingerprint string) (*models.User, error) {
	user, err := s.userRepo.GetUserByDeviceFingerprint(ctx, fingerprint)
	if err != nil {
		return nil, fmt.Errorf("failed to get user by device fingerprint: %w", err)
	}

	s.cacheUser(ctx, user)
	return user, nil
}

// UpdatePhoneNumber updates a user's phone number with proper encryption and validation
func (s *UserService) UpdatePhoneNumber(ctx context.Context, userID uuid.UUID, newPhoneNumber string) error {
	startTime := time.Now()

	// Validate input
	if newPhoneNumber == "" {
		return fmt.Errorf("%w: phone number cannot be empty", ErrInvalidInput)
	}
	if len(newPhoneNumber) < 10 || len(newPhoneNumber) > 15 {
		return fmt.Errorf("%w: phone number must be between 10 and 15 characters", ErrInvalidInput)
	}

	// Get existing user
	user, err := s.GetUserByID(ctx, userID)
	if err != nil {
		return fmt.Errorf("failed to get user: %w", err)
	}

	// Generate new phone hash
	newPhoneHash := s.GeneratePhoneHash(newPhoneNumber)

	// Check if new phone number is already registered to another user
	existingUser, err := s.userRepo.GetUserByPhoneHash(ctx, newPhoneHash)
	if err == nil && existingUser != nil && existingUser.UserID != userID {
		return fmt.Errorf("%w: phone number already registered to another user", ErrUserAlreadyExists)
	}

	// Encrypt the new phone number
	encryptedPhone, err := s.encryptionMgr.EncryptField(ctx, newPhoneNumber, "phone")
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
				Message:     "Failed to encrypt new phone number",
			},
			UserID:      userID.String(),
			Action:      "update_phone_number",
			PhoneNumber: newPhoneNumber,
			Status:      "failed",
			ErrorCode:   "PHONE_ENCRYPTION_FAILED",
			Duration:    int64(time.Since(startTime).Milliseconds()),
		})
		return fmt.Errorf("failed to encrypt new phone number: %w", err)
	}

	keyID, err := uuid.Parse(encryptedPhone.KeyID)
	if err != nil {
		return fmt.Errorf("failed to parse key ID: %w", err)
	}

	// ✅ CORRECT: Update all phone encryption fields
	fields := map[string]interface{}{
		"phone_hash":          newPhoneHash,
		"phone_encrypted":     []byte(encryptedPhone.EncryptedValue),
		"phone_key_id":        keyID,
		"phone_encrypted_dek": encryptedPhone.EncryptedDEK, // ✅ This is now stored
		"updated_at":          time.Now().UTC(),
	}

	if err := s.userRepo.UpdateUserFields(ctx, userID, fields); err != nil {
		s.logUserEvent(ctx, &models.UserLogEvent{
			LogEnvelope: models.LogEnvelope{
				EventID:     uuid.New().String(),
				EventType:   "user",
				ServiceName: "auth-service",
				Timestamp:   time.Now(),
				Environment: "production",
				Version:     "v1.0.0",
				Level:       "error",
				Message:     "Failed to update phone number in database",
			},
			UserID:      userID.String(),
			Action:      "update_phone_number",
			PhoneNumber: newPhoneNumber,
			Status:      "failed",
			ErrorCode:   "UPDATE_PHONE_FAILED",
			Duration:    int64(time.Since(startTime).Milliseconds()),
		})
		return fmt.Errorf("failed to update phone number: %w", err)
	}

	// Invalidate old phone mapping and cache
	oldPhoneHash := user.PhoneHash
	s.invalidateUserCache(ctx, userID)

	// Remove old phone mapping from cache
	s.phoneCache.Remove(oldPhoneHash)
	if s.distCache != nil {
		// Use the correct method to invalidate the old phone mapping in Redis
		if err := s.distCache.InvalidatePhone(ctx, oldPhoneHash); err != nil {
			s.logger.Warn("Failed to invalidate old phone mapping in Redis",
				util.String("old_phone_hash", oldPhoneHash),
				util.ErrorField(err))
		}
	}

	// Update user object and cache
	user.PhoneHash = newPhoneHash
	user.PhoneEncrypted = []byte(encryptedPhone.EncryptedValue)
	user.PhoneKeyID = keyID
	user.PhoneEncryptedDEK = encryptedPhone.EncryptedDEK
	user.UpdatedAt = time.Now().UTC()

	s.cacheUser(ctx, user)
	s.cachePhoneMapping(ctx, newPhoneHash, userID)

	s.logUserEvent(ctx, &models.UserLogEvent{
		LogEnvelope: models.LogEnvelope{
			EventID:     uuid.New().String(),
			EventType:   "user",
			ServiceName: "auth-service",
			Timestamp:   time.Now(),
			Environment: "production",
			Version:     "v1.0.0",
			Level:       "info",
			Message:     "Phone number updated successfully",
		},
		UserID:      userID.String(),
		Action:      "update_phone_number",
		PhoneNumber: newPhoneNumber,
		Status:      "success",
		Changes: map[string]interface{}{
			"old_phone_hash": oldPhoneHash,
			"new_phone_hash": newPhoneHash,
		},
		Duration: int64(time.Since(startTime).Milliseconds()),
	})

	s.logger.Info("Phone number updated successfully",
		util.String("user_id", userID.String()),
		util.String("new_phone_hash", newPhoneHash),
		util.Duration("duration", time.Since(startTime)),
	)

	return nil
}

// BanUser bans a user by setting is_active to false and records the ban reason
func (s *UserService) BanUser(ctx context.Context, req *BanUserRequest) error {
	startTime := time.Now()

	user, err := s.GetUserByID(ctx, req.UserID)
	if err != nil {
		return err
	}

	if !user.IsActive {
		return fmt.Errorf("user is already banned")
	}

	// Update user fields to ban the user
	fields := map[string]interface{}{
		"is_active":  false,
		"updated_at": time.Now().UTC(),
	}

	if err := s.userRepo.UpdateUserFields(ctx, req.UserID, fields); err != nil {
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
			UserID:    req.UserID.String(),
			Action:    "ban_user",
			Status:    "failed",
			ErrorCode: "BAN_USER_FAILED",
			Duration:  int64(time.Since(startTime).Milliseconds()),
		})
		return fmt.Errorf("failed to ban user: %w", err)
	}

	// Invalidate cache
	s.invalidateUserCache(ctx, req.UserID)

	s.logUserEvent(ctx, &models.UserLogEvent{
		LogEnvelope: models.LogEnvelope{
			EventID:     uuid.New().String(),
			EventType:   "user",
			ServiceName: "auth-service",
			Timestamp:   time.Now(),
			Environment: "production",
			Version:     "v1.0.0",
			Level:       "info",
			Message:     "User banned successfully",
		},
		UserID: req.UserID.String(),
		Action: "ban_user",
		Status: "success",
		Changes: map[string]interface{}{
			"old_is_active": true,
			"new_is_active": false,
			"banned_by":     req.BannedBy.String(),
			"reason":        req.Reason,
		},
		Duration: int64(time.Since(startTime).Milliseconds()),
	})

	s.logger.Info("User banned successfully",
		util.String("user_id", req.UserID.String()),
		util.String("banned_by", req.BannedBy.String()),
		util.String("reason", req.Reason),
	)

	return nil
}

// UnbanUser unbans a user by setting is_active to true
func (s *UserService) UnbanUser(ctx context.Context, userID, unbannedBy uuid.UUID, reason string) error {
	startTime := time.Now()

	// Use repository directly to get user without active status check
	user, err := s.userRepo.GetUserByID(ctx, userID)
	if err != nil {
		return fmt.Errorf("failed to get user: %w", err)
	}

	// If user is already active, no need to unban
	if user.IsActive {
		return fmt.Errorf("user is not banned")
	}

	// Update user fields to unban the user
	fields := map[string]interface{}{
		"is_active":  true,
		"updated_at": time.Now().UTC(),
	}

	if err := s.userRepo.UpdateUserFields(ctx, userID, fields); err != nil {
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
			UserID:    userID.String(),
			Action:    "unban_user",
			Status:    "failed",
			ErrorCode: "UNBAN_USER_FAILED",
			Duration:  int64(time.Since(startTime).Milliseconds()),
		})
		return fmt.Errorf("failed to unban user: %w", err)
	}

	// Invalidate cache
	s.invalidateUserCache(ctx, userID)

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
		UserID: userID.String(),
		Action: "unban_user",
		Status: "success",
		Changes: map[string]interface{}{
			"old_is_active": false,
			"new_is_active": true,
			"unbanned_by":   unbannedBy.String(),
			"reason":        reason,
		},
		Duration: int64(time.Since(startTime).Milliseconds()),
	})

	s.logger.Info("User unbanned successfully",
		util.String("user_id", userID.String()),
		util.String("unbanned_by", unbannedBy.String()),
		util.String("reason", reason),
	)

	return nil
}

// ============================================================================
// UTILITY FUNCTIONS
// ============================================================================

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}

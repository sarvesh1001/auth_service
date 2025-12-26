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

// CompanyEmployeeSearchResult for company employee search
type CompanyEmployeeSearchResult struct {
	UserID         uuid.UUID  `db:"user_id" json:"user_id"`
	Username       string     `db:"username" json:"username"`
	FullName       *string    `db:"full_name" json:"full_name,omitempty"`
	PhoneHash      string     `db:"phone_hash" json:"phone_hash"`
	EmployeeID     string     `db:"employee_id" json:"employee_id"`
	RoleID         uuid.UUID  `db:"role_id" json:"role_id"`
	RoleName       string     `db:"role_name" json:"role_name"`
	DepartmentID   *uuid.UUID `db:"department_id" json:"department_id,omitempty"`
	DepartmentName *string    `db:"department_name" json:"department_name,omitempty"`
	HireDate       time.Time  `db:"hire_date" json:"hire_date"`
	IsActive       bool       `db:"is_active" json:"is_active"`
	ReportsTo      *uuid.UUID `db:"reports_to" json:"reports_to,omitempty"`
	ReportsToName  *string    `db:"reports_to_name" json:"reports_to_name,omitempty"`
	CreatedAt      time.Time  `db:"created_at" json:"created_at"`
	RelevanceScore float64    `db:"relevance_score" json:"relevance_score"`
	MatchType      string     `db:"match_type" json:"match_type"`
}

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
	Username          string `json:"username" validate:"required,min=3,max=100,alphanum"`
	FullName          string `json:"full_name" validate:"max=255"`
	PhoneNumber       string `json:"phone_number" validate:"required"`
	DeviceID          string `json:"device_id" validate:"required"`
	DeviceFingerprint string `json:"device_fingerprint" validate:"required"`
	DataRegion        string `json:"data_region" validate:"required"`
	ConsentAgreed     bool   `json:"consent_agreed"`
	ConsentVersion    string `json:"consent_version" validate:"required"`
	KYCStatus         string `json:"kyc_status" validate:"omitempty,oneof=pending verified rejected under_review expired"`
	KYCLevel          string `json:"kyc_level" validate:"omitempty,oneof=basic advanced full"`
}

type UserUpdateRequest struct {
	Username          *string `json:"username,omitempty" validate:"omitempty,min=3,max=100,alphanum"`
	FullName          *string `json:"full_name,omitempty" validate:"omitempty,max=255"`
	DeviceID          *string `json:"device_id,omitempty"`
	DeviceFingerprint *string `json:"device_fingerprint,omitempty"`
	DataRegion        *string `json:"data_region,omitempty" validate:"omitempty,oneof=us eu as"`
	IsVerified        *bool   `json:"is_verified,omitempty"`
	IsActive          *bool   `json:"is_active,omitempty"`
	KYCStatus         *string `json:"kyc_status,omitempty" validate:"omitempty,oneof=pending verified rejected under_review expired"`
	KYCLevel          *string `json:"kyc_level,omitempty" validate:"omitempty,oneof=basic advanced full"`
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

// ============================================================================
// NEW SEARCH METHODS
// ============================================================================

// SearchUsers searches users with full-text and trigram-based search
func (s *UserService) SearchUsers(ctx context.Context, req *models.UserSearchRequest) ([]*models.UserSearchResult, int, error) {
	startTime := time.Now()

	results, total, err := s.userRepo.SearchUsers(ctx, req)
	if err != nil {
		return nil, 0, fmt.Errorf("failed to search users: %w", err)
	}

	s.logger.Debug("User search completed",
		util.String("query", req.Query),
		util.String("search_type", req.SearchType),
		util.Int("results", len(results)),
		util.Int("total", total),
		util.Duration("duration", time.Since(startTime)))

	return results, total, nil
}

// SearchUsersByUsername searches users by username (partial match)
func (s *UserService) SearchUsersByUsername(ctx context.Context, username string, limit int) ([]*models.User, error) {
	if limit <= 0 || limit > 100 {
		limit = 50
	}

	users, err := s.userRepo.SearchUsersByUsername(ctx, username, limit)
	if err != nil {
		return nil, fmt.Errorf("failed to search users by username: %w", err)
	}

	// Cache found users
	for _, user := range users {
		s.cacheUser(ctx, user)
	}

	return users, nil
}

// SearchUsersByFullName searches users by full name (partial match)
func (s *UserService) SearchUsersByFullName(ctx context.Context, fullName string, limit int) ([]*models.User, error) {
	if limit <= 0 || limit > 100 {
		limit = 50
	}

	users, err := s.userRepo.SearchUsersByFullName(ctx, fullName, limit)
	if err != nil {
		return nil, fmt.Errorf("failed to search users by full name: %w", err)
	}

	// Cache found users
	for _, user := range users {
		s.cacheUser(ctx, user)
	}

	return users, nil
}

// GetUserSuggestions returns user suggestions for autocomplete
func (s *UserService) GetUserSuggestions(ctx context.Context, prefix string, limit int) ([]*models.UserSuggestion, error) {
	if limit <= 0 || limit > 20 {
		limit = 10
	}

	suggestions, err := s.userRepo.GetUserSuggestions(ctx, prefix, limit)
	if err != nil {
		return nil, fmt.Errorf("failed to get user suggestions: %w", err)
	}

	return suggestions, nil
}

// FindUserByUsername finds a user by exact username
func (s *UserService) FindUserByUsername(ctx context.Context, username string) (*models.UserByUsername, error) {
	user, err := s.userRepo.FindUserByUsername(ctx, username)
	if err != nil {
		return nil, fmt.Errorf("failed to find user by username: %w", err)
	}

	return user, nil
}

// SearchUsersAdvanced searches users with advanced filters
func (s *UserService) SearchUsersAdvanced(ctx context.Context, filters map[string]interface{}, limit, offset int) ([]*models.User, int, error) {
	if limit <= 0 || limit > 1000 {
		limit = 100
	}
	if offset < 0 {
		offset = 0
	}

	users, total, err := s.userRepo.SearchUsersAdvanced(ctx, filters, limit, offset)
	if err != nil {
		return nil, 0, fmt.Errorf("failed to search users: %w", err)
	}

	// Cache found users
	for _, user := range users {
		s.cacheUser(ctx, user)
	}

	return users, total, nil
}

// GetUserSearchStats gets search statistics
func (s *UserService) GetUserSearchStats(ctx context.Context) (map[string]interface{}, error) {
	stats, err := s.userRepo.GetUserSearchStats(ctx)
	if err != nil {
		return nil, fmt.Errorf("failed to get user search stats: %w", err)
	}

	return stats, nil
}

// ============================================================================
// EXISTING METHODS (UPDATED FOR USERNAME/FULL_NAME)
// ============================================================================

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

func (s *UserService) GetUserByUsername(ctx context.Context, username string) (*models.User, error) {
	user, err := s.userRepo.GetUserByUsername(ctx, username)
	if err != nil {
		return nil, fmt.Errorf("failed to get user by username: %w", err)
	}

	s.cacheUser(ctx, user)
	return user, nil
}

func (s *UserService) GetUserByID(ctx context.Context, userID uuid.UUID) (*models.User, error) {
	if user, ok := s.localCache.Get(userID); ok {
		if err := s.validateUserEncryptionData(user); err != nil {
			s.logger.Warn("User encryption data incomplete in cache",
				util.String("user_id", userID.String()),
				util.ErrorField(err))
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

func (s *UserService) CreateUser(ctx context.Context, req *UserCreateRequest) (*models.User, error) {
	startTime := time.Now()

	if err := s.validateCreateRequest(req); err != nil {
		return nil, fmt.Errorf("%w: %v", ErrInvalidInput, err)
	}

	// Check if username already exists
	existingByUsername, err := s.userRepo.GetUserByUsername(ctx, req.Username)
	if err == nil && existingByUsername != nil {
		return nil, fmt.Errorf("username already exists")
	}

	phoneHash := s.GeneratePhoneHash(req.PhoneNumber)

	existingByPhone, err := s.userRepo.GetUserByPhoneHash(ctx, phoneHash)
	if err == nil && existingByPhone != nil {
		return nil, ErrUserAlreadyExists
	}

	userID := uuid.New()

	// Encrypt phone number
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
			Username:    req.Username,
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
		Username:          req.Username,
		FullName:          req.FullName,
		PhoneHash:         phoneHash,
		PhoneEncrypted:    []byte(encryptedPhone.EncryptedValue),
		PhoneKeyID:        keyID,
		PhoneEncryptedDEK: encryptedPhone.EncryptedDEK,
		DeviceID:          req.DeviceID,
		DeviceFingerprint: req.DeviceFingerprint,
		KYCStatus:         req.KYCStatus,
		KYCLevel:          req.KYCLevel,
		KYCVerifiedAt:     nil,
		IsVerified:        false,
		IsActive:          true,
		DataRegion:        req.DataRegion,
		CreatedAt:         now,
		UpdatedAt:         now,
		LastLogin:         nil,
	}

	if req.KYCStatus == "" {
		user.KYCStatus = models.KYCStatusPending
	}
	if req.KYCLevel == "" {
		user.KYCLevel = models.KYCLevelBasic
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
			Username:    req.Username,
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
		Username:    req.Username,
		FullName:    req.FullName,
		PhoneNumber: req.PhoneNumber,
		Status:      "success",
		DeviceID:    req.DeviceID,
		Changes: map[string]interface{}{
			"data_region":     req.DataRegion,
			"consent_agreed":  req.ConsentAgreed,
			"consent_version": req.ConsentVersion,
			"kyc_status":      user.KYCStatus,
			"kyc_level":       user.KYCLevel,
		},
		Duration: int64(time.Since(startTime).Milliseconds()),
	})

	s.logger.Info("User created successfully",
		util.String("user_id", userID.String()),
		util.String("username", req.Username),
		util.String("phone_hash", phoneHash),
		util.Duration("duration", time.Since(startTime)),
	)

	return user, nil
}

func (s *UserService) UpdateUser(ctx context.Context, userID uuid.UUID, req *UserUpdateRequest) (*models.User, error) {
	startTime := time.Now()

	user, err := s.GetUserByID(ctx, userID)
	if err != nil {
		return nil, err
	}

	changes := make(map[string]interface{})

	// Check if username is being changed and if it's available
	if req.Username != nil && *req.Username != user.Username {
		existingUser, err := s.userRepo.GetUserByUsername(ctx, *req.Username)
		if err == nil && existingUser != nil && existingUser.UserID != userID {
			return nil, fmt.Errorf("username already taken")
		}
		changes["username"] = map[string]interface{}{
			"old": user.Username,
			"new": *req.Username,
		}
		user.Username = *req.Username
	}

	if req.FullName != nil && *req.FullName != user.FullName {
		changes["full_name"] = map[string]interface{}{
			"old": user.FullName,
			"new": *req.FullName,
		}
		user.FullName = *req.FullName
	}

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

	if req.IsVerified != nil && *req.IsVerified != user.IsVerified {
		changes["is_verified"] = map[string]interface{}{
			"old": user.IsVerified,
			"new": *req.IsVerified,
		}
		user.IsVerified = *req.IsVerified
	}

	if req.IsActive != nil && *req.IsActive != user.IsActive {
		changes["is_active"] = map[string]interface{}{
			"old": user.IsActive,
			"new": *req.IsActive,
		}
		user.IsActive = *req.IsActive
	}

	if req.KYCStatus != nil && *req.KYCStatus != user.KYCStatus {
		changes["kyc_status"] = map[string]interface{}{
			"old": user.KYCStatus,
			"new": *req.KYCStatus,
		}
		user.KYCStatus = *req.KYCStatus
	}

	if req.KYCLevel != nil && *req.KYCLevel != user.KYCLevel {
		changes["kyc_level"] = map[string]interface{}{
			"old": user.KYCLevel,
			"new": *req.KYCLevel,
		}
		user.KYCLevel = *req.KYCLevel
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

// ============================================================================
// ADDITIONAL METHODS
// ============================================================================

func (s *UserService) DecryptPhoneNumber(ctx context.Context, user *models.User) (string, error) {
	if len(user.PhoneEncrypted) == 0 {
		return "", fmt.Errorf("no encrypted phone data available")
	}

	encryptedData := &encryption.EncryptedData{
		EncryptedValue: string(user.PhoneEncrypted),
		EncryptedDEK:   user.PhoneEncryptedDEK,
		KeyID:          user.PhoneKeyID.String(),
	}

	return s.encryptionMgr.DecryptField(ctx, encryptedData)
}

func (s *UserService) ReencryptPhoneNumber(ctx context.Context, userID uuid.UUID) error {
	user, err := s.GetUserByID(ctx, userID)
	if err != nil {
		return err
	}

	phoneNumber, err := s.DecryptPhoneNumber(ctx, user)
	if err != nil {
		return fmt.Errorf("failed to decrypt phone number: %w", err)
	}

	encryptedPhone, err := s.encryptionMgr.EncryptField(ctx, phoneNumber, "phone")
	if err != nil {
		return fmt.Errorf("failed to re-encrypt phone number: %w", err)
	}

	keyID, err := uuid.Parse(encryptedPhone.KeyID)
	if err != nil {
		return fmt.Errorf("failed to parse key ID: %w", err)
	}

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
	usernames := make(map[string]bool, len(requests))

	for _, req := range requests {
		phoneHash := s.GeneratePhoneHash(req.PhoneNumber)
		if phoneHashes[phoneHash] {
			return nil, fmt.Errorf("duplicate phone number in batch: %s", req.PhoneNumber)
		}
		phoneHashes[phoneHash] = true

		if usernames[req.Username] {
			return nil, fmt.Errorf("duplicate username in batch: %s", req.Username)
		}
		usernames[req.Username] = true
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
				util.String("username", req.Username),
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

	// Check if anything actually changed
	if user.KYCStatus == req.Status && user.KYCLevel == req.Level {
		s.logger.Info("KYC status unchanged, skipping update",
			util.String("user_id", req.UserID.String()),
			util.String("status", req.Status),
			util.String("level", req.Level),
		)
		return nil // Nothing to update
	}

	// Validate the transition
	if err := s.validateKYCStatusTransition(user.KYCStatus, req.Status); err != nil {
		return err
	}

	now := time.Now().UTC()
	fields := map[string]interface{}{
		"kyc_status": req.Status,
		"kyc_level":  req.Level,
		"updated_at": now,
	}

	// Only set kyc_verified_at if status is changing to verified and wasn't already verified
	if req.Status == models.KYCStatusVerified && user.KYCStatus != models.KYCStatusVerified {
		fields["kyc_verified_at"] = &now
	}

	if req.Status == models.KYCStatusVerified {
		fields["is_verified"] = true
	}

	// Update database fields
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

	// Update the cached user object
	user.KYCStatus = req.Status
	user.KYCLevel = req.Level
	user.UpdatedAt = now

	// Only update KYCVerifiedAt if status is changing to verified
	if req.Status == models.KYCStatusVerified && oldStatus != models.KYCStatusVerified {
		user.KYCVerifiedAt = &now
	}

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
			"reason":      req.Reason,
		},
		Duration: int64(time.Since(startTime).Milliseconds()),
	})

	s.logger.Info("KYC status updated",
		util.String("user_id", req.UserID.String()),
		util.String("status", req.Status),
		util.String("level", req.Level),
		util.String("verified_by", req.VerifiedBy.String()),
		util.Duration("duration", time.Since(startTime)),
	)

	return nil
}

// func (s *UserService) UpdateKYCStatus(ctx context.Context, req *KYCUpdateRequest) error {
// 	startTime := time.Now()

// 	user, err := s.GetUserByID(ctx, req.UserID)
// 	if err != nil {
// 		return err
// 	}

// 	if err := s.validateKYCStatusTransition(user.KYCStatus, req.Status); err != nil {
// 		return err
// 	}

// 	now := time.Now().UTC()
// 	fields := map[string]interface{}{
// 		"kyc_status":      req.Status,
// 		"kyc_level":       req.Level,
// 		"kyc_verified_at": &now,
// 		"updated_at":      now,
// 	}

// 	if req.Status == models.KYCStatusVerified {
// 		fields["is_verified"] = true
// 	}

// 	if err := s.userRepo.UpdateUserFields(ctx, req.UserID, fields); err != nil {
// 		s.logUserEvent(ctx, &models.UserLogEvent{
// 			LogEnvelope: models.LogEnvelope{
// 				EventID:     uuid.New().String(),
// 				EventType:   "user",
// 				ServiceName: "auth-service",
// 				Timestamp:   time.Now(),
// 				Environment: "production",
// 				Version:     "v1.0.0",
// 				Level:       "error",
// 				Message:     "Failed to update KYC status in database",
// 			},
// 			UserID:    req.UserID.String(),
// 			Action:    "update_kyc_status",
// 			Status:    "failed",
// 			ErrorCode: "UPDATE_KYC_FAILED",
// 			Duration:  int64(time.Since(startTime).Milliseconds()),
// 		})
// 		return fmt.Errorf("failed to update KYC status: %w", err)
// 	}

// 	oldStatus := user.KYCStatus
// 	oldLevel := user.KYCLevel

// 	user.KYCStatus = req.Status
// 	user.KYCLevel = req.Level
// 	user.KYCVerifiedAt = &now
// 	user.UpdatedAt = now

// 	if req.Status == models.KYCStatusVerified {
// 		user.IsVerified = true
// 	}

// 	s.invalidateUserCache(ctx, req.UserID)
// 	s.cacheUser(ctx, user)

// 	s.logUserEvent(ctx, &models.UserLogEvent{
// 		LogEnvelope: models.LogEnvelope{
// 			EventID:     uuid.New().String(),
// 			EventType:   "user",
// 			ServiceName: "auth-service",
// 			Timestamp:   time.Now(),
// 			Environment: "production",
// 			Version:     "v1.0.0",
// 			Level:       "info",
// 			Message:     "KYC status updated successfully",
// 		},
// 		UserID: req.UserID.String(),
// 		Action: "update_kyc_status",
// 		Status: "success",
// 		Changes: map[string]interface{}{
// 			"old_status":  oldStatus,
// 			"new_status":  req.Status,
// 			"old_level":   oldLevel,
// 			"new_level":   req.Level,
// 			"verified_by": req.VerifiedBy.String(),
// 		},
// 		Duration: int64(time.Since(startTime).Milliseconds()),
// 	})

// 	s.logger.Info("KYC status updated",
// 		util.String("user_id", req.UserID.String()),
// 		util.String("status", req.Status),
// 		util.String("level", req.Level),
// 		util.String("verified_by", req.VerifiedBy.String()),
// 	)

// 	return nil
// }

func (s *UserService) GetUsersByKYCStatus(ctx context.Context, status string, limit, offset int) ([]*models.User, int, error) {
	if limit <= 0 || limit > 1000 {
		limit = 100
	}
	if offset < 0 {
		offset = 0
	}

	return s.userRepo.GetUsersByKYCStatus(ctx, status, limit, offset)
}

func (s *UserService) GetUsersByCompany(ctx context.Context, companyID uuid.UUID, limit, offset int) ([]*models.User, int, error) {
	if limit <= 0 || limit > 1000 {
		limit = 100
	}
	if offset < 0 {
		offset = 0
	}

	return s.userRepo.GetUsersByCompany(ctx, companyID, limit, offset)
}

func (s *UserService) GetUsersByRegion(ctx context.Context, region string, limit, offset int) ([]*models.User, int, error) {
	if limit <= 0 || limit > 1000 {
		limit = 100
	}
	if offset < 0 {
		offset = 0
	}

	return s.userRepo.GetUsersByRegion(ctx, region, limit, offset)
}

func (s *UserService) GetUsersCreatedAfter(ctx context.Context, after time.Time, limit, offset int) ([]*models.User, int, error) {
	if limit <= 0 || limit > 1000 {
		limit = 100
	}
	if offset < 0 {
		offset = 0
	}

	return s.userRepo.GetUsersCreatedAfter(ctx, after, limit, offset)
}

func (s *UserService) GetUsersByCreationDateRange(ctx context.Context, start, end time.Time, limit int) ([]*models.User, error) {
	if limit <= 0 || limit > 1000 {
		limit = 100
	}

	return s.userRepo.GetUsersByCreationDateRange(ctx, start, end, limit)
}

// ============================================================================
// CACHE METHODS
// ============================================================================

func (s *UserService) cacheUser(ctx context.Context, user *models.User) {
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

// ============================================================================
// VALIDATION METHODS
// ============================================================================

func (s *UserService) validateCreateRequest(req *UserCreateRequest) error {
	if req.Username == "" {
		return fmt.Errorf("username is required")
	}
	if len(req.Username) < 3 || len(req.Username) > 100 {
		return fmt.Errorf("username must be between 3 and 100 characters")
	}
	if req.FullName != "" && len(req.FullName) > 255 {
		return fmt.Errorf("full name must be less than 255 characters")
	}
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
	if req.KYCStatus != "" && !isValidKYCStatus(req.KYCStatus) {
		return fmt.Errorf("invalid KYC status")
	}
	if req.KYCLevel != "" && !isValidKYCLevel(req.KYCLevel) {
		return fmt.Errorf("invalid KYC level")
	}

	return nil
}

func isValidKYCStatus(status string) bool {
	validStatuses := []string{
		models.KYCStatusPending,
		models.KYCStatusVerified,
		models.KYCStatusRejected,
		models.KYCStatusUnderReview,
		models.KYCStatusExpired,
	}
	for _, s := range validStatuses {
		if s == status {
			return true
		}
	}
	return false
}

func isValidKYCLevel(level string) bool {
	validLevels := []string{
		models.KYCLevelBasic,
		models.KYCLevelAdvanced,
		models.KYCLevelFull,
	}
	for _, l := range validLevels {
		if l == level {
			return true
		}
	}
	return false
}

func (s *UserService) validateKYCStatusTransition(currentStatus, newStatus string) error {
	// Allow same status transitions (for updating level/reason)
	if currentStatus == newStatus {
		return nil
	}

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
// ADDITIONAL SERVICE METHODS
// ============================================================================

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

func (s *UserService) GetRecentlyActiveUsers(ctx context.Context, since time.Time, limit int) ([]*models.User, error) {
	if limit <= 0 || limit > 1000 {
		limit = 100
	}

	users, err := s.userRepo.GetRecentlyActiveUsers(ctx, since, limit)
	if err != nil {
		return nil, fmt.Errorf("failed to get recently active users: %w", err)
	}

	for _, user := range users {
		s.cacheUser(ctx, user)
	}

	return users, nil
}

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

func (s *UserService) RecordLoginAttempt(ctx context.Context, userID uuid.UUID, success bool, ip, userAgent string) error {
	if err := s.userRepo.RecordLoginAttempt(ctx, userID, success, ip, userAgent); err != nil {
		s.logger.Warn("Failed to record login attempt",
			util.String("user_id", userID.String()),
			util.ErrorField(err))
		return fmt.Errorf("failed to record login attempt: %w", err)
	}

	if success {
		if err := s.UpdateLastLogin(ctx, userID); err != nil {
			s.logger.Warn("Failed to update last login after successful attempt",
				util.String("user_id", userID.String()),
				util.ErrorField(err))
		}
	}

	return nil
}

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

func (s *UserService) GetUserGrowthMetrics(ctx context.Context, since time.Time) (map[string]interface{}, error) {
	metrics, err := s.userRepo.GetUserGrowthMetrics(ctx, since)
	if err != nil {
		return nil, fmt.Errorf("failed to get user growth metrics: %w", err)
	}

	return metrics, nil
}

func (s *UserService) GetUserActivityStats(ctx context.Context, since time.Time) (map[string]interface{}, error) {
	stats, err := s.userRepo.GetUserActivityStats(ctx, since)
	if err != nil {
		return nil, fmt.Errorf("failed to get user activity stats: %w", err)
	}

	return stats, nil
}

func (s *UserService) GetKYCDistribution(ctx context.Context) (map[string]int, error) {
	distribution, err := s.userRepo.GetKYCDistribution(ctx)
	if err != nil {
		return nil, fmt.Errorf("failed to get KYC distribution: %w", err)
	}

	return distribution, nil
}

func (s *UserService) GetActiveUserCountsByRegion(ctx context.Context) (map[string]int, error) {
	counts, err := s.userRepo.GetActiveUserCountsByRegion(ctx)
	if err != nil {
		return nil, fmt.Errorf("failed to get active user counts by region: %w", err)
	}

	return counts, nil
}

func (s *UserService) AddUserDevice(ctx context.Context, device *models.UserDevice) error {
	if err := s.userRepo.AddUserDevice(ctx, device); err != nil {
		return fmt.Errorf("failed to add user device: %w", err)
	}

	s.logger.Info("User device added",
		util.String("user_id", device.UserID.String()),
		util.String("device_id", device.DeviceID))

	return nil
}

func (s *UserService) GetUserDevices(ctx context.Context, userID uuid.UUID) ([]models.UserDevice, error) {
	devices, err := s.userRepo.GetUserDevices(ctx, userID)
	if err != nil {
		return nil, fmt.Errorf("failed to get user devices: %w", err)
	}

	return devices, nil
}

func (s *UserService) RemoveUserDevice(ctx context.Context, userID uuid.UUID, deviceID string) error {
	if err := s.userRepo.RemoveUserDevice(ctx, userID, deviceID); err != nil {
		return fmt.Errorf("failed to remove user device: %w", err)
	}

	s.logger.Info("User device removed",
		util.String("user_id", userID.String()),
		util.String("device_id", deviceID))

	return nil
}

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

func (s *UserService) UpdateUserFields(ctx context.Context, userID uuid.UUID, fields map[string]interface{}) error {
	startTime := time.Now()

	// Check if username is being updated and if it's available
	if username, ok := fields["username"].(string); ok {
		existingUser, err := s.userRepo.GetUserByUsername(ctx, username)
		if err == nil && existingUser != nil && existingUser.UserID != userID {
			return fmt.Errorf("username already taken")
		}
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

func (s *UserService) GetUserByDeviceFingerprint(ctx context.Context, fingerprint string) (*models.User, error) {
	user, err := s.userRepo.GetUserByDeviceFingerprint(ctx, fingerprint)
	if err != nil {
		return nil, fmt.Errorf("failed to get user by device fingerprint: %w", err)
	}

	s.cacheUser(ctx, user)
	return user, nil
}

func (s *UserService) UpdatePhoneNumber(ctx context.Context, userID uuid.UUID, newPhoneNumber string) error {
	startTime := time.Now()

	if newPhoneNumber == "" {
		return fmt.Errorf("%w: phone number cannot be empty", ErrInvalidInput)
	}
	if len(newPhoneNumber) < 10 || len(newPhoneNumber) > 15 {
		return fmt.Errorf("%w: phone number must be between 10 and 15 characters", ErrInvalidInput)
	}

	user, err := s.GetUserByID(ctx, userID)
	if err != nil {
		return fmt.Errorf("failed to get user: %w", err)
	}

	newPhoneHash := s.GeneratePhoneHash(newPhoneNumber)

	existingUser, err := s.userRepo.GetUserByPhoneHash(ctx, newPhoneHash)
	if err == nil && existingUser != nil && existingUser.UserID != userID {
		return fmt.Errorf("%w: phone number already registered to another user", ErrUserAlreadyExists)
	}

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

	fields := map[string]interface{}{
		"phone_hash":          newPhoneHash,
		"phone_encrypted":     []byte(encryptedPhone.EncryptedValue),
		"phone_key_id":        keyID,
		"phone_encrypted_dek": encryptedPhone.EncryptedDEK,
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

	oldPhoneHash := user.PhoneHash
	s.invalidateUserCache(ctx, userID)

	s.phoneCache.Remove(oldPhoneHash)
	if s.distCache != nil {
		if err := s.distCache.InvalidatePhone(ctx, oldPhoneHash); err != nil {
			s.logger.Warn("Failed to invalidate old phone mapping in Redis",
				util.String("old_phone_hash", oldPhoneHash),
				util.ErrorField(err))
		}
	}

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

func (s *UserService) BanUser(ctx context.Context, req *BanUserRequest) error {
	startTime := time.Now()

	user, err := s.GetUserByID(ctx, req.UserID)
	if err != nil {
		return err
	}

	if !user.IsActive {
		return fmt.Errorf("user is already banned")
	}

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

func (s *UserService) UnbanUser(ctx context.Context, userID, unbannedBy uuid.UUID, reason string) error {
	startTime := time.Now()

	user, err := s.userRepo.GetUserByID(ctx, userID)
	if err != nil {
		return fmt.Errorf("failed to get user: %w", err)
	}

	if user.IsActive {
		return fmt.Errorf("user is not banned")
	}

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

// SearchCompanyEmployees searches employees within a specific company
func (s *UserService) SearchCompanyEmployees(ctx context.Context, req *models.CompanyEmployeeSearchRequest) ([]*models.CompanyEmployeeSearchResult, int, error) {
	startTime := time.Now()

	if req.Limit <= 0 || req.Limit > 100 {
		req.Limit = 50
	}
	if req.Offset < 0 {
		req.Offset = 0
	}

	// You might want to add authorization check here
	// For example, verify that the requesting user has access to this company

	results, total, err := s.userRepo.SearchCompanyEmployees(ctx, req)
	if err != nil {
		return nil, 0, fmt.Errorf("failed to search company employees: %w", err)
	}

	s.logger.Debug("Company employee search completed",
		util.String("company_id", req.CompanyID.String()),
		util.String("query", req.Query),
		util.Int("results", len(results)),
		util.Int("total", total),
		util.Duration("duration", time.Since(startTime)))

	return results, total, nil
}

// SearchCompanyEmployeesAdvanced searches employees with advanced filters
func (s *UserService) SearchCompanyEmployeesAdvanced(ctx context.Context, companyID uuid.UUID, filters map[string]interface{}, limit, offset int) ([]*models.User, int, error) {
	if limit <= 0 || limit > 1000 {
		limit = 100
	}
	if offset < 0 {
		offset = 0
	}

	users, total, err := s.userRepo.SearchCompanyEmployeesAdvanced(ctx, companyID, filters, limit, offset)
	if err != nil {
		return nil, 0, fmt.Errorf("failed to search company employees: %w", err)
	}

	// Cache found users
	for _, user := range users {
		s.cacheUser(ctx, user)
	}

	return users, total, nil
}

// GetCompanyEmployeeSuggestions returns employee suggestions for autocomplete within a company
func (s *UserService) GetCompanyEmployeeSuggestions(ctx context.Context, companyID uuid.UUID, prefix string, limit int) ([]*models.UserSuggestion, error) {
	if limit <= 0 || limit > 20 {
		limit = 10
	}

	suggestions, err := s.userRepo.GetCompanyEmployeeSuggestions(ctx, companyID, prefix, limit)
	if err != nil {
		return nil, fmt.Errorf("failed to get company employee suggestions: %w", err)
	}

	return suggestions, nil
}

// FindCompanyEmployeeByUsername finds an employee by username within a company
func (s *UserService) FindCompanyEmployeeByUsername(ctx context.Context, companyID uuid.UUID, username string) (*models.User, error) {
	empUser, err := s.userRepo.FindCompanyEmployeeByUsername(ctx, companyID, username)
	if err != nil {
		return nil, fmt.Errorf("failed to find company employee by username: %w", err)
	}

	// Convert CompanyEmployeeUser to User
	if empUser == nil {
		return nil, nil
	}

	fullName := ""
	if empUser.FullName != nil {
		fullName = *empUser.FullName
	}

	user := &models.User{
		UserID:            empUser.UserID,
		Username:          empUser.Username,
		FullName:          fullName,
		PhoneHash:         empUser.PhoneHash,
		PhoneEncrypted:    nil, // These might not be available in CompanyEmployeeUser
		PhoneEncryptedDEK: "",
		PhoneKeyID:        uuid.Nil,
		DeviceID:          "",
		DeviceFingerprint: "",
		KYCStatus:         "",
		KYCLevel:          "",
		IsVerified:        false,
		IsActive:          empUser.IsActive,
		DataRegion:        "",
		CreatedAt:         time.Time{},
		UpdatedAt:         time.Time{},
	}

	s.cacheUser(ctx, user)
	return user, nil
}

// GetBannedUsers returns users with is_active = false
func (s *UserService) GetBannedUsers(ctx context.Context, limit, offset int) ([]*models.User, int, error) {
	startTime := time.Now()

	if limit <= 0 || limit > 1000 {
		limit = 100
	}
	if offset < 0 {
		offset = 0
	}

	users, total, err := s.userRepo.GetBannedUsers(ctx, limit, offset)
	if err != nil {
		return nil, 0, fmt.Errorf("failed to get banned users: %w", err)
	}

	s.logger.Debug("Banned users retrieved",
		util.Int("count", len(users)),
		util.Int("total", total),
		util.Duration("duration", time.Since(startTime)))

	return users, total, nil
}

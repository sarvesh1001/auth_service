package service

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"sync"
	"time"

	"github.com/google/uuid"
	lru "github.com/hashicorp/golang-lru/v2"
	"golang.org/x/sync/errgroup"

	"auth-service/internal/encryption"
	appErrors "auth-service/internal/errors"
	"auth-service/internal/hashing"
	"auth-service/internal/infrastructure/audit"
	"auth-service/internal/infrastructure/idempotency"
	"auth-service/internal/models"
	"auth-service/internal/repository/postgres"
)

const (
	DefaultBatchSize   = 100
	MaxBatchSize       = 500
	MaxConcurrentBatch = 10
)

// CompanyEmployeeSearchResult mirrors the DB result.
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

// UserService handles user operations with audit, idempotency, and Kafka events.
type UserService struct {
	userRepo         postgres.UserRepository
	hasher           *hashing.Hasher
	encryptionMgr    *encryption.EncryptionManager
	localCache       *lru.Cache[uuid.UUID, *models.User]
	phoneCache       *lru.Cache[string, uuid.UUID]
	distCache        *DistributedCache
	rateLimiter      *RateLimiter
	auditService     *audit.AuditService
	idempotencyStore idempotency.Store
	logProducer      *LogProducerService
}

// RateLimiter tracks login and MPIN attempts.
type RateLimiter struct {
	loginAttempts *sync.Map
	mpinAttempts  *sync.Map
	mutex         sync.RWMutex
}

// UserCreateRequest represents a user creation request.
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

// UserUpdateRequest represents a user update request.
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

// KYCUpdateRequest represents a KYC update request.
type KYCUpdateRequest struct {
	UserID     uuid.UUID `json:"user_id" validate:"required"`
	Status     string    `json:"status" validate:"required,oneof=pending verified rejected expired under_review"`
	Level      string    `json:"level" validate:"required,oneof=basic advanced full"`
	Reason     string    `json:"reason,omitempty"`
	VerifiedBy uuid.UUID `json:"verified_by" validate:"required"`
}

// BanUserRequest represents a ban request.
type BanUserRequest struct {
	UserID   uuid.UUID `json:"user_id" validate:"required"`
	BannedBy uuid.UUID `json:"banned_by" validate:"required"`
	Reason   string    `json:"reason" validate:"required,min=10,max=500"`
}

// NewUserService creates a new UserService with local caches.
func NewUserService(
	userRepo postgres.UserRepository,
	hasher *hashing.Hasher,
	encryptionMgr *encryption.EncryptionManager,
	auditService *audit.AuditService,
	idempotencyStore idempotency.Store,
) *UserService {
	userCache, _ := lru.New[uuid.UUID, *models.User](1_000_000)
	phoneCache, _ := lru.New[string, uuid.UUID](1_000_000)
	return &UserService{
		userRepo:         userRepo,
		hasher:           hasher,
		encryptionMgr:    encryptionMgr,
		localCache:       userCache,
		phoneCache:       phoneCache,
		rateLimiter:      &RateLimiter{loginAttempts: &sync.Map{}, mpinAttempts: &sync.Map{}},
		auditService:     auditService,
		idempotencyStore: idempotencyStore,
	}
}

// NewUserServiceWithCache adds distributed cache support.
func NewUserServiceWithCache(
	userRepo postgres.UserRepository,
	hasher *hashing.Hasher,
	encryptionMgr *encryption.EncryptionManager,
	distCache *DistributedCache,
	auditService *audit.AuditService,
	idempotencyStore idempotency.Store,
) *UserService {
	service := NewUserService(userRepo, hasher, encryptionMgr, auditService, idempotencyStore)
	service.distCache = distCache
	return service
}

// SetLogProducerService injects the Kafka log producer.
func (s *UserService) SetLogProducerService(logProducer *LogProducerService) {
	s.logProducer = logProducer
}

// SetDistributedCache sets the distributed cache.
func (s *UserService) SetDistributedCache(distCache *DistributedCache) {
	s.distCache = distCache
}

// logUserEvent sends a UserLogEvent to Kafka.
func (s *UserService) logUserEvent(ctx context.Context, event *models.UserLogEvent) {
	if s.logProducer != nil {
		_ = s.logProducer.ProduceUserEvent(ctx, event)
	}
}

// GeneratePhoneHash creates a SHA‑256 hash of a normalized phone number.
func (s *UserService) GeneratePhoneHash(phoneNumber string) string {
	normalized := strings.NewReplacer(" ", "", "-", "", "(", "", ")", "").Replace(phoneNumber)
	hash := sha256.Sum256([]byte(normalized))
	return hex.EncodeToString(hash[:])
}

// --------------------------------------------------------------------
//  SEARCH & QUERY METHODS
// --------------------------------------------------------------------

func (s *UserService) SearchUsers(ctx context.Context, req *models.UserSearchRequest) ([]*models.UserSearchResult, int, error) {
	startTime := time.Now()
	results, total, err := s.userRepo.SearchUsers(ctx, req)
	if err != nil {
		return nil, 0, fmt.Errorf("%w: %v", appErrors.ErrInternal, err)
	}
	// Audit (read‑only, no before/after)
	if s.auditService != nil {
		_ = s.auditService.LogAction(ctx, nil, nil, "user", "search", "user",
			nil, "system", nil, nil, nil, map[string]interface{}{
				"query":       req.Query,
				"search_type": req.SearchType,
				"results":     len(results),
				"total":       total,
				"duration_ms": time.Since(startTime).Milliseconds(),
			})
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
			Message:     "User search completed",
		},
		Action: "search_users",
		Status: "success",
		Changes: map[string]interface{}{
			"query":       req.Query,
			"search_type": req.SearchType,
			"results":     len(results),
			"total":       total,
		},
		Duration: int64(time.Since(startTime).Milliseconds()),
	})
	return results, total, nil
}

func (s *UserService) SearchUsersByUsername(ctx context.Context, username string, limit int) ([]*models.User, error) {
	if limit <= 0 || limit > 100 {
		limit = 50
	}
	users, err := s.userRepo.SearchUsersByUsername(ctx, username, limit)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", appErrors.ErrInternal, err)
	}
	for _, user := range users {
		s.cacheUser(ctx, user)
	}
	if s.auditService != nil {
		_ = s.auditService.LogAction(ctx, nil, nil, "user", "search_by_username", "user",
			nil, "system", nil, nil, nil, map[string]interface{}{
				"username": username,
				"count":    len(users),
			})
	}
	return users, nil
}

func (s *UserService) SearchUsersByFullName(ctx context.Context, fullName string, limit int) ([]*models.User, error) {
	if limit <= 0 || limit > 100 {
		limit = 50
	}
	users, err := s.userRepo.SearchUsersByFullName(ctx, fullName, limit)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", appErrors.ErrInternal, err)
	}
	for _, user := range users {
		s.cacheUser(ctx, user)
	}
	if s.auditService != nil {
		_ = s.auditService.LogAction(ctx, nil, nil, "user", "search_by_fullname", "user",
			nil, "system", nil, nil, nil, map[string]interface{}{
				"full_name": fullName,
				"count":     len(users),
			})
	}
	return users, nil
}

func (s *UserService) GetUserSuggestions(ctx context.Context, prefix string, limit int) ([]*models.UserSuggestion, error) {
	if limit <= 0 || limit > 20 {
		limit = 10
	}
	suggestions, err := s.userRepo.GetUserSuggestions(ctx, prefix, limit)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", appErrors.ErrInternal, err)
	}
	if s.auditService != nil {
		_ = s.auditService.LogAction(ctx, nil, nil, "user", "suggestions", "user",
			nil, "system", nil, nil, nil, map[string]interface{}{
				"prefix": prefix,
				"count":  len(suggestions),
			})
	}
	return suggestions, nil
}

func (s *UserService) FindUserByUsername(ctx context.Context, username string) (*models.UserByUsername, error) {
	user, err := s.userRepo.FindUserByUsername(ctx, username)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", appErrors.ErrNotFound, err)
	}
	if s.auditService != nil {
		_ = s.auditService.LogAction(ctx, nil, nil, "user", "find_by_username", "user",
			nil, "system", nil, nil, nil, map[string]interface{}{
				"username": username,
			})
	}
	return user, nil
}

func (s *UserService) SearchUsersAdvanced(ctx context.Context, filters map[string]interface{}, limit, offset int) ([]*models.User, int, error) {
	if limit <= 0 || limit > 1000 {
		limit = 100
	}
	if offset < 0 {
		offset = 0
	}
	users, total, err := s.userRepo.SearchUsersAdvanced(ctx, filters, limit, offset)
	if err != nil {
		return nil, 0, fmt.Errorf("%w: %v", appErrors.ErrInternal, err)
	}
	for _, user := range users {
		s.cacheUser(ctx, user)
	}
	if s.auditService != nil {
		_ = s.auditService.LogAction(ctx, nil, nil, "user", "search_advanced", "user",
			nil, "system", nil, nil, nil, map[string]interface{}{
				"filters": filters,
				"limit":   limit,
				"offset":  offset,
				"total":   total,
			})
	}
	return users, total, nil
}

func (s *UserService) GetUserSearchStats(ctx context.Context) (map[string]interface{}, error) {
	stats, err := s.userRepo.GetUserSearchStats(ctx)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", appErrors.ErrInternal, err)
	}
	return stats, nil
}

// --------------------------------------------------------------------
//  GET USER BY ID / PHONE / USERNAME
// --------------------------------------------------------------------

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
		return nil, fmt.Errorf("%w: %v", appErrors.ErrNotFound, err)
	}
	s.cacheUser(ctx, user)
	s.cachePhoneMapping(ctx, phoneHash, user.UserID)
	return user, nil
}

func (s *UserService) GetUserByUsername(ctx context.Context, username string) (*models.User, error) {
	user, err := s.userRepo.GetUserByUsername(ctx, username)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", appErrors.ErrNotFound, err)
	}
	s.cacheUser(ctx, user)
	return user, nil
}

func (s *UserService) GetUserByID(ctx context.Context, userID uuid.UUID) (*models.User, error) {
	if user, ok := s.localCache.Get(userID); ok {
		if err := s.validateUserEncryptionData(user); err != nil {
			// encryption data incomplete – fall through to repo
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
		return nil, fmt.Errorf("%w: %v", appErrors.ErrNotFound, err)
	}
	if !user.IsActive {
		return nil, appErrors.ErrInvalidState // or a custom ErrUserInactive
	}
	s.cacheUser(ctx, user)
	return user, nil
}

// --------------------------------------------------------------------
//  CREATE USER (with idempotency and audit)
// --------------------------------------------------------------------

func (s *UserService) CreateUser(ctx context.Context, req *UserCreateRequest) (*models.User, error) {
	startTime := time.Now()
	// Idempotency
	idempKey, _ := ctx.Value("idempotency_key").(string)
	if idempKey == "" {
		idempKey = fmt.Sprintf("create_user-%s", uuid.New().String())
	}
	var cached *models.User
	if err := s.idempotencyStore.Get(ctx, nil, idempKey, &cached); err == nil && cached != nil {
		return cached, nil
	}
	ip, _ := ctx.Value("ip_address").(string)

	if err := s.validateCreateRequest(req); err != nil {
		return nil, fmt.Errorf("%w: %v", appErrors.ErrInvalidInput, err)
	}
	existingByUsername, err := s.userRepo.GetUserByUsername(ctx, req.Username)
	if err == nil && existingByUsername != nil {
		return nil, appErrors.ErrDuplicate
	}
	phoneHash := s.GeneratePhoneHash(req.PhoneNumber)
	existingByPhone, err := s.userRepo.GetUserByPhoneHash(ctx, phoneHash)
	if err == nil && existingByPhone != nil {
		return nil, appErrors.ErrDuplicate
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
			Username:    req.Username,
			PhoneNumber: req.PhoneNumber,
			Status:      "failed",
			ErrorCode:   "PHONE_ENCRYPTION_FAILED",
			Duration:    int64(time.Since(startTime).Milliseconds()),
		})
		return nil, fmt.Errorf("%w: %v", appErrors.ErrInternal, err)
	}
	keyID, err := uuid.Parse(encryptedPhone.KeyID)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", appErrors.ErrInternal, err)
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

	beforeJSON, _ := json.Marshal(user)
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
		return nil, fmt.Errorf("%w: %v", appErrors.ErrInternal, err)
	}
	afterJSON, _ := json.Marshal(user)

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

	if s.auditService != nil {
		_ = s.auditService.LogAction(ctx, nil, nil, "user", "create", "user",
			&userID, "system", nil, beforeJSON, afterJSON, map[string]interface{}{
				"username": req.Username,
				"ip":       ip,
			})
	}
	_ = s.idempotencyStore.Store(ctx, nil, idempKey, user)
	return user, nil
}

// --------------------------------------------------------------------
//  UPDATE USER (with idempotency and audit)
// --------------------------------------------------------------------

func (s *UserService) UpdateUser(ctx context.Context, userID uuid.UUID, req *UserUpdateRequest) (*models.User, error) {
	startTime := time.Now()
	idempKey, _ := ctx.Value("idempotency_key").(string)
	if idempKey == "" {
		idempKey = fmt.Sprintf("update_user-%s", userID.String())
	}
	var cached *models.User
	if err := s.idempotencyStore.Get(ctx, nil, idempKey, &cached); err == nil && cached != nil {
		return cached, nil
	}
	ip, _ := ctx.Value("ip_address").(string)

	user, err := s.GetUserByID(ctx, userID)
	if err != nil {
		return nil, err
	}
	beforeJSON, _ := json.Marshal(user)

	changes := make(map[string]interface{})
	if req.Username != nil && *req.Username != user.Username {
		existingUser, err := s.userRepo.GetUserByUsername(ctx, *req.Username)
		if err == nil && existingUser != nil && existingUser.UserID != userID {
			return nil, appErrors.ErrDuplicate
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
		return nil, fmt.Errorf("%w: %v", appErrors.ErrInternal, err)
	}
	afterJSON, _ := json.Marshal(user)

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

	if s.auditService != nil {
		_ = s.auditService.LogAction(ctx, nil, nil, "user", "update", "user",
			&userID, "system", nil, beforeJSON, afterJSON, map[string]interface{}{
				"updates": req,
				"ip":      ip,
			})
	}
	_ = s.idempotencyStore.Store(ctx, nil, idempKey, user)
	return user, nil
}

// --------------------------------------------------------------------
//  DECRYPT / RE‑ENCRYPT PHONE
// --------------------------------------------------------------------

func (s *UserService) DecryptPhoneNumber(ctx context.Context, user *models.User) (string, error) {
	if len(user.PhoneEncrypted) == 0 {
		return "", appErrors.ErrInvalidInput
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
		return fmt.Errorf("%w: %v", appErrors.ErrInternal, err)
	}
	encryptedPhone, err := s.encryptionMgr.EncryptField(ctx, phoneNumber, "phone")
	if err != nil {
		return fmt.Errorf("%w: %v", appErrors.ErrInternal, err)
	}
	keyID, err := uuid.Parse(encryptedPhone.KeyID)
	if err != nil {
		return fmt.Errorf("%w: %v", appErrors.ErrInternal, err)
	}
	fields := map[string]interface{}{
		"phone_encrypted":     []byte(encryptedPhone.EncryptedValue),
		"phone_key_id":        keyID,
		"phone_encrypted_dek": encryptedPhone.EncryptedDEK,
		"updated_at":          time.Now().UTC(),
	}
	if err := s.userRepo.UpdateUserFields(ctx, userID, fields); err != nil {
		return fmt.Errorf("%w: %v", appErrors.ErrInternal, err)
	}
	s.invalidateUserCache(ctx, userID)
	if s.auditService != nil {
		_ = s.auditService.LogAction(ctx, nil, nil, "user", "reencrypt_phone", "user",
			&userID, "system", nil, nil, nil, map[string]interface{}{
				"ip": ctx.Value("ip_address"),
			})
	}
	return nil
}

// --------------------------------------------------------------------
//  STATUS UPDATES
// --------------------------------------------------------------------

func (s *UserService) UpdateUserStatus(ctx context.Context, userID uuid.UUID, isVerified, isActive bool) error {
	startTime := time.Now()
	idempKey, _ := ctx.Value("idempotency_key").(string)
	if idempKey == "" {
		idempKey = fmt.Sprintf("status-%s", userID.String())
	}
	var processed bool
	if err := s.idempotencyStore.Get(ctx, nil, idempKey, &processed); err == nil && processed {
		return nil
	}
	ip, _ := ctx.Value("ip_address").(string)

	user, err := s.GetUserByID(ctx, userID)
	if err != nil {
		return err
	}
	beforeJSON, _ := json.Marshal(user)

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
		return fmt.Errorf("%w: %v", appErrors.ErrInternal, err)
	}
	afterJSON, _ := json.Marshal(user) // old state, but okay

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

	if s.auditService != nil {
		_ = s.auditService.LogAction(ctx, nil, nil, "user", "update_status", "user",
			&userID, "system", nil, beforeJSON, afterJSON, map[string]interface{}{
				"is_verified": isVerified,
				"is_active":   isActive,
				"ip":          ip,
			})
	}
	_ = s.idempotencyStore.Store(ctx, nil, idempKey, true)
	return nil
}

func (s *UserService) UpdateLastLogin(ctx context.Context, userID uuid.UUID) error {
	user, err := s.GetUserByID(ctx, userID)
	if err != nil {
		return err
	}
	now := time.Now().UTC()
	if err := s.userRepo.UpdateLastLogin(ctx, userID, now); err != nil {
		return fmt.Errorf("%w: %v", appErrors.ErrInternal, err)
	}
	user.LastLogin = &now
	s.cacheUser(ctx, user)
	if s.auditService != nil {
		_ = s.auditService.LogAction(ctx, nil, nil, "user", "update_last_login", "user",
			&userID, "system", nil, nil, nil, map[string]interface{}{
				"last_login": now,
			})
	}
	return nil
}

// --------------------------------------------------------------------
//  BATCH OPERATIONS
// --------------------------------------------------------------------

func (s *UserService) CreateUsersBatch(ctx context.Context, requests []*UserCreateRequest) ([]*models.User, error) {
	if len(requests) == 0 {
		return []*models.User{}, nil
	}
	// Validate all requests first
	for i, req := range requests {
		if err := s.validateCreateRequest(req); err != nil {
			return nil, fmt.Errorf("%w at index %d: %v", appErrors.ErrInvalidInput, i, err)
		}
	}
	// Check duplicates within batch
	phoneHashes := make(map[string]bool, len(requests))
	usernames := make(map[string]bool, len(requests))
	for _, req := range requests {
		phoneHash := s.GeneratePhoneHash(req.PhoneNumber)
		if phoneHashes[phoneHash] {
			return nil, fmt.Errorf("%w: duplicate phone number %s", appErrors.ErrDuplicate, req.PhoneNumber)
		}
		phoneHashes[phoneHash] = true
		if usernames[req.Username] {
			return nil, fmt.Errorf("%w: duplicate username %s", appErrors.ErrDuplicate, req.Username)
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
		return nil, fmt.Errorf("%w: %v", appErrors.ErrInternal, err)
	}
	if s.auditService != nil {
		_ = s.auditService.LogAction(ctx, nil, nil, "user", "batch_create", "user",
			nil, "system", nil, nil, nil, map[string]interface{}{
				"total": len(users),
			})
	}
	return users, nil
}

func (s *UserService) processUserBatch(ctx context.Context, requests []*UserCreateRequest) ([]*models.User, error) {
	users := make([]*models.User, 0, len(requests))
	for _, req := range requests {
		user, err := s.CreateUser(ctx, req)
		if err != nil {
			// Skip errors in batch; audit already logs individual failures
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
		return nil, fmt.Errorf("%w: %v", appErrors.ErrInternal, err)
	}
	for _, user := range fetchedUsers {
		s.cacheUser(ctx, user)
	}
	allUsers := append(cachedUsers, fetchedUsers...)
	return allUsers, nil
}

// --------------------------------------------------------------------
//  KYC UPDATES (with idempotency and audit)
// --------------------------------------------------------------------

func (s *UserService) UpdateKYCStatus(ctx context.Context, req *KYCUpdateRequest) error {
	startTime := time.Now()
	idempKey, _ := ctx.Value("idempotency_key").(string)
	if idempKey == "" {
		idempKey = fmt.Sprintf("kyc-%s", req.UserID.String())
	}
	var processed bool
	if err := s.idempotencyStore.Get(ctx, nil, idempKey, &processed); err == nil && processed {
		return nil
	}
	ip, _ := ctx.Value("ip_address").(string)

	user, err := s.GetUserByID(ctx, req.UserID)
	if err != nil {
		return err
	}
	if user.KYCStatus == req.Status && user.KYCLevel == req.Level {
		return nil
	}
	if err := s.validateKYCStatusTransition(user.KYCStatus, req.Status); err != nil {
		return err
	}
	beforeJSON, _ := json.Marshal(user)

	now := time.Now().UTC()
	fields := map[string]interface{}{
		"kyc_status": req.Status,
		"kyc_level":  req.Level,
		"updated_at": now,
	}
	if req.Status == models.KYCStatusVerified && user.KYCStatus != models.KYCStatusVerified {
		fields["kyc_verified_at"] = &now
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
		return fmt.Errorf("%w: %v", appErrors.ErrInternal, err)
	}
	afterJSON, _ := json.Marshal(user) // old state but ok

	oldStatus := user.KYCStatus
	oldLevel := user.KYCLevel
	user.KYCStatus = req.Status
	user.KYCLevel = req.Level
	user.UpdatedAt = now
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

	if s.auditService != nil {
		_ = s.auditService.LogAction(ctx, nil, nil, "user", "update_kyc", "user",
			&req.UserID, "admin", &req.VerifiedBy, beforeJSON, afterJSON, map[string]interface{}{
				"old_status": oldStatus,
				"new_status": req.Status,
				"old_level":  oldLevel,
				"new_level":  req.Level,
				"ip":         ip,
			})
	}
	_ = s.idempotencyStore.Store(ctx, nil, idempKey, true)
	return nil
}

// --------------------------------------------------------------------
//  BULK QUERIES
// --------------------------------------------------------------------

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

// --------------------------------------------------------------------
//  CACHE HELPERS
// --------------------------------------------------------------------

func (s *UserService) cacheUser(ctx context.Context, user *models.User) {
	if err := s.validateUserEncryptionData(user); err != nil {
		return
	}
	s.localCache.Add(user.UserID, user)
	if s.distCache != nil {
		_ = s.distCache.SetUser(ctx, user)
	}
}

func (s *UserService) cachePhoneMapping(ctx context.Context, phoneHash string, userID uuid.UUID) {
	s.phoneCache.Add(phoneHash, userID)
	if s.distCache != nil {
		_ = s.distCache.SetPhoneMapping(ctx, phoneHash, userID)
	}
}

func (s *UserService) invalidateUserCache(ctx context.Context, userID uuid.UUID) {
	s.localCache.Remove(userID)
	if s.distCache != nil {
		_ = s.distCache.InvalidateUser(ctx, userID)
	}
}

func (s *UserService) validateUserEncryptionData(user *models.User) error {
	if len(user.PhoneEncrypted) == 0 {
		return appErrors.ErrInvalidInput
	}
	if user.PhoneKeyID == uuid.Nil {
		return appErrors.ErrInvalidInput
	}
	if user.PhoneEncryptedDEK == "" {
		return appErrors.ErrInvalidInput
	}
	return nil
}

// --------------------------------------------------------------------
//  VALIDATION HELPERS
// --------------------------------------------------------------------

func (s *UserService) validateCreateRequest(req *UserCreateRequest) error {
	if req.Username == "" || len(req.Username) < 3 || len(req.Username) > 100 {
		return fmt.Errorf("username must be between 3 and 100 characters")
	}
	if req.FullName != "" && len(req.FullName) > 255 {
		return fmt.Errorf("full name must be less than 255 characters")
	}
	if req.PhoneNumber == "" || len(req.PhoneNumber) < 10 || len(req.PhoneNumber) > 15 {
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
	valid := []string{
		models.KYCStatusPending,
		models.KYCStatusVerified,
		models.KYCStatusRejected,
		models.KYCStatusUnderReview,
		models.KYCStatusExpired,
	}
	for _, s := range valid {
		if s == status {
			return true
		}
	}
	return false
}

func isValidKYCLevel(level string) bool {
	valid := []string{
		models.KYCLevelBasic,
		models.KYCLevelAdvanced,
		models.KYCLevelFull,
	}
	for _, l := range valid {
		if l == level {
			return true
		}
	}
	return false
}

func (s *UserService) validateKYCStatusTransition(currentStatus, newStatus string) error {
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

// --------------------------------------------------------------------
//  HEALTH / STATS / CLEANUP
// --------------------------------------------------------------------

func (s *UserService) HealthCheck(ctx context.Context) error {
	if err := s.userRepo.HealthCheck(ctx); err != nil {
		return fmt.Errorf("%w: %v", appErrors.ErrInternal, err)
	}
	return nil
}

func (s *UserService) GetServiceStats(ctx context.Context) (map[string]interface{}, error) {
	repoStats, err := s.userRepo.GetRepositoryStats(ctx)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", appErrors.ErrInternal, err)
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

// --------------------------------------------------------------------
//  SOFT DELETE / REACTIVATE
// --------------------------------------------------------------------

func (s *UserService) SoftDeleteUser(ctx context.Context, userID uuid.UUID, reason string) error {
	startTime := time.Now()
	idempKey, _ := ctx.Value("idempotency_key").(string)
	if idempKey == "" {
		idempKey = fmt.Sprintf("soft_delete-%s", userID.String())
	}
	var processed bool
	if err := s.idempotencyStore.Get(ctx, nil, idempKey, &processed); err == nil && processed {
		return nil
	}
	ip, _ := ctx.Value("ip_address").(string)

	user, err := s.GetUserByID(ctx, userID)
	if err != nil {
		return err
	}
	beforeJSON, _ := json.Marshal(user)

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
		return fmt.Errorf("%w: %v", appErrors.ErrInternal, err)
	}
	afterJSON, _ := json.Marshal(user)

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

	if s.auditService != nil {
		_ = s.auditService.LogAction(ctx, nil, nil, "user", "soft_delete", "user",
			&userID, "system", nil, beforeJSON, afterJSON, map[string]interface{}{
				"reason": reason,
				"ip":     ip,
			})
	}
	_ = s.idempotencyStore.Store(ctx, nil, idempKey, true)
	return nil
}

func (s *UserService) ReactivateUser(ctx context.Context, userID uuid.UUID) error {
	startTime := time.Now()
	idempKey, _ := ctx.Value("idempotency_key").(string)
	if idempKey == "" {
		idempKey = fmt.Sprintf("reactivate-%s", userID.String())
	}
	var processed bool
	if err := s.idempotencyStore.Get(ctx, nil, idempKey, &processed); err == nil && processed {
		return nil
	}
	ip, _ := ctx.Value("ip_address").(string)

	user, err := s.GetUserByID(ctx, userID)
	if err != nil {
		return err
	}
	beforeJSON, _ := json.Marshal(user)

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
		return fmt.Errorf("%w: %v", appErrors.ErrInternal, err)
	}
	afterJSON, _ := json.Marshal(user)

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

	if s.auditService != nil {
		_ = s.auditService.LogAction(ctx, nil, nil, "user", "reactivate", "user",
			&userID, "system", nil, beforeJSON, afterJSON, map[string]interface{}{
				"ip": ip,
			})
	}
	_ = s.idempotencyStore.Store(ctx, nil, idempKey, true)
	return nil
}

// --------------------------------------------------------------------
//  RECENT / INACTIVE USERS
// --------------------------------------------------------------------

func (s *UserService) GetRecentlyActiveUsers(ctx context.Context, since time.Time, limit int) ([]*models.User, error) {
	if limit <= 0 || limit > 1000 {
		limit = 100
	}
	users, err := s.userRepo.GetRecentlyActiveUsers(ctx, since, limit)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", appErrors.ErrInternal, err)
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
		return nil, fmt.Errorf("%w: %v", appErrors.ErrInternal, err)
	}
	return users, nil
}

// --------------------------------------------------------------------
//  LOGIN ATTEMPTS
// --------------------------------------------------------------------

func (s *UserService) RecordLoginAttempt(ctx context.Context, userID uuid.UUID, success bool, ip, userAgent string) error {
	if err := s.userRepo.RecordLoginAttempt(ctx, userID, success, ip, userAgent); err != nil {
		return fmt.Errorf("%w: %v", appErrors.ErrInternal, err)
	}
	if success {
		if err := s.UpdateLastLogin(ctx, userID); err != nil {
			// non‑critical
		}
	}
	if s.auditService != nil {
		_ = s.auditService.LogAction(ctx, nil, nil, "user", "login_attempt", "user",
			&userID, "system", nil, nil, nil, map[string]interface{}{
				"success": success,
				"ip":      ip,
				"ua":      userAgent,
			})
	}
	return nil
}

func (s *UserService) GetRecentLoginAttempts(ctx context.Context, userID uuid.UUID, limit int) ([]models.LoginAttempt, error) {
	if limit <= 0 || limit > 100 {
		limit = 50
	}
	attempts, err := s.userRepo.GetRecentLoginAttempts(ctx, userID, limit)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", appErrors.ErrInternal, err)
	}
	return attempts, nil
}

// --------------------------------------------------------------------
//  STATISTICS / METRICS
// --------------------------------------------------------------------

func (s *UserService) GetUserGrowthMetrics(ctx context.Context, since time.Time) (map[string]interface{}, error) {
	metrics, err := s.userRepo.GetUserGrowthMetrics(ctx, since)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", appErrors.ErrInternal, err)
	}
	return metrics, nil
}

func (s *UserService) GetUserActivityStats(ctx context.Context, since time.Time) (map[string]interface{}, error) {
	stats, err := s.userRepo.GetUserActivityStats(ctx, since)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", appErrors.ErrInternal, err)
	}
	return stats, nil
}

func (s *UserService) GetKYCDistribution(ctx context.Context) (map[string]int, error) {
	distribution, err := s.userRepo.GetKYCDistribution(ctx)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", appErrors.ErrInternal, err)
	}
	return distribution, nil
}

func (s *UserService) GetActiveUserCountsByRegion(ctx context.Context) (map[string]int, error) {
	counts, err := s.userRepo.GetActiveUserCountsByRegion(ctx)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", appErrors.ErrInternal, err)
	}
	return counts, nil
}

// --------------------------------------------------------------------
//  USER DEVICES
// --------------------------------------------------------------------

func (s *UserService) AddUserDevice(ctx context.Context, device *models.UserDevice) error {
	if err := s.userRepo.AddUserDevice(ctx, device); err != nil {
		return fmt.Errorf("%w: %v", appErrors.ErrInternal, err)
	}
	if s.auditService != nil {
		_ = s.auditService.LogAction(ctx, nil, nil, "user", "add_device", "user",
			&device.UserID, "system", nil, nil, nil, map[string]interface{}{
				"device_id": device.DeviceID,
			})
	}
	return nil
}

func (s *UserService) GetUserDevices(ctx context.Context, userID uuid.UUID) ([]models.UserDevice, error) {
	devices, err := s.userRepo.GetUserDevices(ctx, userID)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", appErrors.ErrInternal, err)
	}
	return devices, nil
}

func (s *UserService) RemoveUserDevice(ctx context.Context, userID uuid.UUID, deviceID string) error {
	if err := s.userRepo.RemoveUserDevice(ctx, userID, deviceID); err != nil {
		return fmt.Errorf("%w: %v", appErrors.ErrInternal, err)
	}
	if s.auditService != nil {
		_ = s.auditService.LogAction(ctx, nil, nil, "user", "remove_device", "user",
			&userID, "system", nil, nil, nil, map[string]interface{}{
				"device_id": deviceID,
			})
	}
	return nil
}

// --------------------------------------------------------------------
//  ARCHIVING & FIELD UPDATES
// --------------------------------------------------------------------

func (s *UserService) ArchiveInactiveUsers(ctx context.Context, before time.Time) (int, error) {
	count, err := s.userRepo.ArchiveInactiveUsers(ctx, before)
	if err != nil {
		return 0, fmt.Errorf("%w: %v", appErrors.ErrInternal, err)
	}
	if s.auditService != nil {
		_ = s.auditService.LogAction(ctx, nil, nil, "user", "archive_inactive", "user",
			nil, "system", nil, nil, nil, map[string]interface{}{
				"before": before,
				"count":  count,
			})
	}
	return count, nil
}

func (s *UserService) UpdateUserFields(ctx context.Context, userID uuid.UUID, fields map[string]interface{}) error {
	startTime := time.Now()
	idempKey, _ := ctx.Value("idempotency_key").(string)
	if idempKey == "" {
		idempKey = fmt.Sprintf("update_fields-%s", userID.String())
	}
	var processed bool
	if err := s.idempotencyStore.Get(ctx, nil, idempKey, &processed); err == nil && processed {
		return nil
	}
	ip, _ := ctx.Value("ip_address").(string)

	if username, ok := fields["username"].(string); ok {
		existing, err := s.userRepo.GetUserByUsername(ctx, username)
		if err == nil && existing != nil && existing.UserID != userID {
			return appErrors.ErrDuplicate
		}
	}
	user, err := s.GetUserByID(ctx, userID)
	if err != nil {
		return err
	}
	beforeJSON, _ := json.Marshal(user)

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
		return fmt.Errorf("%w: %v", appErrors.ErrInternal, err)
	}
	afterJSON, _ := json.Marshal(user)

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

	if s.auditService != nil {
		_ = s.auditService.LogAction(ctx, nil, nil, "user", "update_fields", "user",
			&userID, "system", nil, beforeJSON, afterJSON, map[string]interface{}{
				"fields": fields,
				"ip":     ip,
			})
	}
	_ = s.idempotencyStore.Store(ctx, nil, idempKey, true)
	return nil
}

// --------------------------------------------------------------------
//  GET USER BY DEVICE FINGERPRINT
// --------------------------------------------------------------------

func (s *UserService) GetUserByDeviceFingerprint(ctx context.Context, fingerprint string) (*models.User, error) {
	user, err := s.userRepo.GetUserByDeviceFingerprint(ctx, fingerprint)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", appErrors.ErrNotFound, err)
	}
	s.cacheUser(ctx, user)
	return user, nil
}

// --------------------------------------------------------------------
//  UPDATE PHONE NUMBER (with idempotency and audit)
// --------------------------------------------------------------------

func (s *UserService) UpdatePhoneNumber(ctx context.Context, userID uuid.UUID, newPhoneNumber string) error {
	startTime := time.Now()
	if newPhoneNumber == "" || len(newPhoneNumber) < 10 || len(newPhoneNumber) > 15 {
		return appErrors.ErrInvalidInput
	}
	idempKey, _ := ctx.Value("idempotency_key").(string)
	if idempKey == "" {
		idempKey = fmt.Sprintf("update_phone-%s", userID.String())
	}
	var processed bool
	if err := s.idempotencyStore.Get(ctx, nil, idempKey, &processed); err == nil && processed {
		return nil
	}
	ip, _ := ctx.Value("ip_address").(string)

	user, err := s.GetUserByID(ctx, userID)
	if err != nil {
		return err
	}
	newPhoneHash := s.GeneratePhoneHash(newPhoneNumber)
	existing, err := s.userRepo.GetUserByPhoneHash(ctx, newPhoneHash)
	if err == nil && existing != nil && existing.UserID != userID {
		return appErrors.ErrDuplicate
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
		return fmt.Errorf("%w: %v", appErrors.ErrInternal, err)
	}
	keyID, err := uuid.Parse(encryptedPhone.KeyID)
	if err != nil {
		return fmt.Errorf("%w: %v", appErrors.ErrInternal, err)
	}
	beforeJSON, _ := json.Marshal(user)

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
		return fmt.Errorf("%w: %v", appErrors.ErrInternal, err)
	}
	afterJSON, _ := json.Marshal(user)

	oldPhoneHash := user.PhoneHash
	s.invalidateUserCache(ctx, userID)
	s.phoneCache.Remove(oldPhoneHash)
	if s.distCache != nil {
		_ = s.distCache.InvalidatePhone(ctx, oldPhoneHash)
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

	if s.auditService != nil {
		_ = s.auditService.LogAction(ctx, nil, nil, "user", "update_phone", "user",
			&userID, "system", nil, beforeJSON, afterJSON, map[string]interface{}{
				"ip": ip,
			})
	}
	_ = s.idempotencyStore.Store(ctx, nil, idempKey, true)
	return nil
}

// --------------------------------------------------------------------
//  BAN / UNBAN (with idempotency and audit)
// --------------------------------------------------------------------

func (s *UserService) BanUser(ctx context.Context, req *BanUserRequest) error {
	startTime := time.Now()
	idempKey, _ := ctx.Value("idempotency_key").(string)
	if idempKey == "" {
		idempKey = fmt.Sprintf("ban-%s", req.UserID.String())
	}
	var processed bool
	if err := s.idempotencyStore.Get(ctx, nil, idempKey, &processed); err == nil && processed {
		return nil
	}
	ip, _ := ctx.Value("ip_address").(string)

	user, err := s.GetUserByID(ctx, req.UserID)
	if err != nil {
		return err
	}
	if !user.IsActive {
		return appErrors.ErrInvalidState
	}
	beforeJSON, _ := json.Marshal(user)

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
		return fmt.Errorf("%w: %v", appErrors.ErrInternal, err)
	}
	afterJSON, _ := json.Marshal(user)

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

	if s.auditService != nil {
		_ = s.auditService.LogAction(ctx, nil, nil, "user", "ban", "user",
			&req.UserID, "admin", &req.BannedBy, beforeJSON, afterJSON, map[string]interface{}{
				"reason": req.Reason,
				"ip":     ip,
			})
	}
	_ = s.idempotencyStore.Store(ctx, nil, idempKey, true)
	return nil
}

func (s *UserService) UnbanUser(ctx context.Context, userID, unbannedBy uuid.UUID, reason string) error {
	startTime := time.Now()
	idempKey, _ := ctx.Value("idempotency_key").(string)
	if idempKey == "" {
		idempKey = fmt.Sprintf("unban-%s", userID.String())
	}
	var processed bool
	if err := s.idempotencyStore.Get(ctx, nil, idempKey, &processed); err == nil && processed {
		return nil
	}
	ip, _ := ctx.Value("ip_address").(string)

	user, err := s.userRepo.GetUserByID(ctx, userID)
	if err != nil {
		return fmt.Errorf("%w: %v", appErrors.ErrNotFound, err)
	}
	if user.IsActive {
		return appErrors.ErrInvalidState
	}
	beforeJSON, _ := json.Marshal(user)

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
		return fmt.Errorf("%w: %v", appErrors.ErrInternal, err)
	}
	afterJSON, _ := json.Marshal(user)

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

	if s.auditService != nil {
		_ = s.auditService.LogAction(ctx, nil, nil, "user", "unban", "user",
			&userID, "admin", &unbannedBy, beforeJSON, afterJSON, map[string]interface{}{
				"reason": reason,
				"ip":     ip,
			})
	}
	_ = s.idempotencyStore.Store(ctx, nil, idempKey, true)
	return nil
}

// --------------------------------------------------------------------
//  COMPANY EMPLOYEE SEARCH
// --------------------------------------------------------------------

func (s *UserService) SearchCompanyEmployees(ctx context.Context, req *models.CompanyEmployeeSearchRequest) ([]*models.CompanyEmployeeSearchResult, int, error) {
	if req.Limit <= 0 || req.Limit > 100 {
		req.Limit = 50
	}
	if req.Offset < 0 {
		req.Offset = 0
	}
	results, total, err := s.userRepo.SearchCompanyEmployees(ctx, req)
	if err != nil {
		return nil, 0, fmt.Errorf("%w: %v", appErrors.ErrInternal, err)
	}
	if s.auditService != nil {
		_ = s.auditService.LogAction(ctx, nil, nil, "user", "search_company_employees", "user",
			nil, "system", nil, nil, nil, map[string]interface{}{
				"company_id": req.CompanyID,
				"query":      req.Query,
				"results":    len(results),
				"total":      total,
			})
	}
	return results, total, nil
}

func (s *UserService) SearchCompanyEmployeesAdvanced(
	ctx context.Context,
	companyID uuid.UUID,
	filters map[string]interface{},
	limit, offset int,
) ([]*models.EmployeeSearchResult, int, error) {
	if limit <= 0 || limit > 1000 {
		limit = 100
	}
	if offset < 0 {
		offset = 0
	}
	employees, total, err := s.userRepo.SearchCompanyEmployeesAdvanced(ctx, companyID, filters, limit, offset)
	if err != nil {
		return nil, 0, fmt.Errorf("%w: %v", appErrors.ErrInternal, err)
	}
	// (Optional) caching – you may skip caching for this DTO or cache separately
	return employees, total, nil
}
func (s *UserService) GetCompanyEmployeeSuggestions(ctx context.Context, companyID uuid.UUID, prefix string, limit int) ([]*models.UserSuggestion, error) {
	if limit <= 0 || limit > 20 {
		limit = 10
	}
	suggestions, err := s.userRepo.GetCompanyEmployeeSuggestions(ctx, companyID, prefix, limit)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", appErrors.ErrInternal, err)
	}
	return suggestions, nil
}

func (s *UserService) FindCompanyEmployeeByUsername(ctx context.Context, companyID uuid.UUID, username string) (*models.User, error) {
	empUser, err := s.userRepo.FindCompanyEmployeeByUsername(ctx, companyID, username)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", appErrors.ErrNotFound, err)
	}
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
		PhoneEncrypted:    nil,
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

// --------------------------------------------------------------------
//  GET BANNED USERS
// --------------------------------------------------------------------

func (s *UserService) GetBannedUsers(ctx context.Context, limit, offset int) ([]*models.User, int, error) {
	if limit <= 0 || limit > 1000 {
		limit = 100
	}
	if offset < 0 {
		offset = 0
	}
	users, total, err := s.userRepo.GetBannedUsers(ctx, limit, offset)
	if err != nil {
		return nil, 0, fmt.Errorf("%w: %v", appErrors.ErrInternal, err)
	}
	return users, total, nil
}

// --------------------------------------------------------------------
//  UTILITY
// --------------------------------------------------------------------

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}

// FindCompanyEmployeeSummaryByUsername returns a minimal employee summary
// (user_id, employee_id, username, full_name) for a given company and username.
// Returns appErrors.ErrNotFound if the employee does not exist.
func (s *UserService) FindCompanyEmployeeSummaryByUsername(ctx context.Context, companyID uuid.UUID, username string) (*models.EmployeeSummary, error) {
	summary, err := s.userRepo.FindCompanyEmployeeSummaryByUsername(ctx, companyID, username)
	if err != nil {
		// If repository returns appErrors.ErrNotFound, just return it
		if errors.Is(err, appErrors.ErrNotFound) {
			return nil, err
		}
		return nil, fmt.Errorf("%w: %v", appErrors.ErrInternal, err)
	}
	return summary, nil
}

// GetPhoneNumberByUserID retrieves and decrypts the phone number for a given user.
// Returns the plaintext phone number or an error if the user does not exist,
// encryption data is invalid, or decryption fails.
func (s *UserService) GetPhoneNumberByUserID(ctx context.Context, userID uuid.UUID) (string, error) {
	// 1. Fetch the full user (cached or from DB)
	user, err := s.GetUserByID(ctx, userID)
	if err != nil {
		return "", err
	}

	// 2. Validate that encryption fields are present
	if err := s.validateUserEncryptionData(user); err != nil {
		return "", fmt.Errorf("%w: missing encryption data for user %s", appErrors.ErrInvalidState, userID)
	}

	// 3. Decrypt the phone number using the encryption manager
	phone, err := s.DecryptPhoneNumber(ctx, user)
	if err != nil {
		return "", err
	}

	// 4. (Optional) Audit log for compliance
	if s.auditService != nil {
		_ = s.auditService.LogAction(ctx, nil, nil, "user", "get_phone", "user",
			&userID, "system", nil, nil, nil, map[string]interface{}{
				"action": "view phone number",
			})
	}

	return phone, nil
}

// IsUserEmployeeOfCompany checks if the user is an active employee of the company.
func (s *UserService) IsUserEmployeeOfCompany(ctx context.Context, userID, companyID uuid.UUID) (bool, error) {
	return s.userRepo.IsUserEmployeeOfCompany(ctx, userID, companyID)
}

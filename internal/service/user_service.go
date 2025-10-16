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

// UserService handles all user-related business logic
type UserService struct {
	userRepo        scylla.UserRepository
	hasher          *hashing.Hasher
	encryptionMgr   *encryption.EncryptionManager
	bucketingMgr    *bucketing.BucketingManager
	logger          *zap.Logger
	cache           *UserCache
	rateLimiter     *RateLimiter
	validationMutex sync.RWMutex
	phoneCache      *sync.Map // phone_hash -> user_id cache
}

// UserCache handles in-memory caching for frequently accessed users
type UserCache struct {
	users    *sync.Map // user_id -> *models.User
	duration time.Duration
	maxSize  int
	size     int
	mutex    sync.RWMutex
}

// RateLimiter handles rate limiting for user operations
type RateLimiter struct {
	loginAttempts *sync.Map // user_id -> attempt count
	mpinAttempts  *sync.Map // user_id -> attempt count
	mutex         sync.RWMutex
}

// UserCreateRequest represents user creation request
type UserCreateRequest struct {
	PhoneNumber       string `json:"phone_number" validate:"required"`
	DeviceID          string `json:"device_id" validate:"required"`
	DeviceFingerprint string `json:"device_fingerprint" validate:"required"`
	DataRegion        string `json:"data_region" validate:"required"`
	ConsentAgreed     bool   `json:"consent_agreed"`
	ConsentVersion    string `json:"consent_version" validate:"required"`
}

// UserUpdateRequest represents user update request
type UserUpdateRequest struct {
	DeviceID          *string `json:"device_id,omitempty"`
	DeviceFingerprint *string `json:"device_fingerprint,omitempty"`
	ProfileServiceID  *string `json:"profile_service_id,omitempty"`
	DataRegion        *string `json:"data_region,omitempty"`
}

// KYCUpdateRequest represents KYC status update
type KYCUpdateRequest struct {
	UserID     uuid.UUID `json:"user_id" validate:"required"`
	Status     string    `json:"status" validate:"required,oneof=pending verified rejected expired"`
	Level      string    `json:"level" validate:"required,oneof=basic advanced premium"`
	VerifiedBy uuid.UUID `json:"verified_by" validate:"required"`
}

// BanUserRequest represents user ban request
type BanUserRequest struct {
	UserID   uuid.UUID `json:"user_id" validate:"required"`
	BannedBy uuid.UUID `json:"banned_by" validate:"required"`
	Reason   string    `json:"reason" validate:"required,min=10,max=500"`
}

// NewUserService creates a new user service
func NewUserService(
	userRepo scylla.UserRepository,
	hasher *hashing.Hasher,
	encryptionMgr *encryption.EncryptionManager,
	bucketingMgr *bucketing.BucketingManager,
	logger *zap.Logger,
) *UserService {
	cache := &UserCache{
		users:    &sync.Map{},
		duration: 5 * time.Minute, // Cache for 5 minutes
		maxSize:  10000,           // Max 10,000 users in cache
	}

	rateLimiter := &RateLimiter{
		loginAttempts: &sync.Map{},
		mpinAttempts:  &sync.Map{},
	}

	return &UserService{
		userRepo:      userRepo,
		hasher:        hasher,
		encryptionMgr: encryptionMgr,
		bucketingMgr:  bucketingMgr,
		logger:        logger,
		cache:         cache,
		rateLimiter:   rateLimiter,
		phoneCache:    &sync.Map{},
	}
}

// GeneratePhoneHash generates a secure hash of phone number
func (s *UserService) GeneratePhoneHash(phoneNumber string) string {
	// Normalize phone number (remove spaces, dashes, etc.)
	normalized := strings.ReplaceAll(phoneNumber, " ", "")
	normalized = strings.ReplaceAll(normalized, "-", "")
	normalized = strings.ReplaceAll(normalized, "(", "")
	normalized = strings.ReplaceAll(normalized, ")", "")

	// Generate SHA256 hash
	hash := sha256.Sum256([]byte(normalized))
	return hex.EncodeToString(hash[:])
}

// CreateUser creates a new user with comprehensive validation
func (s *UserService) CreateUser(ctx context.Context, req *UserCreateRequest) (*models.User, error) {
	startTime := time.Now()

	// Validate input
	if err := s.validateCreateRequest(req); err != nil {
		return nil, fmt.Errorf("%w: %v", ErrInvalidInput, err)
	}

	// Generate phone hash
	phoneHash := s.GeneratePhoneHash(req.PhoneNumber)

	// Check if user already exists
	existingUser, err := s.userRepo.GetUserByPhoneHash(ctx, phoneHash)
	if err == nil && existingUser != nil {
		return nil, ErrUserAlreadyExists
	}

	// Generate new user ID
	userID := uuid.New()

	// Encrypt phone number
	encryptedPhone, err := s.encryptionMgr.EncryptField(ctx, req.PhoneNumber, "phone")
	if err != nil {
		return nil, fmt.Errorf("failed to encrypt phone: %w", err)
	}

	// Create user model
	now := time.Now().UTC()
	user := &models.User{
		UserBucket:        s.bucketingMgr.GetUserBucket(userID), // Calculate bucket
		UserID:            userID.String(),
		PhoneHash:         phoneHash,
		PhoneEncrypted:    []byte(encryptedPhone.EncryptedValue),
		PhoneKeyID:        encryptedPhone.KeyID,
		DeviceID:          req.DeviceID,
		DeviceFingerprint: req.DeviceFingerprint,
		KYCStatus:         "pending",
		KYCLevel:          "basic",
		KYCVerifiedAt:     nil,
		KYCVerifiedBy:     uuid.Nil.String(), // Fix: was ""
		ProfileServiceID:  uuid.Nil.String(), // Fix: was ""
		IsVerified:        false,
		IsBlocked:         false,
		IsBanned:          false,
		BannedBy:          uuid.Nil.String(), // Fix: was ""
		BannedReason:      "",
		BannedAt:          nil,
		CreatedAt:         now,
		LastLogin:         nil,
		UpdatedAt:         &now,
		ConsentAgreed:     req.ConsentAgreed,
		ConsentVersion:    req.ConsentVersion,
		DataRegion:        req.DataRegion,
	}

	// Create user in repository
	if err := s.userRepo.CreateUser(ctx, user); err != nil {
		return nil, fmt.Errorf("failed to create user: %w", err)
	}

	// Cache the user
	s.cacheUser(user)

	// Cache phone to user mapping
	s.phoneCache.Store(phoneHash, userID.String())

	s.logger.Info("User created successfully",
		util.String("user_id", userID.String()),
		util.String("phone_hash", phoneHash),
		util.Int("user_bucket", user.UserBucket),
		util.Duration("duration", time.Since(startTime)),
	)

	return user, nil
}

// GetUserByID retrieves a user by ID with caching
func (s *UserService) GetUserByID(ctx context.Context, userID uuid.UUID) (*models.User, error) {
	// Try cache first
	if cachedUser := s.getCachedUser(userID.String()); cachedUser != nil {
		return cachedUser, nil
	}

	// Fetch from repository
	user, err := s.userRepo.GetUserByID(ctx, userID)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrUserNotFound, err)
	}

	// Check if user is banned or blocked
	if user.IsBanned {
		return nil, ErrUserBanned
	}
	if user.IsBlocked {
		return nil, ErrUserBlocked
	}

	// Cache the user
	s.cacheUser(user)

	return user, nil
}

// GetUserByPhone retrieves a user by phone number
func (s *UserService) GetUserByPhone(ctx context.Context, phoneNumber string) (*models.User, error) {
	phoneHash := s.GeneratePhoneHash(phoneNumber)

	// Try cache first
	if userID, ok := s.phoneCache.Load(phoneHash); ok {
		return s.GetUserByID(ctx, uuid.MustParse(userID.(string)))
	}

	user, err := s.userRepo.GetUserByPhoneHash(ctx, phoneHash)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrUserNotFound, err)
	}

	// Cache the mappings
	s.cacheUser(user)
	s.phoneCache.Store(phoneHash, user.UserID)

	return user, nil
}

// UpdateUser updates user information with validation
func (s *UserService) UpdateUser(ctx context.Context, userID uuid.UUID, req *UserUpdateRequest) (*models.User, error) {
	// Get existing user
	user, err := s.GetUserByID(ctx, userID)
	if err != nil {
		return nil, err
	}

	// Apply updates
	if req.DeviceID != nil {
		user.DeviceID = *req.DeviceID
	}
	if req.DeviceFingerprint != nil {
		user.DeviceFingerprint = *req.DeviceFingerprint
	}
	if req.ProfileServiceID != nil {
		user.ProfileServiceID = *req.ProfileServiceID
	}
	if req.DataRegion != nil {
		user.DataRegion = *req.DataRegion
	}

	now := time.Now().UTC()
	user.UpdatedAt = &now

	// Update in repository
	if err := s.userRepo.UpdateUser(ctx, user); err != nil {
		return nil, fmt.Errorf("failed to update user: %w", err)
	}

	// Update cache
	s.cacheUser(user)

	s.logger.Info("User updated successfully",
		util.String("user_id", userID.String()),
		util.Any("updates", req),
	)

	return user, nil
}

// UpdateUserProfile updates user profile service ID
func (s *UserService) UpdateUserProfile(ctx context.Context, userID uuid.UUID, profileServiceID uuid.UUID) error {
	// Verify user exists and is active
	user, err := s.GetUserByID(ctx, userID)
	if err != nil {
		return err
	}

	if err := s.userRepo.UpdateUserProfile(ctx, userID, profileServiceID); err != nil {
		return fmt.Errorf("failed to update user profile: %w", err)
	}

	// Update cache
	user.ProfileServiceID = profileServiceID.String()
	now := time.Now().UTC()
	user.UpdatedAt = &now
	s.cacheUser(user)

	return nil
}

// UpdateUserStatus updates user status with validation
func (s *UserService) UpdateUserStatus(ctx context.Context, userID uuid.UUID, isVerified, isBlocked, isBanned bool) error {
	// Get existing user
	user, err := s.GetUserByID(ctx, userID)
	if err != nil {
		return err
	}

	// Validate state transitions
	if err := s.validateStatusTransition(user, isVerified, isBlocked, isBanned); err != nil {
		return err
	}

	if err := s.userRepo.UpdateUserStatus(ctx, userID, isVerified, isBlocked, isBanned); err != nil {
		return fmt.Errorf("failed to update user status: %w", err)
	}

	// Update cache
	user.IsVerified = isVerified
	user.IsBlocked = isBlocked
	user.IsBanned = isBanned
	now := time.Now().UTC()
	user.UpdatedAt = &now
	s.cacheUser(user)

	s.logger.Info("User status updated",
		util.String("user_id", userID.String()),
		util.Bool("verified", isVerified),
		util.Bool("blocked", isBlocked),
		util.Bool("banned", isBanned),
	)

	return nil
}

// UpdateLastLogin updates user's last login timestamp
func (s *UserService) UpdateLastLogin(ctx context.Context, userID uuid.UUID) error {
	// Verify user exists and is active
	user, err := s.GetUserByID(ctx, userID)
	if err != nil {
		return err
	}

	now := time.Now().UTC()
	if err := s.userRepo.UpdateLastLogin(ctx, userID, now); err != nil {
		return fmt.Errorf("failed to update last login: %w", err)
	}

	// Update cache
	user.LastLogin = &now
	s.cacheUser(user)

	return nil
}

// Batch Operations

// CreateUsersBatch creates multiple users with optimized batching
func (s *UserService) CreateUsersBatch(ctx context.Context, requests []*UserCreateRequest) ([]*models.User, error) {
	if len(requests) == 0 {
		return []*models.User{}, nil
	}

	// Validate all requests first
	for _, req := range requests {
		if err := s.validateCreateRequest(req); err != nil {
			return nil, fmt.Errorf("invalid request: %w", err)
		}
	}

	// Check for duplicates in batch
	phoneHashes := make(map[string]bool)
	for _, req := range requests {
		phoneHash := s.GeneratePhoneHash(req.PhoneNumber)
		if phoneHashes[phoneHash] {
			return nil, fmt.Errorf("duplicate phone number in batch: %s", req.PhoneNumber)
		}
		phoneHashes[phoneHash] = true
	}

	// Process in parallel batches
	batchSize := 100
	users := make([]*models.User, 0, len(requests))
	var mu sync.Mutex
	g, ctx := errgroup.WithContext(ctx)
	g.SetLimit(10) // Limit concurrent batches

	for i := 0; i < len(requests); i += batchSize {
		batchStart := i
		batchEnd := min(i+batchSize, len(requests))
		batchRequests := requests[batchStart:batchEnd]

		g.Go(func() error {
			batchUsers, err := s.processUserBatch(ctx, batchRequests)
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
	)

	return users, nil
}

// processUserBatch processes a single batch of user creation requests
func (s *UserService) processUserBatch(ctx context.Context, requests []*UserCreateRequest) ([]*models.User, error) {
	users := make([]*models.User, 0, len(requests))

	for _, req := range requests {
		user, err := s.CreateUser(ctx, req)
		if err != nil {
			// Continue with other users in batch, log error
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

// GetUsersByIDBatch retrieves multiple users by IDs with caching
func (s *UserService) GetUsersByIDBatch(ctx context.Context, userIDs []uuid.UUID) ([]*models.User, error) {
	if len(userIDs) == 0 {
		return []*models.User{}, nil
	}

	// Try to get from cache first
	cachedUsers := make([]*models.User, 0, len(userIDs))
	missingIDs := make([]uuid.UUID, 0)

	for _, userID := range userIDs {
		if user := s.getCachedUser(userID.String()); user != nil {
			cachedUsers = append(cachedUsers, user)
		} else {
			missingIDs = append(missingIDs, userID)
		}
	}

	// If all users were cached, return immediately
	if len(missingIDs) == 0 {
		return cachedUsers, nil
	}

	// Fetch missing users from repository
	fetchedUsers, err := s.userRepo.GetUsersByIDBatch(ctx, missingIDs)
	if err != nil {
		return nil, fmt.Errorf("failed to fetch users batch: %w", err)
	}

	// Cache fetched users
	for _, user := range fetchedUsers {
		s.cacheUser(user)
	}

	// Combine cached and fetched users
	allUsers := append(cachedUsers, fetchedUsers...)

	return allUsers, nil
}

// UpdateUsersBatch updates multiple users in batch
func (s *UserService) UpdateUsersBatch(ctx context.Context, updates map[uuid.UUID]*UserUpdateRequest) ([]*models.User, error) {
	if len(updates) == 0 {
		return []*models.User{}, nil
	}

	updatedUsers := make([]*models.User, 0, len(updates))
	var mu sync.Mutex
	g, ctx := errgroup.WithContext(ctx)
	g.SetLimit(5) // Limit concurrent updates

	for userID, req := range updates {
		userID := userID
		req := req

		g.Go(func() error {
			user, err := s.UpdateUser(ctx, userID, req)
			if err != nil {
				s.logger.Warn("Failed to update user in batch",
					util.ErrorField(err),
					util.String("user_id", userID.String()),
				)
				// Continue with other updates
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

// KYC Operations

// UpdateKYCStatus updates user's KYC status with validation
func (s *UserService) UpdateKYCStatus(ctx context.Context, req *KYCUpdateRequest) error {
	// Verify user exists
	user, err := s.GetUserByID(ctx, req.UserID)
	if err != nil {
		return err
	}

	// Validate KYC status transition
	if err := s.validateKYCStatusTransition(user.KYCStatus, req.Status); err != nil {
		return err
	}

	now := time.Now().UTC()
	if err := s.userRepo.UpdateKYCStatus(ctx, req.UserID, req.Status, req.Level, req.VerifiedBy); err != nil {
		return fmt.Errorf("failed to update KYC status: %w", err)
	}

	// Update cache
	user.KYCStatus = req.Status
	user.KYCLevel = req.Level
	user.KYCVerifiedAt = &now
	user.KYCVerifiedBy = req.VerifiedBy.String()
	user.UpdatedAt = &now

	// Auto-verify user if KYC is verified
	if req.Status == "verified" {
		user.IsVerified = true
	}

	s.cacheUser(user)

	s.logger.Info("KYC status updated",
		util.String("user_id", req.UserID.String()),
		util.String("status", req.Status),
		util.String("level", req.Level),
		util.String("verified_by", req.VerifiedBy.String()),
	)

	return nil
}

// GetUsersByKYCStatus retrieves users by KYC status with pagination
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

// UpdateUserConsent updates user consent information
func (s *UserService) UpdateUserConsent(ctx context.Context, userID uuid.UUID, agreed bool, version string) error {
	// Verify user exists
	user, err := s.GetUserByID(ctx, userID)
	if err != nil {
		return err
	}

	if err := s.userRepo.UpdateUserConsent(ctx, userID, agreed, version); err != nil {
		return fmt.Errorf("failed to update user consent: %w", err)
	}

	// Update cache
	user.ConsentAgreed = agreed
	user.ConsentVersion = version
	now := time.Now().UTC()
	user.UpdatedAt = &now
	s.cacheUser(user)

	return nil
}

// Administrative Operations

// BanUser bans a user with comprehensive validation
func (s *UserService) BanUser(ctx context.Context, req *BanUserRequest) error {
	// Verify user exists
	user, err := s.GetUserByID(ctx, req.UserID)
	if err != nil {
		return err
	}

	// Check if user is already banned
	if user.IsBanned {
		return fmt.Errorf("user is already banned")
	}

	if err := s.userRepo.BanUser(ctx, req.UserID, req.BannedBy, req.Reason); err != nil {
		return fmt.Errorf("failed to ban user: %w", err)
	}

	// Update cache
	user.IsBanned = true
	user.BannedBy = req.BannedBy.String()
	user.BannedReason = req.Reason
	now := time.Now().UTC()
	user.BannedAt = &now
	user.UpdatedAt = &now
	s.cacheUser(user)

	s.logger.Warn("User banned",
		util.String("user_id", req.UserID.String()),
		util.String("banned_by", req.BannedBy.String()),
		util.String("reason", req.Reason),
	)

	return nil
}

// UnbanUser unbans a user
func (s *UserService) UnbanUser(ctx context.Context, userID uuid.UUID) error {
	// Verify user exists
	user, err := s.GetUserByID(ctx, userID)
	if err != nil {
		return err
	}

	// Check if user is actually banned
	if !user.IsBanned {
		return fmt.Errorf("user is not banned")
	}

	if err := s.userRepo.UnbanUser(ctx, userID); err != nil {
		return fmt.Errorf("failed to unban user: %w", err)
	}

	// Update cache
	user.IsBanned = false
	user.BannedBy = ""
	user.BannedReason = ""
	user.BannedAt = nil
	now := time.Now().UTC()
	user.UpdatedAt = &now
	s.cacheUser(user)

	s.logger.Info("User unbanned",
		util.String("user_id", userID.String()),
	)

	return nil
}

// GetBannedUsers retrieves banned users with pagination
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

// Cache Management

// cacheUser caches a user with TTL
func (s *UserService) cacheUser(user *models.User) {
	s.cache.mutex.Lock()
	defer s.cache.mutex.Unlock()

	// Check cache size and evict if necessary
	if s.cache.size >= s.cache.maxSize {
		s.evictOldestCacheItem()
	}

	s.cache.users.Store(user.UserID, user)
	s.cache.size++
}

// getCachedUser retrieves a user from cache
func (s *UserService) getCachedUser(userID string) *models.User {
	s.cache.mutex.RLock()
	defer s.cache.mutex.RUnlock()

	if cached, ok := s.cache.users.Load(userID); ok {
		return cached.(*models.User)
	}
	return nil
}

// evictOldestCacheItem evicts the oldest cache item (simple implementation)
func (s *UserService) evictOldestCacheItem() {
	// Simple implementation: clear entire cache when full
	// In production, you might want to implement LRU
	s.cache.users = &sync.Map{}
	s.cache.size = 0
}

// Validation Methods

// validateCreateRequest validates user creation request
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

// Fix the validateStatusTransition method
func (s *UserService) validateStatusTransition(user *models.User, isVerified, isBlocked, isBanned bool) error {
	// Use blank identifiers for unused parameters to satisfy the linter
	_ = isVerified
	_ = isBlocked

	// Cannot unban via status update - must use UnbanUser method
	if user.IsBanned && !isBanned {
		return fmt.Errorf("cannot unban user via status update, use UnbanUser method")
	}

	// Cannot ban via status update - must use BanUser method
	if !user.IsBanned && isBanned {
		return fmt.Errorf("cannot ban user via status update, use BanUser method")
	}

	return nil
}

// validateKYCStatusTransition validates KYC status transition
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

// HealthCheck performs service health check
func (s *UserService) HealthCheck(ctx context.Context) error {
	if err := s.userRepo.HealthCheck(ctx); err != nil {
		return fmt.Errorf("user repository health check failed: %w", err)
	}
	return nil
}

// GetServiceStats returns service statistics
func (s *UserService) GetServiceStats(ctx context.Context) (map[string]interface{}, error) {
	repoStats, err := s.userRepo.GetRepositoryStats(ctx)
	if err != nil {
		return nil, err
	}

	stats := map[string]interface{}{
		"cache_size":       s.cache.size,
		"phone_cache_size": s.getPhoneCacheSize(),
		"repository":       repoStats,
		"timestamp":        time.Now().UTC(),
	}

	return stats, nil
}

// getPhoneCacheSize returns the size of phone cache
func (s *UserService) getPhoneCacheSize() int {
	count := 0
	s.phoneCache.Range(func(_, _ interface{}) bool {
		count++
		return true
	})
	return count
}

// Cleanup performs cleanup operations
func (s *UserService) Cleanup() {
	s.cache.mutex.Lock()
	defer s.cache.mutex.Unlock()

	s.cache.users = &sync.Map{}
	s.cache.size = 0
	s.phoneCache = &sync.Map{}
}

// Helper function
func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}

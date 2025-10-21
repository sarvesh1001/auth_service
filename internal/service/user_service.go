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

// UserService handles all user-related business logic
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
}

// RateLimiter handles rate limiting for user operations
type RateLimiter struct {
    loginAttempts *sync.Map
    mpinAttempts  *sync.Map
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
    userCache, err := lru.New[uuid.UUID, *models.User](1_000_000)
    if err != nil {
        logger.Fatal("Failed to create user LRU cache", util.ErrorField(err))
    }

    phoneCache, err := lru.New[string, uuid.UUID](1_000_000)
    if err != nil {
        logger.Fatal("Failed to create phone LRU cache", util.ErrorField(err))
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
        localCache:    userCache,
        phoneCache:    phoneCache,
        distCache:     nil,
        rateLimiter:   rateLimiter,
    }
}

// NewUserServiceWithCache creates user service with distributed cache
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

// SetDistributedCache sets the distributed cache
func (s *UserService) SetDistributedCache(distCache *DistributedCache) {
    s.distCache = distCache
}

// GeneratePhoneHash generates a secure hash of phone number
func (s *UserService) GeneratePhoneHash(phoneNumber string) string {
    normalized := strings.ReplaceAll(phoneNumber, " ", "")
    normalized = strings.ReplaceAll(normalized, "-", "")
    normalized = strings.ReplaceAll(normalized, "(", "")
    normalized = strings.ReplaceAll(normalized, ")", "")

    hash := sha256.Sum256([]byte(normalized))
    return hex.EncodeToString(hash[:])
}

// CreateUser creates a new user with comprehensive validation
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

    encryptedPhone, err := s.encryptionMgr.EncryptField(ctx, req.PhoneNumber, "phone")
    if err != nil {
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
        PhoneEncrypted:    []byte(encryptedPhone.EncryptedValue),
        PhoneKeyID:        keyID,
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
    }

    if err := s.userRepo.CreateUser(ctx, user); err != nil {
        return nil, fmt.Errorf("failed to create user: %w", err)
    }

    s.cacheUser(ctx, user)
    s.cachePhoneMapping(ctx, phoneHash, userID)

    s.logger.Info("User created successfully",
        util.String("user_id", userID.String()),
        util.String("phone_hash", phoneHash),
        util.Int("user_bucket", user.UserBucket),
        util.Duration("duration", time.Since(startTime)),
    )

    return user, nil
}

// GetUserByID retrieves a user by ID with multi-level caching
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

// GetUserByPhone retrieves a user by phone number with multi-level caching
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
        return nil, fmt.Errorf("%w: %v", ErrUserNotFound, err)
    }

    s.cacheUser(ctx, user)
    s.cachePhoneMapping(ctx, phoneHash, user.UserID)

    return user, nil
}

// UpdateUser updates user information with validation
func (s *UserService) UpdateUser(ctx context.Context, userID uuid.UUID, req *UserUpdateRequest) (*models.User, error) {
    user, err := s.GetUserByID(ctx, userID)
    if err != nil {
        return nil, err
    }

    if req.DeviceID != nil {
        user.DeviceID = *req.DeviceID
    }
    if req.DeviceFingerprint != nil {
        user.DeviceFingerprint = *req.DeviceFingerprint
    }
    if req.ProfileServiceID != nil {
        profileID, err := uuid.Parse(*req.ProfileServiceID)
        if err != nil {
            return nil, fmt.Errorf("invalid profile service ID format: %w", err)
        }
        user.ProfileServiceID = profileID
    }
    if req.DataRegion != nil {
        user.DataRegion = *req.DataRegion
    }

    now := time.Now().UTC()
    user.UpdatedAt = &now

    if err := s.userRepo.UpdateUser(ctx, user); err != nil {
        return nil, fmt.Errorf("failed to update user: %w", err)
    }

    s.invalidateUserCache(ctx, userID)
    s.cacheUser(ctx, user)

    s.logger.Info("User updated successfully",
        util.String("user_id", userID.String()),
        util.Any("updates", req),
    )

    return user, nil
}

// UpdateUserProfile updates user profile service ID
func (s *UserService) UpdateUserProfile(ctx context.Context, userID uuid.UUID, profileServiceID uuid.UUID) error {
    user, err := s.GetUserByID(ctx, userID)
    if err != nil {
        return err
    }

    if err := s.userRepo.UpdateUserProfile(ctx, userID, profileServiceID); err != nil {
        return fmt.Errorf("failed to update user profile: %w", err)
    }

    user.ProfileServiceID = profileServiceID
    now := time.Now().UTC()
    user.UpdatedAt = &now
    
    s.invalidateUserCache(ctx, userID)
    s.cacheUser(ctx, user)

    return nil
}

// UpdateUserStatus updates user status with validation
func (s *UserService) UpdateUserStatus(ctx context.Context, userID uuid.UUID, isVerified, isBlocked, isBanned bool) error {
    user, err := s.GetUserByID(ctx, userID)
    if err != nil {
        return err
    }

    if err := s.validateStatusTransition(user, isVerified, isBlocked, isBanned); err != nil {
        return err
    }

    if err := s.userRepo.UpdateUserStatus(ctx, userID, isVerified, isBlocked, isBanned); err != nil {
        return fmt.Errorf("failed to update user status: %w", err)
    }

    user.IsVerified = isVerified
    user.IsBlocked = isBlocked
    user.IsBanned = isBanned
    now := time.Now().UTC()
    user.UpdatedAt = &now
    
    s.invalidateUserCache(ctx, userID)
    s.cacheUser(ctx, user)

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

    return nil
}

// Batch Operations

// CreateUsersBatch creates multiple users with optimized batching
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

// processUserBatch processes a single batch of user creation requests
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

// GetUsersByIDBatch retrieves multiple users by IDs with caching
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

// UpdateUsersBatch updates multiple users in batch
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

// KYC Operations

// UpdateKYCStatus updates user's KYC status with validation
func (s *UserService) UpdateKYCStatus(ctx context.Context, req *KYCUpdateRequest) error {
    user, err := s.GetUserByID(ctx, req.UserID)
    if err != nil {
        return err
    }

    if err := s.validateKYCStatusTransition(user.KYCStatus, req.Status); err != nil {
        return err
    }

    now := time.Now().UTC()
    if err := s.userRepo.UpdateKYCStatus(ctx, req.UserID, req.Status, req.Level, req.VerifiedBy); err != nil {
        return fmt.Errorf("failed to update KYC status: %w", err)
    }

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
    user, err := s.GetUserByID(ctx, userID)
    if err != nil {
        return err
    }

    if err := s.userRepo.UpdateUserConsent(ctx, userID, agreed, version); err != nil {
        return fmt.Errorf("failed to update user consent: %w", err)
    }

    user.ConsentAgreed = agreed
    user.ConsentVersion = version
    now := time.Now().UTC()
    user.UpdatedAt = &now
    
    s.invalidateUserCache(ctx, userID)
    s.cacheUser(ctx, user)

    return nil
}

// Administrative Operations

// BanUser bans a user with comprehensive validation
func (s *UserService) BanUser(ctx context.Context, req *BanUserRequest) error {
    user, err := s.GetUserByID(ctx, req.UserID)
    if err != nil {
        return err
    }

    if user.IsBanned {
        return fmt.Errorf("user is already banned")
    }

    if err := s.userRepo.BanUser(ctx, req.UserID, req.BannedBy, req.Reason); err != nil {
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

    s.logger.Warn("User banned",
        util.String("user_id", req.UserID.String()),
        util.String("banned_by", req.BannedBy.String()),
        util.String("reason", req.Reason),
    )

    return nil
}

// UnbanUser unbans a user
func (s *UserService) UnbanUser(ctx context.Context, userID uuid.UUID) error {
    user, err := s.GetUserByID(ctx, userID)
    if err != nil {
        return err
    }

    if !user.IsBanned {
        return fmt.Errorf("user is not banned")
    }

    if err := s.userRepo.UnbanUser(ctx, userID); err != nil {
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

// cacheUser caches a user in both local and distributed cache
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

// cachePhoneMapping caches phone hash to userID mapping
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

// invalidateUserCache invalidates user from all cache layers
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

// validateStatusTransition validates status transition
func (s *UserService) validateStatusTransition(user *models.User, isVerified, isBlocked, isBanned bool) error {
    if user.IsBanned && !isBanned {
        return fmt.Errorf("cannot unban user via status update, use UnbanUser method")
    }

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

// Cleanup performs cleanup operations
func (s *UserService) Cleanup() {
    s.localCache.Purge()
    s.phoneCache.Purge()
}

// Helper function
func min(a, b int) int {
    if a < b {
        return a
    }
    return b
}
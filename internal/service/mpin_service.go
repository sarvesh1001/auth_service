package service

import (
    "context"
    "errors"
    "fmt"
    "regexp"
    "time"

    "auth-service/internal/hashing"
    "auth-service/internal/models"
    "auth-service/internal/repository/scylla"
    "auth-service/internal/util"
	"auth-service/internal/config"
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
    MPINMinLength     = 4
    MPINMaxLength     = 8
    MPINLockDuration  = 30 * time.Minute
    MPINMaxAttempts   = 5
)

// MPINService handles all MPIN-related business logic
type MPINService struct {
    mpinRepo    scylla.MPINRepository
    userRepo    scylla.UserRepository
    hasher      *hashing.Hasher
	config      *config.Config  // <--- this field must be added

    logger      *zap.Logger
    distCache   *DistributedCache
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
    Verified        bool   `json:"verified"`
    FailedAttempts  int    `json:"failed_attempts"`
    RemainingTries  int    `json:"remaining_tries"`
    LockedUntil     *time.Time `json:"locked_until,omitempty"`
    Message         string `json:"message"`
}

type MPINChangeRequest struct {
    UserID      uuid.UUID `json:"user_id" validate:"required"`
    CurrentMPIN string    `json:"current_mpin" validate:"required"`
    NewMPIN     string    `json:"new_mpin" validate:"required,min=4,max=8"`
}

type MPINResetRequest struct {
    UserID  uuid.UUID `json:"user_id" validate:"required"`
    ResetBy uuid.UUID `json:"reset_by" validate:"required"`
    Reason  string    `json:"reason" validate:"required"`
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
func NewMPINService(
    mpinRepo scylla.MPINRepository,
    userRepo scylla.UserRepository,
    hasher *hashing.Hasher,
    cfg *config.Config,
    logger *zap.Logger,
) *MPINService {
    return &MPINService{
        mpinRepo:  mpinRepo,
        userRepo:  userRepo,
        hasher:    hasher,
        config:    cfg,
        logger:    logger,
        distCache: nil,
    }
}


// SetDistributedCache sets the distributed cache
func (s *MPINService) SetDistributedCache(distCache *DistributedCache) {
    s.distCache = distCache
}

// validateMPIN validates MPIN strength and format
func (s *MPINService) validateMPIN(mpin string) error {
    if len(mpin) < MPINMinLength || len(mpin) > MPINMaxLength {
        return fmt.Errorf("%w: MPIN must be between %d and %d digits", ErrInvalidInput, MPINMinLength, MPINMaxLength)
    }
    
    // Check if MPIN contains only digits
    if matched, _ := regexp.MatchString(`^\d+$`, mpin); !matched {
        return fmt.Errorf("%w: MPIN must contain only digits", ErrInvalidInput)
    }
    
    // Check for weak patterns
    if s.isMPINWeak(mpin) {
        return ErrMPINTooWeak
    }
    
    return nil
}

// isMPINWeak checks for common weak MPIN patterns
func (s *MPINService) isMPINWeak(mpin string) bool {
    // Check for repeated digits (e.g., 1111, 0000)
    if matched, _ := regexp.MatchString(`^(\d)\1+$`, mpin); matched {
        return true
    }
    
    // Check for sequential patterns (e.g., 1234, 4321)
    if s.isSequential(mpin) {
        return true
    }
    
    // Check for common weak MPINs
    weakMPINs := []string{"1234", "0000", "1111", "2222", "3333", "4444", "5555", "6666", "7777", "8888", "9999", "1122", "1212"}
    for _, weak := range weakMPINs {
        if mpin == weak {
            return true
        }
    }
    
    return false
}

// isSequential checks if MPIN is a sequential pattern
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

// SetupMPIN sets up MPIN for a user
func (s *MPINService) SetupMPIN(ctx context.Context, req *MPINSetupRequest) error {
    startTime := time.Now()
    
    // Validate MPIN
    if err := s.validateMPIN(req.MPIN); err != nil {
        return err
    }
    
    // Check if user exists
    user, err := s.userRepo.GetUserByID(ctx, req.UserID)
    if err != nil {
        return fmt.Errorf("%w: user not found", ErrInvalidInput)
    }
    
    if user.IsBanned {
        return ErrUserBanned
    }
    if user.IsBlocked {
        return ErrUserBlocked
    }
    
    // Check if MPIN already exists
    existingMPIN, err := s.mpinRepo.GetMPINByUserID(ctx, req.UserID)
    if err == nil && existingMPIN != nil {
        return ErrMPINAlreadyExists
    }
    
    // Hash MPIN
    hashResult, err := s.hasher.HashMPIN(req.MPIN)
    if err != nil {
        return fmt.Errorf("failed to hash MPIN: %w", err)
    }
    
    // Create MPIN credential
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
        return fmt.Errorf("failed to create MPIN: %w", err)
    }
    
    // Invalidate cache if present
    if s.distCache != nil {
        cacheKey := fmt.Sprintf("mpin:%s", req.UserID.String())
        _ = s.distCache.Delete(ctx, cacheKey)
    }
    
    s.logger.Info("MPIN setup completed",
        util.String("user_id", req.UserID.String()),
        util.String("device_id", req.DeviceID),
        util.Duration("duration", time.Since(startTime)),
    )
    
    return nil
}

// VerifyMPIN verifies user's MPIN
func (s *MPINService) VerifyMPIN(ctx context.Context, req *MPINVerifyRequest) (*MPINVerifyResult, error) {
    startTime := time.Now()
    
    // Validate MPIN format
    if err := s.validateMPIN(req.MPIN); err != nil {
        return nil, err
    }
    
    // Get MPIN credential
    mpinCred, err := s.mpinRepo.ValidateMPIN(ctx, req.UserID, req.MPIN)
    if err != nil {
        if err.Error() == "MPIN not found for user: "+req.UserID.String() {
            return nil, ErrMPINNotFound
        }
        if err.Error() == "MPIN locked due to too many failed attempts" {
            return &MPINVerifyResult{
                Verified:       false,
                FailedAttempts: MPINMaxAttempts,
                RemainingTries: 0,
                Message:        "MPIN is locked due to too many failed attempts",
            }, ErrMPINLocked
        }
        return nil, err
    }
    
    // Verify device binding if required
    if mpinCred.DeviceID != "" && mpinCred.DeviceID != req.DeviceID {
        return nil, ErrDeviceNotBound
    }
    
    // Verify MPIN hash
    hashResult := &hashing.HashResult{
        Hash:          mpinCred.MPINHash,
        Salt:          mpinCred.MPINSalt,
        PepperVersion: mpinCred.PepperVersion,
        Algorithm:     mpinCred.HashAlgorithm,
    }
    
    verified, err := s.hasher.VerifyMPIN(req.MPIN, hashResult)
    if err != nil {
        return nil, fmt.Errorf("failed to verify MPIN: %w", err)
    }
    
    result := &MPINVerifyResult{
        Verified:       verified,
        FailedAttempts: mpinCred.FailedAttempts,
        RemainingTries: max(0, MPINMaxAttempts-mpinCred.FailedAttempts),
    }
    
    if verified {
        // Reset failed attempts on successful verification
        if err := s.mpinRepo.ResetFailedAttempts(ctx, req.UserID); err != nil {
            s.logger.Error("Failed to reset failed attempts",
                util.ErrorField(err),
                util.String("user_id", req.UserID.String()),
            )
        }
        result.Message = "MPIN verified successfully"
        result.FailedAttempts = 0
        result.RemainingTries = MPINMaxAttempts
    } else {
        // Increment failed attempts
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
        } else {
            result.Message = fmt.Sprintf("Invalid MPIN. %d attempts remaining", result.RemainingTries)
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

// ChangeMPIN changes user's existing MPIN
func (s *MPINService) ChangeMPIN(ctx context.Context, req *MPINChangeRequest) error {
    startTime := time.Now()
    
    // Validate new MPIN
    if err := s.validateMPIN(req.NewMPIN); err != nil {
        return err
    }
    
    // Verify current MPIN first
    verifyReq := &MPINVerifyRequest{
        UserID: req.UserID,
        MPIN:   req.CurrentMPIN,
    }
    
    verifyResult, err := s.VerifyMPIN(ctx, verifyReq)
    if err != nil {
        return err
    }
    
    if !verifyResult.Verified {
        return ErrMPINInvalid
    }
    
    // Hash new MPIN
    hashResult, err := s.hasher.HashMPIN(req.NewMPIN)
    if err != nil {
        return fmt.Errorf("failed to hash new MPIN: %w", err)
    }
    
    // Update MPIN
    if err := s.mpinRepo.UpdateMPIN(ctx, req.UserID, hashResult.Hash, hashResult.Salt, hashResult.PepperVersion); err != nil {
        return fmt.Errorf("failed to update MPIN: %w", err)
    }
    
    // Invalidate cache if present
    if s.distCache != nil {
        cacheKey := fmt.Sprintf("mpin:%s", req.UserID.String())
        _ = s.distCache.Delete(ctx, cacheKey)
    }
    
    s.logger.Info("MPIN changed successfully",
        util.String("user_id", req.UserID.String()),
        util.Duration("duration", time.Since(startTime)),
    )
    
    return nil
}

// ResetMPIN resets user's MPIN (admin operation)
func (s *MPINService) ResetMPIN(ctx context.Context, req *MPINResetRequest) error {
    startTime := time.Now()
    
    // Check if MPIN exists
    _, err := s.mpinRepo.GetMPINByUserID(ctx, req.UserID)
    if err != nil {
        return ErrMPINNotFound
    }
    
    // Unlock and reset MPIN
    if err := s.mpinRepo.UnlockMPIN(ctx, req.UserID); err != nil {
        return fmt.Errorf("failed to unlock MPIN: %w", err)
    }
    
    // Invalidate cache if present
    if s.distCache != nil {
        cacheKey := fmt.Sprintf("mpin:%s", req.UserID.String())
        _ = s.distCache.Delete(ctx, cacheKey)
    }
    
    s.logger.Warn("MPIN reset by admin",
        util.String("user_id", req.UserID.String()),
        util.String("reset_by", req.ResetBy.String()),
        util.String("reason", req.Reason),
        util.Duration("duration", time.Since(startTime)),
    )
    
    return nil
}

// UnlockMPIN unlocks a locked MPIN
func (s *MPINService) UnlockMPIN(ctx context.Context, userID uuid.UUID) error {
    if err := s.mpinRepo.UnlockMPIN(ctx, userID); err != nil {
        return fmt.Errorf("failed to unlock MPIN: %w", err)
    }
    
    // Invalidate cache if present
    if s.distCache != nil {
        cacheKey := fmt.Sprintf("mpin:%s", userID.String())
        _ = s.distCache.Delete(ctx, cacheKey)
    }
    
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
    
    // Invalidate cache if present
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
    
    // Add service-level stats
    stats["service_constants"] = map[string]interface{}{
        "min_length":     MPINMinLength,
        "max_length":     MPINMaxLength,
        "max_attempts":   MPINMaxAttempts,
        "lock_duration_minutes": int(MPINLockDuration.Minutes()),
    }
    
    return stats, nil
}

// HealthCheck performs a health check on the service
func (s *MPINService) HealthCheck(ctx context.Context) error {
    return s.mpinRepo.HealthCheck(ctx)
}

// Helper function
func max(a, b int) int {
    if a > b {
        return a
    }
    return b
}

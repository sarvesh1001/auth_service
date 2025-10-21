// internal/service/otp_service.go
package service

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"net"
	"strings"
	"sync"
	"time"

	"auth-service/internal/models"
	"auth-service/internal/repository/scylla"
	"auth-service/internal/util"

	lru "github.com/hashicorp/golang-lru/v2"
	"go.uber.org/zap"
)

var (
	ErrOTPNotFound          = errors.New("OTP not found")
	ErrOTPExpired           = errors.New("OTP has expired")
	ErrOTPInvalid           = errors.New("invalid OTP")
	ErrOTPAttemptsExceeded  = errors.New("max OTP attempts exceeded")
	ErrOTPRateLimitExceeded = errors.New("OTP rate limit exceeded")
	ErrOTPAlreadyUsed       = errors.New("OTP has already been used")
)

const (
	// Rate limiting constants
	OTPSendLimit1Min         = 2  // Max 2 OTP sends per minute per phone
	OTPSendLimit5Min         = 3  // Max 3 OTP sends per 5 minutes per phone
	OTPSendLimitHour         = 10 // Max 10 OTP sends per hour per phone
	OTPVerifyLimit30Sec      = 3  // Max 3 verify attempts per 30 seconds
	OTPVerifyLimitMin        = 5  // Max 5 verify attempts per minute
	
	// OTP configurations
	OTPExpiryDuration        = 5 * time.Minute
	OTPCacheDuration         = 6 * time.Minute
	OTPRateLimitCacheDuration = 1 * time.Hour
	
	// Lockout configurations
	AccountLockoutDuration   = 30 * time.Minute
	AccountLockoutThreshold  = 5 // Failed attempts before lockout
)

// OTPService handles all OTP-related business logic
type OTPService struct {
	otpRepo       scylla.OTPRepository
	hasher        *hashing.Hasher
	logger        *zap.Logger
	distCache     *DistributedCache
	
	// Local LRU cache for rate limiting
	sendRateCache    *lru.Cache[string, *TokenBucket]
	verifyRateCache  *lru.Cache[string, *TokenBucket]
	lockoutCache     *lru.Cache[string, time.Time]
	
	rateLimitMutex   sync.RWMutex
}

// TokenBucket implements token bucket rate limiting algorithm
type TokenBucket struct {
	Tokens         float64
	MaxTokens      float64
	RefillRate     float64 // Tokens per second
	LastRefillTime time.Time
	mu             sync.Mutex
}

// OTPSendRequest represents OTP send request
type OTPSendRequest struct {
	PhoneNumber string `json:"phone_number" validate:"required,min=10,max=15"`
	Purpose     string `json:"purpose" validate:"required,oneof=login registration verification password_reset"`
	IPAddress   string `json:"ip_address"`
	DeviceID    string `json:"device_id"`
	Provider    string `json:"provider,omitempty"` // SMS provider name
}

// OTPVerifyRequest represents OTP verification request
type OTPVerifyRequest struct {
	PhoneNumber string `json:"phone_number" validate:"required,min=10,max=15"`
	OTP         string `json:"otp" validate:"required,len=6,numeric"`
	Purpose     string `json:"purpose" validate:"required"`
	IPAddress   string `json:"ip_address"`
}

// OTPResendRequest represents OTP resend request
type OTPResendRequest struct {
	PhoneNumber string `json:"phone_number" validate:"required,min=10,max=15"`
	Purpose     string `json:"purpose" validate:"required"`
	IPAddress   string `json:"ip_address"`
}

// OTPResponse represents OTP operation response
type OTPResponse struct {
	Success      bool      `json:"success"`
	Message      string    `json:"message"`
	ExpiresAt    time.Time `json:"expires_at,omitempty"`
	AttemptsLeft int       `json:"attempts_left,omitempty"`
	RetryAfter   int       `json:"retry_after,omitempty"` // Seconds to wait before retry
}

// NewOTPService creates a new OTP service
func NewOTPService(
	otpRepo scylla.OTPRepository,
	hasher *hashing.Hasher,
	distCache *DistributedCache,
	logger *zap.Logger,
) *OTPService {
	sendCache, _ := lru.New[string, *TokenBucket](100_000)
	verifyCache, _ := lru.New[string, *TokenBucket](100_000)
	lockoutCache, _ := lru.New[string, time.Time](50_000)
	
	return &OTPService{
		otpRepo:         otpRepo,
		hasher:          hasher,
		logger:          logger,
		distCache:       distCache,
		sendRateCache:   sendCache,
		verifyRateCache: verifyCache,
		lockoutCache:    lockoutCache,
	}
}

// ============================================
// TOKEN BUCKET RATE LIMITING
// ============================================

// NewTokenBucket creates a new token bucket
func NewTokenBucket(maxTokens, refillRate float64) *TokenBucket {
	return &TokenBucket{
		Tokens:         maxTokens,
		MaxTokens:      maxTokens,
		RefillRate:     refillRate,
		LastRefillTime: time.Now(),
	}
}

// TakeToken attempts to take a token from the bucket
func (tb *TokenBucket) TakeToken() bool {
	tb.mu.Lock()
	defer tb.mu.Unlock()
	
	// Refill tokens based on elapsed time
	now := time.Now()
	elapsed := now.Sub(tb.LastRefillTime).Seconds()
	tb.Tokens = min(tb.MaxTokens, tb.Tokens+elapsed*tb.RefillRate)
	tb.LastRefillTime = now
	
	if tb.Tokens >= 1.0 {
		tb.Tokens -= 1.0
		return true
	}
	
	return false
}

// TimeUntilToken returns seconds until next token is available
func (tb *TokenBucket) TimeUntilToken() int {
	tb.mu.Lock()
	defer tb.mu.Unlock()
	
	if tb.Tokens >= 1.0 {
		return 0
	}
	
	tokensNeeded := 1.0 - tb.Tokens
	secondsNeeded := tokensNeeded / tb.RefillRate
	return int(secondsNeeded) + 1
}

// ============================================
// CORE OTP OPERATIONS
// ============================================

// SendOTP generates and sends an OTP to a phone number
func (s *OTPService) SendOTP(ctx context.Context, req *OTPSendRequest) (*OTPResponse, error) {
	startTime := time.Now()
	
	// Validate and sanitize input
	if err := s.validateSendRequest(req); err != nil {
		return nil, fmt.Errorf("%w: %v", ErrInvalidInput, err)
	}
	
	// Generate phone hash
	phoneHash := s.generatePhoneHash(req.PhoneNumber)
	
	// Check account lockout
	if locked, until := s.isAccountLocked(phoneHash); locked {
		retryAfter := int(time.Until(until).Seconds())
		return &OTPResponse{
			Success:    false,
			Message:    "Account temporarily locked due to excessive attempts",
			RetryAfter: retryAfter,
		}, ErrOTPRateLimitExceeded
	}
	
	// Check rate limits with token bucket
	if !s.checkSendRateLimit(phoneHash) {
		bucket := s.getSendTokenBucket(phoneHash)
		retryAfter := bucket.TimeUntilToken()
		
		s.logger.Warn("OTP send rate limit exceeded",
			util.String("phone_hash", phoneHash),
			util.String("purpose", req.Purpose),
			util.Int("retry_after", retryAfter),
		)
		
		return &OTPResponse{
			Success:    false,
			Message:    "Too many OTP requests. Please try again later.",
			RetryAfter: retryAfter,
		}, ErrOTPRateLimitExceeded
	}
	
	// Additional database-backed rate limiting check
	if err := s.checkDatabaseRateLimit(ctx, phoneHash); err != nil {
		return nil, err
	}
	
	// Generate OTP
	otp, err := scylla.GenerateOTP(6)
	if err != nil {
		return nil, fmt.Errorf("failed to generate OTP: %w", err)
	}
	
	// Generate salt and hash OTP
	salt, err := scylla.GenerateSalt()
	if err != nil {
		return nil, fmt.Errorf("failed to generate salt: %w", err)
	}
	
	otpHash := scylla.HashOTP(otp, salt)
	
	// Parse IP address
	var ipAddr net.IP
	if req.IPAddress != "" {
		ipAddr = net.ParseIP(req.IPAddress)
	}
	
	// Create OTP verification record
	now := time.Now().UTC()
	expiresAt := now.Add(OTPExpiryDuration)
	
	otpVerification := &models.OTPVerification{
		PhoneHash:     phoneHash,
		CreatedAt:     now,
		OTPHash:       otpHash,
		OTPSalt:       salt,
		HashAlgorithm: "sha256",
		PepperVersion: s.hasher.GetCurrentPepperVersion(),
		Purpose:       req.Purpose,
		Attempts:      0,
		ExpiresAt:     expiresAt,
		IPAddress:     ipAddr,
		ProviderUsed:  req.Provider,
	}
	
	// Save to database
	if err := s.otpRepo.CreateOTP(ctx, otpVerification); err != nil {
		return nil, fmt.Errorf("failed to create OTP: %w", err)
	}
	
	// Cache OTP in Redis for fast verification
	if s.distCache != nil {
		cacheKey := fmt.Sprintf("otp:%s:%s", phoneHash, req.Purpose)
		if err := s.distCache.SetOTPVerification(ctx, cacheKey, otpVerification, OTPCacheDuration); err != nil {
			s.logger.Warn("Failed to cache OTP in Redis",
				util.ErrorField(err),
				util.String("phone_hash", phoneHash),
			)
		}
	}
	
	// TODO: Send OTP via SMS/Email provider
	// This is where you'd integrate with Twilio, AWS SNS, MSG91, etc.
	s.sendOTPViaSMS(ctx, req.PhoneNumber, otp, req.Provider)
	
	s.logger.Info("OTP sent successfully",
		util.String("phone_hash", phoneHash),
		util.String("purpose", req.Purpose),
		util.Duration("duration", time.Since(startTime)),
	)
	
	// In development, log the OTP (REMOVE IN PRODUCTION)
	if s.isDevEnvironment() {
		s.logger.Debug("OTP Generated (DEV ONLY)",
			util.String("phone", req.PhoneNumber),
			util.String("otp", otp),
		)
	}
	
	return &OTPResponse{
		Success:      true,
		Message:      "OTP sent successfully",
		ExpiresAt:    expiresAt,
		AttemptsLeft: scylla.OTPMaxAttempts,
	}, nil
}

// VerifyOTP verifies an OTP for a phone number
func (s *OTPService) VerifyOTP(ctx context.Context, req *OTPVerifyRequest) (*OTPResponse, error) {
	startTime := time.Now()
	
	// Validate input
	if err := s.validateVerifyRequest(req); err != nil {
		return nil, fmt.Errorf("%w: %v", ErrInvalidInput, err)
	}
	
	phoneHash := s.generatePhoneHash(req.PhoneNumber)
	
	// Check account lockout
	if locked, until := s.isAccountLocked(phoneHash); locked {
		retryAfter := int(time.Until(until).Seconds())
		return &OTPResponse{
			Success:    false,
			Message:    "Account temporarily locked",
			RetryAfter: retryAfter,
		}, ErrOTPRateLimitExceeded
	}
	
	// Check verification rate limit
	if !s.checkVerifyRateLimit(phoneHash) {
		bucket := s.getVerifyTokenBucket(phoneHash)
		retryAfter := bucket.TimeUntilToken()
		
		s.logger.Warn("OTP verification rate limit exceeded",
			util.String("phone_hash", phoneHash),
			util.Int("retry_after", retryAfter),
		)
		
		return &OTPResponse{
			Success:    false,
			Message:    "Too many verification attempts",
			RetryAfter: retryAfter,
		}, ErrOTPRateLimitExceeded
	}
	
	// Try to get OTP from cache first
	var otpRecord *models.OTPVerification
	var err error
	
	if s.distCache != nil {
		cacheKey := fmt.Sprintf("otp:%s:%s", phoneHash, req.Purpose)
		otpRecord, err = s.distCache.GetOTPVerification(ctx, cacheKey)
		if err != nil {
			// Cache miss, fetch from database
			otpRecord, err = s.otpRepo.GetActiveOTP(ctx, phoneHash, req.Purpose)
		}
	} else {
		otpRecord, err = s.otpRepo.GetActiveOTP(ctx, phoneHash, req.Purpose)
	}
	
	if err != nil {
		s.incrementFailedAttempts(phoneHash)
		return nil, ErrOTPNotFound
	}
	
	// Check expiry
	if time.Now().After(otpRecord.ExpiresAt) {
		s.incrementFailedAttempts(phoneHash)
		return nil, ErrOTPExpired
	}
	
	// Check attempts
	if otpRecord.Attempts >= scylla.OTPMaxAttempts {
		s.lockAccount(phoneHash)
		return nil, ErrOTPAttemptsExceeded
	}
	
	// Hash the provided OTP
	providedHash := scylla.HashOTP(req.OTP, otpRecord.OTPSalt)
	
	// Validate OTP
	_, err = s.otpRepo.ValidateOTP(ctx, phoneHash, providedHash, req.Purpose)
	if err != nil {
		s.incrementFailedAttempts(phoneHash)
		
		attemptsLeft := scylla.OTPMaxAttempts - (otpRecord.Attempts + 1)
		
		return &OTPResponse{
			Success:      false,
			Message:      "Invalid OTP",
			AttemptsLeft: attemptsLeft,
		}, ErrOTPInvalid
	}
	
	// OTP is valid - invalidate it
	if err := s.otpRepo.InvalidateOTP(ctx, phoneHash, req.Purpose); err != nil {
		s.logger.Warn("Failed to invalidate OTP after successful verification",
			util.ErrorField(err),
			util.String("phone_hash", phoneHash),
		)
	}
	
	// Remove from cache
	if s.distCache != nil {
		cacheKey := fmt.Sprintf("otp:%s:%s", phoneHash, req.Purpose)
		_ = s.distCache.DeleteOTPVerification(ctx, cacheKey)
	}
	
	// Clear failed attempts
	s.clearFailedAttempts(phoneHash)
	
	s.logger.Info("OTP verified successfully",
		util.String("phone_hash", phoneHash),
		util.String("purpose", req.Purpose),
		util.Duration("duration", time.Since(startTime)),
	)
	
	return &OTPResponse{
		Success: true,
		Message: "OTP verified successfully",
	}, nil
}

// ResendOTP resends an OTP with stricter rate limiting
func (s *OTPService) ResendOTP(ctx context.Context, req *OTPResendRequest) (*OTPResponse, error) {
	// Resend has stricter rate limits - only 1 resend per 2 minutes
	phoneHash := s.generatePhoneHash(req.PhoneNumber)
	
	// Check if there's an active OTP
	activeOTP, err := s.otpRepo.GetActiveOTP(ctx, phoneHash, req.Purpose)
	if err != nil {
		return nil, fmt.Errorf("no active OTP to resend: %w", err)
	}
	
	// Check if OTP was created less than 1 minute ago
	if time.Since(activeOTP.CreatedAt) < 60*time.Second {
		waitTime := 60 - int(time.Since(activeOTP.CreatedAt).Seconds())
		return &OTPResponse{
			Success:    false,
			Message:    "Please wait before requesting a new OTP",
			RetryAfter: waitTime,
		}, ErrOTPRateLimitExceeded
	}
	
	// Invalidate old OTP
	_ = s.otpRepo.InvalidateOTP(ctx, phoneHash, req.Purpose)
	
	// Send new OTP with original request structure
	sendReq := &OTPSendRequest{
		PhoneNumber: req.PhoneNumber,
		Purpose:     req.Purpose,
		IPAddress:   req.IPAddress,
		Provider:    "resend",
	}
	
	return s.SendOTP(ctx, sendReq)
}

// ============================================
// RATE LIMITING HELPERS
// ============================================

// getSendTokenBucket gets or creates a token bucket for OTP sending
func (s *OTPService) getSendTokenBucket(phoneHash string) *TokenBucket {
	s.rateLimitMutex.Lock()
	defer s.rateLimitMutex.Unlock()
	
	if bucket, ok := s.sendRateCache.Get(phoneHash); ok {
		return bucket
	}
	
	// Create new bucket: 2 tokens, refill 1 token per 30 seconds
	bucket := NewTokenBucket(2, 1.0/30.0)
	s.sendRateCache.Add(phoneHash, bucket)
	return bucket
}

// getVerifyTokenBucket gets or creates a token bucket for OTP verification
func (s *OTPService) getVerifyTokenBucket(phoneHash string) *TokenBucket {
	s.rateLimitMutex.Lock()
	defer s.rateLimitMutex.Unlock()
	
	if bucket, ok := s.verifyRateCache.Get(phoneHash); ok {
		return bucket
	}
	
	// Create new bucket: 3 tokens, refill 1 token per 10 seconds
	bucket := NewTokenBucket(3, 1.0/10.0)
	s.verifyRateCache.Add(phoneHash, bucket)
	return bucket
}

// checkSendRateLimit checks if sending OTP is allowed
func (s *OTPService) checkSendRateLimit(phoneHash string) bool {
	bucket := s.getSendTokenBucket(phoneHash)
	return bucket.TakeToken()
}

// checkVerifyRateLimit checks if verifying OTP is allowed
func (s *OTPService) checkVerifyRateLimit(phoneHash string) bool {
	bucket := s.getVerifyTokenBucket(phoneHash)
	return bucket.TakeToken()
}

// checkDatabaseRateLimit checks historical rate limits from database
func (s *OTPService) checkDatabaseRateLimit(ctx context.Context, phoneHash string) error {
	// Check 1-minute window
	count1Min, err := s.otpRepo.GetOTPAttemptsByPhone(ctx, phoneHash, 1*time.Minute)
	if err == nil && count1Min >= OTPSendLimit1Min {
		return fmt.Errorf("%w: too many requests in 1 minute", ErrOTPRateLimitExceeded)
	}
	
	// Check 5-minute window
	count5Min, err := s.otpRepo.GetOTPAttemptsByPhone(ctx, phoneHash, 5*time.Minute)
	if err == nil && count5Min >= OTPSendLimit5Min {
		return fmt.Errorf("%w: too many requests in 5 minutes", ErrOTPRateLimitExceeded)
	}
	
	// Check 1-hour window
	count1Hour, err := s.otpRepo.GetOTPAttemptsByPhone(ctx, phoneHash, 1*time.Hour)
	if err == nil && count1Hour >= OTPSendLimitHour {
		return fmt.Errorf("%w: too many requests in 1 hour", ErrOTPRateLimitExceeded)
	}
	
	return nil
}

// ============================================
// ACCOUNT LOCKOUT
// ============================================

// incrementFailedAttempts increments failed verification attempts
func (s *OTPService) incrementFailedAttempts(phoneHash string) {
	key := fmt.Sprintf("failed_attempts:%s", phoneHash)
	if s.distCache != nil {
		count, _ := s.distCache.IncrementCounter(context.Background(), key, 1*time.Hour)
		if count >= AccountLockoutThreshold {
			s.lockAccount(phoneHash)
		}
	}
}

// clearFailedAttempts clears failed attempts after successful verification
func (s *OTPService) clearFailedAttempts(phoneHash string) {
	key := fmt.Sprintf("failed_attempts:%s", phoneHash)
	if s.distCache != nil {
		_ = s.distCache.DeleteKey(context.Background(), key)
	}
}

// lockAccount locks an account temporarily
func (s *OTPService) lockAccount(phoneHash string) {
	lockUntil := time.Now().Add(AccountLockoutDuration)
	s.lockoutCache.Add(phoneHash, lockUntil)
	
	// Also store in Redis for distributed locking
	if s.distCache != nil {
		key := fmt.Sprintf("lockout:%s", phoneHash)
		_ = s.distCache.SetWithExpiry(context.Background(), key, lockUntil.Unix(), AccountLockoutDuration)
	}
	
	s.logger.Warn("Account locked due to excessive failed attempts",
		util.String("phone_hash", phoneHash),
		util.Time("lock_until", lockUntil),
	)
}

// isAccountLocked checks if an account is currently locked
func (s *OTPService) isAccountLocked(phoneHash string) (bool, time.Time) {
	// Check local cache first
	if lockUntil, ok := s.lockoutCache.Get(phoneHash); ok {
		if time.Now().Before(lockUntil) {
			return true, lockUntil
		}
		s.lockoutCache.Remove(phoneHash)
	}
	
	// Check Redis
	if s.distCache != nil {
		key := fmt.Sprintf("lockout:%s", phoneHash)
		var lockUntilUnix int64
		if err := s.distCache.Get(context.Background(), key, &lockUntilUnix); err == nil {
			lockUntil := time.Unix(lockUntilUnix, 0)
			if time.Now().Before(lockUntil) {
				s.lockoutCache.Add(phoneHash, lockUntil)
				return true, lockUntil
			}
		}
	}
	
	return false, time.Time{}
}

// ============================================
// VALIDATION & HELPERS
// ============================================

// validateSendRequest validates OTP send request
func (s *OTPService) validateSendRequest(req *OTPSendRequest) error {
	if req.PhoneNumber == "" {
		return fmt.Errorf("phone number is required")
	}
	if len(req.PhoneNumber) < 10 || len(req.PhoneNumber) > 15 {
		return fmt.Errorf("invalid phone number length")
	}
	if req.Purpose == "" {
		return fmt.Errorf("purpose is required")
	}
	validPurposes := map[string]bool{
		"login": true, "registration": true, 
		"verification": true, "password_reset": true,
	}
	if !validPurposes[req.Purpose] {
		return fmt.Errorf("invalid purpose")
	}
	return nil
}

// validateVerifyRequest validates OTP verification request
func (s *OTPService) validateVerifyRequest(req *OTPVerifyRequest) error {
	if req.PhoneNumber == "" {
		return fmt.Errorf("phone number is required")
	}
	if req.OTP == "" {
		return fmt.Errorf("OTP is required")
	}
	if len(req.OTP) != 6 {
		return fmt.Errorf("OTP must be 6 digits")
	}
	if req.Purpose == "" {
		return fmt.Errorf("purpose is required")
	}
	return nil
}

// generatePhoneHash generates a hash of phone number
func (s *OTPService) generatePhoneHash(phoneNumber string) string {
	normalized := strings.ReplaceAll(phoneNumber, " ", "")
	normalized = strings.ReplaceAll(normalized, "-", "")
	normalized = strings.ReplaceAll(normalized, "(", "")
	normalized = strings.ReplaceAll(normalized, ")", "")
	
	hash := sha256.Sum256([]byte(normalized))
	return hex.EncodeToString(hash[:])
}

// sendOTPViaSMS sends OTP via SMS provider (stub for integration)
func (s *OTPService) sendOTPViaSMS(ctx context.Context, phoneNumber, otp, provider string) error {
	// TODO: Integrate with SMS provider
	// Examples:
	// - Twilio
	// - AWS SNS
	// - MSG91 (India)
	// - Vonage
	
	s.logger.Info("Sending OTP via SMS",
		util.String("phone", phoneNumber),
		util.String("provider", provider),
	)
	
	return nil
}

// isDevEnvironment checks if running in development
func (s *OTPService) isDevEnvironment() bool {
	// Check environment from config
	return true // Placeholder
}

// HealthCheck performs service health check
func (s *OTPService) HealthCheck(ctx context.Context) error {
	return s.otpRepo.HealthCheck(ctx)
}

// GetOTPStats returns OTP service statistics
func (s *OTPService) GetOTPStats(ctx context.Context) (map[string]interface{}, error) {
	repoStats, err := s.otpRepo.GetOTPStats(ctx)
	if err != nil {
		return nil, err
	}
	
	stats := map[string]interface{}{
		"send_rate_cache_size":   s.sendRateCache.Len(),
		"verify_rate_cache_size": s.verifyRateCache.Len(),
		"lockout_cache_size":     s.lockoutCache.Len(),
		"repository":             repoStats,
		"rate_limits": map[string]interface{}{
			"send_limit_1min":  OTPSendLimit1Min,
			"send_limit_5min":  OTPSendLimit5Min,
			"send_limit_hour":  OTPSendLimitHour,
			"verify_limit_30s": OTPVerifyLimit30Sec,
			"verify_limit_min": OTPVerifyLimitMin,
		},
		"lockout": map[string]interface{}{
			"threshold_attempts":  AccountLockoutThreshold,
			"duration_minutes":    int(AccountLockoutDuration.Minutes()),
		},
		"timestamp": time.Now().UTC(),
	}
	
	return stats, nil
}

// Cleanup cleans up caches
func (s *OTPService) Cleanup() {
	s.sendRateCache.Purge()
	s.verifyRateCache.Purge()
	s.lockoutCache.Purge()
}

func min(a, b float64) float64 {
	if a < b {
		return a
	}
	return b
}


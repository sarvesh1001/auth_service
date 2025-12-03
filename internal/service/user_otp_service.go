package service

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"math"
	"net"
	"strings"
	"sync"
	"time"

	"auth-service/internal/config"
	"auth-service/internal/hashing"
	"auth-service/internal/models"
	"auth-service/internal/repository/scylla"
	"auth-service/internal/service/security"
	"auth-service/internal/sms"
	"auth-service/internal/util"

	"github.com/google/uuid"
	lru "github.com/hashicorp/golang-lru/v2"
	"go.uber.org/zap"
)

var (
	ErrUserOTPNotFound          = errors.New("OTP not found or invalid")
	ErrUserOTPExpired           = errors.New("OTP has expired")
	ErrUserOTPInvalid           = errors.New("invalid OTP")
	ErrUserOTPAttemptsExceeded  = errors.New("max OTP attempts exceeded")
	ErrUserOTPRateLimitExceeded = errors.New("OTP rate limit exceeded")
	ErrUserOTPAlreadyUsed       = errors.New("OTP has already been used")
	ErrUserOTPReplayAttempt     = errors.New("OTP replay detected")
	ErrUserDailyQuotaExceeded   = errors.New("daily OTP quota exceeded")
	ErrUserSecurityCheckFailed  = errors.New("security check failed")
	ErrUserPhoneNotRegistered   = errors.New("phone number not registered")
)

const (
	// User Rate Limits
	UserOTPSendLimit1Min         = 3
	UserOTPSendLimit5Min         = 5
	UserOTPSendLimitHour         = 15
	UserOTPSendLimitDay          = 30
	UserOTPVerifyLimit30Sec      = 5
	UserOTPVerifyLimitMin        = 10
	
	// User-specific durations
	UserOTPResendCooldownInitial = 60 * time.Second
	UserOTPResendCooldownMax     = 300 * time.Second
	
	// User Daily quotas
	UserDailyQuotaPerPhone  = 15
	UserDailyQuotaPerIP     = 100
	UserDailyQuotaPerDevice = 25

	UserServiceVersion = "1.0.0"
)

// UserTokenBucket implements rate limiting for users
type UserTokenBucket struct {
	Tokens         float64
	MaxTokens      float64
	RefillRate     float64
	LastRefillTime time.Time
	mu             sync.Mutex
}

// NewUserTokenBucket creates a new token bucket for users
func NewUserTokenBucket(maxTokens, refillRate float64) *UserTokenBucket {
	return &UserTokenBucket{
		Tokens:         maxTokens,
		MaxTokens:      maxTokens,
		RefillRate:     refillRate,
		LastRefillTime: time.Now(),
	}
}

// TakeToken attempts to take a token from the bucket
func (tb *UserTokenBucket) TakeToken() bool {
	tb.mu.Lock()
	defer tb.mu.Unlock()

	now := time.Now()
	elapsed := now.Sub(tb.LastRefillTime).Seconds()
	tb.Tokens = math.Min(tb.MaxTokens, tb.Tokens+elapsed*tb.RefillRate)
	tb.LastRefillTime = now

	if tb.Tokens >= 1.0 {
		tb.Tokens -= 1.0
		return true
	}

	return false
}

// TimeUntilToken returns seconds until next token is available
func (tb *UserTokenBucket) TimeUntilToken() int {
	tb.mu.Lock()
	defer tb.mu.Unlock()

	if tb.Tokens >= 1.0 {
		return 0
	}

	tokensNeeded := 1.0 - tb.Tokens
	secondsNeeded := tokensNeeded / tb.RefillRate
	return int(secondsNeeded) + 1
}

// UserOTPService handles OTP operations for regular users
type UserOTPService struct {
	otpRepo         scylla.OTPRepository
	hasher          *hashing.Hasher
	config          *config.Config
	logger          *zap.Logger
	distCache       *DistributedCache
	logProducer     *LogProducerService
	smsManager      *sms.SMSManager
	sendRateCache   *lru.Cache[string, *UserTokenBucket]
	verifyRateCache *lru.Cache[string, *UserTokenBucket]
	lockoutCache    *lru.Cache[string, time.Time]
	phoneValidator  PhoneValidator
	deviceTrustRepo scylla.DeviceTrustRepository
	// Security components
	botDetector  *security.BotDetector
	ipReputation *security.IPReputation
	riskEngine   *security.RiskEngine
	mu           sync.RWMutex
}

// UserOTPSendRequest for user OTP requests
type UserOTPSendRequest struct {
	PhoneNumber       string `json:"phone_number" validate:"required,min=10,max=15"`
	Purpose           string `json:"purpose" validate:"required,oneof=login verification password_reset forgot_mpin"`
	IPAddress         string `json:"ip_address"`
	DeviceID          string `json:"device_id"`
	Provider          string `json:"provider,omitempty"`
	UserAgent         string `json:"user_agent,omitempty"`
	DeviceFingerprint string `json:"device_fingerprint,omitempty"`
}

// UserOTPResponse for user OTP responses
type UserOTPResponse struct {
	Success      bool      `json:"success"`
	Message      string    `json:"message"`
	ExpiresAt    time.Time `json:"expires_at,omitempty"`
	AttemptsLeft int       `json:"attempts_left,omitempty"`
	RetryAfter   int       `json:"retry_after,omitempty"`
	DailyQuota   int       `json:"daily_quota,omitempty"`
	QuotaUsed    int       `json:"quota_used,omitempty"`
	OTPValue     string    `json:"otp_value,omitempty"`
}

// UserOTPVerifyRequest for user OTP verification
type UserOTPVerifyRequest struct {
	PhoneNumber       string `json:"phone_number" validate:"required,min=10,max=15"`
	OTP               string `json:"otp" validate:"required,len=6,numeric"`
	Purpose           string `json:"purpose" validate:"required,oneof=login verification password_reset forgot_mpin"`
	IPAddress         string `json:"ip_address"`
	DeviceID          string `json:"device_id"`
	DeviceFingerprint string `json:"device_fingerprint"`
	UserAgent         string `json:"user_agent,omitempty"`
}

// NewUserOTPService creates a new user OTP service
func NewUserOTPService(
	otpRepo scylla.OTPRepository,
	hasher *hashing.Hasher,
	cfg *config.Config,
	distCache *DistributedCache,
	logger *zap.Logger,
	logProducer *LogProducerService,
	phoneValidator PhoneValidator,
	deviceTrustRepo scylla.DeviceTrustRepository,
	smsManager *sms.SMSManager,
) *UserOTPService {

	sendCache, _ := lru.New[string, *UserTokenBucket](100_000)
	verifyCache, _ := lru.New[string, *UserTokenBucket](100_000)
	lockoutCache, _ := lru.New[string, time.Time](50_000)

	// Initialize security components
	botDetector := security.NewBotDetector()
	ipReputation := security.NewIPReputation(logger)
	riskEngine := security.NewRiskEngine(botDetector, ipReputation)

	return &UserOTPService{
		otpRepo:         otpRepo,
		hasher:          hasher,
		logger:          logger,
		distCache:       distCache,
		config:          cfg,
		logProducer:     logProducer,
		smsManager:      smsManager,
		sendRateCache:   sendCache,
		verifyRateCache: verifyCache,
		lockoutCache:    lockoutCache,
		phoneValidator:  phoneValidator,
		deviceTrustRepo: deviceTrustRepo,
		botDetector:     botDetector,
		ipReputation:    ipReputation,
		riskEngine:      riskEngine,
	}
}

// Helper to get user send rate limits based on purpose
func (s *UserOTPService) getUserSendRateLimits(purpose string) (maxTokens, refillRate float64) {
	// All user purposes use the same limits
	// 3 tokens per minute = 0.05 tokens per second
	return 3, 1.0 / 60.0
}

// Helper to get user verify rate limits based on purpose
func (s *UserOTPService) getUserVerifyRateLimits(purpose string) (maxTokens, refillRate float64) {
	// All user purposes use the same limits
	// 5 tokens per 30 seconds = 0.166 tokens per second
	return 5, 1.0 / 30.0
}

// getSendTokenBucket gets or creates a token bucket for OTP sending
func (s *UserOTPService) getSendTokenBucket(key, purpose string) *UserTokenBucket {
	s.mu.Lock()
	defer s.mu.Unlock()

	if bucket, ok := s.sendRateCache.Get(key); ok {
		return bucket
	}

	maxTokens, refillRate := s.getUserSendRateLimits(purpose)
	bucket := NewUserTokenBucket(maxTokens, refillRate)
	s.sendRateCache.Add(key, bucket)
	return bucket
}

// getVerifyTokenBucket gets or creates a token bucket for OTP verification
func (s *UserOTPService) getVerifyTokenBucket(key, purpose string) *UserTokenBucket {
	s.mu.Lock()
	defer s.mu.Unlock()

	if bucket, ok := s.verifyRateCache.Get(key); ok {
		return bucket
	}

	maxTokens, refillRate := s.getUserVerifyRateLimits(purpose)
	bucket := NewUserTokenBucket(maxTokens, refillRate)
	s.verifyRateCache.Add(key, bucket)
	return bucket
}

// checkSendRateLimit checks if sending is allowed
func (s *UserOTPService) checkSendRateLimit(key, purpose string) bool {
	bucket := s.getSendTokenBucket(key, purpose)
	return bucket.TakeToken()
}

// checkVerifyRateLimit checks if verification is allowed
func (s *UserOTPService) checkVerifyRateLimit(key, purpose string) bool {
	bucket := s.getVerifyTokenBucket(key, purpose)
	return bucket.TakeToken()
}

// timeUntilSendToken returns seconds until next send token is available
func (s *UserOTPService) timeUntilSendToken(key, purpose string) int {
	bucket := s.getSendTokenBucket(key, purpose)
	return bucket.TimeUntilToken()
}

// timeUntilVerifyToken returns seconds until next verify token is available
func (s *UserOTPService) timeUntilVerifyToken(key, purpose string) int {
	bucket := s.getVerifyTokenBucket(key, purpose)
	return bucket.TimeUntilToken()
}

// isUserPhoneRegistered checks if phone is registered for users
func (s *UserOTPService) isUserPhoneRegistered(ctx context.Context, phoneNumber, purpose string) (bool, error) {
	return s.phoneValidator.IsUserPhoneRegistered(ctx, phoneNumber)
}

// // UserSendOTP sends OTP for users
// func (s *UserOTPService) UserSendOTP(ctx context.Context, req *UserOTPSendRequest) (*UserOTPResponse, error) {
// 	startTime := time.Now()

// 	// Check if phone number is registered for user
// 	isRegistered, err := s.isUserPhoneRegistered(ctx, req.PhoneNumber, req.Purpose)
// 	if err != nil {
// 		s.logUserOTPEvent(ctx, &models.OTPLogEvent{
// 			LogEnvelope: models.LogEnvelope{
// 				EventID:     uuid.New().String(),
// 				EventType:   string(models.LogEventTypeOTP),
// 				ServiceName: "auth-service",
// 				Timestamp:   time.Now(),
// 				Environment: s.config.Environment,
// 				Version:     UserServiceVersion,
// 				Level:       string(models.LogLevelError),
// 				Message:     "User phone registration check failed",
// 			},
// 			PhoneNumber:   req.PhoneNumber,
// 			Status:        "send_failed",
// 			Purpose:       req.Purpose,
// 			IPAddress:     req.IPAddress,
// 			UserAgent:     req.UserAgent,
// 			ErrorCode:     "USER_PHONE_CHECK_FAILED",
// 			ErrorMessage:  err.Error(),
// 			AttemptNumber: 0,
// 		})
// 		return nil, fmt.Errorf("failed to check user phone registration: %w", err)
// 	}

// 	if !isRegistered {
// 		s.logUserOTPEvent(ctx, &models.OTPLogEvent{
// 			LogEnvelope: models.LogEnvelope{
// 				EventID:     uuid.New().String(),
// 				EventType:   string(models.LogEventTypeOTP),
// 				ServiceName: "auth-service",
// 				Timestamp:   time.Now(),
// 				Environment: s.config.Environment,
// 				Version:     UserServiceVersion,
// 				Level:       string(models.LogLevelWarning),
// 				Message:     "User phone number not registered",
// 			},
// 			PhoneNumber:   req.PhoneNumber,
// 			Status:        "send_failed",
// 			Purpose:       req.Purpose,
// 			IPAddress:     req.IPAddress,
// 			UserAgent:     req.UserAgent,
// 			ErrorCode:     "USER_PHONE_NOT_REGISTERED",
// 			ErrorMessage:  "Phone number is not registered in the user system",
// 			AttemptNumber: 0,
// 		})
// 		return &UserOTPResponse{
// 			Success: false,
// 			Message: "Phone number not registered",
// 		}, ErrUserPhoneNotRegistered
// 	}

// 	// Security checks
// 	securityResult := s.performUserSecurityChecks(ctx, req, startTime)
// 	if securityResult != nil {
// 		return securityResult, ErrUserSecurityCheckFailed
// 	}

// 	// Log initiation
// 	s.logUserOTPEvent(ctx, &models.OTPLogEvent{
// 		LogEnvelope: models.LogEnvelope{
// 			EventID:     uuid.New().String(),
// 			EventType:   string(models.LogEventTypeOTP),
// 			ServiceName: "auth-service",
// 			Timestamp:   time.Now(),
// 			Environment: s.config.Environment,
// 			Version:     UserServiceVersion,
// 			Level:       string(models.LogLevelInfo),
// 			Message:     "User OTP send initiated",
// 		},
// 		PhoneNumber: req.PhoneNumber,
// 		Status:      "send_initiated",
// 		Purpose:     req.Purpose,
// 		IPAddress:   req.IPAddress,
// 		UserAgent:   req.UserAgent,
// 	})

// 	// Validate input
// 	if err := s.validateUserSendRequest(req); err != nil {
// 		s.logUserOTPEvent(ctx, &models.OTPLogEvent{
// 			LogEnvelope: models.LogEnvelope{
// 				EventID:     uuid.New().String(),
// 				EventType:   string(models.LogEventTypeOTP),
// 				ServiceName: "auth-service",
// 				Timestamp:   time.Now(),
// 				Environment: s.config.Environment,
// 				Version:     UserServiceVersion,
// 				Level:       string(models.LogLevelError),
// 				Message:     "User OTP send validation failed",
// 			},
// 			PhoneNumber:   req.PhoneNumber,
// 			Status:        "send_failed",
// 			Purpose:       req.Purpose,
// 			IPAddress:     req.IPAddress,
// 			UserAgent:     req.UserAgent,
// 			ErrorCode:     "VALIDATION_FAILED",
// 			ErrorMessage:  err.Error(),
// 			AttemptNumber: 0,
// 		})
// 		return nil, fmt.Errorf("%w: %v", ErrInvalidInput, err)
// 	}

// 	phoneHash := s.generatePhoneHash(req.PhoneNumber)

// 	// Check daily quotas
// 	quotaCheck, err := s.checkUserDailyQuotas(ctx, phoneHash, req.IPAddress, req.DeviceID, req.Purpose)
// 	if err != nil {
// 		return quotaCheck, err
// 	}

// 	// Cooldown check - uses increasing cooldown like admin service
// 	deviceKey := req.DeviceID
// 	if deviceKey == "" {
// 		deviceKey = "nodevice"
// 	}
// 	cooldownKey := fmt.Sprintf("user_otp:cooldown:%s:%s:%s", phoneHash, req.Purpose, deviceKey)
// 	allowed, retryAfter := s.distCache.AllowRateWithIncreasingCooldown(
// 		ctx, cooldownKey, UserOTPResendCooldownInitial, UserOTPResendCooldownMax)
// 	if !allowed {
// 		s.logUserOTPEvent(ctx, &models.OTPLogEvent{
// 			LogEnvelope: models.LogEnvelope{
// 				EventID:     uuid.New().String(),
// 				EventType:   string(models.LogEventTypeOTP),
// 				ServiceName: "auth-service",
// 				Timestamp:   time.Now(),
// 				Environment: s.config.Environment,
// 				Version:     UserServiceVersion,
// 				Level:       string(models.LogLevelWarning),
// 				Message:     "User OTP send cooldown active",
// 			},
// 			PhoneNumber:   req.PhoneNumber,
// 			Status:        "send_cooldown",
// 			Purpose:       req.Purpose,
// 			IPAddress:     req.IPAddress,
// 			UserAgent:     req.UserAgent,
// 			ErrorCode:     "COOLDOWN_ACTIVE",
// 			AttemptNumber: 0,
// 			AttemptsLeft:  retryAfter,
// 		})
// 		return &UserOTPResponse{
// 			Success:    false,
// 			Message:    "Please wait before requesting a new OTP",
// 			RetryAfter: retryAfter,
// 		}, ErrUserOTPRateLimitExceeded
// 	}

// 	// Device/IP rate limit
// 	if s.distCache != nil && req.DeviceID != "" {
// 		key := fmt.Sprintf("user_otp:rate:send:device:%s", req.DeviceID)
// 		if allowed, retry := s.distCache.AllowRate(ctx, key, 5, time.Minute); !allowed {
// 			return &UserOTPResponse{
// 				Success:    false,
// 				Message:    "Too many OTP requests from this device",
// 				RetryAfter: retry,
// 			}, ErrUserOTPRateLimitExceeded
// 		}
// 	}

// 	if s.distCache != nil && req.IPAddress != "" {
// 		key := fmt.Sprintf("user_otp:rate:send:ip:%s", req.IPAddress)
// 		if allowed, retry := s.distCache.AllowRate(ctx, key, 20, time.Minute); !allowed {
// 			return &UserOTPResponse{
// 				Success:    false,
// 				Message:    "Too many OTP requests from this IP",
// 				RetryAfter: retry,
// 			}, ErrUserOTPRateLimitExceeded
// 		}
// 	}

// 	// Account lockout
// 	if locked, until := s.isUserAccountLocked(phoneHash); locked {
// 		retry := int(time.Until(until).Seconds())
// 		return &UserOTPResponse{
// 			Success:    false,
// 			Message:    "Account temporarily locked due to excessive attempts",
// 			RetryAfter: retry,
// 		}, ErrUserOTPRateLimitExceeded
// 	}

// 	// Purpose-based rate limits using token bucket
// 	rateKey := fmt.Sprintf("user:%s:%s", phoneHash, req.Purpose)
// 	if !s.checkSendRateLimit(rateKey, req.Purpose) {
// 		retryAfter := s.timeUntilSendToken(rateKey, req.Purpose)
// 		return &UserOTPResponse{
// 			Success:    false,
// 			Message:    "Too many OTP requests. Try again later.",
// 			RetryAfter: retryAfter,
// 		}, ErrUserOTPRateLimitExceeded
// 	}

// 	// Invalidate any existing OTP
// 	existingOTP, err := s.otpRepo.GetActiveOTP(ctx, phoneHash, req.Purpose)
// 	if err == nil && existingOTP != nil {
// 		// Invalidate the existing OTP
// 		if err := s.otpRepo.InvalidateOTP(ctx, phoneHash, req.Purpose); err != nil {
// 			s.logger.Warn("Failed to invalidate existing user OTP",
// 				util.ErrorField(err),
// 				util.String("phone_hash", phoneHash),
// 				util.String("purpose", req.Purpose))
// 		}

// 		// Remove from cache
// 		if s.distCache != nil {
// 			cacheKey := fmt.Sprintf("user_otp:%s:%s", phoneHash, req.Purpose)
// 			_ = s.distCache.DeleteOTPVerification(ctx, cacheKey)
// 		}

// 		s.logger.Info("Invalidated existing user OTP for new send",
// 			util.String("phone", req.PhoneNumber),
// 			util.String("purpose", req.Purpose))
// 	}

// 	// Generate OTP
// 	otp, err := scylla.GenerateOTP(6)
// 	if err != nil {
// 		return nil, fmt.Errorf("failed to generate user OTP: %w", err)
// 	}

// 	// LOG OTP CODE - Always log for testing
// 	s.logger.Info("USER OTP GENERATED",
// 		util.String("otp_code", otp),
// 		util.String("phone", req.PhoneNumber),
// 		util.String("purpose", req.Purpose),
// 		util.String("device_id", req.DeviceID))

// 	salt, err := scylla.GenerateSalt()
// 	if err != nil {
// 		return nil, fmt.Errorf("failed to generate salt: %w", err)
// 	}

// 	otpHash := scylla.HashOTP(otp, salt)

// 	// Create OTP record
// 	now := time.Now().UTC()
// 	expiresAt := now.Add(OTPExpiryDuration)

// 	otpVerification := &models.OTPVerification{
// 		PhoneHash:     phoneHash,
// 		CreatedAt:     now,
// 		OTPHash:       otpHash,
// 		OTPSalt:       salt,
// 		HashAlgorithm: "sha256",
// 		PepperVersion: s.hasher.GetCurrentPepperVersion(),
// 		Purpose:       req.Purpose,
// 		Attempts:      0,
// 		ExpiresAt:     expiresAt,
// 		IPAddress:     net.ParseIP(req.IPAddress),
// 		ProviderUsed:  req.Provider,
// 		DeviceID:      req.DeviceID,
// 	}

// 	// Save OTP in DB
// 	if err := s.otpRepo.CreateOTP(ctx, otpVerification); err != nil {
// 		return nil, fmt.Errorf("failed to create user OTP: %w", err)
// 	}

// 	// Cache OTP
// 	if s.distCache != nil {
// 		go func() {
// 			cacheKey := fmt.Sprintf("user_otp:%s:%s", phoneHash, req.Purpose)
// 			_ = s.distCache.SetOTPVerification(
// 				context.Background(),
// 				cacheKey,
// 				otpVerification,
// 				OTPCacheDuration,
// 			)
// 		}()
// 	}

// 	// Send OTP via SMSManager
// 	smsReq := sms.SMSRequest{
// 		PhoneNumber:       req.PhoneNumber,
// 		OTP:               otp,
// 		PreferredProvider: req.Provider,
// 		Purpose:           req.Purpose,
// 	}

// 	smsResp := s.smsManager.SendOTP(ctx, smsReq)
// 	if !smsResp.Success {
// 		return nil, fmt.Errorf("all SMS providers failed to send user OTP")
// 	}

// 	// Update quota usage
// 	s.incrementUserDailyQuotas(ctx, phoneHash, req.IPAddress, req.DeviceID)

// 	// Final response
// 	resp := &UserOTPResponse{
// 		Success:      true,
// 		Message:      "OTP sent successfully",
// 		ExpiresAt:    expiresAt,
// 		AttemptsLeft: scylla.OTPMaxAttempts,
// 		DailyQuota:   s.getDailyQuotaLimit(req.Purpose),
// 	}

// 	// Always return OTP in development for testing
// 	resp.OTPValue = otp

// 	// Log successful send
// 	s.logUserOTPEvent(ctx, &models.OTPLogEvent{
// 		LogEnvelope: models.LogEnvelope{
// 			EventID:     uuid.New().String(),
// 			EventType:   string(models.LogEventTypeOTP),
// 			ServiceName: "auth-service",
// 			Timestamp:   time.Now(),
// 			Environment: s.config.Environment,
// 			Version:     UserServiceVersion,
// 			Level:       string(models.LogLevelInfo),
// 			Message:     "User OTP sent successfully",
// 		},
// 		PhoneNumber:   req.PhoneNumber,
// 		Status:        "sent",
// 		Purpose:       req.Purpose,
// 		IPAddress:     req.IPAddress,
// 		UserAgent:     req.UserAgent,
// 		AttemptNumber: 0,
// 		Duration:      int64(time.Since(startTime).Milliseconds()),
// 	})

// 	return resp, nil
// }

// UserVerifyOTP verifies OTP for users
func (s *UserOTPService) UserVerifyOTP(ctx context.Context, req *UserOTPVerifyRequest) (*UserOTPResponse, error) {
	startTime := time.Now()

	// LOG OTP VERIFICATION ATTEMPT
	s.logger.Info("USER OTP VERIFICATION ATTEMPT",
		util.String("otp_code", req.OTP),
		util.String("phone", req.PhoneNumber),
		util.String("purpose", req.Purpose),
		util.String("device_id", req.DeviceID))

	s.logUserOTPEvent(ctx, &models.OTPLogEvent{
		LogEnvelope: models.LogEnvelope{
			EventID:     uuid.New().String(),
			EventType:   string(models.LogEventTypeOTP),
			ServiceName: "auth-service",
			Timestamp:   time.Now(),
			Environment: s.config.Environment,
			Version:     UserServiceVersion,
			Level:       string(models.LogLevelInfo),
			Message:     "User OTP verification initiated",
		},
		PhoneNumber: req.PhoneNumber,
		Status:      "verification_initiated",
		Purpose:     req.Purpose,
		IPAddress:   req.IPAddress,
		UserAgent:   req.UserAgent,
	})

	// Validate input
	if err := s.validateUserVerifyRequest(req); err != nil {
		s.logUserOTPEvent(ctx, &models.OTPLogEvent{
			LogEnvelope: models.LogEnvelope{
				EventID:     uuid.New().String(),
				EventType:   string(models.LogEventTypeOTP),
				ServiceName: "auth-service",
				Timestamp:   time.Now(),
				Environment: s.config.Environment,
				Version:     UserServiceVersion,
				Level:       string(models.LogLevelError),
				Message:     "User OTP verification validation failed",
			},
			PhoneNumber:   req.PhoneNumber,
			Status:        "verification_failed",
			Purpose:       req.Purpose,
			IPAddress:     req.IPAddress,
			UserAgent:     req.UserAgent,
			ErrorCode:     "VALIDATION_FAILED",
			ErrorMessage:  "Invalid request",
			AttemptNumber: 0,
		})
		return nil, fmt.Errorf("%w: %v", ErrInvalidInput, err)
	}

	phoneHash := s.generatePhoneHash(req.PhoneNumber)

	// Enhanced logging
	s.logger.Info("User OTP verification attempt",
		util.String("phone", req.PhoneNumber),
		util.String("purpose", req.Purpose),
		util.String("ip", req.IPAddress),
		util.String("device_id", req.DeviceID),
		util.String("user_agent", req.UserAgent))

	// Purpose-based verification rate limits using token bucket
	verifyRateKey := fmt.Sprintf("user:verify:%s:%s", phoneHash, req.Purpose)
	if !s.checkVerifyRateLimit(verifyRateKey, req.Purpose) {
		retryAfter := s.timeUntilVerifyToken(verifyRateKey, req.Purpose)
		return &UserOTPResponse{
			Success:    false,
			Message:    "Too many verification attempts. Try again later.",
			RetryAfter: retryAfter,
		}, ErrUserOTPRateLimitExceeded
	}

	// Rate limiting checks
	if s.distCache != nil && req.DeviceID != "" {
		key := fmt.Sprintf("user_otp:rate:verify:device:%s", req.DeviceID)
		allowed, retry := s.distCache.AllowRate(ctx, key, 10, time.Minute)
		if !allowed {
			s.logUserOTPEvent(ctx, &models.OTPLogEvent{
				LogEnvelope: models.LogEnvelope{
					EventID:     uuid.New().String(),
					EventType:   string(models.LogEventTypeOTP),
					ServiceName: "auth-service",
					Timestamp:   time.Now(),
					Environment: s.config.Environment,
					Version:     UserServiceVersion,
					Level:       string(models.LogLevelWarning),
					Message:     "User OTP verification device rate limit exceeded",
				},
				PhoneNumber:   req.PhoneNumber,
				Status:        "verification_rate_limited",
				Purpose:       req.Purpose,
				IPAddress:     req.IPAddress,
				UserAgent:     req.UserAgent,
				DeviceID:      req.DeviceID,
				ErrorCode:     "DEVICE_RATE_LIMIT_EXCEEDED",
				AttemptNumber: 0,
				AttemptsLeft:  retry,
			})
			return &UserOTPResponse{
				Success:    false,
				Message:    "Too many verification attempts",
				RetryAfter: retry,
			}, ErrUserOTPRateLimitExceeded
		}
	}

	if s.distCache != nil && req.IPAddress != "" {
		key := fmt.Sprintf("user_otp:rate:verify:ip:%s", req.IPAddress)
		allowed, retry := s.distCache.AllowRate(ctx, key, 30, time.Minute)
		if !allowed {
			s.logUserOTPEvent(ctx, &models.OTPLogEvent{
				LogEnvelope: models.LogEnvelope{
					EventID:     uuid.New().String(),
					EventType:   string(models.LogEventTypeOTP),
					ServiceName: "auth-service",
					Timestamp:   time.Now(),
					Environment: s.config.Environment,
					Version:     UserServiceVersion,
					Level:       string(models.LogLevelWarning),
					Message:     "User OTP verification IP rate limit exceeded",
				},
				PhoneNumber:   req.PhoneNumber,
				Status:        "verification_rate_limited",
				Purpose:       req.Purpose,
				IPAddress:     req.IPAddress,
				UserAgent:     req.UserAgent,
				DeviceID:      req.DeviceID,
				ErrorCode:     "IP_RATE_LIMIT_EXCEEDED",
				AttemptNumber: 0,
				AttemptsLeft:  retry,
			})
			return &UserOTPResponse{
				Success:    false,
				Message:    "Too many verification attempts",
				RetryAfter: retry,
			}, ErrUserOTPRateLimitExceeded
		}
	}

	// Check account lockout
	if locked, until := s.isUserAccountLocked(phoneHash); locked {
		retryAfter := int(time.Until(until).Seconds())
		s.logUserOTPEvent(ctx, &models.OTPLogEvent{
			LogEnvelope: models.LogEnvelope{
				EventID:     uuid.New().String(),
				EventType:   string(models.LogEventTypeOTP),
				ServiceName: "auth-service",
				Timestamp:   time.Now(),
				Environment: s.config.Environment,
				Version:     UserServiceVersion,
				Level:       string(models.LogLevelWarning),
				Message:     "User account locked for OTP verification",
			},
			PhoneNumber:   req.PhoneNumber,
			Status:        "verification_blocked",
			Purpose:       req.Purpose,
			IPAddress:     req.IPAddress,
			UserAgent:     req.UserAgent,
			ErrorCode:     "ACCOUNT_LOCKED",
			AttemptNumber: 0,
			AttemptsLeft:  retryAfter,
		})
		return &UserOTPResponse{
			Success:    false,
			Message:    "Account temporarily locked",
			RetryAfter: retryAfter,
		}, ErrUserOTPRateLimitExceeded
	}

	// Get OTP record
	var otpRecord *models.OTPVerification
	var err error

	if s.distCache != nil {
		cacheKey := fmt.Sprintf("user_otp:%s:%s", phoneHash, req.Purpose)
		otpRecord, err = s.distCache.GetOTPVerification(ctx, cacheKey)
		if err != nil {
			otpRecord, err = s.otpRepo.GetActiveOTP(ctx, phoneHash, req.Purpose)
		}
	} else {
		otpRecord, err = s.otpRepo.GetActiveOTP(ctx, phoneHash, req.Purpose)
	}

	if err != nil {
		s.incrementUserFailedAttempts(phoneHash)

		s.logUserOTPEvent(ctx, &models.OTPLogEvent{
			LogEnvelope: models.LogEnvelope{
				EventID:     uuid.New().String(),
				EventType:   string(models.LogEventTypeOTP),
				ServiceName: "auth-service",
				Timestamp:   time.Now(),
				Environment: s.config.Environment,
				Version:     UserServiceVersion,
				Level:       string(models.LogLevelWarning),
				Message:     "User OTP verification failed",
			},
			PhoneNumber:   req.PhoneNumber,
			Status:        "verification_failed",
			Purpose:       req.Purpose,
			IPAddress:     req.IPAddress,
			UserAgent:     req.UserAgent,
			ErrorCode:     "OTP_NOT_FOUND",
			ErrorMessage:  "Invalid OTP or expired",
			AttemptNumber: 0,
		})

		return &UserOTPResponse{
			Success: false,
			Message: "Invalid OTP or expired",
		}, ErrUserOTPNotFound
	}

	// Device binding validation
	if otpRecord.DeviceID != "" {
		if req.DeviceID == "" || otpRecord.DeviceID != req.DeviceID {
			s.incrementUserFailedAttempts(phoneHash)
			s.logUserOTPEvent(ctx, &models.OTPLogEvent{
				LogEnvelope: models.LogEnvelope{
					EventID:     uuid.New().String(),
					EventType:   string(models.LogEventTypeOTP),
					ServiceName: "auth-service",
					Timestamp:   time.Now(),
					Environment: s.config.Environment,
					Version:     UserServiceVersion,
					Level:       string(models.LogLevelWarning),
					Message:     "User OTP device mismatch",
				},
				PhoneNumber:   req.PhoneNumber,
				Status:        "verification_failed",
				Purpose:       req.Purpose,
				IPAddress:     req.IPAddress,
				UserAgent:     req.UserAgent,
				DeviceID:      req.DeviceID,
				ErrorCode:     "DEVICE_MISMATCH",
				AttemptNumber: otpRecord.Attempts,
				AttemptsLeft:  scylla.OTPMaxAttempts - otpRecord.Attempts,
			})
			return &UserOTPResponse{
				Success:      false,
				Message:      "Invalid OTP or expired",
				AttemptsLeft: scylla.OTPMaxAttempts - otpRecord.Attempts,
			}, ErrUserOTPInvalid
		}
	}

	// Check expiry
	if time.Now().After(otpRecord.ExpiresAt) {
		s.incrementUserFailedAttempts(phoneHash)
		s.logUserOTPEvent(ctx, &models.OTPLogEvent{
			LogEnvelope: models.LogEnvelope{
				EventID:     uuid.New().String(),
				EventType:   string(models.LogEventTypeOTP),
				ServiceName: "auth-service",
				Timestamp:   time.Now(),
				Environment: s.config.Environment,
				Version:     UserServiceVersion,
				Level:       string(models.LogLevelWarning),
				Message:     "User OTP expired for verification",
			},
			PhoneNumber:   req.PhoneNumber,
			Status:        "verification_failed",
			Purpose:       req.Purpose,
			IPAddress:     req.IPAddress,
			UserAgent:     req.UserAgent,
			ErrorCode:     "OTP_EXPIRED",
			AttemptNumber: otpRecord.Attempts,
			AttemptsLeft:  scylla.OTPMaxAttempts - otpRecord.Attempts,
		})
		return &UserOTPResponse{
			Success:   false,
			Message:   "Invalid OTP or expired",
			ExpiresAt: otpRecord.ExpiresAt,
		}, ErrUserOTPExpired
	}

	// Check attempts
	if otpRecord.Attempts >= scylla.OTPMaxAttempts {
		s.lockUserAccount(phoneHash)
		s.logUserOTPEvent(ctx, &models.OTPLogEvent{
			LogEnvelope: models.LogEnvelope{
				EventID:     uuid.New().String(),
				EventType:   string(models.LogEventTypeOTP),
				ServiceName: "auth-service",
				Timestamp:   time.Now(),
				Environment: s.config.Environment,
				Version:     UserServiceVersion,
				Level:       string(models.LogLevelWarning),
				Message:     "User OTP verification attempts exceeded",
			},
			PhoneNumber:   req.PhoneNumber,
			Status:        "verification_blocked",
			Purpose:       req.Purpose,
			IPAddress:     req.IPAddress,
			UserAgent:     req.UserAgent,
			ErrorCode:     "ATTEMPTS_EXCEEDED",
			AttemptNumber: otpRecord.Attempts,
			AttemptsLeft:  0,
		})
		return &UserOTPResponse{
			Success:      false,
			Message:      "Invalid OTP or expired",
			AttemptsLeft: 0,
		}, ErrUserOTPAttemptsExceeded
	}

	// Check OTP replay protection
	providedHash := scylla.HashOTP(req.OTP, otpRecord.OTPSalt)
	replayKey := fmt.Sprintf("user_otp:replay:%s:%s", phoneHash, providedHash)

	replayExists, err := s.distCache.CheckOTPReplayProtection(ctx, replayKey)
	if err != nil {
		s.logger.Warn("Failed to check user OTP replay protection", util.ErrorField(err))
	} else if replayExists {
		s.incrementUserFailedAttempts(phoneHash)
		s.logUserOTPEvent(ctx, &models.OTPLogEvent{
			LogEnvelope: models.LogEnvelope{
				EventID:     uuid.New().String(),
				EventType:   string(models.LogEventTypeOTP),
				ServiceName: "auth-service",
				Timestamp:   time.Now(),
				Environment: s.config.Environment,
				Version:     UserServiceVersion,
				Level:       string(models.LogLevelWarning),
				Message:     "User OTP replay attempt detected",
			},
			PhoneNumber:   req.PhoneNumber,
			Status:        "verification_failed",
			Purpose:       req.Purpose,
			IPAddress:     req.IPAddress,
			UserAgent:     req.UserAgent,
			ErrorCode:     "REPLAY_ATTEMPT",
			AttemptNumber: otpRecord.Attempts,
			AttemptsLeft:  scylla.OTPMaxAttempts - otpRecord.Attempts,
		})
		return &UserOTPResponse{
			Success:      false,
			Message:      "Invalid OTP or expired",
			AttemptsLeft: scylla.OTPMaxAttempts - otpRecord.Attempts,
		}, ErrUserOTPReplayAttempt
	}

	// Validate OTP
	validatedOTP, err := s.otpRepo.ValidateOTP(ctx, phoneHash, providedHash, req.Purpose)
	if err != nil {
		s.incrementUserFailedAttempts(phoneHash)
		attemptsLeft := scylla.OTPMaxAttempts
		if validatedOTP != nil {
			attemptsLeft = scylla.OTPMaxAttempts - validatedOTP.Attempts
		}

		if attemptsLeft <= 0 {
			s.lockUserAccount(phoneHash)
		}

		s.logUserOTPEvent(ctx, &models.OTPLogEvent{
			LogEnvelope: models.LogEnvelope{
				EventID:     uuid.New().String(),
				EventType:   string(models.LogEventTypeOTP),
				ServiceName: "auth-service",
				Timestamp:   time.Now(),
				Environment: s.config.Environment,
				Version:     UserServiceVersion,
				Level:       string(models.LogLevelWarning),
				Message:     "Invalid user OTP provided",
			},
			PhoneNumber:   req.PhoneNumber,
			Status:        "verification_failed",
			Purpose:       req.Purpose,
			IPAddress:     req.IPAddress,
			UserAgent:     req.UserAgent,
			ErrorCode:     "INVALID_OTP",
			AttemptNumber: validatedOTP.Attempts,
			AttemptsLeft:  attemptsLeft,
			Duration:      int64(time.Since(startTime).Milliseconds()),
		})

		return &UserOTPResponse{
			Success:      false,
			Message:      "Invalid OTP or expired",
			AttemptsLeft: attemptsLeft,
			ExpiresAt:    otpRecord.ExpiresAt,
		}, ErrUserOTPInvalid
	}

	// Set replay protection before invalidating OTP
	err = s.distCache.StoreOTPReplayProtection(ctx, replayKey, providedHash, OTPReplayProtectionWindow)
	if err != nil {
		s.logger.Warn("Failed to set user OTP replay protection", util.ErrorField(err))
	}

	// Invalidate OTP
	if err := s.otpRepo.InvalidateOTP(ctx, phoneHash, req.Purpose); err != nil {
		s.logger.Warn("Failed to invalidate user OTP after successful verification",
			util.ErrorField(err),
			util.String("phone_hash", phoneHash),
			util.String("purpose", req.Purpose),
		)
	}

	// Remove from cache
	if s.distCache != nil {
		cacheKey := fmt.Sprintf("user_otp:%s:%s", phoneHash, req.Purpose)
		_ = s.distCache.DeleteOTPVerification(ctx, cacheKey)
	}

	// Clear failed attempts
	s.clearUserFailedAttempts(phoneHash)

	// LOG SUCCESSFUL VERIFICATION
	s.logger.Info("USER OTP VERIFICATION SUCCESS",
		util.String("otp_code", req.OTP),
		util.String("phone", req.PhoneNumber),
		util.String("purpose", req.Purpose),
		util.String("device_id", req.DeviceID))

	s.logUserOTPEvent(ctx, &models.OTPLogEvent{
		LogEnvelope: models.LogEnvelope{
			EventID:     uuid.New().String(),
			EventType:   string(models.LogEventTypeOTP),
			ServiceName: "auth-service",
			Timestamp:   time.Now(),
			Environment: s.config.Environment,
			Version:     UserServiceVersion,
			Level:       string(models.LogLevelInfo),
			Message:     "User OTP verified successfully",
		},
		PhoneNumber:   req.PhoneNumber,
		Status:        "verified",
		Purpose:       req.Purpose,
		IPAddress:     req.IPAddress,
		UserAgent:     req.UserAgent,
		AttemptNumber: validatedOTP.Attempts,
		AttemptsLeft:  scylla.OTPMaxAttempts - validatedOTP.Attempts,
		Duration:      int64(time.Since(startTime).Milliseconds()),
	})

	return &UserOTPResponse{
		Success: true,
		Message: "OTP verified successfully",
	}, nil
}

// Helper methods for UserOTPService

func (s *UserOTPService) performUserSecurityChecks(ctx context.Context, req *UserOTPSendRequest, startTime time.Time) *UserOTPResponse {
	requestLatency := time.Since(startTime)

	s.logger.Info("🔍 Starting user OTP security checks",
		util.String("phone", req.PhoneNumber),
		util.String("purpose", req.Purpose),
		util.String("ip", req.IPAddress),
		util.String("device_id", req.DeviceID),
		util.String("user_agent", req.UserAgent),
		util.Duration("request_latency", requestLatency))

	// Quick risk check
	quickRisk, shouldBlock := s.riskEngine.QuickRiskCheck(req.IPAddress, req.UserAgent, requestLatency, req.Purpose)

	s.logger.Info("🔍 User quick risk check result",
		util.Int("quick_risk_score", quickRisk),
		util.Bool("should_block", shouldBlock))

	if shouldBlock {
		s.logUserSecurityEvent(ctx, req, "user_quick_risk_check_failed", quickRisk, []string{"high_risk_quick_check"})
		s.logger.Warn("🚨 Quick risk check blocked user OTP request",
			util.String("phone", req.PhoneNumber),
			util.Int("risk_score", quickRisk),
			util.String("user_agent", req.UserAgent))
		return &UserOTPResponse{
			Success: false,
			Message: "Security check failed",
		}
	}

	// Full risk assessment
	riskReq := security.RiskAssessmentRequest{
		UserAgent:      req.UserAgent,
		IPAddress:      req.IPAddress,
		DeviceID:       req.DeviceID,
		PhoneNumber:    req.PhoneNumber,
		Purpose:        req.Purpose,
		RequestLatency: requestLatency,
		FailedAttempts: s.getUserFailedAttemptsCount(req.PhoneNumber),
		DailyOTPCount:  s.getUserDailyOTPCount(req.PhoneNumber),
		IsNewDevice:    s.isUserNewDevice(req.DeviceID, req.PhoneNumber),
		IsNewIP:        s.isUserNewIP(req.IPAddress, req.PhoneNumber, req.DeviceID),
	}

	riskAssessment := s.riskEngine.AssessRisk(riskReq)

	s.logger.Info("🔍 User full risk assessment result",
		util.String("phone", req.PhoneNumber),
		util.Int("risk_score", riskAssessment.RiskScore),
		util.String("risk_level", riskAssessment.RiskLevel),
		util.Bool("block_action", riskAssessment.BlockAction),
		util.Strings("reasons", riskAssessment.Reasons),
		util.String("user_agent", req.UserAgent))

	// Send event to Kafka
	s.logUserSecurityEvent(ctx, req, "user_risk_assessment", riskAssessment.RiskScore, riskAssessment.Reasons)

	// Block if needed
	if riskAssessment.BlockAction {
		s.logger.Warn("🚨 Blocking user OTP request due to high risk score",
			util.String("phone", req.PhoneNumber),
			util.String("ip", req.IPAddress),
			util.Int("risk_score", riskAssessment.RiskScore),
			util.String("risk_level", riskAssessment.RiskLevel),
			util.String("purpose", req.Purpose),
			util.String("user_agent", req.UserAgent),
		)

		return &UserOTPResponse{
			Success: false,
			Message: "Security check failed",
		}
	}

	s.logger.Info("✅ User OTP security checks passed",
		util.String("phone", req.PhoneNumber),
		util.Int("risk_score", riskAssessment.RiskScore),
		util.String("user_agent", req.UserAgent))

	return nil
}

func (s *UserOTPService) logUserSecurityEvent(ctx context.Context, req *UserOTPSendRequest, eventType string, riskScore int, reasons []string) {
	if s.logProducer != nil {
		actionTaken := "allowed"
		if riskScore >= 70 {
			actionTaken = "blocked"
		} else if riskScore >= 40 {
			actionTaken = "monitored"
		}

		securityEvent := &models.SecurityEvent{
			LogEnvelope: models.LogEnvelope{
				EventID:     uuid.New().String(),
				EventType:   "user_security_risk",
				ServiceName: "auth-service",
				Timestamp:   time.Now(),
				Environment: s.config.Environment,
				Version:     UserServiceVersion,
				Level:       string(models.LogLevelWarning),
				Message:     fmt.Sprintf("User security check: %s", eventType),
			},
			PhoneNumber: req.PhoneNumber,
			IPAddress:   req.IPAddress,
			DeviceID:    req.DeviceID,
			UserAgent:   req.UserAgent,
			RiskScore:   riskScore,
			EventType:   eventType,
			Reasons:     reasons,
			ActionTaken: actionTaken,
		}
		_ = s.logProducer.ProduceSecurityRiskEvent(ctx, securityEvent)
	}
}

func (s *UserOTPService) logUserOTPEvent(ctx context.Context, event *models.OTPLogEvent) {
	if s.logProducer != nil {
		_ = s.logProducer.ProduceOTPEvent(ctx, event)
	}
}

// func (s *UserOTPService) checkUserDailyQuotas(ctx context.Context, phoneHash, ipAddress, deviceID, purpose string) (*UserOTPResponse, error) {
// 	// Check phone daily quota
// 	phoneQuotaKey := fmt.Sprintf("user_otp:quota:daily:phone:%s", phoneHash)
// 	phoneUsed, err := s.distCache.IncrementDailyQuota(ctx, phoneQuotaKey, 24*time.Hour)
// 	if err != nil {
// 		return nil, err
// 	}

// 	phoneLimit := s.getDailyQuotaLimit(purpose)
// 	if phoneUsed > int64(phoneLimit) {
// 		s.logUserOTPEvent(ctx, &models.OTPLogEvent{
// 			LogEnvelope: models.LogEnvelope{
// 				EventID:     uuid.New().String(),
// 				EventType:   string(models.LogEventTypeOTP),
// 				ServiceName: "auth-service",
// 				Timestamp:   time.Now(),
// 				Environment: s.config.Environment,
// 				Version:     UserServiceVersion,
// 				Level:       string(models.LogLevelWarning),
// 				Message:     "User daily phone quota exceeded",
// 			},
// 			PhoneNumber: "",
// 			Status:      "quota_exceeded",
// 			Purpose:     purpose,
// 			ErrorCode:   "DAILY_QUOTA_EXCEEDED",
// 			UserAgent:   "",
// 		})
// 		return &UserOTPResponse{
// 			Success:    false,
// 			Message:    "Daily OTP limit exceeded",
// 			RetryAfter: 86400,
// 		}, ErrUserDailyQuotaExceeded
// 	}

// 	// Check IP daily quota
// 	if ipAddress != "" {
// 		ipQuotaKey := fmt.Sprintf("user_otp:quota:daily:ip:%s", ipAddress)
// 		ipUsed, err := s.distCache.IncrementDailyQuota(ctx, ipQuotaKey, 24*time.Hour)
// 		if err != nil {
// 			return nil, err
// 		}

// 		if ipUsed > int64(UserDailyQuotaPerIP) {
// 			s.logUserOTPEvent(ctx, &models.OTPLogEvent{
// 				LogEnvelope: models.LogEnvelope{
// 					EventID:     uuid.New().String(),
// 					EventType:   string(models.LogEventTypeOTP),
// 					ServiceName: "auth-service",
// 					Timestamp:   time.Now(),
// 					Environment: s.config.Environment,
// 					Version:     UserServiceVersion,
// 					Level:       string(models.LogLevelWarning),
// 					Message:     "User daily IP quota exceeded",
// 				},
// 				IPAddress: ipAddress,
// 				Status:    "quota_exceeded",
// 				Purpose:   purpose,
// 				ErrorCode: "IP_QUOTA_EXCEEDED",
// 				UserAgent: "",
// 			})
// 			return &UserOTPResponse{
// 				Success:    false,
// 				Message:    "Daily OTP limit exceeded for this IP",
// 				RetryAfter: 86400,
// 			}, ErrUserDailyQuotaExceeded
// 		}
// 	}

// 	// Check device daily quota
// 	if deviceID != "" {
// 		deviceQuotaKey := fmt.Sprintf("user_otp:quota:daily:device:%s", deviceID)
// 		deviceUsed, err := s.distCache.IncrementDailyQuota(ctx, deviceQuotaKey, 24*time.Hour)
// 		if err != nil {
// 			return nil, err
// 		}

// 		if deviceUsed > int64(UserDailyQuotaPerDevice) {
// 			s.logUserOTPEvent(ctx, &models.OTPLogEvent{
// 				LogEnvelope: models.LogEnvelope{
// 					EventID:     uuid.New().String(),
// 					EventType:   string(models.LogEventTypeOTP),
// 					ServiceName: "auth-service",
// 					Timestamp:   time.Now(),
// 					Environment: s.config.Environment,
// 					Version:     UserServiceVersion,
// 					Level:       string(models.LogLevelWarning),
// 					Message:     "User daily device quota exceeded",
// 				},
// 				DeviceID:  deviceID,
// 				Status:    "quota_exceeded",
// 				Purpose:   purpose,
// 				ErrorCode: "DEVICE_QUOTA_EXCEEDED",
// 				UserAgent: "",
// 			})
// 			return &UserOTPResponse{
// 				Success:    false,
// 				Message:    "Daily OTP limit exceeded for this device",
// 				RetryAfter: 86400,
// 			}, ErrUserDailyQuotaExceeded
// 		}
// 	}

// 	return nil, nil
// }

func (s *UserOTPService) incrementUserDailyQuotas(ctx context.Context, phoneHash, ipAddress, deviceID string) {
	s.logger.Debug("User daily quotas incremented",
		util.String("phone_hash", phoneHash),
		util.String("ip", ipAddress),
		util.String("device", deviceID),
	)
}

// Quota limit getters
func (s *UserOTPService) getDailyQuotaLimit(purpose string) int {
	return UserDailyQuotaPerPhone
}

func (s *UserOTPService) getDailyIPQuota() int {
	return UserDailyQuotaPerIP
}

func (s *UserOTPService) getDailyDeviceQuota() int {
	return UserDailyQuotaPerDevice
}

// Account lockout methods for users
func (s *UserOTPService) incrementUserFailedAttempts(phoneHash string) {
	key := fmt.Sprintf("user_failed_attempts:%s", phoneHash)
	if s.distCache != nil {
		count, _ := s.distCache.IncrementCounter(context.Background(), key, 1*time.Hour)
		if count >= AccountLockoutThreshold {
			s.lockUserAccount(phoneHash)
		}
	}
}

func (s *UserOTPService) clearUserFailedAttempts(phoneHash string) {
	key := fmt.Sprintf("user_failed_attempts:%s", phoneHash)
	if s.distCache != nil {
		_ = s.distCache.DeleteKey(context.Background(), key)
	}
}

func (s *UserOTPService) lockUserAccount(phoneHash string) {
	lockUntil := time.Now().Add(AccountLockoutDuration)
	s.lockoutCache.Add(phoneHash, lockUntil)

	if s.distCache != nil {
		key := fmt.Sprintf("user_lockout:%s", phoneHash)
		_ = s.distCache.SetWithExpiry(context.Background(), key, lockUntil.Unix(), AccountLockoutDuration)
	}

	s.logger.Warn("User account locked due to excessive failed attempts",
		util.String("phone_hash", phoneHash),
		util.String("lock_until", lockUntil.Format(time.RFC3339)),
	)
}

func (s *UserOTPService) isUserAccountLocked(phoneHash string) (bool, time.Time) {
	// Check local cache first
	if lockUntil, ok := s.lockoutCache.Get(phoneHash); ok {
		if time.Now().Before(lockUntil) {
			return true, lockUntil
		}
		s.lockoutCache.Remove(phoneHash)
	}

	// Check Redis
	if s.distCache != nil {
		key := fmt.Sprintf("user_lockout:%s", phoneHash)
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

// Validation methods for users
func (s *UserOTPService) validateUserSendRequest(req *UserOTPSendRequest) error {
	if req.PhoneNumber == "" {
		return fmt.Errorf("phone number is required")
	}
	if len(req.PhoneNumber) < 10 || len(req.PhoneNumber) > 15 {
		return fmt.Errorf("invalid phone number")
	}
	if req.Purpose == "" {
		return fmt.Errorf("purpose is required")
	}
	validPurposes := map[string]bool{
		"login":          true,
		"verification":   true,
		"password_reset": true,
		"forgot_mpin":    true,
	}
	if !validPurposes[req.Purpose] {
		return fmt.Errorf("invalid purpose")
	}
	return nil
}

func (s *UserOTPService) validateUserVerifyRequest(req *UserOTPVerifyRequest) error {
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
	validPurposes := map[string]bool{
		"login":          true,
		"verification":   true,
		"password_reset": true,
		"forgot_mpin":    true,
	}
	if !validPurposes[req.Purpose] {
		return fmt.Errorf("invalid purpose")
	}
	return nil
}

func (s *UserOTPService) generatePhoneHash(phoneNumber string) string {
	normalized := strings.ReplaceAll(phoneNumber, " ", "")
	normalized = strings.ReplaceAll(normalized, "-", "")
	normalized = strings.ReplaceAll(normalized, "(", "")
	normalized = strings.ReplaceAll(normalized, ")", "")

	hash := sha256.Sum256([]byte(normalized))
	return hex.EncodeToString(hash[:])
}

// Device trust methods for users
func (s *UserOTPService) isUserNewDevice(deviceID, phoneNumber string) bool {
	if deviceID == "" {
		return true
	}

	ctx := context.Background()

	// Resolve userID from phone number
	userID, err := s.phoneValidator.GetUserIDByPhone(ctx, phoneNumber)
	if err != nil || userID == uuid.Nil {
		return true
	}

	// Fetch device trust record
	rec, err := s.deviceTrustRepo.GetDeviceTrustLevel(ctx, userID, deviceID)
	if err != nil {
		return true
	}

	// No record = device never seen → NEW device
	if rec == nil {
		return true
	}

	// Device ID mismatch
	if rec.DeviceID != deviceID {
		return true
	}

	// Blocked or untrusted device → treat as NEW
	if rec.IsBlocked || rec.TrustStatus == models.TrustStatusUntrusted {
		return true
	}

	// Otherwise → known device
	return false
}

func (s *UserOTPService) isUserNewIP(ipAddress, phoneNumber, deviceID string) bool {
	if ipAddress == "" {
		return true
	}

	ctx := context.Background()

	// Get userID from phone
	userID, err := s.phoneValidator.GetUserIDByPhone(ctx, phoneNumber)
	if err != nil || userID == uuid.Nil {
		return true
	}

	// If deviceID exists → use exact trust record for this device
	if deviceID != "" {
		rec, err := s.deviceTrustRepo.GetDeviceTrustLevel(ctx, userID, deviceID)
		if err == nil && rec != nil {
			// If stored IP matches → NOT NEW
			if rec.LastIPAddress == ipAddress {
				return false
			}
			// Device exists but new IP → NEW IP
			return true
		}
	}

	// Fallback: scan all trusted devices for this user
	recs, err := s.deviceTrustRepo.GetUserDevices(ctx, userID)
	if err != nil {
		return true
	}

	for _, rec := range recs {
		if rec.LastIPAddress == ipAddress {
			return false
		}
	}

	// Never seen this IP before → NEW
	return true
}

func (s *UserOTPService) getUserFailedAttemptsCount(phoneNumber string) int {
	phoneHash := s.generatePhoneHash(phoneNumber)
	key := fmt.Sprintf("user_failed_attempts:%s", phoneHash)

	if s.distCache != nil {
		count, err := s.distCache.GetCounter(context.Background(), key)
		if err == nil {
			return int(count)
		}
	}
	return 0
}

func (s *UserOTPService) getUserDailyOTPCount(phoneNumber string) int {
	phoneHash := s.generatePhoneHash(phoneNumber)
	key := fmt.Sprintf("user_otp:quota:daily:phone:%s", phoneHash)

	if s.distCache != nil {
		count, err := s.distCache.GetDailyQuotaUsage(context.Background(), key)
		if err == nil {
			return int(count)
		}
	}
	return 0
}

// HealthCheck and other common methods
func (s *UserOTPService) HealthCheck(ctx context.Context) error {
	return s.otpRepo.HealthCheck(ctx)
}

func (s *UserOTPService) GetUserOTPStats(ctx context.Context) (map[string]interface{}, error) {
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
			"user": map[string]interface{}{
				"send_limit_1min":  UserOTPSendLimit1Min,
				"send_limit_5min":  UserOTPSendLimit5Min,
				"send_limit_hour":  UserOTPSendLimitHour,
				"verify_limit_30s": UserOTPVerifyLimit30Sec,
				"verify_limit_min": UserOTPVerifyLimitMin,
			},
		},
		"lockout": map[string]interface{}{
			"threshold_attempts": AccountLockoutThreshold,
			"duration_minutes":   int(AccountLockoutDuration.Minutes()),
		},
		"timestamp": time.Now().UTC(),
	}

	return stats, nil
}

func (s *UserOTPService) Cleanup() {
	s.sendRateCache.Purge()
	s.verifyRateCache.Purge()
	s.lockoutCache.Purge()
}

func (s *UserOTPService) CleanupExpiredOTPs(ctx context.Context, batchSize int) (int, error) {
	s.logger.Info("User OTP cleanup skipped - TTL handles expiry automatically")
	return 0, nil
}

func (s *UserOTPService) SetLogProducerService(logProducer *LogProducerService) {
	s.logProducer = logProducer
}
// UserSendOTP sends OTP for users
func (s *UserOTPService) UserSendOTP(ctx context.Context, req *UserOTPSendRequest) (*UserOTPResponse, error) {
	startTime := time.Now()

	// Check if phone number is registered for user
	isRegistered, err := s.isUserPhoneRegistered(ctx, req.PhoneNumber, req.Purpose)
	if err != nil {
		s.logUserOTPEvent(ctx, &models.OTPLogEvent{
			LogEnvelope: models.LogEnvelope{
				EventID:     uuid.New().String(),
				EventType:   string(models.LogEventTypeOTP),
				ServiceName: "auth-service",
				Timestamp:   time.Now(),
				Environment: s.config.Environment,
				Version:     UserServiceVersion,
				Level:       string(models.LogLevelError),
				Message:     "User phone registration check failed",
			},
			PhoneNumber:   req.PhoneNumber,
			Status:        "send_failed",
			Purpose:       req.Purpose,
			IPAddress:     req.IPAddress,
			UserAgent:     req.UserAgent,
			ErrorCode:     "USER_PHONE_CHECK_FAILED",
			ErrorMessage:  err.Error(),
			AttemptNumber: 0,
		})
		return nil, fmt.Errorf("failed to check user phone registration: %w", err)
	}

	if !isRegistered {
		s.logUserOTPEvent(ctx, &models.OTPLogEvent{
			LogEnvelope: models.LogEnvelope{
				EventID:     uuid.New().String(),
				EventType:   string(models.LogEventTypeOTP),
				ServiceName: "auth-service",
				Timestamp:   time.Now(),
				Environment: s.config.Environment,
				Version:     UserServiceVersion,
				Level:       string(models.LogLevelWarning),
				Message:     "User phone number not registered",
			},
			PhoneNumber:   req.PhoneNumber,
			Status:        "send_failed",
			Purpose:       req.Purpose,
			IPAddress:     req.IPAddress,
			UserAgent:     req.UserAgent,
			ErrorCode:     "USER_PHONE_NOT_REGISTERED",
			ErrorMessage:  "Phone number is not registered in the user system",
			AttemptNumber: 0,
		})
		return &UserOTPResponse{
			Success: false,
			Message: "Phone number not registered",
		}, ErrUserPhoneNotRegistered
	}

	// Security checks
	securityResult := s.performUserSecurityChecks(ctx, req, startTime)
	if securityResult != nil {
		return securityResult, ErrUserSecurityCheckFailed
	}

	// Log initiation
	s.logUserOTPEvent(ctx, &models.OTPLogEvent{
		LogEnvelope: models.LogEnvelope{
			EventID:     uuid.New().String(),
			EventType:   string(models.LogEventTypeOTP),
			ServiceName: "auth-service",
			Timestamp:   time.Now(),
			Environment: s.config.Environment,
			Version:     UserServiceVersion,
			Level:       string(models.LogLevelInfo),
			Message:     "User OTP send initiated",
		},
		PhoneNumber: req.PhoneNumber,
		Status:      "send_initiated",
		Purpose:     req.Purpose,
		IPAddress:   req.IPAddress,
		UserAgent:   req.UserAgent,
	})

	// Validate input
	if err := s.validateUserSendRequest(req); err != nil {
		s.logUserOTPEvent(ctx, &models.OTPLogEvent{
			LogEnvelope: models.LogEnvelope{
				EventID:     uuid.New().String(),
				EventType:   string(models.LogEventTypeOTP),
				ServiceName: "auth-service",
				Timestamp:   time.Now(),
				Environment: s.config.Environment,
				Version:     UserServiceVersion,
				Level:       string(models.LogLevelError),
				Message:     "User OTP send validation failed",
			},
			PhoneNumber:   req.PhoneNumber,
			Status:        "send_failed",
			Purpose:       req.Purpose,
			IPAddress:     req.IPAddress,
			UserAgent:     req.UserAgent,
			ErrorCode:     "VALIDATION_FAILED",
			ErrorMessage:  err.Error(),
			AttemptNumber: 0,
		})
		return nil, fmt.Errorf("%w: %v", ErrInvalidInput, err)
	}

	phoneHash := s.generatePhoneHash(req.PhoneNumber)

	// Check daily quotas - return proper format
	quotaCheck, err := s.checkUserDailyQuotas(ctx, phoneHash, req.IPAddress, req.DeviceID, req.Purpose)
	if err != nil {
		return quotaCheck, err
	}

	// 🔥 FIX: Cooldown check - uses increasing cooldown like admin service
	deviceKey := req.DeviceID
	if deviceKey == "" {
		deviceKey = "nodevice"
	}
	cooldownKey := fmt.Sprintf("user_otp:cooldown:%s:%s:%s", phoneHash, req.Purpose, deviceKey)
	allowed, retryAfter := s.distCache.AllowRateWithIncreasingCooldown(
		ctx, cooldownKey, UserOTPResendCooldownInitial, UserOTPResendCooldownMax)
	
	if !allowed {
		s.logUserOTPEvent(ctx, &models.OTPLogEvent{
			LogEnvelope: models.LogEnvelope{
				EventID:     uuid.New().String(),
				EventType:   string(models.LogEventTypeOTP),
				ServiceName: "auth-service",
				Timestamp:   time.Now(),
				Environment: s.config.Environment,
				Version:     UserServiceVersion,
				Level:       string(models.LogLevelWarning),
				Message:     "User OTP send cooldown active",
			},
			PhoneNumber:   req.PhoneNumber,
			Status:        "send_cooldown",
			Purpose:       req.Purpose,
			IPAddress:     req.IPAddress,
			UserAgent:     req.UserAgent,
			ErrorCode:     "COOLDOWN_ACTIVE",
			AttemptNumber: 0,
			AttemptsLeft:  retryAfter,
		})
		
		// 🔥 FIX: Return the exact same response format as admin service
		return &UserOTPResponse{
			Success:    false,
			Message:    "Please wait before requesting a new OTP",
			ExpiresAt:  time.Time{}, // 0001-01-01T00:00:00Z in JSON
			RetryAfter: retryAfter,
		}, ErrUserOTPRateLimitExceeded
	}

	// Device/IP rate limit
	if s.distCache != nil && req.DeviceID != "" {
		key := fmt.Sprintf("user_otp:rate:send:device:%s", req.DeviceID)
		if allowed, retry := s.distCache.AllowRate(ctx, key, 5, time.Minute); !allowed {
			// 🔥 FIX: Return same format as admin
			return &UserOTPResponse{
				Success:    false,
				Message:    "Too many OTP requests from this device",
				ExpiresAt:  time.Time{},
				RetryAfter: retry,
			}, ErrUserOTPRateLimitExceeded
		}
	}

	if s.distCache != nil && req.IPAddress != "" {
		key := fmt.Sprintf("user_otp:rate:send:ip:%s", req.IPAddress)
		if allowed, retry := s.distCache.AllowRate(ctx, key, 20, time.Minute); !allowed {
			// 🔥 FIX: Return same format as admin
			return &UserOTPResponse{
				Success:    false,
				Message:    "Too many OTP requests from this IP",
				ExpiresAt:  time.Time{},
				RetryAfter: retry,
			}, ErrUserOTPRateLimitExceeded
		}
	}

	// Account lockout
	if locked, until := s.isUserAccountLocked(phoneHash); locked {
		retry := int(time.Until(until).Seconds())
		// 🔥 FIX: Return same format as admin
		return &UserOTPResponse{
			Success:    false,
			Message:    "Account temporarily locked due to excessive attempts",
			ExpiresAt:  time.Time{},
			RetryAfter: retry,
		}, ErrUserOTPRateLimitExceeded
	}

	// Purpose-based rate limits using token bucket
	rateKey := fmt.Sprintf("user:%s:%s", phoneHash, req.Purpose)
	if !s.checkSendRateLimit(rateKey, req.Purpose) {
		retryAfter := s.timeUntilSendToken(rateKey, req.Purpose)
		// 🔥 FIX: Return same format as admin
		return &UserOTPResponse{
			Success:    false,
			Message:    "Too many OTP requests. Try again later.",
			ExpiresAt:  time.Time{},
			RetryAfter: retryAfter,
		}, ErrUserOTPRateLimitExceeded
	}

	// Invalidate any existing OTP
	existingOTP, err := s.otpRepo.GetActiveOTP(ctx, phoneHash, req.Purpose)
	if err == nil && existingOTP != nil {
		// Invalidate the existing OTP
		if err := s.otpRepo.InvalidateOTP(ctx, phoneHash, req.Purpose); err != nil {
			s.logger.Warn("Failed to invalidate existing user OTP",
				util.ErrorField(err),
				util.String("phone_hash", phoneHash),
				util.String("purpose", req.Purpose))
		}

		// Remove from cache
		if s.distCache != nil {
			cacheKey := fmt.Sprintf("user_otp:%s:%s", phoneHash, req.Purpose)
			_ = s.distCache.DeleteOTPVerification(ctx, cacheKey)
		}

		s.logger.Info("Invalidated existing user OTP for new send",
			util.String("phone", req.PhoneNumber),
			util.String("purpose", req.Purpose))
	}

	// Generate OTP
	otp, err := scylla.GenerateOTP(6)
	if err != nil {
		return nil, fmt.Errorf("failed to generate user OTP: %w", err)
	}

	// LOG OTP CODE - Always log for testing
	s.logger.Info("USER OTP GENERATED",
		util.String("otp_code", otp),
		util.String("phone", req.PhoneNumber),
		util.String("purpose", req.Purpose),
		util.String("device_id", req.DeviceID))

	salt, err := scylla.GenerateSalt()
	if err != nil {
		return nil, fmt.Errorf("failed to generate salt: %w", err)
	}

	otpHash := scylla.HashOTP(otp, salt)

	// Create OTP record
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
		IPAddress:     net.ParseIP(req.IPAddress),
		ProviderUsed:  req.Provider,
		DeviceID:      req.DeviceID,
	}

	// Save OTP in DB
	if err := s.otpRepo.CreateOTP(ctx, otpVerification); err != nil {
		return nil, fmt.Errorf("failed to create user OTP: %w", err)
	}

	// Cache OTP
	if s.distCache != nil {
		go func() {
			cacheKey := fmt.Sprintf("user_otp:%s:%s", phoneHash, req.Purpose)
			_ = s.distCache.SetOTPVerification(
				context.Background(),
				cacheKey,
				otpVerification,
				OTPCacheDuration,
			)
		}()
	}

	// Send OTP via SMSManager
	smsReq := sms.SMSRequest{
		PhoneNumber:       req.PhoneNumber,
		OTP:               otp,
		PreferredProvider: req.Provider,
		Purpose:           req.Purpose,
	}

	smsResp := s.smsManager.SendOTP(ctx, smsReq)
	if !smsResp.Success {
		return nil, fmt.Errorf("all SMS providers failed to send user OTP")
	}

	// Update quota usage
	s.incrementUserDailyQuotas(ctx, phoneHash, req.IPAddress, req.DeviceID)

	// Final response
	resp := &UserOTPResponse{
		Success:      true,
		Message:      "OTP sent successfully",
		ExpiresAt:    expiresAt,
		AttemptsLeft: scylla.OTPMaxAttempts,
		DailyQuota:   s.getDailyQuotaLimit(req.Purpose),
	}

	// Always return OTP in development for testing
	resp.OTPValue = otp

	// Log successful send
	s.logUserOTPEvent(ctx, &models.OTPLogEvent{
		LogEnvelope: models.LogEnvelope{
			EventID:     uuid.New().String(),
			EventType:   string(models.LogEventTypeOTP),
			ServiceName: "auth-service",
			Timestamp:   time.Now(),
			Environment: s.config.Environment,
			Version:     UserServiceVersion,
			Level:       string(models.LogLevelInfo),
			Message:     "User OTP sent successfully",
		},
		PhoneNumber:   req.PhoneNumber,
		Status:        "sent",
		Purpose:       req.Purpose,
		IPAddress:     req.IPAddress,
		UserAgent:     req.UserAgent,
		AttemptNumber: 0,
		Duration:      int64(time.Since(startTime).Milliseconds()),
	})

	return resp, nil
}

func (s *UserOTPService) checkUserDailyQuotas(ctx context.Context, phoneHash, ipAddress, deviceID, purpose string) (*UserOTPResponse, error) {
	// Check phone daily quota
	phoneQuotaKey := fmt.Sprintf("user_otp:quota:daily:phone:%s", phoneHash)
	phoneUsed, err := s.distCache.IncrementDailyQuota(ctx, phoneQuotaKey, 24*time.Hour)
	if err != nil {
		return nil, err
	}

	phoneLimit := s.getDailyQuotaLimit(purpose)
	if phoneUsed > int64(phoneLimit) {
		s.logUserOTPEvent(ctx, &models.OTPLogEvent{
			LogEnvelope: models.LogEnvelope{
				EventID:     uuid.New().String(),
				EventType:   string(models.LogEventTypeOTP),
				ServiceName: "auth-service",
				Timestamp:   time.Now(),
				Environment: s.config.Environment,
				Version:     UserServiceVersion,
				Level:       string(models.LogLevelWarning),
				Message:     "User daily phone quota exceeded",
			},
			PhoneNumber: "",
			Status:      "quota_exceeded",
			Purpose:     purpose,
			ErrorCode:   "DAILY_QUOTA_EXCEEDED",
			UserAgent:   "",
		})
		
		// 🔥 FIX: Return same format as admin with ExpiresAt
		return &UserOTPResponse{
			Success:    false,
			Message:    "Daily OTP limit exceeded",
			ExpiresAt:  time.Time{},
			RetryAfter: 86400, // 24 hours in seconds
		}, ErrUserDailyQuotaExceeded
	}

	// Check IP daily quota
	if ipAddress != "" {
		ipQuotaKey := fmt.Sprintf("user_otp:quota:daily:ip:%s", ipAddress)
		ipUsed, err := s.distCache.IncrementDailyQuota(ctx, ipQuotaKey, 24*time.Hour)
		if err != nil {
			return nil, err
		}

		if ipUsed > int64(UserDailyQuotaPerIP) {
			s.logUserOTPEvent(ctx, &models.OTPLogEvent{
				LogEnvelope: models.LogEnvelope{
					EventID:     uuid.New().String(),
					EventType:   string(models.LogEventTypeOTP),
					ServiceName: "auth-service",
					Timestamp:   time.Now(),
					Environment: s.config.Environment,
					Version:     UserServiceVersion,
					Level:       string(models.LogLevelWarning),
					Message:     "User daily IP quota exceeded",
				},
				IPAddress: ipAddress,
				Status:    "quota_exceeded",
				Purpose:   purpose,
				ErrorCode: "IP_QUOTA_EXCEEDED",
				UserAgent: "",
			})
			
			// 🔥 FIX: Return same format as admin with ExpiresAt
			return &UserOTPResponse{
				Success:    false,
				Message:    "Daily OTP limit exceeded for this IP",
				ExpiresAt:  time.Time{},
				RetryAfter: 86400,
			}, ErrUserDailyQuotaExceeded
		}
	}

	// Check device daily quota
	if deviceID != "" {
		deviceQuotaKey := fmt.Sprintf("user_otp:quota:daily:device:%s", deviceID)
		deviceUsed, err := s.distCache.IncrementDailyQuota(ctx, deviceQuotaKey, 24*time.Hour)
		if err != nil {
			return nil, err
		}

		if deviceUsed > int64(UserDailyQuotaPerDevice) {
			s.logUserOTPEvent(ctx, &models.OTPLogEvent{
				LogEnvelope: models.LogEnvelope{
					EventID:     uuid.New().String(),
					EventType:   string(models.LogEventTypeOTP),
					ServiceName: "auth-service",
					Timestamp:   time.Now(),
					Environment: s.config.Environment,
					Version:     UserServiceVersion,
					Level:       string(models.LogLevelWarning),
					Message:     "User daily device quota exceeded",
				},
				DeviceID:  deviceID,
				Status:    "quota_exceeded",
				Purpose:   purpose,
				ErrorCode: "DEVICE_QUOTA_EXCEEDED",
				UserAgent: "",
			})
			
			// 🔥 FIX: Return same format as admin with ExpiresAt
			return &UserOTPResponse{
				Success:    false,
				Message:    "Daily OTP limit exceeded for this device",
				ExpiresAt:  time.Time{},
				RetryAfter: 86400,
			}, ErrUserDailyQuotaExceeded
		}
	}

	return nil, nil
}
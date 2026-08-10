package service

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"math"
	"net"
	"strings"
	"sync"
	"time"

	"github.com/google/uuid"
	lru "github.com/hashicorp/golang-lru/v2"
	"go.uber.org/zap"

	"auth-service/internal/config"
	appErrors "auth-service/internal/errors"
	"auth-service/internal/hashing"
	"auth-service/internal/infrastructure/audit"
	"auth-service/internal/infrastructure/idempotency"
	"auth-service/internal/models"
	"auth-service/internal/repository/scylla"
	"auth-service/internal/service/security"
	"auth-service/internal/sms"
)

// PhoneValidator is imported from phone_validator.go – DO NOT redeclare.

const (
	UserOTPSendLimit1Min         = 3
	UserOTPSendLimit5Min         = 5
	UserOTPSendLimitHour         = 15
	UserOTPSendLimitDay          = 30
	UserOTPVerifyLimit30Sec      = 5
	UserOTPVerifyLimitMin        = 10
	UserOTPResendCooldownInitial = 60 * time.Second
	UserOTPResendCooldownMax     = 300 * time.Second
	UserDailyQuotaPerPhone       = 15
	UserDailyQuotaPerIP          = 100
	UserDailyQuotaPerDevice      = 25
	UserServiceVersion           = "1.0.0"
)

// UserOTPService handles OTP operations for users (not admins)
type UserOTPService struct {
	otpRepo          scylla.OTPRepository
	hasher           *hashing.Hasher
	config           *config.Config
	distCache        *DistributedCache
	logProducer      *LogProducerService
	smsManager       *sms.SMSManager
	sendRateCache    *lru.Cache[string, *UserTokenBucket]
	verifyRateCache  *lru.Cache[string, *UserTokenBucket]
	lockoutCache     *lru.Cache[string, time.Time]
	phoneValidator   PhoneValidator
	deviceTrustRepo  scylla.DeviceTrustRepository
	deviceService    *DeviceService // <-- injected to handle trust + binding
	botDetector      *security.BotDetector
	ipReputation     *security.IPReputation
	riskEngine       *security.RiskEngine
	auditService     *audit.AuditService
	idempotencyStore idempotency.Store
	mu               sync.RWMutex
}

// UserOTPSendRequest represents a request to send OTP to a user
type UserOTPSendRequest struct {
	PhoneNumber       string `json:"phone_number" validate:"required,min=10,max=15"`
	Purpose           string `json:"purpose" validate:"required,oneof=login verification password_reset forgot_mpin"`
	IPAddress         string `json:"ip_address"`
	DeviceID          string `json:"device_id"`
	Provider          string `json:"provider,omitempty"`
	UserAgent         string `json:"user_agent,omitempty"`
	DeviceFingerprint string `json:"device_fingerprint,omitempty"`
}

// UserOTPResponse is the response for OTP operations
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

// UserOTPVerifyRequest represents a request to verify OTP
type UserOTPVerifyRequest struct {
	PhoneNumber       string `json:"phone_number" validate:"required,min=10,max=15"`
	OTP               string `json:"otp" validate:"required,len=6,numeric"`
	Purpose           string `json:"purpose" validate:"required,oneof=login verification password_reset forgot_mpin"`
	IPAddress         string `json:"ip_address"`
	DeviceID          string `json:"device_id"`
	DeviceFingerprint string `json:"device_fingerprint"`
	UserAgent         string `json:"user_agent,omitempty"`
}

// UserTokenBucket is a simple token bucket for rate limiting
type UserTokenBucket struct {
	Tokens         float64
	MaxTokens      float64
	RefillRate     float64
	LastRefillTime time.Time
	mu             sync.Mutex
}

func NewUserTokenBucket(maxTokens, refillRate float64) *UserTokenBucket {
	return &UserTokenBucket{
		Tokens:         maxTokens,
		MaxTokens:      maxTokens,
		RefillRate:     refillRate,
		LastRefillTime: time.Now(),
	}
}

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

// NewUserOTPService creates a new UserOTPService with audit and idempotency
func NewUserOTPService(
	otpRepo scylla.OTPRepository,
	hasher *hashing.Hasher,
	cfg *config.Config,
	distCache *DistributedCache,
	logProducer *LogProducerService,
	phoneValidator PhoneValidator,
	deviceTrustRepo scylla.DeviceTrustRepository,
	deviceService *DeviceService, // <-- NEW parameter
	smsManager *sms.SMSManager,
	auditService *audit.AuditService,
	idempotencyStore idempotency.Store,
) *UserOTPService {
	sendCache, _ := lru.New[string, *UserTokenBucket](100_000)
	verifyCache, _ := lru.New[string, *UserTokenBucket](100_000)
	lockoutCache, _ := lru.New[string, time.Time](50_000)

	botDetector := security.NewBotDetector()
	ipReputation := security.NewIPReputation()
	riskEngine := security.NewRiskEngine(botDetector, ipReputation)

	return &UserOTPService{
		otpRepo:          otpRepo,
		hasher:           hasher,
		config:           cfg,
		distCache:        distCache,
		logProducer:      logProducer,
		smsManager:       smsManager,
		sendRateCache:    sendCache,
		verifyRateCache:  verifyCache,
		lockoutCache:     lockoutCache,
		phoneValidator:   phoneValidator,
		deviceTrustRepo:  deviceTrustRepo,
		deviceService:    deviceService, // <-- assign
		botDetector:      botDetector,
		ipReputation:     ipReputation,
		riskEngine:       riskEngine,
		auditService:     auditService,
		idempotencyStore: idempotencyStore,
	}
}

// ---- Rate limiting helpers ----

func (s *UserOTPService) getUserSendRateLimits(purpose string) (maxTokens, refillRate float64) {
	return 3, 1.0 / 60.0
}

func (s *UserOTPService) getUserVerifyRateLimits(purpose string) (maxTokens, refillRate float64) {
	return 5, 1.0 / 30.0
}

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

func (s *UserOTPService) checkSendRateLimit(key, purpose string) bool {
	bucket := s.getSendTokenBucket(key, purpose)
	return bucket.TakeToken()
}

func (s *UserOTPService) checkVerifyRateLimit(key, purpose string) bool {
	bucket := s.getVerifyTokenBucket(key, purpose)
	return bucket.TakeToken()
}

func (s *UserOTPService) timeUntilSendToken(key, purpose string) int {
	bucket := s.getSendTokenBucket(key, purpose)
	return bucket.TimeUntilToken()
}

func (s *UserOTPService) timeUntilVerifyToken(key, purpose string) int {
	bucket := s.getVerifyTokenBucket(key, purpose)
	return bucket.TimeUntilToken()
}

// ---- Core OTP methods ----

// UserSendOTP sends an OTP to the user's phone
func (s *UserOTPService) UserSendOTP(ctx context.Context, req *UserOTPSendRequest) (*UserOTPResponse, error) {
	startTime := time.Now()

	// Idempotency: prevent duplicate sends for same phone+purpose within a short window
	idempKey, _ := ctx.Value("idempotency_key").(string)
	if idempKey == "" {
		idempKey = fmt.Sprintf("user_send_otp:%s:%s", req.PhoneNumber, req.Purpose)
	}
	var cached *UserOTPResponse
	if err := s.idempotencyStore.Get(ctx, nil, idempKey, &cached); err == nil && cached != nil && cached.Success {
		return cached, nil
	}
	ip, _ := ctx.Value("ip_address").(string)
	if ip == "" {
		ip = req.IPAddress
	}

	// Validate request
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
			PhoneNumber:  req.PhoneNumber,
			Status:       "send_failed",
			Purpose:      req.Purpose,
			IPAddress:    ip,
			UserAgent:    req.UserAgent,
			ErrorCode:    "VALIDATION_FAILED",
			ErrorMessage: err.Error(),
		})
		return nil, fmt.Errorf("%w: %v", appErrors.ErrInvalidInput, err)
	}

	// Check if phone is registered
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
			PhoneNumber:  req.PhoneNumber,
			Status:       "send_failed",
			Purpose:      req.Purpose,
			IPAddress:    ip,
			UserAgent:    req.UserAgent,
			ErrorCode:    "USER_PHONE_CHECK_FAILED",
			ErrorMessage: err.Error(),
		})
		return nil, fmt.Errorf("%w: failed to check registration", appErrors.ErrInternal)
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
			PhoneNumber:  req.PhoneNumber,
			Status:       "send_failed",
			Purpose:      req.Purpose,
			IPAddress:    ip,
			UserAgent:    req.UserAgent,
			ErrorCode:    "USER_PHONE_NOT_REGISTERED",
			ErrorMessage: "Phone number is not registered",
		})
		return &UserOTPResponse{
			Success: false,
			Message: "Phone number not registered",
		}, appErrors.ErrPhoneNotRegistered
	}

	// Security checks (risk engine)
	securityResult := s.performUserSecurityChecks(ctx, req, startTime)
	if securityResult != nil {
		if s.auditService != nil {
			_ = s.auditService.LogAction(ctx, nil, nil, "user_otp", "send", "user",
				nil, "system", nil, nil, nil, map[string]interface{}{
					"phone":     req.PhoneNumber,
					"purpose":   req.Purpose,
					"ip":        ip,
					"device_id": req.DeviceID,
					"status":    "blocked_by_security",
				})
		}
		return securityResult, appErrors.ErrSecurityCheckFailed
	}

	phoneHash := s.generatePhoneHash(req.PhoneNumber)

	// Check daily quotas
	quotaResp, err := s.checkUserDailyQuotas(ctx, phoneHash, req.IPAddress, req.DeviceID, req.Purpose)
	if err != nil {
		return quotaResp, err
	}

	// Cooldown / resend interval
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
			PhoneNumber:  req.PhoneNumber,
			Status:       "send_cooldown",
			Purpose:      req.Purpose,
			IPAddress:    ip,
			UserAgent:    req.UserAgent,
			ErrorCode:    "COOLDOWN_ACTIVE",
			AttemptsLeft: retryAfter,
		})
		return &UserOTPResponse{
			Success:    false,
			Message:    "Please wait before requesting a new OTP",
			RetryAfter: retryAfter,
		}, appErrors.ErrOTPRateLimitExceeded
	}

	// Device‑specific rate limiting
	if s.distCache != nil && req.DeviceID != "" {
		key := fmt.Sprintf("user_otp:rate:send:device:%s", req.DeviceID)
		if allowed, retry := s.distCache.AllowRate(ctx, key, 5, time.Minute); !allowed {
			return &UserOTPResponse{
				Success:    false,
				Message:    "Too many OTP requests from this device",
				RetryAfter: retry,
			}, appErrors.ErrOTPRateLimitExceeded
		}
	}
	// IP‑specific rate limiting
	if s.distCache != nil && req.IPAddress != "" {
		key := fmt.Sprintf("user_otp:rate:send:ip:%s", req.IPAddress)
		if allowed, retry := s.distCache.AllowRate(ctx, key, 20, time.Minute); !allowed {
			return &UserOTPResponse{
				Success:    false,
				Message:    "Too many OTP requests from this IP",
				RetryAfter: retry,
			}, appErrors.ErrOTPRateLimitExceeded
		}
	}

	// Account lockout check
	if locked, until := s.isUserAccountLocked(phoneHash); locked {
		retry := int(time.Until(until).Seconds())
		return &UserOTPResponse{
			Success:    false,
			Message:    "Account temporarily locked due to excessive attempts",
			RetryAfter: retry,
		}, appErrors.ErrOTPRateLimitExceeded
	}

	// Send‑rate token bucket
	rateKey := fmt.Sprintf("user:%s:%s", phoneHash, req.Purpose)
	if !s.checkSendRateLimit(rateKey, req.Purpose) {
		retryAfter := s.timeUntilSendToken(rateKey, req.Purpose)
		return &UserOTPResponse{
			Success:    false,
			Message:    "Too many OTP requests. Try again later.",
			RetryAfter: retryAfter,
		}, appErrors.ErrOTPRateLimitExceeded
	}

	// Invalidate any existing OTP for same purpose
	existingOTP, err := s.otpRepo.GetActiveOTP(ctx, phoneHash, req.Purpose)
	if err == nil && existingOTP != nil {
		_ = s.otpRepo.InvalidateOTP(ctx, phoneHash, req.Purpose)
		if s.distCache != nil {
			cacheKey := fmt.Sprintf("user_otp:%s:%s", phoneHash, req.Purpose)
			_ = s.distCache.DeleteOTPVerification(ctx, cacheKey)
		}
	}

	// Generate new OTP
	otp, err := scylla.GenerateOTP(6)
	if err != nil {
		return nil, fmt.Errorf("%w: failed to generate OTP", appErrors.ErrInternal)
	}

	// ========== ZAP LOGGING (for testing) ==========
	if s.config.Environment != "production" {
		logger, _ := zap.NewDevelopment()
		defer logger.Sync()
		logger.Debug("OTP generated for testing",
			zap.String("phone_number", req.PhoneNumber),
			zap.String("purpose", req.Purpose),
			zap.String("otp_value", otp),
		)
	}
	// ===============================================

	salt, err := scylla.GenerateSalt()
	if err != nil {
		return nil, fmt.Errorf("%w: failed to generate salt", appErrors.ErrInternal)
	}
	otpHash := scylla.HashOTP(otp, salt)
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
		IPAddress:     net.ParseIP(ip),
		ProviderUsed:  req.Provider,
		DeviceID:      req.DeviceID,
	}

	if err := s.otpRepo.CreateOTP(ctx, otpVerification); err != nil {
		return nil, fmt.Errorf("%w: failed to store OTP", appErrors.ErrInternal)
	}

	// Cache OTP
	if s.distCache != nil {
		go func() {
			cacheKey := fmt.Sprintf("user_otp:%s:%s", phoneHash, req.Purpose)
			_ = s.distCache.SetOTPVerification(context.Background(), cacheKey, otpVerification, OTPCacheDuration)
		}()
	}

	// Send SMS
	smsReq := sms.SMSRequest{
		PhoneNumber:       req.PhoneNumber,
		OTP:               otp,
		PreferredProvider: req.Provider,
		Purpose:           req.Purpose,
	}
	smsResp := s.smsManager.SendOTP(ctx, smsReq)
	if !smsResp.Success {
		return nil, fmt.Errorf("%w: all SMS providers failed", appErrors.ErrInternal)
	}

	// Increment daily quotas
	s.incrementUserDailyQuotas(ctx, phoneHash, req.IPAddress, req.DeviceID)

	resp := &UserOTPResponse{
		Success:      true,
		Message:      "OTP sent successfully",
		ExpiresAt:    expiresAt,
		AttemptsLeft: scylla.OTPMaxAttempts,
		DailyQuota:   s.getDailyQuotaLimit(req.Purpose),
		OTPValue:     otp, // only for debugging; remove in production
	}

	// Audit
	if s.auditService != nil {
		_ = s.auditService.LogAction(ctx, nil, nil, "user_otp", "send", "user",
			nil, "system", nil, nil, nil, map[string]interface{}{
				"phone":     req.PhoneNumber,
				"purpose":   req.Purpose,
				"ip":        ip,
				"device_id": req.DeviceID,
				"status":    "sent",
			})
	}

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
		PhoneNumber: req.PhoneNumber,
		Status:      "sent",
		Purpose:     req.Purpose,
		IPAddress:   ip,
		UserAgent:   req.UserAgent,
		Duration:    int64(time.Since(startTime).Milliseconds()),
	})

	// Store idempotency
	_ = s.idempotencyStore.Store(ctx, nil, idempKey, resp)
	return resp, nil
}

// UserVerifyOTP verifies the OTP provided by the user
func (s *UserOTPService) UserVerifyOTP(ctx context.Context, req *UserOTPVerifyRequest) (*UserOTPResponse, error) {
	startTime := time.Now()

	// Idempotency: prevent duplicate verification success (idempotent on success)
	idempKey, _ := ctx.Value("idempotency_key").(string)
	if idempKey == "" {
		idempKey = fmt.Sprintf("user_verify_otp:%s:%s", req.PhoneNumber, req.Purpose)
	}
	var cached *UserOTPResponse
	if err := s.idempotencyStore.Get(ctx, nil, idempKey, &cached); err == nil && cached != nil && cached.Success {
		return cached, nil
	}
	ip, _ := ctx.Value("ip_address").(string)
	if ip == "" {
		ip = req.IPAddress
	}

	// Validate request
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
			PhoneNumber:  req.PhoneNumber,
			Status:       "verification_failed",
			Purpose:      req.Purpose,
			IPAddress:    ip,
			UserAgent:    req.UserAgent,
			ErrorCode:    "VALIDATION_FAILED",
			ErrorMessage: err.Error(),
		})
		return nil, fmt.Errorf("%w: %v", appErrors.ErrInvalidInput, err)
	}

	phoneHash := s.generatePhoneHash(req.PhoneNumber)

	// Rate limit verification attempts
	verifyRateKey := fmt.Sprintf("user:verify:%s:%s", phoneHash, req.Purpose)
	if !s.checkVerifyRateLimit(verifyRateKey, req.Purpose) {
		retryAfter := s.timeUntilVerifyToken(verifyRateKey, req.Purpose)
		return &UserOTPResponse{
			Success:    false,
			Message:    "Too many verification attempts. Try again later.",
			RetryAfter: retryAfter,
		}, appErrors.ErrOTPRateLimitExceeded
	}

	// Device & IP verification rate limits
	if s.distCache != nil && req.DeviceID != "" {
		key := fmt.Sprintf("user_otp:rate:verify:device:%s", req.DeviceID)
		if allowed, retry := s.distCache.AllowRate(ctx, key, 10, time.Minute); !allowed {
			return &UserOTPResponse{
				Success:    false,
				Message:    "Too many verification attempts from this device",
				RetryAfter: retry,
			}, appErrors.ErrOTPRateLimitExceeded
		}
	}
	if s.distCache != nil && req.IPAddress != "" {
		key := fmt.Sprintf("user_otp:rate:verify:ip:%s", req.IPAddress)
		if allowed, retry := s.distCache.AllowRate(ctx, key, 30, time.Minute); !allowed {
			return &UserOTPResponse{
				Success:    false,
				Message:    "Too many verification attempts from this IP",
				RetryAfter: retry,
			}, appErrors.ErrOTPRateLimitExceeded
		}
	}

	// Account lockout check
	if locked, until := s.isUserAccountLocked(phoneHash); locked {
		retryAfter := int(time.Until(until).Seconds())
		return &UserOTPResponse{
			Success:    false,
			Message:    "Account temporarily locked",
			RetryAfter: retryAfter,
		}, appErrors.ErrOTPRateLimitExceeded
	}

	// Retrieve OTP record
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
				Message:     "User OTP not found",
			},
			PhoneNumber:  req.PhoneNumber,
			Status:       "verification_failed",
			Purpose:      req.Purpose,
			IPAddress:    ip,
			UserAgent:    req.UserAgent,
			ErrorCode:    "OTP_NOT_FOUND",
			ErrorMessage: "Invalid OTP or expired",
		})
		return &UserOTPResponse{
			Success: false,
			Message: "Invalid OTP or expired",
		}, appErrors.ErrOTPNotFound
	}

	// Device binding check
	if otpRecord.DeviceID != "" && req.DeviceID != otpRecord.DeviceID {
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
			IPAddress:     ip,
			UserAgent:     req.UserAgent,
			DeviceID:      req.DeviceID,
			ErrorCode:     "DEVICE_MISMATCH",
			AttemptNumber: otpRecord.Attempts,
		})
		return &UserOTPResponse{
			Success:      false,
			Message:      "Invalid OTP or expired",
			AttemptsLeft: scylla.OTPMaxAttempts - otpRecord.Attempts,
		}, appErrors.ErrOTPInvalid
	}

	// Expiration check
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
				Message:     "User OTP expired",
			},
			PhoneNumber:   req.PhoneNumber,
			Status:        "verification_failed",
			Purpose:       req.Purpose,
			IPAddress:     ip,
			UserAgent:     req.UserAgent,
			ErrorCode:     "OTP_EXPIRED",
			AttemptNumber: otpRecord.Attempts,
		})
		return &UserOTPResponse{
			Success:   false,
			Message:   "Invalid OTP or expired",
			ExpiresAt: otpRecord.ExpiresAt,
		}, appErrors.ErrOTPExpired
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
				Message:     "User OTP attempts exceeded",
			},
			PhoneNumber:   req.PhoneNumber,
			Status:        "verification_blocked",
			Purpose:       req.Purpose,
			IPAddress:     ip,
			UserAgent:     req.UserAgent,
			ErrorCode:     "ATTEMPTS_EXCEEDED",
			AttemptNumber: otpRecord.Attempts,
		})
		return &UserOTPResponse{
			Success:      false,
			Message:      "Invalid OTP or expired",
			AttemptsLeft: 0,
		}, appErrors.ErrOTPAttemptsExceeded
	}

	// Replay protection
	providedHash := scylla.HashOTP(req.OTP, otpRecord.OTPSalt)
	replayKey := fmt.Sprintf("user_otp:replay:%s:%s", phoneHash, providedHash)
	replayExists, _ := s.distCache.CheckOTPReplayProtection(ctx, replayKey)
	if replayExists {
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
			IPAddress:     ip,
			UserAgent:     req.UserAgent,
			ErrorCode:     "REPLAY_ATTEMPT",
			AttemptNumber: otpRecord.Attempts,
		})
		return &UserOTPResponse{
			Success:      false,
			Message:      "Invalid OTP or expired",
			AttemptsLeft: scylla.OTPMaxAttempts - otpRecord.Attempts,
		}, appErrors.ErrOTPReplayAttempt
	}

	// Validate OTP hash
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
			IPAddress:     ip,
			UserAgent:     req.UserAgent,
			ErrorCode:     "INVALID_OTP",
			AttemptNumber: validatedOTP.Attempts,
			AttemptsLeft:  attemptsLeft,
		})
		return &UserOTPResponse{
			Success:      false,
			Message:      "Invalid OTP or expired",
			AttemptsLeft: attemptsLeft,
			ExpiresAt:    otpRecord.ExpiresAt,
		}, appErrors.ErrOTPInvalid
	}

	// ---- CRITICAL: Set device trust AND bind device via DeviceService ----
	// This ensures the device is trusted for MPIN (device_trust_levels) and also bound (user_active_device).
	userID, err := s.phoneValidator.GetUserIDByPhone(ctx, req.PhoneNumber)
	if err == nil && userID != uuid.Nil && req.DeviceID != "" {
		if err := s.deviceService.MarkSuccessfulLogin(
			ctx,
			userID,
			req.DeviceID,
			req.IPAddress,
			req.UserAgent,
			req.DeviceFingerprint,
		); err != nil {
			s.logUserOTPEvent(ctx, &models.OTPLogEvent{
				LogEnvelope: models.LogEnvelope{
					EventID:     uuid.New().String(),
					EventType:   string(models.LogEventTypeOTP),
					ServiceName: "auth-service",
					Timestamp:   time.Now(),
					Environment: s.config.Environment,
					Version:     UserServiceVersion,
					Level:       string(models.LogLevelError),
					Message:     "Failed to mark successful login (trust/binding) after OTP verification",
				},
				PhoneNumber:   req.PhoneNumber,
				Status:        "trust_bind_failed",
				Purpose:       req.Purpose,
				IPAddress:     ip,
				UserAgent:     req.UserAgent,
				DeviceID:      req.DeviceID,
				ErrorCode:     "MARK_LOGIN_FAILED",
				ErrorMessage:  err.Error(),
				AttemptNumber: validatedOTP.Attempts,
			})
		} else {
			s.logUserOTPEvent(ctx, &models.OTPLogEvent{
				LogEnvelope: models.LogEnvelope{
					EventID:     uuid.New().String(),
					EventType:   string(models.LogEventTypeOTP),
					ServiceName: "auth-service",
					Timestamp:   time.Now(),
					Environment: s.config.Environment,
					Version:     UserServiceVersion,
					Level:       string(models.LogLevelInfo),
					Message:     "Device trust and binding set after successful OTP verification",
				},
				PhoneNumber: req.PhoneNumber,
				Status:      "trust_bind_success",
				Purpose:     req.Purpose,
				IPAddress:   ip,
				UserAgent:   req.UserAgent,
				DeviceID:    req.DeviceID,
			})
		}
	}
	// ---- end trust/binding ----

	// Invalidate OTP
	_ = s.otpRepo.InvalidateOTP(ctx, phoneHash, req.Purpose)
	if s.distCache != nil {
		cacheKey := fmt.Sprintf("user_otp:%s:%s", phoneHash, req.Purpose)
		_ = s.distCache.DeleteOTPVerification(ctx, cacheKey)
	}
	s.clearUserFailedAttempts(phoneHash)

	// Audit
	if s.auditService != nil {
		_ = s.auditService.LogAction(ctx, nil, nil, "user_otp", "verify", "user",
			nil, "system", nil, nil, nil, map[string]interface{}{
				"phone":     req.PhoneNumber,
				"purpose":   req.Purpose,
				"ip":        ip,
				"device_id": req.DeviceID,
				"status":    "verified",
			})
	}

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
		IPAddress:     ip,
		UserAgent:     req.UserAgent,
		AttemptNumber: validatedOTP.Attempts,
		Duration:      int64(time.Since(startTime).Milliseconds()),
	})

	resp := &UserOTPResponse{
		Success: true,
		Message: "OTP verified successfully",
	}
	_ = s.idempotencyStore.Store(ctx, nil, idempKey, resp)
	return resp, nil
}

// ---- Security checks ----

func (s *UserOTPService) performUserSecurityChecks(ctx context.Context, req *UserOTPSendRequest, startTime time.Time) *UserOTPResponse {
	requestLatency := time.Since(startTime)

	// Quick risk check
	quickRisk, shouldBlock := s.riskEngine.QuickRiskCheck(req.IPAddress, req.UserAgent, requestLatency, req.Purpose)
	if shouldBlock {
		s.logUserSecurityEvent(ctx, req, "user_quick_risk_check_failed", quickRisk, []string{"high_risk_quick_check"})
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
	s.logUserSecurityEvent(ctx, req, "user_risk_assessment", riskAssessment.RiskScore, riskAssessment.Reasons)

	if riskAssessment.BlockAction {
		return &UserOTPResponse{
			Success: false,
			Message: "Security check failed",
		}
	}
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

// ---- Quota & rate limit helpers ----

func (s *UserOTPService) incrementUserDailyQuotas(ctx context.Context, phoneHash, ipAddress, deviceID string) {
	// Already incremented in checkUserDailyQuotas; placeholder for additional logic.
}

func (s *UserOTPService) getDailyQuotaLimit(purpose string) int {
	return UserDailyQuotaPerPhone
}

func (s *UserOTPService) getDailyIPQuota() int {
	return UserDailyQuotaPerIP
}

func (s *UserOTPService) getDailyDeviceQuota() int {
	return UserDailyQuotaPerDevice
}

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
}

func (s *UserOTPService) isUserAccountLocked(phoneHash string) (bool, time.Time) {
	if lockUntil, ok := s.lockoutCache.Get(phoneHash); ok {
		if time.Now().Before(lockUntil) {
			return true, lockUntil
		}
		s.lockoutCache.Remove(phoneHash)
	}
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

func (s *UserOTPService) checkUserDailyQuotas(ctx context.Context, phoneHash, ipAddress, deviceID, purpose string) (*UserOTPResponse, error) {
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
			Status:    "quota_exceeded",
			Purpose:   purpose,
			ErrorCode: "DAILY_QUOTA_EXCEEDED",
		})
		return &UserOTPResponse{
			Success:    false,
			Message:    "Daily OTP limit exceeded",
			RetryAfter: 86400,
		}, appErrors.ErrDailyQuotaExceeded
	}
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
			})
			return &UserOTPResponse{
				Success:    false,
				Message:    "Daily OTP limit exceeded for this IP",
				RetryAfter: 86400,
			}, appErrors.ErrDailyQuotaExceeded
		}
	}
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
			})
			return &UserOTPResponse{
				Success:    false,
				Message:    "Daily OTP limit exceeded for this device",
				RetryAfter: 86400,
			}, appErrors.ErrDailyQuotaExceeded
		}
	}
	return nil, nil
}

// ---- Validation helpers ----

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

// ---- Phone hash and device/IP checks ----

func (s *UserOTPService) generatePhoneHash(phoneNumber string) string {
	normalized := strings.ReplaceAll(phoneNumber, " ", "")
	normalized = strings.ReplaceAll(normalized, "-", "")
	normalized = strings.ReplaceAll(normalized, "(", "")
	normalized = strings.ReplaceAll(normalized, ")", "")
	hash := sha256.Sum256([]byte(normalized))
	return hex.EncodeToString(hash[:])
}

func (s *UserOTPService) hashFingerprint(fp string) string {
	sum := sha256.Sum256([]byte(fp))
	return hex.EncodeToString(sum[:])
}

func (s *UserOTPService) isUserNewDevice(deviceID, phoneNumber string) bool {
	if deviceID == "" {
		return true
	}
	ctx := context.Background()
	userID, err := s.phoneValidator.GetUserIDByPhone(ctx, phoneNumber)
	if err != nil || userID == uuid.Nil {
		return true
	}
	rec, err := s.deviceTrustRepo.GetDeviceTrustLevel(ctx, userID, deviceID)
	if err != nil || rec == nil || rec.IsBlocked || rec.TrustStatus == models.TrustStatusUntrusted {
		return true
	}
	return rec.DeviceID != deviceID
}

func (s *UserOTPService) isUserNewIP(ipAddress, phoneNumber, deviceID string) bool {
	if ipAddress == "" {
		return true
	}
	ctx := context.Background()
	userID, err := s.phoneValidator.GetUserIDByPhone(ctx, phoneNumber)
	if err != nil || userID == uuid.Nil {
		return true
	}
	if deviceID != "" {
		rec, err := s.deviceTrustRepo.GetDeviceTrustLevel(ctx, userID, deviceID)
		if err == nil && rec != nil && rec.LastIPAddress == ipAddress {
			return false
		}
	}
	recs, err := s.deviceTrustRepo.GetUserDevices(ctx, userID)
	if err != nil {
		return true
	}
	for _, rec := range recs {
		if rec.LastIPAddress == ipAddress {
			return false
		}
	}
	return true
}

func (s *UserOTPService) isUserPhoneRegistered(ctx context.Context, phoneNumber, purpose string) (bool, error) {
	return s.phoneValidator.IsUserPhoneRegistered(ctx, phoneNumber)
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

// ---- Health & stats ----

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
	// TTL handles expiry automatically
	return 0, nil
}

// SetLogProducerService is kept for compatibility if needed
func (s *UserOTPService) SetLogProducerService(logProducer *LogProducerService) {
	s.logProducer = logProducer
}

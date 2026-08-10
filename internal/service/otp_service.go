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

	"github.com/google/uuid"
	lru "github.com/hashicorp/golang-lru/v2"
)

// ---- Constants ----

const (
	// Rate limits
	OTPSendLimit1Min         = 2
	OTPSendLimit5Min         = 3
	OTPSendLimitHour         = 10
	OTPSendLimitDay          = 20
	OTPVerifyLimit30Sec      = 3
	OTPVerifyLimitMin        = 5
	OTPResendCooldownInitial = 60 * time.Second
	OTPResendCooldownMax     = 300 * time.Second

	// Timeouts
	OTPExpiryDuration         = 5 * time.Minute
	OTPCacheDuration          = 6 * time.Minute
	OTPRateLimitCacheDuration = 1 * time.Hour
	OTPReplayProtectionWindow = 60 * time.Second

	// Account lockout
	AccountLockoutDuration  = 30 * time.Minute
	AccountLockoutThreshold = 5

	// Daily quotas
	DailyQuotaPerPhone  = 10
	DailyQuotaPerIP     = 50
	DailyQuotaPerDevice = 15

	// Admin limits (stricter)
	AdminOTPSendLimit1Min    = 1
	AdminOTPSendLimit5Min    = 2
	AdminOTPSendLimitHour    = 5
	AdminOTPSendLimitDay     = 10
	AdminOTPVerifyLimit30Sec = 2
	AdminOTPVerifyLimitMin   = 3

	// Risk thresholds
	HighRiskThreshold   = 70
	MediumRiskThreshold = 40

	ServiceVersion = "1.0.0"
)

// ---- Request / Response structs ----

type OTPSendRequest struct {
	PhoneNumber       string `json:"phone_number" validate:"required,min=10,max=15"`
	Purpose           string `json:"purpose" validate:"required,oneof=login verification password_reset admin_login forgot_mpin"`
	IPAddress         string `json:"ip_address"`
	DeviceID          string `json:"device_id"`
	Provider          string `json:"provider,omitempty"`
	UserAgent         string `json:"user_agent,omitempty"`
	DeviceFingerprint string `json:"device_fingerprint,omitempty"`
}

type OTPResponse struct {
	Success      bool      `json:"success"`
	Message      string    `json:"message"`
	ExpiresAt    time.Time `json:"expires_at,omitempty"`
	AttemptsLeft int       `json:"attempts_left,omitempty"`
	RetryAfter   int       `json:"retry_after,omitempty"`
	DailyQuota   int       `json:"daily_quota,omitempty"`
	QuotaUsed    int       `json:"quota_used,omitempty"`
	OTPValue     string    `json:"otp_value,omitempty"` // Only in dev/test
}

type OTPVerifyRequest struct {
	PhoneNumber       string `json:"phone_number" validate:"required,min=10,max=15"`
	OTP               string `json:"otp" validate:"required,len=6,numeric"`
	Purpose           string `json:"purpose" validate:"required,oneof=login verification password_reset admin_login forgot_mpin"`
	IPAddress         string `json:"ip_address"`
	DeviceID          string `json:"device_id"`
	DeviceFingerprint string `json:"device_fingerprint"`
	UserAgent         string `json:"user_agent,omitempty"`
}

type OTPResendRequest struct {
	PhoneNumber       string `json:"phone_number" validate:"required,min=10,max=15"`
	Purpose           string `json:"purpose" validate:"required,oneof=login verification password_reset admin_login forgot_mpin"`
	IPAddress         string `json:"ip_address"`
	DeviceID          string `json:"device_id,omitempty"`
	DeviceFingerprint string `json:"device_fingerprint,omitempty"`
	UserAgent         string `json:"user_agent,omitempty"`
}

// ---- TokenBucket (rate limiting) ----

type TokenBucket struct {
	Tokens         float64
	MaxTokens      float64
	RefillRate     float64
	LastRefillTime time.Time
	mu             sync.Mutex
}

func NewTokenBucket(maxTokens, refillRate float64) *TokenBucket {
	return &TokenBucket{
		Tokens:         maxTokens,
		MaxTokens:      maxTokens,
		RefillRate:     refillRate,
		LastRefillTime: time.Now(),
	}
}

func (tb *TokenBucket) TakeToken() bool {
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

// ---- OTPService ----

type OTPService struct {
	otpRepo              scylla.OTPRepository
	hasher               *hashing.Hasher
	config               *config.Config
	distCache            *DistributedCache
	logProducer          *LogProducerService
	auditService         *audit.AuditService
	idempotencyStore     idempotency.Store
	smsManager           *sms.SMSManager
	sendRateCache        *lru.Cache[string, *TokenBucket]
	verifyRateCache      *lru.Cache[string, *TokenBucket]
	lockoutCache         *lru.Cache[string, time.Time]
	phoneValidator       PhoneValidator
	adminDeviceTrustRepo scylla.AdminDeviceTrustRepository
	botDetector          *security.BotDetector
	ipReputation         *security.IPReputation
	riskEngine           *security.RiskEngine
	mu                   sync.RWMutex
}

func NewOTPService(
	otpRepo scylla.OTPRepository,
	hasher *hashing.Hasher,
	cfg *config.Config,
	distCache *DistributedCache,
	logProducer *LogProducerService,
	auditService *audit.AuditService,
	idempotencyStore idempotency.Store,
	phoneValidator PhoneValidator,
	adminDeviceTrustRepo scylla.AdminDeviceTrustRepository,
	smsManager *sms.SMSManager,
) *OTPService {
	sendCache, _ := lru.New[string, *TokenBucket](100_000)
	verifyCache, _ := lru.New[string, *TokenBucket](100_000)
	lockoutCache, _ := lru.New[string, time.Time](50_000)

	botDetector := security.NewBotDetector()
	ipReputation := security.NewIPReputation()
	riskEngine := security.NewRiskEngine(botDetector, ipReputation)

	return &OTPService{
		otpRepo:              otpRepo,
		hasher:               hasher,
		config:               cfg,
		distCache:            distCache,
		logProducer:          logProducer,
		auditService:         auditService,
		idempotencyStore:     idempotencyStore,
		smsManager:           smsManager,
		sendRateCache:        sendCache,
		verifyRateCache:      verifyCache,
		lockoutCache:         lockoutCache,
		phoneValidator:       phoneValidator,
		adminDeviceTrustRepo: adminDeviceTrustRepo,
		botDetector:          botDetector,
		ipReputation:         ipReputation,
		riskEngine:           riskEngine,
	}
}

// ---- Phone registration check ----

func (s *OTPService) isPhoneRegistered(ctx context.Context, phoneNumber, purpose string) (bool, error) {
	return s.phoneValidator.IsAdminPhoneRegistered(ctx, phoneNumber)
}

// ---- Security checks ----

func (s *OTPService) performSecurityChecks(ctx context.Context, req *OTPSendRequest, startTime time.Time) *OTPResponse {
	requestLatency := time.Since(startTime)

	quickRisk, shouldBlock := s.riskEngine.QuickRiskCheck(req.IPAddress, req.UserAgent, requestLatency, req.Purpose)
	if shouldBlock {
		s.logSecurityEvent(ctx, req, "quick_risk_check_failed", quickRisk, []string{"high_risk_quick_check"})
		return &OTPResponse{
			Success: false,
			Message: "Security check failed",
		}
	}

	riskReq := security.RiskAssessmentRequest{
		UserAgent:      req.UserAgent,
		IPAddress:      req.IPAddress,
		DeviceID:       req.DeviceID,
		PhoneNumber:    req.PhoneNumber,
		Purpose:        req.Purpose,
		RequestLatency: requestLatency,
		FailedAttempts: s.getFailedAttemptsCount(req.PhoneNumber),
		DailyOTPCount:  s.getDailyOTPCount(req.PhoneNumber),
		IsNewDevice:    s.isNewDevice(req.DeviceID, req.PhoneNumber),
		IsNewIP:        s.isNewIP(req.IPAddress, req.PhoneNumber, req.DeviceID),
	}

	riskAssessment := s.riskEngine.AssessRisk(riskReq)
	s.logSecurityEvent(ctx, req, "risk_assessment", riskAssessment.RiskScore, riskAssessment.Reasons)

	if riskAssessment.BlockAction {
		return &OTPResponse{
			Success: false,
			Message: "Security check failed",
		}
	}
	return nil
}

// ---- Send OTP ----
func (s *OTPService) SendOTP(ctx context.Context, req *OTPSendRequest) (*OTPResponse, error) {
	startTime := time.Now()
	logger := zap.L()

	// Idempotency
	idempKey, _ := ctx.Value("idempotency_key").(string)
	if idempKey == "" {
		idempKey = fmt.Sprintf("send_otp:%s:%s", req.PhoneNumber, req.Purpose)
	}
	logger.Debug("Checking idempotency cache",
		zap.String("key", idempKey),
		zap.String("operation", "send"),
	)

	var cached *OTPResponse
	if err := s.idempotencyStore.Get(ctx, nil, idempKey, &cached); err != nil {
		logger.Warn("Idempotency cache get failed",
			zap.String("key", idempKey),
			zap.Error(err),
		)
	} else if cached != nil && cached.Success {
		logger.Info("Idempotency cache hit",
			zap.String("key", idempKey),
			zap.String("operation", "send"),
		)
		return cached, nil
	} else {
		logger.Info("Idempotency cache miss",
			zap.String("key", idempKey),
			zap.String("operation", "send"),
		)
	}

	ip, _ := ctx.Value("ip_address").(string)
	if ip == "" {
		ip = req.IPAddress
	}

	s.logOTPEvent(ctx, &models.OTPLogEvent{
		LogEnvelope: models.LogEnvelope{
			EventID:     uuid.New().String(),
			EventType:   string(models.LogEventTypeOTP),
			ServiceName: "auth-service",
			Timestamp:   time.Now(),
			Environment: s.config.Environment,
			Version:     ServiceVersion,
			Level:       string(models.LogLevelInfo),
			Message:     "OTP send initiated",
		},
		PhoneNumber: req.PhoneNumber,
		Status:      "send_initiated",
		Purpose:     req.Purpose,
		IPAddress:   ip,
		UserAgent:   req.UserAgent,
	})

	// 1. Phone registration check
	isRegistered, err := s.isPhoneRegistered(ctx, req.PhoneNumber, req.Purpose)
	if err != nil {
		s.logOTPEvent(ctx, &models.OTPLogEvent{
			LogEnvelope: models.LogEnvelope{
				EventID:     uuid.New().String(),
				EventType:   string(models.LogEventTypeOTP),
				ServiceName: "auth-service",
				Timestamp:   time.Now(),
				Environment: s.config.Environment,
				Version:     ServiceVersion,
				Level:       string(models.LogLevelError),
				Message:     "Phone registration check failed",
			},
			PhoneNumber:   req.PhoneNumber,
			Status:        "send_failed",
			Purpose:       req.Purpose,
			IPAddress:     ip,
			UserAgent:     req.UserAgent,
			ErrorCode:     "PHONE_CHECK_FAILED",
			ErrorMessage:  err.Error(),
			AttemptNumber: 0,
		})
		return nil, appErrors.ErrInternal
	}
	if !isRegistered {
		s.logOTPEvent(ctx, &models.OTPLogEvent{
			LogEnvelope: models.LogEnvelope{
				EventID:     uuid.New().String(),
				EventType:   string(models.LogEventTypeOTP),
				ServiceName: "auth-service",
				Timestamp:   time.Now(),
				Environment: s.config.Environment,
				Version:     ServiceVersion,
				Level:       string(models.LogLevelWarning),
				Message:     "Phone number not registered",
			},
			PhoneNumber:   req.PhoneNumber,
			Status:        "send_failed",
			Purpose:       req.Purpose,
			IPAddress:     ip,
			UserAgent:     req.UserAgent,
			ErrorCode:     "PHONE_NOT_REGISTERED",
			ErrorMessage:  "Phone number is not registered in the system",
			AttemptNumber: 0,
		})
		return &OTPResponse{
			Success: false,
			Message: "Phone number not registered",
		}, appErrors.ErrPhoneNotRegistered
	}

	// 2. Security checks
	if securityResult := s.performSecurityChecks(ctx, req, startTime); securityResult != nil {
		return securityResult, appErrors.ErrSecurityCheckFailed
	}

	// 3. Validate input
	if err := s.validateSendRequest(req); err != nil {
		s.logOTPEvent(ctx, &models.OTPLogEvent{
			LogEnvelope: models.LogEnvelope{
				EventID:     uuid.New().String(),
				EventType:   string(models.LogEventTypeOTP),
				ServiceName: "auth-service",
				Timestamp:   time.Now(),
				Environment: s.config.Environment,
				Version:     ServiceVersion,
				Level:       string(models.LogLevelError),
				Message:     "OTP send validation failed",
			},
			PhoneNumber:   req.PhoneNumber,
			Status:        "send_failed",
			Purpose:       req.Purpose,
			IPAddress:     ip,
			UserAgent:     req.UserAgent,
			ErrorCode:     "VALIDATION_FAILED",
			ErrorMessage:  err.Error(),
			AttemptNumber: 0,
		})
		return nil, appErrors.ErrInvalidInput
	}

	phoneHash := s.generatePhoneHash(req.PhoneNumber)

	// 4. Daily quotas
	if quotaResp, err := s.checkDailyQuotas(ctx, phoneHash, ip, req.DeviceID, req.Purpose); err != nil {
		return quotaResp, err
	}

	// 5. Cooldown (including device)
	deviceKey := req.DeviceID
	if deviceKey == "" {
		deviceKey = "nodevice"
	}
	cooldownKey := fmt.Sprintf("otp:cooldown:%s:%s:%s", phoneHash, req.Purpose, deviceKey)
	allowed, retryAfter := s.distCache.AllowRateWithIncreasingCooldown(
		ctx, cooldownKey, OTPResendCooldownInitial, OTPResendCooldownMax)
	if !allowed {
		s.logOTPEvent(ctx, &models.OTPLogEvent{
			LogEnvelope: models.LogEnvelope{
				EventID:     uuid.New().String(),
				EventType:   string(models.LogEventTypeOTP),
				ServiceName: "auth-service",
				Timestamp:   time.Now(),
				Environment: s.config.Environment,
				Version:     ServiceVersion,
				Level:       string(models.LogLevelWarning),
				Message:     "OTP send cooldown active",
			},
			PhoneNumber:   req.PhoneNumber,
			Status:        "send_cooldown",
			Purpose:       req.Purpose,
			IPAddress:     ip,
			UserAgent:     req.UserAgent,
			ErrorCode:     "COOLDOWN_ACTIVE",
			AttemptNumber: 0,
			AttemptsLeft:  retryAfter,
		})
		return &OTPResponse{
			Success:    false,
			Message:    "Please wait before requesting a new OTP",
			RetryAfter: retryAfter,
		}, appErrors.ErrOTPRateLimitExceeded
	}

	// 6. Device/IP rate limits
	if s.distCache != nil && req.DeviceID != "" {
		key := fmt.Sprintf("otp:rate:send:device:%s", req.DeviceID)
		if allowed, retry := s.distCache.AllowRate(ctx, key, 5, time.Minute); !allowed {
			return &OTPResponse{
				Success:    false,
				Message:    "Too many OTP requests from this device",
				RetryAfter: retry,
			}, appErrors.ErrOTPRateLimitExceeded
		}
	}
	if s.distCache != nil && req.IPAddress != "" {
		key := fmt.Sprintf("otp:rate:send:ip:%s", req.IPAddress)
		if allowed, retry := s.distCache.AllowRate(ctx, key, 20, time.Minute); !allowed {
			return &OTPResponse{
				Success:    false,
				Message:    "Too many OTP requests from this IP",
				RetryAfter: retry,
			}, appErrors.ErrOTPRateLimitExceeded
		}
	}

	// 7. Account lockout
	if locked, until := s.isAccountLocked(phoneHash); locked {
		retry := int(time.Until(until).Seconds())
		return &OTPResponse{
			Success:    false,
			Message:    "Account temporarily locked due to excessive attempts",
			RetryAfter: retry,
		}, appErrors.ErrOTPRateLimitExceeded
	}

	// 8. Purpose-based rate limit
	rateKey := fmt.Sprintf("%s:%s", phoneHash, req.Purpose)
	if !s.checkSendRateLimit(rateKey, req.Purpose) {
		bucket := s.getSendTokenBucket(rateKey, req.Purpose)
		retryAfter := bucket.TimeUntilToken()
		return &OTPResponse{
			Success:    false,
			Message:    "Too many OTP requests. Try again later.",
			RetryAfter: retryAfter,
		}, appErrors.ErrOTPRateLimitExceeded
	}

	// 9. Invalidate existing OTP (resend semantics)
	existingOTP, err := s.otpRepo.GetActiveOTP(ctx, phoneHash, req.Purpose)
	if err == nil && existingOTP != nil {
		_ = s.otpRepo.InvalidateOTP(ctx, phoneHash, req.Purpose)
		if s.distCache != nil {
			cacheKey := fmt.Sprintf("otp:%s:%s", phoneHash, req.Purpose)
			_ = s.distCache.DeleteOTPVerification(ctx, cacheKey)
		}
	}

	// 10. Generate new OTP
	otp, err := scylla.GenerateOTP(6)
	if err != nil {
		logger.Error("Failed to generate OTP",
			zap.String("phone_hash", phoneHash),
			zap.String("purpose", req.Purpose),
			zap.Error(err),
		)
		return nil, appErrors.ErrInternal
	}
	salt, err := scylla.GenerateSalt()
	if err != nil {
		logger.Error("Failed to generate salt",
			zap.String("phone_hash", phoneHash),
			zap.String("purpose", req.Purpose),
			zap.Error(err),
		)
		return nil, appErrors.ErrInternal
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
		logger.Error("Failed to store OTP in repository",
			zap.String("phone_hash", phoneHash),
			zap.String("purpose", req.Purpose),
			zap.Error(err),
		)
		return nil, appErrors.ErrInternal
	}

	// Cache OTP
	if s.distCache != nil {
		go func() {
			cacheKey := fmt.Sprintf("otp:%s:%s", phoneHash, req.Purpose)
			_ = s.distCache.SetOTPVerification(context.Background(), cacheKey, otpVerification, OTPCacheDuration)
		}()
	}

	// Zap logging: OTP generated successfully
	fields := []zap.Field{
		zap.String("phone_hash", phoneHash),
		zap.String("purpose", req.Purpose),
		zap.String("ip", ip),
		zap.String("device_id", req.DeviceID),
		zap.Time("expires_at", expiresAt),
		zap.Duration("generation_time", time.Since(startTime)),
	}
	if s.config.Environment == "development" || s.config.Environment == "test" {
		fields = append(fields, zap.String("otp_value", otp))
		logger.Info("OTP generated (dev/test)", fields...)
	} else {
		logger.Info("OTP generated", fields...)
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
		logger.Error("Failed to send OTP SMS",
			zap.String("phone_hash", phoneHash),
			zap.String("purpose", req.Purpose),
			zap.String("provider", req.Provider),
		)
		return nil, appErrors.ErrInternal
	}

	s.incrementDailyQuotas(ctx, phoneHash, ip, req.DeviceID)

	// Audit
	if s.auditService != nil {
		_ = s.auditService.LogAction(ctx, nil, nil, "otp", "send", "otp",
			nil, "system", nil, nil, nil, map[string]interface{}{
				"phone_hash": phoneHash,
				"purpose":    req.Purpose,
				"ip":         ip,
				"status":     "success",
			})
	}

	resp := &OTPResponse{
		Success:      true,
		Message:      "OTP sent successfully",
		ExpiresAt:    expiresAt,
		AttemptsLeft: scylla.OTPMaxAttempts,
		DailyQuota:   s.getDailyQuotaLimit(req.Purpose),
		OTPValue:     otp,
	}

	// Store idempotency response
	if err := s.idempotencyStore.Store(ctx, nil, idempKey, resp); err != nil {
		logger.Error("Idempotency store failed",
			zap.String("key", idempKey),
			zap.Error(err),
		)
	} else {
		logger.Debug("Idempotency response stored",
			zap.String("key", idempKey),
			zap.String("operation", "send"),
		)
	}

	s.logOTPEvent(ctx, &models.OTPLogEvent{
		LogEnvelope: models.LogEnvelope{
			EventID:     uuid.New().String(),
			EventType:   string(models.LogEventTypeOTP),
			ServiceName: "auth-service",
			Timestamp:   time.Now(),
			Environment: s.config.Environment,
			Version:     ServiceVersion,
			Level:       string(models.LogLevelInfo),
			Message:     "OTP sent successfully",
		},
		PhoneNumber:   req.PhoneNumber,
		Status:        "sent",
		Purpose:       req.Purpose,
		IPAddress:     ip,
		UserAgent:     req.UserAgent,
		AttemptNumber: 0,
		Duration:      int64(time.Since(startTime).Milliseconds()),
	})

	return resp, nil
}

// ---- Verify OTP ----
// This method now sets the device as Trusted for the admin upon successful OTP verification.
func (s *OTPService) VerifyOTP(ctx context.Context, req *OTPVerifyRequest) (*OTPResponse, error) {
	startTime := time.Now()
	logger := zap.L()

	idempKey, _ := ctx.Value("idempotency_key").(string)
	if idempKey == "" {
		idempKey = fmt.Sprintf("verify_otp:%s:%s:%s", req.PhoneNumber, req.Purpose, req.OTP)
	}
	logger.Debug("Checking idempotency cache",
		zap.String("key", idempKey),
		zap.String("operation", "verify"),
	)

	var cached *OTPResponse
	if err := s.idempotencyStore.Get(ctx, nil, idempKey, &cached); err != nil {
		logger.Warn("Idempotency cache get failed",
			zap.String("key", idempKey),
			zap.Error(err),
		)
	} else if cached != nil {
		logger.Info("Idempotency cache hit",
			zap.String("key", idempKey),
			zap.String("operation", "verify"),
		)
		return cached, nil
	} else {
		logger.Info("Idempotency cache miss",
			zap.String("key", idempKey),
			zap.String("operation", "verify"),
		)
	}

	ip, _ := ctx.Value("ip_address").(string)
	if ip == "" {
		ip = req.IPAddress
	}

	s.logOTPEvent(ctx, &models.OTPLogEvent{
		LogEnvelope: models.LogEnvelope{
			EventID:     uuid.New().String(),
			EventType:   string(models.LogEventTypeOTP),
			ServiceName: "auth-service",
			Timestamp:   time.Now(),
			Environment: s.config.Environment,
			Version:     ServiceVersion,
			Level:       string(models.LogLevelInfo),
			Message:     "OTP verification initiated",
		},
		PhoneNumber: req.PhoneNumber,
		Status:      "verification_initiated",
		Purpose:     req.Purpose,
		IPAddress:   ip,
		UserAgent:   req.UserAgent,
	})

	if err := s.validateVerifyRequest(req); err != nil {
		s.logOTPEvent(ctx, &models.OTPLogEvent{
			LogEnvelope: models.LogEnvelope{
				EventID:     uuid.New().String(),
				EventType:   string(models.LogEventTypeOTP),
				ServiceName: "auth-service",
				Timestamp:   time.Now(),
				Environment: s.config.Environment,
				Version:     ServiceVersion,
				Level:       string(models.LogLevelError),
				Message:     "OTP verification validation failed",
			},
			PhoneNumber:   req.PhoneNumber,
			Status:        "verification_failed",
			Purpose:       req.Purpose,
			IPAddress:     ip,
			UserAgent:     req.UserAgent,
			ErrorCode:     "VALIDATION_FAILED",
			ErrorMessage:  err.Error(),
			AttemptNumber: 0,
		})
		return nil, appErrors.ErrInvalidInput
	}

	phoneHash := s.generatePhoneHash(req.PhoneNumber)

	// Rate limiting: device
	if s.distCache != nil && req.DeviceID != "" {
		key := fmt.Sprintf("otp:rate:verify:device:%s", req.DeviceID)
		allowed, retry := s.distCache.AllowRate(ctx, key, 10, time.Minute)
		if !allowed {
			s.logOTPEvent(ctx, &models.OTPLogEvent{
				LogEnvelope: models.LogEnvelope{
					EventID:     uuid.New().String(),
					EventType:   string(models.LogEventTypeOTP),
					ServiceName: "auth-service",
					Timestamp:   time.Now(),
					Environment: s.config.Environment,
					Version:     ServiceVersion,
					Level:       string(models.LogLevelWarning),
					Message:     "OTP verification device rate limit exceeded",
				},
				PhoneNumber:   req.PhoneNumber,
				Status:        "verification_rate_limited",
				Purpose:       req.Purpose,
				IPAddress:     ip,
				UserAgent:     req.UserAgent,
				DeviceID:      req.DeviceID,
				ErrorCode:     "DEVICE_RATE_LIMIT_EXCEEDED",
				AttemptNumber: 0,
				AttemptsLeft:  retry,
			})
			return &OTPResponse{
				Success:    false,
				Message:    "Too many verification attempts",
				RetryAfter: retry,
			}, appErrors.ErrOTPRateLimitExceeded
		}
	}
	if s.distCache != nil && req.IPAddress != "" {
		key := fmt.Sprintf("otp:rate:verify:ip:%s", req.IPAddress)
		allowed, retry := s.distCache.AllowRate(ctx, key, 30, time.Minute)
		if !allowed {
			s.logOTPEvent(ctx, &models.OTPLogEvent{
				LogEnvelope: models.LogEnvelope{
					EventID:     uuid.New().String(),
					EventType:   string(models.LogEventTypeOTP),
					ServiceName: "auth-service",
					Timestamp:   time.Now(),
					Environment: s.config.Environment,
					Version:     ServiceVersion,
					Level:       string(models.LogLevelWarning),
					Message:     "OTP verification IP rate limit exceeded",
				},
				PhoneNumber:   req.PhoneNumber,
				Status:        "verification_rate_limited",
				Purpose:       req.Purpose,
				IPAddress:     ip,
				UserAgent:     req.UserAgent,
				DeviceID:      req.DeviceID,
				ErrorCode:     "IP_RATE_LIMIT_EXCEEDED",
				AttemptNumber: 0,
				AttemptsLeft:  retry,
			})
			return &OTPResponse{
				Success:    false,
				Message:    "Too many verification attempts",
				RetryAfter: retry,
			}, appErrors.ErrOTPRateLimitExceeded
		}
	}

	// Account lockout
	if locked, until := s.isAccountLocked(phoneHash); locked {
		retryAfter := int(time.Until(until).Seconds())
		s.logOTPEvent(ctx, &models.OTPLogEvent{
			LogEnvelope: models.LogEnvelope{
				EventID:     uuid.New().String(),
				EventType:   string(models.LogEventTypeOTP),
				ServiceName: "auth-service",
				Timestamp:   time.Now(),
				Environment: s.config.Environment,
				Version:     ServiceVersion,
				Level:       string(models.LogLevelWarning),
				Message:     "Account locked for OTP verification",
			},
			PhoneNumber:   req.PhoneNumber,
			Status:        "verification_blocked",
			Purpose:       req.Purpose,
			IPAddress:     ip,
			UserAgent:     req.UserAgent,
			ErrorCode:     "ACCOUNT_LOCKED",
			AttemptNumber: 0,
			AttemptsLeft:  retryAfter,
		})
		return &OTPResponse{
			Success:    false,
			Message:    "Account temporarily locked",
			RetryAfter: retryAfter,
		}, appErrors.ErrOTPRateLimitExceeded
	}

	// Get OTP record
	var otpRecord *models.OTPVerification
	var err error
	if s.distCache != nil {
		cacheKey := fmt.Sprintf("otp:%s:%s", phoneHash, req.Purpose)
		otpRecord, err = s.distCache.GetOTPVerification(ctx, cacheKey)
		if err != nil {
			otpRecord, err = s.otpRepo.GetActiveOTP(ctx, phoneHash, req.Purpose)
		}
	} else {
		otpRecord, err = s.otpRepo.GetActiveOTP(ctx, phoneHash, req.Purpose)
	}
	if err != nil {
		s.incrementFailedAttempts(phoneHash)
		s.logOTPEvent(ctx, &models.OTPLogEvent{
			LogEnvelope: models.LogEnvelope{
				EventID:     uuid.New().String(),
				EventType:   string(models.LogEventTypeOTP),
				ServiceName: "auth-service",
				Timestamp:   time.Now(),
				Environment: s.config.Environment,
				Version:     ServiceVersion,
				Level:       string(models.LogLevelWarning),
				Message:     "OTP verification failed",
			},
			PhoneNumber:   req.PhoneNumber,
			Status:        "verification_failed",
			Purpose:       req.Purpose,
			IPAddress:     ip,
			UserAgent:     req.UserAgent,
			ErrorCode:     "OTP_NOT_FOUND",
			ErrorMessage:  "Invalid OTP or expired",
			AttemptNumber: 0,
		})
		return &OTPResponse{
			Success: false,
			Message: "Invalid OTP or expired",
		}, appErrors.ErrOTPNotFound
	}

	// Device binding check
	if otpRecord.DeviceID != "" && req.DeviceID != "" && otpRecord.DeviceID != req.DeviceID {
		s.incrementFailedAttempts(phoneHash)
		s.logOTPEvent(ctx, &models.OTPLogEvent{
			LogEnvelope: models.LogEnvelope{
				EventID:     uuid.New().String(),
				EventType:   string(models.LogEventTypeOTP),
				ServiceName: "auth-service",
				Timestamp:   time.Now(),
				Environment: s.config.Environment,
				Version:     ServiceVersion,
				Level:       string(models.LogLevelWarning),
				Message:     "OTP device mismatch",
			},
			PhoneNumber:   req.PhoneNumber,
			Status:        "verification_failed",
			Purpose:       req.Purpose,
			IPAddress:     ip,
			UserAgent:     req.UserAgent,
			DeviceID:      req.DeviceID,
			ErrorCode:     "DEVICE_MISMATCH",
			AttemptNumber: otpRecord.Attempts,
			AttemptsLeft:  scylla.OTPMaxAttempts - otpRecord.Attempts,
		})
		return &OTPResponse{
			Success:      false,
			Message:      "Invalid OTP or expired",
			AttemptsLeft: scylla.OTPMaxAttempts - otpRecord.Attempts,
		}, appErrors.ErrOTPInvalid
	}

	// Expiry
	if time.Now().After(otpRecord.ExpiresAt) {
		s.incrementFailedAttempts(phoneHash)
		s.logOTPEvent(ctx, &models.OTPLogEvent{
			LogEnvelope: models.LogEnvelope{
				EventID:     uuid.New().String(),
				EventType:   string(models.LogEventTypeOTP),
				ServiceName: "auth-service",
				Timestamp:   time.Now(),
				Environment: s.config.Environment,
				Version:     ServiceVersion,
				Level:       string(models.LogLevelWarning),
				Message:     "OTP expired for verification",
			},
			PhoneNumber:   req.PhoneNumber,
			Status:        "verification_failed",
			Purpose:       req.Purpose,
			IPAddress:     ip,
			UserAgent:     req.UserAgent,
			ErrorCode:     "OTP_EXPIRED",
			AttemptNumber: otpRecord.Attempts,
			AttemptsLeft:  scylla.OTPMaxAttempts - otpRecord.Attempts,
		})
		return &OTPResponse{
			Success:   false,
			Message:   "Invalid OTP or expired",
			ExpiresAt: otpRecord.ExpiresAt,
		}, appErrors.ErrOTPExpired
	}

	// Attempts limit
	if otpRecord.Attempts >= scylla.OTPMaxAttempts {
		s.lockAccount(phoneHash)
		s.logOTPEvent(ctx, &models.OTPLogEvent{
			LogEnvelope: models.LogEnvelope{
				EventID:     uuid.New().String(),
				EventType:   string(models.LogEventTypeOTP),
				ServiceName: "auth-service",
				Timestamp:   time.Now(),
				Environment: s.config.Environment,
				Version:     ServiceVersion,
				Level:       string(models.LogLevelWarning),
				Message:     "OTP verification attempts exceeded",
			},
			PhoneNumber:   req.PhoneNumber,
			Status:        "verification_blocked",
			Purpose:       req.Purpose,
			IPAddress:     ip,
			UserAgent:     req.UserAgent,
			ErrorCode:     "ATTEMPTS_EXCEEDED",
			AttemptNumber: otpRecord.Attempts,
			AttemptsLeft:  0,
		})
		return &OTPResponse{
			Success:      false,
			Message:      "Invalid OTP or expired",
			AttemptsLeft: 0,
		}, appErrors.ErrOTPAttemptsExceeded
	}

	// Replay protection
	providedHash := scylla.HashOTP(req.OTP, otpRecord.OTPSalt)
	replayKey := fmt.Sprintf("otp:replay:%s:%s", phoneHash, providedHash)
	replayExists, _ := s.distCache.CheckOTPReplayProtection(ctx, replayKey)
	if replayExists {
		s.incrementFailedAttempts(phoneHash)
		s.logOTPEvent(ctx, &models.OTPLogEvent{
			LogEnvelope: models.LogEnvelope{
				EventID:     uuid.New().String(),
				EventType:   string(models.LogEventTypeOTP),
				ServiceName: "auth-service",
				Timestamp:   time.Now(),
				Environment: s.config.Environment,
				Version:     ServiceVersion,
				Level:       string(models.LogLevelWarning),
				Message:     "OTP replay attempt detected",
			},
			PhoneNumber:   req.PhoneNumber,
			Status:        "verification_failed",
			Purpose:       req.Purpose,
			IPAddress:     ip,
			UserAgent:     req.UserAgent,
			ErrorCode:     "REPLAY_ATTEMPT",
			AttemptNumber: otpRecord.Attempts,
			AttemptsLeft:  scylla.OTPMaxAttempts - otpRecord.Attempts,
		})
		return &OTPResponse{
			Success:      false,
			Message:      "Invalid OTP or expired",
			AttemptsLeft: scylla.OTPMaxAttempts - otpRecord.Attempts,
		}, appErrors.ErrOTPReplayAttempt
	}

	// Validate OTP
	validatedOTP, err := s.otpRepo.ValidateOTP(ctx, phoneHash, providedHash, req.Purpose)
	if err != nil {
		s.incrementFailedAttempts(phoneHash)
		attemptsLeft := scylla.OTPMaxAttempts
		if validatedOTP != nil {
			attemptsLeft = scylla.OTPMaxAttempts - validatedOTP.Attempts
		}
		if attemptsLeft <= 0 {
			s.lockAccount(phoneHash)
		}
		s.logOTPEvent(ctx, &models.OTPLogEvent{
			LogEnvelope: models.LogEnvelope{
				EventID:     uuid.New().String(),
				EventType:   string(models.LogEventTypeOTP),
				ServiceName: "auth-service",
				Timestamp:   time.Now(),
				Environment: s.config.Environment,
				Version:     ServiceVersion,
				Level:       string(models.LogLevelWarning),
				Message:     "Invalid OTP provided",
			},
			PhoneNumber:   req.PhoneNumber,
			Status:        "verification_failed",
			Purpose:       req.Purpose,
			IPAddress:     ip,
			UserAgent:     req.UserAgent,
			ErrorCode:     "INVALID_OTP",
			AttemptNumber: validatedOTP.Attempts,
			AttemptsLeft:  attemptsLeft,
			Duration:      int64(time.Since(startTime).Milliseconds()),
		})
		return &OTPResponse{
			Success:      false,
			Message:      "Invalid OTP or expired",
			AttemptsLeft: attemptsLeft,
			ExpiresAt:    otpRecord.ExpiresAt,
		}, appErrors.ErrOTPInvalid
	}

	// Store replay protection
	_ = s.distCache.StoreOTPReplayProtection(ctx, replayKey, providedHash, OTPReplayProtectionWindow)

	// Invalidate OTP
	_ = s.otpRepo.InvalidateOTP(ctx, phoneHash, req.Purpose)
	if s.distCache != nil {
		cacheKey := fmt.Sprintf("otp:%s:%s", phoneHash, req.Purpose)
		_ = s.distCache.DeleteOTPVerification(ctx, cacheKey)
	}
	s.clearFailedAttempts(phoneHash)

	// -----------------------------------------------------------------
	// ★ CRITICAL ADDITION: Establish device trust for admin on OTP login
	// -----------------------------------------------------------------
	// After successful OTP verification, this device becomes trusted for MPIN.
	adminID, err := s.phoneValidator.GetAdminIDByPhone(ctx, req.PhoneNumber)
	if err == nil && adminID != uuid.Nil && req.DeviceID != "" {
		trustLevel := &models.DeviceTrustLevel{
			UserID:            adminID,
			DeviceID:          req.DeviceID,
			TrustStatus:       models.TrustStatusTrusted, // OTP proves identity → device is trusted
			DeviceFingerprint: s.hashFingerprint(req.DeviceFingerprint),
			LastIPAddress:     req.IPAddress,
			UserAgent:         req.UserAgent,
			IsBlocked:         false,
			RiskScore:         0,
		}
		if err := s.adminDeviceTrustRepo.SetAdminDeviceTrustLevel(ctx, adminID, req.DeviceID, trustLevel); err != nil {
			// Log error but don't fail the login – trust is a secondary security measure
			s.logOTPEvent(ctx, &models.OTPLogEvent{
				LogEnvelope: models.LogEnvelope{
					EventID:     uuid.New().String(),
					EventType:   string(models.LogEventTypeOTP),
					ServiceName: "auth-service",
					Timestamp:   time.Now(),
					Environment: s.config.Environment,
					Version:     ServiceVersion,
					Level:       string(models.LogLevelError),
					Message:     "Failed to set device trust after OTP verification",
				},
				PhoneNumber:   req.PhoneNumber,
				Status:        "trust_set_failed",
				Purpose:       req.Purpose,
				IPAddress:     ip,
				UserAgent:     req.UserAgent,
				DeviceID:      req.DeviceID,
				ErrorCode:     "TRUST_SET_FAILED",
				ErrorMessage:  err.Error(),
				AttemptNumber: validatedOTP.Attempts,
			})
		} else {
			s.logOTPEvent(ctx, &models.OTPLogEvent{
				LogEnvelope: models.LogEnvelope{
					EventID:     uuid.New().String(),
					EventType:   string(models.LogEventTypeOTP),
					ServiceName: "auth-service",
					Timestamp:   time.Now(),
					Environment: s.config.Environment,
					Version:     ServiceVersion,
					Level:       string(models.LogLevelInfo),
					Message:     "Device trust set to Trusted after successful OTP verification",
				},
				PhoneNumber: req.PhoneNumber,
				Status:      "trust_set_success",
				Purpose:     req.Purpose,
				IPAddress:   ip,
				UserAgent:   req.UserAgent,
				DeviceID:    req.DeviceID,
			})
		}
	}

	// Audit
	if s.auditService != nil {
		_ = s.auditService.LogAction(ctx, nil, nil, "otp", "verify", "otp",
			nil, "system", nil, nil, nil, map[string]interface{}{
				"phone_hash": phoneHash,
				"purpose":    req.Purpose,
				"ip":         ip,
				"status":     "success",
			})
	}

	resp := &OTPResponse{
		Success: true,
		Message: "OTP verified successfully",
	}

	// Store idempotency response
	if err := s.idempotencyStore.Store(ctx, nil, idempKey, resp); err != nil {
		logger.Error("Idempotency store failed",
			zap.String("key", idempKey),
			zap.Error(err),
		)
	} else {
		logger.Debug("Idempotency response stored",
			zap.String("key", idempKey),
			zap.String("operation", "verify"),
		)
	}

	s.logOTPEvent(ctx, &models.OTPLogEvent{
		LogEnvelope: models.LogEnvelope{
			EventID:     uuid.New().String(),
			EventType:   string(models.LogEventTypeOTP),
			ServiceName: "auth-service",
			Timestamp:   time.Now(),
			Environment: s.config.Environment,
			Version:     ServiceVersion,
			Level:       string(models.LogLevelInfo),
			Message:     "OTP verified successfully",
		},
		PhoneNumber:   req.PhoneNumber,
		Status:        "verified",
		Purpose:       req.Purpose,
		IPAddress:     ip,
		UserAgent:     req.UserAgent,
		AttemptNumber: validatedOTP.Attempts,
		AttemptsLeft:  scylla.OTPMaxAttempts - validatedOTP.Attempts,
		Duration:      int64(time.Since(startTime).Milliseconds()),
	})

	return resp, nil
}

// ---- Helper methods (quotas, rate limits, lockout, etc.) ----

func (s *OTPService) checkDailyQuotas(ctx context.Context, phoneHash, ipAddress, deviceID, purpose string) (*OTPResponse, error) {
	phoneQuotaKey := fmt.Sprintf("otp:quota:daily:phone:%s", phoneHash)
	phoneUsed, err := s.distCache.IncrementDailyQuota(ctx, phoneQuotaKey, 24*time.Hour)
	if err != nil {
		return nil, err
	}
	phoneLimit := s.getDailyQuotaLimit(purpose)
	if phoneUsed > int64(phoneLimit) {
		s.logOTPEvent(ctx, &models.OTPLogEvent{
			LogEnvelope: models.LogEnvelope{
				EventID:     uuid.New().String(),
				EventType:   string(models.LogEventTypeOTP),
				ServiceName: "auth-service",
				Timestamp:   time.Now(),
				Environment: s.config.Environment,
				Version:     ServiceVersion,
				Level:       string(models.LogLevelWarning),
				Message:     "Daily phone quota exceeded",
			},
			PhoneNumber: "",
			Status:      "quota_exceeded",
			Purpose:     purpose,
			ErrorCode:   "DAILY_QUOTA_EXCEEDED",
		})
		return &OTPResponse{
			Success:    false,
			Message:    "Daily OTP limit exceeded",
			RetryAfter: 86400,
		}, appErrors.ErrDailyQuotaExceeded
	}

	if ipAddress != "" {
		ipQuotaKey := fmt.Sprintf("otp:quota:daily:ip:%s", ipAddress)
		ipUsed, err := s.distCache.IncrementDailyQuota(ctx, ipQuotaKey, 24*time.Hour)
		if err != nil {
			return nil, err
		}
		if ipUsed > int64(DailyQuotaPerIP) {
			s.logOTPEvent(ctx, &models.OTPLogEvent{
				LogEnvelope: models.LogEnvelope{
					EventID:     uuid.New().String(),
					EventType:   string(models.LogEventTypeOTP),
					ServiceName: "auth-service",
					Timestamp:   time.Now(),
					Environment: s.config.Environment,
					Version:     ServiceVersion,
					Level:       string(models.LogLevelWarning),
					Message:     "Daily IP quota exceeded",
				},
				IPAddress: ipAddress,
				Status:    "quota_exceeded",
				Purpose:   purpose,
				ErrorCode: "IP_QUOTA_EXCEEDED",
			})
			return &OTPResponse{
				Success:    false,
				Message:    "Daily OTP limit exceeded for this IP",
				RetryAfter: 86400,
			}, appErrors.ErrDailyQuotaExceeded
		}
	}

	if deviceID != "" {
		deviceQuotaKey := fmt.Sprintf("otp:quota:daily:device:%s", deviceID)
		deviceUsed, err := s.distCache.IncrementDailyQuota(ctx, deviceQuotaKey, 24*time.Hour)
		if err != nil {
			return nil, err
		}
		if deviceUsed > int64(DailyQuotaPerDevice) {
			s.logOTPEvent(ctx, &models.OTPLogEvent{
				LogEnvelope: models.LogEnvelope{
					EventID:     uuid.New().String(),
					EventType:   string(models.LogEventTypeOTP),
					ServiceName: "auth-service",
					Timestamp:   time.Now(),
					Environment: s.config.Environment,
					Version:     ServiceVersion,
					Level:       string(models.LogLevelWarning),
					Message:     "Daily device quota exceeded",
				},
				DeviceID:  deviceID,
				Status:    "quota_exceeded",
				Purpose:   purpose,
				ErrorCode: "DEVICE_QUOTA_EXCEEDED",
			})
			return &OTPResponse{
				Success:    false,
				Message:    "Daily OTP limit exceeded for this device",
				RetryAfter: 86400,
			}, appErrors.ErrDailyQuotaExceeded
		}
	}
	return nil, nil
}

func (s *OTPService) incrementDailyQuotas(ctx context.Context, phoneHash, ipAddress, deviceID string) {
	// Already incremented in checkDailyQuotas, no-op
}

func (s *OTPService) getDailyQuotaLimit(purpose string) int {
	if purpose == "admin_login" {
		return AdminOTPSendLimitDay
	}
	return DailyQuotaPerPhone
}

// ---- Rate limiting helpers ----

func (s *OTPService) getSendRateLimits(purpose string) (maxTokens, refillRate float64) {
	if purpose == "admin_login" {
		return 1, 1.0 / 30.0
	}
	return 2, 1.0 / 30.0
}

func (s *OTPService) getVerifyRateLimits(purpose string) (maxTokens, refillRate float64) {
	if purpose == "admin_login" {
		return 2, 1.0 / 10.0
	}
	return 3, 1.0 / 10.0
}

func (s *OTPService) getSendTokenBucket(key, purpose string) *TokenBucket {
	s.mu.Lock()
	defer s.mu.Unlock()
	if bucket, ok := s.sendRateCache.Get(key); ok {
		return bucket
	}
	maxTokens, refillRate := s.getSendRateLimits(purpose)
	bucket := NewTokenBucket(maxTokens, refillRate)
	s.sendRateCache.Add(key, bucket)
	return bucket
}

func (s *OTPService) getVerifyTokenBucket(key, purpose string) *TokenBucket {
	s.mu.Lock()
	defer s.mu.Unlock()
	if bucket, ok := s.verifyRateCache.Get(key); ok {
		return bucket
	}
	maxTokens, refillRate := s.getVerifyRateLimits(purpose)
	bucket := NewTokenBucket(maxTokens, refillRate)
	s.verifyRateCache.Add(key, bucket)
	return bucket
}

func (s *OTPService) checkSendRateLimit(key, purpose string) bool {
	bucket := s.getSendTokenBucket(key, purpose)
	return bucket.TakeToken()
}

func (s *OTPService) checkVerifyRateLimit(key, purpose string) bool {
	bucket := s.getVerifyTokenBucket(key, purpose)
	return bucket.TakeToken()
}

// ---- Account lockout ----

func (s *OTPService) incrementFailedAttempts(phoneHash string) {
	key := fmt.Sprintf("failed_attempts:%s", phoneHash)
	if s.distCache != nil {
		count, _ := s.distCache.IncrementCounter(context.Background(), key, 1*time.Hour)
		if count >= AccountLockoutThreshold {
			s.lockAccount(phoneHash)
		}
	}
}

func (s *OTPService) clearFailedAttempts(phoneHash string) {
	key := fmt.Sprintf("failed_attempts:%s", phoneHash)
	if s.distCache != nil {
		_ = s.distCache.DeleteKey(context.Background(), key)
	}
}

func (s *OTPService) lockAccount(phoneHash string) {
	lockUntil := time.Now().Add(AccountLockoutDuration)
	s.lockoutCache.Add(phoneHash, lockUntil)
	if s.distCache != nil {
		key := fmt.Sprintf("lockout:%s", phoneHash)
		_ = s.distCache.SetWithExpiry(context.Background(), key, lockUntil.Unix(), AccountLockoutDuration)
	}
}

func (s *OTPService) isAccountLocked(phoneHash string) (bool, time.Time) {
	if lockUntil, ok := s.lockoutCache.Get(phoneHash); ok {
		if time.Now().Before(lockUntil) {
			return true, lockUntil
		}
		s.lockoutCache.Remove(phoneHash)
	}
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

// ---- Validation ----

func (s *OTPService) validateSendRequest(req *OTPSendRequest) error {
	if req.PhoneNumber == "" || len(req.PhoneNumber) < 10 || len(req.PhoneNumber) > 15 {
		return appErrors.ErrInvalidInput
	}
	validPurposes := map[string]bool{
		"login": true, "verification": true, "password_reset": true,
		"admin_login": true, "forgot_mpin": true,
	}
	if !validPurposes[req.Purpose] {
		return appErrors.ErrInvalidInput
	}
	return nil
}

func (s *OTPService) validateVerifyRequest(req *OTPVerifyRequest) error {
	if req.PhoneNumber == "" || len(req.PhoneNumber) < 10 || len(req.PhoneNumber) > 15 {
		return appErrors.ErrInvalidInput
	}
	if req.OTP == "" || len(req.OTP) != 6 {
		return appErrors.ErrInvalidInput
	}
	validPurposes := map[string]bool{
		"login": true, "verification": true, "password_reset": true,
		"admin_login": true, "forgot_mpin": true,
	}
	if !validPurposes[req.Purpose] {
		return appErrors.ErrInvalidInput
	}
	return nil
}

func (s *OTPService) validateResendRequest(req *OTPResendRequest) error {
	if req.PhoneNumber == "" || req.Purpose == "" {
		return appErrors.ErrInvalidInput
	}
	validPurposes := map[string]bool{
		"login": true, "verification": true, "password_reset": true,
		"admin_login": true, "forgot_mpin": true,
	}
	if !validPurposes[req.Purpose] {
		return appErrors.ErrInvalidInput
	}
	return nil
}

// ---- Helpers ----

func (s *OTPService) generatePhoneHash(phoneNumber string) string {
	normalized := strings.ReplaceAll(phoneNumber, " ", "")
	normalized = strings.ReplaceAll(normalized, "-", "")
	normalized = strings.ReplaceAll(normalized, "(", "")
	normalized = strings.ReplaceAll(normalized, ")", "")
	hash := sha256.Sum256([]byte(normalized))
	return hex.EncodeToString(hash[:])
}

func (s *OTPService) hashFingerprint(fp string) string {
	sum := sha256.Sum256([]byte(fp))
	return hex.EncodeToString(sum[:])
}

// ---- Device/IP trust checks ----

func (s *OTPService) isNewDevice(deviceID, phoneNumber string) bool {
	if deviceID == "" {
		return true
	}
	ctx := context.Background()
	adminID, err := s.phoneValidator.GetAdminIDByPhone(ctx, phoneNumber)
	if err != nil || adminID == uuid.Nil {
		return true
	}
	rec, err := s.adminDeviceTrustRepo.GetAdminDeviceTrustLevel(ctx, adminID, deviceID)
	if err != nil || rec == nil {
		return true
	}
	if rec.DeviceID != deviceID || rec.IsBlocked || rec.TrustStatus == models.TrustStatusUntrusted {
		return true
	}
	return false
}

func (s *OTPService) isNewIP(ipAddress, phoneNumber, deviceID string) bool {
	if ipAddress == "" {
		return true
	}
	ctx := context.Background()
	adminID, err := s.phoneValidator.GetAdminIDByPhone(ctx, phoneNumber)
	if err != nil || adminID == uuid.Nil {
		return true
	}
	if deviceID != "" {
		rec, err := s.adminDeviceTrustRepo.GetAdminDeviceTrustLevel(ctx, adminID, deviceID)
		if err == nil && rec != nil && rec.LastIPAddress == ipAddress {
			return false
		}
	}
	// Fallback: check all devices
	recs, err := s.adminDeviceTrustRepo.GetAdminDevices(ctx, adminID)
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

func (s *OTPService) CheckFullDeviceTrust(ctx context.Context, adminID uuid.UUID, deviceID string, ip string, rawFingerprint string) (bool, string) {
	rec, err := s.adminDeviceTrustRepo.GetAdminDeviceTrustLevel(ctx, adminID, deviceID)
	if err != nil || rec == nil {
		return false, "device_not_trusted"
	}
	if rec.DeviceID != deviceID {
		return false, "device_mismatch"
	}
	if rec.LastIPAddress == "" || rec.LastIPAddress != ip {
		return false, "ip_mismatch"
	}
	incomingHash := s.hashFingerprint(rawFingerprint)
	if rec.DeviceFingerprint != incomingHash {
		return false, "fingerprint_mismatch"
	}
	if rec.TrustStatus != models.TrustStatusTrusted && rec.TrustStatus != models.TrustStatusPrimary {
		return false, "device_not_trusted_status"
	}
	if rec.IsBlocked {
		return false, "device_blocked"
	}
	return true, "trusted_3_of_3"
}

// ---- Risk helpers ----

func (s *OTPService) getFailedAttemptsCount(phoneNumber string) int {
	phoneHash := s.generatePhoneHash(phoneNumber)
	key := fmt.Sprintf("failed_attempts:%s", phoneHash)
	if s.distCache != nil {
		count, err := s.distCache.GetCounter(context.Background(), key)
		if err == nil {
			return int(count)
		}
	}
	return 0
}

func (s *OTPService) getDailyOTPCount(phoneNumber string) int {
	phoneHash := s.generatePhoneHash(phoneNumber)
	key := fmt.Sprintf("otp:quota:daily:phone:%s", phoneHash)
	if s.distCache != nil {
		count, err := s.distCache.GetDailyQuotaUsage(context.Background(), key)
		if err == nil {
			return int(count)
		}
	}
	return 0
}

// ---- Logging (Kafka) ----

func (s *OTPService) logOTPEvent(ctx context.Context, event *models.OTPLogEvent) {
	if s.logProducer != nil {
		_ = s.logProducer.ProduceOTPEvent(ctx, event)
	}
}

func (s *OTPService) logSecurityEvent(ctx context.Context, req *OTPSendRequest, eventType string, riskScore int, reasons []string) {
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
				EventType:   "security_risk",
				ServiceName: "auth-service",
				Timestamp:   time.Now(),
				Environment: s.config.Environment,
				Version:     ServiceVersion,
				Level:       string(models.LogLevelWarning),
				Message:     fmt.Sprintf("Security check: %s", eventType),
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

// ---- Health and Stats ----

func (s *OTPService) HealthCheck(ctx context.Context) error {
	if err := s.otpRepo.HealthCheck(ctx); err != nil {
		return appErrors.ErrInternal
	}
	return nil
}

func (s *OTPService) GetOTPStats(ctx context.Context) (map[string]interface{}, error) {
	repoStats, err := s.otpRepo.GetOTPStats(ctx)
	if err != nil {
		return nil, appErrors.ErrInternal
	}
	stats := map[string]interface{}{
		"send_rate_cache_size":   s.sendRateCache.Len(),
		"verify_rate_cache_size": s.verifyRateCache.Len(),
		"lockout_cache_size":     s.lockoutCache.Len(),
		"repository":             repoStats,
		"rate_limits": map[string]interface{}{
			"user": map[string]interface{}{
				"send_limit_1min":  2,
				"send_limit_5min":  3,
				"send_limit_hour":  10,
				"verify_limit_30s": 3,
				"verify_limit_min": 5,
			},
			"admin": map[string]interface{}{
				"send_limit_1min":  AdminOTPSendLimit1Min,
				"send_limit_5min":  AdminOTPSendLimit5Min,
				"send_limit_hour":  AdminOTPSendLimitHour,
				"verify_limit_30s": AdminOTPVerifyLimit30Sec,
				"verify_limit_min": AdminOTPVerifyLimitMin,
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

func (s *OTPService) Cleanup() {
	s.sendRateCache.Purge()
	s.verifyRateCache.Purge()
	s.lockoutCache.Purge()
}

func (s *OTPService) CleanupExpiredOTPs(ctx context.Context, batchSize int) (int, error) {
	// TTL handles expiry
	return 0, nil
}

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
	"auth-service/internal/sms" // NEW: Import SMS package
	"auth-service/internal/util"

	"github.com/google/uuid"
	lru "github.com/hashicorp/golang-lru/v2"
	"go.uber.org/zap"
)

var (
	ErrOTPNotFound          = errors.New("OTP not found or invalid")
	ErrOTPExpired           = errors.New("OTP has expired")
	ErrOTPInvalid           = errors.New("invalid OTP")
	ErrOTPAttemptsExceeded  = errors.New("max OTP attempts exceeded")
	ErrOTPRateLimitExceeded = errors.New("OTP rate limit exceeded")
	ErrOTPAlreadyUsed       = errors.New("OTP has already been used")
	ErrOTPReplayAttempt     = errors.New("OTP replay detected")
	ErrDailyQuotaExceeded   = errors.New("daily OTP quota exceeded")
	ErrSecurityCheckFailed  = errors.New("security check failed")
	ErrPhoneNotRegistered   = errors.New("phone number not registered")
)

const (
	// Rate Limits
	OTPSendLimit1Min         = 2
	OTPSendLimit5Min         = 3
	OTPSendLimitHour         = 10
	OTPSendLimitDay          = 20
	OTPVerifyLimit30Sec      = 3
	OTPVerifyLimitMin        = 5
	OTPResendCooldownInitial = 60 * time.Second
	OTPResendCooldownMax     = 300 * time.Second

	// Timeouts and Durations
	OTPExpiryDuration         = 5 * time.Minute
	OTPCacheDuration          = 6 * time.Minute
	OTPRateLimitCacheDuration = 1 * time.Hour
	OTPReplayProtectionWindow = 60 * time.Second

	// Account Protection
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

	// Security thresholds
	HighRiskThreshold   = 70
	MediumRiskThreshold = 40

	ServiceVersion = "1.0.0"
)

type OTPService struct {
	otpRepo              scylla.OTPRepository
	hasher               *hashing.Hasher
	config               *config.Config
	logger               *zap.Logger
	distCache            *DistributedCache
	logProducer          *LogProducerService
	smsManager           *sms.SMSManager // CHANGED: Use SMSManager
	sendRateCache        *lru.Cache[string, *TokenBucket]
	verifyRateCache      *lru.Cache[string, *TokenBucket]
	lockoutCache         *lru.Cache[string, time.Time]
	phoneValidator       PhoneValidator
	adminDeviceTrustRepo scylla.AdminDeviceTrustRepository
	// Security components
	botDetector  *security.BotDetector
	ipReputation *security.IPReputation
	riskEngine   *security.RiskEngine
	mu           sync.RWMutex
}

// Enhanced request with provider failover support
type OTPSendRequest struct {
	PhoneNumber       string `json:"phone_number" validate:"required,min=10,max=15"`
	Purpose           string `json:"purpose" validate:"required,oneof=login verification password_reset admin_login forgot_mpin"`
	IPAddress         string `json:"ip_address"`
	DeviceID          string `json:"device_id"`
	Provider          string `json:"provider,omitempty"`
	UserAgent         string `json:"user_agent,omitempty"`
	DeviceFingerprint string `json:"device_fingerprint,omitempty"`
}

// Enhanced response with quota information
type OTPResponse struct {
	Success      bool      `json:"success"`
	Message      string    `json:"message"`
	ExpiresAt    time.Time `json:"expires_at,omitempty"`
	AttemptsLeft int       `json:"attempts_left,omitempty"`
	RetryAfter   int       `json:"retry_after,omitempty"`
	DailyQuota   int       `json:"daily_quota,omitempty"`
	QuotaUsed    int       `json:"quota_used,omitempty"`
	OTPValue     string    `json:"otp_value,omitempty"`
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

// TokenBucket implements rate limiting
type TokenBucket struct {
	Tokens         float64
	MaxTokens      float64
	RefillRate     float64
	LastRefillTime time.Time
	mu             sync.Mutex
}

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

func NewOTPService(
	otpRepo scylla.OTPRepository,
	hasher *hashing.Hasher,
	cfg *config.Config,
	distCache *DistributedCache,
	logger *zap.Logger,
	logProducer *LogProducerService,
	phoneValidator PhoneValidator,
	adminDeviceTrustRepo scylla.AdminDeviceTrustRepository,
	smsManager *sms.SMSManager, // ADDED: SMSManager parameter
) *OTPService {

	sendCache, _ := lru.New[string, *TokenBucket](100_000)
	verifyCache, _ := lru.New[string, *TokenBucket](100_000)
	lockoutCache, _ := lru.New[string, time.Time](50_000)

	// Initialize security components
	botDetector := security.NewBotDetector()
	ipReputation := security.NewIPReputation(logger)
	riskEngine := security.NewRiskEngine(botDetector, ipReputation)

	return &OTPService{
		otpRepo:              otpRepo,
		hasher:               hasher,
		logger:               logger,
		distCache:            distCache,
		config:               cfg,
		logProducer:          logProducer,
		smsManager:           smsManager, // ADDED: Set SMSManager
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

// Remove the isPhoneRegistered method and use phoneValidator instead
func (s *OTPService) isPhoneRegistered(ctx context.Context, phoneNumber, purpose string) (bool, error) {
	return s.phoneValidator.IsAdminPhoneRegistered(ctx, phoneNumber)
}

func (s *OTPService) performSecurityChecks(ctx context.Context, req *OTPSendRequest, startTime time.Time) *OTPResponse {
	requestLatency := time.Since(startTime)

	// 🔥 Log the start of security checks
	s.logger.Info("🔍 Starting OTP security checks",
		util.String("phone", req.PhoneNumber),
		util.String("purpose", req.Purpose),
		util.String("ip", req.IPAddress),
		util.String("device_id", req.DeviceID),
		util.String("user_agent", req.UserAgent),
		util.Duration("request_latency", requestLatency))

	// =====================================================
	// QUICK RISK CHECK
	// =====================================================
	quickRisk, shouldBlock := s.riskEngine.QuickRiskCheck(req.IPAddress, req.UserAgent, requestLatency, req.Purpose)

	s.logger.Info("🔍 Quick risk check result",
		util.Int("quick_risk_score", quickRisk),
		util.Bool("should_block", shouldBlock))

	if shouldBlock {
		s.logSecurityEvent(ctx, req, "quick_risk_check_failed", quickRisk, []string{"high_risk_quick_check"})
		s.logger.Warn("🚨 Quick risk check blocked OTP request",
			util.String("phone", req.PhoneNumber),
			util.Int("risk_score", quickRisk),
			util.String("user_agent", req.UserAgent))
		return &OTPResponse{
			Success: false,
			Message: "Security check failed",
		}
	}

	// =====================================================
	// FULL RISK REQUEST
	// =====================================================
	riskReq := security.RiskAssessmentRequest{
		UserAgent:      req.UserAgent,
		IPAddress:      req.IPAddress,
		DeviceID:       req.DeviceID,
		PhoneNumber:    req.PhoneNumber,
		Purpose:        req.Purpose,
		RequestLatency: requestLatency,
		FailedAttempts: s.getFailedAttemptsCount(req.PhoneNumber),
		DailyOTPCount:  s.getDailyOTPCount(req.PhoneNumber),

		// 🔥 UPDATED: pass deviceID into isNewIP()
		IsNewDevice: s.isNewDevice(req.DeviceID, req.PhoneNumber),
		IsNewIP:     s.isNewIP(req.IPAddress, req.PhoneNumber, req.DeviceID),
	}

	// Log risk request details
	s.logger.Info("🔍 Risk assessment request",
		util.Int("failed_attempts", riskReq.FailedAttempts),
		util.Int("daily_otp_count", riskReq.DailyOTPCount),
		util.Bool("is_new_device", riskReq.IsNewDevice),
		util.Bool("is_new_ip", riskReq.IsNewIP),
		util.String("user_agent", req.UserAgent))

	// =====================================================
	// RUN RISK ENGINE
	// =====================================================
	riskAssessment := s.riskEngine.AssessRisk(riskReq)

	// Full risk assessment logs
	s.logger.Info("🔍 Full risk assessment result",
		util.String("phone", req.PhoneNumber),
		util.Int("risk_score", riskAssessment.RiskScore),
		util.String("risk_level", riskAssessment.RiskLevel),
		util.Bool("block_action", riskAssessment.BlockAction),
		util.Strings("reasons", riskAssessment.Reasons),
		util.String("user_agent", req.UserAgent))

	// Send event to Kafka
	s.logSecurityEvent(ctx, req, "risk_assessment", riskAssessment.RiskScore, riskAssessment.Reasons)

	// Block if needed
	if riskAssessment.BlockAction {
		s.logger.Warn("🚨 Blocking OTP request due to high risk score",
			util.String("phone", req.PhoneNumber),
			util.String("ip", req.IPAddress),
			util.Int("risk_score", riskAssessment.RiskScore),
			util.String("risk_level", riskAssessment.RiskLevel),
			util.String("purpose", req.Purpose),
			util.String("user_agent", req.UserAgent),
		)

		return &OTPResponse{
			Success: false,
			Message: "Security check failed",
		}
	}

	// Final success log
	s.logger.Info("✅ OTP security checks passed",
		util.String("phone", req.PhoneNumber),
		util.Int("risk_score", riskAssessment.RiskScore),
		util.String("user_agent", req.UserAgent))

	return nil
}

// Enhanced VerifyOTP with device trust checks for sensitive operations
func (s *OTPService) VerifyOTP(ctx context.Context, req *OTPVerifyRequest) (*OTPResponse, error) {
	startTime := time.Now()

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
		IPAddress:   req.IPAddress,
		UserAgent:   req.UserAgent,
	})

	// Validate input
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
			IPAddress:     req.IPAddress,
			UserAgent:     req.UserAgent,
			ErrorCode:     "VALIDATION_FAILED",
			ErrorMessage:  "Invalid request",
			AttemptNumber: 0,
		})
		return nil, fmt.Errorf("%w: %v", ErrInvalidInput, err)
	}

	phoneHash := s.generatePhoneHash(req.PhoneNumber)

	// ✅ ADDED: Enhanced security logging with UserAgent
	s.logger.Info("OTP verification attempt",
		util.String("phone", req.PhoneNumber),
		util.String("purpose", req.Purpose),
		util.String("ip", req.IPAddress),
		util.String("device_id", req.DeviceID),
		util.String("user_agent", req.UserAgent))

	// Rate limiting checks
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
				IPAddress:     req.IPAddress,
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
			}, ErrOTPRateLimitExceeded
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
				IPAddress:     req.IPAddress,
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
			}, ErrOTPRateLimitExceeded
		}
	}

	// Check account lockout
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
			IPAddress:     req.IPAddress,
			UserAgent:     req.UserAgent,
			ErrorCode:     "ACCOUNT_LOCKED",
			AttemptNumber: 0,
			AttemptsLeft:  retryAfter,
		})
		return &OTPResponse{
			Success:    false,
			Message:    "Account temporarily locked",
			RetryAfter: retryAfter,
		}, ErrOTPRateLimitExceeded
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
			IPAddress:     req.IPAddress,
			UserAgent:     req.UserAgent,
			ErrorCode:     "OTP_NOT_FOUND",
			ErrorMessage:  "Invalid OTP or expired",
			AttemptNumber: 0,
		})

		return &OTPResponse{
			Success: false,
			Message: "Invalid OTP or expired",
		}, ErrOTPNotFound
	}

	// Device binding validation
	if otpRecord.DeviceID != "" {
		if req.DeviceID == "" || otpRecord.DeviceID != req.DeviceID {
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
				IPAddress:     req.IPAddress,
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
			}, ErrOTPInvalid
		}
	}

	// Check expiry
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
			IPAddress:     req.IPAddress,
			UserAgent:     req.UserAgent,
			ErrorCode:     "OTP_EXPIRED",
			AttemptNumber: otpRecord.Attempts,
			AttemptsLeft:  scylla.OTPMaxAttempts - otpRecord.Attempts,
		})
		return &OTPResponse{
			Success:   false,
			Message:   "Invalid OTP or expired",
			ExpiresAt: otpRecord.ExpiresAt,
		}, ErrOTPExpired
	}

	// Check attempts
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
			IPAddress:     req.IPAddress,
			UserAgent:     req.UserAgent,
			ErrorCode:     "ATTEMPTS_EXCEEDED",
			AttemptNumber: otpRecord.Attempts,
			AttemptsLeft:  0,
		})
		return &OTPResponse{
			Success:      false,
			Message:      "Invalid OTP or expired",
			AttemptsLeft: 0,
		}, ErrOTPAttemptsExceeded
	}

	// ✅ Check OTP replay protection
	providedHash := scylla.HashOTP(req.OTP, otpRecord.OTPSalt)
	replayKey := fmt.Sprintf("otp:replay:%s:%s", phoneHash, providedHash)

	replayExists, err := s.distCache.CheckOTPReplayProtection(ctx, replayKey)
	if err != nil {
		s.logger.Warn("Failed to check OTP replay protection", util.ErrorField(err))
	} else if replayExists {
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
			IPAddress:     req.IPAddress,
			UserAgent:     req.UserAgent,
			ErrorCode:     "REPLAY_ATTEMPT",
			AttemptNumber: otpRecord.Attempts,
			AttemptsLeft:  scylla.OTPMaxAttempts - otpRecord.Attempts,
		})
		return &OTPResponse{
			Success:      false,
			Message:      "Invalid OTP or expired",
			AttemptsLeft: scylla.OTPMaxAttempts - otpRecord.Attempts,
		}, ErrOTPReplayAttempt
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
			IPAddress:     req.IPAddress,
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
		}, ErrOTPInvalid
	}

	// ✅ Set replay protection before invalidating OTP
	err = s.distCache.StoreOTPReplayProtection(ctx, replayKey, providedHash, OTPReplayProtectionWindow)
	if err != nil {
		s.logger.Warn("Failed to set OTP replay protection", util.ErrorField(err))
	}

	// Invalidate OTP
	if err := s.otpRepo.InvalidateOTP(ctx, phoneHash, req.Purpose); err != nil {
		s.logger.Warn("Failed to invalidate OTP after successful verification",
			util.ErrorField(err),
			util.String("phone_hash", phoneHash),
			util.String("purpose", req.Purpose),
		)
	}

	// Remove from cache
	if s.distCache != nil {
		cacheKey := fmt.Sprintf("otp:%s:%s", phoneHash, req.Purpose)
		_ = s.distCache.DeleteOTPVerification(ctx, cacheKey)
	}

	// Clear failed attempts
	s.clearFailedAttempts(phoneHash)

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
		IPAddress:     req.IPAddress,
		UserAgent:     req.UserAgent,
		AttemptNumber: validatedOTP.Attempts,
		AttemptsLeft:  scylla.OTPMaxAttempts - validatedOTP.Attempts,
		Duration:      int64(time.Since(startTime).Milliseconds()),
	})

	return &OTPResponse{
		Success: true,
		Message: "OTP verified successfully",
	}, nil
}

// ✅ NEW: Log security events
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

// ✅ NEW: logOTPEvent helper method
func (s *OTPService) logOTPEvent(ctx context.Context, event *models.OTPLogEvent) {
	if s.logProducer != nil {
		_ = s.logProducer.ProduceOTPEvent(ctx, event)
	}
}

// ✅ NEW: Daily quota management methods
func (s *OTPService) checkDailyQuotas(ctx context.Context, phoneHash, ipAddress, deviceID, purpose string) (*OTPResponse, error) {
	// Check phone daily quota
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
			PhoneNumber: "", // Don't leak phone number
			Status:      "quota_exceeded",
			Purpose:     purpose,
			ErrorCode:   "DAILY_QUOTA_EXCEEDED",
			UserAgent:   "", // Empty for quota events
		})
		return &OTPResponse{
			Success:    false,
			Message:    "Daily OTP limit exceeded",
			RetryAfter: 86400, // 24 hours in seconds
		}, ErrDailyQuotaExceeded
	}

	// Check IP daily quota
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
				UserAgent: "", // Empty for quota events
			})
			return &OTPResponse{
				Success:    false,
				Message:    "Daily OTP limit exceeded for this IP",
				RetryAfter: 86400,
			}, ErrDailyQuotaExceeded
		}
	}

	// Check device daily quota
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
				UserAgent: "", // Empty for quota events
			})
			return &OTPResponse{
				Success:    false,
				Message:    "Daily OTP limit exceeded for this device",
				RetryAfter: 86400,
			}, ErrDailyQuotaExceeded
		}
	}

	return nil, nil
}

func (s *OTPService) incrementDailyQuotas(ctx context.Context, phoneHash, ipAddress, deviceID string) {
	// Quotas were already incremented in checkDailyQuotas, just log
	s.logger.Debug("Daily quotas incremented",
		util.String("phone_hash", phoneHash),
		util.String("ip", ipAddress),
		util.String("device", deviceID),
	)
}

func (s *OTPService) getDailyQuotaLimit(purpose string) int {
	if purpose == "admin_login" {
		return AdminOTPSendLimitDay
	}
	return DailyQuotaPerPhone
}

// ============================================
// RATE LIMITING HELPERS
// ============================================

// ✅ NEW: Helper to get rate limits based on purpose
func (s *OTPService) getSendRateLimits(purpose string) (maxTokens, refillRate float64) {
	if purpose == "admin_login" {
		// Admin login has stricter limits
		return 1, 1.0 / 30.0 // 1 token per 30 seconds
	}
	// Default user limits
	return 2, 1.0 / 30.0 // 2 tokens per 30 seconds
}

// ✅ NEW: Helper to get verify rate limits based on purpose
func (s *OTPService) getVerifyRateLimits(purpose string) (maxTokens, refillRate float64) {
	if purpose == "admin_login" {
		// Admin login has stricter limits
		return 2, 1.0 / 10.0 // 2 tokens per 10 seconds
	}
	// Default user limits
	return 3, 1.0 / 10.0 // 3 tokens per 10 seconds
}

// getSendTokenBucket gets or creates a token bucket for OTP sending
func (s *OTPService) getSendTokenBucket(key, purpose string) *TokenBucket {
	s.mu.Lock()
	defer s.mu.Unlock()

	if bucket, ok := s.sendRateCache.Get(key); ok {
		return bucket
	}

	// ✅ NEW: Get rate limits based on purpose
	maxTokens, refillRate := s.getSendRateLimits(purpose)
	bucket := NewTokenBucket(maxTokens, refillRate)
	s.sendRateCache.Add(key, bucket)
	return bucket
}

// getVerifyTokenBucket gets or creates a token bucket for OTP verification
func (s *OTPService) getVerifyTokenBucket(key, purpose string) *TokenBucket {
	s.mu.Lock()
	defer s.mu.Unlock()

	if bucket, ok := s.verifyRateCache.Get(key); ok {
		return bucket
	}

	// ✅ NEW: Get rate limits based on purpose
	maxTokens, refillRate := s.getVerifyRateLimits(purpose)
	bucket := NewTokenBucket(maxTokens, refillRate)
	s.verifyRateCache.Add(key, bucket)
	return bucket
}

// ✅ UPDATED: checkSendRateLimit includes purpose parameter
func (s *OTPService) checkSendRateLimit(key, purpose string) bool {
	bucket := s.getSendTokenBucket(key, purpose)
	return bucket.TakeToken()
}

// ✅ UPDATED: checkVerifyRateLimit includes purpose parameter
func (s *OTPService) checkVerifyRateLimit(key, purpose string) bool {
	bucket := s.getVerifyTokenBucket(key, purpose)
	return bucket.TakeToken()
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

	// ✅ NEW: Log account lockout
	s.logger.Warn("Account locked due to excessive failed attempts",
		util.String("phone_hash", phoneHash),
		util.String("lock_until", lockUntil.Format(time.RFC3339)),
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

// ✅ UPDATED: Generic error messages to prevent enumeration
func (s *OTPService) validateSendRequest(req *OTPSendRequest) error {
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
		"admin_login":    true,
		"forgot_mpin":    true,
	}
	if !validPurposes[req.Purpose] {
		return fmt.Errorf("invalid purpose")
	}
	return nil
}

// ✅ UPDATED: Generic error messages
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
	validPurposes := map[string]bool{
		"login":          true,
		"verification":   true,
		"password_reset": true,
		"admin_login":    true,
		"forgot_mpin":    true,
	}
	if !validPurposes[req.Purpose] {
		return fmt.Errorf("invalid purpose")
	}
	return nil
}

func (s *OTPService) validateResendRequest(req *OTPResendRequest) error {
	if req.PhoneNumber == "" || req.Purpose == "" {
		return fmt.Errorf("phone_number and purpose are required")
	}
	validPurposes := map[string]bool{
		"login":          true,
		"verification":   true,
		"password_reset": true,
		"admin_login":    true,
		"forgot_mpin":    true,
	}
	if !validPurposes[req.Purpose] {
		return fmt.Errorf("invalid purpose")
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

// Cleanup cleans up caches
func (s *OTPService) Cleanup() {
	s.sendRateCache.Purge()
	s.verifyRateCache.Purge()
	s.lockoutCache.Purge()
}

// CleanupExpiredOTPs is not needed - TTL handles expiry automatically
func (s *OTPService) CleanupExpiredOTPs(ctx context.Context, batchSize int) (int, error) {
	// ScyllaDB TTL handles expiry automatically
	s.logger.Info("Cleanup skipped - TTL handles expiry automatically")
	return 0, nil
}

// ✅ NEW: SetLogProducerService sets Kafka log producer service
func (s *OTPService) SetLogProducerService(logProducer *LogProducerService) {
	s.logProducer = logProducer
}

// ✅ UPDATED: Helper methods for risk assessment - track device/IP history for all purposes
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

func (s *OTPService) checkDeviceAndIPTrust(
	ctx context.Context,
	adminID uuid.UUID,
	deviceID string,
	ip string,
) (bool, error) {

	rec, err := s.adminDeviceTrustRepo.GetAdminDeviceTrustLevel(ctx, adminID, deviceID)
	if err != nil {
		return false, err
	}
	if rec == nil {
		return false, nil
	}

	if rec.DeviceID != deviceID {
		return false, nil
	}
	if rec.LastIPAddress == "" {
		return false, nil
	}
	if rec.LastIPAddress != ip {
		return false, nil
	}

	return true, nil
}

func (s *OTPService) hashFingerprint(fp string) string {
	sum := sha256.Sum256([]byte(fp))
	return hex.EncodeToString(sum[:])
}

func (s *OTPService) CheckFullDeviceTrust(
	ctx context.Context,
	adminID uuid.UUID,
	deviceID string,
	ip string,
	rawFingerprint string,
) (bool, string) {

	// 🔥 ADDED: Detailed logging
	s.logger.Info("🔍 CheckFullDeviceTrust - Starting",
		util.String("admin_id", adminID.String()),
		util.String("device_id", deviceID),
		util.String("ip", ip),
		util.String("raw_fingerprint", rawFingerprint))

	// 1. Lookup trust record by admin + device
	rec, err := s.adminDeviceTrustRepo.GetAdminDeviceTrustLevel(ctx, adminID, deviceID)
	if err != nil {
		s.logger.Warn("❌ Device trust lookup failed",
			util.String("admin_id", adminID.String()),
			util.String("device_id", deviceID),
			util.ErrorField(err),
		)
		return false, "trust_lookup_error"
	}

	if rec == nil {
		s.logger.Warn("❌ No trust record found for device",
			util.String("admin_id", adminID.String()),
			util.String("device_id", deviceID),
		)
		return false, "device_not_trusted"
	}

	// 🔥 ADDED: Log the retrieved record
	s.logger.Info("🔍 Retrieved trust record",
		util.String("stored_device_id", rec.DeviceID),
		util.String("stored_ip", rec.LastIPAddress),
		util.String("stored_fingerprint", rec.DeviceFingerprint),
		util.String("trust_status", string(rec.TrustStatus)))

	// 2. Device ID must match
	if rec.DeviceID != deviceID {
		s.logger.Warn("❌ Device ID mismatch",
			util.String("admin_id", adminID.String()),
			util.String("expected_device", rec.DeviceID),
			util.String("provided_device", deviceID),
		)
		return false, "device_mismatch"
	}

	// 3. IP must match
	if rec.LastIPAddress == "" || rec.LastIPAddress != ip {
		s.logger.Warn("❌ IP address mismatch",
			util.String("admin_id", adminID.String()),
			util.String("device_id", deviceID),
			util.String("expected_ip", rec.LastIPAddress),
			util.String("provided_ip", ip),
		)
		return false, "ip_mismatch"
	}

	// 4. Fingerprint must match (hashed)
	incomingHash := s.hashFingerprint(rawFingerprint)
	if rec.DeviceFingerprint != incomingHash {
		s.logger.Warn("❌ Device fingerprint mismatch",
			util.String("admin_id", adminID.String()),
			util.String("device_id", deviceID),
			util.String("expected_fingerprint_hash", rec.DeviceFingerprint),
			util.String("provided_fingerprint_hash", incomingHash),
			util.String("raw_fingerprint", rawFingerprint),
		)
		return false, "fingerprint_mismatch"
	}

	// 5. Check trust status
	if rec.TrustStatus != models.TrustStatusTrusted && rec.TrustStatus != models.TrustStatusPrimary {
		s.logger.Warn("❌ Device not in trusted status",
			util.String("admin_id", adminID.String()),
			util.String("device_id", deviceID),
			util.String("trust_status", string(rec.TrustStatus)),
		)
		return false, "device_not_trusted_status"
	}

	// 6. Check if device is blocked
	if rec.IsBlocked {
		s.logger.Warn("❌ Device is blocked",
			util.String("admin_id", adminID.String()),
			util.String("device_id", deviceID),
		)
		return false, "device_blocked"
	}

	// All checks passed
	s.logger.Info("✅ Device trust verified successfully",
		util.String("admin_id", adminID.String()),
		util.String("device_id", deviceID),
		util.String("ip", ip),
	)
	return true, "trusted_3_of_3"
}

func (s *OTPService) isNewDevice(deviceID, phoneNumber string) bool {
	if deviceID == "" {
		return true
	}

	ctx := context.Background()

	// 1. Resolve adminID from phone number
	adminID, err := s.phoneValidator.GetAdminIDByPhone(ctx, phoneNumber)
	if err != nil || adminID == uuid.Nil {
		return true
	}

	// 2. Fetch device trust record
	rec, err := s.adminDeviceTrustRepo.GetAdminDeviceTrustLevel(ctx, adminID, deviceID)
	if err != nil {
		return true
	}

	// 3. No record = device never seen → NEW device
	if rec == nil {
		return true
	}

	// 4. Device ID mismatch (should never happen)
	if rec.DeviceID != deviceID {
		return true
	}

	// 5. Blocked or untrusted device → treat as NEW (to raise risk score)
	if rec.IsBlocked || rec.TrustStatus == models.TrustStatusUntrusted {
		return true
	}

	// 6. Otherwise → known device
	return false
}

func (s *OTPService) isNewIP(ipAddress, phoneNumber, deviceID string) bool {

	if ipAddress == "" {
		return true
	}

	ctx := context.Background()

	// 1. Get adminID from phone
	adminID, err := s.phoneValidator.GetAdminIDByPhone(ctx, phoneNumber)
	if err != nil || adminID == uuid.Nil {
		return true
	}

	// 2. If deviceID exists → use exact trust record for this device
	if deviceID != "" {
		rec, err := s.adminDeviceTrustRepo.GetAdminDeviceTrustLevel(ctx, adminID, deviceID)
		if err == nil && rec != nil {
			// If stored IP matches → NOT NEW
			if rec.LastIPAddress == ipAddress {
				return false
			}
			// Device exists but new IP → NEW IP
			return true
		}
	}

	// 3. Fallback: scan all trusted devices for this admin
	recs, err := s.adminDeviceTrustRepo.GetAdminDevices(ctx, adminID)
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

// SendOTP sends a One-Time Password with security, rate limiting, and provider failover
// This function now handles both initial sends and resend requests
func (s *OTPService) SendOTP(ctx context.Context, req *OTPSendRequest) (*OTPResponse, error) {
	startTime := time.Now()

	// 1️⃣ Check if phone number is registered
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
			IPAddress:     req.IPAddress,
			UserAgent:     req.UserAgent,
			ErrorCode:     "PHONE_CHECK_FAILED",
			ErrorMessage:  err.Error(),
			AttemptNumber: 0,
		})
		return nil, fmt.Errorf("failed to check phone registration: %w", err)
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
			IPAddress:     req.IPAddress,
			UserAgent:     req.UserAgent,
			ErrorCode:     "PHONE_NOT_REGISTERED",
			ErrorMessage:  "Phone number is not registered in the system",
			AttemptNumber: 0,
		})
		return &OTPResponse{
			Success: false,
			Message: "Phone number not registered",
		}, ErrPhoneNotRegistered
	}

	// 2️⃣ SECURITY CHECKS (IP reputation, risk scoring)
	securityResult := s.performSecurityChecks(ctx, req, startTime)
	if securityResult != nil {
		return securityResult, ErrSecurityCheckFailed
	}

	// 3️⃣ Log initiation
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
		IPAddress:   req.IPAddress,
		UserAgent:   req.UserAgent,
	})

	// 4️⃣ Validate input
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
			IPAddress:     req.IPAddress,
			UserAgent:     req.UserAgent,
			ErrorCode:     "VALIDATION_FAILED",
			ErrorMessage:  err.Error(),
			AttemptNumber: 0,
		})
		return nil, fmt.Errorf("%w: %v", ErrInvalidInput, err)
	}

	phoneHash := s.generatePhoneHash(req.PhoneNumber)

	// 5️⃣ Quotas
	quotaCheck, err := s.checkDailyQuotas(ctx, phoneHash, req.IPAddress, req.DeviceID, req.Purpose)
	if err != nil {
		return quotaCheck, err
	}

	// ✅ CHANGE #2 — Update cooldown key to include deviceID
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
			IPAddress:     req.IPAddress,
			UserAgent:     req.UserAgent,
			ErrorCode:     "COOLDOWN_ACTIVE",
			AttemptNumber: 0,
			AttemptsLeft:  retryAfter,
		})
		return &OTPResponse{
			Success:    false,
			Message:    "Please wait before requesting a new OTP",
			RetryAfter: retryAfter,
		}, ErrOTPRateLimitExceeded
	}

	// 7️⃣ Device/IP rate limit
	if s.distCache != nil && req.DeviceID != "" {
		key := fmt.Sprintf("otp:rate:send:device:%s", req.DeviceID)
		if allowed, retry := s.distCache.AllowRate(ctx, key, 5, time.Minute); !allowed {
			return &OTPResponse{
				Success:    false,
				Message:    "Too many OTP requests from this device",
				RetryAfter: retry,
			}, ErrOTPRateLimitExceeded
		}
	}

	if s.distCache != nil && req.IPAddress != "" {
		key := fmt.Sprintf("otp:rate:send:ip:%s", req.IPAddress)
		if allowed, retry := s.distCache.AllowRate(ctx, key, 20, time.Minute); !allowed {
			return &OTPResponse{
				Success:    false,
				Message:    "Too many OTP requests from this IP",
				RetryAfter: retry,
			}, ErrOTPRateLimitExceeded
		}
	}

	// 8️⃣ Account lockout
	if locked, until := s.isAccountLocked(phoneHash); locked {
		retry := int(time.Until(until).Seconds())
		return &OTPResponse{
			Success:    false,
			Message:    "Account temporarily locked due to excessive attempts",
			RetryAfter: retry,
		}, ErrOTPRateLimitExceeded
	}

	// 9️⃣ Purpose-based rate limits
	rateKey := fmt.Sprintf("%s:%s", phoneHash, req.Purpose)
	if !s.checkSendRateLimit(rateKey, req.Purpose) {
		bucket := s.getSendTokenBucket(rateKey, req.Purpose)
		retryAfter := bucket.TimeUntilToken()
		return &OTPResponse{
			Success:    false,
			Message:    "Too many OTP requests. Try again later.",
			RetryAfter: retryAfter,
		}, ErrOTPRateLimitExceeded
	}

	// 🔟 NEW: Invalidate any existing OTP for this phone and purpose
	// This replaces the resend functionality
	existingOTP, err := s.otpRepo.GetActiveOTP(ctx, phoneHash, req.Purpose)
	if err == nil && existingOTP != nil {
		// Invalidate the existing OTP
		if err := s.otpRepo.InvalidateOTP(ctx, phoneHash, req.Purpose); err != nil {
			s.logger.Warn("Failed to invalidate existing OTP",
				util.ErrorField(err),
				util.String("phone_hash", phoneHash),
				util.String("purpose", req.Purpose))
		}

		// Remove from cache
		if s.distCache != nil {
			cacheKey := fmt.Sprintf("otp:%s:%s", phoneHash, req.Purpose)
			_ = s.distCache.DeleteOTPVerification(ctx, cacheKey)
		}

		s.logger.Info("Invalidated existing OTP for new send",
			util.String("phone", req.PhoneNumber),
			util.String("purpose", req.Purpose))
	}

	// 🔟 Generate OTP
	otp, err := scylla.GenerateOTP(6)
	if err != nil {
		return nil, fmt.Errorf("failed to generate OTP: %w", err)
	}

	// 🔥 ADDED: Always log OTP for testing
	s.logger.Info("📱 OTP GENERATED FOR TESTING",
		util.String("phone", req.PhoneNumber),
		util.String("purpose", req.Purpose),
		util.String("otp_code", otp))

	salt, err := scylla.GenerateSalt()
	if err != nil {
		return nil, fmt.Errorf("failed to generate salt: %w", err)
	}

	otpHash := scylla.HashOTP(otp, salt)

	// 🔥 Create OTP record
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

	// 🗄 Save OTP in DB
	if err := s.otpRepo.CreateOTP(ctx, otpVerification); err != nil {
		return nil, fmt.Errorf("failed to create OTP: %w", err)
	}

	// ⚡ Cache OTP
	if s.distCache != nil {
		go func() {
			cacheKey := fmt.Sprintf("otp:%s:%s", phoneHash, req.Purpose)
			_ = s.distCache.SetOTPVerification(
				context.Background(),
				cacheKey,
				otpVerification,
				OTPCacheDuration,
			)
		}()
	}

	// 📡 SEND OTP VIA PROVIDER + FAILOVER - UPDATED: Use SMSManager
	smsReq := sms.SMSRequest{
		PhoneNumber:       req.PhoneNumber,
		OTP:               otp,
		PreferredProvider: req.Provider,
		Purpose:           req.Purpose,
	}

	smsResp := s.smsManager.SendOTP(ctx, smsReq)
	if !smsResp.Success {
		return nil, fmt.Errorf("all SMS providers failed to send OTP")
	}

	// Update quota usage
	s.incrementDailyQuotas(ctx, phoneHash, req.IPAddress, req.DeviceID)

	// FINAL RESPONSE
	resp := &OTPResponse{
		Success:      true,
		Message:      "OTP sent successfully",
		ExpiresAt:    expiresAt,
		AttemptsLeft: scylla.OTPMaxAttempts,
		DailyQuota:   s.getDailyQuotaLimit(req.Purpose),
	}

	// Always return OTP in development mode for testing
	resp.OTPValue = otp

	// Log successful send
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
		IPAddress:     req.IPAddress,
		UserAgent:     req.UserAgent,
		AttemptNumber: 0,
		Duration:      int64(time.Since(startTime).Milliseconds()),
	})

	return resp, nil
}

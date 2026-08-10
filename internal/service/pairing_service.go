package service

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"time"

	"github.com/google/uuid"

	"auth-service/internal/config"
	appErrors "auth-service/internal/errors"
	"auth-service/internal/infrastructure/audit"
	"auth-service/internal/infrastructure/idempotency"
	"auth-service/internal/models"
	"auth-service/internal/repository/redis"
	"auth-service/internal/util"
)

// PairingService handles QR-based device pairing for both users and admins.
type PairingService struct {
	pairingRepo      redis.PairingRepository
	sessionService   *SessionService
	qrUtil           *util.QRUtil
	config           *config.Config
	auditService     *audit.AuditService
	idempotencyStore idempotency.Store
}

// NewPairingService creates a new PairingService.
func NewPairingService(
	pairingRepo redis.PairingRepository,
	sessionService *SessionService,
	qrUtil *util.QRUtil,
	config *config.Config,
	auditService *audit.AuditService,
	idempotencyStore idempotency.Store,
) *PairingService {
	return &PairingService{
		pairingRepo:      pairingRepo,
		sessionService:   sessionService,
		qrUtil:           qrUtil,
		config:           config,
		auditService:     auditService,
		idempotencyStore: idempotencyStore,
	}
}

// --------------------------------------------------------------------
// REQUEST / RESPONSE MODELS
// --------------------------------------------------------------------

type GenerateQRRequest struct {
	IPAddress string `json:"ip_address"`
	UserAgent string `json:"user_agent"`
}

type GenerateQRResponse struct {
	SessionID string `json:"session_id"`
	QRCode    string `json:"qr_code"`
	ExpiresIn int64  `json:"expires_in"`
	StatusURL string `json:"status_url"`
}

// PairRequest is used to pair a device (scanned from mobile).
type PairRequest struct {
	SessionID   string   `json:"session_id"`
	QRData      string   `json:"qr_data"`
	UserID      string   `json:"user_id"`
	PhoneNumber string   `json:"phone_number"`
	DeviceID    string   `json:"device_id"`
	SessionType string   `json:"session_type"` // "user" or "admin"
	Role        string   `json:"role"`         // role string (e.g., "super_admin", "owner", "employee")
	Permissions []string `json:"permissions"`  // admin permissions (for admin sessions)
	CompanyID   string   `json:"company_id"`   // 👈 NEW: company ID from authenticated user
}

// --------------------------------------------------------------------
// GENERATE QR
// --------------------------------------------------------------------

func (s *PairingService) GenerateQRCode(ctx context.Context, req *GenerateQRRequest) (*GenerateQRResponse, error) {
	sessionID := uuid.New().String()
	webDeviceID := generateWebDeviceID(req.UserAgent, req.IPAddress)

	qrData, nonce, err := s.qrUtil.GenerateQRCode(sessionID)
	if err != nil {
		return nil, fmt.Errorf("%w: QR generation failed", appErrors.ErrInternal)
	}

	session := &models.PairingSession{
		SessionID:   sessionID,
		Status:      "pending",
		Nonce:       nonce,
		QRPayload:   qrData,
		CreatedAt:   time.Now(),
		ExpiresAt:   time.Now().Add(10 * time.Minute),
		IPAddress:   req.IPAddress,
		UserAgent:   req.UserAgent,
		WebDeviceID: webDeviceID,
	}

	if err := s.pairingRepo.CreatePairingSession(ctx, session); err != nil {
		return nil, fmt.Errorf("%w: %v", appErrors.ErrInternal, err)
	}

	// Audit: QR generated
	if s.auditService != nil {
		_ = s.auditService.LogAction(ctx, nil, nil, "pairing", "generate_qr", "pairing_session",
			nil, "system", nil, nil, nil, map[string]interface{}{
				"session_id":    sessionID,
				"web_device_id": webDeviceID,
				"ip":            req.IPAddress,
				"user_agent":    req.UserAgent,
			})
	}

	return &GenerateQRResponse{
		SessionID: sessionID,
		QRCode:    qrData,
		ExpiresIn: 600,
		StatusURL: "/web/login/status?session_id=" + sessionID,
	}, nil
}

// --------------------------------------------------------------------
// PAIR DEVICE (mobile scans QR and sends user/admin data)
// --------------------------------------------------------------------

func (s *PairingService) PairDevice(ctx context.Context, req *PairRequest) error {
	// Validate QR code
	qrPayload, err := s.qrUtil.ParseQRCode(req.QRData)
	if err != nil {
		return fmt.Errorf("%w: invalid QR code", appErrors.ErrInvalidInput)
	}
	if qrPayload.SessionID != req.SessionID {
		return fmt.Errorf("%w: session mismatch", appErrors.ErrInvalidInput)
	}

	// Check session exists
	_, err = s.pairingRepo.GetPairingSession(ctx, req.SessionID)
	if err != nil {
		return fmt.Errorf("%w: %v", appErrors.ErrNotFound, err)
	}

	// Store user/admin data in redis (marks session as "scanned")
	// Pass companyID to repository
	err = s.pairingRepo.ScanPairingSession(
		ctx,
		req.SessionID,
		req.UserID,
		req.PhoneNumber,
		req.DeviceID,
		req.SessionType,
		req.Role,
		req.Permissions,
		req.CompanyID, // 👈 NEW
	)
	if err != nil {
		return fmt.Errorf("%w: %v", appErrors.ErrInternal, err)
	}

	// Audit: device paired
	if s.auditService != nil {
		ip, _ := ctx.Value("ip_address").(string)
		_ = s.auditService.LogAction(ctx, nil, nil, "pairing", "pair_device", "pairing_session",
			nil, "system", nil, nil, nil, map[string]interface{}{
				"session_id":   req.SessionID,
				"user_id":      req.UserID,
				"session_type": req.SessionType,
				"role":         req.Role,
				"phone_number": req.PhoneNumber,
				"device_id":    req.DeviceID,
				"company_id":   req.CompanyID,
				"ip":           ip,
			})
	}

	return nil
}

// --------------------------------------------------------------------
// GET PAIRING STATUS (used by web polling)
// --------------------------------------------------------------------

func (s *PairingService) GetPairingStatus(ctx context.Context, sessionID string) (*models.PairingStatusResponse, error) {
	session, err := s.pairingRepo.GetPairingSession(ctx, sessionID)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", appErrors.ErrNotFound, err)
	}
	return &models.PairingStatusResponse{
		SessionID:   session.SessionID,
		Status:      session.Status,
		UserID:      session.UserID,
		PhoneNumber: session.PhoneNumber,
		SessionType: session.SessionType,
		Role:        session.Role,
		ExpiresAt:   session.ExpiresAt,
	}, nil
}

// --------------------------------------------------------------------
// CONFIRM PAIRING (web confirms after scanning) – issues tokens
// --------------------------------------------------------------------

func (s *PairingService) ConfirmPairing(ctx context.Context, sessionID string) (*models.TokenPairResponse, error) {
	// Idempotency: prevent duplicate token issuance
	idempKey, _ := ctx.Value("idempotency_key").(string)
	if idempKey == "" {
		idempKey = fmt.Sprintf("confirm_pairing-%s", sessionID)
	}
	var cached *models.TokenPairResponse
	if err := s.idempotencyStore.Get(ctx, nil, idempKey, &cached); err == nil && cached != nil {
		return cached, nil
	}
	ip, _ := ctx.Value("ip_address").(string)

	session, err := s.pairingRepo.GetPairingSession(ctx, sessionID)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", appErrors.ErrNotFound, err)
	}
	if session.Status != "scanned" {
		return nil, fmt.Errorf("%w: session not scanned", appErrors.ErrInvalidState)
	}
	if session.UserID == "" {
		return nil, fmt.Errorf("%w: missing user", appErrors.ErrInvalidState)
	}

	// Mark as confirmed
	if err := s.pairingRepo.ConfirmPairingSession(ctx, sessionID); err != nil {
		return nil, fmt.Errorf("%w: %v", appErrors.ErrInternal, err)
	}

	// Build permission mask (for admin sessions)
	var permissionMask []uint64
	if session.SessionType == "admin" && len(session.Permissions) > 0 {
		permissionMask = s.buildPermissionMask(session.Permissions)
	}
	// Normalise to 13 blocks (800 permissions)
	if len(permissionMask) < 13 {
		fullMask := make([]uint64, 13)
		copy(fullMask, permissionMask)
		permissionMask = fullMask
	}

	// Issue token pair – now using the company ID stored in the session
	tokenPair, err := s.sessionService.IssueTokenPair(ctx, &IssueTokenPairRequest{
		UserID:         session.UserID,
		Role:           session.Role,
		DeviceID:       session.WebDeviceID,
		SessionType:    session.SessionType,
		IPAddress:      session.IPAddress,
		CompanyID:      session.CompanyID, // 👈 use stored company ID
		PermissionMask: permissionMask,
	})
	if err != nil {
		return nil, fmt.Errorf("%w: token issue failed", appErrors.ErrInternal)
	}

	// Audit: pairing confirmed
	if s.auditService != nil {
		_ = s.auditService.LogAction(ctx, nil, nil, "pairing", "confirm_pairing", "pairing_session",
			nil, "system", nil, nil, nil, map[string]interface{}{
				"session_id":   sessionID,
				"user_id":      session.UserID,
				"session_type": session.SessionType,
				"role":         session.Role,
				"company_id":   session.CompanyID,
				"ip":           ip,
			})
	}

	// Store idempotency result
	_ = s.idempotencyStore.Store(ctx, nil, idempKey, tokenPair)

	// Delete pairing session after a delay (non‑critical, run in background)
	go func() {
		time.Sleep(30 * time.Second)
		_ = s.pairingRepo.DeletePairingSession(context.Background(), sessionID)
	}()

	return tokenPair, nil
}

// --------------------------------------------------------------------
// CLEANUP EXPIRED SESSIONS
// --------------------------------------------------------------------

func (s *PairingService) CleanupExpiredSessions(ctx context.Context) (int, error) {
	count, err := s.pairingRepo.CleanupExpiredSessions(ctx)
	if err != nil {
		return 0, fmt.Errorf("%w: %v", appErrors.ErrInternal, err)
	}
	if s.auditService != nil {
		_ = s.auditService.LogAction(ctx, nil, nil, "pairing", "cleanup_expired", "pairing_session",
			nil, "system", nil, nil, nil, map[string]interface{}{
				"deleted_count": count,
			})
	}
	return count, nil
}

// --------------------------------------------------------------------
// HELPERS
// --------------------------------------------------------------------

func generateWebDeviceID(userAgent, ip string) string {
	h := sha256.New()
	h.Write([]byte(userAgent + ":" + ip))
	hash := hex.EncodeToString(h.Sum(nil))
	return "web-" + hash[:16]
}

// buildPermissionMask converts permission strings to a bitmask.
// 🚨 SECURITY: In production, do NOT trust client‑supplied permissions.
// Instead, fetch actual permissions from the database based on role/user.
func (s *PairingService) buildPermissionMask(permissions []string) []uint64 {
	// 800 permissions → 13 uint64 blocks
	mask := make([]uint64, 13)

	// TODO: Replace with actual permission registry mapping.
	// Example:
	// for _, perm := range permissions {
	//     bitIndex := permissionMap[perm]   // e.g., "USER_CREATE" → 42
	//     block := bitIndex / 64
	//     offset := bitIndex % 64
	//     mask[block] |= 1 << offset
	// }

	// For now returns an empty mask (all permissions denied).
	return mask
}

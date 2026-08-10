package handler

import (
	"auth-service/internal/contextkeys"
	"context"
	"encoding/json"
	"errors"
	"net"
	"net/http"
	"strings"

	customErrors "auth-service/internal/errors"
	"auth-service/internal/models"
	"auth-service/internal/service"

	"github.com/gorilla/websocket"
)

// PairingHandler handles QR code pairing and WebSocket updates.
type PairingHandler struct {
	pairingService *service.PairingService
	wsService      *service.WebSocketService
}

var upgrader = websocket.Upgrader{
	ReadBufferSize:  1024,
	WriteBufferSize: 1024,
	CheckOrigin: func(r *http.Request) bool {
		// In production validate properly
		return true
	},
}

// NewPairingHandler creates a new PairingHandler.
func NewPairingHandler(
	pairingService *service.PairingService,
	wsService *service.WebSocketService,
) *PairingHandler {
	return &PairingHandler{
		pairingService: pairingService,
		wsService:      wsService,
	}
}

// ---------- Context injection helpers ----------

func (h *PairingHandler) getIdempotencyKey(r *http.Request) string {
	return r.Header.Get("Idempotency-Key")
}

// injectIdempotencyKey adds the idempotency key to the request context.
func (h *PairingHandler) injectIdempotencyKey(ctx context.Context, r *http.Request) context.Context {
	key := h.getIdempotencyKey(r)
	if key != "" {
		// Use the shared context key type
		return context.WithValue(ctx, "idempotency_key", key) // plain string
	}
	return ctx
}

// injectClientIP adds the client IP to the request context.
func (h *PairingHandler) injectClientIP(ctx context.Context, r *http.Request) context.Context {
	ip := h.getClientIP(r)
	return context.WithValue(ctx, contextkeys.ClientIP, ip)
}

// getClientIP extracts client IP from request.
func (h *PairingHandler) getClientIP(r *http.Request) string {
	// reuse from admin or define
	if forwarded := r.Header.Get("X-Forwarded-For"); forwarded != "" {
		if ips := strings.Split(forwarded, ","); len(ips) > 0 {
			ip := strings.TrimSpace(ips[0])
			if net.ParseIP(ip) != nil {
				return ip
			}
		}
	}
	if realIP := r.Header.Get("X-Real-IP"); realIP != "" {
		if net.ParseIP(realIP) != nil {
			return realIP
		}
	}
	host, _, _ := net.SplitHostPort(r.RemoteAddr)
	if host == "" {
		return r.RemoteAddr
	}
	return host
}

// ---------- Endpoint handlers ----------

// GenerateQR generates a QR code for pairing.
// @Summary Generate QR code
// @Description Generates a new QR session for mobile-web pairing.
// @Tags pairing
// @Produce json
// @Success 200 {object} map[string]interface{} "QR data and session ID"
// @Failure 500 {object} map[string]interface{} "Generation failed"
// @Router /api/v1/web/login/qr [get]
func (h *PairingHandler) GenerateQR(w http.ResponseWriter, r *http.Request) {
	ctx := h.injectClientIP(r.Context(), r)

	req := &service.GenerateQRRequest{
		IPAddress: h.getClientIP(r),
		UserAgent: r.UserAgent(),
	}

	response, err := h.pairingService.GenerateQRCode(ctx, req)
	if err != nil {
		status, msg := h.mapServiceError(err)
		h.respondWithError(w, status, err, msg)
		return
	}

	h.respondWithJSON(w, http.StatusOK, successResponse(response, "QR code generated"))
}

// Pair pairs a mobile device to a web session.
// @Summary Pair device
// @Description Authenticates and pairs the device with a QR session.
// @Tags pairing
// @Accept json
// @Produce json
// @Param body body models.PairingRequest true "Pairing request"
// @Success 200 {object} map[string]interface{} "Pairing successful"
// @Failure 400 {object} map[string]interface{} "Invalid request"
// @Failure 401 {object} map[string]interface{} "Authentication required"
// @Router /api/v1/web/login/pair [post]
func (h *PairingHandler) Pair(w http.ResponseWriter, r *http.Request) {
	ctx := h.injectIdempotencyKey(h.injectClientIP(r.Context(), r), r)

	var req models.PairingRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		h.respondWithError(w, http.StatusBadRequest, err, "Invalid request body")
		return
	}

	// Extract user fields from JWT middleware
	userID, _ := ctx.Value("user_id").(string)
	phoneNumber, _ := ctx.Value("phone_number").(string)
	deviceID, _ := ctx.Value("device_id").(string)
	sessionType, _ := ctx.Value("session_type").(string)
	role, _ := ctx.Value("role").(string)
	companyID, _ := ctx.Value("company_id").(string) // 👈 NEW

	var adminRoleLevel string
	var adminPermissions []string

	if sessionType == "admin" {
		adminRoleLevel, _ = ctx.Value("admin_role_level").(string)
		if perms, ok := ctx.Value("admin_permissions").([]string); ok {
			adminPermissions = perms
		}
		if adminRoleLevel != "" {
			role = adminRoleLevel
		}
	}

	if userID == "" || deviceID == "" {
		h.respondWithError(w, http.StatusUnauthorized, customErrors.ErrUnauthorized, "Authentication required")
		return
	}

	pairReq := &service.PairRequest{
		SessionID:   req.SessionID,
		QRData:      req.Signature,
		UserID:      userID,
		PhoneNumber: phoneNumber,
		DeviceID:    deviceID,
		SessionType: sessionType,
		Role:        role,
		Permissions: adminPermissions,
		CompanyID:   companyID, // 👈 NEW
	}

	if err := h.pairingService.PairDevice(ctx, pairReq); err != nil {
		status, msg := h.mapServiceError(err)
		h.respondWithError(w, status, err, msg)
		return
	}

	status, _ := h.pairingService.GetPairingStatus(ctx, req.SessionID)
	h.wsService.SendStatusUpdate(req.SessionID, status)

	h.respondWithJSON(w, http.StatusOK, map[string]interface{}{
		"status":       "paired",
		"message":      "Device paired successfully",
		"session_type": sessionType,
	})
}

// Status returns the pairing status.
// @Summary Get pairing status
// @Tags pairing
// @Produce json
// @Param session_id query string true "Session ID"
// @Success 200 {object} map[string]interface{} "Status details"
// @Failure 400 {object} map[string]interface{} "Missing session_id"
// @Failure 404 {object} map[string]interface{} "Session not found"
// @Router /api/v1/web/login/status [get]
func (h *PairingHandler) Status(w http.ResponseWriter, r *http.Request) {
	ctx := h.injectClientIP(r.Context(), r)

	sessionID := r.URL.Query().Get("session_id")
	if sessionID == "" {
		h.respondWithError(w, http.StatusBadRequest, customErrors.ErrInvalidInput, "session_id is required")
		return
	}

	status, err := h.pairingService.GetPairingStatus(ctx, sessionID)
	if err != nil {
		statusCode, msg := h.mapServiceError(err)
		h.respondWithError(w, statusCode, err, msg)
		return
	}

	h.respondWithJSON(w, http.StatusOK, successResponse(status, "Status retrieved"))
}

// Confirm confirms the pairing and returns tokens.
// @Summary Confirm pairing
// @Tags pairing
// @Accept json
// @Produce json
// @Param body body object true "Session ID" example({"session_id":"abc123"})
// @Success 200 {object} map[string]interface{} "Token pair"
// @Failure 400 {object} map[string]interface{} "Invalid request"
// @Router /api/v1/web/login/confirm [post]
func (h *PairingHandler) Confirm(w http.ResponseWriter, r *http.Request) {
	ctx := h.injectIdempotencyKey(h.injectClientIP(r.Context(), r), r)

	var req struct {
		SessionID string `json:"session_id"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		h.respondWithError(w, http.StatusBadRequest, err, "Invalid request body")
		return
	}

	tokenPair, err := h.pairingService.ConfirmPairing(ctx, req.SessionID)
	if err != nil {
		status, msg := h.mapServiceError(err)
		h.respondWithError(w, status, err, msg)
		return
	}

	h.wsService.SendPaired(req.SessionID, tokenPair)
	h.respondWithJSON(w, http.StatusOK, successResponse(tokenPair, "Pairing confirmed"))
}

// WebSocket handles WebSocket connection for real-time updates.
// @Summary WebSocket for pairing updates
// @Tags pairing
// @Param session_id query string true "Session ID"
// @Success 101 "Switching Protocols"
// @Failure 400 {object} map[string]interface{} "Missing session_id"
// @Router /api/v1/web/login/ws [get]
func (h *PairingHandler) WebSocket(w http.ResponseWriter, r *http.Request) {
	sessionID := r.URL.Query().Get("session_id")
	if sessionID == "" {
		h.respondWithError(w, http.StatusBadRequest, customErrors.ErrInvalidInput, "session_id is required")
		return
	}

	conn, err := upgrader.Upgrade(w, r, nil)
	if err != nil {
		// no JSON response possible; log would be needed, but we skip
		return
	}

	client := &service.WebSocketClient{
		SessionID: sessionID,
		Conn:      conn,
		Send:      make(chan []byte, 256),
	}

	h.wsService.Register(client)
}

// Cleanup cleans up expired pairing sessions (admin only).
// @Summary Cleanup expired sessions
// @Tags pairing
// @Produce json
// @Success 200 {object} map[string]interface{} "Cleanup result"
// @Failure 500 {object} map[string]interface{} "Cleanup failed"
// @Router /api/v1/web/login/cleanup [post]
func (h *PairingHandler) Cleanup(w http.ResponseWriter, r *http.Request) {
	ctx := h.injectIdempotencyKey(h.injectClientIP(r.Context(), r), r)

	count, err := h.pairingService.CleanupExpiredSessions(ctx)
	if err != nil {
		status, msg := h.mapServiceError(err)
		h.respondWithError(w, status, err, msg)
		return
	}

	h.respondWithJSON(w, http.StatusOK, successResponse(map[string]interface{}{
		"cleaned_sessions": count,
		"message":          "Cleanup completed",
	}, "Cleanup successful"))
}

// ---------- Error mapping ----------
func (h *PairingHandler) mapServiceError(err error) (int, string) {
	if err == nil {
		return http.StatusOK, ""
	}
	// Use custom errors if available
	switch {
	case errors.Is(err, customErrors.ErrNotFound):
		return http.StatusNotFound, err.Error()
	case errors.Is(err, customErrors.ErrInvalidInput):
		return http.StatusBadRequest, err.Error()
	case errors.Is(err, customErrors.ErrUnauthorized):
		return http.StatusUnauthorized, err.Error()
	case errors.Is(err, customErrors.ErrPermissionDenied):
		return http.StatusForbidden, err.Error()
	default:
		return http.StatusInternalServerError, "internal server error"
	}
}

// ---------- Response helpers ----------
func (h *PairingHandler) respondWithJSON(w http.ResponseWriter, statusCode int, data interface{}) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(statusCode)
	_ = json.NewEncoder(w).Encode(data)
}

func (h *PairingHandler) respondWithError(w http.ResponseWriter, statusCode int, err error, message string) {
	h.respondWithJSON(w, statusCode, errorResponse(err, message))
}

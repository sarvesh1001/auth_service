package handler

import (
	"encoding/json"
	"net/http"

	"auth-service/internal/models"
	"auth-service/internal/service"
	"auth-service/internal/util"

	"github.com/gorilla/websocket"
	"go.uber.org/zap"
)

type PairingHandler struct {
	pairingService *service.PairingService
	wsService      *service.WebSocketService
	logger         *zap.Logger
}

var upgrader = websocket.Upgrader{
	ReadBufferSize:  1024,
	WriteBufferSize: 1024,
	CheckOrigin: func(r *http.Request) bool {
		// In production validate properly
		return true
	},
}

func NewPairingHandler(
	pairingService *service.PairingService,
	wsService *service.WebSocketService,
	logger *zap.Logger,
) *PairingHandler {
	return &PairingHandler{
		pairingService: pairingService,
		wsService:      wsService,
		logger:         logger,
	}
}

/* -----------------------------------------------------------
   Generate QR
----------------------------------------------------------- */

func (h *PairingHandler) GenerateQR(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	req := &service.GenerateQRRequest{
		IPAddress: getIPAddress(r),
		UserAgent: r.UserAgent(),
	}

	response, err := h.pairingService.GenerateQRCode(ctx, req)
	if err != nil {
		h.logger.Error("Failed to generate QR code",
			util.ErrorField(err),
			util.String("ip_address", req.IPAddress),
		)
		util.JSONError(w, http.StatusInternalServerError, "Failed to generate QR code")
		return
	}

	util.JSONResponse(w, http.StatusOK, response)
}

/* -----------------------------------------------------------
   Pair Mobile Device → Web QR Session
   Supports USER + ADMIN JWT claims
----------------------------------------------------------- */

func (h *PairingHandler) Pair(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	var req models.PairingRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		util.JSONError(w, http.StatusBadRequest, "Invalid request body")
		return
	}

	// Extract user fields from JWT middleware
	userID, _ := ctx.Value("user_id").(string)
	phoneNumber, _ := ctx.Value("phone_number").(string)
	deviceID, _ := ctx.Value("device_id").(string)

	// NEW — Session type identifying admin/user tokens
	sessionType, _ := ctx.Value("session_type").(string)
	role, _ := ctx.Value("role").(string)

	// NEW — Admin specific fields
	var adminRoleLevel string
	var adminPermissions []string

	if sessionType == "admin" {
		adminRoleLevel, _ = ctx.Value("admin_role_level").(string)

		if perms, ok := ctx.Value("admin_permissions").([]string); ok {
			adminPermissions = perms
		}

		// For admin login use the admin role level as the effective "role"
		if adminRoleLevel != "" {
			role = adminRoleLevel
		}
	}

	if userID == "" || deviceID == "" {
		util.JSONError(w, http.StatusUnauthorized, "Authentication required")
		return
	}

	// Build updated PairRequest
	pairReq := &service.PairRequest{
		SessionID:   req.SessionID,
		QRData:      req.Signature,
		UserID:      userID,
		PhoneNumber: phoneNumber,
		DeviceID:    deviceID,
		SessionType: sessionType,
		Role:        role,
		Permissions: adminPermissions,
	}

	// Process pairing
	if err := h.pairingService.PairDevice(ctx, pairReq); err != nil {
		h.logger.Error("Failed to pair device",
			util.ErrorField(err),
			util.String("user_id", userID),
			util.String("session_id", req.SessionID),
			util.String("session_type", sessionType),
		)
		util.JSONError(w, http.StatusBadRequest, err.Error())
		return
	}

	status, _ := h.pairingService.GetPairingStatus(ctx, req.SessionID)
	h.wsService.SendStatusUpdate(req.SessionID, status)

	util.JSONResponse(w, http.StatusOK, map[string]interface{}{
		"status":       "paired",
		"message":      "Device paired successfully",
		"session_type": sessionType,
	})
}

/* -----------------------------------------------------------
   Get Pairing Status
----------------------------------------------------------- */

func (h *PairingHandler) Status(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	sessionID := r.URL.Query().Get("session_id")
	if sessionID == "" {
		util.JSONError(w, http.StatusBadRequest, "session_id is required")
		return
	}

	status, err := h.pairingService.GetPairingStatus(ctx, sessionID)
	if err != nil {
		util.JSONError(w, http.StatusNotFound, "Session not found")
		return
	}

	util.JSONResponse(w, http.StatusOK, status)
}

/* -----------------------------------------------------------
   Confirm Pairing (User/Admin)
----------------------------------------------------------- */

func (h *PairingHandler) Confirm(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	var req struct {
		SessionID string `json:"session_id"`
	}

	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		util.JSONError(w, http.StatusBadRequest, "Invalid request body")
		return
	}

	tokenPair, err := h.pairingService.ConfirmPairing(ctx, req.SessionID)
	if err != nil {
		h.logger.Error("Failed to confirm pairing",
			util.ErrorField(err),
			util.String("session_id", req.SessionID),
		)
		util.JSONError(w, http.StatusBadRequest, err.Error())
		return
	}

	// Notify all WebSocket subscribers
	h.wsService.SendPaired(req.SessionID, tokenPair)

	util.JSONResponse(w, http.StatusOK, tokenPair)
}

/* -----------------------------------------------------------
   WebSocket for Real-Time Updates
----------------------------------------------------------- */

func (h *PairingHandler) WebSocket(w http.ResponseWriter, r *http.Request) {
	sessionID := r.URL.Query().Get("session_id")
	if sessionID == "" {
		util.JSONError(w, http.StatusBadRequest, "session_id is required")
		return
	}

	conn, err := upgrader.Upgrade(w, r, nil)
	if err != nil {
		h.logger.Error("WebSocket upgrade failed",
			util.ErrorField(err),
			util.String("session_id", sessionID),
		)
		return
	}

	client := &service.WebSocketClient{
		SessionID: sessionID,
		Conn:      conn,
		Send:      make(chan []byte, 256),
	}

	h.wsService.Register(client)

	h.logger.Debug("WebSocket connection established",
		util.String("session_id", sessionID),
	)
}

/* -----------------------------------------------------------
   Admin Cleanup Expired Sessions
----------------------------------------------------------- */

func (h *PairingHandler) Cleanup(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	count, err := h.pairingService.CleanupExpiredSessions(ctx)
	if err != nil {
		util.JSONError(w, http.StatusInternalServerError, "Cleanup failed")
		return
	}

	util.JSONResponse(w, http.StatusOK, map[string]interface{}{
		"cleaned_sessions": count,
		"message":          "Cleanup completed",
	})
}

/* -----------------------------------------------------------
   Helper: Extract IP Address
----------------------------------------------------------- */

func getIPAddress(r *http.Request) string {
	if forwarded := r.Header.Get("X-Forwarded-For"); forwarded != "" {
		return forwarded
	}
	return r.RemoteAddr
}

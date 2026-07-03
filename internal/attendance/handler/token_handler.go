package handler

import (
	"encoding/json"
	"net/http"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"
	"go.uber.org/zap"

	"auth-service/internal/attendance/models"
	"auth-service/internal/attendance/service/device"
)

// DeviceTokenAdminHandler handles device token management.
type DeviceTokenAdminHandler struct {
	tokenService device.TokenService
	logger       *zap.Logger
}

// NewDeviceTokenAdminHandler creates a new handler.
func NewDeviceTokenAdminHandler(
	tokenService device.TokenService,
	logger *zap.Logger,
) *DeviceTokenAdminHandler {
	return &DeviceTokenAdminHandler{
		tokenService: tokenService,
		logger:       logger,
	}
}

// ---- IssueDeviceToken ----

func (h *DeviceTokenAdminHandler) IssueDeviceToken(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	// Admin only
	if getSessionTypeFromContext(ctx) != "admin" {
		h.respondWithError(w, http.StatusForbidden, "admin access required")
		return
	}
	actorID, err := getUserIDFromContext(ctx)
	if err != nil {
		h.respondWithError(w, http.StatusUnauthorized, "authentication required")
		return
	}

	companyIDStr := chi.URLParam(r, "companyID")
	companyID, err := uuid.Parse(companyIDStr)
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid company ID")
		return
	}
	deviceID := chi.URLParam(r, "deviceID")
	if deviceID == "" {
		h.respondWithError(w, http.StatusBadRequest, "device ID required")
		return
	}

	var req struct {
		SourceType string `json:"source_type"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid request body")
		return
	}
	if req.SourceType == "" {
		h.respondWithError(w, http.StatusBadRequest, "source_type is required")
		return
	}

	serviceReq := &models.IssueTokenRequest{
		CompanyID:  companyID,
		DeviceID:   deviceID,
		SourceType: req.SourceType,
		IssuedBy:   &actorID,
	}

	token, rawToken, err := h.tokenService.IssueToken(ctx, serviceReq)
	if err != nil {
		h.logger.Error("Failed to issue device token",
			zap.String("company_id", companyID.String()),
			zap.String("device_id", deviceID),
			zap.Error(err))
		h.respondWithError(w, http.StatusBadRequest, err.Error())
		return
	}

	h.respondWithJSON(w, http.StatusCreated, map[string]interface{}{
		"success": true,
		"message": "Device token issued successfully",
		"data": map[string]interface{}{
			"token_id":      token.TokenID,
			"device_id":     token.DeviceID,
			"company_id":    token.CompanyID,
			"source_type":   token.SourceType,
			"issued_at":     token.IssuedAt,
			"expires_at":    token.ExpiresAt,
			"raw_token":     rawToken,
			"issued_by":     actorID,
			"token_version": token.TokenVersion,
		},
	})
}

// ---- RevokeDeviceToken ----

func (h *DeviceTokenAdminHandler) RevokeDeviceToken(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	if getSessionTypeFromContext(ctx) != "admin" {
		h.respondWithError(w, http.StatusForbidden, "admin access required")
		return
	}
	actorID, err := getUserIDFromContext(ctx)
	if err != nil {
		h.respondWithError(w, http.StatusUnauthorized, "authentication required")
		return
	}

	tokenIDStr := chi.URLParam(r, "tokenID")
	tokenID, err := uuid.Parse(tokenIDStr)
	if err != nil || tokenID == uuid.Nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid token_id")
		return
	}

	var body struct {
		Reason string `json:"reason"`
	}
	_ = json.NewDecoder(r.Body).Decode(&body)
	if body.Reason == "" {
		body.Reason = "revoked by admin"
	}

	if err := h.tokenService.RevokeToken(ctx, tokenID, &actorID, body.Reason); err != nil {
		h.logger.Error("Failed to revoke device token",
			zap.String("token_id", tokenID.String()),
			zap.Error(err))
		h.respondWithError(w, http.StatusInternalServerError, err.Error())
		return
	}

	h.respondWithJSON(w, http.StatusOK, map[string]interface{}{
		"success": true,
		"message": "Device token revoked successfully",
		"data": map[string]interface{}{
			"token_id":   tokenID,
			"revoked_by": actorID,
			"reason":     body.Reason,
		},
	})
}

// ---- RevokeAllDeviceTokens ----

func (h *DeviceTokenAdminHandler) RevokeAllDeviceTokens(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	if getSessionTypeFromContext(ctx) != "admin" {
		h.respondWithError(w, http.StatusForbidden, "admin access required")
		return
	}
	actorID, err := getUserIDFromContext(ctx)
	if err != nil {
		h.respondWithError(w, http.StatusUnauthorized, "authentication required")
		return
	}

	companyIDStr := chi.URLParam(r, "companyID")
	companyID, err := uuid.Parse(companyIDStr)
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid company ID")
		return
	}
	deviceID := chi.URLParam(r, "deviceID")
	if deviceID == "" {
		h.respondWithError(w, http.StatusBadRequest, "device ID required")
		return
	}

	var req struct {
		Reason string `json:"reason"`
	}
	_ = json.NewDecoder(r.Body).Decode(&req)
	if req.Reason == "" {
		req.Reason = "revoked all tokens by admin"
	}

	if err := h.tokenService.RevokeAllDeviceTokens(ctx, companyID, deviceID, &actorID, req.Reason); err != nil {
		h.logger.Error("Failed to revoke all device tokens", zap.Error(err))
		h.respondWithError(w, http.StatusInternalServerError, "failed to revoke tokens")
		return
	}

	h.respondWithJSON(w, http.StatusOK, map[string]interface{}{
		"success": true,
		"message": "All device tokens revoked successfully",
	})
}

// ---- GetCurrentDeviceToken ----

func (h *DeviceTokenAdminHandler) GetCurrentDeviceToken(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	if getSessionTypeFromContext(ctx) != "admin" {
		h.respondWithError(w, http.StatusForbidden, "admin access required")
		return
	}

	companyIDStr := chi.URLParam(r, "companyID")
	companyID, err := uuid.Parse(companyIDStr)
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid company ID")
		return
	}
	deviceID := chi.URLParam(r, "deviceID")
	if deviceID == "" {
		h.respondWithError(w, http.StatusBadRequest, "device ID required")
		return
	}

	token, err := h.tokenService.GetCurrentDeviceToken(ctx, companyID, deviceID)
	if err != nil {
		h.logger.Error("Failed to get current device token",
			zap.String("company_id", companyID.String()),
			zap.String("device_id", deviceID),
			zap.Error(err))
		h.respondWithError(w, http.StatusInternalServerError, "failed to fetch device token")
		return
	}

	if token == nil {
		h.respondWithJSON(w, http.StatusOK, map[string]interface{}{
			"success": true,
			"data":    nil,
			"message": "no active token for device",
		})
		return
	}

	h.respondWithJSON(w, http.StatusOK, map[string]interface{}{
		"success": true,
		"data": map[string]interface{}{
			"token_id":      token.TokenID,
			"company_id":    token.CompanyID,
			"device_id":     token.DeviceID,
			"source_type":   token.SourceType,
			"token_version": token.TokenVersion,
			"is_active":     token.IsActive,
			"issued_at":     token.IssuedAt,
			"expires_at":    token.ExpiresAt,
			"issued_by":     token.IssuedBy,
		},
	})
}

// ---- Helpers ----

func (h *DeviceTokenAdminHandler) respondWithJSON(w http.ResponseWriter, status int, data interface{}) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(data)
}

func (h *DeviceTokenAdminHandler) respondWithError(w http.ResponseWriter, status int, message string) {
	h.respondWithJSON(w, status, map[string]interface{}{
		"success":   false,
		"error":     message,
		"timestamp": time.Now().UTC(),
	})
}

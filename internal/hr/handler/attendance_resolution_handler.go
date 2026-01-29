package handler

import (
	"auth-service/internal/hr/service"
	"encoding/json"
	"fmt"
	"net/http"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"
	"go.uber.org/zap"
)

// AttendanceResolutionHandler handles attendance resolution operations
type AttendanceResolutionHandler struct {
	resolutionService service.AttendanceResolutionService
	logger            *zap.Logger
}

// NewAttendanceResolutionHandler creates a new resolution handler
func NewAttendanceResolutionHandler(
	resolutionService service.AttendanceResolutionService,
	logger *zap.Logger,
) *AttendanceResolutionHandler {
	return &AttendanceResolutionHandler{
		resolutionService: resolutionService,
		logger:            logger,
	}
}

// ResolveEventRequest represents a request to resolve a specific event
type ResolveEventRequest struct {
	EventID uuid.UUID `json:"event_id"`
}

// ResolveDayRequest represents a request to resolve a day for a user
type ResolveDayRequest struct {
	UserID      uuid.UUID `json:"user_id"`
	Date        time.Time `json:"date"`
	Recalculate bool      `json:"recalculate,omitempty"`
}

// BatchResolveRequest represents a batch resolution request
type BatchResolveRequest struct {
	EventIDs []uuid.UUID `json:"event_ids"`
}

// ResolveEvent handles resolving a specific attendance event
func (h *AttendanceResolutionHandler) ResolveEvent(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	// ✅ FIXED: Use mustGetCompanyID helper
	companyID, err := mustGetCompanyID(r)
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid company ID")
		return
	}

	// Check permission
	if !h.hasPermission(ctx, companyID, "attendance:resolve") {
		h.respondWithError(w, http.StatusForbidden, "insufficient permissions")
		return
	}

	var req ResolveEventRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid request body")
		return
	}

	if req.EventID == uuid.Nil {
		h.respondWithError(w, http.StatusBadRequest, "event ID is required")
		return
	}

	if err := h.resolutionService.ResolveEvent(ctx, req.EventID); err != nil {
		h.logger.Error("Failed to resolve event",
			zap.String("event_id", req.EventID.String()),
			zap.Error(err))
		h.respondWithError(w, http.StatusInternalServerError, "failed to resolve event")
		return
	}

	h.respondWithJSON(w, http.StatusOK, map[string]interface{}{
		"success": true,
		"message": "Event resolved successfully",
		"data": map[string]interface{}{
			"event_id": req.EventID,
		},
	})
}

// ResolveDay handles resolving attendance for a specific day
func (h *AttendanceResolutionHandler) ResolveDay(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	// ✅ FIXED: Use mustGetCompanyID helper
	companyID, err := mustGetCompanyID(r)
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid company ID")
		return
	}

	// Check permission
	if !h.hasPermission(ctx, companyID, "attendance:resolve") {
		h.respondWithError(w, http.StatusForbidden, "insufficient permissions")
		return
	}

	var req ResolveDayRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid request body")
		return
	}

	if req.UserID == uuid.Nil {
		h.respondWithError(w, http.StatusBadRequest, "user ID is required")
		return
	}

	if req.Date.IsZero() {
		req.Date = time.Now()
	}

	if req.Recalculate {
		if err := h.resolutionService.RecalculateDay(ctx, companyID, req.UserID, req.Date); err != nil {
			h.logger.Error("Failed to recalculate day",
				zap.String("user_id", req.UserID.String()),
				zap.Time("date", req.Date),
				zap.Error(err))
			h.respondWithError(w, http.StatusInternalServerError, "failed to recalculate day")
			return
		}

		h.respondWithJSON(w, http.StatusOK, map[string]interface{}{
			"success": true,
			"message": "Day recalculated successfully",
		})
	} else {
		if err := h.resolutionService.ResolveDay(ctx, companyID, req.UserID, req.Date); err != nil {
			h.logger.Error("Failed to resolve day",
				zap.String("user_id", req.UserID.String()),
				zap.Time("date", req.Date),
				zap.Error(err))
			h.respondWithError(w, http.StatusInternalServerError, "failed to resolve day")
			return
		}

		h.respondWithJSON(w, http.StatusOK, map[string]interface{}{
			"success": true,
			"message": "Day resolved successfully",
		})
	}
}

// BatchResolve handles batch resolution of events
func (h *AttendanceResolutionHandler) BatchResolve(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	// ✅ FIXED: Use mustGetCompanyID helper
	companyID, err := mustGetCompanyID(r)
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid company ID")
		return
	}

	// Check permission
	if !h.hasPermission(ctx, companyID, "attendance:resolve:batch") {
		h.respondWithError(w, http.StatusForbidden, "insufficient permissions")
		return
	}

	var req BatchResolveRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid request body")
		return
	}

	if len(req.EventIDs) == 0 {
		h.respondWithError(w, http.StatusBadRequest, "at least one event ID is required")
		return
	}

	// Limit batch size
	if len(req.EventIDs) > 1000 {
		h.respondWithError(w, http.StatusBadRequest, "batch size cannot exceed 1000 events")
		return
	}

	if err := h.resolutionService.BatchResolveEvents(ctx, req.EventIDs); err != nil {
		h.logger.Error("Failed to batch resolve events",
			zap.Int("event_count", len(req.EventIDs)),
			zap.Error(err))
		h.respondWithError(w, http.StatusInternalServerError, "failed to batch resolve events")
		return
	}

	h.respondWithJSON(w, http.StatusOK, map[string]interface{}{
		"success": true,
		"message": fmt.Sprintf("Batch resolved %d events successfully", len(req.EventIDs)),
		"data": map[string]interface{}{
			"processed_count": len(req.EventIDs),
		},
	})
}

// ResolveDayByPath handles resolving attendance via URL parameters
func (h *AttendanceResolutionHandler) ResolveDayByPath(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	// ✅ FIXED: Use mustGetCompanyID helper
	companyID, err := mustGetCompanyID(r)
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid company ID")
		return
	}

	userIDStr := chi.URLParam(r, "userID")
	userID, err := uuid.Parse(userIDStr)
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid user ID")
		return
	}

	dateStr := chi.URLParam(r, "date")
	date, err := time.Parse("2006-01-02", dateStr)
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid date format, use YYYY-MM-DD")
		return
	}

	recalculate := r.URL.Query().Get("recalculate") == "true"

	// Check permission
	permission := "attendance:resolve"
	if recalculate {
		permission = "attendance:recalculate"
	}
	if !h.hasPermission(ctx, companyID, permission) {
		h.respondWithError(w, http.StatusForbidden, "insufficient permissions")
		return
	}

	if recalculate {
		if err := h.resolutionService.RecalculateDay(ctx, companyID, userID, date); err != nil {
			h.logger.Error("Failed to recalculate day via path",
				zap.String("user_id", userID.String()),
				zap.Time("date", date),
				zap.Error(err))
			h.respondWithError(w, http.StatusInternalServerError, "failed to recalculate day")
			return
		}

		h.respondWithJSON(w, http.StatusOK, map[string]interface{}{
			"success": true,
			"message": "Day recalculated successfully",
		})
	} else {
		if err := h.resolutionService.ResolveDay(ctx, companyID, userID, date); err != nil {
			h.logger.Error("Failed to resolve day via path",
				zap.String("user_id", userID.String()),
				zap.Time("date", date),
				zap.Error(err))
			h.respondWithError(w, http.StatusInternalServerError, "failed to resolve day")
			return
		}

		h.respondWithJSON(w, http.StatusOK, map[string]interface{}{
			"success": true,
			"message": "Day resolved successfully",
		})
	}
}

// ✅ ADDED: Single source of truth for company ID
func mustGetCompanyID(r *http.Request) (uuid.UUID, error) {
	companyIDStr := chi.URLParam(r, "companyID")
	if companyIDStr == "" {
		return uuid.Nil, fmt.Errorf("company ID missing in URL")
	}
	return uuid.Parse(companyIDStr)
}

func (h *AttendanceResolutionHandler) hasPermission(ctx interface{}, companyID uuid.UUID, permission string) bool {
	// Implement permission checking logic
	return true
}

func (h *AttendanceResolutionHandler) respondWithJSON(w http.ResponseWriter, status int, data interface{}) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	json.NewEncoder(w).Encode(data)
}

func (h *AttendanceResolutionHandler) respondWithError(w http.ResponseWriter, status int, message string) {
	h.respondWithJSON(w, status, map[string]interface{}{
		"success": false,
		"error":   message,
	})
}

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

type AttendanceResolutionHandler struct {
	resolutionService service.AttendanceResolutionService
	logger            *zap.Logger
}

func NewAttendanceResolutionHandler(
	resolutionService service.AttendanceResolutionService,
	logger *zap.Logger,
) *AttendanceResolutionHandler {
	return &AttendanceResolutionHandler{
		resolutionService: resolutionService,
		logger:            logger,
	}
}

// =====================================================
// DTOs
// =====================================================

type ResolveEventRequest struct {
	EventID uuid.UUID `json:"event_id"`
}

type ResolveDayRequest struct {
	UserID      uuid.UUID `json:"user_id"`
	Date        time.Time `json:"date"`
	Recalculate bool      `json:"recalculate,omitempty"`
}

type BatchResolveRequest struct {
	EventIDs []uuid.UUID `json:"event_ids"`
}

// =====================================================
// Handlers
// =====================================================

func (h *AttendanceResolutionHandler) ResolveEvent(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	_, err := getCompanyIDFromContext(ctx)
	if err != nil {
		h.respondWithError(w, http.StatusUnauthorized, err.Error())
		return
	}

	var req ResolveEventRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid request body")
		return
	}

	if req.EventID == uuid.Nil {
		h.respondWithError(w, http.StatusBadRequest, "event_id is required")
		return
	}

	if err := h.resolutionService.ResolveEvent(ctx, req.EventID); err != nil {
		h.logger.Error(
			"Failed to resolve event",
			zap.String("event_id", req.EventID.String()),
			zap.Error(err),
		)
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

func (h *AttendanceResolutionHandler) ResolveDay(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	companyID, err := getCompanyIDFromContext(ctx)
	if err != nil {
		h.respondWithError(w, http.StatusUnauthorized, err.Error())
		return
	}

	var req ResolveDayRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid request body")
		return
	}

	if req.UserID == uuid.Nil {
		h.respondWithError(w, http.StatusBadRequest, "user_id is required")
		return
	}

	if req.Date.IsZero() {
		req.Date = time.Now()
	}

	if req.Recalculate {
		if err := h.resolutionService.RecalculateDay(
			ctx,
			companyID,
			req.UserID,
			req.Date,
		); err != nil {
			h.logger.Error(
				"Failed to recalculate day",
				zap.String("user_id", req.UserID.String()),
				zap.Time("date", req.Date),
				zap.Error(err),
			)
			h.respondWithError(w, http.StatusInternalServerError, "failed to recalculate day")
			return
		}

		h.respondWithJSON(w, http.StatusOK, map[string]interface{}{
			"success": true,
			"message": "Day recalculated successfully",
		})
		return
	}

	if err := h.resolutionService.ResolveDay(
		ctx,
		companyID,
		req.UserID,
		req.Date,
	); err != nil {
		h.logger.Error(
			"Failed to resolve day",
			zap.String("user_id", req.UserID.String()),
			zap.Time("date", req.Date),
			zap.Error(err),
		)
		h.respondWithError(w, http.StatusInternalServerError, "failed to resolve day")
		return
	}

	h.respondWithJSON(w, http.StatusOK, map[string]interface{}{
		"success": true,
		"message": "Day resolved successfully",
	})
}

func (h *AttendanceResolutionHandler) BatchResolve(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	_, err := getCompanyIDFromContext(ctx)
	if err != nil {
		h.respondWithError(w, http.StatusUnauthorized, err.Error())
		return
	}

	var req BatchResolveRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid request body")
		return
	}

	if len(req.EventIDs) == 0 {
		h.respondWithError(w, http.StatusBadRequest, "at least one event_id is required")
		return
	}

	if len(req.EventIDs) > 1000 {
		h.respondWithError(w, http.StatusBadRequest, "batch size cannot exceed 1000 events")
		return
	}

	if err := h.resolutionService.BatchResolveEvents(ctx, req.EventIDs); err != nil {
		h.logger.Error(
			"Failed to batch resolve events",
			zap.Int("event_count", len(req.EventIDs)),
			zap.Error(err),
		)
		h.respondWithError(w, http.StatusInternalServerError, "failed to batch resolve events")
		return
	}

	h.respondWithJSON(w, http.StatusOK, map[string]interface{}{
		"success": true,
		"message": fmt.Sprintf(
			"Batch resolved %d events successfully",
			len(req.EventIDs),
		),
		"data": map[string]interface{}{
			"processed_count": len(req.EventIDs),
		},
	})
}

func (h *AttendanceResolutionHandler) ResolveDayByPath(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	companyID, err := getCompanyIDFromContext(ctx)
	if err != nil {
		h.respondWithError(w, http.StatusUnauthorized, err.Error())
		return
	}

	userID, err := uuid.Parse(chi.URLParam(r, "userID"))
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid user ID")
		return
	}

	date, err := time.Parse("2006-01-02", chi.URLParam(r, "date"))
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid date format, use YYYY-MM-DD")
		return
	}

	recalculate := r.URL.Query().Get("recalculate") == "true"

	if recalculate {
		if err := h.resolutionService.RecalculateDay(
			ctx,
			companyID,
			userID,
			date,
		); err != nil {
			h.logger.Error(
				"Failed to recalculate day via path",
				zap.String("user_id", userID.String()),
				zap.Time("date", date),
				zap.Error(err),
			)
			h.respondWithError(w, http.StatusInternalServerError, "failed to recalculate day")
			return
		}

		h.respondWithJSON(w, http.StatusOK, map[string]interface{}{
			"success": true,
			"message": "Day recalculated successfully",
		})
		return
	}

	if err := h.resolutionService.ResolveDay(
		ctx,
		companyID,
		userID,
		date,
	); err != nil {
		h.logger.Error(
			"Failed to resolve day via path",
			zap.String("user_id", userID.String()),
			zap.Time("date", date),
			zap.Error(err),
		)
		h.respondWithError(w, http.StatusInternalServerError, "failed to resolve day")
		return
	}

	h.respondWithJSON(w, http.StatusOK, map[string]interface{}{
		"success": true,
		"message": "Day resolved successfully",
	})
}

// =====================================================
// Response Helpers
// =====================================================

func (h *AttendanceResolutionHandler) respondWithJSON(
	w http.ResponseWriter,
	status int,
	data interface{},
) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	json.NewEncoder(w).Encode(data)
}

func (h *AttendanceResolutionHandler) respondWithError(
	w http.ResponseWriter,
	status int,
	message string,
) {
	h.respondWithJSON(w, status, map[string]interface{}{
		"success": false,
		"error":   message,
	})
}
func (h *AttendanceResolutionHandler) BatchResolveByPeriod(
	w http.ResponseWriter,
	r *http.Request,
) {
	ctx := r.Context()

	companyID, err := getCompanyIDFromContext(ctx)
	if err != nil {
		h.respondWithError(w, http.StatusUnauthorized, err.Error())
		return
	}

	var req BatchResolveByPeriodRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid request body")
		return
	}

	if len(req.UserIDs) == 0 {
		h.respondWithError(w, http.StatusBadRequest, "at least one user_id is required")
		return
	}

	if req.StartDate.IsZero() || req.EndDate.IsZero() {
		h.respondWithError(w, http.StatusBadRequest, "start_date and end_date are required")
		return
	}

	if req.EndDate.Before(req.StartDate) {
		h.respondWithError(w, http.StatusBadRequest, "end_date cannot be before start_date")
		return
	}

	err = h.resolutionService.ResolvePeriod(
		ctx,
		companyID,
		req.UserIDs,
		req.StartDate,
		req.EndDate,
		req.Recalculate,
	)
	if err != nil {
		h.respondWithError(w, http.StatusInternalServerError, "failed to resolve period")
		return
	}

	h.respondWithJSON(w, http.StatusOK, map[string]interface{}{
		"success": true,
		"message": "Attendance period resolved successfully",
	})
}

type BatchResolveByPeriodRequest struct {
	UserIDs     []uuid.UUID `json:"user_ids"`
	StartDate   time.Time   `json:"start_date"`
	EndDate     time.Time   `json:"end_date"`
	Recalculate bool        `json:"recalculate,omitempty"`
}

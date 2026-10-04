package handler

import (
	"encoding/json"
	"errors"
	"net/http"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"
	"go.uber.org/zap"

	"auth-service/internal/attendance/service/exemption"
	"auth-service/internal/attendance/service/resolver"
)

type AttendanceExemptionHandler struct {
	exemptionService exemption.ExemptionService
	logger           *zap.Logger
}

func NewAttendanceExemptionHandler(
	exemptionService exemption.ExemptionService,
	logger *zap.Logger,
) *AttendanceExemptionHandler {
	return &AttendanceExemptionHandler{
		exemptionService: exemptionService,
		logger:           logger,
	}
}

// ---------------------------------------------------------------------------
// Request DTOs — note the ABSENCE of company_id / created_by.
// ---------------------------------------------------------------------------

type createExemptionRequest struct {
	SubjectType string     `json:"subject_type"`
	SubjectID   uuid.UUID  `json:"subject_id"`
	FromDate    time.Time  `json:"from_date"`
	ToDate      time.Time  `json:"to_date"`
	Reason      *string    `json:"reason,omitempty"`
	ApprovedBy  *uuid.UUID `json:"approved_by,omitempty"`
}

type updateExemptionRequest struct {
	FromDate   *time.Time `json:"from_date,omitempty"`
	ToDate     *time.Time `json:"to_date,omitempty"`
	Reason     *string    `json:"reason,omitempty"`
	ApprovedBy *uuid.UUID `json:"approved_by,omitempty"`
}

// ---------------------------------------------------------------------------
// Handlers
// ---------------------------------------------------------------------------

func (h *AttendanceExemptionHandler) CreateExemption(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	companyID, err := getCompanyIDFromContext(ctx)
	if err != nil {
		h.respondWithError(w, http.StatusUnauthorized, err.Error())
		return
	}
	actorID, err := getUserIDFromContext(ctx)
	if err != nil {
		h.respondWithError(w, http.StatusUnauthorized, "authentication required")
		return
	}
	actorType := getSessionTypeFromContext(ctx)

	var req createExemptionRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid request body")
		return
	}

	created, err := h.exemptionService.Create(ctx, companyID, &exemption.CreateExemptionInput{
		SubjectType: req.SubjectType,
		SubjectID:   req.SubjectID,
		FromDate:    req.FromDate,
		ToDate:      req.ToDate,
		Reason:      req.Reason,
		ApprovedBy:  req.ApprovedBy,
	}, actorType, actorID)
	if err != nil {
		h.writeServiceError(w, err, "create exemption")
		return
	}

	h.respondWithJSON(w, http.StatusCreated, map[string]interface{}{
		"success": true,
		"data":    created,
	})
}

func (h *AttendanceExemptionHandler) UpdateExemption(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	companyID, err := getCompanyIDFromContext(ctx)
	if err != nil {
		h.respondWithError(w, http.StatusUnauthorized, err.Error())
		return
	}
	actorID, err := getUserIDFromContext(ctx)
	if err != nil {
		h.respondWithError(w, http.StatusUnauthorized, "authentication required")
		return
	}
	actorType := getSessionTypeFromContext(ctx)

	exemptionID, err := uuid.Parse(chi.URLParam(r, "exemptionID"))
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid exemption ID")
		return
	}

	var req updateExemptionRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid request body")
		return
	}

	updated, err := h.exemptionService.Update(ctx, companyID, exemptionID, &exemption.UpdateExemptionInput{
		FromDate:   req.FromDate,
		ToDate:     req.ToDate,
		Reason:     req.Reason,
		ApprovedBy: req.ApprovedBy,
	}, actorType, actorID)
	if err != nil {
		h.writeServiceError(w, err, "update exemption")
		return
	}

	h.respondWithJSON(w, http.StatusOK, map[string]interface{}{
		"success": true,
		"data":    updated,
	})
}

func (h *AttendanceExemptionHandler) DeleteExemption(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	companyID, err := getCompanyIDFromContext(ctx)
	if err != nil {
		h.respondWithError(w, http.StatusUnauthorized, err.Error())
		return
	}
	actorID, err := getUserIDFromContext(ctx)
	if err != nil {
		h.respondWithError(w, http.StatusUnauthorized, "authentication required")
		return
	}
	actorType := getSessionTypeFromContext(ctx)

	exemptionID, err := uuid.Parse(chi.URLParam(r, "exemptionID"))
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid exemption ID")
		return
	}

	if err := h.exemptionService.Delete(ctx, companyID, exemptionID, actorType, actorID); err != nil {
		h.writeServiceError(w, err, "delete exemption")
		return
	}

	h.respondWithJSON(w, http.StatusOK, map[string]interface{}{
		"success": true,
		"message": "exemption deleted",
	})
}

// ---------------------------------------------------------------------------
// Error mapping
// ---------------------------------------------------------------------------

func (h *AttendanceExemptionHandler) writeServiceError(w http.ResponseWriter, err error, op string) {
	switch {
	case errors.Is(err, exemption.ErrExemptionNotFound):
		h.respondWithError(w, http.StatusNotFound, "exemption not found")
	case errors.Is(err, exemption.ErrInvalidSubject):
		h.respondWithError(w, http.StatusBadRequest, err.Error())
	case errors.Is(err, exemption.ErrInvalidDateRange):
		h.respondWithError(w, http.StatusBadRequest, "from_date must be on or before to_date")
	case errors.Is(err, exemption.ErrOverlap):
		h.respondWithError(w, http.StatusConflict, err.Error())
	case errors.Is(err, resolver.ErrSubjectOutsideScope):
		h.respondWithError(w, http.StatusForbidden,
			"subject belongs to a different location than your current scope")
	case errors.Is(err, resolver.ErrSubjectHasNoLocation):
		h.respondWithError(w, http.StatusBadRequest,
			"target subject has no employment location assigned")
	case errors.Is(err, exemption.ErrUnauthorized):
		h.respondWithError(w, http.StatusForbidden, "not authorized")
	default:
		h.logger.Error("Exemption service error",
			zap.String("op", op),
			zap.Error(err),
		)
		h.respondWithError(w, http.StatusInternalServerError, "internal error")
	}
}

func (h *AttendanceExemptionHandler) respondWithJSON(w http.ResponseWriter, status int, data interface{}) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(data)
}

func (h *AttendanceExemptionHandler) respondWithError(w http.ResponseWriter, status int, message string) {
	h.respondWithJSON(w, status, map[string]interface{}{
		"success": false,
		"error":   message,
	})
}
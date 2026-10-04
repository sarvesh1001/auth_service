package handler

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"time"

	"github.com/google/uuid"
	"go.uber.org/zap"

	"auth-service/internal/attendance/service/admin"
	"auth-service/internal/attendance/service/resolver"
)

type AttendanceCorrectionHandler struct {
	correctionSvc admin.CorrectionService
	logger        *zap.Logger
}

func NewAttendanceCorrectionHandler(
	correctionSvc admin.CorrectionService,
	logger *zap.Logger,
) *AttendanceCorrectionHandler {
	return &AttendanceCorrectionHandler{
		correctionSvc: correctionSvc,
		logger:        logger,
	}
}

type CorrectionRequest struct {
	TargetUserID   uuid.UUID `json:"target_user_id"`
	SubjectType    string    `json:"subject_type,omitempty"`
	BusinessDate   string    `json:"business_date"`
	CorrectionType string    `json:"correction_type"`
	EventTime      string    `json:"event_time,omitempty"`
	OverrideStatus string    `json:"override_status,omitempty"`
	Reason         string    `json:"reason"`
}

func (h *AttendanceCorrectionHandler) mapCorrectionError(w http.ResponseWriter, err error) bool {
	switch {
	case errors.Is(err, resolver.ErrSubjectOutsideScope):
		h.respondWithError(w, http.StatusForbidden,
			"subject belongs to a different location than your current scope")
		return true
	case errors.Is(err, resolver.ErrSubjectHasNoLocation):
		h.respondWithError(w, http.StatusBadRequest,
			"target subject has no employment location assigned")
		return true
	}
	return false
}

// CreateCorrection creates an attendance correction.
//
// FIX (Handler hygiene):
//   - Accepts `subject_type` from the body (previously hardcoded to
//     "employee"). Defaults to "employee" when empty for backward compat.
//   - Removed the naive `businessDate.After(time.Now().UTC())` check. The
//     service already validates that event_time belongs to business_date
//     in the subject's timezone — a UTC comparison here rejected valid
//     corrections near local midnight for non-UTC subjects.
func (h *AttendanceCorrectionHandler) CreateCorrection(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	companyID, err := getCompanyIDFromContext(ctx)
	if err != nil {
		h.respondWithError(w, http.StatusUnauthorized, err.Error())
		return
	}
	actorType, actorID, err := h.getActorInfo(ctx)
	if err != nil {
		h.respondWithError(w, http.StatusUnauthorized, "authentication required")
		return
	}
	var req CorrectionRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid request body")
		return
	}
	if req.TargetUserID == uuid.Nil {
		h.respondWithError(w, http.StatusBadRequest, "target_user_id is required")
		return
	}
	if req.BusinessDate == "" {
		h.respondWithError(w, http.StatusBadRequest, "business_date is required")
		return
	}
	if req.CorrectionType == "" {
		h.respondWithError(w, http.StatusBadRequest, "correction_type is required")
		return
	}
	if req.Reason == "" {
		h.respondWithError(w, http.StatusBadRequest, "reason is required")
		return
	}
	businessDate, err := time.Parse("2006-01-02", req.BusinessDate)
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid business_date format, use YYYY-MM-DD")
		return
	}
	var eventTime *time.Time
	if req.EventTime != "" {
		parsedTime, err := time.Parse(time.RFC3339, req.EventTime)
		if err != nil {
			h.respondWithError(w, http.StatusBadRequest, "invalid event_time format, use RFC3339")
			return
		}
		eventTime = &parsedTime
	}
	subjectType := req.SubjectType
	if subjectType == "" {
		subjectType = "employee"
	}
	corrReq := &admin.CorrectionRequest{
		CompanyID:      companyID,
		ActorID:        actorID,
		ActorType:      actorType,
		SubjectType:    subjectType,
		SubjectID:      req.TargetUserID,
		BusinessDate:   businessDate,
		CorrectionType: req.CorrectionType,
		EventTime:      eventTime,
		OverrideStatus: req.OverrideStatus,
		Reason:         req.Reason,
	}
	if err := h.correctionSvc.CreateCorrection(ctx, corrReq); err != nil {
		if h.mapCorrectionError(w, err) {
			return
		}
		h.logger.Error("Failed to create attendance correction",
			zap.String("company_id", companyID.String()),
			zap.String("target_user_id", req.TargetUserID.String()),
			zap.String("subject_type", subjectType),
			zap.String("actor_id", actorID.String()),
			zap.Error(err),
		)
		h.respondWithError(w, http.StatusBadRequest, err.Error())
		return
	}
	h.respondWithJSON(w, http.StatusCreated, map[string]interface{}{
		"success": true,
		"message": "Attendance correction created successfully",
		"data": map[string]interface{}{
			"company_id":      companyID,
			"target_user_id":  req.TargetUserID,
			"subject_type":    subjectType,
			"business_date":   req.BusinessDate,
			"correction_type": req.CorrectionType,
			"created_by":      actorID,
			"created_at":      time.Now().UTC(),
		},
	})
}

func (h *AttendanceCorrectionHandler) getActorInfo(ctx context.Context) (string, uuid.UUID, error) {
	actorID, err := getUserIDFromContext(ctx)
	if err != nil {
		return "", uuid.Nil, err
	}
	return getSessionTypeFromContext(ctx), actorID, nil
}

func (h *AttendanceCorrectionHandler) respondWithJSON(w http.ResponseWriter, status int, data interface{}) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(data)
}

func (h *AttendanceCorrectionHandler) respondWithError(w http.ResponseWriter, status int, message string) {
	h.respondWithJSON(w, status, map[string]interface{}{
		"success": false,
		"error":   message,
	})
}
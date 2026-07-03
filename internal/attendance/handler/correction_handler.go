package handler

import (
	"context"
	"encoding/json"
	"net/http"
	"time"

	"github.com/google/uuid"
	"go.uber.org/zap"

	"auth-service/internal/attendance/service/admin"
)

// AttendanceCorrectionHandler handles attendance correction requests.
type AttendanceCorrectionHandler struct {
	correctionSvc admin.CorrectionService // ✅ Use CorrectionService
	logger        *zap.Logger
}

// NewAttendanceCorrectionHandler creates a new handler.
func NewAttendanceCorrectionHandler(
	correctionSvc admin.CorrectionService, // ✅ inject CorrectionService
	logger *zap.Logger,
) *AttendanceCorrectionHandler {
	return &AttendanceCorrectionHandler{
		correctionSvc: correctionSvc,
		logger:        logger,
	}
}

// CorrectionRequest represents the HTTP request for creating a correction.
type CorrectionRequest struct {
	TargetUserID   uuid.UUID `json:"target_user_id"`
	BusinessDate   string    `json:"business_date"`
	CorrectionType string    `json:"correction_type"`
	EventTime      string    `json:"event_time,omitempty"`
	OverrideStatus string    `json:"override_status,omitempty"`
	Reason         string    `json:"reason"`
}

// CreateCorrection creates a new attendance correction.
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

	// Validations
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
	if businessDate.After(time.Now().UTC()) {
		h.respondWithError(w, http.StatusBadRequest, "cannot correct future dates")
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

	corrReq := &admin.CorrectionRequest{
		CompanyID:      companyID,
		ActorID:        actorID,
		ActorType:      actorType,
		SubjectType:    "employee", // HR employees; can be parameterized later
		SubjectID:      req.TargetUserID,
		BusinessDate:   businessDate,
		CorrectionType: req.CorrectionType,
		EventTime:      eventTime,
		OverrideStatus: req.OverrideStatus,
		Reason:         req.Reason,
	}

	// ✅ Use correctionSvc.CreateCorrection
	if err := h.correctionSvc.CreateCorrection(ctx, corrReq); err != nil {
		h.logger.Error("Failed to create attendance correction",
			zap.String("company_id", companyID.String()),
			zap.String("target_user_id", req.TargetUserID.String()),
			zap.String("actor_id", actorID.String()),
			zap.Error(err),
		)
		h.respondWithError(w, http.StatusInternalServerError, "failed to create attendance correction")
		return
	}

	h.respondWithJSON(w, http.StatusCreated, map[string]interface{}{
		"success": true,
		"message": "Attendance correction created successfully",
		"data": map[string]interface{}{
			"company_id":      companyID,
			"target_user_id":  req.TargetUserID,
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

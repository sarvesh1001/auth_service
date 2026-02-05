package handler

import (
	"auth-service/internal/hr/service"
	"context"
	"encoding/json"
	"net/http"
	"time"

	"github.com/google/uuid"
	"go.uber.org/zap"
)

type AttendanceCorrectionHandler struct {
	adminService service.AttendanceAdminService
	logger       *zap.Logger
}

func NewAttendanceCorrectionHandler(
	adminService service.AttendanceAdminService,
	logger *zap.Logger,
) *AttendanceCorrectionHandler {
	return &AttendanceCorrectionHandler{
		adminService: adminService,
		logger:       logger,
	}
}

type AttendanceCorrectionRequest struct {
	TargetUserID   uuid.UUID `json:"target_user_id"`
	BusinessDate   string    `json:"business_date"`
	CorrectionType string    `json:"correction_type"`
	EventTime      string    `json:"event_time,omitempty"`
	OverrideStatus string    `json:"override_status,omitempty"`
	Reason         string    `json:"reason"`
}

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

	if !h.hasPermission(ctx, companyID, "attendance:correction:create") {
		h.respondWithError(w, http.StatusForbidden, "insufficient permissions")
		return
	}

	var req AttendanceCorrectionRequest
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

	correctionReq := &service.AttendanceCorrectionRequest{
		CompanyID:      companyID,
		ActorID:        actorID,
		ActorType:      actorType,
		TargetUserID:   req.TargetUserID,
		BusinessDate:   businessDate,
		CorrectionType: req.CorrectionType,
		EventTime:      eventTime,
		OverrideStatus: req.OverrideStatus,
		Reason:         req.Reason,
	}

	if err := h.adminService.CreateAttendanceCorrection(ctx, correctionReq); err != nil {
		h.logger.Error("Failed to create attendance correction",
			zap.String("company_id", companyID.String()),
			zap.String("user_id", req.TargetUserID.String()),
			zap.Error(err))
		h.respondWithError(w, http.StatusInternalServerError, "failed to create correction: "+err.Error())
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
	actorType := getSessionTypeFromContext(ctx)
	return actorType, actorID, nil
}

func (h *AttendanceCorrectionHandler) hasPermission(ctx context.Context, companyID uuid.UUID, permission string) bool {
	permissions, ok := ctx.Value("permissions").([]string)
	if !ok {
		return false
	}

	for _, p := range permissions {
		if p == permission {
			return true
		}
	}
	return false
}

func (h *AttendanceCorrectionHandler) respondWithJSON(w http.ResponseWriter, status int, data interface{}) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	json.NewEncoder(w).Encode(data)
}

func (h *AttendanceCorrectionHandler) respondWithError(w http.ResponseWriter, status int, message string) {
	h.respondWithJSON(w, status, map[string]interface{}{
		"success": false,
		"error":   message,
	})
}

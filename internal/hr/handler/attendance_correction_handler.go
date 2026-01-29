package handler

import (
	"auth-service/internal/hr/service"
	"encoding/json"
	"net/http"
	"time"

	"github.com/google/uuid"
	"go.uber.org/zap"
)

// AttendanceCorrectionHandler handles attendance correction requests
type AttendanceCorrectionHandler struct {
	adminService service.AttendanceAdminService
	logger       *zap.Logger
}

// NewAttendanceCorrectionHandler creates a new correction handler
func NewAttendanceCorrectionHandler(
	adminService service.AttendanceAdminService,
	logger *zap.Logger,
) *AttendanceCorrectionHandler {
	return &AttendanceCorrectionHandler{
		adminService: adminService,
		logger:       logger,
	}
}

// AttendanceCorrectionRequest defines the API request for corrections
type AttendanceCorrectionRequest struct {
	TargetUserID   uuid.UUID `json:"target_user_id"`
	BusinessDate   string    `json:"business_date"`
	CorrectionType string    `json:"correction_type"`
	EventTime      string    `json:"event_time,omitempty"`
	OverrideStatus string    `json:"override_status,omitempty"`
	Reason         string    `json:"reason"`
}

// CreateCorrection handles POST /companies/{companyId}/attendance/events/correction
func (h *AttendanceCorrectionHandler) CreateCorrection(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	companyID, err := mustGetCompanyID(r)
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid company ID")
		return
	}

	// Get actor info
	actorType, actorID, err := h.getActorInfo(ctx)
	if err != nil {
		h.respondWithError(w, http.StatusUnauthorized, "authentication required")
		return
	}

	// Check permissions
	if !h.hasPermission(ctx, companyID, "attendance:correction:create") {
		h.respondWithError(w, http.StatusForbidden, "insufficient permissions")
		return
	}

	// Parse request
	var req AttendanceCorrectionRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid request body")
		return
	}

	// Validate required fields
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

	// Parse business date
	businessDate, err := time.Parse("2006-01-02", req.BusinessDate)
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid business_date format, use YYYY-MM-DD")
		return
	}

	// Validate business date is not in future
	if businessDate.After(time.Now().UTC()) {
		h.respondWithError(w, http.StatusBadRequest, "cannot correct future dates")
		return
	}

	// Parse event time if provided
	var eventTime *time.Time
	if req.EventTime != "" {
		parsedTime, err := time.Parse(time.RFC3339, req.EventTime)
		if err != nil {
			h.respondWithError(w, http.StatusBadRequest, "invalid event_time format, use RFC3339")
			return
		}
		eventTime = &parsedTime
	}

	// Create service request
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

	// Call admin service
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

func (h *AttendanceCorrectionHandler) getActorInfo(ctx interface{}) (string, uuid.UUID, error) {
	// Implementation depends on your auth system
	// This is a placeholder - replace with actual auth logic
	return "user", uuid.New(), nil
}

func (h *AttendanceCorrectionHandler) hasPermission(ctx interface{}, companyID uuid.UUID, permission string) bool {
	// Implementation depends on your permission system
	// This is a placeholder - replace with actual permission check
	return true
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

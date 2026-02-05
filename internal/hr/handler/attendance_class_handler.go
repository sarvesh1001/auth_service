package handler

import (
	"encoding/json"
	"net/http"
	"time"

	"auth-service/internal/hr/service"
	"auth-service/internal/util"

	"github.com/google/uuid"
	"go.uber.org/zap"
)

type AttendanceClassHandler struct {
	classService service.ClassAttendanceService
	logger       *zap.Logger
}

func NewAttendanceClassHandler(
	classService service.ClassAttendanceService,
	logger *zap.Logger,
) *AttendanceClassHandler {
	return &AttendanceClassHandler{
		classService: classService,
		logger:       logger,
	}
}

type ClassAttendanceHTTPRequest struct {
	Date   string `json:"date"`
	Status string `json:"status"`
	Reason string `json:"reason"`
}

// POST /companies/{companyId}/attendance/classes/{orgUnitId}/mark
func (h *AttendanceClassHandler) MarkClassAttendance(
	w http.ResponseWriter,
	r *http.Request,
) {
	ctx := r.Context()

	actorIDStr := ctx.Value("user_id").(string)
	companyIDStr := ctx.Value("company_id").(string)

	actorID, _ := uuid.Parse(actorIDStr)
	companyID, _ := uuid.Parse(companyIDStr)

	orgUnitIDStr := util.PathParam(r, "orgUnitId")
	orgUnitID, err := uuid.Parse(orgUnitIDStr)
	if err != nil {
		h.respondError(w, http.StatusBadRequest, "invalid org_unit_id")
		return
	}

	var body ClassAttendanceHTTPRequest
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		h.respondError(w, http.StatusBadRequest, "invalid request body")
		return
	}

	date, err := time.Parse("2006-01-02", body.Date)
	if err != nil {
		h.respondError(w, http.StatusBadRequest, "invalid date format")
		return
	}

	result, err := h.classService.MarkClassAttendance(ctx,
		&service.ClassAttendanceRequest{
			CompanyID: companyID,
			ActorID:   actorID,
			ActorType: "teacher",
			OrgUnitID: orgUnitID,
			Date:      date,
			Status:    body.Status,
			Reason:    body.Reason,
		},
	)
	if err != nil {
		h.respondError(w, http.StatusBadRequest, err.Error())
		return
	}

	h.respondJSON(w, http.StatusCreated, map[string]interface{}{
		"success": true,
		"data":    result,
	})
}

func (h *AttendanceClassHandler) respondJSON(
	w http.ResponseWriter,
	status int,
	data interface{},
) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(data)
}

func (h *AttendanceClassHandler) respondError(
	w http.ResponseWriter,
	status int,
	msg string,
) {
	h.respondJSON(w, status, map[string]interface{}{
		"success": false,
		"error":   msg,
	})
}

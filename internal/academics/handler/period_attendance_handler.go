package handler

import (
	"context"
	"encoding/json"
	"net/http"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"
	"go.uber.org/zap"

	"auth-service/internal/academics/models"
	"auth-service/internal/academics/service"
)

// PeriodAttendanceHandler handles endpoints for period‑wise (college) attendance.
type PeriodAttendanceHandler struct {
	periodSvc service.PeriodAttendanceService
	logger    *zap.Logger
}

// NewPeriodAttendanceHandler creates a new handler instance.
func NewPeriodAttendanceHandler(periodSvc service.PeriodAttendanceService, logger *zap.Logger) *PeriodAttendanceHandler {
	return &PeriodAttendanceHandler{
		periodSvc: periodSvc,
		logger:    logger.Named("period_attendance_handler"),
	}
}

// ----------------------------------------------------------------------------
// Teacher marking endpoints
// ----------------------------------------------------------------------------

// MarkPeriodAttendance marks attendance for a single student in a session.
// POST /companies/{companyID}/academics/attendance/period
func (h *PeriodAttendanceHandler) MarkPeriodAttendance(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	companyIDStr := chi.URLParam(r, "companyID")
	companyID, err := uuid.Parse(companyIDStr)
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid company ID")
		return
	}

	userID, err := getUserIDFromContext(ctx)
	if err != nil {
		h.respondWithError(w, http.StatusUnauthorized, "authentication required")
		return
	}

	if !hasPermission(ctx, companyID, "attendance:period_mark") {
		h.respondWithError(w, http.StatusForbidden, "insufficient permissions")
		return
	}

	var req service.MarkPeriodAttendanceRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid request body")
		return
	}

	// Set defaults
	if req.MarkedBy == nil {
		req.MarkedBy = &userID
	}
	if req.SourceType == "" {
		req.SourceType = models.SourceWeb
	}

	idempotencyKey := r.Header.Get("Idempotency-Key")
	att, err := h.periodSvc.MarkSessionAttendance(ctx, req, idempotencyKey)
	if err != nil {
		h.logger.Error("Failed to mark period attendance",
			zap.String("session_id", req.SessionID.String()),
			zap.String("enrollment_id", req.EnrollmentID.String()),
			zap.Error(err))
		h.respondWithError(w, http.StatusBadRequest, err.Error())
		return
	}

	h.respondWithJSON(w, http.StatusCreated, map[string]interface{}{
		"success": true,
		"data":    att,
		"message": "Period attendance marked successfully",
	})
}

// BulkMarkPeriodAttendance marks attendance for multiple students in a session.
// POST /companies/{companyID}/academics/attendance/period/sessions/{sessionID}/bulk
func (h *PeriodAttendanceHandler) BulkMarkPeriodAttendance(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	companyIDStr := chi.URLParam(r, "companyID")
	companyID, err := uuid.Parse(companyIDStr)
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid company ID")
		return
	}

	sessionIDStr := chi.URLParam(r, "sessionID")
	sessionID, err := uuid.Parse(sessionIDStr)
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid session ID")
		return
	}

	userID, err := getUserIDFromContext(ctx)
	if err != nil {
		h.respondWithError(w, http.StatusUnauthorized, "authentication required")
		return
	}

	if !hasPermission(ctx, companyID, "attendance:period_bulk_mark") {
		h.respondWithError(w, http.StatusForbidden, "insufficient permissions")
		return
	}

	var items []service.BulkPeriodAttendanceItem
	if err := json.NewDecoder(r.Body).Decode(&items); err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid request body")
		return
	}

	sourceType := models.SourceWeb
	if st := r.URL.Query().Get("source_type"); st != "" {
		sourceType = models.AttendanceSourceType(st)
	}

	attendances, err := h.periodSvc.BulkMarkSessionAttendance(ctx, sessionID, items, &userID, sourceType)
	if err != nil {
		h.logger.Error("Failed to bulk mark period attendance",
			zap.String("session_id", sessionID.String()),
			zap.Int("count", len(items)),
			zap.Error(err))
		h.respondWithError(w, http.StatusBadRequest, err.Error())
		return
	}

	h.respondWithJSON(w, http.StatusCreated, map[string]interface{}{
		"success": true,
		"data":    attendances,
		"message": "Bulk period attendance marked successfully",
	})
}

// ----------------------------------------------------------------------------
// Session listing endpoints (for teachers / sections)
// ----------------------------------------------------------------------------

// GetTeacherSessions returns all academic sessions for a teacher on a given date.
// GET /companies/{companyID}/academics/attendance/period/teachers/{teacherID}/sessions
func (h *PeriodAttendanceHandler) GetTeacherSessions(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	companyIDStr := chi.URLParam(r, "companyID")
	companyID, err := uuid.Parse(companyIDStr)
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid company ID")
		return
	}

	teacherIDStr := chi.URLParam(r, "teacherID")
	teacherID, err := uuid.Parse(teacherIDStr)
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid teacher ID")
		return
	}

	// Optional date parameter; default to today
	dateStr := r.URL.Query().Get("date")
	var date time.Time
	if dateStr == "" {
		date = time.Now()
	} else {
		date, err = time.Parse("2006-01-02", dateStr)
		if err != nil {
			h.respondWithError(w, http.StatusBadRequest, "invalid date format (use YYYY-MM-DD)")
			return
		}
	}

	if !hasPermission(ctx, companyID, "attendance:period_read") {
		h.respondWithError(w, http.StatusForbidden, "insufficient permissions")
		return
	}

	sessions, err := h.periodSvc.GetTeacherSessions(ctx, teacherID, date)
	if err != nil {
		h.logger.Error("Failed to get teacher sessions",
			zap.String("teacher_id", teacherID.String()),
			zap.Time("date", date),
			zap.Error(err))
		h.respondWithError(w, http.StatusInternalServerError, "failed to retrieve sessions")
		return
	}

	h.respondWithJSON(w, http.StatusOK, map[string]interface{}{
		"success": true,
		"data":    sessions,
	})
}

// GetSectionSessions returns all academic sessions for a section on a given date.
// GET /companies/{companyID}/academics/attendance/period/sections/{sectionID}/sessions
func (h *PeriodAttendanceHandler) GetSectionSessions(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	companyIDStr := chi.URLParam(r, "companyID")
	companyID, err := uuid.Parse(companyIDStr)
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid company ID")
		return
	}

	sectionIDStr := chi.URLParam(r, "sectionID")
	sectionID, err := uuid.Parse(sectionIDStr)
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid section ID")
		return
	}

	dateStr := r.URL.Query().Get("date")
	var date time.Time
	if dateStr == "" {
		date = time.Now()
	} else {
		date, err = time.Parse("2006-01-02", dateStr)
		if err != nil {
			h.respondWithError(w, http.StatusBadRequest, "invalid date format (use YYYY-MM-DD)")
			return
		}
	}

	if !hasPermission(ctx, companyID, "attendance:period_read") {
		h.respondWithError(w, http.StatusForbidden, "insufficient permissions")
		return
	}

	sessions, err := h.periodSvc.GetSectionSessions(ctx, sectionID, date)
	if err != nil {
		h.logger.Error("Failed to get section sessions",
			zap.String("section_id", sectionID.String()),
			zap.Time("date", date),
			zap.Error(err))
		h.respondWithError(w, http.StatusInternalServerError, "failed to retrieve sessions")
		return
	}

	h.respondWithJSON(w, http.StatusOK, map[string]interface{}{
		"success": true,
		"data":    sessions,
	})
}

// ----------------------------------------------------------------------------
// Attendance retrieval endpoints
// ----------------------------------------------------------------------------

// GetSessionAttendance returns all period attendances for a given session.
// GET /companies/{companyID}/academics/attendance/period/sessions/{sessionID}
func (h *PeriodAttendanceHandler) GetSessionAttendance(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	companyIDStr := chi.URLParam(r, "companyID")
	companyID, err := uuid.Parse(companyIDStr)
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid company ID")
		return
	}

	sessionIDStr := chi.URLParam(r, "sessionID")
	sessionID, err := uuid.Parse(sessionIDStr)
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid session ID")
		return
	}

	if !hasPermission(ctx, companyID, "attendance:period_read") {
		h.respondWithError(w, http.StatusForbidden, "insufficient permissions")
		return
	}

	attendances, err := h.periodSvc.GetSessionAttendance(ctx, sessionID)
	if err != nil {
		h.logger.Error("Failed to get session attendance",
			zap.String("session_id", sessionID.String()),
			zap.Error(err))
		h.respondWithError(w, http.StatusInternalServerError, "failed to retrieve session attendance")
		return
	}

	h.respondWithJSON(w, http.StatusOK, map[string]interface{}{
		"success": true,
		"data":    attendances,
	})
}

// GetStudentPeriodAttendance returns attendance for a specific student in a session.
// GET /companies/{companyID}/academics/attendance/period/sessions/{sessionID}/students/{enrollmentID}
func (h *PeriodAttendanceHandler) GetStudentPeriodAttendance(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	companyIDStr := chi.URLParam(r, "companyID")
	companyID, err := uuid.Parse(companyIDStr)
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid company ID")
		return
	}

	sessionIDStr := chi.URLParam(r, "sessionID")
	sessionID, err := uuid.Parse(sessionIDStr)
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid session ID")
		return
	}

	enrollmentIDStr := chi.URLParam(r, "enrollmentID")
	enrollmentID, err := uuid.Parse(enrollmentIDStr)
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid enrollment ID")
		return
	}

	if !hasPermission(ctx, companyID, "attendance:period_read") {
		h.respondWithError(w, http.StatusForbidden, "insufficient permissions")
		return
	}

	att, err := h.periodSvc.GetStudentAttendanceForSession(ctx, sessionID, enrollmentID)
	if err != nil {
		h.logger.Error("Failed to get student period attendance",
			zap.String("session_id", sessionID.String()),
			zap.String("enrollment_id", enrollmentID.String()),
			zap.Error(err))
		h.respondWithError(w, http.StatusNotFound, err.Error())
		return
	}

	h.respondWithJSON(w, http.StatusOK, map[string]interface{}{
		"success": true,
		"data":    att,
	})
}

// ----------------------------------------------------------------------------
// Helper methods (consistent with your existing handlers)
// ----------------------------------------------------------------------------

func (h *PeriodAttendanceHandler) respondWithJSON(w http.ResponseWriter, status int, data interface{}) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	if err := json.NewEncoder(w).Encode(data); err != nil {
		h.logger.Error("Failed to encode JSON response", zap.Error(err))
	}
}

func (h *PeriodAttendanceHandler) respondWithError(w http.ResponseWriter, status int, message string) {
	h.respondWithJSON(w, status, map[string]interface{}{
		"success": false,
		"error":   message,
	})
}

// ----------------------------------------------------------------------------
// Shared helper functions (used by multiple handlers)
// ----------------------------------------------------------------------------

// hasPermission is a placeholder – integrate with your actual permission system.
func hasPermission(ctx context.Context, companyID uuid.UUID, permission string) bool {
	// TODO: Replace with real RBAC check.
	return true
}

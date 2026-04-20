package handler

import (
	"context"
	"encoding/json"
	"net/http"
	"strconv"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"
	"go.uber.org/zap"

	"auth-service/internal/academics/models"
	"auth-service/internal/academics/service"
)

// AttendanceHandler handles all attendance operations.
type AttendanceHandler struct {
	fullDaySvc          service.AttendanceService
	periodSvc           service.PeriodAttendanceService
	biometricSvc        service.BiometricService
	studentBiometricSvc service.StudentBiometricService
	logger              *zap.Logger
}

// NewAttendanceHandler creates a new handler with all required services.
func NewAttendanceHandler(
	fullDaySvc service.AttendanceService,
	periodSvc service.PeriodAttendanceService,
	biometricSvc service.BiometricService,
	studentBiometricSvc service.StudentBiometricService,
	logger *zap.Logger,
) *AttendanceHandler {
	return &AttendanceHandler{
		fullDaySvc:          fullDaySvc,
		periodSvc:           periodSvc,
		biometricSvc:        biometricSvc,
		studentBiometricSvc: studentBiometricSvc,
		logger:              logger.Named("attendance_handler"),
	}
}

// ----------------------------------------------------------------------------
// Full‑Day Attendance (school mode) – methods with names expected by router
// ----------------------------------------------------------------------------

func (h *AttendanceHandler) MarkAttendance(w http.ResponseWriter, r *http.Request) {
	// unchanged from previous version (kept as is)
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

	if !h.hasPermission(ctx, companyID, "attendance:mark") {
		h.respondWithError(w, http.StatusForbidden, "insufficient permissions")
		return
	}

	var req service.MarkAttendanceRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid request body")
		return
	}

	if req.CreatedBy == nil {
		req.CreatedBy = &userID
	}
	if req.MarkedBy == nil {
		req.MarkedBy = &userID
	}

	idempotencyKey := r.Header.Get("Idempotency-Key")
	attendance, err := h.fullDaySvc.MarkAttendance(ctx, req, idempotencyKey)
	if err != nil {
		h.logger.Error("Failed to mark attendance",
			zap.String("enrollment_id", req.EnrollmentID.String()),
			zap.Time("date", req.Date),
			zap.String("status", string(req.Status)),
			zap.Error(err))
		h.respondWithError(w, http.StatusBadRequest, err.Error())
		return
	}

	h.respondWithJSON(w, http.StatusCreated, map[string]interface{}{
		"success": true,
		"data":    attendance,
		"message": "Attendance marked successfully",
	})
}

func (h *AttendanceHandler) BulkMarkAttendance(w http.ResponseWriter, r *http.Request) {
	// unchanged
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

	if !h.hasPermission(ctx, companyID, "attendance:bulk_mark") {
		h.respondWithError(w, http.StatusForbidden, "insufficient permissions")
		return
	}

	var req service.BulkMarkAttendanceRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid request body")
		return
	}

	if req.CreatedBy == nil {
		req.CreatedBy = &userID
	}
	for i := range req.Attendances {
		if req.Attendances[i].CreatedBy == nil {
			req.Attendances[i].CreatedBy = &userID
		}
		if req.Attendances[i].MarkedBy == nil {
			req.Attendances[i].MarkedBy = &userID
		}
	}

	attendances, err := h.fullDaySvc.BulkMarkAttendance(ctx, req)
	if err != nil {
		h.logger.Error("Failed to bulk mark attendance",
			zap.Int("count", len(req.Attendances)),
			zap.Error(err))
		h.respondWithError(w, http.StatusBadRequest, err.Error())
		return
	}

	h.respondWithJSON(w, http.StatusCreated, map[string]interface{}{
		"success": true,
		"data":    attendances,
		"message": "Bulk attendance marked successfully",
	})
}

// GetByID is the name expected by router.
func (h *AttendanceHandler) GetByID(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	companyIDStr := chi.URLParam(r, "companyID")
	companyID, err := uuid.Parse(companyIDStr)
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid company ID")
		return
	}

	attendanceIDStr := chi.URLParam(r, "attendanceID")
	attendanceID, err := uuid.Parse(attendanceIDStr)
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid attendance ID")
		return
	}

	if !h.hasPermission(ctx, companyID, "attendance:read") {
		h.respondWithError(w, http.StatusForbidden, "insufficient permissions")
		return
	}

	attendance, err := h.fullDaySvc.GetAttendanceByID(ctx, attendanceID)
	if err != nil {
		h.logger.Error("Failed to get attendance",
			zap.String("attendance_id", attendanceID.String()),
			zap.Error(err))
		h.respondWithError(w, http.StatusNotFound, err.Error())
		return
	}

	h.respondWithJSON(w, http.StatusOK, map[string]interface{}{
		"success": true,
		"data":    attendance,
	})
}

// List is the name expected by router.
func (h *AttendanceHandler) List(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	companyIDStr := chi.URLParam(r, "companyID")
	companyID, err := uuid.Parse(companyIDStr)
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid company ID")
		return
	}

	if !h.hasPermission(ctx, companyID, "attendance:read") {
		h.respondWithError(w, http.StatusForbidden, "insufficient permissions")
		return
	}

	filter := service.ListAttendanceRequest{}

	if enrollmentIDStr := r.URL.Query().Get("enrollment_id"); enrollmentIDStr != "" {
		if id, err := uuid.Parse(enrollmentIDStr); err == nil {
			filter.EnrollmentID = &id
		}
	}
	if studentIDStr := r.URL.Query().Get("student_id"); studentIDStr != "" {
		if id, err := uuid.Parse(studentIDStr); err == nil {
			filter.StudentID = &id
		}
	}
	if sectionIDStr := r.URL.Query().Get("section_id"); sectionIDStr != "" {
		if id, err := uuid.Parse(sectionIDStr); err == nil {
			filter.SectionID = &id
		}
	}
	if termIDStr := r.URL.Query().Get("term_id"); termIDStr != "" {
		if id, err := uuid.Parse(termIDStr); err == nil {
			filter.TermID = &id
		}
	}
	if academicYearIDStr := r.URL.Query().Get("academic_year_id"); academicYearIDStr != "" {
		if id, err := uuid.Parse(academicYearIDStr); err == nil {
			filter.AcademicYearID = &id
		}
	}
	if fromDateStr := r.URL.Query().Get("from_date"); fromDateStr != "" {
		if t, err := time.Parse("2006-01-02", fromDateStr); err == nil {
			filter.FromDate = &t
		}
	}
	if toDateStr := r.URL.Query().Get("to_date"); toDateStr != "" {
		if t, err := time.Parse("2006-01-02", toDateStr); err == nil {
			filter.ToDate = &t
		}
	}
	if statusStr := r.URL.Query().Get("status"); statusStr != "" {
		status := models.AttendanceStatus(statusStr)
		filter.Status = &status
	}
	if markedByStr := r.URL.Query().Get("marked_by"); markedByStr != "" {
		if id, err := uuid.Parse(markedByStr); err == nil {
			filter.MarkedBy = &id
		}
	}

	limit, _ := strconv.Atoi(r.URL.Query().Get("limit"))
	if limit <= 0 || limit > 1000 {
		limit = 50
	}
	filter.Limit = limit

	offset, _ := strconv.Atoi(r.URL.Query().Get("offset"))
	if offset < 0 {
		offset = 0
	}
	filter.Offset = offset

	filter.SortField = r.URL.Query().Get("sort_field")
	if filter.SortField == "" {
		filter.SortField = "attendance_date"
	}
	filter.SortDirection = r.URL.Query().Get("sort_direction")
	if filter.SortDirection == "" {
		filter.SortDirection = "DESC"
	}

	attendances, total, err := h.fullDaySvc.ListAttendance(ctx, filter)
	if err != nil {
		h.logger.Error("Failed to list attendance",
			zap.Any("filter", filter),
			zap.Error(err))
		h.respondWithError(w, http.StatusInternalServerError, "failed to list attendance")
		return
	}

	h.respondWithJSON(w, http.StatusOK, map[string]interface{}{
		"success": true,
		"data": map[string]interface{}{
			"attendances": attendances,
			"total":       total,
			"limit":       limit,
			"offset":      offset,
		},
	})
}

// Delete is the name expected by router.
func (h *AttendanceHandler) Delete(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	companyIDStr := chi.URLParam(r, "companyID")
	companyID, err := uuid.Parse(companyIDStr)
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid company ID")
		return
	}

	attendanceIDStr := chi.URLParam(r, "attendanceID")
	attendanceID, err := uuid.Parse(attendanceIDStr)
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid attendance ID")
		return
	}

	if !h.hasPermission(ctx, companyID, "attendance:delete") {
		h.respondWithError(w, http.StatusForbidden, "insufficient permissions")
		return
	}

	err = h.fullDaySvc.DeleteAttendance(ctx, attendanceID, nil)
	if err != nil {
		h.logger.Error("Failed to delete attendance",
			zap.String("attendance_id", attendanceID.String()),
			zap.Error(err))
		h.respondWithError(w, http.StatusBadRequest, err.Error())
		return
	}

	h.respondWithJSON(w, http.StatusOK, map[string]interface{}{
		"success": true,
		"message": "Attendance deleted successfully",
	})
}

// GetSummary is the name expected by router.
func (h *AttendanceHandler) GetSummary(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	companyIDStr := chi.URLParam(r, "companyID")
	companyID, err := uuid.Parse(companyIDStr)
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid company ID")
		return
	}

	studentIDStr := chi.URLParam(r, "studentID")
	studentID, err := uuid.Parse(studentIDStr)
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid student ID")
		return
	}

	academicYearIDStr := chi.URLParam(r, "academicYearID")
	academicYearID, err := uuid.Parse(academicYearIDStr)
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid academic year ID")
		return
	}

	if !h.hasPermission(ctx, companyID, "attendance:read") {
		h.respondWithError(w, http.StatusForbidden, "insufficient permissions")
		return
	}

	termIDStr := r.URL.Query().Get("term_id")
	var termID *uuid.UUID
	if termIDStr != "" {
		if parsed, err := uuid.Parse(termIDStr); err == nil {
			termID = &parsed
		}
	}

	summary, err := h.fullDaySvc.GetSummary(ctx, studentID, academicYearID, termID)
	if err != nil {
		h.logger.Error("Failed to get attendance summary",
			zap.String("student_id", studentID.String()),
			zap.String("academic_year_id", academicYearID.String()),
			zap.Error(err))
		h.respondWithError(w, http.StatusNotFound, err.Error())
		return
	}

	h.respondWithJSON(w, http.StatusOK, map[string]interface{}{
		"success": true,
		"data":    summary,
	})
}

// RecalculateSummary is the name expected by router.
func (h *AttendanceHandler) RecalculateSummary(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	companyIDStr := chi.URLParam(r, "companyID")
	companyID, err := uuid.Parse(companyIDStr)
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid company ID")
		return
	}

	studentIDStr := chi.URLParam(r, "studentID")
	studentID, err := uuid.Parse(studentIDStr)
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid student ID")
		return
	}

	academicYearIDStr := chi.URLParam(r, "academicYearID")
	academicYearID, err := uuid.Parse(academicYearIDStr)
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid academic year ID")
		return
	}

	if !h.hasPermission(ctx, companyID, "attendance:recalculate") {
		h.respondWithError(w, http.StatusForbidden, "insufficient permissions")
		return
	}

	var req struct {
		TermID *uuid.UUID `json:"term_id,omitempty"`
	}
	if r.ContentLength > 0 {
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			h.respondWithError(w, http.StatusBadRequest, "invalid request body")
			return
		}
	}

	err = h.fullDaySvc.RecalculateSummary(ctx, studentID, academicYearID, req.TermID)
	if err != nil {
		h.logger.Error("Failed to recalculate summary",
			zap.String("student_id", studentID.String()),
			zap.String("academic_year_id", academicYearID.String()),
			zap.Error(err))
		h.respondWithError(w, http.StatusBadRequest, err.Error())
		return
	}

	h.respondWithJSON(w, http.StatusOK, map[string]interface{}{
		"success": true,
		"message": "Attendance summary recalculated successfully",
	})
}

// BulkRecalcSummaries is the name expected by router.
func (h *AttendanceHandler) BulkRecalcSummaries(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	companyIDStr := chi.URLParam(r, "companyID")
	companyID, err := uuid.Parse(companyIDStr)
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid company ID")
		return
	}

	if !h.hasPermission(ctx, companyID, "attendance:recalculate") {
		h.respondWithError(w, http.StatusForbidden, "insufficient permissions")
		return
	}

	var req struct {
		StudentIDs     []uuid.UUID `json:"student_ids"`
		AcademicYearID uuid.UUID   `json:"academic_year_id"`
		TermID         *uuid.UUID  `json:"term_id,omitempty"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid request body")
		return
	}

	if len(req.StudentIDs) == 0 || req.AcademicYearID == uuid.Nil {
		h.respondWithError(w, http.StatusBadRequest, "student_ids and academic_year_id are required")
		return
	}

	err = h.fullDaySvc.BulkRecalcSummaries(ctx, req.StudentIDs, req.AcademicYearID, req.TermID)
	if err != nil {
		h.logger.Error("Failed to bulk recalc summaries",
			zap.Int("count", len(req.StudentIDs)),
			zap.String("academic_year_id", req.AcademicYearID.String()),
			zap.Error(err))
		h.respondWithError(w, http.StatusBadRequest, err.Error())
		return
	}

	h.respondWithJSON(w, http.StatusOK, map[string]interface{}{
		"success": true,
		"message": "Bulk attendance summaries recalculated successfully",
	})
}

// CreateExemption is the name expected by router.
func (h *AttendanceHandler) CreateExemption(w http.ResponseWriter, r *http.Request) {
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

	if !h.hasPermission(ctx, companyID, "attendance:manage_exemptions") {
		h.respondWithError(w, http.StatusForbidden, "insufficient permissions")
		return
	}

	var req service.CreateAttendanceExemptionRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid request body")
		return
	}

	if req.CreatedBy == nil {
		req.CreatedBy = &userID
	}

	idempotencyKey := r.Header.Get("Idempotency-Key")
	exemption, err := h.fullDaySvc.CreateExemption(ctx, req, idempotencyKey)
	if err != nil {
		h.logger.Error("Failed to create exemption",
			zap.String("student_id", req.StudentID.String()),
			zap.Time("from", req.FromDate),
			zap.Time("to", req.ToDate),
			zap.Error(err))
		h.respondWithError(w, http.StatusBadRequest, err.Error())
		return
	}

	h.respondWithJSON(w, http.StatusCreated, map[string]interface{}{
		"success": true,
		"data":    exemption,
		"message": "Exemption created successfully",
	})
}

// UpdateExemption is the name expected by router.
func (h *AttendanceHandler) UpdateExemption(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	companyIDStr := chi.URLParam(r, "companyID")
	companyID, err := uuid.Parse(companyIDStr)
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid company ID")
		return
	}

	exemptionIDStr := chi.URLParam(r, "exemptionID")
	exemptionID, err := uuid.Parse(exemptionIDStr)
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid exemption ID")
		return
	}

	userID, err := getUserIDFromContext(ctx)
	if err != nil {
		h.respondWithError(w, http.StatusUnauthorized, "authentication required")
		return
	}

	if !h.hasPermission(ctx, companyID, "attendance:manage_exemptions") {
		h.respondWithError(w, http.StatusForbidden, "insufficient permissions")
		return
	}

	var req service.UpdateAttendanceExemptionRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid request body")
		return
	}
	req.ExemptionID = exemptionID
	req.UpdatedBy = &userID

	exemption, err := h.fullDaySvc.UpdateExemption(ctx, req)
	if err != nil {
		h.logger.Error("Failed to update exemption",
			zap.String("exemption_id", exemptionID.String()),
			zap.Error(err))
		h.respondWithError(w, http.StatusBadRequest, err.Error())
		return
	}

	h.respondWithJSON(w, http.StatusOK, map[string]interface{}{
		"success": true,
		"data":    exemption,
		"message": "Exemption updated successfully",
	})
}

// DeleteExemption is the name expected by router.
func (h *AttendanceHandler) DeleteExemption(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	companyIDStr := chi.URLParam(r, "companyID")
	companyID, err := uuid.Parse(companyIDStr)
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid company ID")
		return
	}

	exemptionIDStr := chi.URLParam(r, "exemptionID")
	exemptionID, err := uuid.Parse(exemptionIDStr)
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid exemption ID")
		return
	}

	if !h.hasPermission(ctx, companyID, "attendance:manage_exemptions") {
		h.respondWithError(w, http.StatusForbidden, "insufficient permissions")
		return
	}

	err = h.fullDaySvc.DeleteExemption(ctx, exemptionID, nil)
	if err != nil {
		h.logger.Error("Failed to delete exemption",
			zap.String("exemption_id", exemptionID.String()),
			zap.Error(err))
		h.respondWithError(w, http.StatusBadRequest, err.Error())
		return
	}

	h.respondWithJSON(w, http.StatusOK, map[string]interface{}{
		"success": true,
		"message": "Exemption deleted successfully",
	})
}

// ListExemptions is the name expected by router.
func (h *AttendanceHandler) ListExemptions(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	companyIDStr := chi.URLParam(r, "companyID")
	companyID, err := uuid.Parse(companyIDStr)
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid company ID")
		return
	}

	if !h.hasPermission(ctx, companyID, "attendance:read") {
		h.respondWithError(w, http.StatusForbidden, "insufficient permissions")
		return
	}

	var studentID *uuid.UUID
	if studentIDStr := r.URL.Query().Get("student_id"); studentIDStr != "" {
		if parsed, err := uuid.Parse(studentIDStr); err == nil {
			studentID = &parsed
		}
	}

	var fromDate, toDate *time.Time
	if fromDateStr := r.URL.Query().Get("from_date"); fromDateStr != "" {
		if parsed, err := time.Parse("2006-01-02", fromDateStr); err == nil {
			fromDate = &parsed
		}
	}
	if toDateStr := r.URL.Query().Get("to_date"); toDateStr != "" {
		if parsed, err := time.Parse("2006-01-02", toDateStr); err == nil {
			toDate = &parsed
		}
	}

	limit, _ := strconv.Atoi(r.URL.Query().Get("limit"))
	if limit <= 0 || limit > 1000 {
		limit = 50
	}
	offset, _ := strconv.Atoi(r.URL.Query().Get("offset"))
	if offset < 0 {
		offset = 0
	}

	exemptions, err := h.fullDaySvc.ListExemptions(ctx, studentID, fromDate, toDate, limit, offset)
	if err != nil {
		h.logger.Error("Failed to list exemptions",
			zap.Any("student_id", studentID),
			zap.Any("from_date", fromDate),
			zap.Any("to_date", toDate),
			zap.Error(err))
		h.respondWithError(w, http.StatusInternalServerError, "failed to list exemptions")
		return
	}

	h.respondWithJSON(w, http.StatusOK, map[string]interface{}{
		"success": true,
		"data": map[string]interface{}{
			"exemptions": exemptions,
			"limit":      limit,
			"offset":     offset,
		},
	})
}

// ----------------------------------------------------------------------------
// Period Attendance (college mode) – new methods (router not yet using them)
// ----------------------------------------------------------------------------

func (h *AttendanceHandler) MarkPeriodAttendance(w http.ResponseWriter, r *http.Request) {
	// as previously implemented
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

	if !h.hasPermission(ctx, companyID, "attendance:period_mark") {
		h.respondWithError(w, http.StatusForbidden, "insufficient permissions")
		return
	}

	var req service.MarkPeriodAttendanceRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid request body")
		return
	}

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

func (h *AttendanceHandler) BulkMarkPeriodAttendance(w http.ResponseWriter, r *http.Request) {
	// as previously implemented
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

	if !h.hasPermission(ctx, companyID, "attendance:period_bulk_mark") {
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

func (h *AttendanceHandler) GetSessionAttendance(w http.ResponseWriter, r *http.Request) {
	// as previously implemented
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

	if !h.hasPermission(ctx, companyID, "attendance:period_read") {
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

func (h *AttendanceHandler) GetStudentPeriodAttendance(w http.ResponseWriter, r *http.Request) {
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

	if !h.hasPermission(ctx, companyID, "attendance:period_read") {
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

func (h *AttendanceHandler) GetTeacherSessions(w http.ResponseWriter, r *http.Request) {
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

	dateStr := r.URL.Query().Get("date")
	if dateStr == "" {
		dateStr = time.Now().Format("2006-01-02")
	}
	date, err := time.Parse("2006-01-02", dateStr)
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid date format (use YYYY-MM-DD)")
		return
	}

	if !h.hasPermission(ctx, companyID, "attendance:period_read") {
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

func (h *AttendanceHandler) GetSectionSessions(w http.ResponseWriter, r *http.Request) {
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
	if dateStr == "" {
		dateStr = time.Now().Format("2006-01-02")
	}
	date, err := time.Parse("2006-01-02", dateStr)
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid date format (use YYYY-MM-DD)")
		return
	}

	if !h.hasPermission(ctx, companyID, "attendance:period_read") {
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
// Biometric Punch Webhook for Period Attendance
// ----------------------------------------------------------------------------

// ProcessBiometricPunch handles biometric device webhook punches for period attendance (college mode).
// It resolves student, finds active session, and marks attendance.
// If a manual attendance already exists for that session, the punch is ignored
// and the existing record is returned with a specific message.
func (h *AttendanceHandler) ProcessBiometricPunch(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	companyIDStr := chi.URLParam(r, "companyID")
	companyID, err := uuid.Parse(companyIDStr)
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid company ID")
		return
	}

	var req service.BiometricPunchRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid request body")
		return
	}
	req.CompanyID = companyID

	if req.PunchTime.IsZero() {
		req.PunchTime = time.Now().UTC()
	}

	idempotencyKey := r.Header.Get("Idempotency-Key")
	att, err := h.biometricSvc.ProcessPunch(ctx, req, idempotencyKey)
	if err != nil {
		h.logger.Error("Failed to process biometric punch",
			zap.String("device_id", req.DeviceID),
			zap.String("user_code", req.DeviceUserCode),
			zap.Error(err))
		h.respondWithError(w, http.StatusBadRequest, err.Error())
		return
	}

	// Determine appropriate message based on whether the attendance was actually created by this punch.
	message := "Biometric punch processed"
	if att != nil && !att.IsAuto && att.SourceType != models.SourceBiometric {
		message = "Biometric punch ignored: manual attendance already exists"
	}

	h.respondWithJSON(w, http.StatusOK, map[string]interface{}{
		"success": true,
		"data":    att,
		"message": message,
	})
}

// ----------------------------------------------------------------------------
// Biometric Punch Webhook for Full‑Day Attendance
// ----------------------------------------------------------------------------

// ProcessBiometricFullDayPunch handles biometric device webhook punches for full‑day attendance (school mode).
// It resolves student, finds active enrollment for the punch date, and marks attendance.
// If a manual attendance already exists for that date, the punch is ignored and the existing record is returned.
func (h *AttendanceHandler) ProcessBiometricFullDayPunch(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	companyIDStr := chi.URLParam(r, "companyID")
	companyID, err := uuid.Parse(companyIDStr)
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid company ID")
		return
	}

	var req service.BiometricPunchRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid request body")
		return
	}
	req.CompanyID = companyID

	if req.PunchTime.IsZero() {
		req.PunchTime = time.Now().UTC()
	}

	idempotencyKey := r.Header.Get("Idempotency-Key")
	att, err := h.biometricSvc.ProcessFullDayPunch(ctx, req, idempotencyKey)
	if err != nil {
		h.logger.Error("Failed to process full‑day biometric punch",
			zap.String("device_id", req.DeviceID),
			zap.String("user_code", req.DeviceUserCode),
			zap.Error(err))
		h.respondWithError(w, http.StatusBadRequest, err.Error())
		return
	}

	message := "Biometric full‑day punch processed"
	if att != nil && att.SourceType != nil && *att.SourceType != models.SourceBiometric {
		message = "Biometric full‑day punch ignored: manual attendance already exists"
	}

	h.respondWithJSON(w, http.StatusOK, map[string]interface{}{
		"success": true,
		"data":    att,
		"message": message,
	})
}

// ----------------------------------------------------------------------------
// Student Biometric Mapping CRUD
// ----------------------------------------------------------------------------

func (h *AttendanceHandler) CreateBiometricMapping(w http.ResponseWriter, r *http.Request) {
	// as previously implemented
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

	if !h.hasPermission(ctx, companyID, "attendance:manage_biometric_mappings") {
		h.respondWithError(w, http.StatusForbidden, "insufficient permissions")
		return
	}

	var req service.CreateBiometricMappingRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid request body")
		return
	}
	req.CompanyID = companyID
	if req.EnrolledBy == nil {
		req.EnrolledBy = &userID
	}

	idempotencyKey := r.Header.Get("Idempotency-Key")
	mapping, err := h.studentBiometricSvc.CreateMapping(ctx, req, idempotencyKey)
	if err != nil {
		h.logger.Error("Failed to create biometric mapping",
			zap.String("student_id", req.StudentID.String()),
			zap.String("device_id", req.DeviceID),
			zap.Error(err))
		h.respondWithError(w, http.StatusBadRequest, err.Error())
		return
	}

	h.respondWithJSON(w, http.StatusCreated, map[string]interface{}{
		"success": true,
		"data":    mapping,
		"message": "Biometric mapping created",
	})
}

func (h *AttendanceHandler) GetBiometricMappingByID(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	companyIDStr := chi.URLParam(r, "companyID")
	companyID, err := uuid.Parse(companyIDStr)
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid company ID")
		return
	}

	mappingIDStr := chi.URLParam(r, "mappingID")
	mappingID, err := uuid.Parse(mappingIDStr)
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid mapping ID")
		return
	}

	if !h.hasPermission(ctx, companyID, "attendance:read") {
		h.respondWithError(w, http.StatusForbidden, "insufficient permissions")
		return
	}

	mapping, err := h.studentBiometricSvc.GetMappingByID(ctx, mappingID)
	if err != nil {
		h.logger.Error("Failed to get biometric mapping",
			zap.String("mapping_id", mappingID.String()),
			zap.Error(err))
		h.respondWithError(w, http.StatusNotFound, err.Error())
		return
	}

	h.respondWithJSON(w, http.StatusOK, map[string]interface{}{
		"success": true,
		"data":    mapping,
	})
}

func (h *AttendanceHandler) ListBiometricMappings(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	companyIDStr := chi.URLParam(r, "companyID")
	companyID, err := uuid.Parse(companyIDStr)
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid company ID")
		return
	}

	if !h.hasPermission(ctx, companyID, "attendance:read") {
		h.respondWithError(w, http.StatusForbidden, "insufficient permissions")
		return
	}

	filter := service.BiometricMappingFilter{
		CompanyID: &companyID,
	}

	if studentIDStr := r.URL.Query().Get("student_id"); studentIDStr != "" {
		if sid, err := uuid.Parse(studentIDStr); err == nil {
			filter.StudentID = &sid
		}
	}
	if deviceID := r.URL.Query().Get("device_id"); deviceID != "" {
		filter.DeviceID = &deviceID
	}
	if userCode := r.URL.Query().Get("device_user_code"); userCode != "" {
		filter.DeviceUserCode = &userCode
	}
	if isActiveStr := r.URL.Query().Get("is_active"); isActiveStr != "" {
		if active, err := strconv.ParseBool(isActiveStr); err == nil {
			filter.IsActive = &active
		}
	}

	limit, _ := strconv.Atoi(r.URL.Query().Get("limit"))
	if limit <= 0 || limit > 1000 {
		limit = 50
	}
	offset, _ := strconv.Atoi(r.URL.Query().Get("offset"))
	if offset < 0 {
		offset = 0
	}

	mappings, total, err := h.studentBiometricSvc.ListMappings(ctx, filter, limit, offset)
	if err != nil {
		h.logger.Error("Failed to list biometric mappings",
			zap.Any("filter", filter),
			zap.Error(err))
		h.respondWithError(w, http.StatusInternalServerError, "failed to list mappings")
		return
	}

	h.respondWithJSON(w, http.StatusOK, map[string]interface{}{
		"success": true,
		"data": map[string]interface{}{
			"mappings": mappings,
			"total":    total,
			"limit":    limit,
			"offset":   offset,
		},
	})
}

func (h *AttendanceHandler) UpdateBiometricMapping(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	companyIDStr := chi.URLParam(r, "companyID")
	companyID, err := uuid.Parse(companyIDStr)
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid company ID")
		return
	}

	mappingIDStr := chi.URLParam(r, "mappingID")
	mappingID, err := uuid.Parse(mappingIDStr)
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid mapping ID")
		return
	}

	userID, err := getUserIDFromContext(ctx)
	if err != nil {
		h.respondWithError(w, http.StatusUnauthorized, "authentication required")
		return
	}

	if !h.hasPermission(ctx, companyID, "attendance:manage_biometric_mappings") {
		h.respondWithError(w, http.StatusForbidden, "insufficient permissions")
		return
	}

	var req service.UpdateBiometricMappingRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid request body")
		return
	}
	req.MappingID = mappingID
	if req.EnrolledBy == nil {
		req.EnrolledBy = &userID
	}

	idempotencyKey := r.Header.Get("Idempotency-Key")
	mapping, err := h.studentBiometricSvc.UpdateMapping(ctx, req, idempotencyKey)
	if err != nil {
		h.logger.Error("Failed to update biometric mapping",
			zap.String("mapping_id", mappingID.String()),
			zap.Error(err))
		h.respondWithError(w, http.StatusBadRequest, err.Error())
		return
	}

	h.respondWithJSON(w, http.StatusOK, map[string]interface{}{
		"success": true,
		"data":    mapping,
		"message": "Biometric mapping updated",
	})
}

func (h *AttendanceHandler) DeleteBiometricMapping(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	companyIDStr := chi.URLParam(r, "companyID")
	companyID, err := uuid.Parse(companyIDStr)
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid company ID")
		return
	}

	mappingIDStr := chi.URLParam(r, "mappingID")
	mappingID, err := uuid.Parse(mappingIDStr)
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid mapping ID")
		return
	}

	if !h.hasPermission(ctx, companyID, "attendance:manage_biometric_mappings") {
		h.respondWithError(w, http.StatusForbidden, "insufficient permissions")
		return
	}

	err = h.studentBiometricSvc.DeleteMapping(ctx, mappingID, nil)
	if err != nil {
		h.logger.Error("Failed to delete biometric mapping",
			zap.String("mapping_id", mappingID.String()),
			zap.Error(err))
		h.respondWithError(w, http.StatusBadRequest, err.Error())
		return
	}

	h.respondWithJSON(w, http.StatusOK, map[string]interface{}{
		"success": true,
		"message": "Biometric mapping deleted",
	})
}

func (h *AttendanceHandler) DeactivateStudentBiometricMappings(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	companyIDStr := chi.URLParam(r, "companyID")
	companyID, err := uuid.Parse(companyIDStr)
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid company ID")
		return
	}

	studentIDStr := chi.URLParam(r, "studentID")
	studentID, err := uuid.Parse(studentIDStr)
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid student ID")
		return
	}

	if !h.hasPermission(ctx, companyID, "attendance:manage_biometric_mappings") {
		h.respondWithError(w, http.StatusForbidden, "insufficient permissions")
		return
	}

	err = h.studentBiometricSvc.DeactivateByStudent(ctx, studentID, nil)
	if err != nil {
		h.logger.Error("Failed to deactivate biometric mappings for student",
			zap.String("student_id", studentID.String()),
			zap.Error(err))
		h.respondWithError(w, http.StatusBadRequest, err.Error())
		return
	}

	h.respondWithJSON(w, http.StatusOK, map[string]interface{}{
		"success": true,
		"message": "All biometric mappings deactivated for student",
	})
}

// ----------------------------------------------------------------------------
// Helpers
// ----------------------------------------------------------------------------

func (h *AttendanceHandler) hasPermission(ctx context.Context, companyID uuid.UUID, permission string) bool {
	// TODO: Replace with real RBAC check.
	return true
}

func (h *AttendanceHandler) respondWithJSON(w http.ResponseWriter, status int, data interface{}) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	if err := json.NewEncoder(w).Encode(data); err != nil {
		h.logger.Error("Failed to encode JSON response", zap.Error(err))
	}
}

func (h *AttendanceHandler) respondWithError(w http.ResponseWriter, status int, message string) {
	h.respondWithJSON(w, status, map[string]interface{}{
		"success": false,
		"error":   message,
	})
}

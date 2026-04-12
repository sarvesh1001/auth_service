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

	"auth-service/internal/academics/service"
)

type AttendanceHandler struct {
	attendanceService service.AttendanceService
	logger            *zap.Logger
}

func NewAttendanceHandler(attendanceService service.AttendanceService, logger *zap.Logger) *AttendanceHandler {
	return &AttendanceHandler{
		attendanceService: attendanceService,
		logger:            logger.Named("attendance_handler"),
	}
}

func (h *AttendanceHandler) MarkAttendance(w http.ResponseWriter, r *http.Request) {
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

	// Read idempotency key from header (standard practice)
	idempotencyKey := r.Header.Get("Idempotency-Key")

	attendance, err := h.attendanceService.MarkAttendance(ctx, req, idempotencyKey)
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

	attendances, err := h.attendanceService.BulkMarkAttendance(ctx, req)
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

	attendance, err := h.attendanceService.GetAttendanceByID(ctx, attendanceID)
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
		enrollmentID, err := uuid.Parse(enrollmentIDStr)
		if err == nil {
			filter.EnrollmentID = &enrollmentID
		}
	}
	if studentIDStr := r.URL.Query().Get("student_id"); studentIDStr != "" {
		studentID, err := uuid.Parse(studentIDStr)
		if err == nil {
			filter.StudentID = &studentID
		}
	}
	if sectionIDStr := r.URL.Query().Get("section_id"); sectionIDStr != "" {
		sectionID, err := uuid.Parse(sectionIDStr)
		if err == nil {
			filter.SectionID = &sectionID
		}
	}
	if termIDStr := r.URL.Query().Get("term_id"); termIDStr != "" {
		termID, err := uuid.Parse(termIDStr)
		if err == nil {
			filter.TermID = &termID
		}
	}
	if academicYearIDStr := r.URL.Query().Get("academic_year_id"); academicYearIDStr != "" {
		academicYearID, err := uuid.Parse(academicYearIDStr)
		if err == nil {
			filter.AcademicYearID = &academicYearID
		}
	}
	if fromDateStr := r.URL.Query().Get("from_date"); fromDateStr != "" {
		if fromDate, err := time.Parse("2006-01-02", fromDateStr); err == nil {
			filter.FromDate = &fromDate
		}
	}
	if toDateStr := r.URL.Query().Get("to_date"); toDateStr != "" {
		if toDate, err := time.Parse("2006-01-02", toDateStr); err == nil {
			filter.ToDate = &toDate
		}
	}
	if status := r.URL.Query().Get("status"); status != "" {
		filter.Status = &status
	}
	if markedByStr := r.URL.Query().Get("marked_by"); markedByStr != "" {
		markedBy, err := uuid.Parse(markedByStr)
		if err == nil {
			filter.MarkedBy = &markedBy
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

	attendances, total, err := h.attendanceService.ListAttendance(ctx, filter)
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

	err = h.attendanceService.DeleteAttendance(ctx, attendanceID, nil)
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

	summary, err := h.attendanceService.GetSummary(ctx, studentID, academicYearID, termID)
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

// RecalculateSummary recalculates attendance summary for a specific student and academic year.
// studentID and academicYearID are taken from URL parameters, term_id is optional from JSON body.
func (h *AttendanceHandler) RecalculateSummary(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	companyIDStr := chi.URLParam(r, "companyID")
	companyID, err := uuid.Parse(companyIDStr)
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid company ID")
		return
	}

	// Extract student ID from URL
	studentIDStr := chi.URLParam(r, "studentID")
	studentID, err := uuid.Parse(studentIDStr)
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid student ID")
		return
	}

	// Extract academic year ID from URL
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

	// Read optional term_id from request body
	var req struct {
		TermID *uuid.UUID `json:"term_id,omitempty"`
	}
	// Only decode if there is a body
	if r.ContentLength > 0 {
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			h.respondWithError(w, http.StatusBadRequest, "invalid request body")
			return
		}
	}

	err = h.attendanceService.RecalculateSummary(ctx, studentID, academicYearID, req.TermID)
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

	err = h.attendanceService.BulkRecalcSummaries(ctx, req.StudentIDs, req.AcademicYearID, req.TermID)
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

	// Read idempotency key from header for exemptions as well
	idempotencyKey := r.Header.Get("Idempotency-Key")

	exemption, err := h.attendanceService.CreateExemption(ctx, req, idempotencyKey)
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

	exemption, err := h.attendanceService.UpdateExemption(ctx, req)
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

	err = h.attendanceService.DeleteExemption(ctx, exemptionID, nil)
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

	exemptions, err := h.attendanceService.ListExemptions(ctx, studentID, fromDate, toDate, limit, offset)
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

// hasPermission is a placeholder – integrate with your actual permission system.
func (h *AttendanceHandler) hasPermission(ctx context.Context, companyID uuid.UUID, permission string) bool {
	// TODO: Replace with real permission check (e.g., using context values or RBAC).
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

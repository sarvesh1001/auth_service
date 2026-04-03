package handler

import (
	"context"
	"encoding/json"
	"net/http"
	"strconv"

	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"
	"go.uber.org/zap"

	"auth-service/internal/academics/repository"
	"auth-service/internal/academics/service"
)

// ExamHandler handles HTTP requests for exam management.
type ExamHandler struct {
	examService service.ExamService
	logger      *zap.Logger
}

// NewExamHandler creates a new ExamHandler.
func NewExamHandler(examService service.ExamService, logger *zap.Logger) *ExamHandler {
	return &ExamHandler{
		examService: examService,
		logger:      logger.Named("exam_handler"),
	}
}

// ---------------------------------------------------------------------
// Exam endpoints
// ---------------------------------------------------------------------

// CreateExam handles POST /api/v1/companies/{companyID}/exams
func (h *ExamHandler) CreateExam(w http.ResponseWriter, r *http.Request) {
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

	if !h.hasPermission(ctx, companyID, "exam:create") {
		h.respondWithError(w, http.StatusForbidden, "insufficient permissions")
		return
	}

	var req service.CreateExamRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid request body")
		return
	}

	// Validate required fields
	if req.AcademicYearID == uuid.Nil {
		h.respondWithError(w, http.StatusBadRequest, "academic_year_id is required")
		return
	}
	if req.TermID == uuid.Nil {
		h.respondWithError(w, http.StatusBadRequest, "term_id is required")
		return
	}
	if req.ExamName == "" {
		h.respondWithError(w, http.StatusBadRequest, "exam_name is required")
		return
	}
	if req.StartDate.IsZero() || req.EndDate.IsZero() {
		h.respondWithError(w, http.StatusBadRequest, "start_date and end_date are required")
		return
	}
	if req.StartDate.After(req.EndDate) {
		h.respondWithError(w, http.StatusBadRequest, "start_date must be before end_date")
		return
	}

	req.CreatedBy = &userID
	req.UpdatedBy = &userID

	exam, err := h.examService.CreateExam(ctx, req)
	if err != nil {
		h.logger.Error("Failed to create exam",
			zap.String("exam_name", req.ExamName),
			zap.String("academic_year_id", req.AcademicYearID.String()),
			zap.String("term_id", req.TermID.String()),
			zap.Error(err))
		h.respondWithError(w, http.StatusBadRequest, err.Error())
		return
	}

	h.respondWithJSON(w, http.StatusCreated, map[string]interface{}{
		"success": true,
		"data":    exam,
		"message": "Exam created successfully",
	})
}

// GetExam handles GET /api/v1/companies/{companyID}/exams/{examID}
func (h *ExamHandler) GetExam(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	companyIDStr := chi.URLParam(r, "companyID")
	companyID, err := uuid.Parse(companyIDStr)
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid company ID")
		return
	}

	examIDStr := chi.URLParam(r, "examID")
	examID, err := uuid.Parse(examIDStr)
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid exam ID")
		return
	}

	if !h.hasPermission(ctx, companyID, "exam:read") {
		h.respondWithError(w, http.StatusForbidden, "insufficient permissions")
		return
	}

	exam, err := h.examService.GetExamByID(ctx, examID)
	if err != nil {
		h.logger.Error("Failed to get exam",
			zap.String("exam_id", examID.String()),
			zap.Error(err))
		h.respondWithError(w, http.StatusNotFound, err.Error())
		return
	}

	h.respondWithJSON(w, http.StatusOK, map[string]interface{}{
		"success": true,
		"data":    exam,
	})
}

// ListExams handles GET /api/v1/companies/{companyID}/exams with query params
// ListExams handles GET /api/v1/companies/{companyID}/exams with query params
// ListExams handles GET /api/v1/companies/{companyID}/exams with query params
func (h *ExamHandler) ListExams(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	companyIDStr := chi.URLParam(r, "companyID")
	companyID, err := uuid.Parse(companyIDStr)
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid company ID")
		return
	}

	if !h.hasPermission(ctx, companyID, "exam:read") {
		h.respondWithError(w, http.StatusForbidden, "insufficient permissions")
		return
	}

	// Build filter
	filter := repository.ExamFilter{}
	if termIDStr := r.URL.Query().Get("term_id"); termIDStr != "" {
		termID, err := uuid.Parse(termIDStr)
		if err == nil {
			filter.TermID = &termID // field expects *uuid.UUID
		}
	}
	if academicYearIDStr := r.URL.Query().Get("academic_year_id"); academicYearIDStr != "" {
		academicYearID, err := uuid.Parse(academicYearIDStr)
		if err == nil {
			filter.AcademicYearID = academicYearID // field expects uuid.UUID (non-pointer)
		}
	}
	if search := r.URL.Query().Get("search"); search != "" {
		filter.Search = search
	}
	if isActiveStr := r.URL.Query().Get("is_active"); isActiveStr != "" {
		isActive, err := strconv.ParseBool(isActiveStr)
		if err == nil {
			filter.IsActive = &isActive // field expects *bool
		}
	}

	// Pagination
	limit, _ := strconv.Atoi(r.URL.Query().Get("limit"))
	if limit <= 0 || limit > 100 {
		limit = 20
	}
	offset, _ := strconv.Atoi(r.URL.Query().Get("offset"))
	if offset < 0 {
		offset = 0
	}
	pagination := repository.Pagination{Limit: limit, Offset: offset}

	// Sorting
	sortField := r.URL.Query().Get("sort_field")
	if sortField == "" {
		sortField = "start_date"
	}
	sortDirection := r.URL.Query().Get("sort_direction")
	if sortDirection == "" {
		sortDirection = "DESC"
	}
	sort := repository.Sort{Field: sortField, Direction: sortDirection}

	exams, err := h.examService.ListExams(ctx, filter, pagination, sort)
	if err != nil {
		h.logger.Error("Failed to list exams", zap.Error(err))
		h.respondWithError(w, http.StatusInternalServerError, "failed to list exams")
		return
	}

	h.respondWithJSON(w, http.StatusOK, map[string]interface{}{
		"success": true,
		"data": map[string]interface{}{
			"exams":  exams,
			"limit":  limit,
			"offset": offset,
		},
	})
}

// UpdateExam handles PUT /api/v1/companies/{companyID}/exams/{examID}
func (h *ExamHandler) UpdateExam(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	companyIDStr := chi.URLParam(r, "companyID")
	companyID, err := uuid.Parse(companyIDStr)
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid company ID")
		return
	}

	examIDStr := chi.URLParam(r, "examID")
	examID, err := uuid.Parse(examIDStr)
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid exam ID")
		return
	}

	userID, err := getUserIDFromContext(ctx)
	if err != nil {
		h.respondWithError(w, http.StatusUnauthorized, "authentication required")
		return
	}

	if !h.hasPermission(ctx, companyID, "exam:update") {
		h.respondWithError(w, http.StatusForbidden, "insufficient permissions")
		return
	}

	var req service.UpdateExamRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid request body")
		return
	}

	req.ExamID = examID
	req.UpdatedBy = &userID

	exam, err := h.examService.UpdateExam(ctx, req)
	if err != nil {
		h.logger.Error("Failed to update exam",
			zap.String("exam_id", examID.String()),
			zap.Error(err))
		h.respondWithError(w, http.StatusBadRequest, err.Error())
		return
	}

	h.respondWithJSON(w, http.StatusOK, map[string]interface{}{
		"success": true,
		"data":    exam,
		"message": "Exam updated successfully",
	})
}

// DeleteExam handles DELETE /api/v1/companies/{companyID}/exams/{examID}
func (h *ExamHandler) DeleteExam(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	companyIDStr := chi.URLParam(r, "companyID")
	companyID, err := uuid.Parse(companyIDStr)
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid company ID")
		return
	}

	examIDStr := chi.URLParam(r, "examID")
	examID, err := uuid.Parse(examIDStr)
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid exam ID")
		return
	}

	userID, err := getUserIDFromContext(ctx)
	if err != nil {
		h.respondWithError(w, http.StatusUnauthorized, "authentication required")
		return
	}

	if !h.hasPermission(ctx, companyID, "exam:delete") {
		h.respondWithError(w, http.StatusForbidden, "insufficient permissions")
		return
	}

	err = h.examService.DeleteExam(ctx, examID, &userID)
	if err != nil {
		h.logger.Error("Failed to delete exam",
			zap.String("exam_id", examID.String()),
			zap.Error(err))
		h.respondWithError(w, http.StatusBadRequest, err.Error())
		return
	}

	h.respondWithJSON(w, http.StatusOK, map[string]interface{}{
		"success": true,
		"message": "Exam deleted successfully",
	})
}

// ---------------------------------------------------------------------
// Exam Schedule endpoints
// ---------------------------------------------------------------------

// CreateExamSchedule handles POST /api/v1/companies/{companyID}/exams/{examID}/schedules
func (h *ExamHandler) CreateExamSchedule(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	companyIDStr := chi.URLParam(r, "companyID")
	companyID, err := uuid.Parse(companyIDStr)
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid company ID")
		return
	}

	examIDStr := chi.URLParam(r, "examID")
	examID, err := uuid.Parse(examIDStr)
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid exam ID")
		return
	}

	userID, err := getUserIDFromContext(ctx)
	if err != nil {
		h.respondWithError(w, http.StatusUnauthorized, "authentication required")
		return
	}

	if !h.hasPermission(ctx, companyID, "exam:schedule:create") {
		h.respondWithError(w, http.StatusForbidden, "insufficient permissions")
		return
	}

	var req service.CreateExamScheduleRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid request body")
		return
	}

	req.ExamID = examID
	req.CreatedBy = &userID
	req.UpdatedBy = &userID

	// Validate required fields
	if req.SubjectID == uuid.Nil {
		h.respondWithError(w, http.StatusBadRequest, "subject_id is required")
		return
	}
	if req.Date.IsZero() {
		h.respondWithError(w, http.StatusBadRequest, "date is required")
		return
	}
	if req.MaxMarks <= 0 {
		h.respondWithError(w, http.StatusBadRequest, "max_marks must be positive")
		return
	}
	if req.PassingMarks < 0 {
		h.respondWithError(w, http.StatusBadRequest, "passing_marks cannot be negative")
		return
	}

	schedule, err := h.examService.CreateExamSchedule(ctx, req)
	if err != nil {
		h.logger.Error("Failed to create exam schedule",
			zap.String("exam_id", examID.String()),
			zap.String("subject_id", req.SubjectID.String()),
			zap.Error(err))
		h.respondWithError(w, http.StatusBadRequest, err.Error())
		return
	}

	h.respondWithJSON(w, http.StatusCreated, map[string]interface{}{
		"success": true,
		"data":    schedule,
		"message": "Exam schedule created successfully",
	})
}

// GetExamSchedule handles GET /api/v1/companies/{companyID}/exam-schedules/{scheduleID}
func (h *ExamHandler) GetExamSchedule(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	companyIDStr := chi.URLParam(r, "companyID")
	companyID, err := uuid.Parse(companyIDStr)
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid company ID")
		return
	}

	scheduleIDStr := chi.URLParam(r, "scheduleID")
	scheduleID, err := uuid.Parse(scheduleIDStr)
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid schedule ID")
		return
	}

	if !h.hasPermission(ctx, companyID, "exam:schedule:read") {
		h.respondWithError(w, http.StatusForbidden, "insufficient permissions")
		return
	}

	schedule, err := h.examService.GetExamScheduleByID(ctx, scheduleID)
	if err != nil {
		h.logger.Error("Failed to get exam schedule",
			zap.String("schedule_id", scheduleID.String()),
			zap.Error(err))
		h.respondWithError(w, http.StatusNotFound, err.Error())
		return
	}

	h.respondWithJSON(w, http.StatusOK, map[string]interface{}{
		"success": true,
		"data":    schedule,
	})
}

// ListExamSchedules handles GET /api/v1/companies/{companyID}/exams/{examID}/schedules
func (h *ExamHandler) ListExamSchedules(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	companyIDStr := chi.URLParam(r, "companyID")
	companyID, err := uuid.Parse(companyIDStr)
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid company ID")
		return
	}

	examIDStr := chi.URLParam(r, "examID")
	examID, err := uuid.Parse(examIDStr)
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid exam ID")
		return
	}

	if !h.hasPermission(ctx, companyID, "exam:schedule:read") {
		h.respondWithError(w, http.StatusForbidden, "insufficient permissions")
		return
	}

	// Build filter
	filter := repository.ExamScheduleFilter{
		ExamID: examID, // removed & (field expects uuid.UUID)
	}
	if subjectIDStr := r.URL.Query().Get("subject_id"); subjectIDStr != "" {
		subjectID, err := uuid.Parse(subjectIDStr)
		if err == nil {
			filter.SubjectID = &subjectID // keep pointer if field expects *uuid.UUID
		}
	}
	if fromDateStr := r.URL.Query().Get("from_date"); fromDateStr != "" {
		// If needed, parse time.Time
	}

	// Pagination
	limit, _ := strconv.Atoi(r.URL.Query().Get("limit"))
	if limit <= 0 || limit > 100 {
		limit = 20
	}
	offset, _ := strconv.Atoi(r.URL.Query().Get("offset"))
	if offset < 0 {
		offset = 0
	}
	pagination := repository.Pagination{Limit: limit, Offset: offset}

	// Sorting
	sortField := r.URL.Query().Get("sort_field")
	if sortField == "" {
		sortField = "date"
	}
	sortDirection := r.URL.Query().Get("sort_direction")
	if sortDirection == "" {
		sortDirection = "ASC"
	}
	sort := repository.Sort{Field: sortField, Direction: sortDirection}

	schedules, err := h.examService.ListExamSchedules(ctx, filter, pagination, sort)
	if err != nil {
		h.logger.Error("Failed to list exam schedules", zap.Error(err))
		h.respondWithError(w, http.StatusInternalServerError, "failed to list exam schedules")
		return
	}

	h.respondWithJSON(w, http.StatusOK, map[string]interface{}{
		"success": true,
		"data": map[string]interface{}{
			"schedules": schedules,
			"limit":     limit,
			"offset":    offset,
		},
	})
}

// UpdateExamSchedule handles PUT /api/v1/companies/{companyID}/exam-schedules/{scheduleID}
func (h *ExamHandler) UpdateExamSchedule(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	companyIDStr := chi.URLParam(r, "companyID")
	companyID, err := uuid.Parse(companyIDStr)
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid company ID")
		return
	}

	scheduleIDStr := chi.URLParam(r, "scheduleID")
	scheduleID, err := uuid.Parse(scheduleIDStr)
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid schedule ID")
		return
	}

	userID, err := getUserIDFromContext(ctx)
	if err != nil {
		h.respondWithError(w, http.StatusUnauthorized, "authentication required")
		return
	}

	if !h.hasPermission(ctx, companyID, "exam:schedule:update") {
		h.respondWithError(w, http.StatusForbidden, "insufficient permissions")
		return
	}

	var req service.UpdateExamScheduleRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid request body")
		return
	}

	req.ScheduleID = scheduleID
	req.UpdatedBy = &userID

	schedule, err := h.examService.UpdateExamSchedule(ctx, req)
	if err != nil {
		h.logger.Error("Failed to update exam schedule",
			zap.String("schedule_id", scheduleID.String()),
			zap.Error(err))
		h.respondWithError(w, http.StatusBadRequest, err.Error())
		return
	}

	h.respondWithJSON(w, http.StatusOK, map[string]interface{}{
		"success": true,
		"data":    schedule,
		"message": "Exam schedule updated successfully",
	})
}

// DeleteExamSchedule handles DELETE /api/v1/companies/{companyID}/exam-schedules/{scheduleID}
func (h *ExamHandler) DeleteExamSchedule(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	companyIDStr := chi.URLParam(r, "companyID")
	companyID, err := uuid.Parse(companyIDStr)
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid company ID")
		return
	}

	scheduleIDStr := chi.URLParam(r, "scheduleID")
	scheduleID, err := uuid.Parse(scheduleIDStr)
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid schedule ID")
		return
	}

	if !h.hasPermission(ctx, companyID, "exam:schedule:delete") {
		h.respondWithError(w, http.StatusForbidden, "insufficient permissions")
		return
	}

	err = h.examService.DeleteExamSchedule(ctx, scheduleID)
	if err != nil {
		h.logger.Error("Failed to delete exam schedule",
			zap.String("schedule_id", scheduleID.String()),
			zap.Error(err))
		h.respondWithError(w, http.StatusBadRequest, err.Error())
		return
	}

	h.respondWithJSON(w, http.StatusOK, map[string]interface{}{
		"success": true,
		"message": "Exam schedule deleted successfully",
	})
}

// ---------------------------------------------------------------------
// Exam Result endpoints
// ---------------------------------------------------------------------

// CreateExamResult handles POST /api/v1/companies/{companyID}/exam-results
func (h *ExamHandler) CreateExamResult(w http.ResponseWriter, r *http.Request) {
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

	if !h.hasPermission(ctx, companyID, "exam:result:create") {
		h.respondWithError(w, http.StatusForbidden, "insufficient permissions")
		return
	}

	var req service.CreateExamResultRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid request body")
		return
	}

	// Validate required fields
	if req.ExamID == uuid.Nil {
		h.respondWithError(w, http.StatusBadRequest, "exam_id is required")
		return
	}
	if req.EnrollmentID == uuid.Nil {
		h.respondWithError(w, http.StatusBadRequest, "enrollment_id is required")
		return
	}
	if req.SubjectID == uuid.Nil {
		h.respondWithError(w, http.StatusBadRequest, "subject_id is required")
		return
	}

	req.EnteredBy = &userID
	req.CreatedBy = &userID

	result, err := h.examService.CreateExamResult(ctx, req)
	if err != nil {
		h.logger.Error("Failed to create exam result",
			zap.String("exam_id", req.ExamID.String()),
			zap.String("enrollment_id", req.EnrollmentID.String()),
			zap.String("subject_id", req.SubjectID.String()),
			zap.Error(err))
		h.respondWithError(w, http.StatusBadRequest, err.Error())
		return
	}

	h.respondWithJSON(w, http.StatusCreated, map[string]interface{}{
		"success": true,
		"data":    result,
		"message": "Exam result created successfully",
	})
}

// BulkCreateExamResults handles POST /api/v1/companies/{companyID}/exam-results/bulk
func (h *ExamHandler) BulkCreateExamResults(w http.ResponseWriter, r *http.Request) {
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

	if !h.hasPermission(ctx, companyID, "exam:result:bulk_create") {
		h.respondWithError(w, http.StatusForbidden, "insufficient permissions")
		return
	}

	var reqs []service.CreateExamResultRequest
	if err := json.NewDecoder(r.Body).Decode(&reqs); err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid request body")
		return
	}

	if len(reqs) == 0 {
		h.respondWithError(w, http.StatusBadRequest, "empty batch")
		return
	}

	for i := range reqs {
		reqs[i].EnteredBy = &userID
		reqs[i].CreatedBy = &userID
	}

	results, err := h.examService.BulkCreateExamResults(ctx, reqs)
	if err != nil {
		h.logger.Error("Failed to bulk create exam results",
			zap.Int("batch_size", len(reqs)),
			zap.Error(err))
		h.respondWithError(w, http.StatusBadRequest, err.Error())
		return
	}

	h.respondWithJSON(w, http.StatusCreated, map[string]interface{}{
		"success": true,
		"data":    results,
		"message": "Exam results created successfully",
	})
}

// GetExamResult handles GET /api/v1/companies/{companyID}/exam-results/{resultID}
func (h *ExamHandler) GetExamResult(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	companyIDStr := chi.URLParam(r, "companyID")
	companyID, err := uuid.Parse(companyIDStr)
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid company ID")
		return
	}

	resultIDStr := chi.URLParam(r, "resultID")
	resultID, err := uuid.Parse(resultIDStr)
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid result ID")
		return
	}

	if !h.hasPermission(ctx, companyID, "exam:result:read") {
		h.respondWithError(w, http.StatusForbidden, "insufficient permissions")
		return
	}

	result, err := h.examService.GetExamResultByID(ctx, resultID)
	if err != nil {
		h.logger.Error("Failed to get exam result",
			zap.String("result_id", resultID.String()),
			zap.Error(err))
		h.respondWithError(w, http.StatusNotFound, err.Error())
		return
	}

	h.respondWithJSON(w, http.StatusOK, map[string]interface{}{
		"success": true,
		"data":    result,
	})
}

func (h *ExamHandler) ListExamResults(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	companyIDStr := chi.URLParam(r, "companyID")
	companyID, err := uuid.Parse(companyIDStr)
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid company ID")
		return
	}

	if !h.hasPermission(ctx, companyID, "exam:result:read") {
		h.respondWithError(w, http.StatusForbidden, "insufficient permissions")
		return
	}

	// Build filter
	filter := repository.ExamResultFilter{}
	if examIDStr := r.URL.Query().Get("exam_id"); examIDStr != "" {
		examID, err := uuid.Parse(examIDStr)
		if err == nil {
			filter.ExamID = examID // field expects uuid.UUID (non-pointer)
		}
	}
	if enrollmentIDStr := r.URL.Query().Get("enrollment_id"); enrollmentIDStr != "" {
		enrollmentID, err := uuid.Parse(enrollmentIDStr)
		if err == nil {
			filter.EnrollmentID = &enrollmentID // pointer for optional field
		}
	}
	if subjectIDStr := r.URL.Query().Get("subject_id"); subjectIDStr != "" {
		subjectID, err := uuid.Parse(subjectIDStr)
		if err == nil {
			filter.SubjectID = &subjectID // pointer for optional field
		}
	}
	if grade := r.URL.Query().Get("grade"); grade != "" {
		filter.Grade = &grade // pointer for optional field
	}

	// Pagination
	limit, _ := strconv.Atoi(r.URL.Query().Get("limit"))
	if limit <= 0 || limit > 100 {
		limit = 20
	}
	offset, _ := strconv.Atoi(r.URL.Query().Get("offset"))
	if offset < 0 {
		offset = 0
	}
	pagination := repository.Pagination{Limit: limit, Offset: offset}

	// Sorting
	sortField := r.URL.Query().Get("sort_field")
	if sortField == "" {
		sortField = "entered_at"
	}
	sortDirection := r.URL.Query().Get("sort_direction")
	if sortDirection == "" {
		sortDirection = "DESC"
	}
	sort := repository.Sort{Field: sortField, Direction: sortDirection}

	results, err := h.examService.ListExamResults(ctx, filter, pagination, sort)
	if err != nil {
		h.logger.Error("Failed to list exam results", zap.Error(err))
		h.respondWithError(w, http.StatusInternalServerError, "failed to list exam results")
		return
	}

	h.respondWithJSON(w, http.StatusOK, map[string]interface{}{
		"success": true,
		"data": map[string]interface{}{
			"results": results,
			"limit":   limit,
			"offset":  offset,
		},
	})
}

// UpdateExamResult handles PUT /api/v1/companies/{companyID}/exam-results/{resultID}
func (h *ExamHandler) UpdateExamResult(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	companyIDStr := chi.URLParam(r, "companyID")
	companyID, err := uuid.Parse(companyIDStr)
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid company ID")
		return
	}

	resultIDStr := chi.URLParam(r, "resultID")
	resultID, err := uuid.Parse(resultIDStr)
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid result ID")
		return
	}

	userID, err := getUserIDFromContext(ctx)
	if err != nil {
		h.respondWithError(w, http.StatusUnauthorized, "authentication required")
		return
	}

	if !h.hasPermission(ctx, companyID, "exam:result:update") {
		h.respondWithError(w, http.StatusForbidden, "insufficient permissions")
		return
	}

	var req service.UpdateExamResultRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid request body")
		return
	}

	req.ResultID = resultID
	req.UpdatedBy = &userID

	result, err := h.examService.UpdateExamResult(ctx, req)
	if err != nil {
		h.logger.Error("Failed to update exam result",
			zap.String("result_id", resultID.String()),
			zap.Error(err))
		h.respondWithError(w, http.StatusBadRequest, err.Error())
		return
	}

	h.respondWithJSON(w, http.StatusOK, map[string]interface{}{
		"success": true,
		"data":    result,
		"message": "Exam result updated successfully",
	})
}

// DeleteExamResult handles DELETE /api/v1/companies/{companyID}/exam-results/{resultID}
func (h *ExamHandler) DeleteExamResult(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	companyIDStr := chi.URLParam(r, "companyID")
	companyID, err := uuid.Parse(companyIDStr)
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid company ID")
		return
	}

	resultIDStr := chi.URLParam(r, "resultID")
	resultID, err := uuid.Parse(resultIDStr)
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid result ID")
		return
	}

	if !h.hasPermission(ctx, companyID, "exam:result:delete") {
		h.respondWithError(w, http.StatusForbidden, "insufficient permissions")
		return
	}

	err = h.examService.DeleteExamResult(ctx, resultID)
	if err != nil {
		h.logger.Error("Failed to delete exam result",
			zap.String("result_id", resultID.String()),
			zap.Error(err))
		h.respondWithError(w, http.StatusBadRequest, err.Error())
		return
	}

	h.respondWithJSON(w, http.StatusOK, map[string]interface{}{
		"success": true,
		"message": "Exam result deleted successfully",
	})
}

// ---------------------------------------------------------------------
// Exam Grade endpoints
// ---------------------------------------------------------------------

// CreateExamGrade handles POST /api/v1/companies/{companyID}/exams/{examID}/grades
func (h *ExamHandler) CreateExamGrade(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	companyIDStr := chi.URLParam(r, "companyID")
	companyID, err := uuid.Parse(companyIDStr)
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid company ID")
		return
	}

	examIDStr := chi.URLParam(r, "examID")
	examID, err := uuid.Parse(examIDStr)
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid exam ID")
		return
	}

	userID, err := getUserIDFromContext(ctx)
	if err != nil {
		h.respondWithError(w, http.StatusUnauthorized, "authentication required")
		return
	}

	if !h.hasPermission(ctx, companyID, "exam:grade:create") {
		h.respondWithError(w, http.StatusForbidden, "insufficient permissions")
		return
	}

	var req service.CreateExamGradeRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid request body")
		return
	}

	req.ExamID = examID
	req.CreatedBy = &userID

	// Validate
	if req.GradeName == "" {
		h.respondWithError(w, http.StatusBadRequest, "grade_name is required")
		return
	}
	if req.MinMarks < 0 {
		h.respondWithError(w, http.StatusBadRequest, "min_marks cannot be negative")
		return
	}
	if req.MaxMarks <= req.MinMarks {
		h.respondWithError(w, http.StatusBadRequest, "max_marks must be greater than min_marks")
		return
	}

	grade, err := h.examService.CreateExamGrade(ctx, req)
	if err != nil {
		h.logger.Error("Failed to create exam grade",
			zap.String("exam_id", examID.String()),
			zap.String("grade_name", req.GradeName),
			zap.Error(err))
		h.respondWithError(w, http.StatusBadRequest, err.Error())
		return
	}

	h.respondWithJSON(w, http.StatusCreated, map[string]interface{}{
		"success": true,
		"data":    grade,
		"message": "Exam grade created successfully",
	})
}

// GetExamGrade handles GET /api/v1/companies/{companyID}/exam-grades/{gradeID}
func (h *ExamHandler) GetExamGrade(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	companyIDStr := chi.URLParam(r, "companyID")
	companyID, err := uuid.Parse(companyIDStr)
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid company ID")
		return
	}

	gradeIDStr := chi.URLParam(r, "gradeID")
	gradeID, err := uuid.Parse(gradeIDStr)
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid grade ID")
		return
	}

	if !h.hasPermission(ctx, companyID, "exam:grade:read") {
		h.respondWithError(w, http.StatusForbidden, "insufficient permissions")
		return
	}

	grade, err := h.examService.GetExamGradeByID(ctx, gradeID)
	if err != nil {
		h.logger.Error("Failed to get exam grade",
			zap.String("grade_id", gradeID.String()),
			zap.Error(err))
		h.respondWithError(w, http.StatusNotFound, err.Error())
		return
	}

	h.respondWithJSON(w, http.StatusOK, map[string]interface{}{
		"success": true,
		"data":    grade,
	})
}

// ListExamGrades handles GET /api/v1/companies/{companyID}/exams/{examID}/grades
func (h *ExamHandler) ListExamGrades(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	companyIDStr := chi.URLParam(r, "companyID")
	companyID, err := uuid.Parse(companyIDStr)
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid company ID")
		return
	}

	examIDStr := chi.URLParam(r, "examID")
	examID, err := uuid.Parse(examIDStr)
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid exam ID")
		return
	}

	if !h.hasPermission(ctx, companyID, "exam:grade:read") {
		h.respondWithError(w, http.StatusForbidden, "insufficient permissions")
		return
	}

	// Filter by exam ID
	filter := repository.ExamGradeFilter{
		ExamID: examID,
	}

	// Pagination
	limit, _ := strconv.Atoi(r.URL.Query().Get("limit"))
	if limit <= 0 || limit > 100 {
		limit = 20
	}
	offset, _ := strconv.Atoi(r.URL.Query().Get("offset"))
	if offset < 0 {
		offset = 0
	}
	pagination := repository.Pagination{Limit: limit, Offset: offset}

	// Sorting
	sortField := r.URL.Query().Get("sort_field")
	if sortField == "" {
		sortField = "min_marks"
	}
	sortDirection := r.URL.Query().Get("sort_direction")
	if sortDirection == "" {
		sortDirection = "ASC"
	}
	sort := repository.Sort{Field: sortField, Direction: sortDirection}

	grades, err := h.examService.ListExamGrades(ctx, filter, pagination, sort)
	if err != nil {
		h.logger.Error("Failed to list exam grades", zap.Error(err))
		h.respondWithError(w, http.StatusInternalServerError, "failed to list exam grades")
		return
	}

	h.respondWithJSON(w, http.StatusOK, map[string]interface{}{
		"success": true,
		"data": map[string]interface{}{
			"grades": grades,
			"limit":  limit,
			"offset": offset,
		},
	})
}

// UpdateExamGrade handles PUT /api/v1/companies/{companyID}/exam-grades/{gradeID}
func (h *ExamHandler) UpdateExamGrade(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	companyIDStr := chi.URLParam(r, "companyID")
	companyID, err := uuid.Parse(companyIDStr)
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid company ID")
		return
	}

	gradeIDStr := chi.URLParam(r, "gradeID")
	gradeID, err := uuid.Parse(gradeIDStr)
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid grade ID")
		return
	}

	userID, err := getUserIDFromContext(ctx)
	if err != nil {
		h.respondWithError(w, http.StatusUnauthorized, "authentication required")
		return
	}

	if !h.hasPermission(ctx, companyID, "exam:grade:update") {
		h.respondWithError(w, http.StatusForbidden, "insufficient permissions")
		return
	}

	var req service.UpdateExamGradeRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid request body")
		return
	}

	req.GradeID = gradeID
	req.UpdatedBy = &userID

	grade, err := h.examService.UpdateExamGrade(ctx, req)
	if err != nil {
		h.logger.Error("Failed to update exam grade",
			zap.String("grade_id", gradeID.String()),
			zap.Error(err))
		h.respondWithError(w, http.StatusBadRequest, err.Error())
		return
	}

	h.respondWithJSON(w, http.StatusOK, map[string]interface{}{
		"success": true,
		"data":    grade,
		"message": "Exam grade updated successfully",
	})
}

// DeleteExamGrade handles DELETE /api/v1/companies/{companyID}/exam-grades/{gradeID}
func (h *ExamHandler) DeleteExamGrade(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	companyIDStr := chi.URLParam(r, "companyID")
	companyID, err := uuid.Parse(companyIDStr)
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid company ID")
		return
	}

	gradeIDStr := chi.URLParam(r, "gradeID")
	gradeID, err := uuid.Parse(gradeIDStr)
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid grade ID")
		return
	}

	if !h.hasPermission(ctx, companyID, "exam:grade:delete") {
		h.respondWithError(w, http.StatusForbidden, "insufficient permissions")
		return
	}

	err = h.examService.DeleteExamGrade(ctx, gradeID)
	if err != nil {
		h.logger.Error("Failed to delete exam grade",
			zap.String("grade_id", gradeID.String()),
			zap.Error(err))
		h.respondWithError(w, http.StatusBadRequest, err.Error())
		return
	}

	h.respondWithJSON(w, http.StatusOK, map[string]interface{}{
		"success": true,
		"message": "Exam grade deleted successfully",
	})
}

// ---------------------------------------------------------------------
// Helper methods
// ---------------------------------------------------------------------

// hasPermission is a placeholder for permission checks.
func (h *ExamHandler) hasPermission(ctx context.Context, companyID uuid.UUID, permission string) bool {
	// In real implementation, check RBAC or other authorization mechanism.
	return true
}

// respondWithJSON writes a JSON response.
func (h *ExamHandler) respondWithJSON(w http.ResponseWriter, status int, data interface{}) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	if err := json.NewEncoder(w).Encode(data); err != nil {
		h.logger.Error("Failed to encode JSON response", zap.Error(err))
	}
}

// respondWithError writes an error response.
func (h *ExamHandler) respondWithError(w http.ResponseWriter, status int, message string) {
	h.respondWithJSON(w, status, map[string]interface{}{
		"success": false,
		"error":   message,
	})
}

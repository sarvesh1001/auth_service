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

	"auth-service/internal/academics/repository"
	"auth-service/internal/academics/service"
)

// EnrollmentHandler handles HTTP requests for enrollment operations.
type EnrollmentHandler struct {
	enrollmentService service.EnrollmentService
	logger            *zap.Logger
}

// NewEnrollmentHandler creates a new EnrollmentHandler.
func NewEnrollmentHandler(enrollmentService service.EnrollmentService, logger *zap.Logger) *EnrollmentHandler {
	return &EnrollmentHandler{
		enrollmentService: enrollmentService,
		logger:            logger.Named("enrollment_handler"),
	}
}

// ---------------------------------------------------------------------
// Helper functions (same as in admission handler)
// ---------------------------------------------------------------------

func (h *EnrollmentHandler) hasPermission(ctx context.Context, companyID uuid.UUID, permission string) bool {
	// TODO: implement actual permission check
	return true
}

func (h *EnrollmentHandler) respondWithJSON(w http.ResponseWriter, status int, data interface{}) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	if err := json.NewEncoder(w).Encode(data); err != nil {
		h.logger.Error("failed to encode response", zap.Error(err))
	}
}

func (h *EnrollmentHandler) respondWithError(w http.ResponseWriter, status int, message string) {
	h.respondWithJSON(w, status, map[string]interface{}{
		"success": false,
		"error":   message,
	})
}

// EnrollStudent handles POST /api/v1/companies/{companyID}/enrollments
func (h *EnrollmentHandler) EnrollStudent(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	companyID, err := parseUUIDFromPath(r, "companyID")
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid company ID")
		return
	}

	userID, err := getUserIDFromContext(ctx)
	if err != nil {
		h.respondWithError(w, http.StatusUnauthorized, "authentication required")
		return
	}

	if !h.hasPermission(ctx, companyID, "enrollment:create") {
		h.respondWithError(w, http.StatusForbidden, "insufficient permissions")
		return
	}

	var req service.EnrollStudentRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid request body")
		return
	}

	// Validate required fields
	if req.StudentID == uuid.Nil {
		h.respondWithError(w, http.StatusBadRequest, "student_id is required")
		return
	}
	if req.AcademicYearID == uuid.Nil {
		h.respondWithError(w, http.StatusBadRequest, "academic_year_id is required")
		return
	}
	if req.SectionID == uuid.Nil {
		h.respondWithError(w, http.StatusBadRequest, "section_id is required")
		return
	}
	if req.EnrollmentDate.IsZero() {
		req.EnrollmentDate = time.Now()
	}

	// Set creator/updater from authenticated user
	req.CreatedBy = &userID
	req.UpdatedBy = &userID

	idempotencyKey := r.Header.Get("Idempotency-Key")
	enrollment, err := h.enrollmentService.EnrollStudent(ctx, req, idempotencyKey)
	if err != nil {
		h.logger.Error("failed to enroll student",
			zap.String("student_id", req.StudentID.String()),
			zap.String("section_id", req.SectionID.String()),
			zap.Error(err))
		h.respondWithError(w, http.StatusBadRequest, err.Error())
		return
	}

	h.respondWithJSON(w, http.StatusCreated, map[string]interface{}{
		"success": true,
		"data":    enrollment,
		"message": "Student enrolled successfully",
	})
}

// BulkEnroll handles POST /api/v1/companies/{companyID}/enrollments/bulk
func (h *EnrollmentHandler) BulkEnroll(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	companyID, err := parseUUIDFromPath(r, "companyID")
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid company ID")
		return
	}

	userID, err := getUserIDFromContext(ctx)
	if err != nil {
		h.respondWithError(w, http.StatusUnauthorized, "authentication required")
		return
	}

	if !h.hasPermission(ctx, companyID, "enrollment:bulk_create") {
		h.respondWithError(w, http.StatusForbidden, "insufficient permissions")
		return
	}

	var reqs []service.EnrollStudentRequest
	if err := json.NewDecoder(r.Body).Decode(&reqs); err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid request body")
		return
	}

	if len(reqs) == 0 {
		h.respondWithError(w, http.StatusBadRequest, "empty batch")
		return
	}

	// Set creator/updater for each request
	for i := range reqs {
		if reqs[i].EnrollmentDate.IsZero() {
			reqs[i].EnrollmentDate = time.Now()
		}
		reqs[i].CreatedBy = &userID
		reqs[i].UpdatedBy = &userID
	}

	enrollments, err := h.enrollmentService.BulkEnroll(ctx, reqs)
	if err != nil {
		h.logger.Error("failed to bulk enroll students",
			zap.Int("count", len(reqs)),
			zap.Error(err))
		h.respondWithError(w, http.StatusBadRequest, err.Error())
		return
	}

	h.respondWithJSON(w, http.StatusCreated, map[string]interface{}{
		"success": true,
		"data":    enrollments,
		"message": "Students enrolled successfully",
	})
}

// UpsertEnrollment handles POST /api/v1/companies/{companyID}/enrollments/upsert
func (h *EnrollmentHandler) UpsertEnrollment(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	companyID, err := parseUUIDFromPath(r, "companyID")
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid company ID")
		return
	}

	userID, err := getUserIDFromContext(ctx)
	if err != nil {
		h.respondWithError(w, http.StatusUnauthorized, "authentication required")
		return
	}

	if !h.hasPermission(ctx, companyID, "enrollment:upsert") {
		h.respondWithError(w, http.StatusForbidden, "insufficient permissions")
		return
	}

	var req service.EnrollStudentRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid request body")
		return
	}

	if req.StudentID == uuid.Nil {
		h.respondWithError(w, http.StatusBadRequest, "student_id is required")
		return
	}
	if req.AcademicYearID == uuid.Nil {
		h.respondWithError(w, http.StatusBadRequest, "academic_year_id is required")
		return
	}
	if req.SectionID == uuid.Nil {
		h.respondWithError(w, http.StatusBadRequest, "section_id is required")
		return
	}
	if req.EnrollmentDate.IsZero() {
		req.EnrollmentDate = time.Now()
	}

	req.CreatedBy = &userID
	req.UpdatedBy = &userID

	enrollment, err := h.enrollmentService.UpsertEnrollment(ctx, req)
	if err != nil {
		h.logger.Error("failed to upsert enrollment",
			zap.String("student_id", req.StudentID.String()),
			zap.Error(err))
		h.respondWithError(w, http.StatusBadRequest, err.Error())
		return
	}

	h.respondWithJSON(w, http.StatusOK, map[string]interface{}{
		"success": true,
		"data":    enrollment,
		"message": "Enrollment upserted successfully",
	})
}

// ---------------------------------------------------------------------
// Get by ID
// ---------------------------------------------------------------------

// GetByID handles GET /api/v1/companies/{companyID}/enrollments/{enrollmentID}
func (h *EnrollmentHandler) GetByID(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	companyID, err := parseUUIDFromPath(r, "companyID")
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid company ID")
		return
	}

	enrollmentID, err := parseUUIDFromPath(r, "enrollmentID")
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid enrollment ID")
		return
	}

	if !h.hasPermission(ctx, companyID, "enrollment:read") {
		h.respondWithError(w, http.StatusForbidden, "insufficient permissions")
		return
	}

	enrollment, err := h.enrollmentService.GetByID(ctx, enrollmentID)
	if err != nil {
		h.logger.Error("failed to get enrollment by ID",
			zap.String("enrollment_id", enrollmentID.String()),
			zap.Error(err))
		h.respondWithError(w, http.StatusNotFound, err.Error())
		return
	}

	h.respondWithJSON(w, http.StatusOK, map[string]interface{}{
		"success": true,
		"data":    enrollment,
	})
}

// GetByStudentAndYear handles GET /api/v1/companies/{companyID}/students/{studentID}/academic-years/{academicYearID}/enrollment
func (h *EnrollmentHandler) GetByStudentAndYear(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	companyID, err := parseUUIDFromPath(r, "companyID")
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid company ID")
		return
	}

	studentID, err := parseUUIDFromPath(r, "studentID")
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid student ID")
		return
	}

	academicYearID, err := parseUUIDFromPath(r, "academicYearID")
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid academic year ID")
		return
	}

	if !h.hasPermission(ctx, companyID, "enrollment:read") {
		h.respondWithError(w, http.StatusForbidden, "insufficient permissions")
		return
	}

	enrollment, err := h.enrollmentService.GetByStudentAndYear(ctx, studentID, academicYearID)
	if err != nil {
		h.logger.Error("failed to get enrollment by student and year",
			zap.String("student_id", studentID.String()),
			zap.String("academic_year_id", academicYearID.String()),
			zap.Error(err))
		h.respondWithError(w, http.StatusNotFound, err.Error())
		return
	}

	h.respondWithJSON(w, http.StatusOK, map[string]interface{}{
		"success": true,
		"data":    enrollment,
	})
}

// GetActiveByStudent handles GET /api/v1/companies/{companyID}/students/{studentID}/active-enrollment
func (h *EnrollmentHandler) GetActiveByStudent(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	companyID, err := parseUUIDFromPath(r, "companyID")
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid company ID")
		return
	}

	studentID, err := parseUUIDFromPath(r, "studentID")
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid student ID")
		return
	}

	if !h.hasPermission(ctx, companyID, "enrollment:read") {
		h.respondWithError(w, http.StatusForbidden, "insufficient permissions")
		return
	}

	enrollment, err := h.enrollmentService.GetActiveByStudent(ctx, studentID)
	if err != nil {
		h.logger.Error("failed to get active enrollment for student",
			zap.String("student_id", studentID.String()),
			zap.Error(err))
		h.respondWithError(w, http.StatusNotFound, err.Error())
		return
	}

	h.respondWithJSON(w, http.StatusOK, map[string]interface{}{
		"success": true,
		"data":    enrollment,
	})
}

// List handles GET /api/v1/companies/{companyID}/enrollments with query params
func (h *EnrollmentHandler) List(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	companyID, err := parseUUIDFromPath(r, "companyID")
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid company ID")
		return
	}

	if !h.hasPermission(ctx, companyID, "enrollment:read") {
		h.respondWithError(w, http.StatusForbidden, "insufficient permissions")
		return
	}

	// Build filter from query parameters
	filter := repository.EnrollmentFilter{}
	if studentIDStr := r.URL.Query().Get("student_id"); studentIDStr != "" {
		if studentID, err := uuid.Parse(studentIDStr); err == nil {
			filter.StudentID = studentID // fixed: assign value, not pointer
		}
	}
	if academicYearIDStr := r.URL.Query().Get("academic_year_id"); academicYearIDStr != "" {
		if academicYearID, err := uuid.Parse(academicYearIDStr); err == nil {
			filter.AcademicYearID = academicYearID // fixed
		}
	}
	if sectionIDStr := r.URL.Query().Get("section_id"); sectionIDStr != "" {
		if sectionID, err := uuid.Parse(sectionIDStr); err == nil {
			filter.SectionID = sectionID // fixed
		}
	}
	if status := r.URL.Query().Get("status"); status != "" {
		filter.Status = &status
	}
	if search := r.URL.Query().Get("search"); search != "" {
		filter.Search = search
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
		sortField = "created_at"
	}
	sortDirection := r.URL.Query().Get("sort_direction")
	if sortDirection == "" {
		sortDirection = "DESC"
	}
	sort := repository.Sort{Field: sortField, Direction: sortDirection}

	enrollments, err := h.enrollmentService.List(ctx, filter, pagination, sort)
	if err != nil {
		h.logger.Error("failed to list enrollments",
			zap.Any("filter", filter),
			zap.Error(err))
		h.respondWithError(w, http.StatusInternalServerError, "failed to list enrollments")
		return
	}

	count, err := h.enrollmentService.Count(ctx, filter)
	if err != nil {
		h.logger.Error("failed to count enrollments", zap.Error(err))
		// non-fatal, continue without total
	}

	h.respondWithJSON(w, http.StatusOK, map[string]interface{}{
		"success": true,
		"data": map[string]interface{}{
			"enrollments": enrollments,
			"total":       count,
			"limit":       limit,
			"offset":      offset,
		},
	})
}

// ListByStudent handles GET /api/v1/companies/{companyID}/students/{studentID}/enrollments
func (h *EnrollmentHandler) ListByStudent(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	companyID, err := parseUUIDFromPath(r, "companyID")
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid company ID")
		return
	}

	studentID, err := parseUUIDFromPath(r, "studentID")
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid student ID")
		return
	}

	if !h.hasPermission(ctx, companyID, "enrollment:read") {
		h.respondWithError(w, http.StatusForbidden, "insufficient permissions")
		return
	}

	enrollments, err := h.enrollmentService.ListByStudent(ctx, studentID)
	if err != nil {
		h.logger.Error("failed to list enrollments by student",
			zap.String("student_id", studentID.String()),
			zap.Error(err))
		h.respondWithError(w, http.StatusInternalServerError, "failed to list enrollments")
		return
	}

	h.respondWithJSON(w, http.StatusOK, map[string]interface{}{
		"success": true,
		"data":    enrollments,
	})
}

// ListBySection handles GET /api/v1/companies/{companyID}/sections/{sectionID}/enrollments
func (h *EnrollmentHandler) ListBySection(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	companyID, err := parseUUIDFromPath(r, "companyID")
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid company ID")
		return
	}

	sectionID, err := parseUUIDFromPath(r, "sectionID")
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid section ID")
		return
	}

	if !h.hasPermission(ctx, companyID, "enrollment:read") {
		h.respondWithError(w, http.StatusForbidden, "insufficient permissions")
		return
	}

	enrollments, err := h.enrollmentService.ListBySection(ctx, sectionID)
	if err != nil {
		h.logger.Error("failed to list enrollments by section",
			zap.String("section_id", sectionID.String()),
			zap.Error(err))
		h.respondWithError(w, http.StatusInternalServerError, "failed to list enrollments")
		return
	}

	h.respondWithJSON(w, http.StatusOK, map[string]interface{}{
		"success": true,
		"data":    enrollments,
	})
}

// ListByAcademicYear handles GET /api/v1/companies/{companyID}/academic-years/{academicYearID}/enrollments
func (h *EnrollmentHandler) ListByAcademicYear(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	companyID, err := parseUUIDFromPath(r, "companyID")
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid company ID")
		return
	}

	academicYearID, err := parseUUIDFromPath(r, "academicYearID")
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid academic year ID")
		return
	}

	if !h.hasPermission(ctx, companyID, "enrollment:read") {
		h.respondWithError(w, http.StatusForbidden, "insufficient permissions")
		return
	}

	enrollments, err := h.enrollmentService.ListByAcademicYear(ctx, academicYearID)
	if err != nil {
		h.logger.Error("failed to list enrollments by academic year",
			zap.String("academic_year_id", academicYearID.String()),
			zap.Error(err))
		h.respondWithError(w, http.StatusInternalServerError, "failed to list enrollments")
		return
	}

	h.respondWithJSON(w, http.StatusOK, map[string]interface{}{
		"success": true,
		"data":    enrollments,
	})
}

// ---------------------------------------------------------------------
// Update operations
// ---------------------------------------------------------------------

// Update handles PUT /api/v1/companies/{companyID}/enrollments/{enrollmentID}
func (h *EnrollmentHandler) Update(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	companyID, err := parseUUIDFromPath(r, "companyID")
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid company ID")
		return
	}

	enrollmentID, err := parseUUIDFromPath(r, "enrollmentID")
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid enrollment ID")
		return
	}

	userID, err := getUserIDFromContext(ctx)
	if err != nil {
		h.respondWithError(w, http.StatusUnauthorized, "authentication required")
		return
	}

	if !h.hasPermission(ctx, companyID, "enrollment:update") {
		h.respondWithError(w, http.StatusForbidden, "insufficient permissions")
		return
	}

	var req service.UpdateEnrollmentRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid request body")
		return
	}

	req.EnrollmentID = enrollmentID
	req.UpdatedBy = &userID

	enrollment, err := h.enrollmentService.Update(ctx, req)
	if err != nil {
		h.logger.Error("failed to update enrollment",
			zap.String("enrollment_id", enrollmentID.String()),
			zap.Error(err))
		h.respondWithError(w, http.StatusBadRequest, err.Error())
		return
	}

	h.respondWithJSON(w, http.StatusOK, map[string]interface{}{
		"success": true,
		"data":    enrollment,
		"message": "Enrollment updated successfully",
	})
}

// UpdateRollNumber handles PATCH /api/v1/companies/{companyID}/enrollments/{enrollmentID}/roll-number
func (h *EnrollmentHandler) UpdateRollNumber(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	companyID, err := parseUUIDFromPath(r, "companyID")
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid company ID")
		return
	}

	enrollmentID, err := parseUUIDFromPath(r, "enrollmentID")
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid enrollment ID")
		return
	}

	userID, err := getUserIDFromContext(ctx)
	if err != nil {
		h.respondWithError(w, http.StatusUnauthorized, "authentication required")
		return
	}

	if !h.hasPermission(ctx, companyID, "enrollment:update") {
		h.respondWithError(w, http.StatusForbidden, "insufficient permissions")
		return
	}

	var req struct {
		RollNumber string `json:"roll_number"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid request body")
		return
	}
	if req.RollNumber == "" {
		h.respondWithError(w, http.StatusBadRequest, "roll_number is required")
		return
	}

	if err := h.enrollmentService.UpdateRollNumber(ctx, enrollmentID, req.RollNumber, &userID); err != nil {
		h.logger.Error("failed to update roll number",
			zap.String("enrollment_id", enrollmentID.String()),
			zap.Error(err))
		h.respondWithError(w, http.StatusBadRequest, err.Error())
		return
	}

	h.respondWithJSON(w, http.StatusOK, map[string]interface{}{
		"success": true,
		"message": "Roll number updated successfully",
	})
}

// TransferSection handles POST /api/v1/companies/{companyID}/enrollments/{enrollmentID}/transfer-section
func (h *EnrollmentHandler) TransferSection(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	companyID, err := parseUUIDFromPath(r, "companyID")
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid company ID")
		return
	}

	enrollmentID, err := parseUUIDFromPath(r, "enrollmentID")
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid enrollment ID")
		return
	}

	userID, err := getUserIDFromContext(ctx)
	if err != nil {
		h.respondWithError(w, http.StatusUnauthorized, "authentication required")
		return
	}

	if !h.hasPermission(ctx, companyID, "enrollment:transfer") {
		h.respondWithError(w, http.StatusForbidden, "insufficient permissions")
		return
	}

	var req service.TransferSectionRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid request body")
		return
	}
	if req.NewSectionID == uuid.Nil {
		h.respondWithError(w, http.StatusBadRequest, "new_section_id is required")
		return
	}

	req.EnrollmentID = enrollmentID
	req.UpdatedBy = &userID

	enrollment, err := h.enrollmentService.TransferSection(ctx, req)
	if err != nil {
		h.logger.Error("failed to transfer section",
			zap.String("enrollment_id", enrollmentID.String()),
			zap.String("new_section_id", req.NewSectionID.String()),
			zap.Error(err))
		h.respondWithError(w, http.StatusBadRequest, err.Error())
		return
	}

	h.respondWithJSON(w, http.StatusOK, map[string]interface{}{
		"success": true,
		"data":    enrollment,
		"message": "Section transferred successfully",
	})
}

// BulkTransferSection handles POST /api/v1/companies/{companyID}/enrollments/bulk-transfer
func (h *EnrollmentHandler) BulkTransferSection(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	companyID, err := parseUUIDFromPath(r, "companyID")
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid company ID")
		return
	}

	userID, err := getUserIDFromContext(ctx)
	if err != nil {
		h.respondWithError(w, http.StatusUnauthorized, "authentication required")
		return
	}

	if !h.hasPermission(ctx, companyID, "enrollment:bulk_transfer") {
		h.respondWithError(w, http.StatusForbidden, "insufficient permissions")
		return
	}

	var reqs []service.TransferSectionRequest
	if err := json.NewDecoder(r.Body).Decode(&reqs); err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid request body")
		return
	}
	if len(reqs) == 0 {
		h.respondWithError(w, http.StatusBadRequest, "empty batch")
		return
	}

	for i := range reqs {
		reqs[i].UpdatedBy = &userID
	}

	if err := h.enrollmentService.BulkTransferSection(ctx, reqs); err != nil {
		h.logger.Error("failed to bulk transfer sections",
			zap.Int("count", len(reqs)),
			zap.Error(err))
		h.respondWithError(w, http.StatusBadRequest, err.Error())
		return
	}

	h.respondWithJSON(w, http.StatusOK, map[string]interface{}{
		"success": true,
		"message": "Bulk section transfer completed",
	})
}

// SwapSections handles POST /api/v1/companies/{companyID}/enrollments/swap-sections
func (h *EnrollmentHandler) SwapSections(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	companyID, err := parseUUIDFromPath(r, "companyID")
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid company ID")
		return
	}

	userID, err := getUserIDFromContext(ctx)
	if err != nil {
		h.respondWithError(w, http.StatusUnauthorized, "authentication required")
		return
	}

	if !h.hasPermission(ctx, companyID, "enrollment:swap") {
		h.respondWithError(w, http.StatusForbidden, "insufficient permissions")
		return
	}

	var req struct {
		EnrollmentID1 uuid.UUID `json:"enrollment_id1"`
		EnrollmentID2 uuid.UUID `json:"enrollment_id2"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid request body")
		return
	}
	if req.EnrollmentID1 == uuid.Nil || req.EnrollmentID2 == uuid.Nil {
		h.respondWithError(w, http.StatusBadRequest, "both enrollment IDs are required")
		return
	}

	if err := h.enrollmentService.SwapSections(ctx, req.EnrollmentID1, req.EnrollmentID2, &userID); err != nil {
		h.logger.Error("failed to swap sections",
			zap.String("enrollment_id1", req.EnrollmentID1.String()),
			zap.String("enrollment_id2", req.EnrollmentID2.String()),
			zap.Error(err))
		h.respondWithError(w, http.StatusBadRequest, err.Error())
		return
	}

	h.respondWithJSON(w, http.StatusOK, map[string]interface{}{
		"success": true,
		"message": "Sections swapped successfully",
	})
}

// ---------------------------------------------------------------------
// Promotion
// ---------------------------------------------------------------------

// PromoteStudent handles POST /api/v1/companies/{companyID}/enrollments/promote
func (h *EnrollmentHandler) PromoteStudent(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	companyID, err := parseUUIDFromPath(r, "companyID")
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid company ID")
		return
	}

	userID, err := getUserIDFromContext(ctx)
	if err != nil {
		h.respondWithError(w, http.StatusUnauthorized, "authentication required")
		return
	}

	if !h.hasPermission(ctx, companyID, "enrollment:promote") {
		h.respondWithError(w, http.StatusForbidden, "insufficient permissions")
		return
	}

	var req service.PromoteStudentRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid request body")
		return
	}
	if req.StudentID == uuid.Nil {
		h.respondWithError(w, http.StatusBadRequest, "student_id is required")
		return
	}
	if req.NewSectionID == uuid.Nil {
		h.respondWithError(w, http.StatusBadRequest, "new_section_id is required")
		return
	}
	if req.NewAcademicYearID == uuid.Nil {
		h.respondWithError(w, http.StatusBadRequest, "new_academic_year_id is required")
		return
	}

	req.UpdatedBy = &userID

	enrollment, err := h.enrollmentService.PromoteStudent(ctx, req)
	if err != nil {
		h.logger.Error("failed to promote student",
			zap.String("student_id", req.StudentID.String()),
			zap.Error(err))
		h.respondWithError(w, http.StatusBadRequest, err.Error())
		return
	}

	h.respondWithJSON(w, http.StatusOK, map[string]interface{}{
		"success": true,
		"data":    enrollment,
		"message": "Student promoted successfully",
	})
}

// BulkPromote handles POST /api/v1/companies/{companyID}/enrollments/bulk-promote
func (h *EnrollmentHandler) BulkPromote(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	companyID, err := parseUUIDFromPath(r, "companyID")
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid company ID")
		return
	}

	userID, err := getUserIDFromContext(ctx)
	if err != nil {
		h.respondWithError(w, http.StatusUnauthorized, "authentication required")
		return
	}

	if !h.hasPermission(ctx, companyID, "enrollment:bulk_promote") {
		h.respondWithError(w, http.StatusForbidden, "insufficient permissions")
		return
	}

	var reqs []service.PromoteStudentRequest
	if err := json.NewDecoder(r.Body).Decode(&reqs); err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid request body")
		return
	}
	if len(reqs) == 0 {
		h.respondWithError(w, http.StatusBadRequest, "empty batch")
		return
	}

	for i := range reqs {
		reqs[i].UpdatedBy = &userID
	}

	if err := h.enrollmentService.BulkPromote(ctx, reqs); err != nil {
		h.logger.Error("failed to bulk promote students",
			zap.Int("count", len(reqs)),
			zap.Error(err))
		h.respondWithError(w, http.StatusBadRequest, err.Error())
		return
	}

	h.respondWithJSON(w, http.StatusOK, map[string]interface{}{
		"success": true,
		"message": "Bulk promotion completed",
	})
}

// PromoteSection handles POST /api/v1/companies/{companyID}/sections/{sectionID}/promote
func (h *EnrollmentHandler) PromoteSection(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	companyID, err := parseUUIDFromPath(r, "companyID")
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid company ID")
		return
	}

	sectionID, err := parseUUIDFromPath(r, "sectionID")
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid section ID")
		return
	}

	userID, err := getUserIDFromContext(ctx)
	if err != nil {
		h.respondWithError(w, http.StatusUnauthorized, "authentication required")
		return
	}

	if !h.hasPermission(ctx, companyID, "enrollment:promote_section") {
		h.respondWithError(w, http.StatusForbidden, "insufficient permissions")
		return
	}

	var req struct {
		NextSectionID  uuid.UUID `json:"next_section_id"`
		AcademicYearID uuid.UUID `json:"academic_year_id"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid request body")
		return
	}
	if req.NextSectionID == uuid.Nil {
		h.respondWithError(w, http.StatusBadRequest, "next_section_id is required")
		return
	}
	if req.AcademicYearID == uuid.Nil {
		h.respondWithError(w, http.StatusBadRequest, "academic_year_id is required")
		return
	}

	if err := h.enrollmentService.PromoteSection(ctx, sectionID, req.NextSectionID, req.AcademicYearID, &userID); err != nil {
		h.logger.Error("failed to promote section",
			zap.String("section_id", sectionID.String()),
			zap.String("next_section_id", req.NextSectionID.String()),
			zap.Error(err))
		h.respondWithError(w, http.StatusBadRequest, err.Error())
		return
	}

	h.respondWithJSON(w, http.StatusOK, map[string]interface{}{
		"success": true,
		"message": "Section promoted successfully",
	})
}

// ---------------------------------------------------------------------
// Graduation & Alumni
// ---------------------------------------------------------------------

// GraduateStudent handles POST /api/v1/companies/{companyID}/enrollments/{enrollmentID}/graduate
func (h *EnrollmentHandler) GraduateStudent(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	companyID, err := parseUUIDFromPath(r, "companyID")
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid company ID")
		return
	}

	enrollmentID, err := parseUUIDFromPath(r, "enrollmentID")
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid enrollment ID")
		return
	}

	userID, err := getUserIDFromContext(ctx)
	if err != nil {
		h.respondWithError(w, http.StatusUnauthorized, "authentication required")
		return
	}

	if !h.hasPermission(ctx, companyID, "enrollment:graduate") {
		h.respondWithError(w, http.StatusForbidden, "insufficient permissions")
		return
	}

	if err := h.enrollmentService.GraduateStudent(ctx, enrollmentID, &userID); err != nil {
		h.logger.Error("failed to graduate student",
			zap.String("enrollment_id", enrollmentID.String()),
			zap.Error(err))
		h.respondWithError(w, http.StatusBadRequest, err.Error())
		return
	}

	h.respondWithJSON(w, http.StatusOK, map[string]interface{}{
		"success": true,
		"message": "Student graduated successfully",
	})
}

// MarkAlumni handles POST /api/v1/companies/{companyID}/students/{studentID}/alumni
func (h *EnrollmentHandler) MarkAlumni(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	companyID, err := parseUUIDFromPath(r, "companyID")
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid company ID")
		return
	}

	studentID, err := parseUUIDFromPath(r, "studentID")
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid student ID")
		return
	}

	userID, err := getUserIDFromContext(ctx)
	if err != nil {
		h.respondWithError(w, http.StatusUnauthorized, "authentication required")
		return
	}

	if !h.hasPermission(ctx, companyID, "enrollment:mark_alumni") {
		h.respondWithError(w, http.StatusForbidden, "insufficient permissions")
		return
	}

	if err := h.enrollmentService.MarkAlumni(ctx, studentID, &userID); err != nil {
		h.logger.Error("failed to mark student as alumni",
			zap.String("student_id", studentID.String()),
			zap.Error(err))
		h.respondWithError(w, http.StatusBadRequest, err.Error())
		return
	}

	h.respondWithJSON(w, http.StatusOK, map[string]interface{}{
		"success": true,
		"message": "Student marked as alumni successfully",
	})
}

// ---------------------------------------------------------------------
// Bulk Status & Roll Numbers
// ---------------------------------------------------------------------

// BulkUpdateStatus handles POST /api/v1/companies/{companyID}/enrollments/bulk-update-status
func (h *EnrollmentHandler) BulkUpdateStatus(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	companyID, err := parseUUIDFromPath(r, "companyID")
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid company ID")
		return
	}

	userID, err := getUserIDFromContext(ctx)
	if err != nil {
		h.respondWithError(w, http.StatusUnauthorized, "authentication required")
		return
	}

	if !h.hasPermission(ctx, companyID, "enrollment:bulk_update_status") {
		h.respondWithError(w, http.StatusForbidden, "insufficient permissions")
		return
	}

	var req service.BulkEnrollmentStatusUpdateRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid request body")
		return
	}
	if len(req.EnrollmentIDs) == 0 {
		h.respondWithError(w, http.StatusBadRequest, "enrollment_ids is required")
		return
	}
	if req.Status == "" {
		h.respondWithError(w, http.StatusBadRequest, "status is required")
		return
	}

	req.UpdatedBy = &userID

	if err := h.enrollmentService.BulkUpdateStatus(ctx, req); err != nil {
		h.logger.Error("failed to bulk update enrollment status",
			zap.Int("count", len(req.EnrollmentIDs)),
			zap.String("status", req.Status),
			zap.Error(err))
		h.respondWithError(w, http.StatusBadRequest, err.Error())
		return
	}

	h.respondWithJSON(w, http.StatusOK, map[string]interface{}{
		"success": true,
		"message": "Bulk status update completed",
	})
}

// BulkAssignRollNumbers handles POST /api/v1/companies/{companyID}/enrollments/bulk-assign-roll-numbers
func (h *EnrollmentHandler) BulkAssignRollNumbers(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	companyID, err := parseUUIDFromPath(r, "companyID")
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid company ID")
		return
	}

	userID, err := getUserIDFromContext(ctx)
	if err != nil {
		h.respondWithError(w, http.StatusUnauthorized, "authentication required")
		return
	}

	if !h.hasPermission(ctx, companyID, "enrollment:bulk_assign_roll_numbers") {
		h.respondWithError(w, http.StatusForbidden, "insufficient permissions")
		return
	}

	var req service.BulkRollNumberRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid request body")
		return
	}
	if len(req.RollNumbers) == 0 {
		h.respondWithError(w, http.StatusBadRequest, "roll_numbers is required")
		return
	}

	req.UpdatedBy = &userID

	if err := h.enrollmentService.BulkAssignRollNumbers(ctx, req); err != nil {
		h.logger.Error("failed to bulk assign roll numbers",
			zap.Int("count", len(req.RollNumbers)),
			zap.Error(err))
		h.respondWithError(w, http.StatusBadRequest, err.Error())
		return
	}

	h.respondWithJSON(w, http.StatusOK, map[string]interface{}{
		"success": true,
		"message": "Bulk roll number assignment completed",
	})
}

// ---------------------------------------------------------------------
// Search & Statistics
// ---------------------------------------------------------------------

// Search handles GET /api/v1/companies/{companyID}/enrollments/search
func (h *EnrollmentHandler) Search(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	companyID, err := parseUUIDFromPath(r, "companyID")
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid company ID")
		return
	}

	if !h.hasPermission(ctx, companyID, "enrollment:search") {
		h.respondWithError(w, http.StatusForbidden, "insufficient permissions")
		return
	}

	query := r.URL.Query().Get("q")
	if query == "" {
		h.respondWithError(w, http.StatusBadRequest, "search query is required")
		return
	}

	limit, _ := strconv.Atoi(r.URL.Query().Get("limit"))
	if limit <= 0 || limit > 100 {
		limit = 20
	}
	offset, _ := strconv.Atoi(r.URL.Query().Get("offset"))
	if offset < 0 {
		offset = 0
	}
	pagination := repository.Pagination{Limit: limit, Offset: offset}

	enrollments, err := h.enrollmentService.Search(ctx, query, companyID, pagination)
	if err != nil {
		h.logger.Error("failed to search enrollments",
			zap.String("query", query),
			zap.Error(err))
		h.respondWithError(w, http.StatusInternalServerError, "failed to search enrollments")
		return
	}

	h.respondWithJSON(w, http.StatusOK, map[string]interface{}{
		"success": true,
		"data":    enrollments,
		"limit":   limit,
		"offset":  offset,
	})
}

// GetSectionStrength handles GET /api/v1/companies/{companyID}/sections/{sectionID}/strength
func (h *EnrollmentHandler) GetSectionStrength(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	companyID, err := parseUUIDFromPath(r, "companyID")
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid company ID")
		return
	}

	sectionID, err := parseUUIDFromPath(r, "sectionID")
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid section ID")
		return
	}

	if !h.hasPermission(ctx, companyID, "enrollment:read") {
		h.respondWithError(w, http.StatusForbidden, "insufficient permissions")
		return
	}

	count, err := h.enrollmentService.GetSectionStrength(ctx, sectionID)
	if err != nil {
		h.logger.Error("failed to get section strength",
			zap.String("section_id", sectionID.String()),
			zap.Error(err))
		h.respondWithError(w, http.StatusInternalServerError, "failed to get section strength")
		return
	}

	h.respondWithJSON(w, http.StatusOK, map[string]interface{}{
		"success": true,
		"data": map[string]interface{}{
			"section_id": sectionID,
			"strength":   count,
		},
	})
}

// GetAcademicYearStrength handles GET /api/v1/companies/{companyID}/academic-years/{academicYearID}/strength
func (h *EnrollmentHandler) GetAcademicYearStrength(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	companyID, err := parseUUIDFromPath(r, "companyID")
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid company ID")
		return
	}

	academicYearID, err := parseUUIDFromPath(r, "academicYearID")
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid academic year ID")
		return
	}

	if !h.hasPermission(ctx, companyID, "enrollment:read") {
		h.respondWithError(w, http.StatusForbidden, "insufficient permissions")
		return
	}

	count, err := h.enrollmentService.GetAcademicYearStrength(ctx, academicYearID)
	if err != nil {
		h.logger.Error("failed to get academic year strength",
			zap.String("academic_year_id", academicYearID.String()),
			zap.Error(err))
		h.respondWithError(w, http.StatusInternalServerError, "failed to get academic year strength")
		return
	}

	h.respondWithJSON(w, http.StatusOK, map[string]interface{}{
		"success": true,
		"data": map[string]interface{}{
			"academic_year_id": academicYearID,
			"strength":         count,
		},
	})
}

// GetDropoutCount handles GET /api/v1/companies/{companyID}/academic-years/{academicYearID}/dropout-count
func (h *EnrollmentHandler) GetDropoutCount(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	companyID, err := parseUUIDFromPath(r, "companyID")
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid company ID")
		return
	}

	academicYearID, err := parseUUIDFromPath(r, "academicYearID")
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid academic year ID")
		return
	}

	if !h.hasPermission(ctx, companyID, "enrollment:read") {
		h.respondWithError(w, http.StatusForbidden, "insufficient permissions")
		return
	}

	count, err := h.enrollmentService.GetDropoutCount(ctx, academicYearID)
	if err != nil {
		h.logger.Error("failed to get dropout count",
			zap.String("academic_year_id", academicYearID.String()),
			zap.Error(err))
		h.respondWithError(w, http.StatusInternalServerError, "failed to get dropout count")
		return
	}

	h.respondWithJSON(w, http.StatusOK, map[string]interface{}{
		"success": true,
		"data": map[string]interface{}{
			"academic_year_id": academicYearID,
			"dropout_count":    count,
		},
	})
}

// GetPromotionStats handles GET /api/v1/companies/{companyID}/academic-years/{academicYearID}/promotion-stats
func (h *EnrollmentHandler) GetPromotionStats(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	companyID, err := parseUUIDFromPath(r, "companyID")
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid company ID")
		return
	}

	academicYearID, err := parseUUIDFromPath(r, "academicYearID")
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid academic year ID")
		return
	}

	if !h.hasPermission(ctx, companyID, "enrollment:read") {
		h.respondWithError(w, http.StatusForbidden, "insufficient permissions")
		return
	}

	stats, err := h.enrollmentService.GetPromotionStats(ctx, academicYearID)
	if err != nil {
		h.logger.Error("failed to get promotion stats",
			zap.String("academic_year_id", academicYearID.String()),
			zap.Error(err))
		h.respondWithError(w, http.StatusInternalServerError, "failed to get promotion stats")
		return
	}

	h.respondWithJSON(w, http.StatusOK, map[string]interface{}{
		"success": true,
		"data":    stats,
	})
}

// ---------------------------------------------------------------------
// Status change endpoints (activate, complete, withdraw, update status)
// ---------------------------------------------------------------------

// Activate handles PATCH /api/v1/companies/{companyID}/enrollments/{enrollmentID}/activate
func (h *EnrollmentHandler) Activate(w http.ResponseWriter, r *http.Request) {
	h.updateStatusAction(w, r, "activate", func(ctx context.Context, id uuid.UUID, updatedBy *uuid.UUID) error {
		return h.enrollmentService.Activate(ctx, id, updatedBy)
	})
}

// Complete handles PATCH /api/v1/companies/{companyID}/enrollments/{enrollmentID}/complete
func (h *EnrollmentHandler) Complete(w http.ResponseWriter, r *http.Request) {
	h.updateStatusAction(w, r, "complete", func(ctx context.Context, id uuid.UUID, updatedBy *uuid.UUID) error {
		return h.enrollmentService.Complete(ctx, id, updatedBy)
	})
}

// Withdraw handles PATCH /api/v1/companies/{companyID}/enrollments/{enrollmentID}/withdraw
func (h *EnrollmentHandler) Withdraw(w http.ResponseWriter, r *http.Request) {
	h.updateStatusAction(w, r, "withdraw", func(ctx context.Context, id uuid.UUID, updatedBy *uuid.UUID) error {
		return h.enrollmentService.Withdraw(ctx, id, updatedBy)
	})
}

// UpdateStatus handles PATCH /api/v1/companies/{companyID}/enrollments/{enrollmentID}/status
func (h *EnrollmentHandler) UpdateStatus(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	companyID, err := parseUUIDFromPath(r, "companyID")
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid company ID")
		return
	}

	enrollmentID, err := parseUUIDFromPath(r, "enrollmentID")
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid enrollment ID")
		return
	}

	userID, err := getUserIDFromContext(ctx)
	if err != nil {
		h.respondWithError(w, http.StatusUnauthorized, "authentication required")
		return
	}

	if !h.hasPermission(ctx, companyID, "enrollment:update_status") {
		h.respondWithError(w, http.StatusForbidden, "insufficient permissions")
		return
	}

	var req struct {
		Status string `json:"status"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid request body")
		return
	}
	if req.Status == "" {
		h.respondWithError(w, http.StatusBadRequest, "status is required")
		return
	}

	if err := h.enrollmentService.UpdateStatus(ctx, enrollmentID, req.Status, &userID); err != nil {
		h.logger.Error("failed to update enrollment status",
			zap.String("enrollment_id", enrollmentID.String()),
			zap.String("status", req.Status),
			zap.Error(err))
		h.respondWithError(w, http.StatusBadRequest, err.Error())
		return
	}

	h.respondWithJSON(w, http.StatusOK, map[string]interface{}{
		"success": true,
		"message": "Enrollment status updated successfully",
	})
}

// updateStatusAction is a helper for simple status change endpoints.
func (h *EnrollmentHandler) updateStatusAction(w http.ResponseWriter, r *http.Request, actionName string, fn func(context.Context, uuid.UUID, *uuid.UUID) error) {
	ctx := r.Context()

	companyID, err := parseUUIDFromPath(r, "companyID")
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid company ID")
		return
	}

	enrollmentID, err := parseUUIDFromPath(r, "enrollmentID")
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid enrollment ID")
		return
	}

	userID, err := getUserIDFromContext(ctx)
	if err != nil {
		h.respondWithError(w, http.StatusUnauthorized, "authentication required")
		return
	}

	perm := "enrollment:" + actionName
	if !h.hasPermission(ctx, companyID, perm) {
		h.respondWithError(w, http.StatusForbidden, "insufficient permissions")
		return
	}

	if err := fn(ctx, enrollmentID, &userID); err != nil {
		h.logger.Error("failed to "+actionName+" enrollment",
			zap.String("enrollment_id", enrollmentID.String()),
			zap.Error(err))
		h.respondWithError(w, http.StatusBadRequest, err.Error())
		return
	}

	h.respondWithJSON(w, http.StatusOK, map[string]interface{}{
		"success": true,
		"message": "Enrollment " + actionName + "d successfully",
	})
}

// ---------------------------------------------------------------------
// Helper to parse UUID from chi URL param
// ---------------------------------------------------------------------

func parseUUIDFromPath(r *http.Request, key string) (uuid.UUID, error) {
	param := chi.URLParam(r, key)
	if param == "" {
		return uuid.Nil, nil
	}
	return uuid.Parse(param)
}

// Count handles GET /api/v1/companies/{companyID}/enrollments/count
func (h *EnrollmentHandler) Count(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	companyID, err := parseUUIDFromPath(r, "companyID")
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid company ID")
		return
	}

	if !h.hasPermission(ctx, companyID, "enrollment:read") {
		h.respondWithError(w, http.StatusForbidden, "insufficient permissions")
		return
	}

	// Build filter from query parameters (same as List)
	filter := repository.EnrollmentFilter{}
	if studentIDStr := r.URL.Query().Get("student_id"); studentIDStr != "" {
		if studentID, err := uuid.Parse(studentIDStr); err == nil {
			filter.StudentID = studentID
		}
	}
	if academicYearIDStr := r.URL.Query().Get("academic_year_id"); academicYearIDStr != "" {
		if academicYearID, err := uuid.Parse(academicYearIDStr); err == nil {
			filter.AcademicYearID = academicYearID
		}
	}
	if sectionIDStr := r.URL.Query().Get("section_id"); sectionIDStr != "" {
		if sectionID, err := uuid.Parse(sectionIDStr); err == nil {
			filter.SectionID = sectionID
		}
	}
	if status := r.URL.Query().Get("status"); status != "" {
		filter.Status = &status
	}
	if search := r.URL.Query().Get("search"); search != "" {
		filter.Search = search
	}

	count, err := h.enrollmentService.Count(ctx, filter)
	if err != nil {
		h.logger.Error("failed to count enrollments", zap.Error(err))
		h.respondWithError(w, http.StatusInternalServerError, "failed to count enrollments")
		return
	}

	h.respondWithJSON(w, http.StatusOK, map[string]interface{}{
		"success": true,
		"data":    count,
	})
}

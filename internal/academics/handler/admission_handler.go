package handler

import (
	"context"
	"encoding/json"
	"net/http"
	"strconv"

	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"
	"go.uber.org/zap"

	"auth-service/internal/academics/models"
	"auth-service/internal/academics/repository"
	"auth-service/internal/academics/service"
)

type AdmissionHandler struct {
	admissionService service.AdmissionService
	logger           *zap.Logger
}

func NewAdmissionHandler(admissionService service.AdmissionService, logger *zap.Logger) *AdmissionHandler {
	return &AdmissionHandler{
		admissionService: admissionService,
		logger:           logger.Named("admission_handler"),
	}
}

// Create handles POST /api/v1/companies/{companyID}/admissions
func (h *AdmissionHandler) Create(w http.ResponseWriter, r *http.Request) {
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

	if !h.hasPermission(ctx, companyID, "admission:create") {
		h.respondWithError(w, http.StatusForbidden, "insufficient permissions")
		return
	}

	var req service.CreateAdmissionRequest
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
	if req.AdmissionDate.IsZero() {
		h.respondWithError(w, http.StatusBadRequest, "admission_date is required")
		return
	}

	req.CreatedBy = &userID
	req.UpdatedBy = &userID

	admission, err := h.admissionService.Create(ctx, req)
	if err != nil {
		h.logger.Error("Failed to create admission",
			zap.String("student_id", req.StudentID.String()),
			zap.String("academic_year_id", req.AcademicYearID.String()),
			zap.Error(err))
		h.respondWithError(w, http.StatusBadRequest, err.Error())
		return
	}

	h.respondWithJSON(w, http.StatusCreated, map[string]interface{}{
		"success": true,
		"data":    admission,
		"message": "Admission created successfully",
	})
}

// BulkCreate handles POST /api/v1/companies/{companyID}/admissions/bulk
func (h *AdmissionHandler) BulkCreate(w http.ResponseWriter, r *http.Request) {
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

	if !h.hasPermission(ctx, companyID, "admission:bulk_create") {
		h.respondWithError(w, http.StatusForbidden, "insufficient permissions")
		return
	}

	var reqs []service.CreateAdmissionRequest
	if err := json.NewDecoder(r.Body).Decode(&reqs); err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid request body")
		return
	}

	if len(reqs) == 0 {
		h.respondWithError(w, http.StatusBadRequest, "empty batch")
		return
	}

	// Set CreatedBy/UpdatedBy for each
	for i := range reqs {
		reqs[i].CreatedBy = &userID
		reqs[i].UpdatedBy = &userID
	}

	admissions, err := h.admissionService.BulkCreate(ctx, reqs)
	if err != nil {
		h.logger.Error("Failed to bulk create admissions",
			zap.Int("batch_size", len(reqs)),
			zap.Error(err))
		h.respondWithError(w, http.StatusBadRequest, err.Error())
		return
	}

	h.respondWithJSON(w, http.StatusCreated, map[string]interface{}{
		"success": true,
		"data":    admissions,
		"message": "Admissions created successfully",
	})
}

// GetByID handles GET /api/v1/companies/{companyID}/admissions/{admissionID}
func (h *AdmissionHandler) GetByID(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	companyIDStr := chi.URLParam(r, "companyID")
	companyID, err := uuid.Parse(companyIDStr)
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid company ID")
		return
	}

	admissionIDStr := chi.URLParam(r, "admissionID")
	admissionID, err := uuid.Parse(admissionIDStr)
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid admission ID")
		return
	}

	if !h.hasPermission(ctx, companyID, "admission:read") {
		h.respondWithError(w, http.StatusForbidden, "insufficient permissions")
		return
	}

	admission, err := h.admissionService.GetByID(ctx, admissionID)
	if err != nil {
		h.logger.Error("Failed to get admission",
			zap.String("admission_id", admissionID.String()),
			zap.Error(err))
		h.respondWithError(w, http.StatusNotFound, err.Error())
		return
	}

	h.respondWithJSON(w, http.StatusOK, map[string]interface{}{
		"success": true,
		"data":    admission,
	})
}

// GetByStudentID handles GET /api/v1/companies/{companyID}/students/{studentID}/admissions
func (h *AdmissionHandler) GetByStudentID(w http.ResponseWriter, r *http.Request) {
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

	if !h.hasPermission(ctx, companyID, "admission:read") {
		h.respondWithError(w, http.StatusForbidden, "insufficient permissions")
		return
	}

	admissions, err := h.admissionService.GetByStudentID(ctx, studentID)
	if err != nil {
		h.logger.Error("Failed to get admissions by student",
			zap.String("student_id", studentID.String()),
			zap.Error(err))
		h.respondWithError(w, http.StatusInternalServerError, "failed to retrieve admissions")
		return
	}

	h.respondWithJSON(w, http.StatusOK, map[string]interface{}{
		"success": true,
		"data":    admissions,
	})
}

// GetByAcademicYearID handles GET /api/v1/companies/{companyID}/academic-years/{academicYearID}/admissions
func (h *AdmissionHandler) GetByAcademicYearID(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	companyIDStr := chi.URLParam(r, "companyID")
	companyID, err := uuid.Parse(companyIDStr)
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid company ID")
		return
	}

	academicYearIDStr := chi.URLParam(r, "academicYearID")
	academicYearID, err := uuid.Parse(academicYearIDStr)
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid academic year ID")
		return
	}

	if !h.hasPermission(ctx, companyID, "admission:read") {
		h.respondWithError(w, http.StatusForbidden, "insufficient permissions")
		return
	}

	admissions, err := h.admissionService.GetByAcademicYearID(ctx, academicYearID)
	if err != nil {
		h.logger.Error("Failed to get admissions by academic year",
			zap.String("academic_year_id", academicYearID.String()),
			zap.Error(err))
		h.respondWithError(w, http.StatusInternalServerError, "failed to retrieve admissions")
		return
	}

	h.respondWithJSON(w, http.StatusOK, map[string]interface{}{
		"success": true,
		"data":    admissions,
	})
}

// GetByStudentAndYear handles GET /api/v1/companies/{companyID}/students/{studentID}/academic-years/{academicYearID}/admission
func (h *AdmissionHandler) GetByStudentAndYear(w http.ResponseWriter, r *http.Request) {
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

	if !h.hasPermission(ctx, companyID, "admission:read") {
		h.respondWithError(w, http.StatusForbidden, "insufficient permissions")
		return
	}

	admission, err := h.admissionService.GetByStudentAndYear(ctx, studentID, academicYearID)
	if err != nil {
		h.logger.Error("Failed to get admission by student and year",
			zap.String("student_id", studentID.String()),
			zap.String("academic_year_id", academicYearID.String()),
			zap.Error(err))
		h.respondWithError(w, http.StatusNotFound, err.Error())
		return
	}

	h.respondWithJSON(w, http.StatusOK, map[string]interface{}{
		"success": true,
		"data":    admission,
	})
}

// List handles GET /api/v1/companies/{companyID}/admissions with query params
func (h *AdmissionHandler) List(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	companyIDStr := chi.URLParam(r, "companyID")
	companyID, err := uuid.Parse(companyIDStr)
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid company ID")
		return
	}

	if !h.hasPermission(ctx, companyID, "admission:read") {
		h.respondWithError(w, http.StatusForbidden, "insufficient permissions")
		return
	}

	// Parse filter
	filter := repository.AdmissionFilter{}
	if studentIDStr := r.URL.Query().Get("student_id"); studentIDStr != "" {
		studentID, err := uuid.Parse(studentIDStr)
		if err == nil {
			filter.StudentID = &studentID
		}
	}
	if academicYearIDStr := r.URL.Query().Get("academic_year_id"); academicYearIDStr != "" {
		academicYearID, err := uuid.Parse(academicYearIDStr)
		if err == nil {
			filter.AcademicYearID = &academicYearID
		}
	}
	if status := r.URL.Query().Get("status"); status != "" {
		filter.AdmissionStatus = &status
	}
	if search := r.URL.Query().Get("search"); search != "" {
		// Search is a string field, not a pointer
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
		sortField = "admission_date"
	}
	sortDirection := r.URL.Query().Get("sort_direction")
	if sortDirection == "" {
		sortDirection = "DESC"
	}
	sort := repository.Sort{Field: sortField, Direction: sortDirection}

	admissions, err := h.admissionService.List(ctx, filter, pagination, sort)
	if err != nil {
		h.logger.Error("Failed to list admissions",
			zap.Any("filter", filter),
			zap.Error(err))
		h.respondWithError(w, http.StatusInternalServerError, "failed to list admissions")
		return
	}

	count, err := h.admissionService.Count(ctx, filter)
	if err != nil {
		h.logger.Error("Failed to count admissions", zap.Error(err))
		// Non-fatal, we can still return admissions without total
	}

	h.respondWithJSON(w, http.StatusOK, map[string]interface{}{
		"success": true,
		"data": map[string]interface{}{
			"admissions": admissions,
			"total":      count,
			"limit":      limit,
			"offset":     offset,
		},
	})
}

// Update handles PUT /api/v1/companies/{companyID}/admissions/{admissionID}
func (h *AdmissionHandler) Update(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	companyIDStr := chi.URLParam(r, "companyID")
	companyID, err := uuid.Parse(companyIDStr)
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid company ID")
		return
	}

	admissionIDStr := chi.URLParam(r, "admissionID")
	admissionID, err := uuid.Parse(admissionIDStr)
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid admission ID")
		return
	}

	userID, err := getUserIDFromContext(ctx)
	if err != nil {
		h.respondWithError(w, http.StatusUnauthorized, "authentication required")
		return
	}

	if !h.hasPermission(ctx, companyID, "admission:update") {
		h.respondWithError(w, http.StatusForbidden, "insufficient permissions")
		return
	}

	var req service.UpdateAdmissionRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid request body")
		return
	}

	req.AdmissionID = admissionID
	req.UpdatedBy = &userID

	admission, err := h.admissionService.Update(ctx, req)
	if err != nil {
		h.logger.Error("Failed to update admission",
			zap.String("admission_id", admissionID.String()),
			zap.Error(err))
		h.respondWithError(w, http.StatusBadRequest, err.Error())
		return
	}

	h.respondWithJSON(w, http.StatusOK, map[string]interface{}{
		"success": true,
		"data":    admission,
		"message": "Admission updated successfully",
	})
}

// UpdateStatus handles PATCH /api/v1/companies/{companyID}/admissions/{admissionID}/status
func (h *AdmissionHandler) UpdateStatus(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	companyIDStr := chi.URLParam(r, "companyID")
	companyID, err := uuid.Parse(companyIDStr)
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid company ID")
		return
	}

	admissionIDStr := chi.URLParam(r, "admissionID")
	admissionID, err := uuid.Parse(admissionIDStr)
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid admission ID")
		return
	}

	userID, err := getUserIDFromContext(ctx)
	if err != nil {
		h.respondWithError(w, http.StatusUnauthorized, "authentication required")
		return
	}

	if !h.hasPermission(ctx, companyID, "admission:update_status") {
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
	if !models.IsValidAdmissionStatus(req.Status) {
		h.respondWithError(w, http.StatusBadRequest, "invalid status value")
		return
	}

	err = h.admissionService.UpdateStatus(ctx, admissionID, req.Status, &userID)
	if err != nil {
		h.logger.Error("Failed to update admission status",
			zap.String("admission_id", admissionID.String()),
			zap.String("status", req.Status),
			zap.Error(err))
		h.respondWithError(w, http.StatusBadRequest, err.Error())
		return
	}

	h.respondWithJSON(w, http.StatusOK, map[string]interface{}{
		"success": true,
		"message": "Admission status updated successfully",
	})
}

// Delete handles DELETE /api/v1/companies/{companyID}/admissions/{admissionID}
func (h *AdmissionHandler) Delete(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	companyIDStr := chi.URLParam(r, "companyID")
	companyID, err := uuid.Parse(companyIDStr)
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid company ID")
		return
	}

	admissionIDStr := chi.URLParam(r, "admissionID")
	admissionID, err := uuid.Parse(admissionIDStr)
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid admission ID")
		return
	}

	if !h.hasPermission(ctx, companyID, "admission:delete") {
		h.respondWithError(w, http.StatusForbidden, "insufficient permissions")
		return
	}

	err = h.admissionService.Delete(ctx, admissionID)
	if err != nil {
		h.logger.Error("Failed to delete admission",
			zap.String("admission_id", admissionID.String()),
			zap.Error(err))
		h.respondWithError(w, http.StatusBadRequest, err.Error())
		return
	}

	h.respondWithJSON(w, http.StatusOK, map[string]interface{}{
		"success": true,
		"message": "Admission deleted successfully",
	})
}

// Helper methods
func (h *AdmissionHandler) hasPermission(ctx context.Context, companyID uuid.UUID, permission string) bool {
	// Placeholder – implement actual permission check
	return true
}

func (h *AdmissionHandler) respondWithJSON(w http.ResponseWriter, status int, data interface{}) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	json.NewEncoder(w).Encode(data)
}

func (h *AdmissionHandler) respondWithError(w http.ResponseWriter, status int, message string) {
	h.respondWithJSON(w, status, map[string]interface{}{
		"success": false,
		"error":   message,
	})
}

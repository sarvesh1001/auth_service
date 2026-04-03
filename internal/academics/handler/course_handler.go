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

type CourseHandler struct {
	courseService service.CourseService
	logger        *zap.Logger
}

func NewCourseHandler(courseService service.CourseService, logger *zap.Logger) *CourseHandler {
	return &CourseHandler{
		courseService: courseService,
		logger:        logger.Named("course_handler"),
	}
}

// Create handles POST /api/v1/companies/{companyID}/courses
func (h *CourseHandler) Create(w http.ResponseWriter, r *http.Request) {
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

	if !h.hasPermission(ctx, companyID, "course:create") {
		h.respondWithError(w, http.StatusForbidden, "insufficient permissions")
		return
	}

	var req service.CreateCourseRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid request body")
		return
	}

	req.CompanyID = companyID
	req.CreatedBy = &userID
	req.UpdatedBy = &userID

	course, err := h.courseService.Create(ctx, req)
	if err != nil {
		h.logger.Error("Failed to create course",
			zap.String("company_id", companyID.String()),
			zap.String("code", req.Code),
			zap.Error(err))
		h.respondWithError(w, http.StatusBadRequest, err.Error())
		return
	}

	h.respondWithJSON(w, http.StatusCreated, map[string]interface{}{
		"success": true,
		"data":    course,
		"message": "Course created successfully",
	})
}

// BulkCreate handles POST /api/v1/companies/{companyID}/courses/bulk
func (h *CourseHandler) BulkCreate(w http.ResponseWriter, r *http.Request) {
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

	if !h.hasPermission(ctx, companyID, "course:bulk_create") {
		h.respondWithError(w, http.StatusForbidden, "insufficient permissions")
		return
	}

	var reqs []service.CreateCourseRequest
	if err := json.NewDecoder(r.Body).Decode(&reqs); err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid request body")
		return
	}

	if len(reqs) == 0 {
		h.respondWithError(w, http.StatusBadRequest, "empty batch")
		return
	}

	for i := range reqs {
		reqs[i].CompanyID = companyID
		reqs[i].CreatedBy = &userID
		reqs[i].UpdatedBy = &userID
	}

	courses, err := h.courseService.BulkCreate(ctx, reqs)
	if err != nil {
		h.logger.Error("Failed to bulk create courses",
			zap.Int("batch_size", len(reqs)),
			zap.Error(err))
		h.respondWithError(w, http.StatusBadRequest, err.Error())
		return
	}

	h.respondWithJSON(w, http.StatusCreated, map[string]interface{}{
		"success": true,
		"data":    courses,
		"message": "Courses created successfully",
	})
}

// GetByID handles GET /api/v1/companies/{companyID}/courses/{courseID}
func (h *CourseHandler) GetByID(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	companyIDStr := chi.URLParam(r, "companyID")
	companyID, err := uuid.Parse(companyIDStr)
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid company ID")
		return
	}

	courseIDStr := chi.URLParam(r, "courseID")
	courseID, err := uuid.Parse(courseIDStr)
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid course ID")
		return
	}

	if !h.hasPermission(ctx, companyID, "course:read") {
		h.respondWithError(w, http.StatusForbidden, "insufficient permissions")
		return
	}

	course, err := h.courseService.GetByID(ctx, courseID)
	if err != nil {
		h.logger.Error("Failed to get course",
			zap.String("course_id", courseID.String()),
			zap.Error(err))
		h.respondWithError(w, http.StatusNotFound, err.Error())
		return
	}

	// Ensure course belongs to the requested company
	if course.CompanyID != companyID {
		h.respondWithError(w, http.StatusNotFound, "course not found")
		return
	}

	h.respondWithJSON(w, http.StatusOK, map[string]interface{}{
		"success": true,
		"data":    course,
	})
}

// GetByCode handles GET /api/v1/companies/{companyID}/courses/by-code?code=...
func (h *CourseHandler) GetByCode(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	companyIDStr := chi.URLParam(r, "companyID")
	companyID, err := uuid.Parse(companyIDStr)
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid company ID")
		return
	}

	code := r.URL.Query().Get("code")
	if code == "" {
		h.respondWithError(w, http.StatusBadRequest, "code query parameter is required")
		return
	}

	if !h.hasPermission(ctx, companyID, "course:read") {
		h.respondWithError(w, http.StatusForbidden, "insufficient permissions")
		return
	}

	course, err := h.courseService.GetByCode(ctx, companyID, code)
	if err != nil {
		h.logger.Error("Failed to get course by code",
			zap.String("company_id", companyID.String()),
			zap.String("code", code),
			zap.Error(err))
		h.respondWithError(w, http.StatusNotFound, err.Error())
		return
	}

	h.respondWithJSON(w, http.StatusOK, map[string]interface{}{
		"success": true,
		"data":    course,
	})
}

// List handles GET /api/v1/companies/{companyID}/courses
func (h *CourseHandler) List(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	companyIDStr := chi.URLParam(r, "companyID")
	companyID, err := uuid.Parse(companyIDStr)
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid company ID")
		return
	}

	if !h.hasPermission(ctx, companyID, "course:read") {
		h.respondWithError(w, http.StatusForbidden, "insufficient permissions")
		return
	}

	// Parse filter – only include fields supported by CourseFilter
	filter := repository.CourseFilter{
		CompanyID: companyID, // not pointer
	}

	if search := r.URL.Query().Get("search"); search != "" {
		filter.Search = search // string, not pointer
	}
	if isActiveStr := r.URL.Query().Get("is_active"); isActiveStr != "" {
		isActive, err := strconv.ParseBool(isActiveStr)
		if err == nil {
			filter.IsActive = &isActive // IsActive is *bool
		}
	}
	if code := r.URL.Query().Get("code"); code != "" {
		filter.Code = code // string, not pointer
	}
	// Note: Name, CreatedBy, UpdatedBy, FromDate, ToDate are not part of CourseFilter; removed.

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

	courses, err := h.courseService.List(ctx, filter, pagination, sort)
	if err != nil {
		h.logger.Error("Failed to list courses",
			zap.Any("filter", filter),
			zap.Error(err))
		h.respondWithError(w, http.StatusInternalServerError, "failed to list courses")
		return
	}

	count, err := h.courseService.Count(ctx, filter)
	if err != nil {
		h.logger.Error("Failed to count courses", zap.Error(err))
		// Non-fatal, we can still return courses without total
	}

	h.respondWithJSON(w, http.StatusOK, map[string]interface{}{
		"success": true,
		"data": map[string]interface{}{
			"courses": courses,
			"total":   count,
			"limit":   limit,
			"offset":  offset,
		},
	})
}

// ListActive handles GET /api/v1/companies/{companyID}/courses/active
func (h *CourseHandler) ListActive(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	companyIDStr := chi.URLParam(r, "companyID")
	companyID, err := uuid.Parse(companyIDStr)
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid company ID")
		return
	}

	if !h.hasPermission(ctx, companyID, "course:read") {
		h.respondWithError(w, http.StatusForbidden, "insufficient permissions")
		return
	}

	courses, err := h.courseService.ListActive(ctx, companyID)
	if err != nil {
		h.logger.Error("Failed to list active courses",
			zap.String("company_id", companyID.String()),
			zap.Error(err))
		h.respondWithError(w, http.StatusInternalServerError, "failed to list active courses")
		return
	}

	h.respondWithJSON(w, http.StatusOK, map[string]interface{}{
		"success": true,
		"data":    courses,
	})
}

// Update handles PUT /api/v1/companies/{companyID}/courses/{courseID}
func (h *CourseHandler) Update(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	companyIDStr := chi.URLParam(r, "companyID")
	companyID, err := uuid.Parse(companyIDStr)
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid company ID")
		return
	}

	courseIDStr := chi.URLParam(r, "courseID")
	courseID, err := uuid.Parse(courseIDStr)
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid course ID")
		return
	}

	userID, err := getUserIDFromContext(ctx)
	if err != nil {
		h.respondWithError(w, http.StatusUnauthorized, "authentication required")
		return
	}

	if !h.hasPermission(ctx, companyID, "course:update") {
		h.respondWithError(w, http.StatusForbidden, "insufficient permissions")
		return
	}

	var req service.UpdateCourseRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid request body")
		return
	}

	req.CourseID = courseID
	req.UpdatedBy = &userID

	course, err := h.courseService.Update(ctx, req)
	if err != nil {
		h.logger.Error("Failed to update course",
			zap.String("course_id", courseID.String()),
			zap.Error(err))
		h.respondWithError(w, http.StatusBadRequest, err.Error())
		return
	}

	// Ensure course belongs to the requested company
	if course.CompanyID != companyID {
		h.respondWithError(w, http.StatusNotFound, "course not found")
		return
	}

	h.respondWithJSON(w, http.StatusOK, map[string]interface{}{
		"success": true,
		"data":    course,
		"message": "Course updated successfully",
	})
}

// Activate handles PATCH /api/v1/companies/{companyID}/courses/{courseID}/activate
func (h *CourseHandler) Activate(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	companyIDStr := chi.URLParam(r, "companyID")
	companyID, err := uuid.Parse(companyIDStr)
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid company ID")
		return
	}

	courseIDStr := chi.URLParam(r, "courseID")
	courseID, err := uuid.Parse(courseIDStr)
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid course ID")
		return
	}

	userID, err := getUserIDFromContext(ctx)
	if err != nil {
		h.respondWithError(w, http.StatusUnauthorized, "authentication required")
		return
	}

	if !h.hasPermission(ctx, companyID, "course:activate") {
		h.respondWithError(w, http.StatusForbidden, "insufficient permissions")
		return
	}

	if err := h.courseService.Activate(ctx, courseID, &userID); err != nil {
		h.logger.Error("Failed to activate course",
			zap.String("course_id", courseID.String()),
			zap.Error(err))
		h.respondWithError(w, http.StatusBadRequest, err.Error())
		return
	}

	h.respondWithJSON(w, http.StatusOK, map[string]interface{}{
		"success": true,
		"message": "Course activated successfully",
	})
}

// Deactivate handles PATCH /api/v1/companies/{companyID}/courses/{courseID}/deactivate
func (h *CourseHandler) Deactivate(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	companyIDStr := chi.URLParam(r, "companyID")
	companyID, err := uuid.Parse(companyIDStr)
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid company ID")
		return
	}

	courseIDStr := chi.URLParam(r, "courseID")
	courseID, err := uuid.Parse(courseIDStr)
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid course ID")
		return
	}

	userID, err := getUserIDFromContext(ctx)
	if err != nil {
		h.respondWithError(w, http.StatusUnauthorized, "authentication required")
		return
	}

	if !h.hasPermission(ctx, companyID, "course:deactivate") {
		h.respondWithError(w, http.StatusForbidden, "insufficient permissions")
		return
	}

	if err := h.courseService.Deactivate(ctx, courseID, &userID); err != nil {
		h.logger.Error("Failed to deactivate course",
			zap.String("course_id", courseID.String()),
			zap.Error(err))
		h.respondWithError(w, http.StatusBadRequest, err.Error())
		return
	}

	h.respondWithJSON(w, http.StatusOK, map[string]interface{}{
		"success": true,
		"message": "Course deactivated successfully",
	})
}

// Delete handles DELETE /api/v1/companies/{companyID}/courses/{courseID}
func (h *CourseHandler) Delete(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	companyIDStr := chi.URLParam(r, "companyID")
	companyID, err := uuid.Parse(companyIDStr)
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid company ID")
		return
	}

	courseIDStr := chi.URLParam(r, "courseID")
	courseID, err := uuid.Parse(courseIDStr)
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid course ID")
		return
	}

	userID, err := getUserIDFromContext(ctx)
	if err != nil {
		h.respondWithError(w, http.StatusUnauthorized, "authentication required")
		return
	}

	if !h.hasPermission(ctx, companyID, "course:delete") {
		h.respondWithError(w, http.StatusForbidden, "insufficient permissions")
		return
	}

	if err := h.courseService.Delete(ctx, courseID, &userID); err != nil {
		h.logger.Error("Failed to delete course",
			zap.String("course_id", courseID.String()),
			zap.Error(err))
		h.respondWithError(w, http.StatusBadRequest, err.Error())
		return
	}

	h.respondWithJSON(w, http.StatusOK, map[string]interface{}{
		"success": true,
		"message": "Course deleted successfully",
	})
}

// ValidateUniqueCode handles POST /api/v1/companies/{companyID}/courses/validate-code
func (h *CourseHandler) ValidateUniqueCode(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	companyIDStr := chi.URLParam(r, "companyID")
	companyID, err := uuid.Parse(companyIDStr)
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid company ID")
		return
	}

	if !h.hasPermission(ctx, companyID, "course:read") {
		h.respondWithError(w, http.StatusForbidden, "insufficient permissions")
		return
	}

	var req struct {
		Code string `json:"code"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid request body")
		return
	}
	if req.Code == "" {
		h.respondWithError(w, http.StatusBadRequest, "code is required")
		return
	}

	err = h.courseService.ValidateUniqueCode(ctx, companyID, req.Code)
	if err != nil {
		// Return 409 Conflict if duplicate
		if err == service.ErrDuplicate {
			h.respondWithError(w, http.StatusConflict, err.Error())
		} else {
			h.respondWithError(w, http.StatusBadRequest, err.Error())
		}
		return
	}

	h.respondWithJSON(w, http.StatusOK, map[string]interface{}{
		"success": true,
		"message": "Code is unique",
	})
}

// Helper methods
func (h *CourseHandler) hasPermission(ctx context.Context, companyID uuid.UUID, permission string) bool {
	// Placeholder – implement actual permission check
	return true
}

func (h *CourseHandler) respondWithJSON(w http.ResponseWriter, status int, data interface{}) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	json.NewEncoder(w).Encode(data)
}

func (h *CourseHandler) respondWithError(w http.ResponseWriter, status int, message string) {
	h.respondWithJSON(w, status, map[string]interface{}{
		"success": false,
		"error":   message,
	})
}

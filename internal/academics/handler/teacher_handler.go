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
	"auth-service/internal/academics/repository"
	"auth-service/internal/academics/service"
)

// TeacherHandler handles all teacher-related endpoints.
type TeacherHandler struct {
	teacherService service.TeacherService
	logger         *zap.Logger
}

// NewTeacherHandler creates a new TeacherHandler.
func NewTeacherHandler(teacherService service.TeacherService, logger *zap.Logger) *TeacherHandler {
	return &TeacherHandler{
		teacherService: teacherService,
		logger:         logger.Named("teacher_handler"),
	}
}

// ---------------------- Teacher CRUD ----------------------------------------

// CreateTeacherRequest is the body for creating a single teacher.
type CreateTeacherRequest struct {
	UserID         string     `json:"user_id"`
	EmployeeCode   string     `json:"employee_code"`
	Qualification  string     `json:"qualification,omitempty"`
	Specialization string     `json:"specialization,omitempty"`
	JoiningDate    *time.Time `json:"joining_date,omitempty"`
	Status         string     `json:"status,omitempty"` // defaults to "active"
}

// Create handles POST /api/v1/companies/{companyID}/teachers
func (h *TeacherHandler) Create(w http.ResponseWriter, r *http.Request) {
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

	if !h.hasPermission(ctx, companyID, "teacher:create") {
		h.respondWithError(w, http.StatusForbidden, "insufficient permissions")
		return
	}

	var req CreateTeacherRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid request body")
		return
	}

	if req.UserID == "" {
		h.respondWithError(w, http.StatusBadRequest, "user_id is required")
		return
	}
	if req.EmployeeCode == "" {
		h.respondWithError(w, http.StatusBadRequest, "employee_code is required")
		return
	}
	if req.Status == "" {
		req.Status = string(models.TeacherActive)
	}

	userUUID, err := uuid.Parse(req.UserID)
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid user_id")
		return
	}

	createReq := service.CreateTeacherRequest{
		CompanyID:      companyID,
		UserID:         userUUID,
		EmployeeCode:   req.EmployeeCode,
		Qualification:  req.Qualification,
		Specialization: req.Specialization,
		JoiningDate:    req.JoiningDate,
		Status:         req.Status,
		CreatedBy:      &userID,
		UpdatedBy:      &userID,
	}

	teacher, err := h.teacherService.Create(ctx, createReq, "")
	if err != nil {
		h.logger.Error("Failed to create teacher",
			zap.String("company_id", companyID.String()),
			zap.String("employee_code", req.EmployeeCode),
			zap.Error(err))
		h.respondWithError(w, http.StatusBadRequest, err.Error())
		return
	}

	h.respondWithJSON(w, http.StatusCreated, map[string]interface{}{
		"success": true,
		"data":    teacher,
		"message": "Teacher created successfully",
	})
}

// BulkCreateTeachersRequest is the body for bulk create.
type BulkCreateTeachersRequest []CreateTeacherRequest

// BulkCreate handles POST /api/v1/companies/{companyID}/teachers/bulk
func (h *TeacherHandler) BulkCreate(w http.ResponseWriter, r *http.Request) {
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

	if !h.hasPermission(ctx, companyID, "teacher:bulk_create") {
		h.respondWithError(w, http.StatusForbidden, "insufficient permissions")
		return
	}

	var reqs BulkCreateTeachersRequest
	if err := json.NewDecoder(r.Body).Decode(&reqs); err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid request body")
		return
	}
	if len(reqs) == 0 {
		h.respondWithError(w, http.StatusBadRequest, "empty batch")
		return
	}

	// Convert to service requests
	createReqs := make([]service.CreateTeacherRequest, len(reqs))
	for i, r := range reqs {
		if r.UserID == "" || r.EmployeeCode == "" {
			h.respondWithError(w, http.StatusBadRequest, "user_id and employee_code are required for all teachers")
			return
		}
		if r.Status == "" {
			r.Status = string(models.TeacherActive)
		}
		userUUID, err := uuid.Parse(r.UserID)
		if err != nil {
			h.respondWithError(w, http.StatusBadRequest, "invalid user_id in batch")
			return
		}
		createReqs[i] = service.CreateTeacherRequest{
			CompanyID:      companyID,
			UserID:         userUUID,
			EmployeeCode:   r.EmployeeCode,
			Qualification:  r.Qualification,
			Specialization: r.Specialization,
			JoiningDate:    r.JoiningDate,
			Status:         r.Status,
			CreatedBy:      &userID,
			UpdatedBy:      &userID,
		}
	}

	teachers, err := h.teacherService.BulkCreate(ctx, createReqs)
	if err != nil {
		h.logger.Error("Failed to bulk create teachers",
			zap.Int("count", len(reqs)),
			zap.Error(err))
		h.respondWithError(w, http.StatusBadRequest, err.Error())
		return
	}

	h.respondWithJSON(w, http.StatusCreated, map[string]interface{}{
		"success": true,
		"data":    teachers,
		"message": "Teachers created successfully",
	})
}

// GetByID handles GET /api/v1/companies/{companyID}/teachers/{teacherID}
func (h *TeacherHandler) GetByID(w http.ResponseWriter, r *http.Request) {
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

	if !h.hasPermission(ctx, companyID, "teacher:read") {
		h.respondWithError(w, http.StatusForbidden, "insufficient permissions")
		return
	}

	teacher, err := h.teacherService.GetByID(ctx, teacherID)
	if err != nil {
		h.logger.Error("Failed to get teacher",
			zap.String("teacher_id", teacherID.String()),
			zap.Error(err))
		h.respondWithError(w, http.StatusNotFound, err.Error())
		return
	}

	h.respondWithJSON(w, http.StatusOK, map[string]interface{}{
		"success": true,
		"data":    teacher,
	})
}

// GetByUserID handles GET /api/v1/companies/{companyID}/teachers/by-user/{userID}
func (h *TeacherHandler) GetByUserID(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	companyIDStr := chi.URLParam(r, "companyID")
	companyID, err := uuid.Parse(companyIDStr)
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid company ID")
		return
	}

	userIDStr := chi.URLParam(r, "userID")
	userID, err := uuid.Parse(userIDStr)
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid user ID")
		return
	}

	if !h.hasPermission(ctx, companyID, "teacher:read") {
		h.respondWithError(w, http.StatusForbidden, "insufficient permissions")
		return
	}

	teacher, err := h.teacherService.GetByUserID(ctx, userID)
	if err != nil {
		h.logger.Error("Failed to get teacher by user ID",
			zap.String("user_id", userID.String()),
			zap.Error(err))
		h.respondWithError(w, http.StatusNotFound, err.Error())
		return
	}

	h.respondWithJSON(w, http.StatusOK, map[string]interface{}{
		"success": true,
		"data":    teacher,
	})
}

// GetByEmployeeCode handles GET /api/v1/companies/{companyID}/teachers/by-code/{employeeCode}
func (h *TeacherHandler) GetByEmployeeCode(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	companyIDStr := chi.URLParam(r, "companyID")
	companyID, err := uuid.Parse(companyIDStr)
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid company ID")
		return
	}

	employeeCode := chi.URLParam(r, "employeeCode")
	if employeeCode == "" {
		h.respondWithError(w, http.StatusBadRequest, "employee code is required")
		return
	}

	if !h.hasPermission(ctx, companyID, "teacher:read") {
		h.respondWithError(w, http.StatusForbidden, "insufficient permissions")
		return
	}

	teacher, err := h.teacherService.GetByEmployeeCode(ctx, companyID, employeeCode)
	if err != nil {
		h.logger.Error("Failed to get teacher by employee code",
			zap.String("company_id", companyID.String()),
			zap.String("employee_code", employeeCode),
			zap.Error(err))
		h.respondWithError(w, http.StatusNotFound, err.Error())
		return
	}

	h.respondWithJSON(w, http.StatusOK, map[string]interface{}{
		"success": true,
		"data":    teacher,
	})
}

// List handles GET /api/v1/companies/{companyID}/teachers
func (h *TeacherHandler) List(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	companyIDStr := chi.URLParam(r, "companyID")
	companyID, err := uuid.Parse(companyIDStr)
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid company ID")
		return
	}

	if !h.hasPermission(ctx, companyID, "teacher:read") {
		h.respondWithError(w, http.StatusForbidden, "insufficient permissions")
		return
	}

	// Build filter
	filter := repository.TeacherFilter{
		CompanyID: companyID,
	}
	if status := r.URL.Query().Get("status"); status != "" {
		filter.Status = &status
	}
	if specialization := r.URL.Query().Get("specialization"); specialization != "" {
		filter.Specialization = specialization // field is string, not pointer
	}
	if search := r.URL.Query().Get("search"); search != "" {
		filter.Search = search
	}
	if userIDStr := r.URL.Query().Get("user_id"); userIDStr != "" {
		if uid, err := uuid.Parse(userIDStr); err == nil {
			filter.UserID = &uid
		}
	}
	// Note: SectionID and SubjectID filters are not part of TeacherFilter; remove if not present.
	// If your filter supports them, add accordingly. Otherwise omit.

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

	teachers, err := h.teacherService.List(ctx, filter, pagination, sort)
	if err != nil {
		h.logger.Error("Failed to list teachers",
			zap.Any("filter", filter),
			zap.Error(err))
		h.respondWithError(w, http.StatusInternalServerError, "failed to list teachers")
		return
	}

	count, err := h.teacherService.Count(ctx, filter)
	if err != nil {
		h.logger.Error("Failed to count teachers", zap.Error(err))
		// non-fatal
	}

	h.respondWithJSON(w, http.StatusOK, map[string]interface{}{
		"success": true,
		"data": map[string]interface{}{
			"teachers": teachers,
			"total":    count,
			"limit":    limit,
			"offset":   offset,
		},
	})
}

// UpdateTeacherRequest is the body for updating a teacher.
type UpdateTeacherRequest struct {
	UserID         string     `json:"user_id,omitempty"`
	EmployeeCode   string     `json:"employee_code,omitempty"`
	Qualification  string     `json:"qualification,omitempty"`
	Specialization string     `json:"specialization,omitempty"`
	JoiningDate    *time.Time `json:"joining_date,omitempty"`
	Status         string     `json:"status,omitempty"`
}

// Update handles PUT /api/v1/companies/{companyID}/teachers/{teacherID}
func (h *TeacherHandler) Update(w http.ResponseWriter, r *http.Request) {
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

	userID, err := getUserIDFromContext(ctx)
	if err != nil {
		h.respondWithError(w, http.StatusUnauthorized, "authentication required")
		return
	}

	if !h.hasPermission(ctx, companyID, "teacher:update") {
		h.respondWithError(w, http.StatusForbidden, "insufficient permissions")
		return
	}

	var req UpdateTeacherRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid request body")
		return
	}

	// At least one field must be provided
	if req.UserID == "" && req.EmployeeCode == "" && req.Qualification == "" && req.Specialization == "" && req.JoiningDate == nil && req.Status == "" {
		h.respondWithError(w, http.StatusBadRequest, "no fields to update")
		return
	}

	updateReq := service.UpdateTeacherRequest{
		TeacherID:      teacherID,
		EmployeeCode:   req.EmployeeCode,
		Qualification:  req.Qualification,
		Specialization: req.Specialization,
		JoiningDate:    req.JoiningDate,
		Status:         req.Status,
		UpdatedBy:      &userID,
	}
	if req.UserID != "" {
		uid, err := uuid.Parse(req.UserID)
		if err != nil {
			h.respondWithError(w, http.StatusBadRequest, "invalid user_id")
			return
		}
		updateReq.UserID = uid
	}

	teacher, err := h.teacherService.Update(ctx, updateReq)
	if err != nil {
		h.logger.Error("Failed to update teacher",
			zap.String("teacher_id", teacherID.String()),
			zap.Error(err))
		h.respondWithError(w, http.StatusBadRequest, err.Error())
		return
	}

	h.respondWithJSON(w, http.StatusOK, map[string]interface{}{
		"success": true,
		"data":    teacher,
		"message": "Teacher updated successfully",
	})
}

// UpdateStatusRequest is the body for updating status.
type UpdateStatusRequest struct {
	Status string `json:"status"`
}

// UpdateStatus handles PATCH /api/v1/companies/{companyID}/teachers/{teacherID}/status
func (h *TeacherHandler) UpdateStatus(w http.ResponseWriter, r *http.Request) {
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

	userID, err := getUserIDFromContext(ctx)
	if err != nil {
		h.respondWithError(w, http.StatusUnauthorized, "authentication required")
		return
	}

	if !h.hasPermission(ctx, companyID, "teacher:update_status") {
		h.respondWithError(w, http.StatusForbidden, "insufficient permissions")
		return
	}

	var req UpdateStatusRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid request body")
		return
	}
	if req.Status == "" {
		h.respondWithError(w, http.StatusBadRequest, "status is required")
		return
	}
	if !models.IsValidTeacherStatus(req.Status) {
		h.respondWithError(w, http.StatusBadRequest, "invalid status")
		return
	}

	err = h.teacherService.UpdateStatus(ctx, teacherID, req.Status, &userID)
	if err != nil {
		h.logger.Error("Failed to update teacher status",
			zap.String("teacher_id", teacherID.String()),
			zap.Error(err))
		h.respondWithError(w, http.StatusBadRequest, err.Error())
		return
	}

	h.respondWithJSON(w, http.StatusOK, map[string]interface{}{
		"success": true,
		"message": "Teacher status updated",
	})
}

// Delete handles DELETE /api/v1/companies/{companyID}/teachers/{teacherID}
func (h *TeacherHandler) Delete(w http.ResponseWriter, r *http.Request) {
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

	userID, err := getUserIDFromContext(ctx)
	if err != nil {
		h.respondWithError(w, http.StatusUnauthorized, "authentication required")
		return
	}

	if !h.hasPermission(ctx, companyID, "teacher:delete") {
		h.respondWithError(w, http.StatusForbidden, "insufficient permissions")
		return
	}

	err = h.teacherService.Delete(ctx, teacherID, &userID)
	if err != nil {
		h.logger.Error("Failed to delete teacher",
			zap.String("teacher_id", teacherID.String()),
			zap.Error(err))
		h.respondWithError(w, http.StatusBadRequest, err.Error())
		return
	}

	h.respondWithJSON(w, http.StatusOK, map[string]interface{}{
		"success": true,
		"message": "Teacher deleted",
	})
}

// TeacherBulkUpdateStatusRequest is the body for bulk status update.
type TeacherBulkUpdateStatusRequest struct {
	TeacherIDs []string `json:"teacher_ids"`
	Status     string   `json:"status"`
}

// BulkUpdateStatus handles PATCH /api/v1/companies/{companyID}/teachers/bulk/status
func (h *TeacherHandler) BulkUpdateStatus(w http.ResponseWriter, r *http.Request) {
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

	if !h.hasPermission(ctx, companyID, "teacher:bulk_update_status") {
		h.respondWithError(w, http.StatusForbidden, "insufficient permissions")
		return
	}

	var req TeacherBulkUpdateStatusRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid request body")
		return
	}
	if len(req.TeacherIDs) == 0 {
		h.respondWithError(w, http.StatusBadRequest, "teacher_ids is required")
		return
	}
	if req.Status == "" {
		h.respondWithError(w, http.StatusBadRequest, "status is required")
		return
	}
	if !models.IsValidTeacherStatus(req.Status) {
		h.respondWithError(w, http.StatusBadRequest, "invalid status")
		return
	}

	ids := make([]uuid.UUID, len(req.TeacherIDs))
	for i, sid := range req.TeacherIDs {
		uid, err := uuid.Parse(sid)
		if err != nil {
			h.respondWithError(w, http.StatusBadRequest, "invalid teacher_id in list")
			return
		}
		ids[i] = uid
	}

	err = h.teacherService.BulkUpdateStatus(ctx, ids, req.Status, &userID)
	if err != nil {
		h.logger.Error("Failed to bulk update teacher status",
			zap.Int("count", len(ids)),
			zap.Error(err))
		h.respondWithError(w, http.StatusBadRequest, err.Error())
		return
	}

	h.respondWithJSON(w, http.StatusOK, map[string]interface{}{
		"success": true,
		"message": "Teacher statuses updated",
	})
}

// CountByCompany handles GET /api/v1/companies/{companyID}/teachers/count
func (h *TeacherHandler) CountByCompany(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	companyIDStr := chi.URLParam(r, "companyID")
	companyID, err := uuid.Parse(companyIDStr)
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid company ID")
		return
	}

	if !h.hasPermission(ctx, companyID, "teacher:read") {
		h.respondWithError(w, http.StatusForbidden, "insufficient permissions")
		return
	}

	count, err := h.teacherService.CountByCompany(ctx, companyID)
	if err != nil {
		h.logger.Error("Failed to count teachers by company",
			zap.String("company_id", companyID.String()),
			zap.Error(err))
		h.respondWithError(w, http.StatusInternalServerError, "failed to count teachers")
		return
	}

	h.respondWithJSON(w, http.StatusOK, map[string]interface{}{
		"success": true,
		"data":    map[string]interface{}{"count": count},
	})
}

// ---------------------- Subject Management --------------------------------

// AddSubjectRequest is the body for adding a subject to a teacher.
type AddSubjectRequest struct {
	SubjectID string `json:"subject_id"`
	IsPrimary bool   `json:"is_primary"`
}

// AddSubject handles POST /api/v1/companies/{companyID}/teachers/{teacherID}/subjects
func (h *TeacherHandler) AddSubject(w http.ResponseWriter, r *http.Request) {
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

	if !h.hasPermission(ctx, companyID, "teacher:manage_subjects") {
		h.respondWithError(w, http.StatusForbidden, "insufficient permissions")
		return
	}

	var req AddSubjectRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid request body")
		return
	}
	if req.SubjectID == "" {
		h.respondWithError(w, http.StatusBadRequest, "subject_id is required")
		return
	}
	subjectID, err := uuid.Parse(req.SubjectID)
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid subject_id")
		return
	}

	err = h.teacherService.AddSubject(ctx, teacherID, subjectID, req.IsPrimary)
	if err != nil {
		h.logger.Error("Failed to add subject to teacher",
			zap.String("teacher_id", teacherID.String()),
			zap.String("subject_id", subjectID.String()),
			zap.Error(err))
		h.respondWithError(w, http.StatusBadRequest, err.Error())
		return
	}

	h.respondWithJSON(w, http.StatusOK, map[string]interface{}{
		"success": true,
		"message": "Subject added to teacher",
	})
}

// RemoveSubject handles DELETE /api/v1/companies/{companyID}/teachers/{teacherID}/subjects/{subjectID}
func (h *TeacherHandler) RemoveSubject(w http.ResponseWriter, r *http.Request) {
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
	subjectIDStr := chi.URLParam(r, "subjectID")
	subjectID, err := uuid.Parse(subjectIDStr)
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid subject ID")
		return
	}

	if !h.hasPermission(ctx, companyID, "teacher:manage_subjects") {
		h.respondWithError(w, http.StatusForbidden, "insufficient permissions")
		return
	}

	err = h.teacherService.RemoveSubject(ctx, teacherID, subjectID)
	if err != nil {
		h.logger.Error("Failed to remove subject from teacher",
			zap.String("teacher_id", teacherID.String()),
			zap.String("subject_id", subjectID.String()),
			zap.Error(err))
		h.respondWithError(w, http.StatusBadRequest, err.Error())
		return
	}

	h.respondWithJSON(w, http.StatusOK, map[string]interface{}{
		"success": true,
		"message": "Subject removed from teacher",
	})
}

// GetSubjectsByTeacher handles GET /api/v1/companies/{companyID}/teachers/{teacherID}/subjects
func (h *TeacherHandler) GetSubjectsByTeacher(w http.ResponseWriter, r *http.Request) {
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

	if !h.hasPermission(ctx, companyID, "teacher:read") {
		h.respondWithError(w, http.StatusForbidden, "insufficient permissions")
		return
	}

	subjects, err := h.teacherService.GetSubjectsByTeacher(ctx, teacherID)
	if err != nil {
		h.logger.Error("Failed to get subjects for teacher",
			zap.String("teacher_id", teacherID.String()),
			zap.Error(err))
		h.respondWithError(w, http.StatusInternalServerError, "failed to retrieve subjects")
		return
	}

	h.respondWithJSON(w, http.StatusOK, map[string]interface{}{
		"success": true,
		"data":    subjects,
	})
}

// GetTeachersBySubject handles GET /api/v1/companies/{companyID}/subjects/{subjectID}/teachers
func (h *TeacherHandler) GetTeachersBySubject(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	companyIDStr := chi.URLParam(r, "companyID")
	companyID, err := uuid.Parse(companyIDStr)
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid company ID")
		return
	}

	subjectIDStr := chi.URLParam(r, "subjectID")
	subjectID, err := uuid.Parse(subjectIDStr)
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid subject ID")
		return
	}

	if !h.hasPermission(ctx, companyID, "teacher:read") {
		h.respondWithError(w, http.StatusForbidden, "insufficient permissions")
		return
	}

	teachers, err := h.teacherService.GetTeachersBySubject(ctx, subjectID)
	if err != nil {
		h.logger.Error("Failed to get teachers by subject",
			zap.String("subject_id", subjectID.String()),
			zap.Error(err))
		h.respondWithError(w, http.StatusInternalServerError, "failed to retrieve teachers")
		return
	}

	h.respondWithJSON(w, http.StatusOK, map[string]interface{}{
		"success": true,
		"data":    teachers,
	})
}

// UpdateSubjectPrimaryRequest is the body for updating subject primary status.
type UpdateSubjectPrimaryRequest struct {
	IsPrimary bool `json:"is_primary"`
}

// UpdateSubjectPrimary handles PATCH /api/v1/companies/{companyID}/teachers/{teacherID}/subjects/{subjectID}
func (h *TeacherHandler) UpdateSubjectPrimary(w http.ResponseWriter, r *http.Request) {
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
	subjectIDStr := chi.URLParam(r, "subjectID")
	subjectID, err := uuid.Parse(subjectIDStr)
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid subject ID")
		return
	}

	if !h.hasPermission(ctx, companyID, "teacher:manage_subjects") {
		h.respondWithError(w, http.StatusForbidden, "insufficient permissions")
		return
	}

	var req UpdateSubjectPrimaryRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid request body")
		return
	}

	err = h.teacherService.UpdateSubjectPrimary(ctx, teacherID, subjectID, req.IsPrimary)
	if err != nil {
		h.logger.Error("Failed to update subject primary status",
			zap.String("teacher_id", teacherID.String()),
			zap.String("subject_id", subjectID.String()),
			zap.Error(err))
		h.respondWithError(w, http.StatusBadRequest, err.Error())
		return
	}

	h.respondWithJSON(w, http.StatusOK, map[string]interface{}{
		"success": true,
		"message": "Subject primary status updated",
	})
}

// ---------------------- Section Management --------------------------------

// AddSectionRequest is the body for adding a section to a teacher.
type AddSectionRequest struct {
	SectionID      string `json:"section_id"`
	IsClassTeacher bool   `json:"is_class_teacher"`
}

// AddSection handles POST /api/v1/companies/{companyID}/teachers/{teacherID}/sections
func (h *TeacherHandler) AddSection(w http.ResponseWriter, r *http.Request) {
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

	if !h.hasPermission(ctx, companyID, "teacher:manage_sections") {
		h.respondWithError(w, http.StatusForbidden, "insufficient permissions")
		return
	}

	var req AddSectionRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid request body")
		return
	}
	if req.SectionID == "" {
		h.respondWithError(w, http.StatusBadRequest, "section_id is required")
		return
	}
	sectionID, err := uuid.Parse(req.SectionID)
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid section_id")
		return
	}

	err = h.teacherService.AddSection(ctx, teacherID, sectionID, req.IsClassTeacher)
	if err != nil {
		h.logger.Error("Failed to add section to teacher",
			zap.String("teacher_id", teacherID.String()),
			zap.String("section_id", sectionID.String()),
			zap.Error(err))
		h.respondWithError(w, http.StatusBadRequest, err.Error())
		return
	}

	h.respondWithJSON(w, http.StatusOK, map[string]interface{}{
		"success": true,
		"message": "Section added to teacher",
	})
}

// RemoveSection handles DELETE /api/v1/companies/{companyID}/teachers/{teacherID}/sections/{sectionID}
func (h *TeacherHandler) RemoveSection(w http.ResponseWriter, r *http.Request) {
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
	sectionIDStr := chi.URLParam(r, "sectionID")
	sectionID, err := uuid.Parse(sectionIDStr)
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid section ID")
		return
	}

	if !h.hasPermission(ctx, companyID, "teacher:manage_sections") {
		h.respondWithError(w, http.StatusForbidden, "insufficient permissions")
		return
	}

	err = h.teacherService.RemoveSection(ctx, teacherID, sectionID)
	if err != nil {
		h.logger.Error("Failed to remove section from teacher",
			zap.String("teacher_id", teacherID.String()),
			zap.String("section_id", sectionID.String()),
			zap.Error(err))
		h.respondWithError(w, http.StatusBadRequest, err.Error())
		return
	}

	h.respondWithJSON(w, http.StatusOK, map[string]interface{}{
		"success": true,
		"message": "Section removed from teacher",
	})
}

// GetSectionsByTeacher handles GET /api/v1/companies/{companyID}/teachers/{teacherID}/sections
func (h *TeacherHandler) GetSectionsByTeacher(w http.ResponseWriter, r *http.Request) {
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

	if !h.hasPermission(ctx, companyID, "teacher:read") {
		h.respondWithError(w, http.StatusForbidden, "insufficient permissions")
		return
	}

	sections, err := h.teacherService.GetSectionsByTeacher(ctx, teacherID)
	if err != nil {
		h.logger.Error("Failed to get sections for teacher",
			zap.String("teacher_id", teacherID.String()),
			zap.Error(err))
		h.respondWithError(w, http.StatusInternalServerError, "failed to retrieve sections")
		return
	}

	h.respondWithJSON(w, http.StatusOK, map[string]interface{}{
		"success": true,
		"data":    sections,
	})
}

// GetTeachersBySection handles GET /api/v1/companies/{companyID}/sections/{sectionID}/teachers
func (h *TeacherHandler) GetTeachersBySection(w http.ResponseWriter, r *http.Request) {
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

	if !h.hasPermission(ctx, companyID, "teacher:read") {
		h.respondWithError(w, http.StatusForbidden, "insufficient permissions")
		return
	}

	teachers, err := h.teacherService.GetTeachersBySection(ctx, sectionID)
	if err != nil {
		h.logger.Error("Failed to get teachers by section",
			zap.String("section_id", sectionID.String()),
			zap.Error(err))
		h.respondWithError(w, http.StatusInternalServerError, "failed to retrieve teachers")
		return
	}

	h.respondWithJSON(w, http.StatusOK, map[string]interface{}{
		"success": true,
		"data":    teachers,
	})
}

// UpdateClassTeacherStatusRequest is the body for updating class teacher status.
type UpdateClassTeacherStatusRequest struct {
	IsClassTeacher bool `json:"is_class_teacher"`
}

// UpdateClassTeacherStatus handles PATCH /api/v1/companies/{companyID}/teachers/{teacherID}/sections/{sectionID}
func (h *TeacherHandler) UpdateClassTeacherStatus(w http.ResponseWriter, r *http.Request) {
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
	sectionIDStr := chi.URLParam(r, "sectionID")
	sectionID, err := uuid.Parse(sectionIDStr)
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid section ID")
		return
	}

	if !h.hasPermission(ctx, companyID, "teacher:manage_sections") {
		h.respondWithError(w, http.StatusForbidden, "insufficient permissions")
		return
	}

	var req UpdateClassTeacherStatusRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid request body")
		return
	}

	err = h.teacherService.UpdateClassTeacherStatus(ctx, teacherID, sectionID, req.IsClassTeacher)
	if err != nil {
		h.logger.Error("Failed to update class teacher status",
			zap.String("teacher_id", teacherID.String()),
			zap.String("section_id", sectionID.String()),
			zap.Error(err))
		h.respondWithError(w, http.StatusBadRequest, err.Error())
		return
	}

	h.respondWithJSON(w, http.StatusOK, map[string]interface{}{
		"success": true,
		"message": "Class teacher status updated",
	})
}

// ---------------------- Schedule Preferences --------------------------------

// SetSchedulePreferenceRequest is the body for setting a schedule preference.
type SetSchedulePreferenceRequest struct {
	DayOfWeek          int        `json:"day_of_week"`
	PreferredStartTime *time.Time `json:"preferred_start_time,omitempty"`
	PreferredEndTime   *time.Time `json:"preferred_end_time,omitempty"`
}

// SetSchedulePreference handles POST /api/v1/companies/{companyID}/teachers/{teacherID}/preferences
func (h *TeacherHandler) SetSchedulePreference(w http.ResponseWriter, r *http.Request) {
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

	userID, err := getUserIDFromContext(ctx)
	if err != nil {
		h.respondWithError(w, http.StatusUnauthorized, "authentication required")
		return
	}

	if !h.hasPermission(ctx, companyID, "teacher:manage_preferences") {
		h.respondWithError(w, http.StatusForbidden, "insufficient permissions")
		return
	}

	var req SetSchedulePreferenceRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid request body")
		return
	}
	if req.DayOfWeek < 0 || req.DayOfWeek > 6 {
		h.respondWithError(w, http.StatusBadRequest, "day_of_week must be between 0 and 6")
		return
	}

	pref := &models.TeacherSchedulePreference{
		TeacherID:          teacherID,
		DayOfWeek:          req.DayOfWeek,
		PreferredStartTime: req.PreferredStartTime,
		PreferredEndTime:   req.PreferredEndTime,
		CreatedBy:          &userID,
	}

	err = h.teacherService.SetSchedulePreference(ctx, pref)
	if err != nil {
		h.logger.Error("Failed to set schedule preference",
			zap.String("teacher_id", teacherID.String()),
			zap.Error(err))
		h.respondWithError(w, http.StatusBadRequest, err.Error())
		return
	}

	h.respondWithJSON(w, http.StatusOK, map[string]interface{}{
		"success": true,
		"message": "Schedule preference set",
	})
}

// GetSchedulePreferences handles GET /api/v1/companies/{companyID}/teachers/{teacherID}/preferences
func (h *TeacherHandler) GetSchedulePreferences(w http.ResponseWriter, r *http.Request) {
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

	if !h.hasPermission(ctx, companyID, "teacher:read") {
		h.respondWithError(w, http.StatusForbidden, "insufficient permissions")
		return
	}

	prefs, err := h.teacherService.GetSchedulePreferences(ctx, teacherID)
	if err != nil {
		h.logger.Error("Failed to get schedule preferences",
			zap.String("teacher_id", teacherID.String()),
			zap.Error(err))
		h.respondWithError(w, http.StatusInternalServerError, "failed to retrieve preferences")
		return
	}

	h.respondWithJSON(w, http.StatusOK, map[string]interface{}{
		"success": true,
		"data":    prefs,
	})
}

// UpdateSchedulePreferenceRequest is the body for updating a schedule preference.
type UpdateSchedulePreferenceRequest struct {
	DayOfWeek          int        `json:"day_of_week"`
	PreferredStartTime *time.Time `json:"preferred_start_time,omitempty"`
	PreferredEndTime   *time.Time `json:"preferred_end_time,omitempty"`
}

// UpdateSchedulePreference handles PUT /api/v1/companies/{companyID}/teachers/preferences/{preferenceID}
func (h *TeacherHandler) UpdateSchedulePreference(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	companyIDStr := chi.URLParam(r, "companyID")
	companyID, err := uuid.Parse(companyIDStr)
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid company ID")
		return
	}

	preferenceIDStr := chi.URLParam(r, "preferenceID")
	preferenceID, err := uuid.Parse(preferenceIDStr)
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid preference ID")
		return
	}

	userID, err := getUserIDFromContext(ctx)
	if err != nil {
		h.respondWithError(w, http.StatusUnauthorized, "authentication required")
		return
	}

	if !h.hasPermission(ctx, companyID, "teacher:manage_preferences") {
		h.respondWithError(w, http.StatusForbidden, "insufficient permissions")
		return
	}

	var req UpdateSchedulePreferenceRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid request body")
		return
	}
	if req.DayOfWeek < 0 || req.DayOfWeek > 6 {
		h.respondWithError(w, http.StatusBadRequest, "day_of_week must be between 0 and 6")
		return
	}

	// We need teacher_id – require it in request body
	var updateReq struct {
		TeacherID          string     `json:"teacher_id"`
		DayOfWeek          int        `json:"day_of_week"`
		PreferredStartTime *time.Time `json:"preferred_start_time,omitempty"`
		PreferredEndTime   *time.Time `json:"preferred_end_time,omitempty"`
	}
	if err := json.NewDecoder(r.Body).Decode(&updateReq); err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid request body")
		return
	}
	teacherID, err := uuid.Parse(updateReq.TeacherID)
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid teacher_id")
		return
	}
	if updateReq.DayOfWeek < 0 || updateReq.DayOfWeek > 6 {
		h.respondWithError(w, http.StatusBadRequest, "day_of_week must be between 0 and 6")
		return
	}

	pref := &models.TeacherSchedulePreference{
		PreferenceID:       preferenceID,
		TeacherID:          teacherID,
		DayOfWeek:          updateReq.DayOfWeek,
		PreferredStartTime: updateReq.PreferredStartTime,
		PreferredEndTime:   updateReq.PreferredEndTime,
		CreatedBy:          &userID,
	}

	err = h.teacherService.UpdateSchedulePreference(ctx, pref)
	if err != nil {
		h.logger.Error("Failed to update schedule preference",
			zap.String("preference_id", preferenceID.String()),
			zap.Error(err))
		h.respondWithError(w, http.StatusBadRequest, err.Error())
		return
	}

	h.respondWithJSON(w, http.StatusOK, map[string]interface{}{
		"success": true,
		"message": "Schedule preference updated",
	})
}

// DeleteSchedulePreference handles DELETE /api/v1/companies/{companyID}/teachers/preferences/{preferenceID}
func (h *TeacherHandler) DeleteSchedulePreference(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	companyIDStr := chi.URLParam(r, "companyID")
	companyID, err := uuid.Parse(companyIDStr)
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid company ID")
		return
	}

	preferenceIDStr := chi.URLParam(r, "preferenceID")
	preferenceID, err := uuid.Parse(preferenceIDStr)
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid preference ID")
		return
	}

	if !h.hasPermission(ctx, companyID, "teacher:manage_preferences") {
		h.respondWithError(w, http.StatusForbidden, "insufficient permissions")
		return
	}

	err = h.teacherService.DeleteSchedulePreference(ctx, preferenceID)
	if err != nil {
		h.logger.Error("Failed to delete schedule preference",
			zap.String("preference_id", preferenceID.String()),
			zap.Error(err))
		h.respondWithError(w, http.StatusBadRequest, err.Error())
		return
	}

	h.respondWithJSON(w, http.StatusOK, map[string]interface{}{
		"success": true,
		"message": "Schedule preference deleted",
	})
}

// ClearSchedulePreferences handles DELETE /api/v1/companies/{companyID}/teachers/{teacherID}/preferences
func (h *TeacherHandler) ClearSchedulePreferences(w http.ResponseWriter, r *http.Request) {
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

	if !h.hasPermission(ctx, companyID, "teacher:manage_preferences") {
		h.respondWithError(w, http.StatusForbidden, "insufficient permissions")
		return
	}

	err = h.teacherService.ClearSchedulePreferences(ctx, teacherID)
	if err != nil {
		h.logger.Error("Failed to clear schedule preferences",
			zap.String("teacher_id", teacherID.String()),
			zap.Error(err))
		h.respondWithError(w, http.StatusBadRequest, err.Error())
		return
	}

	h.respondWithJSON(w, http.StatusOK, map[string]interface{}{
		"success": true,
		"message": "All schedule preferences cleared",
	})
}

// ---------------------- Helper Methods -------------------------------------

func (h *TeacherHandler) hasPermission(ctx context.Context, companyID uuid.UUID, permission string) bool {
	// Placeholder – implement actual permission check
	return true
}

func (h *TeacherHandler) respondWithJSON(w http.ResponseWriter, status int, data interface{}) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	if err := json.NewEncoder(w).Encode(data); err != nil {
		h.logger.Error("failed to encode JSON response", zap.Error(err))
	}
}

func (h *TeacherHandler) respondWithError(w http.ResponseWriter, status int, message string) {
	h.respondWithJSON(w, status, map[string]interface{}{
		"success": false,
		"error":   message,
	})
}

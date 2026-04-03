package handler

import (
	"context"
	"encoding/json"
	"net/http"
	"strconv"

	"auth-service/internal/academics/repository"
	"auth-service/internal/academics/service"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"
	"go.uber.org/zap"
)

type AssignmentHandler struct {
	assignmentService service.AssignmentService
	logger            *zap.Logger
}

func NewAssignmentHandler(assignmentService service.AssignmentService, logger *zap.Logger) *AssignmentHandler {
	return &AssignmentHandler{
		assignmentService: assignmentService,
		logger:            logger.Named("assignment_handler"),
	}
}

// Create handles POST /api/v1/companies/{companyID}/assignments
// Expects X-Idempotency-Key header (optional)
func (h *AssignmentHandler) Create(w http.ResponseWriter, r *http.Request) {
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

	if !h.hasPermission(ctx, companyID, "assignment:create") {
		h.respondWithError(w, http.StatusForbidden, "insufficient permissions")
		return
	}

	var req service.CreateAssignmentRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid request body")
		return
	}

	// Validate required fields
	if req.SectionID == uuid.Nil {
		h.respondWithError(w, http.StatusBadRequest, "section_id is required")
		return
	}
	if req.SubjectID == uuid.Nil {
		h.respondWithError(w, http.StatusBadRequest, "subject_id is required")
		return
	}
	if req.TeacherID == uuid.Nil {
		h.respondWithError(w, http.StatusBadRequest, "teacher_id is required")
		return
	}
	if req.Title == "" {
		h.respondWithError(w, http.StatusBadRequest, "title is required")
		return
	}
	if req.DueDate.IsZero() {
		h.respondWithError(w, http.StatusBadRequest, "due_date is required")
		return
	}

	// Set created/updated by
	req.CreatedBy = &userID
	req.UpdatedBy = &userID

	idempotencyKey := r.Header.Get("X-Idempotency-Key")

	assignment, err := h.assignmentService.Create(ctx, req, idempotencyKey)
	if err != nil {
		h.logger.Error("Failed to create assignment",
			zap.String("section_id", req.SectionID.String()),
			zap.String("subject_id", req.SubjectID.String()),
			zap.String("teacher_id", req.TeacherID.String()),
			zap.Error(err))
		h.respondWithError(w, http.StatusBadRequest, err.Error())
		return
	}

	h.respondWithJSON(w, http.StatusCreated, map[string]interface{}{
		"success": true,
		"data":    assignment,
		"message": "Assignment created successfully",
	})
}

// BulkCreate handles POST /api/v1/companies/{companyID}/assignments/bulk
func (h *AssignmentHandler) BulkCreate(w http.ResponseWriter, r *http.Request) {
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

	if !h.hasPermission(ctx, companyID, "assignment:bulk_create") {
		h.respondWithError(w, http.StatusForbidden, "insufficient permissions")
		return
	}

	var reqs []service.CreateAssignmentRequest
	if err := json.NewDecoder(r.Body).Decode(&reqs); err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid request body")
		return
	}

	if len(reqs) == 0 {
		h.respondWithError(w, http.StatusBadRequest, "empty batch")
		return
	}

	// Set created/updated by for each
	for i := range reqs {
		reqs[i].CreatedBy = &userID
		reqs[i].UpdatedBy = &userID
	}

	assignments, err := h.assignmentService.BulkCreate(ctx, reqs)
	if err != nil {
		h.logger.Error("Failed to bulk create assignments",
			zap.Int("batch_size", len(reqs)),
			zap.Error(err))
		h.respondWithError(w, http.StatusBadRequest, err.Error())
		return
	}

	h.respondWithJSON(w, http.StatusCreated, map[string]interface{}{
		"success": true,
		"data":    assignments,
		"message": "Assignments created successfully",
	})
}

// GetByID handles GET /api/v1/companies/{companyID}/assignments/{assignmentID}
func (h *AssignmentHandler) GetByID(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	companyIDStr := chi.URLParam(r, "companyID")
	companyID, err := uuid.Parse(companyIDStr)
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid company ID")
		return
	}

	assignmentIDStr := chi.URLParam(r, "assignmentID")
	assignmentID, err := uuid.Parse(assignmentIDStr)
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid assignment ID")
		return
	}

	if !h.hasPermission(ctx, companyID, "assignment:read") {
		h.respondWithError(w, http.StatusForbidden, "insufficient permissions")
		return
	}

	assignment, err := h.assignmentService.GetByID(ctx, assignmentID)
	if err != nil {
		h.logger.Error("Failed to get assignment",
			zap.String("assignment_id", assignmentID.String()),
			zap.Error(err))
		h.respondWithError(w, http.StatusNotFound, err.Error())
		return
	}

	h.respondWithJSON(w, http.StatusOK, map[string]interface{}{
		"success": true,
		"data":    assignment,
	})
}

// List handles GET /api/v1/companies/{companyID}/assignments
// Query params:
//
//	section_id, subject_id, teacher_id, is_published, search, due_from, due_to
//	limit, offset, sort_field, sort_direction
func (h *AssignmentHandler) List(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	companyIDStr := chi.URLParam(r, "companyID")
	companyID, err := uuid.Parse(companyIDStr)
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid company ID")
		return
	}

	if !h.hasPermission(ctx, companyID, "assignment:read") {
		h.respondWithError(w, http.StatusForbidden, "insufficient permissions")
		return
	}

	// Parse filter
	filter := repository.AssignmentFilter{}

	if sectionIDStr := r.URL.Query().Get("section_id"); sectionIDStr != "" {
		if sectionID, err := uuid.Parse(sectionIDStr); err == nil {
			filter.SectionID = &sectionID
		}
	}
	if subjectIDStr := r.URL.Query().Get("subject_id"); subjectIDStr != "" {
		if subjectID, err := uuid.Parse(subjectIDStr); err == nil {
			filter.SubjectID = &subjectID
		}
	}
	if teacherIDStr := r.URL.Query().Get("teacher_id"); teacherIDStr != "" {
		if teacherID, err := uuid.Parse(teacherIDStr); err == nil {
			filter.TeacherID = &teacherID
		}
	}
	if isPublishedStr := r.URL.Query().Get("is_published"); isPublishedStr != "" {
		if isPublished, err := strconv.ParseBool(isPublishedStr); err == nil {
			filter.IsPublished = &isPublished
		}
	}
	if search := r.URL.Query().Get("search"); search != "" {
		filter.Search = search
	}
	// Use DueDateFrom and DueDateTo (adjust field names as per your AssignmentFilter)
	if dueFromStr := r.URL.Query().Get("due_from"); dueFromStr != "" {
		if dueFrom, err := time.Parse(time.RFC3339, dueFromStr); err == nil {
			filter.DueDateFrom = &dueFrom
		}
	}
	if dueToStr := r.URL.Query().Get("due_to"); dueToStr != "" {
		if dueTo, err := time.Parse(time.RFC3339, dueToStr); err == nil {
			filter.DueDateTo = &dueTo
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
		sortField = "created_at"
	}
	sortDirection := r.URL.Query().Get("sort_direction")
	if sortDirection == "" {
		sortDirection = "DESC"
	}
	sort := repository.Sort{Field: sortField, Direction: sortDirection}

	assignments, err := h.assignmentService.List(ctx, filter, pagination, sort)
	if err != nil {
		h.logger.Error("Failed to list assignments",
			zap.Any("filter", filter),
			zap.Error(err))
		h.respondWithError(w, http.StatusInternalServerError, "failed to list assignments")
		return
	}

	count, err := h.assignmentService.Count(ctx, filter)
	if err != nil {
		h.logger.Error("Failed to count assignments", zap.Error(err))
		// Non-fatal, we can still return assignments without total
		count = 0
	}

	h.respondWithJSON(w, http.StatusOK, map[string]interface{}{
		"success": true,
		"data": map[string]interface{}{
			"assignments": assignments,
			"total":       count,
			"limit":       limit,
			"offset":      offset,
		},
	})
}

// Update handles PUT /api/v1/companies/{companyID}/assignments/{assignmentID}
func (h *AssignmentHandler) Update(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	companyIDStr := chi.URLParam(r, "companyID")
	companyID, err := uuid.Parse(companyIDStr)
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid company ID")
		return
	}

	assignmentIDStr := chi.URLParam(r, "assignmentID")
	assignmentID, err := uuid.Parse(assignmentIDStr)
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid assignment ID")
		return
	}

	userID, err := getUserIDFromContext(ctx)
	if err != nil {
		h.respondWithError(w, http.StatusUnauthorized, "authentication required")
		return
	}

	if !h.hasPermission(ctx, companyID, "assignment:update") {
		h.respondWithError(w, http.StatusForbidden, "insufficient permissions")
		return
	}

	var req service.UpdateAssignmentRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid request body")
		return
	}

	req.AssignmentID = assignmentID
	req.UpdatedBy = &userID

	assignment, err := h.assignmentService.Update(ctx, req)
	if err != nil {
		h.logger.Error("Failed to update assignment",
			zap.String("assignment_id", assignmentID.String()),
			zap.Error(err))
		h.respondWithError(w, http.StatusBadRequest, err.Error())
		return
	}

	h.respondWithJSON(w, http.StatusOK, map[string]interface{}{
		"success": true,
		"data":    assignment,
		"message": "Assignment updated successfully",
	})
}

// Delete handles DELETE /api/v1/companies/{companyID}/assignments/{assignmentID}
func (h *AssignmentHandler) Delete(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	companyIDStr := chi.URLParam(r, "companyID")
	companyID, err := uuid.Parse(companyIDStr)
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid company ID")
		return
	}

	assignmentIDStr := chi.URLParam(r, "assignmentID")
	assignmentID, err := uuid.Parse(assignmentIDStr)
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid assignment ID")
		return
	}

	userID, err := getUserIDFromContext(ctx)
	if err != nil {
		h.respondWithError(w, http.StatusUnauthorized, "authentication required")
		return
	}

	if !h.hasPermission(ctx, companyID, "assignment:delete") {
		h.respondWithError(w, http.StatusForbidden, "insufficient permissions")
		return
	}

	err = h.assignmentService.Delete(ctx, assignmentID, &userID)
	if err != nil {
		h.logger.Error("Failed to delete assignment",
			zap.String("assignment_id", assignmentID.String()),
			zap.Error(err))
		h.respondWithError(w, http.StatusBadRequest, err.Error())
		return
	}

	h.respondWithJSON(w, http.StatusOK, map[string]interface{}{
		"success": true,
		"message": "Assignment deleted successfully",
	})
}

// Publish handles PATCH /api/v1/companies/{companyID}/assignments/{assignmentID}/publish
// Request body: { "published": true/false }
func (h *AssignmentHandler) Publish(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	companyIDStr := chi.URLParam(r, "companyID")
	companyID, err := uuid.Parse(companyIDStr)
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid company ID")
		return
	}

	assignmentIDStr := chi.URLParam(r, "assignmentID")
	assignmentID, err := uuid.Parse(assignmentIDStr)
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid assignment ID")
		return
	}

	userID, err := getUserIDFromContext(ctx)
	if err != nil {
		h.respondWithError(w, http.StatusUnauthorized, "authentication required")
		return
	}

	if !h.hasPermission(ctx, companyID, "assignment:publish") {
		h.respondWithError(w, http.StatusForbidden, "insufficient permissions")
		return
	}

	var req struct {
		Published bool `json:"published"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid request body")
		return
	}

	err = h.assignmentService.Publish(ctx, assignmentID, req.Published, &userID)
	if err != nil {
		h.logger.Error("Failed to publish/unpublish assignment",
			zap.String("assignment_id", assignmentID.String()),
			zap.Bool("published", req.Published),
			zap.Error(err))
		h.respondWithError(w, http.StatusBadRequest, err.Error())
		return
	}

	message := "Assignment published successfully"
	if !req.Published {
		message = "Assignment unpublished successfully"
	}

	h.respondWithJSON(w, http.StatusOK, map[string]interface{}{
		"success": true,
		"message": message,
	})
}

// Helper methods

func (h *AssignmentHandler) hasPermission(ctx context.Context, companyID uuid.UUID, permission string) bool {
	// TODO: Implement actual permission check
	return true
}

func (h *AssignmentHandler) respondWithJSON(w http.ResponseWriter, status int, data interface{}) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	json.NewEncoder(w).Encode(data)
}

func (h *AssignmentHandler) respondWithError(w http.ResponseWriter, status int, message string) {
	h.respondWithJSON(w, status, map[string]interface{}{
		"success": false,
		"error":   message,
	})
}

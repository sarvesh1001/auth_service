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

type SubmissionHandler struct {
	submissionService service.SubmissionService
	logger            *zap.Logger
}

func NewSubmissionHandler(submissionService service.SubmissionService, logger *zap.Logger) *SubmissionHandler {
	return &SubmissionHandler{
		submissionService: submissionService,
		logger:            logger.Named("submission_handler"),
	}
}

// CreateSubmission – POST /api/v1/companies/{companyID}/assignments/{assignmentID}/submissions
func (h *SubmissionHandler) CreateSubmission(w http.ResponseWriter, r *http.Request) {
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

	_, err = getUserIDFromContext(ctx)
	if err != nil {
		h.respondWithError(w, http.StatusUnauthorized, "authentication required")
		return
	}

	if !h.hasPermission(ctx, companyID, "submission:create") {
		h.respondWithError(w, http.StatusForbidden, "insufficient permissions")
		return
	}

	var req service.CreateSubmissionRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid request body")
		return
	}

	req.AssignmentID = assignmentID
	if req.StudentID == uuid.Nil {
		h.respondWithError(w, http.StatusBadRequest, "student_id is required")
		return
	}
	// ❌ Removed: req.CreatedBy = &userID (no longer exists)

	// Read idempotency key from context (set by middleware)
	idempotencyKey, _ := ctx.Value("idempotency_key").(string)

	submission, err := h.submissionService.CreateSubmission(ctx, req, idempotencyKey)
	if err != nil {
		h.logger.Error("Failed to create submission",
			zap.String("assignment_id", assignmentID.String()),
			zap.String("student_id", req.StudentID.String()),
			zap.Error(err))
		h.respondWithError(w, http.StatusBadRequest, err.Error())
		return
	}

	h.respondWithJSON(w, http.StatusCreated, map[string]interface{}{
		"success": true,
		"data":    submission,
		"message": "Submission created successfully",
	})
}

// GetSubmissionByID – GET /api/v1/companies/{companyID}/submissions/{submissionID}
func (h *SubmissionHandler) GetSubmissionByID(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	companyIDStr := chi.URLParam(r, "companyID")
	companyID, err := uuid.Parse(companyIDStr)
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid company ID")
		return
	}

	submissionIDStr := chi.URLParam(r, "submissionID")
	submissionID, err := uuid.Parse(submissionIDStr)
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid submission ID")
		return
	}

	if !h.hasPermission(ctx, companyID, "submission:read") {
		h.respondWithError(w, http.StatusForbidden, "insufficient permissions")
		return
	}

	submission, err := h.submissionService.GetSubmissionByID(ctx, submissionID)
	if err != nil {
		h.logger.Error("Failed to get submission",
			zap.String("submission_id", submissionID.String()),
			zap.Error(err))
		h.respondWithError(w, http.StatusNotFound, err.Error())
		return
	}

	h.respondWithJSON(w, http.StatusOK, map[string]interface{}{
		"success": true,
		"data":    submission,
	})
}

// GetSubmissionByAssignmentAndStudent – GET /api/v1/companies/{companyID}/students/{studentID}/assignments/{assignmentID}/submission
func (h *SubmissionHandler) GetSubmissionByAssignmentAndStudent(w http.ResponseWriter, r *http.Request) {
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

	assignmentIDStr := chi.URLParam(r, "assignmentID")
	assignmentID, err := uuid.Parse(assignmentIDStr)
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid assignment ID")
		return
	}

	if !h.hasPermission(ctx, companyID, "submission:read") {
		h.respondWithError(w, http.StatusForbidden, "insufficient permissions")
		return
	}

	submission, err := h.submissionService.GetSubmissionByAssignmentAndStudent(ctx, assignmentID, studentID)
	if err != nil {
		h.logger.Error("Failed to get submission by assignment and student",
			zap.String("assignment_id", assignmentID.String()),
			zap.String("student_id", studentID.String()),
			zap.Error(err))
		h.respondWithError(w, http.StatusNotFound, err.Error())
		return
	}

	h.respondWithJSON(w, http.StatusOK, map[string]interface{}{
		"success": true,
		"data":    submission,
	})
}

// ListSubmissions – GET /api/v1/companies/{companyID}/submissions
func (h *SubmissionHandler) ListSubmissions(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	companyIDStr := chi.URLParam(r, "companyID")
	companyID, err := uuid.Parse(companyIDStr)
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid company ID")
		return
	}

	if !h.hasPermission(ctx, companyID, "submission:read") {
		h.respondWithError(w, http.StatusForbidden, "insufficient permissions")
		return
	}

	filter := repository.SubmissionFilter{}
	if assignmentIDStr := r.URL.Query().Get("assignment_id"); assignmentIDStr != "" {
		if aid, err := uuid.Parse(assignmentIDStr); err == nil {
			filter.AssignmentID = &aid
		}
	}
	if studentIDStr := r.URL.Query().Get("student_id"); studentIDStr != "" {
		if sid, err := uuid.Parse(studentIDStr); err == nil {
			filter.StudentID = &sid
		}
	}
	if status := r.URL.Query().Get("status"); status != "" {
		filter.Status = &status
	}
	if graded := r.URL.Query().Get("graded"); graded != "" {
		b, _ := strconv.ParseBool(graded)
		filter.Graded = &b
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

	sortField := r.URL.Query().Get("sort_field")
	if sortField == "" {
		sortField = "submission_date"
	}
	sortDirection := r.URL.Query().Get("sort_direction")
	if sortDirection == "" {
		sortDirection = "DESC"
	}
	sort := repository.Sort{Field: sortField, Direction: sortDirection}

	submissions, err := h.submissionService.ListSubmissions(ctx, filter, pagination, sort)
	if err != nil {
		h.logger.Error("Failed to list submissions",
			zap.Any("filter", filter),
			zap.Error(err))
		h.respondWithError(w, http.StatusInternalServerError, "failed to list submissions")
		return
	}

	count, err := h.submissionService.CountSubmissions(ctx, filter)
	if err != nil {
		h.logger.Error("Failed to count submissions", zap.Error(err))
	}

	h.respondWithJSON(w, http.StatusOK, map[string]interface{}{
		"success": true,
		"data": map[string]interface{}{
			"submissions": submissions,
			"total":       count,
			"limit":       limit,
			"offset":      offset,
		},
	})
}

// UpdateSubmission – PUT /api/v1/companies/{companyID}/submissions/{submissionID}
func (h *SubmissionHandler) UpdateSubmission(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	companyIDStr := chi.URLParam(r, "companyID")
	companyID, err := uuid.Parse(companyIDStr)
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid company ID")
		return
	}

	submissionIDStr := chi.URLParam(r, "submissionID")
	submissionID, err := uuid.Parse(submissionIDStr)
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid submission ID")
		return
	}

	_, err = getUserIDFromContext(ctx)
	if err != nil {
		h.respondWithError(w, http.StatusUnauthorized, "authentication required")
		return
	}

	if !h.hasPermission(ctx, companyID, "submission:update") {
		h.respondWithError(w, http.StatusForbidden, "insufficient permissions")
		return
	}

	var req service.UpdateSubmissionRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid request body")
		return
	}
	req.SubmissionID = submissionID
	// ❌ Removed: req.UpdatedBy = &userID (no longer exists)

	submission, err := h.submissionService.UpdateSubmission(ctx, req)
	if err != nil {
		h.logger.Error("Failed to update submission",
			zap.String("submission_id", submissionID.String()),
			zap.Error(err))
		h.respondWithError(w, http.StatusBadRequest, err.Error())
		return
	}

	h.respondWithJSON(w, http.StatusOK, map[string]interface{}{
		"success": true,
		"data":    submission,
		"message": "Submission updated successfully",
	})
}

// DeleteSubmission – DELETE /api/v1/companies/{companyID}/submissions/{submissionID}
func (h *SubmissionHandler) DeleteSubmission(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	companyIDStr := chi.URLParam(r, "companyID")
	companyID, err := uuid.Parse(companyIDStr)
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid company ID")
		return
	}

	submissionIDStr := chi.URLParam(r, "submissionID")
	submissionID, err := uuid.Parse(submissionIDStr)
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid submission ID")
		return
	}

	if !h.hasPermission(ctx, companyID, "submission:delete") {
		h.respondWithError(w, http.StatusForbidden, "insufficient permissions")
		return
	}

	userID, _ := getUserIDFromContext(ctx)
	err = h.submissionService.DeleteSubmission(ctx, submissionID, &userID)
	if err != nil {
		h.logger.Error("Failed to delete submission",
			zap.String("submission_id", submissionID.String()),
			zap.Error(err))
		h.respondWithError(w, http.StatusBadRequest, err.Error())
		return
	}

	h.respondWithJSON(w, http.StatusOK, map[string]interface{}{
		"success": true,
		"message": "Submission deleted successfully",
	})
}

// GradeSubmission – POST /api/v1/companies/{companyID}/submissions/{submissionID}/grade
func (h *SubmissionHandler) GradeSubmission(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	companyIDStr := chi.URLParam(r, "companyID")
	companyID, err := uuid.Parse(companyIDStr)
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid company ID")
		return
	}

	submissionIDStr := chi.URLParam(r, "submissionID")
	submissionID, err := uuid.Parse(submissionIDStr)
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid submission ID")
		return
	}

	userID, err := getUserIDFromContext(ctx)
	if err != nil {
		h.respondWithError(w, http.StatusUnauthorized, "authentication required")
		return
	}

	if !h.hasPermission(ctx, companyID, "submission:grade") {
		h.respondWithError(w, http.StatusForbidden, "insufficient permissions")
		return
	}

	var req service.GradeSubmissionRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid request body")
		return
	}
	req.SubmissionID = submissionID
	req.GradedBy = userID
	// ❌ Removed: req.CreatedBy = &userID (no longer exists)

	grade, err := h.submissionService.GradeSubmission(ctx, req)
	if err != nil {
		h.logger.Error("Failed to grade submission",
			zap.String("submission_id", submissionID.String()),
			zap.Error(err))
		h.respondWithError(w, http.StatusBadRequest, err.Error())
		return
	}

	h.respondWithJSON(w, http.StatusOK, map[string]interface{}{
		"success": true,
		"data":    grade,
		"message": "Submission graded successfully",
	})
}

// AddComment – POST /api/v1/companies/{companyID}/submissions/{submissionID}/comments
func (h *SubmissionHandler) AddComment(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	companyIDStr := chi.URLParam(r, "companyID")
	companyID, err := uuid.Parse(companyIDStr)
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid company ID")
		return
	}

	submissionIDStr := chi.URLParam(r, "submissionID")
	submissionID, err := uuid.Parse(submissionIDStr)
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid submission ID")
		return
	}

	userID, err := getUserIDFromContext(ctx)
	if err != nil {
		h.respondWithError(w, http.StatusUnauthorized, "authentication required")
		return
	}

	if !h.hasPermission(ctx, companyID, "submission:comment") {
		h.respondWithError(w, http.StatusForbidden, "insufficient permissions")
		return
	}

	var req service.AddCommentRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid request body")
		return
	}
	req.SubmissionID = submissionID
	req.CommentBy = userID
	// ❌ Removed: req.CreatedBy = &userID (no longer exists)

	comment, err := h.submissionService.AddComment(ctx, req)
	if err != nil {
		h.logger.Error("Failed to add comment",
			zap.String("submission_id", submissionID.String()),
			zap.Error(err))
		h.respondWithError(w, http.StatusBadRequest, err.Error())
		return
	}

	h.respondWithJSON(w, http.StatusCreated, map[string]interface{}{
		"success": true,
		"data":    comment,
		"message": "Comment added successfully",
	})
}

// GetCommentsBySubmission – GET /api/v1/companies/{companyID}/submissions/{submissionID}/comments
func (h *SubmissionHandler) GetCommentsBySubmission(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	companyIDStr := chi.URLParam(r, "companyID")
	companyID, err := uuid.Parse(companyIDStr)
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid company ID")
		return
	}

	submissionIDStr := chi.URLParam(r, "submissionID")
	submissionID, err := uuid.Parse(submissionIDStr)
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid submission ID")
		return
	}

	if !h.hasPermission(ctx, companyID, "submission:read") {
		h.respondWithError(w, http.StatusForbidden, "insufficient permissions")
		return
	}

	comments, err := h.submissionService.GetCommentsBySubmission(ctx, submissionID)
	if err != nil {
		h.logger.Error("Failed to get comments",
			zap.String("submission_id", submissionID.String()),
			zap.Error(err))
		h.respondWithError(w, http.StatusInternalServerError, "failed to retrieve comments")
		return
	}

	h.respondWithJSON(w, http.StatusOK, map[string]interface{}{
		"success": true,
		"data":    comments,
	})
}

// Helper methods
func (h *SubmissionHandler) hasPermission(ctx context.Context, companyID uuid.UUID, permission string) bool {
	// TODO: implement proper permission check
	return true
}

func (h *SubmissionHandler) respondWithJSON(w http.ResponseWriter, status int, data interface{}) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	if err := json.NewEncoder(w).Encode(data); err != nil {
		h.logger.Error("failed to encode JSON response", zap.Error(err))
	}
}

func (h *SubmissionHandler) respondWithError(w http.ResponseWriter, status int, message string) {
	h.respondWithJSON(w, status, map[string]interface{}{
		"success": false,
		"error":   message,
	})
}

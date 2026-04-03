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
	"auth-service/internal/academics/service"
)

// CurriculumHandler handles HTTP requests for curriculum operations
type CurriculumHandler struct {
	curriculumService service.CurriculumService
	logger            *zap.Logger
}

// NewCurriculumHandler creates a new CurriculumHandler
func NewCurriculumHandler(curriculumService service.CurriculumService, logger *zap.Logger) *CurriculumHandler {
	return &CurriculumHandler{
		curriculumService: curriculumService,
		logger:            logger.Named("curriculum_handler"),
	}
}

// assignSubjectRequest is used to parse the request body for assigning a subject
type assignSubjectRequest struct {
	SubjectID    uuid.UUID `json:"subject_id"`
	TermNumber   int       `json:"term_number"`
	IsCompulsory bool      `json:"is_compulsory"`
}

// AssignSubject handles POST /api/v1/companies/{companyID}/courses/{courseID}/subjects
func (h *CurriculumHandler) AssignSubject(w http.ResponseWriter, r *http.Request) {
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

	// TODO: Use userID if needed for audit/notifications
	// userID, err := getUserIDFromContext(ctx)
	// if err != nil { ... }

	if !h.hasPermission(ctx, companyID, "curriculum:assign") {
		h.respondWithError(w, http.StatusForbidden, "insufficient permissions")
		return
	}

	var req assignSubjectRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid request body")
		return
	}

	if req.SubjectID == uuid.Nil {
		h.respondWithError(w, http.StatusBadRequest, "subject_id is required")
		return
	}
	if req.TermNumber <= 0 {
		h.respondWithError(w, http.StatusBadRequest, "term_number must be positive")
		return
	}

	assignReq := service.AssignSubjectRequest{
		CourseID:     courseID,
		SubjectID:    req.SubjectID,
		TermNumber:   req.TermNumber,
		IsCompulsory: req.IsCompulsory,
	}

	err = h.curriculumService.AssignSubjectToCourse(ctx, assignReq)
	if err != nil {
		h.logger.Error("Failed to assign subject to course",
			zap.String("course_id", courseID.String()),
			zap.String("subject_id", req.SubjectID.String()),
			zap.Int("term", req.TermNumber),
			zap.Error(err))
		h.respondWithError(w, http.StatusBadRequest, err.Error())
		return
	}

	h.respondWithJSON(w, http.StatusCreated, map[string]interface{}{
		"success": true,
		"message": "Subject assigned to course successfully",
	})
}

// BulkAssignSubjects handles POST /api/v1/companies/{companyID}/courses/subjects/bulk
func (h *CurriculumHandler) BulkAssignSubjects(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	companyIDStr := chi.URLParam(r, "companyID")
	companyID, err := uuid.Parse(companyIDStr)
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid company ID")
		return
	}

	// TODO: Use userID if needed for audit/notifications
	// userID, err := getUserIDFromContext(ctx)
	// if err != nil { ... }

	if !h.hasPermission(ctx, companyID, "curriculum:bulk_assign") {
		h.respondWithError(w, http.StatusForbidden, "insufficient permissions")
		return
	}

	var reqs []service.AssignSubjectRequest
	if err := json.NewDecoder(r.Body).Decode(&reqs); err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid request body")
		return
	}

	if len(reqs) == 0 {
		h.respondWithError(w, http.StatusBadRequest, "empty batch")
		return
	}

	err = h.curriculumService.BulkAssignSubjects(ctx, reqs)
	if err != nil {
		h.logger.Error("Failed to bulk assign subjects",
			zap.Int("batch_size", len(reqs)),
			zap.Error(err))
		h.respondWithError(w, http.StatusBadRequest, err.Error())
		return
	}

	h.respondWithJSON(w, http.StatusCreated, map[string]interface{}{
		"success": true,
		"message": "Subjects assigned successfully",
	})
}

// GetSubjectsByCourse handles GET /api/v1/companies/{companyID}/courses/{courseID}/subjects
// Optional query param: term_number
func (h *CurriculumHandler) GetSubjectsByCourse(w http.ResponseWriter, r *http.Request) {
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

	if !h.hasPermission(ctx, companyID, "curriculum:read") {
		h.respondWithError(w, http.StatusForbidden, "insufficient permissions")
		return
	}

	termNumberStr := r.URL.Query().Get("term_number")
	var mappings []*models.SubjectCourseMapping
	if termNumberStr != "" {
		termNumber, err := strconv.Atoi(termNumberStr)
		if err != nil {
			h.respondWithError(w, http.StatusBadRequest, "invalid term_number")
			return
		}
		mappings, err = h.curriculumService.GetSubjectsByCourseAndTerm(ctx, courseID, termNumber)
		if err != nil {
			h.logger.Error("Failed to get subjects by course and term",
				zap.String("course_id", courseID.String()),
				zap.Int("term", termNumber),
				zap.Error(err))
			h.respondWithError(w, http.StatusInternalServerError, "failed to retrieve subjects")
			return
		}
	} else {
		mappings, err = h.curriculumService.GetSubjectsByCourse(ctx, courseID)
		if err != nil {
			h.logger.Error("Failed to get subjects by course",
				zap.String("course_id", courseID.String()),
				zap.Error(err))
			h.respondWithError(w, http.StatusInternalServerError, "failed to retrieve subjects")
			return
		}
	}

	h.respondWithJSON(w, http.StatusOK, map[string]interface{}{
		"success": true,
		"data":    mappings,
	})
}

// GetCoursesBySubject handles GET /api/v1/companies/{companyID}/subjects/{subjectID}/courses
func (h *CurriculumHandler) GetCoursesBySubject(w http.ResponseWriter, r *http.Request) {
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

	if !h.hasPermission(ctx, companyID, "curriculum:read") {
		h.respondWithError(w, http.StatusForbidden, "insufficient permissions")
		return
	}

	mappings, err := h.curriculumService.GetCoursesBySubject(ctx, subjectID)
	if err != nil {
		h.logger.Error("Failed to get courses by subject",
			zap.String("subject_id", subjectID.String()),
			zap.Error(err))
		h.respondWithError(w, http.StatusInternalServerError, "failed to retrieve courses")
		return
	}

	h.respondWithJSON(w, http.StatusOK, map[string]interface{}{
		"success": true,
		"data":    mappings,
	})
}

// RemoveMapping handles DELETE /api/v1/companies/{companyID}/curriculum/mappings/{mappingID}
func (h *CurriculumHandler) RemoveMapping(w http.ResponseWriter, r *http.Request) {
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

	if !h.hasPermission(ctx, companyID, "curriculum:remove") {
		h.respondWithError(w, http.StatusForbidden, "insufficient permissions")
		return
	}

	err = h.curriculumService.RemoveMapping(ctx, mappingID)
	if err != nil {
		h.logger.Error("Failed to remove mapping",
			zap.String("mapping_id", mappingID.String()),
			zap.Error(err))
		h.respondWithError(w, http.StatusBadRequest, err.Error())
		return
	}

	h.respondWithJSON(w, http.StatusOK, map[string]interface{}{
		"success": true,
		"message": "Mapping removed successfully",
	})
}

// RemoveAllForCourse handles DELETE /api/v1/companies/{companyID}/courses/{courseID}/curriculum
func (h *CurriculumHandler) RemoveAllForCourse(w http.ResponseWriter, r *http.Request) {
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

	if !h.hasPermission(ctx, companyID, "curriculum:remove_all") {
		h.respondWithError(w, http.StatusForbidden, "insufficient permissions")
		return
	}

	err = h.curriculumService.RemoveAllForCourse(ctx, courseID)
	if err != nil {
		h.logger.Error("Failed to remove all mappings for course",
			zap.String("course_id", courseID.String()),
			zap.Error(err))
		h.respondWithError(w, http.StatusBadRequest, err.Error())
		return
	}

	h.respondWithJSON(w, http.StatusOK, map[string]interface{}{
		"success": true,
		"message": "All mappings removed for course",
	})
}

// Exists handles GET /api/v1/companies/{companyID}/courses/{courseID}/curriculum/exists
// Query params: subject_id, term_number
func (h *CurriculumHandler) Exists(w http.ResponseWriter, r *http.Request) {
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

	subjectIDStr := r.URL.Query().Get("subject_id")
	if subjectIDStr == "" {
		h.respondWithError(w, http.StatusBadRequest, "subject_id is required")
		return
	}
	subjectID, err := uuid.Parse(subjectIDStr)
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid subject_id")
		return
	}

	termNumberStr := r.URL.Query().Get("term_number")
	if termNumberStr == "" {
		h.respondWithError(w, http.StatusBadRequest, "term_number is required")
		return
	}
	termNumber, err := strconv.Atoi(termNumberStr)
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, "invalid term_number")
		return
	}

	if !h.hasPermission(ctx, companyID, "curriculum:read") {
		h.respondWithError(w, http.StatusForbidden, "insufficient permissions")
		return
	}

	exists, err := h.curriculumService.Exists(ctx, courseID, subjectID, termNumber)
	if err != nil {
		h.logger.Error("Failed to check mapping existence",
			zap.String("course_id", courseID.String()),
			zap.String("subject_id", subjectID.String()),
			zap.Int("term", termNumber),
			zap.Error(err))
		h.respondWithError(w, http.StatusInternalServerError, "failed to check existence")
		return
	}

	h.respondWithJSON(w, http.StatusOK, map[string]interface{}{
		"success": true,
		"data":    exists,
	})
}

// ValidateCurriculum handles POST /api/v1/companies/{companyID}/courses/{courseID}/curriculum/validate
func (h *CurriculumHandler) ValidateCurriculum(w http.ResponseWriter, r *http.Request) {
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

	if !h.hasPermission(ctx, companyID, "curriculum:validate") {
		h.respondWithError(w, http.StatusForbidden, "insufficient permissions")
		return
	}

	err = h.curriculumService.ValidateCurriculum(ctx, courseID)
	if err != nil {
		h.logger.Error("Curriculum validation failed",
			zap.String("course_id", courseID.String()),
			zap.Error(err))
		h.respondWithError(w, http.StatusBadRequest, err.Error())
		return
	}

	h.respondWithJSON(w, http.StatusOK, map[string]interface{}{
		"success": true,
		"message": "Curriculum validation passed",
	})
}

// Helper methods (same as AdmissionHandler)
func (h *CurriculumHandler) hasPermission(ctx context.Context, companyID uuid.UUID, permission string) bool {
	// Placeholder – implement actual permission check
	return true
}

func (h *CurriculumHandler) respondWithJSON(w http.ResponseWriter, status int, data interface{}) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	json.NewEncoder(w).Encode(data)
}

func (h *CurriculumHandler) respondWithError(w http.ResponseWriter, status int, message string) {
	h.respondWithJSON(w, status, map[string]interface{}{
		"success": false,
		"error":   message,
	})
}

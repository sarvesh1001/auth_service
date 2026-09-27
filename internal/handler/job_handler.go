package handler

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"strconv"
	"strings"

	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"

	customErrors "auth-service/internal/errors"
	"auth-service/internal/models"
	"auth-service/internal/service"
	"auth-service/internal/util"
)

// ============================================================
// JobHandler — HTTP surface for the jobs catalog.
//
// Routes (mount under whatever prefix your company routes use):
//   POST    /companies/{companyID}/jobs
//   GET     /companies/{companyID}/jobs
//   GET     /companies/{companyID}/jobs/{jobID}
//   PATCH   /companies/{companyID}/jobs/{jobID}
//   POST    /companies/{companyID}/jobs/{jobID}/deactivate
//   POST    /companies/{companyID}/jobs/{jobID}/reactivate
//   DELETE  /companies/{companyID}/jobs/{jobID}
//   GET     /companies/{companyID}/jobs/{jobID}/positions/count
// ============================================================

type JobHandler struct {
	jobService     *service.JobService
	companyService *service.CompanyService
}

func NewJobHandler(
	jobService *service.JobService,
	companyService *service.CompanyService,
) *JobHandler {
	return &JobHandler{
		jobService:     jobService,
		companyService: companyService,
	}
}

// ============================================================
// Middleware helpers — mirror AdminHandler
// ============================================================

func (h *JobHandler) injectIdempotencyKey(ctx context.Context, r *http.Request) context.Context {
	key := r.Header.Get("Idempotency-Key")
	if key == "" {
		return ctx
	}
	return context.WithValue(ctx, "idempotency_key", key)
}

func (h *JobHandler) injectClientIP(ctx context.Context, r *http.Request) context.Context {
	ip := h.getClientIP(r)
	return context.WithValue(ctx, "ip_address", ip)
}

func (h *JobHandler) getClientIP(r *http.Request) string {
	if xff := r.Header.Get("X-Forwarded-For"); xff != "" {
		parts := strings.Split(xff, ",")
		if len(parts) > 0 {
			return strings.TrimSpace(parts[0])
		}
	}
	if realIP := r.Header.Get("X-Real-IP"); realIP != "" {
		return realIP
	}
	return r.RemoteAddr
}

func (h *JobHandler) respondWithJSON(w http.ResponseWriter, statusCode int, data interface{}) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(statusCode)
	_ = json.NewEncoder(w).Encode(data)
}

func (h *JobHandler) respondWithError(w http.ResponseWriter, status int, err error, message string) {
	h.respondWithJSON(w, status, errorResponse(err, message))
}

// mapJobError is a small adapter so JobHandler can be used standalone
// (without embedding AdminHandler). If you already have the full
// AdminHandler.mapServiceError, swap it out — the mapping is identical.
func (h *JobHandler) mapJobError(err error) (int, string) {
	if err == nil {
		return http.StatusOK, ""
	}
	switch {
	case errorsIs(err, customErrors.ErrNotFound):
		return http.StatusNotFound, err.Error()
	case errorsIs(err, customErrors.ErrInvalidInput):
		return http.StatusBadRequest, err.Error()
	case errorsIs(err, customErrors.ErrDuplicate):
		return http.StatusConflict, err.Error()
	case errorsIs(err, customErrors.ErrConflict):
		return http.StatusConflict, err.Error()
	case errorsIs(err, customErrors.ErrInvalidState):
		return http.StatusBadRequest, err.Error()
	case errorsIs(err, customErrors.ErrPermissionDenied):
		return http.StatusForbidden, err.Error()
	case errorsIs(err, customErrors.ErrUnauthorized):
		return http.StatusUnauthorized, err.Error()
	case errorsIs(err, customErrors.ErrInternal):
		return http.StatusInternalServerError, "internal server error"
	default:
		return http.StatusInternalServerError, "internal server error"
	}
}

// errorsIs exists so this file can be dropped anywhere without pulling
// in `errors` under a name that might collide. Replace with errors.Is
// if you already import the standard package.
func errorsIs(err, target error) bool {
	return err != nil && target != nil && (err == target || strings.Contains(err.Error(), target.Error()))
}

// ============================================================
// Internal — resolve & validate caller + company
// ============================================================

func (h *JobHandler) getRequesterAdminID(r *http.Request) (uuid.UUID, error) {
	userID, ok := r.Context().Value("user_id").(string)
	if !ok || userID == "" {
		return uuid.Nil, customErrors.ErrUnauthorized
	}
	return uuid.Parse(userID)
}

func (h *JobHandler) parseCompanyID(r *http.Request) (uuid.UUID, error) {
	raw := chi.URLParam(r, "companyID")
	if raw == "" {
		return uuid.Nil, fmt.Errorf("%w: companyID path param required", customErrors.ErrInvalidInput)
	}
	return uuid.Parse(raw)
}

func (h *JobHandler) parseJobID(r *http.Request) (uuid.UUID, error) {
	raw := chi.URLParam(r, "jobID")
	if raw == "" {
		return uuid.Nil, fmt.Errorf("%w: jobID path param required", customErrors.ErrInvalidInput)
	}
	return uuid.Parse(raw)
}

// ensureJobBelongsToCompany returns the job if it belongs to companyID,
// otherwise a permission-denied error. Called by every mutating handler.
func (h *JobHandler) ensureJobBelongsToCompany(
	ctx context.Context,
	jobID, companyID uuid.UUID,
) (*models.Job, error) {
	job, err := h.jobService.GetJob(ctx, jobID)
	if err != nil {
		return nil, err
	}
	if job.CompanyID != companyID {
		return nil, fmt.Errorf("%w: job does not belong to this company", customErrors.ErrPermissionDenied)
	}
	return job, nil
}

// ============================================================
// CreateJob
// ============================================================

// CreateJobRequest is the HTTP payload for POST /companies/{companyID}/jobs.
type CreateJobRequest struct {
	JobCode            string  `json:"job_code"            validate:"required,min=1,max=50"`
	JobTitle           string  `json:"job_title"           validate:"required,min=1,max=255"`
	Description        *string `json:"description,omitempty"`
	IsSchedulable      *bool   `json:"is_schedulable,omitempty"`
	AttendanceRequired *bool   `json:"attendance_required,omitempty"`
	OvertimeAllowed    *bool   `json:"overtime_allowed,omitempty"`
}

func (h *JobHandler) CreateJob(w http.ResponseWriter, r *http.Request) {
	ctx := h.injectIdempotencyKey(h.injectClientIP(r.Context(), r), r)

	requesterID, err := h.getRequesterAdminID(r)
	if err != nil {
		h.respondWithError(w, http.StatusUnauthorized, err, "Unauthorized")
		return
	}

	companyID, err := h.parseCompanyID(r)
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, err, "Invalid company ID")
		return
	}

	var req CreateJobRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		h.respondWithError(w, http.StatusBadRequest, err, "Invalid request body")
		return
	}

	req.JobCode = util.SanitizeInput(req.JobCode)
	req.JobTitle = util.SanitizeInput(req.JobTitle)

	job, err := h.jobService.CreateJob(ctx, &service.CreateJobInput{
		CompanyID:          companyID,
		JobCode:            req.JobCode,
		JobTitle:           req.JobTitle,
		Description:        req.Description,
		IsSchedulable:      req.IsSchedulable,
		AttendanceRequired: req.AttendanceRequired,
		OvertimeAllowed:    req.OvertimeAllowed,
	}, requesterID)
	if err != nil {
		status, msg := h.mapJobError(err)
		h.respondWithError(w, status, err, msg)
		return
	}

	h.respondWithJSON(w, http.StatusCreated, successResponse(
		h.toJobResponse(job),
		"Job created successfully",
	))
}

// ============================================================
// ListJobs
// ============================================================

// GET /companies/{companyID}/jobs?active_only=true
func (h *JobHandler) ListJobs(w http.ResponseWriter, r *http.Request) {
	ctx := h.injectClientIP(r.Context(), r)

	if _, err := h.getRequesterAdminID(r); err != nil {
		h.respondWithError(w, http.StatusUnauthorized, err, "Unauthorized")
		return
	}

	companyID, err := h.parseCompanyID(r)
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, err, "Invalid company ID")
		return
	}

	activeOnly := true
	if raw := r.URL.Query().Get("active_only"); raw != "" {
		if parsed, err := strconv.ParseBool(raw); err == nil {
			activeOnly = parsed
		}
	}

	jobs, err := h.jobService.ListJobs(ctx, companyID, activeOnly)
	if err != nil {
		status, msg := h.mapJobError(err)
		h.respondWithError(w, status, err, msg)
		return
	}

	items := make([]map[string]interface{}, 0, len(jobs))
	for _, j := range jobs {
		items = append(items, h.toJobResponse(j))
	}

	h.respondWithJSON(w, http.StatusOK, successResponse(map[string]interface{}{
		"jobs": items,
		"meta": map[string]interface{}{
			"company_id":  companyID.String(),
			"count":       len(items),
			"active_only": activeOnly,
		},
	}, "Jobs retrieved successfully"))
}

// ============================================================
// GetJob
// ============================================================

// GET /companies/{companyID}/jobs/{jobID}
func (h *JobHandler) GetJob(w http.ResponseWriter, r *http.Request) {
	ctx := h.injectClientIP(r.Context(), r)

	if _, err := h.getRequesterAdminID(r); err != nil {
		h.respondWithError(w, http.StatusUnauthorized, err, "Unauthorized")
		return
	}

	companyID, err := h.parseCompanyID(r)
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, err, "Invalid company ID")
		return
	}

	jobID, err := h.parseJobID(r)
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, err, "Invalid job ID")
		return
	}

	job, err := h.ensureJobBelongsToCompany(ctx, jobID, companyID)
	if err != nil {
		status, msg := h.mapJobError(err)
		h.respondWithError(w, status, err, msg)
		return
	}

	h.respondWithJSON(w, http.StatusOK, successResponse(
		h.toJobResponse(job),
		"Job retrieved successfully",
	))
}

// ============================================================
// UpdateJob
// ============================================================

// PATCH /companies/{companyID}/jobs/{jobID}
//
// All fields optional. job_code is immutable — to change it, delete and
// recreate the job.
type UpdateJobRequest struct {
	JobTitle           *string `json:"job_title,omitempty"`
	Description        *string `json:"description,omitempty"`
	IsSchedulable      *bool   `json:"is_schedulable,omitempty"`
	AttendanceRequired *bool   `json:"attendance_required,omitempty"`
	OvertimeAllowed    *bool   `json:"overtime_allowed,omitempty"`
	IsActive           *bool   `json:"is_active,omitempty"`
}

func (h *JobHandler) UpdateJob(w http.ResponseWriter, r *http.Request) {
	ctx := h.injectIdempotencyKey(h.injectClientIP(r.Context(), r), r)

	requesterID, err := h.getRequesterAdminID(r)
	if err != nil {
		h.respondWithError(w, http.StatusUnauthorized, err, "Unauthorized")
		return
	}

	companyID, err := h.parseCompanyID(r)
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, err, "Invalid company ID")
		return
	}

	jobID, err := h.parseJobID(r)
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, err, "Invalid job ID")
		return
	}

	if _, err := h.ensureJobBelongsToCompany(ctx, jobID, companyID); err != nil {
		status, msg := h.mapJobError(err)
		h.respondWithError(w, status, err, msg)
		return
	}

	var req UpdateJobRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		h.respondWithError(w, http.StatusBadRequest, err, "Invalid request body")
		return
	}

	// Guard: reject empty body — the caller must actually change something.
	if req.JobTitle == nil &&
		req.Description == nil &&
		req.IsSchedulable == nil &&
		req.AttendanceRequired == nil &&
		req.OvertimeAllowed == nil &&
		req.IsActive == nil {
		h.respondWithError(w, http.StatusBadRequest, customErrors.ErrInvalidInput, "At least one field must be provided")
		return
	}

	job, err := h.jobService.UpdateJob(ctx, jobID, &service.UpdateJobInput{
		JobTitle:           req.JobTitle,
		Description:        req.Description,
		IsSchedulable:      req.IsSchedulable,
		AttendanceRequired: req.AttendanceRequired,
		OvertimeAllowed:    req.OvertimeAllowed,
		IsActive:           req.IsActive,
	}, requesterID)
	if err != nil {
		status, msg := h.mapJobError(err)
		h.respondWithError(w, status, err, msg)
		return
	}

	h.respondWithJSON(w, http.StatusOK, successResponse(
		h.toJobResponse(job),
		"Job updated successfully",
	))
}

// ============================================================
// DeactivateJob  (soft delete)
// ============================================================

// POST /companies/{companyID}/jobs/{jobID}/deactivate
func (h *JobHandler) DeactivateJob(w http.ResponseWriter, r *http.Request) {
	ctx := h.injectIdempotencyKey(h.injectClientIP(r.Context(), r), r)

	requesterID, err := h.getRequesterAdminID(r)
	if err != nil {
		h.respondWithError(w, http.StatusUnauthorized, err, "Unauthorized")
		return
	}

	companyID, err := h.parseCompanyID(r)
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, err, "Invalid company ID")
		return
	}

	jobID, err := h.parseJobID(r)
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, err, "Invalid job ID")
		return
	}

	if _, err := h.ensureJobBelongsToCompany(ctx, jobID, companyID); err != nil {
		status, msg := h.mapJobError(err)
		h.respondWithError(w, status, err, msg)
		return
	}

	if err := h.jobService.DeactivateJob(ctx, jobID, requesterID); err != nil {
		status, msg := h.mapJobError(err)
		h.respondWithError(w, status, err, msg)
		return
	}

	h.respondWithJSON(w, http.StatusOK, successResponse(nil, "Job deactivated successfully"))
}

// ============================================================
// ReactivateJob
// ============================================================

// POST /companies/{companyID}/jobs/{jobID}/reactivate
func (h *JobHandler) ReactivateJob(w http.ResponseWriter, r *http.Request) {
	ctx := h.injectIdempotencyKey(h.injectClientIP(r.Context(), r), r)

	requesterID, err := h.getRequesterAdminID(r)
	if err != nil {
		h.respondWithError(w, http.StatusUnauthorized, err, "Unauthorized")
		return
	}

	companyID, err := h.parseCompanyID(r)
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, err, "Invalid company ID")
		return
	}

	jobID, err := h.parseJobID(r)
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, err, "Invalid job ID")
		return
	}

	if _, err := h.ensureJobBelongsToCompany(ctx, jobID, companyID); err != nil {
		status, msg := h.mapJobError(err)
		h.respondWithError(w, status, err, msg)
		return
	}

	if err := h.jobService.ReactivateJob(ctx, jobID, requesterID); err != nil {
		status, msg := h.mapJobError(err)
		h.respondWithError(w, status, err, msg)
		return
	}

	h.respondWithJSON(w, http.StatusOK, successResponse(nil, "Job reactivated successfully"))
}

// ============================================================
// DeleteJob  (hard delete — only if no positions reference it)
// ============================================================

// DELETE /companies/{companyID}/jobs/{jobID}
func (h *JobHandler) DeleteJob(w http.ResponseWriter, r *http.Request) {
	ctx := h.injectIdempotencyKey(h.injectClientIP(r.Context(), r), r)

	requesterID, err := h.getRequesterAdminID(r)
	if err != nil {
		h.respondWithError(w, http.StatusUnauthorized, err, "Unauthorized")
		return
	}

	companyID, err := h.parseCompanyID(r)
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, err, "Invalid company ID")
		return
	}

	jobID, err := h.parseJobID(r)
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, err, "Invalid job ID")
		return
	}

	if _, err := h.ensureJobBelongsToCompany(ctx, jobID, companyID); err != nil {
		status, msg := h.mapJobError(err)
		h.respondWithError(w, status, err, msg)
		return
	}

	if err := h.jobService.DeleteJob(ctx, jobID, requesterID); err != nil {
		status, msg := h.mapJobError(err)
		h.respondWithError(w, status, err, msg)
		return
	}

	h.respondWithJSON(w, http.StatusOK, successResponse(nil, "Job deleted successfully"))
}

// ============================================================
// CountPositionsInJob
// ============================================================

// GET /companies/{companyID}/jobs/{jobID}/positions/count
//
// The UI calls this before showing a "delete job" button — if count > 0
// the delete will 409 and the user should deactivate instead.
func (h *JobHandler) CountPositionsInJob(w http.ResponseWriter, r *http.Request) {
	ctx := h.injectClientIP(r.Context(), r)

	if _, err := h.getRequesterAdminID(r); err != nil {
		h.respondWithError(w, http.StatusUnauthorized, err, "Unauthorized")
		return
	}

	companyID, err := h.parseCompanyID(r)
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, err, "Invalid company ID")
		return
	}

	jobID, err := h.parseJobID(r)
	if err != nil {
		h.respondWithError(w, http.StatusBadRequest, err, "Invalid job ID")
		return
	}

	if _, err := h.ensureJobBelongsToCompany(ctx, jobID, companyID); err != nil {
		status, msg := h.mapJobError(err)
		h.respondWithError(w, status, err, msg)
		return
	}

	count, err := h.jobService.CountPositionsInJob(ctx, jobID)
	if err != nil {
		status, msg := h.mapJobError(err)
		h.respondWithError(w, status, err, msg)
		return
	}

	h.respondWithJSON(w, http.StatusOK, successResponse(map[string]interface{}{
		"job_id":          jobID.String(),
		"company_id":      companyID.String(),
		"position_count":  count,
		"deletable":       count == 0,
		"deactivate_hint": count > 0,
	}, "Position count retrieved"))
}

// ============================================================
// toJobResponse — canonical JSON shape for a job.
// ============================================================

func (h *JobHandler) toJobResponse(j *models.Job) map[string]interface{} {
	if j == nil {
		return nil
	}
	return map[string]interface{}{
		"job_id":              j.JobID.String(),
		"company_id":          j.CompanyID.String(),
		"job_code":            j.JobCode,
		"job_title":           j.JobTitle,
		"description":         j.Description,
		"is_schedulable":      j.IsSchedulable,
		"attendance_required": j.AttendanceRequired,
		"overtime_allowed":    j.OvertimeAllowed,
		"is_active":           j.IsActive,
		"created_at":          j.CreatedAt,
		"updated_at":          j.UpdatedAt,
	}
}

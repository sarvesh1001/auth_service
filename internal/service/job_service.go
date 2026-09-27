package service

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"regexp"
	"strings"
	"time"

	"github.com/google/uuid"

	"auth-service/internal/client"
	appErrors "auth-service/internal/errors"
	"auth-service/internal/infrastructure/audit"
	"auth-service/internal/infrastructure/idempotency"
	"auth-service/internal/models"
	"auth-service/internal/repository/postgres"
)

// ============================================================
// JobService — CRUD over the jobs catalog.
//
// A "job" is a definition ("Cashier", "Senior Cashier", "Line Operator").
// It has NO location, NO work center, NO department. Those live on
// positions (seats). JobService owns the definition side of the split.
//
// Called by:
//   • HR UI to create/edit the company's job catalog
//   • CompanyService.CreateCompany (via repo, inside its tx)
//   • Anywhere a caller needs a job_id before creating a position
// ============================================================

type JobService struct {
	pgClient         *client.PostgresClient
	jobRepo          postgres.JobRepository
	companyRepo      postgres.CompanyRepository
	auditService     *audit.AuditService
	idempotencyStore idempotency.Store
}

func NewJobService(
	pgClient *client.PostgresClient,
	jobRepo postgres.JobRepository,
	companyRepo postgres.CompanyRepository,
	auditService *audit.AuditService,
	idempotencyStore idempotency.Store,
) *JobService {
	if pgClient == nil {
		panic("pgClient is required for JobService")
	}
	if jobRepo == nil {
		panic("jobRepo is required for JobService")
	}
	if companyRepo == nil {
		panic("companyRepo is required for JobService")
	}
	if idempotencyStore == nil {
		panic("idempotencyStore is required for JobService")
	}
	return &JobService{
		pgClient:         pgClient,
		jobRepo:          jobRepo,
		companyRepo:      companyRepo,
		auditService:     auditService,
		idempotencyStore: idempotencyStore,
	}
}

// ============================================================
// Request DTOs
// ============================================================

type CreateJobInput struct {
	CompanyID          uuid.UUID `json:"-"`
	JobCode            string    `json:"job_code"            validate:"required,min=1,max=50"`
	JobTitle           string    `json:"job_title"           validate:"required,min=1,max=255"`
	Description        *string   `json:"description,omitempty"`
	IsSchedulable      *bool     `json:"is_schedulable,omitempty"`
	AttendanceRequired *bool     `json:"attendance_required,omitempty"`
	OvertimeAllowed    *bool     `json:"overtime_allowed,omitempty"`
}

type UpdateJobInput struct {
	JobTitle           *string `json:"job_title,omitempty"`
	Description        *string `json:"description,omitempty"`
	IsSchedulable      *bool   `json:"is_schedulable,omitempty"`
	AttendanceRequired *bool   `json:"attendance_required,omitempty"`
	OvertimeAllowed    *bool   `json:"overtime_allowed,omitempty"`
	IsActive           *bool   `json:"is_active,omitempty"`
}

// ============================================================
// Validation
// ============================================================

// Job codes are uppercase A-Z, 0-9, and underscores.
var jobCodeRe = regexp.MustCompile(`^[A-Z][A-Z0-9_]{0,49}$`)

func normalizeJobCode(code string) string {
	s := strings.ToUpper(strings.TrimSpace(code))
	// Replace any run of non-alphanumerics with a single underscore.
	s = regexp.MustCompile(`[^A-Z0-9]+`).ReplaceAllString(s, "_")
	s = strings.Trim(s, "_")
	return s
}

func validateJobCode(code string) error {
	if !jobCodeRe.MatchString(code) {
		return fmt.Errorf("%w: job_code must match [A-Z][A-Z0-9_]{0,49}", appErrors.ErrInvalidInput)
	}
	return nil
}

// ============================================================
// CreateJob
// ============================================================

func (s *JobService) CreateJob(
	ctx context.Context,
	in *CreateJobInput,
	createdBy uuid.UUID,
) (*models.Job, error) {
	if in == nil {
		return nil, fmt.Errorf("%w: empty request", appErrors.ErrInvalidInput)
	}
	if in.CompanyID == uuid.Nil {
		return nil, fmt.Errorf("%w: company_id is required", appErrors.ErrInvalidInput)
	}

	// Normalize + validate inputs.
	in.JobCode = normalizeJobCode(in.JobCode)
	in.JobTitle = strings.TrimSpace(in.JobTitle)
	if in.JobCode == "" {
		in.JobCode = normalizeJobCode(in.JobTitle)
	}
	if err := validateJobCode(in.JobCode); err != nil {
		return nil, err
	}
	if in.JobTitle == "" {
		return nil, fmt.Errorf("%w: job_title is required", appErrors.ErrInvalidInput)
	}

	// Idempotency
	idempKey, _ := ctx.Value("idempotency_key").(string)
	if idempKey == "" {
		idempKey = fmt.Sprintf("create_job:%s:%s", in.CompanyID.String(), in.JobCode)
	}
	var cached models.Job
	if err := s.idempotencyStore.Get(ctx, nil, idempKey, &cached); err == nil {
		return &cached, nil
	}
	ip, _ := ctx.Value("ip_address").(string)

	// Company existence + active check.
	company, err := s.companyRepo.GetCompany(ctx, in.CompanyID)
	if err != nil {
		if errors.Is(err, appErrors.ErrNotFound) {
			return nil, fmt.Errorf("%w: company not found", appErrors.ErrNotFound)
		}
		return nil, fmt.Errorf("%w: %v", appErrors.ErrInternal, err)
	}
	if !company.IsActive {
		return nil, fmt.Errorf("%w: company is not active", appErrors.ErrInvalidState)
	}

	// Uniqueness preflight (also enforced by UNIQUE(company_id, job_code)).
	exists, err := s.jobRepo.JobCodeExists(ctx, in.CompanyID, in.JobCode)
	if err != nil {
		return nil, fmt.Errorf("%w: failed to check job code: %v", appErrors.ErrInternal, err)
	}
	if exists {
		return nil, fmt.Errorf("%w: job with code '%s' already exists", appErrors.ErrDuplicate, in.JobCode)
	}

	// Defaults: schedulable=true, attendance=true, overtime=false.
	// Remote / non-attendance jobs explicitly set attendance=false.
	isSchedulable := true
	if in.IsSchedulable != nil {
		isSchedulable = *in.IsSchedulable
	}
	attendanceRequired := true
	if in.AttendanceRequired != nil {
		attendanceRequired = *in.AttendanceRequired
	}
	overtimeAllowed := false
	if in.OvertimeAllowed != nil {
		overtimeAllowed = *in.OvertimeAllowed
	}

	now := time.Now().UTC()
	job := &models.Job{
		JobID:              uuid.New(),
		CompanyID:          in.CompanyID,
		JobCode:            in.JobCode,
		JobTitle:           in.JobTitle,
		Description:        in.Description,
		IsSchedulable:      isSchedulable,
		AttendanceRequired: attendanceRequired,
		OvertimeAllowed:    overtimeAllowed,
		IsActive:           true,
		CreatedAt:          now,
		UpdatedAt:          now,
	}

	if err := s.jobRepo.CreateJob(ctx, s.pgClient.Pool(), job); err != nil {
		// Race: unique violation from another concurrent create.
		if strings.Contains(err.Error(), "uq_jobs_company_code") {
			return nil, fmt.Errorf("%w: job with code '%s' already exists", appErrors.ErrDuplicate, in.JobCode)
		}
		return nil, fmt.Errorf("%w: failed to create job: %v", appErrors.ErrInternal, err)
	}

	_ = s.idempotencyStore.Store(ctx, nil, idempKey, job)

	if s.auditService != nil {
		_ = s.auditService.LogAction(ctx, nil, &in.CompanyID, "job", "create", "hr",
			&createdBy, "hr", &createdBy, nil, nil, map[string]interface{}{
				"company_id":          in.CompanyID.String(),
				"job_id":              job.JobID.String(),
				"job_code":            job.JobCode,
				"job_title":           job.JobTitle,
				"is_schedulable":      job.IsSchedulable,
				"attendance_required": job.AttendanceRequired,
				"overtime_allowed":    job.OvertimeAllowed,
				"ip_address":          ip,
			})
	}
	return job, nil
}

// ============================================================
// FindOrCreateJob — used by CompanyService.CreateCompany or any
// caller that wants "get me a job_id for this title" without
// caring whether it already exists.
//
// Takes a DBTX so it can participate in an outer transaction.
// ============================================================

func (s *JobService) FindOrCreateJob(
	ctx context.Context,
	db client.DBTX,
	companyID uuid.UUID,
	jobTitle string,
	jobCode string, // optional; derived from jobTitle if empty
	isSchedulable, attendanceRequired, overtimeAllowed bool,
) (*models.Job, error) {
	if companyID == uuid.Nil {
		return nil, fmt.Errorf("%w: company_id is required", appErrors.ErrInvalidInput)
	}
	jobTitle = strings.TrimSpace(jobTitle)
	if jobTitle == "" {
		return nil, fmt.Errorf("%w: job_title is required", appErrors.ErrInvalidInput)
	}
	if jobCode == "" {
		jobCode = normalizeJobCode(jobTitle)
	} else {
		jobCode = normalizeJobCode(jobCode)
	}
	if err := validateJobCode(jobCode); err != nil {
		return nil, err
	}

	job, err := s.jobRepo.FindOrCreateJob(
		ctx, db, companyID, jobCode, jobTitle,
		isSchedulable, attendanceRequired, overtimeAllowed,
	)
	if err != nil {
		return nil, fmt.Errorf("%w: find-or-create job: %v", appErrors.ErrInternal, err)
	}
	return job, nil
}

// ============================================================
// GetJob / ListJobs
// ============================================================

func (s *JobService) GetJob(ctx context.Context, jobID uuid.UUID) (*models.Job, error) {
	if jobID == uuid.Nil {
		return nil, fmt.Errorf("%w: job_id is required", appErrors.ErrInvalidInput)
	}
	job, err := s.jobRepo.GetJobByID(ctx, jobID)
	if err != nil {
		if errors.Is(err, appErrors.ErrNotFound) {
			return nil, fmt.Errorf("%w: job not found", appErrors.ErrNotFound)
		}
		return nil, fmt.Errorf("%w: %v", appErrors.ErrInternal, err)
	}
	return job, nil
}

// ListJobs returns the company's job catalog. Pass activeOnly=true to
// hide soft-deleted jobs.
func (s *JobService) ListJobs(ctx context.Context, companyID uuid.UUID, activeOnly bool) ([]*models.Job, error) {
	if companyID == uuid.Nil {
		return nil, fmt.Errorf("%w: company_id is required", appErrors.ErrInvalidInput)
	}
	jobs, err := s.jobRepo.ListJobsByCompany(ctx, companyID)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", appErrors.ErrInternal, err)
	}
	if !activeOnly {
		return jobs, nil
	}
	out := make([]*models.Job, 0, len(jobs))
	for _, j := range jobs {
		if j.IsActive {
			out = append(out, j)
		}
	}
	return out, nil
}

// ============================================================
// UpdateJob
// ============================================================

func (s *JobService) UpdateJob(
	ctx context.Context,
	jobID uuid.UUID,
	in *UpdateJobInput,
	updatedBy uuid.UUID,
) (*models.Job, error) {
	if in == nil {
		return nil, fmt.Errorf("%w: empty request", appErrors.ErrInvalidInput)
	}
	if jobID == uuid.Nil {
		return nil, fmt.Errorf("%w: job_id is required", appErrors.ErrInvalidInput)
	}

	existing, err := s.jobRepo.GetJobByID(ctx, jobID)
	if err != nil {
		if errors.Is(err, appErrors.ErrNotFound) {
			return nil, fmt.Errorf("%w: job not found", appErrors.ErrNotFound)
		}
		return nil, fmt.Errorf("%w: %v", appErrors.ErrInternal, err)
	}

	if in.JobTitle != nil {
		t := strings.TrimSpace(*in.JobTitle)
		if t == "" {
			return nil, fmt.Errorf("%w: job_title cannot be empty", appErrors.ErrInvalidInput)
		}
		existing.JobTitle = t
	}
	if in.Description != nil {
		existing.Description = in.Description
	}
	if in.IsSchedulable != nil {
		existing.IsSchedulable = *in.IsSchedulable
	}
	if in.AttendanceRequired != nil {
		existing.AttendanceRequired = *in.AttendanceRequired
	}
	if in.OvertimeAllowed != nil {
		existing.OvertimeAllowed = *in.OvertimeAllowed
	}
	if in.IsActive != nil {
		existing.IsActive = *in.IsActive
	}
	existing.UpdatedAt = time.Now().UTC()

	if err := s.jobRepo.UpdateJob(ctx, existing); err != nil {
		return nil, fmt.Errorf("%w: failed to update job: %v", appErrors.ErrInternal, err)
	}

	ip, _ := ctx.Value("ip_address").(string)
	if s.auditService != nil {
		_ = s.auditService.LogAction(ctx, nil, &existing.CompanyID, "job", "update", "hr",
			&updatedBy, "hr", &updatedBy, nil, nil, map[string]interface{}{
				"company_id": existing.CompanyID.String(),
				"job_id":     jobID.String(),
				"job_code":   existing.JobCode,
				"ip_address": ip,
			})
	}
	return existing, nil
}

// ============================================================
// DeactivateJob — soft delete. Existing positions keep referencing
// the job, but new positions cannot be created against it.
// ============================================================

func (s *JobService) DeactivateJob(ctx context.Context, jobID, deactivatedBy uuid.UUID) error {
	job, err := s.jobRepo.GetJobByID(ctx, jobID)
	if err != nil {
		if errors.Is(err, appErrors.ErrNotFound) {
			return fmt.Errorf("%w: job not found", appErrors.ErrNotFound)
		}
		return fmt.Errorf("%w: %v", appErrors.ErrInternal, err)
	}
	if !job.IsActive {
		return fmt.Errorf("%w: job is already inactive", appErrors.ErrInvalidState)
	}

	if err := s.jobRepo.DeactivateJob(ctx, jobID); err != nil {
		return fmt.Errorf("%w: %v", appErrors.ErrInternal, err)
	}

	ip, _ := ctx.Value("ip_address").(string)
	if s.auditService != nil {
		_ = s.auditService.LogAction(ctx, nil, &job.CompanyID, "job", "deactivate", "hr",
			&deactivatedBy, "hr", &deactivatedBy, nil, nil, map[string]interface{}{
				"company_id": job.CompanyID.String(),
				"job_id":     jobID.String(),
				"job_code":   job.JobCode,
				"ip_address": ip,
			})
	}
	return nil
}

// ============================================================
// ReactivateJob — brings a soft-deleted job back into the catalog.
// ============================================================

func (s *JobService) ReactivateJob(ctx context.Context, jobID, reactivatedBy uuid.UUID) error {
	job, err := s.jobRepo.GetJobByID(ctx, jobID)
	if err != nil {
		if errors.Is(err, appErrors.ErrNotFound) {
			return fmt.Errorf("%w: job not found", appErrors.ErrNotFound)
		}
		return fmt.Errorf("%w: %v", appErrors.ErrInternal, err)
	}
	if job.IsActive {
		return fmt.Errorf("%w: job is already active", appErrors.ErrInvalidState)
	}

	if err := s.jobRepo.ReactivateJob(ctx, jobID); err != nil {
		return fmt.Errorf("%w: %v", appErrors.ErrInternal, err)
	}

	ip, _ := ctx.Value("ip_address").(string)
	if s.auditService != nil {
		_ = s.auditService.LogAction(ctx, nil, &job.CompanyID, "job", "reactivate", "hr",
			&reactivatedBy, "hr", &reactivatedBy, nil, nil, map[string]interface{}{
				"company_id": job.CompanyID.String(),
				"job_id":     jobID.String(),
				"job_code":   job.JobCode,
				"ip_address": ip,
			})
	}
	return nil
}

// ============================================================
// DeleteJob — hard delete. Only allowed when no positions reference
// the job (active or otherwise). Prefer DeactivateJob otherwise.
// ============================================================

func (s *JobService) DeleteJob(ctx context.Context, jobID, deletedBy uuid.UUID) error {
	job, err := s.jobRepo.GetJobByID(ctx, jobID)
	if err != nil {
		if errors.Is(err, appErrors.ErrNotFound) {
			return fmt.Errorf("%w: job not found", appErrors.ErrNotFound)
		}
		return fmt.Errorf("%w: %v", appErrors.ErrInternal, err)
	}

	count, err := s.jobRepo.CountPositionsByJob(ctx, jobID)
	if err != nil {
		return fmt.Errorf("%w: failed to check positions: %v", appErrors.ErrInternal, err)
	}
	if count > 0 {
		return fmt.Errorf("%w: job is referenced by %d position(s); deactivate instead",
			appErrors.ErrConflict, count)
	}

	if err := s.jobRepo.DeleteJob(ctx, jobID); err != nil {
		return fmt.Errorf("%w: %v", appErrors.ErrInternal, err)
	}

	ip, _ := ctx.Value("ip_address").(string)
	if s.auditService != nil {
		_ = s.auditService.LogAction(ctx, nil, &job.CompanyID, "job", "delete", "hr",
			&deletedBy, "hr", &deletedBy, nil, nil, map[string]interface{}{
				"company_id": job.CompanyID.String(),
				"job_id":     jobID.String(),
				"job_code":   job.JobCode,
				"ip_address": ip,
			})
	}
	return nil
}

// ============================================================
// Convenience: CountPositionsInJob — used by the UI before showing
// a "delete job" button.
// ============================================================

func (s *JobService) CountPositionsInJob(ctx context.Context, jobID uuid.UUID) (int, error) {
	if jobID == uuid.Nil {
		return 0, fmt.Errorf("%w: job_id is required", appErrors.ErrInvalidInput)
	}
	n, err := s.jobRepo.CountPositionsByJob(ctx, jobID)
	if err != nil {
		return 0, fmt.Errorf("%w: %v", appErrors.ErrInternal, err)
	}
	return n, nil
}

// ============================================================
// Helper used by any caller that needs a DB transaction:
// wraps FindOrCreateJob in its own tx for callers that aren't
// already inside one.
// ============================================================

func (s *JobService) FindOrCreateJobTx(
	ctx context.Context,
	companyID uuid.UUID,
	jobTitle, jobCode string,
	isSchedulable, attendanceRequired, overtimeAllowed bool,
) (*models.Job, error) {
	var out *models.Job
	err := s.pgClient.WithTx(ctx, func(tx *sql.Tx) error {
		job, err := s.FindOrCreateJob(
			ctx, tx, companyID, jobTitle, jobCode,
			isSchedulable, attendanceRequired, overtimeAllowed,
		)
		if err != nil {
			return err
		}
		out = job
		return nil
	})
	if err != nil {
		return nil, err
	}
	return out, nil
}

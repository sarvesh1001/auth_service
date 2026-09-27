package postgres

import (
	"context"
	"database/sql"
	"fmt"
	"strings"

	"github.com/google/uuid"
	"github.com/lib/pq"

	"auth-service/internal/client"
	apperrors "auth-service/internal/errors"
	"auth-service/internal/models"
)

// ============================================================
// JobRepository — the interface JobService consumes.
//
// *CompanyRepositoryImpl implements both CompanyRepository and
// JobRepository. NewJobRepository just returns the same concrete
// type with the narrower interface, so a single DB client and no
// duplicate wrapper.
// ============================================================

type JobRepository interface {
	FindOrCreateJob(
		ctx context.Context, db client.DBTX,
		companyID uuid.UUID,
		jobCode, jobTitle string,
		isSchedulable, attendanceRequired, overtimeAllowed bool,
	) (*models.Job, error)

	GetJobByID(ctx context.Context, jobID uuid.UUID) (*models.Job, error)
	ListJobsByCompany(ctx context.Context, companyID uuid.UUID) ([]*models.Job, error)
	UpdateJob(ctx context.Context, j *models.Job) error
	DeactivateJob(ctx context.Context, jobID uuid.UUID) error

	CreateJob(ctx context.Context, db client.DBTX, j *models.Job) error
	ReactivateJob(ctx context.Context, jobID uuid.UUID) error
	DeleteJob(ctx context.Context, jobID uuid.UUID) error
	JobCodeExists(ctx context.Context, companyID uuid.UUID, jobCode string) (bool, error)
	CountPositionsByJob(ctx context.Context, jobID uuid.UUID) (int, error)
}

func NewJobRepository(client *client.PostgresClient) JobRepository {
	return &CompanyRepositoryImpl{client: client}
}

// ============================================================
// DeactivateJob — soft delete. This is the method the compiler
// said was missing on *CompanyRepositoryImpl.
// ============================================================

func (r *CompanyRepositoryImpl) DeactivateJob(ctx context.Context, jobID uuid.UUID) error {
	const query = `UPDATE jobs SET is_active = false, updated_at = NOW() WHERE job_id = $1`
	res, err := r.client.Exec(ctx, query, jobID)
	if err != nil {
		return fmt.Errorf("deactivate job: %w", err)
	}
	if rows, _ := res.RowsAffected(); rows == 0 {
		return apperrors.ErrNotFound
	}
	return nil
}

// ============================================================
// CreateJob — used by JobService.CreateJob
// ============================================================

func (r *CompanyRepositoryImpl) CreateJob(ctx context.Context, db client.DBTX, j *models.Job) error {
	const query = `
		INSERT INTO jobs (
			job_id, company_id, job_code, job_title, description,
			is_schedulable, attendance_required, overtime_allowed,
			is_active, created_at, updated_at
		) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11)`
	_, err := db.ExecContext(ctx, query,
		j.JobID,
		j.CompanyID,
		j.JobCode,
		j.JobTitle,
		j.Description,
		j.IsSchedulable,
		j.AttendanceRequired,
		j.OvertimeAllowed,
		j.IsActive,
		j.CreatedAt,
		j.UpdatedAt,
	)
	if err != nil {
		if pgErr, ok := err.(*pq.Error); ok && pgErr.Code == "23505" {
			return apperrors.ErrDuplicate
		}
		return fmt.Errorf("create job: %w", err)
	}
	return nil
}

func (r *CompanyRepositoryImpl) ReactivateJob(ctx context.Context, jobID uuid.UUID) error {
	const query = `UPDATE jobs SET is_active = true, updated_at = NOW() WHERE job_id = $1`
	res, err := r.client.Exec(ctx, query, jobID)
	if err != nil {
		return fmt.Errorf("reactivate job: %w", err)
	}
	if rows, _ := res.RowsAffected(); rows == 0 {
		return apperrors.ErrNotFound
	}
	return nil
}

func (r *CompanyRepositoryImpl) DeleteJob(ctx context.Context, jobID uuid.UUID) error {
	const query = `DELETE FROM jobs WHERE job_id = $1`
	res, err := r.client.Exec(ctx, query, jobID)
	if err != nil {
		if pgErr, ok := err.(*pq.Error); ok && pgErr.Code == "23503" {
			return apperrors.ErrConflict
		}
		return fmt.Errorf("delete job: %w", err)
	}
	if rows, _ := res.RowsAffected(); rows == 0 {
		return apperrors.ErrNotFound
	}
	return nil
}

func (r *CompanyRepositoryImpl) JobCodeExists(ctx context.Context, companyID uuid.UUID, jobCode string) (bool, error) {
	const query = `SELECT EXISTS(SELECT 1 FROM jobs WHERE company_id = $1 AND job_code = $2)`
	var exists bool
	if err := r.client.QueryRow(ctx, query, companyID, jobCode).Scan(&exists); err != nil {
		return false, fmt.Errorf("check job code: %w", err)
	}
	return exists, nil
}

func (r *CompanyRepositoryImpl) CountPositionsByJob(ctx context.Context, jobID uuid.UUID) (int, error) {
	const query = `SELECT COUNT(*) FROM positions WHERE job_id = $1`
	var n int
	if err := r.client.QueryRow(ctx, query, jobID).Scan(&n); err != nil {
		return 0, fmt.Errorf("count positions by job: %w", err)
	}
	return n, nil
}

// ============================================================
// slugifyJobCode — "Senior Cashier" → "SENIOR_CASHIER".
// Used by CompanyRepositoryImpl.CreateCompany to derive a job_code
// from the owner's title when one is not supplied.
// ============================================================

func slugifyJobCode(title string) string {
	s := strings.ToUpper(strings.TrimSpace(title))
	var b strings.Builder
	for _, r := range s {
		if (r >= 'A' && r <= 'Z') || (r >= '0' && r <= '9') {
			b.WriteRune(r)
		} else {
			b.WriteRune('_')
		}
	}
	out := strings.Trim(b.String(), "_")
	for strings.Contains(out, "__") {
		out = strings.ReplaceAll(out, "__", "_")
	}
	if out == "" {
		out = "UNNAMED_" + uuid.New().String()[:8]
	}
	return out
}

// Silence "imported and not used" if FindOrCreateJob/GetJobByID/etc.
// live in this same file. Drop this block if you don't need it.
var (
	_ = sql.ErrNoRows
)

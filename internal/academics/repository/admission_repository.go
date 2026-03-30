package repository

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"strings"

	"github.com/google/uuid"
	"go.uber.org/zap"

	"auth-service/internal/academics/models"
	"auth-service/internal/util"
)

// AdmissionRepository defines all database operations for admissions.
type AdmissionRepository interface {
	Create(ctx context.Context, db DBTX, a *models.Admission) error
	GetByID(ctx context.Context, db DBTX, id uuid.UUID) (*models.Admission, error)
	GetByStudentID(ctx context.Context, db DBTX, studentID uuid.UUID) ([]*models.Admission, error)
	GetByAcademicYearID(ctx context.Context, db DBTX, academicYearID uuid.UUID) ([]*models.Admission, error)
	GetByStudentAndYear(ctx context.Context, db DBTX, studentID, academicYearID uuid.UUID) (*models.Admission, error)
	List(ctx context.Context, db DBTX, filter AdmissionFilter, p Pagination, s Sort) ([]*models.Admission, error)
	Count(ctx context.Context, db DBTX, filter AdmissionFilter) (int64, error)
	Update(ctx context.Context, db DBTX, a *models.Admission) error
	UpdateStatus(ctx context.Context, db DBTX, id uuid.UUID, status string, updatedBy *uuid.UUID) error
	Delete(ctx context.Context, db DBTX, id uuid.UUID) error
	BulkCreate(ctx context.Context, db DBTX, admissions []*models.Admission) error
}

type admissionRepository struct {
	logger *zap.Logger
}

// NewAdmissionRepository creates a new admission repository.
func NewAdmissionRepository(logger *zap.Logger) AdmissionRepository {
	return &admissionRepository{
		logger: logger.Named("admission_repo"),
	}
}

var allowedAdmissionSortFields = map[string]bool{
	"created_at":        true,
	"updated_at":        true,
	"admission_date":    true,
	"admission_status":  true,
	"class_applied_for": true,
}

func (r *admissionRepository) validateSort(s Sort) (string, error) {
	field := s.Field
	if field == "" {
		field = "created_at"
	}
	if !allowedAdmissionSortFields[field] {
		return "", fmt.Errorf("invalid sort field: %s", field)
	}
	dir := strings.ToUpper(s.Direction)
	if dir != "ASC" && dir != "DESC" {
		dir = "DESC"
	}
	return fmt.Sprintf("ORDER BY a.%s %s", field, dir), nil
}

func (r *admissionRepository) validatePagination(p Pagination) (int, int) {
	limit := p.Limit
	if limit <= 0 {
		limit = 50
	}
	if limit > 1000 {
		limit = 1000
	}
	offset := p.Offset
	if offset < 0 {
		offset = 0
	}
	return limit, offset
}

// buildAdmissionFilter builds WHERE clause and args for admission queries.
func (r *admissionRepository) buildAdmissionFilter(filter AdmissionFilter) (string, []interface{}) {
	var conditions []string
	var args []interface{}
	idx := 1

	if filter.StudentID != nil {
		conditions = append(conditions, fmt.Sprintf("a.student_id = $%d", idx))
		args = append(args, *filter.StudentID)
		idx++
	}

	if filter.AcademicYearID != nil {
		conditions = append(conditions, fmt.Sprintf("a.academic_year_id = $%d", idx))
		args = append(args, *filter.AcademicYearID)
		idx++
	}

	if filter.AdmissionStatus != nil {
		conditions = append(conditions, fmt.Sprintf("a.admission_status = $%d", idx))
		args = append(args, *filter.AdmissionStatus)
		idx++
	}

	if filter.FromDate != nil {
		conditions = append(conditions, fmt.Sprintf("a.admission_date >= $%d", idx))
		args = append(args, *filter.FromDate)
		idx++
	}

	if filter.ToDate != nil {
		conditions = append(conditions, fmt.Sprintf("a.admission_date <= $%d", idx))
		args = append(args, *filter.ToDate)
		idx++
	}

	if filter.Search != "" {
		// search on class_applied_for and remarks
		conditions = append(conditions, fmt.Sprintf("(a.class_applied_for ILIKE $%d OR a.remarks ILIKE $%d)", idx, idx))
		args = append(args, "%"+filter.Search+"%")
		idx++
	}

	// Note: admissions table does not have deleted_at, so no soft delete filter.

	if len(conditions) == 0 {
		return "", args
	}
	return "WHERE " + strings.Join(conditions, " AND "), args
}

// --- Create ------------------------------------------------------------

func (r *admissionRepository) Create(ctx context.Context, db DBTX, a *models.Admission) error {
	query := `
        INSERT INTO academics.admissions (
            student_id, academic_year_id, admission_date, class_applied_for,
            admission_status, remarks, created_by, created_at, updated_at
        ) VALUES ($1, $2, $3, $4, $5, $6, $7, NOW(), NOW())
        RETURNING admission_id, created_at, updated_at
    `
	err := db.QueryRowContext(ctx, query,
		a.StudentID, a.AcademicYearID, a.AdmissionDate, a.ClassAppliedFor,
		a.AdmissionStatus, a.Remarks, a.CreatedBy,
	).Scan(&a.AdmissionID, &a.CreatedAt, &a.UpdatedAt)

	if err != nil {
		r.logger.Error("failed to create admission",
			util.String("student_id", a.StudentID.String()),
			util.ErrorField(err))
		return fmt.Errorf("create admission: %w", err)
	}
	return nil
}

// --- BulkCreate ---------------------------------------------------------

func (r *admissionRepository) BulkCreate(ctx context.Context, db DBTX, admissions []*models.Admission) error {
	if len(admissions) == 0 {
		return nil
	}
	tx, isOwner, err := beginTxIfNotTx(ctx, db)
	if err != nil {
		return err
	}
	needRollback := isOwner
	defer func() {
		if needRollback {
			_ = tx.Rollback()
		}
	}()

	stmt, err := tx.PrepareContext(ctx, `
        INSERT INTO academics.admissions (
            student_id, academic_year_id, admission_date, class_applied_for,
            admission_status, remarks, created_by, created_at, updated_at
        ) VALUES ($1, $2, $3, $4, $5, $6, $7, NOW(), NOW())
        RETURNING admission_id, created_at, updated_at
    `)
	if err != nil {
		return fmt.Errorf("prepare statement: %w", err)
	}
	defer stmt.Close()

	for _, a := range admissions {
		err := stmt.QueryRowContext(ctx,
			a.StudentID, a.AcademicYearID, a.AdmissionDate, a.ClassAppliedFor,
			a.AdmissionStatus, a.Remarks, a.CreatedBy,
		).Scan(&a.AdmissionID, &a.CreatedAt, &a.UpdatedAt)
		if err != nil {
			r.logger.Error("bulk create admission failed",
				util.String("student_id", a.StudentID.String()),
				util.ErrorField(err))
			return fmt.Errorf("bulk create admission row: %w", err)
		}
	}

	if isOwner {
		if err = tx.Commit(); err != nil {
			return fmt.Errorf("commit tx: %w", err)
		}
		needRollback = false
	}
	return nil
}

// --- GetByID ------------------------------------------------------------

func (r *admissionRepository) GetByID(ctx context.Context, db DBTX, id uuid.UUID) (*models.Admission, error) {
	query := `
        SELECT
            admission_id, student_id, academic_year_id, admission_date,
            class_applied_for, admission_status, remarks,
            created_at, updated_at, created_by
        FROM academics.admissions
        WHERE admission_id = $1
    `
	row := db.QueryRowContext(ctx, query, id)
	return r.scanAdmission(row)
}

// --- GetByStudentID -----------------------------------------------------

func (r *admissionRepository) GetByStudentID(ctx context.Context, db DBTX, studentID uuid.UUID) ([]*models.Admission, error) {
	filter := AdmissionFilter{StudentID: &studentID}
	return r.List(ctx, db, filter, Pagination{Limit: 1000}, Sort{Field: "admission_date", Direction: "DESC"})
}

// --- GetByAcademicYearID ------------------------------------------------

func (r *admissionRepository) GetByAcademicYearID(ctx context.Context, db DBTX, academicYearID uuid.UUID) ([]*models.Admission, error) {
	filter := AdmissionFilter{AcademicYearID: &academicYearID}
	return r.List(ctx, db, filter, Pagination{Limit: 1000}, Sort{Field: "admission_date", Direction: "DESC"})
}

// --- GetByStudentAndYear ------------------------------------------------

func (r *admissionRepository) GetByStudentAndYear(ctx context.Context, db DBTX, studentID, academicYearID uuid.UUID) (*models.Admission, error) {
	query := `
        SELECT
            admission_id, student_id, academic_year_id, admission_date,
            class_applied_for, admission_status, remarks,
            created_at, updated_at, created_by
        FROM academics.admissions
        WHERE student_id = $1 AND academic_year_id = $2
    `
	row := db.QueryRowContext(ctx, query, studentID, academicYearID)
	return r.scanAdmission(row)
}

// --- List ---------------------------------------------------------------

func (r *admissionRepository) List(ctx context.Context, db DBTX, filter AdmissionFilter, p Pagination, s Sort) ([]*models.Admission, error) {
	where, args := r.buildAdmissionFilter(filter)
	orderBy, err := r.validateSort(s)
	if err != nil {
		return nil, err
	}
	limit, offset := r.validatePagination(p)

	query := fmt.Sprintf(`
        SELECT
            admission_id, student_id, academic_year_id, admission_date,
            class_applied_for, admission_status, remarks,
            created_at, updated_at, created_by
        FROM academics.admissions a
        %s
        %s
        LIMIT $%d OFFSET $%d
    `, where, orderBy, len(args)+1, len(args)+2)

	args = append(args, limit, offset)

	rows, err := db.QueryContext(ctx, query, args...)
	if err != nil {
		r.logger.Error("failed to list admissions",
			util.Any("filter", filter),
			util.ErrorField(err))
		return nil, fmt.Errorf("list admissions: %w", err)
	}
	defer rows.Close()

	var result []*models.Admission
	for rows.Next() {
		a, err := r.scanAdmission(rows)
		if err != nil {
			return nil, err
		}
		result = append(result, a)
	}
	if err = rows.Err(); err != nil {
		return nil, fmt.Errorf("rows iteration: %w", err)
	}
	return result, nil
}

// --- Count --------------------------------------------------------------

func (r *admissionRepository) Count(ctx context.Context, db DBTX, filter AdmissionFilter) (int64, error) {
	where, args := r.buildAdmissionFilter(filter)

	query := fmt.Sprintf("SELECT COUNT(*) FROM academics.admissions a %s", where)

	var count int64
	err := db.QueryRowContext(ctx, query, args...).Scan(&count)
	if err != nil {
		r.logger.Error("failed to count admissions",
			util.Any("filter", filter),
			util.ErrorField(err))
		return 0, fmt.Errorf("count admissions: %w", err)
	}
	return count, nil
}

// --- Update -------------------------------------------------------------

func (r *admissionRepository) Update(ctx context.Context, db DBTX, a *models.Admission) error {
	query := `
        UPDATE academics.admissions
        SET
            student_id = $2,
            academic_year_id = $3,
            admission_date = $4,
            class_applied_for = $5,
            admission_status = $6,
            remarks = $7,
            updated_at = NOW()
        WHERE admission_id = $1
        RETURNING updated_at
    `
	err := db.QueryRowContext(ctx, query,
		a.AdmissionID,
		a.StudentID,
		a.AcademicYearID,
		a.AdmissionDate,
		a.ClassAppliedFor,
		a.AdmissionStatus,
		a.Remarks,
	).Scan(&a.UpdatedAt)

	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return fmt.Errorf("%w: admission %s", ErrNotFound, a.AdmissionID)
		}
		r.logger.Error("failed to update admission",
			util.String("id", a.AdmissionID.String()),
			util.ErrorField(err))
		return fmt.Errorf("update admission: %w", err)
	}
	return nil
}

// --- UpdateStatus -------------------------------------------------------

func (r *admissionRepository) UpdateStatus(ctx context.Context, db DBTX, id uuid.UUID, status string, updatedBy *uuid.UUID) error {
	query := `UPDATE academics.admissions SET admission_status = $2, updated_by = $3, updated_at = NOW() WHERE admission_id = $1`
	result, err := db.ExecContext(ctx, query, id, status, updatedBy)
	if err != nil {
		r.logger.Error("failed to update admission status",
			util.String("id", id.String()),
			util.String("status", status),
			util.ErrorField(err))
		return fmt.Errorf("update admission status: %w", err)
	}
	rows, err := result.RowsAffected()
	if err != nil {
		return fmt.Errorf("rows affected: %w", err)
	}
	if rows == 0 {
		return fmt.Errorf("admission %s not found", id)
	}
	return nil
}

// --- Delete -------------------------------------------------------------

func (r *admissionRepository) Delete(ctx context.Context, db DBTX, id uuid.UUID) error {
	query := `DELETE FROM academics.admissions WHERE admission_id = $1`
	result, err := db.ExecContext(ctx, query, id)
	if err != nil {
		r.logger.Error("failed to delete admission",
			util.String("id", id.String()),
			util.ErrorField(err))
		return fmt.Errorf("delete admission: %w", err)
	}
	rows, err := result.RowsAffected()
	if err != nil {
		return fmt.Errorf("rows affected: %w", err)
	}
	if rows == 0 {
		return fmt.Errorf("admission %s not found", id)
	}
	return nil
}

// --- scanAdmission ------------------------------------------------------

func (r *admissionRepository) scanAdmission(row scanner) (*models.Admission, error) {
	var a models.Admission
	var createdBy uuid.NullUUID

	err := row.Scan(
		&a.AdmissionID,
		&a.StudentID,
		&a.AcademicYearID,
		&a.AdmissionDate,
		&a.ClassAppliedFor,
		&a.AdmissionStatus,
		&a.Remarks,
		&a.CreatedAt,
		&a.UpdatedAt,
		&createdBy,
	)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, nil
		}
		return nil, fmt.Errorf("scan admission: %w", err)
	}

	if createdBy.Valid {
		a.CreatedBy = &createdBy.UUID
	}

	return &a, nil
}

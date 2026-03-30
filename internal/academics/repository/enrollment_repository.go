// enrollment_repository.go
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

// Enrollment status constants
const (
	EnrollmentStatusActive    = "active"
	EnrollmentStatusCompleted = "completed"
	EnrollmentStatusWithdrawn = "withdrawn"
)

// EnrollmentRepository defines the database operations for enrollments.
type EnrollmentRepository interface {
	// Basic CRUD
	Create(ctx context.Context, db DBTX, e *models.Enrollment) error
	BulkCreate(ctx context.Context, db DBTX, e []*models.Enrollment) error
	Upsert(ctx context.Context, db DBTX, e *models.Enrollment) error
	GetByID(ctx context.Context, db DBTX, companyID, id uuid.UUID) (*models.Enrollment, error)
	GetByIDForUpdate(ctx context.Context, db DBTX, companyID, id uuid.UUID) (*models.Enrollment, error)
	GetByStudentAndYear(ctx context.Context, db DBTX, companyID, studentID, academicYearID uuid.UUID) (*models.Enrollment, error)
	GetActiveByStudent(ctx context.Context, db DBTX, companyID, studentID uuid.UUID) (*models.Enrollment, error)
	List(ctx context.Context, db DBTX, filter EnrollmentFilter, p Pagination, s Sort) ([]*models.Enrollment, error)
	ListByStudent(ctx context.Context, db DBTX, companyID, studentID uuid.UUID) ([]*models.Enrollment, error)
	ListBySection(ctx context.Context, db DBTX, companyID, sectionID uuid.UUID) ([]*models.Enrollment, error)
	ListByAcademicYear(ctx context.Context, db DBTX, companyID, academicYearID uuid.UUID) ([]*models.Enrollment, error)
	Count(ctx context.Context, db DBTX, filter EnrollmentFilter) (int64, error)
	Update(ctx context.Context, db DBTX, e *models.Enrollment) error
	UpdateStatus(ctx context.Context, db DBTX, id uuid.UUID, status string, updatedBy *uuid.UUID) error
	UpdateRollNumber(ctx context.Context, db DBTX, id uuid.UUID, rollNumber string, updatedBy *uuid.UUID) error
	Delete(ctx context.Context, db DBTX, id uuid.UUID, deletedBy *uuid.UUID) error
	Exists(ctx context.Context, db DBTX, studentID, academicYearID uuid.UUID) (bool, error)
	CountBySection(ctx context.Context, db DBTX, sectionID uuid.UUID) (int64, error)
	CountByAcademicYear(ctx context.Context, db DBTX, academicYearID uuid.UUID) (int64, error)
	Search(ctx context.Context, db DBTX, query string, companyID uuid.UUID, p Pagination) ([]*models.Enrollment, error)
	BulkUpdateStatus(ctx context.Context, db DBTX, ids []uuid.UUID, status string, updatedBy *uuid.UUID) error
	BulkAssignRollNumbers(ctx context.Context, db DBTX, data map[uuid.UUID]string, updatedBy *uuid.UUID) error
	GetBySectionForPromotion(ctx context.Context, db DBTX, sectionID uuid.UUID) ([]*models.Enrollment, error)
	FindDuplicates(ctx context.Context, db DBTX, academicYearID uuid.UUID) ([]*models.Enrollment, error)
	GetByIDForUpdateUnsafe(ctx context.Context, tx *sql.Tx, id uuid.UUID) (*models.Enrollment, error)
	GetByIDUnsafe(ctx context.Context, db DBTX, id uuid.UUID) (*models.Enrollment, error) // Extended operations for transactional workflows
	CountActiveBySection(ctx context.Context, db DBTX, sectionID uuid.UUID) (int64, error)
	CountActiveByStudent(ctx context.Context, db DBTX, studentID uuid.UUID) (int64, error)
	CompleteActiveEnrollment(ctx context.Context, tx *sql.Tx, companyID, studentID, academicYearID uuid.UUID, updatedBy *uuid.UUID) error
	CompleteAllActiveEnrollments(ctx context.Context, tx *sql.Tx, companyID, studentID uuid.UUID, updatedBy *uuid.UUID) error
	WithdrawAllActiveEnrollments(ctx context.Context, tx *sql.Tx, companyID, studentID uuid.UUID, updatedBy *uuid.UUID) error
	CreateEnrollment(ctx context.Context, tx *sql.Tx, companyID, studentID, academicYearID, sectionID uuid.UUID, createdBy, updatedBy *uuid.UUID) (uuid.UUID, error)
	GetActiveEnrollmentForUpdate(ctx context.Context, tx *sql.Tx, companyID, studentID, academicYearID uuid.UUID) (*models.Enrollment, error)
	GetActiveCountForSectionForUpdate(ctx context.Context, tx *sql.Tx, companyID, sectionID uuid.UUID) (int64, error)
	ExistsActiveEnrollment(ctx context.Context, db DBTX, companyID, studentID, academicYearID uuid.UUID) (bool, error)
}

type enrollmentRepository struct {
	logger *zap.Logger
}

// NewEnrollmentRepository creates a new enrollment repository.
func NewEnrollmentRepository(logger *zap.Logger) EnrollmentRepository {
	return &enrollmentRepository{
		logger: logger.Named("enrollment_repo"),
	}
}

// allowedEnrollmentSortFields defines fields that can be used for sorting.
var allowedEnrollmentSortFields = map[string]bool{
	"created_at":      true,
	"updated_at":      true,
	"enrollment_date": true,
	"roll_number":     true,
	"status":          true,
}

func (r *enrollmentRepository) validateSort(s Sort) (string, error) {
	field := s.Field
	if field == "" {
		field = "created_at"
	}
	if !allowedEnrollmentSortFields[field] {
		return "", fmt.Errorf("invalid sort field: %s", field)
	}
	dir := strings.ToUpper(s.Direction)
	if dir != "ASC" && dir != "DESC" {
		dir = "DESC"
	}
	return fmt.Sprintf("ORDER BY e.%s %s", field, dir), nil
}

func (r *enrollmentRepository) validatePagination(p Pagination) (int, int) {
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

// buildEnrollmentFilter constructs WHERE clause and args for filtering enrollments.
// Note: For multi-tenancy, we always join with students to enforce company_id.
func (r *enrollmentRepository) buildEnrollmentFilter(filter EnrollmentFilter) (string, []interface{}) {
	var conditions []string
	var args []interface{}
	idx := 1

	if filter.CompanyID != uuid.Nil {
		conditions = append(conditions, fmt.Sprintf("s.company_id = $%d", idx))
		args = append(args, filter.CompanyID)
		idx++
	}
	if filter.StudentID != uuid.Nil {
		conditions = append(conditions, fmt.Sprintf("e.student_id = $%d", idx))
		args = append(args, filter.StudentID)
		idx++
	}
	if filter.AcademicYearID != uuid.Nil {
		conditions = append(conditions, fmt.Sprintf("e.academic_year_id = $%d", idx))
		args = append(args, filter.AcademicYearID)
		idx++
	}
	if filter.SectionID != uuid.Nil {
		conditions = append(conditions, fmt.Sprintf("e.section_id = $%d", idx))
		args = append(args, filter.SectionID)
		idx++
	}
	if filter.Status != nil {
		conditions = append(conditions, fmt.Sprintf("e.status = $%d", idx))
		args = append(args, *filter.Status)
		idx++
	}
	if filter.EnrollmentDateFrom != nil {
		conditions = append(conditions, fmt.Sprintf("e.enrollment_date >= $%d", idx))
		args = append(args, *filter.EnrollmentDateFrom)
		idx++
	}
	if filter.EnrollmentDateTo != nil {
		conditions = append(conditions, fmt.Sprintf("e.enrollment_date <= $%d", idx))
		args = append(args, *filter.EnrollmentDateTo)
		idx++
	}
	if filter.Search != "" {
		conditions = append(conditions, fmt.Sprintf("e.roll_number ILIKE $%d", idx))
		args = append(args, "%"+filter.Search+"%")
		idx++
	}

	conditions = append(conditions, "e.deleted_at IS NULL")

	if len(conditions) == 0 {
		return "", args
	}
	return "WHERE " + strings.Join(conditions, " AND "), args
}

// Create inserts a new enrollment record.
func (r *enrollmentRepository) Create(ctx context.Context, db DBTX, e *models.Enrollment) error {
	query := `
		INSERT INTO academics.enrollments (
			student_id, academic_year_id, section_id, enrollment_date,
			roll_number, status, version, created_by, updated_by, created_at, updated_at
		) VALUES ($1, $2, $3, $4, $5, $6, 0, $7, $8, NOW(), NOW())
		RETURNING enrollment_id, created_at, updated_at, version
	`
	err := db.QueryRowContext(ctx, query,
		e.StudentID, e.AcademicYearID, e.SectionID, e.EnrollmentDate,
		e.RollNumber, e.Status, e.CreatedBy, e.UpdatedBy,
	).Scan(&e.EnrollmentID, &e.CreatedAt, &e.UpdatedAt, &e.Version)
	if err != nil {
		r.logger.Error("failed to create enrollment",
			util.String("student_id", e.StudentID.String()),
			util.String("academic_year_id", e.AcademicYearID.String()),
			util.ErrorField(err))
		return fmt.Errorf("create enrollment: %w", err)
	}
	return nil
}

// BulkCreate inserts multiple enrollment records in a transaction.
func (r *enrollmentRepository) BulkCreate(ctx context.Context, db DBTX, e []*models.Enrollment) error {
	if len(e) == 0 {
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
		INSERT INTO academics.enrollments (
			student_id, academic_year_id, section_id, enrollment_date,
			roll_number, status, version, created_by, updated_by, created_at, updated_at
		) VALUES ($1, $2, $3, $4, $5, $6, 0, $7, $8, NOW(), NOW())
		RETURNING enrollment_id, created_at, updated_at, version
	`)
	if err != nil {
		return fmt.Errorf("prepare statement: %w", err)
	}
	defer stmt.Close()

	for _, enr := range e {
		err = stmt.QueryRowContext(ctx,
			enr.StudentID, enr.AcademicYearID, enr.SectionID, enr.EnrollmentDate,
			enr.RollNumber, enr.Status, enr.CreatedBy, enr.UpdatedBy,
		).Scan(&enr.EnrollmentID, &enr.CreatedAt, &enr.UpdatedAt, &enr.Version)
		if err != nil {
			r.logger.Error("bulk create enrollment failed",
				util.String("student_id", enr.StudentID.String()),
				util.String("academic_year_id", enr.AcademicYearID.String()),
				util.ErrorField(err))
			return fmt.Errorf("bulk create enrollment row: %w", err)
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

// Upsert inserts a new enrollment or updates existing one based on unique constraint.
// Assumes unique constraint on (student_id, academic_year_id) where deleted_at IS NULL.
func (r *enrollmentRepository) Upsert(ctx context.Context, db DBTX, e *models.Enrollment) error {
	query := `
		INSERT INTO academics.enrollments (
			student_id, academic_year_id, section_id, enrollment_date,
			roll_number, status, version, created_by, updated_by, created_at, updated_at
		) VALUES ($1, $2, $3, $4, $5, $6, 0, $7, $8, NOW(), NOW())
		ON CONFLICT (student_id, academic_year_id) WHERE deleted_at IS NULL
		DO UPDATE SET
			section_id = EXCLUDED.section_id,
			enrollment_date = EXCLUDED.enrollment_date,
			roll_number = EXCLUDED.roll_number,
			status = EXCLUDED.status,
			updated_by = EXCLUDED.updated_by,
			updated_at = NOW(),
			version = academics.enrollments.version + 1
		RETURNING enrollment_id, created_at, updated_at, version
	`
	err := db.QueryRowContext(ctx, query,
		e.StudentID, e.AcademicYearID, e.SectionID, e.EnrollmentDate,
		e.RollNumber, e.Status, e.CreatedBy, e.UpdatedBy,
	).Scan(&e.EnrollmentID, &e.CreatedAt, &e.UpdatedAt, &e.Version)
	if err != nil {
		r.logger.Error("failed to upsert enrollment",
			util.String("student_id", e.StudentID.String()),
			util.String("academic_year_id", e.AcademicYearID.String()),
			util.ErrorField(err))
		return fmt.Errorf("upsert enrollment: %w", err)
	}
	return nil
}

// GetByID retrieves an enrollment by its ID, enforcing company isolation via student join.
func (r *enrollmentRepository) GetByID(ctx context.Context, db DBTX, companyID, id uuid.UUID) (*models.Enrollment, error) {
	query := `
		SELECT e.enrollment_id, e.student_id, e.academic_year_id, e.section_id,
		       e.enrollment_date, e.roll_number, e.status, e.version,
		       e.created_at, e.updated_at, e.created_by, e.updated_by
		FROM academics.enrollments e
		JOIN academics.students s ON e.student_id = s.student_id
		WHERE e.enrollment_id = $1 AND s.company_id = $2 AND e.deleted_at IS NULL
	`
	var e models.Enrollment
	var createdBy, updatedBy uuid.NullUUID
	err := db.QueryRowContext(ctx, query, id, companyID).Scan(
		&e.EnrollmentID, &e.StudentID, &e.AcademicYearID, &e.SectionID,
		&e.EnrollmentDate, &e.RollNumber, &e.Status, &e.Version,
		&e.CreatedAt, &e.UpdatedAt, &createdBy, &updatedBy,
	)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, nil
		}
		r.logger.Error("failed to get enrollment by ID",
			util.String("id", id.String()),
			util.String("company_id", companyID.String()),
			util.ErrorField(err))
		return nil, fmt.Errorf("get enrollment by ID: %w", err)
	}
	if createdBy.Valid {
		e.CreatedBy = &createdBy.UUID
	}
	if updatedBy.Valid {
		e.UpdatedBy = &updatedBy.UUID
	}
	return &e, nil
}

// GetByIDForUpdate retrieves an enrollment by ID with row lock, enforcing company isolation.
func (r *enrollmentRepository) GetByIDForUpdate(ctx context.Context, db DBTX, companyID, id uuid.UUID) (*models.Enrollment, error) {
	query := `
		SELECT e.enrollment_id, e.student_id, e.academic_year_id, e.section_id,
		       e.enrollment_date, e.roll_number, e.status, e.version,
		       e.created_at, e.updated_at, e.created_by, e.updated_by
		FROM academics.enrollments e
		JOIN academics.students s ON e.student_id = s.student_id
		WHERE e.enrollment_id = $1 AND s.company_id = $2 AND e.deleted_at IS NULL
		FOR UPDATE
	`
	var e models.Enrollment
	var createdBy, updatedBy uuid.NullUUID
	err := db.QueryRowContext(ctx, query, id, companyID).Scan(
		&e.EnrollmentID, &e.StudentID, &e.AcademicYearID, &e.SectionID,
		&e.EnrollmentDate, &e.RollNumber, &e.Status, &e.Version,
		&e.CreatedAt, &e.UpdatedAt, &createdBy, &updatedBy,
	)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, nil
		}
		r.logger.Error("failed to get enrollment for update",
			util.String("id", id.String()),
			util.String("company_id", companyID.String()),
			util.ErrorField(err))
		return nil, fmt.Errorf("get enrollment for update: %w", err)
	}
	if createdBy.Valid {
		e.CreatedBy = &createdBy.UUID
	}
	if updatedBy.Valid {
		e.UpdatedBy = &updatedBy.UUID
	}
	return &e, nil
}

// GetByStudentAndYear retrieves enrollment for a student in a specific academic year, enforcing company isolation.
func (r *enrollmentRepository) GetByStudentAndYear(ctx context.Context, db DBTX, companyID, studentID, academicYearID uuid.UUID) (*models.Enrollment, error) {
	query := `
		SELECT e.enrollment_id, e.student_id, e.academic_year_id, e.section_id,
		       e.enrollment_date, e.roll_number, e.status, e.version,
		       e.created_at, e.updated_at, e.created_by, e.updated_by
		FROM academics.enrollments e
		JOIN academics.students s ON e.student_id = s.student_id
		WHERE e.student_id = $1 AND e.academic_year_id = $2 AND s.company_id = $3 AND e.deleted_at IS NULL
	`
	var e models.Enrollment
	var createdBy, updatedBy uuid.NullUUID
	err := db.QueryRowContext(ctx, query, studentID, academicYearID, companyID).Scan(
		&e.EnrollmentID, &e.StudentID, &e.AcademicYearID, &e.SectionID,
		&e.EnrollmentDate, &e.RollNumber, &e.Status, &e.Version,
		&e.CreatedAt, &e.UpdatedAt, &createdBy, &updatedBy,
	)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, nil
		}
		r.logger.Error("failed to get enrollment by student and year",
			util.String("student_id", studentID.String()),
			util.String("academic_year_id", academicYearID.String()),
			util.String("company_id", companyID.String()),
			util.ErrorField(err))
		return nil, fmt.Errorf("get enrollment by student and year: %w", err)
	}
	if createdBy.Valid {
		e.CreatedBy = &createdBy.UUID
	}
	if updatedBy.Valid {
		e.UpdatedBy = &updatedBy.UUID
	}
	return &e, nil
}

// GetActiveByStudent retrieves the active enrollment for a student (status = 'active'), enforcing company isolation.
func (r *enrollmentRepository) GetActiveByStudent(ctx context.Context, db DBTX, companyID, studentID uuid.UUID) (*models.Enrollment, error) {
	query := `
		SELECT e.enrollment_id, e.student_id, e.academic_year_id, e.section_id,
		       e.enrollment_date, e.roll_number, e.status, e.version,
		       e.created_at, e.updated_at, e.created_by, e.updated_by
		FROM academics.enrollments e
		JOIN academics.students s ON e.student_id = s.student_id
		WHERE e.student_id = $1 AND s.company_id = $2 AND e.status = $3 AND e.deleted_at IS NULL
		LIMIT 1
	`
	var e models.Enrollment
	var createdBy, updatedBy uuid.NullUUID
	err := db.QueryRowContext(ctx, query, studentID, companyID, EnrollmentStatusActive).Scan(
		&e.EnrollmentID, &e.StudentID, &e.AcademicYearID, &e.SectionID,
		&e.EnrollmentDate, &e.RollNumber, &e.Status, &e.Version,
		&e.CreatedAt, &e.UpdatedAt, &createdBy, &updatedBy,
	)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, nil
		}
		r.logger.Error("failed to get active enrollment by student",
			util.String("student_id", studentID.String()),
			util.String("company_id", companyID.String()),
			util.ErrorField(err))
		return nil, fmt.Errorf("get active enrollment by student: %w", err)
	}
	if createdBy.Valid {
		e.CreatedBy = &createdBy.UUID
	}
	if updatedBy.Valid {
		e.UpdatedBy = &updatedBy.UUID
	}
	return &e, nil
}

// List returns enrollments matching filter with pagination and sorting, enforcing company isolation via join.
func (r *enrollmentRepository) List(ctx context.Context, db DBTX, filter EnrollmentFilter, p Pagination, s Sort) ([]*models.Enrollment, error) {
	where, args := r.buildEnrollmentFilter(filter)
	orderBy, err := r.validateSort(s)
	if err != nil {
		return nil, err
	}
	limit, offset := r.validatePagination(p)

	query := fmt.Sprintf(`
		SELECT e.enrollment_id, e.student_id, e.academic_year_id, e.section_id,
		       e.enrollment_date, e.roll_number, e.status, e.version,
		       e.created_at, e.updated_at, e.created_by, e.updated_by
		FROM academics.enrollments e
		JOIN academics.students s ON e.student_id = s.student_id
		%s %s
		LIMIT $%d OFFSET $%d
	`, where, orderBy, len(args)+1, len(args)+2)
	args = append(args, limit, offset)

	rows, err := db.QueryContext(ctx, query, args...)
	if err != nil {
		r.logger.Error("failed to list enrollments",
			util.Any("filter", filter),
			util.ErrorField(err))
		return nil, fmt.Errorf("list enrollments: %w", err)
	}
	defer rows.Close()

	var result []*models.Enrollment
	for rows.Next() {
		var e models.Enrollment
		var createdBy, updatedBy uuid.NullUUID
		if err := rows.Scan(
			&e.EnrollmentID, &e.StudentID, &e.AcademicYearID, &e.SectionID,
			&e.EnrollmentDate, &e.RollNumber, &e.Status, &e.Version,
			&e.CreatedAt, &e.UpdatedAt, &createdBy, &updatedBy,
		); err != nil {
			return nil, fmt.Errorf("scan enrollment: %w", err)
		}
		if createdBy.Valid {
			e.CreatedBy = &createdBy.UUID
		}
		if updatedBy.Valid {
			e.UpdatedBy = &updatedBy.UUID
		}
		result = append(result, &e)
	}
	if err = rows.Err(); err != nil {
		return nil, fmt.Errorf("rows iteration: %w", err)
	}
	return result, nil
}

// ListByStudent returns all enrollments for a student, enforcing company isolation.
func (r *enrollmentRepository) ListByStudent(ctx context.Context, db DBTX, companyID, studentID uuid.UUID) ([]*models.Enrollment, error) {
	filter := EnrollmentFilter{
		CompanyID: companyID,
		StudentID: studentID,
	}
	return r.List(ctx, db, filter, Pagination{Limit: 1000}, Sort{Field: "enrollment_date", Direction: "DESC"})
}

// ListBySection returns all enrollments for a section, enforcing company isolation.
func (r *enrollmentRepository) ListBySection(ctx context.Context, db DBTX, companyID, sectionID uuid.UUID) ([]*models.Enrollment, error) {
	filter := EnrollmentFilter{
		CompanyID: companyID,
		SectionID: sectionID,
	}
	return r.List(ctx, db, filter, Pagination{Limit: 1000}, Sort{Field: "roll_number", Direction: "ASC"})
}

// ListByAcademicYear returns all enrollments for an academic year, enforcing company isolation.
func (r *enrollmentRepository) ListByAcademicYear(ctx context.Context, db DBTX, companyID, academicYearID uuid.UUID) ([]*models.Enrollment, error) {
	filter := EnrollmentFilter{
		CompanyID:      companyID,
		AcademicYearID: academicYearID,
	}
	return r.List(ctx, db, filter, Pagination{Limit: 1000}, Sort{Field: "enrollment_date", Direction: "ASC"})
}

// Count returns total number of enrollments matching the filter.
func (r *enrollmentRepository) Count(ctx context.Context, db DBTX, filter EnrollmentFilter) (int64, error) {
	where, args := r.buildEnrollmentFilter(filter)
	query := fmt.Sprintf(`
		SELECT COUNT(*)
		FROM academics.enrollments e
		JOIN academics.students s ON e.student_id = s.student_id
		%s
	`, where)
	var count int64
	err := db.QueryRowContext(ctx, query, args...).Scan(&count)
	if err != nil {
		r.logger.Error("failed to count enrollments",
			util.Any("filter", filter),
			util.ErrorField(err))
		return 0, fmt.Errorf("count enrollments: %w", err)
	}
	return count, nil
}

// Update updates an existing enrollment with optimistic locking.
func (r *enrollmentRepository) Update(ctx context.Context, db DBTX, e *models.Enrollment) error {
	query := `
		UPDATE academics.enrollments
		SET section_id = $2, enrollment_date = $3, roll_number = $4,
		    status = $5, updated_by = $6, updated_at = NOW(),
		    version = version + 1
		WHERE enrollment_id = $1 AND version = $7 AND deleted_at IS NULL
		RETURNING updated_at, version
	`
	err := db.QueryRowContext(ctx, query,
		e.EnrollmentID, e.SectionID, e.EnrollmentDate, e.RollNumber,
		e.Status, e.UpdatedBy, e.Version,
	).Scan(&e.UpdatedAt, &e.Version)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return fmt.Errorf("%w: enrollment %s version mismatch", ErrVersionConflict, e.EnrollmentID)
		}
		r.logger.Error("failed to update enrollment",
			util.String("id", e.EnrollmentID.String()),
			util.ErrorField(err))
		return fmt.Errorf("update enrollment: %w", err)
	}
	return nil
}

// UpdateStatus updates the status of an enrollment.
func (r *enrollmentRepository) UpdateStatus(ctx context.Context, db DBTX, id uuid.UUID, status string, updatedBy *uuid.UUID) error {
	query := `
		UPDATE academics.enrollments
		SET status = $2, updated_by = $3, updated_at = NOW(),
		    version = version + 1
		WHERE enrollment_id = $1 AND deleted_at IS NULL
	`
	result, err := db.ExecContext(ctx, query, id, status, updatedBy)
	if err != nil {
		r.logger.Error("failed to update enrollment status",
			util.String("id", id.String()),
			util.String("status", status),
			util.ErrorField(err))
		return fmt.Errorf("update enrollment status: %w", err)
	}
	rows, _ := result.RowsAffected()
	if rows == 0 {
		return fmt.Errorf("enrollment %s not found or deleted", id)
	}
	return nil
}

// UpdateRollNumber updates the roll number of an enrollment.
func (r *enrollmentRepository) UpdateRollNumber(ctx context.Context, db DBTX, id uuid.UUID, rollNumber string, updatedBy *uuid.UUID) error {
	query := `
		UPDATE academics.enrollments
		SET roll_number = $2, updated_by = $3, updated_at = NOW(),
		    version = version + 1
		WHERE enrollment_id = $1 AND deleted_at IS NULL
	`
	result, err := db.ExecContext(ctx, query, id, rollNumber, updatedBy)
	if err != nil {
		r.logger.Error("failed to update roll number",
			util.String("id", id.String()),
			util.String("roll_number", rollNumber),
			util.ErrorField(err))
		return fmt.Errorf("update roll number: %w", err)
	}
	rows, _ := result.RowsAffected()
	if rows == 0 {
		return fmt.Errorf("enrollment %s not found or deleted", id)
	}
	return nil
}

// Delete soft-deletes an enrollment.
func (r *enrollmentRepository) Delete(ctx context.Context, db DBTX, id uuid.UUID, deletedBy *uuid.UUID) error {
	query := `
		UPDATE academics.enrollments
		SET deleted_at = NOW(), updated_by = $2, updated_at = NOW(),
		    version = version + 1
		WHERE enrollment_id = $1 AND deleted_at IS NULL
	`
	result, err := db.ExecContext(ctx, query, id, deletedBy)
	if err != nil {
		r.logger.Error("failed to delete enrollment",
			util.String("id", id.String()),
			util.ErrorField(err))
		return fmt.Errorf("delete enrollment: %w", err)
	}
	rows, _ := result.RowsAffected()
	if rows == 0 {
		return fmt.Errorf("enrollment %s not found or already deleted", id)
	}
	return nil
}

// Exists checks if an enrollment exists for given student and academic year.
func (r *enrollmentRepository) Exists(ctx context.Context, db DBTX, studentID, academicYearID uuid.UUID) (bool, error) {
	query := `
		SELECT EXISTS(
			SELECT 1 FROM academics.enrollments
			WHERE student_id = $1 AND academic_year_id = $2 AND deleted_at IS NULL
		)
	`
	var exists bool
	err := db.QueryRowContext(ctx, query, studentID, academicYearID).Scan(&exists)
	if err != nil {
		r.logger.Error("failed to check existence",
			util.String("student_id", studentID.String()),
			util.String("academic_year_id", academicYearID.String()),
			util.ErrorField(err))
		return false, fmt.Errorf("exists enrollment: %w", err)
	}
	return exists, nil
}

// CountBySection returns total enrollments in a section (including non-active).
func (r *enrollmentRepository) CountBySection(ctx context.Context, db DBTX, sectionID uuid.UUID) (int64, error) {
	query := `SELECT COUNT(*) FROM academics.enrollments WHERE section_id = $1 AND deleted_at IS NULL`
	var count int64
	err := db.QueryRowContext(ctx, query, sectionID).Scan(&count)
	if err != nil {
		r.logger.Error("failed to count enrollments by section",
			zap.String("section_id", sectionID.String()),
			zap.Error(err))
		return 0, fmt.Errorf("count enrollments by section: %w", err)
	}
	return count, nil
}

// CountByAcademicYear returns number of enrollments in an academic year.
func (r *enrollmentRepository) CountByAcademicYear(ctx context.Context, db DBTX, academicYearID uuid.UUID) (int64, error) {
	query := `SELECT COUNT(*) FROM academics.enrollments WHERE academic_year_id = $1 AND deleted_at IS NULL`
	var count int64
	err := db.QueryRowContext(ctx, query, academicYearID).Scan(&count)
	if err != nil {
		r.logger.Error("failed to count enrollments by academic year",
			zap.String("academic_year_id", academicYearID.String()),
			zap.Error(err))
		return 0, fmt.Errorf("count by academic year: %w", err)
	}
	return count, nil
}

// Search performs a full-text search on roll_number (with ILIKE) and filters by company.
func (r *enrollmentRepository) Search(ctx context.Context, db DBTX, query string, companyID uuid.UUID, p Pagination) ([]*models.Enrollment, error) {
	limit, offset := r.validatePagination(p)
	sqlQuery := `
		SELECT e.enrollment_id, e.student_id, e.academic_year_id, e.section_id,
		       e.enrollment_date, e.roll_number, e.status, e.version,
		       e.created_at, e.updated_at, e.created_by, e.updated_by
		FROM academics.enrollments e
		JOIN academics.students s ON e.student_id = s.student_id
		WHERE s.company_id = $1
		  AND e.deleted_at IS NULL
		  AND e.roll_number ILIKE $2
		ORDER BY e.roll_number ASC
		LIMIT $3 OFFSET $4
	`
	rows, err := db.QueryContext(ctx, sqlQuery, companyID, "%"+query+"%", limit, offset)
	if err != nil {
		r.logger.Error("failed to search enrollments",
			util.String("company_id", companyID.String()),
			util.String("query", query),
			util.ErrorField(err))
		return nil, fmt.Errorf("search enrollments: %w", err)
	}
	defer rows.Close()

	var result []*models.Enrollment
	for rows.Next() {
		var e models.Enrollment
		var createdBy, updatedBy uuid.NullUUID
		if err := rows.Scan(
			&e.EnrollmentID, &e.StudentID, &e.AcademicYearID, &e.SectionID,
			&e.EnrollmentDate, &e.RollNumber, &e.Status, &e.Version,
			&e.CreatedAt, &e.UpdatedAt, &createdBy, &updatedBy,
		); err != nil {
			return nil, fmt.Errorf("scan enrollment: %w", err)
		}
		if createdBy.Valid {
			e.CreatedBy = &createdBy.UUID
		}
		if updatedBy.Valid {
			e.UpdatedBy = &updatedBy.UUID
		}
		result = append(result, &e)
	}
	if err = rows.Err(); err != nil {
		return nil, fmt.Errorf("rows iteration: %w", err)
	}
	return result, nil
}

// BulkUpdateStatus updates status for multiple enrollments in a transaction.
func (r *enrollmentRepository) BulkUpdateStatus(ctx context.Context, db DBTX, ids []uuid.UUID, status string, updatedBy *uuid.UUID) error {
	if len(ids) == 0 {
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

	placeholders := make([]string, len(ids))
	args := make([]interface{}, len(ids)+2)
	args[0] = status
	args[1] = updatedBy
	for i, id := range ids {
		placeholders[i] = fmt.Sprintf("$%d", i+3)
		args[i+2] = id
	}
	query := fmt.Sprintf(`
		UPDATE academics.enrollments
		SET status = $1, updated_by = $2, updated_at = NOW(),
		    version = version + 1
		WHERE enrollment_id IN (%s) AND deleted_at IS NULL
	`, strings.Join(placeholders, ","))
	result, err := tx.ExecContext(ctx, query, args...)
	if err != nil {
		r.logger.Error("failed to bulk update enrollment status",
			zap.Int("count", len(ids)),
			zap.String("status", status),
			util.ErrorField(err))
		return fmt.Errorf("bulk update status: %w", err)
	}
	rows, _ := result.RowsAffected()
	if rows == 0 {
		return fmt.Errorf("no enrollments updated")
	}
	if isOwner {
		if err = tx.Commit(); err != nil {
			return fmt.Errorf("commit tx: %w", err)
		}
		needRollback = false
	}
	return nil
}

// BulkAssignRollNumbers assigns roll numbers to multiple enrollments.
// Fixed: proper slice allocation and case-when update.
func (r *enrollmentRepository) BulkAssignRollNumbers(ctx context.Context, db DBTX, data map[uuid.UUID]string, updatedBy *uuid.UUID) error {
	if len(data) == 0 {
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

	// Prepare placeholders and arguments
	ids := make([]uuid.UUID, 0, len(data))
	rollNumbers := make([]string, 0, len(data))
	placeholders := make([]string, 0, len(data))
	args := make([]interface{}, 0, len(data)*2+1)
	args = append(args, updatedBy) // $1
	idx := 2

	for id, roll := range data {
		ids = append(ids, id)
		rollNumbers = append(rollNumbers, roll)
		placeholders = append(placeholders, fmt.Sprintf("$%d::uuid", idx))
		args = append(args, id)
		idx++
	}
	// Build the CASE WHEN part
	caseWhen := "CASE enrollment_id"
	for i, _ := range ids {
		caseWhen += fmt.Sprintf(" WHEN $%d::uuid THEN $%d", i+2, len(data)+i+2)
		args = append(args, rollNumbers[i])
	}
	caseWhen += " END"

	query := fmt.Sprintf(`
		UPDATE academics.enrollments
		SET roll_number = %s, updated_by = $1, updated_at = NOW(),
		    version = version + 1
		WHERE enrollment_id IN (%s) AND deleted_at IS NULL
	`, caseWhen, strings.Join(placeholders, ","))
	result, err := tx.ExecContext(ctx, query, args...)
	if err != nil {
		r.logger.Error("failed to bulk assign roll numbers",
			zap.Int("count", len(data)),
			util.ErrorField(err))
		return fmt.Errorf("bulk assign roll numbers: %w", err)
	}
	rows, _ := result.RowsAffected()
	if int(rows) != len(data) {
		r.logger.Warn("some enrollments not updated",
			zap.Int("expected", len(data)),
			zap.Int64("updated", rows))
	}
	if isOwner {
		if err = tx.Commit(); err != nil {
			return fmt.Errorf("commit tx: %w", err)
		}
		needRollback = false
	}
	return nil
}

// GetBySectionForPromotion retrieves active enrollments for a section to be promoted.
func (r *enrollmentRepository) GetBySectionForPromotion(ctx context.Context, db DBTX, sectionID uuid.UUID) ([]*models.Enrollment, error) {
	query := `
		SELECT enrollment_id, student_id, academic_year_id, section_id,
		       enrollment_date, roll_number, status, version,
		       created_at, updated_at, created_by, updated_by
		FROM academics.enrollments
		WHERE section_id = $1 AND status = $2 AND deleted_at IS NULL
		ORDER BY roll_number ASC
	`
	rows, err := db.QueryContext(ctx, query, sectionID, EnrollmentStatusActive)
	if err != nil {
		r.logger.Error("failed to get enrollments for promotion",
			util.String("section_id", sectionID.String()),
			util.ErrorField(err))
		return nil, fmt.Errorf("get by section for promotion: %w", err)
	}
	defer rows.Close()

	var result []*models.Enrollment
	for rows.Next() {
		var e models.Enrollment
		var createdBy, updatedBy uuid.NullUUID
		if err := rows.Scan(
			&e.EnrollmentID, &e.StudentID, &e.AcademicYearID, &e.SectionID,
			&e.EnrollmentDate, &e.RollNumber, &e.Status, &e.Version,
			&e.CreatedAt, &e.UpdatedAt, &createdBy, &updatedBy,
		); err != nil {
			return nil, fmt.Errorf("scan enrollment: %w", err)
		}
		if createdBy.Valid {
			e.CreatedBy = &createdBy.UUID
		}
		if updatedBy.Valid {
			e.UpdatedBy = &updatedBy.UUID
		}
		result = append(result, &e)
	}
	if err = rows.Err(); err != nil {
		return nil, fmt.Errorf("rows iteration: %w", err)
	}
	return result, nil
}

// FindDuplicates returns enrollments that violate the unique constraint for a given academic year.
func (r *enrollmentRepository) FindDuplicates(ctx context.Context, db DBTX, academicYearID uuid.UUID) ([]*models.Enrollment, error) {
	query := `
		SELECT e.enrollment_id, e.student_id, e.academic_year_id, e.section_id,
		       e.enrollment_date, e.roll_number, e.status, e.version,
		       e.created_at, e.updated_at, e.created_by, e.updated_by
		FROM academics.enrollments e
		WHERE e.academic_year_id = $1
		  AND e.deleted_at IS NULL
		  AND EXISTS (
		    SELECT 1
		    FROM academics.enrollments e2
		    WHERE e2.student_id = e.student_id
		      AND e2.academic_year_id = e.academic_year_id
		      AND e2.enrollment_id != e.enrollment_id
		      AND e2.deleted_at IS NULL
		  )
		ORDER BY e.student_id, e.created_at
	`
	rows, err := db.QueryContext(ctx, query, academicYearID)
	if err != nil {
		r.logger.Error("failed to find duplicate enrollments",
			util.String("academic_year_id", academicYearID.String()),
			util.ErrorField(err))
		return nil, fmt.Errorf("find duplicates: %w", err)
	}
	defer rows.Close()

	var result []*models.Enrollment
	for rows.Next() {
		var e models.Enrollment
		var createdBy, updatedBy uuid.NullUUID
		if err := rows.Scan(
			&e.EnrollmentID, &e.StudentID, &e.AcademicYearID, &e.SectionID,
			&e.EnrollmentDate, &e.RollNumber, &e.Status, &e.Version,
			&e.CreatedAt, &e.UpdatedAt, &createdBy, &updatedBy,
		); err != nil {
			return nil, fmt.Errorf("scan enrollment: %w", err)
		}
		if createdBy.Valid {
			e.CreatedBy = &createdBy.UUID
		}
		if updatedBy.Valid {
			e.UpdatedBy = &updatedBy.UUID
		}
		result = append(result, &e)
	}
	if err = rows.Err(); err != nil {
		return nil, fmt.Errorf("rows iteration: %w", err)
	}
	return result, nil
}

// --- New methods from second interface (with company isolation) ---

// CountActiveBySection returns the number of active enrollments in a section.
func (r *enrollmentRepository) CountActiveBySection(ctx context.Context, db DBTX, sectionID uuid.UUID) (int64, error) {
	query := `SELECT COUNT(*) FROM academics.enrollments WHERE section_id = $1 AND status = $2 AND deleted_at IS NULL`
	var count int64
	err := db.QueryRowContext(ctx, query, sectionID, EnrollmentStatusActive).Scan(&count)
	if err != nil {
		r.logger.Error("failed to count active enrollments by section",
			zap.String("section_id", sectionID.String()),
			zap.Error(err))
		return 0, fmt.Errorf("count active enrollments by section: %w", err)
	}
	return count, nil
}

// CountActiveByStudent returns the number of active enrollments for a student.
func (r *enrollmentRepository) CountActiveByStudent(ctx context.Context, db DBTX, studentID uuid.UUID) (int64, error) {
	query := `SELECT COUNT(*) FROM academics.enrollments WHERE student_id = $1 AND status = $2 AND deleted_at IS NULL`
	var count int64
	err := db.QueryRowContext(ctx, query, studentID, EnrollmentStatusActive).Scan(&count)
	if err != nil {
		r.logger.Error("failed to count active enrollments by student",
			zap.String("student_id", studentID.String()),
			zap.Error(err))
		return 0, fmt.Errorf("count active enrollments by student: %w", err)
	}
	return count, nil
}

// CompleteActiveEnrollment sets the status of the active enrollment for a given student and academic year to 'completed'.
// Enforces company isolation by joining with students.
func (r *enrollmentRepository) CompleteActiveEnrollment(ctx context.Context, tx *sql.Tx, companyID, studentID, academicYearID uuid.UUID, updatedBy *uuid.UUID) error {
	query := `
		UPDATE academics.enrollments e
		SET status = $1, updated_at = NOW(), updated_by = $4, version = version + 1
		FROM academics.students s
		WHERE e.student_id = s.student_id
		  AND e.student_id = $2
		  AND e.academic_year_id = $3
		  AND e.status = $5
		  AND e.deleted_at IS NULL
		  AND s.company_id = $6
	`
	result, err := tx.ExecContext(ctx, query,
		EnrollmentStatusCompleted, studentID, academicYearID, updatedBy,
		EnrollmentStatusActive, companyID,
	)
	if err != nil {
		r.logger.Error("failed to complete active enrollment",
			zap.String("company_id", companyID.String()),
			zap.String("student_id", studentID.String()),
			zap.String("academic_year_id", academicYearID.String()),
			zap.Error(err))
		return fmt.Errorf("complete active enrollment: %w", err)
	}
	rows, err := result.RowsAffected()
	if err != nil {
		return fmt.Errorf("rows affected: %w", err)
	}
	if rows == 0 {
		return sql.ErrNoRows
	}
	return nil
}

// CompleteAllActiveEnrollments sets all active enrollments for a student to 'completed'.
func (r *enrollmentRepository) CompleteAllActiveEnrollments(ctx context.Context, tx *sql.Tx, companyID, studentID uuid.UUID, updatedBy *uuid.UUID) error {
	query := `
		UPDATE academics.enrollments e
		SET status = $1, updated_at = NOW(), updated_by = $3, version = version + 1
		FROM academics.students s
		WHERE e.student_id = s.student_id
		  AND e.student_id = $2
		  AND e.status = $4
		  AND e.deleted_at IS NULL
		  AND s.company_id = $5
	`
	_, err := tx.ExecContext(ctx, query,
		EnrollmentStatusCompleted, studentID, updatedBy, EnrollmentStatusActive, companyID,
	)
	if err != nil {
		r.logger.Error("failed to complete all active enrollments",
			zap.String("company_id", companyID.String()),
			zap.String("student_id", studentID.String()),
			zap.Error(err))
		return fmt.Errorf("complete all active enrollments: %w", err)
	}
	return nil
}

// WithdrawAllActiveEnrollments sets all active enrollments for a student to 'withdrawn'.
func (r *enrollmentRepository) WithdrawAllActiveEnrollments(ctx context.Context, tx *sql.Tx, companyID, studentID uuid.UUID, updatedBy *uuid.UUID) error {
	query := `
		UPDATE academics.enrollments e
		SET status = $1, updated_at = NOW(), updated_by = $3, version = version + 1
		FROM academics.students s
		WHERE e.student_id = s.student_id
		  AND e.student_id = $2
		  AND e.status = $4
		  AND e.deleted_at IS NULL
		  AND s.company_id = $5
	`
	_, err := tx.ExecContext(ctx, query,
		EnrollmentStatusWithdrawn, studentID, updatedBy, EnrollmentStatusActive, companyID,
	)
	if err != nil {
		r.logger.Error("failed to withdraw all active enrollments",
			zap.String("company_id", companyID.String()),
			zap.String("student_id", studentID.String()),
			zap.Error(err))
		return fmt.Errorf("withdraw all active enrollments: %w", err)
	}
	return nil
}

// CreateEnrollment creates a new enrollment record.
// It prevents duplicate active enrollment for the same student and academic year via ON CONFLICT.
func (r *enrollmentRepository) CreateEnrollment(ctx context.Context, tx *sql.Tx, companyID, studentID, academicYearID, sectionID uuid.UUID, createdBy, updatedBy *uuid.UUID) (uuid.UUID, error) {
	query := `
		INSERT INTO academics.enrollments (
			student_id, academic_year_id, section_id, enrollment_date, status,
			version, created_by, updated_by, created_at, updated_at
		) VALUES ($1, $2, $3, NOW(), $4, 0, $5, $6, NOW(), NOW())
		ON CONFLICT (student_id, academic_year_id) WHERE status = $4 AND deleted_at IS NULL
		DO NOTHING
		RETURNING enrollment_id
	`
	var enrollmentID uuid.UUID
	err := tx.QueryRowContext(ctx, query,
		studentID, academicYearID, sectionID, EnrollmentStatusActive, createdBy, updatedBy,
	).Scan(&enrollmentID)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return uuid.Nil, errors.New("active enrollment already exists for this academic year")
		}
		r.logger.Error("failed to create enrollment",
			zap.String("company_id", companyID.String()),
			zap.String("student_id", studentID.String()),
			zap.String("section_id", sectionID.String()),
			zap.Error(err))
		return uuid.Nil, fmt.Errorf("create enrollment: %w", err)
	}
	return enrollmentID, nil
}

// GetActiveEnrollmentForUpdate retrieves an active enrollment for a student and academic year with row lock.
func (r *enrollmentRepository) GetActiveEnrollmentForUpdate(ctx context.Context, tx *sql.Tx, companyID, studentID, academicYearID uuid.UUID) (*models.Enrollment, error) {
	query := `
		SELECT e.enrollment_id, e.student_id, e.academic_year_id, e.section_id,
		       e.enrollment_date, e.roll_number, e.status, e.version,
		       e.created_at, e.updated_at, e.created_by, e.updated_by
		FROM academics.enrollments e
		JOIN academics.students s ON e.student_id = s.student_id
		WHERE e.student_id = $1
		  AND e.academic_year_id = $2
		  AND e.status = $3
		  AND e.deleted_at IS NULL
		  AND s.company_id = $4
		FOR UPDATE
	`
	var e models.Enrollment
	var createdBy, updatedBy uuid.NullUUID
	err := tx.QueryRowContext(ctx, query, studentID, academicYearID, EnrollmentStatusActive, companyID).Scan(
		&e.EnrollmentID, &e.StudentID, &e.AcademicYearID, &e.SectionID,
		&e.EnrollmentDate, &e.RollNumber, &e.Status, &e.Version,
		&e.CreatedAt, &e.UpdatedAt, &createdBy, &updatedBy,
	)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, nil
		}
		r.logger.Error("failed to get active enrollment for update",
			zap.String("company_id", companyID.String()),
			zap.String("student_id", studentID.String()),
			zap.String("academic_year_id", academicYearID.String()),
			zap.Error(err))
		return nil, fmt.Errorf("get active enrollment for update: %w", err)
	}
	if createdBy.Valid {
		e.CreatedBy = &createdBy.UUID
	}
	if updatedBy.Valid {
		e.UpdatedBy = &updatedBy.UUID
	}
	return &e, nil
}

// GetActiveCountForSectionForUpdate returns the number of active enrollments in a section with row lock.
func (r *enrollmentRepository) GetActiveCountForSectionForUpdate(ctx context.Context, tx *sql.Tx, companyID, sectionID uuid.UUID) (int64, error) {
	query := `
		SELECT COUNT(*)
		FROM academics.enrollments e
		JOIN academics.section sec ON e.section_id = sec.section_id
		JOIN academics.course c ON sec.course_id = c.course_id
		WHERE e.section_id = $1
		  AND e.status = $2
		  AND e.deleted_at IS NULL
		  AND c.company_id = $3
		FOR UPDATE
	`
	var count int64
	err := tx.QueryRowContext(ctx, query, sectionID, EnrollmentStatusActive, companyID).Scan(&count)
	if err != nil {
		r.logger.Error("failed to count active enrollments for update",
			zap.String("company_id", companyID.String()),
			zap.String("section_id", sectionID.String()),
			zap.Error(err))
		return 0, fmt.Errorf("count active enrollments for update: %w", err)
	}
	return count, nil
}

// ExistsActiveEnrollment checks if a student already has an active enrollment in the given academic year.
func (r *enrollmentRepository) ExistsActiveEnrollment(ctx context.Context, db DBTX, companyID, studentID, academicYearID uuid.UUID) (bool, error) {
	query := `
		SELECT EXISTS(
			SELECT 1
			FROM academics.enrollments e
			JOIN academics.students s ON e.student_id = s.student_id
			WHERE e.student_id = $1
			  AND e.academic_year_id = $2
			  AND e.status = $3
			  AND e.deleted_at IS NULL
			  AND s.company_id = $4
		)
	`
	var exists bool
	err := db.QueryRowContext(ctx, query, studentID, academicYearID, EnrollmentStatusActive, companyID).Scan(&exists)
	if err != nil {
		r.logger.Error("failed to check active enrollment existence",
			zap.String("company_id", companyID.String()),
			zap.String("student_id", studentID.String()),
			zap.String("academic_year_id", academicYearID.String()),
			zap.Error(err))
		return false, fmt.Errorf("exists active enrollment: %w", err)
	}
	return exists, nil
}

// GetByIDUnsafe retrieves an enrollment by its ID without joining with students.
// This bypasses company isolation and should only be used when the calling code
// has already verified the enrollment belongs to the correct company.
func (r *enrollmentRepository) GetByIDUnsafe(ctx context.Context, db DBTX, id uuid.UUID) (*models.Enrollment, error) {
	query := `
        SELECT enrollment_id, student_id, academic_year_id, section_id,
               enrollment_date, roll_number, status, version,
               created_at, updated_at, created_by, updated_by
        FROM academics.enrollments
        WHERE enrollment_id = $1 AND deleted_at IS NULL
    `
	var e models.Enrollment
	var createdBy, updatedBy uuid.NullUUID
	err := db.QueryRowContext(ctx, query, id).Scan(
		&e.EnrollmentID, &e.StudentID, &e.AcademicYearID, &e.SectionID,
		&e.EnrollmentDate, &e.RollNumber, &e.Status, &e.Version,
		&e.CreatedAt, &e.UpdatedAt, &createdBy, &updatedBy,
	)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, nil
		}
		r.logger.Error("failed to get enrollment by ID (unsafe)",
			zap.String("id", id.String()),
			zap.Error(err))
		return nil, fmt.Errorf("get enrollment by ID unsafe: %w", err)
	}
	if createdBy.Valid {
		e.CreatedBy = &createdBy.UUID
	}
	if updatedBy.Valid {
		e.UpdatedBy = &updatedBy.UUID
	}
	return &e, nil
}

// GetByIDForUpdateUnsafe retrieves an enrollment by its ID with a row lock,
// without joining with students. Use this only when company isolation is already
// guaranteed (e.g., inside a transaction where the row was previously locked).
func (r *enrollmentRepository) GetByIDForUpdateUnsafe(ctx context.Context, tx *sql.Tx, id uuid.UUID) (*models.Enrollment, error) {
	query := `
        SELECT enrollment_id, student_id, academic_year_id, section_id,
               enrollment_date, roll_number, status, version,
               created_at, updated_at, created_by, updated_by
        FROM academics.enrollments
        WHERE enrollment_id = $1 AND deleted_at IS NULL
        FOR UPDATE
    `
	var e models.Enrollment
	var createdBy, updatedBy uuid.NullUUID
	err := tx.QueryRowContext(ctx, query, id).Scan(
		&e.EnrollmentID, &e.StudentID, &e.AcademicYearID, &e.SectionID,
		&e.EnrollmentDate, &e.RollNumber, &e.Status, &e.Version,
		&e.CreatedAt, &e.UpdatedAt, &createdBy, &updatedBy,
	)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, nil
		}
		r.logger.Error("failed to get enrollment for update (unsafe)",
			zap.String("id", id.String()),
			zap.Error(err))
		return nil, fmt.Errorf("get enrollment for update unsafe: %w", err)
	}
	if createdBy.Valid {
		e.CreatedBy = &createdBy.UUID
	}
	if updatedBy.Valid {
		e.UpdatedBy = &updatedBy.UUID
	}
	return &e, nil
}

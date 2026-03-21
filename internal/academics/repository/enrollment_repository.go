package repository

import (
	"context"
	"database/sql"
	"errors"
	"fmt"

	"github.com/google/uuid"
	"go.uber.org/zap"

	"auth-service/internal/academics/models" // ✅ added import
)

type EnrollmentRepository interface {
	CountBySection(ctx context.Context, db DBTX, sectionID uuid.UUID) (int64, error)
	CountActiveBySection(ctx context.Context, db DBTX, sectionID uuid.UUID) (int64, error)
	CountActiveByStudent(ctx context.Context, db DBTX, studentID uuid.UUID) (int64, error)

	// transaction-aware operations
	CompleteActiveEnrollment(ctx context.Context, tx *sql.Tx, studentID, academicYearID uuid.UUID, updatedBy *uuid.UUID) error
	CompleteAllActiveEnrollments(ctx context.Context, tx *sql.Tx, studentID uuid.UUID, updatedBy *uuid.UUID) error
	WithdrawAllActiveEnrollments(ctx context.Context, tx *sql.Tx, studentID uuid.UUID, updatedBy *uuid.UUID) error
	CreateEnrollment(ctx context.Context, tx *sql.Tx, studentID, academicYearID, sectionID uuid.UUID, createdBy, updatedBy *uuid.UUID) (uuid.UUID, error)
	GetActiveEnrollmentForUpdate(ctx context.Context, tx *sql.Tx, studentID, academicYearID uuid.UUID) (*models.Enrollment, error)
}

type enrollmentRepository struct {
	logger *zap.Logger
}

func NewEnrollmentRepository(logger *zap.Logger) EnrollmentRepository {
	return &enrollmentRepository{
		logger: logger.Named("enrollment_repo"),
	}
}

// Existing methods (unchanged)
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

func (r *enrollmentRepository) CountActiveBySection(ctx context.Context, db DBTX, sectionID uuid.UUID) (int64, error) {
	query := `SELECT COUNT(*) FROM academics.enrollments WHERE section_id = $1 AND status = 'active' AND deleted_at IS NULL`
	var count int64
	err := db.QueryRowContext(ctx, query, sectionID).Scan(&count)
	if err != nil {
		r.logger.Error("failed to count active enrollments by section",
			zap.String("section_id", sectionID.String()),
			zap.Error(err))
		return 0, fmt.Errorf("count active enrollments by section: %w", err)
	}
	return count, nil
}

func (r *enrollmentRepository) CountActiveByStudent(ctx context.Context, db DBTX, studentID uuid.UUID) (int64, error) {
	query := `SELECT COUNT(*) FROM academics.enrollments WHERE student_id = $1 AND status = 'active' AND deleted_at IS NULL`
	var count int64
	err := db.QueryRowContext(ctx, query, studentID).Scan(&count)
	if err != nil {
		r.logger.Error("failed to count active enrollments by student",
			zap.String("student_id", studentID.String()),
			zap.Error(err))
		return 0, fmt.Errorf("count active enrollments by student: %w", err)
	}
	return count, nil
}

// New methods

// CompleteActiveEnrollment sets the status of the active enrollment for a given student and academic year to 'completed'.
// If no such enrollment exists, returns sql.ErrNoRows (caller can ignore if needed).
func (r *enrollmentRepository) CompleteActiveEnrollment(ctx context.Context, tx *sql.Tx, studentID, academicYearID uuid.UUID, updatedBy *uuid.UUID) error {
	query := `
		UPDATE academics.enrollments
		SET status = 'completed', updated_at = NOW(), updated_by = $3
		WHERE student_id = $1 AND academic_year_id = $2 AND status = 'active' AND deleted_at IS NULL
	`
	result, err := tx.ExecContext(ctx, query, studentID, academicYearID, updatedBy)
	if err != nil {
		r.logger.Error("failed to complete active enrollment",
			zap.String("student_id", studentID.String()),
			zap.String("academic_year_id", academicYearID.String()),
			zap.Error(err))
		return fmt.Errorf("complete active enrollment: %w", err)
	}
	rows, _ := result.RowsAffected()
	if rows == 0 {
		return sql.ErrNoRows
	}
	return nil
}

// CompleteAllActiveEnrollments sets all active enrollments for a student to 'completed'.
func (r *enrollmentRepository) CompleteAllActiveEnrollments(ctx context.Context, tx *sql.Tx, studentID uuid.UUID, updatedBy *uuid.UUID) error {
	query := `
		UPDATE academics.enrollments
		SET status = 'completed', updated_at = NOW(), updated_by = $2
		WHERE student_id = $1 AND status = 'active' AND deleted_at IS NULL
	`
	_, err := tx.ExecContext(ctx, query, studentID, updatedBy)
	if err != nil {
		r.logger.Error("failed to complete all active enrollments",
			zap.String("student_id", studentID.String()),
			zap.Error(err))
		return fmt.Errorf("complete all active enrollments: %w", err)
	}
	return nil
}

// WithdrawAllActiveEnrollments sets all active enrollments for a student to 'withdrawn'.
func (r *enrollmentRepository) WithdrawAllActiveEnrollments(ctx context.Context, tx *sql.Tx, studentID uuid.UUID, updatedBy *uuid.UUID) error {
	query := `
		UPDATE academics.enrollments
		SET status = 'withdrawn', updated_at = NOW(), updated_by = $2
		WHERE student_id = $1 AND status = 'active' AND deleted_at IS NULL
	`
	_, err := tx.ExecContext(ctx, query, studentID, updatedBy)
	if err != nil {
		r.logger.Error("failed to withdraw all active enrollments",
			zap.String("student_id", studentID.String()),
			zap.Error(err))
		return fmt.Errorf("withdraw all active enrollments: %w", err)
	}
	return nil
}

// CreateEnrollment creates a new enrollment record.
func (r *enrollmentRepository) CreateEnrollment(ctx context.Context, tx *sql.Tx, studentID, academicYearID, sectionID uuid.UUID, createdBy, updatedBy *uuid.UUID) (uuid.UUID, error) {
	query := `
		INSERT INTO academics.enrollments (
			student_id, academic_year_id, section_id, enrollment_date, status,
			created_by, updated_by, created_at, updated_at
		) VALUES ($1, $2, $3, NOW(), 'active', $4, $5, NOW(), NOW())
		RETURNING enrollment_id
	`
	var enrollmentID uuid.UUID
	err := tx.QueryRowContext(ctx, query, studentID, academicYearID, sectionID, createdBy, updatedBy).Scan(&enrollmentID)
	if err != nil {
		r.logger.Error("failed to create enrollment",
			zap.String("student_id", studentID.String()),
			zap.String("section_id", sectionID.String()),
			zap.Error(err))
		return uuid.Nil, fmt.Errorf("create enrollment: %w", err)
	}
	return enrollmentID, nil
}

// GetActiveEnrollmentForUpdate retrieves an active enrollment for a student and academic year with row lock.
func (r *enrollmentRepository) GetActiveEnrollmentForUpdate(ctx context.Context, tx *sql.Tx, studentID, academicYearID uuid.UUID) (*models.Enrollment, error) {
	query := `
		SELECT enrollment_id, student_id, academic_year_id, section_id, enrollment_date, roll_number, status, version, created_at, updated_at, created_by, updated_by, deleted_at
		FROM academics.enrollments
		WHERE student_id = $1 AND academic_year_id = $2 AND status = 'active' AND deleted_at IS NULL
		FOR UPDATE
	`
	var e models.Enrollment
	err := tx.QueryRowContext(ctx, query, studentID, academicYearID).Scan(
		&e.EnrollmentID, &e.StudentID, &e.AcademicYearID, &e.SectionID, &e.EnrollmentDate,
		&e.RollNumber, &e.Status, &e.Version, &e.CreatedAt, &e.UpdatedAt, &e.CreatedBy, &e.UpdatedBy, &e.DeletedAt,
	)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, nil
		}
		return nil, fmt.Errorf("get active enrollment for update: %w", err)
	}
	return &e, nil
}

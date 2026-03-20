package repository

import (
	"context"
	"fmt"

	"github.com/google/uuid"
	"go.uber.org/zap"
)

type EnrollmentRepository interface {
	// CountBySection returns total number of enrollments (including all statuses) for a section.
	CountBySection(ctx context.Context, db DBTX, sectionID uuid.UUID) (int64, error)
	// CountActiveBySection returns number of active enrollments in a section.
	CountActiveBySection(ctx context.Context, db DBTX, sectionID uuid.UUID) (int64, error)
	CountActiveByStudent(ctx context.Context, db DBTX, studentID uuid.UUID) (int64, error)
}

type enrollmentRepository struct {
	logger *zap.Logger
}

func NewEnrollmentRepository(logger *zap.Logger) EnrollmentRepository {
	return &enrollmentRepository{
		logger: logger.Named("enrollment_repo"),
	}
}

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

package resolver

import (
	"context"
	"database/sql"

	"github.com/google/uuid"
	"go.uber.org/zap"

	academicsRepo "auth-service/internal/academics/repository"
)

type studentDataProvider struct {
	db          *sql.DB
	studentRepo academicsRepo.StudentRepository
	logger      *zap.Logger
}

func NewStudentDataProvider(db *sql.DB, studentRepo academicsRepo.StudentRepository, logger *zap.Logger) StudentDataProvider {
	return &studentDataProvider{
		db:          db,
		studentRepo: studentRepo,
		logger:      logger,
	}
}

func (p *studentDataProvider) GetStudent(ctx context.Context, companyID, studentID uuid.UUID) (active bool, err error) {
	p.logger.Info("GetStudent called",
		zap.String("company_id", companyID.String()),
		zap.String("student_id", studentID.String()),
	)

	student, err := p.studentRepo.GetByID(ctx, p.db, studentID)
	if err != nil {
		p.logger.Error("GetByID failed", zap.Error(err))
		return false, err
	}
	if student == nil {
		p.logger.Warn("Student not found", zap.String("student_id", studentID.String()))
		return false, nil
	}
	if student.CompanyID != companyID {
		p.logger.Warn("Student belongs to different company",
			zap.String("student_id", studentID.String()),
			zap.String("actual_company", student.CompanyID.String()),
		)
		return false, nil
	}
	// Convert StudentStatus to string for logging
	if student.Status != "active" {
		p.logger.Warn("Student inactive",
			zap.String("student_id", studentID.String()),
			zap.String("status", string(student.Status)), // ✅ convert to string
		)
		return false, nil
	}

	p.logger.Info("Student found and active", zap.String("student_id", studentID.String()))
	return true, nil
}

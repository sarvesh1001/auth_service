package resolver

import (
	"context"
	"database/sql"
	"time"

	"github.com/google/uuid"
	"go.uber.org/zap"

	academicsRepo "auth-service/internal/academics/repository"
)

type enrollmentDataProvider struct {
	db             *sql.DB
	enrollmentRepo academicsRepo.EnrollmentRepository
	logger         *zap.Logger
}

func NewEnrollmentDataProvider(db *sql.DB, enrollmentRepo academicsRepo.EnrollmentRepository, logger *zap.Logger) EnrollmentDataProvider {
	return &enrollmentDataProvider{
		db:             db,
		enrollmentRepo: enrollmentRepo,
		logger:         logger,
	}
}

func (p *enrollmentDataProvider) GetActiveEnrollment(ctx context.Context, companyID, studentID uuid.UUID, date time.Time) (sectionID *uuid.UUID, academicYearID *uuid.UUID, err error) {
	enrollment, err := p.enrollmentRepo.GetActiveEnrollmentByStudentOnDate(ctx, p.db, companyID, studentID, date)
	if err != nil {
		p.logger.Error("GetActiveEnrollmentByStudentOnDate failed", zap.Error(err))
		return nil, nil, err
	}
	if enrollment == nil {
		p.logger.Warn("No active enrollment on date")
		return nil, nil, nil
	}
	return &enrollment.SectionID, &enrollment.AcademicYearID, nil
}

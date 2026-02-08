package service

import (
	"auth-service/internal/hr/models/attendance"
	"auth-service/internal/hr/repository"
	"context"
	"errors"
	"strings"
	"time"

	"github.com/google/uuid"
	"go.uber.org/zap"
)

// =====================================================
// SERVICE INTERFACE
// =====================================================

type AttendanceSourceAdminService interface {

	// List all sources for a company
	GetSourcesByCompany(
		ctx context.Context,
		companyID uuid.UUID,
		activeOnly bool,
	) ([]*attendance.AttendanceSource, error)

	// Explicit admin create (OPTION 2)
	CreateSource(
		ctx context.Context,
		companyID uuid.UUID,
		sourceType string,
		name string,
		actor *uuid.UUID,
	) (*attendance.AttendanceSource, error)

	// Enable / Disable source
	UpdateSourceStatus(
		ctx context.Context,
		companyID uuid.UUID,
		sourceType string,
		isActive bool,
		actor *uuid.UUID,
	) error
}

// =====================================================
// IMPLEMENTATION
// =====================================================

type attendanceSourceAdminService struct {
	attendanceRepo repository.AttendanceRepository
	auditService   *AuditService
	logger         *zap.Logger
}

func NewAttendanceSourceAdminService(
	attendanceRepo repository.AttendanceRepository,
	auditService *AuditService,
	logger *zap.Logger,
) AttendanceSourceAdminService {
	return &attendanceSourceAdminService{
		attendanceRepo: attendanceRepo,
		auditService:   auditService,
		logger:         logger,
	}
}

// =====================================================
// LIST SOURCES
// =====================================================

func (s *attendanceSourceAdminService) GetSourcesByCompany(
	ctx context.Context,
	companyID uuid.UUID,
	activeOnly bool,
) ([]*attendance.AttendanceSource, error) {

	return s.attendanceRepo.GetAttendanceSourcesByCompany(
		ctx,
		companyID,
		activeOnly,
	)
}

// =====================================================
// CREATE SOURCE (ADMIN / EXPLICIT)
// =====================================================

func (s *attendanceSourceAdminService) CreateSource(
	ctx context.Context,
	companyID uuid.UUID,
	sourceType string,
	name string,
	actor *uuid.UUID,
) (*attendance.AttendanceSource, error) {

	existing, err := s.attendanceRepo.GetAttendanceSourceByCompanyAndType(
		ctx,
		companyID,
		sourceType,
	)
	if err != nil {
		return nil, err
	}
	if existing != nil {
		return nil, errors.New("attendance source already exists")
	}

	if name == "" {
		name = strings.Title(sourceType) + " Attendance"
	}

	source := &attendance.AttendanceSource{
		SourceID:   uuid.New(),
		CompanyID:  companyID,
		SourceType: sourceType,
		Name:       name,
		IsActive:   true,
		CreatedAt:  time.Now().UTC(),
		CreatedBy:  actor,
	}

	if err := s.attendanceRepo.CreateAttendanceSource(ctx, source); err != nil {
		return nil, err
	}

	// Audit
	if s.auditService != nil && actor != nil {
		_ = s.auditService.LogAction(
			ctx,
			&companyID,
			"attendance",
			"attendance_source_created",
			"attendance_source",
			&source.SourceID,
			"admin",
			actor,
			nil,
			nil,
			map[string]interface{}{
				"source_type": sourceType,
				"mode":        "explicit",
			},
		)
	}

	return source, nil
}

// =====================================================
// ENABLE / DISABLE SOURCE
// =====================================================

func (s *attendanceSourceAdminService) UpdateSourceStatus(
	ctx context.Context,
	companyID uuid.UUID,
	sourceType string,
	isActive bool,
	actor *uuid.UUID,
) error {

	source, err := s.attendanceRepo.GetAttendanceSourceByCompanyAndType(
		ctx,
		companyID,
		sourceType,
	)
	if err != nil {
		return err
	}
	if source == nil {
		return errors.New("attendance source not found")
	}

	source.IsActive = isActive

	if err := s.attendanceRepo.UpdateAttendanceSource(ctx, source); err != nil {
		return err
	}

	// Audit
	if s.auditService != nil && actor != nil {
		action := "attendance_source_enabled"
		if !isActive {
			action = "attendance_source_disabled"
		}

		_ = s.auditService.LogAction(
			ctx,
			&companyID,
			"attendance",
			action,
			"attendance_source",
			&source.SourceID,
			"admin",
			actor,
			nil,
			nil,
			map[string]interface{}{
				"source_type": sourceType,
			},
		)
	}

	return nil
}

func timePtr(t time.Time) *time.Time {
	return &t
}

package source

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/google/uuid"
	"go.uber.org/zap"

	"auth-service/internal/attendance/models"
	"auth-service/internal/attendance/repository"
	auditservice "auth-service/internal/infrastructure/audit"
)

// SourceAdminService manages attendance sources (CRUD + enable/disable)
type SourceAdminService interface {
	// GetSourcesByCompany lists all sources for a company
	GetSourcesByCompany(ctx context.Context, companyID uuid.UUID, activeOnly bool) ([]*models.AttendanceSource, error)

	// CreateSource explicitly creates a new attendance source (admin use)
	CreateSource(ctx context.Context, companyID uuid.UUID, sourceType, name string, actor *uuid.UUID) (*models.AttendanceSource, error)

	// UpdateSourceStatus enables or disables a source
	UpdateSourceStatus(ctx context.Context, companyID uuid.UUID, sourceType string, isActive bool, actor *uuid.UUID) error
}

type sourceAdminService struct {
	sourceRepo repository.SourceRepository
	audit      *auditservice.AuditService
	logger     *zap.Logger
}

// NewSourceAdminService creates a new admin service for sources
func NewSourceAdminService(
	sourceRepo repository.SourceRepository,
	audit *auditservice.AuditService,
	logger *zap.Logger,
) SourceAdminService {
	return &sourceAdminService{
		sourceRepo: sourceRepo,
		audit:      audit,
		logger:     logger,
	}
}

// GetSourcesByCompany returns all sources for a company, optionally filtering by active state
func (s *sourceAdminService) GetSourcesByCompany(ctx context.Context, companyID uuid.UUID, activeOnly bool) ([]*models.AttendanceSource, error) {
	if companyID == uuid.Nil {
		return nil, errors.New("company_id is required")
	}
	return s.sourceRepo.GetByCompany(ctx, companyID, activeOnly)
}

// CreateSource explicitly creates a new source. It fails if the source type already exists for the company.
func (s *sourceAdminService) CreateSource(ctx context.Context, companyID uuid.UUID, sourceType, name string, actor *uuid.UUID) (*models.AttendanceSource, error) {
	if companyID == uuid.Nil {
		return nil, errors.New("company_id is required")
	}
	if sourceType == "" {
		return nil, errors.New("source_type is required")
	}

	// Check existing
	existing, err := s.sourceRepo.GetByType(ctx, companyID, sourceType)
	if err != nil {
		return nil, fmt.Errorf("check existing source: %w", err)
	}
	if existing != nil {
		return nil, fmt.Errorf("source type '%s' already exists for company", sourceType)
	}

	if name == "" {
		name = strings.Title(sourceType) + " Attendance"
	}

	source := &models.AttendanceSource{
		SourceID:   uuid.New(),
		CompanyID:  companyID,
		SourceType: sourceType,
		Name:       name,
		IsActive:   true,
		CreatedAt:  time.Now().UTC(),
		CreatedBy:  actor,
	}

	if err := s.sourceRepo.Create(ctx, nil, source); err != nil {
		return nil, fmt.Errorf("create source: %w", err)
	}

	// Audit
	if s.audit != nil && actor != nil {
		_ = s.audit.LogAction(
			ctx,
			nil,
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

	s.logger.Info("Attendance source created",
		zap.String("source_type", sourceType),
		zap.String("company_id", companyID.String()),
	)
	return source, nil
}

// UpdateSourceStatus enables or disables a source
func (s *sourceAdminService) UpdateSourceStatus(ctx context.Context, companyID uuid.UUID, sourceType string, isActive bool, actor *uuid.UUID) error {
	if companyID == uuid.Nil {
		return errors.New("company_id is required")
	}
	if sourceType == "" {
		return errors.New("source_type is required")
	}

	source, err := s.sourceRepo.GetByType(ctx, companyID, sourceType)
	if err != nil {
		return fmt.Errorf("get source: %w", err)
	}
	if source == nil {
		return errors.New("source not found")
	}

	source.IsActive = isActive
	if err := s.sourceRepo.Update(ctx, nil, source); err != nil {
		return fmt.Errorf("update source: %w", err)
	}

	// Audit
	if s.audit != nil && actor != nil {
		action := "attendance_source_enabled"
		if !isActive {
			action = "attendance_source_disabled"
		}
		_ = s.audit.LogAction(
			ctx,
			nil,
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

	s.logger.Info("Attendance source status updated",
		zap.String("source_type", sourceType),
		zap.String("company_id", companyID.String()),
		zap.Bool("is_active", isActive),
	)
	return nil
}

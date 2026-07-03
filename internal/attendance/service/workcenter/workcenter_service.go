package workcenter

import (
	"context"
	"encoding/json"
	"fmt"
	"time"

	"github.com/google/uuid"
	"go.uber.org/zap"

	"auth-service/internal/attendance/models"
	"auth-service/internal/attendance/repository"
	"auth-service/internal/infrastructure/audit"
)

type workcenterService struct {
	repo         repository.WorkCenterRepository
	auditService *audit.AuditService
	logger       *zap.Logger
}

func NewService(
	repo repository.WorkCenterRepository,
	auditService *audit.AuditService,
	logger *zap.Logger,
) Service {
	return &workcenterService{
		repo:         repo,
		auditService: auditService,
		logger:       logger,
	}
}

func (s *workcenterService) CreateWorkCenter(
	ctx context.Context,
	wc *models.WorkCenter,
	actorType string,
	actorID uuid.UUID,
	metadata map[string]interface{},
) (*models.WorkCenter, error) {
	// Validate
	if wc.WorkCenterCode == "" {
		return nil, fmt.Errorf("work center code is required")
	}
	if wc.Name == "" {
		return nil, fmt.Errorf("work center name is required")
	}
	if wc.Timezone == "" {
		wc.Timezone = "UTC"
	}
	if wc.CompanyID == uuid.Nil {
		return nil, fmt.Errorf("company ID is required")
	}

	// Check existence by code
	exists, err := s.repo.Exists(ctx, wc.CompanyID, wc.WorkCenterCode)
	if err != nil {
		return nil, fmt.Errorf("failed to check work center existence: %w", err)
	}
	if exists {
		return nil, fmt.Errorf("work center with code %s already exists", wc.WorkCenterCode)
	}

	// Check name uniqueness
	nameExists, err := s.repo.ExistsByName(ctx, wc.CompanyID, wc.Name)
	if err != nil {
		return nil, fmt.Errorf("failed to check name uniqueness: %w", err)
	}
	if nameExists {
		return nil, fmt.Errorf("work center with name %s already exists in this company", wc.Name)
	}

	now := time.Now().UTC()
	wc.CreatedAt = now
	wc.UpdatedAt = now
	wc.IsActive = true // default

	if err := s.repo.Create(ctx, nil, wc); err != nil {
		return nil, fmt.Errorf("failed to create work center: %w", err)
	}

	// Audit (pass nil for resource UUID, include code in metadata)
	if s.auditService != nil {
		afterJSON, _ := json.Marshal(wc)
		if metadata == nil {
			metadata = make(map[string]interface{})
		}
		metadata["work_center_code"] = wc.WorkCenterCode
		_ = s.auditService.LogAction(ctx, nil, &wc.CompanyID, "workcenter", "create", "workcenter", nil, actorType, &actorID, nil, afterJSON, metadata)
	}

	return wc, nil
}

func (s *workcenterService) UpdateWorkCenter(
	ctx context.Context,
	companyID uuid.UUID,
	code string,
	name, description, timezone *string,
	isActive *bool,
	actorType string,
	actorID uuid.UUID,
	metadata map[string]interface{},
) (*models.WorkCenter, error) {
	if code == "" {
		return nil, fmt.Errorf("work center code is required")
	}
	if companyID == uuid.Nil {
		return nil, fmt.Errorf("company ID is required")
	}

	existing, err := s.repo.GetByCode(ctx, companyID, code)
	if err != nil {
		return nil, fmt.Errorf("failed to get work center: %w", err)
	}
	if existing == nil {
		return nil, fmt.Errorf("work center not found")
	}

	// Check name uniqueness if name is being changed
	if name != nil && *name != existing.Name {
		nameExists, err := s.repo.ExistsByName(ctx, companyID, *name)
		if err != nil {
			return nil, fmt.Errorf("failed to check name uniqueness: %w", err)
		}
		if nameExists {
			return nil, fmt.Errorf("work center with name %s already exists in this company", *name)
		}
	}

	// Apply updates
	if name != nil {
		existing.Name = *name
	}
	if description != nil {
		existing.Description = description
	}
	if timezone != nil {
		existing.Timezone = *timezone
	}
	if isActive != nil {
		existing.IsActive = *isActive
	}
	existing.UpdatedAt = time.Now().UTC()

	beforeJSON, _ := json.Marshal(existing)
	if err := s.repo.Update(ctx, nil, existing); err != nil {
		return nil, fmt.Errorf("failed to update work center: %w", err)
	}
	afterJSON, _ := json.Marshal(existing)

	if s.auditService != nil {
		if metadata == nil {
			metadata = make(map[string]interface{})
		}
		metadata["work_center_code"] = code
		_ = s.auditService.LogAction(ctx, nil, &companyID, "workcenter", "update", "workcenter", nil, actorType, &actorID, beforeJSON, afterJSON, metadata)
	}

	return existing, nil
}

func (s *workcenterService) DeleteWorkCenter(
	ctx context.Context,
	companyID uuid.UUID,
	code string,
	actorType string,
	actorID uuid.UUID,
	metadata map[string]interface{},
) error {
	if code == "" {
		return fmt.Errorf("work center code is required")
	}
	if companyID == uuid.Nil {
		return fmt.Errorf("company ID is required")
	}

	existing, err := s.repo.GetByCode(ctx, companyID, code)
	if err != nil {
		return fmt.Errorf("failed to get work center: %w", err)
	}
	if existing == nil {
		return fmt.Errorf("work center not found")
	}

	beforeJSON, _ := json.Marshal(existing)
	if err := s.repo.Delete(ctx, companyID, code); err != nil {
		return fmt.Errorf("failed to delete work center: %w", err)
	}

	if s.auditService != nil {
		if metadata == nil {
			metadata = make(map[string]interface{})
		}
		metadata["work_center_code"] = code
		_ = s.auditService.LogAction(ctx, nil, &companyID, "workcenter", "delete", "workcenter", nil, actorType, &actorID, beforeJSON, nil, metadata)
	}

	return nil
}

func (s *workcenterService) HealthCheck(ctx context.Context) error {
	return s.repo.HealthCheck(ctx)
}

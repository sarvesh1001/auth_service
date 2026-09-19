package workcenter

import (
	"context"
	"fmt"

	"github.com/google/uuid"

	"auth-service/internal/attendance/models"
	"auth-service/internal/attendance/repository"
)

type workcenterQueryService struct {
	repo repository.WorkCenterRepository
}

func NewQueryService(repo repository.WorkCenterRepository) QueryService {
	return &workcenterQueryService{repo: repo}
}

func (s *workcenterQueryService) GetWorkCenter(
	ctx context.Context,
	companyID uuid.UUID,
	code string,
) (*models.WorkCenter, error) {
	if code == "" {
		return nil, fmt.Errorf("work center code is required")
	}
	if companyID == uuid.Nil {
		return nil, fmt.Errorf("company ID is required")
	}
	return s.repo.GetByCode(ctx, companyID, code)
}

// ListWorkCenters — locationID == nil means no filter (ALL scope).
func (s *workcenterQueryService) ListWorkCenters(
	ctx context.Context,
	companyID uuid.UUID,
	locationID *uuid.UUID,
	page, pageSize int,
) ([]*models.WorkCenter, int, error) {
	if companyID == uuid.Nil {
		return nil, 0, fmt.Errorf("company ID is required")
	}
	if page < 1 {
		page = 1
	}
	if pageSize < 1 || pageSize > 100 {
		pageSize = 50
	}
	offset := (page - 1) * pageSize
	return s.repo.List(ctx, companyID, locationID, pageSize, offset)
}

// SearchWorkCenters — locationID == nil means no filter (ALL scope).
func (s *workcenterQueryService) SearchWorkCenters(
	ctx context.Context,
	companyID uuid.UUID,
	locationID *uuid.UUID,
	filters map[string]interface{},
	page, pageSize int,
) ([]*models.WorkCenter, int, error) {
	if companyID == uuid.Nil {
		return nil, 0, fmt.Errorf("company ID is required")
	}
	if page < 1 {
		page = 1
	}
	if pageSize < 1 || pageSize > 100 {
		pageSize = 50
	}
	offset := (page - 1) * pageSize
	return s.repo.Search(ctx, companyID, locationID, filters, pageSize, offset)
}

// GetActiveWorkCenters — locationID == nil means no filter (ALL scope).
func (s *workcenterQueryService) GetActiveWorkCenters(
	ctx context.Context,
	companyID uuid.UUID,
	locationID *uuid.UUID,
) ([]*models.WorkCenter, error) {
	if companyID == uuid.Nil {
		return nil, fmt.Errorf("company ID is required")
	}
	return s.repo.GetActive(ctx, companyID, locationID)
}

func (s *workcenterQueryService) HealthCheck(ctx context.Context) error {
	return s.repo.HealthCheck(ctx)
}

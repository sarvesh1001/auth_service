// auth-service/internal/hr/service/work_center_query_service.go
package service

import (
	"auth-service/internal/hr/models/workcenter"
	"auth-service/internal/hr/repository"
	"context"

	"github.com/google/uuid"
	"go.uber.org/zap"
)

type WorkCenterQueryService struct {
	workCenterRepo repository.WorkCenterRepository
	logger         *zap.Logger
}

func NewWorkCenterQueryService(
	workCenterRepo repository.WorkCenterRepository,
	logger *zap.Logger,
) *WorkCenterQueryService {
	return &WorkCenterQueryService{
		workCenterRepo: workCenterRepo,
		logger:         logger,
	}
}

func (s *WorkCenterQueryService) GetWorkCenter(
	ctx context.Context,
	companyID uuid.UUID,
	workCenterCode string,
) (*workcenter.WorkCenter, error) {
	return s.workCenterRepo.GetWorkCenterByCode(ctx, companyID, workCenterCode)
}

func (s *WorkCenterQueryService) ListWorkCenters(
	ctx context.Context,
	companyID uuid.UUID,
	page, pageSize int,
) ([]*workcenter.WorkCenter, int, error) {
	if page < 1 {
		page = 1
	}
	if pageSize < 1 || pageSize > 100 {
		pageSize = 50
	}

	offset := (page - 1) * pageSize
	return s.workCenterRepo.ListWorkCenters(ctx, companyID, pageSize, offset)
}

func (s *WorkCenterQueryService) SearchWorkCenters(
	ctx context.Context,
	companyID uuid.UUID,
	filters map[string]interface{},
	page, pageSize int,
) ([]*workcenter.WorkCenter, int, error) {
	if page < 1 {
		page = 1
	}
	if pageSize < 1 || pageSize > 100 {
		pageSize = 50
	}

	offset := (page - 1) * pageSize
	return s.workCenterRepo.SearchWorkCenters(ctx, companyID, filters, pageSize, offset)
}

func (s *WorkCenterQueryService) GetActiveWorkCenters(
	ctx context.Context,
	companyID uuid.UUID,
) ([]*workcenter.WorkCenter, error) {
	return s.workCenterRepo.GetActiveWorkCenters(ctx, companyID)
}

func (s *WorkCenterQueryService) HealthCheck(ctx context.Context) error {
	return s.workCenterRepo.HealthCheck(ctx)
}

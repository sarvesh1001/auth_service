// auth-service/internal/hr/repository/work_center_repository.go
package repository

import (
	"auth-service/internal/hr/models/workcenter"
	"context"

	"github.com/google/uuid"
)

type WorkCenterRepository interface {
	CreateWorkCenter(ctx context.Context, workCenter *workcenter.WorkCenter) error
	GetWorkCenterByCode(ctx context.Context, companyID uuid.UUID, workCenterCode string) (*workcenter.WorkCenter, error)
	GetWorkCenterByID(ctx context.Context, companyID uuid.UUID, workCenterCode string) (*workcenter.WorkCenter, error)
	UpdateWorkCenter(ctx context.Context, workCenter *workcenter.WorkCenter) error
	DeleteWorkCenter(ctx context.Context, companyID uuid.UUID, workCenterCode string) error
	ListWorkCenters(ctx context.Context, companyID uuid.UUID, limit, offset int) ([]*workcenter.WorkCenter, int, error)
	SearchWorkCenters(ctx context.Context, companyID uuid.UUID, filters map[string]interface{}, limit, offset int) ([]*workcenter.WorkCenter, int, error)
	CheckWorkCenterExists(ctx context.Context, companyID uuid.UUID, workCenterCode string) (bool, error)
	CheckWorkCenterNameExists(ctx context.Context, companyID uuid.UUID, name string) (bool, error)
	GetActiveWorkCenters(ctx context.Context, companyID uuid.UUID) ([]*workcenter.WorkCenter, error)
	HealthCheck(ctx context.Context) error
}

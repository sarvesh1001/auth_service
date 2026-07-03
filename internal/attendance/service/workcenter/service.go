package workcenter

import (
	"context"

	"github.com/google/uuid"

	"auth-service/internal/attendance/models"
)

// Service defines the business operations for work centers.
type Service interface {
	CreateWorkCenter(ctx context.Context, wc *models.WorkCenter, actorType string, actorID uuid.UUID, metadata map[string]interface{}) (*models.WorkCenter, error)
	UpdateWorkCenter(ctx context.Context, companyID uuid.UUID, code string, name, description, timezone *string, isActive *bool, actorType string, actorID uuid.UUID, metadata map[string]interface{}) (*models.WorkCenter, error)
	DeleteWorkCenter(ctx context.Context, companyID uuid.UUID, code string, actorType string, actorID uuid.UUID, metadata map[string]interface{}) error
	HealthCheck(ctx context.Context) error
}

// QueryService defines read operations for work centers.
type QueryService interface {
	GetWorkCenter(ctx context.Context, companyID uuid.UUID, code string) (*models.WorkCenter, error)
	ListWorkCenters(ctx context.Context, companyID uuid.UUID, page, pageSize int) ([]*models.WorkCenter, int, error)
	SearchWorkCenters(ctx context.Context, companyID uuid.UUID, filters map[string]interface{}, page, pageSize int) ([]*models.WorkCenter, int, error)
	GetActiveWorkCenters(ctx context.Context, companyID uuid.UUID) ([]*models.WorkCenter, error)
	HealthCheck(ctx context.Context) error
}

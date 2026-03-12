package repository

import (
	"auth-service/internal/hr/payroll/models"
	"context"

	"github.com/google/uuid"
)

type ComponentRepository interface {
	// GetComponentsByCompany returns a map of component_code -> PayrollComponent for the company.
	// Only active components are returned.
	GetComponentsByCompany(ctx context.Context, companyID uuid.UUID) (map[string]*models.PayrollComponent, error)

	// GetComponent returns a single component by company and code.
	// Returns nil, nil if not found.
	GetComponent(ctx context.Context, companyID uuid.UUID, code string) (*models.PayrollComponent, error)

	// GetComponentsByCodes returns a slice of components for the given codes.
	// Useful for resolving multiple specific components.
	GetComponentsByCodes(ctx context.Context, companyID uuid.UUID, codes []string) ([]*models.PayrollComponent, error)
}

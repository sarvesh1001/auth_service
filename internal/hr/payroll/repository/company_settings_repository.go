package repository

import (
	"auth-service/internal/hr/payroll/models"
	"context"

	"github.com/google/uuid"
)

type CompanySettingsRepository interface {
	// GetPayrollSettings returns the payroll settings for a company.
	// Returns nil, nil if not found (settings row may not exist yet).
	GetPayrollSettings(ctx context.Context, companyID uuid.UUID) (*models.CompanyPayrollSettings, error)

	// UpsertPayrollSettings creates or updates the payroll settings for a company.
	UpsertPayrollSettings(ctx context.Context, settings *models.CompanyPayrollSettings) error
}

package repository

import (
	"context"
	"time"

	"auth-service/internal/hr/payroll/models"

	"github.com/google/uuid"
)

type EmployeeFineRepository interface {
	// =========================================================================
	// Create & Update
	// =========================================================================

	Create(ctx context.Context, fine *models.EmployeeFine) error

	Update(ctx context.Context, fine *models.EmployeeFine) error

	MarkAsProcessed(
		ctx context.Context,
		fineID uuid.UUID,
		payrollRunID uuid.UUID,
	) error

	BulkMarkAsProcessed(
		ctx context.Context,
		fineIDs []uuid.UUID,
		payrollRunID uuid.UUID,
	) error

	// =========================================================================
	// Retrieval
	// =========================================================================

	GetByID(
		ctx context.Context,
		companyID, fineID uuid.UUID,
	) (*models.EmployeeFine, error)

	GetByFilter(
		ctx context.Context,
		filter models.EmployeeFineFilter,
	) ([]models.EmployeeFine, int, error)

	GetUnprocessedByUserAndPeriod(
		ctx context.Context,
		companyID uuid.UUID,
		userID uuid.UUID,
		periodStart, periodEnd time.Time,
	) ([]models.EmployeeFine, error)

	GetUnprocessedByCompanyAndPeriod(
		ctx context.Context,
		companyID uuid.UUID,
		periodStart, periodEnd time.Time,
	) ([]models.EmployeeFine, error)

	// =========================================================================
	// Run Safety
	// =========================================================================

	LockUnprocessedForPayrollRun(
		ctx context.Context,
		companyID uuid.UUID,
		periodStart, periodEnd time.Time,
		payrollRunID uuid.UUID,
	) ([]models.EmployeeFine, error)

	// =========================================================================
	// Audit / Integrity
	// =========================================================================

	DeleteIfUnprocessed(
		ctx context.Context,
		companyID, fineID uuid.UUID,
	) error
}

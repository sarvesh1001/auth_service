package repository

import (
	"context"
	"time"

	"auth-service/internal/hr/payroll/models"

	"github.com/google/uuid"
)

type AttendanceRuleRepository interface {
	// =========================================================================
	// CRUD
	// =========================================================================

	Create(ctx context.Context, rule *models.AttendanceRule) error

	Update(ctx context.Context, rule *models.AttendanceRule) error

	SoftDeactivate(ctx context.Context, companyID, ruleID, actorID uuid.UUID) error

	GetByID(ctx context.Context, companyID, ruleID uuid.UUID) (*models.AttendanceRule, error)

	// =========================================================================
	// Queries
	// =========================================================================

	GetActiveByCompany(
		ctx context.Context,
		companyID uuid.UUID,
		asOf time.Time,
	) ([]models.AttendanceRule, error)

	GetByFilter(
		ctx context.Context,
		filter models.AttendanceRuleFilter,
	) ([]models.AttendanceRule, int, error) // returns rules + total count

	GetByRuleType(
		ctx context.Context,
		companyID uuid.UUID,
		ruleType string,
	) ([]models.AttendanceRule, error)

	// =========================================================================
	// Bulk / Versioning Safety
	// =========================================================================

	BulkDeactivateByType(
		ctx context.Context,
		companyID uuid.UUID,
		ruleType string,
		actorID uuid.UUID,
	) error

	ExistsActiveRuleOfType(
		ctx context.Context,
		companyID uuid.UUID,
		ruleType string,
	) (bool, error)
}

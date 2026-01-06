// internal/hr/service/compensation_service.go
package service

import (
	"auth-service/internal/hr/models/compensation"
	"context"
	"time"

	"github.com/google/uuid"
	"github.com/shopspring/decimal"
)

// ============================================================================
// COMPENSATION SERVICE INTERFACE
// ============================================================================

// CompensationService handles business logic for compensation operations
type CompensationService interface {
	// Pay Unit Management
	CreatePayUnit(ctx context.Context, payUnit *compensation.PayUnit, actorType string, actorID uuid.UUID) (*compensation.PayUnit, error)

	// Compensation Structure Management
	CreateCompensationStructure(ctx context.Context, structure *compensation.CompensationStructure, actorType string, actorID uuid.UUID, metadata map[string]interface{}) (*compensation.CompensationStructure, error)
	UpdateCompensationStructure(ctx context.Context, structure *compensation.CompensationStructure, actorType string, actorID uuid.UUID, metadata map[string]interface{}) error
	DeactivateCompensationStructure(ctx context.Context, structureID uuid.UUID, actorType string, actorID uuid.UUID, metadata map[string]interface{}) error
	AssignCompensationStructureToUsers(ctx context.Context, companyID uuid.UUID, structureID uuid.UUID, userIDs []uuid.UUID, effectiveFrom time.Time, effectiveTo *time.Time, assignedBy uuid.UUID, metadata map[string]interface{}) ([]*compensation.UserCompensation, error)

	// User Compensation Management
	CreateUserCompensation(ctx context.Context, userComp *compensation.UserCompensation, actorType string, actorID uuid.UUID, metadata map[string]interface{}) (*compensation.UserCompensation, error)
	UpdateUserCompensation(ctx context.Context, userComp *compensation.UserCompensation, actorType string, actorID uuid.UUID, metadata map[string]interface{}) error
	EndUserCompensation(ctx context.Context, userID uuid.UUID, endDate time.Time, actorType string, actorID uuid.UUID, metadata map[string]interface{}) error

	// Bulk Operations
	BulkAssignCompensationStructure(ctx context.Context, companyID uuid.UUID, structureID uuid.UUID, userCompensations []*compensation.UserCompensation, actorType string, actorID uuid.UUID, metadata map[string]interface{}) error

	// Payroll Calculations
	CalculateMonthlyPayroll(ctx context.Context, companyID uuid.UUID, monthYear time.Time) (map[uuid.UUID]decimal.Decimal, error)
	CalculateUserMonthlySalary(ctx context.Context, userID uuid.UUID, monthYear time.Time) (decimal.Decimal, map[string]interface{}, error)

	// Health Check
	HealthCheck(ctx context.Context) error
}

// ============================================================================
// COMPENSATION QUERY SERVICE INTERFACE
// ============================================================================

// CompensationQueryService handles read operations and reporting for compensation
type CompensationQueryService interface {
	// Pay Unit Queries
	GetPayUnitByID(ctx context.Context, payUnitID uuid.UUID) (*compensation.PayUnit, error)
	ListPayUnits(ctx context.Context) ([]*compensation.PayUnit, error)

	// Compensation Structure Queries
	GetCompensationStructureByID(ctx context.Context, structureID uuid.UUID) (*compensation.CompensationStructure, error)
	GetCompensationStructuresByCompany(ctx context.Context, companyID uuid.UUID, activeOnly bool, page, pageSize int) ([]*compensation.CompensationStructure, int, error)
	GetCompensationStructureByCode(ctx context.Context, companyID uuid.UUID, structureCode string) (*compensation.CompensationStructure, error)

	// User Compensation Queries
	GetUserCompensationByID(ctx context.Context, userID, structureID uuid.UUID, effectiveFrom time.Time) (*compensation.UserCompensation, error)
	GetUserCompensationsByUser(ctx context.Context, userID uuid.UUID) ([]*compensation.UserCompensation, error)
	GetCurrentUserCompensation(ctx context.Context, userID uuid.UUID) (*compensation.UserCompensation, error)
	GetUserCompensationsByCompany(ctx context.Context, companyID uuid.UUID, page, pageSize int) ([]*compensation.UserCompensation, int, error)

	// Analytics and Reports
	GetCompensationStatsByCompany(ctx context.Context, companyID uuid.UUID) (map[string]interface{}, error)
	GetAverageCTCByDepartment(ctx context.Context, companyID uuid.UUID) (map[uuid.UUID]decimal.Decimal, error)
	GetCompensationTrends(ctx context.Context, companyID uuid.UUID, startDate, endDate time.Time) ([]map[string]interface{}, error)
	GenerateCompensationReport(ctx context.Context, companyID uuid.UUID, reportType string, startDate, endDate time.Time) ([]byte, string, error)

	// Search and Filter
	SearchCompensationStructures(ctx context.Context, companyID uuid.UUID, filters map[string]interface{}, page, pageSize int) ([]*compensation.CompensationStructure, int, error)
	SearchUserCompensations(ctx context.Context, companyID uuid.UUID, filters map[string]interface{}, page, pageSize int) ([]*compensation.UserCompensation, int, error)

	// Health Check
	HealthCheck(ctx context.Context) error
}

package repository

import (
	"context"
	"time"

	"auth-service/internal/hr/models/compensation"

	"github.com/google/uuid"
	"github.com/shopspring/decimal"
)

// CompensationRepository defines the interface for compensation operations
type CompensationRepository interface {
	// Pay Units
	GetPayUnitByID(ctx context.Context, payUnitID uuid.UUID) (*compensation.PayUnit, error)
	ListPayUnits(ctx context.Context) ([]*compensation.PayUnit, error)

	// Compensation Structures
	CreateCompensationStructure(ctx context.Context, structure *compensation.CompensationStructure) error
	GetCompensationStructureByID(ctx context.Context, structureID uuid.UUID) (*compensation.CompensationStructure, error)
	GetCompensationStructuresByCompany(ctx context.Context, companyID uuid.UUID, limit, offset int) ([]*compensation.CompensationStructure, int, error)
	GetActiveCompensationStructures(ctx context.Context, companyID uuid.UUID) ([]*compensation.CompensationStructure, error)
	UpdateCompensationStructure(ctx context.Context, structure *compensation.CompensationStructure) error
	DeleteCompensationStructure(ctx context.Context, structureID uuid.UUID) error
	GetCompensationStructureByCode(ctx context.Context, companyID uuid.UUID, structureCode string) (*compensation.CompensationStructure, error)

	// User Compensations
	CreateUserCompensation(ctx context.Context, userComp *compensation.UserCompensation) error
	GetUserCompensationByID(ctx context.Context, userID, structureID uuid.UUID, effectiveFrom time.Time) (*compensation.UserCompensation, error)
	GetUserCompensationsByUser(ctx context.Context, userID uuid.UUID) ([]*compensation.UserCompensation, error)
	GetCurrentUserCompensation(ctx context.Context, userID uuid.UUID) (*compensation.UserCompensation, error)
	GetUserCompensationsByCompany(ctx context.Context, companyID uuid.UUID, limit, offset int) ([]*compensation.UserCompensation, int, error)
	UpdateUserCompensation(ctx context.Context, userComp *compensation.UserCompensation) error
	DeleteUserCompensation(ctx context.Context, userID, structureID uuid.UUID, effectiveFrom time.Time) error
	EndUserCompensation(ctx context.Context, userID uuid.UUID, endDate time.Time) error

	// Batch Operations
	CreateUserCompensationsBatch(ctx context.Context, compensations []*compensation.UserCompensation) error
	CreatePayUnit(ctx context.Context, payUnit *compensation.PayUnit) error
	GetPayUnitByName(ctx context.Context, name string) (*compensation.PayUnit, error)

	// Analytics
	GetCompensationStatsByCompany(ctx context.Context, companyID uuid.UUID) (map[string]interface{}, error)
	GetAverageCTCByDepartment(ctx context.Context, companyID uuid.UUID) (map[uuid.UUID]decimal.Decimal, error)
	GetCompensationTrends(ctx context.Context, companyID uuid.UUID, startDate, endDate time.Time) ([]map[string]interface{}, error)

	// Health Check
	HealthCheck(ctx context.Context) error
}

package repository

import (
	"context"
	"time"

	"auth-service/internal/hr/payroll/models"

	"github.com/google/uuid"
)

type CompensationRepository interface {

	// ============================================================
	// EMPLOYEE SALARY (Assignment Layer)
	// ============================================================

	CreateEmployeeSalary(
		ctx context.Context,
		salary *models.EmployeeSalary,
	) error

	UpdateEmployeeSalary(
		ctx context.Context,
		salary *models.EmployeeSalary,
	) error

	DeactivateEmployeeSalary(
		ctx context.Context,
		employeeSalaryID uuid.UUID,
		updatedBy uuid.UUID,
	) error

	GetEmployeeSalaryByID(
		ctx context.Context,
		employeeSalaryID uuid.UUID,
	) (*models.EmployeeSalary, error)

	// Current active salary as of specific date (Payroll Engine uses this)
	GetActiveEmployeeSalary(
		ctx context.Context,
		companyID uuid.UUID,
		userID uuid.UUID,
		asOf time.Time,
	) (*models.EmployeeSalary, error)

	// Full salary history (for increments, promotion audit, compliance)
	GetEmployeeSalaryHistory(
		ctx context.Context,
		companyID uuid.UUID,
		userID uuid.UUID,
		page int,
		pageSize int,
	) ([]models.EmployeeSalary, error)

	// Get employees having active salary in period (used in payroll pre-validation)
	GetEmployeesWithActiveSalaryInPeriod(
		ctx context.Context,
		companyID uuid.UUID,
		startDate, endDate time.Time,
	) ([]uuid.UUID, error)

	// ============================================================
	// SALARY STRUCTURE (Template Layer)
	// ============================================================

	CreateSalaryStructure(
		ctx context.Context,
		structure *models.SalaryStructure,
	) error

	UpdateSalaryStructure(
		ctx context.Context,
		structure *models.SalaryStructure,
	) error

	DeactivateSalaryStructure(ctx context.Context, structureID uuid.UUID, updatedBy uuid.UUID) error

	GetSalaryStructure(
		ctx context.Context,
		structureID uuid.UUID,
		companyID uuid.UUID,
	) (*models.SalaryStructure, error)

	GetSalaryStructuresByCompany(
		ctx context.Context,
		companyID uuid.UUID,
		includeInactive bool,
	) ([]models.SalaryStructure, error)

	// Check if structure is currently assigned to any employee
	IsSalaryStructureInUse(
		ctx context.Context,
		structureID uuid.UUID,
	) (bool, error)

	// ============================================================
	// SALARY STRUCTURE COMPONENTS
	// ============================================================

	AddStructureComponent(
		ctx context.Context,
		component *models.SalaryStructureComponent,
	) error

	UpdateStructureComponent(
		ctx context.Context,
		component *models.SalaryStructureComponent,
	) error

	RemoveStructureComponent(
		ctx context.Context,
		mappingID uuid.UUID,
	) error

	GetStructureComponentByID(
		ctx context.Context,
		mappingID uuid.UUID,
	) (*models.SalaryStructureComponent, error)

	GetStructureComponents(
		ctx context.Context,
		structureID uuid.UUID,
		companyID uuid.UUID,
	) ([]models.SalaryStructureComponent, error)

	// Used by payroll engine to resolve structure quickly
	GetStructureComponentsOrdered(
		ctx context.Context,
		structureID uuid.UUID,
		companyID uuid.UUID,
	) ([]models.SalaryStructureComponent, error)
	// 🟢 NEW: Get a single payroll component by its code
	GetComponent(ctx context.Context, code string) (*models.PayrollComponent, error)

	// 🟢 NEW: Bulk fetch payroll components by their codes (for performance)
	GetComponentsByCodes(ctx context.Context, codes []string) ([]*models.PayrollComponent, error)
	GetEmployeeSalaryHistoryInRange(
		ctx context.Context,
		companyID uuid.UUID,
		userID uuid.UUID,
		startDate, endDate time.Time,
	) ([]models.EmployeeSalary, error)
	GetSalaryStructureWithComponents(
		ctx context.Context,
		structureID uuid.UUID,
		companyID uuid.UUID,
		asOf time.Time, // 🟢 NEW
	) (*models.SalaryStructure, []models.SalaryStructureComponent, error)
	GetActiveEmployeeSalaryForUpdate(
		ctx context.Context,
		companyID uuid.UUID,
		userID uuid.UUID,
		asOf time.Time,
	) (*models.EmployeeSalary, error)
	GetEmployeeSalaryHistoryInRangeForUpdate(
		ctx context.Context,
		companyID uuid.UUID,
		userID uuid.UUID,
		startDate, endDate time.Time,
	) ([]models.EmployeeSalary, error)
}

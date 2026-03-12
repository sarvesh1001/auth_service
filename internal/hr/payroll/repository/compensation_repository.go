package repository

import (
	"context"
	"time"

	"auth-service/internal/hr/payroll/models"

	"github.com/google/uuid"
)

// CompensationRepository defines all data access methods for compensation management.
// It covers employee salary assignments, salary structure templates, and their components.
type CompensationRepository interface {

	// ============================================================
	// EMPLOYEE SALARY (Assignment Layer)
	// ============================================================

	// CreateEmployeeSalary inserts a new employee salary assignment.
	// It performs an overlapping check before insertion.
	CreateEmployeeSalary(ctx context.Context, salary *models.EmployeeSalary) error

	// UpdateEmployeeSalary modifies an existing salary assignment.
	// It uses optimistic locking (version field) and checks for overlaps excluding itself.
	UpdateEmployeeSalary(ctx context.Context, salary *models.EmployeeSalary) error

	// DeactivateEmployeeSalary soft‑deactivates a salary assignment (sets is_active = false).
	// It records who and when performed the deactivation.
	DeactivateEmployeeSalary(ctx context.Context, employeeSalaryID uuid.UUID, updatedBy uuid.UUID) error

	// GetEmployeeSalaryByID retrieves a salary assignment by its ID (any status, any company).
	GetEmployeeSalaryByID(ctx context.Context, employeeSalaryID uuid.UUID) (*models.EmployeeSalary, error)

	// GetActiveEmployeeSalary returns the currently active salary assignment for an employee
	// as of a specific date. Used by the payroll engine.
	GetActiveEmployeeSalary(ctx context.Context, companyID uuid.UUID, userID uuid.UUID, asOf time.Time) (*models.EmployeeSalary, error)

	// GetEmployeeSalaryHistory returns paginated history of all salary assignments for an employee.
	GetEmployeeSalaryHistory(ctx context.Context, companyID uuid.UUID, userID uuid.UUID, page, pageSize int) ([]models.EmployeeSalary, error)

	// GetEmployeesWithActiveSalaryInPeriod returns distinct user IDs that have an active salary
	// overlapping the given date range. Used for payroll pre‑validation.
	GetEmployeesWithActiveSalaryInPeriod(ctx context.Context, companyID uuid.UUID, startDate, endDate time.Time) ([]uuid.UUID, error)

	// CloseActiveSalaryBefore closes (sets effective_to) any active salary assignment that overlaps
	// a new effective date. Called before assigning a new salary to avoid gaps/overlaps.
	CloseActiveSalaryBefore(ctx context.Context, companyID uuid.UUID, userID uuid.UUID, newEffectiveFrom time.Time, closedBy uuid.UUID) error

	// ============================================================
	// SALARY STRUCTURE (Template Layer)
	// ============================================================

	// CreateSalaryStructure inserts a new salary structure template.
	CreateSalaryStructure(ctx context.Context, structure *models.SalaryStructure) error

	// UpdateSalaryStructure modifies an existing structure (optimistic locking).
	UpdateSalaryStructure(ctx context.Context, structure *models.SalaryStructure) error

	// DeactivateSalaryStructure soft‑deactivates a structure.
	DeactivateSalaryStructure(ctx context.Context, structureID uuid.UUID, updatedBy uuid.UUID) error

	// GetSalaryStructure retrieves a structure by its ID, but only if it belongs to the given company.
	GetSalaryStructure(ctx context.Context, structureID uuid.UUID, companyID uuid.UUID) (*models.SalaryStructure, error)

	// GetSalaryStructuresByCompany lists all structures for a company, optionally including inactive ones.
	GetSalaryStructuresByCompany(ctx context.Context, companyID uuid.UUID, includeInactive bool) ([]models.SalaryStructure, error)

	// IsSalaryStructureInUse checks whether any employee salary references the given structure.
	IsSalaryStructureInUse(ctx context.Context, structureID uuid.UUID) (bool, error)

	// ============================================================
	// SALARY STRUCTURE COMPONENTS
	// ============================================================

	// AddStructureComponent adds a single component to a salary structure.
	// It validates that the structure exists and belongs to the company.
	AddStructureComponent(ctx context.Context, component *models.SalaryStructureComponent) error

	// UpdateStructureComponent modifies an existing component mapping.
	UpdateStructureComponent(ctx context.Context, component *models.SalaryStructureComponent) error

	// RemoveStructureComponent deletes a component mapping from a structure.
	RemoveStructureComponent(ctx context.Context, mappingID uuid.UUID) error

	// GetStructureComponentByID retrieves a component mapping by its ID.
	GetStructureComponentByID(ctx context.Context, mappingID uuid.UUID) (*models.SalaryStructureComponent, error)

	// GetStructureComponents returns all components of a structure (unordered).
	GetStructureComponents(ctx context.Context, structureID uuid.UUID, companyID uuid.UUID) ([]models.SalaryStructureComponent, error)

	// GetStructureComponentsOrdered returns components ordered by sequence_order.
	// Used by the payroll engine for deterministic calculation.
	GetStructureComponentsOrdered(ctx context.Context, structureID uuid.UUID, companyID uuid.UUID) ([]models.SalaryStructureComponent, error)

	// ============================================================
	// COMPONENT METADATA (from payroll.payroll_component)
	// ============================================================

	// GetComponent retrieves a single payroll component by its code for a specific company.
	// Returns nil, nil if not found.
	GetComponent(ctx context.Context, companyID uuid.UUID, code string) (*models.PayrollComponent, error)

	// GetComponentsByCodes bulk‑fetches payroll components for a company.
	// Critical for performance when resolving salary structures.
	GetComponentsByCodes(ctx context.Context, companyID uuid.UUID, codes []string) ([]*models.PayrollComponent, error)

	// ============================================================
	// VALIDATION & RESOLUTION HELPERS
	// ============================================================

	// HasOverlappingSalaryAssignment checks whether a new or updated salary assignment
	// would overlap with any existing active assignment for the same employee.
	// excludeSalaryID can be provided during updates to skip self‑comparison.
	HasOverlappingSalaryAssignment(ctx context.Context, companyID uuid.UUID, userID uuid.UUID, effectiveFrom time.Time, effectiveTo *time.Time, excludeSalaryID *uuid.UUID) (bool, error)

	// IsSalaryStructureValid validates a structure’s components:
	// - at least one earning component
	// - all components active
	// - no duplicate component codes
	// - sequence order unique (if not null)
	IsSalaryStructureValid(ctx context.Context, structureID uuid.UUID) (bool, error)

	// ============================================================
	// REPORTING & ANALYTICS
	// ============================================================

	// GetTotalMonthlyCTCByCompany returns the sum of monthly CTC for all employees
	// with active salary as of the given date.
	GetTotalMonthlyCTCByCompany(ctx context.Context, companyID uuid.UUID, asOf time.Time) (float64, error)

	// GetEmployeeCompensationSnapshot is an alias for GetActiveEmployeeSalary,
	// kept for interface completeness.
	GetEmployeeCompensationSnapshot(ctx context.Context, companyID uuid.UUID, userID uuid.UUID, asOf time.Time) (*models.EmployeeSalary, error)

	// ============================================================
	// COMPLEX RETRIEVALS (for payroll engine)
	// ============================================================

	// GetSalaryStructureWithComponents returns a structure and its components together.
	// The asOf parameter is kept for interface consistency but not used in current implementation.
	GetSalaryStructureWithComponents(ctx context.Context, structureID uuid.UUID, companyID uuid.UUID, asOf time.Time) (*models.SalaryStructure, []models.SalaryStructureComponent, error)

	// GetEmployeeSalaryHistoryInRange returns all active salary assignments overlapping
	// the given date range, ordered by effective_from ASC.
	GetEmployeeSalaryHistoryInRange(ctx context.Context, companyID uuid.UUID, userID uuid.UUID, startDate, endDate time.Time) ([]models.EmployeeSalary, error)

	// GetActiveEmployeeSalaryForUpdate returns the active salary and locks the row (SELECT FOR UPDATE).
	// Used during payroll processing to prevent concurrent modifications.
	GetActiveEmployeeSalaryForUpdate(ctx context.Context, companyID uuid.UUID, userID uuid.UUID, asOf time.Time) (*models.EmployeeSalary, error)

	// GetEmployeeSalaryHistoryInRangeForUpdate returns all salaries in range and locks them.
	GetEmployeeSalaryHistoryInRangeForUpdate(ctx context.Context, companyID uuid.UUID, userID uuid.UUID, startDate, endDate time.Time) ([]models.EmployeeSalary, error)

	// ============================================================
	// HEALTH
	// ============================================================

	// HealthCheck performs a simple query to verify database connectivity.
	HealthCheck(ctx context.Context) error
}

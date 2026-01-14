package repository

import (
	"auth-service/internal/hr/models/employee"
	"context"
	"time"

	"github.com/google/uuid"
)

// EmployeeRepository defines the interface for HR employee operations
type EmployeeRepository interface {
	// EmployeeProfile operations
	CreateEmployeeProfile(ctx context.Context, profile *employee.EmployeeProfile) error
	GetEmployeeProfileByID(ctx context.Context, profileID uuid.UUID) (*employee.EmployeeProfile, error)
	GetEmployeeProfileByUserID(ctx context.Context, userID, companyID uuid.UUID) (*employee.EmployeeProfile, error)
	UpdateEmployeeProfile(ctx context.Context, profile *employee.EmployeeProfile) error
	DeleteEmployeeProfile(ctx context.Context, profileID uuid.UUID) error
	ListEmployeeProfilesByCompany(ctx context.Context, companyID uuid.UUID, limit, offset int) ([]*employee.EmployeeProfile, int, error)
	SearchEmployeeProfiles(ctx context.Context, companyID uuid.UUID, filters map[string]interface{}, limit, offset int) ([]*employee.EmployeeProfile, int, error)
	// Validation helpers
	UserExists(ctx context.Context, userID uuid.UUID) (bool, error)
	IsUserEmployeeOfCompany(ctx context.Context, userID, companyID uuid.UUID) (bool, error)

	// EmployeeDepartmentHistory operations
	CreateDepartmentHistory(ctx context.Context, history *employee.EmployeeDepartmentHistory) error
	GetDepartmentHistoryByID(ctx context.Context, id uuid.UUID) (*employee.EmployeeDepartmentHistory, error)
	GetDepartmentHistoryByUserID(ctx context.Context, userID, companyID uuid.UUID) ([]*employee.EmployeeDepartmentHistory, error)
	UpdateDepartmentHistory(ctx context.Context, history *employee.EmployeeDepartmentHistory) error
	EndDepartmentAssignment(ctx context.Context, userID uuid.UUID, endDate time.Time) error

	// EmployeeDocument operations
	CreateEmployeeDocument(ctx context.Context, doc *employee.EmployeeDocument) error
	GetEmployeeDocumentByID(ctx context.Context, documentID uuid.UUID) (*employee.EmployeeDocument, error)
	GetEmployeeDocumentsByUserID(ctx context.Context, userID, companyID uuid.UUID) ([]*employee.EmployeeDocument, error)
	GetConfidentialDocumentsByUserID(ctx context.Context, userID, companyID uuid.UUID) ([]*employee.EmployeeDocument, error)
	UpdateEmployeeDocument(ctx context.Context, doc *employee.EmployeeDocument) error
	DeleteEmployeeDocument(ctx context.Context, documentID uuid.UUID) error

	// EmployeeExit operations
	CreateEmployeeExit(ctx context.Context, exit *employee.EmployeeExit) error
	GetEmployeeExitByID(ctx context.Context, exitID uuid.UUID) (*employee.EmployeeExit, error)
	GetEmployeeExitByUserID(ctx context.Context, userID, companyID uuid.UUID) (*employee.EmployeeExit, error)
	UpdateEmployeeExit(ctx context.Context, exit *employee.EmployeeExit) error

	// Position operations
	CreatePosition(ctx context.Context, position *employee.Position) error
	GetPositionByID(ctx context.Context, positionID uuid.UUID) (*employee.Position, error)
	GetPositionsByDepartment(ctx context.Context, companyID, departmentID uuid.UUID) ([]*employee.Position, error)
	GetOpenPositions(ctx context.Context, companyID uuid.UUID) ([]*employee.Position, error)
	UpdatePosition(ctx context.Context, position *employee.Position) error
	DeletePosition(ctx context.Context, positionID uuid.UUID) error

	// EmployeeRoleHistory operations
	CreateRoleHistory(ctx context.Context, history *employee.EmployeeRoleHistory) error
	GetRoleHistoryByID(ctx context.Context, id uuid.UUID) (*employee.EmployeeRoleHistory, error)
	GetRoleHistoryByUserID(ctx context.Context, userID uuid.UUID) ([]*employee.EmployeeRoleHistory, error)
	UpdateRoleHistory(ctx context.Context, history *employee.EmployeeRoleHistory) error
	EndRoleAssignment(ctx context.Context, userID uuid.UUID, endDate time.Time) error

	// Batch operations
	CreateEmployeeProfilesBatch(ctx context.Context, profiles []*employee.EmployeeProfile) error
	CreateDepartmentHistoryBatch(ctx context.Context, histories []*employee.EmployeeDepartmentHistory) error
	CreateEmployeeDocumentsBatch(ctx context.Context, documents []*employee.EmployeeDocument) error

	// Search and analytics
	GetEmployeeStatsByCompany(ctx context.Context, companyID uuid.UUID) (map[string]interface{}, error)
	GetEmployeeCountByDepartment(ctx context.Context, companyID uuid.UUID) (map[uuid.UUID]int, error)
	GetActiveEmployeesByDateRange(ctx context.Context, companyID uuid.UUID, startDate, endDate time.Time) ([]*employee.EmployeeProfile, error)

	GetActiveDepartmentAssignment(
		ctx context.Context,
		userID uuid.UUID,
	) (*employee.EmployeeDepartmentHistory, error)
	EnforceScheduledEmployeeExits(
		ctx context.Context,
		effectiveDate time.Time,
		enforcedBy uuid.UUID,
	) (int, error)
	RehireEmployee(
		ctx context.Context,
		companyID, userID uuid.UUID,
	) error
	// Health check
	HealthCheck(ctx context.Context) error
}

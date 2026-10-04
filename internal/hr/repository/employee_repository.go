package repository

import (
	"auth-service/internal/hr/models/employee"
	"context"
	"database/sql"
	"time"

	"github.com/google/uuid"
)

// EnforcedExitPair identifies a (company, user) that a scheduled-exit
// enforcement pass will flip (or has just flipped) to effective.
type EnforcedExitPair struct {
	CompanyID uuid.UUID
	UserID    uuid.UUID
}

// EmployeeRepository defines the interface for HR employee operations
type EmployeeRepository interface {
	// EmployeeProfile operations
	CreateEmployeeProfile(ctx context.Context, profile *employee.EmployeeProfile) error
	GetEmployeeProfileByID(ctx context.Context, profileID uuid.UUID) (*employee.EmployeeProfile, error)
	GetEmployeeProfileByUserID(ctx context.Context, userID, companyID uuid.UUID) (*employee.EmployeeProfile, error)
	UpdateEmployeeProfile(ctx context.Context, profile *employee.EmployeeProfile) error
	DeleteEmployeeProfile(ctx context.Context, profileID uuid.UUID) error

	// ListEmployeeProfilesByCompany returns a page of profiles for a company,
	// optionally filtered by employment location.
	// locationID == nil means "no location filter" (company-wide).
	ListEmployeeProfilesByCompany(ctx context.Context, companyID uuid.UUID, locationID *uuid.UUID, limit, offset int) ([]*employee.EmployeeProfile, int, error)

	// SearchEmployeeProfiles applies arbitrary filters plus an optional
	// employment-location filter.
	SearchEmployeeProfiles(ctx context.Context, companyID uuid.UUID, locationID *uuid.UUID, filters map[string]interface{}, limit, offset int) ([]*employee.EmployeeProfile, int, error)

	// Validation helpers
	UserExists(ctx context.Context, userID uuid.UUID) (bool, error)
	IsUserEmployeeOfCompany(ctx context.Context, userID, companyID uuid.UUID) (bool, error)

	// EmployeeDepartmentHistory operations
	CreateDepartmentHistory(ctx context.Context, history *employee.EmployeeDepartmentHistory) error
	GetDepartmentHistoryByID(ctx context.Context, id uuid.UUID) (*employee.EmployeeDepartmentHistory, error)
	GetDepartmentHistoryByUserID(ctx context.Context, userID, companyID uuid.UUID) ([]*employee.EmployeeDepartmentHistory, error)
	UpdateDepartmentHistory(ctx context.Context, history *employee.EmployeeDepartmentHistory) error
	EndDepartmentAssignment(ctx context.Context, userID uuid.UUID, endDate time.Time) error
	GetEmploymentLocationID(ctx context.Context, companyID, userID uuid.UUID) (*uuid.UUID, error)

	// EmployeeDocument operations
	CreateEmployeeDocument(ctx context.Context, doc *employee.EmployeeDocument) error
	GetEmployeeDocumentByID(ctx context.Context, documentID uuid.UUID) (*employee.EmployeeDocument, error)
	GetEmployeeDocumentsByUserID(ctx context.Context, userID, companyID uuid.UUID) ([]*employee.EmployeeDocument, error)
	GetConfidentialDocumentsByUserID(ctx context.Context, userID, companyID uuid.UUID) ([]*employee.EmployeeDocument, error)
	UpdateEmployeeDocument(ctx context.Context, doc *employee.EmployeeDocument) error
	DeleteEmployeeDocument(ctx context.Context, documentID uuid.UUID) error
	PositionHasAssignedEmployees(ctx context.Context, companyID, positionID uuid.UUID) (bool, error)

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
	GetEmployeeStatsByCompany(ctx context.Context, companyID uuid.UUID, locationID *uuid.UUID) (map[string]interface{}, error)
	GetEmployeeCountByDepartment(ctx context.Context, companyID uuid.UUID) (map[uuid.UUID]int, error)
	GetActiveEmployeesByDateRange(ctx context.Context, companyID uuid.UUID, locationID *uuid.UUID, startDate, endDate time.Time) ([]*employee.EmployeeProfile, error)

	GetActiveDepartmentAssignment(ctx context.Context, userID uuid.UUID) (*employee.EmployeeDepartmentHistory, error)

	// GetDueScheduledExits returns the (company_id, user_id) pairs whose
	// exit_state='scheduled' and exit_date <= effectiveDate. Called BEFORE
	// EnforceScheduledEmployeeExits so the service can enqueue resolver jobs
	// for the affected users.
	GetDueScheduledExits(ctx context.Context, effectiveDate time.Time) ([]EnforcedExitPair, error)

	EnforceScheduledEmployeeExits(ctx context.Context, effectiveDate time.Time, enforcedBy uuid.UUID) (int, error)
	RehireEmployee(ctx context.Context, companyID, userID uuid.UUID) error

	// Health check
	HealthCheck(ctx context.Context) error

	// GetActiveUsersByPosition returns all active user IDs for a given position.
	GetActiveUsersByPosition(ctx context.Context, positionID uuid.UUID) ([]uuid.UUID, error)
	CreateEmployeeProfileTx(ctx context.Context, tx *sql.Tx, profile *employee.EmployeeProfile) error

	// GetActiveEmployeesByCompany returns all active employee user IDs for a company.
	GetActiveEmployeesByCompany(ctx context.Context, companyID uuid.UUID) ([]uuid.UUID, error)
	GetCompanyEmployeeByUserID(ctx context.Context, userID uuid.UUID) (*employee.CompanyEmployee, error)
	// Existing interface — add these three:

	// ReactivateEmployee flips employment_status back to 'active', re-enables
	// the roster row, and marks the last exit record as 'rehired'. Idempotent:
	// calling on an already-active employee is a no-op and returns nil.
	ReactivateEmployee(ctx context.Context, companyID, userID uuid.UUID) error

	// SearchEmployeeIDsByStatus is the status-aware sibling of
	// SearchEmployeeIDs. Pass status = "" or "all" for the old behavior.
	SearchEmployeeIDsByStatus(
		ctx context.Context,
		companyID uuid.UUID,
		query string,
		locationIDs []uuid.UUID,
		status string,
		limit, offset int,
	) ([]uuid.UUID, error)

	// CountEmployeeIDsByStatus returns the total row count for the same filters
	// so the HTTP layer can populate pagination metadata.
	CountEmployeeIDsByStatus(
		ctx context.Context,
		companyID uuid.UUID,
		query string,
		locationIDs []uuid.UUID,
		status string,
	) (int, error)
	SearchEmployeeIDs(
		ctx context.Context,
		companyID uuid.UUID,
		query string,
		locationIDs []uuid.UUID,
		limit, offset int,
	) ([]uuid.UUID, error)
	// ── Probation ──────────────────────────────────────────────
	CreateProbation(ctx context.Context, p *employee.EmployeeProbation) error
	GetActiveProbation(ctx context.Context, companyID, userID uuid.UUID) (*employee.EmployeeProbation, error)
	UpdateProbationStatus(ctx context.Context, p *employee.EmployeeProbation) error
	ListProbationsDueOn(ctx context.Context, asOf time.Time) ([]*employee.EmployeeProbation, error)

	// ── Notice ─────────────────────────────────────────────────
	CreateNotice(ctx context.Context, n *employee.EmployeeNotice) error
	GetActiveNotice(ctx context.Context, companyID, userID uuid.UUID) (*employee.EmployeeNotice, error)
	UpdateNoticeStatus(ctx context.Context, noticeID uuid.UUID, status string) error
	AttachNoticeToExit(ctx context.Context, noticeID, exitID uuid.UUID) error

	// ── On hold ────────────────────────────────────────────────
	CreateOnHold(ctx context.Context, h *employee.EmployeeOnHold) error
	GetActiveOnHold(ctx context.Context, companyID, userID uuid.UUID) (*employee.EmployeeOnHold, error)
	EndOnHoldRow(ctx context.Context, onHoldID uuid.UUID, endedBy uuid.UUID) error

	// ── Scheduled jobs ─────────────────────────────────────────
	EnqueueScheduledJob(ctx context.Context, job *employee.ScheduledJob) error
	ClaimScheduledJobs(ctx context.Context, workerID string, batch int) ([]*employee.ScheduledJob, error)
	CompleteScheduledJob(ctx context.Context, jobID uuid.UUID) error
	FailScheduledJob(ctx context.Context, jobID uuid.UUID, errMsg string) error
	// Cancel queued/processing scheduled jobs for (company, user, type).
	// Pass userID == nil to cancel company-scoped jobs of that type.
	CancelScheduledJobs(ctx context.Context, companyID uuid.UUID, userID *uuid.UUID, jobType string) error

	// CancelEmployeeExit flips a scheduled exit to 'cancelled'. No-op if
	// the exit is not in 'scheduled' state.
	CancelEmployeeExit(ctx context.Context, exitID uuid.UUID) error
	// Called by the on-hold expiry worker.
	ApplyOnHoldExpiry(ctx context.Context, onHoldID uuid.UUID) error
	UpdateEmployeeProfileTx(ctx context.Context, tx *sql.Tx, profile *employee.EmployeeProfile) error
	GetPositionViewByID(ctx context.Context, positionID uuid.UUID) (*employee.PositionView, error)
	GetEmployeeFullDetailsByIDs(ctx context.Context, companyID uuid.UUID, userIDs []uuid.UUID, locationIDs []uuid.UUID) ([]*employee.EmployeeFullDetailsExt, error)
}

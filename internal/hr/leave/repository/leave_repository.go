package repository

import (
	"context"
	"database/sql"
	"time"

	"github.com/google/uuid"

	"auth-service/internal/hr/leave/models"
)

type LeaveRepository interface {
	// ========================================================================
	// Leave types
	// ========================================================================
	CreateLeaveType(ctx context.Context, leaveType *models.LeaveType) error
	GetLeaveTypeByID(ctx context.Context, leaveTypeID uuid.UUID) (*models.LeaveType, error)
	GetLeaveTypeByCode(ctx context.Context, companyID uuid.UUID, code string) (*models.LeaveType, error)
	GetLeaveTypesByCompany(ctx context.Context, companyID uuid.UUID) ([]*models.LeaveType, error)
	UpdateLeaveType(ctx context.Context, leaveTypeID uuid.UUID, update *models.LeaveTypeUpdate) error
	DeleteLeaveType(ctx context.Context, leaveTypeID uuid.UUID) error
	IsLeaveTypeInUse(ctx context.Context, leaveTypeID uuid.UUID) (bool, error)

	// ========================================================================
	// Ledger — reads
	// ========================================================================
	GetCompanyLedger(ctx context.Context, filter models.LeaveLedgerFilter) ([]*models.LeaveLedgerEntry, int64, error)
	CreateLeaveLedgerEntry(ctx context.Context, entry *models.LeaveLedger) error
	CreateBulkLeaveLedgerEntries(ctx context.Context, entries []*models.LeaveLedger) error
	GetLeaveLedgerEntriesByEntitlement(ctx context.Context, entitlementID uuid.UUID) ([]*models.LeaveLedger, error)
	GetLeaveLedgerEntriesByRequest(ctx context.Context, requestID uuid.UUID) ([]*models.LeaveLedger, error)

	// ========================================================================
	// Entitlements — non-Tx
	// ========================================================================
	CreateLeaveEntitlement(ctx context.Context, entitlement *models.LeaveEntitlement) error
	GetLeaveEntitlementByID(ctx context.Context, entitlementID uuid.UUID) (*models.LeaveEntitlement, error)
	GetLeaveEntitlementsByUser(
		ctx context.Context,
		userID uuid.UUID,
		positionID *uuid.UUID,
	) ([]*models.LeaveEntitlement, error)

	// GetLeaveEntitlementsByCompany — location filter applies when non-nil.
	GetLeaveEntitlementsByCompany(
		ctx context.Context,
		companyID uuid.UUID,
		locationID *uuid.UUID,
		page, pageSize int,
	) ([]*models.LeaveEntitlement, int64, error)
	// GetUserPositionContextOnDate returns the user's position and work center
	// as they were effective on the given date, reading hr.employee_assignment_history
	// and hr.position_history. Same pattern as the attendance resolver.
	GetUserPositionContextOnDate(
		ctx context.Context,
		companyID, userID uuid.UUID,
		date time.Time,
	) (*uuid.UUID, *string, error)
	// GetLeaveEntitlementsByCompanyAndUser — location filter applies when non-nil.
	GetLeaveEntitlementsByCompanyAndUser(
		ctx context.Context,
		companyID uuid.UUID,
		userID *uuid.UUID,
		locationID *uuid.UUID,
		page, pageSize int,
	) ([]*models.LeaveEntitlement, int64, error)

	UpdateLeaveEntitlement(ctx context.Context, entitlementID uuid.UUID, update *models.LeaveEntitlementUpdate) error
	EndLeaveEntitlement(ctx context.Context, entitlementID uuid.UUID, endDate time.Time) error
	GetActiveLeaveEntitlement(
		ctx context.Context,
		userID, leaveTypeID uuid.UUID,
		date time.Time,
		positionID *uuid.UUID,
	) (*models.LeaveEntitlement, error)

	// ========================================================================
	// Accruals
	// ========================================================================
	CreateLeaveAccrual(ctx context.Context, accrual *models.LeaveAccrual) error
	CreateBulkLeaveAccruals(ctx context.Context, accruals []*models.LeaveAccrual) error
	GetLeaveAccrualsByEntitlement(ctx context.Context, entitlementID uuid.UUID) ([]*models.LeaveAccrual, error)
	GetLeaveAccrualsByDate(ctx context.Context, companyID uuid.UUID, date time.Time) ([]*models.LeaveAccrual, error)
	GetTotalAccruedDays(ctx context.Context, entitlementID uuid.UUID) (float64, error)

	// ========================================================================
	// Leave requests
	// ========================================================================
	CreateLeaveRequest(ctx context.Context, request *models.LeaveRequest) error
	GetLeaveRequestByID(ctx context.Context, requestID uuid.UUID) (*models.LeaveRequest, error)
	GetLeaveRequestsByUser(ctx context.Context, userID uuid.UUID, startDate, endDate time.Time) ([]*models.LeaveRequest, error)
	GetLeaveRequestsByCompany(ctx context.Context, filter models.LeaveRequestFilter) ([]*models.LeaveRequest, int64, error)
	GetPendingLeaveRequests(
		ctx context.Context,
		companyID uuid.UUID,
		approverID uuid.UUID,
		locationID *uuid.UUID,
	) ([]*models.LeaveRequest, error)
	UpdateLeaveRequest(ctx context.Context, requestID uuid.UUID, update *models.LeaveRequestUpdate) error
	CancelLeaveRequest(ctx context.Context, requestID uuid.UUID) error
	CheckLeaveOverlap(ctx context.Context, userID uuid.UUID, startDate, endDate time.Time, excludeRequestID *uuid.UUID) (bool, error)
	ValidateLeaveRequest(
		ctx context.Context,
		req *models.LeaveRequestCreate,
		positionID *uuid.UUID,
	) (bool, string, error)
	ProcessLeaveRequest(ctx context.Context, requestID uuid.UUID, approved bool, approvedBy uuid.UUID) error

	// ========================================================================
	// Balances / quota
	// ========================================================================
	GetLeaveBalance(
		ctx context.Context,
		userID, leaveTypeID uuid.UUID,
		positionID *uuid.UUID,
	) (*models.LeaveBalance, error)
	GetLeaveBalancesByUser(
		ctx context.Context,
		userID uuid.UUID,
		positionID *uuid.UUID,
		asOfDate time.Time,
	) ([]*models.LeaveBalance, error)
	CalculateLeaveBalance(
		ctx context.Context,
		userID, leaveTypeID uuid.UUID,
		asOfDate time.Time,
		positionID *uuid.UUID,
	) (*models.LeaveBalance, error)
	GetLeaveQuota(
		ctx context.Context,
		userID, leaveTypeID uuid.UUID,
		positionID *uuid.UUID,
	) (int, float64, error)
	CheckLeaveAvailability(
		ctx context.Context,
		userID, leaveTypeID uuid.UUID,
		days int,
		startDate time.Time,
		positionID *uuid.UUID,
	) (bool, float64, error)
	GetLeaveTransactionHistory(ctx context.Context, userID uuid.UUID, startDate, endDate time.Time) ([]*models.LeaveTransaction, error)
	GetLeaveForecast(ctx context.Context, userID uuid.UUID, months int) ([]*models.LeaveBalance, error)
	GetLeaveUtilizationReport(
		ctx context.Context,
		companyID uuid.UUID,
		locationID *uuid.UUID,
		startDate, endDate time.Time,
	) ([]*models.LeaveBalance, error)
	CreateLeaveBalanceSnapshot(
		ctx context.Context,
		snapshot *models.LeaveBalanceSnapshot,
	) error
	GetLatestLeaveBalanceSnapshot(
		ctx context.Context,
		entitlementID uuid.UUID,
	) (*models.LeaveBalanceSnapshot, error)

	// ========================================================================
	// Accrual processing (batched, idempotent)
	// ========================================================================
	ProcessLeaveAccruals(ctx context.Context, companyID uuid.UUID, accrualDate time.Time) (int, error)
	GetCompanyFinancialYearStartMonth(ctx context.Context, companyID uuid.UUID) (int, error)

	// ========================================================================
	// Leave policy management
	// ========================================================================
	CreateLeavePolicy(ctx context.Context, policy *models.LeavePolicy) error
	GetLeavePolicyByID(ctx context.Context, policyID uuid.UUID) (*models.LeavePolicy, error)
	GetActiveLeavePoliciesByCompany(ctx context.Context, companyID uuid.UUID, asOf time.Time) ([]*models.LeavePolicy, error)
	DeactivateLeavePolicy(ctx context.Context, policyID uuid.UUID) error
	UpdateLeavePolicy(
		ctx context.Context,
		policyID uuid.UUID,
		update *models.LeavePolicyUpdate,
	) error

	// ========================================================================
	// Policy rules
	// ========================================================================
	AddPolicyRule(ctx context.Context, rule *models.LeavePolicyRule) error
	GetPolicyRules(ctx context.Context, policyID uuid.UUID) ([]*models.LeavePolicyRule, error)
	DeletePolicyRule(ctx context.Context, policyRuleID uuid.UUID) error
	UpdatePolicyRule(
		ctx context.Context,
		companyID uuid.UUID,
		policyRuleID uuid.UUID,
		update *models.LeavePolicyRuleUpdate,
	) error

	// GetPolicyRuleByID — single-row lookup. Needed by RemovePolicyRule to
	// derive the owning company from the rule instead of trusting caller
	// metadata.
	GetPolicyRuleByID(ctx context.Context, policyRuleID uuid.UUID) (*models.LeavePolicyRule, error)

	// ========================================================================
	// Policy resolution
	// ========================================================================
	CreateLeavePolicyResolution(
		ctx context.Context,
		companyID uuid.UUID,
		userID uuid.UUID,
		policyID *uuid.UUID,
		reason string,
		meta map[string]interface{},
	) error
	ResolveUserPolicyRules(
		ctx context.Context,
		companyID uuid.UUID,
		userID uuid.UUID,
		asOf time.Time,
	) ([]*models.LeavePolicyRuleResolution, error)

	// ========================================================================
	// Policy-driven entitlement helpers (non-Tx)
	// ========================================================================
	EndActivePolicyEntitlements(
		ctx context.Context,
		companyID uuid.UUID,
		userID uuid.UUID,
		effectiveTo time.Time,
		positionID *uuid.UUID,
	) error
	EndActivePolicyEntitlementsByLeaveType(
		ctx context.Context,
		companyID uuid.UUID,
		userID uuid.UUID,
		leaveTypeID uuid.UUID,
		effectiveTo time.Time,
		positionID *uuid.UUID,
	) error
	CreatePolicyLeaveEntitlement(
		ctx context.Context,
		entitlement *models.LeaveEntitlement,
	) error
	GetActivePolicyEntitlement(
		ctx context.Context,
		companyID uuid.UUID,
		userID uuid.UUID,
		leaveTypeID uuid.UUID,
		positionID *uuid.UUID,
	) (*models.LeaveEntitlement, error)

	// ========================================================================
	// Employee / position context
	// ========================================================================
	ListActiveEmployeeUserIDs(ctx context.Context, companyID uuid.UUID) ([]uuid.UUID, error)
	ListActiveEmployeeUserIDsByPosition(ctx context.Context, companyID, positionID uuid.UUID) ([]uuid.UUID, error)
	GetUserPositionContext(
		ctx context.Context,
		companyID uuid.UUID,
		userID uuid.UUID,
	) (*uuid.UUID, *string, error)

	// ========================================================================
	// Health
	// ========================================================================
	HealthCheck(ctx context.Context) error

	// ============================================================================
	// *Tx variants — methods that must run inside a caller-owned transaction
	// so their writes can commit atomically with a sibling write (typically
	// the resolver-job enqueue in leave_policy_config_service.go, or the
	// request + ledger insert in leave_request_service.go).
	//
	// Each *Tx variant mirrors a non-Tx method above with identical SQL. The
	// caller is responsible for BeginTx / Commit / Rollback.
	// ============================================================================

	// --- Leave policy lifecycle ---

	CreateLeavePolicyTx(
		ctx context.Context,
		tx *sql.Tx,
		policy *models.LeavePolicy,
	) error
	DeactivateLeavePolicyTx(
		ctx context.Context,
		tx *sql.Tx,
		policyID uuid.UUID,
	) error
	UpdateLeavePolicyTx(
		ctx context.Context,
		tx *sql.Tx,
		policyID uuid.UUID,
		update *models.LeavePolicyUpdate,
	) error

	// --- Policy rules ---

	AddPolicyRuleTx(
		ctx context.Context,
		tx *sql.Tx,
		rule *models.LeavePolicyRule,
	) error
	UpdatePolicyRuleTx(
		ctx context.Context,
		tx *sql.Tx,
		companyID uuid.UUID,
		policyRuleID uuid.UUID,
		update *models.LeavePolicyRuleUpdate,
	) error
	DeletePolicyRuleTx(
		ctx context.Context,
		tx *sql.Tx,
		policyRuleID uuid.UUID,
	) error

	// --- Leave request lifecycle ---

	CreateLeaveRequestTx(
		ctx context.Context,
		tx *sql.Tx,
		request *models.LeaveRequest,
	) error
	ProcessLeaveRequestTx(
		ctx context.Context,
		tx *sql.Tx,
		requestID uuid.UUID,
		approved bool,
		approvedBy uuid.UUID,
	) error

	// --- Policy entitlement swap (end + create) ---

	EndActivePolicyEntitlementsByLeaveTypeTx(
		ctx context.Context,
		tx *sql.Tx,
		companyID uuid.UUID,
		userID uuid.UUID,
		leaveTypeID uuid.UUID,
		endDate time.Time,
		positionID *uuid.UUID,
	) error
	CreatePolicyLeaveEntitlementTx(
		ctx context.Context,
		tx *sql.Tx,
		entitlement *models.LeaveEntitlement,
	) error
}

package repository

import (
	"auth-service/internal/hr/leave/models"
	"context"
	"time"

	"github.com/google/uuid"
)

type LeaveRepository interface {
	// Existing methods
	CreateLeaveType(ctx context.Context, leaveType *models.LeaveType) error
	GetLeaveTypeByID(ctx context.Context, leaveTypeID uuid.UUID) (*models.LeaveType, error)
	GetLeaveTypeByCode(ctx context.Context, companyID uuid.UUID, code string) (*models.LeaveType, error)
	GetLeaveTypesByCompany(ctx context.Context, companyID uuid.UUID) ([]*models.LeaveType, error)
	UpdateLeaveType(ctx context.Context, leaveTypeID uuid.UUID, update *models.LeaveTypeUpdate) error
	DeleteLeaveType(ctx context.Context, leaveTypeID uuid.UUID) error

	CreateLeaveEntitlement(ctx context.Context, entitlement *models.LeaveEntitlement) error
	GetLeaveEntitlementByID(ctx context.Context, entitlementID uuid.UUID) (*models.LeaveEntitlement, error)
	GetLeaveEntitlementsByUser(ctx context.Context, userID uuid.UUID, positionID *uuid.UUID,
	) ([]*models.LeaveEntitlement, error)
	GetLeaveEntitlementsByCompany(ctx context.Context, companyID uuid.UUID, page, pageSize int) ([]*models.LeaveEntitlement, int64, error)
	UpdateLeaveEntitlement(ctx context.Context, entitlementID uuid.UUID, update *models.LeaveEntitlementUpdate) error
	EndLeaveEntitlement(ctx context.Context, entitlementID uuid.UUID, endDate time.Time) error
	GetActiveLeaveEntitlement(
		context.Context,
		uuid.UUID,
		uuid.UUID,
		time.Time,
		*uuid.UUID,
	) (*models.LeaveEntitlement, error)

	CreateLeaveAccrual(ctx context.Context, accrual *models.LeaveAccrual) error
	CreateBulkLeaveAccruals(ctx context.Context, accruals []*models.LeaveAccrual) error
	GetLeaveAccrualsByEntitlement(ctx context.Context, entitlementID uuid.UUID) ([]*models.LeaveAccrual, error)
	GetLeaveAccrualsByDate(ctx context.Context, companyID uuid.UUID, date time.Time) ([]*models.LeaveAccrual, error)
	GetTotalAccruedDays(ctx context.Context, entitlementID uuid.UUID) (float64, error)

	CreateLeaveRequest(ctx context.Context, request *models.LeaveRequest) error
	GetLeaveRequestByID(ctx context.Context, requestID uuid.UUID) (*models.LeaveRequest, error)
	GetLeaveRequestsByUser(ctx context.Context, userID uuid.UUID, startDate, endDate time.Time) ([]*models.LeaveRequest, error)
	GetLeaveRequestsByCompany(ctx context.Context, filter models.LeaveRequestFilter) ([]*models.LeaveRequest, int64, error)
	GetPendingLeaveRequests(ctx context.Context, companyID uuid.UUID, approverID uuid.UUID) ([]*models.LeaveRequest, error)
	UpdateLeaveRequest(ctx context.Context, requestID uuid.UUID, update *models.LeaveRequestUpdate) error
	CancelLeaveRequest(ctx context.Context, requestID uuid.UUID) error
	CheckLeaveOverlap(ctx context.Context, userID uuid.UUID, startDate, endDate time.Time, excludeRequestID *uuid.UUID) (bool, error)

	CreateLeaveLedgerEntry(ctx context.Context, entry *models.LeaveLedger) error
	CreateBulkLeaveLedgerEntries(ctx context.Context, entries []*models.LeaveLedger) error
	GetLeaveLedgerEntriesByEntitlement(ctx context.Context, entitlementID uuid.UUID) ([]*models.LeaveLedger, error)
	GetLeaveLedgerEntriesByRequest(ctx context.Context, requestID uuid.UUID) ([]*models.LeaveLedger, error)

	GetLeaveBalance(
		ctx context.Context,
		userID uuid.UUID,
		leaveTypeID uuid.UUID,
		positionID *uuid.UUID,
	) (*models.LeaveBalance, error)

	GetLeaveBalancesByUser(
		ctx context.Context,
		userID uuid.UUID,
		positionID *uuid.UUID,
		asOfDate time.Time,
	) ([]*models.LeaveBalance, error)

	GetLeaveTransactionHistory(ctx context.Context, userID uuid.UUID, startDate, endDate time.Time) ([]*models.LeaveTransaction, error)

	ProcessLeaveRequest(ctx context.Context, requestID uuid.UUID, approved bool, approvedBy uuid.UUID) error
	ProcessLeaveAccruals(ctx context.Context, companyID uuid.UUID, accrualDate time.Time) (int, error)
	GetLeaveUtilizationReport(ctx context.Context, companyID uuid.UUID, startDate, endDate time.Time) ([]*models.LeaveBalance, error)
	GetLeaveForecast(ctx context.Context, userID uuid.UUID, months int) ([]*models.LeaveBalance, error)
	CalculateLeaveBalance(
		ctx context.Context,
		userID uuid.UUID,
		leaveTypeID uuid.UUID,
		asOfDate time.Time,
		positionID *uuid.UUID,
	) (*models.LeaveBalance, error)

	ValidateLeaveRequest(
		ctx context.Context,
		req *models.LeaveRequestCreate,
		positionID *uuid.UUID,
	) (bool, string, error)

	GetLeaveQuota(
		ctx context.Context,
		userID uuid.UUID,
		leaveTypeID uuid.UUID,
		positionID *uuid.UUID,
	) (int, float64, error)
	CheckLeaveAvailability(
		ctx context.Context,
		userID, leaveTypeID uuid.UUID,
		days int,
		startDate time.Time,
		positionID *uuid.UUID,
	) (bool, float64, error)
	CreateLeaveBalanceSnapshot(
		ctx context.Context,
		snapshot *models.LeaveBalanceSnapshot,
	) error
	GetLatestLeaveBalanceSnapshot(
		ctx context.Context,
		entitlementID uuid.UUID,
	) (*models.LeaveBalanceSnapshot, error)

	HealthCheck(ctx context.Context) error

	// NEW METHODS: Leave Policy Management
	CreateLeavePolicy(ctx context.Context, policy *models.LeavePolicy) error
	GetLeavePolicyByID(ctx context.Context, policyID uuid.UUID) (*models.LeavePolicy, error)
	GetActiveLeavePoliciesByCompany(ctx context.Context, companyID uuid.UUID, asOf time.Time) ([]*models.LeavePolicy, error)
	DeactivateLeavePolicy(ctx context.Context, policyID uuid.UUID) error

	// Policy Rules
	AddPolicyRule(ctx context.Context, rule *models.LeavePolicyRule) error
	GetPolicyRules(ctx context.Context, policyID uuid.UUID) ([]*models.LeavePolicyRule, error)
	DeletePolicyRule(ctx context.Context, policyRuleID uuid.UUID) error

	// Policy Resolution (SAP-style)
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
	// Policy Entitlement Helpers
	EndActivePolicyEntitlements(
		ctx context.Context,
		companyID uuid.UUID,
		userID uuid.UUID,
		effectiveTo time.Time,
		positionID *uuid.UUID,
	) error

	CreatePolicyLeaveEntitlement(
		ctx context.Context,
		entitlement *models.LeaveEntitlement,
	) error
	EndActivePolicyEntitlementsByLeaveType(
		ctx context.Context,
		companyID uuid.UUID,
		userID uuid.UUID,
		leaveTypeID uuid.UUID,
		effectiveTo time.Time,
		positionID *uuid.UUID,
	) error
	// In LeaveRepository interface
	GetLeaveEntitlementsByCompanyAndUser(
		ctx context.Context,
		companyID uuid.UUID,
		userID *uuid.UUID,
		page, pageSize int,
	) ([]*models.LeaveEntitlement, int64, error)
	GetUserPositionContext(
		ctx context.Context,
		companyID uuid.UUID,
		userID uuid.UUID,
	) (*uuid.UUID, *string, error)
	GetActivePolicyEntitlement(
		ctx context.Context,
		companyID uuid.UUID,
		userID uuid.UUID,
		leaveTypeID uuid.UUID,
		positionID *uuid.UUID,
	) (*models.LeaveEntitlement, error)
	UpdateLeavePolicy(
		ctx context.Context,
		policyID uuid.UUID,
		update *models.LeavePolicyUpdate,
	) error
	UpdatePolicyRule(
		ctx context.Context,
		companyID uuid.UUID,
		policyRuleID uuid.UUID,
		update *models.LeavePolicyRuleUpdate,
	) error
	IsLeaveTypeInUse(ctx context.Context, leaveTypeID uuid.UUID) (bool, error)
	GetCompanyFinancialYearStartMonth(
		ctx context.Context,
		companyID uuid.UUID,
	) (int, error)
}

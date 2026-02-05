package repository

import (
	"context"
	"time"

	"github.com/google/uuid"

	"auth-service/internal/hr/leave/models"
)

type LeaveRepository interface {
	// ==============================================
	// LEAVE TYPE OPERATIONS
	// ==============================================
	CreateLeaveType(ctx context.Context, leaveType *models.LeaveType) error
	GetLeaveTypeByID(ctx context.Context, leaveTypeID uuid.UUID) (*models.LeaveType, error)
	GetLeaveTypeByCode(ctx context.Context, companyID uuid.UUID, code string) (*models.LeaveType, error)
	GetLeaveTypesByCompany(ctx context.Context, companyID uuid.UUID) ([]*models.LeaveType, error)
	UpdateLeaveType(ctx context.Context, leaveTypeID uuid.UUID, update *models.LeaveTypeUpdate) error
	DeleteLeaveType(ctx context.Context, leaveTypeID uuid.UUID) error

	// ==============================================
	// LEAVE ENTITLEMENT OPERATIONS
	// ==============================================
	CreateLeaveEntitlement(ctx context.Context, entitlement *models.LeaveEntitlement) error
	GetLeaveEntitlementByID(ctx context.Context, entitlementID uuid.UUID) (*models.LeaveEntitlement, error)
	GetLeaveEntitlementsByUser(ctx context.Context, userID uuid.UUID) ([]*models.LeaveEntitlement, error)
	GetActiveLeaveEntitlement(ctx context.Context, userID, leaveTypeID uuid.UUID, date time.Time) (*models.LeaveEntitlement, error)
	GetLeaveEntitlementsByCompany(ctx context.Context, companyID uuid.UUID, page, pageSize int) ([]*models.LeaveEntitlement, int64, error)
	UpdateLeaveEntitlement(ctx context.Context, entitlementID uuid.UUID, update *models.LeaveEntitlementUpdate) error
	EndLeaveEntitlement(ctx context.Context, entitlementID uuid.UUID, endDate time.Time) error

	// ==============================================
	// LEAVE ACCRUAL OPERATIONS
	// ==============================================
	CreateLeaveAccrual(ctx context.Context, accrual *models.LeaveAccrual) error
	CreateBulkLeaveAccruals(ctx context.Context, accruals []*models.LeaveAccrual) error
	GetLeaveAccrualsByEntitlement(ctx context.Context, entitlementID uuid.UUID) ([]*models.LeaveAccrual, error)
	GetLeaveAccrualsByDate(ctx context.Context, companyID uuid.UUID, date time.Time) ([]*models.LeaveAccrual, error)
	GetTotalAccruedDays(ctx context.Context, entitlementID uuid.UUID) (int, error)

	// ==============================================
	// LEAVE REQUEST OPERATIONS
	// ==============================================
	CreateLeaveRequest(ctx context.Context, request *models.LeaveRequest) error
	GetLeaveRequestByID(ctx context.Context, requestID uuid.UUID) (*models.LeaveRequest, error)
	GetLeaveRequestsByUser(ctx context.Context, userID uuid.UUID, startDate, endDate time.Time) ([]*models.LeaveRequest, error)
	GetLeaveRequestsByCompany(ctx context.Context, filter models.LeaveRequestFilter) ([]*models.LeaveRequest, int64, error)
	GetPendingLeaveRequests(ctx context.Context, companyID uuid.UUID, approverID uuid.UUID) ([]*models.LeaveRequest, error)
	UpdateLeaveRequest(ctx context.Context, requestID uuid.UUID, update *models.LeaveRequestUpdate) error
	CancelLeaveRequest(ctx context.Context, requestID uuid.UUID) error
	CheckLeaveOverlap(ctx context.Context, userID uuid.UUID, startDate, endDate time.Time, excludeRequestID *uuid.UUID) (bool, error)

	// ==============================================
	// LEAVE LEDGER OPERATIONS
	// ==============================================
	CreateLeaveLedgerEntry(ctx context.Context, entry *models.LeaveLedger) error
	CreateBulkLeaveLedgerEntries(ctx context.Context, entries []*models.LeaveLedger) error
	GetLeaveLedgerEntriesByEntitlement(ctx context.Context, entitlementID uuid.UUID) ([]*models.LeaveLedger, error)
	GetLeaveLedgerEntriesByRequest(ctx context.Context, requestID uuid.UUID) ([]*models.LeaveLedger, error)
	GetLeaveBalance(ctx context.Context, userID, leaveTypeID uuid.UUID) (*models.LeaveBalance, error)
	GetLeaveBalancesByUser(ctx context.Context, userID uuid.UUID) ([]*models.LeaveBalance, error)
	GetLeaveTransactionHistory(ctx context.Context, userID uuid.UUID, startDate, endDate time.Time) ([]*models.LeaveTransaction, error)

	// ==============================================
	// BUSINESS LOGIC OPERATIONS
	// ==============================================
	ProcessLeaveRequest(ctx context.Context, requestID uuid.UUID, approved bool, approvedBy uuid.UUID) error
	ProcessLeaveAccruals(ctx context.Context, companyID uuid.UUID, accrualDate time.Time) (int, error)
	CalculateLeaveBalance(ctx context.Context, userID, leaveTypeID uuid.UUID, asOfDate time.Time) (*models.LeaveBalance, error)
	GetLeaveUtilizationReport(ctx context.Context, companyID uuid.UUID, startDate, endDate time.Time) ([]*models.LeaveBalance, error)
	GetLeaveForecast(ctx context.Context, userID uuid.UUID, months int) ([]*models.LeaveBalance, error)

	// ==============================================
	// VALIDATION OPERATIONS
	// ==============================================
	ValidateLeaveRequest(ctx context.Context, request *models.LeaveRequestCreate) (bool, string, error)
	CheckLeaveAvailability(ctx context.Context, userID, leaveTypeID uuid.UUID, days int, startDate time.Time) (bool, int, error)
	GetLeaveQuota(ctx context.Context, userID, leaveTypeID uuid.UUID) (int, int, error) // available, total
	CreateLeaveBalanceSnapshot(
		ctx context.Context,
		snapshot *models.LeaveBalanceSnapshot,
	) error

	GetLatestLeaveBalanceSnapshot(
		ctx context.Context,
		entitlementID uuid.UUID,
	) (*models.LeaveBalanceSnapshot, error)

	// ==============================================
	// HEALTH CHECK
	// ==============================================
	HealthCheck(ctx context.Context) error
}

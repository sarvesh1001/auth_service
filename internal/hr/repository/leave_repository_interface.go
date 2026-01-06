package repository

import (
	"auth-service/internal/hr/models/leave"
	"context"
	"time"

	"github.com/google/uuid"
)

// LeaveRepository defines all operations for Leave module
type LeaveRepository interface {
	// Health check
	HealthCheck(ctx context.Context) error

	// Leave Types
	CreateLeaveType(ctx context.Context, leaveType *leave.LeaveType) error
	GetLeaveTypeByID(ctx context.Context, leaveTypeID uuid.UUID) (*leave.LeaveType, error)
	GetLeaveTypeByCode(ctx context.Context, companyID uuid.UUID, leaveCode string) (*leave.LeaveType, error)
	UpdateLeaveType(ctx context.Context, leaveType *leave.LeaveType) error
	DeleteLeaveType(ctx context.Context, leaveTypeID uuid.UUID) error
	ListLeaveTypesByCompany(ctx context.Context, companyID uuid.UUID, includeInactive bool) ([]*leave.LeaveType, error)
	SearchLeaveTypes(ctx context.Context, companyID uuid.UUID, filters map[string]interface{}, limit, offset int) ([]*leave.LeaveType, int, error)

	// Leave Policies
	CreateLeavePolicy(ctx context.Context, policy *leave.LeavePolicy) error
	GetLeavePolicyByID(ctx context.Context, policyID uuid.UUID) (*leave.LeavePolicy, error)
	GetLeavePolicyByCode(ctx context.Context, companyID uuid.UUID, policyCode string) (*leave.LeavePolicy, error)
	UpdateLeavePolicy(ctx context.Context, policy *leave.LeavePolicy) error
	DeleteLeavePolicy(ctx context.Context, policyID uuid.UUID) error
	ListLeavePoliciesByCompany(ctx context.Context, companyID uuid.UUID, includeInactive bool) ([]*leave.LeavePolicy, error)
	ListLeavePoliciesByDepartment(ctx context.Context, companyID, departmentID uuid.UUID) ([]*leave.LeavePolicy, error)
	SearchLeavePolicies(ctx context.Context, companyID uuid.UUID, filters map[string]interface{}, limit, offset int) ([]*leave.LeavePolicy, int, error)

	// User Leave Policies
	AssignUserLeavePolicy(ctx context.Context, userPolicy *leave.UserLeavePolicy) error
	GetUserLeavePolicy(ctx context.Context, userID, policyID uuid.UUID, effectiveFrom time.Time) (*leave.UserLeavePolicy, error)
	GetActiveUserLeavePolicies(ctx context.Context, userID uuid.UUID, asOf time.Time) ([]*leave.UserLeavePolicy, error)
	UpdateUserLeavePolicy(ctx context.Context, userPolicy *leave.UserLeavePolicy) error
	RemoveUserLeavePolicy(ctx context.Context, userID, policyID uuid.UUID, effectiveFrom time.Time) error
	ListUserLeavePoliciesByUser(ctx context.Context, userID uuid.UUID) ([]*leave.UserLeavePolicy, error)
	ListUsersByLeavePolicy(ctx context.Context, policyID uuid.UUID, effectiveDate time.Time) ([]uuid.UUID, error)

	// Leave Requests
	CreateLeaveRequest(ctx context.Context, req *leave.LeaveRequest) error
	GetLeaveRequestByID(ctx context.Context, requestID uuid.UUID) (*leave.LeaveRequest, error)
	GetLeaveRequestWithApprovals(ctx context.Context, requestID uuid.UUID) (*leave.LeaveRequest, []*leave.LeaveApproval, error)
	UpdateLeaveRequest(ctx context.Context, req *leave.LeaveRequest) error
	CancelLeaveRequest(ctx context.Context, requestID uuid.UUID, reason string) error
	DeleteLeaveRequest(ctx context.Context, requestID uuid.UUID) error
	ListLeaveRequestsByUser(ctx context.Context, userID uuid.UUID, startDate, endDate time.Time) ([]*leave.LeaveRequest, error)
	ListLeaveRequestsByCompany(ctx context.Context, companyID uuid.UUID, filters map[string]interface{}, limit, offset int) ([]*leave.LeaveRequest, int, error)
	ListPendingLeaveRequests(ctx context.Context, companyID uuid.UUID, approverID uuid.UUID) ([]*leave.LeaveRequest, error)
	CheckLeaveOverlap(ctx context.Context, userID uuid.UUID, startDate, endDate time.Time, excludeRequestID *uuid.UUID) (bool, error)

	// Leave Approvals
	CreateLeaveApproval(ctx context.Context, approval *leave.LeaveApproval) error
	GetLeaveApprovalByID(ctx context.Context, approvalID uuid.UUID) (*leave.LeaveApproval, error)
	GetApprovalsByLeaveRequest(ctx context.Context, requestID uuid.UUID) ([]*leave.LeaveApproval, error)
	UpdateLeaveApproval(ctx context.Context, approval *leave.LeaveApproval) error
	DeleteLeaveApproval(ctx context.Context, approvalID uuid.UUID) error
	GetApprovalChain(ctx context.Context, requestID uuid.UUID) ([]*leave.LeaveApproval, error)
	HasUserApprovedRequest(ctx context.Context, requestID, userID uuid.UUID) (bool, error)

	// Leave Transactions
	CreateLeaveTransaction(ctx context.Context, txn *leave.LeaveTransaction) error
	GetLeaveTransactionByID(ctx context.Context, txnID uuid.UUID) (*leave.LeaveTransaction, error)
	GetLeaveTransactionsByUser(ctx context.Context, userID uuid.UUID, leaveTypeID *uuid.UUID, startDate, endDate time.Time) ([]*leave.LeaveTransaction, error)
	GetLeaveTransactionsByRequest(ctx context.Context, requestID uuid.UUID) ([]*leave.LeaveTransaction, error)
	CalculateLeaveBalance(ctx context.Context, userID, leaveTypeID uuid.UUID, asOf time.Time) (float64, error)
	GetTransactionSummary(ctx context.Context, userID uuid.UUID, startDate, endDate time.Time) (map[string]float64, error)

	// Leave Balances
	CreateOrUpdateLeaveBalance(ctx context.Context, balance *leave.LeaveBalance) error
	GetLeaveBalance(ctx context.Context, companyID, userID, leaveTypeID uuid.UUID, asOf time.Time) (*leave.LeaveBalance, error)
	GetCurrentLeaveBalance(ctx context.Context, userID, leaveTypeID uuid.UUID) (*leave.LeaveBalance, error)
	GetLeaveBalancesByUser(ctx context.Context, userID uuid.UUID, asOf time.Time) ([]*leave.LeaveBalance, error)
	UpdateLeaveBalance(ctx context.Context, balance *leave.LeaveBalance) error
	DeleteLeaveBalance(ctx context.Context, companyID, userID, leaveTypeID uuid.UUID, asOf time.Time) error
	RecalculateLeaveBalances(ctx context.Context, userID uuid.UUID, fromDate time.Time) error

	// Analytics and Reports
	GetLeaveUsageStats(ctx context.Context, companyID uuid.UUID, startDate, endDate time.Time) (*LeaveUsageStats, error)
	GetDepartmentLeaveStats(ctx context.Context, companyID uuid.UUID, departmentID *uuid.UUID, startDate, endDate time.Time) (map[uuid.UUID]*LeaveDepartmentStats, error)
	GetEmployeeLeaveSummary(ctx context.Context, userID uuid.UUID, year int) (*EmployeeLeaveSummary, error)
	GetLeaveTrends(ctx context.Context, companyID uuid.UUID, startDate, endDate time.Time, interval string) ([]*LeaveTrendData, error)

	// Batch Operations
	CreateLeaveTypesBatch(ctx context.Context, leaveTypes []*leave.LeaveType) error
	CreateLeavePoliciesBatch(ctx context.Context, policies []*leave.LeavePolicy) error
	AssignLeavePoliciesBatch(ctx context.Context, userPolicies []*leave.UserLeavePolicy) error
	CreateLeaveRequestsBatch(ctx context.Context, requests []*leave.LeaveRequest) error
	CreateLeaveTransactionsBatch(ctx context.Context, transactions []*leave.LeaveTransaction) error
}

// LeaveUsageStats represents leave usage statistics
type LeaveUsageStats struct {
	TotalRequests     int     `json:"total_requests"`
	ApprovedRequests  int     `json:"approved_requests"`
	PendingRequests   int     `json:"pending_requests"`
	RejectedRequests  int     `json:"rejected_requests"`
	TotalLeaveDays    float64 `json:"total_leave_days"`
	AverageLeaveDays  float64 `json:"average_leave_days"`
	MostUsedLeaveType string  `json:"most_used_leave_type"`
}

// LeaveDepartmentStats represents leave statistics by department
type LeaveDepartmentStats struct {
	DepartmentName  string  `json:"department_name"`
	TotalEmployees  int     `json:"total_employees"`
	TotalLeaveDays  float64 `json:"total_leave_days"`
	AvgLeavePerEmp  float64 `json:"avg_leave_per_emp"`
	PendingRequests int     `json:"pending_requests"`
}

// EmployeeLeaveSummary represents yearly leave summary for an employee
type EmployeeLeaveSummary struct {
	Year               int                         `json:"year"`
	TotalEntitlement   float64                     `json:"total_entitlement"`
	TotalUsed          float64                     `json:"total_used"`
	TotalBalance       float64                     `json:"total_balance"`
	LeaveTypeBreakdown map[string]LeaveTypeSummary `json:"leave_type_breakdown"`
	MonthlyBreakdown   map[string]float64          `json:"monthly_breakdown"`
	CarryForward       float64                     `json:"carry_forward"`
}

// LeaveTypeSummary represents summary for a specific leave type
type LeaveTypeSummary struct {
	LeaveTypeName string  `json:"leave_type_name"`
	Entitlement   float64 `json:"entitlement"`
	Used          float64 `json:"used"`
	Balance       float64 `json:"balance"`
	CarryForward  float64 `json:"carry_forward"`
}

// LeaveTrendData represents leave trend data for visualization
type LeaveTrendData struct {
	Period          string  `json:"period"`
	TotalRequests   int     `json:"total_requests"`
	ApprovedDays    float64 `json:"approved_days"`
	PendingDays     float64 `json:"pending_days"`
	AvgApprovalTime float64 `json:"avg_approval_time"`
}

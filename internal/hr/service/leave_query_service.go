package service

import (
	"auth-service/internal/hr/models/leave"
	"auth-service/internal/hr/repository"
	"auth-service/internal/util"
	"context"
	"encoding/csv"
	"encoding/json"
	"fmt"
	"io"
	"strings"
	"sync"
	"time"

	"github.com/google/uuid"
	"go.uber.org/zap"
)

// LeaveQueryFilters provides typed filters for leave queries
type LeaveQueryFilters struct {
	UserID            *uuid.UUID
	UserIDs           []uuid.UUID
	LeaveTypeID       *uuid.UUID
	LeaveTypeIDs      []uuid.UUID
	Status            *string
	Statuses          []string
	StartDateFrom     *time.Time
	StartDateTo       *time.Time
	EndDateFrom       *time.Time
	EndDateTo         *time.Time
	DepartmentID      *uuid.UUID
	RequiresApproval  *bool
	IsStatutory       *bool
	AffectsPay        *bool
	PolicyID          *uuid.UUID
	ApproverID        *uuid.UUID
	TransactionReason *string
	MinBalance        *float64
	MaxBalance        *float64
}

// LeaveSummaryStats provides statistical summary of leaves
type LeaveSummaryStats struct {
	TotalRequests        int64            `json:"total_requests"`
	ApprovedRequests     int64            `json:"approved_requests"`
	PendingRequests      int64            `json:"pending_requests"`
	RejectedRequests     int64            `json:"rejected_requests"`
	TotalLeaveDays       float64          `json:"total_leave_days"`
	AverageLeaveDays     float64          `json:"average_leave_days"`
	MostUsedLeaveType    string           `json:"most_used_leave_type"`
	ByMonth              map[string]int64 `json:"by_month"`
	ByDepartment         map[string]int64 `json:"by_department"`
	ByStatus             map[string]int64 `json:"by_status"`
	AvgApprovalTimeHours float64          `json:"avg_approval_time_hours"`
	LeaveUtilizationRate float64          `json:"leave_utilization_rate"`
}

// LeaveDepartmentStats provides department-level leave statistics
type LeaveDepartmentStats struct {
	DepartmentName  string  `json:"department_name"`
	TotalEmployees  int     `json:"total_employees"`
	TotalLeaveDays  float64 `json:"total_leave_days"`
	AvgLeavePerEmp  float64 `json:"avg_leave_per_emp"`
	PendingRequests int     `json:"pending_requests"`
}

// EmployeeLeaveSummary provides comprehensive leave summary for an employee
type EmployeeLeaveSummary struct {
	Year               int                         `json:"year"`
	TotalEntitlement   float64                     `json:"total_entitlement"`
	TotalUsed          float64                     `json:"total_used"`
	TotalBalance       float64                     `json:"total_balance"`
	LeaveTypeBreakdown map[string]LeaveTypeSummary `json:"leave_type_breakdown"`
	MonthlyBreakdown   map[string]float64          `json:"monthly_breakdown"`
	RecentRequests     []*leave.LeaveRequest       `json:"recent_requests"`
	UpcomingLeaves     []*leave.LeaveRequest       `json:"upcoming_leaves"`
}

// LeaveTypeSummary provides summary for a specific leave type
type LeaveTypeSummary struct {
	LeaveTypeName string  `json:"leave_type_name"`
	Entitlement   float64 `json:"entitlement"`
	Used          float64 `json:"used"`
	Balance       float64 `json:"balance"`
}

// LeaveTrendData provides trend analysis data
type LeaveTrendData struct {
	Period          string  `json:"period"`
	TotalRequests   int64   `json:"total_requests"`
	ApprovedDays    float64 `json:"approved_days"`
	PendingDays     float64 `json:"pending_days"`
	AvgApprovalTime float64 `json:"avg_approval_time"`
}

// LeaveUsageStats provides usage statistics
type LeaveUsageStats struct {
	TotalRequests     int64   `json:"total_requests"`
	ApprovedRequests  int64   `json:"approved_requests"`
	PendingRequests   int64   `json:"pending_requests"`
	RejectedRequests  int64   `json:"rejected_requests"`
	TotalLeaveDays    float64 `json:"total_leave_days"`
	AverageLeaveDays  float64 `json:"average_leave_days"`
	MostUsedLeaveType string  `json:"most_used_leave_type"`
}

// LeaveReport defines a leave report structure
type LeaveReport struct {
	ReportID    uuid.UUID `json:"report_id"`
	ReportType  string    `json:"report_type"`
	CompanyID   uuid.UUID `json:"company_id"`
	GeneratedAt time.Time `json:"generated_at"`
	GeneratedBy string    `json:"generated_by"`
	PeriodStart time.Time `json:"period_start"`
	PeriodEnd   time.Time `json:"period_end"`
	Format      string    `json:"format"`
	Status      string    `json:"status"`
	DownloadURL *string   `json:"download_url,omitempty"`
	FileSize    *int64    `json:"file_size,omitempty"`
	Error       *string   `json:"error,omitempty"`
}

// LeaveQueryService provides query and reporting functionality for leave management
type LeaveQueryService interface {
	// Leave Types
	GetLeaveTypeByID(ctx context.Context, leaveTypeID uuid.UUID) (*leave.LeaveType, error)
	GetLeaveTypeByCode(ctx context.Context, companyID uuid.UUID, leaveCode string) (*leave.LeaveType, error)
	ListLeaveTypesByCompany(ctx context.Context, companyID uuid.UUID, includeInactive bool) ([]*leave.LeaveType, error)
	SearchLeaveTypes(ctx context.Context, companyID uuid.UUID, filters map[string]interface{}, page, pageSize int) ([]*leave.LeaveType, int, error)

	// Leave Policies
	GetLeavePolicyByID(ctx context.Context, policyID uuid.UUID) (*leave.LeavePolicy, error)
	GetLeavePolicyByCode(ctx context.Context, companyID uuid.UUID, policyCode string) (*leave.LeavePolicy, error)
	ListLeavePoliciesByCompany(ctx context.Context, companyID uuid.UUID, includeInactive bool) ([]*leave.LeavePolicy, error)
	ListLeavePoliciesByDepartment(ctx context.Context, companyID, departmentID uuid.UUID) ([]*leave.LeavePolicy, error)
	SearchLeavePolicies(ctx context.Context, companyID uuid.UUID, filters map[string]interface{}, page, pageSize int) ([]*leave.LeavePolicy, int, error)

	// User Leave Policies
	GetActiveUserLeavePolicies(ctx context.Context, userID uuid.UUID, asOf time.Time) ([]*leave.UserLeavePolicy, error)
	ListUserLeavePoliciesByUser(ctx context.Context, userID uuid.UUID) ([]*leave.UserLeavePolicy, error)
	ListUsersByLeavePolicy(ctx context.Context, policyID uuid.UUID, effectiveDate time.Time) ([]uuid.UUID, error)

	// Leave Requests
	GetLeaveRequestByID(ctx context.Context, requestID uuid.UUID) (*leave.LeaveRequest, error)
	GetLeaveRequestWithApprovals(ctx context.Context, requestID uuid.UUID) (*leave.LeaveRequest, []*leave.LeaveApproval, error)
	ListLeaveRequestsByUser(ctx context.Context, userID uuid.UUID, startDate, endDate time.Time) ([]*leave.LeaveRequest, error)
	ListLeaveRequestsByCompany(ctx context.Context, companyID uuid.UUID, filters map[string]interface{}, page, pageSize int) ([]*leave.LeaveRequest, int, error)
	ListPendingLeaveRequests(ctx context.Context, companyID uuid.UUID, approverID uuid.UUID) ([]*leave.LeaveRequest, error)
	CheckLeaveOverlap(ctx context.Context, userID uuid.UUID, startDate, endDate time.Time, excludeRequestID *uuid.UUID) (bool, error)

	// Leave Approvals
	GetApprovalsByLeaveRequest(ctx context.Context, requestID uuid.UUID) ([]*leave.LeaveApproval, error)
	GetApprovalChain(ctx context.Context, requestID uuid.UUID) ([]*leave.LeaveApproval, error)
	HasUserApprovedRequest(ctx context.Context, requestID, userID uuid.UUID) (bool, error)

	// Leave Transactions
	GetLeaveTransactionsByUser(ctx context.Context, userID uuid.UUID, leaveTypeID *uuid.UUID, startDate, endDate time.Time) ([]*leave.LeaveTransaction, error)
	GetLeaveTransactionsByRequest(ctx context.Context, requestID uuid.UUID) ([]*leave.LeaveTransaction, error)
	CalculateLeaveBalance(ctx context.Context, userID, leaveTypeID uuid.UUID, asOf time.Time) (float64, error)
	GetTransactionSummary(ctx context.Context, userID uuid.UUID, startDate, endDate time.Time) (map[string]float64, error)

	// Leave Balances
	GetCurrentLeaveBalance(ctx context.Context, userID, leaveTypeID uuid.UUID) (*leave.LeaveBalance, error)
	GetLeaveBalancesByUser(ctx context.Context, userID uuid.UUID, asOf time.Time) ([]*leave.LeaveBalance, error)

	// Reporting and Analytics
	GetLeaveUsageStats(ctx context.Context, companyID uuid.UUID, startDate, endDate time.Time) (*LeaveUsageStats, error)
	GetDepartmentLeaveStats(ctx context.Context, companyID uuid.UUID, departmentID *uuid.UUID, startDate, endDate time.Time) (map[uuid.UUID]*LeaveDepartmentStats, error)
	GetEmployeeLeaveSummary(ctx context.Context, userID uuid.UUID, year int) (*EmployeeLeaveSummary, error)
	GetLeaveTrends(ctx context.Context, companyID uuid.UUID, startDate, endDate time.Time, interval string) ([]*LeaveTrendData, error)
	GetLeaveSummaryStats(ctx context.Context, companyID uuid.UUID, startDate, endDate time.Time) (*LeaveSummaryStats, error)

	// Export and Streaming
	GenerateLeaveReport(ctx context.Context, companyID uuid.UUID, reportType string, startDate, endDate time.Time) ([]byte, string, error)
	StreamLeaveRequests(ctx context.Context, companyID uuid.UUID, startDate, endDate time.Time, writer io.Writer, format string) error
	ExportLeaveBalances(ctx context.Context, companyID uuid.UUID, asOf time.Time, writer io.Writer) error

	// Health Check
	HealthCheck(ctx context.Context) error
}

// leaveQueryServiceImpl implements LeaveQueryService
type leaveQueryServiceImpl struct {
	leaveRepo   repository.LeaveRepository
	logger      *zap.Logger
	mu          sync.RWMutex
	reportCache map[uuid.UUID]*LeaveReport
}

// NewLeaveQueryService creates a new LeaveQueryService
func NewLeaveQueryService(
	leaveRepo repository.LeaveRepository,
	logger *zap.Logger,
) LeaveQueryService {
	return &leaveQueryServiceImpl{
		leaveRepo:   leaveRepo,
		logger:      logger,
		reportCache: make(map[uuid.UUID]*LeaveReport),
	}
}

// GetLeaveTypeByID retrieves a leave type by ID
func (qs *leaveQueryServiceImpl) GetLeaveTypeByID(ctx context.Context, leaveTypeID uuid.UUID) (*leave.LeaveType, error) {
	startTime := time.Now()

	leaveType, err := qs.leaveRepo.GetLeaveTypeByID(ctx, leaveTypeID)
	if err != nil {
		qs.logger.Error("Failed to get leave type by ID",
			util.String("leave_type_id", leaveTypeID.String()),
			util.ErrorField(err))
		return nil, fmt.Errorf("failed to get leave type: %w", err)
	}

	qs.logger.Debug("Leave type retrieved by ID",
		util.String("leave_type_id", leaveTypeID.String()),
		util.Duration("duration", time.Since(startTime)))

	return leaveType, nil
}

// GetLeaveTypeByCode retrieves a leave type by code
func (qs *leaveQueryServiceImpl) GetLeaveTypeByCode(ctx context.Context, companyID uuid.UUID, leaveCode string) (*leave.LeaveType, error) {
	startTime := time.Now()

	leaveType, err := qs.leaveRepo.GetLeaveTypeByCode(ctx, companyID, leaveCode)
	if err != nil {
		qs.logger.Error("Failed to get leave type by code",
			util.String("company_id", companyID.String()),
			util.String("leave_code", leaveCode),
			util.ErrorField(err))
		return nil, fmt.Errorf("failed to get leave type: %w", err)
	}

	qs.logger.Debug("Leave type retrieved by code",
		util.String("company_id", companyID.String()),
		util.String("leave_code", leaveCode),
		util.Duration("duration", time.Since(startTime)))

	return leaveType, nil
}

// ListLeaveTypesByCompany lists leave types for a company
func (qs *leaveQueryServiceImpl) ListLeaveTypesByCompany(ctx context.Context, companyID uuid.UUID, includeInactive bool) ([]*leave.LeaveType, error) {
	startTime := time.Now()

	leaveTypes, err := qs.leaveRepo.ListLeaveTypesByCompany(ctx, companyID, includeInactive)
	if err != nil {
		qs.logger.Error("Failed to list leave types by company",
			util.String("company_id", companyID.String()),
			util.ErrorField(err))
		return nil, fmt.Errorf("failed to list leave types: %w", err)
	}

	qs.logger.Debug("Leave types listed",
		util.String("company_id", companyID.String()),
		util.Bool("include_inactive", includeInactive),
		util.Int("count", len(leaveTypes)),
		util.Duration("duration", time.Since(startTime)))

	return leaveTypes, nil
}

// SearchLeaveTypes searches leave types with filters
func (qs *leaveQueryServiceImpl) SearchLeaveTypes(
	ctx context.Context,
	companyID uuid.UUID,
	filters map[string]interface{},
	page, pageSize int,
) ([]*leave.LeaveType, int, error) {
	startTime := time.Now()

	if page < 1 {
		page = 1
	}
	if pageSize < 1 || pageSize > 1000 {
		pageSize = 100
	}

	leaveTypes, totalCount, err := qs.leaveRepo.SearchLeaveTypes(ctx, companyID, filters, pageSize, (page-1)*pageSize)
	if err != nil {
		qs.logger.Error("Failed to search leave types",
			util.String("company_id", companyID.String()),
			util.Int("filter_count", len(filters)),
			util.ErrorField(err))
		return nil, 0, fmt.Errorf("failed to search leave types: %w", err)
	}

	qs.logger.Debug("Leave types searched",
		util.String("company_id", companyID.String()),
		util.Int("filter_count", len(filters)),
		util.Int("page", page),
		util.Int("page_size", pageSize),
		util.Int("total_count", totalCount),
		util.Int("returned_count", len(leaveTypes)),
		util.Duration("duration", time.Since(startTime)))

	return leaveTypes, totalCount, nil
}

// GetLeavePolicyByID retrieves a leave policy by ID
func (qs *leaveQueryServiceImpl) GetLeavePolicyByID(ctx context.Context, policyID uuid.UUID) (*leave.LeavePolicy, error) {
	startTime := time.Now()

	policy, err := qs.leaveRepo.GetLeavePolicyByID(ctx, policyID)
	if err != nil {
		qs.logger.Error("Failed to get leave policy by ID",
			util.String("policy_id", policyID.String()),
			util.ErrorField(err))
		return nil, fmt.Errorf("failed to get leave policy: %w", err)
	}

	qs.logger.Debug("Leave policy retrieved by ID",
		util.String("policy_id", policyID.String()),
		util.Duration("duration", time.Since(startTime)))

	return policy, nil
}

// GetLeavePolicyByCode retrieves a leave policy by code
func (qs *leaveQueryServiceImpl) GetLeavePolicyByCode(ctx context.Context, companyID uuid.UUID, policyCode string) (*leave.LeavePolicy, error) {
	startTime := time.Now()

	policy, err := qs.leaveRepo.GetLeavePolicyByCode(ctx, companyID, policyCode)
	if err != nil {
		qs.logger.Error("Failed to get leave policy by code",
			util.String("company_id", companyID.String()),
			util.String("policy_code", policyCode),
			util.ErrorField(err))
		return nil, fmt.Errorf("failed to get leave policy: %w", err)
	}

	qs.logger.Debug("Leave policy retrieved by code",
		util.String("company_id", companyID.String()),
		util.String("policy_code", policyCode),
		util.Duration("duration", time.Since(startTime)))

	return policy, nil
}

// ListLeavePoliciesByCompany lists leave policies for a company
func (qs *leaveQueryServiceImpl) ListLeavePoliciesByCompany(ctx context.Context, companyID uuid.UUID, includeInactive bool) ([]*leave.LeavePolicy, error) {
	startTime := time.Now()

	policies, err := qs.leaveRepo.ListLeavePoliciesByCompany(ctx, companyID, includeInactive)
	if err != nil {
		qs.logger.Error("Failed to list leave policies by company",
			util.String("company_id", companyID.String()),
			util.ErrorField(err))
		return nil, fmt.Errorf("failed to list leave policies: %w", err)
	}

	qs.logger.Debug("Leave policies listed",
		util.String("company_id", companyID.String()),
		util.Bool("include_inactive", includeInactive),
		util.Int("count", len(policies)),
		util.Duration("duration", time.Since(startTime)))

	return policies, nil
}

// ListLeavePoliciesByDepartment lists leave policies for a department
func (qs *leaveQueryServiceImpl) ListLeavePoliciesByDepartment(ctx context.Context, companyID, departmentID uuid.UUID) ([]*leave.LeavePolicy, error) {
	startTime := time.Now()

	policies, err := qs.leaveRepo.ListLeavePoliciesByDepartment(ctx, companyID, departmentID)
	if err != nil {
		qs.logger.Error("Failed to list leave policies by department",
			util.String("company_id", companyID.String()),
			util.String("department_id", departmentID.String()),
			util.ErrorField(err))
		return nil, fmt.Errorf("failed to list leave policies: %w", err)
	}

	qs.logger.Debug("Leave policies listed by department",
		util.String("company_id", companyID.String()),
		util.String("department_id", departmentID.String()),
		util.Int("count", len(policies)),
		util.Duration("duration", time.Since(startTime)))

	return policies, nil
}

// SearchLeavePolicies searches leave policies with filters
func (qs *leaveQueryServiceImpl) SearchLeavePolicies(
	ctx context.Context,
	companyID uuid.UUID,
	filters map[string]interface{},
	page, pageSize int,
) ([]*leave.LeavePolicy, int, error) {
	startTime := time.Now()

	if page < 1 {
		page = 1
	}
	if pageSize < 1 || pageSize > 1000 {
		pageSize = 100
	}

	policies, totalCount, err := qs.leaveRepo.SearchLeavePolicies(ctx, companyID, filters, pageSize, (page-1)*pageSize)
	if err != nil {
		qs.logger.Error("Failed to search leave policies",
			util.String("company_id", companyID.String()),
			util.Int("filter_count", len(filters)),
			util.ErrorField(err))
		return nil, 0, fmt.Errorf("failed to search leave policies: %w", err)
	}

	qs.logger.Debug("Leave policies searched",
		util.String("company_id", companyID.String()),
		util.Int("filter_count", len(filters)),
		util.Int("page", page),
		util.Int("page_size", pageSize),
		util.Int("total_count", totalCount),
		util.Int("returned_count", len(policies)),
		util.Duration("duration", time.Since(startTime)))

	return policies, totalCount, nil
}

// GetActiveUserLeavePolicies gets active leave policies for a user
func (qs *leaveQueryServiceImpl) GetActiveUserLeavePolicies(ctx context.Context, userID uuid.UUID, asOf time.Time) ([]*leave.UserLeavePolicy, error) {
	startTime := time.Now()

	if asOf.IsZero() {
		asOf = time.Now().UTC()
	}

	policies, err := qs.leaveRepo.GetActiveUserLeavePolicies(ctx, userID, asOf)
	if err != nil {
		qs.logger.Error("Failed to get active user leave policies",
			util.String("user_id", userID.String()),
			util.ErrorField(err))
		return nil, fmt.Errorf("failed to get active user leave policies: %w", err)
	}

	qs.logger.Debug("Active user leave policies retrieved",
		util.String("user_id", userID.String()),
		util.Int("policy_count", len(policies)),
		util.Duration("duration", time.Since(startTime)))

	return policies, nil
}

// ListUserLeavePoliciesByUser lists all leave policy assignments for a user
func (qs *leaveQueryServiceImpl) ListUserLeavePoliciesByUser(ctx context.Context, userID uuid.UUID) ([]*leave.UserLeavePolicy, error) {
	startTime := time.Now()

	policies, err := qs.leaveRepo.ListUserLeavePoliciesByUser(ctx, userID)
	if err != nil {
		qs.logger.Error("Failed to list user leave policies",
			util.String("user_id", userID.String()),
			util.ErrorField(err))
		return nil, fmt.Errorf("failed to list user leave policies: %w", err)
	}

	qs.logger.Debug("User leave policies listed",
		util.String("user_id", userID.String()),
		util.Int("policy_count", len(policies)),
		util.Duration("duration", time.Since(startTime)))

	return policies, nil
}

// ListUsersByLeavePolicy lists users assigned to a leave policy
func (qs *leaveQueryServiceImpl) ListUsersByLeavePolicy(ctx context.Context, policyID uuid.UUID, effectiveDate time.Time) ([]uuid.UUID, error) {
	startTime := time.Now()

	if effectiveDate.IsZero() {
		effectiveDate = time.Now().UTC()
	}

	userIDs, err := qs.leaveRepo.ListUsersByLeavePolicy(ctx, policyID, effectiveDate)
	if err != nil {
		qs.logger.Error("Failed to list users by leave policy",
			util.String("policy_id", policyID.String()),
			util.ErrorField(err))
		return nil, fmt.Errorf("failed to list users by leave policy: %w", err)
	}

	qs.logger.Debug("Users listed by leave policy",
		util.String("policy_id", policyID.String()),
		util.Int("user_count", len(userIDs)),
		util.Duration("duration", time.Since(startTime)))

	return userIDs, nil
}

// GetLeaveRequestByID retrieves a leave request by ID
func (qs *leaveQueryServiceImpl) GetLeaveRequestByID(ctx context.Context, requestID uuid.UUID) (*leave.LeaveRequest, error) {
	startTime := time.Now()

	req, err := qs.leaveRepo.GetLeaveRequestByID(ctx, requestID)
	if err != nil {
		qs.logger.Error("Failed to get leave request by ID",
			util.String("request_id", requestID.String()),
			util.ErrorField(err))
		return nil, fmt.Errorf("failed to get leave request: %w", err)
	}

	qs.logger.Debug("Leave request retrieved",
		util.String("request_id", requestID.String()),
		util.Duration("duration", time.Since(startTime)))

	return req, nil
}

// GetLeaveRequestWithApprovals retrieves a leave request with its approvals
func (qs *leaveQueryServiceImpl) GetLeaveRequestWithApprovals(ctx context.Context, requestID uuid.UUID) (*leave.LeaveRequest, []*leave.LeaveApproval, error) {
	startTime := time.Now()

	req, approvals, err := qs.leaveRepo.GetLeaveRequestWithApprovals(ctx, requestID)
	if err != nil {
		qs.logger.Error("Failed to get leave request with approvals",
			util.String("request_id", requestID.String()),
			util.ErrorField(err))
		return nil, nil, fmt.Errorf("failed to get leave request with approvals: %w", err)
	}

	qs.logger.Debug("Leave request with approvals retrieved",
		util.String("request_id", requestID.String()),
		util.Int("approval_count", len(approvals)),
		util.Duration("duration", time.Since(startTime)))

	return req, approvals, nil
}

// ListLeaveRequestsByUser lists leave requests for a user
func (qs *leaveQueryServiceImpl) ListLeaveRequestsByUser(ctx context.Context, userID uuid.UUID, startDate, endDate time.Time) ([]*leave.LeaveRequest, error) {
	startTime := time.Now()

	if startDate.IsZero() {
		startDate = time.Now().AddDate(0, -6, 0) // Default: last 6 months
	}
	if endDate.IsZero() {
		endDate = time.Now().AddDate(0, 6, 0) // Default: next 6 months
	}

	// Validate date range
	calendarDays := int(endDate.Sub(startDate).Hours()/24) + 1
	if calendarDays > 365 {
		return nil, fmt.Errorf("date range cannot exceed 365 days, got %d days", calendarDays)
	}

	requests, err := qs.leaveRepo.ListLeaveRequestsByUser(ctx, userID, startDate, endDate)
	if err != nil {
		qs.logger.Error("Failed to list leave requests by user",
			util.String("user_id", userID.String()),
			util.ErrorField(err))
		return nil, fmt.Errorf("failed to list leave requests: %w", err)
	}

	qs.logger.Debug("Leave requests listed by user",
		util.String("user_id", userID.String()),
		util.Int("calendar_days", calendarDays),
		util.Int("request_count", len(requests)),
		util.Duration("duration", time.Since(startTime)))

	return requests, nil
}

// ListLeaveRequestsByCompany lists leave requests for a company
func (qs *leaveQueryServiceImpl) ListLeaveRequestsByCompany(
	ctx context.Context,
	companyID uuid.UUID,
	filters map[string]interface{},
	page, pageSize int,
) ([]*leave.LeaveRequest, int, error) {
	startTime := time.Now()

	if page < 1 {
		page = 1
	}
	if pageSize < 1 || pageSize > 1000 {
		pageSize = 100
	}

	requests, totalCount, err := qs.leaveRepo.ListLeaveRequestsByCompany(ctx, companyID, filters, pageSize, (page-1)*pageSize)
	if err != nil {
		qs.logger.Error("Failed to list leave requests by company",
			util.String("company_id", companyID.String()),
			util.ErrorField(err))
		return nil, 0, fmt.Errorf("failed to list leave requests: %w", err)
	}

	qs.logger.Debug("Leave requests listed by company",
		util.String("company_id", companyID.String()),
		util.Int("filter_count", len(filters)),
		util.Int("page", page),
		util.Int("page_size", pageSize),
		util.Int("total_count", totalCount),
		util.Int("returned_count", len(requests)),
		util.Duration("duration", time.Since(startTime)))

	return requests, totalCount, nil
}

// ListPendingLeaveRequests lists pending leave requests for an approver
func (qs *leaveQueryServiceImpl) ListPendingLeaveRequests(ctx context.Context, companyID uuid.UUID, approverID uuid.UUID) ([]*leave.LeaveRequest, error) {
	startTime := time.Now()

	requests, err := qs.leaveRepo.ListPendingLeaveRequests(ctx, companyID, approverID)
	if err != nil {
		qs.logger.Error("Failed to list pending leave requests",
			util.String("company_id", companyID.String()),
			util.String("approver_id", approverID.String()),
			util.ErrorField(err))
		return nil, fmt.Errorf("failed to list pending leave requests: %w", err)
	}

	qs.logger.Debug("Pending leave requests listed",
		util.String("company_id", companyID.String()),
		util.String("approver_id", approverID.String()),
		util.Int("request_count", len(requests)),
		util.Duration("duration", time.Since(startTime)))

	return requests, nil
}

// CheckLeaveOverlap checks for overlapping leave requests
func (qs *leaveQueryServiceImpl) CheckLeaveOverlap(ctx context.Context, userID uuid.UUID, startDate, endDate time.Time, excludeRequestID *uuid.UUID) (bool, error) {
	startTime := time.Now()

	hasOverlap, err := qs.leaveRepo.CheckLeaveOverlap(ctx, userID, startDate, endDate, excludeRequestID)
	if err != nil {
		qs.logger.Error("Failed to check leave overlap",
			util.String("user_id", userID.String()),
			util.ErrorField(err))
		return false, fmt.Errorf("failed to check leave overlap: %w", err)
	}

	qs.logger.Debug("Leave overlap checked",
		util.String("user_id", userID.String()),
		util.Bool("has_overlap", hasOverlap),
		util.Duration("duration", time.Since(startTime)))

	return hasOverlap, nil
}

// GetApprovalsByLeaveRequest gets approvals for a leave request
func (qs *leaveQueryServiceImpl) GetApprovalsByLeaveRequest(ctx context.Context, requestID uuid.UUID) ([]*leave.LeaveApproval, error) {
	startTime := time.Now()

	approvals, err := qs.leaveRepo.GetApprovalsByLeaveRequest(ctx, requestID)
	if err != nil {
		qs.logger.Error("Failed to get approvals by leave request",
			util.String("request_id", requestID.String()),
			util.ErrorField(err))
		return nil, fmt.Errorf("failed to get approvals: %w", err)
	}

	qs.logger.Debug("Approvals retrieved by request",
		util.String("request_id", requestID.String()),
		util.Int("approval_count", len(approvals)),
		util.Duration("duration", time.Since(startTime)))

	return approvals, nil
}

// GetApprovalChain gets the approval chain for a leave request
func (qs *leaveQueryServiceImpl) GetApprovalChain(ctx context.Context, requestID uuid.UUID) ([]*leave.LeaveApproval, error) {
	startTime := time.Now()

	approvals, err := qs.leaveRepo.GetApprovalChain(ctx, requestID)
	if err != nil {
		qs.logger.Error("Failed to get approval chain",
			util.String("request_id", requestID.String()),
			util.ErrorField(err))
		return nil, fmt.Errorf("failed to get approval chain: %w", err)
	}

	qs.logger.Debug("Approval chain retrieved",
		util.String("request_id", requestID.String()),
		util.Int("approval_count", len(approvals)),
		util.Duration("duration", time.Since(startTime)))

	return approvals, nil
}

// HasUserApprovedRequest checks if a user has approved a request
func (qs *leaveQueryServiceImpl) HasUserApprovedRequest(ctx context.Context, requestID, userID uuid.UUID) (bool, error) {
	startTime := time.Now()

	hasApproved, err := qs.leaveRepo.HasUserApprovedRequest(ctx, requestID, userID)
	if err != nil {
		qs.logger.Error("Failed to check if user approved request",
			util.String("request_id", requestID.String()),
			util.String("user_id", userID.String()),
			util.ErrorField(err))
		return false, fmt.Errorf("failed to check approval: %w", err)
	}

	qs.logger.Debug("User approval check completed",
		util.String("request_id", requestID.String()),
		util.String("user_id", userID.String()),
		util.Bool("has_approved", hasApproved),
		util.Duration("duration", time.Since(startTime)))

	return hasApproved, nil
}

// GetLeaveTransactionsByUser gets leave transactions for a user
func (qs *leaveQueryServiceImpl) GetLeaveTransactionsByUser(
	ctx context.Context,
	userID uuid.UUID,
	leaveTypeID *uuid.UUID,
	startDate, endDate time.Time,
) ([]*leave.LeaveTransaction, error) {
	startTime := time.Now()

	if startDate.IsZero() {
		startDate = time.Now().AddDate(-1, 0, 0) // Default: last year
	}
	if endDate.IsZero() {
		endDate = time.Now()
	}

	// Validate date range
	calendarDays := int(endDate.Sub(startDate).Hours()/24) + 1
	if calendarDays > 365 {
		return nil, fmt.Errorf("date range cannot exceed 365 days, got %d days", calendarDays)
	}

	transactions, err := qs.leaveRepo.GetLeaveTransactionsByUser(ctx, userID, leaveTypeID, startDate, endDate)
	if err != nil {
		qs.logger.Error("Failed to get leave transactions by user",
			util.String("user_id", userID.String()),
			util.ErrorField(err))
		return nil, fmt.Errorf("failed to get leave transactions: %w", err)
	}

	qs.logger.Debug("Leave transactions retrieved by user",
		util.String("user_id", userID.String()),
		util.Int("calendar_days", calendarDays),
		util.Int("transaction_count", len(transactions)),
		util.Duration("duration", time.Since(startTime)))

	return transactions, nil
}

// GetLeaveTransactionsByRequest gets leave transactions for a request
func (qs *leaveQueryServiceImpl) GetLeaveTransactionsByRequest(ctx context.Context, requestID uuid.UUID) ([]*leave.LeaveTransaction, error) {
	startTime := time.Now()

	transactions, err := qs.leaveRepo.GetLeaveTransactionsByRequest(ctx, requestID)
	if err != nil {
		qs.logger.Error("Failed to get leave transactions by request",
			util.String("request_id", requestID.String()),
			util.ErrorField(err))
		return nil, fmt.Errorf("failed to get leave transactions: %w", err)
	}

	qs.logger.Debug("Leave transactions retrieved by request",
		util.String("request_id", requestID.String()),
		util.Int("transaction_count", len(transactions)),
		util.Duration("duration", time.Since(startTime)))

	return transactions, nil
}

// CalculateLeaveBalance calculates leave balance for a user
func (qs *leaveQueryServiceImpl) CalculateLeaveBalance(ctx context.Context, userID, leaveTypeID uuid.UUID, asOf time.Time) (float64, error) {
	startTime := time.Now()

	if asOf.IsZero() {
		asOf = time.Now().UTC()
	}

	balance, err := qs.leaveRepo.CalculateLeaveBalance(ctx, userID, leaveTypeID, asOf)
	if err != nil {
		qs.logger.Error("Failed to calculate leave balance",
			util.String("user_id", userID.String()),
			util.String("leave_type_id", leaveTypeID.String()),
			util.ErrorField(err))
		return 0, fmt.Errorf("failed to calculate leave balance: %w", err)
	}

	qs.logger.Debug("Leave balance calculated",
		util.String("user_id", userID.String()),
		util.String("leave_type_id", leaveTypeID.String()),
		util.Float64("balance", balance),
		util.Duration("duration", time.Since(startTime)))

	return balance, nil
}

// GetTransactionSummary gets transaction summary for a user
func (qs *leaveQueryServiceImpl) GetTransactionSummary(ctx context.Context, userID uuid.UUID, startDate, endDate time.Time) (map[string]float64, error) {
	startTime := time.Now()

	if startDate.IsZero() {
		startDate = time.Now().AddDate(-1, 0, 0) // Default: last year
	}
	if endDate.IsZero() {
		endDate = time.Now()
	}

	summary, err := qs.leaveRepo.GetTransactionSummary(ctx, userID, startDate, endDate)
	if err != nil {
		qs.logger.Error("Failed to get transaction summary",
			util.String("user_id", userID.String()),
			util.ErrorField(err))
		return nil, fmt.Errorf("failed to get transaction summary: %w", err)
	}

	qs.logger.Debug("Transaction summary retrieved",
		util.String("user_id", userID.String()),
		util.Duration("duration", time.Since(startTime)))

	return summary, nil
}

// GetCurrentLeaveBalance gets the current leave balance for a user
func (qs *leaveQueryServiceImpl) GetCurrentLeaveBalance(ctx context.Context, userID, leaveTypeID uuid.UUID) (*leave.LeaveBalance, error) {
	startTime := time.Now()

	balance, err := qs.leaveRepo.GetCurrentLeaveBalance(ctx, userID, leaveTypeID)
	if err != nil {
		qs.logger.Error("Failed to get current leave balance",
			util.String("user_id", userID.String()),
			util.String("leave_type_id", leaveTypeID.String()),
			util.ErrorField(err))
		return nil, fmt.Errorf("failed to get current leave balance: %w", err)
	}

	qs.logger.Debug("Current leave balance retrieved",
		util.String("user_id", userID.String()),
		util.String("leave_type_id", leaveTypeID.String()),
		util.Float64("balance", balance.Balance),
		util.Duration("duration", time.Since(startTime)))

	return balance, nil
}

// GetLeaveBalancesByUser gets all leave balances for a user
func (qs *leaveQueryServiceImpl) GetLeaveBalancesByUser(ctx context.Context, userID uuid.UUID, asOf time.Time) ([]*leave.LeaveBalance, error) {
	startTime := time.Now()

	if asOf.IsZero() {
		asOf = time.Now().UTC()
	}

	balances, err := qs.leaveRepo.GetLeaveBalancesByUser(ctx, userID, asOf)
	if err != nil {
		qs.logger.Error("Failed to get leave balances by user",
			util.String("user_id", userID.String()),
			util.ErrorField(err))
		return nil, fmt.Errorf("failed to get leave balances: %w", err)
	}

	qs.logger.Debug("Leave balances retrieved by user",
		util.String("user_id", userID.String()),
		util.Int("balance_count", len(balances)),
		util.Duration("duration", time.Since(startTime)))

	return balances, nil
}

func (qs *leaveQueryServiceImpl) GetLeaveUsageStats(
	ctx context.Context,
	companyID uuid.UUID,
	startDate, endDate time.Time,
) (*LeaveUsageStats, error) {

	if startDate.IsZero() {
		startDate = time.Now().AddDate(0, -12, 0)
	}
	if endDate.IsZero() {
		endDate = time.Now()
	}

	repoStats, err := qs.leaveRepo.GetLeaveUsageStats(ctx, companyID, startDate, endDate)
	if err != nil {
		return nil, err
	}

	return &LeaveUsageStats{
		TotalRequests:     int64(repoStats.TotalRequests),
		ApprovedRequests:  int64(repoStats.ApprovedRequests),
		PendingRequests:   int64(repoStats.PendingRequests),
		RejectedRequests:  int64(repoStats.RejectedRequests),
		TotalLeaveDays:    repoStats.TotalLeaveDays,
		AverageLeaveDays:  repoStats.AverageLeaveDays,
		MostUsedLeaveType: repoStats.MostUsedLeaveType,
	}, nil
}
func (qs *leaveQueryServiceImpl) GetDepartmentLeaveStats(
	ctx context.Context,
	companyID uuid.UUID,
	departmentID *uuid.UUID,
	startDate, endDate time.Time,
) (map[uuid.UUID]*LeaveDepartmentStats, error) {

	repoStats, err := qs.leaveRepo.GetDepartmentLeaveStats(
		ctx, companyID, departmentID, startDate, endDate,
	)
	if err != nil {
		return nil, err
	}

	stats := make(map[uuid.UUID]*LeaveDepartmentStats)

	for deptID, s := range repoStats {
		stats[deptID] = &LeaveDepartmentStats{
			DepartmentName:  s.DepartmentName,
			TotalEmployees:  s.TotalEmployees,
			TotalLeaveDays:  s.TotalLeaveDays,
			AvgLeavePerEmp:  s.AvgLeavePerEmp, // already calculated in repo
			PendingRequests: s.PendingRequests,
		}
	}

	return stats, nil
}

func (qs *leaveQueryServiceImpl) GetEmployeeLeaveSummary(
	ctx context.Context,
	userID uuid.UUID,
	year int,
) (*EmployeeLeaveSummary, error) {

	if year <= 0 {
		year = time.Now().Year()
	}

	repoSummary, err := qs.leaveRepo.GetEmployeeLeaveSummary(ctx, userID, year)
	if err != nil {
		return nil, err
	}

	summary := &EmployeeLeaveSummary{
		Year:               repoSummary.Year,
		TotalEntitlement:   repoSummary.TotalEntitlement,
		TotalUsed:          repoSummary.TotalUsed,
		TotalBalance:       repoSummary.TotalBalance,
		LeaveTypeBreakdown: map[string]LeaveTypeSummary{},
		MonthlyBreakdown:   repoSummary.MonthlyBreakdown,
	}

	// Map leave-type breakdown
	for k, v := range repoSummary.LeaveTypeBreakdown {
		summary.LeaveTypeBreakdown[k] = LeaveTypeSummary{
			LeaveTypeName: v.LeaveTypeName,
			Entitlement:   v.Entitlement,
			Used:          v.Used,
			Balance:       v.Balance,
		}
	}

	// Enrich: recent leaves (last 3 months)
	recentStart := time.Now().AddDate(0, -3, 0)
	recentEnd := time.Now()
	summary.RecentRequests, _ =
		qs.ListLeaveRequestsByUser(ctx, userID, recentStart, recentEnd)

	// Enrich: upcoming leaves (next 3 months)
	upcomingStart := time.Now()
	upcomingEnd := time.Now().AddDate(0, 3, 0)
	summary.UpcomingLeaves, _ =
		qs.ListLeaveRequestsByUser(ctx, userID, upcomingStart, upcomingEnd)

	return summary, nil
}

func (qs *leaveQueryServiceImpl) GetLeaveTrends(
	ctx context.Context,
	companyID uuid.UUID,
	startDate, endDate time.Time,
	interval string,
) ([]*LeaveTrendData, error) {

	repoTrends, err := qs.leaveRepo.GetLeaveTrends(
		ctx, companyID, startDate, endDate, interval,
	)
	if err != nil {
		return nil, err
	}

	trends := make([]*LeaveTrendData, 0, len(repoTrends))

	for _, t := range repoTrends {
		trends = append(trends, &LeaveTrendData{
			Period:          t.Period,
			TotalRequests:   int64(t.TotalRequests),
			ApprovedDays:    t.ApprovedDays,
			PendingDays:     t.PendingDays,
			AvgApprovalTime: t.AvgApprovalTime,
		})
	}

	return trends, nil
}

// GetLeaveSummaryStats gets comprehensive leave summary statistics
func (qs *leaveQueryServiceImpl) GetLeaveSummaryStats(ctx context.Context, companyID uuid.UUID, startDate, endDate time.Time) (*LeaveSummaryStats, error) {
	startTime := time.Now()

	if startDate.IsZero() {
		startDate = time.Now().AddDate(0, -12, 0) // Default: last 12 months
	}
	if endDate.IsZero() {
		endDate = time.Now()
	}

	// Get usage stats
	usageStats, err := qs.GetLeaveUsageStats(ctx, companyID, startDate, endDate)
	if err != nil {
		return nil, fmt.Errorf("failed to get usage stats: %w", err)
	}

	// Get department stats
	deptStats, err := qs.GetDepartmentLeaveStats(ctx, companyID, nil, startDate, endDate)
	if err != nil {
		return nil, fmt.Errorf("failed to get department stats: %w", err)
	}

	// Get trends for monthly breakdown
	trends, err := qs.GetLeaveTrends(ctx, companyID, startDate, endDate, "month")
	if err != nil {
		return nil, fmt.Errorf("failed to get trends: %w", err)
	}

	// Convert to summary stats
	summary := &LeaveSummaryStats{
		TotalRequests:        usageStats.TotalRequests,
		ApprovedRequests:     usageStats.ApprovedRequests,
		PendingRequests:      usageStats.PendingRequests,
		RejectedRequests:     usageStats.RejectedRequests,
		TotalLeaveDays:       usageStats.TotalLeaveDays,
		AverageLeaveDays:     usageStats.AverageLeaveDays,
		MostUsedLeaveType:    usageStats.MostUsedLeaveType,
		ByMonth:              make(map[string]int64),
		ByDepartment:         make(map[string]int64),
		ByStatus:             make(map[string]int64),
		AvgApprovalTimeHours: 0,
		LeaveUtilizationRate: 0,
	}

	// Process monthly breakdown
	for _, trend := range trends {
		summary.ByMonth[trend.Period] = trend.TotalRequests
	}

	// Process department breakdown
	for _, deptStat := range deptStats {
		summary.ByDepartment[deptStat.DepartmentName] = int64(deptStat.PendingRequests)
	}

	// Process status breakdown
	summary.ByStatus["approved"] = usageStats.ApprovedRequests
	summary.ByStatus["pending"] = usageStats.PendingRequests
	summary.ByStatus["rejected"] = usageStats.RejectedRequests

	// Calculate utilization rate
	if usageStats.TotalRequests > 0 {
		summary.LeaveUtilizationRate = float64(usageStats.ApprovedRequests) / float64(usageStats.TotalRequests) * 100
	}

	qs.logger.Debug("Leave summary stats retrieved",
		util.String("company_id", companyID.String()),
		util.Duration("duration", time.Since(startTime)))

	return summary, nil
}

// GenerateLeaveReport generates a leave report in specified format
func (qs *leaveQueryServiceImpl) GenerateLeaveReport(
	ctx context.Context,
	companyID uuid.UUID,
	reportType string,
	startDate, endDate time.Time,
) ([]byte, string, error) {
	startTime := time.Now()

	if startDate.IsZero() {
		startDate = time.Now().AddDate(0, -1, 0) // Default: last month
	}
	if endDate.IsZero() {
		endDate = time.Now()
	}

	// Validate date range
	calendarDays := int(endDate.Sub(startDate).Hours()/24) + 1
	if calendarDays > 31 {
		return nil, "", fmt.Errorf("report period cannot exceed 31 days, got %d days", calendarDays)
	}

	var data []byte
	var contentType string
	var err error

	switch strings.ToLower(reportType) {
	case "summary":
		summary, err := qs.GetLeaveSummaryStats(ctx, companyID, startDate, endDate)
		if err != nil {
			return nil, "", err
		}
		data, err = json.MarshalIndent(summary, "", "  ")
		contentType = "application/json"

	case "department":
		deptStats, err := qs.GetDepartmentLeaveStats(ctx, companyID, nil, startDate, endDate)
		if err != nil {
			return nil, "", err
		}
		data, err = json.MarshalIndent(deptStats, "", "  ")
		contentType = "application/json"

	case "csv":
		data, err = qs.generateCSVReport(ctx, companyID, startDate, endDate)
		if err != nil {
			return nil, "", err
		}
		contentType = "text/csv"

	default:
		return nil, "", fmt.Errorf("unsupported report type: %s", reportType)
	}

	if err != nil {
		return nil, "", fmt.Errorf("failed to generate %s report: %w", reportType, err)
	}

	qs.logger.Info("Leave report generated",
		util.String("company_id", companyID.String()),
		util.String("report_type", reportType),
		util.Time("start_date", startDate),
		util.Time("end_date", endDate),
		util.Int("calendar_days", calendarDays),
		util.Int("data_size", len(data)),
		util.Duration("duration", time.Since(startTime)))

	return data, contentType, nil
}

// generateCSVReport generates a CSV report of leave requests
func (qs *leaveQueryServiceImpl) generateCSVReport(
	ctx context.Context,
	companyID uuid.UUID,
	startDate, endDate time.Time,
) ([]byte, error) {
	var buf strings.Builder
	writer := csv.NewWriter(&buf)

	// Write header
	header := []string{
		"Request ID",
		"Employee ID",
		"Employee Name",
		"Leave Type",
		"Start Date",
		"End Date",
		"Duration (days)",
		"Status",
		"Requested At",
		"Reason",
		"Department",
	}

	if err := writer.Write(header); err != nil {
		return nil, fmt.Errorf("failed to write CSV header: %w", err)
	}

	// Fetch leave requests in batches
	page := 1
	pageSize := 1000

	for {
		filters := map[string]interface{}{
			"start_date_from": startDate,
			"start_date_to":   endDate,
		}

		requests, totalCount, err := qs.ListLeaveRequestsByCompany(ctx, companyID, filters, page, pageSize)
		if err != nil {
			return nil, fmt.Errorf("failed to fetch leave requests for CSV: %w", err)
		}

		if len(requests) == 0 {
			break
		}

		// TODO: Fetch employee details and department information
		// For now, using placeholder data
		for _, req := range requests {
			reason := ""
			if req.Reason != nil {
				reason = *req.Reason
			}

			row := []string{
				req.LeaveRequestID.String(),
				req.UserID.String(),
				"Employee Name", // TODO: Fetch from user service
				"Leave Type",    // TODO: Fetch from leave type
				req.StartDate.Format("2006-01-02"),
				req.EndDate.Format("2006-01-02"),
				fmt.Sprintf("%.2f", req.Duration),
				req.Status,
				req.RequestedAt.Format("2006-01-02 15:04:05"),
				reason,
				"Department", // TODO: Fetch from department service
			}

			if err := writer.Write(row); err != nil {
				return nil, fmt.Errorf("failed to write CSV row: %w", err)
			}
		}

		qs.logger.Debug("CSV report batch processed",
			util.String("company_id", companyID.String()),
			util.Int("page", page),
			util.Int("batch_size", len(requests)))

		if page*pageSize >= totalCount {
			break
		}
		page++
	}

	writer.Flush()
	if err := writer.Error(); err != nil {
		return nil, fmt.Errorf("CSV flush error: %w", err)
	}

	return []byte(buf.String()), nil
}

// StreamLeaveRequests streams leave requests in specified format
func (qs *leaveQueryServiceImpl) StreamLeaveRequests(
	ctx context.Context,
	companyID uuid.UUID,
	startDate, endDate time.Time,
	writer io.Writer,
	format string,
) error {
	if format != "csv" && format != "jsonl" {
		return fmt.Errorf("unsupported format: %s", format)
	}

	// Validate date range
	calendarDays := int(endDate.Sub(startDate).Hours()/24) + 1
	if calendarDays > 31 {
		return fmt.Errorf("streaming period cannot exceed 31 days, got %d days", calendarDays)
	}

	if format == "csv" {
		csvWriter := csv.NewWriter(writer)
		defer csvWriter.Flush()

		// Write header
		header := []string{
			"Request ID",
			"User ID",
			"Leave Type ID",
			"Start Date",
			"End Date",
			"Duration",
			"Status",
			"Requested At",
		}
		if err := csvWriter.Write(header); err != nil {
			return err
		}

		// Stream data in batches
		page := 1
		pageSize := 1000

		for {
			filters := map[string]interface{}{
				"start_date_from": startDate,
				"start_date_to":   endDate,
			}

			requests, totalCount, err := qs.ListLeaveRequestsByCompany(ctx, companyID, filters, page, pageSize)
			if err != nil {
				return err
			}

			if len(requests) == 0 {
				break
			}

			for _, req := range requests {
				row := []string{
					req.LeaveRequestID.String(),
					req.UserID.String(),
					req.LeaveTypeID.String(),
					req.StartDate.Format("2006-01-02"),
					req.EndDate.Format("2006-01-02"),
					fmt.Sprintf("%.2f", req.Duration),
					req.Status,
					req.RequestedAt.Format("2006-01-02 15:04:05"),
				}
				if err := csvWriter.Write(row); err != nil {
					return err
				}
			}

			if page*pageSize >= totalCount {
				break
			}
			page++
		}

		return csvWriter.Error()
	}

	// JSONL format
	page := 1
	pageSize := 1000

	for {
		filters := map[string]interface{}{
			"start_date_from": startDate,
			"start_date_to":   endDate,
		}

		requests, totalCount, err := qs.ListLeaveRequestsByCompany(ctx, companyID, filters, page, pageSize)
		if err != nil {
			return err
		}

		if len(requests) == 0 {
			break
		}

		for _, req := range requests {
			jsonData, err := json.Marshal(req)
			if err != nil {
				return err
			}
			if _, err := writer.Write(jsonData); err != nil {
				return err
			}
			if _, err := writer.Write([]byte("\n")); err != nil {
				return err
			}
		}

		if page*pageSize >= totalCount {
			break
		}
		page++
	}

	return nil
}

// ExportLeaveBalances exports leave balances for a company
func (qs *leaveQueryServiceImpl) ExportLeaveBalances(
	ctx context.Context,
	companyID uuid.UUID,
	asOf time.Time,
	writer io.Writer,
) error {
	if asOf.IsZero() {
		asOf = time.Now().UTC()
	}

	csvWriter := csv.NewWriter(writer)
	defer csvWriter.Flush()

	// Write header
	header := []string{
		"Employee ID",
		"Employee Name",
		"Leave Type",
		"Balance",
		"As Of",
		"Department",
		"Employment Status",
	}

	if err := csvWriter.Write(header); err != nil {
		return err
	}

	// TODO: Implement actual balance export
	// This would typically involve:
	// 1. Get all employees in the company
	// 2. For each employee, get their leave balances
	// 3. Write to CSV

	qs.logger.Info("Leave balances export initiated",
		util.String("company_id", companyID.String()),
		util.Time("as_of", asOf))

	return csvWriter.Error()
}

// HealthCheck performs health check
func (qs *leaveQueryServiceImpl) HealthCheck(ctx context.Context) error {
	if err := qs.leaveRepo.HealthCheck(ctx); err != nil {
		return fmt.Errorf("leave repository health check failed: %w", err)
	}
	return nil
}

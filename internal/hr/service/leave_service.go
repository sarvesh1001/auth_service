package service

import (
	"auth-service/internal/hr/models/leave"
	"auth-service/internal/hr/repository"
	"auth-service/internal/util"
	"context"
	"fmt"
	"strings"
	"sync"
	"time"

	"github.com/google/uuid"
	"go.uber.org/zap"
)

// LeaveService provides business logic for leave management
type LeaveService interface {
	// Leave Types
	CreateLeaveType(ctx context.Context, leaveType *leave.LeaveType, actorType string, actorID uuid.UUID, metadata map[string]interface{}) (*leave.LeaveType, error)
	GetLeaveTypeByID(ctx context.Context, leaveTypeID uuid.UUID) (*leave.LeaveType, error)
	UpdateLeaveType(ctx context.Context, leaveType *leave.LeaveType, actorType string, actorID uuid.UUID, metadata map[string]interface{}) error
	DeleteLeaveType(ctx context.Context, leaveTypeID uuid.UUID, actorType string, actorID uuid.UUID, reason string) error
	ListLeaveTypesByCompany(ctx context.Context, companyID uuid.UUID, includeInactive bool) ([]*leave.LeaveType, error)
	SearchLeaveTypes(ctx context.Context, companyID uuid.UUID, filters map[string]interface{}, page, pageSize int) ([]*leave.LeaveType, int, error)

	// Leave Policies
	CreateLeavePolicy(ctx context.Context, policy *leave.LeavePolicy, actorType string, actorID uuid.UUID, metadata map[string]interface{}) (*leave.LeavePolicy, error)
	GetLeavePolicyByID(ctx context.Context, policyID uuid.UUID) (*leave.LeavePolicy, error)
	UpdateLeavePolicy(ctx context.Context, policy *leave.LeavePolicy, actorType string, actorID uuid.UUID, metadata map[string]interface{}) error
	DeleteLeavePolicy(ctx context.Context, policyID uuid.UUID, actorType string, actorID uuid.UUID, reason string) error
	ListLeavePoliciesByCompany(ctx context.Context, companyID uuid.UUID, includeInactive bool) ([]*leave.LeavePolicy, error)
	ListLeavePoliciesByDepartment(ctx context.Context, companyID, departmentID uuid.UUID) ([]*leave.LeavePolicy, error)
	SearchLeavePolicies(ctx context.Context, companyID uuid.UUID, filters map[string]interface{}, page, pageSize int) ([]*leave.LeavePolicy, int, error)

	// User Leave Policies
	AssignUserLeavePolicy(ctx context.Context, userPolicy *leave.UserLeavePolicy, actorType string, actorID uuid.UUID, metadata map[string]interface{}) error
	GetActiveUserLeavePolicies(ctx context.Context, userID uuid.UUID, asOf time.Time) ([]*leave.UserLeavePolicy, error)
	RemoveUserLeavePolicy(ctx context.Context, userID, policyID uuid.UUID, effectiveFrom time.Time, actorType string, actorID uuid.UUID, reason string) error
	ListUserLeavePoliciesByUser(ctx context.Context, userID uuid.UUID) ([]*leave.UserLeavePolicy, error)

	// Leave Requests
	CreateLeaveRequest(ctx context.Context, req *leave.LeaveRequest, actorType string, actorID uuid.UUID, metadata map[string]interface{}) (*leave.LeaveRequest, error)
	GetLeaveRequestByID(ctx context.Context, requestID uuid.UUID) (*leave.LeaveRequest, error)
	UpdateLeaveRequest(ctx context.Context, req *leave.LeaveRequest, actorType string, actorID uuid.UUID, metadata map[string]interface{}) error
	CancelLeaveRequest(ctx context.Context, requestID uuid.UUID, reason string, actorType string, actorID uuid.UUID) error
	DeleteLeaveRequest(ctx context.Context, requestID uuid.UUID, actorType string, actorID uuid.UUID, reason string) error
	ListLeaveRequestsByUser(ctx context.Context, userID uuid.UUID, startDate, endDate time.Time) ([]*leave.LeaveRequest, error)
	ListLeaveRequestsByCompany(ctx context.Context, companyID uuid.UUID, filters map[string]interface{}, page, pageSize int) ([]*leave.LeaveRequest, int, error)
	ListPendingLeaveRequests(ctx context.Context, companyID uuid.UUID, approverID uuid.UUID) ([]*leave.LeaveRequest, error)
	CheckLeaveOverlap(ctx context.Context, userID uuid.UUID, startDate, endDate time.Time, excludeRequestID *uuid.UUID) (bool, error)

	// Leave Approvals
	CreateLeaveApproval(ctx context.Context, approval *leave.LeaveApproval, actorType string, actorID uuid.UUID, metadata map[string]interface{}) (*leave.LeaveApproval, error)
	GetApprovalsByLeaveRequest(ctx context.Context, requestID uuid.UUID) ([]*leave.LeaveApproval, error)
	HasUserApprovedRequest(ctx context.Context, requestID, userID uuid.UUID) (bool, error)
	GetApprovalChain(ctx context.Context, requestID uuid.UUID) ([]*leave.LeaveApproval, error)

	// Leave Transactions
	CreateLeaveTransaction(ctx context.Context, txn *leave.LeaveTransaction, actorType string, actorID uuid.UUID, metadata map[string]interface{}) (*leave.LeaveTransaction, error)
	GetLeaveTransactionsByUser(ctx context.Context, userID uuid.UUID, leaveTypeID *uuid.UUID, startDate, endDate time.Time) ([]*leave.LeaveTransaction, error)
	CalculateLeaveBalance(ctx context.Context, userID, leaveTypeID uuid.UUID, asOf time.Time) (float64, error)
	GetTransactionSummary(ctx context.Context, userID uuid.UUID, startDate, endDate time.Time) (map[string]float64, error)

	// Leave Balances
	CreateOrUpdateLeaveBalance(ctx context.Context, balance *leave.LeaveBalance, actorType string, actorID uuid.UUID, metadata map[string]interface{}) error
	GetCurrentLeaveBalance(ctx context.Context, userID, leaveTypeID uuid.UUID) (*leave.LeaveBalance, error)
	GetLeaveBalancesByUser(ctx context.Context, userID uuid.UUID, asOf time.Time) ([]*leave.LeaveBalance, error)
	RecalculateLeaveBalances(ctx context.Context, userID uuid.UUID, fromDate time.Time) error

	// Leave Accrual
	AccrueLeavesForUser(ctx context.Context, userID uuid.UUID, accrualDate time.Time, actorType string, actorID uuid.UUID) ([]*leave.LeaveTransaction, error)
	ProcessMonthlyAccrual(ctx context.Context, companyID uuid.UUID, month time.Time, actorType string, actorID uuid.UUID) error

	// Leave Management
	ApproveLeaveRequest(ctx context.Context, requestID uuid.UUID, approverID uuid.UUID, reason string, metadata map[string]interface{}) error
	RejectLeaveRequest(ctx context.Context, requestID uuid.UUID, approverID uuid.UUID, reason string, metadata map[string]interface{}) error
	WithdrawLeaveRequest(ctx context.Context, requestID uuid.UUID, userID uuid.UUID, reason string, metadata map[string]interface{}) error

	// Batch Operations
	CreateLeaveTypesBatch(ctx context.Context, leaveTypes []*leave.LeaveType, actorType string, actorID uuid.UUID) error
	CreateLeavePoliciesBatch(ctx context.Context, policies []*leave.LeavePolicy, actorType string, actorID uuid.UUID) error
	AssignLeavePoliciesBatch(ctx context.Context, userPolicies []*leave.UserLeavePolicy, actorType string, actorID uuid.UUID) error
	CreateLeaveRequestsBatch(ctx context.Context, requests []*leave.LeaveRequest, actorType string, actorID uuid.UUID) error

	// Health Check
	HealthCheck(ctx context.Context) error
}

// LeaveServiceImpl implements LeaveService
type leaveServiceImpl struct {
	leaveRepo repository.LeaveRepository
	logger    *zap.Logger
	mu        sync.RWMutex
}

// NewLeaveService creates a new LeaveService
func NewLeaveService(
	leaveRepo repository.LeaveRepository,
	logger *zap.Logger,
) LeaveService {
	return &leaveServiceImpl{
		leaveRepo: leaveRepo,
		logger:    logger,
	}
}

// CreateLeaveType creates a new leave type
func (s *leaveServiceImpl) CreateLeaveType(
	ctx context.Context,
	leaveType *leave.LeaveType,
	actorType string,
	actorID uuid.UUID,
	metadata map[string]interface{},
) (*leave.LeaveType, error) {
	startTime := time.Now()

	// Validate leave type
	if err := s.validateLeaveType(leaveType); err != nil {
		return nil, fmt.Errorf("leave type validation failed: %w", err)
	}

	// Generate UUID if not provided
	if leaveType.LeaveTypeID == uuid.Nil {
		leaveType.LeaveTypeID = uuid.New()
	}

	// Set timestamps
	now := time.Now().UTC()
	if leaveType.CreatedAt.IsZero() {
		leaveType.CreatedAt = now
	}

	// Check if leave code already exists
	existingType, err := s.leaveRepo.GetLeaveTypeByCode(ctx, leaveType.CompanyID, leaveType.LeaveCode)
	if err == nil && existingType != nil {
		return nil, fmt.Errorf("leave code already exists: %s", leaveType.LeaveCode)
	}

	// Create leave type
	err = s.leaveRepo.CreateLeaveType(ctx, leaveType)
	if err != nil {
		s.logger.Error("Failed to create leave type",
			util.String("company_id", leaveType.CompanyID.String()),
			util.String("leave_code", leaveType.LeaveCode),
			util.ErrorField(err))
		return nil, fmt.Errorf("failed to create leave type: %w", err)
	}

	s.logger.Info("Leave type created",
		util.String("leave_type_id", leaveType.LeaveTypeID.String()),
		util.String("leave_code", leaveType.LeaveCode),
		util.String("company_id", leaveType.CompanyID.String()),
		util.String("actor_type", actorType),
		util.String("actor_id", actorID.String()),
		util.Duration("duration", time.Since(startTime)))

	return leaveType, nil
}

// GetLeaveTypeByID retrieves a leave type by ID
func (s *leaveServiceImpl) GetLeaveTypeByID(ctx context.Context, leaveTypeID uuid.UUID) (*leave.LeaveType, error) {
	startTime := time.Now()

	leaveType, err := s.leaveRepo.GetLeaveTypeByID(ctx, leaveTypeID)
	if err != nil {
		s.logger.Error("Failed to get leave type by ID",
			util.String("leave_type_id", leaveTypeID.String()),
			util.ErrorField(err))
		return nil, fmt.Errorf("failed to get leave type: %w", err)
	}

	s.logger.Debug("Leave type retrieved",
		util.String("leave_type_id", leaveTypeID.String()),
		util.Duration("duration", time.Since(startTime)))

	return leaveType, nil
}

// UpdateLeaveType updates an existing leave type
func (s *leaveServiceImpl) UpdateLeaveType(
	ctx context.Context,
	leaveType *leave.LeaveType,
	actorType string,
	actorID uuid.UUID,
	metadata map[string]interface{},
) error {
	startTime := time.Now()

	// Validate leave type
	if err := s.validateLeaveType(leaveType); err != nil {
		return fmt.Errorf("leave type validation failed: %w", err)
	}

	// Check if leave type exists
	existingType, err := s.leaveRepo.GetLeaveTypeByID(ctx, leaveType.LeaveTypeID)
	if err != nil {
		return fmt.Errorf("leave type not found: %w", err)
	}

	// Check if leave code conflict
	if leaveType.LeaveCode != existingType.LeaveCode {
		existingByCode, err := s.leaveRepo.GetLeaveTypeByCode(ctx, leaveType.CompanyID, leaveType.LeaveCode)
		if err == nil && existingByCode != nil {
			return fmt.Errorf("leave code already exists: %s", leaveType.LeaveCode)
		}
	}

	// Update leave type
	err = s.leaveRepo.UpdateLeaveType(ctx, leaveType)
	if err != nil {
		s.logger.Error("Failed to update leave type",
			util.String("leave_type_id", leaveType.LeaveTypeID.String()),
			util.ErrorField(err))
		return fmt.Errorf("failed to update leave type: %w", err)
	}

	s.logger.Info("Leave type updated",
		util.String("leave_type_id", leaveType.LeaveTypeID.String()),
		util.String("actor_type", actorType),
		util.String("actor_id", actorID.String()),
		util.Duration("duration", time.Since(startTime)))

	return nil
}

// DeleteLeaveType deletes a leave type
func (s *leaveServiceImpl) DeleteLeaveType(
	ctx context.Context,
	leaveTypeID uuid.UUID,
	actorType string,
	actorID uuid.UUID,
	reason string,
) error {
	startTime := time.Now()

	// Check if leave type has active leave requests
	filters := map[string]interface{}{
		"leave_type_id": leaveTypeID,
		"status":        []string{"pending", "approved"},
	}
	_, total, err := s.leaveRepo.ListLeaveRequestsByCompany(ctx, uuid.Nil, filters, 1, 1)
	if err == nil && total > 0 {
		return fmt.Errorf("cannot delete leave type with active leave requests")
	}

	err = s.leaveRepo.DeleteLeaveType(ctx, leaveTypeID)
	if err != nil {
		s.logger.Error("Failed to delete leave type",
			util.String("leave_type_id", leaveTypeID.String()),
			util.ErrorField(err))
		return fmt.Errorf("failed to delete leave type: %w", err)
	}

	s.logger.Info("Leave type deleted",
		util.String("leave_type_id", leaveTypeID.String()),
		util.String("reason", reason),
		util.String("actor_type", actorType),
		util.String("actor_id", actorID.String()),
		util.Duration("duration", time.Since(startTime)))

	return nil
}

// ListLeaveTypesByCompany lists leave types for a company
func (s *leaveServiceImpl) ListLeaveTypesByCompany(ctx context.Context, companyID uuid.UUID, includeInactive bool) ([]*leave.LeaveType, error) {
	startTime := time.Now()

	leaveTypes, err := s.leaveRepo.ListLeaveTypesByCompany(ctx, companyID, includeInactive)
	if err != nil {
		s.logger.Error("Failed to list leave types by company",
			util.String("company_id", companyID.String()),
			util.ErrorField(err))
		return nil, fmt.Errorf("failed to list leave types: %w", err)
	}

	s.logger.Debug("Leave types listed",
		util.String("company_id", companyID.String()),
		util.Bool("include_inactive", includeInactive),
		util.Int("count", len(leaveTypes)),
		util.Duration("duration", time.Since(startTime)))

	return leaveTypes, nil
}

// SearchLeaveTypes searches leave types with filters
func (s *leaveServiceImpl) SearchLeaveTypes(
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

	leaveTypes, totalCount, err := s.leaveRepo.SearchLeaveTypes(ctx, companyID, filters, pageSize, (page-1)*pageSize)
	if err != nil {
		s.logger.Error("Failed to search leave types",
			util.String("company_id", companyID.String()),
			util.Int("filter_count", len(filters)),
			util.ErrorField(err))
		return nil, 0, fmt.Errorf("failed to search leave types: %w", err)
	}

	s.logger.Debug("Leave types searched",
		util.String("company_id", companyID.String()),
		util.Int("filter_count", len(filters)),
		util.Int("page", page),
		util.Int("page_size", pageSize),
		util.Int("total_count", totalCount),
		util.Int("returned_count", len(leaveTypes)),
		util.Duration("duration", time.Since(startTime)))

	return leaveTypes, totalCount, nil
}

// CreateLeavePolicy creates a new leave policy
func (s *leaveServiceImpl) CreateLeavePolicy(
	ctx context.Context,
	policy *leave.LeavePolicy,
	actorType string,
	actorID uuid.UUID,
	metadata map[string]interface{},
) (*leave.LeavePolicy, error) {
	startTime := time.Now()

	// Validate leave policy
	if err := s.validateLeavePolicy(policy); err != nil {
		return nil, fmt.Errorf("leave policy validation failed: %w", err)
	}

	// Generate UUID if not provided
	if policy.LeavePolicyID == uuid.Nil {
		policy.LeavePolicyID = uuid.New()
	}

	// Set timestamps
	now := time.Now().UTC()
	if policy.CreatedAt.IsZero() {
		policy.CreatedAt = now
	}

	// Check if policy code already exists
	existingPolicy, err := s.leaveRepo.GetLeavePolicyByCode(ctx, policy.CompanyID, policy.PolicyCode)
	if err == nil && existingPolicy != nil {
		return nil, fmt.Errorf("policy code already exists: %s", policy.PolicyCode)
	}

	// Create leave policy
	err = s.leaveRepo.CreateLeavePolicy(ctx, policy)
	if err != nil {
		s.logger.Error("Failed to create leave policy",
			util.String("company_id", policy.CompanyID.String()),
			util.String("policy_code", policy.PolicyCode),
			util.ErrorField(err))
		return nil, fmt.Errorf("failed to create leave policy: %w", err)
	}

	s.logger.Info("Leave policy created",
		util.String("policy_id", policy.LeavePolicyID.String()),
		util.String("policy_code", policy.PolicyCode),
		util.String("company_id", policy.CompanyID.String()),
		util.String("actor_type", actorType),
		util.String("actor_id", actorID.String()),
		util.Duration("duration", time.Since(startTime)))

	return policy, nil
}

// GetLeavePolicyByID retrieves a leave policy by ID
func (s *leaveServiceImpl) GetLeavePolicyByID(ctx context.Context, policyID uuid.UUID) (*leave.LeavePolicy, error) {
	startTime := time.Now()

	policy, err := s.leaveRepo.GetLeavePolicyByID(ctx, policyID)
	if err != nil {
		s.logger.Error("Failed to get leave policy by ID",
			util.String("policy_id", policyID.String()),
			util.ErrorField(err))
		return nil, fmt.Errorf("failed to get leave policy: %w", err)
	}

	s.logger.Debug("Leave policy retrieved",
		util.String("policy_id", policyID.String()),
		util.Duration("duration", time.Since(startTime)))

	return policy, nil
}

// // UpdateLeavePolicy updates an existing leave policy
// func (s *leaveServiceImpl) UpdateLeavePolicy(
// 	ctx context.Context,
// 	policy *leave.LeavePolicy,
// 	actorType string,
// 	actorID uuid.UUID,
// 	metadata map[string]interface{},
// ) error {
// 	startTime := time.Now()

// 	// Validate leave policy
// 	if err := s.validateLeavePolicy(policy); err != nil {
// 		return fmt.Errorf("leave policy validation failed: %w", err)
// 	}

// 	// Update leave policy
// 	err = s.leaveRepo.UpdateLeavePolicy(ctx, policy)
// 	if err != nil {
// 		s.logger.Error("Failed to update leave policy",
// 			util.String("policy_id", policy.LeavePolicyID.String()),
// 			util.ErrorField(err))
// 		return fmt.Errorf("failed to update leave policy: %w", err)
// 	}

// 	s.logger.Info("Leave policy updated",
// 		util.String("policy_id", policy.LeavePolicyID.String()),
// 		util.String("actor_type", actorType),
// 		util.String("actor_id", actorID.String()),
// 		util.Duration("duration", time.Since(startTime)))

// 	return nil
// }

// UpdateLeavePolicy updates an existing leave policy
func (s *leaveServiceImpl) UpdateLeavePolicy(
	ctx context.Context,
	policy *leave.LeavePolicy,
	actorType string,
	actorID uuid.UUID,
	metadata map[string]interface{},
) error {
	startTime := time.Now()

	// Validate leave policy
	if err := s.validateLeavePolicy(policy); err != nil {
		return fmt.Errorf("leave policy validation failed: %w", err)
	}

	// Ensure policy exists
	existingPolicy, err := s.leaveRepo.GetLeavePolicyByID(ctx, policy.LeavePolicyID)
	if err != nil {
		return fmt.Errorf("leave policy not found: %w", err)
	}

	// Prevent policy code conflict
	if policy.PolicyCode != existingPolicy.PolicyCode {
		byCode, err := s.leaveRepo.GetLeavePolicyByCode(ctx, policy.CompanyID, policy.PolicyCode)
		if err == nil && byCode != nil {
			return fmt.Errorf("policy code already exists: %s", policy.PolicyCode)
		}
	}

	// Update leave policy
	err = s.leaveRepo.UpdateLeavePolicy(ctx, policy)
	if err != nil {
		s.logger.Error("Failed to update leave policy",
			util.String("policy_id", policy.LeavePolicyID.String()),
			util.ErrorField(err))
		return fmt.Errorf("failed to update leave policy: %w", err)
	}

	s.logger.Info("Leave policy updated",
		util.String("policy_id", policy.LeavePolicyID.String()),
		util.String("policy_code", policy.PolicyCode),
		util.String("actor_type", actorType),
		util.String("actor_id", actorID.String()),
		util.Duration("duration", time.Since(startTime)))

	return nil
}

// DeleteLeavePolicy deletes a leave policy
func (s *leaveServiceImpl) DeleteLeavePolicy(
	ctx context.Context,
	policyID uuid.UUID,
	actorType string,
	actorID uuid.UUID,
	reason string,
) error {
	startTime := time.Now()

	// Check if policy is assigned to users
	userIDs, err := s.leaveRepo.ListUsersByLeavePolicy(ctx, policyID, time.Now().UTC())
	if err == nil && len(userIDs) > 0 {
		return fmt.Errorf("cannot delete leave policy assigned to users")
	}

	err = s.leaveRepo.DeleteLeavePolicy(ctx, policyID)
	if err != nil {
		s.logger.Error("Failed to delete leave policy",
			util.String("policy_id", policyID.String()),
			util.ErrorField(err))
		return fmt.Errorf("failed to delete leave policy: %w", err)
	}

	s.logger.Info("Leave policy deleted",
		util.String("policy_id", policyID.String()),
		util.String("reason", reason),
		util.String("actor_type", actorType),
		util.String("actor_id", actorID.String()),
		util.Duration("duration", time.Since(startTime)))

	return nil
}

// ListLeavePoliciesByCompany lists leave policies for a company
func (s *leaveServiceImpl) ListLeavePoliciesByCompany(ctx context.Context, companyID uuid.UUID, includeInactive bool) ([]*leave.LeavePolicy, error) {
	startTime := time.Now()

	policies, err := s.leaveRepo.ListLeavePoliciesByCompany(ctx, companyID, includeInactive)
	if err != nil {
		s.logger.Error("Failed to list leave policies by company",
			util.String("company_id", companyID.String()),
			util.ErrorField(err))
		return nil, fmt.Errorf("failed to list leave policies: %w", err)
	}

	s.logger.Debug("Leave policies listed",
		util.String("company_id", companyID.String()),
		util.Bool("include_inactive", includeInactive),
		util.Int("count", len(policies)),
		util.Duration("duration", time.Since(startTime)))

	return policies, nil
}

// ListLeavePoliciesByDepartment lists leave policies for a department
func (s *leaveServiceImpl) ListLeavePoliciesByDepartment(ctx context.Context, companyID, departmentID uuid.UUID) ([]*leave.LeavePolicy, error) {
	startTime := time.Now()

	policies, err := s.leaveRepo.ListLeavePoliciesByDepartment(ctx, companyID, departmentID)
	if err != nil {
		s.logger.Error("Failed to list leave policies by department",
			util.String("company_id", companyID.String()),
			util.String("department_id", departmentID.String()),
			util.ErrorField(err))
		return nil, fmt.Errorf("failed to list leave policies: %w", err)
	}

	s.logger.Debug("Leave policies listed by department",
		util.String("company_id", companyID.String()),
		util.String("department_id", departmentID.String()),
		util.Int("count", len(policies)),
		util.Duration("duration", time.Since(startTime)))

	return policies, nil
}

// SearchLeavePolicies searches leave policies with filters
func (s *leaveServiceImpl) SearchLeavePolicies(
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

	policies, totalCount, err := s.leaveRepo.SearchLeavePolicies(ctx, companyID, filters, pageSize, (page-1)*pageSize)
	if err != nil {
		s.logger.Error("Failed to search leave policies",
			util.String("company_id", companyID.String()),
			util.Int("filter_count", len(filters)),
			util.ErrorField(err))
		return nil, 0, fmt.Errorf("failed to search leave policies: %w", err)
	}

	s.logger.Debug("Leave policies searched",
		util.String("company_id", companyID.String()),
		util.Int("filter_count", len(filters)),
		util.Int("page", page),
		util.Int("page_size", pageSize),
		util.Int("total_count", totalCount),
		util.Int("returned_count", len(policies)),
		util.Duration("duration", time.Since(startTime)))

	return policies, totalCount, nil
}

// AssignUserLeavePolicy assigns a leave policy to a user
func (s *leaveServiceImpl) AssignUserLeavePolicy(
	ctx context.Context,
	userPolicy *leave.UserLeavePolicy,
	actorType string,
	actorID uuid.UUID,
	metadata map[string]interface{},
) error {
	startTime := time.Now()

	// Validate user policy
	if userPolicy.UserID == uuid.Nil {
		return fmt.Errorf("user ID is required")
	}
	if userPolicy.LeavePolicyID == uuid.Nil {
		return fmt.Errorf("policy ID is required")
	}
	if userPolicy.EffectiveFrom.IsZero() {
		userPolicy.EffectiveFrom = time.Now().UTC()
	}

	// Check if policy exists
	policy, err := s.leaveRepo.GetLeavePolicyByID(ctx, userPolicy.LeavePolicyID)
	if err != nil {
		return fmt.Errorf("leave policy not found: %w", err)
	}

	// Check if user already has active policy of same type
	activePolicies, err := s.leaveRepo.GetActiveUserLeavePolicies(ctx, userPolicy.UserID, time.Now().UTC())
	if err == nil && len(activePolicies) > 0 {
		// End previous active policy
		for _, activePolicy := range activePolicies {
			now := time.Now().UTC()
			activePolicy.EffectiveTo = &now
			if err := s.leaveRepo.UpdateUserLeavePolicy(ctx, activePolicy); err != nil {
				s.logger.Warn("Failed to end previous policy assignment",
					util.String("user_id", userPolicy.UserID.String()),
					util.ErrorField(err))
			}
		}
	}

	// Set timestamps
	userPolicy.CreatedAt = time.Now().UTC()
	if userPolicy.AssignedBy == nil {
		userPolicy.AssignedBy = &actorID
	}

	// Assign policy
	err = s.leaveRepo.AssignUserLeavePolicy(ctx, userPolicy)
	if err != nil {
		s.logger.Error("Failed to assign user leave policy",
			util.String("user_id", userPolicy.UserID.String()),
			util.String("policy_id", userPolicy.LeavePolicyID.String()),
			util.ErrorField(err))
		return fmt.Errorf("failed to assign user leave policy: %w", err)
	}

	s.logger.Info("User leave policy assigned",
		util.String("user_id", userPolicy.UserID.String()),
		util.String("policy_id", userPolicy.LeavePolicyID.String()),
		util.String("policy_code", policy.PolicyCode),
		util.Time("effective_from", userPolicy.EffectiveFrom),
		util.String("actor_type", actorType),
		util.String("actor_id", actorID.String()),
		util.Duration("duration", time.Since(startTime)))

	return nil
}

// GetActiveUserLeavePolicies gets active leave policies for a user
func (s *leaveServiceImpl) GetActiveUserLeavePolicies(ctx context.Context, userID uuid.UUID, asOf time.Time) ([]*leave.UserLeavePolicy, error) {
	startTime := time.Now()

	if asOf.IsZero() {
		asOf = time.Now().UTC()
	}

	policies, err := s.leaveRepo.GetActiveUserLeavePolicies(ctx, userID, asOf)
	if err != nil {
		s.logger.Error("Failed to get active user leave policies",
			util.String("user_id", userID.String()),
			util.ErrorField(err))
		return nil, fmt.Errorf("failed to get active user leave policies: %w", err)
	}

	s.logger.Debug("Active user leave policies retrieved",
		util.String("user_id", userID.String()),
		util.Int("policy_count", len(policies)),
		util.Duration("duration", time.Since(startTime)))

	return policies, nil
}

// RemoveUserLeavePolicy removes a leave policy assignment from a user
func (s *leaveServiceImpl) RemoveUserLeavePolicy(
	ctx context.Context,
	userID, policyID uuid.UUID,
	effectiveFrom time.Time,
	actorType string,
	actorID uuid.UUID,
	reason string,
) error {
	startTime := time.Now()

	err := s.leaveRepo.RemoveUserLeavePolicy(ctx, userID, policyID, effectiveFrom)
	if err != nil {
		s.logger.Error("Failed to remove user leave policy",
			util.String("user_id", userID.String()),
			util.String("policy_id", policyID.String()),
			util.ErrorField(err))
		return fmt.Errorf("failed to remove user leave policy: %w", err)
	}

	s.logger.Info("User leave policy removed",
		util.String("user_id", userID.String()),
		util.String("policy_id", policyID.String()),
		util.String("reason", reason),
		util.String("actor_type", actorType),
		util.String("actor_id", actorID.String()),
		util.Duration("duration", time.Since(startTime)))

	return nil
}

// ListUserLeavePoliciesByUser lists all leave policy assignments for a user
func (s *leaveServiceImpl) ListUserLeavePoliciesByUser(ctx context.Context, userID uuid.UUID) ([]*leave.UserLeavePolicy, error) {
	startTime := time.Now()

	policies, err := s.leaveRepo.ListUserLeavePoliciesByUser(ctx, userID)
	if err != nil {
		s.logger.Error("Failed to list user leave policies",
			util.String("user_id", userID.String()),
			util.ErrorField(err))
		return nil, fmt.Errorf("failed to list user leave policies: %w", err)
	}

	s.logger.Debug("User leave policies listed",
		util.String("user_id", userID.String()),
		util.Int("policy_count", len(policies)),
		util.Duration("duration", time.Since(startTime)))

	return policies, nil
}

// CreateLeaveRequest creates a new leave request
func (s *leaveServiceImpl) CreateLeaveRequest(
	ctx context.Context,
	req *leave.LeaveRequest,
	actorType string,
	actorID uuid.UUID,
	metadata map[string]interface{},
) (*leave.LeaveRequest, error) {
	startTime := time.Now()

	// Validate leave request
	if err := s.validateLeaveRequest(req); err != nil {
		return nil, fmt.Errorf("leave request validation failed: %w", err)
	}

	// Generate UUID if not provided
	if req.LeaveRequestID == uuid.Nil {
		req.LeaveRequestID = uuid.New()
	}

	// Set timestamps
	now := time.Now().UTC()
	if req.RequestedAt.IsZero() {
		req.RequestedAt = now
	}

	// Check for overlapping leaves
	hasOverlap, err := s.leaveRepo.CheckLeaveOverlap(ctx, req.UserID, req.StartDate, req.EndDate, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to check leave overlap: %w", err)
	}
	if hasOverlap {
		return nil, fmt.Errorf("overlapping leave request found")
	}

	// Check leave balance
	balance, err := s.leaveRepo.CalculateLeaveBalance(ctx, req.UserID, req.LeaveTypeID, time.Now().UTC())
	if err != nil {
		return nil, fmt.Errorf("failed to calculate leave balance: %w", err)
	}

	if balance < req.Duration {
		return nil, fmt.Errorf("insufficient leave balance: available %.2f, requested %.2f", balance, req.Duration)
	}

	// Set default status
	if req.Status == "" {
		req.Status = "pending"
	}

	// Create leave request
	err = s.leaveRepo.CreateLeaveRequest(ctx, req)
	if err != nil {
		s.logger.Error("Failed to create leave request",
			util.String("user_id", req.UserID.String()),
			util.String("company_id", req.CompanyID.String()),
			util.ErrorField(err))
		return nil, fmt.Errorf("failed to create leave request: %w", err)
	}

	// Create leave transaction
	txn := &leave.LeaveTransaction{
		TransactionID:  uuid.New(),
		CompanyID:      req.CompanyID,
		UserID:         req.UserID,
		LeaveTypeID:    req.LeaveTypeID,
		LeaveRequestID: &req.LeaveRequestID,
		ChangeAmount:   -req.Duration,
		Reason:         "request",
		CreatedAt:      now,
	}

	if err := s.leaveRepo.CreateLeaveTransaction(ctx, txn); err != nil {
		s.logger.Warn("Failed to create leave transaction for request",
			util.String("request_id", req.LeaveRequestID.String()),
			util.ErrorField(err))
	}

	s.logger.Info("Leave request created",
		util.String("request_id", req.LeaveRequestID.String()),
		util.String("user_id", req.UserID.String()),
		util.String("company_id", req.CompanyID.String()),
		util.String("status", req.Status),
		util.String("actor_type", actorType),
		util.String("actor_id", actorID.String()),
		util.Duration("duration", time.Since(startTime)))

	return req, nil
}

// GetLeaveRequestByID retrieves a leave request by ID
func (s *leaveServiceImpl) GetLeaveRequestByID(ctx context.Context, requestID uuid.UUID) (*leave.LeaveRequest, error) {
	startTime := time.Now()

	req, err := s.leaveRepo.GetLeaveRequestByID(ctx, requestID)
	if err != nil {
		s.logger.Error("Failed to get leave request by ID",
			util.String("request_id", requestID.String()),
			util.ErrorField(err))
		return nil, fmt.Errorf("failed to get leave request: %w", err)
	}

	s.logger.Debug("Leave request retrieved",
		util.String("request_id", requestID.String()),
		util.Duration("duration", time.Since(startTime)))

	return req, nil
}

// UpdateLeaveRequest updates an existing leave request
func (s *leaveServiceImpl) UpdateLeaveRequest(
	ctx context.Context,
	req *leave.LeaveRequest,
	actorType string,
	actorID uuid.UUID,
	metadata map[string]interface{},
) error {
	startTime := time.Now()

	// Validate leave request
	if err := s.validateLeaveRequest(req); err != nil {
		return fmt.Errorf("leave request validation failed: %w", err)
	}

	// Get existing request
	existingReq, err := s.leaveRepo.GetLeaveRequestByID(ctx, req.LeaveRequestID)
	if err != nil {
		return fmt.Errorf("leave request not found: %w", err)
	}

	// Check if dates changed
	datesChanged := !existingReq.StartDate.Equal(req.StartDate) || !existingReq.EndDate.Equal(req.EndDate)
	durationChanged := existingReq.Duration != req.Duration

	// If dates or duration changed, check for overlap and balance
	if datesChanged || durationChanged {
		// Check for overlapping leaves (excluding current request)
		hasOverlap, err := s.leaveRepo.CheckLeaveOverlap(ctx, req.UserID, req.StartDate, req.EndDate, &req.LeaveRequestID)
		if err != nil {
			return fmt.Errorf("failed to check leave overlap: %w", err)
		}
		if hasOverlap {
			return fmt.Errorf("overlapping leave request found")
		}

		// Check leave balance for increased duration
		if durationChanged && req.Duration > existingReq.Duration {
			additionalDays := req.Duration - existingReq.Duration
			balance, err := s.leaveRepo.CalculateLeaveBalance(ctx, req.UserID, req.LeaveTypeID, time.Now().UTC())
			if err != nil {
				return fmt.Errorf("failed to calculate leave balance: %w", err)
			}
			if balance < additionalDays {
				return fmt.Errorf("insufficient leave balance for additional days")
			}

			// Create transaction for the difference
			txn := &leave.LeaveTransaction{
				TransactionID:  uuid.New(),
				CompanyID:      req.CompanyID,
				UserID:         req.UserID,
				LeaveTypeID:    req.LeaveTypeID,
				LeaveRequestID: &req.LeaveRequestID,
				ChangeAmount:   -(additionalDays),
				Reason:         "request_adjustment",
				CreatedAt:      time.Now().UTC(),
			}
			if err := s.leaveRepo.CreateLeaveTransaction(ctx, txn); err != nil {
				s.logger.Warn("Failed to create adjustment transaction",
					util.String("request_id", req.LeaveRequestID.String()),
					util.ErrorField(err))
			}
		}
	}

	// Update leave request
	err = s.leaveRepo.UpdateLeaveRequest(ctx, req)
	if err != nil {
		s.logger.Error("Failed to update leave request",
			util.String("request_id", req.LeaveRequestID.String()),
			util.ErrorField(err))
		return fmt.Errorf("failed to update leave request: %w", err)
	}

	s.logger.Info("Leave request updated",
		util.String("request_id", req.LeaveRequestID.String()),
		util.String("actor_type", actorType),
		util.String("actor_id", actorID.String()),
		util.Duration("duration", time.Since(startTime)))

	return nil
}

// CancelLeaveRequest cancels a leave request
func (s *leaveServiceImpl) CancelLeaveRequest(
	ctx context.Context,
	requestID uuid.UUID,
	reason string,
	actorType string,
	actorID uuid.UUID,
) error {
	startTime := time.Now()

	// Get existing request
	existingReq, err := s.leaveRepo.GetLeaveRequestByID(ctx, requestID)
	if err != nil {
		return fmt.Errorf("leave request not found: %w", err)
	}

	// Check if can be cancelled
	if existingReq.Status != "pending" && existingReq.Status != "approved" {
		return fmt.Errorf("only pending or approved requests can be cancelled")
	}

	// Cancel the request
	err = s.leaveRepo.CancelLeaveRequest(ctx, requestID, reason)
	if err != nil {
		s.logger.Error("Failed to cancel leave request",
			util.String("request_id", requestID.String()),
			util.ErrorField(err))
		return fmt.Errorf("failed to cancel leave request: %w", err)
	}

	// Refund leave balance if request was approved
	if existingReq.Status == "approved" {
		txn := &leave.LeaveTransaction{
			TransactionID:  uuid.New(),
			CompanyID:      existingReq.CompanyID,
			UserID:         existingReq.UserID,
			LeaveTypeID:    existingReq.LeaveTypeID,
			LeaveRequestID: &requestID,
			ChangeAmount:   existingReq.Duration,
			Reason:         "cancel",
			CreatedAt:      time.Now().UTC(),
		}
		if err := s.leaveRepo.CreateLeaveTransaction(ctx, txn); err != nil {
			s.logger.Warn("Failed to create cancellation transaction",
				util.String("request_id", requestID.String()),
				util.ErrorField(err))
		}
	}

	s.logger.Info("Leave request cancelled",
		util.String("request_id", requestID.String()),
		util.String("reason", reason),
		util.String("actor_type", actorType),
		util.String("actor_id", actorID.String()),
		util.Duration("duration", time.Since(startTime)))

	return nil
}

// DeleteLeaveRequest deletes a leave request
func (s *leaveServiceImpl) DeleteLeaveRequest(
	ctx context.Context,
	requestID uuid.UUID,
	actorType string,
	actorID uuid.UUID,
	reason string,
) error {
	startTime := time.Now()

	// Get existing request
	existingReq, err := s.leaveRepo.GetLeaveRequestByID(ctx, requestID)
	if err != nil {
		return fmt.Errorf("leave request not found: %w", err)
	}

	// Refund leave balance if request was approved
	if existingReq.Status == "approved" {
		txn := &leave.LeaveTransaction{
			TransactionID:  uuid.New(),
			CompanyID:      existingReq.CompanyID,
			UserID:         existingReq.UserID,
			LeaveTypeID:    existingReq.LeaveTypeID,
			LeaveRequestID: &requestID,
			ChangeAmount:   existingReq.Duration,
			Reason:         "delete",
			CreatedAt:      time.Now().UTC(),
		}
		if err := s.leaveRepo.CreateLeaveTransaction(ctx, txn); err != nil {
			s.logger.Warn("Failed to create deletion transaction",
				util.String("request_id", requestID.String()),
				util.ErrorField(err))
		}
	}

	// Delete leave request
	err = s.leaveRepo.DeleteLeaveRequest(ctx, requestID)
	if err != nil {
		s.logger.Error("Failed to delete leave request",
			util.String("request_id", requestID.String()),
			util.ErrorField(err))
		return fmt.Errorf("failed to delete leave request: %w", err)
	}

	s.logger.Info("Leave request deleted",
		util.String("request_id", requestID.String()),
		util.String("reason", reason),
		util.String("actor_type", actorType),
		util.String("actor_id", actorID.String()),
		util.Duration("duration", time.Since(startTime)))

	return nil
}

// ListLeaveRequestsByUser lists leave requests for a user
func (s *leaveServiceImpl) ListLeaveRequestsByUser(ctx context.Context, userID uuid.UUID, startDate, endDate time.Time) ([]*leave.LeaveRequest, error) {
	startTime := time.Now()

	if startDate.IsZero() {
		startDate = time.Now().AddDate(0, -6, 0) // Default: last 6 months
	}
	if endDate.IsZero() {
		endDate = time.Now().AddDate(0, 6, 0) // Default: next 6 months
	}

	requests, err := s.leaveRepo.ListLeaveRequestsByUser(ctx, userID, startDate, endDate)
	if err != nil {
		s.logger.Error("Failed to list leave requests by user",
			util.String("user_id", userID.String()),
			util.ErrorField(err))
		return nil, fmt.Errorf("failed to list leave requests: %w", err)
	}

	s.logger.Debug("Leave requests listed by user",
		util.String("user_id", userID.String()),
		util.Int("request_count", len(requests)),
		util.Duration("duration", time.Since(startTime)))

	return requests, nil
}

// ListLeaveRequestsByCompany lists leave requests for a company
func (s *leaveServiceImpl) ListLeaveRequestsByCompany(
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

	requests, totalCount, err := s.leaveRepo.ListLeaveRequestsByCompany(ctx, companyID, filters, pageSize, (page-1)*pageSize)
	if err != nil {
		s.logger.Error("Failed to list leave requests by company",
			util.String("company_id", companyID.String()),
			util.ErrorField(err))
		return nil, 0, fmt.Errorf("failed to list leave requests: %w", err)
	}

	s.logger.Debug("Leave requests listed by company",
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
func (s *leaveServiceImpl) ListPendingLeaveRequests(ctx context.Context, companyID uuid.UUID, approverID uuid.UUID) ([]*leave.LeaveRequest, error) {
	startTime := time.Now()

	requests, err := s.leaveRepo.ListPendingLeaveRequests(ctx, companyID, approverID)
	if err != nil {
		s.logger.Error("Failed to list pending leave requests",
			util.String("company_id", companyID.String()),
			util.String("approver_id", approverID.String()),
			util.ErrorField(err))
		return nil, fmt.Errorf("failed to list pending leave requests: %w", err)
	}

	s.logger.Debug("Pending leave requests listed",
		util.String("company_id", companyID.String()),
		util.String("approver_id", approverID.String()),
		util.Int("request_count", len(requests)),
		util.Duration("duration", time.Since(startTime)))

	return requests, nil
}

// CheckLeaveOverlap checks for overlapping leave requests
func (s *leaveServiceImpl) CheckLeaveOverlap(ctx context.Context, userID uuid.UUID, startDate, endDate time.Time, excludeRequestID *uuid.UUID) (bool, error) {
	startTime := time.Now()

	hasOverlap, err := s.leaveRepo.CheckLeaveOverlap(ctx, userID, startDate, endDate, excludeRequestID)
	if err != nil {
		s.logger.Error("Failed to check leave overlap",
			util.String("user_id", userID.String()),
			util.ErrorField(err))
		return false, fmt.Errorf("failed to check leave overlap: %w", err)
	}

	s.logger.Debug("Leave overlap checked",
		util.String("user_id", userID.String()),
		util.Bool("has_overlap", hasOverlap),
		util.Duration("duration", time.Since(startTime)))

	return hasOverlap, nil
}

// CreateLeaveApproval creates a new leave approval
func (s *leaveServiceImpl) CreateLeaveApproval(
	ctx context.Context,
	approval *leave.LeaveApproval,
	actorType string,
	actorID uuid.UUID,
	metadata map[string]interface{},
) (*leave.LeaveApproval, error) {
	startTime := time.Now()

	// Validate leave approval
	if approval.LeaveRequestID == uuid.Nil {
		return nil, fmt.Errorf("leave request ID is required")
	}
	if approval.ApprovedBy == uuid.Nil {
		return nil, fmt.Errorf("approver ID is required")
	}
	if approval.Decision == "" {
		return nil, fmt.Errorf("decision is required")
	}
	if approval.Decision != "approved" && approval.Decision != "rejected" {
		return nil, fmt.Errorf("invalid decision: must be 'approved' or 'rejected'")
	}

	// Generate UUID if not provided
	if approval.ApprovalID == uuid.Nil {
		approval.ApprovalID = uuid.New()
	}

	// Set timestamps
	if approval.DecidedAt.IsZero() {
		approval.DecidedAt = time.Now().UTC()
	}

	// Check if user already approved this request
	hasApproved, err := s.leaveRepo.HasUserApprovedRequest(ctx, approval.LeaveRequestID, approval.ApprovedBy)
	if err != nil {
		return nil, fmt.Errorf("failed to check existing approval: %w", err)
	}
	if hasApproved {
		return nil, fmt.Errorf("user has already approved this request")
	}

	// Create leave approval
	err = s.leaveRepo.CreateLeaveApproval(ctx, approval)
	if err != nil {
		s.logger.Error("Failed to create leave approval",
			util.String("request_id", approval.LeaveRequestID.String()),
			util.String("approver_id", approval.ApprovedBy.String()),
			util.ErrorField(err))
		return nil, fmt.Errorf("failed to create leave approval: %w", err)
	}

	s.logger.Info("Leave approval created",
		util.String("approval_id", approval.ApprovalID.String()),
		util.String("request_id", approval.LeaveRequestID.String()),
		util.String("decision", approval.Decision),
		util.String("actor_type", actorType),
		util.String("actor_id", actorID.String()),
		util.Duration("duration", time.Since(startTime)))

	return approval, nil
}

// GetApprovalsByLeaveRequest gets approvals for a leave request
func (s *leaveServiceImpl) GetApprovalsByLeaveRequest(ctx context.Context, requestID uuid.UUID) ([]*leave.LeaveApproval, error) {
	startTime := time.Now()

	approvals, err := s.leaveRepo.GetApprovalsByLeaveRequest(ctx, requestID)
	if err != nil {
		s.logger.Error("Failed to get approvals by leave request",
			util.String("request_id", requestID.String()),
			util.ErrorField(err))
		return nil, fmt.Errorf("failed to get approvals: %w", err)
	}

	s.logger.Debug("Approvals retrieved by request",
		util.String("request_id", requestID.String()),
		util.Int("approval_count", len(approvals)),
		util.Duration("duration", time.Since(startTime)))

	return approvals, nil
}

// HasUserApprovedRequest checks if a user has approved a request
func (s *leaveServiceImpl) HasUserApprovedRequest(ctx context.Context, requestID, userID uuid.UUID) (bool, error) {
	startTime := time.Now()

	hasApproved, err := s.leaveRepo.HasUserApprovedRequest(ctx, requestID, userID)
	if err != nil {
		s.logger.Error("Failed to check if user approved request",
			util.String("request_id", requestID.String()),
			util.String("user_id", userID.String()),
			util.ErrorField(err))
		return false, fmt.Errorf("failed to check approval: %w", err)
	}

	s.logger.Debug("User approval check completed",
		util.String("request_id", requestID.String()),
		util.String("user_id", userID.String()),
		util.Bool("has_approved", hasApproved),
		util.Duration("duration", time.Since(startTime)))

	return hasApproved, nil
}

// GetApprovalChain gets the approval chain for a leave request
func (s *leaveServiceImpl) GetApprovalChain(ctx context.Context, requestID uuid.UUID) ([]*leave.LeaveApproval, error) {
	startTime := time.Now()

	approvals, err := s.leaveRepo.GetApprovalChain(ctx, requestID)
	if err != nil {
		s.logger.Error("Failed to get approval chain",
			util.String("request_id", requestID.String()),
			util.ErrorField(err))
		return nil, fmt.Errorf("failed to get approval chain: %w", err)
	}

	s.logger.Debug("Approval chain retrieved",
		util.String("request_id", requestID.String()),
		util.Int("approval_count", len(approvals)),
		util.Duration("duration", time.Since(startTime)))

	return approvals, nil
}

// CreateLeaveTransaction creates a new leave transaction
func (s *leaveServiceImpl) CreateLeaveTransaction(
	ctx context.Context,
	txn *leave.LeaveTransaction,
	actorType string,
	actorID uuid.UUID,
	metadata map[string]interface{},
) (*leave.LeaveTransaction, error) {
	startTime := time.Now()

	// Validate leave transaction
	if txn.CompanyID == uuid.Nil {
		return nil, fmt.Errorf("company ID is required")
	}
	if txn.UserID == uuid.Nil {
		return nil, fmt.Errorf("user ID is required")
	}
	if txn.LeaveTypeID == uuid.Nil {
		return nil, fmt.Errorf("leave type ID is required")
	}
	if txn.ChangeAmount == 0 {
		return nil, fmt.Errorf("change amount cannot be zero")
	}
	if txn.Reason == "" {
		return nil, fmt.Errorf("reason is required")
	}

	// Generate UUID if not provided
	if txn.TransactionID == uuid.Nil {
		txn.TransactionID = uuid.New()
	}

	// Set timestamps
	if txn.CreatedAt.IsZero() {
		txn.CreatedAt = time.Now().UTC()
	}

	// Create leave transaction
	err := s.leaveRepo.CreateLeaveTransaction(ctx, txn)
	if err != nil {
		s.logger.Error("Failed to create leave transaction",
			util.String("user_id", txn.UserID.String()),
			util.String("leave_type_id", txn.LeaveTypeID.String()),
			util.ErrorField(err))
		return nil, fmt.Errorf("failed to create leave transaction: %w", err)
	}

	s.logger.Info("Leave transaction created",
		util.String("transaction_id", txn.TransactionID.String()),
		util.String("user_id", txn.UserID.String()),
		util.Float64("change_amount", txn.ChangeAmount),
		util.String("reason", txn.Reason),
		util.String("actor_type", actorType),
		util.String("actor_id", actorID.String()),
		util.Duration("duration", time.Since(startTime)))

	return txn, nil
}

// GetLeaveTransactionsByUser gets leave transactions for a user
func (s *leaveServiceImpl) GetLeaveTransactionsByUser(
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

	transactions, err := s.leaveRepo.GetLeaveTransactionsByUser(ctx, userID, leaveTypeID, startDate, endDate)
	if err != nil {
		s.logger.Error("Failed to get leave transactions by user",
			util.String("user_id", userID.String()),
			util.ErrorField(err))
		return nil, fmt.Errorf("failed to get leave transactions: %w", err)
	}

	s.logger.Debug("Leave transactions retrieved by user",
		util.String("user_id", userID.String()),
		util.Int("transaction_count", len(transactions)),
		util.Duration("duration", time.Since(startTime)))

	return transactions, nil
}

// CalculateLeaveBalance calculates leave balance for a user
func (s *leaveServiceImpl) CalculateLeaveBalance(ctx context.Context, userID, leaveTypeID uuid.UUID, asOf time.Time) (float64, error) {
	startTime := time.Now()

	if asOf.IsZero() {
		asOf = time.Now().UTC()
	}

	balance, err := s.leaveRepo.CalculateLeaveBalance(ctx, userID, leaveTypeID, asOf)
	if err != nil {
		s.logger.Error("Failed to calculate leave balance",
			util.String("user_id", userID.String()),
			util.String("leave_type_id", leaveTypeID.String()),
			util.ErrorField(err))
		return 0, fmt.Errorf("failed to calculate leave balance: %w", err)
	}

	s.logger.Debug("Leave balance calculated",
		util.String("user_id", userID.String()),
		util.String("leave_type_id", leaveTypeID.String()),
		util.Float64("balance", balance),
		util.Duration("duration", time.Since(startTime)))

	return balance, nil
}

// GetTransactionSummary gets transaction summary for a user
func (s *leaveServiceImpl) GetTransactionSummary(ctx context.Context, userID uuid.UUID, startDate, endDate time.Time) (map[string]float64, error) {
	startTime := time.Now()

	if startDate.IsZero() {
		startDate = time.Now().AddDate(-1, 0, 0) // Default: last year
	}
	if endDate.IsZero() {
		endDate = time.Now()
	}

	summary, err := s.leaveRepo.GetTransactionSummary(ctx, userID, startDate, endDate)
	if err != nil {
		s.logger.Error("Failed to get transaction summary",
			util.String("user_id", userID.String()),
			util.ErrorField(err))
		return nil, fmt.Errorf("failed to get transaction summary: %w", err)
	}

	s.logger.Debug("Transaction summary retrieved",
		util.String("user_id", userID.String()),
		util.Duration("duration", time.Since(startTime)))

	return summary, nil
}

// CreateOrUpdateLeaveBalance creates or updates a leave balance record
func (s *leaveServiceImpl) CreateOrUpdateLeaveBalance(
	ctx context.Context,
	balance *leave.LeaveBalance,
	actorType string,
	actorID uuid.UUID,
	metadata map[string]interface{},
) error {
	startTime := time.Now()

	// Validate leave balance
	if balance.CompanyID == uuid.Nil {
		return fmt.Errorf("company ID is required")
	}
	if balance.UserID == uuid.Nil {
		return fmt.Errorf("user ID is required")
	}
	if balance.LeaveTypeID == uuid.Nil {
		return fmt.Errorf("leave type ID is required")
	}
	if balance.AsOf.IsZero() {
		return fmt.Errorf("as of date is required")
	}

	// Set timestamps
	if balance.GeneratedAt.IsZero() {
		balance.GeneratedAt = time.Now().UTC()
	}

	// Create or update leave balance
	err := s.leaveRepo.CreateOrUpdateLeaveBalance(ctx, balance)
	if err != nil {
		s.logger.Error("Failed to create/update leave balance",
			util.String("user_id", balance.UserID.String()),
			util.String("leave_type_id", balance.LeaveTypeID.String()),
			util.ErrorField(err))
		return fmt.Errorf("failed to create/update leave balance: %w", err)
	}

	s.logger.Info("Leave balance created/updated",
		util.String("user_id", balance.UserID.String()),
		util.String("leave_type_id", balance.LeaveTypeID.String()),
		util.Float64("balance", balance.Balance),
		util.Time("as_of", balance.AsOf),
		util.String("actor_type", actorType),
		util.String("actor_id", actorID.String()),
		util.Duration("duration", time.Since(startTime)))

	return nil
}

// GetCurrentLeaveBalance gets the current leave balance for a user
func (s *leaveServiceImpl) GetCurrentLeaveBalance(ctx context.Context, userID, leaveTypeID uuid.UUID) (*leave.LeaveBalance, error) {
	startTime := time.Now()

	balance, err := s.leaveRepo.GetCurrentLeaveBalance(ctx, userID, leaveTypeID)
	if err != nil {
		s.logger.Error("Failed to get current leave balance",
			util.String("user_id", userID.String()),
			util.String("leave_type_id", leaveTypeID.String()),
			util.ErrorField(err))
		return nil, fmt.Errorf("failed to get current leave balance: %w", err)
	}

	s.logger.Debug("Current leave balance retrieved",
		util.String("user_id", userID.String()),
		util.String("leave_type_id", leaveTypeID.String()),
		util.Float64("balance", balance.Balance),
		util.Duration("duration", time.Since(startTime)))

	return balance, nil
}

// GetLeaveBalancesByUser gets all leave balances for a user
func (s *leaveServiceImpl) GetLeaveBalancesByUser(ctx context.Context, userID uuid.UUID, asOf time.Time) ([]*leave.LeaveBalance, error) {
	startTime := time.Now()

	if asOf.IsZero() {
		asOf = time.Now().UTC()
	}

	balances, err := s.leaveRepo.GetLeaveBalancesByUser(ctx, userID, asOf)
	if err != nil {
		s.logger.Error("Failed to get leave balances by user",
			util.String("user_id", userID.String()),
			util.ErrorField(err))
		return nil, fmt.Errorf("failed to get leave balances: %w", err)
	}

	s.logger.Debug("Leave balances retrieved by user",
		util.String("user_id", userID.String()),
		util.Int("balance_count", len(balances)),
		util.Duration("duration", time.Since(startTime)))

	return balances, nil
}

// RecalculateLeaveBalances recalculates leave balances for a user
func (s *leaveServiceImpl) RecalculateLeaveBalances(ctx context.Context, userID uuid.UUID, fromDate time.Time) error {
	startTime := time.Now()

	err := s.leaveRepo.RecalculateLeaveBalances(ctx, userID, fromDate)
	if err != nil {
		s.logger.Error("Failed to recalculate leave balances",
			util.String("user_id", userID.String()),
			util.ErrorField(err))
		return fmt.Errorf("failed to recalculate leave balances: %w", err)
	}

	s.logger.Info("Leave balances recalculated",
		util.String("user_id", userID.String()),
		util.Duration("duration", time.Since(startTime)))

	return nil
}

// AccrueLeavesForUser accrues leaves for a user based on their policy
func (s *leaveServiceImpl) AccrueLeavesForUser(
	ctx context.Context,
	userID uuid.UUID,
	accrualDate time.Time,
	actorType string,
	actorID uuid.UUID,
) ([]*leave.LeaveTransaction, error) {
	startTime := time.Now()

	if accrualDate.IsZero() {
		accrualDate = time.Now().UTC()
	}

	// Get active leave policies for user
	activePolicies, err := s.leaveRepo.GetActiveUserLeavePolicies(ctx, userID, accrualDate)
	if err != nil {
		return nil, fmt.Errorf("failed to get active leave policies: %w", err)
	}

	var transactions []*leave.LeaveTransaction

	for _, policy := range activePolicies {
		// Get policy details
		policyDetails, err := s.leaveRepo.GetLeavePolicyByID(ctx, policy.LeavePolicyID)
		if err != nil {
			s.logger.Warn("Failed to get policy details for accrual",
				util.String("policy_id", policy.LeavePolicyID.String()),
				util.ErrorField(err))
			continue
		}

		// Check if accrual should be processed based on policy rules
		if policyDetails.Rules.Accrual == "monthly" {
			// Calculate accrual amount
			accrualAmount := policyDetails.Rules.AccrualRate

			// Create transaction
			txn := &leave.LeaveTransaction{
				TransactionID:  uuid.New(),
				CompanyID:      policyDetails.CompanyID,
				UserID:         userID,
				LeaveTypeID:    uuid.Nil, // TODO: Map from policy to leave type
				LeaveRequestID: nil,
				ChangeAmount:   accrualAmount,
				Reason:         "accrual",
				CreatedAt:      accrualDate,
			}

			// Create transaction
			if err := s.leaveRepo.CreateLeaveTransaction(ctx, txn); err != nil {
				s.logger.Warn("Failed to create accrual transaction",
					util.String("user_id", userID.String()),
					util.String("policy_id", policy.LeavePolicyID.String()),
					util.ErrorField(err))
				continue
			}

			transactions = append(transactions, txn)
		}
	}

	s.logger.Info("Leaves accrued for user",
		util.String("user_id", userID.String()),
		util.Int("transaction_count", len(transactions)),
		util.String("actor_type", actorType),
		util.String("actor_id", actorID.String()),
		util.Duration("duration", time.Since(startTime)))

	return transactions, nil
}

// ProcessMonthlyAccrual processes monthly accrual for all employees in a company
func (s *leaveServiceImpl) ProcessMonthlyAccrual(
	ctx context.Context,
	companyID uuid.UUID,
	month time.Time,
	actorType string,
	actorID uuid.UUID,
) error {
	startTime := time.Now()

	if month.IsZero() {
		month = time.Now().UTC()
	}

	// TODO: Implement bulk accrual processing
	// This would typically involve:
	// 1. Get all active employees in the company
	// 2. For each employee, call AccrueLeavesForUser
	// 3. Handle batch processing and error recovery

	s.logger.Info("Monthly accrual processing started",
		util.String("company_id", companyID.String()),
		util.String("month", month.Format("2006-01")),
		util.String("actor_type", actorType),
		util.String("actor_id", actorID.String()),
		util.Duration("duration", time.Since(startTime)))

	return nil
}

// ApproveLeaveRequest approves a leave request
func (s *leaveServiceImpl) ApproveLeaveRequest(
	ctx context.Context,
	requestID uuid.UUID,
	approverID uuid.UUID,
	reason string,
	metadata map[string]interface{},
) error {
	startTime := time.Now()

	// Get the leave request
	req, err := s.leaveRepo.GetLeaveRequestByID(ctx, requestID)
	if err != nil {
		return fmt.Errorf("leave request not found: %w", err)
	}

	// Check if already approved
	if req.Status == "approved" {
		return fmt.Errorf("leave request already approved")
	}

	// Create approval
	approval := &leave.LeaveApproval{
		ApprovalID:     uuid.New(),
		LeaveRequestID: requestID,
		ApprovedBy:     approverID,
		Decision:       "approved",
		DecisionReason: &reason,
		ApprovalLevel:  1,
		DecidedAt:      time.Now().UTC(),
	}

	// Create approval record
	if err := s.leaveRepo.CreateLeaveApproval(ctx, approval); err != nil {
		s.logger.Error("Failed to create approval record",
			util.String("request_id", requestID.String()),
			util.String("approver_id", approverID.String()),
			util.ErrorField(err))
		return fmt.Errorf("failed to create approval record: %w", err)
	}

	// Update request status
	req.Status = "approved"
	if err := s.leaveRepo.UpdateLeaveRequest(ctx, req); err != nil {
		s.logger.Error("Failed to update leave request status",
			util.String("request_id", requestID.String()),
			util.ErrorField(err))
		return fmt.Errorf("failed to update leave request: %w", err)
	}

	s.logger.Info("Leave request approved",
		util.String("request_id", requestID.String()),
		util.String("approver_id", approverID.String()),
		util.String("reason", reason),
		util.Duration("duration", time.Since(startTime)))

	return nil
}

// RejectLeaveRequest rejects a leave request
func (s *leaveServiceImpl) RejectLeaveRequest(
	ctx context.Context,
	requestID uuid.UUID,
	approverID uuid.UUID,
	reason string,
	metadata map[string]interface{},
) error {
	startTime := time.Now()

	// Get the leave request
	req, err := s.leaveRepo.GetLeaveRequestByID(ctx, requestID)
	if err != nil {
		return fmt.Errorf("leave request not found: %w", err)
	}

	// Check if already processed
	if req.Status != "pending" {
		return fmt.Errorf("leave request already processed")
	}

	// Create approval/rejection record
	approval := &leave.LeaveApproval{
		ApprovalID:     uuid.New(),
		LeaveRequestID: requestID,
		ApprovedBy:     approverID,
		Decision:       "rejected",
		DecisionReason: &reason,
		ApprovalLevel:  1,
		DecidedAt:      time.Now().UTC(),
	}

	// Create rejection record
	if err := s.leaveRepo.CreateLeaveApproval(ctx, approval); err != nil {
		s.logger.Error("Failed to create rejection record",
			util.String("request_id", requestID.String()),
			util.String("approver_id", approverID.String()),
			util.ErrorField(err))
		return fmt.Errorf("failed to create rejection record: %w", err)
	}

	// Update request status
	req.Status = "rejected"
	if err := s.leaveRepo.UpdateLeaveRequest(ctx, req); err != nil {
		s.logger.Error("Failed to update leave request status",
			util.String("request_id", requestID.String()),
			util.ErrorField(err))
		return fmt.Errorf("failed to update leave request: %w", err)
	}

	// Refund leave balance
	txn := &leave.LeaveTransaction{
		TransactionID:  uuid.New(),
		CompanyID:      req.CompanyID,
		UserID:         req.UserID,
		LeaveTypeID:    req.LeaveTypeID,
		LeaveRequestID: &requestID,
		ChangeAmount:   req.Duration,
		Reason:         "rejection",
		CreatedAt:      time.Now().UTC(),
	}

	if err := s.leaveRepo.CreateLeaveTransaction(ctx, txn); err != nil {
		s.logger.Warn("Failed to create refund transaction",
			util.String("request_id", requestID.String()),
			util.ErrorField(err))
	}

	s.logger.Info("Leave request rejected",
		util.String("request_id", requestID.String()),
		util.String("approver_id", approverID.String()),
		util.String("reason", reason),
		util.Duration("duration", time.Since(startTime)))

	return nil
}

// WithdrawLeaveRequest withdraws a leave request
func (s *leaveServiceImpl) WithdrawLeaveRequest(
	ctx context.Context,
	requestID uuid.UUID,
	userID uuid.UUID,
	reason string,
	metadata map[string]interface{},
) error {
	startTime := time.Now()

	// Get the leave request
	req, err := s.leaveRepo.GetLeaveRequestByID(ctx, requestID)
	if err != nil {
		return fmt.Errorf("leave request not found: %w", err)
	}

	// Check if user owns the request
	if req.UserID != userID {
		return fmt.Errorf("unauthorized to withdraw this leave request")
	}

	// Check if can be withdrawn
	if req.Status != "pending" {
		return fmt.Errorf("only pending requests can be withdrawn")
	}

	// Update request status
	req.Status = "withdrawn"
	if err := s.leaveRepo.UpdateLeaveRequest(ctx, req); err != nil {
		s.logger.Error("Failed to update leave request status",
			util.String("request_id", requestID.String()),
			util.ErrorField(err))
		return fmt.Errorf("failed to update leave request: %w", err)
	}

	// Refund leave balance
	txn := &leave.LeaveTransaction{
		TransactionID:  uuid.New(),
		CompanyID:      req.CompanyID,
		UserID:         req.UserID,
		LeaveTypeID:    req.LeaveTypeID,
		LeaveRequestID: &requestID,
		ChangeAmount:   req.Duration,
		Reason:         "withdrawal",
		CreatedAt:      time.Now().UTC(),
	}

	if err := s.leaveRepo.CreateLeaveTransaction(ctx, txn); err != nil {
		s.logger.Warn("Failed to create withdrawal transaction",
			util.String("request_id", requestID.String()),
			util.ErrorField(err))
	}

	s.logger.Info("Leave request withdrawn",
		util.String("request_id", requestID.String()),
		util.String("user_id", userID.String()),
		util.String("reason", reason),
		util.Duration("duration", time.Since(startTime)))

	return nil
}

// CreateLeaveTypesBatch creates multiple leave types in batch
func (s *leaveServiceImpl) CreateLeaveTypesBatch(
	ctx context.Context,
	leaveTypes []*leave.LeaveType,
	actorType string,
	actorID uuid.UUID,
) error {
	startTime := time.Now()

	if len(leaveTypes) == 0 {
		return fmt.Errorf("no leave types provided")
	}

	// Validate each leave type
	for i, lt := range leaveTypes {
		if err := s.validateLeaveType(lt); err != nil {
			return fmt.Errorf("leave type %d validation failed: %w", i, err)
		}
		if lt.LeaveTypeID == uuid.Nil {
			lt.LeaveTypeID = uuid.New()
		}
		if lt.CreatedAt.IsZero() {
			lt.CreatedAt = time.Now().UTC()
		}
	}

	// Create batch
	err := s.leaveRepo.CreateLeaveTypesBatch(ctx, leaveTypes)
	if err != nil {
		s.logger.Error("Failed to create batch leave types",
			util.Int("leave_type_count", len(leaveTypes)),
			util.ErrorField(err))
		return fmt.Errorf("failed to create batch leave types: %w", err)
	}

	s.logger.Info("Batch leave types created",
		util.Int("leave_type_count", len(leaveTypes)),
		util.String("actor_type", actorType),
		util.String("actor_id", actorID.String()),
		util.Duration("duration", time.Since(startTime)))

	return nil
}

// CreateLeavePoliciesBatch creates multiple leave policies in batch
func (s *leaveServiceImpl) CreateLeavePoliciesBatch(
	ctx context.Context,
	policies []*leave.LeavePolicy,
	actorType string,
	actorID uuid.UUID,
) error {
	startTime := time.Now()

	if len(policies) == 0 {
		return fmt.Errorf("no leave policies provided")
	}

	// Validate each policy
	for i, policy := range policies {
		if err := s.validateLeavePolicy(policy); err != nil {
			return fmt.Errorf("leave policy %d validation failed: %w", i, err)
		}
		if policy.LeavePolicyID == uuid.Nil {
			policy.LeavePolicyID = uuid.New()
		}
		if policy.CreatedAt.IsZero() {
			policy.CreatedAt = time.Now().UTC()
		}
	}

	// Create batch
	err := s.leaveRepo.CreateLeavePoliciesBatch(ctx, policies)
	if err != nil {
		s.logger.Error("Failed to create batch leave policies",
			util.Int("policy_count", len(policies)),
			util.ErrorField(err))
		return fmt.Errorf("failed to create batch leave policies: %w", err)
	}

	s.logger.Info("Batch leave policies created",
		util.Int("policy_count", len(policies)),
		util.String("actor_type", actorType),
		util.String("actor_id", actorID.String()),
		util.Duration("duration", time.Since(startTime)))

	return nil
}

// AssignLeavePoliciesBatch assigns multiple leave policies to users in batch
func (s *leaveServiceImpl) AssignLeavePoliciesBatch(
	ctx context.Context,
	userPolicies []*leave.UserLeavePolicy,
	actorType string,
	actorID uuid.UUID,
) error {
	startTime := time.Now()

	if len(userPolicies) == 0 {
		return fmt.Errorf("no user policies provided")
	}

	// Validate each user policy
	for i, policy := range userPolicies {
		if policy.UserID == uuid.Nil {
			return fmt.Errorf("user policy %d: user ID is required", i)
		}
		if policy.LeavePolicyID == uuid.Nil {
			return fmt.Errorf("user policy %d: policy ID is required", i)
		}
		if policy.EffectiveFrom.IsZero() {
			policy.EffectiveFrom = time.Now().UTC()
		}
		if policy.CreatedAt.IsZero() {
			policy.CreatedAt = time.Now().UTC()
		}
		if policy.AssignedBy == nil {
			policy.AssignedBy = &actorID
		}
	}

	// Create batch
	err := s.leaveRepo.AssignLeavePoliciesBatch(ctx, userPolicies)
	if err != nil {
		s.logger.Error("Failed to assign batch leave policies",
			util.Int("user_policy_count", len(userPolicies)),
			util.ErrorField(err))
		return fmt.Errorf("failed to assign batch leave policies: %w", err)
	}

	s.logger.Info("Batch leave policies assigned",
		util.Int("user_policy_count", len(userPolicies)),
		util.String("actor_type", actorType),
		util.String("actor_id", actorID.String()),
		util.Duration("duration", time.Since(startTime)))

	return nil
}

// CreateLeaveRequestsBatch creates multiple leave requests in batch
func (s *leaveServiceImpl) CreateLeaveRequestsBatch(
	ctx context.Context,
	requests []*leave.LeaveRequest,
	actorType string,
	actorID uuid.UUID,
) error {
	startTime := time.Now()

	if len(requests) == 0 {
		return fmt.Errorf("no leave requests provided")
	}

	// Validate each request
	for i, req := range requests {
		if err := s.validateLeaveRequest(req); err != nil {
			return fmt.Errorf("leave request %d validation failed: %w", i, err)
		}
		if req.LeaveRequestID == uuid.Nil {
			req.LeaveRequestID = uuid.New()
		}
		if req.RequestedAt.IsZero() {
			req.RequestedAt = time.Now().UTC()
		}
		if req.Status == "" {
			req.Status = "pending"
		}
	}

	// Create batch
	err := s.leaveRepo.CreateLeaveRequestsBatch(ctx, requests)
	if err != nil {
		s.logger.Error("Failed to create batch leave requests",
			util.Int("request_count", len(requests)),
			util.ErrorField(err))
		return fmt.Errorf("failed to create batch leave requests: %w", err)
	}

	// Create transactions for each request
	for _, req := range requests {
		txn := &leave.LeaveTransaction{
			TransactionID:  uuid.New(),
			CompanyID:      req.CompanyID,
			UserID:         req.UserID,
			LeaveTypeID:    req.LeaveTypeID,
			LeaveRequestID: &req.LeaveRequestID,
			ChangeAmount:   -req.Duration,
			Reason:         "request",
			CreatedAt:      time.Now().UTC(),
		}
		if err := s.leaveRepo.CreateLeaveTransaction(ctx, txn); err != nil {
			s.logger.Warn("Failed to create transaction for batch request",
				util.String("request_id", req.LeaveRequestID.String()),
				util.ErrorField(err))
		}
	}

	s.logger.Info("Batch leave requests created",
		util.Int("request_count", len(requests)),
		util.String("actor_type", actorType),
		util.String("actor_id", actorID.String()),
		util.Duration("duration", time.Since(startTime)))

	return nil
}

// HealthCheck performs health check
func (s *leaveServiceImpl) HealthCheck(ctx context.Context) error {
	if err := s.leaveRepo.HealthCheck(ctx); err != nil {
		return fmt.Errorf("leave repository health check failed: %w", err)
	}
	return nil
}

// validateLeaveType validates a leave type
func (s *leaveServiceImpl) validateLeaveType(leaveType *leave.LeaveType) error {
	if leaveType.CompanyID == uuid.Nil {
		return fmt.Errorf("company ID is required")
	}
	if leaveType.LeaveCode == "" {
		return fmt.Errorf("leave code is required")
	}
	if len(leaveType.LeaveCode) > 30 {
		return fmt.Errorf("leave code cannot exceed 30 characters")
	}
	if leaveType.Name == "" {
		return fmt.Errorf("name is required")
	}
	if leaveType.Category == "" {
		return fmt.Errorf("category is required")
	}
	validCategories := map[string]bool{
		"annual":       true,
		"sick":         true,
		"casual":       true,
		"maternity":    true,
		"paternity":    true,
		"compensatory": true,
		"unpaid":       true,
	}
	if !validCategories[strings.ToLower(leaveType.Category)] {
		return fmt.Errorf("invalid category: %s", leaveType.Category)
	}
	return nil
}

// validateLeavePolicy validates a leave policy
func (s *leaveServiceImpl) validateLeavePolicy(policy *leave.LeavePolicy) error {
	if policy.CompanyID == uuid.Nil {
		return fmt.Errorf("company ID is required")
	}
	if policy.PolicyCode == "" {
		return fmt.Errorf("policy code is required")
	}
	if len(policy.PolicyCode) > 50 {
		return fmt.Errorf("policy code cannot exceed 50 characters")
	}
	if policy.CountryCode == "" {
		return fmt.Errorf("country code is required")
	}
	if len(policy.CountryCode) > 10 {
		return fmt.Errorf("country code cannot exceed 10 characters")
	}
	// Validate policy rules
	if policy.Rules.LeaveType == "" {
		return fmt.Errorf("leave type is required in rules")
	}
	if policy.Rules.MaxPerYear <= 0 {
		return fmt.Errorf("max per year must be positive")
	}
	if policy.Rules.AccrualRate <= 0 {
		return fmt.Errorf("accrual rate must be positive")
	}
	validAccrualTypes := map[string]bool{
		"monthly":   true,
		"quarterly": true,
		"yearly":    true,
		"none":      true,
	}
	if !validAccrualTypes[policy.Rules.Accrual] {
		return fmt.Errorf("invalid accrual type: %s", policy.Rules.Accrual)
	}
	return nil
}

// validateLeaveRequest validates a leave request
func (s *leaveServiceImpl) validateLeaveRequest(req *leave.LeaveRequest) error {
	if req.CompanyID == uuid.Nil {
		return fmt.Errorf("company ID is required")
	}
	if req.UserID == uuid.Nil {
		return fmt.Errorf("user ID is required")
	}
	if req.LeaveTypeID == uuid.Nil {
		return fmt.Errorf("leave type ID is required")
	}
	if req.StartDate.IsZero() {
		return fmt.Errorf("start date is required")
	}
	if req.EndDate.IsZero() {
		return fmt.Errorf("end date is required")
	}
	if req.StartDate.After(req.EndDate) {
		return fmt.Errorf("start date cannot be after end date")
	}
	if req.Duration <= 0 {
		return fmt.Errorf("duration must be positive")
	}
	validStatuses := map[string]bool{
		"pending":   true,
		"approved":  true,
		"rejected":  true,
		"cancelled": true,
		"withdrawn": true,
	}
	if req.Status != "" && !validStatuses[req.Status] {
		return fmt.Errorf("invalid status: %s", req.Status)
	}
	return nil
}

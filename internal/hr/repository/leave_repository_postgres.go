package repository

import (
	"auth-service/internal/client"
	"auth-service/internal/hr/models/leave"
	"auth-service/internal/util"
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"strings"
	"sync"
	"time"

	"github.com/google/uuid"
	"go.uber.org/zap"
)

// LeaveRepositoryImpl handles PostgreSQL leave operations
type LeaveRepositoryImpl struct {
	client    *client.PostgresClient
	logger    *zap.Logger
	stmtCache map[string]*sql.Stmt
	stmtMutex sync.RWMutex
}

// NewLeaveRepository creates a new PostgreSQL leave repository
func NewLeaveRepository(postgresClient *client.PostgresClient, logger *zap.Logger) LeaveRepository {
	repo := &LeaveRepositoryImpl{
		client:    postgresClient,
		logger:    logger,
		stmtCache: make(map[string]*sql.Stmt),
	}

	go repo.initializePreparedStatements(context.Background())
	return repo
}

// ============================================================================
// LEAVE TYPE METHODS
// ============================================================================

func (r *LeaveRepositoryImpl) CreateLeaveType(ctx context.Context, leaveType *leave.LeaveType) error {
	startTime := time.Now()

	query := `
		INSERT INTO leave_types (
			leave_type_id, company_id, leave_code, name, category, 
			is_statutory, affects_pay, requires_approval, requires_document,
			allow_half_day, allow_hourly, is_active, created_at
		) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13)`

	_, err := r.client.Exec(ctx, query,
		leaveType.LeaveTypeID,
		leaveType.CompanyID,
		leaveType.LeaveCode,
		leaveType.Name,
		leaveType.Category,
		leaveType.IsStatutory,
		leaveType.AffectsPay,
		leaveType.RequiresApproval,
		leaveType.RequiresDocument,
		leaveType.AllowHalfDay,
		leaveType.AllowHourly,
		leaveType.IsActive,
		leaveType.CreatedAt,
	)

	if err != nil {
		r.logger.Error("Failed to create leave type",
			util.String("company_id", leaveType.CompanyID.String()),
			util.String("leave_code", leaveType.LeaveCode),
			util.ErrorField(err))
		return fmt.Errorf("failed to create leave type: %w", err)
	}

	r.logger.Debug("Leave type created",
		util.String("leave_type_id", leaveType.LeaveTypeID.String()),
		util.String("leave_code", leaveType.LeaveCode),
		util.Duration("duration", time.Since(startTime)))

	return nil
}

func (r *LeaveRepositoryImpl) GetLeaveTypeByID(ctx context.Context, leaveTypeID uuid.UUID) (*leave.LeaveType, error) {
	stmt, ok := r.getStmt("get_leave_type_by_id")
	if !ok {
		return nil, fmt.Errorf("prepared statement not found: get_leave_type_by_id")
	}

	rows, err := stmt.QueryContext(ctx, leaveTypeID)
	if err != nil {
		return nil, fmt.Errorf("failed to get leave type by ID: %w", err)
	}
	defer rows.Close()

	if rows.Next() {
		return r.scanLeaveType(rows)
	}

	return nil, fmt.Errorf("leave type not found: %s", leaveTypeID)
}

func (r *LeaveRepositoryImpl) GetLeaveTypeByCode(ctx context.Context, companyID uuid.UUID, leaveCode string) (*leave.LeaveType, error) {
	stmt, ok := r.getStmt("get_leave_type_by_code")
	if !ok {
		return nil, fmt.Errorf("prepared statement not found: get_leave_type_by_code")
	}

	rows, err := stmt.QueryContext(ctx, companyID, leaveCode)
	if err != nil {
		return nil, fmt.Errorf("failed to get leave type by code: %w", err)
	}
	defer rows.Close()

	if rows.Next() {
		return r.scanLeaveType(rows)
	}

	return nil, fmt.Errorf("leave type not found for company %s with code %s", companyID, leaveCode)
}

func (r *LeaveRepositoryImpl) UpdateLeaveType(ctx context.Context, leaveType *leave.LeaveType) error {
	_ = time.Now().UTC()

	query := `
		UPDATE leave_types SET
			name = $1, category = $2, is_statutory = $3, affects_pay = $4,
			requires_approval = $5, requires_document = $6, allow_half_day = $7,
			allow_hourly = $8, is_active = $9
		WHERE leave_type_id = $10`

	result, err := r.client.Exec(ctx, query,
		leaveType.Name,
		leaveType.Category,
		leaveType.IsStatutory,
		leaveType.AffectsPay,
		leaveType.RequiresApproval,
		leaveType.RequiresDocument,
		leaveType.AllowHalfDay,
		leaveType.AllowHourly,
		leaveType.IsActive,
		leaveType.LeaveTypeID,
	)

	if err != nil {
		return fmt.Errorf("failed to update leave type: %w", err)
	}

	rowsAffected, _ := result.RowsAffected()
	if rowsAffected == 0 {
		return fmt.Errorf("leave type not found: %s", leaveType.LeaveTypeID)
	}

	r.logger.Debug("Leave type updated",
		util.String("leave_type_id", leaveType.LeaveTypeID.String()),
		util.String("name", leaveType.Name))

	return nil
}

func (r *LeaveRepositoryImpl) DeleteLeaveType(ctx context.Context, leaveTypeID uuid.UUID) error {
	query := `DELETE FROM leave_types WHERE leave_type_id = $1`
	result, err := r.client.Exec(ctx, query, leaveTypeID)
	if err != nil {
		return fmt.Errorf("failed to delete leave type: %w", err)
	}

	rowsAffected, _ := result.RowsAffected()
	if rowsAffected == 0 {
		return fmt.Errorf("leave type not found: %s", leaveTypeID)
	}

	r.logger.Debug("Leave type deleted",
		util.String("leave_type_id", leaveTypeID.String()))

	return nil
}

func (r *LeaveRepositoryImpl) ListLeaveTypesByCompany(ctx context.Context, companyID uuid.UUID, includeInactive bool) ([]*leave.LeaveType, error) {
	var query string
	var args []interface{}

	if includeInactive {
		query = `
			SELECT leave_type_id, company_id, leave_code, name, category, 
			       is_statutory, affects_pay, requires_approval, requires_document,
			       allow_half_day, allow_hourly, is_active, created_at
			FROM leave_types 
			WHERE company_id = $1
			ORDER BY created_at DESC`
		args = []interface{}{companyID}
	} else {
		query = `
			SELECT leave_type_id, company_id, leave_code, name, category, 
			       is_statutory, affects_pay, requires_approval, requires_document,
			       allow_half_day, allow_hourly, is_active, created_at
			FROM leave_types 
			WHERE company_id = $1 AND is_active = true
			ORDER BY created_at DESC`
		args = []interface{}{companyID}
	}

	rows, err := r.client.Query(ctx, query, args...)
	if err != nil {
		return nil, fmt.Errorf("failed to list leave types: %w", err)
	}
	defer rows.Close()

	leaveTypes := make([]*leave.LeaveType, 0)
	for rows.Next() {
		lt, err := r.scanLeaveType(rows)
		if err != nil {
			r.logger.Warn("Failed to scan leave type", util.ErrorField(err))
			continue
		}
		leaveTypes = append(leaveTypes, lt)
	}

	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("error iterating leave types: %w", err)
	}

	return leaveTypes, nil
}

func (r *LeaveRepositoryImpl) SearchLeaveTypes(ctx context.Context, companyID uuid.UUID, filters map[string]interface{}, limit, offset int) ([]*leave.LeaveType, int, error) {
	if limit <= 0 || limit > 1000 {
		limit = 100
	}
	if offset < 0 {
		offset = 0
	}

	// Build WHERE clause
	conditions := []string{"company_id = $1"}
	params := []interface{}{companyID}
	paramCounter := 2

	for field, value := range filters {
		switch field {
		case "category":
			conditions = append(conditions, fmt.Sprintf("category = $%d", paramCounter))
			params = append(params, value)
			paramCounter++
		case "is_statutory":
			conditions = append(conditions, fmt.Sprintf("is_statutory = $%d", paramCounter))
			params = append(params, value)
			paramCounter++
		case "is_active":
			conditions = append(conditions, fmt.Sprintf("is_active = $%d", paramCounter))
			params = append(params, value)
			paramCounter++
		case "name":
			conditions = append(conditions, fmt.Sprintf("name ILIKE $%d", paramCounter))
			params = append(params, "%"+value.(string)+"%")
			paramCounter++
		case "leave_code":
			conditions = append(conditions, fmt.Sprintf("leave_code ILIKE $%d", paramCounter))
			params = append(params, "%"+value.(string)+"%")
			paramCounter++
		}
	}

	whereClause := ""
	if len(conditions) > 0 {
		whereClause = "WHERE " + strings.Join(conditions, " AND ")
	}

	// Count query
	countQuery := fmt.Sprintf("SELECT COUNT(*) FROM leave_types %s", whereClause)
	var totalCount int
	err := r.client.QueryRow(ctx, countQuery, params...).Scan(&totalCount)
	if err != nil {
		return nil, 0, fmt.Errorf("failed to count leave types: %w", err)
	}

	// Search query
	searchQuery := fmt.Sprintf(`
		SELECT leave_type_id, company_id, leave_code, name, category, 
		       is_statutory, affects_pay, requires_approval, requires_document,
		       allow_half_day, allow_hourly, is_active, created_at
		FROM leave_types %s
		ORDER BY created_at DESC
		LIMIT $%d OFFSET $%d`, whereClause, paramCounter, paramCounter+1)

	params = append(params, limit, offset)

	rows, err := r.client.Query(ctx, searchQuery, params...)
	if err != nil {
		return nil, 0, fmt.Errorf("failed to search leave types: %w", err)
	}
	defer rows.Close()

	leaveTypes := make([]*leave.LeaveType, 0, limit)
	for rows.Next() {
		lt, err := r.scanLeaveType(rows)
		if err != nil {
			r.logger.Warn("Failed to scan leave type", util.ErrorField(err))
			continue
		}
		leaveTypes = append(leaveTypes, lt)
	}

	if err := rows.Err(); err != nil {
		return nil, 0, fmt.Errorf("error iterating search results: %w", err)
	}

	return leaveTypes, totalCount, nil
}

// ============================================================================
// LEAVE POLICY METHODS
// ============================================================================

func (r *LeaveRepositoryImpl) CreateLeavePolicy(ctx context.Context, policy *leave.LeavePolicy) error {
	// Convert rules to JSON
	rulesJSON, err := json.Marshal(policy.Rules)
	if err != nil {
		return fmt.Errorf("failed to marshal policy rules: %w", err)
	}

	query := `
		INSERT INTO leave_policies (
			leave_policy_id, company_id, department_id, country_code, 
			policy_code, rules, is_active, created_at
		) VALUES ($1, $2, $3, $4, $5, $6, $7, $8)`

	_, err = r.client.Exec(ctx, query,
		policy.LeavePolicyID,
		policy.CompanyID,
		policy.DepartmentID,
		policy.CountryCode,
		policy.PolicyCode,
		rulesJSON,
		policy.IsActive,
		policy.CreatedAt,
	)

	if err != nil {
		r.logger.Error("Failed to create leave policy",
			util.String("company_id", policy.CompanyID.String()),
			util.String("policy_code", policy.PolicyCode),
			util.ErrorField(err))
		return fmt.Errorf("failed to create leave policy: %w", err)
	}

	r.logger.Debug("Leave policy created",
		util.String("policy_id", policy.LeavePolicyID.String()),
		util.String("policy_code", policy.PolicyCode))

	return nil
}

func (r *LeaveRepositoryImpl) GetLeavePolicyByID(ctx context.Context, policyID uuid.UUID) (*leave.LeavePolicy, error) {
	query := `
		SELECT leave_policy_id, company_id, department_id, country_code, 
		       policy_code, rules, is_active, created_at
		FROM leave_policies 
		WHERE leave_policy_id = $1`

	rows, err := r.client.Query(ctx, query, policyID)
	if err != nil {
		return nil, fmt.Errorf("failed to get leave policy by ID: %w", err)
	}
	defer rows.Close()

	if rows.Next() {
		return r.scanLeavePolicy(rows)
	}

	return nil, fmt.Errorf("leave policy not found: %s", policyID)
}

func (r *LeaveRepositoryImpl) GetLeavePolicyByCode(ctx context.Context, companyID uuid.UUID, policyCode string) (*leave.LeavePolicy, error) {
	stmt, ok := r.getStmt("get_leave_policy_by_code")
	if !ok {
		return nil, fmt.Errorf("prepared statement not found: get_leave_policy_by_code")
	}

	rows, err := stmt.QueryContext(ctx, companyID, policyCode)
	if err != nil {
		return nil, fmt.Errorf("failed to get leave policy by code: %w", err)
	}
	defer rows.Close()

	if rows.Next() {
		return r.scanLeavePolicy(rows)
	}

	return nil, fmt.Errorf("leave policy not found for company %s with code %s", companyID, policyCode)
}

func (r *LeaveRepositoryImpl) UpdateLeavePolicy(ctx context.Context, policy *leave.LeavePolicy) error {
	// Convert rules to JSON
	rulesJSON, err := json.Marshal(policy.Rules)
	if err != nil {
		return fmt.Errorf("failed to marshal policy rules: %w", err)
	}

	query := `
		UPDATE leave_policies SET
			department_id = $1, country_code = $2, policy_code = $3, 
			rules = $4, is_active = $5
		WHERE leave_policy_id = $6`

	result, err := r.client.Exec(ctx, query,
		policy.DepartmentID,
		policy.CountryCode,
		policy.PolicyCode,
		rulesJSON,
		policy.IsActive,
		policy.LeavePolicyID,
	)

	if err != nil {
		return fmt.Errorf("failed to update leave policy: %w", err)
	}

	rowsAffected, _ := result.RowsAffected()
	if rowsAffected == 0 {
		return fmt.Errorf("leave policy not found: %s", policy.LeavePolicyID)
	}

	return nil
}

func (r *LeaveRepositoryImpl) DeleteLeavePolicy(ctx context.Context, policyID uuid.UUID) error {
	query := `DELETE FROM leave_policies WHERE leave_policy_id = $1`
	result, err := r.client.Exec(ctx, query, policyID)
	if err != nil {
		return fmt.Errorf("failed to delete leave policy: %w", err)
	}

	rowsAffected, _ := result.RowsAffected()
	if rowsAffected == 0 {
		return fmt.Errorf("leave policy not found: %s", policyID)
	}

	return nil
}

func (r *LeaveRepositoryImpl) ListLeavePoliciesByCompany(ctx context.Context, companyID uuid.UUID, includeInactive bool) ([]*leave.LeavePolicy, error) {
	var query string
	var args []interface{}

	if includeInactive {
		query = `
			SELECT leave_policy_id, company_id, department_id, country_code, 
			       policy_code, rules, is_active, created_at
			FROM leave_policies 
			WHERE company_id = $1
			ORDER BY created_at DESC`
		args = []interface{}{companyID}
	} else {
		query = `
			SELECT leave_policy_id, company_id, department_id, country_code, 
			       policy_code, rules, is_active, created_at
			FROM leave_policies 
			WHERE company_id = $1 AND is_active = true
			ORDER BY created_at DESC`
		args = []interface{}{companyID}
	}

	rows, err := r.client.Query(ctx, query, args...)
	if err != nil {
		return nil, fmt.Errorf("failed to list leave policies: %w", err)
	}
	defer rows.Close()

	policies := make([]*leave.LeavePolicy, 0)
	for rows.Next() {
		policy, err := r.scanLeavePolicy(rows)
		if err != nil {
			r.logger.Warn("Failed to scan leave policy", util.ErrorField(err))
			continue
		}
		policies = append(policies, policy)
	}

	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("error iterating leave policies: %w", err)
	}

	return policies, nil
}

func (r *LeaveRepositoryImpl) ListLeavePoliciesByDepartment(ctx context.Context, companyID, departmentID uuid.UUID) ([]*leave.LeavePolicy, error) {
	query := `
		SELECT leave_policy_id, company_id, department_id, country_code, 
		       policy_code, rules, is_active, created_at
		FROM leave_policies 
		WHERE company_id = $1 AND (department_id = $2 OR department_id IS NULL)
		ORDER BY 
			CASE WHEN department_id IS NULL THEN 1 ELSE 0 END,
			created_at DESC`

	rows, err := r.client.Query(ctx, query, companyID, departmentID)
	if err != nil {
		return nil, fmt.Errorf("failed to list leave policies by department: %w", err)
	}
	defer rows.Close()

	policies := make([]*leave.LeavePolicy, 0)
	for rows.Next() {
		policy, err := r.scanLeavePolicy(rows)
		if err != nil {
			r.logger.Warn("Failed to scan leave policy", util.ErrorField(err))
			continue
		}
		policies = append(policies, policy)
	}

	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("error iterating leave policies: %w", err)
	}

	return policies, nil
}

func (r *LeaveRepositoryImpl) SearchLeavePolicies(ctx context.Context, companyID uuid.UUID, filters map[string]interface{}, limit, offset int) ([]*leave.LeavePolicy, int, error) {
	if limit <= 0 || limit > 1000 {
		limit = 100
	}
	if offset < 0 {
		offset = 0
	}

	// Build WHERE clause
	conditions := []string{"company_id = $1"}
	params := []interface{}{companyID}
	paramCounter := 2

	for field, value := range filters {
		switch field {
		case "department_id":
			if value == nil {
				conditions = append(conditions, "department_id IS NULL")
			} else {
				conditions = append(conditions, fmt.Sprintf("department_id = $%d", paramCounter))
				params = append(params, value)
				paramCounter++
			}
		case "country_code":
			conditions = append(conditions, fmt.Sprintf("country_code = $%d", paramCounter))
			params = append(params, value)
			paramCounter++
		case "is_active":
			conditions = append(conditions, fmt.Sprintf("is_active = $%d", paramCounter))
			params = append(params, value)
			paramCounter++
		case "policy_code":
			conditions = append(conditions, fmt.Sprintf("policy_code ILIKE $%d", paramCounter))
			params = append(params, "%"+value.(string)+"%")
			paramCounter++
		}
	}

	whereClause := ""
	if len(conditions) > 0 {
		whereClause = "WHERE " + strings.Join(conditions, " AND ")
	}

	// Count query
	countQuery := fmt.Sprintf("SELECT COUNT(*) FROM leave_policies %s", whereClause)
	var totalCount int
	err := r.client.QueryRow(ctx, countQuery, params...).Scan(&totalCount)
	if err != nil {
		return nil, 0, fmt.Errorf("failed to count leave policies: %w", err)
	}

	// Search query
	searchQuery := fmt.Sprintf(`
		SELECT leave_policy_id, company_id, department_id, country_code, 
		       policy_code, rules, is_active, created_at
		FROM leave_policies %s
		ORDER BY created_at DESC
		LIMIT $%d OFFSET $%d`, whereClause, paramCounter, paramCounter+1)

	params = append(params, limit, offset)

	rows, err := r.client.Query(ctx, searchQuery, params...)
	if err != nil {
		return nil, 0, fmt.Errorf("failed to search leave policies: %w", err)
	}
	defer rows.Close()

	policies := make([]*leave.LeavePolicy, 0, limit)
	for rows.Next() {
		policy, err := r.scanLeavePolicy(rows)
		if err != nil {
			r.logger.Warn("Failed to scan leave policy", util.ErrorField(err))
			continue
		}
		policies = append(policies, policy)
	}

	if err := rows.Err(); err != nil {
		return nil, 0, fmt.Errorf("error iterating search results: %w", err)
	}

	return policies, totalCount, nil
}

// ============================================================================
// USER LEAVE POLICY METHODS
// ============================================================================

func (r *LeaveRepositoryImpl) AssignUserLeavePolicy(ctx context.Context, userPolicy *leave.UserLeavePolicy) error {
	query := `
		INSERT INTO user_leave_policies (
			user_id, leave_policy_id, effective_from, effective_to, 
			assigned_by, created_at
		) VALUES ($1, $2, $3, $4, $5, $6)
		ON CONFLICT (user_id, leave_policy_id, effective_from) 
		DO UPDATE SET
			effective_to = EXCLUDED.effective_to,
			assigned_by = EXCLUDED.assigned_by`

	_, err := r.client.Exec(ctx, query,
		userPolicy.UserID,
		userPolicy.LeavePolicyID,
		userPolicy.EffectiveFrom,
		userPolicy.EffectiveTo,
		userPolicy.AssignedBy,
		userPolicy.CreatedAt,
	)

	if err != nil {
		r.logger.Error("Failed to assign user leave policy",
			util.String("user_id", userPolicy.UserID.String()),
			util.String("policy_id", userPolicy.LeavePolicyID.String()),
			util.ErrorField(err))
		return fmt.Errorf("failed to assign user leave policy: %w", err)
	}

	r.logger.Debug("User leave policy assigned",
		util.String("user_id", userPolicy.UserID.String()),
		util.String("policy_id", userPolicy.LeavePolicyID.String()))

	return nil
}

func (r *LeaveRepositoryImpl) GetUserLeavePolicy(ctx context.Context, userID, policyID uuid.UUID, effectiveFrom time.Time) (*leave.UserLeavePolicy, error) {
	query := `
		SELECT user_id, leave_policy_id, effective_from, effective_to, 
		       assigned_by, created_at
		FROM user_leave_policies 
		WHERE user_id = $1 AND leave_policy_id = $2 AND effective_from = $3`

	rows, err := r.client.Query(ctx, query, userID, policyID, effectiveFrom)
	if err != nil {
		return nil, fmt.Errorf("failed to get user leave policy: %w", err)
	}
	defer rows.Close()

	if rows.Next() {
		return r.scanUserLeavePolicy(rows)
	}

	return nil, fmt.Errorf("user leave policy not found")
}

func (r *LeaveRepositoryImpl) GetActiveUserLeavePolicies(ctx context.Context, userID uuid.UUID, asOf time.Time) ([]*leave.UserLeavePolicy, error) {
	query := `
		SELECT user_id, leave_policy_id, effective_from, effective_to, 
		       assigned_by, created_at
		FROM user_leave_policies 
		WHERE user_id = $1 
		  AND effective_from <= $2 
		  AND (effective_to IS NULL OR effective_to >= $2)
		ORDER BY effective_from DESC`

	rows, err := r.client.Query(ctx, query, userID, asOf)
	if err != nil {
		return nil, fmt.Errorf("failed to get active user leave policies: %w", err)
	}
	defer rows.Close()

	policies := make([]*leave.UserLeavePolicy, 0)
	for rows.Next() {
		policy, err := r.scanUserLeavePolicy(rows)
		if err != nil {
			r.logger.Warn("Failed to scan user leave policy", util.ErrorField(err))
			continue
		}
		policies = append(policies, policy)
	}

	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("error iterating user leave policies: %w", err)
	}

	return policies, nil
}

func (r *LeaveRepositoryImpl) UpdateUserLeavePolicy(ctx context.Context, userPolicy *leave.UserLeavePolicy) error {
	query := `
		UPDATE user_leave_policies SET
			effective_to = $1, assigned_by = $2
		WHERE user_id = $3 AND leave_policy_id = $4 AND effective_from = $5`

	result, err := r.client.Exec(ctx, query,
		userPolicy.EffectiveTo,
		userPolicy.AssignedBy,
		userPolicy.UserID,
		userPolicy.LeavePolicyID,
		userPolicy.EffectiveFrom,
	)

	if err != nil {
		return fmt.Errorf("failed to update user leave policy: %w", err)
	}

	rowsAffected, _ := result.RowsAffected()
	if rowsAffected == 0 {
		return fmt.Errorf("user leave policy not found")
	}

	return nil
}

func (r *LeaveRepositoryImpl) RemoveUserLeavePolicy(ctx context.Context, userID, policyID uuid.UUID, effectiveFrom time.Time) error {
	query := `DELETE FROM user_leave_policies WHERE user_id = $1 AND leave_policy_id = $2 AND effective_from = $3`
	result, err := r.client.Exec(ctx, query, userID, policyID, effectiveFrom)
	if err != nil {
		return fmt.Errorf("failed to remove user leave policy: %w", err)
	}

	rowsAffected, _ := result.RowsAffected()
	if rowsAffected == 0 {
		return fmt.Errorf("user leave policy not found")
	}

	return nil
}

func (r *LeaveRepositoryImpl) ListUserLeavePoliciesByUser(ctx context.Context, userID uuid.UUID) ([]*leave.UserLeavePolicy, error) {
	query := `
		SELECT user_id, leave_policy_id, effective_from, effective_to, 
		       assigned_by, created_at
		FROM user_leave_policies 
		WHERE user_id = $1
		ORDER BY effective_from DESC`

	rows, err := r.client.Query(ctx, query, userID)
	if err != nil {
		return nil, fmt.Errorf("failed to list user leave policies: %w", err)
	}
	defer rows.Close()

	policies := make([]*leave.UserLeavePolicy, 0)
	for rows.Next() {
		policy, err := r.scanUserLeavePolicy(rows)
		if err != nil {
			r.logger.Warn("Failed to scan user leave policy", util.ErrorField(err))
			continue
		}
		policies = append(policies, policy)
	}

	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("error iterating user leave policies: %w", err)
	}

	return policies, nil
}

func (r *LeaveRepositoryImpl) ListUsersByLeavePolicy(ctx context.Context, policyID uuid.UUID, effectiveDate time.Time) ([]uuid.UUID, error) {
	query := `
		SELECT DISTINCT user_id
		FROM user_leave_policies 
		WHERE leave_policy_id = $1 
		  AND effective_from <= $2 
		  AND (effective_to IS NULL OR effective_to >= $2)`

	rows, err := r.client.Query(ctx, query, policyID, effectiveDate)
	if err != nil {
		return nil, fmt.Errorf("failed to list users by leave policy: %w", err)
	}
	defer rows.Close()

	userIDs := make([]uuid.UUID, 0)
	for rows.Next() {
		var userID uuid.UUID
		if err := rows.Scan(&userID); err != nil {
			r.logger.Warn("Failed to scan user ID", util.ErrorField(err))
			continue
		}
		userIDs = append(userIDs, userID)
	}

	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("error iterating users: %w", err)
	}

	return userIDs, nil
}

// ============================================================================
// LEAVE REQUEST METHODS
// ============================================================================

func (r *LeaveRepositoryImpl) CreateLeaveRequest(ctx context.Context, req *leave.LeaveRequest) error {
	query := `
		INSERT INTO leave_requests (
			leave_request_id, company_id, user_id, leave_type_id, 
			start_date, end_date, duration, reason, status, requested_at
		) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10)`

	_, err := r.client.Exec(ctx, query,
		req.LeaveRequestID,
		req.CompanyID,
		req.UserID,
		req.LeaveTypeID,
		req.StartDate,
		req.EndDate,
		req.Duration,
		req.Reason,
		req.Status,
		req.RequestedAt,
	)

	if err != nil {
		r.logger.Error("Failed to create leave request",
			util.String("user_id", req.UserID.String()),
			util.String("company_id", req.CompanyID.String()),
			util.ErrorField(err))
		return fmt.Errorf("failed to create leave request: %w", err)
	}

	r.logger.Debug("Leave request created",
		util.String("request_id", req.LeaveRequestID.String()),
		util.String("status", req.Status))

	return nil
}

func (r *LeaveRepositoryImpl) GetLeaveRequestByID(ctx context.Context, requestID uuid.UUID) (*leave.LeaveRequest, error) {
	stmt, ok := r.getStmt("get_leave_request_by_id")
	if !ok {
		return nil, fmt.Errorf("prepared statement not found: get_leave_request_by_id")
	}

	rows, err := stmt.QueryContext(ctx, requestID)
	if err != nil {
		return nil, fmt.Errorf("failed to get leave request by ID: %w", err)
	}
	defer rows.Close()

	if rows.Next() {
		return r.scanLeaveRequest(rows)
	}

	return nil, fmt.Errorf("leave request not found: %s", requestID)
}

func (r *LeaveRepositoryImpl) GetLeaveRequestWithApprovals(ctx context.Context, requestID uuid.UUID) (*leave.LeaveRequest, []*leave.LeaveApproval, error) {
	// Get the leave request
	req, err := r.GetLeaveRequestByID(ctx, requestID)
	if err != nil {
		return nil, nil, err
	}

	// Get approvals
	approvals, err := r.GetApprovalsByLeaveRequest(ctx, requestID)
	if err != nil {
		return req, nil, fmt.Errorf("failed to get approvals: %w", err)
	}

	return req, approvals, nil
}

func (r *LeaveRepositoryImpl) UpdateLeaveRequest(ctx context.Context, req *leave.LeaveRequest) error {
	query := `
		UPDATE leave_requests SET
			start_date = $1, end_date = $2, duration = $3, reason = $4, 
			status = $5
		WHERE leave_request_id = $6`

	result, err := r.client.Exec(ctx, query,
		req.StartDate,
		req.EndDate,
		req.Duration,
		req.Reason,
		req.Status,
		req.LeaveRequestID,
	)

	if err != nil {
		return fmt.Errorf("failed to update leave request: %w", err)
	}

	rowsAffected, _ := result.RowsAffected()
	if rowsAffected == 0 {
		return fmt.Errorf("leave request not found: %s", req.LeaveRequestID)
	}

	return nil
}

func (r *LeaveRepositoryImpl) CancelLeaveRequest(ctx context.Context, requestID uuid.UUID, reason string) error {
	query := `
		UPDATE leave_requests 
		SET status = 'cancelled', reason = COALESCE($2, reason)
		WHERE leave_request_id = $1 AND status IN ('pending', 'approved')`

	result, err := r.client.Exec(ctx, query, requestID, reason)
	if err != nil {
		return fmt.Errorf("failed to cancel leave request: %w", err)
	}

	rowsAffected, _ := result.RowsAffected()
	if rowsAffected == 0 {
		return fmt.Errorf("leave request not found or cannot be cancelled: %s", requestID)
	}

	return nil
}

func (r *LeaveRepositoryImpl) DeleteLeaveRequest(ctx context.Context, requestID uuid.UUID) error {
	// First delete approvals
	deleteApprovalsQuery := `DELETE FROM leave_approvals WHERE leave_request_id = $1`
	if _, err := r.client.Exec(ctx, deleteApprovalsQuery, requestID); err != nil {
		return fmt.Errorf("failed to delete leave approvals: %w", err)
	}

	// Then delete the request
	deleteRequestQuery := `DELETE FROM leave_requests WHERE leave_request_id = $1`
	result, err := r.client.Exec(ctx, deleteRequestQuery, requestID)
	if err != nil {
		return fmt.Errorf("failed to delete leave request: %w", err)
	}

	rowsAffected, _ := result.RowsAffected()
	if rowsAffected == 0 {
		return fmt.Errorf("leave request not found: %s", requestID)
	}

	return nil
}

func (r *LeaveRepositoryImpl) ListLeaveRequestsByUser(ctx context.Context, userID uuid.UUID, startDate, endDate time.Time) ([]*leave.LeaveRequest, error) {
	query := `
		SELECT leave_request_id, company_id, user_id, leave_type_id, 
		       start_date, end_date, duration, reason, status, requested_at
		FROM leave_requests 
		WHERE user_id = $1 
		  AND ((start_date BETWEEN $2 AND $3) OR (end_date BETWEEN $2 AND $3))
		ORDER BY requested_at DESC`

	rows, err := r.client.Query(ctx, query, userID, startDate, endDate)
	if err != nil {
		return nil, fmt.Errorf("failed to list leave requests by user: %w", err)
	}
	defer rows.Close()

	requests := make([]*leave.LeaveRequest, 0)
	for rows.Next() {
		req, err := r.scanLeaveRequest(rows)
		if err != nil {
			r.logger.Warn("Failed to scan leave request", util.ErrorField(err))
			continue
		}
		requests = append(requests, req)
	}

	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("error iterating leave requests: %w", err)
	}

	return requests, nil
}

func (r *LeaveRepositoryImpl) ListLeaveRequestsByCompany(ctx context.Context, companyID uuid.UUID, filters map[string]interface{}, limit, offset int) ([]*leave.LeaveRequest, int, error) {
	if limit <= 0 || limit > 1000 {
		limit = 100
	}
	if offset < 0 {
		offset = 0
	}

	// Build WHERE clause
	conditions := []string{"company_id = $1"}
	params := []interface{}{companyID}
	paramCounter := 2

	for field, value := range filters {
		switch field {
		case "user_id":
			conditions = append(conditions, fmt.Sprintf("user_id = $%d", paramCounter))
			params = append(params, value)
			paramCounter++
		case "leave_type_id":
			conditions = append(conditions, fmt.Sprintf("leave_type_id = $%d", paramCounter))
			params = append(params, value)
			paramCounter++
		case "status":
			conditions = append(conditions, fmt.Sprintf("status = $%d", paramCounter))
			params = append(params, value)
			paramCounter++
		case "start_date_from":
			conditions = append(conditions, fmt.Sprintf("start_date >= $%d", paramCounter))
			params = append(params, value)
			paramCounter++
		case "start_date_to":
			conditions = append(conditions, fmt.Sprintf("start_date <= $%d", paramCounter))
			params = append(params, value)
			paramCounter++
		case "department_id":
			// Join with employee department history to filter by department
			conditions = append(conditions, fmt.Sprintf(
				"user_id IN (SELECT user_id FROM employee_department_history WHERE department_id = $%d AND end_date IS NULL)",
				paramCounter))
			params = append(params, value)
			paramCounter++
		}
	}

	whereClause := ""
	if len(conditions) > 0 {
		whereClause = "WHERE " + strings.Join(conditions, " AND ")
	}

	// Count query
	countQuery := fmt.Sprintf("SELECT COUNT(*) FROM leave_requests %s", whereClause)
	var totalCount int
	err := r.client.QueryRow(ctx, countQuery, params...).Scan(&totalCount)
	if err != nil {
		return nil, 0, fmt.Errorf("failed to count leave requests: %w", err)
	}

	// Search query
	searchQuery := fmt.Sprintf(`
		SELECT leave_request_id, company_id, user_id, leave_type_id, 
		       start_date, end_date, duration, reason, status, requested_at
		FROM leave_requests %s
		ORDER BY requested_at DESC
		LIMIT $%d OFFSET $%d`, whereClause, paramCounter, paramCounter+1)

	params = append(params, limit, offset)

	rows, err := r.client.Query(ctx, searchQuery, params...)
	if err != nil {
		return nil, 0, fmt.Errorf("failed to list leave requests: %w", err)
	}
	defer rows.Close()

	requests := make([]*leave.LeaveRequest, 0, limit)
	for rows.Next() {
		req, err := r.scanLeaveRequest(rows)
		if err != nil {
			r.logger.Warn("Failed to scan leave request", util.ErrorField(err))
			continue
		}
		requests = append(requests, req)
	}

	if err := rows.Err(); err != nil {
		return nil, 0, fmt.Errorf("error iterating leave requests: %w", err)
	}

	return requests, totalCount, nil
}

func (r *LeaveRepositoryImpl) ListPendingLeaveRequests(ctx context.Context, companyID uuid.UUID, approverID uuid.UUID) ([]*leave.LeaveRequest, error) {
	// This is a simplified version - in reality, you'd need to check
	// the approval hierarchy based on company policies
	query := `
		SELECT lr.leave_request_id, lr.company_id, lr.user_id, lr.leave_type_id, 
		       lr.start_date, lr.end_date, lr.duration, lr.reason, lr.status, lr.requested_at
		FROM leave_requests lr
		WHERE lr.company_id = $1 
		  AND lr.status = 'pending'
		  AND NOT EXISTS (
			SELECT 1 FROM leave_approvals la 
			WHERE la.leave_request_id = lr.leave_request_id 
			  AND la.approved_by = $2
		  )
		ORDER BY lr.requested_at DESC`

	rows, err := r.client.Query(ctx, query, companyID, approverID)
	if err != nil {
		return nil, fmt.Errorf("failed to list pending leave requests: %w", err)
	}
	defer rows.Close()

	requests := make([]*leave.LeaveRequest, 0)
	for rows.Next() {
		req, err := r.scanLeaveRequest(rows)
		if err != nil {
			r.logger.Warn("Failed to scan leave request", util.ErrorField(err))
			continue
		}
		requests = append(requests, req)
	}

	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("error iterating pending leave requests: %w", err)
	}

	return requests, nil
}

func (r *LeaveRepositoryImpl) CheckLeaveOverlap(ctx context.Context, userID uuid.UUID, startDate, endDate time.Time, excludeRequestID *uuid.UUID) (bool, error) {
	var query string
	var args []interface{}

	if excludeRequestID != nil {
		query = `
			SELECT EXISTS (
				SELECT 1 FROM leave_requests 
				WHERE user_id = $1 
				  AND status IN ('pending', 'approved')
				  AND leave_request_id != $2
				  AND (
					(start_date <= $3 AND end_date >= $3) OR
					(start_date <= $4 AND end_date >= $4) OR
					(start_date >= $3 AND end_date <= $4)
				  )
			)`
		args = []interface{}{userID, excludeRequestID, startDate, endDate}
	} else {
		query = `
			SELECT EXISTS (
				SELECT 1 FROM leave_requests 
				WHERE user_id = $1 
				  AND status IN ('pending', 'approved')
				  AND (
					(start_date <= $2 AND end_date >= $2) OR
					(start_date <= $3 AND end_date >= $3) OR
					(start_date >= $2 AND end_date <= $3)
				  )
			)`
		args = []interface{}{userID, startDate, endDate}
	}

	var exists bool
	err := r.client.QueryRow(ctx, query, args...).Scan(&exists)
	if err != nil {
		return false, fmt.Errorf("failed to check leave overlap: %w", err)
	}

	return exists, nil
}

// ============================================================================
// LEAVE APPROVAL METHODS
// ============================================================================

func (r *LeaveRepositoryImpl) CreateLeaveApproval(ctx context.Context, approval *leave.LeaveApproval) error {
	query := `
		INSERT INTO leave_approvals (
			approval_id, leave_request_id, approved_by, decision, 
			decision_reason, approval_level, decided_at
		) VALUES ($1, $2, $3, $4, $5, $6, $7)`

	_, err := r.client.Exec(ctx, query,
		approval.ApprovalID,
		approval.LeaveRequestID,
		approval.ApprovedBy,
		approval.Decision,
		approval.DecisionReason,
		approval.ApprovalLevel,
		approval.DecidedAt,
	)

	if err != nil {
		r.logger.Error("Failed to create leave approval",
			util.String("request_id", approval.LeaveRequestID.String()),
			util.String("approver_id", approval.ApprovedBy.String()),
			util.ErrorField(err))
		return fmt.Errorf("failed to create leave approval: %w", err)
	}

	return nil
}

func (r *LeaveRepositoryImpl) GetLeaveApprovalByID(ctx context.Context, approvalID uuid.UUID) (*leave.LeaveApproval, error) {
	query := `
		SELECT approval_id, leave_request_id, approved_by, decision, 
		       decision_reason, approval_level, decided_at
		FROM leave_approvals 
		WHERE approval_id = $1`

	rows, err := r.client.Query(ctx, query, approvalID)
	if err != nil {
		return nil, fmt.Errorf("failed to get leave approval: %w", err)
	}
	defer rows.Close()

	if rows.Next() {
		return r.scanLeaveApproval(rows)
	}

	return nil, fmt.Errorf("leave approval not found: %s", approvalID)
}

func (r *LeaveRepositoryImpl) GetApprovalsByLeaveRequest(ctx context.Context, requestID uuid.UUID) ([]*leave.LeaveApproval, error) {
	query := `
		SELECT approval_id, leave_request_id, approved_by, decision, 
		       decision_reason, approval_level, decided_at
		FROM leave_approvals 
		WHERE leave_request_id = $1
		ORDER BY approval_level, decided_at`

	rows, err := r.client.Query(ctx, query, requestID)
	if err != nil {
		return nil, fmt.Errorf("failed to get leave approvals: %w", err)
	}
	defer rows.Close()

	approvals := make([]*leave.LeaveApproval, 0)
	for rows.Next() {
		approval, err := r.scanLeaveApproval(rows)
		if err != nil {
			r.logger.Warn("Failed to scan leave approval", util.ErrorField(err))
			continue
		}
		approvals = append(approvals, approval)
	}

	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("error iterating leave approvals: %w", err)
	}

	return approvals, nil
}

func (r *LeaveRepositoryImpl) UpdateLeaveApproval(ctx context.Context, approval *leave.LeaveApproval) error {
	query := `
		UPDATE leave_approvals SET
			decision = $1, decision_reason = $2, approval_level = $3, decided_at = $4
		WHERE approval_id = $5`

	result, err := r.client.Exec(ctx, query,
		approval.Decision,
		approval.DecisionReason,
		approval.ApprovalLevel,
		approval.DecidedAt,
		approval.ApprovalID,
	)

	if err != nil {
		return fmt.Errorf("failed to update leave approval: %w", err)
	}

	rowsAffected, _ := result.RowsAffected()
	if rowsAffected == 0 {
		return fmt.Errorf("leave approval not found: %s", approval.ApprovalID)
	}

	return nil
}

func (r *LeaveRepositoryImpl) DeleteLeaveApproval(ctx context.Context, approvalID uuid.UUID) error {
	query := `DELETE FROM leave_approvals WHERE approval_id = $1`
	result, err := r.client.Exec(ctx, query, approvalID)
	if err != nil {
		return fmt.Errorf("failed to delete leave approval: %w", err)
	}

	rowsAffected, _ := result.RowsAffected()
	if rowsAffected == 0 {
		return fmt.Errorf("leave approval not found: %s", approvalID)
	}

	return nil
}

func (r *LeaveRepositoryImpl) GetApprovalChain(ctx context.Context, requestID uuid.UUID) ([]*leave.LeaveApproval, error) {
	query := `
		SELECT approval_id, leave_request_id, approved_by, decision, 
		       decision_reason, approval_level, decided_at
		FROM leave_approvals 
		WHERE leave_request_id = $1
		ORDER BY approval_level`

	rows, err := r.client.Query(ctx, query, requestID)
	if err != nil {
		return nil, fmt.Errorf("failed to get approval chain: %w", err)
	}
	defer rows.Close()

	approvals := make([]*leave.LeaveApproval, 0)
	for rows.Next() {
		approval, err := r.scanLeaveApproval(rows)
		if err != nil {
			r.logger.Warn("Failed to scan leave approval", util.ErrorField(err))
			continue
		}
		approvals = append(approvals, approval)
	}

	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("error iterating approval chain: %w", err)
	}

	return approvals, nil
}

func (r *LeaveRepositoryImpl) HasUserApprovedRequest(ctx context.Context, requestID, userID uuid.UUID) (bool, error) {
	query := `
		SELECT EXISTS (
			SELECT 1 FROM leave_approvals 
			WHERE leave_request_id = $1 AND approved_by = $2
		)`

	var exists bool
	err := r.client.QueryRow(ctx, query, requestID, userID).Scan(&exists)
	if err != nil {
		return false, fmt.Errorf("failed to check if user approved request: %w", err)
	}

	return exists, nil
}

// ============================================================================
// LEAVE TRANSACTION METHODS
// ============================================================================

func (r *LeaveRepositoryImpl) CreateLeaveTransaction(ctx context.Context, txn *leave.LeaveTransaction) error {
	query := `
		INSERT INTO leave_transactions (
			transaction_id, company_id, user_id, leave_type_id, 
			leave_request_id, change_amount, reason, created_at
		) VALUES ($1, $2, $3, $4, $5, $6, $7, $8)`

	_, err := r.client.Exec(ctx, query,
		txn.TransactionID,
		txn.CompanyID,
		txn.UserID,
		txn.LeaveTypeID,
		txn.LeaveRequestID,
		txn.ChangeAmount,
		txn.Reason,
		txn.CreatedAt,
	)

	if err != nil {
		r.logger.Error("Failed to create leave transaction",
			util.String("user_id", txn.UserID.String()),
			util.String("leave_type_id", txn.LeaveTypeID.String()),
			util.ErrorField(err))
		return fmt.Errorf("failed to create leave transaction: %w", err)
	}

	return nil
}

func (r *LeaveRepositoryImpl) GetLeaveTransactionByID(ctx context.Context, txnID uuid.UUID) (*leave.LeaveTransaction, error) {
	query := `
		SELECT transaction_id, company_id, user_id, leave_type_id, 
		       leave_request_id, change_amount, reason, created_at
		FROM leave_transactions 
		WHERE transaction_id = $1`

	rows, err := r.client.Query(ctx, query, txnID)
	if err != nil {
		return nil, fmt.Errorf("failed to get leave transaction: %w", err)
	}
	defer rows.Close()

	if rows.Next() {
		return r.scanLeaveTransaction(rows)
	}

	return nil, fmt.Errorf("leave transaction not found: %s", txnID)
}

func (r *LeaveRepositoryImpl) GetLeaveTransactionsByUser(ctx context.Context, userID uuid.UUID, leaveTypeID *uuid.UUID, startDate, endDate time.Time) ([]*leave.LeaveTransaction, error) {
	var query string
	var args []interface{}

	if leaveTypeID != nil {
		query = `
			SELECT transaction_id, company_id, user_id, leave_type_id, 
			       leave_request_id, change_amount, reason, created_at
			FROM leave_transactions 
			WHERE user_id = $1 AND leave_type_id = $2 
			  AND created_at BETWEEN $3 AND $4
			ORDER BY created_at DESC`
		args = []interface{}{userID, leaveTypeID, startDate, endDate}
	} else {
		query = `
			SELECT transaction_id, company_id, user_id, leave_type_id, 
			       leave_request_id, change_amount, reason, created_at
			FROM leave_transactions 
			WHERE user_id = $1 AND created_at BETWEEN $2 AND $3
			ORDER BY created_at DESC`
		args = []interface{}{userID, startDate, endDate}
	}

	rows, err := r.client.Query(ctx, query, args...)
	if err != nil {
		return nil, fmt.Errorf("failed to get leave transactions: %w", err)
	}
	defer rows.Close()

	transactions := make([]*leave.LeaveTransaction, 0)
	for rows.Next() {
		txn, err := r.scanLeaveTransaction(rows)
		if err != nil {
			r.logger.Warn("Failed to scan leave transaction", util.ErrorField(err))
			continue
		}
		transactions = append(transactions, txn)
	}

	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("error iterating leave transactions: %w", err)
	}

	return transactions, nil
}

func (r *LeaveRepositoryImpl) GetLeaveTransactionsByRequest(ctx context.Context, requestID uuid.UUID) ([]*leave.LeaveTransaction, error) {
	query := `
		SELECT transaction_id, company_id, user_id, leave_type_id, 
		       leave_request_id, change_amount, reason, created_at
		FROM leave_transactions 
		WHERE leave_request_id = $1
		ORDER BY created_at DESC`

	rows, err := r.client.Query(ctx, query, requestID)
	if err != nil {
		return nil, fmt.Errorf("failed to get leave transactions by request: %w", err)
	}
	defer rows.Close()

	transactions := make([]*leave.LeaveTransaction, 0)
	for rows.Next() {
		txn, err := r.scanLeaveTransaction(rows)
		if err != nil {
			r.logger.Warn("Failed to scan leave transaction", util.ErrorField(err))
			continue
		}
		transactions = append(transactions, txn)
	}

	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("error iterating leave transactions: %w", err)
	}

	return transactions, nil
}

func (r *LeaveRepositoryImpl) CalculateLeaveBalance(ctx context.Context, userID, leaveTypeID uuid.UUID, asOf time.Time) (float64, error) {
	query := `
		SELECT COALESCE(SUM(change_amount), 0)
		FROM leave_transactions 
		WHERE user_id = $1 AND leave_type_id = $2 AND created_at <= $3`

	var balance float64
	err := r.client.QueryRow(ctx, query, userID, leaveTypeID, asOf).Scan(&balance)
	if err != nil {
		return 0, fmt.Errorf("failed to calculate leave balance: %w", err)
	}

	return balance, nil
}

func (r *LeaveRepositoryImpl) GetTransactionSummary(ctx context.Context, userID uuid.UUID, startDate, endDate time.Time) (map[string]float64, error) {
	query := `
		SELECT 
			COALESCE(SUM(CASE WHEN reason = 'accrual' THEN change_amount ELSE 0 END), 0) as accruals,
			COALESCE(SUM(CASE WHEN reason = 'request' THEN change_amount ELSE 0 END), 0) as requests,
			COALESCE(SUM(CASE WHEN reason = 'cancel' THEN change_amount ELSE 0 END), 0) as cancellations,
			COALESCE(SUM(CASE WHEN reason = 'manual' THEN change_amount ELSE 0 END), 0) as manual_adjustments
		FROM leave_transactions 
		WHERE user_id = $1 AND created_at BETWEEN $2 AND $3`

	var accruals, requests, cancellations, manual float64
	err := r.client.QueryRow(ctx, query, userID, startDate, endDate).Scan(
		&accruals, &requests, &cancellations, &manual,
	)
	if err != nil {
		return nil, fmt.Errorf("failed to get transaction summary: %w", err)
	}

	summary := map[string]float64{
		"accruals":           accruals,
		"requests":           requests,
		"cancellations":      cancellations,
		"manual_adjustments": manual,
		"net_change":         accruals + requests + cancellations + manual,
	}

	return summary, nil
}

// ============================================================================
// LEAVE BALANCE METHODS
// ============================================================================

func (r *LeaveRepositoryImpl) CreateOrUpdateLeaveBalance(ctx context.Context, balance *leave.LeaveBalance) error {
	query := `
		INSERT INTO leave_balances (
			company_id, user_id, leave_type_id, balance, as_of, generated_at
		) VALUES ($1, $2, $3, $4, $5, $6)
		ON CONFLICT (company_id, user_id, leave_type_id, as_of) 
		DO UPDATE SET
			balance = EXCLUDED.balance,
			generated_at = EXCLUDED.generated_at`

	_, err := r.client.Exec(ctx, query,
		balance.CompanyID,
		balance.UserID,
		balance.LeaveTypeID,
		balance.Balance,
		balance.AsOf,
		balance.GeneratedAt,
	)

	if err != nil {
		r.logger.Error("Failed to create/update leave balance",
			util.String("user_id", balance.UserID.String()),
			util.String("leave_type_id", balance.LeaveTypeID.String()),
			util.ErrorField(err))
		return fmt.Errorf("failed to create/update leave balance: %w", err)
	}

	return nil
}

func (r *LeaveRepositoryImpl) GetLeaveBalance(ctx context.Context, companyID, userID, leaveTypeID uuid.UUID, asOf time.Time) (*leave.LeaveBalance, error) {
	query := `
		SELECT company_id, user_id, leave_type_id, balance, as_of, generated_at
		FROM leave_balances 
		WHERE company_id = $1 AND user_id = $2 AND leave_type_id = $3 AND as_of = $4`

	rows, err := r.client.Query(ctx, query, companyID, userID, leaveTypeID, asOf)
	if err != nil {
		return nil, fmt.Errorf("failed to get leave balance: %w", err)
	}
	defer rows.Close()

	if rows.Next() {
		return r.scanLeaveBalance(rows)
	}

	return nil, fmt.Errorf("leave balance not found")
}

func (r *LeaveRepositoryImpl) GetCurrentLeaveBalance(ctx context.Context, userID, leaveTypeID uuid.UUID) (*leave.LeaveBalance, error) {
	query := `
		SELECT company_id, user_id, leave_type_id, balance, as_of, generated_at
		FROM leave_balances 
		WHERE user_id = $1 AND leave_type_id = $2
		ORDER BY as_of DESC
		LIMIT 1`

	rows, err := r.client.Query(ctx, query, userID, leaveTypeID)
	if err != nil {
		return nil, fmt.Errorf("failed to get current leave balance: %w", err)
	}
	defer rows.Close()

	if rows.Next() {
		return r.scanLeaveBalance(rows)
	}

	return nil, fmt.Errorf("no leave balance found for user")
}

func (r *LeaveRepositoryImpl) GetLeaveBalancesByUser(ctx context.Context, userID uuid.UUID, asOf time.Time) ([]*leave.LeaveBalance, error) {
	query := `
		SELECT lb.company_id, lb.user_id, lb.leave_type_id, lb.balance, lb.as_of, lb.generated_at
		FROM leave_balances lb
		INNER JOIN (
			SELECT leave_type_id, MAX(as_of) as latest_as_of
			FROM leave_balances 
			WHERE user_id = $1 AND as_of <= $2
			GROUP BY leave_type_id
		) latest ON lb.leave_type_id = latest.leave_type_id AND lb.as_of = latest.latest_as_of
		WHERE lb.user_id = $1`

	rows, err := r.client.Query(ctx, query, userID, asOf)
	if err != nil {
		return nil, fmt.Errorf("failed to get leave balances: %w", err)
	}
	defer rows.Close()

	balances := make([]*leave.LeaveBalance, 0)
	for rows.Next() {
		balance, err := r.scanLeaveBalance(rows)
		if err != nil {
			r.logger.Warn("Failed to scan leave balance", util.ErrorField(err))
			continue
		}
		balances = append(balances, balance)
	}

	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("error iterating leave balances: %w", err)
	}

	return balances, nil
}

func (r *LeaveRepositoryImpl) UpdateLeaveBalance(ctx context.Context, balance *leave.LeaveBalance) error {
	query := `
		UPDATE leave_balances SET
			balance = $1, generated_at = $2
		WHERE company_id = $3 AND user_id = $4 AND leave_type_id = $5 AND as_of = $6`

	result, err := r.client.Exec(ctx, query,
		balance.Balance,
		balance.GeneratedAt,
		balance.CompanyID,
		balance.UserID,
		balance.LeaveTypeID,
		balance.AsOf,
	)

	if err != nil {
		return fmt.Errorf("failed to update leave balance: %w", err)
	}

	rowsAffected, _ := result.RowsAffected()
	if rowsAffected == 0 {
		return fmt.Errorf("leave balance not found")
	}

	return nil
}

func (r *LeaveRepositoryImpl) DeleteLeaveBalance(ctx context.Context, companyID, userID, leaveTypeID uuid.UUID, asOf time.Time) error {
	query := `DELETE FROM leave_balances WHERE company_id = $1 AND user_id = $2 AND leave_type_id = $3 AND as_of = $4`
	result, err := r.client.Exec(ctx, query, companyID, userID, leaveTypeID, asOf)
	if err != nil {
		return fmt.Errorf("failed to delete leave balance: %w", err)
	}

	rowsAffected, _ := result.RowsAffected()
	if rowsAffected == 0 {
		return fmt.Errorf("leave balance not found")
	}

	return nil
}

func (r *LeaveRepositoryImpl) RecalculateLeaveBalances(ctx context.Context, userID uuid.UUID, fromDate time.Time) error {
	// This is a complex operation that would recalculate all balances
	// Implementation depends on your business logic
	r.logger.Warn("RecalculateLeaveBalances not fully implemented",
		util.String("user_id", userID.String()),
		util.Time("from_date", fromDate))
	return fmt.Errorf("recalculate leave balances not implemented")
}

// ============================================================================
// ANALYTICS AND REPORTS
// ============================================================================

func (r *LeaveRepositoryImpl) GetLeaveUsageStats(ctx context.Context, companyID uuid.UUID, startDate, endDate time.Time) (*LeaveUsageStats, error) {
	query := `
		SELECT 
			COUNT(*) as total_requests,
			COUNT(CASE WHEN status = 'approved' THEN 1 END) as approved_requests,
			COUNT(CASE WHEN status = 'pending' THEN 1 END) as pending_requests,
			COUNT(CASE WHEN status = 'rejected' THEN 1 END) as rejected_requests,
			COALESCE(SUM(CASE WHEN status = 'approved' THEN duration ELSE 0 END), 0) as total_leave_days,
			COALESCE(AVG(CASE WHEN status = 'approved' THEN duration ELSE NULL END), 0) as average_leave_days
		FROM leave_requests 
		WHERE company_id = $1 
		  AND start_date BETWEEN $2 AND $3`

	var stats LeaveUsageStats
	err := r.client.QueryRow(ctx, query, companyID, startDate, endDate).Scan(
		&stats.TotalRequests,
		&stats.ApprovedRequests,
		&stats.PendingRequests,
		&stats.RejectedRequests,
		&stats.TotalLeaveDays,
		&stats.AverageLeaveDays,
	)
	if err != nil {
		return nil, fmt.Errorf("failed to get leave usage stats: %w", err)
	}

	// Get most used leave type
	var mostUsedType string
	typeQuery := `
		SELECT lt.name
		FROM leave_requests lr
		JOIN leave_types lt ON lr.leave_type_id = lt.leave_type_id
		WHERE lr.company_id = $1 
		  AND lr.start_date BETWEEN $2 AND $3
		  AND lr.status = 'approved'
		GROUP BY lt.name
		ORDER BY SUM(lr.duration) DESC
		LIMIT 1`

	err = r.client.QueryRow(ctx, typeQuery, companyID, startDate, endDate).Scan(&mostUsedType)
	if err == nil {
		stats.MostUsedLeaveType = mostUsedType
	}

	return &stats, nil
}

func (r *LeaveRepositoryImpl) GetDepartmentLeaveStats(ctx context.Context, companyID uuid.UUID, departmentID *uuid.UUID, startDate, endDate time.Time) (map[uuid.UUID]*LeaveDepartmentStats, error) {
	query := `
		SELECT 
			d.department_id,
			d.department_name,
			COUNT(DISTINCT ce.user_id) as total_employees,
			COALESCE(SUM(CASE WHEN lr.status = 'approved' THEN lr.duration ELSE 0 END), 0) as total_leave_days,
			COUNT(CASE WHEN lr.status = 'pending' THEN 1 END) as pending_requests
		FROM departments d
		LEFT JOIN company_employees ce ON d.company_id = ce.company_id 
			AND ce.is_active = true
		LEFT JOIN leave_requests lr ON ce.user_id = lr.user_id 
			AND lr.start_date BETWEEN $2 AND $3
		WHERE d.company_id = $1 
		  AND ($4::uuid IS NULL OR d.department_id = $4)
		GROUP BY d.department_id, d.department_name`

	rows, err := r.client.Query(ctx, query, companyID, startDate, endDate, departmentID)
	if err != nil {
		return nil, fmt.Errorf("failed to get department leave stats: %w", err)
	}
	defer rows.Close()

	stats := make(map[uuid.UUID]*LeaveDepartmentStats)
	for rows.Next() {
		var deptID uuid.UUID
		var deptName string
		var totalEmployees, pendingRequests int
		var totalLeaveDays float64

		err := rows.Scan(&deptID, &deptName, &totalEmployees, &totalLeaveDays, &pendingRequests)
		if err != nil {
			r.logger.Warn("Failed to scan department stats", util.ErrorField(err))
			continue
		}

		avgLeavePerEmp := 0.0
		if totalEmployees > 0 {
			avgLeavePerEmp = totalLeaveDays / float64(totalEmployees)
		}

		stats[deptID] = &LeaveDepartmentStats{
			DepartmentName:  deptName,
			TotalEmployees:  totalEmployees,
			TotalLeaveDays:  totalLeaveDays,
			AvgLeavePerEmp:  avgLeavePerEmp,
			PendingRequests: pendingRequests,
		}
	}

	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("error iterating department stats: %w", err)
	}

	return stats, nil
}

func (r *LeaveRepositoryImpl) GetEmployeeLeaveSummary(ctx context.Context, userID uuid.UUID, year int) (*EmployeeLeaveSummary, error) {
	_ = time.Date(year, 1, 1, 0, 0, 0, 0, time.UTC)
	_ = time.Date(year, 12, 31, 23, 59, 59, 0, time.UTC)

	// Get leave type breakdown
	typeQuery := `
		SELECT 
			lt.leave_type_id,
			lt.name,
			COALESCE(SUM(CASE WHEN txn.reason = 'accrual' THEN txn.change_amount ELSE 0 END), 0) as entitlement,
			COALESCE(SUM(CASE WHEN txn.reason = 'request' AND txn.change_amount < 0 THEN ABS(txn.change_amount) ELSE 0 END), 0) as used
		FROM leave_types lt
		LEFT JOIN leave_transactions txn ON lt.leave_type_id = txn.leave_type_id 
			AND txn.user_id = $1 
			AND EXTRACT(YEAR FROM txn.created_at) = $2
		WHERE EXISTS (
			SELECT 1 FROM leave_requests lr 
			WHERE lr.user_id = $1 AND lr.leave_type_id = lt.leave_type_id
		)
		GROUP BY lt.leave_type_id, lt.name`

	rows, err := r.client.Query(ctx, typeQuery, userID, year)
	if err != nil {
		return nil, fmt.Errorf("failed to get leave type breakdown: %w", err)
	}
	defer rows.Close()

	breakdown := make(map[string]LeaveTypeSummary)
	var totalEntitlement, totalUsed float64

	for rows.Next() {
		var leaveTypeID uuid.UUID
		var name string
		var entitlement, used float64

		err := rows.Scan(&leaveTypeID, &name, &entitlement, &used)
		if err != nil {
			r.logger.Warn("Failed to scan leave type breakdown", util.ErrorField(err))
			continue
		}

		balance := entitlement - used
		totalEntitlement += entitlement
		totalUsed += used

		breakdown[name] = LeaveTypeSummary{
			LeaveTypeName: name,
			Entitlement:   entitlement,
			Used:          used,
			Balance:       balance,
		}
	}

	// Get monthly breakdown
	monthlyQuery := `
		SELECT 
			TO_CHAR(lr.start_date, 'YYYY-MM') as month,
			COALESCE(SUM(lr.duration), 0) as total_days
		FROM leave_requests lr
		WHERE lr.user_id = $1 
		  AND EXTRACT(YEAR FROM lr.start_date) = $2
		  AND lr.status = 'approved'
		GROUP BY TO_CHAR(lr.start_date, 'YYYY-MM')
		ORDER BY month`

	monthlyRows, err := r.client.Query(ctx, monthlyQuery, userID, year)
	if err != nil {
		return nil, fmt.Errorf("failed to get monthly breakdown: %w", err)
	}
	defer monthlyRows.Close()

	monthlyBreakdown := make(map[string]float64)
	for monthlyRows.Next() {
		var month string
		var totalDays float64
		err := monthlyRows.Scan(&month, &totalDays)
		if err != nil {
			r.logger.Warn("Failed to scan monthly breakdown", util.ErrorField(err))
			continue
		}
		monthlyBreakdown[month] = totalDays
	}

	summary := &EmployeeLeaveSummary{
		Year:               year,
		TotalEntitlement:   totalEntitlement,
		TotalUsed:          totalUsed,
		TotalBalance:       totalEntitlement - totalUsed,
		LeaveTypeBreakdown: breakdown,
		MonthlyBreakdown:   monthlyBreakdown,
	}

	return summary, nil
}

func (r *LeaveRepositoryImpl) GetLeaveTrends(ctx context.Context, companyID uuid.UUID, startDate, endDate time.Time, interval string) ([]*LeaveTrendData, error) {
	var dateFormat string
	switch interval {
	case "day":
		dateFormat = "YYYY-MM-DD"
	case "week":
		dateFormat = "IYYY-IW"
	case "month":
		dateFormat = "YYYY-MM"
	default:
		dateFormat = "YYYY-MM"
	}

	query := fmt.Sprintf(`
		SELECT 
			TO_CHAR(lr.start_date, '%s') as period,
			COUNT(*) as total_requests,
			COALESCE(SUM(CASE WHEN lr.status = 'approved' THEN lr.duration ELSE 0 END), 0) as approved_days,
			COALESCE(SUM(CASE WHEN lr.status = 'pending' THEN lr.duration ELSE 0 END), 0) as pending_days,
			COALESCE(AVG(EXTRACT(EPOCH FROM (la.decided_at - lr.requested_at)) / 3600), 0) as avg_approval_time_hours
		FROM leave_requests lr
		LEFT JOIN leave_approvals la ON lr.leave_request_id = la.leave_request_id 
			AND la.decision = 'approved'
		WHERE lr.company_id = $1 
		  AND lr.start_date BETWEEN $2 AND $3
		GROUP BY TO_CHAR(lr.start_date, '%s')
		ORDER BY period`, dateFormat, dateFormat)

	rows, err := r.client.Query(ctx, query, companyID, startDate, endDate)
	if err != nil {
		return nil, fmt.Errorf("failed to get leave trends: %w", err)
	}
	defer rows.Close()

	trends := make([]*LeaveTrendData, 0)
	for rows.Next() {
		var trend LeaveTrendData
		var avgApprovalTimeHours float64

		err := rows.Scan(
			&trend.Period,
			&trend.TotalRequests,
			&trend.ApprovedDays,
			&trend.PendingDays,
			&avgApprovalTimeHours,
		)
		if err != nil {
			r.logger.Warn("Failed to scan trend data", util.ErrorField(err))
			continue
		}

		trend.AvgApprovalTime = avgApprovalTimeHours
		trends = append(trends, &trend)
	}

	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("error iterating trend data: %w", err)
	}

	return trends, nil
}

// ============================================================================
// BATCH OPERATIONS
// ============================================================================

func (r *LeaveRepositoryImpl) CreateLeaveTypesBatch(ctx context.Context, leaveTypes []*leave.LeaveType) error {
	if len(leaveTypes) == 0 {
		return nil
	}

	tx, err := r.client.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("failed to begin transaction: %w", err)
	}
	defer tx.Rollback()

	query := `
		INSERT INTO leave_types (
			leave_type_id, company_id, leave_code, name, category, 
			is_statutory, affects_pay, requires_approval, requires_document,
			allow_half_day, allow_hourly, is_active, created_at
		) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13)`

	stmt, err := tx.PrepareContext(ctx, query)
	if err != nil {
		return fmt.Errorf("failed to prepare batch statement: %w", err)
	}
	defer stmt.Close()

	for _, lt := range leaveTypes {
		_, err := stmt.ExecContext(ctx,
			lt.LeaveTypeID,
			lt.CompanyID,
			lt.LeaveCode,
			lt.Name,
			lt.Category,
			lt.IsStatutory,
			lt.AffectsPay,
			lt.RequiresApproval,
			lt.RequiresDocument,
			lt.AllowHalfDay,
			lt.AllowHourly,
			lt.IsActive,
			lt.CreatedAt,
		)
		if err != nil {
			return fmt.Errorf("failed to insert leave type %s: %w", lt.LeaveTypeID, err)
		}
	}

	if err := tx.Commit(); err != nil {
		return fmt.Errorf("failed to commit batch transaction: %w", err)
	}

	r.logger.Info("Batch leave types creation completed",
		util.Int("leave_types_created", len(leaveTypes)))
	return nil
}

func (r *LeaveRepositoryImpl) CreateLeavePoliciesBatch(ctx context.Context, policies []*leave.LeavePolicy) error {
	if len(policies) == 0 {
		return nil
	}

	tx, err := r.client.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("failed to begin transaction: %w", err)
	}
	defer tx.Rollback()

	query := `
		INSERT INTO leave_policies (
			leave_policy_id, company_id, department_id, country_code, 
			policy_code, rules, is_active, created_at
		) VALUES ($1, $2, $3, $4, $5, $6, $7, $8)`

	stmt, err := tx.PrepareContext(ctx, query)
	if err != nil {
		return fmt.Errorf("failed to prepare batch statement: %w", err)
	}
	defer stmt.Close()

	for _, policy := range policies {
		rulesJSON, err := json.Marshal(policy.Rules)
		if err != nil {
			return fmt.Errorf("failed to marshal policy rules for %s: %w", policy.LeavePolicyID, err)
		}

		_, err = stmt.ExecContext(ctx,
			policy.LeavePolicyID,
			policy.CompanyID,
			policy.DepartmentID,
			policy.CountryCode,
			policy.PolicyCode,
			rulesJSON,
			policy.IsActive,
			policy.CreatedAt,
		)
		if err != nil {
			return fmt.Errorf("failed to insert leave policy %s: %w", policy.LeavePolicyID, err)
		}
	}

	if err := tx.Commit(); err != nil {
		return fmt.Errorf("failed to commit batch transaction: %w", err)
	}

	return nil
}

func (r *LeaveRepositoryImpl) AssignLeavePoliciesBatch(ctx context.Context, userPolicies []*leave.UserLeavePolicy) error {
	if len(userPolicies) == 0 {
		return nil
	}

	tx, err := r.client.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("failed to begin transaction: %w", err)
	}
	defer tx.Rollback()

	query := `
		INSERT INTO user_leave_policies (
			user_id, leave_policy_id, effective_from, effective_to, 
			assigned_by, created_at
		) VALUES ($1, $2, $3, $4, $5, $6)
		ON CONFLICT (user_id, leave_policy_id, effective_from) 
		DO UPDATE SET
			effective_to = EXCLUDED.effective_to,
			assigned_by = EXCLUDED.assigned_by`

	stmt, err := tx.PrepareContext(ctx, query)
	if err != nil {
		return fmt.Errorf("failed to prepare batch statement: %w", err)
	}
	defer stmt.Close()

	for _, policy := range userPolicies {
		_, err := stmt.ExecContext(ctx,
			policy.UserID,
			policy.LeavePolicyID,
			policy.EffectiveFrom,
			policy.EffectiveTo,
			policy.AssignedBy,
			policy.CreatedAt,
		)
		if err != nil {
			return fmt.Errorf("failed to assign user leave policy %s: %w", policy.UserID, err)
		}
	}

	if err := tx.Commit(); err != nil {
		return fmt.Errorf("failed to commit batch transaction: %w", err)
	}

	return nil
}

func (r *LeaveRepositoryImpl) CreateLeaveRequestsBatch(ctx context.Context, requests []*leave.LeaveRequest) error {
	if len(requests) == 0 {
		return nil
	}

	tx, err := r.client.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("failed to begin transaction: %w", err)
	}
	defer tx.Rollback()

	query := `
		INSERT INTO leave_requests (
			leave_request_id, company_id, user_id, leave_type_id, 
			start_date, end_date, duration, reason, status, requested_at
		) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10)`

	stmt, err := tx.PrepareContext(ctx, query)
	if err != nil {
		return fmt.Errorf("failed to prepare batch statement: %w", err)
	}
	defer stmt.Close()

	for _, req := range requests {
		_, err := stmt.ExecContext(ctx,
			req.LeaveRequestID,
			req.CompanyID,
			req.UserID,
			req.LeaveTypeID,
			req.StartDate,
			req.EndDate,
			req.Duration,
			req.Reason,
			req.Status,
			req.RequestedAt,
		)
		if err != nil {
			return fmt.Errorf("failed to insert leave request %s: %w", req.LeaveRequestID, err)
		}
	}

	if err := tx.Commit(); err != nil {
		return fmt.Errorf("failed to commit batch transaction: %w", err)
	}

	return nil
}

func (r *LeaveRepositoryImpl) CreateLeaveTransactionsBatch(ctx context.Context, transactions []*leave.LeaveTransaction) error {
	if len(transactions) == 0 {
		return nil
	}

	tx, err := r.client.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("failed to begin transaction: %w", err)
	}
	defer tx.Rollback()

	query := `
		INSERT INTO leave_transactions (
			transaction_id, company_id, user_id, leave_type_id, 
			leave_request_id, change_amount, reason, created_at
		) VALUES ($1, $2, $3, $4, $5, $6, $7, $8)`

	stmt, err := tx.PrepareContext(ctx, query)
	if err != nil {
		return fmt.Errorf("failed to prepare batch statement: %w", err)
	}
	defer stmt.Close()

	for _, txn := range transactions {
		_, err := stmt.ExecContext(ctx,
			txn.TransactionID,
			txn.CompanyID,
			txn.UserID,
			txn.LeaveTypeID,
			txn.LeaveRequestID,
			txn.ChangeAmount,
			txn.Reason,
			txn.CreatedAt,
		)
		if err != nil {
			return fmt.Errorf("failed to insert leave transaction %s: %w", txn.TransactionID, err)
		}
	}

	if err := tx.Commit(); err != nil {
		return fmt.Errorf("failed to commit batch transaction: %w", err)
	}

	return nil
}

// ============================================================================
// HELPER METHODS
// ============================================================================

func (r *LeaveRepositoryImpl) scanLeaveType(rows *sql.Rows) (*leave.LeaveType, error) {
	var lt leave.LeaveType
	var category string

	err := rows.Scan(
		&lt.LeaveTypeID,
		&lt.CompanyID,
		&lt.LeaveCode,
		&lt.Name,
		&category,
		&lt.IsStatutory,
		&lt.AffectsPay,
		&lt.RequiresApproval,
		&lt.RequiresDocument,
		&lt.AllowHalfDay,
		&lt.AllowHourly,
		&lt.IsActive,
		&lt.CreatedAt,
	)

	if err != nil {
		return nil, err
	}

	lt.Category = category
	return &lt, nil
}

func (r *LeaveRepositoryImpl) scanLeavePolicy(rows *sql.Rows) (*leave.LeavePolicy, error) {
	var policy leave.LeavePolicy
	var departmentID sql.NullString
	var rulesJSON []byte

	err := rows.Scan(
		&policy.LeavePolicyID,
		&policy.CompanyID,
		&departmentID,
		&policy.CountryCode,
		&policy.PolicyCode,
		&rulesJSON,
		&policy.IsActive,
		&policy.CreatedAt,
	)

	if err != nil {
		return nil, err
	}

	// Handle nullable department ID
	if departmentID.Valid && departmentID.String != "" {
		deptUUID, err := uuid.Parse(departmentID.String)
		if err == nil {
			policy.DepartmentID = &deptUUID
		}
	}

	// Parse rules JSON
	var rules leave.PolicyRules
	if err := json.Unmarshal(rulesJSON, &rules); err != nil {
		r.logger.Warn("Failed to unmarshal policy rules",
			util.String("policy_id", policy.LeavePolicyID.String()),
			util.ErrorField(err))
		// Continue with empty rules
	}
	policy.Rules = rules

	return &policy, nil
}

func (r *LeaveRepositoryImpl) scanUserLeavePolicy(rows *sql.Rows) (*leave.UserLeavePolicy, error) {
	var policy leave.UserLeavePolicy
	var effectiveTo sql.NullTime
	var assignedBy sql.NullString

	err := rows.Scan(
		&policy.UserID,
		&policy.LeavePolicyID,
		&policy.EffectiveFrom,
		&effectiveTo,
		&assignedBy,
		&policy.CreatedAt,
	)

	if err != nil {
		return nil, err
	}

	if effectiveTo.Valid {
		policy.EffectiveTo = &effectiveTo.Time
	}

	if assignedBy.Valid && assignedBy.String != "" {
		assignedByUUID, err := uuid.Parse(assignedBy.String)
		if err == nil {
			policy.AssignedBy = &assignedByUUID
		}
	}

	return &policy, nil
}

func (r *LeaveRepositoryImpl) scanLeaveRequest(rows *sql.Rows) (*leave.LeaveRequest, error) {
	var req leave.LeaveRequest
	var reason sql.NullString

	err := rows.Scan(
		&req.LeaveRequestID,
		&req.CompanyID,
		&req.UserID,
		&req.LeaveTypeID,
		&req.StartDate,
		&req.EndDate,
		&req.Duration,
		&reason,
		&req.Status,
		&req.RequestedAt,
	)

	if err != nil {
		return nil, err
	}

	if reason.Valid {
		req.Reason = &reason.String
	}

	return &req, nil
}

func (r *LeaveRepositoryImpl) scanLeaveApproval(rows *sql.Rows) (*leave.LeaveApproval, error) {
	var approval leave.LeaveApproval
	var decisionReason sql.NullString

	err := rows.Scan(
		&approval.ApprovalID,
		&approval.LeaveRequestID,
		&approval.ApprovedBy,
		&approval.Decision,
		&decisionReason,
		&approval.ApprovalLevel,
		&approval.DecidedAt,
	)

	if err != nil {
		return nil, err
	}

	if decisionReason.Valid {
		approval.DecisionReason = &decisionReason.String
	}

	return &approval, nil
}

func (r *LeaveRepositoryImpl) scanLeaveTransaction(rows *sql.Rows) (*leave.LeaveTransaction, error) {
	var txn leave.LeaveTransaction
	var leaveRequestID sql.NullString

	err := rows.Scan(
		&txn.TransactionID,
		&txn.CompanyID,
		&txn.UserID,
		&txn.LeaveTypeID,
		&leaveRequestID,
		&txn.ChangeAmount,
		&txn.Reason,
		&txn.CreatedAt,
	)

	if err != nil {
		return nil, err
	}

	if leaveRequestID.Valid && leaveRequestID.String != "" {
		requestID, err := uuid.Parse(leaveRequestID.String)
		if err == nil {
			txn.LeaveRequestID = &requestID
		}
	}

	return &txn, nil
}

func (r *LeaveRepositoryImpl) scanLeaveBalance(rows *sql.Rows) (*leave.LeaveBalance, error) {
	var balance leave.LeaveBalance

	err := rows.Scan(
		&balance.CompanyID,
		&balance.UserID,
		&balance.LeaveTypeID,
		&balance.Balance,
		&balance.AsOf,
		&balance.GeneratedAt,
	)

	if err != nil {
		return nil, err
	}

	return &balance, nil
}

// ============================================================================
// PREPARED STATEMENTS
// ============================================================================

func (r *LeaveRepositoryImpl) initializePreparedStatements(ctx context.Context) {
	statements := map[string]string{
		"get_leave_type_by_id": `
			SELECT leave_type_id, company_id, leave_code, name, category, 
			       is_statutory, affects_pay, requires_approval, requires_document,
			       allow_half_day, allow_hourly, is_active, created_at
			FROM leave_types WHERE leave_type_id = $1`,

		"get_leave_type_by_code": `
			SELECT leave_type_id, company_id, leave_code, name, category, 
			       is_statutory, affects_pay, requires_approval, requires_document,
			       allow_half_day, allow_hourly, is_active, created_at
			FROM leave_types WHERE company_id = $1 AND leave_code = $2`,

		"get_leave_policy_by_code": `
			SELECT leave_policy_id, company_id, department_id, country_code, 
			       policy_code, rules, is_active, created_at
			FROM leave_policies WHERE company_id = $1 AND policy_code = $2`,

		"get_leave_request_by_id": `
			SELECT leave_request_id, company_id, user_id, leave_type_id, 
			       start_date, end_date, duration, reason, status, requested_at
			FROM leave_requests WHERE leave_request_id = $1`,
	}

	for name, query := range statements {
		stmt, err := r.client.DB.PrepareContext(ctx, query)
		if err != nil {
			r.logger.Warn("Failed to prepare statement",
				util.String("statement", name),
				util.ErrorField(err))
			continue
		}

		r.stmtMutex.Lock()
		r.stmtCache[name] = stmt
		r.stmtMutex.Unlock()
	}

	r.logger.Info("Leave prepared statements initialized",
		util.Int("statements", len(r.stmtCache)))
}

func (r *LeaveRepositoryImpl) getStmt(name string) (*sql.Stmt, bool) {
	r.stmtMutex.RLock()
	defer r.stmtMutex.RUnlock()
	stmt, exists := r.stmtCache[name]
	return stmt, exists
}

// ============================================================================
// HEALTH CHECK
// ============================================================================

func (r *LeaveRepositoryImpl) HealthCheck(ctx context.Context) error {
	// Simple query to check database connectivity
	query := `SELECT 1 FROM leave_types LIMIT 1`
	_, err := r.client.Exec(ctx, query)
	if err != nil {
		return fmt.Errorf("leave repository health check failed: %w", err)
	}
	return nil
}

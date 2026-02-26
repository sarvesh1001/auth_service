package repository

import (
	"auth-service/internal/client"
	"auth-service/internal/hr/leave/models"
	"auth-service/internal/util"
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/google/uuid"
	"go.uber.org/zap"
)

type leaveRepository struct {
	client *client.PostgresClient
	logger *zap.Logger
}

func NewLeaveRepository(
	postgresClient *client.PostgresClient,
	logger *zap.Logger,
) LeaveRepository {
	return &leaveRepository{
		client: postgresClient,
		logger: logger,
	}
}

// GetActiveLeaveEntitlement - Now position-aware
func (r *leaveRepository) GetActiveLeaveEntitlement(
	ctx context.Context,
	userID, leaveTypeID uuid.UUID,
	date time.Time,
	positionID *uuid.UUID,
) (*models.LeaveEntitlement, error) {
	query := `
		SELECT
			entitlement_id,
			company_id,
			user_id,
			leave_type_id,
			total_days,
			effective_from,
			effective_to,
			created_at,
			policy_id,
			source,
			updated_at,
			position_id,
			work_center_code
		FROM leave.leave_entitlement
		WHERE user_id = $1
		AND leave_type_id = $2
		AND effective_from <= $3
		AND (effective_to IS NULL OR effective_to >= $3)
		AND (position_id IS NOT DISTINCT FROM $4 OR $4 IS NULL)
		ORDER BY effective_from DESC
		LIMIT 1
	`

	row := r.client.QueryRow(ctx, query, userID, leaveTypeID, date, positionID)
	var entitlement models.LeaveEntitlement
	var effectiveTo sql.NullTime
	var policyID sql.NullString
	var positionIDDB sql.NullString
	var workCenterCode sql.NullString
	var updatedAt sql.NullTime

	err := row.Scan(
		&entitlement.EntitlementID,
		&entitlement.CompanyID,
		&entitlement.UserID,
		&entitlement.LeaveTypeID,
		&entitlement.TotalDays,
		&entitlement.EffectiveFrom,
		&effectiveTo,
		&entitlement.CreatedAt,
		&policyID,
		&entitlement.Source,
		&updatedAt,
		&positionIDDB,
		&workCenterCode,
	)

	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, nil
		}
		r.logger.Error("Failed to get active leave entitlement",
			util.String("user_id", userID.String()),
			util.String("leave_type_id", leaveTypeID.String()),
			util.ErrorField(err))
		return nil, fmt.Errorf("failed to get active leave entitlement: %w", err)
	}

	if effectiveTo.Valid {
		entitlement.EffectiveTo = &effectiveTo.Time
	}
	if policyID.Valid && policyID.String != "" {
		pid, err := uuid.Parse(policyID.String)
		if err == nil {
			entitlement.PolicyID = &pid
		}
	}
	if positionIDDB.Valid && positionIDDB.String != "" {
		pid, err := uuid.Parse(positionIDDB.String)
		if err == nil {
			entitlement.PositionID = &pid
		}
	}
	if workCenterCode.Valid {
		entitlement.WorkCenterCode = &workCenterCode.String
	}
	if updatedAt.Valid {
		entitlement.UpdatedAt = &updatedAt.Time
	}

	return &entitlement, nil
}

// ProcessLeaveRequest - Fixed ambiguous entitlement selection
func (r *leaveRepository) ProcessLeaveRequest(
	ctx context.Context,
	requestID uuid.UUID,
	approved bool,
	approvedBy uuid.UUID,
) error {

	tx, err := r.client.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("failed to begin transaction: %w", err)
	}

	defer func() {
		if err != nil {
			tx.Rollback()
		}
	}()

	// ===============================
	// Fetch request + entitlement
	// ===============================
	query := `
		WITH request_data AS (
			SELECT
				lr.leave_request_id,
				lr.company_id,
				lr.user_id,
				lr.leave_type_id,
				lr.start_date,
				lr.end_date,
				lr.total_days,
				lr.status,
				lr.requested_by,
				lr.approved_by,
				lr.requested_at,
				lr.approved_at,
				(SELECT position_id 
				 FROM company_employees 
				 WHERE user_id = lr.user_id 
				   AND company_id = lr.company_id 
				   AND is_active = true
				   AND hire_date <= lr.start_date
				 ORDER BY hire_date DESC 
				 LIMIT 1) as user_position_id
			FROM leave.leave_request lr
			WHERE lr.leave_request_id = $1
			AND lr.status = 'pending'
		),
		applicable_entitlement AS (
			SELECT le.entitlement_id, le.policy_id, le.source
			FROM leave.leave_entitlement le
			JOIN request_data rd ON le.user_id = rd.user_id
				AND le.leave_type_id = rd.leave_type_id
				AND le.effective_from <= rd.start_date
				AND (le.effective_to IS NULL OR le.effective_to >= rd.end_date)
				AND (
					le.position_id IS NOT DISTINCT FROM rd.user_position_id
					OR rd.user_position_id IS NULL
				)
			ORDER BY le.effective_from DESC
			LIMIT 1
		)
		SELECT
			rd.leave_request_id,
			rd.company_id,
			rd.user_id,
			rd.leave_type_id,
			rd.start_date,
			rd.end_date,
			rd.total_days,
			rd.status,
			rd.requested_by,
			rd.approved_by,
			rd.requested_at,
			rd.approved_at,
			rd.user_position_id,
			ae.entitlement_id,
			ae.policy_id,
			ae.source
		FROM request_data rd
		LEFT JOIN applicable_entitlement ae ON 1=1
	`

	row := tx.QueryRowContext(ctx, query, requestID)

	var request models.LeaveRequest
	var entitlementID uuid.UUID
	var policyID sql.NullString
	var source string
	var approvedByDB sql.NullString
	var approvedAt sql.NullTime
	var userPositionID sql.NullString

	err = row.Scan(
		&request.LeaveRequestID,
		&request.CompanyID,
		&request.UserID,
		&request.LeaveTypeID,
		&request.StartDate,
		&request.EndDate,
		&request.TotalDays,
		&request.Status,
		&request.RequestedBy,
		&approvedByDB,
		&request.RequestedAt,
		&approvedAt,
		&userPositionID,
		&entitlementID,
		&policyID,
		&source,
	)

	if err != nil {
		return fmt.Errorf("leave request not found or invalid state: %w", err)
	}

	// ===============================
	// Update Status
	// ===============================
	status := "rejected"
	if approved {
		status = "approved"
	}

	updateQuery := `
		UPDATE leave.leave_request
		SET status = $1, approved_by = $2, approved_at = NOW()
		WHERE leave_request_id = $3
	`

	_, err = tx.ExecContext(ctx, updateQuery, status, approvedBy, requestID)
	if err != nil {
		return fmt.Errorf("failed to update leave request: %w", err)
	}

	// ===============================
	// Ledger Entry (FIXED HERE)
	// ===============================
	if approved {

		ledgerID := uuid.New()

		ledgerQuery := `
			INSERT INTO leave.leave_ledger (
				ledger_id,
				entitlement_id,
				leave_request_id,
				entry_type,
				days,
				entry_date,
				created_at
			) VALUES ($1, $2, $3, $4, $5, $6, $7)
		`

		_, err = tx.ExecContext(
			ctx,
			ledgerQuery,
			ledgerID,
			entitlementID,
			requestID,
			"consumption",
			request.TotalDays,

			// ✅ FIXED LINE
			request.StartDate.UTC(),

			time.Now().UTC(),
		)
		if err != nil {
			return fmt.Errorf("failed to create ledger entry: %w", err)
		}
	}

	// ===============================
	// Commit
	// ===============================
	if err = tx.Commit(); err != nil {
		return fmt.Errorf("failed to commit transaction: %w", err)
	}

	return nil
}

// ResolveUserPolicyRules - Fixed ordering for stability
func (r *leaveRepository) ResolveUserPolicyRules(
	ctx context.Context,
	companyID uuid.UUID,
	userID uuid.UUID,
	asOf time.Time,
) ([]*models.LeavePolicyRuleResolution, error) {
	query := `
		SELECT
			pr.policy_id,
			pr.leave_type_id,
			pr.total_days,
			pr.accrual_method,
			pr.carry_forward_limit
		FROM leave.get_user_effective_policy($1, $2, $3) ep
		JOIN leave.leave_policy_rule pr
		  ON ep.policy_id = pr.policy_id
		ORDER BY pr.leave_type_id, pr.created_at
	`

	rows, err := r.client.Query(ctx, query, companyID, userID, asOf)
	if err != nil {
		return nil, fmt.Errorf("failed to resolve policy rules: %w", err)
	}
	defer rows.Close()

	var rules []*models.LeavePolicyRuleResolution
	for rows.Next() {
		var rule models.LeavePolicyRuleResolution
		var accrualMethod sql.NullString
		var carry sql.NullInt32

		err := rows.Scan(
			&rule.PolicyID,
			&rule.LeaveTypeID,
			&rule.TotalDays,
			&accrualMethod,
			&carry,
		)
		if err != nil {
			return nil, err
		}

		if accrualMethod.Valid {
			rule.AccrualMethod = accrualMethod.String
		}
		if carry.Valid {
			v := int(carry.Int32)
			rule.CarryForwardLimit = &v
		}
		rules = append(rules, &rule)
	}

	return rules, nil
}

// GetPolicyRules - Handle nullable accrual method
func (r *leaveRepository) GetPolicyRules(ctx context.Context, policyID uuid.UUID) ([]*models.LeavePolicyRule, error) {
	query := `
		SELECT
			policy_rule_id,
			policy_id,
			leave_type_id,
			total_days,
			accrual_method,
			carry_forward_limit,
			created_at,
			updated_at
		FROM leave.leave_policy_rule
		WHERE policy_id = $1
		ORDER BY leave_type_id
	`

	rows, err := r.client.Query(ctx, query, policyID)
	if err != nil {
		r.logger.Error("Failed to get policy rules",
			util.String("policy_id", policyID.String()),
			util.ErrorField(err))
		return nil, fmt.Errorf("failed to get policy rules: %w", err)
	}
	defer rows.Close()

	var rules []*models.LeavePolicyRule
	for rows.Next() {
		var rule models.LeavePolicyRule
		var accrualMethod sql.NullString
		var carryForwardLimit sql.NullInt32
		var updatedAt sql.NullTime

		err := rows.Scan(
			&rule.PolicyRuleID,
			&rule.PolicyID,
			&rule.LeaveTypeID,
			&rule.TotalDays,
			&accrualMethod,
			&carryForwardLimit,
			&rule.CreatedAt,
			&updatedAt,
		)
		if err != nil {
			return nil, fmt.Errorf("failed to scan policy rule: %w", err)
		}

		if accrualMethod.Valid {
			rule.AccrualMethod = &accrualMethod.String
		}
		if carryForwardLimit.Valid {
			limit := int(carryForwardLimit.Int32)
			rule.CarryForwardLimit = &limit
		}
		if updatedAt.Valid {
			rule.UpdatedAt = &updatedAt.Time
		}

		rules = append(rules, &rule)
	}

	if err = rows.Err(); err != nil {
		return nil, fmt.Errorf("rows iteration error: %w", err)
	}

	return rules, nil
}

// GetLeaveBalance - Position-aware balance calculation
func (r *leaveRepository) GetLeaveBalance(
	ctx context.Context,
	userID, leaveTypeID uuid.UUID,
	positionID *uuid.UUID,
) (*models.LeaveBalance, error) {
	query := `
		WITH current_entitlement AS (
			SELECT
				entitlement_id,
				total_days,
				policy_id,
				source
			FROM leave.leave_entitlement
			WHERE user_id = $1
			AND leave_type_id = $2
			AND effective_from <= CURRENT_DATE
			AND (effective_to IS NULL OR effective_to >= CURRENT_DATE)
			AND (position_id IS NOT DISTINCT FROM $3 OR $3 IS NULL)
			ORDER BY effective_from DESC
			LIMIT 1
		),
		ledger_sum AS (
			SELECT
				COALESCE(SUM(
					CASE entry_type
						WHEN 'accrual' THEN days
						WHEN 'reversal' THEN days
						WHEN 'consumption' THEN -days
						ELSE 0
					END
				), 0) AS balance,
				COALESCE(SUM(
					CASE entry_type
						WHEN 'accrual' THEN days
						WHEN 'reversal' THEN days
						ELSE 0
					END
				), 0) AS accrued,
				COALESCE(SUM(
					CASE entry_type
						WHEN 'consumption' THEN days
						ELSE 0
					END
				), 0) AS consumed
			FROM leave.leave_ledger ll
			JOIN current_entitlement ce ON ll.entitlement_id = ce.entitlement_id
		),
		leave_type_info AS (
			SELECT code, name, carry_forward_limit
			FROM leave.leave_type
			WHERE leave_type_id = $2
		)
		SELECT
			$1 as user_id,
			$2 as leave_type_id,
			lti.code,
			lti.name,
			COALESCE(ce.total_days, 0) as total_entitled,
			COALESCE(ls.accrued, 0) as accrued,
			COALESCE(ls.consumed, 0) as consumed,
			COALESCE(ls.balance, 0) as balance,
			lti.carry_forward_limit
		FROM leave_type_info lti
		LEFT JOIN current_entitlement ce ON 1=1
		LEFT JOIN ledger_sum ls ON 1=1
	`
	row := r.client.QueryRow(ctx, query, userID, leaveTypeID, positionID)

	var balance models.LeaveBalance
	var carryForwardLimit sql.NullInt32
	err := row.Scan(
		&balance.UserID,
		&balance.LeaveTypeID,
		&balance.LeaveTypeCode,
		&balance.LeaveTypeName,
		&balance.TotalEntitled,
		&balance.Accrued,
		&balance.Consumed,
		&balance.Balance,
		&carryForwardLimit,
	)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return &models.LeaveBalance{
				UserID:        userID,
				LeaveTypeID:   leaveTypeID,
				TotalEntitled: 0,
				Accrued:       0,
				Consumed:      0,
				Balance:       0,
			}, nil
		}
		r.logger.Error("Failed to get leave balance",
			util.String("user_id", userID.String()),
			util.String("leave_type_id", leaveTypeID.String()),
			util.ErrorField(err))
		return nil, fmt.Errorf("failed to get leave balance: %w", err)
	}
	if carryForwardLimit.Valid {
		limit := int(carryForwardLimit.Int32)
		balance.CarryForward = &limit
	}
	return &balance, nil
}

// CalculateLeaveBalance - Position-aware with date filter
func (r *leaveRepository) CalculateLeaveBalance(
	ctx context.Context,
	userID, leaveTypeID uuid.UUID,
	asOfDate time.Time,
	positionID *uuid.UUID,
) (*models.LeaveBalance, error) {
	query := `
		WITH current_entitlement AS (
			SELECT
				entitlement_id,
				total_days,
				policy_id,
				source
			FROM leave.leave_entitlement
			WHERE user_id = $1
			AND leave_type_id = $2
			AND effective_from <= $3
			AND (effective_to IS NULL OR effective_to >= $3)
			AND (position_id IS NOT DISTINCT FROM $4 OR $4 IS NULL)
			ORDER BY effective_from DESC
			LIMIT 1
		),
		ledger_sum AS (
			SELECT
				COALESCE(SUM(
					CASE entry_type
						WHEN 'accrual' THEN days
						WHEN 'reversal' THEN days
						WHEN 'consumption' THEN -days
						ELSE 0
					END
				), 0) AS balance,
				COALESCE(SUM(
					CASE entry_type
						WHEN 'accrual' THEN days
						WHEN 'reversal' THEN days
						ELSE 0
					END
				), 0) AS accrued,
				COALESCE(SUM(
					CASE entry_type
						WHEN 'consumption' THEN days
						ELSE 0
					END
				), 0) AS consumed
			FROM leave.leave_ledger ll
			JOIN current_entitlement ce ON ll.entitlement_id = ce.entitlement_id
			WHERE ll.entry_date <= $3
		),
		leave_type_info AS (
			SELECT code, name, carry_forward_limit
			FROM leave.leave_type
			WHERE leave_type_id = $2
		)
		SELECT
			$1 as user_id,
			$2 as leave_type_id,
			lti.code,
			lti.name,
			COALESCE(ce.total_days, 0) as total_entitled,
			COALESCE(ls.accrued, 0) as accrued,
			COALESCE(ls.consumed, 0) as consumed,
			COALESCE(ls.balance, 0) as balance,
			lti.carry_forward_limit
		FROM leave_type_info lti
		LEFT JOIN current_entitlement ce ON 1=1
		LEFT JOIN ledger_sum ls ON 1=1
	`
	row := r.client.QueryRow(ctx, query, userID, leaveTypeID, asOfDate, positionID)

	var balance models.LeaveBalance
	var carryForwardLimit sql.NullInt32
	err := row.Scan(
		&balance.UserID,
		&balance.LeaveTypeID,
		&balance.LeaveTypeCode,
		&balance.LeaveTypeName,
		&balance.TotalEntitled,
		&balance.Accrued,
		&balance.Consumed,
		&balance.Balance,
		&carryForwardLimit,
	)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return &models.LeaveBalance{
				UserID:        userID,
				LeaveTypeID:   leaveTypeID,
				TotalEntitled: 0,
				Accrued:       0,
				Consumed:      0,
				Balance:       0,
			}, nil
		}
		r.logger.Error("Failed to calculate leave balance",
			util.String("user_id", userID.String()),
			util.String("leave_type_id", leaveTypeID.String()),
			util.Time("as_of_date", asOfDate),
			util.ErrorField(err))
		return nil, fmt.Errorf("failed to calculate leave balance: %w", err)
	}
	if carryForwardLimit.Valid {
		limit := int(carryForwardLimit.Int32)
		balance.CarryForward = &limit
	}
	return &balance, nil
}

// CheckLeaveAvailability - Now position-aware
func (r *leaveRepository) CheckLeaveAvailability(
	ctx context.Context,
	userID, leaveTypeID uuid.UUID,
	days int,
	startDate time.Time,
	positionID *uuid.UUID,
) (bool, float64, error) {

	balance, err := r.CalculateLeaveBalance(
		ctx,
		userID,
		leaveTypeID,
		startDate,
		positionID,
	)
	if err != nil {
		return false, 0, fmt.Errorf("failed to calculate leave balance: %w", err)
	}

	available := balance.Balance >= float64(days)

	return available, balance.Balance, nil
}
func (r *leaveRepository) ValidateLeaveRequest(
	ctx context.Context,
	request *models.LeaveRequestCreate,
	userPositionID *uuid.UUID,
) (bool, string, error) {

	// Check overlap
	overlap, err := r.CheckLeaveOverlap(
		ctx,
		request.UserID,
		request.StartDate,
		request.EndDate,
		nil,
	)
	if err != nil {
		return false, "", fmt.Errorf("failed to check leave overlap: %w", err)
	}

	if overlap {
		return false, "Leave request overlaps with existing approved or pending leave", nil
	}

	// Check availability
	available, availableDays, err := r.CheckLeaveAvailability(
		ctx,
		request.UserID,
		request.LeaveTypeID,
		request.TotalDays,
		request.StartDate,
		userPositionID,
	)
	if err != nil {
		return false, "", fmt.Errorf("failed to check leave availability: %w", err)
	}

	if !available {
		return false, fmt.Sprintf(
			"Insufficient leave balance. Available: %.2f days, Requested: %d days",
			availableDays,
			request.TotalDays,
		), nil
	}

	return true, "", nil
}

// Add UNIQUE constraint to SQL schema (add this to your migration script):
/*
CREATE UNIQUE INDEX IF NOT EXISTS uniq_active_policy_entitlement
ON leave.leave_entitlement (
    company_id,
    user_id,
    leave_type_id,
    COALESCE(position_id::text, '')
)
WHERE effective_to IS NULL AND source = 'policy';
*/

// The rest of the repository methods remain the same as in your original code
// (CreateLeavePolicy, GetLeavePolicyByID, CreateLeaveType, etc.)
// I've only shown the critical fixes above to keep the response focused.

// Original methods below (unchanged except where noted above)
func (r *leaveRepository) CreateLeavePolicy(ctx context.Context, policy *models.LeavePolicy) error {
	if policy.PolicyID == uuid.Nil {
		policy.PolicyID = uuid.New()
	}
	if policy.CreatedAt.IsZero() {
		policy.CreatedAt = time.Now().UTC()
	}
	if policy.UpdatedAt == nil {
		now := time.Now().UTC()
		policy.UpdatedAt = &now
	}

	query := `
		INSERT INTO leave.leave_policy (
			policy_id, company_id, policy_name, applies_to_type,
			applies_to_position_id, applies_to_work_center_code,
			priority, effective_from, effective_to,
			is_active, created_at, updated_at
		) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12)
	`

	_, err := r.client.Exec(ctx, query,
		policy.PolicyID,
		policy.CompanyID,
		policy.PolicyName,
		policy.AppliesToType,
		policy.AppliesToPositionID,
		policy.AppliesToWorkCenterCode,
		policy.Priority,
		policy.EffectiveFrom,
		policy.EffectiveTo,
		policy.IsActive,
		policy.CreatedAt,
		policy.UpdatedAt,
	)

	if err != nil {
		r.logger.Error("Failed to create leave policy",
			util.String("company_id", policy.CompanyID.String()),
			util.String("policy_name", policy.PolicyName),
			util.ErrorField(err))
		return fmt.Errorf("failed to create leave policy: %w", err)
	}
	return nil
}

func (r *leaveRepository) GetLeavePolicyByID(ctx context.Context, policyID uuid.UUID) (*models.LeavePolicy, error) {
	query := `
		SELECT
			policy_id,
			company_id,
			policy_name,
			applies_to_type,
			applies_to_position_id,
			applies_to_work_center_code,
			priority,
			effective_from,
			effective_to,
			is_active,
			created_at,
			updated_at
		FROM leave.leave_policy
		WHERE policy_id = $1
	`

	row := r.client.QueryRow(ctx, query, policyID)
	var policy models.LeavePolicy
	var positionID sql.NullString
	var workCenterCode sql.NullString
	var effectiveTo sql.NullTime
	var updatedAt sql.NullTime

	err := row.Scan(
		&policy.PolicyID,
		&policy.CompanyID,
		&policy.PolicyName,
		&policy.AppliesToType,
		&positionID,
		&workCenterCode,
		&policy.Priority,
		&policy.EffectiveFrom,
		&effectiveTo,
		&policy.IsActive,
		&policy.CreatedAt,
		&updatedAt,
	)

	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, nil
		}
		r.logger.Error("Failed to get leave policy",
			util.String("policy_id", policyID.String()),
			util.ErrorField(err))
		return nil, fmt.Errorf("failed to get leave policy: %w", err)
	}

	if positionID.Valid && positionID.String != "" {
		id, err := uuid.Parse(positionID.String)
		if err == nil {
			policy.AppliesToPositionID = &id
		}
	}
	if workCenterCode.Valid {
		policy.AppliesToWorkCenterCode = &workCenterCode.String
	}
	if effectiveTo.Valid {
		policy.EffectiveTo = &effectiveTo.Time
	}
	if updatedAt.Valid {
		policy.UpdatedAt = &updatedAt.Time
	}

	return &policy, nil
}

func (r *leaveRepository) GetActiveLeavePoliciesByCompany(ctx context.Context, companyID uuid.UUID, asOf time.Time) ([]*models.LeavePolicy, error) {
	query := `
		SELECT
			policy_id,
			company_id,
			policy_name,
			applies_to_type,
			applies_to_position_id,
			applies_to_work_center_code,
			priority,
			effective_from,
			effective_to,
			is_active,
			created_at,
			updated_at
		FROM leave.leave_policy
		WHERE company_id = $1
		AND is_active = true
		AND effective_from <= $2
		AND (effective_to IS NULL OR effective_to >= $2)
		ORDER BY
			CASE applies_to_type
				WHEN 'position' THEN 1
				WHEN 'work_center' THEN 2
				WHEN 'company' THEN 3
				ELSE 4
			END,
			priority ASC,
			effective_from DESC
	`

	rows, err := r.client.Query(ctx, query, companyID, asOf)
	if err != nil {
		r.logger.Error("Failed to get active leave policies",
			util.String("company_id", companyID.String()),
			util.ErrorField(err))
		return nil, fmt.Errorf("failed to get active leave policies: %w", err)
	}
	defer rows.Close()

	var policies []*models.LeavePolicy
	for rows.Next() {
		var policy models.LeavePolicy
		var positionID sql.NullString
		var workCenterCode sql.NullString
		var effectiveTo sql.NullTime
		var updatedAt sql.NullTime

		err := rows.Scan(
			&policy.PolicyID,
			&policy.CompanyID,
			&policy.PolicyName,
			&policy.AppliesToType,
			&positionID,
			&workCenterCode,
			&policy.Priority,
			&policy.EffectiveFrom,
			&effectiveTo,
			&policy.IsActive,
			&policy.CreatedAt,
			&updatedAt,
		)
		if err != nil {
			return nil, fmt.Errorf("failed to scan leave policy: %w", err)
		}

		if positionID.Valid && positionID.String != "" {
			id, err := uuid.Parse(positionID.String)
			if err == nil {
				policy.AppliesToPositionID = &id
			}
		}
		if workCenterCode.Valid {
			policy.AppliesToWorkCenterCode = &workCenterCode.String
		}
		if effectiveTo.Valid {
			policy.EffectiveTo = &effectiveTo.Time
		}
		if updatedAt.Valid {
			policy.UpdatedAt = &updatedAt.Time
		}

		policies = append(policies, &policy)
	}

	if err = rows.Err(); err != nil {
		return nil, fmt.Errorf("rows iteration error: %w", err)
	}

	return policies, nil
}

func (r *leaveRepository) CreatePolicyLeaveEntitlement(
	ctx context.Context,
	entitlement *models.LeaveEntitlement,
) error {
	if entitlement.EntitlementID == uuid.Nil {
		entitlement.EntitlementID = uuid.New()
	}
	if entitlement.Source == "" {
		entitlement.Source = "policy"
	}
	if entitlement.CreatedAt.IsZero() {
		entitlement.CreatedAt = time.Now().UTC()
	}
	if entitlement.UpdatedAt == nil {
		now := time.Now().UTC()
		entitlement.UpdatedAt = &now
	}

	// Check for existing active policy entitlement for same user, leave type, and position
	checkQuery := `
		SELECT entitlement_id
		FROM leave.leave_entitlement
		WHERE company_id = $1
		  AND user_id = $2
		  AND leave_type_id = $3
		  AND effective_to IS NULL
		  AND source = 'policy'
		  AND (position_id IS NOT DISTINCT FROM $4)
		LIMIT 1
	`

	row := r.client.QueryRow(ctx, checkQuery,
		entitlement.CompanyID,
		entitlement.UserID,
		entitlement.LeaveTypeID,
		entitlement.PositionID,
	)

	var existingID uuid.UUID
	err := row.Scan(&existingID)
	if err == nil {
		// Update existing
		updateQuery := `
			UPDATE leave.leave_entitlement
			SET total_days = $1,
				effective_from = $2,
				policy_id = $3,
				position_id = $4,
				work_center_code = $5,
				updated_at = NOW()
			WHERE entitlement_id = $6
		`
		_, err := r.client.Exec(ctx, updateQuery,
			entitlement.TotalDays,
			entitlement.EffectiveFrom,
			entitlement.PolicyID,
			entitlement.PositionID,
			entitlement.WorkCenterCode,
			existingID,
		)
		if err != nil {
			r.logger.Error(
				"Failed to update existing policy entitlement",
				util.String("entitlement_id", existingID.String()),
				util.ErrorField(err),
			)
			return fmt.Errorf("failed to update existing policy entitlement: %w", err)
		}
		return nil
	}

	if !errors.Is(err, sql.ErrNoRows) {
		r.logger.Error(
			"Failed to check existing policy entitlement",
			util.String("user_id", entitlement.UserID.String()),
			util.ErrorField(err),
		)
		return fmt.Errorf("failed to check existing policy entitlement: %w", err)
	}

	// Insert new
	insertQuery := `
		INSERT INTO leave.leave_entitlement (
			entitlement_id,
			company_id,
			user_id,
			leave_type_id,
			total_days,
			effective_from,
			effective_to,
			created_at,
			policy_id,
			source,
			position_id,
			work_center_code,
			updated_at
		) VALUES (
			$1, $2, $3, $4,
			$5, $6, NULL, $7,
			$8, $9,
			$10, $11, $12
		)
	`

	_, err = r.client.Exec(ctx, insertQuery,
		entitlement.EntitlementID,
		entitlement.CompanyID,
		entitlement.UserID,
		entitlement.LeaveTypeID,
		entitlement.TotalDays,
		entitlement.EffectiveFrom,
		entitlement.CreatedAt,
		entitlement.PolicyID,
		entitlement.Source,
		entitlement.PositionID,
		entitlement.WorkCenterCode,
		entitlement.UpdatedAt,
	)

	if err != nil {
		r.logger.Error(
			"Failed to create policy leave entitlement",
			util.String("user_id", entitlement.UserID.String()),
			util.String("leave_type_id", entitlement.LeaveTypeID.String()),
			util.ErrorField(err),
		)
		return fmt.Errorf("failed to create policy leave entitlement: %w", err)
	}

	return nil
}

func (r *leaveRepository) EndActivePolicyEntitlements(
	ctx context.Context,
	companyID uuid.UUID,
	userID uuid.UUID,
	endDate time.Time,
	positionID *uuid.UUID,
) error {
	query := `
		UPDATE leave.leave_entitlement
		SET effective_to = $3, updated_at = NOW()
		WHERE company_id = $1
		AND user_id = $2
		AND source = 'policy'
		AND (effective_to IS NULL OR effective_to > $3)
		AND (position_id IS NOT DISTINCT FROM $4 OR $4 IS NULL)
	`

	result, err := r.client.Exec(ctx, query, companyID, userID, endDate, positionID)
	if err != nil {
		r.logger.Error("Failed to end active policy entitlements",
			util.String("company_id", companyID.String()),
			util.String("user_id", userID.String()),
			util.ErrorField(err))
		return fmt.Errorf("failed to end active policy entitlements: %w", err)
	}

	rowsAffected, _ := result.RowsAffected()
	r.logger.Info("Ended policy entitlements",
		util.String("company_id", companyID.String()),
		util.String("user_id", userID.String()),
		util.Int("count", int(rowsAffected)))

	return nil
}

func (r *leaveRepository) EndActivePolicyEntitlementsByLeaveType(
	ctx context.Context,
	companyID uuid.UUID,
	userID uuid.UUID,
	leaveTypeID uuid.UUID,
	endDate time.Time,
	positionID *uuid.UUID,
) error {
	query := `
		UPDATE leave.leave_entitlement
		SET effective_to = $4, updated_at = NOW()
		WHERE company_id = $1
		AND user_id = $2
		AND leave_type_id = $3
		AND source = 'policy'
		AND (effective_to IS NULL OR effective_to > $4)
		AND (position_id IS NOT DISTINCT FROM $5 OR $5 IS NULL)
	`

	result, err := r.client.Exec(ctx, query, companyID, userID, leaveTypeID, endDate, positionID)
	if err != nil {
		r.logger.Error("Failed to end active policy entitlements by leave type",
			util.String("company_id", companyID.String()),
			util.String("user_id", userID.String()),
			util.String("leave_type_id", leaveTypeID.String()),
			util.ErrorField(err))
		return fmt.Errorf("failed to end active policy entitlements by leave type: %w", err)
	}

	rowsAffected, _ := result.RowsAffected()
	r.logger.Info("Ended policy entitlements by leave type",
		util.String("company_id", companyID.String()),
		util.String("user_id", userID.String()),
		util.String("leave_type_id", leaveTypeID.String()),
		util.Int("count", int(rowsAffected)))

	return nil
}

func (r *leaveRepository) CreateLeaveType(ctx context.Context, leaveType *models.LeaveType) error {
	if leaveType.LeaveTypeID == uuid.Nil {
		leaveType.LeaveTypeID = uuid.New()
	}
	if leaveType.CreatedAt.IsZero() {
		leaveType.CreatedAt = time.Now().UTC()
	}

	query := `
		INSERT INTO leave.leave_type (
			leave_type_id, company_id, code, name,
			is_paid, requires_approval, accrual_method,
			carry_forward_limit, created_at
		) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)
	`

	_, err := r.client.Exec(ctx, query,
		leaveType.LeaveTypeID,
		leaveType.CompanyID,
		leaveType.Code,
		leaveType.Name,
		leaveType.IsPaid,
		leaveType.RequiresApproval,
		leaveType.AccrualMethod,
		leaveType.CarryForwardLimit,
		leaveType.CreatedAt,
	)

	if err != nil {
		r.logger.Error("Failed to create leave type",
			util.String("company_id", leaveType.CompanyID.String()),
			util.String("code", leaveType.Code),
			util.ErrorField(err))
		return fmt.Errorf("failed to create leave type: %w", err)
	}

	return nil
}

func (r *leaveRepository) GetLeaveTypeByID(ctx context.Context, leaveTypeID uuid.UUID) (*models.LeaveType, error) {
	query := `
		SELECT
			leave_type_id,
			company_id,
			code,
			name,
			is_paid,
			requires_approval,
			accrual_method,
			carry_forward_limit,
			created_at
		FROM leave.leave_type
		WHERE leave_type_id = $1
	`

	row := r.client.QueryRow(ctx, query, leaveTypeID)
	var leaveType models.LeaveType
	var carryForwardLimit sql.NullInt32

	err := row.Scan(
		&leaveType.LeaveTypeID,
		&leaveType.CompanyID,
		&leaveType.Code,
		&leaveType.Name,
		&leaveType.IsPaid,
		&leaveType.RequiresApproval,
		&leaveType.AccrualMethod,
		&carryForwardLimit,
		&leaveType.CreatedAt,
	)

	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, nil
		}
		r.logger.Error("Failed to get leave type",
			util.String("leave_type_id", leaveTypeID.String()),
			util.ErrorField(err))
		return nil, fmt.Errorf("failed to get leave type: %w", err)
	}

	if carryForwardLimit.Valid {
		limit := int(carryForwardLimit.Int32)
		leaveType.CarryForwardLimit = &limit
	}

	return &leaveType, nil
}

func (r *leaveRepository) GetLeaveTypeByCode(ctx context.Context, companyID uuid.UUID, code string) (*models.LeaveType, error) {
	query := `
		SELECT
			leave_type_id,
			company_id,
			code,
			name,
			is_paid,
			requires_approval,
			accrual_method,
			carry_forward_limit,
			created_at
		FROM leave.leave_type
		WHERE company_id = $1 AND code = $2
	`

	row := r.client.QueryRow(ctx, query, companyID, code)
	var leaveType models.LeaveType
	var carryForwardLimit sql.NullInt32

	err := row.Scan(
		&leaveType.LeaveTypeID,
		&leaveType.CompanyID,
		&leaveType.Code,
		&leaveType.Name,
		&leaveType.IsPaid,
		&leaveType.RequiresApproval,
		&leaveType.AccrualMethod,
		&carryForwardLimit,
		&leaveType.CreatedAt,
	)

	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, nil
		}
		r.logger.Error("Failed to get leave type by code",
			util.String("company_id", companyID.String()),
			util.String("code", code),
			util.ErrorField(err))
		return nil, fmt.Errorf("failed to get leave type: %w", err)
	}

	if carryForwardLimit.Valid {
		limit := int(carryForwardLimit.Int32)
		leaveType.CarryForwardLimit = &limit
	}

	return &leaveType, nil
}

func (r *leaveRepository) GetLeaveTypesByCompany(ctx context.Context, companyID uuid.UUID) ([]*models.LeaveType, error) {
	query := `
		SELECT
			leave_type_id,
			company_id,
			code,
			name,
			is_paid,
			requires_approval,
			accrual_method,
			carry_forward_limit,
			created_at
		FROM leave.leave_type
		WHERE company_id = $1
		ORDER BY code
	`

	rows, err := r.client.Query(ctx, query, companyID)
	if err != nil {
		r.logger.Error("Failed to get leave types by company",
			util.String("company_id", companyID.String()),
			util.ErrorField(err))
		return nil, fmt.Errorf("failed to get leave types: %w", err)
	}
	defer rows.Close()

	var leaveTypes []*models.LeaveType
	for rows.Next() {
		var leaveType models.LeaveType
		var carryForwardLimit sql.NullInt32

		err := rows.Scan(
			&leaveType.LeaveTypeID,
			&leaveType.CompanyID,
			&leaveType.Code,
			&leaveType.Name,
			&leaveType.IsPaid,
			&leaveType.RequiresApproval,
			&leaveType.AccrualMethod,
			&carryForwardLimit,
			&leaveType.CreatedAt,
		)
		if err != nil {
			return nil, fmt.Errorf("failed to scan leave type: %w", err)
		}

		if carryForwardLimit.Valid {
			limit := int(carryForwardLimit.Int32)
			leaveType.CarryForwardLimit = &limit
		}

		leaveTypes = append(leaveTypes, &leaveType)
	}

	if err = rows.Err(); err != nil {
		return nil, fmt.Errorf("rows iteration error: %w", err)
	}

	return leaveTypes, nil
}

func (r *leaveRepository) UpdateLeaveType(ctx context.Context, leaveTypeID uuid.UUID, update *models.LeaveTypeUpdate) error {
	var setClauses []string
	var args []interface{}
	argIdx := 1

	if update.Name != nil {
		setClauses = append(setClauses, fmt.Sprintf("name = $%d", argIdx))
		args = append(args, *update.Name)
		argIdx++
	}
	if update.IsPaid != nil {
		setClauses = append(setClauses, fmt.Sprintf("is_paid = $%d", argIdx))
		args = append(args, *update.IsPaid)
		argIdx++
	}
	if update.RequiresApproval != nil {
		setClauses = append(setClauses, fmt.Sprintf("requires_approval = $%d", argIdx))
		args = append(args, *update.RequiresApproval)
		argIdx++
	}
	if update.AccrualMethod != nil {
		setClauses = append(setClauses, fmt.Sprintf("accrual_method = $%d", argIdx))
		args = append(args, *update.AccrualMethod)
		argIdx++
	}
	if update.CarryForwardLimit != nil {
		setClauses = append(setClauses, fmt.Sprintf("carry_forward_limit = $%d", argIdx))
		args = append(args, *update.CarryForwardLimit)
		argIdx++
	}

	if len(setClauses) == 0 {
		return nil
	}

	query := fmt.Sprintf(`
		UPDATE leave.leave_type
		SET %s
		WHERE leave_type_id = $%d
	`, strings.Join(setClauses, ", "), argIdx)

	args = append(args, leaveTypeID)
	result, err := r.client.Exec(ctx, query, args...)
	if err != nil {
		r.logger.Error("Failed to update leave type",
			util.String("leave_type_id", leaveTypeID.String()),
			util.ErrorField(err))
		return fmt.Errorf("failed to update leave type: %w", err)
	}

	rowsAffected, _ := result.RowsAffected()
	if rowsAffected == 0 {
		return fmt.Errorf("leave type not found")
	}

	return nil
}

func (r *leaveRepository) DeleteLeaveType(ctx context.Context, leaveTypeID uuid.UUID) error {
	query := `
		DELETE FROM leave.leave_type
		WHERE leave_type_id = $1
	`

	result, err := r.client.Exec(ctx, query, leaveTypeID)
	if err != nil {
		r.logger.Error("Failed to delete leave type",
			util.String("leave_type_id", leaveTypeID.String()),
			util.ErrorField(err))
		return fmt.Errorf("failed to delete leave type: %w", err)
	}

	rowsAffected, _ := result.RowsAffected()
	if rowsAffected == 0 {
		return fmt.Errorf("leave type not found")
	}

	return nil
}

func (r *leaveRepository) CreateLeaveEntitlement(
	ctx context.Context,
	entitlement *models.LeaveEntitlement,
) error {
	if entitlement.EntitlementID == uuid.Nil {
		entitlement.EntitlementID = uuid.New()
	}
	if entitlement.CreatedAt.IsZero() {
		entitlement.CreatedAt = time.Now().UTC()
	}
	if entitlement.Source == "" {
		entitlement.Source = "manual"
	}
	if entitlement.UpdatedAt == nil {
		now := time.Now().UTC()
		entitlement.UpdatedAt = &now
	}

	query := `
		INSERT INTO leave.leave_entitlement (
			entitlement_id,
			company_id,
			user_id,
			leave_type_id,
			total_days,
			effective_from,
			effective_to,
			created_at,
			policy_id,
			source,
			position_id,
			work_center_code,
			updated_at
		) VALUES (
			$1, $2, $3, $4,
			$5, $6, $7, $8,
			$9, $10,
			$11, $12, $13
		)
	`

	_, err := r.client.Exec(ctx, query,
		entitlement.EntitlementID,
		entitlement.CompanyID,
		entitlement.UserID,
		entitlement.LeaveTypeID,
		entitlement.TotalDays,
		entitlement.EffectiveFrom,
		entitlement.EffectiveTo,
		entitlement.CreatedAt,
		entitlement.PolicyID,
		entitlement.Source,
		entitlement.PositionID,
		entitlement.WorkCenterCode,
		entitlement.UpdatedAt,
	)

	if err != nil {
		r.logger.Error(
			"Failed to create leave entitlement",
			util.String("user_id", entitlement.UserID.String()),
			util.String("leave_type_id", entitlement.LeaveTypeID.String()),
			util.ErrorField(err),
		)
		return fmt.Errorf("failed to create leave entitlement: %w", err)
	}

	return nil
}

func (r *leaveRepository) GetLeaveEntitlementByID(ctx context.Context, entitlementID uuid.UUID) (*models.LeaveEntitlement, error) {
	query := `
		SELECT
			entitlement_id,
			company_id,
			user_id,
			leave_type_id,
			total_days,
			effective_from,
			effective_to,
			created_at,
			policy_id,
			source,
			updated_at,
			position_id,
			work_center_code
		FROM leave.leave_entitlement
		WHERE entitlement_id = $1
	`

	row := r.client.QueryRow(ctx, query, entitlementID)
	var entitlement models.LeaveEntitlement
	var effectiveTo sql.NullTime
	var positionID sql.NullString
	var workCenterCode sql.NullString
	var policyID sql.NullString
	var updatedAt sql.NullTime

	err := row.Scan(
		&entitlement.EntitlementID,
		&entitlement.CompanyID,
		&entitlement.UserID,
		&entitlement.LeaveTypeID,
		&entitlement.TotalDays,
		&entitlement.EffectiveFrom,
		&effectiveTo,
		&entitlement.CreatedAt,
		&policyID,
		&entitlement.Source,
		&updatedAt,
		&positionID,
		&workCenterCode,
	)

	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, nil
		}
		r.logger.Error("Failed to get leave entitlement",
			util.String("entitlement_id", entitlementID.String()),
			util.ErrorField(err))
		return nil, fmt.Errorf("failed to get leave entitlement: %w", err)
	}

	if effectiveTo.Valid {
		entitlement.EffectiveTo = &effectiveTo.Time
	}
	if policyID.Valid && policyID.String != "" {
		pid, err := uuid.Parse(policyID.String)
		if err == nil {
			entitlement.PolicyID = &pid
		}
	}
	if positionID.Valid && positionID.String != "" {
		pid, err := uuid.Parse(positionID.String)
		if err == nil {
			entitlement.PositionID = &pid
		}
	}
	if workCenterCode.Valid {
		entitlement.WorkCenterCode = &workCenterCode.String
	}
	if updatedAt.Valid {
		entitlement.UpdatedAt = &updatedAt.Time
	}

	return &entitlement, nil
}

func (r *leaveRepository) GetLeaveEntitlementsByUser(
	ctx context.Context,
	userID uuid.UUID,
	positionID *uuid.UUID,
) ([]*models.LeaveEntitlement, error) {

	query := `
		SELECT
			entitlement_id,
			company_id,
			user_id,
			leave_type_id,
			total_days,
			effective_from,
			effective_to,
			created_at,
			policy_id,
			source,
			updated_at,
			position_id,
			work_center_code
		FROM leave.leave_entitlement
		WHERE user_id = $1
		AND (effective_to IS NULL OR effective_to >= CURRENT_DATE)
		AND (position_id IS NOT DISTINCT FROM $2 OR $2 IS NULL)
		ORDER BY effective_from DESC
	`

	rows, err := r.client.Query(ctx, query, userID, positionID)
	if err != nil {
		r.logger.Error(
			"Failed to get leave entitlements by user",
			util.String("user_id", userID.String()),
			util.ErrorField(err),
		)
		return nil, fmt.Errorf("failed to get leave entitlements: %w", err)
	}
	defer rows.Close()

	var entitlements []*models.LeaveEntitlement

	for rows.Next() {
		var entitlement models.LeaveEntitlement
		var effectiveTo sql.NullTime
		var positionIDDB sql.NullString
		var workCenterCode sql.NullString
		var policyID sql.NullString
		var updatedAt sql.NullTime

		err := rows.Scan(
			&entitlement.EntitlementID,
			&entitlement.CompanyID,
			&entitlement.UserID,
			&entitlement.LeaveTypeID,
			&entitlement.TotalDays,
			&entitlement.EffectiveFrom,
			&effectiveTo,
			&entitlement.CreatedAt,
			&policyID,
			&entitlement.Source,
			&updatedAt,
			&positionIDDB,
			&workCenterCode,
		)
		if err != nil {
			return nil, fmt.Errorf("failed to scan leave entitlement: %w", err)
		}

		if effectiveTo.Valid {
			entitlement.EffectiveTo = &effectiveTo.Time
		}
		if policyID.Valid && policyID.String != "" {
			if pid, err := uuid.Parse(policyID.String); err == nil {
				entitlement.PolicyID = &pid
			}
		}
		if positionIDDB.Valid && positionIDDB.String != "" {
			if pid, err := uuid.Parse(positionIDDB.String); err == nil {
				entitlement.PositionID = &pid
			}
		}
		if workCenterCode.Valid {
			entitlement.WorkCenterCode = &workCenterCode.String
		}
		if updatedAt.Valid {
			entitlement.UpdatedAt = &updatedAt.Time
		}

		entitlements = append(entitlements, &entitlement)
	}

	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("rows iteration error: %w", err)
	}

	return entitlements, nil
}
func (r *leaveRepository) GetLeaveQuota(
	ctx context.Context,
	userID uuid.UUID,
	leaveTypeID uuid.UUID,
	positionID *uuid.UUID,
) (totalDays int, availableDays float64, err error) {
	query := `
		SELECT
			COALESCE(le.total_days, 0) as total_days,
			COALESCE(SUM(
				CASE ll.entry_type
					WHEN 'accrual' THEN ll.days
					WHEN 'reversal' THEN ll.days
					WHEN 'consumption' THEN -ll.days
					ELSE 0
				END
			), 0) as available_days
		FROM leave.leave_entitlement le
		LEFT JOIN leave.leave_ledger ll ON le.entitlement_id = ll.entitlement_id
		WHERE le.user_id = $1
		  AND le.leave_type_id = $2
		  AND le.effective_from <= CURRENT_DATE
		  AND (le.effective_to IS NULL OR le.effective_to >= CURRENT_DATE)
		  AND (le.position_id IS NOT DISTINCT FROM $3 OR $3 IS NULL)
		GROUP BY le.entitlement_id, le.total_days
		LIMIT 1
	`
	row := r.client.QueryRow(ctx, query, userID, leaveTypeID, positionID)
	err = row.Scan(&totalDays, &availableDays)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return 0, 0, nil
		}
		r.logger.Error(
			"Failed to get leave quota",
			util.String("user_id", userID.String()),
			util.String("leave_type_id", leaveTypeID.String()),
			util.ErrorField(err),
		)
		return 0, 0, fmt.Errorf("failed to get leave quota: %w", err)
	}
	return totalDays, availableDays, nil
}
func (r *leaveRepository) GetLeaveEntitlementsByCompany(ctx context.Context, companyID uuid.UUID, page, pageSize int) ([]*models.LeaveEntitlement, int64, error) {
	offset := (page - 1) * pageSize

	countQuery := `
		SELECT COUNT(*) FROM leave.leave_entitlement
		WHERE company_id = $1
	`

	row := r.client.QueryRow(ctx, countQuery, companyID)
	var total int64
	err := row.Scan(&total)
	if err != nil {
		return nil, 0, fmt.Errorf("failed to count leave entitlements: %w", err)
	}

	query := `
		SELECT
			entitlement_id,
			company_id,
			user_id,
			leave_type_id,
			total_days,
			effective_from,
			effective_to,
			created_at,
			policy_id,
			source,
			updated_at,
			position_id,
			work_center_code
		FROM leave.leave_entitlement
		WHERE company_id = $1
		ORDER BY created_at DESC
		LIMIT $2 OFFSET $3
	`

	rows, err := r.client.Query(ctx, query, companyID, pageSize, offset)
	if err != nil {
		r.logger.Error("Failed to get leave entitlements by company",
			util.String("company_id", companyID.String()),
			util.ErrorField(err))
		return nil, 0, fmt.Errorf("failed to get leave entitlements: %w", err)
	}
	defer rows.Close()

	var entitlements []*models.LeaveEntitlement
	for rows.Next() {
		var entitlement models.LeaveEntitlement
		var effectiveTo sql.NullTime
		var positionID sql.NullString
		var workCenterCode sql.NullString
		var policyID sql.NullString
		var updatedAt sql.NullTime

		err := rows.Scan(
			&entitlement.EntitlementID,
			&entitlement.CompanyID,
			&entitlement.UserID,
			&entitlement.LeaveTypeID,
			&entitlement.TotalDays,
			&entitlement.EffectiveFrom,
			&effectiveTo,
			&entitlement.CreatedAt,
			&policyID,
			&entitlement.Source,
			&updatedAt,
			&positionID,
			&workCenterCode,
		)
		if err != nil {
			return nil, 0, fmt.Errorf("failed to scan leave entitlement: %w", err)
		}

		if effectiveTo.Valid {
			entitlement.EffectiveTo = &effectiveTo.Time
		}
		if policyID.Valid && policyID.String != "" {
			pid, err := uuid.Parse(policyID.String)
			if err == nil {
				entitlement.PolicyID = &pid
			}
		}
		if positionID.Valid && positionID.String != "" {
			pid, err := uuid.Parse(positionID.String)
			if err == nil {
				entitlement.PositionID = &pid
			}
		}
		if workCenterCode.Valid {
			entitlement.WorkCenterCode = &workCenterCode.String
		}
		if updatedAt.Valid {
			entitlement.UpdatedAt = &updatedAt.Time
		}

		entitlements = append(entitlements, &entitlement)
	}

	if err = rows.Err(); err != nil {
		return nil, 0, fmt.Errorf("rows iteration error: %w", err)
	}

	return entitlements, total, nil
}

func (r *leaveRepository) UpdateLeaveEntitlement(ctx context.Context, entitlementID uuid.UUID, update *models.LeaveEntitlementUpdate) error {
	var setClauses []string
	var args []interface{}
	argIdx := 1

	if update.TotalDays != nil {
		setClauses = append(setClauses, fmt.Sprintf("total_days = $%d", argIdx))
		args = append(args, *update.TotalDays)
		argIdx++
	}
	if update.EffectiveFrom != nil {
		setClauses = append(setClauses, fmt.Sprintf("effective_from = $%d", argIdx))
		args = append(args, *update.EffectiveFrom)
		argIdx++
	}
	if update.EffectiveTo != nil {
		setClauses = append(setClauses, fmt.Sprintf("effective_to = $%d", argIdx))
		args = append(args, *update.EffectiveTo)
		argIdx++
	}

	setClauses = append(setClauses, "updated_at = NOW()")

	query := fmt.Sprintf(`
		UPDATE leave.leave_entitlement
		SET %s
		WHERE entitlement_id = $%d
	`, strings.Join(setClauses, ", "), argIdx)

	args = append(args, entitlementID)
	result, err := r.client.Exec(ctx, query, args...)
	if err != nil {
		r.logger.Error("Failed to update leave entitlement",
			util.String("entitlement_id", entitlementID.String()),
			util.ErrorField(err))
		return fmt.Errorf("failed to update leave entitlement: %w", err)
	}

	rowsAffected, _ := result.RowsAffected()
	if rowsAffected == 0 {
		return fmt.Errorf("leave entitlement not found")
	}

	return nil
}

func (r *leaveRepository) EndLeaveEntitlement(ctx context.Context, entitlementID uuid.UUID, endDate time.Time) error {
	query := `
		UPDATE leave.leave_entitlement
		SET effective_to = $1, updated_at = NOW()
		WHERE entitlement_id = $2
		AND (effective_to IS NULL OR effective_to > $1)
	`

	result, err := r.client.Exec(ctx, query, endDate, entitlementID)
	if err != nil {
		r.logger.Error("Failed to end leave entitlement",
			util.String("entitlement_id", entitlementID.String()),
			util.ErrorField(err))
		return fmt.Errorf("failed to end leave entitlement: %w", err)
	}

	rowsAffected, _ := result.RowsAffected()
	if rowsAffected == 0 {
		return fmt.Errorf("leave entitlement not found or already ended")
	}

	return nil
}

func (r *leaveRepository) CreateLeaveAccrual(ctx context.Context, accrual *models.LeaveAccrual) error {
	if accrual.AccrualID == uuid.Nil {
		accrual.AccrualID = uuid.New()
	}
	if accrual.CreatedAt.IsZero() {
		accrual.CreatedAt = time.Now().UTC()
	}

	query := `
		INSERT INTO leave.leave_accrual (
			accrual_id, entitlement_id, accrual_date,
			days_accrued, fractional_days, created_at
		) VALUES ($1, $2, $3, $4, $5, $6)
		ON CONFLICT (entitlement_id, accrual_date) DO NOTHING
	`

	_, err := r.client.Exec(ctx, query,
		accrual.AccrualID,
		accrual.EntitlementID,
		accrual.AccrualDate,
		accrual.DaysAccrued,
		accrual.FractionalDays,
		accrual.CreatedAt,
	)

	if err != nil {
		r.logger.Error("Failed to create leave accrual",
			util.String("entitlement_id", accrual.EntitlementID.String()),
			util.ErrorField(err))
		return fmt.Errorf("failed to create leave accrual: %w", err)
	}

	return nil
}

func (r *leaveRepository) CreateBulkLeaveAccruals(ctx context.Context, accruals []*models.LeaveAccrual) error {
	tx, err := r.client.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("failed to begin transaction: %w", err)
	}
	defer func() {
		if err != nil {
			tx.Rollback()
		}
	}()

	query := `
		INSERT INTO leave.leave_accrual (
			accrual_id, entitlement_id, accrual_date,
			days_accrued, fractional_days, created_at
		) VALUES ($1, $2, $3, $4, $5, $6)
		ON CONFLICT (entitlement_id, accrual_date) DO NOTHING
	`

	stmt, err := tx.Prepare(query)
	if err != nil {
		return fmt.Errorf("failed to prepare statement: %w", err)
	}
	defer stmt.Close()

	for _, accrual := range accruals {
		if accrual.AccrualID == uuid.Nil {
			accrual.AccrualID = uuid.New()
		}
		if accrual.CreatedAt.IsZero() {
			accrual.CreatedAt = time.Now().UTC()
		}

		_, err := stmt.ExecContext(ctx,
			accrual.AccrualID,
			accrual.EntitlementID,
			accrual.AccrualDate,
			accrual.DaysAccrued,
			accrual.FractionalDays,
			accrual.CreatedAt,
		)
		if err != nil {
			return fmt.Errorf("failed to insert accrual %s: %w", accrual.AccrualID, err)
		}
	}

	if err := tx.Commit(); err != nil {
		return fmt.Errorf("failed to commit transaction: %w", err)
	}

	return nil
}

func (r *leaveRepository) GetLeaveAccrualsByEntitlement(ctx context.Context, entitlementID uuid.UUID) ([]*models.LeaveAccrual, error) {
	query := `
		SELECT
			accrual_id,
			entitlement_id,
			accrual_date,
			days_accrued,
			fractional_days,
			created_at,
			cumulative_balance
		FROM leave.leave_accrual
		WHERE entitlement_id = $1
		ORDER BY accrual_date
	`

	rows, err := r.client.Query(ctx, query, entitlementID)
	if err != nil {
		r.logger.Error("Failed to get leave accruals by entitlement",
			util.String("entitlement_id", entitlementID.String()),
			util.ErrorField(err))
		return nil, fmt.Errorf("failed to get leave accruals: %w", err)
	}
	defer rows.Close()

	var accruals []*models.LeaveAccrual
	for rows.Next() {
		var accrual models.LeaveAccrual
		err := rows.Scan(
			&accrual.AccrualID,
			&accrual.EntitlementID,
			&accrual.AccrualDate,
			&accrual.DaysAccrued,
			&accrual.FractionalDays,
			&accrual.CreatedAt,
			&accrual.CumulativeBalance,
		)
		if err != nil {
			return nil, fmt.Errorf("failed to scan leave accrual: %w", err)
		}
		accruals = append(accruals, &accrual)
	}

	if err = rows.Err(); err != nil {
		return nil, fmt.Errorf("rows iteration error: %w", err)
	}

	return accruals, nil
}

func (r *leaveRepository) GetLeaveAccrualsByDate(ctx context.Context, companyID uuid.UUID, date time.Time) ([]*models.LeaveAccrual, error) {
	query := `
		SELECT
			la.accrual_id,
			la.entitlement_id,
			la.accrual_date,
			la.days_accrued,
			la.fractional_days,
			la.created_at,
			la.cumulative_balance
		FROM leave.leave_accrual la
		JOIN leave.leave_entitlement le ON la.entitlement_id = le.entitlement_id
		WHERE le.company_id = $1
		AND la.accrual_date = $2
		ORDER BY le.user_id, la.accrual_date
	`

	rows, err := r.client.Query(ctx, query, companyID, date)
	if err != nil {
		r.logger.Error("Failed to get leave accruals by date",
			util.String("company_id", companyID.String()),
			util.Time("date", date),
			util.ErrorField(err))
		return nil, fmt.Errorf("failed to get leave accruals: %w", err)
	}
	defer rows.Close()

	var accruals []*models.LeaveAccrual
	for rows.Next() {
		var accrual models.LeaveAccrual
		err := rows.Scan(
			&accrual.AccrualID,
			&accrual.EntitlementID,
			&accrual.AccrualDate,
			&accrual.DaysAccrued,
			&accrual.FractionalDays,
			&accrual.CreatedAt,
			&accrual.CumulativeBalance,
		)
		if err != nil {
			return nil, fmt.Errorf("failed to scan leave accrual: %w", err)
		}
		accruals = append(accruals, &accrual)
	}

	if err = rows.Err(); err != nil {
		return nil, fmt.Errorf("rows iteration error: %w", err)
	}

	return accruals, nil
}

func (r *leaveRepository) GetTotalAccruedDays(ctx context.Context, entitlementID uuid.UUID) (float64, error) {
	query := `
		SELECT COALESCE(SUM(cumulative_balance), 0)
		FROM leave.leave_accrual
		WHERE entitlement_id = $1
	`

	row := r.client.QueryRow(ctx, query, entitlementID)
	var total float64
	err := row.Scan(&total)
	if err != nil {
		r.logger.Error("Failed to get total accrued days",
			util.String("entitlement_id", entitlementID.String()),
			util.ErrorField(err))
		return 0, fmt.Errorf("failed to get total accrued days: %w", err)
	}

	return total, nil
}

func (r *leaveRepository) CreateLeaveRequest(ctx context.Context, request *models.LeaveRequest) error {
	if request.LeaveRequestID == uuid.Nil {
		request.LeaveRequestID = uuid.New()
	}
	if request.RequestedAt.IsZero() {
		request.RequestedAt = time.Now().UTC()
	}

	query := `
		INSERT INTO leave.leave_request (
			leave_request_id, company_id, user_id, leave_type_id,
			start_date, end_date, total_days, status,
			requested_by, approved_by, requested_at, approved_at
		) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12)
	`

	_, err := r.client.Exec(ctx, query,
		request.LeaveRequestID,
		request.CompanyID,
		request.UserID,
		request.LeaveTypeID,
		request.StartDate,
		request.EndDate,
		request.TotalDays,
		request.Status,
		request.RequestedBy,
		request.ApprovedBy,
		request.RequestedAt,
		request.ApprovedAt,
	)

	if err != nil {
		r.logger.Error("Failed to create leave request",
			util.String("user_id", request.UserID.String()),
			util.String("leave_type_id", request.LeaveTypeID.String()),
			util.ErrorField(err))
		return fmt.Errorf("failed to create leave request: %w", err)
	}

	return nil
}

func (r *leaveRepository) GetLeaveRequestByID(ctx context.Context, requestID uuid.UUID) (*models.LeaveRequest, error) {
	query := `
		SELECT
			leave_request_id,
			company_id,
			user_id,
			leave_type_id,
			start_date,
			end_date,
			total_days,
			status,
			requested_by,
			approved_by,
			requested_at,
			approved_at
		FROM leave.leave_request
		WHERE leave_request_id = $1
	`

	row := r.client.QueryRow(ctx, query, requestID)
	var request models.LeaveRequest
	var approvedBy sql.NullString
	var approvedAt sql.NullTime

	err := row.Scan(
		&request.LeaveRequestID,
		&request.CompanyID,
		&request.UserID,
		&request.LeaveTypeID,
		&request.StartDate,
		&request.EndDate,
		&request.TotalDays,
		&request.Status,
		&request.RequestedBy,
		&approvedBy,
		&request.RequestedAt,
		&approvedAt,
	)

	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, nil
		}
		r.logger.Error("Failed to get leave request",
			util.String("leave_request_id", requestID.String()),
			util.ErrorField(err))
		return nil, fmt.Errorf("failed to get leave request: %w", err)
	}

	if approvedBy.Valid && approvedBy.String != "" {
		id, err := uuid.Parse(approvedBy.String)
		if err == nil {
			request.ApprovedBy = &id
		}
	}
	if approvedAt.Valid {
		request.ApprovedAt = &approvedAt.Time
	}

	return &request, nil
}

func (r *leaveRepository) GetLeaveRequestsByUser(ctx context.Context, userID uuid.UUID, startDate, endDate time.Time) ([]*models.LeaveRequest, error) {
	query := `
		SELECT
			leave_request_id,
			company_id,
			user_id,
			leave_type_id,
			start_date,
			end_date,
			total_days,
			status,
			requested_by,
			approved_by,
			requested_at,
			approved_at
		FROM leave.leave_request
		WHERE user_id = $1
		AND (
			(start_date BETWEEN $2 AND $3)
			OR (end_date BETWEEN $2 AND $3)
			OR ($2 BETWEEN start_date AND end_date)
		)
		ORDER BY start_date DESC
	`

	rows, err := r.client.Query(ctx, query, userID, startDate, endDate)
	if err != nil {
		r.logger.Error("Failed to get leave requests by user",
			util.String("user_id", userID.String()),
			util.ErrorField(err))
		return nil, fmt.Errorf("failed to get leave requests: %w", err)
	}
	defer rows.Close()

	var requests []*models.LeaveRequest
	for rows.Next() {
		var request models.LeaveRequest
		var approvedBy sql.NullString
		var approvedAt sql.NullTime

		err := rows.Scan(
			&request.LeaveRequestID,
			&request.CompanyID,
			&request.UserID,
			&request.LeaveTypeID,
			&request.StartDate,
			&request.EndDate,
			&request.TotalDays,
			&request.Status,
			&request.RequestedBy,
			&approvedBy,
			&request.RequestedAt,
			&approvedAt,
		)
		if err != nil {
			return nil, fmt.Errorf("failed to scan leave request: %w", err)
		}

		if approvedBy.Valid && approvedBy.String != "" {
			id, err := uuid.Parse(approvedBy.String)
			if err == nil {
				request.ApprovedBy = &id
			}
		}
		if approvedAt.Valid {
			request.ApprovedAt = &approvedAt.Time
		}

		requests = append(requests, &request)
	}

	if err = rows.Err(); err != nil {
		return nil, fmt.Errorf("rows iteration error: %w", err)
	}

	return requests, nil
}

func (r *leaveRepository) GetLeaveRequestsByCompany(ctx context.Context, filter models.LeaveRequestFilter) ([]*models.LeaveRequest, int64, error) {
	var conditions []string
	var args []interface{}
	argIdx := 1

	conditions = append(conditions, fmt.Sprintf("company_id = $%d", argIdx))
	args = append(args, filter.CompanyID)
	argIdx++

	if filter.UserID != nil {
		conditions = append(conditions, fmt.Sprintf("user_id = $%d", argIdx))
		args = append(args, *filter.UserID)
		argIdx++
	}
	if filter.LeaveTypeID != nil {
		conditions = append(conditions, fmt.Sprintf("leave_type_id = $%d", argIdx))
		args = append(args, *filter.LeaveTypeID)
		argIdx++
	}
	if filter.Status != nil {
		conditions = append(conditions, fmt.Sprintf("status = $%d", argIdx))
		args = append(args, *filter.Status)
		argIdx++
	}
	if filter.StartDate != nil && filter.EndDate != nil {
		conditions = append(conditions, fmt.Sprintf("start_date BETWEEN $%d AND $%d", argIdx, argIdx+1))
		args = append(args, *filter.StartDate, *filter.EndDate)
		argIdx += 2
	}

	whereClause := ""
	if len(conditions) > 0 {
		whereClause = "WHERE " + strings.Join(conditions, " AND ")
	}

	countQuery := fmt.Sprintf(`
		SELECT COUNT(*) FROM leave.leave_request
		%s
	`, whereClause)

	row := r.client.QueryRow(ctx, countQuery, args...)
	var total int64
	err := row.Scan(&total)
	if err != nil {
		return nil, 0, fmt.Errorf("failed to count leave requests: %w", err)
	}

	offset := (filter.Page - 1) * filter.PageSize
	query := fmt.Sprintf(`
		SELECT
			leave_request_id,
			company_id,
			user_id,
			leave_type_id,
			start_date,
			end_date,
			total_days,
			status,
			requested_by,
			approved_by,
			requested_at,
			approved_at
		FROM leave.leave_request
		%s
		ORDER BY requested_at DESC
		LIMIT $%d OFFSET $%d
	`, whereClause, argIdx, argIdx+1)

	args = append(args, filter.PageSize, offset)
	rows, err := r.client.Query(ctx, query, args...)
	if err != nil {
		r.logger.Error("Failed to get leave requests by company",
			util.String("company_id", filter.CompanyID.String()),
			util.ErrorField(err))
		return nil, 0, fmt.Errorf("failed to get leave requests: %w", err)
	}
	defer rows.Close()

	var requests []*models.LeaveRequest
	for rows.Next() {
		var request models.LeaveRequest
		var approvedBy sql.NullString
		var approvedAt sql.NullTime

		err := rows.Scan(
			&request.LeaveRequestID,
			&request.CompanyID,
			&request.UserID,
			&request.LeaveTypeID,
			&request.StartDate,
			&request.EndDate,
			&request.TotalDays,
			&request.Status,
			&request.RequestedBy,
			&approvedBy,
			&request.RequestedAt,
			&approvedAt,
		)
		if err != nil {
			return nil, 0, fmt.Errorf("failed to scan leave request: %w", err)
		}

		if approvedBy.Valid && approvedBy.String != "" {
			id, err := uuid.Parse(approvedBy.String)
			if err == nil {
				request.ApprovedBy = &id
			}
		}
		if approvedAt.Valid {
			request.ApprovedAt = &approvedAt.Time
		}

		requests = append(requests, &request)
	}

	if err = rows.Err(); err != nil {
		return nil, 0, fmt.Errorf("rows iteration error: %w", err)
	}

	return requests, total, nil
}

func (r *leaveRepository) GetPendingLeaveRequests(ctx context.Context, companyID uuid.UUID, approverID uuid.UUID) ([]*models.LeaveRequest, error) {
	query := `
		SELECT
			lr.leave_request_id,
			lr.company_id,
			lr.user_id,
			lr.leave_type_id,
			lr.start_date,
			lr.end_date,
			lr.total_days,
			lr.status,
			lr.requested_by,
			lr.approved_by,
			lr.requested_at,
			lr.approved_at
		FROM leave.leave_request lr
		JOIN leave.leave_type lt ON lr.leave_type_id = lt.leave_type_id
		WHERE lr.company_id = $1
		AND lr.status = 'pending'
		AND lt.requires_approval = true
		ORDER BY lr.requested_at
	`

	rows, err := r.client.Query(ctx, query, companyID)
	if err != nil {
		r.logger.Error("Failed to get pending leave requests",
			util.String("company_id", companyID.String()),
			util.ErrorField(err))
		return nil, fmt.Errorf("failed to get pending leave requests: %w", err)
	}
	defer rows.Close()

	var requests []*models.LeaveRequest
	for rows.Next() {
		var request models.LeaveRequest
		var approvedBy sql.NullString
		var approvedAt sql.NullTime

		err := rows.Scan(
			&request.LeaveRequestID,
			&request.CompanyID,
			&request.UserID,
			&request.LeaveTypeID,
			&request.StartDate,
			&request.EndDate,
			&request.TotalDays,
			&request.Status,
			&request.RequestedBy,
			&approvedBy,
			&request.RequestedAt,
			&approvedAt,
		)
		if err != nil {
			return nil, fmt.Errorf("failed to scan leave request: %w", err)
		}

		if approvedBy.Valid && approvedBy.String != "" {
			id, err := uuid.Parse(approvedBy.String)
			if err == nil {
				request.ApprovedBy = &id
			}
		}
		if approvedAt.Valid {
			request.ApprovedAt = &approvedAt.Time
		}

		requests = append(requests, &request)
	}

	if err = rows.Err(); err != nil {
		return nil, fmt.Errorf("rows iteration error: %w", err)
	}

	return requests, nil
}

func (r *leaveRepository) UpdateLeaveRequest(ctx context.Context, requestID uuid.UUID, update *models.LeaveRequestUpdate) error {
	var setClauses []string
	var args []interface{}
	argIdx := 1

	if update.Status != nil {
		setClauses = append(setClauses, fmt.Sprintf("status = $%d", argIdx))
		args = append(args, *update.Status)
		argIdx++
	}
	if update.ApprovedBy != nil {
		setClauses = append(setClauses, fmt.Sprintf("approved_by = $%d", argIdx))
		args = append(args, *update.ApprovedBy)
		argIdx++
	}
	if update.ApprovedAt != nil {
		setClauses = append(setClauses, fmt.Sprintf("approved_at = $%d", argIdx))
		args = append(args, *update.ApprovedAt)
		argIdx++
	}

	if len(setClauses) == 0 {
		return nil
	}

	query := fmt.Sprintf(`
		UPDATE leave.leave_request
		SET %s
		WHERE leave_request_id = $%d
	`, strings.Join(setClauses, ", "), argIdx)

	args = append(args, requestID)
	result, err := r.client.Exec(ctx, query, args...)
	if err != nil {
		r.logger.Error("Failed to update leave request",
			util.String("leave_request_id", requestID.String()),
			util.ErrorField(err))
		return fmt.Errorf("failed to update leave request: %w", err)
	}

	rowsAffected, _ := result.RowsAffected()
	if rowsAffected == 0 {
		return fmt.Errorf("leave request not found")
	}

	return nil
}

func (r *leaveRepository) CancelLeaveRequest(
	ctx context.Context,
	requestID uuid.UUID,
) error {

	tx, err := r.client.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("failed to begin transaction: %w", err)
	}
	defer func() {
		if err != nil {
			tx.Rollback()
		}
	}()

	// 1️⃣ Lock request
	query := `
		SELECT leave_request_id, status, start_date
		FROM leave.leave_request
		WHERE leave_request_id = $1
		FOR UPDATE
	`

	var status string
	var startDate time.Time

	err = tx.QueryRowContext(ctx, query, requestID).
		Scan(&requestID, &status, &startDate)

	if err != nil {
		return fmt.Errorf("leave request not found: %w", err)
	}

	today := time.Now().UTC().Truncate(24 * time.Hour)

	// 2️⃣ Validate state
	if status == "rejected" || status == "cancelled" {
		return fmt.Errorf("leave already closed")
	}

	if status == "approved" && !startDate.After(today) {
		return fmt.Errorf("cannot cancel leave that already started")
	}

	// 3️⃣ Update request status
	_, err = tx.ExecContext(ctx, `
		UPDATE leave.leave_request
		SET status = 'cancelled',
		    approved_at = NULL
		WHERE leave_request_id = $1
	`, requestID)

	if err != nil {
		return fmt.Errorf("failed to update leave request: %w", err)
	}

	// 4️⃣ If approved → reverse ledger
	if status == "approved" {

		reversalID := uuid.New()

		_, err = tx.ExecContext(ctx, `
			INSERT INTO leave.leave_ledger (
				ledger_id,
				entitlement_id,
				leave_request_id,
				entry_type,
				days,
				entry_date,
				created_at
			)
			SELECT
				$1,
				entitlement_id,
				leave_request_id,
				'reversal',
				days,
				NOW(),
				NOW()
			FROM leave.leave_ledger
			WHERE leave_request_id = $2
			AND entry_type = 'consumption'
		`, reversalID, requestID)

		if err != nil {
			return fmt.Errorf("failed to create reversal entry: %w", err)
		}
	}

	if err = tx.Commit(); err != nil {
		return fmt.Errorf("failed to commit transaction: %w", err)
	}

	return nil
}

func (r *leaveRepository) CheckLeaveOverlap(ctx context.Context, userID uuid.UUID, startDate, endDate time.Time, excludeRequestID *uuid.UUID) (bool, error) {
	query := `
		SELECT EXISTS (
			SELECT 1 FROM leave.leave_request
			WHERE user_id = $1
			AND status IN ('pending', 'approved')
			AND (
				(start_date BETWEEN $2 AND $3)
				OR (end_date BETWEEN $2 AND $3)
				OR ($2 BETWEEN start_date AND end_date)
			)
		)
	`

	args := []interface{}{userID, startDate, endDate}
	if excludeRequestID != nil {
		query = `
			SELECT EXISTS (
				SELECT 1 FROM leave.leave_request
				WHERE user_id = $1
				AND leave_request_id != $4
				AND status IN ('pending', 'approved')
				AND (
					(start_date BETWEEN $2 AND $3)
					OR (end_date BETWEEN $2 AND $3)
					OR ($2 BETWEEN start_date AND end_date)
				)
			)
		`
		args = append(args, *excludeRequestID)
	}

	row := r.client.QueryRow(ctx, query, args...)
	var exists bool
	err := row.Scan(&exists)
	if err != nil {
		r.logger.Error("Failed to check leave overlap",
			util.String("user_id", userID.String()),
			util.ErrorField(err))
		return false, fmt.Errorf("failed to check leave overlap: %w", err)
	}

	return exists, nil
}

func (r *leaveRepository) CreateLeaveLedgerEntry(ctx context.Context, entry *models.LeaveLedger) error {
	if entry.LedgerID == uuid.Nil {
		entry.LedgerID = uuid.New()
	}
	if entry.CreatedAt.IsZero() {
		entry.CreatedAt = time.Now().UTC()
	}

	query := `
		INSERT INTO leave.leave_ledger (
			ledger_id, entitlement_id, leave_request_id,
			entry_type, days, entry_date, created_at
		) VALUES ($1, $2, $3, $4, $5, $6, $7)
	`

	_, err := r.client.Exec(ctx, query,
		entry.LedgerID,
		entry.EntitlementID,
		entry.LeaveRequestID,
		entry.EntryType,
		entry.Days,
		entry.EntryDate,
		entry.CreatedAt,
	)

	if err != nil {
		r.logger.Error("Failed to create leave ledger entry",
			util.String("entitlement_id", entry.EntitlementID.String()),
			util.ErrorField(err))
		return fmt.Errorf("failed to create leave ledger entry: %w", err)
	}

	return nil
}

func (r *leaveRepository) CreateBulkLeaveLedgerEntries(ctx context.Context, entries []*models.LeaveLedger) error {
	tx, err := r.client.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("failed to begin transaction: %w", err)
	}
	defer func() {
		if err != nil {
			tx.Rollback()
		}
	}()

	query := `
		INSERT INTO leave.leave_ledger (
			ledger_id, entitlement_id, leave_request_id,
			entry_type, days, entry_date, created_at
		) VALUES ($1, $2, $3, $4, $5, $6, $7)
	`

	stmt, err := tx.Prepare(query)
	if err != nil {
		return fmt.Errorf("failed to prepare statement: %w", err)
	}
	defer stmt.Close()

	for _, entry := range entries {
		if entry.LedgerID == uuid.Nil {
			entry.LedgerID = uuid.New()
		}
		if entry.CreatedAt.IsZero() {
			entry.CreatedAt = time.Now().UTC()
		}

		_, err := stmt.ExecContext(ctx,
			entry.LedgerID,
			entry.EntitlementID,
			entry.LeaveRequestID,
			entry.EntryType,
			entry.Days,
			entry.EntryDate,
			entry.CreatedAt,
		)
		if err != nil {
			return fmt.Errorf("failed to insert ledger entry %s: %w", entry.LedgerID, err)
		}
	}

	if err := tx.Commit(); err != nil {
		return fmt.Errorf("failed to commit transaction: %w", err)
	}

	return nil
}

func (r *leaveRepository) GetLeaveLedgerEntriesByEntitlement(ctx context.Context, entitlementID uuid.UUID) ([]*models.LeaveLedger, error) {
	query := `
		SELECT
			ledger_id,
			entitlement_id,
			leave_request_id,
			entry_type,
			days,
			entry_date,
			created_at
		FROM leave.leave_ledger
		WHERE entitlement_id = $1
		ORDER BY entry_date, created_at
	`

	rows, err := r.client.Query(ctx, query, entitlementID)
	if err != nil {
		r.logger.Error("Failed to get leave ledger entries by entitlement",
			util.String("entitlement_id", entitlementID.String()),
			util.ErrorField(err))
		return nil, fmt.Errorf("failed to get leave ledger entries: %w", err)
	}
	defer rows.Close()

	var entries []*models.LeaveLedger
	for rows.Next() {
		var entry models.LeaveLedger
		var leaveRequestID sql.NullString

		err := rows.Scan(
			&entry.LedgerID,
			&entry.EntitlementID,
			&leaveRequestID,
			&entry.EntryType,
			&entry.Days,
			&entry.EntryDate,
			&entry.CreatedAt,
		)
		if err != nil {
			return nil, fmt.Errorf("failed to scan leave ledger entry: %w", err)
		}

		if leaveRequestID.Valid && leaveRequestID.String != "" {
			id, err := uuid.Parse(leaveRequestID.String)
			if err == nil {
				entry.LeaveRequestID = &id
			}
		}

		entries = append(entries, &entry)
	}

	if err = rows.Err(); err != nil {
		return nil, fmt.Errorf("rows iteration error: %w", err)
	}

	return entries, nil
}

func (r *leaveRepository) GetLeaveLedgerEntriesByRequest(ctx context.Context, requestID uuid.UUID) ([]*models.LeaveLedger, error) {
	query := `
		SELECT
			ledger_id,
			entitlement_id,
			leave_request_id,
			entry_type,
			days,
			entry_date,
			created_at
		FROM leave.leave_ledger
		WHERE leave_request_id = $1
		ORDER BY entry_date, created_at
	`

	rows, err := r.client.Query(ctx, query, requestID)
	if err != nil {
		r.logger.Error("Failed to get leave ledger entries by request",
			util.String("leave_request_id", requestID.String()),
			util.ErrorField(err))
		return nil, fmt.Errorf("failed to get leave ledger entries: %w", err)
	}
	defer rows.Close()

	var entries []*models.LeaveLedger
	for rows.Next() {
		var entry models.LeaveLedger
		var leaveRequestID sql.NullString

		err := rows.Scan(
			&entry.LedgerID,
			&entry.EntitlementID,
			&leaveRequestID,
			&entry.EntryType,
			&entry.Days,
			&entry.EntryDate,
			&entry.CreatedAt,
		)
		if err != nil {
			return nil, fmt.Errorf("failed to scan leave ledger entry: %w", err)
		}

		if leaveRequestID.Valid && leaveRequestID.String != "" {
			id, err := uuid.Parse(leaveRequestID.String)
			if err == nil {
				entry.LeaveRequestID = &id
			}
		}

		entries = append(entries, &entry)
	}

	if err = rows.Err(); err != nil {
		return nil, fmt.Errorf("rows iteration error: %w", err)
	}

	return entries, nil
}

func (r *leaveRepository) GetLeaveBalancesByUser(
	ctx context.Context,
	userID uuid.UUID,
	positionID *uuid.UUID,
	asOfDate time.Time,
) ([]*models.LeaveBalance, error) {
	query := `
		WITH user_leave_types AS (
			SELECT DISTINCT
				lt.leave_type_id,
				lt.code,
				lt.name,
				lt.carry_forward_limit
			FROM leave.leave_entitlement le
			JOIN leave.leave_type lt ON le.leave_type_id = lt.leave_type_id
			WHERE le.user_id = $1
			  AND le.effective_from <= $3
			  AND (le.effective_to IS NULL OR le.effective_to >= $3)
			  AND (le.position_id IS NOT DISTINCT FROM $2 OR $2 IS NULL)
		),
		current_entitlement AS (
			SELECT
				le.leave_type_id,
				le.entitlement_id,
				le.total_days
			FROM leave.leave_entitlement le
			WHERE le.user_id = $1
			  AND le.effective_from <= $3
			  AND (le.effective_to IS NULL OR le.effective_to >= $3)
			  AND (le.position_id IS NOT DISTINCT FROM $2 OR $2 IS NULL)
		),
		ledger_sum AS (
			SELECT
				ce.leave_type_id,
				COALESCE(SUM(
					CASE ll.entry_type
						WHEN 'accrual' THEN ll.days
						WHEN 'reversal' THEN ll.days
						WHEN 'consumption' THEN -ll.days
						ELSE 0
					END
				), 0) AS balance,
				COALESCE(SUM(
					CASE ll.entry_type
						WHEN 'accrual' THEN ll.days
						WHEN 'reversal' THEN ll.days
						ELSE 0
					END
				), 0) AS accrued,
				COALESCE(SUM(
					CASE ll.entry_type
						WHEN 'consumption' THEN ll.days
						ELSE 0
					END
				), 0) AS consumed
			FROM leave.leave_ledger ll
			JOIN current_entitlement ce ON ll.entitlement_id = ce.entitlement_id
			WHERE ll.entry_date <= $3
			GROUP BY ce.leave_type_id
		)
		SELECT
			$1 AS user_id,
			ult.leave_type_id,
			ult.code,
			ult.name,
			COALESCE(ce.total_days, 0) AS total_entitled,
			COALESCE(ls.accrued, 0) AS accrued,
			COALESCE(ls.consumed, 0) AS consumed,
			COALESCE(ls.balance, 0) AS balance,
			ult.carry_forward_limit
		FROM user_leave_types ult
		LEFT JOIN current_entitlement ce
		  ON ult.leave_type_id = ce.leave_type_id
		LEFT JOIN ledger_sum ls
		  ON ult.leave_type_id = ls.leave_type_id
		ORDER BY ult.code
	`
	rows, err := r.client.Query(ctx, query, userID, positionID, asOfDate)
	if err != nil {
		r.logger.Error("Failed to get leave balances by user",
			util.String("user_id", userID.String()),
			util.Time("as_of_date", asOfDate),
			util.ErrorField(err))
		return nil, fmt.Errorf("failed to get leave balances: %w", err)
	}
	defer rows.Close()

	var balances []*models.LeaveBalance
	for rows.Next() {
		var balance models.LeaveBalance
		var carryForwardLimit sql.NullInt32
		if err := rows.Scan(
			&balance.UserID,
			&balance.LeaveTypeID,
			&balance.LeaveTypeCode,
			&balance.LeaveTypeName,
			&balance.TotalEntitled,
			&balance.Accrued,
			&balance.Consumed,
			&balance.Balance,
			&carryForwardLimit,
		); err != nil {
			return nil, fmt.Errorf("failed to scan leave balance: %w", err)
		}
		if carryForwardLimit.Valid {
			v := int(carryForwardLimit.Int32)
			balance.CarryForward = &v
		}
		balances = append(balances, &balance)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("rows iteration error: %w", err)
	}
	return balances, nil
}

func (r *leaveRepository) GetLeaveTransactionHistory(ctx context.Context, userID uuid.UUID, startDate, endDate time.Time) ([]*models.LeaveTransaction, error) {
	query := `
		SELECT
			ll.ledger_id as transaction_id,
			le.user_id,
			le.leave_type_id,
			ll.entry_type,
			ll.days,
			ll.entry_date,
			ll.leave_request_id as reference_id,
			CASE
				WHEN ll.leave_request_id IS NOT NULL THEN 'leave_request'
				ELSE NULL
			END as reference_type,
			CASE
				WHEN ll.entry_type = 'accrual' THEN 'Leave Accrual'
				WHEN ll.entry_type = 'consumption' AND lr.leave_request_id IS NOT NULL THEN 'Leave Taken (' || lt.code || ')'
				WHEN ll.entry_type = 'reversal' AND lr.leave_request_id IS NOT NULL THEN 'Leave Reversal (' || lt.code || ')'
				ELSE ll.entry_type
			END as description
		FROM leave.leave_ledger ll
		JOIN leave.leave_entitlement le ON ll.entitlement_id = le.entitlement_id
		LEFT JOIN leave.leave_request lr ON ll.leave_request_id = lr.leave_request_id
		LEFT JOIN leave.leave_type lt ON le.leave_type_id = lt.leave_type_id
		WHERE le.user_id = $1
		AND ll.entry_date BETWEEN $2 AND $3
		ORDER BY ll.entry_date DESC, ll.created_at DESC
	`

	rows, err := r.client.Query(ctx, query, userID, startDate, endDate)
	if err != nil {
		r.logger.Error("Failed to get leave transaction history",
			util.String("user_id", userID.String()),
			util.ErrorField(err))
		return nil, fmt.Errorf("failed to get leave transaction history: %w", err)
	}
	defer rows.Close()

	var transactions []*models.LeaveTransaction
	for rows.Next() {
		var transaction models.LeaveTransaction
		var referenceID sql.NullString
		var referenceType sql.NullString

		err := rows.Scan(
			&transaction.TransactionID,
			&transaction.UserID,
			&transaction.LeaveTypeID,
			&transaction.EntryType,
			&transaction.Days,
			&transaction.EntryDate,
			&referenceID,
			&referenceType,
			&transaction.Description,
		)
		if err != nil {
			return nil, fmt.Errorf("failed to scan leave transaction: %w", err)
		}

		if referenceID.Valid {
			id, _ := uuid.Parse(referenceID.String)
			transaction.ReferenceID = &id
		}
		if referenceType.Valid {
			transaction.ReferenceType = &referenceType.String
		}

		transactions = append(transactions, &transaction)
	}

	if err = rows.Err(); err != nil {
		return nil, fmt.Errorf("rows iteration error: %w", err)
	}

	return transactions, nil
}

func (r *leaveRepository) ProcessLeaveAccruals(
	ctx context.Context,
	companyID uuid.UUID,
	accrualDate time.Time,
) (int, error) {
	fyStartMonth, err := r.GetCompanyFinancialYearStartMonth(ctx, companyID)
	if err != nil {
		return 0, fmt.Errorf("failed to get financial year start: %w", err)
	}

	tx, err := r.client.BeginTx(ctx, nil)
	if err != nil {
		return 0, fmt.Errorf("failed to begin transaction: %w", err)
	}
	defer func() {
		if err != nil {
			tx.Rollback()
		}
	}()

	query := `
		SELECT
			le.entitlement_id,
			lt.accrual_method,
			le.total_days
		FROM leave.leave_entitlement le
		JOIN leave.leave_type lt ON le.leave_type_id = lt.leave_type_id
		WHERE le.company_id = $1
		  AND le.effective_from <= $2
		  AND (le.effective_to IS NULL OR le.effective_to >= $2)
		  AND lt.accrual_method != 'none'
	`
	rows, err := tx.QueryContext(ctx, query, companyID, accrualDate)
	if err != nil {
		return 0, fmt.Errorf("failed to get entitlements for accrual: %w", err)
	}
	defer rows.Close()

	type entitlementRow struct {
		id            uuid.UUID
		accrualMethod string
		totalDays     int
	}
	var entitlements []entitlementRow
	for rows.Next() {
		var e entitlementRow
		if err := rows.Scan(&e.id, &e.accrualMethod, &e.totalDays); err != nil {
			return 0, fmt.Errorf("failed to scan entitlement: %w", err)
		}
		entitlements = append(entitlements, e)
	}
	if err = rows.Err(); err != nil {
		return 0, err
	}

	processedCount := 0
	month := accrualDate.Month()
	day := accrualDate.Day()

	for _, e := range entitlements {
		var daysToAccrue float64
		shouldAccrue := false

		switch e.accrualMethod {
		case "monthly":
			if day == 1 {
				shouldAccrue = true
				daysToAccrue = float64(e.totalDays) / 12.0
			}
		case "quarterly":
			// Improved: check if month is a quarter start relative to FY start
			monthDiff := (int(month) - fyStartMonth + 12) % 12
			if monthDiff%3 == 0 && day == 1 {
				shouldAccrue = true
				daysToAccrue = float64(e.totalDays) / 4.0
			}
		case "yearly":
			if month == time.Month(fyStartMonth) && day == 1 {
				shouldAccrue = true
				daysToAccrue = float64(e.totalDays)
			}
		}

		if !shouldAccrue || daysToAccrue <= 0 {
			continue
		}

		daysAccrued := int(daysToAccrue)
		fractionalDays := daysToAccrue - float64(daysAccrued)

		accrualQuery := `
			INSERT INTO leave.leave_accrual (
				accrual_id,
				entitlement_id,
				accrual_date,
				days_accrued,
				fractional_days,
				created_at
			) VALUES ($1, $2, $3, $4, $5, $6)
			ON CONFLICT (entitlement_id, accrual_date) DO NOTHING
		`
		result, err := tx.ExecContext(
			ctx,
			accrualQuery,
			uuid.New(),
			e.id,
			accrualDate,
			daysAccrued,
			fractionalDays,
			time.Now().UTC(),
		)
		if err != nil {
			return 0, fmt.Errorf("failed to insert accrual: %w", err)
		}
		rowsAffected, _ := result.RowsAffected()
		if rowsAffected == 0 {
			// already exists – skip ledger entry too
			continue
		}

		if daysAccrued > 0 {
			ledgerQuery := `
				INSERT INTO leave.leave_ledger (
					ledger_id,
					entitlement_id,
					leave_request_id,
					entry_type,
					days,
					entry_date,
					created_at
				) VALUES ($1, $2, NULL, 'accrual', $3, $4, $5)
			`
			_, err = tx.ExecContext(
				ctx,
				ledgerQuery,
				uuid.New(),
				e.id,
				daysAccrued,
				accrualDate,
				time.Now().UTC(),
			)
			if err != nil {
				return 0, fmt.Errorf("failed to create ledger entry: %w", err)
			}
		}
		processedCount++
	}

	if err = tx.Commit(); err != nil {
		return 0, fmt.Errorf("failed to commit transaction: %w", err)
	}
	return processedCount, nil
}

func (r *leaveRepository) GetLeaveUtilizationReport(ctx context.Context, companyID uuid.UUID, startDate, endDate time.Time) ([]*models.LeaveBalance, error) {
	query := `
		WITH user_leave_data AS (
			SELECT
				le.user_id,
				le.leave_type_id,
				lt.code as leave_type_code,
				lt.name as leave_type_name,
				le.total_days,
				le.policy_id,
				le.source,
				COALESCE(SUM(
					CASE
						WHEN ll.entry_type IN ('accrual', 'reversal')
						 AND ll.entry_date BETWEEN $2 AND $3
						THEN ll.days
						ELSE 0
					END
				), 0) as accrued_days,
				COALESCE(SUM(
					CASE
						WHEN ll.entry_type = 'consumption'
						 AND ll.entry_date BETWEEN $2 AND $3
						THEN ll.days
						ELSE 0
					END
				), 0) as consumed_days
			FROM leave.leave_entitlement le
			JOIN leave.leave_type lt ON le.leave_type_id = lt.leave_type_id
			LEFT JOIN leave.leave_ledger ll ON le.entitlement_id = ll.entitlement_id
			WHERE le.company_id = $1
			AND le.effective_from <= $3
			AND (le.effective_to IS NULL OR le.effective_to >= $2)
			GROUP BY le.user_id, le.leave_type_id, lt.code, lt.name, le.total_days, le.policy_id, le.source
		)
		SELECT
			user_id,
			leave_type_id,
			leave_type_code,
			leave_type_name,
			total_days as total_entitled,
			accrued_days as accrued,
			consumed_days as consumed,
			accrued_days - consumed_days as balance
		FROM user_leave_data
		WHERE accrued_days > 0 OR consumed_days > 0
		ORDER BY user_id, leave_type_code
	`
	rows, err := r.client.Query(ctx, query, companyID, startDate, endDate)
	if err != nil {
		r.logger.Error("Failed to get leave utilization report",
			util.String("company_id", companyID.String()),
			util.ErrorField(err))
		return nil, fmt.Errorf("failed to get leave utilization report: %w", err)
	}
	defer rows.Close()

	var balances []*models.LeaveBalance
	for rows.Next() {
		var balance models.LeaveBalance
		err := rows.Scan(
			&balance.UserID,
			&balance.LeaveTypeID,
			&balance.LeaveTypeCode,
			&balance.LeaveTypeName,
			&balance.TotalEntitled,
			&balance.Accrued,
			&balance.Consumed,
			&balance.Balance,
		)
		if err != nil {
			return nil, fmt.Errorf("failed to scan leave balance: %w", err)
		}
		balances = append(balances, &balance)
	}
	if err = rows.Err(); err != nil {
		return nil, fmt.Errorf("rows iteration error: %w", err)
	}
	return balances, nil
}

func (r *leaveRepository) GetLeaveForecast(
	ctx context.Context,
	userID uuid.UUID,
	months int,
) ([]*models.LeaveBalance, error) {
	forecastDate := time.Now().AddDate(0, months, 0)

	query := `
		WITH leave_types AS (
			SELECT DISTINCT lt.leave_type_id, lt.code, lt.name, lt.accrual_method
			FROM leave.leave_entitlement le
			JOIN leave.leave_type lt ON le.leave_type_id = lt.leave_type_id
			WHERE le.user_id = $1
			AND le.effective_from <= $2
			AND (le.effective_to IS NULL OR le.effective_to >= $2)
		),
		current_balances AS (
			SELECT
				ce.leave_type_id,
				COALESCE(SUM(
					CASE ll.entry_type
						WHEN 'accrual' THEN ll.days
						WHEN 'reversal' THEN ll.days
						WHEN 'consumption' THEN -ll.days
						ELSE 0
					END
				), 0) as current_balance
			FROM leave.leave_entitlement le
			JOIN leave.leave_ledger ll ON le.entitlement_id = ll.entitlement_id
			JOIN leave_types ce ON le.leave_type_id = ce.leave_type_id
			GROUP BY ce.leave_type_id
		),
		entitlement_info AS (
			SELECT
				le.leave_type_id,
				le.total_days
			FROM leave.leave_entitlement le
			WHERE le.user_id = $1
			  AND le.effective_from <= $2
			  AND (le.effective_to IS NULL OR le.effective_to >= $2)
		),
		future_accruals AS (
			SELECT
				lt.leave_type_id,
				CASE
					WHEN lt.accrual_method = 'monthly'
						THEN $3 * (ei.total_days::DECIMAL / 12.0)
					WHEN lt.accrual_method = 'quarterly'
						THEN CEIL($3 / 3.0) * (ei.total_days::DECIMAL / 4.0)
					WHEN lt.accrual_method = 'yearly'
						THEN CEIL($3 / 12.0) * ei.total_days::DECIMAL
					ELSE 0
				END as forecast_accrual
			FROM leave_types lt
			LEFT JOIN entitlement_info ei ON lt.leave_type_id = ei.leave_type_id
		)
		SELECT
			$1 as user_id,
			lt.leave_type_id,
			lt.code,
			lt.name,
			COALESCE(cb.current_balance, 0) as current_balance,
			COALESCE(fa.forecast_accrual, 0) as forecast_accrual,
			COALESCE(cb.current_balance, 0) + COALESCE(fa.forecast_accrual, 0) as forecast_balance
		FROM leave_types lt
		LEFT JOIN current_balances cb ON lt.leave_type_id = cb.leave_type_id
		LEFT JOIN future_accruals fa ON lt.leave_type_id = fa.leave_type_id
		ORDER BY lt.code
	`
	rows, err := r.client.Query(ctx, query, userID, forecastDate, months)
	if err != nil {
		r.logger.Error(
			"Failed to get leave forecast",
			util.String("user_id", userID.String()),
			util.Int("months", months),
			util.ErrorField(err),
		)
		return nil, fmt.Errorf("failed to get leave forecast: %w", err)
	}
	defer rows.Close()

	var forecasts []*models.LeaveBalance
	for rows.Next() {
		var forecast models.LeaveBalance
		var currentBalance float64
		var forecastAccrual float64
		var forecastBalance float64
		err := rows.Scan(
			&forecast.UserID,
			&forecast.LeaveTypeID,
			&forecast.LeaveTypeCode,
			&forecast.LeaveTypeName,
			&currentBalance,
			&forecastAccrual,
			&forecastBalance,
		)
		if err != nil {
			return nil, fmt.Errorf("failed to scan leave forecast: %w", err)
		}
		// Map to LeaveBalance fields
		forecast.Balance = forecastBalance
		forecast.Accrued = currentBalance // current balance as accrued? maybe leave as is
		forecasts = append(forecasts, &forecast)
	}
	if err = rows.Err(); err != nil {
		return nil, fmt.Errorf("rows iteration error: %w", err)
	}
	return forecasts, nil
}

func (r *leaveRepository) HealthCheck(ctx context.Context) error {
	query := `SELECT 1 FROM leave.leave_type LIMIT 1`
	var result int
	row := r.client.QueryRow(ctx, query)
	err := row.Scan(&result)
	if err != nil && !errors.Is(err, sql.ErrNoRows) {
		r.logger.Error("Leave repository health check failed",
			util.ErrorField(err))
		return fmt.Errorf("leave repository health check failed: %w", err)
	}
	return nil
}

func (r *leaveRepository) CreateLeaveBalanceSnapshot(
	ctx context.Context,
	snapshot *models.LeaveBalanceSnapshot,
) error {
	if snapshot.SnapshotID == uuid.Nil {
		snapshot.SnapshotID = uuid.New()
	}
	if snapshot.CalculatedAt.IsZero() {
		snapshot.CalculatedAt = time.Now().UTC()
	}
	if snapshot.UpdatedAt == nil {
		now := time.Now().UTC()
		snapshot.UpdatedAt = &now
	}

	query := `
		INSERT INTO leave.leave_balance_snapshot (
			snapshot_id,
			entitlement_id,
			balance_days,
			calculated_at,
			updated_at
		) VALUES ($1, $2, $3, $4, $5)
	`

	_, err := r.client.Exec(ctx, query,
		snapshot.SnapshotID,
		snapshot.EntitlementID,
		snapshot.BalanceDays,
		snapshot.CalculatedAt,
		snapshot.UpdatedAt,
	)

	if err != nil {
		return fmt.Errorf("failed to create leave balance snapshot: %w", err)
	}

	return nil
}

func (r *leaveRepository) GetLatestLeaveBalanceSnapshot(
	ctx context.Context,
	entitlementID uuid.UUID,
) (*models.LeaveBalanceSnapshot, error) {
	query := `
		SELECT
			snapshot_id,
			entitlement_id,
			balance_days,
			calculated_at,
			updated_at
		FROM leave.leave_balance_snapshot
		WHERE entitlement_id = $1
		ORDER BY calculated_at DESC
		LIMIT 1
	`

	row := r.client.QueryRow(ctx, query, entitlementID)
	var snapshot models.LeaveBalanceSnapshot
	var updatedAt sql.NullTime

	err := row.Scan(
		&snapshot.SnapshotID,
		&snapshot.EntitlementID,
		&snapshot.BalanceDays,
		&snapshot.CalculatedAt,
		&updatedAt,
	)

	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, nil
		}
		return nil, fmt.Errorf("failed to get leave balance snapshot: %w", err)
	}

	if updatedAt.Valid {
		snapshot.UpdatedAt = &updatedAt.Time
	}

	return &snapshot, nil
}

func (r *leaveRepository) AddPolicyRule(ctx context.Context, rule *models.LeavePolicyRule) error {
	if rule.PolicyRuleID == uuid.Nil {
		rule.PolicyRuleID = uuid.New()
	}
	if rule.CreatedAt.IsZero() {
		rule.CreatedAt = time.Now().UTC()
	}
	if rule.UpdatedAt == nil {
		now := time.Now().UTC()
		rule.UpdatedAt = &now
	}

	query := `
		INSERT INTO leave.leave_policy_rule (
			policy_rule_id, policy_id, leave_type_id,
			total_days, accrual_method, carry_forward_limit,
			created_at, updated_at
		) VALUES ($1, $2, $3, $4, $5, $6, $7, $8)
	`

	_, err := r.client.Exec(ctx, query,
		rule.PolicyRuleID,
		rule.PolicyID,
		rule.LeaveTypeID,
		rule.TotalDays,
		rule.AccrualMethod,
		rule.CarryForwardLimit,
		rule.CreatedAt,
		rule.UpdatedAt,
	)

	if err != nil {
		r.logger.Error("Failed to add policy rule",
			util.String("policy_id", rule.PolicyID.String()),
			util.ErrorField(err))
		return fmt.Errorf("failed to add policy rule: %w", err)
	}

	return nil
}

func (r *leaveRepository) DeletePolicyRule(ctx context.Context, policyRuleID uuid.UUID) error {
	query := `
		DELETE FROM leave.leave_policy_rule
		WHERE policy_rule_id = $1
	`

	result, err := r.client.Exec(ctx, query, policyRuleID)
	if err != nil {
		r.logger.Error("Failed to delete policy rule",
			util.String("policy_rule_id", policyRuleID.String()),
			util.ErrorField(err))
		return fmt.Errorf("failed to delete policy rule: %w", err)
	}

	rowsAffected, _ := result.RowsAffected()
	if rowsAffected == 0 {
		return fmt.Errorf("policy rule not found")
	}
	return nil
}

func (r *leaveRepository) CreateLeavePolicyResolution(
	ctx context.Context,
	companyID uuid.UUID,
	userID uuid.UUID,
	policyID *uuid.UUID,
	reason string,
	meta map[string]interface{},
) error {
	resolutionID := uuid.New()
	now := time.Now().UTC()

	metaJSON, err := json.Marshal(meta)
	if err != nil {
		return fmt.Errorf("failed to marshal policy resolution metadata: %w", err)
	}

	query := `
        INSERT INTO leave.leave_policy_resolution (
            resolution_id, company_id, user_id, policy_id,
            resolved_at, reason, metadata, updated_at
        ) VALUES ($1, $2, $3, $4, $5, $6, $7, $8)
    `

	_, err = r.client.Exec(ctx, query,
		resolutionID,
		companyID,
		userID,
		policyID,
		now,
		reason,
		metaJSON, // ✅ []byte → jsonb
		now,
	)
	if err != nil {
		r.logger.Error("Failed to create policy resolution",
			util.String("company_id", companyID.String()),
			util.String("user_id", userID.String()),
			util.String("policy_id", policyID.String()),
			util.ErrorField(err))
		return fmt.Errorf("failed to create policy resolution: %w", err)
	}

	return nil
}

func (r *leaveRepository) DeactivateLeavePolicy(ctx context.Context, policyID uuid.UUID) error {
	query := `
		UPDATE leave.leave_policy
		SET is_active = false, updated_at = NOW()
		WHERE policy_id = $1
		AND is_active = true
	`

	result, err := r.client.Exec(ctx, query, policyID)
	if err != nil {
		r.logger.Error("Failed to deactivate leave policy",
			util.String("policy_id", policyID.String()),
			util.ErrorField(err))
		return fmt.Errorf("failed to deactivate leave policy: %w", err)
	}

	rowsAffected, _ := result.RowsAffected()
	if rowsAffected == 0 {
		return fmt.Errorf("leave policy not found or already deactivated")
	}
	return nil
}

func (r *leaveRepository) GetLeaveEntitlementsByCompanyAndUser(
	ctx context.Context,
	companyID uuid.UUID,
	userID *uuid.UUID,
	page, pageSize int,
) ([]*models.LeaveEntitlement, int64, error) {
	var conditions []string
	var args []interface{}
	conditions = append(conditions, "company_id = $1")
	args = append(args, companyID)

	if userID != nil {
		conditions = append(conditions, fmt.Sprintf("user_id = $%d", len(args)+1))
		args = append(args, *userID)
	}

	whereClause := ""
	if len(conditions) > 0 {
		whereClause = "WHERE " + strings.Join(conditions, " AND ")
	}

	countQuery := fmt.Sprintf(`
		SELECT COUNT(*)
		FROM leave.leave_entitlement
		%s
	`, whereClause)

	var total int64
	row := r.client.QueryRow(ctx, countQuery, args...)
	if err := row.Scan(&total); err != nil {
		r.logger.Error("Failed to count entitlements",
			util.String("company_id", companyID.String()),
			util.ErrorField(err))
		return nil, 0, fmt.Errorf("failed to count entitlements: %w", err)
	}

	offset := (page - 1) * pageSize
	args = append(args, pageSize, offset)

	query := fmt.Sprintf(`
		SELECT
			entitlement_id,
			company_id,
			user_id,
			leave_type_id,
			total_days,
			effective_from,
			effective_to,
			created_at,
			policy_id,
			source,
			updated_at,
			position_id,
			work_center_code
		FROM leave.leave_entitlement
		%s
		ORDER BY user_id, effective_from DESC
		LIMIT $%d OFFSET $%d
	`, whereClause, len(args)-1, len(args))

	rows, err := r.client.Query(ctx, query, args...)
	if err != nil {
		r.logger.Error("Failed to get entitlements",
			util.String("company_id", companyID.String()),
			util.ErrorField(err))
		return nil, 0, fmt.Errorf("failed to get entitlements: %w", err)
	}
	defer rows.Close()

	var entitlements []*models.LeaveEntitlement
	for rows.Next() {
		var entitlement models.LeaveEntitlement
		var effectiveTo sql.NullTime
		var policyID sql.NullString
		var positionID sql.NullString
		var workCenterCode sql.NullString
		var updatedAt sql.NullTime

		err := rows.Scan(
			&entitlement.EntitlementID,
			&entitlement.CompanyID,
			&entitlement.UserID,
			&entitlement.LeaveTypeID,
			&entitlement.TotalDays,
			&entitlement.EffectiveFrom,
			&effectiveTo,
			&entitlement.CreatedAt,
			&policyID,
			&entitlement.Source,
			&updatedAt,
			&positionID,
			&workCenterCode,
		)
		if err != nil {
			return nil, 0, fmt.Errorf("failed to scan entitlement: %w", err)
		}

		if effectiveTo.Valid {
			entitlement.EffectiveTo = &effectiveTo.Time
		}
		if policyID.Valid && policyID.String != "" {
			pid, err := uuid.Parse(policyID.String)
			if err == nil {
				entitlement.PolicyID = &pid
			}
		}
		if positionID.Valid && positionID.String != "" {
			pid, err := uuid.Parse(positionID.String)
			if err == nil {
				entitlement.PositionID = &pid
			}
		}
		if workCenterCode.Valid {
			entitlement.WorkCenterCode = &workCenterCode.String
		}
		if updatedAt.Valid {
			entitlement.UpdatedAt = &updatedAt.Time
		}

		entitlements = append(entitlements, &entitlement)
	}
	return entitlements, total, nil
}

func (r *leaveRepository) GetUserPositionContext(
	ctx context.Context,
	companyID uuid.UUID,
	userID uuid.UUID,
) (*uuid.UUID, *string, error) {
	query := `
		SELECT
			ce.position_id,
			p.work_center_code
		FROM company_employees ce
		LEFT JOIN positions p ON ce.position_id = p.position_id
		WHERE ce.company_id = $1
		AND ce.user_id = $2
		AND ce.is_active = true
		ORDER BY ce.hire_date DESC
		LIMIT 1
		`

	row := r.client.QueryRow(ctx, query, companyID, userID)
	var positionID sql.NullString
	var workCenterCode sql.NullString

	err := row.Scan(&positionID, &workCenterCode)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, nil, nil
		}
		r.logger.Error(
			"Failed to get user position context",
			util.String("company_id", companyID.String()),
			util.String("user_id", userID.String()),
			util.ErrorField(err),
		)
		return nil, nil, fmt.Errorf("failed to get user position context: %w", err)
	}

	var pid *uuid.UUID
	if positionID.Valid && positionID.String != "" {
		id, err := uuid.Parse(positionID.String)
		if err == nil {
			pid = &id
		}
	}

	var wc *string
	if workCenterCode.Valid {
		wc = &workCenterCode.String
	}
	return pid, wc, nil
}
func (r *leaveRepository) GetActivePolicyEntitlement(
	ctx context.Context,
	companyID uuid.UUID,
	userID uuid.UUID,
	leaveTypeID uuid.UUID,
	positionID *uuid.UUID,
) (*models.LeaveEntitlement, error) {

	query := `
		SELECT
			entitlement_id,
			company_id,
			user_id,
			leave_type_id,
			total_days,
			effective_from,
			effective_to,
			created_at,
			policy_id,
			source,
			updated_at,
			position_id,
			work_center_code
		FROM leave.leave_entitlement
		WHERE company_id = $1
		  AND user_id = $2
		  AND leave_type_id = $3
		  AND source = 'policy'
		  AND effective_to IS NULL
		  AND (position_id IS NOT DISTINCT FROM $4)
		ORDER BY effective_from DESC
		LIMIT 1
	`

	row := r.client.QueryRow(
		ctx,
		query,
		companyID,
		userID,
		leaveTypeID,
		positionID,
	)

	var entitlement models.LeaveEntitlement
	var effectiveTo sql.NullTime
	var policyID sql.NullString
	var positionIDDB sql.NullString
	var workCenterCode sql.NullString
	var updatedAt sql.NullTime

	err := row.Scan(
		&entitlement.EntitlementID,
		&entitlement.CompanyID,
		&entitlement.UserID,
		&entitlement.LeaveTypeID,
		&entitlement.TotalDays,
		&entitlement.EffectiveFrom,
		&effectiveTo,
		&entitlement.CreatedAt,
		&policyID,
		&entitlement.Source,
		&updatedAt,
		&positionIDDB,
		&workCenterCode,
	)

	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, nil
		}
		r.logger.Error(
			"Failed to get active policy entitlement",
			util.String("company_id", companyID.String()),
			util.String("user_id", userID.String()),
			util.String("leave_type_id", leaveTypeID.String()),
			util.ErrorField(err),
		)
		return nil, fmt.Errorf("failed to get active policy entitlement: %w", err)
	}

	// hydrate nullable fields
	if effectiveTo.Valid {
		entitlement.EffectiveTo = &effectiveTo.Time
	}
	if policyID.Valid && policyID.String != "" {
		if pid, err := uuid.Parse(policyID.String); err == nil {
			entitlement.PolicyID = &pid
		}
	}
	if positionIDDB.Valid && positionIDDB.String != "" {
		if pid, err := uuid.Parse(positionIDDB.String); err == nil {
			entitlement.PositionID = &pid
		}
	}
	if workCenterCode.Valid {
		entitlement.WorkCenterCode = &workCenterCode.String
	}
	if updatedAt.Valid {
		entitlement.UpdatedAt = &updatedAt.Time
	}

	return &entitlement, nil
}
func (r *leaveRepository) UpdateLeavePolicy(
	ctx context.Context,
	policyID uuid.UUID,
	update *models.LeavePolicyUpdate,
) error {

	var setClauses []string
	var args []interface{}
	argIdx := 1

	if update.PolicyName != nil {
		setClauses = append(setClauses, fmt.Sprintf("policy_name = $%d", argIdx))
		args = append(args, *update.PolicyName)
		argIdx++
	}

	if update.AppliesToType != nil {
		setClauses = append(setClauses, fmt.Sprintf("applies_to_type = $%d", argIdx))
		args = append(args, *update.AppliesToType)
		argIdx++
	}

	if update.AppliesToPositionID != nil {
		setClauses = append(setClauses, fmt.Sprintf("applies_to_position_id = $%d", argIdx))
		args = append(args, *update.AppliesToPositionID)
		argIdx++
	}

	if update.AppliesToWorkCenterCode != nil {
		setClauses = append(setClauses, fmt.Sprintf("applies_to_work_center_code = $%d", argIdx))
		args = append(args, *update.AppliesToWorkCenterCode)
		argIdx++
	}

	if update.Priority != nil {
		setClauses = append(setClauses, fmt.Sprintf("priority = $%d", argIdx))
		args = append(args, *update.Priority)
		argIdx++
	}

	if update.EffectiveFrom != nil {
		setClauses = append(setClauses, fmt.Sprintf("effective_from = $%d", argIdx))
		args = append(args, *update.EffectiveFrom)
		argIdx++
	}

	if update.EffectiveTo != nil {
		setClauses = append(setClauses, fmt.Sprintf("effective_to = $%d", argIdx))
		args = append(args, *update.EffectiveTo)
		argIdx++
	}

	if update.IsActive != nil {
		setClauses = append(setClauses, fmt.Sprintf("is_active = $%d", argIdx))
		args = append(args, *update.IsActive)
		argIdx++
	}

	if len(setClauses) == 0 {
		return nil
	}

	setClauses = append(setClauses, "updated_at = NOW()")

	query := fmt.Sprintf(`
		UPDATE leave.leave_policy
		SET %s
		WHERE policy_id = $%d
	`, strings.Join(setClauses, ", "), argIdx)

	args = append(args, policyID)

	result, err := r.client.Exec(ctx, query, args...)
	if err != nil {
		return fmt.Errorf("failed to update leave policy: %w", err)
	}

	rowsAffected, _ := result.RowsAffected()
	if rowsAffected == 0 {
		return fmt.Errorf("leave policy not found")
	}

	return nil
}
func (r *leaveRepository) UpdatePolicyRule(
	ctx context.Context,
	companyID uuid.UUID,
	policyRuleID uuid.UUID,
	update *models.LeavePolicyRuleUpdate,
) error {

	var setClauses []string
	var args []interface{}
	argPos := 1

	// ✅ REMOVE lpr. prefix here
	if update.TotalDays != nil {
		setClauses = append(setClauses, fmt.Sprintf("total_days = $%d", argPos))
		args = append(args, *update.TotalDays)
		argPos++
	}

	if update.AccrualMethod != nil {
		setClauses = append(setClauses, fmt.Sprintf("accrual_method = $%d", argPos))
		args = append(args, *update.AccrualMethod)
		argPos++
	}

	if update.CarryForwardLimit != nil {
		setClauses = append(setClauses, fmt.Sprintf("carry_forward_limit = $%d", argPos))
		args = append(args, *update.CarryForwardLimit)
		argPos++
	}

	if len(setClauses) == 0 {
		return fmt.Errorf("no fields provided for update")
	}

	// ✅ Alias can remain in FROM + WHERE, but NOT in SET
	query := fmt.Sprintf(`
		UPDATE leave.leave_policy_rule
		SET %s
		FROM leave.leave_policy lp
		WHERE leave.leave_policy_rule.policy_rule_id = $%d
		  AND leave.leave_policy_rule.policy_id = lp.policy_id
		  AND lp.company_id = $%d
	`, strings.Join(setClauses, ", "), argPos, argPos+1)

	args = append(args, policyRuleID, companyID)

	result, err := r.client.Exec(ctx, query, args...)
	if err != nil {
		r.logger.Error("Failed to update policy rule",
			util.String("policy_rule_id", policyRuleID.String()),
			util.String("company_id", companyID.String()),
			util.ErrorField(err))
		return fmt.Errorf("failed to update policy rule: %w", err)
	}

	rowsAffected, _ := result.RowsAffected()
	if rowsAffected == 0 {
		return fmt.Errorf("policy rule not found or access denied")
	}

	return nil
}

func (r *leaveRepository) IsLeaveTypeInUse(
	ctx context.Context,
	leaveTypeID uuid.UUID,
) (bool, error) {

	query := `
		SELECT EXISTS (
			SELECT 1
			FROM leave.leave_entitlement
			WHERE leave_type_id = $1
			LIMIT 1
		)
	`

	var exists bool
	err := r.client.QueryRow(ctx, query, leaveTypeID).Scan(&exists)
	if err != nil {
		r.logger.Error(
			"Failed to check if leave type is in use",
			util.String("leave_type_id", leaveTypeID.String()),
			util.ErrorField(err),
		)
		return false, fmt.Errorf("failed to check leave type usage: %w", err)
	}

	return exists, nil
}
func (r *leaveRepository) GetCompanyFinancialYearStartMonth(
	ctx context.Context,
	companyID uuid.UUID,
) (int, error) {

	query := `
		SELECT financial_year_start_month
		FROM companies
		WHERE company_id = $1
	`

	var month int
	err := r.client.QueryRow(ctx, query, companyID).Scan(&month)
	if err != nil {
		return 0, fmt.Errorf("failed to get financial year start month: %w", err)
	}

	return month, nil
}

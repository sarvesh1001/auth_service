// internal/attendance/repository/postgres/policy_repository_pg.go
package postgres

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/google/uuid"
	"go.uber.org/zap"

	"auth-service/internal/attendance/models"
	"auth-service/internal/attendance/repository"
	"auth-service/internal/client"
	"auth-service/internal/util"
)

type policyRepository struct {
	client *client.PostgresClient
	logger *zap.Logger
}

func NewPolicyRepository(pg *client.PostgresClient, logger *zap.Logger) repository.PolicyRepository {
	return &policyRepository{
		client: pg,
		logger: logger.Named("policy_repo"),
	}
}

// =============================================================================
// Legacy (employee‑only) methods – kept for backward compatibility
// =============================================================================

func (r *policyRepository) CreatePolicy(ctx context.Context, tx *sql.Tx, policy *models.AttendancePolicy) error {
	if policy.PolicyID == uuid.Nil {
		policy.PolicyID = uuid.New()
	}
	now := time.Now().UTC()
	if policy.CreatedAt.IsZero() {
		policy.CreatedAt = now
	}
	policy.UpdatedAt = now

	rulesJSON, err := json.Marshal(policy.Rules)
	if err != nil {
		return fmt.Errorf("marshal rules: %w", err)
	}

	query := `
	INSERT INTO attendance.attendance_policies (
		policy_id, company_id, work_center_code, position_id,
		policy_code, policy_type, rules, is_active,
		created_at, updated_at, effective_from
	) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11)
	`

	exec := func(q string, args ...interface{}) (sql.Result, error) {
		if tx != nil {
			return tx.ExecContext(ctx, q, args...)
		}
		return r.client.Exec(ctx, q, args...)
	}

	_, err = exec(query,
		policy.PolicyID,
		policy.CompanyID,
		policy.WorkCenterCode,
		policy.PositionID,
		policy.PolicyCode,
		policy.PolicyType,
		rulesJSON,
		policy.IsActive,
		policy.CreatedAt,
		policy.UpdatedAt,
		policy.CreatedAt.UTC().Truncate(24*time.Hour),
	)
	if err != nil {
		r.logger.Error("failed to create attendance policy",
			util.String("policy_id", policy.PolicyID.String()),
			util.ErrorField(err))
		return fmt.Errorf("create policy: %w", err)
	}
	return nil
}

// GetPolicyByID returns the latest version of a policy.
// For the version active on a specific date, use GetPolicyByIDOnDate.
func (r *policyRepository) GetPolicyByID(ctx context.Context, policyID uuid.UUID) (*models.AttendancePolicy, error) {
	query := `
	SELECT policy_id, company_id, work_center_code, position_id,
	       policy_code, policy_type, rules, is_active,
	       created_at, updated_at
	FROM attendance.attendance_policies
	WHERE policy_id = $1
	ORDER BY effective_from DESC
	LIMIT 1
	`
	row := r.client.QueryRow(ctx, query, policyID)
	return r.scanPolicy(row)
}

// GetPoliciesByCompany returns the current version of every distinct policy
// in the company. Historical versions are collapsed via DISTINCT ON.
func (r *policyRepository) GetPoliciesByCompany(ctx context.Context, companyID uuid.UUID, activeOnly bool) ([]*models.AttendancePolicy, error) {
	query := `
	SELECT DISTINCT ON (policy_id)
	       policy_id, company_id, work_center_code, position_id,
	       policy_code, policy_type, rules, is_active,
	       created_at, updated_at
	FROM attendance.attendance_policies
	WHERE company_id = $1
`
	if activeOnly {
		query += " AND is_active = true"
	}
	query += " ORDER BY policy_id, effective_from DESC"

	rows, err := r.client.Query(ctx, query, companyID)
	if err != nil {
		r.logger.Error("failed to list policies",
			util.String("company_id", companyID.String()),
			util.ErrorField(err))
		return nil, fmt.Errorf("list policies: %w", err)
	}
	defer rows.Close()

	var policies []*models.AttendancePolicy
	for rows.Next() {
		p, err := r.scanPolicyFromRows(rows)
		if err != nil {
			return nil, err
		}
		policies = append(policies, p)
	}
	if err = rows.Err(); err != nil {
		return nil, fmt.Errorf("rows iteration: %w", err)
	}
	return policies, nil
}

func (r *policyRepository) GetPolicyByCode(ctx context.Context, companyID uuid.UUID, policyCode string) (*models.AttendancePolicy, error) {
	query := `
		SELECT policy_id, company_id, work_center_code, position_id,
		       policy_code, policy_type, rules, is_active,
		       created_at, updated_at
		FROM attendance.attendance_policies
		WHERE company_id = $1 AND policy_code = $2
		ORDER BY effective_from DESC
		LIMIT 1
	`
	row := r.client.QueryRow(ctx, query, companyID, policyCode)
	return r.scanPolicy(row)
}

// GetPolicyByIDOnDate returns the version of a policy that was active on
// the given date. Used by the resolver when the caller already has the
// policy_id and wants the dated snapshot.
func (r *policyRepository) GetPolicyByIDOnDate(ctx context.Context, policyID uuid.UUID, date time.Time) (*models.AttendancePolicy, error) {
	query := `
		SELECT policy_id, company_id, work_center_code, position_id,
		       policy_code, policy_type, rules, is_active,
		       created_at, updated_at
		FROM attendance.attendance_policies
		WHERE policy_id = $1
		  AND effective_from <= $2::date
		  AND (effective_to IS NULL OR effective_to >= $2::date)
		ORDER BY effective_from DESC
		LIMIT 1
	`
	row := r.client.QueryRow(ctx, query, policyID, date)
	return r.scanPolicy(row)
}

// GetPositionPolicy returns the policy active for the position on CURRENT_DATE.
// For a historical date, use GetPositionPolicyOnDate.
func (r *policyRepository) GetPositionPolicy(ctx context.Context, positionID uuid.UUID) (*models.AttendancePolicy, error) {
	query := `
		SELECT policy_id, company_id, work_center_code, position_id,
		       policy_code, policy_type, rules, is_active,
		       created_at, updated_at
		FROM attendance.attendance_policies
		WHERE position_id = $1
		  AND is_active = true
		  AND effective_from <= CURRENT_DATE
		  AND (effective_to IS NULL OR effective_to >= CURRENT_DATE)
		ORDER BY effective_from DESC
		LIMIT 1
	`
	row := r.client.QueryRow(ctx, query, positionID)
	return r.scanPolicy(row)
}

// GetPositionPolicyOnDate is the date-scoped variant. The resolver must use
// this, not GetPositionPolicy, for historical queries.
func (r *policyRepository) GetPositionPolicyOnDate(ctx context.Context, positionID uuid.UUID, date time.Time) (*models.AttendancePolicy, error) {
	query := `
		SELECT policy_id, company_id, work_center_code, position_id,
		       policy_code, policy_type, rules, is_active,
		       created_at, updated_at
		FROM attendance.attendance_policies
		WHERE position_id = $1
		  AND is_active = true
		  AND effective_from <= $2::date
		  AND (effective_to IS NULL OR effective_to >= $2::date)
		ORDER BY effective_from DESC
		LIMIT 1
	`
	row := r.client.QueryRow(ctx, query, positionID, date)
	return r.scanPolicy(row)
}

// GetWorkCenterPolicy returns the policy active for the work center on CURRENT_DATE.
// For a historical date, use GetWorkCenterPolicyOnDate.
func (r *policyRepository) GetWorkCenterPolicy(ctx context.Context, companyID uuid.UUID, workCenterCode string) (*models.AttendancePolicy, error) {
	query := `
		SELECT policy_id, company_id, work_center_code, position_id,
		       policy_code, policy_type, rules, is_active,
		       created_at, updated_at
		FROM attendance.attendance_policies
		WHERE company_id = $1
		  AND work_center_code = $2
		  AND is_active = true
		  AND effective_from <= CURRENT_DATE
		  AND (effective_to IS NULL OR effective_to >= CURRENT_DATE)
		ORDER BY effective_from DESC
		LIMIT 1
	`
	row := r.client.QueryRow(ctx, query, companyID, workCenterCode)
	return r.scanPolicy(row)
}

// GetWorkCenterPolicyOnDate is the date-scoped variant.
func (r *policyRepository) GetWorkCenterPolicyOnDate(ctx context.Context, companyID uuid.UUID, workCenterCode string, date time.Time) (*models.AttendancePolicy, error) {
	query := `
		SELECT policy_id, company_id, work_center_code, position_id,
		       policy_code, policy_type, rules, is_active,
		       created_at, updated_at
		FROM attendance.attendance_policies
		WHERE company_id = $1
		  AND work_center_code = $2
		  AND is_active = true
		  AND effective_from <= $3::date
		  AND (effective_to IS NULL OR effective_to >= $3::date)
		ORDER BY effective_from DESC
		LIMIT 1
	`
	row := r.client.QueryRow(ctx, query, companyID, workCenterCode, date)
	return r.scanPolicy(row)
}

// UpdatePolicy versions in place: close the current row, insert a new one.
// Same-day edits collapse into the current row so a user fixing a typo
// doesn't blow up the version history.
func (r *policyRepository) UpdatePolicy(ctx context.Context, tx *sql.Tx, policy *models.AttendancePolicy) error {
	policy.UpdatedAt = time.Now().UTC()
	rulesJSON, err := json.Marshal(policy.Rules)
	if err != nil {
		return fmt.Errorf("marshal rules: %w", err)
	}

	exec := func(q string, args ...interface{}) (sql.Result, error) {
		if tx != nil {
			return tx.ExecContext(ctx, q, args...)
		}
		return r.client.Exec(ctx, q, args...)
	}

	// Case 1: the open version was created today. Collapse the edit into it.
	res, err := exec(`
		UPDATE attendance.attendance_policies
		SET work_center_code = $1,
		    position_id = $2,
		    policy_code = $3,
		    policy_type = $4,
		    rules = $5,
		    is_active = $6,
		    updated_at = $7
		WHERE policy_id = $8
		  AND effective_to IS NULL
		  AND effective_from = CURRENT_DATE
	`,
		policy.WorkCenterCode,
		policy.PositionID,
		policy.PolicyCode,
		policy.PolicyType,
		rulesJSON,
		policy.IsActive,
		policy.UpdatedAt,
		policy.PolicyID,
	)
	if err != nil {
		return fmt.Errorf("update same-day policy version: %w", err)
	}
	affected, _ := res.RowsAffected()
	if affected > 0 {
		return nil
	}

	// Case 2: close the open version, insert a new one starting today.
	if _, err := exec(`
		UPDATE attendance.attendance_policies
		SET effective_to = CURRENT_DATE - 1
		WHERE policy_id = $1
		  AND effective_to IS NULL
	`, policy.PolicyID); err != nil {
		return fmt.Errorf("close old policy version: %w", err)
	}

	if _, err := exec(`
		INSERT INTO attendance.attendance_policies (
			policy_id, company_id, work_center_code, position_id,
			policy_code, policy_type, rules, is_active,
			created_at, updated_at, effective_from
		) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, CURRENT_DATE)
	`,
		policy.PolicyID,
		policy.CompanyID,
		policy.WorkCenterCode,
		policy.PositionID,
		policy.PolicyCode,
		policy.PolicyType,
		rulesJSON,
		policy.IsActive,
		policy.CreatedAt,
		policy.UpdatedAt,
	); err != nil {
		return fmt.Errorf("insert new policy version: %w", err)
	}
	return nil
}

func (r *policyRepository) DeletePolicy(ctx context.Context, policyID uuid.UUID) error {
	query := `DELETE FROM attendance.attendance_policies WHERE policy_id = $1`
	result, err := r.client.Exec(ctx, query, policyID)
	if err != nil {
		r.logger.Error("failed to delete policy",
			util.String("policy_id", policyID.String()),
			util.ErrorField(err))
		return fmt.Errorf("delete policy: %w", err)
	}
	rows, _ := result.RowsAffected()
	if rows == 0 {
		return errors.New("policy not found")
	}
	return nil
}

// AssignUserPolicy (legacy) – now also sets subject_type='employee', subject_id=user_id
func (r *policyRepository) AssignUserPolicy(ctx context.Context, tx *sql.Tx, assignment *models.UserAttendancePolicy) error {
	if assignment.CreatedAt.IsZero() {
		assignment.CreatedAt = time.Now().UTC()
	}
	if assignment.SubjectType == "" {
		assignment.SubjectType = "employee"
	}
	if assignment.SubjectID == nil {
		assignment.SubjectID = &assignment.UserID
	}

	query := `
		INSERT INTO attendance.user_attendance_policies (
			user_id, policy_id, effective_from, effective_to,
			assigned_by, created_at, subject_type, subject_id
		) VALUES ($1, $2, $3, $4, $5, $6, $7, $8)
	`

	exec := func(q string, args ...interface{}) (sql.Result, error) {
		if tx != nil {
			return tx.ExecContext(ctx, q, args...)
		}
		return r.client.Exec(ctx, q, args...)
	}

	_, err := exec(query,
		assignment.UserID,
		assignment.PolicyID,
		assignment.EffectiveFrom,
		assignment.EffectiveTo,
		assignment.AssignedBy,
		assignment.CreatedAt,
		assignment.SubjectType,
		assignment.SubjectID,
	)
	if err != nil {
		r.logger.Error("failed to assign user policy",
			util.String("user_id", assignment.UserID.String()),
			util.String("policy_id", assignment.PolicyID.String()),
			util.ErrorField(err))
		return fmt.Errorf("assign user policy: %w", err)
	}
	return nil
}

// GetUserActivePolicy (legacy) – tries the polymorphic lookup first,
// then falls back to the legacy user_id query. Both filter the policy
// version so the caller gets the rules that were true on `at`.
func (r *policyRepository) GetUserActivePolicy(ctx context.Context, userID uuid.UUID, at time.Time) (*models.AttendancePolicy, error) {
	policy, err := r.GetActivePolicyBySubject(ctx, "employee", userID, at)
	if err == nil && policy != nil {
		return policy, nil
	}

	query := `
		SELECT ap.policy_id, ap.company_id, ap.work_center_code, ap.position_id,
		       ap.policy_code, ap.policy_type, ap.rules, ap.is_active,
		       ap.created_at, ap.updated_at
		FROM attendance.user_attendance_policies uap
		JOIN attendance.attendance_policies ap ON uap.policy_id = ap.policy_id
		WHERE uap.user_id = $1
		  AND uap.effective_from <= $2
		  AND (uap.effective_to IS NULL OR uap.effective_to >= $2)
		  AND ap.is_active = true
		  AND ap.effective_from <= $2::date
		  AND (ap.effective_to IS NULL OR ap.effective_to >= $2::date)
		ORDER BY uap.effective_from DESC, ap.effective_from DESC
		LIMIT 1
	`
	row := r.client.QueryRow(ctx, query, userID, at)
	return r.scanPolicy(row)
}

// EndUserPolicy (legacy) – tries legacy first, then polymorphic
func (r *policyRepository) EndUserPolicy(ctx context.Context, userID, policyID uuid.UUID, endDate time.Time) error {
	query := `
		UPDATE attendance.user_attendance_policies
		SET effective_to = $1
		WHERE user_id = $2 AND policy_id = $3 AND effective_to IS NULL
	`
	result, err := r.client.Exec(ctx, query, endDate, userID, policyID)
	if err != nil {
		return fmt.Errorf("end user policy: %w", err)
	}
	rows, _ := result.RowsAffected()
	if rows == 0 {
		return r.EndPolicyForSubject(ctx, "employee", userID, policyID, endDate)
	}
	return nil
}

// GetUsersByPolicy (legacy) – only returns employees (user_ids)
func (r *policyRepository) GetUsersByPolicy(ctx context.Context, policyID uuid.UUID, effectiveDate time.Time) ([]uuid.UUID, error) {
	query := `
		SELECT user_id
		FROM attendance.user_attendance_policies
		WHERE policy_id = $1
		  AND effective_from <= $2
		  AND (effective_to IS NULL OR effective_to >= $2)
	`
	rows, err := r.client.Query(ctx, query, policyID, effectiveDate)
	if err != nil {
		r.logger.Error("failed to get users by policy",
			util.String("policy_id", policyID.String()),
			util.ErrorField(err))
		return nil, fmt.Errorf("get users by policy: %w", err)
	}
	defer rows.Close()

	var userIDs []uuid.UUID
	for rows.Next() {
		var id uuid.UUID
		if err := rows.Scan(&id); err != nil {
			return nil, fmt.Errorf("scan user_id: %w", err)
		}
		userIDs = append(userIDs, id)
	}
	if err = rows.Err(); err != nil {
		return nil, fmt.Errorf("rows iteration: %w", err)
	}
	return userIDs, nil
}

// GetUserPolicyAssignment (legacy) – unchanged
func (r *policyRepository) GetUserPolicyAssignment(ctx context.Context, userID, policyID uuid.UUID, effectiveFrom time.Time) (*models.UserAttendancePolicy, error) {
	query := `
		SELECT user_id, policy_id, effective_from, effective_to, assigned_by, created_at
		FROM attendance.user_attendance_policies
		WHERE user_id = $1 AND policy_id = $2 AND effective_from = $3
	`
	row := r.client.QueryRow(ctx, query, userID, policyID, effectiveFrom)
	var uap models.UserAttendancePolicy
	err := row.Scan(
		&uap.UserID,
		&uap.PolicyID,
		&uap.EffectiveFrom,
		&uap.EffectiveTo,
		&uap.AssignedBy,
		&uap.CreatedAt,
	)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, nil
		}
		return nil, fmt.Errorf("scan user policy assignment: %w", err)
	}
	return &uap, nil
}

// =============================================================================
// NEW POLYMORPHIC METHODS (support any subject type)
// =============================================================================

// AssignPolicyToSubject assigns a policy to any subject (employee, student, teacher, etc.)
func (r *policyRepository) AssignPolicyToSubject(ctx context.Context, tx *sql.Tx, subjectType string, subjectID uuid.UUID, policyID uuid.UUID, effectiveFrom, effectiveTo *time.Time, assignedBy *uuid.UUID) error {
	if subjectType == "" {
		subjectType = "employee"
	}
	now := time.Now().UTC()
	var userID uuid.UUID
	if subjectType == "employee" {
		userID = subjectID
	}

	query := `
		INSERT INTO attendance.user_attendance_policies (
			user_id, policy_id, effective_from, effective_to,
			assigned_by, created_at, subject_type, subject_id
		) VALUES ($1, $2, $3, $4, $5, $6, $7, $8)
	`
	exec := func(q string, args ...interface{}) (sql.Result, error) {
		if tx != nil {
			return tx.ExecContext(ctx, q, args...)
		}
		return r.client.Exec(ctx, q, args...)
	}

	_, err := exec(query,
		userID,
		policyID,
		effectiveFrom,
		effectiveTo,
		assignedBy,
		now,
		subjectType,
		subjectID,
	)
	if err != nil {
		r.logger.Error("failed to assign policy to subject",
			util.String("subject_type", subjectType),
			util.String("subject_id", subjectID.String()),
			util.String("policy_id", policyID.String()),
			util.ErrorField(err))
		return fmt.Errorf("assign policy to subject: %w", err)
	}
	return nil
}

// GetActivePolicyBySubject retrieves the policy version active on `at`,
// filtering both the assignment window (user_attendance_policies) and the
// policy version window (attendance_policies).
func (r *policyRepository) GetActivePolicyBySubject(ctx context.Context, subjectType string, subjectID uuid.UUID, at time.Time) (*models.AttendancePolicy, error) {
	query := `
		SELECT ap.policy_id, ap.company_id, ap.work_center_code, ap.position_id,
		       ap.policy_code, ap.policy_type, ap.rules, ap.is_active,
		       ap.created_at, ap.updated_at
		FROM attendance.user_attendance_policies uap
		JOIN attendance.attendance_policies ap ON uap.policy_id = ap.policy_id
		WHERE uap.subject_type = $1
		  AND uap.subject_id = $2
		  AND uap.effective_from <= $3
		  AND (uap.effective_to IS NULL OR uap.effective_to >= $3)
		  AND ap.is_active = true
		  AND ap.effective_from <= $3::date
		  AND (ap.effective_to IS NULL OR ap.effective_to >= $3::date)
		ORDER BY uap.effective_from DESC, ap.effective_from DESC
		LIMIT 1
	`
	row := r.client.QueryRow(ctx, query, subjectType, subjectID, at)
	return r.scanPolicy(row)
}

// EndPolicyForSubject ends an active subject-policy assignment
func (r *policyRepository) EndPolicyForSubject(ctx context.Context, subjectType string, subjectID uuid.UUID, policyID uuid.UUID, endDate time.Time) error {
	query := `
		UPDATE attendance.user_attendance_policies
		SET effective_to = $1
		WHERE subject_type = $2
		  AND subject_id = $3
		  AND policy_id = $4
		  AND effective_to IS NULL
	`
	result, err := r.client.Exec(ctx, query, endDate, subjectType, subjectID, policyID)
	if err != nil {
		r.logger.Error("failed to end policy for subject",
			util.String("subject_type", subjectType),
			util.String("subject_id", subjectID.String()),
			util.String("policy_id", policyID.String()),
			util.ErrorField(err))
		return fmt.Errorf("end policy for subject: %w", err)
	}
	rows, _ := result.RowsAffected()
	if rows == 0 {
		return errors.New("active subject-policy assignment not found")
	}
	return nil
}

// GetSubjectsByPolicy retrieves subject IDs of a given type assigned to a policy at a given date
func (r *policyRepository) GetSubjectsByPolicy(ctx context.Context, policyID uuid.UUID, subjectType string, effectiveDate time.Time) ([]uuid.UUID, error) {
	query := `
		SELECT subject_id
		FROM attendance.user_attendance_policies
		WHERE policy_id = $1
		  AND subject_type = $2
		  AND effective_from <= $3
		  AND (effective_to IS NULL OR effective_to >= $3)
	`
	rows, err := r.client.Query(ctx, query, policyID, subjectType, effectiveDate)
	if err != nil {
		r.logger.Error("failed to get subjects by policy",
			util.String("policy_id", policyID.String()),
			util.String("subject_type", subjectType),
			util.ErrorField(err))
		return nil, fmt.Errorf("get subjects by policy: %w", err)
	}
	defer rows.Close()

	var subjectIDs []uuid.UUID
	for rows.Next() {
		var id uuid.UUID
		if err := rows.Scan(&id); err != nil {
			return nil, fmt.Errorf("scan subject_id: %w", err)
		}
		subjectIDs = append(subjectIDs, id)
	}
	if err = rows.Err(); err != nil {
		return nil, fmt.Errorf("rows iteration: %w", err)
	}
	return subjectIDs, nil
}

// =============================================================================
// Health check
// =============================================================================

func (r *policyRepository) HealthCheck(ctx context.Context) error {
	query := `SELECT 1 FROM attendance.attendance_policies LIMIT 1`
	_, err := r.client.Exec(ctx, query)
	if err != nil {
		r.logger.Error("health check failed", util.ErrorField(err))
		return fmt.Errorf("health check: %w", err)
	}
	return nil
}

// =============================================================================
// Internal scanning helpers
// =============================================================================

func (r *policyRepository) scanPolicy(row *sql.Row) (*models.AttendancePolicy, error) {
	var policy models.AttendancePolicy
	var rulesJSON []byte
	err := row.Scan(
		&policy.PolicyID,
		&policy.CompanyID,
		&policy.WorkCenterCode,
		&policy.PositionID,
		&policy.PolicyCode,
		&policy.PolicyType,
		&rulesJSON,
		&policy.IsActive,
		&policy.CreatedAt,
		&policy.UpdatedAt,
	)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, nil
		}
		return nil, fmt.Errorf("scan policy: %w", err)
	}
	if err := json.Unmarshal(rulesJSON, &policy.Rules); err != nil {
		return nil, fmt.Errorf("unmarshal rules: %w", err)
	}
	return &policy, nil
}

func (r *policyRepository) scanPolicyFromRows(rows *sql.Rows) (*models.AttendancePolicy, error) {
	var policy models.AttendancePolicy
	var rulesJSON []byte
	err := rows.Scan(
		&policy.PolicyID,
		&policy.CompanyID,
		&policy.WorkCenterCode,
		&policy.PositionID,
		&policy.PolicyCode,
		&policy.PolicyType,
		&rulesJSON,
		&policy.IsActive,
		&policy.CreatedAt,
		&policy.UpdatedAt,
	)
	if err != nil {
		return nil, fmt.Errorf("scan policy rows: %w", err)
	}
	if err := json.Unmarshal(rulesJSON, &policy.Rules); err != nil {
		return nil, fmt.Errorf("unmarshal rules: %w", err)
	}
	return &policy, nil
}

package repository

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"time"

	"github.com/google/uuid"
	"go.uber.org/zap"

	"auth-service/internal/client"
	"auth-service/internal/hr/payroll/models"
	"auth-service/internal/util"
)

type attendanceRuleRepository struct {
	client *client.PostgresClient
	logger *zap.Logger
}

// NewAttendanceRuleRepository creates a new AttendanceRuleRepository instance.
func NewAttendanceRuleRepository(
	postgresClient *client.PostgresClient,
	logger *zap.Logger,
) AttendanceRuleRepository {
	return &attendanceRuleRepository{
		client: postgresClient,
		logger: logger,
	}
}

// ---------------------------------------------------------------------
// CRUD
// ---------------------------------------------------------------------

func (r *attendanceRuleRepository) Create(ctx context.Context, rule *models.AttendanceRule) error {
	// Defensive: set ID if missing
	if rule.RuleID == uuid.Nil {
		rule.RuleID = uuid.New()
	}
	if rule.CreatedAt.IsZero() {
		rule.CreatedAt = time.Now().UTC()
	}
	if rule.UpdatedAt == nil {
		rule.UpdatedAt = &rule.CreatedAt
	}

	query := `
		INSERT INTO payroll.attendance_rule (
			rule_id,
			company_id,
			rule_type,
			calculation_type,
			value,
			based_on,
			threshold_minutes,
			is_active,
			created_at,
			created_by,
			updated_at,
			updated_by
		) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12)
	`

	_, err := r.client.Exec(ctx, query,
		rule.RuleID,
		rule.CompanyID,
		rule.RuleType,
		rule.CalculationType,
		rule.Value,
		rule.BasedOn,
		rule.ThresholdMinutes,
		rule.IsActive,
		rule.CreatedAt,
		rule.CreatedBy,
		rule.UpdatedAt,
		rule.UpdatedBy,
	)
	if err != nil {
		r.logger.Error("Failed to create attendance rule",
			util.String("rule_id", rule.RuleID.String()),
			util.String("company_id", rule.CompanyID.String()),
			util.ErrorField(err),
		)
		return fmt.Errorf("failed to create attendance rule: %w", err)
	}
	return nil
}

func (r *attendanceRuleRepository) Update(ctx context.Context, rule *models.AttendanceRule) error {
	now := time.Now().UTC()
	rule.UpdatedAt = &now

	query := `
		UPDATE payroll.attendance_rule
		SET
			rule_type = $1,
			calculation_type = $2,
			value = $3,
			based_on = $4,
			threshold_minutes = $5,
			is_active = $6,
			updated_at = $7,
			updated_by = $8
		WHERE rule_id = $9 AND company_id = $10
	`
	result, err := r.client.Exec(ctx, query,
		rule.RuleType,
		rule.CalculationType,
		rule.Value,
		rule.BasedOn,
		rule.ThresholdMinutes,
		rule.IsActive,
		rule.UpdatedAt,
		rule.UpdatedBy,
		rule.RuleID,
		rule.CompanyID,
	)
	if err != nil {
		r.logger.Error("Failed to update attendance rule",
			util.String("rule_id", rule.RuleID.String()),
			util.String("company_id", rule.CompanyID.String()),
			util.ErrorField(err),
		)
		return fmt.Errorf("failed to update attendance rule: %w", err)
	}
	rowsAffected, _ := result.RowsAffected()
	if rowsAffected == 0 {
		return fmt.Errorf("attendance rule not found for company")
	}
	return nil
}

func (r *attendanceRuleRepository) SoftDeactivate(ctx context.Context, companyID, ruleID, actorID uuid.UUID) error {
	now := time.Now().UTC()
	query := `
		UPDATE payroll.attendance_rule
		SET
			is_active = false,
			updated_at = $1,
			updated_by = $2
		WHERE rule_id = $3 AND company_id = $4
	`
	result, err := r.client.Exec(ctx, query, now, actorID, ruleID, companyID)
	if err != nil {
		r.logger.Error("Failed to soft‑deactivate attendance rule",
			util.String("rule_id", ruleID.String()),
			util.String("company_id", companyID.String()),
			util.ErrorField(err),
		)
		return fmt.Errorf("failed to deactivate attendance rule: %w", err)
	}
	rowsAffected, _ := result.RowsAffected()
	if rowsAffected == 0 {
		return fmt.Errorf("attendance rule not found")
	}
	return nil
}

func (r *attendanceRuleRepository) GetByID(ctx context.Context, companyID, ruleID uuid.UUID) (*models.AttendanceRule, error) {
	query := `
		SELECT
			rule_id,
			company_id,
			rule_type,
			calculation_type,
			value,
			based_on,
			threshold_minutes,
			is_active,
			created_at,
			created_by,
			updated_at,
			updated_by
		FROM payroll.attendance_rule
		WHERE rule_id = $1 AND company_id = $2
	`
	row := r.client.QueryRow(ctx, query, ruleID, companyID)
	var rule models.AttendanceRule
	err := row.Scan(
		&rule.RuleID,
		&rule.CompanyID,
		&rule.RuleType,
		&rule.CalculationType,
		&rule.Value,
		&rule.BasedOn,
		&rule.ThresholdMinutes,
		&rule.IsActive,
		&rule.CreatedAt,
		&rule.CreatedBy,
		&rule.UpdatedAt,
		&rule.UpdatedBy,
	)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, nil
		}
		r.logger.Error("Failed to get attendance rule by ID",
			util.String("rule_id", ruleID.String()),
			util.String("company_id", companyID.String()),
			util.ErrorField(err),
		)
		return nil, fmt.Errorf("failed to get attendance rule: %w", err)
	}
	return &rule, nil
}

// ---------------------------------------------------------------------
// Queries
// ---------------------------------------------------------------------

func (r *attendanceRuleRepository) GetActiveByCompany(
	ctx context.Context,
	companyID uuid.UUID,
	asOf time.Time,
) ([]models.AttendanceRule, error) {
	query := `
		SELECT
			rule_id,
			company_id,
			rule_type,
			calculation_type,
			value,
			based_on,
			threshold_minutes,
			is_active,
			created_at,
			created_by,
			updated_at,
			updated_by
		FROM payroll.attendance_rule
		WHERE company_id = $1
			AND is_active = true
			AND (created_at <= $2 OR updated_at <= $2)
	`
	rows, err := r.client.Query(ctx, query, companyID, asOf)
	if err != nil {
		r.logger.Error("Failed to get active attendance rules",
			util.String("company_id", companyID.String()),
			util.ErrorField(err),
		)
		return nil, fmt.Errorf("failed to get active attendance rules: %w", err)
	}
	defer rows.Close()

	var rules []models.AttendanceRule
	for rows.Next() {
		var rule models.AttendanceRule
		if err := rows.Scan(
			&rule.RuleID,
			&rule.CompanyID,
			&rule.RuleType,
			&rule.CalculationType,
			&rule.Value,
			&rule.BasedOn,
			&rule.ThresholdMinutes,
			&rule.IsActive,
			&rule.CreatedAt,
			&rule.CreatedBy,
			&rule.UpdatedAt,
			&rule.UpdatedBy,
		); err != nil {
			return nil, fmt.Errorf("failed to scan attendance rule: %w", err)
		}
		rules = append(rules, rule)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("rows iteration error: %w", err)
	}
	return rules, nil
}

func (r *attendanceRuleRepository) GetByFilter(
	ctx context.Context,
	filter models.AttendanceRuleFilter,
) ([]models.AttendanceRule, int, error) {
	// Build WHERE clause dynamically
	whereClause := "WHERE company_id = $1"
	args := []interface{}{filter.CompanyID}
	paramIdx := 2

	if filter.RuleType != nil {
		whereClause += fmt.Sprintf(" AND rule_type = $%d", paramIdx)
		args = append(args, *filter.RuleType)
		paramIdx++
	}
	if filter.IsActive != nil {
		whereClause += fmt.Sprintf(" AND is_active = $%d", paramIdx)
		args = append(args, *filter.IsActive)
		paramIdx++
	}
	if filter.BasedOn != nil {
		whereClause += fmt.Sprintf(" AND based_on = $%d", paramIdx)
		args = append(args, *filter.BasedOn)
		paramIdx++
	}
	if filter.MinThreshold != nil {
		whereClause += fmt.Sprintf(" AND threshold_minutes >= $%d", paramIdx)
		args = append(args, *filter.MinThreshold)
		paramIdx++
	}

	// Count total
	countQuery := `SELECT COUNT(*) FROM payroll.attendance_rule ` + whereClause
	var total int
	err := r.client.QueryRow(ctx, countQuery, args...).Scan(&total)
	if err != nil {
		r.logger.Error("Failed to count attendance rules by filter",
			util.String("company_id", filter.CompanyID.String()),
			util.ErrorField(err),
		)
		return nil, 0, fmt.Errorf("failed to count attendance rules: %w", err)
	}
	if total == 0 {
		return []models.AttendanceRule{}, 0, nil
	}

	// Fetch paginated data
	query := `
		SELECT
			rule_id,
			company_id,
			rule_type,
			calculation_type,
			value,
			based_on,
			threshold_minutes,
			is_active,
			created_at,
			created_by,
			updated_at,
			updated_by
		FROM payroll.attendance_rule
	` + whereClause + ` ORDER BY created_at DESC`

	// Add pagination
	if filter.Page > 0 && filter.PageSize > 0 {
		offset := (filter.Page - 1) * filter.PageSize
		query += fmt.Sprintf(" LIMIT $%d OFFSET $%d", paramIdx, paramIdx+1)
		args = append(args, filter.PageSize, offset)
	} else {
		// default limit to avoid huge result sets
		query += fmt.Sprintf(" LIMIT $%d", paramIdx)
		args = append(args, 100)
	}

	rows, err := r.client.Query(ctx, query, args...)
	if err != nil {
		r.logger.Error("Failed to get attendance rules by filter",
			util.String("company_id", filter.CompanyID.String()),
			util.ErrorField(err),
		)
		return nil, 0, fmt.Errorf("failed to get attendance rules: %w", err)
	}
	defer rows.Close()

	var rules []models.AttendanceRule
	for rows.Next() {
		var rule models.AttendanceRule
		if err := rows.Scan(
			&rule.RuleID,
			&rule.CompanyID,
			&rule.RuleType,
			&rule.CalculationType,
			&rule.Value,
			&rule.BasedOn,
			&rule.ThresholdMinutes,
			&rule.IsActive,
			&rule.CreatedAt,
			&rule.CreatedBy,
			&rule.UpdatedAt,
			&rule.UpdatedBy,
		); err != nil {
			return nil, 0, fmt.Errorf("failed to scan attendance rule: %w", err)
		}
		rules = append(rules, rule)
	}
	if err := rows.Err(); err != nil {
		return nil, 0, fmt.Errorf("rows iteration error: %w", err)
	}
	return rules, total, nil
}

func (r *attendanceRuleRepository) GetByRuleType(
	ctx context.Context,
	companyID uuid.UUID,
	ruleType string,
) ([]models.AttendanceRule, error) {
	query := `
		SELECT
			rule_id,
			company_id,
			rule_type,
			calculation_type,
			value,
			based_on,
			threshold_minutes,
			is_active,
			created_at,
			created_by,
			updated_at,
			updated_by
		FROM payroll.attendance_rule
		WHERE company_id = $1 AND rule_type = $2
		ORDER BY created_at DESC
	`
	rows, err := r.client.Query(ctx, query, companyID, ruleType)
	if err != nil {
		r.logger.Error("Failed to get attendance rules by type",
			util.String("company_id", companyID.String()),
			util.String("rule_type", ruleType),
			util.ErrorField(err),
		)
		return nil, fmt.Errorf("failed to get attendance rules by type: %w", err)
	}
	defer rows.Close()

	var rules []models.AttendanceRule
	for rows.Next() {
		var rule models.AttendanceRule
		if err := rows.Scan(
			&rule.RuleID,
			&rule.CompanyID,
			&rule.RuleType,
			&rule.CalculationType,
			&rule.Value,
			&rule.BasedOn,
			&rule.ThresholdMinutes,
			&rule.IsActive,
			&rule.CreatedAt,
			&rule.CreatedBy,
			&rule.UpdatedAt,
			&rule.UpdatedBy,
		); err != nil {
			return nil, fmt.Errorf("failed to scan attendance rule: %w", err)
		}
		rules = append(rules, rule)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("rows iteration error: %w", err)
	}
	return rules, nil
}

// ---------------------------------------------------------------------
// Bulk / Versioning Safety
// ---------------------------------------------------------------------

func (r *attendanceRuleRepository) BulkDeactivateByType(
	ctx context.Context,
	companyID uuid.UUID,
	ruleType string,
	actorID uuid.UUID,
) error {
	now := time.Now().UTC()
	query := `
		UPDATE payroll.attendance_rule
		SET
			is_active = false,
			updated_at = $1,
			updated_by = $2
		WHERE company_id = $3 AND rule_type = $4 AND is_active = true
	`
	_, err := r.client.Exec(ctx, query, now, actorID, companyID, ruleType)
	if err != nil {
		r.logger.Error("Failed to bulk deactivate attendance rules by type",
			util.String("company_id", companyID.String()),
			util.String("rule_type", ruleType),
			util.ErrorField(err),
		)
		return fmt.Errorf("failed to bulk deactivate attendance rules: %w", err)
	}
	return nil
}

func (r *attendanceRuleRepository) ExistsActiveRuleOfType(
	ctx context.Context,
	companyID uuid.UUID,
	ruleType string,
) (bool, error) {
	query := `
		SELECT EXISTS (
			SELECT 1
			FROM payroll.attendance_rule
			WHERE company_id = $1 AND rule_type = $2 AND is_active = true
		)
	`
	var exists bool
	err := r.client.QueryRow(ctx, query, companyID, ruleType).Scan(&exists)
	if err != nil {
		r.logger.Error("Failed to check existence of active rule",
			util.String("company_id", companyID.String()),
			util.String("rule_type", ruleType),
			util.ErrorField(err),
		)
		return false, fmt.Errorf("failed to check active rule existence: %w", err)
	}
	return exists, nil
}

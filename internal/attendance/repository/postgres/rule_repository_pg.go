package postgres

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"time"

	"github.com/google/uuid"
	"github.com/lib/pq"
	"go.uber.org/zap"

	"auth-service/internal/attendance/models"
	"auth-service/internal/attendance/repository"
	"auth-service/internal/client"
	"auth-service/internal/util"
)

type ruleRepository struct {
	client *client.PostgresClient
	logger *zap.Logger
}

func NewRuleRepository(pg *client.PostgresClient, logger *zap.Logger) repository.RuleRepository {
	return &ruleRepository{
		client: pg,
		logger: logger.Named("rule_repo"),
	}
}

// ──────────────────────────────────────────────────────────────
// COMPANY RULES
// ──────────────────────────────────────────────────────────────

func (r *ruleRepository) GetCompanyRules(ctx context.Context, companyID uuid.UUID) (*models.CompanyAttendanceRules, error) {
	query := `
		SELECT company_id, allowed_source_types, allow_multiple_checkins,
		       timezone, created_at
		FROM attendance.company_attendance_rules
		WHERE company_id = $1
	`
	row := r.client.QueryRow(ctx, query, companyID)

	var rules models.CompanyAttendanceRules
	var allowedSources []string

	err := row.Scan(
		&rules.CompanyID,
		pq.Array(&allowedSources),
		&rules.AllowMultipleCheckins,
		&rules.Timezone,
		&rules.CreatedAt,
	)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, nil
		}
		r.logger.Error("failed to get company attendance rules",
			util.String("company_id", companyID.String()),
			util.ErrorField(err))
		return nil, fmt.Errorf("get company rules: %w", err)
	}
	rules.AllowedSourceTypes = allowedSources
	return &rules, nil
}

func (r *ruleRepository) UpsertCompanyRules(ctx context.Context, tx *sql.Tx, rules *models.CompanyAttendanceRules) error {
	if rules.CreatedAt.IsZero() {
		rules.CreatedAt = time.Now().UTC()
	}

	query := `
		INSERT INTO attendance.company_attendance_rules (
			company_id, allowed_source_types, allow_multiple_checkins,
			timezone, created_at
		) VALUES ($1, $2, $3, $4, $5)
		ON CONFLICT (company_id) DO UPDATE SET
			allowed_source_types = EXCLUDED.allowed_source_types,
			allow_multiple_checkins = EXCLUDED.allow_multiple_checkins,
			timezone = EXCLUDED.timezone
	`

	exec := func(q string, args ...interface{}) (sql.Result, error) {
		if tx != nil {
			return tx.ExecContext(ctx, q, args...)
		}
		return r.client.Exec(ctx, q, args...)
	}

	_, err := exec(query,
		rules.CompanyID,
		pq.Array(rules.AllowedSourceTypes),
		rules.AllowMultipleCheckins,
		rules.Timezone,
		rules.CreatedAt,
	)
	if err != nil {
		r.logger.Error("failed to upsert company attendance rules",
			util.String("company_id", rules.CompanyID.String()),
			util.ErrorField(err))
		return fmt.Errorf("upsert company rules: %w", err)
	}
	return nil
}

// ──────────────────────────────────────────────────────────────
// DEPARTMENT RULES
// ──────────────────────────────────────────────────────────────

func (r *ruleRepository) GetDepartmentRules(ctx context.Context, companyID, departmentID uuid.UUID) (*models.DepartmentAttendanceRules, error) {
	query := `
		SELECT rule_id, company_id, department_id,
		       allowed_source_types, allowed_event_types,
		       require_location, require_device, created_at
		FROM attendance.department_attendance_rules
		WHERE company_id = $1 AND department_id = $2
	`
	row := r.client.QueryRow(ctx, query, companyID, departmentID)

	var rules models.DepartmentAttendanceRules
	var allowedSources, allowedEvents []string

	err := row.Scan(
		&rules.RuleID,
		&rules.CompanyID,
		&rules.DepartmentID,
		pq.Array(&allowedSources),
		pq.Array(&allowedEvents),
		&rules.RequireLocation,
		&rules.RequireDevice,
		&rules.CreatedAt,
	)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, nil
		}
		r.logger.Error("failed to get department attendance rules",
			util.String("company_id", companyID.String()),
			util.String("department_id", departmentID.String()),
			util.ErrorField(err))
		return nil, fmt.Errorf("get department rules: %w", err)
	}
	rules.AllowedSourceTypes = allowedSources
	rules.AllowedEventTypes = allowedEvents
	return &rules, nil
}

func (r *ruleRepository) UpsertDepartmentRules(ctx context.Context, tx *sql.Tx, rules *models.DepartmentAttendanceRules) error {
	if rules.RuleID == uuid.Nil {
		rules.RuleID = uuid.New()
	}
	if rules.CreatedAt.IsZero() {
		rules.CreatedAt = time.Now().UTC()
	}

	query := `
		INSERT INTO attendance.department_attendance_rules (
			rule_id, company_id, department_id,
			allowed_source_types, allowed_event_types,
			require_location, require_device, created_at
		) VALUES ($1, $2, $3, $4, $5, $6, $7, $8)
		ON CONFLICT (company_id, department_id) DO UPDATE SET
			allowed_source_types = EXCLUDED.allowed_source_types,
			allowed_event_types = EXCLUDED.allowed_event_types,
			require_location = EXCLUDED.require_location,
			require_device = EXCLUDED.require_device
	`

	exec := func(q string, args ...interface{}) (sql.Result, error) {
		if tx != nil {
			return tx.ExecContext(ctx, q, args...)
		}
		return r.client.Exec(ctx, q, args...)
	}

	_, err := exec(query,
		rules.RuleID,
		rules.CompanyID,
		rules.DepartmentID,
		pq.Array(rules.AllowedSourceTypes),
		pq.Array(rules.AllowedEventTypes),
		rules.RequireLocation,
		rules.RequireDevice,
		rules.CreatedAt,
	)
	if err != nil {
		r.logger.Error("failed to upsert department attendance rules",
			util.String("company_id", rules.CompanyID.String()),
			util.String("department_id", rules.DepartmentID.String()),
			util.ErrorField(err))
		return fmt.Errorf("upsert department rules: %w", err)
	}
	return nil
}

// ──────────────────────────────────────────────────────────────
// USER ATTENDANCE PROFILE
// ──────────────────────────────────────────────────────────────

func (r *ruleRepository) GetUserProfile(ctx context.Context, userID uuid.UUID) (*models.UserAttendanceProfile, error) {
	query := `
		SELECT user_id, company_id, override_source_types, override_event_types, created_at
		FROM attendance.user_attendance_profiles
		WHERE user_id = $1
	`
	row := r.client.QueryRow(ctx, query, userID)

	var profile models.UserAttendanceProfile
	var overrideSources, overrideEvents []string

	err := row.Scan(
		&profile.UserID,
		&profile.CompanyID,
		pq.Array(&overrideSources),
		pq.Array(&overrideEvents),
		&profile.CreatedAt,
	)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, nil
		}
		r.logger.Error("failed to get user attendance profile",
			util.String("user_id", userID.String()),
			util.ErrorField(err))
		return nil, fmt.Errorf("get user profile: %w", err)
	}
	profile.OverrideSourceTypes = overrideSources
	profile.OverrideEventTypes = overrideEvents
	return &profile, nil
}

func (r *ruleRepository) UpsertUserProfile(ctx context.Context, tx *sql.Tx, profile *models.UserAttendanceProfile) error {
	if profile.CreatedAt.IsZero() {
		profile.CreatedAt = time.Now().UTC()
	}

	query := `
		INSERT INTO attendance.user_attendance_profiles (
			user_id, company_id, override_source_types, override_event_types, created_at
		) VALUES ($1, $2, $3, $4, $5)
		ON CONFLICT (user_id) DO UPDATE SET
			override_source_types = EXCLUDED.override_source_types,
			override_event_types = EXCLUDED.override_event_types
	`

	exec := func(q string, args ...interface{}) (sql.Result, error) {
		if tx != nil {
			return tx.ExecContext(ctx, q, args...)
		}
		return r.client.Exec(ctx, q, args...)
	}

	_, err := exec(query,
		profile.UserID,
		profile.CompanyID,
		pq.Array(profile.OverrideSourceTypes),
		pq.Array(profile.OverrideEventTypes),
		profile.CreatedAt,
	)
	if err != nil {
		r.logger.Error("failed to upsert user attendance profile",
			util.String("user_id", profile.UserID.String()),
			util.ErrorField(err))
		return fmt.Errorf("upsert user profile: %w", err)
	}
	return nil
}

// ──────────────────────────────────────────────────────────────
// HEALTH CHECK
// ──────────────────────────────────────────────────────────────

func (r *ruleRepository) HealthCheck(ctx context.Context) error {
	query := `SELECT 1 FROM attendance.company_attendance_rules LIMIT 1`
	_, err := r.client.Exec(ctx, query)
	if err != nil {
		r.logger.Error("rule repository health check failed", util.ErrorField(err))
		return fmt.Errorf("health check: %w", err)
	}
	return nil
}

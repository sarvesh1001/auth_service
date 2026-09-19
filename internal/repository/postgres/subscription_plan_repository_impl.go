package postgres

import (
	"context"
	"database/sql"
	"errors"
	"fmt"

	"github.com/google/uuid"
	"github.com/lib/pq"

	"auth-service/internal/client"
	apperrors "auth-service/internal/errors"
	"auth-service/internal/models"
)

// Ensure SubscriptionPlanRepositoryImpl implements the interface.
var _ SubscriptionPlanRepository = (*SubscriptionPlanRepositoryImpl)(nil)

type SubscriptionPlanRepositoryImpl struct {
	client *client.PostgresClient
}

func NewSubscriptionPlanRepository(pgClient *client.PostgresClient) *SubscriptionPlanRepositoryImpl {
	return &SubscriptionPlanRepositoryImpl{client: pgClient}
}

// ---------- Create ----------
func (r *SubscriptionPlanRepositoryImpl) Create(ctx context.Context, plan *models.SubscriptionPlan) error {
	query := `
		INSERT INTO subscription_plans (
			plan_id, plan_code, plan_name, description,
			duration_days, price, currency, gateway_plan_id,
			is_active, created_at, updated_at
		) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11)
	`
	_, err := r.client.Exec(ctx, query,
		plan.PlanID,
		plan.PlanCode,
		plan.PlanName,
		plan.Description,
		plan.DurationDays,
		plan.Price,
		plan.Currency,
		plan.GatewayPlanID,
		plan.IsActive,
		plan.CreatedAt,
		plan.UpdatedAt,
	)
	if err != nil {
		if pgErr, ok := err.(*pq.Error); ok && pgErr.Code == "23505" { // unique violation
			return apperrors.ErrDuplicate
		}
		return fmt.Errorf("failed to create subscription plan: %w", err)
	}
	return nil
}

// ---------- GetByID ----------
func (r *SubscriptionPlanRepositoryImpl) GetByID(ctx context.Context, planID uuid.UUID) (*models.SubscriptionPlan, error) {
	query := `
		SELECT plan_id, plan_code, plan_name, description,
			duration_days, price, currency, gateway_plan_id,
			is_active, created_at, updated_at, deleted_at
		FROM subscription_plans
		WHERE plan_id = $1 AND deleted_at IS NULL
	`
	var plan models.SubscriptionPlan
	var deletedAt sql.NullTime
	err := r.client.QueryRow(ctx, query, planID).Scan(
		&plan.PlanID,
		&plan.PlanCode,
		&plan.PlanName,
		&plan.Description,
		&plan.DurationDays,
		&plan.Price,
		&plan.Currency,
		&plan.GatewayPlanID,
		&plan.IsActive,
		&plan.CreatedAt,
		&plan.UpdatedAt,
		&deletedAt,
	)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, apperrors.ErrNotFound
		}
		return nil, fmt.Errorf("failed to get subscription plan by ID: %w", err)
	}
	if deletedAt.Valid {
		plan.DeletedAt = &deletedAt.Time
	}
	return &plan, nil
}

// ---------- GetByCode ----------
func (r *SubscriptionPlanRepositoryImpl) GetByCode(ctx context.Context, planCode string) (*models.SubscriptionPlan, error) {
	query := `
		SELECT plan_id, plan_code, plan_name, description,
			duration_days, price, currency, gateway_plan_id,
			is_active, created_at, updated_at, deleted_at
		FROM subscription_plans
		WHERE plan_code = $1 AND deleted_at IS NULL
	`
	var plan models.SubscriptionPlan
	var deletedAt sql.NullTime
	err := r.client.QueryRow(ctx, query, planCode).Scan(
		&plan.PlanID,
		&plan.PlanCode,
		&plan.PlanName,
		&plan.Description,
		&plan.DurationDays,
		&plan.Price,
		&plan.Currency,
		&plan.GatewayPlanID,
		&plan.IsActive,
		&plan.CreatedAt,
		&plan.UpdatedAt,
		&deletedAt,
	)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, apperrors.ErrNotFound
		}
		return nil, fmt.Errorf("failed to get subscription plan by code: %w", err)
	}
	if deletedAt.Valid {
		plan.DeletedAt = &deletedAt.Time
	}
	return &plan, nil
}

// ---------- GetByGatewayPlanID ----------
func (r *SubscriptionPlanRepositoryImpl) GetByGatewayPlanID(ctx context.Context, gatewayPlanID string) (*models.SubscriptionPlan, error) {
	query := `
		SELECT plan_id, plan_code, plan_name, description,
			duration_days, price, currency, gateway_plan_id,
			is_active, created_at, updated_at, deleted_at
		FROM subscription_plans
		WHERE gateway_plan_id = $1 AND deleted_at IS NULL
	`
	var plan models.SubscriptionPlan
	var deletedAt sql.NullTime
	err := r.client.QueryRow(ctx, query, gatewayPlanID).Scan(
		&plan.PlanID,
		&plan.PlanCode,
		&plan.PlanName,
		&plan.Description,
		&plan.DurationDays,
		&plan.Price,
		&plan.Currency,
		&plan.GatewayPlanID,
		&plan.IsActive,
		&plan.CreatedAt,
		&plan.UpdatedAt,
		&deletedAt,
	)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, apperrors.ErrNotFound
		}
		return nil, fmt.Errorf("failed to get subscription plan by gateway plan ID: %w", err)
	}
	if deletedAt.Valid {
		plan.DeletedAt = &deletedAt.Time
	}
	return &plan, nil
}

// ---------- Update ----------
func (r *SubscriptionPlanRepositoryImpl) Update(ctx context.Context, plan *models.SubscriptionPlan) error {
	query := `
		UPDATE subscription_plans SET
			plan_code = $1,
			plan_name = $2,
			description = $3,
			duration_days = $4,
			price = $5,
			currency = $6,
			gateway_plan_id = $7,
			is_active = $8,
			updated_at = $9
		WHERE plan_id = $10 AND deleted_at IS NULL
	`
	result, err := r.client.Exec(ctx, query,
		plan.PlanCode,
		plan.PlanName,
		plan.Description,
		plan.DurationDays,
		plan.Price,
		plan.Currency,
		plan.GatewayPlanID,
		plan.IsActive,
		plan.UpdatedAt,
		plan.PlanID,
	)
	if err != nil {
		if pgErr, ok := err.(*pq.Error); ok && pgErr.Code == "23505" {
			return apperrors.ErrDuplicate
		}
		return fmt.Errorf("failed to update subscription plan: %w", err)
	}
	rows, _ := result.RowsAffected()
	if rows == 0 {
		return apperrors.ErrNotFound
	}
	return nil
}

// ---------- SoftDelete ----------
func (r *SubscriptionPlanRepositoryImpl) SoftDelete(ctx context.Context, planID uuid.UUID) error {
	query := `UPDATE subscription_plans SET deleted_at = NOW() WHERE plan_id = $1 AND deleted_at IS NULL`
	result, err := r.client.Exec(ctx, query, planID)
	if err != nil {
		return fmt.Errorf("failed to soft-delete subscription plan: %w", err)
	}
	rows, _ := result.RowsAffected()
	if rows == 0 {
		return apperrors.ErrNotFound
	}
	return nil
}

// ---------- ListActive ----------
func (r *SubscriptionPlanRepositoryImpl) ListActive(ctx context.Context) ([]*models.SubscriptionPlan, error) {
	query := `
		SELECT plan_id, plan_code, plan_name, description,
			duration_days, price, currency, gateway_plan_id,
			is_active, created_at, updated_at, deleted_at
		FROM subscription_plans
		WHERE is_active = true AND deleted_at IS NULL
		ORDER BY price ASC
	`
	rows, err := r.client.Query(ctx, query)
	if err != nil {
		return nil, fmt.Errorf("failed to list active subscription plans: %w", err)
	}
	defer rows.Close()

	var plans []*models.SubscriptionPlan
	for rows.Next() {
		var plan models.SubscriptionPlan
		var deletedAt sql.NullTime
		err := rows.Scan(
			&plan.PlanID,
			&plan.PlanCode,
			&plan.PlanName,
			&plan.Description,
			&plan.DurationDays,
			&plan.Price,
			&plan.Currency,
			&plan.GatewayPlanID,
			&plan.IsActive,
			&plan.CreatedAt,
			&plan.UpdatedAt,
			&deletedAt,
		)
		if err != nil {
			return nil, fmt.Errorf("failed to scan subscription plan: %w", err)
		}
		if deletedAt.Valid {
			plan.DeletedAt = &deletedAt.Time
		}
		plans = append(plans, &plan)
	}
	return plans, nil
}

// ---------- ListAll (with pagination) ----------
func (r *SubscriptionPlanRepositoryImpl) ListAll(ctx context.Context, limit, offset int) ([]*models.SubscriptionPlan, int, error) {
	// Count total (excluding soft‑deleted)
	var total int
	countQuery := `SELECT COUNT(*) FROM subscription_plans WHERE deleted_at IS NULL`
	err := r.client.QueryRow(ctx, countQuery).Scan(&total)
	if err != nil {
		return nil, 0, fmt.Errorf("failed to count subscription plans: %w", err)
	}

	if limit <= 0 || limit > 1000 {
		limit = 50
	}
	if offset < 0 {
		offset = 0
	}

	query := `
		SELECT plan_id, plan_code, plan_name, description,
			duration_days, price, currency, gateway_plan_id,
			is_active, created_at, updated_at, deleted_at
		FROM subscription_plans
		WHERE deleted_at IS NULL
		ORDER BY created_at DESC
		LIMIT $1 OFFSET $2
	`
	rows, err := r.client.Query(ctx, query, limit, offset)
	if err != nil {
		return nil, 0, fmt.Errorf("failed to list subscription plans: %w", err)
	}
	defer rows.Close()

	var plans []*models.SubscriptionPlan
	for rows.Next() {
		var plan models.SubscriptionPlan
		var deletedAt sql.NullTime
		err := rows.Scan(
			&plan.PlanID,
			&plan.PlanCode,
			&plan.PlanName,
			&plan.Description,
			&plan.DurationDays,
			&plan.Price,
			&plan.Currency,
			&plan.GatewayPlanID,
			&plan.IsActive,
			&plan.CreatedAt,
			&plan.UpdatedAt,
			&deletedAt,
		)
		if err != nil {
			return nil, 0, fmt.Errorf("failed to scan subscription plan: %w", err)
		}
		if deletedAt.Valid {
			plan.DeletedAt = &deletedAt.Time
		}
		plans = append(plans, &plan)
	}
	return plans, total, nil
}

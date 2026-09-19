package postgres

import (
	"auth-service/internal/models"
	"context"

	"github.com/google/uuid"
)

// SubscriptionPlanRepository defines all operations for subscription plans.
type SubscriptionPlanRepository interface {
	// Create inserts a new subscription plan.
	Create(ctx context.Context, plan *models.SubscriptionPlan) error

	// GetByID retrieves a plan by its primary key (ignores soft‑deleted).
	GetByID(ctx context.Context, planID uuid.UUID) (*models.SubscriptionPlan, error)

	// GetByCode retrieves a plan by its unique plan_code (ignores soft‑deleted).
	GetByCode(ctx context.Context, planCode string) (*models.SubscriptionPlan, error)

	// GetByGatewayPlanID retrieves a plan by the gateway's plan ID (e.g. Stripe price ID).
	GetByGatewayPlanID(ctx context.Context, gatewayPlanID string) (*models.SubscriptionPlan, error)

	// Update updates an existing plan (ignores soft‑deleted).
	Update(ctx context.Context, plan *models.SubscriptionPlan) error

	// SoftDelete marks a plan as deleted (sets deleted_at) – does not physically remove.
	SoftDelete(ctx context.Context, planID uuid.UUID) error

	// ListActive returns all plans that are active and not soft‑deleted, ordered by price.
	ListActive(ctx context.Context) ([]*models.SubscriptionPlan, error)

	// ListAll returns all plans (including inactive, but excluding soft‑deleted) with pagination.
	ListAll(ctx context.Context, limit, offset int) ([]*models.SubscriptionPlan, int, error)
}

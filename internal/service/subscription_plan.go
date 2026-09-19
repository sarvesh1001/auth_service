// internal/service/subscription_plan.go
package service

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"github.com/google/uuid"

	apperrors "auth-service/internal/errors"
	"auth-service/internal/infrastructure/audit"
	"auth-service/internal/infrastructure/idempotency"
	"auth-service/internal/models"
	"auth-service/internal/repository/postgres"
)

// SubscriptionPlanConfig holds configuration specific to subscription plan service.
type SubscriptionPlanConfig struct {
	DefaultPageSize int
	MaxPageSize     int
	DefaultPlanCode string
}

// DefaultSubscriptionPlanConfig returns a sensible default configuration.
func DefaultSubscriptionPlanConfig() SubscriptionPlanConfig {
	return SubscriptionPlanConfig{
		DefaultPageSize: 50,
		MaxPageSize:     100,
		DefaultPlanCode: "monthly",
	}
}

// SubscriptionPlanService handles all operations related to subscription plans.
type SubscriptionPlanService struct {
	planRepo         postgres.SubscriptionPlanRepository
	auditService     *audit.AuditService
	idempotencyStore idempotency.Store
	cfg              SubscriptionPlanConfig
}

// NewSubscriptionPlanService creates a new instance.
// Pass nil for cfg to use defaults.
func NewSubscriptionPlanService(
	planRepo postgres.SubscriptionPlanRepository,
	auditService *audit.AuditService,
	idempotencyStore idempotency.Store,
	cfg *SubscriptionPlanConfig,
) *SubscriptionPlanService {
	if cfg == nil {
		defaultCfg := DefaultSubscriptionPlanConfig()
		cfg = &defaultCfg
	}
	return &SubscriptionPlanService{
		planRepo:         planRepo,
		auditService:     auditService,
		idempotencyStore: idempotencyStore,
		cfg:              *cfg,
	}
}

// ---------- Input validation helpers ----------

// validatePlan ensures required fields and business rules.
func (s *SubscriptionPlanService) validatePlan(plan *models.SubscriptionPlan) error {
	if plan == nil {
		return fmt.Errorf("%w: plan cannot be nil", apperrors.ErrInvalidInput)
	}
	plan.PlanCode = strings.TrimSpace(plan.PlanCode)
	if plan.PlanCode == "" {
		return fmt.Errorf("%w: plan_code is required", apperrors.ErrInvalidInput)
	}
	if len(plan.PlanCode) > 50 {
		return fmt.Errorf("%w: plan_code exceeds 50 characters", apperrors.ErrInvalidInput)
	}
	plan.PlanName = strings.TrimSpace(plan.PlanName)
	if plan.PlanName == "" {
		return fmt.Errorf("%w: plan_name is required", apperrors.ErrInvalidInput)
	}
	if len(plan.PlanName) > 100 {
		return fmt.Errorf("%w: plan_name exceeds 100 characters", apperrors.ErrInvalidInput)
	}
	if plan.DurationDays <= 0 {
		return fmt.Errorf("%w: duration_days must be positive", apperrors.ErrInvalidInput)
	}
	if plan.DurationDays > 3650 {
		return fmt.Errorf("%w: duration_days cannot exceed 3650", apperrors.ErrInvalidInput)
	}
	if plan.Price < 0 {
		return fmt.Errorf("%w: price cannot be negative", apperrors.ErrInvalidInput)
	}
	if plan.Price > 999999999.99 {
		return fmt.Errorf("%w: price exceeds maximum allowed", apperrors.ErrInvalidInput)
	}
	plan.Currency = strings.ToUpper(strings.TrimSpace(plan.Currency))
	if plan.Currency == "" {
		plan.Currency = "USD"
	}
	if len(plan.Currency) != 3 {
		return fmt.Errorf("%w: currency must be a 3‑letter ISO code", apperrors.ErrInvalidInput)
	}
	if plan.GatewayPlanID != nil {
		gw := strings.TrimSpace(*plan.GatewayPlanID)
		plan.GatewayPlanID = &gw
		if len(gw) > 255 {
			return fmt.Errorf("%w: gateway_plan_id exceeds 255 characters", apperrors.ErrInvalidInput)
		}
	}
	return nil
}

// ---------- Create ----------

// CreatePlan inserts a new subscription plan.
// It is idempotent via idempotency key; duplicate plan_code will return ErrDuplicate.
// CreatePlan inserts a new subscription plan.
// It is idempotent via idempotency key; if a plan with the same code already exists,
// it returns the existing plan without error.

// CreatePlan inserts a new subscription plan.
// It is idempotent via idempotency key; if a plan with the same code already exists,
// it returns ErrDuplicate (conflict) and does not reuse the existing plan.
func (s *SubscriptionPlanService) CreatePlan(
	ctx context.Context,
	req *models.SubscriptionPlan,
) (*models.SubscriptionPlan, error) {
	// Validate input
	if err := s.validatePlan(req); err != nil {
		return nil, err
	}

	// Idempotency: use plan_code as key (or allow override from context)
	idempKey, _ := ctx.Value("idempotency_key").(string)
	if idempKey == "" {
		idempKey = fmt.Sprintf("create_subscription_plan:%s", req.PlanCode)
	}
	ip, _ := ctx.Value("ip_address").(string)

	// 1. Check idempotency store first – if this key already produced a plan, return it.
	var cached models.SubscriptionPlan
	if err := s.idempotencyStore.Get(ctx, nil, idempKey, &cached); err == nil {
		return &cached, nil
	}

	// 2. Explicitly check if a plan with this code already exists (even if not using idempotency key)
	_, err := s.planRepo.GetByCode(ctx, req.PlanCode)
	if err == nil {
		// Plan exists – return conflict error, do NOT return the existing plan.
		return nil, fmt.Errorf("%w: plan with code '%s' already exists", apperrors.ErrDuplicate, req.PlanCode)
	}
	if err != apperrors.ErrNotFound {
		// Unexpected repository error
		return nil, fmt.Errorf("%w: failed to check existing plan: %v", apperrors.ErrInternal, err)
	}

	// 3. Prepare and insert the new plan
	now := time.Now().UTC()
	plan := &models.SubscriptionPlan{
		PlanID:        uuid.New(),
		PlanCode:      req.PlanCode,
		PlanName:      req.PlanName,
		Description:   req.Description,
		DurationDays:  req.DurationDays,
		Price:         req.Price,
		Currency:      req.Currency,
		GatewayPlanID: req.GatewayPlanID,
		IsActive:      true,
		CreatedAt:     now,
		UpdatedAt:     now,
	}

	if err := s.planRepo.Create(ctx, plan); err != nil {
		if err == apperrors.ErrDuplicate {
			// Race condition: another request inserted the plan between our check and insert.
			// Return conflict error (do not return the existing plan).
			return nil, fmt.Errorf("%w: plan with code '%s' already exists", apperrors.ErrDuplicate, req.PlanCode)
		}
		return nil, fmt.Errorf("%w: failed to create plan: %v", apperrors.ErrInternal, err)
	}

	// 4. Cache idempotency result (successful creation)
	_ = s.idempotencyStore.Store(ctx, nil, idempKey, plan)

	// 5. Audit
	if s.auditService != nil {
		_ = s.auditService.LogAction(ctx, nil, nil, "subscription", "create_plan", "subscription_plan",
			&plan.PlanID, "system", nil, nil, nil, map[string]interface{}{
				"plan_code":       plan.PlanCode,
				"price":           plan.Price,
				"duration_days":   plan.DurationDays,
				"currency":        plan.Currency,
				"gateway_plan_id": plan.GatewayPlanID,
				"ip_address":      ip,
			})
	}

	return plan, nil
}

// ---------- Read ----------

// GetPlanByID retrieves a plan by its ID.
func (s *SubscriptionPlanService) GetPlanByID(ctx context.Context, planID uuid.UUID) (*models.SubscriptionPlan, error) {
	if planID == uuid.Nil {
		return nil, fmt.Errorf("%w: plan_id is required", apperrors.ErrInvalidInput)
	}
	plan, err := s.planRepo.GetByID(ctx, planID)
	if err != nil {
		if err == apperrors.ErrNotFound {
			return nil, fmt.Errorf("%w: plan with id %s not found", apperrors.ErrNotFound, planID)
		}
		return nil, fmt.Errorf("%w: %v", apperrors.ErrInternal, err)
	}
	return plan, nil
}

// GetPlanByCode retrieves a plan by its unique code.
func (s *SubscriptionPlanService) GetPlanByCode(ctx context.Context, planCode string) (*models.SubscriptionPlan, error) {
	planCode = strings.TrimSpace(planCode)
	if planCode == "" {
		return nil, fmt.Errorf("%w: plan_code is required", apperrors.ErrInvalidInput)
	}
	plan, err := s.planRepo.GetByCode(ctx, planCode)
	if err != nil {
		if err == apperrors.ErrNotFound {
			return nil, fmt.Errorf("%w: plan with code '%s' not found", apperrors.ErrNotFound, planCode)
		}
		return nil, fmt.Errorf("%w: %v", apperrors.ErrInternal, err)
	}
	return plan, nil
}

// GetPlanByGatewayPlanID retrieves a plan by the payment gateway's plan ID.
func (s *SubscriptionPlanService) GetPlanByGatewayPlanID(ctx context.Context, gatewayPlanID string) (*models.SubscriptionPlan, error) {
	gatewayPlanID = strings.TrimSpace(gatewayPlanID)
	if gatewayPlanID == "" {
		return nil, fmt.Errorf("%w: gateway_plan_id is required", apperrors.ErrInvalidInput)
	}
	plan, err := s.planRepo.GetByGatewayPlanID(ctx, gatewayPlanID)
	if err != nil {
		if err == apperrors.ErrNotFound {
			return nil, fmt.Errorf("%w: plan with gateway id '%s' not found", apperrors.ErrNotFound, gatewayPlanID)
		}
		return nil, fmt.Errorf("%w: %v", apperrors.ErrInternal, err)
	}
	return plan, nil
}

// ListActivePlans returns all active (and not soft‑deleted) plans, ordered by price.
func (s *SubscriptionPlanService) ListActivePlans(ctx context.Context) ([]*models.SubscriptionPlan, error) {
	plans, err := s.planRepo.ListActive(ctx)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", apperrors.ErrInternal, err)
	}
	return plans, nil
}

// ListAllPlans returns all non‑deleted plans with pagination.
func (s *SubscriptionPlanService) ListAllPlans(ctx context.Context, limit, offset int) ([]*models.SubscriptionPlan, int, error) {
	if limit <= 0 {
		limit = s.cfg.DefaultPageSize
	}
	if limit > s.cfg.MaxPageSize {
		limit = s.cfg.MaxPageSize
	}
	if offset < 0 {
		offset = 0
	}
	plans, total, err := s.planRepo.ListAll(ctx, limit, offset)
	if err != nil {
		return nil, 0, fmt.Errorf("%w: %v", apperrors.ErrInternal, err)
	}
	return plans, total, nil
}

// ---------- Update ----------

// UpdatePlan updates an existing plan. Only fields provided in the request will be changed.
// If a field is omitted (zero value), it remains unchanged.
func (s *SubscriptionPlanService) UpdatePlan(
	ctx context.Context,
	planID uuid.UUID,
	req *models.SubscriptionPlan,
) (*models.SubscriptionPlan, error) {
	if planID == uuid.Nil {
		return nil, fmt.Errorf("%w: plan_id is required", apperrors.ErrInvalidInput)
	}

	existing, err := s.planRepo.GetByID(ctx, planID)
	if err != nil {
		if err == apperrors.ErrNotFound {
			return nil, fmt.Errorf("%w: plan with id %s not found", apperrors.ErrNotFound, planID)
		}
		return nil, fmt.Errorf("%w: %v", apperrors.ErrInternal, err)
	}

	// Validate the updated fields
	if req.PlanCode != "" && req.PlanCode != existing.PlanCode {
		existingWithCode, _ := s.planRepo.GetByCode(ctx, req.PlanCode)
		if existingWithCode != nil && existingWithCode.PlanID != planID {
			return nil, fmt.Errorf("%w: plan_code '%s' already in use", apperrors.ErrDuplicate, req.PlanCode)
		}
		existing.PlanCode = req.PlanCode
	}
	if req.PlanName != "" {
		existing.PlanName = req.PlanName
	}
	if req.Description != nil {
		existing.Description = req.Description
	}
	if req.DurationDays > 0 {
		if req.DurationDays > 3650 {
			return nil, fmt.Errorf("%w: duration_days cannot exceed 3650", apperrors.ErrInvalidInput)
		}
		existing.DurationDays = req.DurationDays
	}
	if req.Price >= 0 {
		if req.Price > 999999999.99 {
			return nil, fmt.Errorf("%w: price exceeds maximum allowed", apperrors.ErrInvalidInput)
		}
		existing.Price = req.Price
	}
	if req.Currency != "" {
		cur := strings.ToUpper(strings.TrimSpace(req.Currency))
		if len(cur) != 3 {
			return nil, fmt.Errorf("%w: currency must be 3‑letter ISO code", apperrors.ErrInvalidInput)
		}
		existing.Currency = cur
	}
	if req.GatewayPlanID != nil {
		gw := strings.TrimSpace(*req.GatewayPlanID)
		if len(gw) > 255 {
			return nil, fmt.Errorf("%w: gateway_plan_id exceeds 255 characters", apperrors.ErrInvalidInput)
		}
		existing.GatewayPlanID = &gw
	}
	// is_active: only set if explicitly provided (zero value false means no change; we use a pointer in req)
	if req.IsActive != existing.IsActive {
		existing.IsActive = req.IsActive
	}
	existing.UpdatedAt = time.Now().UTC()

	before, _ := json.Marshal(existing)
	if err := s.planRepo.Update(ctx, existing); err != nil {
		if err == apperrors.ErrDuplicate {
			return nil, fmt.Errorf("%w: plan_code conflict", apperrors.ErrDuplicate)
		}
		return nil, fmt.Errorf("%w: %v", apperrors.ErrInternal, err)
	}
	after, _ := json.Marshal(existing)

	if s.auditService != nil {
		ip, _ := ctx.Value("ip_address").(string)
		_ = s.auditService.LogAction(ctx, nil, nil, "subscription", "update_plan", "subscription_plan",
			&planID, "system", nil, before, after, map[string]interface{}{
				"ip_address": ip,
			})
	}
	return existing, nil
}

// ---------- Soft Delete ----------

// SoftDeletePlan marks a plan as deleted (sets deleted_at).
func (s *SubscriptionPlanService) SoftDeletePlan(ctx context.Context, planID uuid.UUID) error {
	if planID == uuid.Nil {
		return fmt.Errorf("%w: plan_id is required", apperrors.ErrInvalidInput)
	}
	_, err := s.planRepo.GetByID(ctx, planID)
	if err != nil {
		return err
	}
	if err := s.planRepo.SoftDelete(ctx, planID); err != nil {
		if err == apperrors.ErrNotFound {
			return fmt.Errorf("%w: plan already deleted", apperrors.ErrNotFound)
		}
		return fmt.Errorf("%w: %v", apperrors.ErrInternal, err)
	}
	if s.auditService != nil {
		ip, _ := ctx.Value("ip_address").(string)
		_ = s.auditService.LogAction(ctx, nil, nil, "subscription", "delete_plan", "subscription_plan",
			&planID, "system", nil, nil, nil, map[string]interface{}{
				"ip_address": ip,
			})
	}
	return nil
}

// ---------- Utilities ----------

// PlanExists checks if a plan with the given code exists.
func (s *SubscriptionPlanService) PlanExists(ctx context.Context, planCode string) (bool, error) {
	planCode = strings.TrimSpace(planCode)
	if planCode == "" {
		return false, fmt.Errorf("%w: plan_code is required", apperrors.ErrInvalidInput)
	}
	_, err := s.planRepo.GetByCode(ctx, planCode)
	if err == nil {
		return true, nil
	}
	if err == apperrors.ErrNotFound {
		return false, nil
	}
	return false, fmt.Errorf("%w: %v", apperrors.ErrInternal, err)
}

// GetDefaultPlan returns the default plan from configuration.
func (s *SubscriptionPlanService) GetDefaultPlan(ctx context.Context) (*models.SubscriptionPlan, error) {
	return s.GetPlanByCode(ctx, s.cfg.DefaultPlanCode)
}

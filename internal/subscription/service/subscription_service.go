// FILE: ./service/subscription_service.go
package service

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"time"

	"github.com/google/uuid"
	"github.com/shopspring/decimal" // used for subscription item quantities
	"go.uber.org/zap"

	"auth-service/internal/client"
	"auth-service/internal/infrastructure/audit"
	"auth-service/internal/infrastructure/idempotency"
	"auth-service/internal/infrastructure/outbox"
	"auth-service/internal/subscription/errors"
	"auth-service/internal/subscription/events"
	"auth-service/internal/subscription/models"
	"auth-service/internal/subscription/models/enums"
	"auth-service/internal/subscription/repository"
)

// ----------------------------------------------------------------------------
// Interface
// ----------------------------------------------------------------------------

type SubscriptionService interface {
	// CRUD
	Create(ctx context.Context, subscription *models.Subscription) error
	Update(ctx context.Context, subscription *models.Subscription) error
	Delete(ctx context.Context, companyID uuid.UUID, subscriptionID uuid.UUID) error
	GetByID(ctx context.Context, companyID uuid.UUID, subscriptionID uuid.UUID) (*models.Subscription, error)
	GetByNumber(ctx context.Context, companyID uuid.UUID, contractNumber string) (*models.Subscription, error)

	// Assignment
	AssignCustomer(ctx context.Context, companyID uuid.UUID, subscriptionID uuid.UUID, customerID uuid.UUID) error
	AssignPlan(ctx context.Context, companyID uuid.UUID, subscriptionID uuid.UUID, planID uuid.UUID) error
	UpdateSalesOrder(ctx context.Context, companyID uuid.UUID, subscriptionID uuid.UUID, salesOrderID uuid.UUID) error

	// Billing Configuration
	UpdateAutoRenew(ctx context.Context, companyID uuid.UUID, subscriptionID uuid.UUID, autoRenew bool) error
	UpdateCurrency(ctx context.Context, companyID uuid.UUID, subscriptionID uuid.UUID, currency string) error
	UpdateCoupon(ctx context.Context, companyID uuid.UUID, subscriptionID uuid.UUID, couponID *uuid.UUID) error
	RemoveCoupon(ctx context.Context, companyID uuid.UUID, subscriptionID uuid.UUID) error

	// Dates
	UpdateStartDate(ctx context.Context, companyID uuid.UUID, subscriptionID uuid.UUID, startDate time.Time) error
	UpdateEndDate(ctx context.Context, companyID uuid.UUID, subscriptionID uuid.UUID, endDate time.Time) error
	UpdateBillingStart(ctx context.Context, companyID uuid.UUID, subscriptionID uuid.UUID, billingStart time.Time) error

	// Validation
	Validate(ctx context.Context, subscription *models.Subscription) error
	Exists(ctx context.Context, companyID uuid.UUID, subscriptionID uuid.UUID) (bool, error)
	CanDelete(ctx context.Context, companyID uuid.UUID, subscriptionID uuid.UUID) error

	// Query
	List(ctx context.Context, filter repository.SubscriptionFilter, p repository.Pagination, s repository.Sort) ([]*models.Subscription, int64, error)
	Search(ctx context.Context, companyID uuid.UUID, query string, limit, offset int) ([]*models.Subscription, int64, error)
	GetByCustomer(ctx context.Context, companyID uuid.UUID, customerID uuid.UUID) ([]*models.Subscription, error)
	GetByPlan(ctx context.Context, companyID uuid.UUID, planID uuid.UUID) ([]*models.Subscription, error)
	GetBySalesOrder(ctx context.Context, companyID uuid.UUID, salesOrderID uuid.UUID) ([]*models.Subscription, error)
	GetExpiring(ctx context.Context, companyID uuid.UUID, before time.Time) ([]*models.Subscription, error)
	GetExpired(ctx context.Context, companyID uuid.UUID) ([]*models.Subscription, error)
	GetActive(ctx context.Context, companyID uuid.UUID) ([]*models.Subscription, error)
	GetTrial(ctx context.Context, companyID uuid.UUID) ([]*models.Subscription, error)
	GetCancelled(ctx context.Context, companyID uuid.UUID) ([]*models.Subscription, error)
	GetSuspended(ctx context.Context, companyID uuid.UUID) ([]*models.Subscription, error)
	GetPaused(ctx context.Context, companyID uuid.UUID) ([]*models.Subscription, error)
}

// ----------------------------------------------------------------------------
// Implementation
// ----------------------------------------------------------------------------

type subscriptionService struct {
	subRepo           repository.SubscriptionRepository
	subItemRepo       repository.SubscriptionItemRepository
	timelineRepo      repository.TimelineRepository
	planRepo          repository.PlanRepository
	planItemRepo      repository.PlanItemRepository // <-- NEW: to clone plan items
	validationService SubscriptionValidationService
	auditService      *audit.AuditService
	outboxRepo        outbox.Repository
	idempotencyStore  idempotency.Store
	pgClient          *client.PostgresClient
	logger            *zap.Logger
}

// NewSubscriptionService creates a new instance of SubscriptionService.
func NewSubscriptionService(
	subRepo repository.SubscriptionRepository,
	subItemRepo repository.SubscriptionItemRepository,
	timelineRepo repository.TimelineRepository,
	planRepo repository.PlanRepository,
	planItemRepo repository.PlanItemRepository, // <-- NEW
	validationService SubscriptionValidationService,
	auditService *audit.AuditService,
	outboxRepo outbox.Repository,
	idempotencyStore idempotency.Store,
	pgClient *client.PostgresClient,
	logger *zap.Logger,
) SubscriptionService {
	return &subscriptionService{
		subRepo:           subRepo,
		subItemRepo:       subItemRepo,
		timelineRepo:      timelineRepo,
		planRepo:          planRepo,
		planItemRepo:      planItemRepo, // <-- NEW
		validationService: validationService,
		auditService:      auditService,
		outboxRepo:        outboxRepo,
		idempotencyStore:  idempotencyStore,
		pgClient:          pgClient,
		logger:            logger.Named("subscription_service"),
	}
}

// helper to unwrap *sql.Tx from repository.DBTX
func (s *subscriptionService) getSQLTx(tx repository.DBTX) (*sql.Tx, error) {
	sqlTx, ok := tx.(*sql.Tx)
	if !ok {
		return nil, fmt.Errorf("tx is not a *sql.Tx")
	}
	return sqlTx, nil
}

// helper to emit an outbox event within a transaction
func (s *subscriptionService) emitEvent(ctx context.Context, tx repository.DBTX, aggregateID uuid.UUID, eventType string, payload interface{}) error {
	sqlTx, err := s.getSQLTx(tx)
	if err != nil {
		return err
	}
	data, err := json.Marshal(payload)
	if err != nil {
		return err
	}
	event := &outbox.Event{
		EventID:       uuid.New().String(),
		AggregateType: "subscription",
		AggregateID:   aggregateID.String(),
		EventType:     eventType,
		Topic:         events.TopicSubscriptionEvents,
		Payload:       data,
	}
	return s.outboxRepo.Store(ctx, sqlTx, event)
}

// idempotency key helper
func getIDempotencyKeyFromContext(ctx context.Context, fallback string) string {
	if key, ok := ctx.Value("idempotency_key").(string); ok && key != "" {
		return key
	}
	return fallback
}

// ----------------------------------------------------------------------------
// Plan Validation Helper
// ----------------------------------------------------------------------------

// validatePlan checks that the plan exists and is active.
func (s *subscriptionService) validatePlan(ctx context.Context, db repository.DBTX, companyID, planID uuid.UUID) error {
	plan, err := s.planRepo.GetByID(ctx, db, companyID, planID)
	if err != nil {
		return fmt.Errorf("validate plan: %w", err)
	}
	if plan == nil {
		return errors.ErrPlanNotFound
	}
	if !plan.IsActive {
		return errors.ErrPlanInactive
	}
	return nil
}

// ----------------------------------------------------------------------------
// CRUD
// ----------------------------------------------------------------------------

// Create creates a new subscription and clones its plan items into subscription items.
// Create creates a new subscription and clones its plan items into subscription items.
// It supports idempotency using the client-provided Idempotency-Key.
func (s *subscriptionService) Create(ctx context.Context, subscription *models.Subscription) error {
	logger := s.logger.With(
		zap.String("method", "Create"),
		zap.String("plan_id", subscription.PlanID.String()),
		zap.String("customer_id", subscription.CustomerID.String()),
	)

	// Get the client-provided idempotency key from context
	idempKey := getIDempotencyKeyFromContext(ctx, "")
	if idempKey == "" {
		logger.Warn("idempotency key not provided, falling back to subscription ID")
		idempKey = subscription.SubscriptionID.String()
	} else {
		logger.Debug("using client-provided idempotency key", zap.String("key", idempKey))
	}

	tx, err := s.pgClient.BeginTx(ctx, nil)
	if err != nil {
		logger.Error("failed to begin transaction", zap.Error(err))
		return fmt.Errorf("begin tx: %w", err)
	}
	defer tx.Rollback()

	// 1. Check idempotency cache
	var cached *models.Subscription
	if err := s.idempotencyStore.Get(ctx, tx, idempKey, &cached); err == nil && cached != nil {
		logger.Info("idempotent – returning cached subscription",
			zap.String("cached_subscription_id", cached.SubscriptionID.String()),
		)
		// Copy cached data into the passed subscription pointer
		*subscription = *cached
		return nil
	}
	logger.Debug("idempotency cache miss, proceeding with creation")

	// 2. Validate plan
	if err := s.validatePlan(ctx, tx, subscription.CompanyID, subscription.PlanID); err != nil {
		logger.Error("plan validation failed", zap.Error(err))
		return err
	}

	// 3. Set timestamps
	now := time.Now()
	subscription.CreatedAt = now
	subscription.UpdatedAt = now

	// 4. Insert subscription
	if err := s.subRepo.Create(ctx, tx, subscription); err != nil {
		logger.Error("failed to insert subscription", zap.Error(err))
		return err
	}

	// 5. Clone plan items into subscription items
	planItems, err := s.planItemRepo.GetByPlan(ctx, tx, subscription.PlanID)
	if err != nil {
		logger.Error("failed to get plan items", zap.Error(err))
		return fmt.Errorf("get plan items: %w", err)
	}
	if len(planItems) == 0 {
		logger.Error("plan has no items")
		return errors.ErrPlanHasNoItems
	}

	for _, planItem := range planItems {
		subItem := &models.SubscriptionItem{
			SubItemID:      uuid.New(),
			SubscriptionID: subscription.SubscriptionID,
			PlanItemID:     planItem.PlanItemID,
			Quantity:       decimal.NewFromInt(1),
			UnitPrice:      planItem.Price,
			Currency:       planItem.Currency,
			Status:         enums.ItemStatusActive,
			StartDate:      subscription.StartDate,
			CreatedAt:      now,
			UpdatedAt:      now,
			ProductID:      planItem.ProductID,
		}
		if err := s.subItemRepo.Create(ctx, tx, subItem); err != nil {
			logger.Error("failed to create subscription item", zap.Error(err))
			return fmt.Errorf("create subscription item: %w", err)
		}
	}

	// 6. Emit event
	payload := buildSubscriptionPayload(subscription)
	if err := s.emitEvent(ctx, tx, subscription.SubscriptionID, events.EventSubscriptionCreated, payload); err != nil {
		logger.Warn("failed to emit created event", zap.Error(err))
	}

	// 7. Store the created subscription in the idempotency cache
	if err := s.idempotencyStore.Store(ctx, tx, idempKey, subscription); err != nil {
		logger.Warn("failed to store idempotency record", zap.Error(err))
	}

	if err := tx.Commit(); err != nil {
		logger.Error("failed to commit transaction", zap.Error(err))
		return fmt.Errorf("commit tx: %w", err)
	}

	logger.Info("subscription created successfully",
		zap.String("subscription_id", subscription.SubscriptionID.String()),
	)

	if s.auditService != nil {
		_ = s.auditService.LogAction(ctx, nil, &subscription.CompanyID, "subscription", "create", "subscription",
			&subscription.SubscriptionID, "system", nil, nil, nil, map[string]interface{}{
				"plan_id":     subscription.PlanID,
				"customer_id": subscription.CustomerID,
			})
	}

	return nil
}
func (s *subscriptionService) Update(ctx context.Context, subscription *models.Subscription) error {
	logger := s.logger.With(zap.String("method", "Update"))

	tx, err := s.pgClient.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("begin tx: %w", err)
	}
	defer tx.Rollback()

	idempKey := getIDempotencyKeyFromContext(ctx, fmt.Sprintf("update-sub-%s", subscription.SubscriptionID.String()))
	var cached bool
	if err := s.idempotencyStore.Get(ctx, tx, idempKey, &cached); err == nil && cached {
		logger.Info("idempotent – update already processed")
		return nil
	}

	// Validate the existing subscription (fetch and validate)
	existing, err := s.validationService.ValidateSubscription(ctx, subscription.CompanyID, subscription.SubscriptionID)
	if err != nil {
		return err
	}

	// If plan is being changed, validate the new plan
	if existing.PlanID != subscription.PlanID {
		if err := s.validatePlan(ctx, tx, subscription.CompanyID, subscription.PlanID); err != nil {
			return err
		}
	}

	// Ensure version matches (optimistic locking)
	if existing.Version != subscription.Version {
		return errors.ErrVersionMismatch
	}
	subscription.Version = existing.Version + 1
	// Update timestamp
	subscription.UpdatedAt = time.Now()

	if err := s.subRepo.Update(ctx, tx, subscription); err != nil {
		return err
	}

	// Emit updated event
	payload := buildSubscriptionPayload(subscription)
	if err := s.emitEvent(ctx, tx, subscription.SubscriptionID, events.EventSubscriptionUpdated, payload); err != nil {
		logger.Warn("failed to emit updated event", zap.Error(err))
	}

	if err := s.idempotencyStore.Store(ctx, tx, idempKey, true); err != nil {
		logger.Warn("failed to store idempotency record", zap.Error(err))
	}

	if err := tx.Commit(); err != nil {
		return fmt.Errorf("commit tx: %w", err)
	}

	if s.auditService != nil {
		_ = s.auditService.LogAction(ctx, tx, &subscription.CompanyID, "subscription", "update", "subscription",
			&subscription.SubscriptionID, "system", nil, nil, nil, nil)
	}

	return nil
}

func (s *subscriptionService) Delete(ctx context.Context, companyID uuid.UUID, subscriptionID uuid.UUID) error {
	logger := s.logger.With(zap.String("method", "Delete"))

	tx, err := s.pgClient.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("begin tx: %w", err)
	}
	defer tx.Rollback()

	idempKey := getIDempotencyKeyFromContext(ctx, fmt.Sprintf("delete-sub-%s", subscriptionID.String()))
	var cached bool
	if err := s.idempotencyStore.Get(ctx, tx, idempKey, &cached); err == nil && cached {
		logger.Info("idempotent – delete already processed")
		return nil
	}

	if err := s.CanDelete(ctx, companyID, subscriptionID); err != nil {
		return err
	}

	if err := s.subRepo.SoftDelete(ctx, tx, companyID, subscriptionID); err != nil {
		return err
	}

	payload := events.SubscriptionDeletedPayload{
		SubscriptionID: subscriptionID.String(),
		CompanyID:      companyID.String(),
		DeletedAt:      time.Now().Format(time.RFC3339),
	}
	if err := s.emitEvent(ctx, tx, subscriptionID, events.EventSubscriptionDeleted, payload); err != nil {
		logger.Warn("failed to emit deleted event", zap.Error(err))
	}

	if err := s.idempotencyStore.Store(ctx, tx, idempKey, true); err != nil {
		logger.Warn("failed to store idempotency record", zap.Error(err))
	}

	if err := tx.Commit(); err != nil {
		return fmt.Errorf("commit tx: %w", err)
	}

	if s.auditService != nil {
		_ = s.auditService.LogAction(ctx, tx, &companyID, "subscription", "delete", "subscription",
			&subscriptionID, "system", nil, nil, nil, nil)
	}

	return nil
}

// ----------------------------------------------------------------------------
// Get* methods with nil handling
// ----------------------------------------------------------------------------

func (s *subscriptionService) GetByID(ctx context.Context, companyID uuid.UUID, subscriptionID uuid.UUID) (*models.Subscription, error) {
	sub, err := s.subRepo.GetByID(ctx, s.pgClient.DB, companyID, subscriptionID)
	if err != nil {
		return nil, err
	}
	if sub == nil {
		return nil, errors.ErrNotFound
	}
	return sub, nil
}

func (s *subscriptionService) GetByNumber(ctx context.Context, companyID uuid.UUID, contractNumber string) (*models.Subscription, error) {
	sub, err := s.subRepo.GetByContractNumber(ctx, s.pgClient.DB, companyID, contractNumber)
	if err != nil {
		return nil, err
	}
	if sub == nil {
		return nil, errors.ErrNotFound
	}
	return sub, nil
}

// ----------------------------------------------------------------------------
// Assignment
// ----------------------------------------------------------------------------

func (s *subscriptionService) AssignCustomer(ctx context.Context, companyID uuid.UUID, subscriptionID uuid.UUID, customerID uuid.UUID) error {
	logger := s.logger.With(zap.String("method", "AssignCustomer"))

	tx, err := s.pgClient.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("begin tx: %w", err)
	}
	defer tx.Rollback()

	idempKey := getIDempotencyKeyFromContext(ctx, fmt.Sprintf("assign-cust-%s", subscriptionID.String()))
	var cached bool
	if err := s.idempotencyStore.Get(ctx, tx, idempKey, &cached); err == nil && cached {
		logger.Info("idempotent – assign customer already processed")
		return nil
	}

	sub, err := s.subRepo.GetByIDForUpdate(ctx, tx, companyID, subscriptionID)
	if err != nil {
		return err
	}
	if sub == nil {
		return errors.ErrNotFound
	}

	oldCustomer := sub.CustomerID
	sub.CustomerID = customerID
	sub.Version++
	sub.UpdatedAt = time.Now()
	if err := s.subRepo.Update(ctx, tx, sub); err != nil {
		return err
	}

	payload := events.SubscriptionAssignmentPayload{
		SubscriptionID: subscriptionID.String(),
		CompanyID:      companyID.String(),
		CustomerID:     customerID.String(),
		OldCustomerID:  oldCustomer.String(),
		AssignedAt:     time.Now().Format(time.RFC3339),
	}
	if err := s.emitEvent(ctx, tx, subscriptionID, events.EventSubscriptionCustomerAssigned, payload); err != nil {
		logger.Warn("failed to emit customer assignment event", zap.Error(err))
	}

	if err := s.idempotencyStore.Store(ctx, tx, idempKey, true); err != nil {
		logger.Warn("failed to store idempotency record", zap.Error(err))
	}

	if err := tx.Commit(); err != nil {
		return fmt.Errorf("commit tx: %w", err)
	}

	if s.auditService != nil {
		_ = s.auditService.LogAction(ctx, tx, &companyID, "subscription", "assign_customer", "subscription",
			&subscriptionID, "system", nil, nil, nil, map[string]interface{}{
				"old_customer": oldCustomer,
				"new_customer": customerID,
			})
	}

	return nil
}

func (s *subscriptionService) AssignPlan(ctx context.Context, companyID uuid.UUID, subscriptionID uuid.UUID, planID uuid.UUID) error {
	logger := s.logger.With(zap.String("method", "AssignPlan"))

	tx, err := s.pgClient.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("begin tx: %w", err)
	}
	defer tx.Rollback()

	idempKey := getIDempotencyKeyFromContext(ctx, fmt.Sprintf("assign-plan-%s", subscriptionID.String()))
	var cached bool
	if err := s.idempotencyStore.Get(ctx, tx, idempKey, &cached); err == nil && cached {
		logger.Info("idempotent – assign plan already processed")
		return nil
	}

	sub, err := s.subRepo.GetByIDForUpdate(ctx, tx, companyID, subscriptionID)
	if err != nil {
		return err
	}
	if sub == nil {
		return errors.ErrNotFound
	}

	if err := s.validatePlan(ctx, tx, companyID, planID); err != nil {
		return err
	}

	oldPlan := sub.PlanID
	sub.PlanID = planID
	sub.Version++
	sub.UpdatedAt = time.Now()
	if err := s.subRepo.Update(ctx, tx, sub); err != nil {
		return err
	}

	payload := events.SubscriptionAssignmentPayload{
		SubscriptionID: subscriptionID.String(),
		CompanyID:      companyID.String(),
		PlanID:         planID.String(),
		OldPlanID:      oldPlan.String(),
		AssignedAt:     time.Now().Format(time.RFC3339),
	}
	if err := s.emitEvent(ctx, tx, subscriptionID, events.EventSubscriptionPlanAssigned, payload); err != nil {
		logger.Warn("failed to emit plan assignment event", zap.Error(err))
	}

	if err := s.idempotencyStore.Store(ctx, tx, idempKey, true); err != nil {
		logger.Warn("failed to store idempotency record", zap.Error(err))
	}

	if err := tx.Commit(); err != nil {
		return fmt.Errorf("commit tx: %w", err)
	}

	if s.auditService != nil {
		_ = s.auditService.LogAction(ctx, tx, &companyID, "subscription", "assign_plan", "subscription",
			&subscriptionID, "system", nil, nil, nil, map[string]interface{}{
				"old_plan": oldPlan,
				"new_plan": planID,
			})
	}

	return nil
}

func (s *subscriptionService) UpdateSalesOrder(ctx context.Context, companyID uuid.UUID, subscriptionID uuid.UUID, salesOrderID uuid.UUID) error {
	logger := s.logger.With(zap.String("method", "UpdateSalesOrder"))

	tx, err := s.pgClient.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("begin tx: %w", err)
	}
	defer tx.Rollback()

	idempKey := getIDempotencyKeyFromContext(ctx, fmt.Sprintf("salesorder-%s", subscriptionID.String()))
	var cached bool
	if err := s.idempotencyStore.Get(ctx, tx, idempKey, &cached); err == nil && cached {
		logger.Info("idempotent – sales order update already processed")
		return nil
	}

	exists, err := s.subRepo.Exists(ctx, tx, companyID, subscriptionID)
	if err != nil {
		return err
	}
	if !exists {
		return errors.ErrNotFound
	}

	if err := s.subRepo.UpdateSalesOrder(ctx, tx, companyID, subscriptionID, salesOrderID); err != nil {
		return err
	}

	payload := events.SubscriptionSalesOrderPayload{
		SubscriptionID: subscriptionID.String(),
		CompanyID:      companyID.String(),
		SalesOrderID:   salesOrderID.String(),
		UpdatedAt:      time.Now().Format(time.RFC3339),
	}
	if err := s.emitEvent(ctx, tx, subscriptionID, events.EventSubscriptionSalesOrderUpdated, payload); err != nil {
		logger.Warn("failed to emit sales order update event", zap.Error(err))
	}

	if err := s.idempotencyStore.Store(ctx, tx, idempKey, true); err != nil {
		logger.Warn("failed to store idempotency record", zap.Error(err))
	}

	if err := tx.Commit(); err != nil {
		return fmt.Errorf("commit tx: %w", err)
	}

	if s.auditService != nil {
		_ = s.auditService.LogAction(ctx, tx, &companyID, "subscription", "update_sales_order", "subscription",
			&subscriptionID, "system", nil, nil, nil, map[string]interface{}{
				"sales_order_id": salesOrderID,
			})
	}

	return nil
}

// ----------------------------------------------------------------------------
// Billing Configuration
// ----------------------------------------------------------------------------

func (s *subscriptionService) UpdateAutoRenew(ctx context.Context, companyID uuid.UUID, subscriptionID uuid.UUID, autoRenew bool) error {
	logger := s.logger.With(zap.String("method", "UpdateAutoRenew"))

	tx, err := s.pgClient.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("begin tx: %w", err)
	}
	defer tx.Rollback()

	idempKey := getIDempotencyKeyFromContext(ctx, fmt.Sprintf("autorenew-%s", subscriptionID.String()))
	var cached bool
	if err := s.idempotencyStore.Get(ctx, tx, idempKey, &cached); err == nil && cached {
		logger.Info("idempotent – auto renew update already processed")
		return nil
	}

	sub, err := s.subRepo.GetByIDForUpdate(ctx, tx, companyID, subscriptionID)
	if err != nil {
		return err
	}
	if sub == nil {
		return errors.ErrNotFound
	}
	sub.AutoRenew = autoRenew
	sub.Version++
	sub.UpdatedAt = time.Now()
	if err := s.subRepo.Update(ctx, tx, sub); err != nil {
		return err
	}

	payload := events.SubscriptionAutoRenewPayload{
		SubscriptionID: subscriptionID.String(),
		CompanyID:      companyID.String(),
		AutoRenew:      autoRenew,
		UpdatedAt:      time.Now().Format(time.RFC3339),
	}
	if err := s.emitEvent(ctx, tx, subscriptionID, events.EventSubscriptionAutoRenewUpdated, payload); err != nil {
		logger.Warn("failed to emit auto renew event", zap.Error(err))
	}

	if err := s.idempotencyStore.Store(ctx, tx, idempKey, true); err != nil {
		logger.Warn("failed to store idempotency record", zap.Error(err))
	}

	if err := tx.Commit(); err != nil {
		return fmt.Errorf("commit tx: %w", err)
	}

	if s.auditService != nil {
		_ = s.auditService.LogAction(ctx, tx, &companyID, "subscription", "update_auto_renew", "subscription",
			&subscriptionID, "system", nil, nil, nil, map[string]interface{}{
				"auto_renew": autoRenew,
			})
	}

	return nil
}

func (s *subscriptionService) UpdateCurrency(ctx context.Context, companyID uuid.UUID, subscriptionID uuid.UUID, currency string) error {
	// Currency not on Subscription model – log and skip
	logger := s.logger.With(zap.String("method", "UpdateCurrency"))
	logger.Warn("UpdateCurrency not implemented – Subscription model lacks currency field")
	return nil
}

func (s *subscriptionService) UpdateCoupon(ctx context.Context, companyID uuid.UUID, subscriptionID uuid.UUID, couponID *uuid.UUID) error {
	logger := s.logger.With(zap.String("method", "UpdateCoupon"))

	tx, err := s.pgClient.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("begin tx: %w", err)
	}
	defer tx.Rollback()

	idempKey := getIDempotencyKeyFromContext(ctx, fmt.Sprintf("coupon-%s", subscriptionID.String()))
	var cached bool
	if err := s.idempotencyStore.Get(ctx, tx, idempKey, &cached); err == nil && cached {
		logger.Info("idempotent – coupon update already processed")
		return nil
	}

	sub, err := s.subRepo.GetByIDForUpdate(ctx, tx, companyID, subscriptionID)
	if err != nil {
		return err
	}
	if sub == nil {
		return errors.ErrNotFound
	}
	sub.CouponID = couponID
	sub.Version++
	sub.UpdatedAt = time.Now()
	if err := s.subRepo.Update(ctx, tx, sub); err != nil {
		return err
	}

	payload := events.SubscriptionCouponPayload{
		SubscriptionID: subscriptionID.String(),
		CompanyID:      companyID.String(),
		CouponID:       nil,
		UpdatedAt:      time.Now().Format(time.RFC3339),
	}
	if couponID != nil {
		c := couponID.String()
		payload.CouponID = &c
	}
	if err := s.emitEvent(ctx, tx, subscriptionID, events.EventSubscriptionCouponUpdated, payload); err != nil {
		logger.Warn("failed to emit coupon update event", zap.Error(err))
	}

	if err := s.idempotencyStore.Store(ctx, tx, idempKey, true); err != nil {
		logger.Warn("failed to store idempotency record", zap.Error(err))
	}

	if err := tx.Commit(); err != nil {
		return fmt.Errorf("commit tx: %w", err)
	}

	if s.auditService != nil {
		_ = s.auditService.LogAction(ctx, tx, &companyID, "subscription", "update_coupon", "subscription",
			&subscriptionID, "system", nil, nil, nil, map[string]interface{}{
				"coupon_id": couponID,
			})
	}

	return nil
}

func (s *subscriptionService) RemoveCoupon(ctx context.Context, companyID uuid.UUID, subscriptionID uuid.UUID) error {
	return s.UpdateCoupon(ctx, companyID, subscriptionID, nil)
}

// ----------------------------------------------------------------------------
// Dates
// ----------------------------------------------------------------------------

func (s *subscriptionService) UpdateStartDate(ctx context.Context, companyID uuid.UUID, subscriptionID uuid.UUID, startDate time.Time) error {
	logger := s.logger.With(zap.String("method", "UpdateStartDate"))

	tx, err := s.pgClient.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("begin tx: %w", err)
	}
	defer tx.Rollback()

	idempKey := getIDempotencyKeyFromContext(ctx, fmt.Sprintf("startdate-%s", subscriptionID.String()))
	var cached bool
	if err := s.idempotencyStore.Get(ctx, tx, idempKey, &cached); err == nil && cached {
		logger.Info("idempotent – start date update already processed")
		return nil
	}

	sub, err := s.subRepo.GetByIDForUpdate(ctx, tx, companyID, subscriptionID)
	if err != nil {
		return err
	}
	if sub == nil {
		return errors.ErrNotFound
	}
	sub.StartDate = startDate
	sub.Version++
	sub.UpdatedAt = time.Now()
	if err := s.subRepo.Update(ctx, tx, sub); err != nil {
		return err
	}

	if err := s.idempotencyStore.Store(ctx, tx, idempKey, true); err != nil {
		logger.Warn("failed to store idempotency record", zap.Error(err))
	}
	if err := tx.Commit(); err != nil {
		return fmt.Errorf("commit tx: %w", err)
	}

	if s.auditService != nil {
		_ = s.auditService.LogAction(ctx, tx, &companyID, "subscription", "update_start_date", "subscription",
			&subscriptionID, "system", nil, nil, nil, map[string]interface{}{
				"start_date": startDate,
			})
	}
	return nil
}

func (s *subscriptionService) UpdateEndDate(ctx context.Context, companyID uuid.UUID, subscriptionID uuid.UUID, endDate time.Time) error {
	logger := s.logger.With(zap.String("method", "UpdateEndDate"))

	tx, err := s.pgClient.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("begin tx: %w", err)
	}
	defer tx.Rollback()

	idempKey := getIDempotencyKeyFromContext(ctx, fmt.Sprintf("enddate-%s", subscriptionID.String()))
	var cached bool
	if err := s.idempotencyStore.Get(ctx, tx, idempKey, &cached); err == nil && cached {
		logger.Info("idempotent – end date update already processed")
		return nil
	}

	sub, err := s.subRepo.GetByIDForUpdate(ctx, tx, companyID, subscriptionID)
	if err != nil {
		return err
	}
	if sub == nil {
		return errors.ErrNotFound
	}
	sub.EndDate = &endDate
	sub.Version++
	sub.UpdatedAt = time.Now()
	if err := s.subRepo.Update(ctx, tx, sub); err != nil {
		return err
	}

	if err := s.idempotencyStore.Store(ctx, tx, idempKey, true); err != nil {
		logger.Warn("failed to store idempotency record", zap.Error(err))
	}
	if err := tx.Commit(); err != nil {
		return fmt.Errorf("commit tx: %w", err)
	}

	if s.auditService != nil {
		_ = s.auditService.LogAction(ctx, tx, &companyID, "subscription", "update_end_date", "subscription",
			&subscriptionID, "system", nil, nil, nil, map[string]interface{}{
				"end_date": endDate,
			})
	}
	return nil
}

func (s *subscriptionService) UpdateBillingStart(ctx context.Context, companyID uuid.UUID, subscriptionID uuid.UUID, billingStart time.Time) error {
	logger := s.logger.With(zap.String("method", "UpdateBillingStart"))

	tx, err := s.pgClient.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("begin tx: %w", err)
	}
	defer tx.Rollback()

	idempKey := getIDempotencyKeyFromContext(ctx, fmt.Sprintf("billingstart-%s", subscriptionID.String()))
	var cached bool
	if err := s.idempotencyStore.Get(ctx, tx, idempKey, &cached); err == nil && cached {
		logger.Info("idempotent – billing start update already processed")
		return nil
	}

	sub, err := s.subRepo.GetByIDForUpdate(ctx, tx, companyID, subscriptionID)
	if err != nil {
		return err
	}
	if sub == nil {
		return errors.ErrNotFound
	}
	sub.BillingStart = billingStart
	sub.Version++
	sub.UpdatedAt = time.Now()
	if err := s.subRepo.Update(ctx, tx, sub); err != nil {
		return err
	}

	if err := s.idempotencyStore.Store(ctx, tx, idempKey, true); err != nil {
		logger.Warn("failed to store idempotency record", zap.Error(err))
	}
	if err := tx.Commit(); err != nil {
		return fmt.Errorf("commit tx: %w", err)
	}

	if s.auditService != nil {
		_ = s.auditService.LogAction(ctx, tx, &companyID, "subscription", "update_billing_start", "subscription",
			&subscriptionID, "system", nil, nil, nil, map[string]interface{}{
				"billing_start": billingStart,
			})
	}
	return nil
}

// ----------------------------------------------------------------------------
// Validation
// ----------------------------------------------------------------------------

func (s *subscriptionService) Validate(ctx context.Context, subscription *models.Subscription) error {
	_, err := s.validationService.ValidateSubscription(ctx, subscription.CompanyID, subscription.SubscriptionID)
	return err
}

func (s *subscriptionService) Exists(ctx context.Context, companyID uuid.UUID, subscriptionID uuid.UUID) (bool, error) {
	return s.subRepo.Exists(ctx, s.pgClient.DB, companyID, subscriptionID)
}

func (s *subscriptionService) CanDelete(ctx context.Context, companyID uuid.UUID, subscriptionID uuid.UUID) error {
	sub, err := s.GetByID(ctx, companyID, subscriptionID)
	if err != nil {
		return err
	}
	if sub.Status == enums.SubStatusActive {
		return errors.ErrInvalidState
	}
	return nil
}

// ----------------------------------------------------------------------------
// Query
// ----------------------------------------------------------------------------

func (s *subscriptionService) List(ctx context.Context, filter repository.SubscriptionFilter, p repository.Pagination, srt repository.Sort) ([]*models.Subscription, int64, error) {
	return s.subRepo.List(ctx, s.pgClient.DB, filter, p, srt)
}

func (s *subscriptionService) Search(ctx context.Context, companyID uuid.UUID, query string, limit, offset int) ([]*models.Subscription, int64, error) {
	return s.subRepo.Search(ctx, s.pgClient.DB, companyID, query, limit, offset)
}

func (s *subscriptionService) GetByCustomer(ctx context.Context, companyID uuid.UUID, customerID uuid.UUID) ([]*models.Subscription, error) {
	return s.subRepo.GetByCustomer(ctx, s.pgClient.DB, companyID, customerID)
}

func (s *subscriptionService) GetByPlan(ctx context.Context, companyID uuid.UUID, planID uuid.UUID) ([]*models.Subscription, error) {
	return s.subRepo.GetByPlan(ctx, s.pgClient.DB, companyID, planID)
}

func (s *subscriptionService) GetBySalesOrder(ctx context.Context, companyID uuid.UUID, salesOrderID uuid.UUID) ([]*models.Subscription, error) {
	// Not directly supported; return empty slice
	return []*models.Subscription{}, nil
}

func (s *subscriptionService) GetExpiring(ctx context.Context, companyID uuid.UUID, before time.Time) ([]*models.Subscription, error) {
	return s.subRepo.GetExpiringBetween(ctx, s.pgClient.DB, companyID, time.Now(), before)
}

func (s *subscriptionService) GetExpired(ctx context.Context, companyID uuid.UUID) ([]*models.Subscription, error) {
	return s.subRepo.GetByStatus(ctx, s.pgClient.DB, companyID, enums.SubStatusExpired)
}

func (s *subscriptionService) GetActive(ctx context.Context, companyID uuid.UUID) ([]*models.Subscription, error) {
	return s.subRepo.GetByStatus(ctx, s.pgClient.DB, companyID, enums.SubStatusActive)
}

func (s *subscriptionService) GetTrial(ctx context.Context, companyID uuid.UUID) ([]*models.Subscription, error) {
	return s.subRepo.GetByStatus(ctx, s.pgClient.DB, companyID, enums.SubStatusTrial)
}

func (s *subscriptionService) GetCancelled(ctx context.Context, companyID uuid.UUID) ([]*models.Subscription, error) {
	return s.subRepo.GetByStatus(ctx, s.pgClient.DB, companyID, enums.SubStatusCancelled)
}

func (s *subscriptionService) GetSuspended(ctx context.Context, companyID uuid.UUID) ([]*models.Subscription, error) {
	return s.subRepo.GetByStatus(ctx, s.pgClient.DB, companyID, enums.SubStatusPaused)
}

func (s *subscriptionService) GetPaused(ctx context.Context, companyID uuid.UUID) ([]*models.Subscription, error) {
	return s.subRepo.GetByStatus(ctx, s.pgClient.DB, companyID, enums.SubStatusPaused)
}

// ----------------------------------------------------------------------------
// Helper: buildSubscriptionPayload
// ----------------------------------------------------------------------------

// buildSubscriptionPayload constructs a generic payload for subscription events.
// In a real implementation you would define specific structs per event type,
// but this minimal version serializes the subscription to JSON.

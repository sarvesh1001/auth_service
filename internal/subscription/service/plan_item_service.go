// FILE: service/plan_item_service.go

package service

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"time"

	"github.com/google/uuid"
	"github.com/shopspring/decimal"
	"go.uber.org/zap"

	"auth-service/internal/client"
	"auth-service/internal/infrastructure/audit"
	"auth-service/internal/infrastructure/idempotency"
	"auth-service/internal/infrastructure/outbox"
	"auth-service/internal/subscription/errors"
	"auth-service/internal/subscription/events"
	"auth-service/internal/subscription/models"
	"auth-service/internal/subscription/repository"
)

// -------------------------------------------------------------------------
// Interface
// -------------------------------------------------------------------------

type PlanItemService interface {
	// CRUD
	Create(ctx context.Context, item *models.PlanItem) error
	BulkCreate(ctx context.Context, items []*models.PlanItem) error
	Update(ctx context.Context, item *models.PlanItem) error
	Delete(ctx context.Context, companyID uuid.UUID, planItemID uuid.UUID) error
	GetByID(ctx context.Context, companyID uuid.UUID, planItemID uuid.UUID) (*models.PlanItem, error)
	GetByCode(ctx context.Context, companyID uuid.UUID, code string) (*models.PlanItem, error)

	// Plan Management
	AddToPlan(ctx context.Context, planID uuid.UUID, item *models.PlanItem) error
	RemoveFromPlan(ctx context.Context, planID uuid.UUID, planItemID uuid.UUID) error
	MoveToPlan(ctx context.Context, sourcePlanID uuid.UUID, targetPlanID uuid.UUID, planItemID uuid.UUID) error
	CopyToPlan(ctx context.Context, sourcePlanID uuid.UUID, targetPlanID uuid.UUID, planItemID uuid.UUID) error
	Reorder(ctx context.Context, planID uuid.UUID, itemIDs []uuid.UUID) error

	// Lifecycle
	Activate(ctx context.Context, companyID uuid.UUID, planItemID uuid.UUID) error
	Deactivate(ctx context.Context, companyID uuid.UUID, planItemID uuid.UUID) error
	Restore(ctx context.Context, companyID uuid.UUID, planItemID uuid.UUID) error

	// Configuration
	UpdatePrice(ctx context.Context, companyID uuid.UUID, planItemID uuid.UUID, price decimal.Decimal, currency string) error
	UpdateQuantity(ctx context.Context, companyID uuid.UUID, planItemID uuid.UUID, quantity int) error
	UpdateSortOrder(ctx context.Context, companyID uuid.UUID, planItemID uuid.UUID, sortOrder int) error

	// NEW: Back‑link product ID (implements PlanItemUpdater)
	UpdatePlanItemProductID(ctx context.Context, planItemID, productID uuid.UUID) error

	// Validation
	Validate(ctx context.Context, item *models.PlanItem) error
	Exists(ctx context.Context, companyID uuid.UUID, planItemID uuid.UUID) (bool, error)
	CodeExists(ctx context.Context, companyID uuid.UUID, code string) (bool, error)
	CanDelete(ctx context.Context, companyID uuid.UUID, planItemID uuid.UUID) error

	// Query
	List(ctx context.Context, filter repository.PlanItemFilter, p Pagination, s Sort) ([]*models.PlanItem, int64, error)
	Search(ctx context.Context, companyID uuid.UUID, query string, limit, offset int) ([]*models.PlanItem, int64, error)
	GetByPlan(ctx context.Context, planID uuid.UUID) ([]*models.PlanItem, error)
	GetActiveByPlan(ctx context.Context, planID uuid.UUID) ([]*models.PlanItem, error)
	GetBySubscription(ctx context.Context, subscriptionID uuid.UUID) ([]*models.PlanItem, error)
}

// -------------------------------------------------------------------------
// Implementation
// -------------------------------------------------------------------------

type planItemService struct {
	planItemRepo     repository.PlanItemRepository
	planRepo         repository.PlanRepository
	subscriptionRepo repository.SubscriptionRepository
	subItemRepo      repository.SubscriptionItemRepository
	outboxRepo       outbox.Repository
	idempotencyStore idempotency.Store
	auditService     *audit.AuditService
	pgClient         *client.PostgresClient
	logger           *zap.Logger
}

func NewPlanItemService(
	planItemRepo repository.PlanItemRepository,
	planRepo repository.PlanRepository,
	subscriptionRepo repository.SubscriptionRepository,
	subItemRepo repository.SubscriptionItemRepository,
	outboxRepo outbox.Repository,
	idempotencyStore idempotency.Store,
	auditService *audit.AuditService,
	pgClient *client.PostgresClient,
	logger *zap.Logger,
) PlanItemService {
	return &planItemService{
		planItemRepo:     planItemRepo,
		planRepo:         planRepo,
		subscriptionRepo: subscriptionRepo,
		subItemRepo:      subItemRepo,
		outboxRepo:       outboxRepo,
		idempotencyStore: idempotencyStore,
		auditService:     auditService,
		pgClient:         pgClient,
		logger:           logger.Named("plan_item_service"),
	}
}

// -------------------------------------------------------------------------
// Helpers
// -------------------------------------------------------------------------

func (s *planItemService) getSQLTx(tx repository.DBTX) (*sql.Tx, error) {
	sqlTx, ok := tx.(*sql.Tx)
	if !ok {
		return nil, fmt.Errorf("tx is not a *sql.Tx")
	}
	return sqlTx, nil
}

func (s *planItemService) emitEvent(ctx context.Context, tx repository.DBTX, aggregateID uuid.UUID, eventType string, payload interface{}) error {
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
		AggregateType: "plan_item",
		AggregateID:   aggregateID.String(),
		EventType:     eventType,
		Topic:         events.TopicPlanItemEvents,
		Payload:       data,
	}
	return s.outboxRepo.Store(ctx, sqlTx, event)
}

func (s *planItemService) getPlanItemWithCompany(ctx context.Context, tx repository.DBTX, companyID, planItemID uuid.UUID) (*models.PlanItem, error) {
	item, err := s.planItemRepo.GetByIDForUpdate(ctx, tx, planItemID)
	if err != nil {
		return nil, err
	}
	if item == nil {
		return nil, errors.ErrNotFound
	}
	plan, err := s.planRepo.GetByID(ctx, tx, companyID, item.PlanID)
	if err != nil {
		return nil, err
	}
	if plan == nil {
		return nil, errors.ErrPermissionDenied
	}
	return item, nil
}

// buildPlanItemPayload includes all fields including CompanyID, TaxRate, ProductID, Metadata
func buildPlanItemPayload(item *models.PlanItem) events.PlanItemPayload {
	payload := events.PlanItemPayload{
		PlanItemID:    item.PlanItemID.String(),
		PlanID:        item.PlanID.String(),
		CompanyID:     item.CompanyID.String(),
		ItemType:      string(item.ItemType),
		Name:          item.Name,
		Description:   item.Description,
		FeatureKey:    item.FeatureKey,
		Price:         item.Price.String(),
		Currency:      item.Currency,
		EffectiveFrom: item.EffectiveFrom.Format(time.RFC3339),
		IsMandatory:   item.IsMandatory,
		IsActive:      item.IsActive,
		Metadata:      item.Metadata,
	}
	if item.BillingPolicyID != nil {
		id := item.BillingPolicyID.String()
		payload.BillingPolicyID = &id
	}
	if item.EffectiveTo != nil {
		payload.EffectiveTo = item.EffectiveTo.Format(time.RFC3339)
	}
	if item.TaxRate != nil {
		tr := item.TaxRate.String()
		payload.TaxRate = &tr
	}
	if item.ProductID != nil {
		pid := item.ProductID.String()
		payload.ProductID = &pid
	}
	return payload
}

// -------------------------------------------------------------------------
// CRUD
// -------------------------------------------------------------------------

func (s *planItemService) Create(ctx context.Context, item *models.PlanItem) error {
	logger := s.logger.With(zap.String("method", "Create"))
	tx, err := s.pgClient.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("begin tx: %w", err)
	}
	defer tx.Rollback()

	key := getIDempotencyKey(ctx, fmt.Sprintf("create-planitem-%s", item.Name))
	var cached *models.PlanItem
	if err := s.idempotencyStore.Get(ctx, tx, key, &cached); err == nil && cached != nil {
		logger.Info("idempotent – returning cached result")
		return nil
	}

	if err := s.Validate(ctx, item); err != nil {
		return err
	}
	if item.PlanID == uuid.Nil {
		return errors.ErrInvalidInput
	}
	now := time.Now()
	item.PlanItemID = uuid.New()
	item.CreatedAt = now
	item.UpdatedAt = now
	if item.EffectiveFrom.IsZero() {
		item.EffectiveFrom = now
	}

	if err := s.planItemRepo.Create(ctx, tx, item); err != nil {
		return err
	}

	payload := buildPlanItemPayload(item)
	if err := s.emitEvent(ctx, tx, item.PlanItemID, events.EventPlanItemCreated, payload); err != nil {
		logger.Warn("failed to emit event", zap.Error(err))
	}

	if err := s.idempotencyStore.Store(ctx, tx, key, item); err != nil {
		logger.Warn("failed to store idempotency", zap.Error(err))
	}

	if s.auditService != nil {
		_ = s.auditService.LogAction(ctx, tx, nil, "plan_item", "create", "plan_item",
			&item.PlanItemID, "system", nil, nil, nil, map[string]interface{}{
				"name":       item.Name,
				"plan":       item.PlanID.String(),
				"company_id": item.CompanyID.String(),
			})
	}

	if err := tx.Commit(); err != nil {
		return fmt.Errorf("commit tx: %w", err)
	}

	return nil
}

func (s *planItemService) BulkCreate(ctx context.Context, items []*models.PlanItem) error {
	if len(items) == 0 {
		return nil
	}
	logger := s.logger.With(zap.String("method", "BulkCreate"))
	tx, err := s.pgClient.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("begin tx: %w", err)
	}
	defer tx.Rollback()

	key := getIDempotencyKey(ctx, fmt.Sprintf("bulk-create-planitems-%s", items[0].PlanID.String()))
	var cached []*models.PlanItem
	if err := s.idempotencyStore.Get(ctx, tx, key, &cached); err == nil && cached != nil {
		logger.Info("idempotent – returning cached result")
		return nil
	}

	for _, item := range items {
		if err := s.Validate(ctx, item); err != nil {
			return err
		}
		if item.PlanID == uuid.Nil {
			return errors.ErrInvalidInput
		}
		now := time.Now()
		item.PlanItemID = uuid.New()
		item.CreatedAt = now
		item.UpdatedAt = now
		if item.EffectiveFrom.IsZero() {
			item.EffectiveFrom = now
		}
	}

	if err := s.planItemRepo.BulkCreate(ctx, tx, items); err != nil {
		return err
	}

	for _, item := range items {
		payload := buildPlanItemPayload(item)
		if err := s.emitEvent(ctx, tx, item.PlanItemID, events.EventPlanItemCreated, payload); err != nil {
			logger.Warn("failed to emit event", zap.Error(err))
		}
	}

	if err := s.idempotencyStore.Store(ctx, tx, key, items); err != nil {
		logger.Warn("failed to store idempotency", zap.Error(err))
	}

	if s.auditService != nil {
		_ = s.auditService.LogAction(ctx, tx, nil, "plan_item", "bulk_create", "plan_item",
			nil, "system", nil, nil, nil, map[string]interface{}{
				"count": len(items),
				"plan":  items[0].PlanID.String(),
			})
	}

	if err := tx.Commit(); err != nil {
		return fmt.Errorf("commit tx: %w", err)
	}

	return nil
}

func (s *planItemService) Update(ctx context.Context, item *models.PlanItem) error {
	logger := s.logger.With(zap.String("method", "Update"))
	tx, err := s.pgClient.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("begin tx: %w", err)
	}
	defer tx.Rollback()

	key := getIDempotencyKey(ctx, fmt.Sprintf("update-planitem-%s", item.PlanItemID.String()))
	var cached *models.PlanItem
	if err := s.idempotencyStore.Get(ctx, tx, key, &cached); err == nil && cached != nil {
		logger.Info("idempotent – returning cached result")
		return nil
	}

	if err := s.Validate(ctx, item); err != nil {
		return err
	}
	existing, err := s.planItemRepo.GetByIDForUpdate(ctx, tx, item.PlanItemID)
	if err != nil {
		return err
	}
	if existing == nil {
		return errors.ErrNotFound
	}
	if existing.PlanID != item.PlanID {
		return errors.ErrInvalidInput
	}
	item.CreatedAt = existing.CreatedAt
	item.UpdatedAt = time.Now()
	item.DeletedAt = existing.DeletedAt

	if err := s.planItemRepo.Update(ctx, tx, item); err != nil {
		return err
	}

	payload := buildPlanItemPayload(item)
	if err := s.emitEvent(ctx, tx, item.PlanItemID, events.EventPlanItemUpdated, payload); err != nil {
		logger.Warn("failed to emit event", zap.Error(err))
	}

	if err := s.idempotencyStore.Store(ctx, tx, key, item); err != nil {
		logger.Warn("failed to store idempotency", zap.Error(err))
	}

	if s.auditService != nil {
		_ = s.auditService.LogAction(ctx, tx, nil, "plan_item", "update", "plan_item",
			&item.PlanItemID, "system", nil, nil, nil, map[string]interface{}{
				"name": item.Name,
			})
	}

	if err := tx.Commit(); err != nil {
		return fmt.Errorf("commit tx: %w", err)
	}

	return nil
}

func (s *planItemService) Delete(ctx context.Context, companyID uuid.UUID, planItemID uuid.UUID) error {
	logger := s.logger.With(zap.String("method", "Delete"))
	tx, err := s.pgClient.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("begin tx: %w", err)
	}
	defer tx.Rollback()

	key := getIDempotencyKey(ctx, fmt.Sprintf("delete-planitem-%s", planItemID.String()))
	var cached bool
	if err := s.idempotencyStore.Get(ctx, tx, key, &cached); err == nil && cached {
		logger.Info("idempotent – returning cached result")
		return nil
	}

	item, err := s.getPlanItemWithCompany(ctx, tx, companyID, planItemID)
	if err != nil {
		return err
	}
	if err := s.CanDelete(ctx, companyID, planItemID); err != nil {
		return err
	}

	if err := s.planItemRepo.SoftDelete(ctx, tx, planItemID); err != nil {
		return err
	}

	payload := buildPlanItemPayload(item)
	if err := s.emitEvent(ctx, tx, planItemID, events.EventPlanItemDeleted, payload); err != nil {
		logger.Warn("failed to emit event", zap.Error(err))
	}

	if err := s.idempotencyStore.Store(ctx, tx, key, true); err != nil {
		logger.Warn("failed to store idempotency", zap.Error(err))
	}

	if s.auditService != nil {
		_ = s.auditService.LogAction(ctx, tx, &companyID, "plan_item", "delete", "plan_item",
			&planItemID, "system", nil, nil, nil, nil)
	}

	if err := tx.Commit(); err != nil {
		return fmt.Errorf("commit tx: %w", err)
	}

	return nil
}

func (s *planItemService) GetByID(ctx context.Context, companyID uuid.UUID, planItemID uuid.UUID) (*models.PlanItem, error) {
	tx, err := s.pgClient.BeginTx(ctx, nil)
	if err != nil {
		return nil, fmt.Errorf("begin tx: %w", err)
	}
	defer tx.Rollback()

	item, err := s.getPlanItemWithCompany(ctx, tx, companyID, planItemID)
	if err != nil {
		return nil, err
	}
	return item, nil
}

func (s *planItemService) GetByCode(ctx context.Context, companyID uuid.UUID, code string) (*models.PlanItem, error) {
	return nil, errors.ErrNotFound
}

// -------------------------------------------------------------------------
// Plan Management
// -------------------------------------------------------------------------

func (s *planItemService) AddToPlan(ctx context.Context, planID uuid.UUID, item *models.PlanItem) error {
	item.PlanID = planID
	return s.Create(ctx, item)
}

func (s *planItemService) RemoveFromPlan(ctx context.Context, planID uuid.UUID, planItemID uuid.UUID) error {
	tx, err := s.pgClient.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("begin tx: %w", err)
	}
	defer tx.Rollback()

	item, err := s.planItemRepo.GetByIDForUpdate(ctx, tx, planItemID)
	if err != nil {
		return err
	}
	if item == nil {
		return errors.ErrNotFound
	}
	if item.PlanID != planID {
		return errors.ErrInvalidInput
	}
	if err := s.planItemRepo.SoftDelete(ctx, tx, planItemID); err != nil {
		return err
	}
	payload := buildPlanItemPayload(item)
	if err := s.emitEvent(ctx, tx, planItemID, events.EventPlanItemDeleted, payload); err != nil {
		s.logger.Warn("failed to emit event", zap.Error(err))
	}
	return tx.Commit()
}

func (s *planItemService) MoveToPlan(ctx context.Context, sourcePlanID uuid.UUID, targetPlanID uuid.UUID, planItemID uuid.UUID) error {
	tx, err := s.pgClient.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("begin tx: %w", err)
	}
	defer tx.Rollback()

	item, err := s.planItemRepo.GetByIDForUpdate(ctx, tx, planItemID)
	if err != nil {
		return err
	}
	if item == nil {
		return errors.ErrNotFound
	}
	if item.PlanID != sourcePlanID {
		return errors.ErrInvalidInput
	}
	item.PlanID = targetPlanID
	item.UpdatedAt = time.Now()
	if err := s.planItemRepo.Update(ctx, tx, item); err != nil {
		return err
	}
	payload := buildPlanItemPayload(item)
	if err := s.emitEvent(ctx, tx, planItemID, events.EventPlanItemUpdated, payload); err != nil {
		s.logger.Warn("failed to emit event", zap.Error(err))
	}
	return tx.Commit()
}

func (s *planItemService) CopyToPlan(ctx context.Context, sourcePlanID uuid.UUID, targetPlanID uuid.UUID, planItemID uuid.UUID) error {
	tx, err := s.pgClient.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("begin tx: %w", err)
	}
	defer tx.Rollback()

	source, err := s.planItemRepo.GetByID(ctx, tx, planItemID)
	if err != nil {
		return err
	}
	if source == nil || source.PlanID != sourcePlanID {
		return errors.ErrNotFound
	}
	copyItem := &models.PlanItem{
		PlanID:          targetPlanID,
		CompanyID:       source.CompanyID,
		ItemType:        source.ItemType,
		Name:            source.Name,
		Description:     source.Description,
		FeatureKey:      source.FeatureKey,
		BillingPolicyID: source.BillingPolicyID,
		Price:           source.Price,
		Currency:        source.Currency,
		EffectiveFrom:   source.EffectiveFrom,
		EffectiveTo:     source.EffectiveTo,
		IsMandatory:     source.IsMandatory,
		IsActive:        source.IsActive,
		TaxRate:         source.TaxRate,
		ProductID:       source.ProductID,
		Metadata:        source.Metadata,
	}
	if err := s.Create(ctx, copyItem); err != nil {
		return err
	}
	return tx.Commit()
}

func (s *planItemService) Reorder(ctx context.Context, planID uuid.UUID, itemIDs []uuid.UUID) error {
	return errors.ErrInvalidInput
}

// -------------------------------------------------------------------------
// Lifecycle
// -------------------------------------------------------------------------

func (s *planItemService) Activate(ctx context.Context, companyID uuid.UUID, planItemID uuid.UUID) error {
	logger := s.logger.With(zap.String("method", "Activate"))
	tx, err := s.pgClient.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("begin tx: %w", err)
	}
	defer tx.Rollback()

	key := getIDempotencyKey(ctx, fmt.Sprintf("activate-planitem-%s", planItemID.String()))
	var cached bool
	if err := s.idempotencyStore.Get(ctx, tx, key, &cached); err == nil && cached {
		logger.Info("idempotent – returning cached result")
		return nil
	}

	item, err := s.getPlanItemWithCompany(ctx, tx, companyID, planItemID)
	if err != nil {
		return err
	}
	if item.IsActive {
		return nil
	}
	item.IsActive = true
	item.UpdatedAt = time.Now()
	if err := s.planItemRepo.Update(ctx, tx, item); err != nil {
		return err
	}

	payload := buildPlanItemPayload(item)
	if err := s.emitEvent(ctx, tx, planItemID, events.EventPlanItemActivated, payload); err != nil {
		logger.Warn("failed to emit event", zap.Error(err))
	}

	if err := s.idempotencyStore.Store(ctx, tx, key, true); err != nil {
		logger.Warn("failed to store idempotency", zap.Error(err))
	}

	if s.auditService != nil {
		_ = s.auditService.LogAction(ctx, tx, &companyID, "plan_item", "activate", "plan_item",
			&planItemID, "system", nil, nil, nil, nil)
	}

	if err := tx.Commit(); err != nil {
		return fmt.Errorf("commit tx: %w", err)
	}

	return nil
}

func (s *planItemService) Deactivate(ctx context.Context, companyID uuid.UUID, planItemID uuid.UUID) error {
	logger := s.logger.With(zap.String("method", "Deactivate"))
	tx, err := s.pgClient.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("begin tx: %w", err)
	}
	defer tx.Rollback()

	key := getIDempotencyKey(ctx, fmt.Sprintf("deactivate-planitem-%s", planItemID.String()))
	var cached bool
	if err := s.idempotencyStore.Get(ctx, tx, key, &cached); err == nil && cached {
		logger.Info("idempotent – returning cached result")
		return nil
	}

	item, err := s.getPlanItemWithCompany(ctx, tx, companyID, planItemID)
	if err != nil {
		return err
	}
	if !item.IsActive {
		return nil
	}
	item.IsActive = false
	item.UpdatedAt = time.Now()
	if err := s.planItemRepo.Update(ctx, tx, item); err != nil {
		return err
	}

	payload := buildPlanItemPayload(item)
	if err := s.emitEvent(ctx, tx, planItemID, events.EventPlanItemDeactivated, payload); err != nil {
		logger.Warn("failed to emit event", zap.Error(err))
	}

	if err := s.idempotencyStore.Store(ctx, tx, key, true); err != nil {
		logger.Warn("failed to store idempotency", zap.Error(err))
	}

	if s.auditService != nil {
		_ = s.auditService.LogAction(ctx, tx, &companyID, "plan_item", "deactivate", "plan_item",
			&planItemID, "system", nil, nil, nil, nil)
	}

	if err := tx.Commit(); err != nil {
		return fmt.Errorf("commit tx: %w", err)
	}

	return nil
}

func (s *planItemService) Restore(ctx context.Context, companyID uuid.UUID, planItemID uuid.UUID) error {
	logger := s.logger.With(zap.String("method", "Restore"))
	tx, err := s.pgClient.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("begin tx: %w", err)
	}
	defer tx.Rollback()

	key := getIDempotencyKey(ctx, fmt.Sprintf("restore-planitem-%s", planItemID.String()))
	var cached bool
	if err := s.idempotencyStore.Get(ctx, tx, key, &cached); err == nil && cached {
		logger.Info("idempotent – returning cached result")
		return nil
	}

	if err := s.planItemRepo.Restore(ctx, tx, planItemID); err != nil {
		return err
	}
	item, err := s.getPlanItemWithCompany(ctx, tx, companyID, planItemID)
	if err != nil {
		return err
	}
	payload := buildPlanItemPayload(item)
	if err := s.emitEvent(ctx, tx, planItemID, events.EventPlanItemRestored, payload); err != nil {
		logger.Warn("failed to emit event", zap.Error(err))
	}

	if err := s.idempotencyStore.Store(ctx, tx, key, true); err != nil {
		logger.Warn("failed to store idempotency", zap.Error(err))
	}

	if s.auditService != nil {
		_ = s.auditService.LogAction(ctx, tx, &companyID, "plan_item", "restore", "plan_item",
			&planItemID, "system", nil, nil, nil, nil)
	}

	if err := tx.Commit(); err != nil {
		return fmt.Errorf("commit tx: %w", err)
	}

	return nil
}

// -------------------------------------------------------------------------
// Configuration
// -------------------------------------------------------------------------

func (s *planItemService) UpdatePrice(ctx context.Context, companyID uuid.UUID, planItemID uuid.UUID, price decimal.Decimal, currency string) error {
	logger := s.logger.With(zap.String("method", "UpdatePrice"))
	tx, err := s.pgClient.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("begin tx: %w", err)
	}
	defer tx.Rollback()

	key := getIDempotencyKey(ctx, fmt.Sprintf("updateprice-planitem-%s", planItemID.String()))
	var cached bool
	if err := s.idempotencyStore.Get(ctx, tx, key, &cached); err == nil && cached {
		logger.Info("idempotent – returning cached result")
		return nil
	}

	item, err := s.getPlanItemWithCompany(ctx, tx, companyID, planItemID)
	if err != nil {
		return err
	}
	if err := s.planItemRepo.UpdatePrice(ctx, tx, planItemID, price, currency); err != nil {
		return err
	}
	item.Price = price
	item.Currency = currency
	payload := buildPlanItemPayload(item)
	if err := s.emitEvent(ctx, tx, planItemID, events.EventPlanItemPriceUpdated, payload); err != nil {
		logger.Warn("failed to emit event", zap.Error(err))
	}

	if err := s.idempotencyStore.Store(ctx, tx, key, true); err != nil {
		logger.Warn("failed to store idempotency", zap.Error(err))
	}

	if s.auditService != nil {
		_ = s.auditService.LogAction(ctx, tx, &companyID, "plan_item", "update_price", "plan_item",
			&planItemID, "system", nil, nil, nil, map[string]interface{}{
				"price":    price.String(),
				"currency": currency,
			})
	}

	if err := tx.Commit(); err != nil {
		return fmt.Errorf("commit tx: %w", err)
	}

	return nil
}

func (s *planItemService) UpdateQuantity(ctx context.Context, companyID uuid.UUID, planItemID uuid.UUID, quantity int) error {
	return errors.ErrInvalidInput
}

func (s *planItemService) UpdateSortOrder(ctx context.Context, companyID uuid.UUID, planItemID uuid.UUID, sortOrder int) error {
	return errors.ErrInvalidInput
}

// -------------------------------------------------------------------------
// NEW: UpdatePlanItemProductID – Implements PlanItemUpdater interface
// -------------------------------------------------------------------------

func (s *planItemService) UpdatePlanItemProductID(ctx context.Context, planItemID, productID uuid.UUID) error {
	logger := s.logger.With(
		zap.String("method", "UpdatePlanItemProductID"),
		zap.String("plan_item_id", planItemID.String()),
		zap.String("product_id", productID.String()),
	)

	tx, err := s.pgClient.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("begin tx: %w", err)
	}
	defer tx.Rollback()

	key := getIDempotencyKey(ctx, fmt.Sprintf("link-planitem-product-%s-%s", planItemID.String(), productID.String()))
	var done bool
	if err := s.idempotencyStore.Get(ctx, tx, key, &done); err == nil && done {
		logger.Info("idempotent – product already linked")
		return nil
	}

	item, err := s.planItemRepo.GetByIDForUpdate(ctx, tx, planItemID)
	if err != nil {
		return fmt.Errorf("get plan item: %w", err)
	}
	if item == nil {
		return errors.ErrNotFound
	}

	// Update product_id
	item.ProductID = &productID
	item.UpdatedAt = time.Now()

	if err := s.planItemRepo.Update(ctx, tx, item); err != nil {
		return fmt.Errorf("update plan item: %w", err)
	}

	// Emit updated event so downstream listeners know the product link changed
	payload := buildPlanItemPayload(item)
	if err := s.emitEvent(ctx, tx, planItemID, events.EventPlanItemUpdated, payload); err != nil {
		logger.Warn("failed to emit plan item updated event (product link)", zap.Error(err))
		// Not a critical failure – the DB update already succeeded.
	}

	if err := s.idempotencyStore.Store(ctx, tx, key, true); err != nil {
		logger.Warn("failed to store idempotency", zap.Error(err))
	}

	if err := tx.Commit(); err != nil {
		return fmt.Errorf("commit tx: %w", err)
	}

	logger.Info("successfully linked product ID to plan item")
	return nil
}

// -------------------------------------------------------------------------
// Validation
// -------------------------------------------------------------------------

func (s *planItemService) Validate(ctx context.Context, item *models.PlanItem) error {
	if item == nil {
		return errors.ErrInvalidInput
	}
	if item.CompanyID == uuid.Nil {
		return fmt.Errorf("%w: company_id is required", errors.ErrInvalidInput)
	}
	if item.Name == "" {
		return fmt.Errorf("%w: name is required", errors.ErrInvalidInput)
	}
	if !item.ItemType.IsValid() {
		return fmt.Errorf("%w: invalid item type", errors.ErrInvalidInput)
	}
	if item.Price.LessThan(decimal.Zero) {
		return fmt.Errorf("%w: price cannot be negative", errors.ErrInvalidInput)
	}
	if item.Currency == "" {
		return fmt.Errorf("%w: currency is required", errors.ErrInvalidInput)
	}
	if item.EffectiveFrom.IsZero() {
		return fmt.Errorf("%w: effective_from is required", errors.ErrInvalidInput)
	}
	if item.EffectiveTo != nil && item.EffectiveTo.Before(item.EffectiveFrom) {
		return fmt.Errorf("%w: effective_to must be after effective_from", errors.ErrInvalidInput)
	}
	return nil
}

func (s *planItemService) Exists(ctx context.Context, companyID uuid.UUID, planItemID uuid.UUID) (bool, error) {
	tx, err := s.pgClient.BeginTx(ctx, nil)
	if err != nil {
		return false, fmt.Errorf("begin tx: %w", err)
	}
	defer tx.Rollback()

	exists, err := s.planItemRepo.Exists(ctx, tx, planItemID)
	if err != nil {
		return false, err
	}
	if !exists {
		return false, nil
	}
	item, err := s.planItemRepo.GetByID(ctx, tx, planItemID)
	if err != nil {
		return false, err
	}
	if item == nil {
		return false, nil
	}
	plan, err := s.planRepo.GetByID(ctx, tx, companyID, item.PlanID)
	if err != nil {
		return false, err
	}
	return plan != nil, nil
}

func (s *planItemService) CodeExists(ctx context.Context, companyID uuid.UUID, code string) (bool, error) {
	return false, nil
}

func (s *planItemService) CanDelete(ctx context.Context, companyID uuid.UUID, planItemID uuid.UUID) error {
	tx, err := s.pgClient.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("begin tx: %w", err)
	}
	defer tx.Rollback()

	subItems, err := s.subItemRepo.GetByPlanItem(ctx, tx, planItemID)
	if err != nil {
		return err
	}
	if len(subItems) > 0 {
		return errors.ErrConflict
	}
	return nil
}

// -------------------------------------------------------------------------
// Query
// -------------------------------------------------------------------------

func (s *planItemService) List(ctx context.Context, filter repository.PlanItemFilter, p Pagination, srt Sort) ([]*models.PlanItem, int64, error) {
	tx, err := s.pgClient.BeginTx(ctx, nil)
	if err != nil {
		return nil, 0, fmt.Errorf("begin tx: %w", err)
	}
	defer tx.Rollback()

	repoFilter := repository.PlanItemFilter{
		PlanID:          filter.PlanID,
		PlanItemIDs:     filter.PlanItemIDs,
		CompanyID:       filter.CompanyID,
		ProductID:       filter.ProductID,
		Name:            filter.Name,
		ItemType:        filter.ItemType,
		FeatureKey:      filter.FeatureKey,
		BillingPolicyID: filter.BillingPolicyID,
		MinPrice:        filter.MinPrice,
		MaxPrice:        filter.MaxPrice,
		Currency:        filter.Currency,
		IsMandatory:     filter.IsMandatory,
		IsActive:        filter.IsActive,
		EffectiveFrom:   filter.EffectiveFrom,
		EffectiveTo:     filter.EffectiveTo,
		CreatedFrom:     filter.CreatedFrom,
		CreatedTo:       filter.CreatedTo,
		UpdatedFrom:     filter.UpdatedFrom,
		UpdatedTo:       filter.UpdatedTo,
		Deleted:         filter.Deleted,
		MinTaxRate:      filter.MinTaxRate,
		MaxTaxRate:      filter.MaxTaxRate,
	}
	repoP := repository.Pagination{Limit: p.Limit, Offset: p.Offset}
	repoS := repository.Sort{Field: srt.Field, Direction: srt.Direction}
	return s.planItemRepo.List(ctx, tx, repoFilter, repoP, repoS)
}

func (s *planItemService) Search(ctx context.Context, companyID uuid.UUID, query string, limit, offset int) ([]*models.PlanItem, int64, error) {
	return nil, 0, errors.ErrInvalidInput
}

func (s *planItemService) GetByPlan(ctx context.Context, planID uuid.UUID) ([]*models.PlanItem, error) {
	tx, err := s.pgClient.BeginTx(ctx, nil)
	if err != nil {
		return nil, fmt.Errorf("begin tx: %w", err)
	}
	defer tx.Rollback()

	return s.planItemRepo.GetByPlan(ctx, tx, planID)
}

func (s *planItemService) GetActiveByPlan(ctx context.Context, planID uuid.UUID) ([]*models.PlanItem, error) {
	tx, err := s.pgClient.BeginTx(ctx, nil)
	if err != nil {
		return nil, fmt.Errorf("begin tx: %w", err)
	}
	defer tx.Rollback()

	return s.planItemRepo.GetActiveByPlan(ctx, tx, planID)
}

func (s *planItemService) GetBySubscription(ctx context.Context, subscriptionID uuid.UUID) ([]*models.PlanItem, error) {
	return nil, errors.ErrInvalidInput
}

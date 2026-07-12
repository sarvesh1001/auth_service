// internal/subscription/service/subscription_item_service.go
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
	subErrors "auth-service/internal/subscription/errors"
	"auth-service/internal/subscription/events"
	"auth-service/internal/subscription/models"
	"auth-service/internal/subscription/models/enums"
	"auth-service/internal/subscription/repository"
)

// SubscriptionItemService defines the business operations for managing
// subscription items (both plan items and addons attached to a subscription).
type SubscriptionItemService interface {
	// -------------------------------------------------------------------------
	// CRUD
	// -------------------------------------------------------------------------
	Create(ctx context.Context, item *models.SubscriptionItem) error
	BulkCreate(ctx context.Context, items []*models.SubscriptionItem) error
	Update(ctx context.Context, item *models.SubscriptionItem) error
	Delete(ctx context.Context, companyID uuid.UUID, subItemID uuid.UUID) error
	GetByID(ctx context.Context, companyID uuid.UUID, subItemID uuid.UUID) (*models.SubscriptionItem, error)

	// -------------------------------------------------------------------------
	// Subscription‑scoped Operations
	// -------------------------------------------------------------------------
	AddToSubscription(ctx context.Context, subscriptionID uuid.UUID, item *models.SubscriptionItem) error
	RemoveFromSubscription(ctx context.Context, subscriptionID uuid.UUID, subItemID uuid.UUID) error
	ReplaceSubscriptionItems(ctx context.Context, subscriptionID uuid.UUID, items []*models.SubscriptionItem) error
	CopyFromPlan(ctx context.Context, subscriptionID uuid.UUID, planID uuid.UUID) error
	RefreshFromPlan(ctx context.Context, subscriptionID uuid.UUID) error

	// -------------------------------------------------------------------------
	// Configuration (on existing items)
	// -------------------------------------------------------------------------
	UpdateQuantity(ctx context.Context, companyID uuid.UUID, subItemID uuid.UUID, quantity int) error
	UpdatePrice(ctx context.Context, companyID uuid.UUID, subItemID uuid.UUID, price decimal.Decimal, currency string) error
	Activate(ctx context.Context, companyID uuid.UUID, subItemID uuid.UUID) error
	Deactivate(ctx context.Context, companyID uuid.UUID, subItemID uuid.UUID) error
	Restore(ctx context.Context, companyID uuid.UUID, subItemID uuid.UUID) error

	// -------------------------------------------------------------------------
	// Validation & Existence
	// -------------------------------------------------------------------------
	Validate(ctx context.Context, item *models.SubscriptionItem) error
	Exists(ctx context.Context, companyID uuid.UUID, subItemID uuid.UUID) (bool, error)
	CanDelete(ctx context.Context, companyID uuid.UUID, subItemID uuid.UUID) error

	// -------------------------------------------------------------------------
	// Query
	// -------------------------------------------------------------------------
	List(ctx context.Context, filter repository.SubscriptionItemFilter, p repository.Pagination, s repository.Sort) ([]*models.SubscriptionItem, int64, error)
	Search(ctx context.Context, subscriptionID uuid.UUID, query string, limit, offset int) ([]*models.SubscriptionItem, int64, error)
	GetBySubscription(ctx context.Context, subscriptionID uuid.UUID) ([]*models.SubscriptionItem, error)
	GetActiveBySubscription(ctx context.Context, subscriptionID uuid.UUID) ([]*models.SubscriptionItem, error)
	GetByPlanItem(ctx context.Context, planItemID uuid.UUID) ([]*models.SubscriptionItem, error)
	GetByAddon(ctx context.Context, addonID uuid.UUID) ([]*models.SubscriptionItem, error)
}

// subscriptionItemService implements SubscriptionItemService.
type subscriptionItemService struct {
	subItemRepo      repository.SubscriptionItemRepository
	planItemRepo     repository.PlanItemRepository
	addonRepo        repository.AddonRepository
	subRepo          repository.SubscriptionRepository
	outboxRepo       outbox.Repository
	idempotencyStore idempotency.Store
	auditService     *audit.AuditService
	pgClient         *client.PostgresClient
	logger           *zap.Logger
}

// NewSubscriptionItemService creates a new SubscriptionItemService.
func NewSubscriptionItemService(
	subItemRepo repository.SubscriptionItemRepository,
	planItemRepo repository.PlanItemRepository,
	addonRepo repository.AddonRepository,
	subRepo repository.SubscriptionRepository,
	outboxRepo outbox.Repository,
	idempotencyStore idempotency.Store,
	auditService *audit.AuditService,
	pgClient *client.PostgresClient,
	logger *zap.Logger,
) SubscriptionItemService {
	return &subscriptionItemService{
		subItemRepo:      subItemRepo,
		planItemRepo:     planItemRepo,
		addonRepo:        addonRepo,
		subRepo:          subRepo,
		outboxRepo:       outboxRepo,
		idempotencyStore: idempotencyStore,
		auditService:     auditService,
		pgClient:         pgClient,
		logger:           logger.Named("subscription_item_service"),
	}
}

// ----------------------------------------------------------------------------
// Helpers
// ----------------------------------------------------------------------------

// getSQLTx extracts a *sql.Tx from a repository.DBTX.
func (s *subscriptionItemService) getSQLTx(tx repository.DBTX) (*sql.Tx, error) {
	sqlTx, ok := tx.(*sql.Tx)
	if !ok {
		return nil, fmt.Errorf("tx is not a *sql.Tx")
	}
	return sqlTx, nil
}

// emitItemEvent stores an outbox event for the subscription item aggregate.
func (s *subscriptionItemService) emitItemEvent(ctx context.Context, tx repository.DBTX, itemID, subscriptionID uuid.UUID, eventType string, payload interface{}) error {
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
		AggregateType: "subscription_item",
		AggregateID:   itemID.String(),
		EventType:     eventType,
		Topic:         events.TopicSubscriptionEvents,
		Payload:       data,
	}
	return s.outboxRepo.Store(ctx, sqlTx, event)
}

// getItemIdempotencyKey returns the idempotency key from context or a fallback.
// (Renamed to avoid duplicate declaration with subscription_lifecycle_service)
func getItemIdempotencyKey(ctx context.Context, fallback string) string {
	if key, ok := ctx.Value("idempotency_key").(string); ok && key != "" {
		return key
	}
	return fallback
}

// buildItemPayload constructs the event payload for a subscription item.
func buildItemPayload(item *models.SubscriptionItem) events.SubscriptionItemPayload {
	payload := events.SubscriptionItemPayload{
		SubItemID:      item.SubItemID.String(),
		SubscriptionID: item.SubscriptionID.String(),
		PlanItemID:     item.PlanItemID.String(),
		Quantity:       item.Quantity.String(),
		UnitPrice:      item.UnitPrice.String(),
		TotalPrice:     item.TotalPrice.String(),
		Currency:       item.Currency,
		Status:         string(item.Status),
		StartDate:      item.StartDate.Format(time.RFC3339),
	}
	if item.AddonID != nil {
		payload.AddonID = item.AddonID.String()
	}
	if item.EndDate != nil {
		payload.EndDate = item.EndDate.Format(time.RFC3339)
	}
	if item.ProductID != nil {
		payload.ProductID = item.ProductID.String()
	}
	if item.Metadata != nil {
		payload.Metadata = item.Metadata
	}
	return payload
}

// ----------------------------------------------------------------------------
// CRUD
// ----------------------------------------------------------------------------

func (s *subscriptionItemService) Create(ctx context.Context, item *models.SubscriptionItem) error {
	logger := s.logger.With(zap.String("method", "Create"), zap.String("sub_item_id", item.SubItemID.String()))
	tx, err := s.pgClient.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("begin tx: %w", err)
	}
	defer tx.Rollback()

	idempKey := getItemIdempotencyKey(ctx, fmt.Sprintf("item-create-%s", item.SubItemID.String()))
	var done bool
	if err := s.idempotencyStore.Get(ctx, tx, idempKey, &done); err == nil && done {
		logger.Info("idempotent – item creation already processed")
		return nil
	}

	// Validate
	if err := s.Validate(ctx, item); err != nil {
		return err
	}

	// Ensure subscription exists (and optionally that it is not terminal)
	sub, err := s.subRepo.GetByID(ctx, tx, uuid.Nil, item.SubscriptionID) // companyID not needed for existence
	if err != nil {
		return subErrors.ErrSubscriptionNotFound
	}
	// Business rule: do not add items to cancelled/expired subscriptions
	if sub.Status == enums.SubStatusCancelled || sub.Status == enums.SubStatusExpired {
		return subErrors.ErrInvalidState
	}

	// If PlanItemID is set, ensure the plan item exists and is active
	if item.PlanItemID != uuid.Nil {
		planItem, err := s.planItemRepo.GetByID(ctx, tx, item.PlanItemID)
		if err != nil {
			return subErrors.ErrPlanNotFound
		}
		if !planItem.IsActive {
			return subErrors.ErrPlanInactive
		}
	}

	// If AddonID is set, ensure the addon exists and is active
	if item.AddonID != nil {
		addon, err := s.addonRepo.GetByID(ctx, tx, uuid.Nil, *item.AddonID) // companyID not required here
		if err != nil {
			return subErrors.ErrAddonNotFound
		}
		if !addon.IsActive {
			return subErrors.ErrAddonInactive
		}
	}

	// Persist
	if err := s.subItemRepo.Create(ctx, tx, item); err != nil {
		return err
	}

	// Emit event
	payload := buildItemPayload(item)
	if err := s.emitItemEvent(ctx, tx, item.SubItemID, item.SubscriptionID, events.EventSubscriptionItemCreated, payload); err != nil {
		logger.Warn("failed to emit subscription.item.created event", zap.Error(err))
	}

	if err := s.idempotencyStore.Store(ctx, tx, idempKey, true); err != nil {
		logger.Warn("failed to store idempotency record", zap.Error(err))
	}

	if err := tx.Commit(); err != nil {
		return fmt.Errorf("commit tx: %w", err)
	}

	if s.auditService != nil {
		metadata := map[string]interface{}{
			"subscription_id": item.SubscriptionID.String(),
			"plan_item_id":    item.PlanItemID.String(),
			"addon_id":        item.AddonID,
			"quantity":        item.Quantity.String(),
		}
		_ = s.auditService.LogAction(ctx, nil, nil, "subscription_item", "create", "subscription_item",
			&item.SubItemID, "system", nil, nil, nil, metadata)
	}
	return nil
}

func (s *subscriptionItemService) BulkCreate(ctx context.Context, items []*models.SubscriptionItem) error {
	if len(items) == 0 {
		return nil
	}
	logger := s.logger.With(zap.String("method", "BulkCreate"), zap.Int("count", len(items)))
	tx, err := s.pgClient.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("begin tx: %w", err)
	}
	defer tx.Rollback()

	// Use a composite idempotency key based on subscription and count/version? For simplicity, we use the subscription ID.
	subscriptionID := items[0].SubscriptionID
	idempKey := getItemIdempotencyKey(ctx, fmt.Sprintf("item-bulkcreate-%s", subscriptionID.String()))
	var done bool
	if err := s.idempotencyStore.Get(ctx, tx, idempKey, &done); err == nil && done {
		logger.Info("idempotent – bulk creation already processed")
		return nil
	}

	// Validate each item
	for _, item := range items {
		if err := s.Validate(ctx, item); err != nil {
			return err
		}
		// Ensure they all belong to the same subscription (optional)
		if item.SubscriptionID != subscriptionID {
			return subErrors.ErrInvalidInput
		}
	}

	// Check subscription once
	sub, err := s.subRepo.GetByID(ctx, tx, uuid.Nil, subscriptionID)
	if err != nil {
		return subErrors.ErrSubscriptionNotFound
	}
	if sub.Status == enums.SubStatusCancelled || sub.Status == enums.SubStatusExpired {
		return subErrors.ErrInvalidState
	}

	// Other validations (plan item & addon existence) could be done per item, but we rely on DB constraints.

	if err := s.subItemRepo.BulkCreate(ctx, tx, items); err != nil {
		return err
	}

	// Emit events and audit each
	for _, item := range items {
		payload := buildItemPayload(item)
		_ = s.emitItemEvent(ctx, tx, item.SubItemID, item.SubscriptionID, events.EventSubscriptionItemCreated, payload)
		if s.auditService != nil {
			_ = s.auditService.LogAction(ctx, nil, nil, "subscription_item", "bulk_create", "subscription_item",
				&item.SubItemID, "system", nil, nil, nil, nil)
		}
	}

	if err := s.idempotencyStore.Store(ctx, tx, idempKey, true); err != nil {
		logger.Warn("failed to store idempotency record", zap.Error(err))
	}

	if err := tx.Commit(); err != nil {
		return fmt.Errorf("commit tx: %w", err)
	}
	return nil
}

func (s *subscriptionItemService) Update(ctx context.Context, item *models.SubscriptionItem) error {
	logger := s.logger.With(zap.String("method", "Update"), zap.String("sub_item_id", item.SubItemID.String()))
	tx, err := s.pgClient.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("begin tx: %w", err)
	}
	defer tx.Rollback()

	idempKey := getItemIdempotencyKey(ctx, fmt.Sprintf("item-update-%s", item.SubItemID.String()))
	var done bool
	if err := s.idempotencyStore.Get(ctx, tx, idempKey, &done); err == nil && done {
		logger.Info("idempotent – item update already processed")
		return nil
	}

	// Validate
	if err := s.Validate(ctx, item); err != nil {
		return err
	}

	// Fetch existing (with lock) to ensure it exists and get current state
	existing, err := s.subItemRepo.GetByIDForUpdate(ctx, tx, item.SubItemID)
	if err != nil {
		return err
	}
	if existing == nil {
		return subErrors.ErrNotFound
	}

	// Preserve immutable fields (SubscriptionID, PlanItemID, AddonID, ProductID)
	item.SubscriptionID = existing.SubscriptionID
	item.PlanItemID = existing.PlanItemID
	item.AddonID = existing.AddonID
	item.ProductID = existing.ProductID
	item.UpdatedAt = time.Now()

	if err := s.subItemRepo.Update(ctx, tx, item); err != nil {
		return err
	}

	// Emit event
	payload := buildItemPayload(item)
	if err := s.emitItemEvent(ctx, tx, item.SubItemID, item.SubscriptionID, events.EventSubscriptionItemUpdated, payload); err != nil {
		logger.Warn("failed to emit subscription.item.updated event", zap.Error(err))
	}

	if err := s.idempotencyStore.Store(ctx, tx, idempKey, true); err != nil {
		logger.Warn("failed to store idempotency record", zap.Error(err))
	}

	if err := tx.Commit(); err != nil {
		return fmt.Errorf("commit tx: %w", err)
	}

	if s.auditService != nil {
		oldData, _ := json.Marshal(existing)
		newData, _ := json.Marshal(item)
		_ = s.auditService.LogAction(ctx, nil, nil, "subscription_item", "update", "subscription_item",
			&item.SubItemID, "system", nil, oldData, newData, nil)
	}
	return nil
}

func (s *subscriptionItemService) Delete(ctx context.Context, companyID uuid.UUID, subItemID uuid.UUID) error {
	logger := s.logger.With(zap.String("method", "Delete"), zap.String("sub_item_id", subItemID.String()))
	tx, err := s.pgClient.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("begin tx: %w", err)
	}
	defer tx.Rollback()

	idempKey := getItemIdempotencyKey(ctx, fmt.Sprintf("item-delete-%s", subItemID.String()))
	var done bool
	if err := s.idempotencyStore.Get(ctx, tx, idempKey, &done); err == nil && done {
		logger.Info("idempotent – item deletion already processed")
		return nil
	}

	if err := s.CanDelete(ctx, companyID, subItemID); err != nil {
		return err
	}

	if err := s.subItemRepo.Delete(ctx, tx, subItemID); err != nil {
		return err
	}

	// Emit event (we don't have the full item, so send minimal payload)
	payload := map[string]interface{}{
		"sub_item_id": subItemID.String(),
		"company_id":  companyID.String(),
	}
	if err := s.emitItemEvent(ctx, tx, subItemID, uuid.Nil, events.EventSubscriptionItemDeleted, payload); err != nil {
		logger.Warn("failed to emit subscription.item.deleted event", zap.Error(err))
	}

	if err := s.idempotencyStore.Store(ctx, tx, idempKey, true); err != nil {
		logger.Warn("failed to store idempotency record", zap.Error(err))
	}

	if err := tx.Commit(); err != nil {
		return fmt.Errorf("commit tx: %w", err)
	}

	if s.auditService != nil {
		_ = s.auditService.LogAction(ctx, nil, &companyID, "subscription_item", "delete", "subscription_item",
			&subItemID, "system", nil, nil, nil, nil)
	}
	return nil
}

func (s *subscriptionItemService) GetByID(ctx context.Context, companyID uuid.UUID, subItemID uuid.UUID) (*models.SubscriptionItem, error) {
	db := s.pgClient.DB
	item, err := s.subItemRepo.GetByID(ctx, db, subItemID)
	if err != nil {
		return nil, err
	}
	if item == nil {
		return nil, subErrors.ErrNotFound
	}
	// Optionally verify company ownership by fetching subscription
	// We can ignore companyID if not needed – repository might enforce it.
	return item, nil
}

// ----------------------------------------------------------------------------
// Subscription‑scoped Operations
// ----------------------------------------------------------------------------

func (s *subscriptionItemService) AddToSubscription(ctx context.Context, subscriptionID uuid.UUID, item *models.SubscriptionItem) error {
	item.SubscriptionID = subscriptionID
	return s.Create(ctx, item)
}

func (s *subscriptionItemService) RemoveFromSubscription(ctx context.Context, subscriptionID uuid.UUID, subItemID uuid.UUID) error {
	// Ensure the item belongs to this subscription
	item, err := s.subItemRepo.GetByID(ctx, s.pgClient.DB, subItemID)
	if err != nil {
		return err
	}
	if item == nil {
		return subErrors.ErrNotFound
	}
	if item.SubscriptionID != subscriptionID {
		return subErrors.ErrInvalidInput
	}
	return s.Delete(ctx, uuid.Nil, subItemID) // companyID not used inside Delete for validation
}

func (s *subscriptionItemService) ReplaceSubscriptionItems(ctx context.Context, subscriptionID uuid.UUID, items []*models.SubscriptionItem) error {
	logger := s.logger.With(zap.String("method", "ReplaceSubscriptionItems"), zap.String("subscription_id", subscriptionID.String()))
	tx, err := s.pgClient.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("begin tx: %w", err)
	}
	defer tx.Rollback()

	idempKey := getItemIdempotencyKey(ctx, fmt.Sprintf("item-replace-%s", subscriptionID.String()))
	var done bool
	if err := s.idempotencyStore.Get(ctx, tx, idempKey, &done); err == nil && done {
		logger.Info("idempotent – replacement already processed")
		return nil
	}

	// Validate all items and ensure they belong to the subscription
	for _, item := range items {
		item.SubscriptionID = subscriptionID
		if err := s.Validate(ctx, item); err != nil {
			return err
		}
	}

	if err := s.subItemRepo.ReplaceBySubscription(ctx, tx, subscriptionID, items); err != nil {
		return err
	}

	// Emit events for new items (or a single replacement event)
	for _, item := range items {
		payload := buildItemPayload(item)
		_ = s.emitItemEvent(ctx, tx, item.SubItemID, subscriptionID, events.EventSubscriptionItemReplaced, payload)
	}
	// Also could emit a "items_replaced" event; we do per‑item for simplicity.

	if err := s.idempotencyStore.Store(ctx, tx, idempKey, true); err != nil {
		logger.Warn("failed to store idempotency record", zap.Error(err))
	}

	if err := tx.Commit(); err != nil {
		return fmt.Errorf("commit tx: %w", err)
	}

	if s.auditService != nil {
		_ = s.auditService.LogAction(ctx, nil, nil, "subscription_item", "replace", "subscription",
			&subscriptionID, "system", nil, nil, nil, map[string]interface{}{
				"count": len(items),
			})
	}
	return nil
}

func (s *subscriptionItemService) CopyFromPlan(ctx context.Context, subscriptionID uuid.UUID, planID uuid.UUID) error {
	db := s.pgClient.DB
	planItems, err := s.planItemRepo.GetActiveByPlan(ctx, db, planID)
	if err != nil {
		return err
	}
	items := make([]*models.SubscriptionItem, 0, len(planItems))
	for _, pi := range planItems {
		item := &models.SubscriptionItem{
			SubItemID:      uuid.New(),
			SubscriptionID: subscriptionID,
			PlanItemID:     pi.PlanItemID,
			Quantity:       decimal.NewFromInt(1), // default quantity; could be derived from plan
			UnitPrice:      pi.Price,
			Currency:       pi.Currency,
			Status:         enums.ItemStatusActive,
			StartDate:      time.Now(),
			// EndDate is left nil; will be set by subscription logic
		}
		items = append(items, item)
	}
	return s.ReplaceSubscriptionItems(ctx, subscriptionID, items)
}

func (s *subscriptionItemService) RefreshFromPlan(ctx context.Context, subscriptionID uuid.UUID) error {
	// Get the subscription's current plan
	sub, err := s.subRepo.GetByID(ctx, s.pgClient.DB, uuid.Nil, subscriptionID)
	if err != nil {
		return err
	}
	if sub == nil {
		return subErrors.ErrSubscriptionNotFound
	}
	return s.CopyFromPlan(ctx, subscriptionID, sub.PlanID)
}

// ----------------------------------------------------------------------------
// Configuration
// ----------------------------------------------------------------------------

func (s *subscriptionItemService) UpdateQuantity(ctx context.Context, companyID uuid.UUID, subItemID uuid.UUID, quantity int) error {
	item, err := s.subItemRepo.GetByID(ctx, s.pgClient.DB, subItemID)
	if err != nil {
		return err
	}
	if item == nil {
		return subErrors.ErrNotFound
	}
	item.Quantity = decimal.NewFromInt(int64(quantity))
	return s.Update(ctx, item)
}

func (s *subscriptionItemService) UpdatePrice(ctx context.Context, companyID uuid.UUID, subItemID uuid.UUID, price decimal.Decimal, currency string) error {
	item, err := s.subItemRepo.GetByID(ctx, s.pgClient.DB, subItemID)
	if err != nil {
		return err
	}
	if item == nil {
		return subErrors.ErrNotFound
	}
	item.UnitPrice = price
	item.Currency = currency
	return s.Update(ctx, item)
}

func (s *subscriptionItemService) Activate(ctx context.Context, companyID uuid.UUID, subItemID uuid.UUID) error {
	item, err := s.subItemRepo.GetByID(ctx, s.pgClient.DB, subItemID)
	if err != nil {
		return err
	}
	if item == nil {
		return subErrors.ErrNotFound
	}
	item.Status = enums.ItemStatusActive
	return s.Update(ctx, item)
}

func (s *subscriptionItemService) Deactivate(ctx context.Context, companyID uuid.UUID, subItemID uuid.UUID) error {
	item, err := s.subItemRepo.GetByID(ctx, s.pgClient.DB, subItemID)
	if err != nil {
		return err
	}
	if item == nil {
		return subErrors.ErrNotFound
	}
	item.Status = enums.ItemStatusInactive
	return s.Update(ctx, item)
}

// Restore sets deleted_at = NULL for a soft‑deleted item.
// Since the repository interface doesn't have a Restore method, we use a raw UPDATE.
func (s *subscriptionItemService) Restore(ctx context.Context, companyID uuid.UUID, subItemID uuid.UUID) error {
	logger := s.logger.With(zap.String("method", "Restore"), zap.String("sub_item_id", subItemID.String()))
	tx, err := s.pgClient.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("begin tx: %w", err)
	}
	defer tx.Rollback()

	idempKey := getItemIdempotencyKey(ctx, fmt.Sprintf("item-restore-%s", subItemID.String()))
	var done bool
	if err := s.idempotencyStore.Get(ctx, tx, idempKey, &done); err == nil && done {
		logger.Info("idempotent – restore already processed")
		return nil
	}

	// Check if the item exists (ignoring deleted_at) – use GetByID (it returns even if deleted_at is set? Actually the repository's GetByID likely filters out deleted rows if using soft delete).
	// We'll use a raw query to check existence regardless of deleted_at.
	var exists bool
	err = tx.QueryRowContext(ctx, `SELECT EXISTS(SELECT 1 FROM subscription.subscription_items WHERE sub_item_id = $1)`, subItemID).Scan(&exists)
	if err != nil {
		return fmt.Errorf("check existence: %w", err)
	}
	if !exists {
		return subErrors.ErrNotFound
	}

	// Update deleted_at to NULL
	_, err = tx.ExecContext(ctx, `UPDATE subscription.subscription_items SET deleted_at = NULL WHERE sub_item_id = $1`, subItemID)
	if err != nil {
		return fmt.Errorf("restore item: %w", err)
	}

	// Emit event
	payload := map[string]interface{}{
		"sub_item_id": subItemID.String(),
		"company_id":  companyID.String(),
	}
	if err := s.emitItemEvent(ctx, tx, subItemID, uuid.Nil, events.EventSubscriptionItemRestored, payload); err != nil {
		logger.Warn("failed to emit subscription.item.restored event", zap.Error(err))
	}

	if err := s.idempotencyStore.Store(ctx, tx, idempKey, true); err != nil {
		logger.Warn("failed to store idempotency record", zap.Error(err))
	}

	if err := tx.Commit(); err != nil {
		return fmt.Errorf("commit tx: %w", err)
	}

	if s.auditService != nil {
		_ = s.auditService.LogAction(ctx, nil, &companyID, "subscription_item", "restore", "subscription_item",
			&subItemID, "system", nil, nil, nil, nil)
	}
	return nil
}

// ----------------------------------------------------------------------------
// Validation & Existence
// ----------------------------------------------------------------------------

func (s *subscriptionItemService) Validate(ctx context.Context, item *models.SubscriptionItem) error {
	if item == nil {
		return subErrors.ErrInvalidInput
	}
	if item.SubscriptionID == uuid.Nil {
		return subErrors.ErrInvalidInput
	}
	// Must have either PlanItemID or AddonID (or both? but typically one)
	if item.PlanItemID == uuid.Nil && item.AddonID == nil {
		return subErrors.ErrInvalidInput
	}
	if item.Quantity.LessThanOrEqual(decimal.Zero) {
		return subErrors.ErrInvalidInput
	}
	if item.UnitPrice.LessThan(decimal.Zero) {
		return subErrors.ErrInvalidInput
	}
	if !item.Status.IsValid() {
		return subErrors.ErrInvalidStatus
	}
	// Currency length validation (optional)
	if len(item.Currency) != 3 {
		return subErrors.ErrInvalidInput
	}
	return nil
}

func (s *subscriptionItemService) Exists(ctx context.Context, companyID uuid.UUID, subItemID uuid.UUID) (bool, error) {
	db := s.pgClient.DB
	exists, err := s.subItemRepo.Exists(ctx, db, subItemID)
	if err != nil {
		return false, err
	}
	if !exists {
		return false, nil
	}
	// Optionally verify company ownership by fetching subscription
	return true, nil
}

func (s *subscriptionItemService) CanDelete(ctx context.Context, companyID uuid.UUID, subItemID uuid.UUID) error {
	// Check existence
	exists, err := s.subItemRepo.Exists(ctx, s.pgClient.DB, subItemID)
	if err != nil {
		return err
	}
	if !exists {
		return subErrors.ErrNotFound
	}
	// Additional business rules: e.g., cannot delete if subscription is active? That's orchestration, not here.
	return nil
}

// ----------------------------------------------------------------------------
// Query
// ----------------------------------------------------------------------------

func (s *subscriptionItemService) List(ctx context.Context, filter repository.SubscriptionItemFilter, p repository.Pagination, sort repository.Sort) ([]*models.SubscriptionItem, int64, error) {
	db := s.pgClient.DB
	return s.subItemRepo.List(ctx, db, filter, p, sort)
}

func (s *subscriptionItemService) Search(ctx context.Context, subscriptionID uuid.UUID, query string, limit, offset int) ([]*models.SubscriptionItem, int64, error) {
	db := s.pgClient.DB
	return s.subItemRepo.Search(ctx, db, subscriptionID, query, limit, offset)
}

func (s *subscriptionItemService) GetBySubscription(ctx context.Context, subscriptionID uuid.UUID) ([]*models.SubscriptionItem, error) {
	db := s.pgClient.DB
	return s.subItemRepo.GetBySubscription(ctx, db, subscriptionID)
}

func (s *subscriptionItemService) GetActiveBySubscription(ctx context.Context, subscriptionID uuid.UUID) ([]*models.SubscriptionItem, error) {
	db := s.pgClient.DB
	return s.subItemRepo.GetActiveBySubscription(ctx, db, subscriptionID)
}

func (s *subscriptionItemService) GetByPlanItem(ctx context.Context, planItemID uuid.UUID) ([]*models.SubscriptionItem, error) {
	db := s.pgClient.DB
	return s.subItemRepo.GetByPlanItem(ctx, db, planItemID)
}

func (s *subscriptionItemService) GetByAddon(ctx context.Context, addonID uuid.UUID) ([]*models.SubscriptionItem, error) {
	db := s.pgClient.DB
	return s.subItemRepo.GetByAddon(ctx, db, addonID)
}

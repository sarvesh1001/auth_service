package service

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"time"

	"github.com/google/uuid"
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

// EntitlementService defines the interface.
type EntitlementService interface {
	// CRUD
	Create(ctx context.Context, entitlement *models.Entitlement) error
	BulkCreate(ctx context.Context, entitlements []*models.Entitlement) error
	Update(ctx context.Context, entitlement *models.Entitlement) error
	Delete(ctx context.Context, entitlementID uuid.UUID) error
	GetByID(ctx context.Context, entitlementID uuid.UUID) (*models.Entitlement, error)

	// Plan Item Management
	ReplaceByPlanItem(ctx context.Context, planItemID uuid.UUID, entitlements []*models.Entitlement) error
	DeleteByPlanItem(ctx context.Context, planItemID uuid.UUID) error
	CopyToPlanItem(ctx context.Context, sourcePlanItemID uuid.UUID, targetPlanItemID uuid.UUID) error

	// Subscription Provisioning
	GrantToSubscription(ctx context.Context, subscriptionID uuid.UUID) error
	RefreshSubscription(ctx context.Context, subscriptionID uuid.UUID) error
	RevokeFromSubscription(ctx context.Context, subscriptionID uuid.UUID) error

	// Validation
	Validate(ctx context.Context, entitlement *models.Entitlement) error
	Exists(ctx context.Context, entitlementID uuid.UUID) (bool, error)
	HasFeature(ctx context.Context, planItemID uuid.UUID, featureID uuid.UUID) (bool, error)

	// Query
	List(ctx context.Context, filter repository.EntitlementFilter, p repository.Pagination, s repository.Sort) ([]*models.Entitlement, int64, error)
	Search(ctx context.Context, planItemID uuid.UUID, query string, limit, offset int) ([]*models.Entitlement, int64, error)
	GetByPlanItem(ctx context.Context, planItemID uuid.UUID) ([]*models.Entitlement, error)
	GetByFeature(ctx context.Context, featureID uuid.UUID) ([]*models.Entitlement, error)
	GetBySubscription(ctx context.Context, subscriptionID uuid.UUID) ([]*models.Entitlement, error)
}

type entitlementService struct {
	repo             repository.EntitlementRepository
	planItemRepo     repository.PlanItemRepository
	planRepo         repository.PlanRepository
	subRepo          repository.SubscriptionRepository
	subItemRepo      repository.SubscriptionItemRepository
	usageRepo        repository.UsageRepository
	featureRepo      repository.FeatureRepository
	outboxRepo       outbox.Repository
	idempotencyStore idempotency.Store
	auditService     *audit.AuditService
	pgClient         *client.PostgresClient
	logger           *zap.Logger
}

func NewEntitlementService(
	repo repository.EntitlementRepository,
	planItemRepo repository.PlanItemRepository,
	planRepo repository.PlanRepository,
	subRepo repository.SubscriptionRepository,
	subItemRepo repository.SubscriptionItemRepository,
	usageRepo repository.UsageRepository,
	featureRepo repository.FeatureRepository,
	outboxRepo outbox.Repository,
	idempotencyStore idempotency.Store,
	auditService *audit.AuditService,
	pgClient *client.PostgresClient,
	logger *zap.Logger,
) EntitlementService {
	return &entitlementService{
		repo:             repo,
		planItemRepo:     planItemRepo,
		planRepo:         planRepo,
		subRepo:          subRepo,
		subItemRepo:      subItemRepo,
		usageRepo:        usageRepo,
		featureRepo:      featureRepo,
		outboxRepo:       outboxRepo,
		idempotencyStore: idempotencyStore,
		auditService:     auditService,
		pgClient:         pgClient,
		logger:           logger.Named("entitlement_service"),
	}
}

// ----------------------------------------------------------------------------
// Helpers
// ----------------------------------------------------------------------------

func (s *entitlementService) getSQLTx(tx repository.DBTX) (*sql.Tx, error) {
	sqlTx, ok := tx.(*sql.Tx)
	if !ok {
		return nil, fmt.Errorf("tx is not a *sql.Tx")
	}
	return sqlTx, nil
}

func (s *entitlementService) emitEvent(ctx context.Context, tx repository.DBTX, aggregateID uuid.UUID, eventType string, payload interface{}) error {
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
		AggregateType: "entitlement",
		AggregateID:   aggregateID.String(),
		EventType:     eventType,
		Topic:         events.TopicSubscriptionEvents,
		Payload:       data,
	}
	return s.outboxRepo.Store(ctx, sqlTx, event)
}

func idempotencyKey(prefix, id string) string {
	return fmt.Sprintf("%s-%s", prefix, id)
}

func (s *entitlementService) validateEntitlement(ctx context.Context, ent *models.Entitlement) error {
	if ent.PlanItemID == uuid.Nil {
		return errors.ErrInvalidInput
	}
	if ent.FeatureKey == "" {
		return errors.ErrInvalidInput
	}
	exists, err := s.featureRepo.Exists(ctx, nil, ent.FeatureKey)
	if err != nil {
		return err
	}
	if !exists {
		return errors.ErrInvalidInput
	}
	if ent.LimitValue != nil && !ent.LimitPeriod.IsValid() {
		return errors.ErrInvalidInput
	}
	planItemExists, err := s.planItemRepo.Exists(ctx, nil, ent.PlanItemID)
	if err != nil {
		return err
	}
	if !planItemExists {
		return errors.ErrInvalidInput
	}
	return nil
}

func buildEntitlementPayload(ent *models.Entitlement) events.EntitlementPayload {
	payload := events.EntitlementPayload{
		EntitlementID: ent.EntitlementID.String(),
		PlanItemID:    ent.PlanItemID.String(),
		FeatureKey:    ent.FeatureKey,
		IsEnabled:     ent.IsEnabled,
		CreatedAt:     ent.CreatedAt.Format(time.RFC3339),
		UpdatedAt:     ent.UpdatedAt.Format(time.RFC3339),
	}
	if ent.LimitValue != nil {
		payload.LimitValue = ent.LimitValue.String()
	}
	if ent.LimitPeriod != "" {
		payload.LimitPeriod = string(ent.LimitPeriod)
	}
	return payload
}

// ----------------------------------------------------------------------------
// CRUD
// ----------------------------------------------------------------------------

func (s *entitlementService) Create(ctx context.Context, ent *models.Entitlement) error {
	logger := s.logger.With(zap.String("method", "Create"))
	if err := s.validateEntitlement(ctx, ent); err != nil {
		return err
	}

	tx, err := s.pgClient.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("begin tx: %w", err)
	}
	defer tx.Rollback()

	key := idempotencyKey("entitlement-create", ent.EntitlementID.String())
	var cached bool
	if err := s.idempotencyStore.Get(ctx, tx, key, &cached); err == nil && cached {
		logger.Info("idempotent – create already processed")
		return nil
	}

	if err := s.repo.Create(ctx, tx, ent); err != nil {
		return err
	}

	payload := buildEntitlementPayload(ent)
	if err := s.emitEvent(ctx, tx, ent.EntitlementID, events.EventEntitlementCreated, payload); err != nil {
		logger.Warn("failed to emit event", zap.Error(err))
	}

	if err := s.idempotencyStore.Store(ctx, tx, key, true); err != nil {
		logger.Warn("failed to store idempotency record", zap.Error(err))
	}

	if err := tx.Commit(); err != nil {
		return fmt.Errorf("commit tx: %w", err)
	}

	if s.auditService != nil {
		_ = s.auditService.LogAction(ctx, tx, nil, "entitlement", "create", "entitlement",
			&ent.EntitlementID, "system", nil, nil, nil, map[string]interface{}{
				"feature_key": ent.FeatureKey,
				"plan_item":   ent.PlanItemID.String(),
			})
	}
	return nil
}

func (s *entitlementService) BulkCreate(ctx context.Context, entitlements []*models.Entitlement) error {
	logger := s.logger.With(zap.String("method", "BulkCreate"))
	if len(entitlements) == 0 {
		return nil
	}

	for _, ent := range entitlements {
		if err := s.validateEntitlement(ctx, ent); err != nil {
			return err
		}
	}

	tx, err := s.pgClient.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("begin tx: %w", err)
	}
	defer tx.Rollback()

	key := idempotencyKey("entitlement-bulk-create", fmt.Sprintf("%d-%s", len(entitlements), entitlements[0].EntitlementID.String()))
	var cached bool
	if err := s.idempotencyStore.Get(ctx, tx, key, &cached); err == nil && cached {
		logger.Info("idempotent – bulk create already processed")
		return nil
	}

	if err := s.repo.BulkCreate(ctx, tx, entitlements); err != nil {
		return err
	}

	payload := events.EntitlementBulkPayload{
		EntitlementIDs: make([]string, len(entitlements)),
		PlanItemID:     entitlements[0].PlanItemID.String(),
		Count:          len(entitlements),
	}
	for i, e := range entitlements {
		payload.EntitlementIDs[i] = e.EntitlementID.String()
	}
	if err := s.emitEvent(ctx, tx, entitlements[0].PlanItemID, events.EventEntitlementBulkCreated, payload); err != nil {
		logger.Warn("failed to emit event", zap.Error(err))
	}

	if err := s.idempotencyStore.Store(ctx, tx, key, true); err != nil {
		logger.Warn("failed to store idempotency record", zap.Error(err))
	}

	if err := tx.Commit(); err != nil {
		return fmt.Errorf("commit tx: %w", err)
	}

	if s.auditService != nil {
		_ = s.auditService.LogAction(ctx, tx, nil, "entitlement", "bulk_create", "entitlement",
			nil, "system", nil, nil, nil, map[string]interface{}{
				"count": len(entitlements),
			})
	}
	return nil
}

func (s *entitlementService) Update(ctx context.Context, ent *models.Entitlement) error {
	logger := s.logger.With(zap.String("method", "Update"))
	if ent.EntitlementID == uuid.Nil {
		return errors.ErrInvalidInput
	}
	if err := s.validateEntitlement(ctx, ent); err != nil {
		return err
	}

	tx, err := s.pgClient.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("begin tx: %w", err)
	}
	defer tx.Rollback()

	key := idempotencyKey("entitlement-update", ent.EntitlementID.String())
	var cached bool
	if err := s.idempotencyStore.Get(ctx, tx, key, &cached); err == nil && cached {
		logger.Info("idempotent – update already processed")
		return nil
	}

	old, err := s.repo.GetByIDForUpdate(ctx, tx, ent.EntitlementID)
	if err != nil {
		return err
	}
	if old == nil {
		return errors.ErrNotFound
	}

	if err := s.repo.Update(ctx, tx, ent); err != nil {
		return err
	}

	payload := buildEntitlementPayload(ent)
	if err := s.emitEvent(ctx, tx, ent.EntitlementID, events.EventEntitlementUpdated, payload); err != nil {
		logger.Warn("failed to emit event", zap.Error(err))
	}

	if err := s.idempotencyStore.Store(ctx, tx, key, true); err != nil {
		logger.Warn("failed to store idempotency record", zap.Error(err))
	}

	if err := tx.Commit(); err != nil {
		return fmt.Errorf("commit tx: %w", err)
	}

	if s.auditService != nil {
		oldData, _ := json.Marshal(old)
		newData, _ := json.Marshal(ent)
		_ = s.auditService.LogAction(ctx, tx, nil, "entitlement", "update", "entitlement",
			&ent.EntitlementID, "system", nil, oldData, newData, nil)
	}
	return nil
}

func (s *entitlementService) Delete(ctx context.Context, entitlementID uuid.UUID) error {
	logger := s.logger.With(zap.String("method", "Delete"))
	if entitlementID == uuid.Nil {
		return errors.ErrInvalidInput
	}

	tx, err := s.pgClient.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("begin tx: %w", err)
	}
	defer tx.Rollback()

	key := idempotencyKey("entitlement-delete", entitlementID.String())
	var cached bool
	if err := s.idempotencyStore.Get(ctx, tx, key, &cached); err == nil && cached {
		logger.Info("idempotent – delete already processed")
		return nil
	}

	ent, err := s.repo.GetByID(ctx, tx, entitlementID)
	if err != nil {
		return err
	}
	if ent == nil {
		return errors.ErrNotFound
	}

	if err := s.repo.Delete(ctx, tx, entitlementID); err != nil {
		return err
	}

	payload := events.EntitlementPayload{EntitlementID: entitlementID.String()}
	if err := s.emitEvent(ctx, tx, entitlementID, events.EventEntitlementDeleted, payload); err != nil {
		logger.Warn("failed to emit event", zap.Error(err))
	}

	if err := s.idempotencyStore.Store(ctx, tx, key, true); err != nil {
		logger.Warn("failed to store idempotency record", zap.Error(err))
	}

	if err := tx.Commit(); err != nil {
		return fmt.Errorf("commit tx: %w", err)
	}

	if s.auditService != nil {
		_ = s.auditService.LogAction(ctx, tx, nil, "entitlement", "delete", "entitlement",
			&entitlementID, "system", nil, nil, nil, nil)
	}
	return nil
}

func (s *entitlementService) GetByID(ctx context.Context, entitlementID uuid.UUID) (*models.Entitlement, error) {
	if entitlementID == uuid.Nil {
		return nil, errors.ErrInvalidInput
	}
	return s.repo.GetByID(ctx, nil, entitlementID)
}

// ----------------------------------------------------------------------------
// Plan Item Management
// ----------------------------------------------------------------------------

func (s *entitlementService) ReplaceByPlanItem(ctx context.Context, planItemID uuid.UUID, entitlements []*models.Entitlement) error {
	logger := s.logger.With(zap.String("method", "ReplaceByPlanItem"))
	if planItemID == uuid.Nil {
		return errors.ErrInvalidInput
	}
	for _, ent := range entitlements {
		if ent.PlanItemID != planItemID {
			return errors.ErrInvalidInput
		}
		if err := s.validateEntitlement(ctx, ent); err != nil {
			return err
		}
	}

	tx, err := s.pgClient.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("begin tx: %w", err)
	}
	defer tx.Rollback()

	key := idempotencyKey("entitlement-replace", planItemID.String())
	var cached bool
	if err := s.idempotencyStore.Get(ctx, tx, key, &cached); err == nil && cached {
		logger.Info("idempotent – replace already processed")
		return nil
	}

	if err := s.repo.ReplaceByPlanItem(ctx, tx, planItemID, entitlements); err != nil {
		return err
	}

	payload := events.EntitlementReplacePayload{
		PlanItemID:     planItemID.String(),
		EntitlementIDs: make([]string, len(entitlements)),
	}
	for i, e := range entitlements {
		payload.EntitlementIDs[i] = e.EntitlementID.String()
	}
	if err := s.emitEvent(ctx, tx, planItemID, events.EventEntitlementReplaced, payload); err != nil {
		logger.Warn("failed to emit event", zap.Error(err))
	}

	if err := s.idempotencyStore.Store(ctx, tx, key, true); err != nil {
		logger.Warn("failed to store idempotency record", zap.Error(err))
	}

	if err := tx.Commit(); err != nil {
		return fmt.Errorf("commit tx: %w", err)
	}

	if s.auditService != nil {
		_ = s.auditService.LogAction(ctx, tx, nil, "entitlement", "replace", "plan_item",
			&planItemID, "system", nil, nil, nil, map[string]interface{}{
				"count": len(entitlements),
			})
	}
	return nil
}

func (s *entitlementService) DeleteByPlanItem(ctx context.Context, planItemID uuid.UUID) error {
	logger := s.logger.With(zap.String("method", "DeleteByPlanItem"))
	if planItemID == uuid.Nil {
		return errors.ErrInvalidInput
	}

	tx, err := s.pgClient.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("begin tx: %w", err)
	}
	defer tx.Rollback()

	key := idempotencyKey("entitlement-delete-by-planitem", planItemID.String())
	var cached bool
	if err := s.idempotencyStore.Get(ctx, tx, key, &cached); err == nil && cached {
		logger.Info("idempotent – delete by plan item already processed")
		return nil
	}

	if err := s.repo.DeleteByPlanItem(ctx, tx, planItemID); err != nil {
		return err
	}

	payload := events.EntitlementDeleteByPlanItemPayload{PlanItemID: planItemID.String()}
	if err := s.emitEvent(ctx, tx, planItemID, events.EventEntitlementDeletedByPlanItem, payload); err != nil {
		logger.Warn("failed to emit event", zap.Error(err))
	}

	if err := s.idempotencyStore.Store(ctx, tx, key, true); err != nil {
		logger.Warn("failed to store idempotency record", zap.Error(err))
	}

	if err := tx.Commit(); err != nil {
		return fmt.Errorf("commit tx: %w", err)
	}

	if s.auditService != nil {
		_ = s.auditService.LogAction(ctx, tx, nil, "entitlement", "delete_by_plan_item", "plan_item",
			&planItemID, "system", nil, nil, nil, nil)
	}
	return nil
}

func (s *entitlementService) CopyToPlanItem(ctx context.Context, sourcePlanItemID uuid.UUID, targetPlanItemID uuid.UUID) error {
	logger := s.logger.With(zap.String("method", "CopyToPlanItem"))
	if sourcePlanItemID == uuid.Nil || targetPlanItemID == uuid.Nil {
		return errors.ErrInvalidInput
	}
	if sourcePlanItemID == targetPlanItemID {
		return errors.ErrInvalidInput
	}

	tx, err := s.pgClient.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("begin tx: %w", err)
	}
	defer tx.Rollback()

	key := idempotencyKey("entitlement-copy", fmt.Sprintf("%s-%s", sourcePlanItemID.String(), targetPlanItemID.String()))
	var cached bool
	if err := s.idempotencyStore.Get(ctx, tx, key, &cached); err == nil && cached {
		logger.Info("idempotent – copy already processed")
		return nil
	}

	ents, err := s.repo.GetByPlanItem(ctx, tx, sourcePlanItemID)
	if err != nil {
		return err
	}
	if len(ents) == 0 {
		if err := s.idempotencyStore.Store(ctx, tx, key, true); err != nil {
			logger.Warn("failed to store idempotency record", zap.Error(err))
		}
		return tx.Commit()
	}

	newEnts := make([]*models.Entitlement, len(ents))
	for i, e := range ents {
		newEnt := *e
		newEnt.EntitlementID = uuid.New()
		newEnt.PlanItemID = targetPlanItemID
		newEnt.CreatedAt = time.Now()
		newEnt.UpdatedAt = time.Now()
		newEnts[i] = &newEnt
	}

	if err := s.repo.BulkCreate(ctx, tx, newEnts); err != nil {
		return err
	}

	payload := events.EntitlementCopyPayload{
		SourcePlanItemID: sourcePlanItemID.String(),
		TargetPlanItemID: targetPlanItemID.String(),
		Count:            len(newEnts),
	}
	if err := s.emitEvent(ctx, tx, targetPlanItemID, events.EventEntitlementCopied, payload); err != nil {
		logger.Warn("failed to emit event", zap.Error(err))
	}

	if err := s.idempotencyStore.Store(ctx, tx, key, true); err != nil {
		logger.Warn("failed to store idempotency record", zap.Error(err))
	}

	if err := tx.Commit(); err != nil {
		return fmt.Errorf("commit tx: %w", err)
	}

	if s.auditService != nil {
		_ = s.auditService.LogAction(ctx, tx, nil, "entitlement", "copy", "plan_item",
			&targetPlanItemID, "system", nil, nil, nil, map[string]interface{}{
				"source": sourcePlanItemID.String(),
				"count":  len(newEnts),
			})
	}
	return nil
}

// ----------------------------------------------------------------------------
// Subscription Provisioning
// ----------------------------------------------------------------------------

func (s *entitlementService) grantEntitlementsForSubscription(ctx context.Context, tx repository.DBTX, subscriptionID uuid.UUID) error {
	sub, err := s.subRepo.GetByID(ctx, tx, uuid.Nil, subscriptionID)
	if err != nil {
		return err
	}
	if sub == nil {
		return errors.ErrSubscriptionNotFound
	}

	planItems, err := s.planItemRepo.GetActiveByPlan(ctx, tx, sub.PlanID)
	if err != nil {
		return err
	}

	for _, pi := range planItems {
		ents, err := s.repo.GetEnabledByPlanItem(ctx, tx, pi.PlanItemID)
		if err != nil {
			return err
		}
		if len(ents) == 0 {
			continue
		}

		subItems, err := s.subItemRepo.GetByPlanItem(ctx, tx, pi.PlanItemID)
		if err != nil {
			return err
		}
		var subItem *models.SubscriptionItem
		for _, si := range subItems {
			if si.SubscriptionID == subscriptionID && si.Status == enums.ItemStatusActive {
				subItem = si
				break
			}
		}
		if subItem == nil {
			s.logger.Warn("no active subscription item found for plan item",
				zap.String("plan_item_id", pi.PlanItemID.String()),
				zap.String("subscription_id", subscriptionID.String()))
			continue
		}

		// Here you would upsert UsageRemaining records.
		// For demonstration, we only log.
		for _, ent := range ents {
			s.logger.Info("granting entitlement to subscription",
				zap.String("subscription_id", subscriptionID.String()),
				zap.String("feature_key", ent.FeatureKey),
				zap.String("plan_item_id", pi.PlanItemID.String()))
		}
	}
	return nil
}

func (s *entitlementService) revokeEntitlementsForSubscription(ctx context.Context, tx repository.DBTX, subscriptionID uuid.UUID) error {
	s.logger.Info("revoking entitlements for subscription", zap.String("subscription_id", subscriptionID.String()))
	return nil
}

func (s *entitlementService) GrantToSubscription(ctx context.Context, subscriptionID uuid.UUID) error {
	logger := s.logger.With(zap.String("method", "GrantToSubscription"))
	if subscriptionID == uuid.Nil {
		return errors.ErrInvalidInput
	}

	tx, err := s.pgClient.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("begin tx: %w", err)
	}
	defer tx.Rollback()

	key := idempotencyKey("entitlement-grant", subscriptionID.String())
	var cached bool
	if err := s.idempotencyStore.Get(ctx, tx, key, &cached); err == nil && cached {
		logger.Info("idempotent – grant already processed")
		return nil
	}

	if err := s.grantEntitlementsForSubscription(ctx, tx, subscriptionID); err != nil {
		return err
	}

	payload := events.EntitlementGrantPayload{SubscriptionID: subscriptionID.String()}
	if err := s.emitEvent(ctx, tx, subscriptionID, events.EventEntitlementGranted, payload); err != nil {
		logger.Warn("failed to emit event", zap.Error(err))
	}

	if err := s.idempotencyStore.Store(ctx, tx, key, true); err != nil {
		logger.Warn("failed to store idempotency record", zap.Error(err))
	}

	if err := tx.Commit(); err != nil {
		return fmt.Errorf("commit tx: %w", err)
	}

	if s.auditService != nil {
		_ = s.auditService.LogAction(ctx, tx, nil, "entitlement", "grant", "subscription",
			&subscriptionID, "system", nil, nil, nil, nil)
	}
	return nil
}

func (s *entitlementService) RefreshSubscription(ctx context.Context, subscriptionID uuid.UUID) error {
	logger := s.logger.With(zap.String("method", "RefreshSubscription"))
	if subscriptionID == uuid.Nil {
		return errors.ErrInvalidInput
	}

	tx, err := s.pgClient.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("begin tx: %w", err)
	}
	defer tx.Rollback()

	key := idempotencyKey("entitlement-refresh", subscriptionID.String())
	var cached bool
	if err := s.idempotencyStore.Get(ctx, tx, key, &cached); err == nil && cached {
		logger.Info("idempotent – refresh already processed")
		return nil
	}

	if err := s.revokeEntitlementsForSubscription(ctx, tx, subscriptionID); err != nil {
		return err
	}
	if err := s.grantEntitlementsForSubscription(ctx, tx, subscriptionID); err != nil {
		return err
	}

	payload := events.EntitlementRefreshPayload{SubscriptionID: subscriptionID.String()}
	if err := s.emitEvent(ctx, tx, subscriptionID, events.EventEntitlementRefreshed, payload); err != nil {
		logger.Warn("failed to emit event", zap.Error(err))
	}

	if err := s.idempotencyStore.Store(ctx, tx, key, true); err != nil {
		logger.Warn("failed to store idempotency record", zap.Error(err))
	}

	if err := tx.Commit(); err != nil {
		return fmt.Errorf("commit tx: %w", err)
	}

	if s.auditService != nil {
		_ = s.auditService.LogAction(ctx, tx, nil, "entitlement", "refresh", "subscription",
			&subscriptionID, "system", nil, nil, nil, nil)
	}
	return nil
}

func (s *entitlementService) RevokeFromSubscription(ctx context.Context, subscriptionID uuid.UUID) error {
	logger := s.logger.With(zap.String("method", "RevokeFromSubscription"))
	if subscriptionID == uuid.Nil {
		return errors.ErrInvalidInput
	}

	tx, err := s.pgClient.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("begin tx: %w", err)
	}
	defer tx.Rollback()

	key := idempotencyKey("entitlement-revoke", subscriptionID.String())
	var cached bool
	if err := s.idempotencyStore.Get(ctx, tx, key, &cached); err == nil && cached {
		logger.Info("idempotent – revoke already processed")
		return nil
	}

	if err := s.revokeEntitlementsForSubscription(ctx, tx, subscriptionID); err != nil {
		return err
	}

	payload := events.EntitlementRevokePayload{SubscriptionID: subscriptionID.String()}
	if err := s.emitEvent(ctx, tx, subscriptionID, events.EventEntitlementRevoked, payload); err != nil {
		logger.Warn("failed to emit event", zap.Error(err))
	}

	if err := s.idempotencyStore.Store(ctx, tx, key, true); err != nil {
		logger.Warn("failed to store idempotency record", zap.Error(err))
	}

	if err := tx.Commit(); err != nil {
		return fmt.Errorf("commit tx: %w", err)
	}

	if s.auditService != nil {
		_ = s.auditService.LogAction(ctx, tx, nil, "entitlement", "revoke", "subscription",
			&subscriptionID, "system", nil, nil, nil, nil)
	}
	return nil
}

// ----------------------------------------------------------------------------
// Validation
// ----------------------------------------------------------------------------

func (s *entitlementService) Validate(ctx context.Context, entitlement *models.Entitlement) error {
	return s.validateEntitlement(ctx, entitlement)
}

func (s *entitlementService) Exists(ctx context.Context, entitlementID uuid.UUID) (bool, error) {
	if entitlementID == uuid.Nil {
		return false, errors.ErrInvalidInput
	}
	return s.repo.Exists(ctx, nil, entitlementID)
}

func (s *entitlementService) HasFeature(ctx context.Context, planItemID uuid.UUID, featureID uuid.UUID) (bool, error) {
	featureKey := featureID.String() // assuming featureID is actually the key; adjust if needed
	return s.repo.ExistsByFeature(ctx, nil, planItemID, featureKey)
}

// ----------------------------------------------------------------------------
// Query
// ----------------------------------------------------------------------------

func (s *entitlementService) List(ctx context.Context, filter repository.EntitlementFilter, p repository.Pagination, srt repository.Sort) ([]*models.Entitlement, int64, error) {
	return s.repo.List(ctx, nil, filter, p, srt)
}

func (s *entitlementService) Search(ctx context.Context, planItemID uuid.UUID, query string, limit, offset int) ([]*models.Entitlement, int64, error) {
	return s.repo.Search(ctx, nil, planItemID, query, limit, offset)
}

func (s *entitlementService) GetByPlanItem(ctx context.Context, planItemID uuid.UUID) ([]*models.Entitlement, error) {
	return s.repo.GetByPlanItem(ctx, nil, planItemID)
}

func (s *entitlementService) GetByFeature(ctx context.Context, featureID uuid.UUID) ([]*models.Entitlement, error) {
	return s.repo.GetByFeature(ctx, nil, featureID.String())
}

func (s *entitlementService) GetBySubscription(ctx context.Context, subscriptionID uuid.UUID) ([]*models.Entitlement, error) {
	tx, err := s.pgClient.BeginTx(ctx, nil)
	if err != nil {
		return nil, fmt.Errorf("begin tx: %w", err)
	}
	defer tx.Rollback()

	sub, err := s.subRepo.GetByID(ctx, tx, uuid.Nil, subscriptionID)
	if err != nil {
		return nil, err
	}
	if sub == nil {
		return nil, errors.ErrSubscriptionNotFound
	}

	planItems, err := s.planItemRepo.GetByPlan(ctx, tx, sub.PlanID)
	if err != nil {
		return nil, err
	}

	var allEnts []*models.Entitlement
	for _, pi := range planItems {
		ents, err := s.repo.GetByPlanItem(ctx, tx, pi.PlanItemID)
		if err != nil {
			return nil, err
		}
		allEnts = append(allEnts, ents...)
	}
	return allEnts, nil
}

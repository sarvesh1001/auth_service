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
	"auth-service/internal/subscription/models/enums"
	"auth-service/internal/subscription/repository"
)

// SubscriptionProvisioningService provisions and deprovisions resources
// associated with a subscription (items, entitlements, usage, trial, timeline).
type SubscriptionProvisioningService interface {
	// Provisioning
	Provision(ctx context.Context, subscription *models.Subscription) error
	Deprovision(ctx context.Context, subscription *models.Subscription) error
	Reprovision(ctx context.Context, subscription *models.Subscription) error

	// Subscription Items
	CreateSubscriptionItems(ctx context.Context, subscription *models.Subscription) error
	RefreshSubscriptionItems(ctx context.Context, subscription *models.Subscription) error
	RemoveSubscriptionItems(ctx context.Context, subscriptionID uuid.UUID) error

	// Entitlements
	GrantEntitlements(ctx context.Context, subscription *models.Subscription) error
	RevokeEntitlements(ctx context.Context, subscriptionID uuid.UUID) error
	RefreshEntitlements(ctx context.Context, subscription *models.Subscription) error

	// Usage
	CreateUsageLimits(ctx context.Context, subscription *models.Subscription) error
	ResetUsageLimits(ctx context.Context, subscriptionID uuid.UUID) error
	RemoveUsageLimits(ctx context.Context, subscriptionID uuid.UUID) error

	// Trial
	InitializeTrial(ctx context.Context, subscription *models.Subscription) error
	EndTrial(ctx context.Context, subscriptionID uuid.UUID) error

	// Timeline
	InitializeTimeline(ctx context.Context, subscription *models.Subscription) error
	AddTimelineEvent(ctx context.Context, event *models.SubscriptionTimeline) error

	// Health
	ValidateProvisioning(ctx context.Context, subscriptionID uuid.UUID) error
}

type provisioningService struct {
	subRepo          repository.SubscriptionRepository
	subItemRepo      repository.SubscriptionItemRepository
	planRepo         repository.PlanRepository
	planItemRepo     repository.PlanItemRepository
	entitlementRepo  repository.EntitlementRepository
	benefitRepo      repository.BenefitRepository
	usageRepo        repository.UsageRepository
	trialRepo        repository.TrialRepository
	timelineRepo     repository.TimelineRepository
	featureRepo      repository.FeatureRepository
	outboxRepo       outbox.Repository
	idempotencyStore idempotency.Store
	auditService     *audit.AuditService
	pgClient         *client.PostgresClient
	logger           *zap.Logger
}

func NewSubscriptionProvisioningService(
	subRepo repository.SubscriptionRepository,
	subItemRepo repository.SubscriptionItemRepository,
	planRepo repository.PlanRepository,
	planItemRepo repository.PlanItemRepository,
	entitlementRepo repository.EntitlementRepository,
	benefitRepo repository.BenefitRepository,
	usageRepo repository.UsageRepository,
	trialRepo repository.TrialRepository,
	timelineRepo repository.TimelineRepository,
	featureRepo repository.FeatureRepository,
	outboxRepo outbox.Repository,
	idempotencyStore idempotency.Store,
	auditService *audit.AuditService,
	pgClient *client.PostgresClient,
	logger *zap.Logger,
) SubscriptionProvisioningService {
	return &provisioningService{
		subRepo:          subRepo,
		subItemRepo:      subItemRepo,
		planRepo:         planRepo,
		planItemRepo:     planItemRepo,
		entitlementRepo:  entitlementRepo,
		benefitRepo:      benefitRepo,
		usageRepo:        usageRepo,
		trialRepo:        trialRepo,
		timelineRepo:     timelineRepo,
		featureRepo:      featureRepo,
		outboxRepo:       outboxRepo,
		idempotencyStore: idempotencyStore,
		auditService:     auditService,
		pgClient:         pgClient,
		logger:           logger.Named("subscription_provisioning_service"),
	}
}

// ----------------------------------------------------------------------------
// Helpers (reuse getIDempotencyKey from lifecycle service)
// ----------------------------------------------------------------------------

func (s *provisioningService) getSQLTx(tx repository.DBTX) (*sql.Tx, error) {
	sqlTx, ok := tx.(*sql.Tx)
	if !ok {
		return nil, fmt.Errorf("tx is not a *sql.Tx")
	}
	return sqlTx, nil
}

func (s *provisioningService) emitEvent(ctx context.Context, tx repository.DBTX, aggregateID uuid.UUID, eventType string, payload interface{}) error {
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

func (s *provisioningService) logAudit(ctx context.Context, companyID *uuid.UUID, action, entityType string, entityID *uuid.UUID, userID *uuid.UUID, oldState, newState interface{}, changes map[string]interface{}) {
	if s.auditService == nil {
		return
	}
	var oldBytes, newBytes []byte
	if oldState != nil {
		oldBytes, _ = json.Marshal(oldState)
	}
	if newState != nil {
		newBytes, _ = json.Marshal(newState)
	}
	_ = s.auditService.LogAction(ctx, nil, companyID, "subscription", action, entityType, entityID, "user", userID, oldBytes, newBytes, changes)
}

// ----------------------------------------------------------------------------
// Provisioning
// ----------------------------------------------------------------------------

func (s *provisioningService) Provision(ctx context.Context, subscription *models.Subscription) error {
	if subscription == nil {
		return errors.ErrInvalidInput
	}
	logger := s.logger.With(zap.String("subscription_id", subscription.SubscriptionID.String()))

	tx, err := s.pgClient.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("begin tx: %w", err)
	}
	defer tx.Rollback()

	idempKey := getIDempotencyKey(ctx, fmt.Sprintf("provision-%s", subscription.SubscriptionID.String()))
	var done bool
	if err := s.idempotencyStore.Get(ctx, tx, idempKey, &done); err == nil && done {
		logger.Info("idempotent – subscription already provisioned")
		return nil
	}

	// 1. Create subscription items
	if err := s.createSubscriptionItems(ctx, tx, subscription); err != nil {
		logger.Error("failed to create subscription items", zap.Error(err))
		return err
	}

	// 2. Grant entitlements
	if err := s.grantEntitlements(ctx, tx, subscription); err != nil {
		logger.Error("failed to grant entitlements", zap.Error(err))
		return err
	}

	// 3. Create usage limits
	if err := s.createUsageLimits(ctx, tx, subscription); err != nil {
		logger.Error("failed to create usage limits", zap.Error(err))
		return err
	}

	// 4. Initialize timeline
	if err := s.initializeTimeline(ctx, tx, subscription); err != nil {
		logger.Error("failed to initialize timeline", zap.Error(err))
		return err
	}

	// 5. If subscription has trial, initialize trial
	if subscription.TrialEnd != nil {
		if err := s.initializeTrial(ctx, tx, subscription); err != nil {
			logger.Error("failed to initialize trial", zap.Error(err))
			return err
		}
	}

	// Emit event
	payload := events.SubscriptionPayload{
		SubscriptionID: subscription.SubscriptionID.String(),
		CompanyID:      subscription.CompanyID.String(),
		CustomerID:     subscription.CustomerID.String(),
		PlanID:         subscription.PlanID.String(),
		Status:         string(subscription.Status),
		StartDate:      subscription.StartDate.Format(time.RFC3339),
		AutoRenew:      subscription.AutoRenew,
		Version:        subscription.Version,
	}
	if subscription.EndDate != nil {
		payload.EndDate = subscription.EndDate.Format(time.RFC3339)
	}
	if subscription.TrialEnd != nil {
		payload.TrialEnd = subscription.TrialEnd.Format(time.RFC3339)
	}
	if err := s.emitEvent(ctx, tx, subscription.SubscriptionID, events.EventSubscriptionProvisioned, payload); err != nil {
		logger.Warn("failed to emit provision event", zap.Error(err))
	}

	if err := s.idempotencyStore.Store(ctx, tx, idempKey, true); err != nil {
		logger.Warn("failed to store idempotency record", zap.Error(err))
	}

	if err := tx.Commit(); err != nil {
		return fmt.Errorf("commit tx: %w", err)
	}
	logger.Info("subscription provisioned successfully")

	s.logAudit(ctx, &subscription.CompanyID, "provision", "subscription", &subscription.SubscriptionID, nil, nil, subscription, map[string]interface{}{
		"plan_id": subscription.PlanID.String(),
	})
	return nil
}

func (s *provisioningService) Deprovision(ctx context.Context, subscription *models.Subscription) error {
	if subscription == nil {
		return errors.ErrInvalidInput
	}
	logger := s.logger.With(zap.String("subscription_id", subscription.SubscriptionID.String()))

	tx, err := s.pgClient.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("begin tx: %w", err)
	}
	defer tx.Rollback()

	idempKey := getIDempotencyKey(ctx, fmt.Sprintf("deprovision-%s", subscription.SubscriptionID.String()))
	var done bool
	if err := s.idempotencyStore.Get(ctx, tx, idempKey, &done); err == nil && done {
		logger.Info("idempotent – subscription already deprovisioned")
		return nil
	}

	// 1. Revoke entitlements (no direct record, but we remove items which effectively revokes)
	if err := s.revokeEntitlements(ctx, tx, subscription.SubscriptionID); err != nil {
		logger.Error("failed to revoke entitlements", zap.Error(err))
		return err
	}

	// 2. Remove usage limits
	if err := s.removeUsageLimits(ctx, tx, subscription.SubscriptionID); err != nil {
		logger.Error("failed to remove usage limits", zap.Error(err))
		return err
	}

	// 3. Remove subscription items
	if err := s.removeSubscriptionItems(ctx, tx, subscription.SubscriptionID); err != nil {
		logger.Error("failed to remove subscription items", zap.Error(err))
		return err
	}

	// 4. End trial if active
	if err := s.endTrial(ctx, tx, subscription.SubscriptionID); err != nil {
		logger.Error("failed to end trial", zap.Error(err))
		// Not critical; continue
	}

	// 5. Add timeline event for deprovisioning
	event := &models.SubscriptionTimeline{
		TimelineID:     uuid.New(),
		SubscriptionID: subscription.SubscriptionID,
		EventType:      enums.EventCancelled,
		PerformedBy:    nil,
		Metadata:       models.JSONB{"action": "deprovision"},
		CreatedAt:      time.Now(),
	}
	if err := s.timelineRepo.Create(ctx, tx, event); err != nil {
		logger.Warn("failed to add deprovision timeline event", zap.Error(err))
	}

	// Emit event
	payload := events.SubscriptionPayload{
		SubscriptionID: subscription.SubscriptionID.String(),
		CompanyID:      subscription.CompanyID.String(),
		Status:         string(subscription.Status),
	}
	if err := s.emitEvent(ctx, tx, subscription.SubscriptionID, events.EventSubscriptionDeprovisioned, payload); err != nil {
		logger.Warn("failed to emit deprovision event", zap.Error(err))
	}

	if err := s.idempotencyStore.Store(ctx, tx, idempKey, true); err != nil {
		logger.Warn("failed to store idempotency record", zap.Error(err))
	}
	if err := tx.Commit(); err != nil {
		return fmt.Errorf("commit tx: %w", err)
	}
	logger.Info("subscription deprovisioned successfully")

	s.logAudit(ctx, &subscription.CompanyID, "deprovision", "subscription", &subscription.SubscriptionID, nil, subscription, nil, nil)
	return nil
}

func (s *provisioningService) Reprovision(ctx context.Context, subscription *models.Subscription) error {
	if subscription == nil {
		return errors.ErrInvalidInput
	}
	logger := s.logger.With(zap.String("subscription_id", subscription.SubscriptionID.String()))

	tx, err := s.pgClient.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("begin tx: %w", err)
	}
	defer tx.Rollback()

	idempKey := getIDempotencyKey(ctx, fmt.Sprintf("reprovision-%s", subscription.SubscriptionID.String()))
	var done bool
	if err := s.idempotencyStore.Get(ctx, tx, idempKey, &done); err == nil && done {
		logger.Info("idempotent – subscription already reprovisioned")
		return nil
	}

	// 1. Refresh subscription items (remove old, create new)
	if err := s.refreshSubscriptionItems(ctx, tx, subscription); err != nil {
		logger.Error("failed to refresh subscription items", zap.Error(err))
		return err
	}

	// 2. Refresh entitlements (since items are new, entitlements are derived)
	if err := s.refreshEntitlements(ctx, tx, subscription); err != nil {
		logger.Error("failed to refresh entitlements", zap.Error(err))
		return err
	}

	// 3. Reset usage limits (delete old usage and recreate if needed)
	if err := s.resetUsageLimits(ctx, tx, subscription.SubscriptionID); err != nil {
		logger.Error("failed to reset usage limits", zap.Error(err))
		return err
	}
	if err := s.createUsageLimits(ctx, tx, subscription); err != nil {
		logger.Error("failed to recreate usage limits", zap.Error(err))
		return err
	}

	// 4. Add timeline event for reprovision
	event := &models.SubscriptionTimeline{
		TimelineID:     uuid.New(),
		SubscriptionID: subscription.SubscriptionID,
		EventType:      enums.EventChanged,
		PerformedBy:    nil,
		Metadata:       models.JSONB{"action": "reprovision"},
		CreatedAt:      time.Now(),
	}
	if err := s.timelineRepo.Create(ctx, tx, event); err != nil {
		logger.Warn("failed to add reprovision timeline event", zap.Error(err))
	}

	// Emit event
	payload := events.SubscriptionPayload{
		SubscriptionID: subscription.SubscriptionID.String(),
		CompanyID:      subscription.CompanyID.String(),
		PlanID:         subscription.PlanID.String(),
		Status:         string(subscription.Status),
	}
	if err := s.emitEvent(ctx, tx, subscription.SubscriptionID, events.EventSubscriptionReprovisioned, payload); err != nil {
		logger.Warn("failed to emit reprovision event", zap.Error(err))
	}

	if err := s.idempotencyStore.Store(ctx, tx, idempKey, true); err != nil {
		logger.Warn("failed to store idempotency record", zap.Error(err))
	}
	if err := tx.Commit(); err != nil {
		return fmt.Errorf("commit tx: %w", err)
	}
	logger.Info("subscription reprovisioned successfully")

	s.logAudit(ctx, &subscription.CompanyID, "reprovision", "subscription", &subscription.SubscriptionID, nil, nil, subscription, map[string]interface{}{
		"plan_id": subscription.PlanID.String(),
	})
	return nil
}

// ----------------------------------------------------------------------------
// Subscription Items
// ----------------------------------------------------------------------------

func (s *provisioningService) CreateSubscriptionItems(ctx context.Context, subscription *models.Subscription) error {
	tx, err := s.pgClient.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	idempKey := getIDempotencyKey(ctx, fmt.Sprintf("create-items-%s", subscription.SubscriptionID.String()))
	var done bool
	if err := s.idempotencyStore.Get(ctx, tx, idempKey, &done); err == nil && done {
		s.logger.Info("idempotent – items already created")
		return nil
	}
	err = s.createSubscriptionItems(ctx, tx, subscription)
	if err != nil {
		return err
	}
	if err := s.idempotencyStore.Store(ctx, tx, idempKey, true); err != nil {
		s.logger.Warn("failed to store idempotency record", zap.Error(err))
	}
	// Emit event for items creation
	payload := map[string]interface{}{
		"subscription_id": subscription.SubscriptionID.String(),
		"plan_id":         subscription.PlanID.String(),
	}
	if err := s.emitEvent(ctx, tx, subscription.SubscriptionID, events.EventSubscriptionItemsCreated, payload); err != nil {
		s.logger.Warn("failed to emit items created event", zap.Error(err))
	}
	return tx.Commit()
}

func (s *provisioningService) createSubscriptionItems(ctx context.Context, tx repository.DBTX, subscription *models.Subscription) error {
	planItems, err := s.planItemRepo.GetActiveByPlan(ctx, tx, subscription.PlanID)
	if err != nil {
		return err
	}
	if len(planItems) == 0 {
		return fmt.Errorf("%w: no active items found for plan %s", errors.ErrInvalidInput, subscription.PlanID)
	}
	subItems := make([]*models.SubscriptionItem, 0, len(planItems))
	for _, pi := range planItems {
		subItem := &models.SubscriptionItem{
			SubItemID:      uuid.New(),
			SubscriptionID: subscription.SubscriptionID,
			PlanItemID:     pi.PlanItemID,
			AddonID:        nil,
			Quantity:       decimal.NewFromInt(1),
			UnitPrice:      pi.Price,
			Currency:       pi.Currency,
			Status:         enums.ItemStatusActive,
			StartDate:      subscription.StartDate,
			EndDate:        subscription.EndDate,
			Metadata:       nil,
			ProductID:      nil,
		}
		subItems = append(subItems, subItem)
	}
	if len(subItems) == 0 {
		return nil
	}
	return s.subItemRepo.BulkCreate(ctx, tx, subItems)
}

func (s *provisioningService) RefreshSubscriptionItems(ctx context.Context, subscription *models.Subscription) error {
	tx, err := s.pgClient.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	idempKey := getIDempotencyKey(ctx, fmt.Sprintf("refresh-items-%s", subscription.SubscriptionID.String()))
	var done bool
	if err := s.idempotencyStore.Get(ctx, tx, idempKey, &done); err == nil && done {
		s.logger.Info("idempotent – items already refreshed")
		return nil
	}
	err = s.refreshSubscriptionItems(ctx, tx, subscription)
	if err != nil {
		return err
	}
	if err := s.idempotencyStore.Store(ctx, tx, idempKey, true); err != nil {
		s.logger.Warn("failed to store idempotency record", zap.Error(err))
	}
	// Emit event
	payload := map[string]interface{}{
		"subscription_id": subscription.SubscriptionID.String(),
		"plan_id":         subscription.PlanID.String(),
	}
	if err := s.emitEvent(ctx, tx, subscription.SubscriptionID, events.EventSubscriptionItemsRefreshed, payload); err != nil {
		s.logger.Warn("failed to emit items refreshed event", zap.Error(err))
	}
	return tx.Commit()
}

func (s *provisioningService) refreshSubscriptionItems(ctx context.Context, tx repository.DBTX, subscription *models.Subscription) error {
	if err := s.subItemRepo.DeleteBySubscription(ctx, tx, subscription.SubscriptionID); err != nil {
		return err
	}
	return s.createSubscriptionItems(ctx, tx, subscription)
}

func (s *provisioningService) RemoveSubscriptionItems(ctx context.Context, subscriptionID uuid.UUID) error {
	tx, err := s.pgClient.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	idempKey := getIDempotencyKey(ctx, fmt.Sprintf("remove-items-%s", subscriptionID.String()))
	var done bool
	if err := s.idempotencyStore.Get(ctx, tx, idempKey, &done); err == nil && done {
		s.logger.Info("idempotent – items already removed")
		return nil
	}
	err = s.removeSubscriptionItems(ctx, tx, subscriptionID)
	if err != nil {
		return err
	}
	if err := s.idempotencyStore.Store(ctx, tx, idempKey, true); err != nil {
		s.logger.Warn("failed to store idempotency record", zap.Error(err))
	}
	// Emit event
	payload := map[string]interface{}{
		"subscription_id": subscriptionID.String(),
	}
	if err := s.emitEvent(ctx, tx, subscriptionID, events.EventSubscriptionItemsRemoved, payload); err != nil {
		s.logger.Warn("failed to emit items removed event", zap.Error(err))
	}
	return tx.Commit()
}

func (s *provisioningService) removeSubscriptionItems(ctx context.Context, tx repository.DBTX, subscriptionID uuid.UUID) error {
	return s.subItemRepo.DeleteBySubscription(ctx, tx, subscriptionID)
}

// ----------------------------------------------------------------------------
// Entitlements (similar pattern)
// ----------------------------------------------------------------------------

func (s *provisioningService) GrantEntitlements(ctx context.Context, subscription *models.Subscription) error {
	tx, err := s.pgClient.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	idempKey := getIDempotencyKey(ctx, fmt.Sprintf("grant-entitlements-%s", subscription.SubscriptionID.String()))
	var done bool
	if err := s.idempotencyStore.Get(ctx, tx, idempKey, &done); err == nil && done {
		s.logger.Info("idempotent – entitlements already granted")
		return nil
	}
	err = s.grantEntitlements(ctx, tx, subscription)
	if err != nil {
		return err
	}
	if err := s.idempotencyStore.Store(ctx, tx, idempKey, true); err != nil {
		s.logger.Warn("failed to store idempotency record", zap.Error(err))
	}
	return tx.Commit()
}

func (s *provisioningService) grantEntitlements(ctx context.Context, tx repository.DBTX, subscription *models.Subscription) error {
	planItems, err := s.planItemRepo.GetActiveByPlan(ctx, tx, subscription.PlanID)
	if err != nil {
		return err
	}
	for _, pi := range planItems {
		ents, err := s.entitlementRepo.GetByPlanItem(ctx, tx, pi.PlanItemID)
		if err != nil {
			return err
		}
		if len(ents) == 0 {
			s.logger.Warn("plan item has no entitlements", zap.String("plan_item_id", pi.PlanItemID.String()))
		}
	}
	return nil
}

func (s *provisioningService) RevokeEntitlements(ctx context.Context, subscriptionID uuid.UUID) error {
	tx, err := s.pgClient.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	idempKey := getIDempotencyKey(ctx, fmt.Sprintf("revoke-entitlements-%s", subscriptionID.String()))
	var done bool
	if err := s.idempotencyStore.Get(ctx, tx, idempKey, &done); err == nil && done {
		s.logger.Info("idempotent – entitlements already revoked")
		return nil
	}
	err = s.revokeEntitlements(ctx, tx, subscriptionID)
	if err != nil {
		return err
	}
	if err := s.idempotencyStore.Store(ctx, tx, idempKey, true); err != nil {
		s.logger.Warn("failed to store idempotency record", zap.Error(err))
	}
	return tx.Commit()
}

func (s *provisioningService) revokeEntitlements(ctx context.Context, tx repository.DBTX, subscriptionID uuid.UUID) error {
	// No direct action; removal of items revokes them.
	return nil
}

func (s *provisioningService) RefreshEntitlements(ctx context.Context, subscription *models.Subscription) error {
	tx, err := s.pgClient.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	idempKey := getIDempotencyKey(ctx, fmt.Sprintf("refresh-entitlements-%s", subscription.SubscriptionID.String()))
	var done bool
	if err := s.idempotencyStore.Get(ctx, tx, idempKey, &done); err == nil && done {
		s.logger.Info("idempotent – entitlements already refreshed")
		return nil
	}
	err = s.refreshEntitlements(ctx, tx, subscription)
	if err != nil {
		return err
	}
	if err := s.idempotencyStore.Store(ctx, tx, idempKey, true); err != nil {
		s.logger.Warn("failed to store idempotency record", zap.Error(err))
	}
	return tx.Commit()
}

func (s *provisioningService) refreshEntitlements(ctx context.Context, tx repository.DBTX, subscription *models.Subscription) error {
	return s.refreshSubscriptionItems(ctx, tx, subscription)
}

// ----------------------------------------------------------------------------
// Usage (similar pattern)
// ----------------------------------------------------------------------------

func (s *provisioningService) CreateUsageLimits(ctx context.Context, subscription *models.Subscription) error {
	tx, err := s.pgClient.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	idempKey := getIDempotencyKey(ctx, fmt.Sprintf("create-usage-%s", subscription.SubscriptionID.String()))
	var done bool
	if err := s.idempotencyStore.Get(ctx, tx, idempKey, &done); err == nil && done {
		s.logger.Info("idempotent – usage limits already created")
		return nil
	}
	err = s.createUsageLimits(ctx, tx, subscription)
	if err != nil {
		return err
	}
	if err := s.idempotencyStore.Store(ctx, tx, idempKey, true); err != nil {
		s.logger.Warn("failed to store idempotency record", zap.Error(err))
	}
	return tx.Commit()
}

func (s *provisioningService) createUsageLimits(ctx context.Context, tx repository.DBTX, subscription *models.Subscription) error {
	// No action; usage limits are derived from entitlements.
	return nil
}

func (s *provisioningService) ResetUsageLimits(ctx context.Context, subscriptionID uuid.UUID) error {
	tx, err := s.pgClient.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	idempKey := getIDempotencyKey(ctx, fmt.Sprintf("reset-usage-%s", subscriptionID.String()))
	var done bool
	if err := s.idempotencyStore.Get(ctx, tx, idempKey, &done); err == nil && done {
		s.logger.Info("idempotent – usage limits already reset")
		return nil
	}
	err = s.resetUsageLimits(ctx, tx, subscriptionID)
	if err != nil {
		return err
	}
	if err := s.idempotencyStore.Store(ctx, tx, idempKey, true); err != nil {
		s.logger.Warn("failed to store idempotency record", zap.Error(err))
	}
	return tx.Commit()
}

func (s *provisioningService) resetUsageLimits(ctx context.Context, tx repository.DBTX, subscriptionID uuid.UUID) error {
	items, err := s.subItemRepo.GetBySubscription(ctx, tx, subscriptionID)
	if err != nil {
		return err
	}
	for _, item := range items {
		filter := repository.UsageFilter{
			SubscriptionItemID: &item.SubItemID,
		}
		usages, _, err := s.usageRepo.List(ctx, tx, filter, repository.Pagination{Limit: 1000, Offset: 0}, repository.Sort{})
		if err != nil {
			return err
		}
		for _, usage := range usages {
			if err := s.usageRepo.Delete(ctx, tx, usage.UsageID); err != nil {
				return err
			}
		}
	}
	return nil
}

func (s *provisioningService) RemoveUsageLimits(ctx context.Context, subscriptionID uuid.UUID) error {
	tx, err := s.pgClient.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	idempKey := getIDempotencyKey(ctx, fmt.Sprintf("remove-usage-%s", subscriptionID.String()))
	var done bool
	if err := s.idempotencyStore.Get(ctx, tx, idempKey, &done); err == nil && done {
		s.logger.Info("idempotent – usage limits already removed")
		return nil
	}
	err = s.removeUsageLimits(ctx, tx, subscriptionID)
	if err != nil {
		return err
	}
	if err := s.idempotencyStore.Store(ctx, tx, idempKey, true); err != nil {
		s.logger.Warn("failed to store idempotency record", zap.Error(err))
	}
	return tx.Commit()
}

func (s *provisioningService) removeUsageLimits(ctx context.Context, tx repository.DBTX, subscriptionID uuid.UUID) error {
	return s.resetUsageLimits(ctx, tx, subscriptionID)
}

// ----------------------------------------------------------------------------
// Trial
// ----------------------------------------------------------------------------

func (s *provisioningService) InitializeTrial(ctx context.Context, subscription *models.Subscription) error {
	tx, err := s.pgClient.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	idempKey := getIDempotencyKey(ctx, fmt.Sprintf("init-trial-%s", subscription.SubscriptionID.String()))
	var done bool
	if err := s.idempotencyStore.Get(ctx, tx, idempKey, &done); err == nil && done {
		s.logger.Info("idempotent – trial already initialized")
		return nil
	}
	err = s.initializeTrial(ctx, tx, subscription)
	if err != nil {
		return err
	}
	if err := s.idempotencyStore.Store(ctx, tx, idempKey, true); err != nil {
		s.logger.Warn("failed to store idempotency record", zap.Error(err))
	}
	// Emit event
	payload := map[string]interface{}{
		"subscription_id": subscription.SubscriptionID.String(),
		"trial_days":      int(subscription.TrialEnd.Sub(subscription.StartDate).Hours() / 24),
	}
	if err := s.emitEvent(ctx, tx, subscription.SubscriptionID, events.EventTrialStarted, payload); err != nil {
		s.logger.Warn("failed to emit trial started event", zap.Error(err))
	}
	return tx.Commit()
}

func (s *provisioningService) initializeTrial(ctx context.Context, tx repository.DBTX, subscription *models.Subscription) error {
	if subscription.TrialEnd == nil {
		return nil
	}
	exists, err := s.trialRepo.ExistsBySubscription(ctx, tx, subscription.SubscriptionID)
	if err != nil {
		return err
	}
	if exists {
		return errors.ErrTrialAlreadyActive
	}
	trialDays := int(subscription.TrialEnd.Sub(subscription.StartDate).Hours() / 24)
	if trialDays <= 0 {
		trialDays = 14
	}
	trial := &models.Trial{
		TrialID:         uuid.New(),
		SubscriptionID:  subscription.SubscriptionID,
		StartedAt:       subscription.StartDate,
		EndedAt:         subscription.TrialEnd,
		TrialDays:       trialDays,
		FeaturesEnabled: models.JSONB{},
		UsageConsumed:   models.JSONB{},
		Status:          enums.TrialActive,
		CreatedAt:       time.Now(),
		UpdatedAt:       time.Now(),
	}
	return s.trialRepo.Create(ctx, tx, trial)
}

func (s *provisioningService) EndTrial(ctx context.Context, subscriptionID uuid.UUID) error {
	tx, err := s.pgClient.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	idempKey := getIDempotencyKey(ctx, fmt.Sprintf("end-trial-%s", subscriptionID.String()))
	var done bool
	if err := s.idempotencyStore.Get(ctx, tx, idempKey, &done); err == nil && done {
		s.logger.Info("idempotent – trial already ended")
		return nil
	}
	err = s.endTrial(ctx, tx, subscriptionID)
	if err != nil {
		return err
	}
	if err := s.idempotencyStore.Store(ctx, tx, idempKey, true); err != nil {
		s.logger.Warn("failed to store idempotency record", zap.Error(err))
	}
	// Emit event
	payload := map[string]interface{}{
		"subscription_id": subscriptionID.String(),
	}
	if err := s.emitEvent(ctx, tx, subscriptionID, events.EventTrialEnded, payload); err != nil {
		s.logger.Warn("failed to emit trial ended event", zap.Error(err))
	}
	return tx.Commit()
}

func (s *provisioningService) endTrial(ctx context.Context, tx repository.DBTX, subscriptionID uuid.UUID) error {
	trial, err := s.trialRepo.GetBySubscription(ctx, tx, subscriptionID)
	if err != nil {
		if err == errors.ErrNotFound {
			return nil
		}
		return err
	}
	if trial.Status == enums.TrialActive {
		now := time.Now()
		trial.Status = enums.TrialExpired
		trial.EndedAt = &now
		return s.trialRepo.Update(ctx, tx, trial)
	}
	return nil
}

// ----------------------------------------------------------------------------
// Timeline
// ----------------------------------------------------------------------------

func (s *provisioningService) InitializeTimeline(ctx context.Context, subscription *models.Subscription) error {
	tx, err := s.pgClient.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	idempKey := getIDempotencyKey(ctx, fmt.Sprintf("init-timeline-%s", subscription.SubscriptionID.String()))
	var done bool
	if err := s.idempotencyStore.Get(ctx, tx, idempKey, &done); err == nil && done {
		s.logger.Info("idempotent – timeline already initialized")
		return nil
	}
	err = s.initializeTimeline(ctx, tx, subscription)
	if err != nil {
		return err
	}
	if err := s.idempotencyStore.Store(ctx, tx, idempKey, true); err != nil {
		s.logger.Warn("failed to store idempotency record", zap.Error(err))
	}
	return tx.Commit()
}

func (s *provisioningService) initializeTimeline(ctx context.Context, tx repository.DBTX, subscription *models.Subscription) error {
	event := &models.SubscriptionTimeline{
		TimelineID:     uuid.New(),
		SubscriptionID: subscription.SubscriptionID,
		EventType:      enums.EventCreated,
		OldStatus:      nil,
		NewStatus:      &subscription.Status,
		PerformedBy:    nil,
		Metadata:       models.JSONB{"action": "provision"},
		CreatedAt:      time.Now(),
	}
	return s.timelineRepo.Create(ctx, tx, event)
}

func (s *provisioningService) AddTimelineEvent(ctx context.Context, event *models.SubscriptionTimeline) error {
	tx, err := s.pgClient.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	idempKey := getIDempotencyKey(ctx, fmt.Sprintf("add-timeline-%s", event.TimelineID.String()))
	var done bool
	if err := s.idempotencyStore.Get(ctx, tx, idempKey, &done); err == nil && done {
		s.logger.Info("idempotent – timeline event already added")
		return nil
	}
	if err := s.timelineRepo.Create(ctx, tx, event); err != nil {
		return err
	}
	if err := s.idempotencyStore.Store(ctx, tx, idempKey, true); err != nil {
		s.logger.Warn("failed to store idempotency record", zap.Error(err))
	}
	return tx.Commit()
}

// ----------------------------------------------------------------------------
// Health (no state change)
// ----------------------------------------------------------------------------

func (s *provisioningService) ValidateProvisioning(ctx context.Context, subscriptionID uuid.UUID) error {
	db := s.pgClient.DB
	items, err := s.subItemRepo.GetBySubscription(ctx, db, subscriptionID)
	if err != nil {
		return err
	}
	if len(items) == 0 {
		return fmt.Errorf("%w: no subscription items found", errors.ErrInvalidState)
	}
	for _, item := range items {
		_, err := s.planItemRepo.GetByID(ctx, db, item.PlanItemID)
		if err != nil {
			return fmt.Errorf("plan item %s not found: %w", item.PlanItemID, err)
		}
	}
	for _, item := range items {
		ents, err := s.entitlementRepo.GetByPlanItem(ctx, db, item.PlanItemID)
		if err != nil {
			return err
		}
		if len(ents) == 0 {
			return fmt.Errorf("no entitlements found for plan item %s", item.PlanItemID)
		}
	}
	trial, err := s.trialRepo.GetBySubscription(ctx, db, subscriptionID)
	if err != nil && err != errors.ErrNotFound {
		return err
	}
	_ = trial // could check consistency
	return nil
}

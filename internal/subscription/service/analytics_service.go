// file: internal/subscription/service/analytics_service.go
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
	"auth-service/internal/infrastructure/idempotency"
	"auth-service/internal/subscription/events"
	"auth-service/internal/subscription/models"
	"auth-service/internal/subscription/models/enums"
	"auth-service/internal/subscription/repository"
)

// SubscriptionAnalyticsService processes subscription, addon, benefit, billing policy,
// renewal policy, pause policy, entitlement, and plan domain events, updating analytical tables.
type SubscriptionAnalyticsService interface {
	// ProcessSubscriptionEvent handles subscription events (created, activated, paused, etc.)
	ProcessSubscriptionEvent(ctx context.Context, eventType string, payload []byte) error

	// ProcessAddonEvent handles addon catalog events (created, updated, activated, etc.)
	ProcessAddonEvent(ctx context.Context, eventType string, payload []byte) error

	// ProcessBenefitEvent handles benefit events (created, updated, deleted, etc.)
	ProcessBenefitEvent(ctx context.Context, eventType string, payload []byte) error

	// ProcessBillingPolicyEvent handles billing policy events (created, activated, deactivated, etc.)
	ProcessBillingPolicyEvent(ctx context.Context, eventType string, payload []byte) error

	// ProcessRenewalPolicyEvent handles renewal policy events (created, activated, deactivated, etc.)
	ProcessRenewalPolicyEvent(ctx context.Context, eventType string, payload []byte) error

	// ProcessPausePolicyEvent handles pause policy events (created, activated, deactivated, etc.)
	ProcessPausePolicyEvent(ctx context.Context, eventType string, payload []byte) error

	// ProcessEntitlementEvent handles entitlement events (granted, revoked, refreshed)
	ProcessEntitlementEvent(ctx context.Context, eventType string, payload []byte) error

	// ProcessPlanEvent handles plan catalog events (created, updated, etc.)
	ProcessPlanEvent(ctx context.Context, eventType string, payload []byte) error
}

type subscriptionAnalyticsService struct {
	analyticsRepo     repository.AnalyticsRepository
	subRepo           repository.SubscriptionRepository
	subItemRepo       repository.SubscriptionItemRepository
	planRepo          repository.PlanRepository
	planItemRepo      repository.PlanItemRepository
	benefitRepo       repository.BenefitRepository
	billingPolicyRepo repository.BillingPolicyRepository
	renewalPolicyRepo repository.RenewalPolicyRepository
	pausePolicyRepo   repository.PausePolicyRepository
	entitlementRepo   repository.EntitlementRepository
	featureRepo       repository.FeatureRepository
	idempotencyStore  idempotency.Store
	pgClient          *client.PostgresClient
	logger            *zap.Logger
}

func NewSubscriptionAnalyticsService(
	analyticsRepo repository.AnalyticsRepository,
	subRepo repository.SubscriptionRepository,
	subItemRepo repository.SubscriptionItemRepository,
	planRepo repository.PlanRepository,
	planItemRepo repository.PlanItemRepository,
	benefitRepo repository.BenefitRepository,
	billingPolicyRepo repository.BillingPolicyRepository,
	renewalPolicyRepo repository.RenewalPolicyRepository,
	pausePolicyRepo repository.PausePolicyRepository,
	entitlementRepo repository.EntitlementRepository,
	featureRepo repository.FeatureRepository,
	idempotencyStore idempotency.Store,
	pgClient *client.PostgresClient,
	logger *zap.Logger,
) SubscriptionAnalyticsService {
	return &subscriptionAnalyticsService{
		analyticsRepo:     analyticsRepo,
		subRepo:           subRepo,
		subItemRepo:       subItemRepo,
		planRepo:          planRepo,
		planItemRepo:      planItemRepo,
		benefitRepo:       benefitRepo,
		billingPolicyRepo: billingPolicyRepo,
		renewalPolicyRepo: renewalPolicyRepo,
		pausePolicyRepo:   pausePolicyRepo,
		entitlementRepo:   entitlementRepo,
		featureRepo:       featureRepo,
		idempotencyStore:  idempotencyStore,
		pgClient:          pgClient,
		logger:            logger.Named("subscription_analytics_service"),
	}
}

// ----------------------------------------------------------------------------
// PLAN CATALOG EVENT PROCESSING
// ----------------------------------------------------------------------------

func (s *subscriptionAnalyticsService) ProcessPlanEvent(ctx context.Context, eventType string, payload []byte) error {
	s.logger.Debug("processing plan catalog event", zap.String("event_type", eventType))

	switch eventType {
	case events.EventPlanCreated:
		var p events.PlanPayload
		if err := json.Unmarshal(payload, &p); err != nil {
			return fmt.Errorf("unmarshal plan created payload: %w", err)
		}
		s.logger.Info("plan created – catalog synced", zap.String("plan_id", p.PlanID), zap.String("name", p.Name))
		// Optionally insert a catalog record or update cache; no analytical fact needed yet.

	case events.EventPlanUpdated:
		var p events.PlanPayload
		if err := json.Unmarshal(payload, &p); err != nil {
			return fmt.Errorf("unmarshal plan updated payload: %w", err)
		}
		s.logger.Info("plan updated", zap.String("plan_id", p.PlanID), zap.Int("version", p.Version))

	case events.EventPlanDeleted:
		var p events.PlanPayload
		if err := json.Unmarshal(payload, &p); err != nil {
			return fmt.Errorf("unmarshal plan deleted payload: %w", err)
		}
		s.logger.Info("plan deleted", zap.String("plan_id", p.PlanID))

	case events.EventPlanActivated:
		var p events.PlanPayload
		if err := json.Unmarshal(payload, &p); err != nil {
			return fmt.Errorf("unmarshal plan activated payload: %w", err)
		}
		s.logger.Info("plan activated", zap.String("plan_id", p.PlanID))

	case events.EventPlanDeactivated:
		var p events.PlanPayload
		if err := json.Unmarshal(payload, &p); err != nil {
			return fmt.Errorf("unmarshal plan deactivated payload: %w", err)
		}
		s.logger.Info("plan deactivated", zap.String("plan_id", p.PlanID))

	case events.EventPlanArchived:
		var p events.PlanPayload
		if err := json.Unmarshal(payload, &p); err != nil {
			return fmt.Errorf("unmarshal plan archived payload: %w", err)
		}
		s.logger.Info("plan archived", zap.String("plan_id", p.PlanID))

	case events.EventPlanRestored:
		var p events.PlanPayload
		if err := json.Unmarshal(payload, &p); err != nil {
			return fmt.Errorf("unmarshal plan restored payload: %w", err)
		}
		s.logger.Info("plan restored", zap.String("plan_id", p.PlanID))

	case events.EventPlanPriceUpdated:
		var p events.PlanPayload
		if err := json.Unmarshal(payload, &p); err != nil {
			return fmt.Errorf("unmarshal plan price updated payload: %w", err)
		}
		s.logger.Info("plan price updated", zap.String("plan_id", p.PlanID))

	default:
		s.logger.Debug("ignored unknown plan event", zap.String("event_type", eventType))
	}
	return nil
}

// ----------------------------------------------------------------------------
// Subscription event processing
// ----------------------------------------------------------------------------

func (s *subscriptionAnalyticsService) ProcessSubscriptionEvent(ctx context.Context, eventType string, payload []byte) error {
	switch eventType {
	case events.EventSubscriptionCreated:
		var p events.SubscriptionPayload
		if err := json.Unmarshal(payload, &p); err != nil {
			return fmt.Errorf("unmarshal subscription created payload: %w", err)
		}
		return s.onSubscriptionCreated(ctx, p)

	case events.EventSubscriptionActivated:
		var p events.SubscriptionPayload
		if err := json.Unmarshal(payload, &p); err != nil {
			return fmt.Errorf("unmarshal subscription activated payload: %w", err)
		}
		return s.onSubscriptionActivated(ctx, p)

	case events.EventSubscriptionPaused:
		var p events.SubscriptionPayload
		if err := json.Unmarshal(payload, &p); err != nil {
			return fmt.Errorf("unmarshal subscription paused payload: %w", err)
		}
		return s.onSubscriptionPaused(ctx, p)

	case events.EventSubscriptionResumed:
		var p events.SubscriptionPayload
		if err := json.Unmarshal(payload, &p); err != nil {
			return fmt.Errorf("unmarshal subscription resumed payload: %w", err)
		}
		return s.onSubscriptionResumed(ctx, p)

	case events.EventSubscriptionRenewed:
		var p events.SubscriptionPayload
		if err := json.Unmarshal(payload, &p); err != nil {
			return fmt.Errorf("unmarshal subscription renewed payload: %w", err)
		}
		return s.onSubscriptionRenewed(ctx, p)

	case events.EventSubscriptionExpired:
		var p events.SubscriptionPayload
		if err := json.Unmarshal(payload, &p); err != nil {
			return fmt.Errorf("unmarshal subscription expired payload: %w", err)
		}
		return s.onSubscriptionExpired(ctx, p)

	case events.EventSubscriptionCancelled:
		var p events.SubscriptionPayload
		if err := json.Unmarshal(payload, &p); err != nil {
			return fmt.Errorf("unmarshal subscription cancelled payload: %w", err)
		}
		return s.onSubscriptionCancelled(ctx, p)

	case events.EventSubscriptionUpgraded, events.EventSubscriptionDowngraded, events.EventSubscriptionChanged:
		var p events.SubscriptionPayload
		if err := json.Unmarshal(payload, &p); err != nil {
			return fmt.Errorf("unmarshal subscription changed payload: %w", err)
		}
		return s.onSubscriptionPlanChanged(ctx, p, eventType)

	case events.EventTrialStarted:
		var p events.TrialPayload
		if err := json.Unmarshal(payload, &p); err != nil {
			return fmt.Errorf("unmarshal trial started payload: %w", err)
		}
		return s.onTrialStarted(ctx, p)

	case events.EventTrialEnded:
		var p events.TrialPayload
		if err := json.Unmarshal(payload, &p); err != nil {
			return fmt.Errorf("unmarshal trial ended payload: %w", err)
		}
		return s.onTrialEnded(ctx, p)

	case events.EventTrialConverted:
		var p events.TrialPayload
		if err := json.Unmarshal(payload, &p); err != nil {
			return fmt.Errorf("unmarshal trial converted payload: %w", err)
		}
		return s.onTrialConverted(ctx, p)

	case events.EventTrialCancelled:
		var p events.TrialPayload
		if err := json.Unmarshal(payload, &p); err != nil {
			return fmt.Errorf("unmarshal trial cancelled payload: %w", err)
		}
		return s.onTrialCancelled(ctx, p)

	default:
		s.logger.Debug("ignored subscription event", zap.String("event_type", eventType))
		return nil
	}
}

// ----------------------------------------------------------------------------
// Addon event processing (catalog events)
// ----------------------------------------------------------------------------

func (s *subscriptionAnalyticsService) ProcessAddonEvent(ctx context.Context, eventType string, payload []byte) error {
	s.logger.Debug("processing addon catalog event", zap.String("event_type", eventType))

	switch eventType {
	case events.EventAddonCreated:
		var p events.AddonPayload
		if err := json.Unmarshal(payload, &p); err != nil {
			return fmt.Errorf("unmarshal addon created payload: %w", err)
		}
		s.logger.Info("addon created", zap.String("addon_id", p.AddonID), zap.String("name", p.Name))
		return nil

	case events.EventAddonUpdated:
		var p events.AddonPayload
		if err := json.Unmarshal(payload, &p); err != nil {
			return fmt.Errorf("unmarshal addon updated payload: %w", err)
		}
		s.logger.Info("addon updated", zap.String("addon_id", p.AddonID))
		return nil

	case events.EventAddonDeleted:
		var p events.AddonPayload
		if err := json.Unmarshal(payload, &p); err != nil {
			return fmt.Errorf("unmarshal addon deleted payload: %w", err)
		}
		s.logger.Info("addon deleted", zap.String("addon_id", p.AddonID))
		return nil

	case events.EventAddonActivated:
		var p events.AddonPayload
		if err := json.Unmarshal(payload, &p); err != nil {
			return fmt.Errorf("unmarshal addon activated payload: %w", err)
		}
		s.logger.Info("addon activated", zap.String("addon_id", p.AddonID))
		return nil

	case events.EventAddonDeactivated:
		var p events.AddonPayload
		if err := json.Unmarshal(payload, &p); err != nil {
			return fmt.Errorf("unmarshal addon deactivated payload: %w", err)
		}
		s.logger.Info("addon deactivated", zap.String("addon_id", p.AddonID))
		return nil

	case events.EventAddonRestored:
		var p events.AddonPayload
		if err := json.Unmarshal(payload, &p); err != nil {
			return fmt.Errorf("unmarshal addon restored payload: %w", err)
		}
		s.logger.Info("addon restored", zap.String("addon_id", p.AddonID))
		return nil

	case events.EventAddonPriceUpdated:
		var p events.AddonPayload
		if err := json.Unmarshal(payload, &p); err != nil {
			return fmt.Errorf("unmarshal addon price updated payload: %w", err)
		}
		s.logger.Info("addon price updated", zap.String("addon_id", p.AddonID), zap.String("price", p.Price))
		return nil

	case events.EventAddonBillingPolicyUpdated:
		var p events.AddonPayload
		if err := json.Unmarshal(payload, &p); err != nil {
			return fmt.Errorf("unmarshal addon billing policy updated payload: %w", err)
		}
		s.logger.Info("addon billing policy updated", zap.String("addon_id", p.AddonID))
		return nil

	default:
		s.logger.Debug("ignored unknown addon event", zap.String("event_type", eventType))
		return nil
	}
}

// ----------------------------------------------------------------------------
// Benefit event processing
// ----------------------------------------------------------------------------

func (s *subscriptionAnalyticsService) ProcessBenefitEvent(ctx context.Context, eventType string, payload []byte) error {
	switch eventType {
	case events.EventBenefitCreated:
		var p events.BenefitPayload
		if err := json.Unmarshal(payload, &p); err != nil {
			return fmt.Errorf("unmarshal benefit created payload: %w", err)
		}
		return s.onBenefitCreated(ctx, p)

	case events.EventBenefitUpdated:
		var p events.BenefitPayload
		if err := json.Unmarshal(payload, &p); err != nil {
			return fmt.Errorf("unmarshal benefit updated payload: %w", err)
		}
		s.logger.Info("benefit updated – no analytics changes", zap.String("benefit_id", p.BenefitID))
		return nil

	case events.EventBenefitDeleted:
		var p events.BenefitPayload
		if err := json.Unmarshal(payload, &p); err != nil {
			return fmt.Errorf("unmarshal benefit deleted payload: %w", err)
		}
		return s.onBenefitDeleted(ctx, p)

	case events.EventBenefitBulkCreated:
		var p events.BenefitPayload
		if err := json.Unmarshal(payload, &p); err != nil {
			return fmt.Errorf("unmarshal benefit bulk created payload: %w", err)
		}
		return s.onBenefitCreated(ctx, p)

	case events.EventBenefitCopied:
		var p events.BenefitPayload
		if err := json.Unmarshal(payload, &p); err != nil {
			return fmt.Errorf("unmarshal benefit copied payload: %w", err)
		}
		return s.onBenefitCreated(ctx, p)

	default:
		s.logger.Debug("ignored unknown benefit event", zap.String("event_type", eventType))
		return nil
	}
}

// ----------------------------------------------------------------------------
// Benefit event handlers
// ----------------------------------------------------------------------------

// onBenefitCreated processes a benefit creation event.
func (s *subscriptionAnalyticsService) onBenefitCreated(ctx context.Context, p events.BenefitPayload) error {
	benefitID, err := uuid.Parse(p.BenefitID)
	if err != nil {
		return fmt.Errorf("invalid benefit_id: %w", err)
	}

	db := s.pgClient.DB

	query := `
		SELECT DISTINCT s.subscription_id, s.company_id
		FROM subscription.subscriptions s
		INNER JOIN subscription.subscription_items si ON s.subscription_id = si.subscription_id
		INNER JOIN subscription.plan_items pi ON si.plan_item_id = pi.plan_item_id
		INNER JOIN subscription.benefits b ON pi.plan_item_id = b.plan_item_id
		WHERE b.benefit_id = $1
		  AND s.status = $2
		  AND s.deleted_at IS NULL
		  AND si.status = $3
	`
	rows, err := db.QueryContext(ctx, query, benefitID, enums.SubStatusActive, enums.ItemStatusActive)
	if err != nil {
		return fmt.Errorf("query active subscriptions for benefit: %w", err)
	}
	defer rows.Close()

	var subIDs []uuid.UUID
	var companyIDs []uuid.UUID
	for rows.Next() {
		var subID, compID uuid.UUID
		if err := rows.Scan(&subID, &compID); err != nil {
			return fmt.Errorf("scan subscription: %w", err)
		}
		subIDs = append(subIDs, subID)
		companyIDs = append(companyIDs, compID)
	}
	if err := rows.Err(); err != nil {
		return fmt.Errorf("rows error: %w", err)
	}

	if len(subIDs) == 0 {
		s.logger.Info("benefit created but no active subscriptions use it", zap.String("benefit_id", p.BenefitID))
		return nil
	}

	tx, err := s.pgClient.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("begin tx: %w", err)
	}
	defer tx.Rollback()

	idempKey := getIDempotencyKey(ctx, fmt.Sprintf("benefit-analytics-created-%s", p.BenefitID))
	var done bool
	if err := s.idempotencyStore.Get(ctx, tx, idempKey, &done); err == nil && done {
		s.logger.Info("idempotent – benefit creation already processed", zap.String("benefit_id", p.BenefitID))
		return nil
	}

	usageDate := time.Now().Truncate(24 * time.Hour)

	for i, subID := range subIDs {
		compID := companyIDs[i]

		fact := &models.BenefitUsageFact{
			CompanyID:      compID,
			BenefitID:      benefitID,
			SubscriptionID: subID,
			BenefitType:    p.BenefitType,
			Quantity:       decimal.NewFromInt(1),
			UsageDate:      usageDate,
		}
		if err := s.analyticsRepo.InsertBenefitUsageFact(ctx, tx, fact); err != nil {
			return fmt.Errorf("insert benefit usage fact: %w", err)
		}

		delta := &models.DailyBenefitMetricsDelta{
			ActiveCount: 1,
			NewCount:    1,
		}
		if err := s.analyticsRepo.IncrementDailyBenefitMetrics(ctx, tx, compID, benefitID, usageDate, delta); err != nil {
			return fmt.Errorf("increment daily benefit metrics: %w", err)
		}
	}

	if err := s.idempotencyStore.Store(ctx, tx, idempKey, true); err != nil {
		s.logger.Warn("failed to store idempotency record", zap.Error(err))
	}
	return tx.Commit()
}

// onBenefitDeleted handles a benefit deletion event.
func (s *subscriptionAnalyticsService) onBenefitDeleted(ctx context.Context, p events.BenefitPayload) error {
	benefitID, err := uuid.Parse(p.BenefitID)
	if err != nil {
		return fmt.Errorf("invalid benefit_id: %w", err)
	}
	companyID, err := uuid.Parse(p.CompanyID)
	if err != nil {
		return fmt.Errorf("invalid company_id: %w", err)
	}

	db := s.pgClient.DB
	query := `
		SELECT COUNT(DISTINCT s.subscription_id)
		FROM subscription.subscriptions s
		INNER JOIN subscription.subscription_items si ON s.subscription_id = si.subscription_id
		INNER JOIN subscription.plan_items pi ON si.plan_item_id = pi.plan_item_id
		INNER JOIN subscription.benefits b ON pi.plan_item_id = b.plan_item_id
		WHERE b.benefit_id = $1
		  AND s.status = $2
		  AND s.deleted_at IS NULL
		  AND si.status = $3
	`
	var activeCount int64
	err = db.QueryRowContext(ctx, query, benefitID, enums.SubStatusActive, enums.ItemStatusActive).Scan(&activeCount)
	if err != nil {
		return fmt.Errorf("count active subscriptions for benefit: %w", err)
	}

	if activeCount == 0 {
		s.logger.Info("benefit deleted – no active subscriptions using it", zap.String("benefit_id", p.BenefitID))
		return nil
	}

	tx, err := s.pgClient.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("begin tx: %w", err)
	}
	defer tx.Rollback()

	idempKey := getIDempotencyKey(ctx, fmt.Sprintf("benefit-analytics-deleted-%s", p.BenefitID))
	var done bool
	if err := s.idempotencyStore.Get(ctx, tx, idempKey, &done); err == nil && done {
		s.logger.Info("idempotent – benefit deletion already processed", zap.String("benefit_id", p.BenefitID))
		return nil
	}

	date := time.Now().Truncate(24 * time.Hour)
	delta := &models.DailyBenefitMetricsDelta{
		ActiveCount: -int(activeCount),
		NewCount:    0,
	}
	if err := s.analyticsRepo.IncrementDailyBenefitMetrics(ctx, tx, companyID, benefitID, date, delta); err != nil {
		return fmt.Errorf("decrement daily benefit metrics: %w", err)
	}

	if err := s.idempotencyStore.Store(ctx, tx, idempKey, true); err != nil {
		s.logger.Warn("failed to store idempotency record", zap.Error(err))
	}
	return tx.Commit()
}

// ----------------------------------------------------------------------------
// Helper: update benefit metrics for subscription
// ----------------------------------------------------------------------------

func (s *subscriptionAnalyticsService) updateBenefitMetricsForSubscription(
	ctx context.Context,
	tx *sql.Tx,
	companyID, subscriptionID uuid.UUID,
	eventDate time.Time,
	deltaActive int,
	deltaNew int,
) error {
	items, err := s.subItemRepo.GetActiveBySubscription(ctx, tx, subscriptionID)
	if err != nil {
		return fmt.Errorf("get subscription items: %w", err)
	}

	for _, item := range items {
		planItem, err := s.planItemRepo.GetByID(ctx, tx, item.PlanItemID)
		if err != nil {
			return fmt.Errorf("get plan item %s: %w", item.PlanItemID, err)
		}
		benefits, err := s.benefitRepo.GetByPlanItem(ctx, tx, planItem.PlanItemID)
		if err != nil {
			return fmt.Errorf("get benefits for plan item %s: %w", planItem.PlanItemID, err)
		}
		for _, benefit := range benefits {
			fact := &models.BenefitUsageFact{
				CompanyID:      companyID,
				BenefitID:      benefit.BenefitID,
				SubscriptionID: subscriptionID,
				BenefitType:    string(benefit.BenefitType),
				Quantity:       decimal.NewFromInt(1),
				UsageDate:      eventDate,
			}
			if err := s.analyticsRepo.InsertBenefitUsageFact(ctx, tx, fact); err != nil {
				return fmt.Errorf("insert benefit fact for benefit %s: %w", benefit.BenefitID, err)
			}

			delta := &models.DailyBenefitMetricsDelta{
				ActiveCount: deltaActive,
				NewCount:    deltaNew,
			}
			if err := s.analyticsRepo.IncrementDailyBenefitMetrics(ctx, tx, companyID, benefit.BenefitID, eventDate, delta); err != nil {
				return fmt.Errorf("increment daily benefit metrics for benefit %s: %w", benefit.BenefitID, err)
			}
		}
	}
	return nil
}

// ----------------------------------------------------------------------------
// Subscription event handlers
// ----------------------------------------------------------------------------

func (s *subscriptionAnalyticsService) onSubscriptionCreated(ctx context.Context, p events.SubscriptionPayload) error {
	subID, err := uuid.Parse(p.SubscriptionID)
	if err != nil {
		return fmt.Errorf("invalid subscription_id: %w", err)
	}
	companyID, err := uuid.Parse(p.CompanyID)
	if err != nil {
		return fmt.Errorf("invalid company_id: %w", err)
	}
	planID, err := uuid.Parse(p.PlanID)
	if err != nil {
		return fmt.Errorf("invalid plan_id: %w", err)
	}
	customerID, err := uuid.Parse(p.CustomerID)
	if err != nil {
		return fmt.Errorf("invalid customer_id: %w", err)
	}
	eventDate, err := time.Parse(time.RFC3339, p.StartDate)
	if err != nil {
		eventDate = time.Now()
	}

	tx, err := s.pgClient.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("begin tx: %w", err)
	}
	defer tx.Rollback()

	idempKey := getIDempotencyKey(ctx, fmt.Sprintf("sub-analytics-created-%s", p.SubscriptionID))
	var done bool
	if err := s.idempotencyStore.Get(ctx, tx, idempKey, &done); err == nil && done {
		s.logger.Info("idempotent – subscription created already processed")
		return nil
	}

	fact := &models.SubscriptionFact{
		CompanyID:      companyID,
		SubscriptionID: subID,
		EventDate:      eventDate,
		EventType:      "created",
		PlanID:         &planID,
		CustomerID:     &customerID,
		OldStatusID:    nil,
		NewStatusID:    nil,
		MRRChange:      nil,
		Metadata:       nil,
	}
	if err := s.analyticsRepo.InsertSubscriptionFact(ctx, tx, fact); err != nil {
		return fmt.Errorf("insert subscription fact: %w", err)
	}

	if err := s.idempotencyStore.Store(ctx, tx, idempKey, true); err != nil {
		s.logger.Warn("failed to store idempotency record", zap.Error(err))
	}
	return tx.Commit()
}

func (s *subscriptionAnalyticsService) onSubscriptionActivated(ctx context.Context, p events.SubscriptionPayload) error {
	subID, err := uuid.Parse(p.SubscriptionID)
	if err != nil {
		return fmt.Errorf("invalid subscription_id: %w", err)
	}
	companyID, err := uuid.Parse(p.CompanyID)
	if err != nil {
		return fmt.Errorf("invalid company_id: %w", err)
	}
	planID, err := uuid.Parse(p.PlanID)
	if err != nil {
		return fmt.Errorf("invalid plan_id: %w", err)
	}
	customerID, err := uuid.Parse(p.CustomerID)
	if err != nil {
		return fmt.Errorf("invalid customer_id: %w", err)
	}
	eventDate, err := time.Parse(time.RFC3339, p.StartDate)
	if err != nil {
		eventDate = time.Now()
	}

	tx, err := s.pgClient.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("begin tx: %w", err)
	}
	defer tx.Rollback()

	idempKey := getIDempotencyKey(ctx, fmt.Sprintf("sub-analytics-activated-%s", p.SubscriptionID))
	var done bool
	if err := s.idempotencyStore.Get(ctx, tx, idempKey, &done); err == nil && done {
		s.logger.Info("idempotent – subscription activated already processed")
		return nil
	}

	mrr, err := s.computeSubscriptionMRR(ctx, tx, subID, companyID)
	if err != nil {
		s.logger.Warn("failed to compute MRR, using 0", zap.Error(err))
		mrr = decimal.Zero
	}

	date := eventDate.Truncate(24 * time.Hour)
	delta := &repository.DailySubscriptionMetricsDelta{
		NewSubscriptions:    1,
		ActiveSubscriptions: 1,
		MRR:                 mrr,
		ARR:                 mrr.Mul(decimal.NewFromInt(12)),
	}
	if err := s.analyticsRepo.IncrementDailySubscriptionMetrics(ctx, tx, companyID, date, delta); err != nil {
		return fmt.Errorf("increment daily subscription metrics: %w", err)
	}

	planDelta := &repository.DailyPlanMetricsDelta{
		ActiveCount: 1,
		NewCount:    1,
		MRR:         mrr,
		ARR:         mrr.Mul(decimal.NewFromInt(12)),
	}
	if err := s.analyticsRepo.IncrementDailyPlanMetrics(ctx, tx, companyID, planID, date, planDelta); err != nil {
		return fmt.Errorf("increment daily plan metrics: %w", err)
	}

	fact := &models.SubscriptionFact{
		CompanyID:      companyID,
		SubscriptionID: subID,
		EventDate:      eventDate,
		EventType:      "activated",
		PlanID:         &planID,
		CustomerID:     &customerID,
		OldStatusID:    nil,
		NewStatusID:    ptrInt16(1),
		MRRChange:      &mrr,
		Metadata:       nil,
	}
	if err := s.analyticsRepo.InsertSubscriptionFact(ctx, tx, fact); err != nil {
		return fmt.Errorf("insert subscription fact: %w", err)
	}

	// Update addon metrics for this subscription
	if err := s.updateAddonMetricsForSubscription(ctx, tx, companyID, subID, eventDate, 1, 1); err != nil {
		s.logger.Warn("failed to update addon metrics on activation", zap.Error(err))
	}

	// Update benefit metrics for this subscription
	if err := s.updateBenefitMetricsForSubscription(ctx, tx, companyID, subID, eventDate, 1, 1); err != nil {
		s.logger.Warn("failed to update benefit metrics on activation", zap.Error(err))
	}

	if err := s.idempotencyStore.Store(ctx, tx, idempKey, true); err != nil {
		s.logger.Warn("failed to store idempotency record", zap.Error(err))
	}
	return tx.Commit()
}

// ----------------------------------------------------------------------------
// Status change and other subscription handlers
// ----------------------------------------------------------------------------

func (s *subscriptionAnalyticsService) onSubscriptionPaused(ctx context.Context, p events.SubscriptionPayload) error {
	return s.handleStatusChange(ctx, p, "paused", -1, 1, 0, 0)
}

func (s *subscriptionAnalyticsService) onSubscriptionResumed(ctx context.Context, p events.SubscriptionPayload) error {
	return s.handleStatusChange(ctx, p, "resumed", 1, -1, 0, 0)
}

func (s *subscriptionAnalyticsService) onSubscriptionExpired(ctx context.Context, p events.SubscriptionPayload) error {
	return s.handleStatusChange(ctx, p, "expired", -1, 0, 1, 0)
}

func (s *subscriptionAnalyticsService) onSubscriptionCancelled(ctx context.Context, p events.SubscriptionPayload) error {
	return s.handleStatusChange(ctx, p, "cancelled", -1, 0, 0, 1)
}

func (s *subscriptionAnalyticsService) onSubscriptionRenewed(ctx context.Context, p events.SubscriptionPayload) error {
	subID, err := uuid.Parse(p.SubscriptionID)
	if err != nil {
		return fmt.Errorf("invalid subscription_id: %w", err)
	}
	companyID, err := uuid.Parse(p.CompanyID)
	if err != nil {
		return fmt.Errorf("invalid company_id: %w", err)
	}
	planID, err := uuid.Parse(p.PlanID)
	if err != nil {
		return fmt.Errorf("invalid plan_id: %w", err)
	}
	customerID, err := uuid.Parse(p.CustomerID)
	if err != nil {
		return fmt.Errorf("invalid customer_id: %w", err)
	}
	eventDate := time.Now()
	if p.EndDate != "" {
		if d, err := time.Parse(time.RFC3339, p.EndDate); err == nil {
			eventDate = d
		}
	}

	tx, err := s.pgClient.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("begin tx: %w", err)
	}
	defer tx.Rollback()

	idempKey := getIDempotencyKey(ctx, fmt.Sprintf("sub-analytics-renewed-%s", p.SubscriptionID))
	var done bool
	if err := s.idempotencyStore.Get(ctx, tx, idempKey, &done); err == nil && done {
		s.logger.Info("idempotent – subscription renewed already processed")
		return nil
	}

	fact := &models.SubscriptionFact{
		CompanyID:      companyID,
		SubscriptionID: subID,
		EventDate:      eventDate,
		EventType:      "renewed",
		PlanID:         &planID,
		CustomerID:     &customerID,
		OldStatusID:    nil,
		NewStatusID:    nil,
		MRRChange:      nil,
		Metadata:       nil,
	}
	if err := s.analyticsRepo.InsertSubscriptionFact(ctx, tx, fact); err != nil {
		return fmt.Errorf("insert subscription fact: %w", err)
	}

	if err := s.idempotencyStore.Store(ctx, tx, idempKey, true); err != nil {
		s.logger.Warn("failed to store idempotency record", zap.Error(err))
	}
	return tx.Commit()
}

// onSubscriptionPlanChanged handles plan change events and updates plan_change_fact + daily_plan_change_metrics.
func (s *subscriptionAnalyticsService) onSubscriptionPlanChanged(ctx context.Context, p events.SubscriptionPayload, changeType string) error {
	subID, err := uuid.Parse(p.SubscriptionID)
	if err != nil {
		return fmt.Errorf("invalid subscription_id: %w", err)
	}
	companyID, err := uuid.Parse(p.CompanyID)
	if err != nil {
		return fmt.Errorf("invalid company_id: %w", err)
	}
	newPlanID, err := uuid.Parse(p.PlanID)
	if err != nil {
		return fmt.Errorf("invalid plan_id: %w", err)
	}
	customerID, err := uuid.Parse(p.CustomerID)
	if err != nil {
		return fmt.Errorf("invalid customer_id: %w", err)
	}
	eventDate := time.Now()

	tx, err := s.pgClient.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("begin tx: %w", err)
	}
	defer tx.Rollback()

	idempKey := getIDempotencyKey(ctx, fmt.Sprintf("sub-analytics-planchange-%s", p.SubscriptionID))
	var done bool
	if err := s.idempotencyStore.Get(ctx, tx, idempKey, &done); err == nil && done {
		s.logger.Info("idempotent – plan change already processed")
		return nil
	}

	sub, err := s.subRepo.GetByID(ctx, tx, companyID, subID)
	if err != nil {
		return fmt.Errorf("get subscription for plan change: %w", err)
	}
	oldPlanID := sub.PlanID

	oldMRR, err := s.computePlanMRR(ctx, tx, oldPlanID, companyID)
	if err != nil {
		s.logger.Warn("failed to compute old plan MRR, using 0", zap.Error(err))
		oldMRR = decimal.Zero
	}
	newMRR, err := s.computePlanMRR(ctx, tx, newPlanID, companyID)
	if err != nil {
		s.logger.Warn("failed to compute new plan MRR, using 0", zap.Error(err))
		newMRR = decimal.Zero
	}
	mrrDelta := newMRR.Sub(oldMRR)

	// Determine change type for plan_change_fact
	planChangeType := s.determineChangeType(oldMRR, newMRR, oldPlanID, newPlanID)

	date := eventDate.Truncate(24 * time.Hour)

	// 1. Update daily subscription metrics
	delta := &repository.DailySubscriptionMetricsDelta{
		MRR: mrrDelta,
		ARR: mrrDelta.Mul(decimal.NewFromInt(12)),
	}
	if err := s.analyticsRepo.IncrementDailySubscriptionMetrics(ctx, tx, companyID, date, delta); err != nil {
		return fmt.Errorf("increment daily subscription metrics: %w", err)
	}

	// 2. Update daily plan metrics (active counts)
	oldPlanDelta := &repository.DailyPlanMetricsDelta{
		ActiveCount: -1,
		MRR:         oldMRR.Neg(),
		ARR:         oldMRR.Mul(decimal.NewFromInt(-12)),
	}
	if err := s.analyticsRepo.IncrementDailyPlanMetrics(ctx, tx, companyID, oldPlanID, date, oldPlanDelta); err != nil {
		return fmt.Errorf("increment daily plan metrics for old plan: %w", err)
	}
	newPlanDelta := &repository.DailyPlanMetricsDelta{
		ActiveCount: 1,
		MRR:         newMRR,
		ARR:         newMRR.Mul(decimal.NewFromInt(12)),
	}
	if err := s.analyticsRepo.IncrementDailyPlanMetrics(ctx, tx, companyID, newPlanID, date, newPlanDelta); err != nil {
		return fmt.Errorf("increment daily plan metrics for new plan: %w", err)
	}

	// 3. Insert plan_change_fact
	planChangeFact := &models.PlanChangeFact{
		CompanyID:      companyID,
		SubscriptionID: subID,
		OldPlanID:      oldPlanID,
		NewPlanID:      newPlanID,
		ChangeType:     planChangeType,
		ChangeDate:     date,
		OldPlanVersion: nil, // could fetch from plan versions if needed
		NewPlanVersion: nil,
		MRRDelta:       &mrrDelta,
		PerformedBy:    nil,
		Reason:         nil,
	}
	if err := s.analyticsRepo.InsertPlanChangeFact(ctx, tx, planChangeFact); err != nil {
		return fmt.Errorf("insert plan change fact: %w", err)
	}

	// 4. Increment daily plan change metrics for old plan (outgoing)
	oldPlanChangeDelta := &models.PlanChangeDelta{
		UpgradeOutCount:   0,
		DowngradeOutCount: 0,
		LateralOutCount:   0,
	}
	switch planChangeType {
	case "upgrade":
		oldPlanChangeDelta.UpgradeOutCount = 1
	case "downgrade":
		oldPlanChangeDelta.DowngradeOutCount = 1
	case "lateral":
		oldPlanChangeDelta.LateralOutCount = 1
	}
	oldPlanChangeDelta.NetChange = -1
	if err := s.analyticsRepo.IncrementDailyPlanChangeMetrics(ctx, tx, companyID, oldPlanID, date, oldPlanChangeDelta); err != nil {
		return fmt.Errorf("increment daily plan change metrics for old plan: %w", err)
	}

	// 5. Increment daily plan change metrics for new plan (incoming)
	newPlanChangeDelta := &models.PlanChangeDelta{
		UpgradeInCount:   0,
		DowngradeInCount: 0,
		LateralInCount:   0,
	}
	switch planChangeType {
	case "upgrade":
		newPlanChangeDelta.UpgradeInCount = 1
	case "downgrade":
		newPlanChangeDelta.DowngradeInCount = 1
	case "lateral":
		newPlanChangeDelta.LateralInCount = 1
	}
	newPlanChangeDelta.NetChange = 1
	if err := s.analyticsRepo.IncrementDailyPlanChangeMetrics(ctx, tx, companyID, newPlanID, date, newPlanChangeDelta); err != nil {
		return fmt.Errorf("increment daily plan change metrics for new plan: %w", err)
	}

	// 6. Insert subscription fact (existing)
	fact := &models.SubscriptionFact{
		CompanyID:      companyID,
		SubscriptionID: subID,
		EventDate:      eventDate,
		EventType:      changeType,
		PlanID:         &newPlanID,
		CustomerID:     &customerID,
		OldStatusID:    nil,
		NewStatusID:    nil,
		MRRChange:      &mrrDelta,
		Metadata:       map[string]interface{}{"old_plan_id": oldPlanID.String()},
	}
	if err := s.analyticsRepo.InsertSubscriptionFact(ctx, tx, fact); err != nil {
		return fmt.Errorf("insert subscription fact: %w", err)
	}

	if err := s.idempotencyStore.Store(ctx, tx, idempKey, true); err != nil {
		s.logger.Warn("failed to store idempotency record", zap.Error(err))
	}
	return tx.Commit()
}

// ----------------------------------------------------------------------------
// Trial handlers
// ----------------------------------------------------------------------------

func (s *subscriptionAnalyticsService) onTrialStarted(ctx context.Context, p events.TrialPayload) error {
	subID, err := uuid.Parse(p.SubscriptionID)
	if err != nil {
		return fmt.Errorf("invalid subscription_id: %w", err)
	}
	companyID, err := uuid.Parse(p.CompanyID)
	if err != nil {
		return fmt.Errorf("invalid company_id: %w", err)
	}
	startedAt, err := time.Parse(time.RFC3339, p.StartedAt)
	if err != nil {
		startedAt = time.Now()
	}

	tx, err := s.pgClient.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("begin tx: %w", err)
	}
	defer tx.Rollback()

	idempKey := getIDempotencyKey(ctx, fmt.Sprintf("sub-analytics-trialstart-%s", p.TrialID))
	var done bool
	if err := s.idempotencyStore.Get(ctx, tx, idempKey, &done); err == nil && done {
		s.logger.Info("idempotent – trial started already processed")
		return nil
	}

	date := startedAt.Truncate(24 * time.Hour)
	delta := &repository.DailySubscriptionMetricsDelta{
		TrialStarts: 1,
	}
	if err := s.analyticsRepo.IncrementDailySubscriptionMetrics(ctx, tx, companyID, date, delta); err != nil {
		return fmt.Errorf("increment daily subscription metrics: %w", err)
	}

	fact := &models.SubscriptionFact{
		CompanyID:      companyID,
		SubscriptionID: subID,
		EventDate:      startedAt,
		EventType:      "trial_started",
		PlanID:         nil,
		CustomerID:     nil,
		OldStatusID:    nil,
		NewStatusID:    nil,
		MRRChange:      nil,
		Metadata:       map[string]interface{}{"trial_days": p.TrialDays},
	}
	if err := s.analyticsRepo.InsertSubscriptionFact(ctx, tx, fact); err != nil {
		return fmt.Errorf("insert subscription fact: %w", err)
	}

	if err := s.idempotencyStore.Store(ctx, tx, idempKey, true); err != nil {
		s.logger.Warn("failed to store idempotency record", zap.Error(err))
	}
	return tx.Commit()
}

func (s *subscriptionAnalyticsService) onTrialEnded(ctx context.Context, p events.TrialPayload) error {
	subID, err := uuid.Parse(p.SubscriptionID)
	if err != nil {
		return fmt.Errorf("invalid subscription_id: %w", err)
	}
	companyID, err := uuid.Parse(p.CompanyID)
	if err != nil {
		return fmt.Errorf("invalid company_id: %w", err)
	}
	endedAt, err := time.Parse(time.RFC3339, p.EndedAt)
	if err != nil {
		endedAt = time.Now()
	}

	tx, err := s.pgClient.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("begin tx: %w", err)
	}
	defer tx.Rollback()

	idempKey := getIDempotencyKey(ctx, fmt.Sprintf("sub-analytics-trialend-%s", p.TrialID))
	var done bool
	if err := s.idempotencyStore.Get(ctx, tx, idempKey, &done); err == nil && done {
		s.logger.Info("idempotent – trial ended already processed")
		return nil
	}

	date := endedAt.Truncate(24 * time.Hour)
	delta := &repository.DailySubscriptionMetricsDelta{
		TrialExpirations: 1,
	}
	if err := s.analyticsRepo.IncrementDailySubscriptionMetrics(ctx, tx, companyID, date, delta); err != nil {
		return fmt.Errorf("increment daily subscription metrics: %w", err)
	}

	fact := &models.SubscriptionFact{
		CompanyID:      companyID,
		SubscriptionID: subID,
		EventDate:      endedAt,
		EventType:      "trial_ended",
		PlanID:         nil,
		CustomerID:     nil,
		OldStatusID:    nil,
		NewStatusID:    nil,
		MRRChange:      nil,
		Metadata:       nil,
	}
	if err := s.analyticsRepo.InsertSubscriptionFact(ctx, tx, fact); err != nil {
		return fmt.Errorf("insert subscription fact: %w", err)
	}

	if err := s.idempotencyStore.Store(ctx, tx, idempKey, true); err != nil {
		s.logger.Warn("failed to store idempotency record", zap.Error(err))
	}
	return tx.Commit()
}

func (s *subscriptionAnalyticsService) onTrialConverted(ctx context.Context, p events.TrialPayload) error {
	subID, err := uuid.Parse(p.SubscriptionID)
	if err != nil {
		return fmt.Errorf("invalid subscription_id: %w", err)
	}
	companyID, err := uuid.Parse(p.CompanyID)
	if err != nil {
		return fmt.Errorf("invalid company_id: %w", err)
	}
	convertedAt, err := time.Parse(time.RFC3339, p.StartedAt)
	if err != nil {
		convertedAt = time.Now()
	}

	tx, err := s.pgClient.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("begin tx: %w", err)
	}
	defer tx.Rollback()

	idempKey := getIDempotencyKey(ctx, fmt.Sprintf("sub-analytics-trialconv-%s", p.TrialID))
	var done bool
	if err := s.idempotencyStore.Get(ctx, tx, idempKey, &done); err == nil && done {
		s.logger.Info("idempotent – trial converted already processed")
		return nil
	}

	date := convertedAt.Truncate(24 * time.Hour)
	delta := &repository.DailySubscriptionMetricsDelta{
		TrialConversions: 1,
	}
	if err := s.analyticsRepo.IncrementDailySubscriptionMetrics(ctx, tx, companyID, date, delta); err != nil {
		return fmt.Errorf("increment daily subscription metrics: %w", err)
	}

	fact := &models.SubscriptionFact{
		CompanyID:      companyID,
		SubscriptionID: subID,
		EventDate:      convertedAt,
		EventType:      "trial_converted",
		PlanID:         nil,
		CustomerID:     nil,
		OldStatusID:    nil,
		NewStatusID:    nil,
		MRRChange:      nil,
		Metadata:       nil,
	}
	if err := s.analyticsRepo.InsertSubscriptionFact(ctx, tx, fact); err != nil {
		return fmt.Errorf("insert subscription fact: %w", err)
	}

	if err := s.idempotencyStore.Store(ctx, tx, idempKey, true); err != nil {
		s.logger.Warn("failed to store idempotency record", zap.Error(err))
	}
	return tx.Commit()
}

func (s *subscriptionAnalyticsService) onTrialCancelled(ctx context.Context, p events.TrialPayload) error {
	subID, err := uuid.Parse(p.SubscriptionID)
	if err != nil {
		return fmt.Errorf("invalid subscription_id: %w", err)
	}
	companyID, err := uuid.Parse(p.CompanyID)
	if err != nil {
		return fmt.Errorf("invalid company_id: %w", err)
	}
	cancelledAt, err := time.Parse(time.RFC3339, p.EndedAt)
	if err != nil {
		cancelledAt = time.Now()
	}

	tx, err := s.pgClient.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("begin tx: %w", err)
	}
	defer tx.Rollback()

	idempKey := getIDempotencyKey(ctx, fmt.Sprintf("sub-analytics-trialcancel-%s", p.TrialID))
	var done bool
	if err := s.idempotencyStore.Get(ctx, tx, idempKey, &done); err == nil && done {
		s.logger.Info("idempotent – trial cancelled already processed")
		return nil
	}

	date := cancelledAt.Truncate(24 * time.Hour)
	delta := &repository.DailySubscriptionMetricsDelta{
		TrialExpirations: 1,
	}
	if err := s.analyticsRepo.IncrementDailySubscriptionMetrics(ctx, tx, companyID, date, delta); err != nil {
		return fmt.Errorf("increment daily subscription metrics: %w", err)
	}

	fact := &models.SubscriptionFact{
		CompanyID:      companyID,
		SubscriptionID: subID,
		EventDate:      cancelledAt,
		EventType:      "trial_cancelled",
		PlanID:         nil,
		CustomerID:     nil,
		OldStatusID:    nil,
		NewStatusID:    nil,
		MRRChange:      nil,
		Metadata:       nil,
	}
	if err := s.analyticsRepo.InsertSubscriptionFact(ctx, tx, fact); err != nil {
		return fmt.Errorf("insert subscription fact: %w", err)
	}

	if err := s.idempotencyStore.Store(ctx, tx, idempKey, true); err != nil {
		s.logger.Warn("failed to store idempotency record", zap.Error(err))
	}
	return tx.Commit()
}

// ----------------------------------------------------------------------------
// Helper: status change
// ----------------------------------------------------------------------------

func (s *subscriptionAnalyticsService) handleStatusChange(ctx context.Context, p events.SubscriptionPayload, eventType string, activeDelta int, pausedDelta int, expiredDelta int, cancelledDelta int) error {
	subID, err := uuid.Parse(p.SubscriptionID)
	if err != nil {
		return fmt.Errorf("invalid subscription_id: %w", err)
	}
	companyID, err := uuid.Parse(p.CompanyID)
	if err != nil {
		return fmt.Errorf("invalid company_id: %w", err)
	}
	planID, err := uuid.Parse(p.PlanID)
	if err != nil {
		return fmt.Errorf("invalid plan_id: %w", err)
	}
	customerID, err := uuid.Parse(p.CustomerID)
	if err != nil {
		return fmt.Errorf("invalid customer_id: %w", err)
	}
	eventDate := time.Now()
	if p.StartDate != "" {
		if d, err := time.Parse(time.RFC3339, p.StartDate); err == nil {
			eventDate = d
		}
	}

	tx, err := s.pgClient.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("begin tx: %w", err)
	}
	defer tx.Rollback()

	idempKey := getIDempotencyKey(ctx, fmt.Sprintf("sub-analytics-%s-%s", eventType, p.SubscriptionID))
	var done bool
	if err := s.idempotencyStore.Get(ctx, tx, idempKey, &done); err == nil && done {
		s.logger.Info("idempotent – event already processed", zap.String("event", eventType))
		return nil
	}

	var mrrDelta decimal.Decimal
	if activeDelta != 0 {
		mrr, err := s.computeSubscriptionMRR(ctx, tx, subID, companyID)
		if err != nil {
			s.logger.Warn("failed to compute MRR, using 0", zap.Error(err))
			mrr = decimal.Zero
		}
		mrrDelta = mrr.Mul(decimal.NewFromInt(int64(activeDelta)))
	}

	date := eventDate.Truncate(24 * time.Hour)
	delta := &repository.DailySubscriptionMetricsDelta{
		ActiveSubscriptions:    activeDelta,
		PausedSubscriptions:    pausedDelta,
		ExpiredSubscriptions:   expiredDelta,
		CancelledSubscriptions: cancelledDelta,
		MRR:                    mrrDelta,
		ARR:                    mrrDelta.Mul(decimal.NewFromInt(12)),
	}
	if err := s.analyticsRepo.IncrementDailySubscriptionMetrics(ctx, tx, companyID, date, delta); err != nil {
		return fmt.Errorf("increment daily subscription metrics: %w", err)
	}

	if activeDelta != 0 {
		planDelta := &repository.DailyPlanMetricsDelta{
			ActiveCount: activeDelta,
			MRR:         mrrDelta,
			ARR:         mrrDelta.Mul(decimal.NewFromInt(12)),
		}
		if err := s.analyticsRepo.IncrementDailyPlanMetrics(ctx, tx, companyID, planID, date, planDelta); err != nil {
			return fmt.Errorf("increment daily plan metrics: %w", err)
		}

		// Update benefit metrics for this subscription if active count changes
		newDelta := 0
		if activeDelta > 0 {
			newDelta = activeDelta
		}
		if err := s.updateBenefitMetricsForSubscription(ctx, tx, companyID, subID, date, activeDelta, newDelta); err != nil {
			s.logger.Warn("failed to update benefit metrics on status change", zap.String("event", eventType), zap.Error(err))
		}
	}

	fact := &models.SubscriptionFact{
		CompanyID:      companyID,
		SubscriptionID: subID,
		EventDate:      eventDate,
		EventType:      eventType,
		PlanID:         &planID,
		CustomerID:     &customerID,
		OldStatusID:    nil,
		NewStatusID:    nil,
		MRRChange:      &mrrDelta,
		Metadata:       nil,
	}
	if err := s.analyticsRepo.InsertSubscriptionFact(ctx, tx, fact); err != nil {
		return fmt.Errorf("insert subscription fact: %w", err)
	}

	if err := s.idempotencyStore.Store(ctx, tx, idempKey, true); err != nil {
		s.logger.Warn("failed to store idempotency record", zap.Error(err))
	}
	return tx.Commit()
}

// ----------------------------------------------------------------------------
// MRR and Addon helpers
// ----------------------------------------------------------------------------

func (s *subscriptionAnalyticsService) computeSubscriptionMRR(ctx context.Context, tx repository.DBTX, subID, companyID uuid.UUID) (decimal.Decimal, error) {
	items, err := s.subItemRepo.GetActiveBySubscription(ctx, tx, subID)
	if err != nil {
		return decimal.Zero, err
	}
	total := decimal.Zero
	for _, item := range items {
		planItem, err := s.planItemRepo.GetByID(ctx, tx, item.PlanItemID)
		if err != nil {
			return decimal.Zero, fmt.Errorf("get plan item %s: %w", item.PlanItemID, err)
		}
		if planItem.ItemType == enums.ItemTypeBase || planItem.ItemType == enums.ItemTypeAddon {
			total = total.Add(item.UnitPrice.Mul(item.Quantity))
		}
	}
	return total, nil
}

func (s *subscriptionAnalyticsService) computePlanMRR(ctx context.Context, tx repository.DBTX, planID, companyID uuid.UUID) (decimal.Decimal, error) {
	planItems, err := s.planItemRepo.GetActiveByPlan(ctx, tx, planID)
	if err != nil {
		return decimal.Zero, err
	}
	total := decimal.Zero
	for _, pi := range planItems {
		if pi.ItemType == enums.ItemTypeBase || pi.ItemType == enums.ItemTypeAddon {
			total = total.Add(pi.Price)
		}
	}
	return total, nil
}

func (s *subscriptionAnalyticsService) updateAddonMetricsForSubscription(
	ctx context.Context,
	tx repository.DBTX,
	companyID, subscriptionID uuid.UUID,
	eventDate time.Time,
	deltaActive int,
	deltaNew int,
) error {
	items, err := s.subItemRepo.GetActiveBySubscription(ctx, tx, subscriptionID)
	if err != nil {
		return fmt.Errorf("get subscription items: %w", err)
	}
	for _, item := range items {
		if item.AddonID == nil {
			continue
		}
		revenue := item.UnitPrice.Mul(item.Quantity)
		mrr := revenue
		arr := mrr.Mul(decimal.NewFromInt(12))

		delta := &models.DailyAddonMetricsDelta{
			ActiveCount: deltaActive,
			NewCount:    deltaNew,
			Revenue:     revenue,
			MRR:         mrr,
			ARR:         arr,
		}
		date := eventDate.Truncate(24 * time.Hour)

		sqlTx, ok := tx.(*sql.Tx)
		if !ok {
			return fmt.Errorf("tx is not a *sql.Tx")
		}
		if err := s.analyticsRepo.IncrementDailyAddonMetrics(ctx, sqlTx, companyID, *item.AddonID, date, delta); err != nil {
			return fmt.Errorf("increment addon metrics for addon %s: %w", item.AddonID.String(), err)
		}
	}
	return nil
}

// ----------------------------------------------------------------------------
// BILLING POLICY EVENT PROCESSING
// ----------------------------------------------------------------------------

func (s *subscriptionAnalyticsService) ProcessBillingPolicyEvent(ctx context.Context, eventType string, payload []byte) error {
	switch eventType {
	case events.EventBillingPolicyCreated:
		var p events.BillingPolicyPayload
		if err := json.Unmarshal(payload, &p); err != nil {
			return fmt.Errorf("unmarshal billing policy created payload: %w", err)
		}
		return s.onBillingPolicyCreated(ctx, p)

	case events.EventBillingPolicyUpdated:
		s.logger.Debug("billing policy updated – no metrics change")
		return nil

	case events.EventBillingPolicyActivated:
		var p events.BillingPolicyPayload
		if err := json.Unmarshal(payload, &p); err != nil {
			return fmt.Errorf("unmarshal billing policy activated payload: %w", err)
		}
		return s.onBillingPolicyActivated(ctx, p)

	case events.EventBillingPolicyDeactivated:
		var p events.BillingPolicyPayload
		if err := json.Unmarshal(payload, &p); err != nil {
			return fmt.Errorf("unmarshal billing policy deactivated payload: %w", err)
		}
		return s.onBillingPolicyDeactivated(ctx, p)

	case events.EventBillingPolicyDeleted:
		var p events.BillingPolicyPayload
		if err := json.Unmarshal(payload, &p); err != nil {
			return fmt.Errorf("unmarshal billing policy deleted payload: %w", err)
		}
		return s.onBillingPolicyDeleted(ctx, p)

	case events.EventBillingPolicyRestored:
		var p events.BillingPolicyPayload
		if err := json.Unmarshal(payload, &p); err != nil {
			return fmt.Errorf("unmarshal billing policy restored payload: %w", err)
		}
		return s.onBillingPolicyRestored(ctx, p)

	default:
		s.logger.Debug("ignored unknown billing policy event", zap.String("event_type", eventType))
		return nil
	}
}

func (s *subscriptionAnalyticsService) onBillingPolicyCreated(ctx context.Context, p events.BillingPolicyPayload) error {
	if !p.IsActive {
		s.logger.Info("billing policy created but not active – no analytics update", zap.String("policy_id", p.BillingPolicyID))
		return nil
	}
	return s.updateBillingPolicyActiveCount(ctx, p, 1, 1)
}

func (s *subscriptionAnalyticsService) onBillingPolicyActivated(ctx context.Context, p events.BillingPolicyPayload) error {
	return s.updateBillingPolicyActiveCount(ctx, p, 1, 0)
}

func (s *subscriptionAnalyticsService) onBillingPolicyDeactivated(ctx context.Context, p events.BillingPolicyPayload) error {
	return s.updateBillingPolicyActiveCount(ctx, p, -1, 0)
}

func (s *subscriptionAnalyticsService) onBillingPolicyDeleted(ctx context.Context, p events.BillingPolicyPayload) error {
	policyID, err := uuid.Parse(p.BillingPolicyID)
	if err != nil {
		return fmt.Errorf("invalid billing policy id: %w", err)
	}
	companyID, err := uuid.Parse(p.CompanyID)
	if err != nil {
		return fmt.Errorf("invalid company id: %w", err)
	}
	policy, err := s.billingPolicyRepo.GetByID(ctx, s.pgClient.DB, companyID, policyID)
	if err != nil {
		s.logger.Warn("could not fetch billing policy for deletion analytics", zap.Error(err))
		return nil
	}
	if policy == nil || !policy.IsActive {
		return nil
	}
	return s.updateBillingPolicyActiveCount(ctx, p, -1, 0)
}

func (s *subscriptionAnalyticsService) onBillingPolicyRestored(ctx context.Context, p events.BillingPolicyPayload) error {
	policyID, err := uuid.Parse(p.BillingPolicyID)
	if err != nil {
		return fmt.Errorf("invalid billing policy id: %w", err)
	}
	companyID, err := uuid.Parse(p.CompanyID)
	if err != nil {
		return fmt.Errorf("invalid company id: %w", err)
	}
	policy, err := s.billingPolicyRepo.GetByID(ctx, s.pgClient.DB, companyID, policyID)
	if err != nil {
		s.logger.Warn("could not fetch billing policy for restore analytics", zap.Error(err))
		return nil
	}
	if policy == nil || !policy.IsActive {
		return nil
	}
	return s.updateBillingPolicyActiveCount(ctx, p, 1, 0)
}

func (s *subscriptionAnalyticsService) updateBillingPolicyActiveCount(
	ctx context.Context,
	p events.BillingPolicyPayload,
	activeDelta int,
	newDelta int,
) error {
	policyID, err := uuid.Parse(p.BillingPolicyID)
	if err != nil {
		return fmt.Errorf("invalid billing policy id: %w", err)
	}
	companyID, err := uuid.Parse(p.CompanyID)
	if err != nil {
		return fmt.Errorf("invalid company id: %w", err)
	}

	tx, err := s.pgClient.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("begin tx: %w", err)
	}
	defer tx.Rollback()

	idempKey := getIDempotencyKey(ctx, fmt.Sprintf("bp-analytics-%s-%s", p.BillingPolicyID, "active"))
	var done bool
	if err := s.idempotencyStore.Get(ctx, tx, idempKey, &done); err == nil && done {
		s.logger.Info("idempotent – billing policy active count update already processed")
		return nil
	}

	date := time.Now().Truncate(24 * time.Hour)
	delta := &models.DailyBillingPolicyMetricsDelta{
		ActiveCount: activeDelta,
		NewCount:    newDelta,
	}
	if err := s.analyticsRepo.IncrementDailyBillingPolicyMetrics(ctx, tx, companyID, policyID, date, delta); err != nil {
		return fmt.Errorf("increment daily billing policy metrics: %w", err)
	}

	if err := s.idempotencyStore.Store(ctx, tx, idempKey, true); err != nil {
		s.logger.Warn("failed to store idempotency record", zap.Error(err))
	}
	return tx.Commit()
}

// ----------------------------------------------------------------------------
// RENEWAL POLICY EVENT PROCESSING
// ----------------------------------------------------------------------------

func (s *subscriptionAnalyticsService) ProcessRenewalPolicyEvent(ctx context.Context, eventType string, payload []byte) error {
	switch eventType {
	case events.EventRenewalPolicyCreated:
		var p events.RenewalPolicyPayload
		if err := json.Unmarshal(payload, &p); err != nil {
			return fmt.Errorf("unmarshal renewal policy created payload: %w", err)
		}
		return s.onRenewalPolicyCreated(ctx, p)

	case events.EventRenewalPolicyUpdated:
		s.logger.Debug("renewal policy updated – no metrics change")
		return nil

	case events.EventRenewalPolicyActivated:
		var p events.RenewalPolicyPayload
		if err := json.Unmarshal(payload, &p); err != nil {
			return fmt.Errorf("unmarshal renewal policy activated payload: %w", err)
		}
		return s.onRenewalPolicyActivated(ctx, p)

	case events.EventRenewalPolicyDeactivated:
		var p events.RenewalPolicyPayload
		if err := json.Unmarshal(payload, &p); err != nil {
			return fmt.Errorf("unmarshal renewal policy deactivated payload: %w", err)
		}
		return s.onRenewalPolicyDeactivated(ctx, p)

	case events.EventRenewalPolicyDeleted:
		var p events.RenewalPolicyPayload
		if err := json.Unmarshal(payload, &p); err != nil {
			return fmt.Errorf("unmarshal renewal policy deleted payload: %w", err)
		}
		return s.onRenewalPolicyDeleted(ctx, p)

	case events.EventRenewalPolicyRestored:
		var p events.RenewalPolicyPayload
		if err := json.Unmarshal(payload, &p); err != nil {
			return fmt.Errorf("unmarshal renewal policy restored payload: %w", err)
		}
		return s.onRenewalPolicyRestored(ctx, p)

	default:
		s.logger.Debug("ignored unknown renewal policy event", zap.String("event_type", eventType))
		return nil
	}
}

func (s *subscriptionAnalyticsService) onRenewalPolicyCreated(ctx context.Context, p events.RenewalPolicyPayload) error {
	if !p.IsActive {
		s.logger.Info("renewal policy created but not active – no analytics update", zap.String("policy_id", p.RenewalPolicyID))
		return nil
	}
	return s.updateRenewalPolicyActiveCount(ctx, p, 1, 1)
}

func (s *subscriptionAnalyticsService) onRenewalPolicyActivated(ctx context.Context, p events.RenewalPolicyPayload) error {
	return s.updateRenewalPolicyActiveCount(ctx, p, 1, 0)
}

func (s *subscriptionAnalyticsService) onRenewalPolicyDeactivated(ctx context.Context, p events.RenewalPolicyPayload) error {
	return s.updateRenewalPolicyActiveCount(ctx, p, -1, 0)
}

func (s *subscriptionAnalyticsService) onRenewalPolicyDeleted(ctx context.Context, p events.RenewalPolicyPayload) error {
	policyID, err := uuid.Parse(p.RenewalPolicyID)
	if err != nil {
		return fmt.Errorf("invalid renewal policy id: %w", err)
	}
	companyID, err := uuid.Parse(p.CompanyID)
	if err != nil {
		return fmt.Errorf("invalid company id: %w", err)
	}
	policy, err := s.renewalPolicyRepo.GetByID(ctx, s.pgClient.DB, companyID, policyID)
	if err != nil {
		s.logger.Warn("could not fetch renewal policy for deletion analytics", zap.Error(err))
		return nil
	}
	if policy == nil || !policy.IsActive {
		return nil
	}
	return s.updateRenewalPolicyActiveCount(ctx, p, -1, 0)
}

func (s *subscriptionAnalyticsService) onRenewalPolicyRestored(ctx context.Context, p events.RenewalPolicyPayload) error {
	policyID, err := uuid.Parse(p.RenewalPolicyID)
	if err != nil {
		return fmt.Errorf("invalid renewal policy id: %w", err)
	}
	companyID, err := uuid.Parse(p.CompanyID)
	if err != nil {
		return fmt.Errorf("invalid company id: %w", err)
	}
	policy, err := s.renewalPolicyRepo.GetByID(ctx, s.pgClient.DB, companyID, policyID)
	if err != nil {
		s.logger.Warn("could not fetch renewal policy for restore analytics", zap.Error(err))
		return nil
	}
	if policy == nil || !policy.IsActive {
		return nil
	}
	return s.updateRenewalPolicyActiveCount(ctx, p, 1, 0)
}

func (s *subscriptionAnalyticsService) updateRenewalPolicyActiveCount(
	ctx context.Context,
	p events.RenewalPolicyPayload,
	activeDelta int,
	newDelta int,
) error {
	policyID, err := uuid.Parse(p.RenewalPolicyID)
	if err != nil {
		return fmt.Errorf("invalid renewal policy id: %w", err)
	}
	companyID, err := uuid.Parse(p.CompanyID)
	if err != nil {
		return fmt.Errorf("invalid company id: %w", err)
	}

	tx, err := s.pgClient.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("begin tx: %w", err)
	}
	defer tx.Rollback()

	idempKey := getIDempotencyKey(ctx, fmt.Sprintf("rp-analytics-%s-%s", p.RenewalPolicyID, "active"))
	var done bool
	if err := s.idempotencyStore.Get(ctx, tx, idempKey, &done); err == nil && done {
		s.logger.Info("idempotent – renewal policy active count update already processed")
		return nil
	}

	date := time.Now().Truncate(24 * time.Hour)
	delta := &models.DailyRenewalPolicyMetricsDelta{
		ActiveCount: activeDelta,
		NewCount:    newDelta,
	}
	if err := s.analyticsRepo.IncrementDailyRenewalPolicyMetrics(ctx, tx, companyID, policyID, date, delta); err != nil {
		return fmt.Errorf("increment daily renewal policy metrics: %w", err)
	}

	if err := s.idempotencyStore.Store(ctx, tx, idempKey, true); err != nil {
		s.logger.Warn("failed to store idempotency record", zap.Error(err))
	}
	return tx.Commit()
}

// ----------------------------------------------------------------------------
// PAUSE POLICY EVENT PROCESSING
// ----------------------------------------------------------------------------

func (s *subscriptionAnalyticsService) ProcessPausePolicyEvent(ctx context.Context, eventType string, payload []byte) error {
	switch eventType {
	case events.EventPausePolicyCreated:
		var p events.PausePolicyPayload
		if err := json.Unmarshal(payload, &p); err != nil {
			return fmt.Errorf("unmarshal pause policy created payload: %w", err)
		}
		return s.onPausePolicyCreated(ctx, p)

	case events.EventPausePolicyUpdated:
		s.logger.Debug("pause policy updated – no metrics change")
		return nil

	case events.EventPausePolicyActivated:
		var p events.PausePolicyPayload
		if err := json.Unmarshal(payload, &p); err != nil {
			return fmt.Errorf("unmarshal pause policy activated payload: %w", err)
		}
		return s.onPausePolicyActivated(ctx, p)

	case events.EventPausePolicyDeactivated:
		var p events.PausePolicyPayload
		if err := json.Unmarshal(payload, &p); err != nil {
			return fmt.Errorf("unmarshal pause policy deactivated payload: %w", err)
		}
		return s.onPausePolicyDeactivated(ctx, p)

	case events.EventPausePolicyDeleted:
		var p events.PausePolicyPayload
		if err := json.Unmarshal(payload, &p); err != nil {
			return fmt.Errorf("unmarshal pause policy deleted payload: %w", err)
		}
		return s.onPausePolicyDeleted(ctx, p)

	case events.EventPausePolicyRestored:
		var p events.PausePolicyPayload
		if err := json.Unmarshal(payload, &p); err != nil {
			return fmt.Errorf("unmarshal pause policy restored payload: %w", err)
		}
		return s.onPausePolicyRestored(ctx, p)

	default:
		s.logger.Debug("ignored unknown pause policy event", zap.String("event_type", eventType))
		return nil
	}
}

func (s *subscriptionAnalyticsService) onPausePolicyCreated(ctx context.Context, p events.PausePolicyPayload) error {
	if !p.IsActive {
		s.logger.Info("pause policy created but not active – no analytics update", zap.String("policy_id", p.PausePolicyID))
		return nil
	}
	return s.updatePausePolicyActiveCount(ctx, p, 1, 1)
}

func (s *subscriptionAnalyticsService) onPausePolicyActivated(ctx context.Context, p events.PausePolicyPayload) error {
	return s.updatePausePolicyActiveCount(ctx, p, 1, 0)
}

func (s *subscriptionAnalyticsService) onPausePolicyDeactivated(ctx context.Context, p events.PausePolicyPayload) error {
	return s.updatePausePolicyActiveCount(ctx, p, -1, 0)
}

func (s *subscriptionAnalyticsService) onPausePolicyDeleted(ctx context.Context, p events.PausePolicyPayload) error {
	policyID, err := uuid.Parse(p.PausePolicyID)
	if err != nil {
		return fmt.Errorf("invalid pause policy id: %w", err)
	}
	companyID, err := uuid.Parse(p.CompanyID)
	if err != nil {
		return fmt.Errorf("invalid company id: %w", err)
	}
	policy, err := s.pausePolicyRepo.GetByID(ctx, s.pgClient.DB, companyID, policyID)
	if err != nil {
		s.logger.Warn("could not fetch pause policy for deletion analytics", zap.Error(err))
		return nil
	}
	if policy == nil || !policy.IsActive {
		return nil
	}
	return s.updatePausePolicyActiveCount(ctx, p, -1, 0)
}

func (s *subscriptionAnalyticsService) onPausePolicyRestored(ctx context.Context, p events.PausePolicyPayload) error {
	policyID, err := uuid.Parse(p.PausePolicyID)
	if err != nil {
		return fmt.Errorf("invalid pause policy id: %w", err)
	}
	companyID, err := uuid.Parse(p.CompanyID)
	if err != nil {
		return fmt.Errorf("invalid company id: %w", err)
	}
	policy, err := s.pausePolicyRepo.GetByID(ctx, s.pgClient.DB, companyID, policyID)
	if err != nil {
		s.logger.Warn("could not fetch pause policy for restore analytics", zap.Error(err))
		return nil
	}
	if policy == nil || !policy.IsActive {
		return nil
	}
	return s.updatePausePolicyActiveCount(ctx, p, 1, 0)
}

func (s *subscriptionAnalyticsService) updatePausePolicyActiveCount(
	ctx context.Context,
	p events.PausePolicyPayload,
	activeDelta int,
	newDelta int,
) error {
	policyID, err := uuid.Parse(p.PausePolicyID)
	if err != nil {
		return fmt.Errorf("invalid pause policy id: %w", err)
	}
	companyID, err := uuid.Parse(p.CompanyID)
	if err != nil {
		return fmt.Errorf("invalid company id: %w", err)
	}

	tx, err := s.pgClient.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("begin tx: %w", err)
	}
	defer tx.Rollback()

	idempKey := getIDempotencyKey(ctx, fmt.Sprintf("pp-analytics-%s-%s", p.PausePolicyID, "active"))
	var done bool
	if err := s.idempotencyStore.Get(ctx, tx, idempKey, &done); err == nil && done {
		s.logger.Info("idempotent – pause policy active count update already processed")
		return nil
	}

	date := time.Now().Truncate(24 * time.Hour)
	delta := &models.DailyPausePolicyMetricsDelta{
		ActiveCount: activeDelta,
		NewCount:    newDelta,
	}
	if err := s.analyticsRepo.IncrementDailyPausePolicyMetrics(ctx, tx, companyID, policyID, date, delta); err != nil {
		return fmt.Errorf("increment daily pause policy metrics: %w", err)
	}

	if err := s.idempotencyStore.Store(ctx, tx, idempKey, true); err != nil {
		s.logger.Warn("failed to store idempotency record", zap.Error(err))
	}
	return tx.Commit()
}

// ----------------------------------------------------------------------------
// ENTITLEMENT EVENT PROCESSING
// ----------------------------------------------------------------------------

func (s *subscriptionAnalyticsService) ProcessEntitlementEvent(ctx context.Context, eventType string, payload []byte) error {
	s.logger.Debug("processing entitlement event", zap.String("event_type", eventType))

	switch eventType {
	case events.EventEntitlementGranted:
		var p events.EntitlementGrantPayload
		if err := json.Unmarshal(payload, &p); err != nil {
			return fmt.Errorf("unmarshal entitlement granted payload: %w", err)
		}
		return s.onEntitlementGranted(ctx, p)

	case events.EventEntitlementRevoked:
		var p events.EntitlementRevokePayload
		if err := json.Unmarshal(payload, &p); err != nil {
			return fmt.Errorf("unmarshal entitlement revoked payload: %w", err)
		}
		return s.onEntitlementRevoked(ctx, p)

	case events.EventEntitlementRefreshed:
		var p events.EntitlementRefreshPayload
		if err := json.Unmarshal(payload, &p); err != nil {
			return fmt.Errorf("unmarshal entitlement refreshed payload: %w", err)
		}
		return s.onEntitlementRefreshed(ctx, p)

	default:
		s.logger.Debug("ignored entitlement event", zap.String("event_type", eventType))
		return nil
	}
}

// onEntitlementGranted processes a grant event: inserts facts and increments daily metrics.
func (s *subscriptionAnalyticsService) onEntitlementGranted(ctx context.Context, p events.EntitlementGrantPayload) error {
	subID, err := uuid.Parse(p.SubscriptionID)
	if err != nil {
		return fmt.Errorf("invalid subscription_id: %w", err)
	}

	db := s.pgClient.DB
	sub, err := s.subRepo.GetByID(ctx, db, uuid.Nil, subID)
	if err != nil {
		return fmt.Errorf("get subscription: %w", err)
	}
	if sub == nil {
		s.logger.Warn("subscription not found for grant analytics", zap.String("subscription_id", p.SubscriptionID))
		return nil
	}
	companyID := sub.CompanyID

	tx, err := s.pgClient.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("begin tx: %w", err)
	}
	defer tx.Rollback()

	idempKey := getIDempotencyKey(ctx, fmt.Sprintf("ent-analytics-grant-%s", p.SubscriptionID))
	var done bool
	if err := s.idempotencyStore.Get(ctx, tx, idempKey, &done); err == nil && done {
		s.logger.Info("idempotent – entitlement grant already processed", zap.String("subscription_id", p.SubscriptionID))
		return nil
	}

	items, err := s.subItemRepo.GetActiveBySubscription(ctx, tx, subID)
	if err != nil {
		return fmt.Errorf("get subscription items: %w", err)
	}
	if len(items) == 0 {
		s.logger.Info("no active subscription items for grant", zap.String("subscription_id", p.SubscriptionID))
		_ = s.idempotencyStore.Store(ctx, tx, idempKey, true)
		return tx.Commit()
	}

	var entitlementFacts []*models.EntitlementUsageFact
	featureKeys := make(map[string]bool)
	grantDate := time.Now().UTC().Truncate(24 * time.Hour)

	for _, item := range items {
		planItem, err := s.planItemRepo.GetByID(ctx, tx, item.PlanItemID)
		if err != nil {
			return fmt.Errorf("get plan item %s: %w", item.PlanItemID, err)
		}
		ents, err := s.entitlementRepo.GetEnabledByPlanItem(ctx, tx, planItem.PlanItemID)
		if err != nil {
			return fmt.Errorf("get entitlements for plan item %s: %w", planItem.PlanItemID, err)
		}
		for _, ent := range ents {
			fact := &models.EntitlementUsageFact{
				CompanyID:      companyID,
				SubscriptionID: subID,
				PlanItemID:     planItem.PlanItemID,
				FeatureKey:     ent.FeatureKey,
				LimitValue:     ent.LimitValue,
				LimitPeriod:    string(ent.LimitPeriod),
				IsEnabled:      ent.IsEnabled,
				GrantDate:      grantDate,
			}
			entitlementFacts = append(entitlementFacts, fact)
			featureKeys[ent.FeatureKey] = true
		}
	}

	if len(entitlementFacts) == 0 {
		s.logger.Info("no entitlements to grant", zap.String("subscription_id", p.SubscriptionID))
		_ = s.idempotencyStore.Store(ctx, tx, idempKey, true)
		return tx.Commit()
	}

	for _, fact := range entitlementFacts {
		if err := s.analyticsRepo.InsertEntitlementUsageFact(ctx, tx, fact); err != nil {
			return fmt.Errorf("insert entitlement usage fact: %w", err)
		}
	}

	date := grantDate
	for featureKey := range featureKeys {
		delta := &models.DailyEntitlementMetricsDelta{
			ActiveCount: 1,
			NewCount:    1,
		}
		if err := s.analyticsRepo.IncrementDailyEntitlementMetrics(ctx, tx, companyID, featureKey, date, delta); err != nil {
			return fmt.Errorf("increment daily entitlement metrics for %s: %w", featureKey, err)
		}
	}

	if err := s.idempotencyStore.Store(ctx, tx, idempKey, true); err != nil {
		s.logger.Warn("failed to store idempotency record", zap.Error(err))
	}
	return tx.Commit()
}

// onEntitlementRevoked processes a revoke event: decrements daily metrics.
func (s *subscriptionAnalyticsService) onEntitlementRevoked(ctx context.Context, p events.EntitlementRevokePayload) error {
	subID, err := uuid.Parse(p.SubscriptionID)
	if err != nil {
		return fmt.Errorf("invalid subscription_id: %w", err)
	}

	db := s.pgClient.DB
	sub, err := s.subRepo.GetByID(ctx, db, uuid.Nil, subID)
	if err != nil {
		return fmt.Errorf("get subscription: %w", err)
	}
	if sub == nil {
		s.logger.Warn("subscription not found for revoke analytics", zap.String("subscription_id", p.SubscriptionID))
		return nil
	}
	companyID := sub.CompanyID

	tx, err := s.pgClient.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("begin tx: %w", err)
	}
	defer tx.Rollback()

	idempKey := getIDempotencyKey(ctx, fmt.Sprintf("ent-analytics-revoke-%s", p.SubscriptionID))
	var done bool
	if err := s.idempotencyStore.Get(ctx, tx, idempKey, &done); err == nil && done {
		s.logger.Info("idempotent – entitlement revoke already processed", zap.String("subscription_id", p.SubscriptionID))
		return nil
	}

	items, err := s.subItemRepo.GetActiveBySubscription(ctx, tx, subID)
	if err != nil {
		return fmt.Errorf("get subscription items: %w", err)
	}
	featureKeys := make(map[string]bool)
	for _, item := range items {
		planItem, err := s.planItemRepo.GetByID(ctx, tx, item.PlanItemID)
		if err != nil {
			return fmt.Errorf("get plan item %s: %w", item.PlanItemID, err)
		}
		ents, err := s.entitlementRepo.GetEnabledByPlanItem(ctx, tx, planItem.PlanItemID)
		if err != nil {
			return fmt.Errorf("get entitlements for plan item %s: %w", planItem.PlanItemID, err)
		}
		for _, ent := range ents {
			featureKeys[ent.FeatureKey] = true
		}
	}

	if len(featureKeys) == 0 {
		s.logger.Info("no entitlements to revoke", zap.String("subscription_id", p.SubscriptionID))
		_ = s.idempotencyStore.Store(ctx, tx, idempKey, true)
		return tx.Commit()
	}

	date := time.Now().UTC().Truncate(24 * time.Hour)
	for featureKey := range featureKeys {
		delta := &models.DailyEntitlementMetricsDelta{
			ActiveCount: -1,
			NewCount:    0,
		}
		if err := s.analyticsRepo.IncrementDailyEntitlementMetrics(ctx, tx, companyID, featureKey, date, delta); err != nil {
			return fmt.Errorf("decrement daily entitlement metrics for %s: %w", featureKey, err)
		}
	}

	if err := s.idempotencyStore.Store(ctx, tx, idempKey, true); err != nil {
		s.logger.Warn("failed to store idempotency record", zap.Error(err))
	}
	return tx.Commit()
}

// onEntitlementRefreshed processes a refresh: revoke then grant.
func (s *subscriptionAnalyticsService) onEntitlementRefreshed(ctx context.Context, p events.EntitlementRefreshPayload) error {
	subID, err := uuid.Parse(p.SubscriptionID)
	if err != nil {
		return fmt.Errorf("invalid subscription_id: %w", err)
	}

	db := s.pgClient.DB
	sub, err := s.subRepo.GetByID(ctx, db, uuid.Nil, subID)
	if err != nil {
		return fmt.Errorf("get subscription: %w", err)
	}
	if sub == nil {
		s.logger.Warn("subscription not found for refresh analytics", zap.String("subscription_id", p.SubscriptionID))
		return nil
	}
	companyID := sub.CompanyID

	tx, err := s.pgClient.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("begin tx: %w", err)
	}
	defer tx.Rollback()

	idempKey := getIDempotencyKey(ctx, fmt.Sprintf("ent-analytics-refresh-%s", p.SubscriptionID))
	var done bool
	if err := s.idempotencyStore.Get(ctx, tx, idempKey, &done); err == nil && done {
		s.logger.Info("idempotent – entitlement refresh already processed", zap.String("subscription_id", p.SubscriptionID))
		return nil
	}

	// Revoke phase: decrement daily metrics for all currently enabled entitlements.
	items, err := s.subItemRepo.GetActiveBySubscription(ctx, tx, subID)
	if err != nil {
		return fmt.Errorf("get subscription items: %w", err)
	}
	oldFeatureKeys := make(map[string]bool)
	for _, item := range items {
		planItem, err := s.planItemRepo.GetByID(ctx, tx, item.PlanItemID)
		if err != nil {
			return fmt.Errorf("get plan item %s: %w", item.PlanItemID, err)
		}
		ents, err := s.entitlementRepo.GetEnabledByPlanItem(ctx, tx, planItem.PlanItemID)
		if err != nil {
			return fmt.Errorf("get entitlements for plan item %s: %w", planItem.PlanItemID, err)
		}
		for _, ent := range ents {
			oldFeatureKeys[ent.FeatureKey] = true
		}
	}
	date := time.Now().UTC().Truncate(24 * time.Hour)

	for featureKey := range oldFeatureKeys {
		delta := &models.DailyEntitlementMetricsDelta{
			ActiveCount: -1,
			NewCount:    0,
		}
		if err := s.analyticsRepo.IncrementDailyEntitlementMetrics(ctx, tx, companyID, featureKey, date, delta); err != nil {
			return fmt.Errorf("decrement daily entitlement metrics (refresh) for %s: %w", featureKey, err)
		}
	}

	// Grant phase: re-fetch subscription items after refresh (they may have changed)
	itemsAfter, err := s.subItemRepo.GetActiveBySubscription(ctx, tx, subID)
	if err != nil {
		return fmt.Errorf("get subscription items after refresh: %w", err)
	}
	newFeatureKeys := make(map[string]bool)
	for _, item := range itemsAfter {
		planItem, err := s.planItemRepo.GetByID(ctx, tx, item.PlanItemID)
		if err != nil {
			return fmt.Errorf("get plan item %s after refresh: %w", item.PlanItemID, err)
		}
		ents, err := s.entitlementRepo.GetEnabledByPlanItem(ctx, tx, planItem.PlanItemID)
		if err != nil {
			return fmt.Errorf("get entitlements for plan item %s after refresh: %w", planItem.PlanItemID, err)
		}
		for _, ent := range ents {
			newFeatureKeys[ent.FeatureKey] = true
			fact := &models.EntitlementUsageFact{
				CompanyID:      companyID,
				SubscriptionID: subID,
				PlanItemID:     planItem.PlanItemID,
				FeatureKey:     ent.FeatureKey,
				LimitValue:     ent.LimitValue,
				LimitPeriod:    string(ent.LimitPeriod),
				IsEnabled:      ent.IsEnabled,
				GrantDate:      date,
			}
			if err := s.analyticsRepo.InsertEntitlementUsageFact(ctx, tx, fact); err != nil {
				return fmt.Errorf("insert entitlement usage fact (refresh): %w", err)
			}
		}
	}
	for featureKey := range newFeatureKeys {
		delta := &models.DailyEntitlementMetricsDelta{
			ActiveCount: 1,
			NewCount:    1,
		}
		if err := s.analyticsRepo.IncrementDailyEntitlementMetrics(ctx, tx, companyID, featureKey, date, delta); err != nil {
			return fmt.Errorf("increment daily entitlement metrics (refresh) for %s: %w", featureKey, err)
		}
	}

	if err := s.idempotencyStore.Store(ctx, tx, idempKey, true); err != nil {
		s.logger.Warn("failed to store idempotency record", zap.Error(err))
	}
	return tx.Commit()
}

// ----------------------------------------------------------------------------
// Helpers
// ----------------------------------------------------------------------------

func ptrInt16(v int16) *int16 {
	return &v
}

// determineChangeType comparxes old and new plans' MRR and IDs.
func (s *subscriptionAnalyticsService) determineChangeType(oldMRR, newMRR decimal.Decimal, oldPlanID, newPlanID uuid.UUID) string {
	if oldPlanID == newPlanID {
		return "lateral" // shouldn't happen in practice, but safe
	}
	cmp := newMRR.Cmp(oldMRR)
	if cmp > 0 {
		return "upgrade"
	} else if cmp < 0 {
		return "downgrade"
	}
	return "lateral"
}

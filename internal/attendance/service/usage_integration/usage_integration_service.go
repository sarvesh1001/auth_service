package usage_integration

import (
	"context"
	"database/sql"
	"fmt"
	"time"

	"github.com/google/uuid"
	"github.com/shopspring/decimal"
	"go.uber.org/zap"

	"auth-service/internal/subscription/models"
	"auth-service/internal/subscription/models/enums"
	"auth-service/internal/subscription/repository"
)

// UsageIntegrationService orchestrates creating usage from attendance events.
type UsageIntegrationService struct {
	db               *sql.DB
	subscriptionRepo repository.SubscriptionRepository
	subItemRepo      repository.SubscriptionItemRepository
	planItemRepo     repository.PlanItemRepository
	entitlementRepo  repository.EntitlementRepository
	usageRepo        repository.UsageRepository
	logger           *zap.Logger
}

func NewUsageIntegrationService(
	db *sql.DB,
	subscriptionRepo repository.SubscriptionRepository,
	subItemRepo repository.SubscriptionItemRepository,
	planItemRepo repository.PlanItemRepository,
	entitlementRepo repository.EntitlementRepository,
	usageRepo repository.UsageRepository,
	logger *zap.Logger,
) *UsageIntegrationService {
	return &UsageIntegrationService{
		db:               db,
		subscriptionRepo: subscriptionRepo,
		subItemRepo:      subItemRepo,
		planItemRepo:     planItemRepo,
		entitlementRepo:  entitlementRepo,
		usageRepo:        usageRepo,
		logger:           logger.Named("usage_integration"),
	}
}

// ProcessCheckIn handles a customer check-in event:
// - finds the active subscription item with the given feature key
// - checks if the entitlement limit allows usage
// - creates a usage record and links it to the attendance event
// It expects an already started transaction (tx) to allow atomicity with the attendance event.
func (s *UsageIntegrationService) ProcessCheckIn(
	ctx context.Context,
	tx *sql.Tx, // <-- transaction passed from caller
	companyID, customerID uuid.UUID,
	attendanceEventID uuid.UUID,
	featureKey string,
	quantity decimal.Decimal,
) error {
	s.logger.Debug("ProcessCheckIn called",
		zap.Any("tx_ptr", tx),
		zap.Bool("tx_is_nil", tx == nil),
		zap.String("company_id", companyID.String()),
		zap.String("customer_id", customerID.String()),
		zap.String("attendance_event_id", attendanceEventID.String()),
		zap.String("feature_key", featureKey),
		zap.String("quantity", quantity.String()),
	)

	// Check if transaction is nil
	if tx == nil {
		s.logger.Error("Transaction is nil")
		return fmt.Errorf("transaction is nil")
	}

	// 0. Idempotency: check if an attendance link already exists for this event.
	s.logger.Debug("Checking if attendance link already exists")
	exists, err := s.usageRepo.ExistsAttendanceLink(ctx, tx, attendanceEventID)
	if err != nil {
		s.logger.Error("Failed to check attendance link existence", zap.Error(err))
		return fmt.Errorf("check attendance link existence: %w", err)
	}
	if exists {
		s.logger.Warn("attendance event already linked to a usage; skipping",
			zap.String("attendance_event_id", attendanceEventID.String()))
		return nil
	}

	// 1. Get the active subscription for this customer
	s.logger.Debug("Fetching active subscription for customer")
	subs, err := s.subscriptionRepo.GetByCustomer(ctx, tx, companyID, customerID)
	if err != nil {
		s.logger.Error("Failed to fetch subscriptions", zap.Error(err))
		return fmt.Errorf("fetch subscriptions: %w", err)
	}
	var activeSub *models.Subscription
	for _, sub := range subs {
		if sub.Status == enums.SubStatusActive || sub.Status == enums.SubStatusTrial {
			activeSub = sub
			break
		}
	}
	if activeSub == nil {
		s.logger.Warn("No active subscription found for customer", zap.String("customer_id", customerID.String()))
		return fmt.Errorf("no active subscription found for customer %s", customerID)
	}
	s.logger.Debug("Found active subscription", zap.String("subscription_id", activeSub.SubscriptionID.String()))

	// 2. Get the subscription items for this subscription (only active ones)
	s.logger.Debug("Fetching active subscription items")
	items, err := s.subItemRepo.GetActiveBySubscription(ctx, tx, activeSub.SubscriptionID)
	if err != nil {
		s.logger.Error("Failed to fetch subscription items", zap.Error(err))
		return fmt.Errorf("fetch subscription items: %w", err)
	}
	if len(items) == 0 {
		s.logger.Warn("No subscription items for subscription", zap.String("subscription_id", activeSub.SubscriptionID.String()))
		return fmt.Errorf("no subscription items for subscription %s", activeSub.SubscriptionID)
	}
	s.logger.Debug("Found subscription items", zap.Int("count", len(items)))

	// 3. Find the item that has the required feature as an entitlement
	s.logger.Debug("Searching for entitlement with feature key", zap.String("feature_key", featureKey))
	var targetItem *models.SubscriptionItem
	for _, item := range items {
		entitlements, err := s.entitlementRepo.GetByPlanItem(ctx, tx, item.PlanItemID)
		if err != nil {
			s.logger.Warn("failed to get entitlements for plan item", zap.Error(err), zap.String("plan_item_id", item.PlanItemID.String()))
			continue
		}
		for _, ent := range entitlements {
			if ent.FeatureKey == featureKey && ent.IsEnabled {
				targetItem = item
				break
			}
		}
		if targetItem != nil {
			break
		}
	}
	if targetItem == nil {
		s.logger.Warn("No active entitlement found for feature", zap.String("feature_key", featureKey))
		return fmt.Errorf("no active entitlement for feature '%s' in customer's subscription", featureKey)
	}
	s.logger.Debug("Found target item", zap.String("sub_item_id", targetItem.SubItemID.String()))

	// 4. Check remaining quota for the current period (e.g., month)
	now := time.Now()
	periodStart := time.Date(now.Year(), now.Month(), 1, 0, 0, 0, 0, now.Location())
	periodEnd := periodStart.AddDate(0, 1, 0).Add(-time.Second)

	s.logger.Debug("Checking remaining quota",
		zap.String("period_start", periodStart.String()),
		zap.String("period_end", periodEnd.String()),
	)
	remaining, err := s.usageRepo.GetUsageRemaining(ctx, tx, targetItem.SubItemID, featureKey, periodStart, periodEnd)
	if err != nil {
		s.logger.Error("Failed to get usage remaining", zap.Error(err))
		return fmt.Errorf("get usage remaining: %w", err)
	}
	if remaining == nil || remaining.Remaining.LessThan(quantity) {
		s.logger.Warn("Insufficient quota",
			zap.Any("remaining", remaining),
			zap.String("requested", quantity.String()),
		)
		if remaining == nil {
			return fmt.Errorf("insufficient quota: remaining unavailable")
		}
		return fmt.Errorf("insufficient quota: remaining %s, requested %s", remaining.Remaining.String(), quantity.String())
	}
	s.logger.Debug("Quota sufficient", zap.String("remaining", remaining.Remaining.String()))

	// 5. Create usage record using the provided transaction
	s.logger.Debug("Creating usage record")
	usage := &models.Usage{
		UsageID:            uuid.New(),
		SubscriptionItemID: targetItem.SubItemID,
		FeatureKey:         featureKey,
		QuantityUsed:       quantity,
		PeriodStart:        periodStart,
		PeriodEnd:          periodEnd,
		RecordedAt:         time.Now(),
		SourceType:         stringPtr("attendance"),
		SourceID:           &attendanceEventID,
		CreatedBy:          nil,
	}
	if err := s.usageRepo.Create(ctx, tx, usage); err != nil {
		s.logger.Error("Failed to create usage", zap.Error(err))
		return fmt.Errorf("create usage: %w", err)
	}
	s.logger.Debug("Usage created", zap.String("usage_id", usage.UsageID.String()))

	// 6. Create link
	s.logger.Debug("Creating attendance link")
	link := &models.UsageAttendanceLink{
		LinkID:            uuid.New(),
		UsageID:           usage.UsageID,
		AttendanceEventID: attendanceEventID,
		CreatedAt:         time.Now(),
	}
	if err := s.usageRepo.AddAttendanceLink(ctx, tx, link); err != nil {
		s.logger.Error("Failed to add attendance link", zap.Error(err))
		return fmt.Errorf("add attendance link: %w", err)
	}
	s.logger.Debug("Attendance link created", zap.String("link_id", link.LinkID.String()))

	s.logger.Info("usage recorded for attendance event",
		zap.String("usage_id", usage.UsageID.String()),
		zap.String("attendance_event_id", attendanceEventID.String()),
		zap.String("feature", featureKey),
		zap.String("quantity", quantity.String()),
	)
	return nil
}

func stringPtr(s string) *string { return &s }

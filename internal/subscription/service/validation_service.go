package service

import (
	"context"
	"fmt"
	"time"

	"github.com/google/uuid"
	"go.uber.org/zap"

	"auth-service/internal/client"
	"auth-service/internal/subscription/errors"
	"auth-service/internal/subscription/models"
	"auth-service/internal/subscription/models/enums"
	"auth-service/internal/subscription/repository"
)

// SubscriptionValidationService centralizes all subscription business validations.
type SubscriptionValidationService interface {
	// Entity Validation
	ValidateSubscription(ctx context.Context, companyID, subscriptionID uuid.UUID) (*models.Subscription, error)
	ValidatePlan(ctx context.Context, companyID, planID uuid.UUID) (*models.Plan, error)
	ValidateAddon(ctx context.Context, companyID, addonID uuid.UUID) (*models.Addon, error)
	ValidateTrial(ctx context.Context, subscriptionID uuid.UUID) (*models.Trial, error)

	// Lifecycle Validation
	ValidateActivation(ctx context.Context, subscription *models.Subscription) error
	ValidatePause(ctx context.Context, subscription *models.Subscription) error
	ValidateResume(ctx context.Context, subscription *models.Subscription) error
	ValidateRenew(ctx context.Context, subscription *models.Subscription, renewalDate time.Time) error
	ValidateCancel(ctx context.Context, subscription *models.Subscription) error
	ValidateExpire(ctx context.Context, subscription *models.Subscription) error

	// Plan Changes
	ValidateUpgrade(ctx context.Context, subscription *models.Subscription, targetPlan *models.Plan) error
	ValidateDowngrade(ctx context.Context, subscription *models.Subscription, targetPlan *models.Plan) error
	ValidatePlanChange(ctx context.Context, subscription *models.Subscription, targetPlan *models.Plan) error

	// Business Rules
	ValidateUsageLimits(ctx context.Context, subscriptionID uuid.UUID) error
	ValidateEntitlements(ctx context.Context, subscriptionID uuid.UUID) error
	ValidateTrialEligibility(ctx context.Context, companyID, customerID, planID uuid.UUID) error
	ValidateRenewalEligibility(ctx context.Context, subscription *models.Subscription) error
	ValidateCancellationEligibility(ctx context.Context, subscription *models.Subscription) error
}

type validationService struct {
	subRepo         repository.SubscriptionRepository
	subItemRepo     repository.SubscriptionItemRepository
	planRepo        repository.PlanRepository
	addonRepo       repository.AddonRepository
	trialRepo       repository.TrialRepository
	usageRepo       repository.UsageRepository
	entitlementRepo repository.EntitlementRepository
	pgClient        *client.PostgresClient
	logger          *zap.Logger
}

func NewSubscriptionValidationService(
	subRepo repository.SubscriptionRepository,
	subItemRepo repository.SubscriptionItemRepository,
	planRepo repository.PlanRepository,
	addonRepo repository.AddonRepository,
	trialRepo repository.TrialRepository,
	usageRepo repository.UsageRepository,
	entitlementRepo repository.EntitlementRepository,
	pgClient *client.PostgresClient,
	logger *zap.Logger,
) SubscriptionValidationService {
	return &validationService{
		subRepo:         subRepo,
		subItemRepo:     subItemRepo,
		planRepo:        planRepo,
		addonRepo:       addonRepo,
		trialRepo:       trialRepo,
		usageRepo:       usageRepo,
		entitlementRepo: entitlementRepo,
		pgClient:        pgClient,
		logger:          logger.Named("subscription_validation_service"),
	}
}

// ----------------------------------------------------------------------------
// Entity Validation
// ----------------------------------------------------------------------------

func (s *validationService) ValidateSubscription(ctx context.Context, companyID, subscriptionID uuid.UUID) (*models.Subscription, error) {
	db := s.pgClient.DB
	sub, err := s.subRepo.GetByID(ctx, db, companyID, subscriptionID)
	if err != nil {
		return nil, errors.ErrSubscriptionNotFound
	}
	return sub, nil
}

func (s *validationService) ValidatePlan(ctx context.Context, companyID, planID uuid.UUID) (*models.Plan, error) {
	db := s.pgClient.DB
	plan, err := s.planRepo.GetByID(ctx, db, companyID, planID)
	if err != nil {
		return nil, errors.ErrPlanNotFound
	}
	if !plan.IsActive {
		return nil, errors.ErrPlanInactive
	}
	if plan.PublishedAt == nil {
		return nil, errors.ErrPlanNotPublished
	}
	return plan, nil
}

func (s *validationService) ValidateAddon(ctx context.Context, companyID, addonID uuid.UUID) (*models.Addon, error) {
	db := s.pgClient.DB
	addon, err := s.addonRepo.GetByID(ctx, db, companyID, addonID)
	if err != nil {
		return nil, errors.ErrAddonNotFound
	}
	if !addon.IsActive {
		return nil, errors.ErrAddonInactive
	}
	return addon, nil
}

func (s *validationService) ValidateTrial(ctx context.Context, subscriptionID uuid.UUID) (*models.Trial, error) {
	db := s.pgClient.DB
	trial, err := s.trialRepo.GetBySubscription(ctx, db, subscriptionID)
	if err != nil {
		return nil, errors.ErrTrialNotFound
	}
	if trial.Status != enums.TrialActive {
		return nil, errors.ErrTrialNotActive
	}
	return trial, nil
}

// ----------------------------------------------------------------------------
// Lifecycle Validation
// ----------------------------------------------------------------------------

func (s *validationService) ValidateActivation(ctx context.Context, subscription *models.Subscription) error {
	if subscription == nil {
		return errors.ErrInvalidInput
	}
	switch subscription.Status {
	case enums.SubStatusActive:
		return fmt.Errorf("%w: subscription is already active", errors.ErrInvalidState)
	case enums.SubStatusCancelled:
		return fmt.Errorf("%w: cannot activate a cancelled subscription", errors.ErrInvalidState)
	case enums.SubStatusExpired:
		return fmt.Errorf("%w: cannot activate an expired subscription", errors.ErrInvalidState)
	case enums.SubStatusPending, enums.SubStatusTrial, enums.SubStatusPaused:
		// Allowed
	default:
		return fmt.Errorf("%w: unknown status %s", errors.ErrInvalidStatus, subscription.Status)
	}
	return nil
}

func (s *validationService) ValidatePause(ctx context.Context, subscription *models.Subscription) error {
	if subscription == nil {
		return errors.ErrInvalidInput
	}
	if subscription.Status != enums.SubStatusActive {
		return fmt.Errorf("%w: only active subscriptions can be paused (current: %s)", errors.ErrInvalidState, subscription.Status)
	}
	// Optionally check pause policy (max days, allowed reasons).
	return nil
}

func (s *validationService) ValidateResume(ctx context.Context, subscription *models.Subscription) error {
	if subscription == nil {
		return errors.ErrInvalidInput
	}
	if subscription.Status != enums.SubStatusPaused {
		return fmt.Errorf("%w: only paused subscriptions can be resumed (current: %s)", errors.ErrInvalidState, subscription.Status)
	}
	return nil
}

func (s *validationService) ValidateRenew(ctx context.Context, subscription *models.Subscription, renewalDate time.Time) error {
	if subscription == nil {
		return errors.ErrInvalidInput
	}
	if subscription.Status != enums.SubStatusActive && subscription.Status != enums.SubStatusTrial {
		return fmt.Errorf("%w: only active or trial subscriptions can be renewed (current: %s)", errors.ErrInvalidState, subscription.Status)
	}
	if subscription.EndDate == nil {
		return fmt.Errorf("%w: subscription has no end date", errors.ErrInvalidInput)
	}
	if !renewalDate.After(*subscription.EndDate) {
		return fmt.Errorf("%w: renewal date %v must be after current end date %v", errors.ErrInvalidInput, renewalDate, *subscription.EndDate)
	}
	return nil
}

func (s *validationService) ValidateCancel(ctx context.Context, subscription *models.Subscription) error {
	if subscription == nil {
		return errors.ErrInvalidInput
	}
	if subscription.Status == enums.SubStatusCancelled {
		return fmt.Errorf("%w: subscription already cancelled", errors.ErrInvalidState)
	}
	if subscription.Status == enums.SubStatusExpired {
		return fmt.Errorf("%w: subscription already expired", errors.ErrInvalidState)
	}
	return nil
}

func (s *validationService) ValidateExpire(ctx context.Context, subscription *models.Subscription) error {
	if subscription == nil {
		return errors.ErrInvalidInput
	}
	if subscription.Status == enums.SubStatusExpired || subscription.Status == enums.SubStatusCancelled {
		return fmt.Errorf("%w: subscription already ended", errors.ErrInvalidState)
	}
	if subscription.EndDate == nil {
		return fmt.Errorf("%w: subscription has no end date", errors.ErrInvalidInput)
	}
	return nil
}

// ----------------------------------------------------------------------------
// Plan Changes
// ----------------------------------------------------------------------------

func (s *validationService) ValidateUpgrade(ctx context.Context, subscription *models.Subscription, targetPlan *models.Plan) error {
	if err := s.ValidatePlanChange(ctx, subscription, targetPlan); err != nil {
		return err
	}
	// Additional upgrade-specific rules (e.g., target plan must be "higher" tier).
	// For now, assume caller distinguishes upgrade vs downgrade.
	return nil
}

func (s *validationService) ValidateDowngrade(ctx context.Context, subscription *models.Subscription, targetPlan *models.Plan) error {
	if err := s.ValidatePlanChange(ctx, subscription, targetPlan); err != nil {
		return err
	}
	// Additional downgrade-specific rules.
	return nil
}

func (s *validationService) ValidatePlanChange(ctx context.Context, subscription *models.Subscription, targetPlan *models.Plan) error {
	if subscription == nil || targetPlan == nil {
		return errors.ErrInvalidInput
	}
	if subscription.Status != enums.SubStatusActive && subscription.Status != enums.SubStatusTrial {
		return fmt.Errorf("%w: only active or trial subscriptions can change plan (current: %s)", errors.ErrInvalidState, subscription.Status)
	}
	if subscription.PlanID == targetPlan.PlanID {
		return fmt.Errorf("%w: target plan is the same as current plan", errors.ErrInvalidInput)
	}
	return nil
}

// ----------------------------------------------------------------------------
// Business Rules
// ----------------------------------------------------------------------------

func (s *validationService) ValidateUsageLimits(ctx context.Context, subscriptionID uuid.UUID) error {
	db := s.pgClient.DB
	// Fetch subscription items for this subscription
	items, err := s.subItemRepo.GetBySubscription(ctx, db, subscriptionID)
	if err != nil {
		return err
	}
	for _, item := range items {
		// For each item, get the entitlements (limits)
		entitlements, err := s.entitlementRepo.GetByPlanItem(ctx, db, item.PlanItemID)
		if err != nil {
			return err
		}
		for _, ent := range entitlements {
			if !ent.IsEnabled || ent.LimitValue == nil {
				continue
			}
			// Get current usage for the period (e.g., current month)
			periodStart := time.Now().AddDate(0, 0, -30) // placeholder; should use billing period
			periodEnd := time.Now()
			used, err := s.usageRepo.GetTotalUsage(ctx, db, item.SubItemID, ent.FeatureKey, periodStart, periodEnd)
			if err != nil {
				return err
			}
			if used.GreaterThan(*ent.LimitValue) {
				return fmt.Errorf("%w: usage limit exceeded for feature %s (used %s, limit %s)",
					errors.ErrInvalidState, ent.FeatureKey, used.String(), ent.LimitValue.String())
			}
		}
	}
	return nil
}

func (s *validationService) ValidateEntitlements(ctx context.Context, subscriptionID uuid.UUID) error {
	db := s.pgClient.DB
	items, err := s.subItemRepo.GetBySubscription(ctx, db, subscriptionID)
	if err != nil {
		return err
	}
	for _, item := range items {
		entitlements, err := s.entitlementRepo.GetEnabledByPlanItem(ctx, db, item.PlanItemID)
		if err != nil {
			return err
		}
		if len(entitlements) == 0 {
			// No entitlements – maybe allowed, or maybe should have at least one.
			// We'll treat as valid; if required, the plan definition should enforce.
		}
		// Additional checks: e.g., ensure that all mandatory features are enabled.
	}
	return nil
}

func (s *validationService) ValidateTrialEligibility(ctx context.Context, companyID, customerID, planID uuid.UUID) error {
	db := s.pgClient.DB
	// Check if the customer has already had a trial for this plan or any plan.
	// We need to fetch all subscriptions for this customer and plan.
	// Since we don't have a direct method, we'll use subscriptions list.
	subs, err := s.subRepo.GetByCustomer(ctx, db, companyID, customerID)
	if err != nil {
		return err
	}
	for _, sub := range subs {
		if sub.PlanID == planID {
			// Check if this subscription had a trial
			trial, err := s.trialRepo.GetBySubscription(ctx, db, sub.SubscriptionID)
			if err == nil && trial != nil {
				// Trial exists – not eligible for another trial on same plan.
				return fmt.Errorf("%w: customer already had a trial for this plan", errors.ErrInvalidState)
			}
		}
	}
	// Additional rules: global trial limit per customer, time window, etc.
	return nil
}

func (s *validationService) ValidateRenewalEligibility(ctx context.Context, subscription *models.Subscription) error {
	if subscription == nil {
		return errors.ErrInvalidInput
	}
	if subscription.Status != enums.SubStatusActive {
		return fmt.Errorf("%w: only active subscriptions can be renewed", errors.ErrInvalidState)
	}
	if !subscription.AutoRenew {
		return fmt.Errorf("%w: subscription does not have auto-renew enabled", errors.ErrInvalidState)
	}
	// Could check if within grace period, etc.
	return nil
}

func (s *validationService) ValidateCancellationEligibility(ctx context.Context, subscription *models.Subscription) error {
	if subscription == nil {
		return errors.ErrInvalidInput
	}
	if subscription.Status == enums.SubStatusCancelled {
		return fmt.Errorf("%w: subscription already cancelled", errors.ErrInvalidState)
	}
	if subscription.Status == enums.SubStatusExpired {
		return fmt.Errorf("%w: subscription already expired", errors.ErrInvalidState)
	}
	// Additional: check if minimum commitment period has passed.
	return nil
}

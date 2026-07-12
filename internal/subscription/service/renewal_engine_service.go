package service

import (
	"context"
	"fmt"
	"time"

	"github.com/google/uuid"
	"go.uber.org/zap"

	"auth-service/internal/subscription/errors"
	submodels "auth-service/internal/subscription/models"
	"auth-service/internal/subscription/repository"
)

// RenewalResult encapsulates the outcome of a single renewal attempt.
type RenewalResult struct {
	SubscriptionID uuid.UUID
	InvoiceID      *uuid.UUID // set if invoice was generated
	Renewed        bool       // whether subscription was extended
	InGrace        bool       // whether it's still within grace period
	Error          error      // any error encountered
}

// RenewalEngineService orchestrates the renewal of subscriptions.
type RenewalEngineService struct {
	subRepo           repository.SubscriptionRepository
	planRepo          repository.PlanRepository
	renewalPolicyRepo repository.RenewalPolicyRepository
	billingEngine     *BillingEngineService
	lifecycleService  SubscriptionLifecycleService
	logger            *zap.Logger
}

func NewRenewalEngineService(
	subRepo repository.SubscriptionRepository,
	planRepo repository.PlanRepository,
	renewalPolicyRepo repository.RenewalPolicyRepository,
	billingEngine *BillingEngineService,
	lifecycleService SubscriptionLifecycleService,
	logger *zap.Logger,
) *RenewalEngineService {
	return &RenewalEngineService{
		subRepo:           subRepo,
		planRepo:          planRepo,
		renewalPolicyRepo: renewalPolicyRepo,
		billingEngine:     billingEngine,
		lifecycleService:  lifecycleService,
		logger:            logger.Named("renewal_engine"),
	}
}

// ProcessRenewals processes all subscriptions due for renewal as of the given time.
// This is the primary entry point for the scheduler.
func (s *RenewalEngineService) ProcessRenewals(ctx context.Context, asOf time.Time) ([]RenewalResult, error) {
	logger := s.logger.With(zap.Time("as_of", asOf))
	logger.Info("starting renewal processing")

	subs, err := s.subRepo.GetRenewalDue(ctx, nil, uuid.Nil, asOf)
	if err != nil {
		logger.Error("failed to get renewal due subscriptions", zap.Error(err))
		return nil, fmt.Errorf("get renewal due: %w", err)
	}

	if len(subs) == 0 {
		logger.Info("no subscriptions due for renewal")
		return []RenewalResult{}, nil
	}

	logger.Info("processing renewals", zap.Int("count", len(subs)))

	results := make([]RenewalResult, 0, len(subs))
	for _, sub := range subs {
		// Use the public single-renewal method
		result := s.ProcessRenewal(ctx, sub.CompanyID, sub.SubscriptionID)
		results = append(results, result)
		if result.Error != nil {
			logger.Error("failed to process renewal",
				zap.String("subscription_id", sub.SubscriptionID.String()),
				zap.Error(result.Error),
			)
		} else if result.Renewed {
			logger.Info("subscription renewed successfully",
				zap.String("subscription_id", sub.SubscriptionID.String()),
				zap.String("invoice_id", result.InvoiceID.String()),
			)
		}
	}

	logger.Info("renewal processing completed",
		zap.Int("total", len(results)),
		zap.Int("renewed", countRenewed(results)),
		zap.Int("failed", countFailed(results)),
	)
	return results, nil
}

// ProcessRenewal handles a single subscription renewal.
// This is the public method for admin, retry workers, and trial conversion.
func (s *RenewalEngineService) ProcessRenewal(ctx context.Context, companyID, subscriptionID uuid.UUID) RenewalResult {
	// Fetch the subscription (with lock for consistency)
	sub, err := s.subRepo.GetByIDForUpdate(ctx, nil, companyID, subscriptionID)
	if err != nil {
		return RenewalResult{SubscriptionID: subscriptionID, Error: fmt.Errorf("get subscription: %w", err)}
	}
	if sub == nil {
		return RenewalResult{SubscriptionID: subscriptionID, Error: errors.ErrNotFound}
	}

	result := RenewalResult{SubscriptionID: sub.SubscriptionID}

	// 1. Eligibility
	if !sub.AutoRenew {
		result.Error = fmt.Errorf("auto_renew is false")
		return result
	}

	// 2. Plan & policy
	plan, err := s.planRepo.GetByID(ctx, nil, companyID, sub.PlanID)
	if err != nil {
		result.Error = fmt.Errorf("get plan: %w", err)
		return result
	}
	if plan == nil {
		result.Error = errors.ErrPlanNotFound
		return result
	}

	policy, err := s.renewalPolicyRepo.GetByID(ctx, nil, companyID, plan.RenewalPolicyID)
	if err != nil {
		result.Error = fmt.Errorf("get renewal policy: %w", err)
		return result
	}
	if policy == nil {
		result.Error = fmt.Errorf("renewal policy not found")
		return result
	}

	// 3. Grace period
	now := time.Now()
	if !s.isWithinGracePeriod(sub, policy, now) {
		result.InGrace = false
		_ = s.HandleGracePeriod(ctx, sub)
		return result
	}
	result.InGrace = true

	// 4. Generate invoice
	invoice, err := s.billingEngine.GenerateRenewalInvoice(ctx, companyID, subscriptionID)
	if err != nil {
		result.Error = fmt.Errorf("generate renewal invoice: %w", err)
		_ = s.HandleRenewalFailure(ctx, sub, err)
		return result
	}
	result.InvoiceID = &invoice.InvoiceID

	// 5. Payment (placeholder – to be implemented when BillingEngine supports it)
	// For now we assume payment is collected asynchronously or the invoice is already paid.
	// When ready, uncomment:
	//
	// paid, err := s.billingEngine.CollectInvoicePayment(ctx, invoice.InvoiceID)
	// if err != nil { result.Error = ...; return result }
	// if !paid { _ = s.HandleGracePeriod(ctx, sub); return result }
	// if err := s.billingEngine.MarkInvoicePaid(ctx, invoice.InvoiceID); err != nil { log }

	// 6. Complete renewal
	renewReq := &RenewSubscriptionRequest{
		CompanyID:      companyID,
		SubscriptionID: subscriptionID,
		RenewedBy:      uuid.Nil,
		NewEndDate:     nil,
	}
	if _, err := s.lifecycleService.Renew(ctx, renewReq); err != nil {
		result.Error = fmt.Errorf("lifecycle renew failed: %w", err)
		_ = s.HandleRenewalFailure(ctx, sub, err)
		return result
	}
	result.Renewed = true
	return result
}

// isWithinGracePeriod checks if now is within the grace period after end date.
func (s *RenewalEngineService) isWithinGracePeriod(sub *submodels.Subscription, policy *submodels.RenewalPolicy, now time.Time) bool {
	if sub.EndDate == nil {
		return false
	}
	graceEnd := sub.EndDate.AddDate(0, 0, policy.GraceDays)
	return !now.After(graceEnd)
}

// --- Helper methods (can be extended) ---

func (s *RenewalEngineService) HandleGracePeriod(ctx context.Context, sub *submodels.Subscription) error {
	s.logger.Info("subscription in grace period", zap.String("sub_id", sub.SubscriptionID.String()))
	// TODO: send reminders, apply late fees, etc.
	return nil
}

func (s *RenewalEngineService) HandleRenewalFailure(ctx context.Context, sub *submodels.Subscription, err error) error {
	s.logger.Error("renewal failed", zap.String("sub_id", sub.SubscriptionID.String()), zap.Error(err))
	// TODO: enqueue retry, send admin alert, etc.
	return nil
}

func countRenewed(results []RenewalResult) int {
	c := 0
	for _, r := range results {
		if r.Renewed {
			c++
		}
	}
	return c
}

func countFailed(results []RenewalResult) int {
	c := 0
	for _, r := range results {
		if r.Error != nil {
			c++
		}
	}
	return c
}

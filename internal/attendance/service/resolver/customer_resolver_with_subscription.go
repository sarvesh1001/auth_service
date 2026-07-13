// file: service/resolver/customer_resolver_with_subscription.go

package resolver

import (
	"context"
	"database/sql"
	"fmt"
	"time"

	"github.com/google/uuid"
	"go.uber.org/zap"

	"auth-service/internal/sales/repository"          // customer repo
	"auth-service/internal/subscription/models/enums" // correct enums package
	subRepo "auth-service/internal/subscription/repository"
)

// CustomerResolverWithSubscription validates customer and subscription status.
type CustomerResolverWithSubscription struct {
	db               *sql.DB
	customerRepo     repository.CustomerRepository
	subscriptionRepo subRepo.SubscriptionRepository
	trialRepo        subRepo.TrialRepository
	logger           *zap.Logger
}

func NewCustomerResolverWithSubscription(
	db *sql.DB,
	customerRepo repository.CustomerRepository,
	subscriptionRepo subRepo.SubscriptionRepository,
	trialRepo subRepo.TrialRepository,
	logger *zap.Logger,
) *CustomerResolverWithSubscription {
	return &CustomerResolverWithSubscription{
		db:               db,
		customerRepo:     customerRepo,
		subscriptionRepo: subscriptionRepo,
		trialRepo:        trialRepo,
		logger:           logger,
	}
}

// Resolve implements SubjectResolver.
func (r *CustomerResolverWithSubscription) Resolve(ctx context.Context, companyID uuid.UUID, subjectType string, subjectID uuid.UUID, date time.Time) (*ResolvedSubject, error) {
	if subjectType != SubjectTypeCustomer {
		return nil, fmt.Errorf("customer resolver called with subject_type=%s", subjectType)
	}

	// 1. Check if customer exists and is active
	active, err := r.customerRepo.IsActive(ctx, r.db, companyID, subjectID)
	if err != nil {
		r.logger.Error("failed to check customer active status", zap.Error(err))
		return nil, fmt.Errorf("customer active check: %w", err)
	}
	if !active {
		r.logger.Info("Customer is inactive", zap.String("customer_id", subjectID.String()))
		return &ResolvedSubject{IsActive: false}, nil
	}

	// 2. Fetch all subscriptions for this customer
	subs, err := r.subscriptionRepo.GetByCustomer(ctx, r.db, companyID, subjectID)
	if err != nil {
		r.logger.Error("failed to get subscriptions for customer", zap.Error(err))
		return nil, fmt.Errorf("get subscriptions: %w", err)
	}

	// 3. Determine active subscription and trial status
	var (
		hasActiveSub       bool
		hasActiveTrial     bool
		activeSubID        *uuid.UUID
		trialID            *uuid.UUID
		subscriptionStatus string
	)

	for _, sub := range subs {
		// Consider Active, Trial, or maybe Pending as active? We'll treat Active and Trial as valid.
		if sub.Status == enums.SubStatusActive || sub.Status == enums.SubStatusTrial {
			hasActiveSub = true
			activeSubID = &sub.SubscriptionID
			if sub.Status == enums.SubStatusActive {
				subscriptionStatus = "active"
			} else {
				subscriptionStatus = "trial"
			}
			// Check if this subscription has an active trial (only if subscription is active)
			if sub.Status == enums.SubStatusActive {
				trial, err := r.trialRepo.GetBySubscription(ctx, r.db, sub.SubscriptionID)
				if err == nil && trial != nil && trial.Status == enums.TrialActive {
					hasActiveTrial = true
					trialID = &trial.TrialID
					subscriptionStatus = "trial" // treat as trial if trial is active
				}
			} else if sub.Status == enums.SubStatusTrial {
				trial, _ := r.trialRepo.GetBySubscription(ctx, r.db, sub.SubscriptionID)
				if trial != nil && trial.Status == enums.TrialActive {
					hasActiveTrial = true
					trialID = &trial.TrialID
				}
			}
			break // we only need one active subscription; you can refine if multiple
		}
	}

	// 4. Build ResolvedSubject
	resolved := &ResolvedSubject{
		IsActive:       true,
		Timezone:       "UTC",             // optionally fetch from customer or company
		ScheduleStatus: "not_schedulable", // default for customers
	}

	// Set subscription fields
	if hasActiveSub {
		resolved.SubscriptionStatus = subscriptionStatus
		resolved.SubscriptionID = activeSubID
		resolved.HasActiveSubscription = true
		resolved.HasActiveTrial = hasActiveTrial
		if hasActiveTrial && trialID != nil {
			resolved.TrialID = trialID
		}
	} else {
		resolved.SubscriptionStatus = "no_subscription"
		resolved.HasActiveSubscription = false
	}

	// Optionally, set ScheduleStatus to reflect subscription state for downstream logic
	if hasActiveSub && hasActiveTrial {
		resolved.ScheduleStatus = "trial_active"
	} else if hasActiveSub {
		resolved.ScheduleStatus = "subscription_active"
	} else {
		resolved.ScheduleStatus = "no_active_subscription"
	}

	r.logger.Debug("Customer resolved with subscription status",
		zap.String("customer_id", subjectID.String()),
		zap.String("subscription_status", resolved.SubscriptionStatus),
	)

	return resolved, nil
}

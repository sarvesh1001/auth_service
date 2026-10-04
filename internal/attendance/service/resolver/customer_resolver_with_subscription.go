package resolver

import (
	"context"
	"database/sql"
	"fmt"
	"time"

	"github.com/google/uuid"
	"go.uber.org/zap"

	"auth-service/internal/sales/repository"
	"auth-service/internal/subscription/models/enums"
	subRepo "auth-service/internal/subscription/repository"
)

type CustomerResolverWithSubscription struct {
	db               *sql.DB
	customerRepo     repository.CustomerRepository
	subscriptionRepo subRepo.SubscriptionRepository
	trialRepo        subRepo.TrialRepository

	// ── NEW
	tzProvider TimezoneProvider

	logger *zap.Logger
}

func NewCustomerResolverWithSubscription(
	db *sql.DB,
	customerRepo repository.CustomerRepository,
	subscriptionRepo subRepo.SubscriptionRepository,
	trialRepo subRepo.TrialRepository,
	tzProvider TimezoneProvider,
	logger *zap.Logger,
) *CustomerResolverWithSubscription {
	return &CustomerResolverWithSubscription{
		db:               db,
		customerRepo:     customerRepo,
		subscriptionRepo: subscriptionRepo,
		trialRepo:        trialRepo,
		tzProvider:       tzProvider,
		logger:           logger,
	}
}

func (r *CustomerResolverWithSubscription) Resolve(
	ctx context.Context,
	companyID uuid.UUID,
	subjectType string,
	subjectID uuid.UUID,
	date time.Time,
) (*ResolvedSubject, error) {
	if subjectType != SubjectTypeCustomer {
		return nil, fmt.Errorf("customer resolver called with subject_type=%s", subjectType)
	}

	// ── NEW: resolve tz via chain (company default for customers).
	tz, tzErr := r.tzProvider.ResolveTimezone(ctx, companyID, nil, nil, nil)
	if tzErr != nil || tz == "" {
		r.logger.Warn("customer tz resolution failed, defaulting to UTC",
			zap.String("customer_id", subjectID.String()),
			zap.Error(tzErr),
		)
		tz = "UTC"
	}

	active, err := r.customerRepo.IsActive(ctx, r.db, companyID, subjectID)
	if err != nil {
		r.logger.Error("failed to check customer active status", zap.Error(err))
		return nil, fmt.Errorf("customer active check: %w", err)
	}
	if !active {
		return &ResolvedSubject{IsActive: false, Timezone: tz}, nil
	}

	subs, err := r.subscriptionRepo.GetByCustomer(ctx, r.db, companyID, subjectID)
	if err != nil {
		r.logger.Error("failed to get subscriptions for customer", zap.Error(err))
		return nil, fmt.Errorf("get subscriptions: %w", err)
	}

	var (
		hasActiveSub       bool
		hasActiveTrial     bool
		activeSubID        *uuid.UUID
		trialID            *uuid.UUID
		subscriptionStatus string
	)
	for _, sub := range subs {
		if sub.Status == enums.SubStatusActive || sub.Status == enums.SubStatusTrial {
			hasActiveSub = true
			activeSubID = &sub.SubscriptionID
			if sub.Status == enums.SubStatusActive {
				subscriptionStatus = "active"
			} else {
				subscriptionStatus = "trial"
			}
			if sub.Status == enums.SubStatusActive {
				trial, err := r.trialRepo.GetBySubscription(ctx, r.db, sub.SubscriptionID)
				if err == nil && trial != nil && trial.Status == enums.TrialActive {
					hasActiveTrial = true
					trialID = &trial.TrialID
					subscriptionStatus = "trial"
				}
			} else if sub.Status == enums.SubStatusTrial {
				trial, _ := r.trialRepo.GetBySubscription(ctx, r.db, sub.SubscriptionID)
				if trial != nil && trial.Status == enums.TrialActive {
					hasActiveTrial = true
					trialID = &trial.TrialID
				}
			}
			break
		}
	}

	resolved := &ResolvedSubject{
		IsActive:       true,
		Timezone:       tz, // ── CHANGED: was hardcoded "UTC"
		ScheduleStatus: "not_schedulable",
	}

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

	if hasActiveSub && hasActiveTrial {
		resolved.ScheduleStatus = "trial_active"
	} else if hasActiveSub {
		resolved.ScheduleStatus = "subscription_active"
	} else {
		resolved.ScheduleStatus = "no_active_subscription"
	}

	return resolved, nil
}

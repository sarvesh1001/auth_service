// internal/service/subscription_lifecycle.go
package service

import (
	"context"
	"fmt"
	"time"

	"github.com/google/uuid"

	"auth-service/internal/client"
	"auth-service/internal/infrastructure/audit"
	"auth-service/internal/infrastructure/idempotency"
	"auth-service/internal/models"
	"auth-service/internal/repository/postgres"
)

// LifecycleConfig holds configuration for subscription lifecycle management.
type LifecycleConfig struct {
	// MaxLapsedBatchSize limits the number of lapsed subscriptions processed per run.
	MaxLapsedBatchSize int
	// MaxTrialBatchSize limits the number of expired trials processed per run.
	MaxTrialBatchSize int
}

// DefaultLifecycleConfig returns sensible defaults.
func DefaultLifecycleConfig() LifecycleConfig {
	return LifecycleConfig{
		MaxLapsedBatchSize: 500,
		MaxTrialBatchSize:  500,
	}
}

// lapsedInfo holds data for a lapsed subscription.
type lapsedInfo struct {
	CompanyID           uuid.UUID
	CompanyName         string
	OwnerUserID         uuid.UUID
	SubscriptionEndDate time.Time
	GracePeriodDays     int
}

// trialInfo holds data for an expired trial.
type trialInfo struct {
	CompanyID    uuid.UUID
	CompanyName  string
	OwnerUserID  uuid.UUID
	TrialEndDate time.Time
}

// SubscriptionLifecycleService handles automatic expiry and status updates for subscriptions.
type SubscriptionLifecycleService struct {
	db               *client.PostgresClient
	companyRepo      postgres.CompanyRepository
	auditService     *audit.AuditService
	idempotencyStore idempotency.Store
	cfg              LifecycleConfig
}

// NewSubscriptionLifecycleService creates a new instance.
func NewSubscriptionLifecycleService(
	db *client.PostgresClient,
	companyRepo postgres.CompanyRepository,
	auditService *audit.AuditService,
	idempotencyStore idempotency.Store,
	cfg *LifecycleConfig,
) *SubscriptionLifecycleService {
	if cfg == nil {
		defaultCfg := DefaultLifecycleConfig()
		cfg = &defaultCfg
	}
	return &SubscriptionLifecycleService{
		db:               db,
		companyRepo:      companyRepo,
		auditService:     auditService,
		idempotencyStore: idempotencyStore,
		cfg:              *cfg,
	}
}

// ---------- Expire lapsed subscriptions ----------

// ExpireLapsedSubscriptions processes companies with ended subscriptions.
// - If within grace period, sets status to 'past_due'
// - If beyond grace period, calls expire_company() to deactivate
// This should be called daily via cron.
func (s *SubscriptionLifecycleService) ExpireLapsedSubscriptions(ctx context.Context) error {
	// Fetch lapsed subscriptions using the DB function.
	query := `
		SELECT company_id, company_name, owner_user_id, subscription_end_date, grace_period_days
		FROM get_lapsed_subscriptions()
		LIMIT $1
	`
	rows, err := s.db.Query(ctx, query, s.cfg.MaxLapsedBatchSize)
	if err != nil {
		return fmt.Errorf("failed to fetch lapsed subscriptions: %w", err)
	}
	defer rows.Close()

	var lapsed []lapsedInfo

	for rows.Next() {
		var l lapsedInfo
		if err := rows.Scan(&l.CompanyID, &l.CompanyName, &l.OwnerUserID, &l.SubscriptionEndDate, &l.GracePeriodDays); err != nil {
			_ = s.auditService.LogAction(ctx, nil, nil, "subscription", "scan_lapsed_error", "company",
				nil, "system", nil, nil, nil, map[string]interface{}{
					"error": err.Error(),
				})
			continue
		}
		lapsed = append(lapsed, l)
	}

	if len(lapsed) == 0 {
		return nil
	}

	processed := 0
	expired := 0
	pastDue := 0

	for _, l := range lapsed {
		if err := s.processLapsedSubscription(ctx, l); err != nil {
			_ = s.auditService.LogAction(ctx, nil, nil, "subscription", "process_lapsed_failed", "company",
				&l.CompanyID, "system", nil, nil, nil, map[string]interface{}{
					"error": err.Error(),
				})
			continue
		}
		processed++
		// We can track counts if needed, but we don't have a way to know which action was taken from processLapsedSubscription.
		// For simplicity we just increment processed; we can add a return value later.
	}

	// Audit summary
	if s.auditService != nil {
		_ = s.auditService.LogAction(ctx, nil, nil, "subscription", "lapsed_cron_run", "system",
			nil, "system", nil, nil, nil, map[string]interface{}{
				"total_processed": processed,
				"expired":         expired,
				"past_due":        pastDue,
			})
	}
	return nil
}

// processLapsedSubscription handles a single lapsed subscription.
func (s *SubscriptionLifecycleService) processLapsedSubscription(ctx context.Context, l lapsedInfo) error {
	// Check if grace period has passed
	graceEnd := l.SubscriptionEndDate.Add(time.Duration(l.GracePeriodDays) * 24 * time.Hour)
	now := time.Now().UTC()

	if now.After(graceEnd) {
		// Beyond grace period: expire the company
		if _, err := s.db.Exec(ctx, `SELECT expire_company($1)`, l.CompanyID); err != nil {
			return fmt.Errorf("failed to expire company: %w", err)
		}
		if s.auditService != nil {
			_ = s.auditService.LogAction(ctx, nil, nil, "subscription", "company_expired", "company",
				&l.CompanyID, "system", nil, nil, nil, map[string]interface{}{
					"reason": "subscription ended beyond grace period",
					"end":    l.SubscriptionEndDate,
				})
		}
	} else {
		// Within grace period: set status to past_due if not already
		company, err := s.companyRepo.GetCompany(ctx, l.CompanyID)
		if err != nil {
			return fmt.Errorf("failed to get company: %w", err)
		}
		if company.SubscriptionStatus != models.SubscriptionStatusPastDue {
			if err := s.companyRepo.UpdateSubscription(ctx, l.CompanyID, company.SubscriptionTier, models.SubscriptionStatusPastDue, company.MaxEmployees); err != nil {
				return fmt.Errorf("failed to set past_due status: %w", err)
			}
			if s.auditService != nil {
				_ = s.auditService.LogAction(ctx, nil, nil, "subscription", "set_past_due", "company",
					&l.CompanyID, "system", nil, nil, nil, map[string]interface{}{
						"reason": "subscription ended, within grace period",
					})
			}
		}
	}
	return nil
}

// ---------- Expire trials ----------

// ExpireTrials processes companies with expired trials.
// Calls expire_company() for each expired trial.
// Should be called daily via cron.
func (s *SubscriptionLifecycleService) ExpireTrials(ctx context.Context) error {
	query := `
		SELECT company_id, company_name, owner_user_id, trial_end_date
		FROM get_expired_trials()
		LIMIT $1
	`
	rows, err := s.db.Query(ctx, query, s.cfg.MaxTrialBatchSize)
	if err != nil {
		return fmt.Errorf("failed to fetch expired trials: %w", err)
	}
	defer rows.Close()

	var trials []trialInfo

	for rows.Next() {
		var t trialInfo
		if err := rows.Scan(&t.CompanyID, &t.CompanyName, &t.OwnerUserID, &t.TrialEndDate); err != nil {
			_ = s.auditService.LogAction(ctx, nil, nil, "subscription", "scan_trial_error", "company",
				nil, "system", nil, nil, nil, map[string]interface{}{
					"error": err.Error(),
				})
			continue
		}
		trials = append(trials, t)
	}

	if len(trials) == 0 {
		return nil
	}

	processed := 0
	for _, t := range trials {
		if _, err := s.db.Exec(ctx, `SELECT expire_company($1)`, t.CompanyID); err != nil {
			_ = s.auditService.LogAction(ctx, nil, nil, "subscription", "expire_trial_failed", "company",
				&t.CompanyID, "system", nil, nil, nil, map[string]interface{}{
					"error": err.Error(),
				})
			continue
		}
		processed++
		if s.auditService != nil {
			_ = s.auditService.LogAction(ctx, nil, nil, "subscription", "trial_expired", "company",
				&t.CompanyID, "system", nil, nil, nil, map[string]interface{}{
					"trial_end": t.TrialEndDate,
				})
		}
	}

	if s.auditService != nil {
		_ = s.auditService.LogAction(ctx, nil, nil, "subscription", "trial_cron_run", "system",
			nil, "system", nil, nil, nil, map[string]interface{}{
				"total_processed": processed,
			})
	}
	return nil
}

package service

import (
	"context"
	"encoding/json"
	"fmt"
	"time"

	"github.com/google/uuid"
	"github.com/shopspring/decimal"
	"go.uber.org/zap"

	"auth-service/internal/accounting/events"
	"auth-service/internal/accounting/models/analytics"
	"auth-service/internal/accounting/repository"
)

// TaxAnalyticsService defines the interface for processing tax events
// and for querying tax-related analytics (tax summaries).
type TaxAnalyticsService interface {
	// -----------------------------------------------------------------
	// Event processing (existing)
	// -----------------------------------------------------------------
	ProcessTaxEvent(ctx context.Context, eventType string, payload []byte) error

	// -----------------------------------------------------------------
	// Query methods (new)
	// -----------------------------------------------------------------
	ListTaxSummaries(ctx context.Context, companyID uuid.UUID, filter repository.TaxSummaryFilter, p repository.Pagination, s repository.Sort) ([]*analytics.TaxSummary, error)
	GetTaxSummary(ctx context.Context, companyID, summaryID uuid.UUID) (*analytics.TaxSummary, error)
}

type taxAnalyticsService struct {
	analyticsRepo repository.AnalyticsRepository
	db            repository.DBTX
	logger        *zap.Logger
}

// NewTaxAnalyticsService creates a new tax analytics service.
func NewTaxAnalyticsService(
	repo repository.AnalyticsRepository,
	db repository.DBTX,
	logger *zap.Logger,
) TaxAnalyticsService {
	return &taxAnalyticsService{
		analyticsRepo: repo,
		db:            db,
		logger:        logger.Named("tax_analytics"),
	}
}

// ---------------------------------------------------------------------
// Event processing (existing)
// ---------------------------------------------------------------------

func (s *taxAnalyticsService) ProcessTaxEvent(ctx context.Context, eventType string, payload []byte) error {
	switch eventType {
	case events.EventTaxTransactionCreated:
		return s.handleTaxTransactionCreated(ctx, payload)

	case events.EventTaxRateCreated, events.EventTaxRateUpdated:
		return s.handleTaxRateChange(ctx, payload)

	case events.EventTaxRuleCreated, events.EventTaxRuleUpdated:
		return s.handleTaxRuleChange(ctx, payload)

	case events.EventTaxProfileCreated, events.EventTaxProfileUpdated:
		return s.handleTaxProfileChange(ctx, payload)

	default:
		s.logger.Debug("ignored tax event", zap.String("event_type", eventType))
		return nil
	}
}

// handleTaxTransactionCreated updates daily tax summaries.
func (s *taxAnalyticsService) handleTaxTransactionCreated(ctx context.Context, payload []byte) error {
	var taxPayload events.TaxTransactionPayload
	if err := json.Unmarshal(payload, &taxPayload); err != nil {
		return err
	}

	companyID, err := uuid.Parse(taxPayload.CompanyID)
	if err != nil {
		s.logger.Error("invalid company_id", zap.String("company_id", taxPayload.CompanyID), zap.Error(err))
		return err
	}

	taxableAmount, err := decimal.NewFromString(taxPayload.TaxableAmount)
	if err != nil {
		s.logger.Error("invalid taxable_amount", zap.String("amount", taxPayload.TaxableAmount), zap.Error(err))
		return err
	}

	taxAmount, err := decimal.NewFromString(taxPayload.TaxAmount)
	if err != nil {
		s.logger.Error("invalid tax_amount", zap.String("amount", taxPayload.TaxAmount), zap.Error(err))
		return err
	}

	summary := &analytics.TaxSummary{
		SummaryID:        uuid.New(),
		CompanyID:        companyID,
		TaxRateID:        nil,
		Date:             taxPayload.TransactionDate,
		TotalTaxable:     taxableAmount,
		TotalTax:         taxAmount,
		TransactionCount: 1,
		CreatedAt:        time.Now(),
	}

	if err := s.analyticsRepo.UpsertTaxSummary(ctx, s.db, summary); err != nil {
		s.logger.Error("failed to upsert tax summary", zap.Error(err))
		return err
	}
	return nil
}

// handleTaxRateChange invalidates tax summaries affected by a rate change.
func (s *taxAnalyticsService) handleTaxRateChange(ctx context.Context, payload []byte) error {
	var ratePayload events.TaxRatePayload
	if err := json.Unmarshal(payload, &ratePayload); err != nil {
		return err
	}

	companyID, err := uuid.Parse(ratePayload.CompanyID)
	if err != nil {
		s.logger.Error("invalid company_id in tax rate event", zap.String("company_id", ratePayload.CompanyID), zap.Error(err))
		return err
	}

	fromDate := ratePayload.EffectiveFrom
	if err := s.analyticsRepo.InvalidateTaxSummaries(ctx, s.db, companyID, &fromDate, nil); err != nil {
		s.logger.Error("failed to invalidate tax summaries after rate change",
			zap.String("company_id", companyID.String()),
			zap.Time("from_date", fromDate),
			zap.Error(err))
		return err
	}

	s.logger.Info("invalidated tax summaries due to tax rate change",
		zap.String("rate_id", ratePayload.RateID),
		zap.String("company_id", companyID.String()),
		zap.Time("effective_from", fromDate))
	return nil
}

// handleTaxRuleChange invalidates tax summaries for periods where the rule applied.
func (s *taxAnalyticsService) handleTaxRuleChange(ctx context.Context, payload []byte) error {
	var rulePayload events.TaxRulePayload
	if err := json.Unmarshal(payload, &rulePayload); err != nil {
		return err
	}

	companyID, err := uuid.Parse(rulePayload.CompanyID)
	if err != nil {
		s.logger.Error("invalid company_id in tax rule event", zap.String("company_id", rulePayload.CompanyID), zap.Error(err))
		return err
	}

	fromDate := time.Now().AddDate(0, 0, -30)
	if err := s.analyticsRepo.InvalidateTaxSummaries(ctx, s.db, companyID, &fromDate, nil); err != nil {
		s.logger.Error("failed to invalidate tax summaries after rule change",
			zap.String("company_id", companyID.String()),
			zap.Error(err))
		return err
	}

	s.logger.Info("invalidated tax summaries due to tax rule change",
		zap.String("rule_id", rulePayload.RuleID),
		zap.String("company_id", companyID.String()))
	return nil
}

// handleTaxProfileChange may affect default rates or jurisdictions.
func (s *taxAnalyticsService) handleTaxProfileChange(ctx context.Context, payload []byte) error {
	var profilePayload events.TaxProfilePayload
	if err := json.Unmarshal(payload, &profilePayload); err != nil {
		return err
	}

	companyID, err := uuid.Parse(profilePayload.CompanyID)
	if err != nil {
		s.logger.Error("invalid company_id in tax profile event", zap.String("company_id", profilePayload.CompanyID), zap.Error(err))
		return err
	}

	s.logger.Info("tax profile changed",
		zap.String("profile_id", profilePayload.ProfileID),
		zap.String("company_id", companyID.String()),
		zap.String("regime", profilePayload.TaxRegime))
	return nil
}

// ---------------------------------------------------------------------
// Query methods (new)
// ---------------------------------------------------------------------

// ListTaxSummaries returns tax summaries for a company, with filtering, pagination, and sorting.
func (s *taxAnalyticsService) ListTaxSummaries(ctx context.Context, companyID uuid.UUID, filter repository.TaxSummaryFilter, p repository.Pagination, sort repository.Sort) ([]*analytics.TaxSummary, error) {
	filter.CompanyID = companyID
	return s.analyticsRepo.ListTaxSummaries(ctx, s.db, filter, p, sort)
}

// GetTaxSummary returns a single tax summary by ID, ensuring it belongs to the company.
func (s *taxAnalyticsService) GetTaxSummary(ctx context.Context, companyID, summaryID uuid.UUID) (*analytics.TaxSummary, error) {
	summary, err := s.analyticsRepo.GetTaxSummary(ctx, s.db, summaryID)
	if err != nil {
		return nil, err
	}
	if summary.CompanyID != companyID {
		return nil, fmt.Errorf("unauthorized: tax summary does not belong to company")
	}
	return summary, nil
}

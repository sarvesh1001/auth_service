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
	"auth-service/internal/client"
)

// ComplianceAnalyticsService defines the interface for processing compliance events
// and for querying compliance-related analytics (tax summaries and cashflows).
type ComplianceAnalyticsService interface {
	// -----------------------------------------------------------------
	// Event processing (existing)
	// -----------------------------------------------------------------
	ProcessComplianceEvent(ctx context.Context, eventType string, payload []byte) error

	// -----------------------------------------------------------------
	// Tax Summary queries (populated by compliance events)
	// -----------------------------------------------------------------
	ListTaxSummaries(ctx context.Context, companyID uuid.UUID, filter repository.TaxSummaryFilter, p repository.Pagination, s repository.Sort) ([]*analytics.TaxSummary, error)
	GetTaxSummary(ctx context.Context, companyID, summaryID uuid.UUID) (*analytics.TaxSummary, error)

	// -----------------------------------------------------------------
	// Cashflow queries (populated by compliance payments)
	// -----------------------------------------------------------------
	ListCashflows(ctx context.Context, companyID uuid.UUID, filter repository.CashflowFilter, p repository.Pagination, s repository.Sort) ([]*analytics.Cashflow, error)
	GetCashflow(ctx context.Context, companyID, cashflowID uuid.UUID) (*analytics.Cashflow, error)
}

type complianceAnalyticsService struct {
	analyticsRepo repository.AnalyticsRepository
	pgClient      *client.PostgresClient
	logger        *zap.Logger
}

// NewComplianceAnalyticsService creates a new compliance analytics service.
func NewComplianceAnalyticsService(
	repo repository.AnalyticsRepository,
	pgClient *client.PostgresClient,
	logger *zap.Logger,
) ComplianceAnalyticsService {
	return &complianceAnalyticsService{
		analyticsRepo: repo,
		pgClient:      pgClient,
		logger:        logger.Named("compliance_analytics"),
	}
}

// ---------------------------------------------------------------------
// Event processing
// ---------------------------------------------------------------------

func (s *complianceAnalyticsService) ProcessComplianceEvent(ctx context.Context, eventType string, payload []byte) error {
	switch eventType {
	case events.EventReturnFiled, events.EventReturnAmended:
		var retPayload events.ComplianceReturnPayload
		if err := json.Unmarshal(payload, &retPayload); err != nil {
			return err
		}
		companyID, _ := uuid.Parse(retPayload.CompanyID)
		totalLiability, _ := decimal.NewFromString(retPayload.TotalLiability)
		totalPaid, _ := decimal.NewFromString(retPayload.TotalPaid)

		// Update tax summary analytics
		taxSummary := &analytics.TaxSummary{
			SummaryID:        uuid.New(),
			CompanyID:        companyID,
			TaxRateID:        nil,
			Date:             retPayload.PeriodEnd,
			TotalTaxable:     decimal.Zero,
			TotalTax:         totalLiability,
			TransactionCount: 1,
			CreatedAt:        time.Now(),
		}
		if err := s.analyticsRepo.UpsertTaxSummary(ctx, s.pgClient.DB, taxSummary); err != nil {
			s.logger.Error("failed to upsert tax summary", zap.Error(err))
		}

		// Update cashflow for payments
		if !totalPaid.IsZero() {
			cashflow := &analytics.Cashflow{
				CashflowID:  uuid.New(),
				CompanyID:   companyID,
				Date:        time.Now(),
				Inflow:      decimal.Zero,
				Outflow:     totalPaid,
				NetCashflow: totalPaid.Neg(),
				CreatedAt:   time.Now(),
			}
			if err := s.analyticsRepo.UpsertCashflow(ctx, s.pgClient.DB, cashflow); err != nil {
				s.logger.Error("failed to upsert cashflow", zap.Error(err))
			}
		}
	}
	return nil
}

// ---------------------------------------------------------------------
// Query methods (new)
// ---------------------------------------------------------------------

// Tax Summary queries
func (s *complianceAnalyticsService) ListTaxSummaries(ctx context.Context, companyID uuid.UUID, filter repository.TaxSummaryFilter, p repository.Pagination, sort repository.Sort) ([]*analytics.TaxSummary, error) {
	filter.CompanyID = companyID
	return s.analyticsRepo.ListTaxSummaries(ctx, s.pgClient.DB, filter, p, sort)
}

func (s *complianceAnalyticsService) GetTaxSummary(ctx context.Context, companyID, summaryID uuid.UUID) (*analytics.TaxSummary, error) {
	summary, err := s.analyticsRepo.GetTaxSummary(ctx, s.pgClient.DB, summaryID)
	if err != nil {
		return nil, err
	}
	// Authorisation: ensure summary belongs to the company
	if summary.CompanyID != companyID {
		return nil, fmt.Errorf("unauthorized: tax summary does not belong to company")
	}
	return summary, nil
}

// Cashflow queries
func (s *complianceAnalyticsService) ListCashflows(ctx context.Context, companyID uuid.UUID, filter repository.CashflowFilter, p repository.Pagination, sort repository.Sort) ([]*analytics.Cashflow, error) {
	filter.CompanyID = companyID
	return s.analyticsRepo.ListCashflows(ctx, s.pgClient.DB, filter, p, sort)
}

func (s *complianceAnalyticsService) GetCashflow(ctx context.Context, companyID, cashflowID uuid.UUID) (*analytics.Cashflow, error) {
	cashflow, err := s.analyticsRepo.GetCashflow(ctx, s.pgClient.DB, cashflowID)
	if err != nil {
		return nil, err
	}
	if cashflow.CompanyID != companyID {
		return nil, fmt.Errorf("unauthorized: cashflow record does not belong to company")
	}
	return cashflow, nil
}

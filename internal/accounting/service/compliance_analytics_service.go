package service

import (
	"context"
	"encoding/json"
	"time"

	"github.com/google/uuid"
	"github.com/shopspring/decimal"
	"go.uber.org/zap"

	"auth-service/internal/accounting/events"
	"auth-service/internal/accounting/models/analytics"
	"auth-service/internal/accounting/repository"
	"auth-service/internal/client"
)

type ComplianceAnalyticsService interface {
	ProcessComplianceEvent(ctx context.Context, eventType string, payload []byte) error
}

type complianceAnalyticsService struct {
	analyticsRepo repository.AnalyticsRepository
	pgClient      *client.PostgresClient
	logger        *zap.Logger
}

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
		// Pass DBTX (use the DB connection directly, no transaction needed)
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

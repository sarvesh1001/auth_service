package service

import (
	"context"
	"time"

	"github.com/google/uuid"
	"github.com/shopspring/decimal"
	"go.uber.org/zap"

	"auth-service/internal/accounting/models"
	"auth-service/internal/accounting/models/compliance"
	"auth-service/internal/accounting/models/settings"
	"auth-service/internal/accounting/models/tax"
	"auth-service/internal/accounting/repository"
	"auth-service/internal/client"
	"auth-service/internal/infrastructure/audit"
	"auth-service/internal/infrastructure/idempotency"
	"auth-service/internal/infrastructure/outbox"
)

type AccountingService interface {
	CreateJournal(ctx context.Context, req CreateJournalRequest) (*models.JournalEntry, error)
	UpdateJournal(ctx context.Context, req UpdateJournalRequest) (*models.JournalEntry, error)
	PostJournal(ctx context.Context, journalID uuid.UUID, postedBy *uuid.UUID) error
	ReverseJournal(ctx context.Context, journalID uuid.UUID, reason string, reversedBy *uuid.UUID) error
	GetJournal(ctx context.Context, id uuid.UUID) (*models.JournalEntry, error)
	ListJournals(ctx context.Context, filter repository.JournalFilter, page, pageSize int) ([]*models.JournalEntry, int64, error)
	GetAccountBalance(ctx context.Context, companyID, accountID uuid.UUID, fiscalYear, period int) (*models.AccountBalance, error)
	RecomputeLedger(ctx context.Context, companyID uuid.UUID, fiscalYear int) error
	ComputeTax(ctx context.Context, companyID uuid.UUID, amount decimal.Decimal, taxRateID *uuid.UUID) (*TaxResult, error)
	CreateTaxTransaction(ctx context.Context, req CreateTaxTransactionRequest) (*tax.TaxTransaction, error)
	GetApplicableTaxRate(ctx context.Context, companyID uuid.UUID, date time.Time) (*tax.TaxRate, error)
	CreateReturn(ctx context.Context, req CreateReturnRequest) (*compliance.ComplianceReturn, error)
	SubmitReturn(ctx context.Context, returnID uuid.UUID, submittedBy *uuid.UUID) error
	FileReturn(ctx context.Context, returnID uuid.UUID, req FileReturnRequest) (*compliance.ComplianceFiling, error)
	AmendReturn(ctx context.Context, returnID uuid.UUID, req AmendReturnRequest) (*compliance.ComplianceReturn, error)
	GetReturn(ctx context.Context, id uuid.UUID) (*compliance.ComplianceReturn, error)
	ListReturns(ctx context.Context, filter repository.ComplianceReturnFilter, page, pageSize int) ([]*compliance.ComplianceReturn, int64, error)

	// Accounting Settings management
	GetAccountingSettings(ctx context.Context, companyID uuid.UUID) (*settings.AccountingSettings, error)
	UpdateFiscalYear(ctx context.Context, companyID uuid.UUID, startMonth int, updatedBy *uuid.UUID) error
	UpdateCurrency(ctx context.Context, companyID uuid.UUID, currencyCode string, updatedBy *uuid.UUID) error
	UpdateTaxScheme(ctx context.Context, companyID uuid.UUID, taxScheme string, updatedBy *uuid.UUID) error
}

type accountingService struct {
	journalSvc       JournalService
	ledgerSvc        LedgerService
	taxSvc           TaxEngineService
	complianceSvc    ComplianceService
	settingsRepo     repository.AccountingSettingsRepository
	pgClient         *client.PostgresClient
	logger           *zap.Logger
	outboxRepo       outbox.Repository
	idempotencyStore idempotency.Store
	auditService     *audit.AuditService
}

func NewAccountingService(
	journalSvc JournalService,
	ledgerSvc LedgerService,
	taxSvc TaxEngineService,
	complianceSvc ComplianceService,
	settingsRepo repository.AccountingSettingsRepository,
	pgClient *client.PostgresClient,
	logger *zap.Logger,
	outboxRepo outbox.Repository,
	idempotencyStore idempotency.Store,
	auditService *audit.AuditService,
) AccountingService {
	return &accountingService{
		journalSvc:       journalSvc,
		ledgerSvc:        ledgerSvc,
		taxSvc:           taxSvc,
		complianceSvc:    complianceSvc,
		settingsRepo:     settingsRepo,
		pgClient:         pgClient,
		logger:           logger.Named("accounting_service"),
		outboxRepo:       outboxRepo,
		idempotencyStore: idempotencyStore,
		auditService:     auditService,
	}
}

func (s *accountingService) CreateJournal(ctx context.Context, req CreateJournalRequest) (*models.JournalEntry, error) {
	return s.journalSvc.Create(ctx, req)
}

func (s *accountingService) UpdateJournal(ctx context.Context, req UpdateJournalRequest) (*models.JournalEntry, error) {
	return s.journalSvc.Update(ctx, req)
}

func (s *accountingService) PostJournal(ctx context.Context, journalID uuid.UUID, postedBy *uuid.UUID) error {
	return s.journalSvc.Post(ctx, journalID, postedBy)
}

func (s *accountingService) ReverseJournal(ctx context.Context, journalID uuid.UUID, reason string, reversedBy *uuid.UUID) error {
	return s.journalSvc.Reverse(ctx, journalID, reason, reversedBy)
}

func (s *accountingService) GetJournal(ctx context.Context, id uuid.UUID) (*models.JournalEntry, error) {
	return s.journalSvc.GetByID(ctx, id)
}

func (s *accountingService) ListJournals(ctx context.Context, filter repository.JournalFilter, page, pageSize int) ([]*models.JournalEntry, int64, error) {
	offset := (page - 1) * pageSize
	if offset < 0 {
		offset = 0
	}
	return s.journalSvc.List(ctx, filter, Pagination{Limit: pageSize, Offset: offset})
}

func (s *accountingService) GetAccountBalance(ctx context.Context, companyID, accountID uuid.UUID, fiscalYear, period int) (*models.AccountBalance, error) {
	return s.ledgerSvc.GetAccountBalance(ctx, companyID, accountID, fiscalYear, period)
}

func (s *accountingService) RecomputeLedger(ctx context.Context, companyID uuid.UUID, fiscalYear int) error {
	return s.ledgerSvc.RecomputeBalances(ctx, companyID, fiscalYear)
}

func (s *accountingService) ComputeTax(ctx context.Context, companyID uuid.UUID, amount decimal.Decimal, taxRateID *uuid.UUID) (*TaxResult, error) {
	return s.taxSvc.ComputeTax(ctx, companyID, amount, taxRateID)
}

func (s *accountingService) CreateTaxTransaction(ctx context.Context, req CreateTaxTransactionRequest) (*tax.TaxTransaction, error) {
	return s.taxSvc.CreateTaxTransaction(ctx, req)
}

func (s *accountingService) GetApplicableTaxRate(ctx context.Context, companyID uuid.UUID, date time.Time) (*tax.TaxRate, error) {
	return s.taxSvc.GetApplicableTaxRate(ctx, companyID, date)
}

func (s *accountingService) CreateReturn(ctx context.Context, req CreateReturnRequest) (*compliance.ComplianceReturn, error) {
	return s.complianceSvc.CreateReturn(ctx, req)
}

func (s *accountingService) SubmitReturn(ctx context.Context, returnID uuid.UUID, submittedBy *uuid.UUID) error {
	return s.complianceSvc.SubmitReturn(ctx, returnID, submittedBy)
}

func (s *accountingService) FileReturn(ctx context.Context, returnID uuid.UUID, req FileReturnRequest) (*compliance.ComplianceFiling, error) {
	return s.complianceSvc.FileReturn(ctx, returnID, req)
}

func (s *accountingService) AmendReturn(ctx context.Context, returnID uuid.UUID, req AmendReturnRequest) (*compliance.ComplianceReturn, error) {
	return s.complianceSvc.AmendReturn(ctx, returnID, req)
}

func (s *accountingService) GetReturn(ctx context.Context, id uuid.UUID) (*compliance.ComplianceReturn, error) {
	return s.complianceSvc.GetReturnByID(ctx, id)
}

func (s *accountingService) ListReturns(ctx context.Context, filter repository.ComplianceReturnFilter, page, pageSize int) ([]*compliance.ComplianceReturn, int64, error) {
	offset := (page - 1) * pageSize
	if offset < 0 {
		offset = 0
	}
	return s.complianceSvc.ListReturns(ctx, filter, Pagination{Limit: pageSize, Offset: offset})
}

// ----------------------------------------------------------------------
// Accounting Settings Management
// ----------------------------------------------------------------------

func (s *accountingService) GetAccountingSettings(ctx context.Context, companyID uuid.UUID) (*settings.AccountingSettings, error) {
	if companyID == uuid.Nil {
		return nil, ErrInvalidInput
	}
	settings, err := s.settingsRepo.GetByCompany(ctx, s.pgClient.DB, companyID)
	if err != nil {
		s.logger.Error("failed to get accounting settings", zap.String("company_id", companyID.String()), zap.Error(err))
		return nil, err
	}
	if settings == nil {
		return nil, ErrNotFound
	}
	return settings, nil
}

func (s *accountingService) UpdateFiscalYear(ctx context.Context, companyID uuid.UUID, startMonth int, updatedBy *uuid.UUID) error {
	if companyID == uuid.Nil {
		return ErrInvalidInput
	}
	if startMonth < 1 || startMonth > 12 {
		return ErrInvalidInput
	}
	err := s.settingsRepo.UpdateFiscalYear(ctx, s.pgClient.DB, companyID, startMonth, updatedBy)
	if err != nil {
		s.logger.Error("failed to update fiscal year", zap.String("company_id", companyID.String()), zap.Int("start_month", startMonth), zap.Error(err))
		return err
	}
	if s.auditService != nil {
		_ = s.auditService.LogAction(ctx, nil, &companyID, "settings", "update_fiscal_year", "accounting_settings",
			nil, "user", updatedBy, nil, nil, map[string]interface{}{"start_month": startMonth})
	}
	return nil
}

func (s *accountingService) UpdateCurrency(ctx context.Context, companyID uuid.UUID, currencyCode string, updatedBy *uuid.UUID) error {
	if companyID == uuid.Nil {
		return ErrInvalidInput
	}
	if len(currencyCode) != 3 {
		return ErrInvalidInput
	}
	err := s.settingsRepo.UpdateCurrency(ctx, s.pgClient.DB, companyID, currencyCode, updatedBy)
	if err != nil {
		s.logger.Error("failed to update currency", zap.String("company_id", companyID.String()), zap.String("currency", currencyCode), zap.Error(err))
		return err
	}
	if s.auditService != nil {
		_ = s.auditService.LogAction(ctx, nil, &companyID, "settings", "update_currency", "accounting_settings",
			nil, "user", updatedBy, nil, nil, map[string]interface{}{"currency_code": currencyCode})
	}
	return nil
}

func (s *accountingService) UpdateTaxScheme(ctx context.Context, companyID uuid.UUID, taxScheme string, updatedBy *uuid.UUID) error {
	if companyID == uuid.Nil {
		return ErrInvalidInput
	}
	if taxScheme != "accrual" && taxScheme != "cash" {
		return ErrInvalidInput
	}
	err := s.settingsRepo.UpdateTaxScheme(ctx, s.pgClient.DB, companyID, taxScheme, updatedBy)
	if err != nil {
		s.logger.Error("failed to update tax scheme", zap.String("company_id", companyID.String()), zap.String("tax_scheme", taxScheme), zap.Error(err))
		return err
	}
	if s.auditService != nil {
		_ = s.auditService.LogAction(ctx, nil, &companyID, "settings", "update_tax_scheme", "accounting_settings",
			nil, "user", updatedBy, nil, nil, map[string]interface{}{"tax_scheme": taxScheme})
	}
	return nil
}

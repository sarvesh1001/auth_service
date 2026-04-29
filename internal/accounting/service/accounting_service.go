package service

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"time"

	"github.com/google/uuid"
	"github.com/shopspring/decimal"
	"go.uber.org/zap"

	"auth-service/internal/accounting/events"
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

// AccountingService defines the full accounting interface.
type AccountingService interface {
	// Journal
	CreateJournal(ctx context.Context, req CreateJournalRequest, idempotencyKey string) (*models.JournalEntry, error)
	UpdateJournal(ctx context.Context, req UpdateJournalRequest, idempotencyKey string) (*models.JournalEntry, error)
	PostJournal(ctx context.Context, journalID uuid.UUID, postedBy *uuid.UUID, idempotencyKey string) error
	ReverseJournal(ctx context.Context, journalID uuid.UUID, reason string, reversedBy *uuid.UUID, idempotencyKey string) error
	GetJournal(ctx context.Context, id uuid.UUID) (*models.JournalEntry, error)
	ListJournals(ctx context.Context, filter repository.JournalFilter, page, pageSize int) ([]*models.JournalEntry, int64, error)

	// Ledger
	GetAccountBalance(ctx context.Context, companyID, accountID uuid.UUID, fiscalYear, period int) (*models.AccountBalance, error)
	RecomputeLedger(ctx context.Context, companyID uuid.UUID, fiscalYear int, idempotencyKey string) error

	// Tax
	ComputeTax(ctx context.Context, companyID uuid.UUID, amount decimal.Decimal, taxRateID *uuid.UUID) (*TaxResult, error)
	CreateTaxTransaction(ctx context.Context, req CreateTaxTransactionRequest, idempotencyKey string) (*tax.TaxTransaction, error)
	GetApplicableTaxRate(ctx context.Context, companyID uuid.UUID, date time.Time) (*tax.TaxRate, error)

	// Compliance
	CreateReturn(ctx context.Context, req CreateReturnRequest, idempotencyKey string) (*compliance.ComplianceReturn, error)
	SubmitReturn(ctx context.Context, returnID uuid.UUID, submittedBy *uuid.UUID, idempotencyKey string) error
	FileReturn(ctx context.Context, returnID uuid.UUID, req FileReturnRequest, idempotencyKey string) (*compliance.ComplianceFiling, error)
	AmendReturn(ctx context.Context, returnID uuid.UUID, req AmendReturnRequest, idempotencyKey string) (*compliance.ComplianceReturn, error)
	GetReturn(ctx context.Context, id uuid.UUID) (*compliance.ComplianceReturn, error)
	ListReturns(ctx context.Context, filter repository.ComplianceReturnFilter, page, pageSize int) ([]*compliance.ComplianceReturn, int64, error)

	// Accounting Settings (with idempotency)
	GetAccountingSettings(ctx context.Context, companyID uuid.UUID) (*settings.AccountingSettings, error)
	GetAccountingSettingsForUpdate(ctx context.Context, companyID uuid.UUID) (*settings.AccountingSettings, error)
	CreateAccountingSettings(ctx context.Context, s *settings.AccountingSettings, idempotencyKey string) error
	UpsertAccountingSettings(ctx context.Context, s *settings.AccountingSettings, idempotencyKey string) error
	UpdateAccountingSettings(ctx context.Context, s *settings.AccountingSettings, idempotencyKey string) error
	UpdateFiscalYear(ctx context.Context, companyID uuid.UUID, startMonth int, updatedBy *uuid.UUID, idempotencyKey string) error
	UpdateCurrency(ctx context.Context, companyID uuid.UUID, currencyCode string, updatedBy *uuid.UUID, idempotencyKey string) error
	UpdateTaxScheme(ctx context.Context, companyID uuid.UUID, taxScheme string, updatedBy *uuid.UUID, idempotencyKey string) error
	UpdateFlags(ctx context.Context, companyID uuid.UUID, allowIntercompany, autoReversal bool, updatedBy *uuid.UUID, idempotencyKey string) error
	ExistsAccountingSettings(ctx context.Context, companyID uuid.UUID) (bool, error)
	GetFiscalYearPeriod(ctx context.Context, companyID uuid.UUID, date time.Time) (fiscalYear int, period int, err error)
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

// ----------------------------------------------------------------------
// Journal passthrough (idempotency handled inside journalSvc via its own store)
// Note: we do NOT pass idempotencyKey to underlying journal methods because
// they have their own idempotency handling (e.g., using the same store).
// Instead, we rely on the idempotencyStore in this layer if needed, but for
// journal we assume it's already handled inside journalSvc.
// To keep it simple, we just forward the request without the key.
// ----------------------------------------------------------------------
func (s *accountingService) CreateJournal(ctx context.Context, req CreateJournalRequest, idempotencyKey string) (*models.JournalEntry, error) {
	// Journal service already handles idempotency internally using the same store.
	// We ignore the passed key because journalSvc doesn't accept it.
	return s.journalSvc.Create(ctx, req)
}

func (s *accountingService) UpdateJournal(ctx context.Context, req UpdateJournalRequest, idempotencyKey string) (*models.JournalEntry, error) {
	return s.journalSvc.Update(ctx, req)
}

func (s *accountingService) PostJournal(ctx context.Context, journalID uuid.UUID, postedBy *uuid.UUID, idempotencyKey string) error {
	return s.journalSvc.Post(ctx, journalID, postedBy)
}

func (s *accountingService) ReverseJournal(ctx context.Context, journalID uuid.UUID, reason string, reversedBy *uuid.UUID, idempotencyKey string) error {
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

// ----------------------------------------------------------------------
// Ledger passthrough
// ----------------------------------------------------------------------
func (s *accountingService) GetAccountBalance(ctx context.Context, companyID, accountID uuid.UUID, fiscalYear, period int) (*models.AccountBalance, error) {
	return s.ledgerSvc.GetAccountBalance(ctx, companyID, accountID, fiscalYear, period)
}

func (s *accountingService) RecomputeLedger(ctx context.Context, companyID uuid.UUID, fiscalYear int, idempotencyKey string) error {
	// Idempotency not critical for recompute; just call.
	return s.ledgerSvc.RecomputeBalances(ctx, companyID, fiscalYear)
}

// ----------------------------------------------------------------------
// Tax passthrough
// ----------------------------------------------------------------------
func (s *accountingService) ComputeTax(ctx context.Context, companyID uuid.UUID, amount decimal.Decimal, taxRateID *uuid.UUID) (*TaxResult, error) {
	return s.taxSvc.ComputeTax(ctx, companyID, amount, taxRateID)
}

func (s *accountingService) CreateTaxTransaction(ctx context.Context, req CreateTaxTransactionRequest, idempotencyKey string) (*tax.TaxTransaction, error) {
	// taxSvc might have its own idempotency; ignore key.
	return s.taxSvc.CreateTaxTransaction(ctx, req)
}

func (s *accountingService) GetApplicableTaxRate(ctx context.Context, companyID uuid.UUID, date time.Time) (*tax.TaxRate, error) {
	return s.taxSvc.GetApplicableTaxRate(ctx, companyID, date)
}

// ----------------------------------------------------------------------
// Compliance passthrough
// ----------------------------------------------------------------------
func (s *accountingService) CreateReturn(ctx context.Context, req CreateReturnRequest, idempotencyKey string) (*compliance.ComplianceReturn, error) {
	// complianceSvc already handles idempotency internally using the store.
	return s.complianceSvc.CreateReturn(ctx, req)
}

func (s *accountingService) SubmitReturn(ctx context.Context, returnID uuid.UUID, submittedBy *uuid.UUID, idempotencyKey string) error {
	return s.complianceSvc.SubmitReturn(ctx, returnID, submittedBy)
}

func (s *accountingService) FileReturn(ctx context.Context, returnID uuid.UUID, req FileReturnRequest, idempotencyKey string) (*compliance.ComplianceFiling, error) {
	return s.complianceSvc.FileReturn(ctx, returnID, req)
}

func (s *accountingService) AmendReturn(ctx context.Context, returnID uuid.UUID, req AmendReturnRequest, idempotencyKey string) (*compliance.ComplianceReturn, error) {
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
// Accounting Settings Management (with idempotency & outbox)
// ----------------------------------------------------------------------

// GetAccountingSettings retrieves settings. Returns ErrNotFound if missing.
func (s *accountingService) GetAccountingSettings(ctx context.Context, companyID uuid.UUID) (*settings.AccountingSettings, error) {
	if companyID == uuid.Nil {
		return nil, ErrInvalidInput
	}
	accSettings, err := s.settingsRepo.GetByCompany(ctx, s.pgClient.DB, companyID)
	if err != nil {
		s.logger.Error("failed to get accounting settings", zap.String("company_id", companyID.String()), zap.Error(err))
		return nil, err
	}
	if accSettings == nil {
		return nil, ErrNotFound
	}
	return accSettings, nil
}

// GetAccountingSettingsForUpdate retrieves settings with row-level lock.
func (s *accountingService) GetAccountingSettingsForUpdate(ctx context.Context, companyID uuid.UUID) (*settings.AccountingSettings, error) {
	if companyID == uuid.Nil {
		return nil, ErrInvalidInput
	}
	accSettings, err := s.settingsRepo.GetByCompanyForUpdate(ctx, s.pgClient.DB, companyID)
	if err != nil {
		s.logger.Error("failed to get accounting settings for update", zap.String("company_id", companyID.String()), zap.Error(err))
		return nil, err
	}
	if accSettings == nil {
		return nil, ErrNotFound
	}
	return accSettings, nil
}

// // CreateAccountingSettings creates new settings with idempotency.
// func (s *accountingService) CreateAccountingSettings(ctx context.Context, settings *settings.AccountingSettings, idempotencyKey string) error {
// 	if settings.CompanyID == uuid.Nil {
// 		return ErrInvalidInput
// 	}
// 	if idempotencyKey == "" {
// 		return ErrInvalidInput
// 	}

// 	tx, err := s.pgClient.BeginTx(ctx, nil)
// 	if err != nil {
// 		return fmt.Errorf("begin tx: %w", err)
// 	}
// 	defer tx.Rollback()

// 	// Idempotency check
// 	var existingSettings *settings.AccountingSettings
// 	if err := s.idempotencyStore.Get(ctx, tx, idempotencyKey, &existingSettings); err == nil && existingSettings != nil {
// 		// Already processed
// 		return nil
// 	}

// 	exists, err := s.settingsRepo.Exists(ctx, tx, settings.CompanyID)
// 	if err != nil {
// 		return err
// 	}
// 	if exists {
// 		return ErrDuplicate
// 	}

// 	err = s.settingsRepo.Create(ctx, tx, settings)
// 	if err != nil {
// 		return err
// 	}

// 	// Store idempotency result
// 	_ = s.idempotencyStore.Store(ctx, tx, idempotencyKey, settings)

// 	// Emit outbox event
// 	if err := s.emitSettingsEvent(ctx, tx, settings, events.EventAccountingSettingsCreated); err != nil {
// 		s.logger.Warn("failed to emit settings created event", zap.Error(err))
// 	}

// 	if err := tx.Commit(); err != nil {
// 		return fmt.Errorf("commit tx: %w", err)
// 	}

// 	// Audit (non‑transactional)
// 	if s.auditService != nil {
// 		_ = s.auditService.LogAction(ctx, nil, &settings.CompanyID, "settings", "create", "accounting_settings",
// 			nil, "user", settings.CreatedBy, nil, nil, map[string]interface{}{
// 				"fiscal_year_start_month": settings.FiscalYearStartMonth,
// 				"currency_code":           settings.CurrencyCode,
// 				"tax_scheme":              settings.TaxScheme,
// 			})
// 	}
// 	return nil
// }

// // UpsertAccountingSettings creates or replaces settings with idempotency.
// func (s *accountingService) UpsertAccountingSettings(ctx context.Context, settings *settings.AccountingSettings, idempotencyKey string) error {
// 	if settings.CompanyID == uuid.Nil {
// 		return ErrInvalidInput
// 	}
// 	if idempotencyKey == "" {
// 		return ErrInvalidInput
// 	}

// 	tx, err := s.pgClient.BeginTx(ctx, nil)
// 	if err != nil {
// 		return fmt.Errorf("begin tx: %w", err)
// 	}
// 	defer tx.Rollback()

// 	var existingSettings *settings.AccountingSettings
// 	if err := s.idempotencyStore.Get(ctx, tx, idempotencyKey, &existingSettings); err == nil && existingSettings != nil {
// 		return nil
// 	}

// 	err = s.settingsRepo.Upsert(ctx, tx, settings)
// 	if err != nil {
// 		return err
// 	}

// 	_ = s.idempotencyStore.Store(ctx, tx, idempotencyKey, settings)

// 	if err := s.emitSettingsEvent(ctx, tx, settings, events.EventAccountingSettingsUpdated); err != nil {
// 		s.logger.Warn("failed to emit settings updated event", zap.Error(err))
// 	}

// 	if err := tx.Commit(); err != nil {
// 		return fmt.Errorf("commit tx: %w", err)
// 	}

// 	if s.auditService != nil {
// 		_ = s.auditService.LogAction(ctx, nil, &settings.CompanyID, "settings", "upsert", "accounting_settings",
// 			nil, "user", settings.UpdatedBy, nil, nil, map[string]interface{}{
// 				"fiscal_year_start_month": settings.FiscalYearStartMonth,
// 				"currency_code":           settings.CurrencyCode,
// 				"tax_scheme":              settings.TaxScheme,
// 			})
// 	}
// 	return nil
// }

// // UpdateAccountingSettings performs full update with idempotency.
// func (s *accountingService) UpdateAccountingSettings(ctx context.Context, settings *settings.AccountingSettings, idempotencyKey string) error {
// 	if settings.CompanyID == uuid.Nil {
// 		return ErrInvalidInput
// 	}
// 	if idempotencyKey == "" {
// 		return ErrInvalidInput
// 	}

// 	tx, err := s.pgClient.BeginTx(ctx, nil)
// 	if err != nil {
// 		return fmt.Errorf("begin tx: %w", err)
// 	}
// 	defer tx.Rollback()

// 	var existingSettings *settings.AccountingSettings
// 	if err := s.idempotencyStore.Get(ctx, tx, idempotencyKey, &existingSettings); err == nil && existingSettings != nil {
// 		return nil
// 	}

// 	err = s.settingsRepo.Update(ctx, tx, settings)
// 	if err != nil {
// 		return err
// 	}

// 	_ = s.idempotencyStore.Store(ctx, tx, idempotencyKey, settings)

// 	if err := s.emitSettingsEvent(ctx, tx, settings, events.EventAccountingSettingsUpdated); err != nil {
// 		s.logger.Warn("failed to emit settings updated event", zap.Error(err))
// 	}

// 	if err := tx.Commit(); err != nil {
// 		return fmt.Errorf("commit tx: %w", err)
// 	}

// 	if s.auditService != nil {
// 		_ = s.auditService.LogAction(ctx, nil, &settings.CompanyID, "settings", "full_update", "accounting_settings",
// 			nil, "user", settings.UpdatedBy, nil, nil, map[string]interface{}{
// 				"fiscal_year_start_month": settings.FiscalYearStartMonth,
// 				"currency_code":           settings.CurrencyCode,
// 				"tax_scheme":              settings.TaxScheme,
// 				"allow_intercompany":      settings.AllowIntercompanyJournal,
// 				"auto_reversal":           settings.AutoGenerateReversals,
// 			})
// 	}
// 	return nil
// }

// UpdateFiscalYear updates only the fiscal year start month with idempotency.
func (s *accountingService) UpdateFiscalYear(ctx context.Context, companyID uuid.UUID, startMonth int, updatedBy *uuid.UUID, idempotencyKey string) error {
	if companyID == uuid.Nil || startMonth < 1 || startMonth > 12 {
		return ErrInvalidInput
	}
	if idempotencyKey == "" {
		return ErrInvalidInput
	}

	tx, err := s.pgClient.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("begin tx: %w", err)
	}
	defer tx.Rollback()

	var processed bool
	if err := s.idempotencyStore.Get(ctx, tx, idempotencyKey, &processed); err == nil && processed {
		return nil
	}

	err = s.settingsRepo.UpdateFiscalYear(ctx, tx, companyID, startMonth, updatedBy)
	if err != nil {
		return err
	}

	_ = s.idempotencyStore.Store(ctx, tx, idempotencyKey, true)

	// Emit partial update event (re-fetch full settings)
	if err := s.emitPartialSettingsEvent(ctx, tx, companyID, events.EventAccountingSettingsUpdated); err != nil {
		s.logger.Warn("failed to emit settings event after fiscal year update", zap.Error(err))
	}

	if err := tx.Commit(); err != nil {
		return fmt.Errorf("commit tx: %w", err)
	}

	if s.auditService != nil {
		_ = s.auditService.LogAction(ctx, nil, &companyID, "settings", "update_fiscal_year", "accounting_settings",
			nil, "user", updatedBy, nil, nil, map[string]interface{}{"start_month": startMonth})
	}
	return nil
}

// UpdateCurrency updates the functional currency with idempotency.
func (s *accountingService) UpdateCurrency(ctx context.Context, companyID uuid.UUID, currencyCode string, updatedBy *uuid.UUID, idempotencyKey string) error {
	if companyID == uuid.Nil || len(currencyCode) != 3 {
		return ErrInvalidInput
	}
	if idempotencyKey == "" {
		return ErrInvalidInput
	}

	tx, err := s.pgClient.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("begin tx: %w", err)
	}
	defer tx.Rollback()

	var processed bool
	if err := s.idempotencyStore.Get(ctx, tx, idempotencyKey, &processed); err == nil && processed {
		return nil
	}

	err = s.settingsRepo.UpdateCurrency(ctx, tx, companyID, currencyCode, updatedBy)
	if err != nil {
		return err
	}

	_ = s.idempotencyStore.Store(ctx, tx, idempotencyKey, true)

	if err := s.emitPartialSettingsEvent(ctx, tx, companyID, events.EventAccountingSettingsUpdated); err != nil {
		s.logger.Warn("failed to emit settings event after currency update", zap.Error(err))
	}

	if err := tx.Commit(); err != nil {
		return fmt.Errorf("commit tx: %w", err)
	}

	if s.auditService != nil {
		_ = s.auditService.LogAction(ctx, nil, &companyID, "settings", "update_currency", "accounting_settings",
			nil, "user", updatedBy, nil, nil, map[string]interface{}{"currency_code": currencyCode})
	}
	return nil
}

// UpdateTaxScheme updates the tax scheme with idempotency.
func (s *accountingService) UpdateTaxScheme(ctx context.Context, companyID uuid.UUID, taxScheme string, updatedBy *uuid.UUID, idempotencyKey string) error {
	if companyID == uuid.Nil || (taxScheme != "accrual" && taxScheme != "cash") {
		return ErrInvalidInput
	}
	if idempotencyKey == "" {
		return ErrInvalidInput
	}

	tx, err := s.pgClient.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("begin tx: %w", err)
	}
	defer tx.Rollback()

	var processed bool
	if err := s.idempotencyStore.Get(ctx, tx, idempotencyKey, &processed); err == nil && processed {
		return nil
	}

	err = s.settingsRepo.UpdateTaxScheme(ctx, tx, companyID, taxScheme, updatedBy)
	if err != nil {
		return err
	}

	_ = s.idempotencyStore.Store(ctx, tx, idempotencyKey, true)

	if err := s.emitPartialSettingsEvent(ctx, tx, companyID, events.EventAccountingSettingsUpdated); err != nil {
		s.logger.Warn("failed to emit settings event after tax scheme update", zap.Error(err))
	}

	if err := tx.Commit(); err != nil {
		return fmt.Errorf("commit tx: %w", err)
	}

	if s.auditService != nil {
		_ = s.auditService.LogAction(ctx, nil, &companyID, "settings", "update_tax_scheme", "accounting_settings",
			nil, "user", updatedBy, nil, nil, map[string]interface{}{"tax_scheme": taxScheme})
	}
	return nil
}

// UpdateFlags updates boolean flags with idempotency.
func (s *accountingService) UpdateFlags(ctx context.Context, companyID uuid.UUID, allowIntercompany, autoReversal bool, updatedBy *uuid.UUID, idempotencyKey string) error {
	if companyID == uuid.Nil {
		return ErrInvalidInput
	}
	if idempotencyKey == "" {
		return ErrInvalidInput
	}

	tx, err := s.pgClient.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("begin tx: %w", err)
	}
	defer tx.Rollback()

	var processed bool
	if err := s.idempotencyStore.Get(ctx, tx, idempotencyKey, &processed); err == nil && processed {
		return nil
	}

	err = s.settingsRepo.UpdateFlags(ctx, tx, companyID, allowIntercompany, autoReversal, updatedBy)
	if err != nil {
		return err
	}

	_ = s.idempotencyStore.Store(ctx, tx, idempotencyKey, true)

	if err := s.emitPartialSettingsEvent(ctx, tx, companyID, events.EventAccountingSettingsUpdated); err != nil {
		s.logger.Warn("failed to emit settings event after flags update", zap.Error(err))
	}

	if err := tx.Commit(); err != nil {
		return fmt.Errorf("commit tx: %w", err)
	}

	if s.auditService != nil {
		_ = s.auditService.LogAction(ctx, nil, &companyID, "settings", "update_flags", "accounting_settings",
			nil, "user", updatedBy, nil, nil, map[string]interface{}{
				"allow_intercompany_journal": allowIntercompany,
				"auto_generate_reversals":    autoReversal,
			})
	}
	return nil
}

// ExistsAccountingSettings checks if settings exist.
func (s *accountingService) ExistsAccountingSettings(ctx context.Context, companyID uuid.UUID) (bool, error) {
	if companyID == uuid.Nil {
		return false, ErrInvalidInput
	}
	return s.settingsRepo.Exists(ctx, s.pgClient.DB, companyID)
}

// GetFiscalYearPeriod returns fiscal year and period.
func (s *accountingService) GetFiscalYearPeriod(ctx context.Context, companyID uuid.UUID, date time.Time) (fiscalYear int, period int, err error) {
	if companyID == uuid.Nil {
		return 0, 0, ErrInvalidInput
	}
	return s.settingsRepo.GetFiscalYear(ctx, s.pgClient.DB, companyID, date)
}

// ----------------------------------------------------------------------
// Helpers for outbox events
// ----------------------------------------------------------------------

// emitSettingsEvent stores an outbox event for the full settings object.
func (s *accountingService) emitSettingsEvent(ctx context.Context, tx *sql.Tx, settings *settings.AccountingSettings, eventType string) error {
	if s.outboxRepo == nil {
		return nil
	}
	payload, err := json.Marshal(settings)
	if err != nil {
		return err
	}
	event := &outbox.Event{
		EventID:       uuid.New().String(),
		AggregateType: "accounting_settings",
		AggregateID:   settings.CompanyID.String(),
		EventType:     eventType,
		Topic:         TopicAccountingEvents,
		Payload:       payload,
		Status:        "pending",
	}
	return s.outboxRepo.Store(ctx, tx, event)
}

// emitPartialSettingsEvent fetches fresh settings and emits an event.
func (s *accountingService) emitPartialSettingsEvent(ctx context.Context, tx *sql.Tx, companyID uuid.UUID, eventType string) error {
	var accSettings *settings.AccountingSettings
	var err error
	if tx != nil {
		accSettings, err = s.settingsRepo.GetByCompany(ctx, tx, companyID)
	} else {
		accSettings, err = s.settingsRepo.GetByCompany(ctx, s.pgClient.DB, companyID)
	}
	if err != nil {
		return err
	}
	if accSettings == nil {
		return nil
	}
	return s.emitSettingsEvent(ctx, tx, accSettings, eventType)
}

// CreateAccountingSettings creates new settings with idempotency.
func (s *accountingService) CreateAccountingSettings(ctx context.Context, accSettings *settings.AccountingSettings, idempotencyKey string) error {
	logger := s.logger.With(
		zap.String("method", "CreateAccountingSettings"),
		zap.String("company_id", accSettings.CompanyID.String()),
		zap.String("idempotency_key", idempotencyKey),
	)

	if accSettings.CompanyID == uuid.Nil {
		return ErrInvalidInput
	}
	if idempotencyKey == "" {
		return ErrInvalidInput
	}

	tx, err := s.pgClient.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("begin tx: %w", err)
	}
	defer tx.Rollback()

	// 1. Idempotency check
	var existing *settings.AccountingSettings
	errGet := s.idempotencyStore.Get(ctx, tx, idempotencyKey, &existing)
	if errGet == nil && existing != nil {
		logger.Info("Idempotent request detected – returning cached response")
		return nil
	}
	if errGet != nil {
		logger.Warn("IdempotencyStore.Get failed", zap.Error(errGet))
	} else {
		logger.Debug("IdempotencyStore.Get returned no existing record")
	}

	// 2. Check if settings already exist for this company
	exists, err := s.settingsRepo.Exists(ctx, tx, accSettings.CompanyID)
	if err != nil {
		logger.Error("Failed to check existence", zap.Error(err))
		return err
	}
	if exists {
		logger.Warn("Settings already exist for company – returning duplicate error")
		return ErrDuplicate
	}
	logger.Debug("No existing settings found for company")

	// 3. Create the settings
	err = s.settingsRepo.Create(ctx, tx, accSettings)
	if err != nil {
		logger.Error("Failed to create settings", zap.Error(err))
		return err
	}
	logger.Info("Settings created in database")

	// 4. Store idempotency record
	errStore := s.idempotencyStore.Store(ctx, tx, idempotencyKey, accSettings)
	if errStore != nil {
		logger.Error("Failed to store idempotency record", zap.Error(errStore))
		// Do not fail the whole operation – the data is already committed
	} else {
		logger.Debug("Idempotency record stored successfully")
	}

	// 5. Emit outbox event (non‑critical)
	if err := s.emitSettingsEvent(ctx, tx, accSettings, events.EventAccountingSettingsCreated); err != nil {
		logger.Warn("Failed to emit settings created event", zap.Error(err))
	}

	// 6. Commit transaction
	if err := tx.Commit(); err != nil {
		logger.Error("Transaction commit failed", zap.Error(err))
		return fmt.Errorf("commit tx: %w", err)
	}

	logger.Info("Accounting settings created successfully")

	// 7. Audit log (after commit)
	if s.auditService != nil {
		_ = s.auditService.LogAction(ctx, nil, &accSettings.CompanyID, "settings", "create", "accounting_settings",
			nil, "user", accSettings.CreatedBy, nil, nil, map[string]interface{}{
				"fiscal_year_start_month": accSettings.FiscalYearStartMonth,
				"currency_code":           accSettings.CurrencyCode,
				"tax_scheme":              accSettings.TaxScheme,
			})
	}

	return nil
}

// UpsertAccountingSettings creates or replaces settings with idempotency.
func (s *accountingService) UpsertAccountingSettings(ctx context.Context, accSettings *settings.AccountingSettings, idempotencyKey string) error {
	if accSettings.CompanyID == uuid.Nil {
		return ErrInvalidInput
	}
	if idempotencyKey == "" {
		return ErrInvalidInput
	}

	tx, err := s.pgClient.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("begin tx: %w", err)
	}
	defer tx.Rollback()

	var existing *settings.AccountingSettings
	if err := s.idempotencyStore.Get(ctx, tx, idempotencyKey, &existing); err == nil && existing != nil {
		return nil
	}

	err = s.settingsRepo.Upsert(ctx, tx, accSettings)
	if err != nil {
		return err
	}

	_ = s.idempotencyStore.Store(ctx, tx, idempotencyKey, accSettings)

	if err := s.emitSettingsEvent(ctx, tx, accSettings, events.EventAccountingSettingsUpdated); err != nil {
		s.logger.Warn("failed to emit settings updated event", zap.Error(err))
	}

	if err := tx.Commit(); err != nil {
		return fmt.Errorf("commit tx: %w", err)
	}

	if s.auditService != nil {
		_ = s.auditService.LogAction(ctx, nil, &accSettings.CompanyID, "settings", "upsert", "accounting_settings",
			nil, "user", accSettings.UpdatedBy, nil, nil, map[string]interface{}{
				"fiscal_year_start_month": accSettings.FiscalYearStartMonth,
				"currency_code":           accSettings.CurrencyCode,
				"tax_scheme":              accSettings.TaxScheme,
			})
	}
	return nil
}

// UpdateAccountingSettings performs full update with idempotency.
func (s *accountingService) UpdateAccountingSettings(ctx context.Context, accSettings *settings.AccountingSettings, idempotencyKey string) error {
	if accSettings.CompanyID == uuid.Nil {
		return ErrInvalidInput
	}
	if idempotencyKey == "" {
		return ErrInvalidInput
	}

	tx, err := s.pgClient.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("begin tx: %w", err)
	}
	defer tx.Rollback()

	var existing *settings.AccountingSettings
	if err := s.idempotencyStore.Get(ctx, tx, idempotencyKey, &existing); err == nil && existing != nil {
		return nil
	}

	err = s.settingsRepo.Update(ctx, tx, accSettings)
	if err != nil {
		return err
	}

	_ = s.idempotencyStore.Store(ctx, tx, idempotencyKey, accSettings)

	if err := s.emitSettingsEvent(ctx, tx, accSettings, events.EventAccountingSettingsUpdated); err != nil {
		s.logger.Warn("failed to emit settings updated event", zap.Error(err))
	}

	if err := tx.Commit(); err != nil {
		return fmt.Errorf("commit tx: %w", err)
	}

	if s.auditService != nil {
		_ = s.auditService.LogAction(ctx, nil, &accSettings.CompanyID, "settings", "full_update", "accounting_settings",
			nil, "user", accSettings.UpdatedBy, nil, nil, map[string]interface{}{
				"fiscal_year_start_month": accSettings.FiscalYearStartMonth,
				"currency_code":           accSettings.CurrencyCode,
				"tax_scheme":              accSettings.TaxScheme,
				"allow_intercompany":      accSettings.AllowIntercompanyJournal,
				"auto_reversal":           accSettings.AutoGenerateReversals,
			})
	}
	return nil
}

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
	"auth-service/internal/accounting/models"
	"auth-service/internal/accounting/models/enums"
	"auth-service/internal/accounting/repository"
	"auth-service/internal/client"
	"auth-service/internal/infrastructure/audit"
	"auth-service/internal/infrastructure/idempotency"
	"auth-service/internal/infrastructure/outbox"
)

// JournalService defines the journal entry operations
type JournalService interface {
	Create(ctx context.Context, req CreateJournalRequest) (*models.JournalEntry, error)
	Update(ctx context.Context, req UpdateJournalRequest) (*models.JournalEntry, error)
	Post(ctx context.Context, id uuid.UUID, postedBy *uuid.UUID) error
	Reverse(ctx context.Context, id uuid.UUID, reason string, reversedBy *uuid.UUID) error
	GetByID(ctx context.Context, id uuid.UUID) (*models.JournalEntry, error)
	List(ctx context.Context, filter repository.JournalFilter, p Pagination) ([]*models.JournalEntry, int64, error)
	Delete(ctx context.Context, id uuid.UUID, deletedBy *uuid.UUID) error
}

type journalService struct {
	repo             repository.JournalRepository
	ledgerService    LedgerService
	pgClient         *client.PostgresClient
	logger           *zap.Logger
	outboxRepo       outbox.Repository
	idempotencyStore idempotency.Store
	auditService     *audit.AuditService
}

// NewJournalService creates a new journal service instance
func NewJournalService(
	repo repository.JournalRepository,
	ledgerService LedgerService,
	pgClient *client.PostgresClient,
	logger *zap.Logger,
	outboxRepo outbox.Repository,
	idempotencyStore idempotency.Store,
	auditService *audit.AuditService,
) JournalService {
	return &journalService{
		repo:             repo,
		ledgerService:    ledgerService,
		pgClient:         pgClient,
		logger:           logger.Named("journal_service"),
		outboxRepo:       outboxRepo,
		idempotencyStore: idempotencyStore,
		auditService:     auditService,
	}
}

// Create creates a new draft journal entry with source tracking and uniqueness enforcement
func (s *journalService) Create(ctx context.Context, req CreateJournalRequest) (*models.JournalEntry, error) {
	logger := s.logger.With(zap.String("method", "Create"), zap.String("company_id", req.CompanyID.String()))
	idempotencyKey, _ := ctx.Value("idempotency_key").(string)

	if err := s.validateJournal(req); err != nil {
		return nil, err
	}

	tx, err := s.pgClient.BeginTx(ctx, nil)
	if err != nil {
		return nil, fmt.Errorf("begin tx: %w", err)
	}
	defer tx.Rollback()

	if idempotencyKey != "" {
		var existing *models.JournalEntry
		if err := s.idempotencyStore.Get(ctx, tx, idempotencyKey, &existing); err == nil && existing != nil {
			logger.Info("idempotent request, returning cached response")
			return existing, nil
		}
	}

	// Enforce source uniqueness
	if req.SourceType != nil && req.SourceID != nil {
		exists, err := s.repo.ExistsBySource(ctx, tx, req.CompanyID, *req.SourceType, *req.SourceID)
		if err != nil {
			return nil, fmt.Errorf("check source uniqueness: %w", err)
		}
		if exists {
			return nil, fmt.Errorf("%w: journal already exists for source %s/%s", ErrDuplicate, *req.SourceType, req.SourceID.String())
		}
	}

	journal := &models.JournalEntry{
		JournalEntryID: uuid.New(),
		CompanyID:      req.CompanyID,
		JournalType:    req.JournalType,
		EntryDate:      req.EntryDate,
		Reference:      req.Reference,
		Description:    req.Description,
		Status:         enums.JournalStatusDraft,
		CreatedBy:      req.CreatedBy,
		UpdatedBy:      req.UpdatedBy,
		SourceType:     req.SourceType,
		SourceID:       req.SourceID,
	}

	if err := s.repo.Create(ctx, tx, journal); err != nil {
		return nil, fmt.Errorf("create entry: %w", err)
	}

	lines := make([]*models.JournalLine, len(req.Lines))
	for i, lineReq := range req.Lines {
		lines[i] = &models.JournalLine{
			JournalLineID:  uuid.New(),
			JournalEntryID: journal.JournalEntryID,
			AccountID:      lineReq.AccountID,
			LineNumber:     i + 1,
			DebitAmount:    lineReq.DebitAmount,
			CreditAmount:   lineReq.CreditAmount,
			Description:    lineReq.Description,
		}
	}
	if err := s.repo.BulkAddLines(ctx, tx, lines); err != nil {
		return nil, fmt.Errorf("create lines: %w", err)
	}

	payload, _ := json.Marshal(events.JournalEventPayload{
		JournalEntryID: journal.JournalEntryID.String(),
		CompanyID:      journal.CompanyID.String(),
		JournalType:    journal.JournalType,
		EntryDate:      journal.EntryDate,
		TotalDebit:     req.TotalDebit().String(),
		TotalCredit:    req.TotalCredit().String(),
		Status:         journal.Status,
	})

	outboxEvent := &outbox.Event{
		EventID:       uuid.New().String(),
		AggregateType: "journal_entry",
		AggregateID:   journal.JournalEntryID.String(),
		EventType:     events.EventJournalCreated,
		Payload:       payload,
		Status:        "pending",
	}
	if err := s.outboxRepo.Store(ctx, tx, outboxEvent); err != nil {
		return nil, fmt.Errorf("store outbox event: %w", err)
	}

	if idempotencyKey != "" {
		_ = s.idempotencyStore.Store(ctx, tx, idempotencyKey, journal)
	}

	if err := tx.Commit(); err != nil {
		return nil, fmt.Errorf("commit tx: %w", err)
	}

	if s.auditService != nil {
		_ = s.auditService.LogAction(ctx, nil, &req.CompanyID, "accounting", "create", "journal_entry",
			&journal.JournalEntryID, "user", req.CreatedBy, nil, nil, nil)
	}

	logger.Info("journal entry created", zap.String("journal_id", journal.JournalEntryID.String()))
	return journal, nil
}

// Update modifies a draft journal entry (source fields are immutable)
func (s *journalService) Update(ctx context.Context, req UpdateJournalRequest) (*models.JournalEntry, error) {
	logger := s.logger.With(zap.String("method", "Update"), zap.String("journal_id", req.JournalEntryID.String()))
	idempotencyKey, _ := ctx.Value("idempotency_key").(string)

	if req.JournalEntryID == uuid.Nil {
		return nil, fmt.Errorf("%w: journal_entry_id is required", ErrInvalidInput)
	}

	tx, err := s.pgClient.BeginTx(ctx, nil)
	if err != nil {
		return nil, fmt.Errorf("begin tx: %w", err)
	}
	defer tx.Rollback()

	if idempotencyKey != "" {
		var existing *models.JournalEntry
		if err := s.idempotencyStore.Get(ctx, tx, idempotencyKey, &existing); err == nil && existing != nil {
			logger.Info("idempotent request, returning cached response")
			return existing, nil
		}
	}

	existing, err := s.repo.GetByIDForUpdate(ctx, tx, req.JournalEntryID)
	if err != nil {
		return nil, fmt.Errorf("get entry for update: %w", err)
	}
	if existing == nil {
		return nil, fmt.Errorf("%w: journal entry %s", ErrNotFound, req.JournalEntryID)
	}
	if existing.Status != enums.JournalStatusDraft {
		return nil, fmt.Errorf("%w: cannot update journal entry in status %s", ErrInvalidState, existing.Status)
	}

	if req.EntryDate != nil {
		existing.EntryDate = *req.EntryDate
	}
	if req.Reference != nil {
		existing.Reference = req.Reference
	}
	if req.Description != nil {
		existing.Description = req.Description
	}
	existing.UpdatedBy = req.UpdatedBy

	if err := s.repo.Update(ctx, tx, existing); err != nil {
		return nil, fmt.Errorf("update entry: %w", err)
	}

	if req.Lines != nil {
		if err := s.repo.ClearLines(ctx, tx, existing.JournalEntryID); err != nil {
			return nil, fmt.Errorf("delete old lines: %w", err)
		}
		lines := make([]*models.JournalLine, len(req.Lines))
		for i, lineReq := range req.Lines {
			lines[i] = &models.JournalLine{
				JournalLineID:  uuid.New(),
				JournalEntryID: existing.JournalEntryID,
				AccountID:      lineReq.AccountID,
				LineNumber:     i + 1,
				DebitAmount:    lineReq.DebitAmount,
				CreditAmount:   lineReq.CreditAmount,
				Description:    lineReq.Description,
			}
		}
		if err := s.repo.BulkAddLines(ctx, tx, lines); err != nil {
			return nil, fmt.Errorf("create new lines: %w", err)
		}
	}

	payload, _ := json.Marshal(events.JournalEventPayload{
		JournalEntryID: existing.JournalEntryID.String(),
		CompanyID:      existing.CompanyID.String(),
		JournalType:    existing.JournalType,
		EntryDate:      existing.EntryDate,
		Status:         existing.Status,
	})

	outboxEvent := &outbox.Event{
		EventID:       uuid.New().String(),
		AggregateType: "journal_entry",
		AggregateID:   existing.JournalEntryID.String(),
		EventType:     events.EventJournalUpdated,
		Payload:       payload,
		Status:        "pending",
	}
	if err := s.outboxRepo.Store(ctx, tx, outboxEvent); err != nil {
		return nil, fmt.Errorf("store outbox event: %w", err)
	}

	if idempotencyKey != "" {
		_ = s.idempotencyStore.Store(ctx, tx, idempotencyKey, existing)
	}

	if err := tx.Commit(); err != nil {
		return nil, fmt.Errorf("commit tx: %w", err)
	}

	if s.auditService != nil {
		_ = s.auditService.LogAction(ctx, nil, &existing.CompanyID, "accounting", "update", "journal_entry",
			&existing.JournalEntryID, "user", req.UpdatedBy, nil, nil, nil)
	}

	logger.Info("journal entry updated")
	return existing, nil
}

// Post changes status from draft to posted and updates ledger balances
func (s *journalService) Post(ctx context.Context, id uuid.UUID, postedBy *uuid.UUID) error {
	logger := s.logger.With(zap.String("method", "Post"), zap.String("journal_id", id.String()))
	idempotencyKey, _ := ctx.Value("idempotency_key").(string)

	tx, err := s.pgClient.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("begin tx: %w", err)
	}
	defer tx.Rollback()

	if idempotencyKey != "" {
		var processed bool
		if err := s.idempotencyStore.Get(ctx, tx, idempotencyKey, &processed); err == nil && processed {
			logger.Info("idempotent request, already posted")
			return nil
		}
	}

	entry, err := s.repo.GetByIDForUpdate(ctx, tx, id)
	if err != nil {
		return fmt.Errorf("get entry: %w", err)
	}
	if entry == nil {
		return fmt.Errorf("%w: journal entry %s", ErrNotFound, id)
	}
	if entry.Status != enums.JournalStatusDraft {
		return fmt.Errorf("%w: journal entry already %s", ErrInvalidState, entry.Status)
	}

	lines, err := s.repo.GetLines(ctx, tx, id)
	if err != nil {
		return fmt.Errorf("get lines: %w", err)
	}
	if len(lines) == 0 {
		return fmt.Errorf("%w: journal entry has no lines", ErrInvalidState)
	}

	totalDebit := decimal.Zero
	totalCredit := decimal.Zero
	for _, line := range lines {
		totalDebit = totalDebit.Add(line.DebitAmount)
		totalCredit = totalCredit.Add(line.CreditAmount)
	}
	if !totalDebit.Equal(totalCredit) {
		return fmt.Errorf("%w: total debits %s do not equal total credits %s", ErrInvalidState, totalDebit, totalCredit)
	}

	if err := s.repo.Post(ctx, tx, id, postedBy); err != nil {
		return fmt.Errorf("post journal entry: %w", err)
	}

	entry, _ = s.repo.GetByID(ctx, tx, id)
	if err := s.ledgerService.PostJournalToLedger(ctx, tx, entry, lines); err != nil {
		return fmt.Errorf("post to ledger: %w", err)
	}

	payload, _ := json.Marshal(events.JournalEventPayload{
		JournalEntryID: entry.JournalEntryID.String(),
		CompanyID:      entry.CompanyID.String(),
		JournalType:    entry.JournalType,
		EntryDate:      entry.EntryDate,
		TotalDebit:     totalDebit.String(),
		TotalCredit:    totalCredit.String(),
		Status:         entry.Status,
	})

	outboxEvent := &outbox.Event{
		EventID:       uuid.New().String(),
		AggregateType: "journal_entry",
		AggregateID:   entry.JournalEntryID.String(),
		EventType:     events.EventJournalPosted,
		Payload:       payload,
		Status:        "pending",
	}
	if err := s.outboxRepo.Store(ctx, tx, outboxEvent); err != nil {
		return fmt.Errorf("store outbox event: %w", err)
	}

	if idempotencyKey != "" {
		_ = s.idempotencyStore.Store(ctx, tx, idempotencyKey, true)
	}

	if err := tx.Commit(); err != nil {
		return fmt.Errorf("commit tx: %w", err)
	}

	if s.auditService != nil {
		_ = s.auditService.LogAction(ctx, nil, &entry.CompanyID, "accounting", "post", "journal_entry",
			&id, "user", postedBy, nil, nil, nil)
	}

	logger.Info("journal entry posted")
	return nil
}

// Reverse creates a reversing entry for a posted journal and marks original as reversed
func (s *journalService) Reverse(ctx context.Context, id uuid.UUID, reason string, reversedBy *uuid.UUID) error {
	logger := s.logger.With(zap.String("method", "Reverse"), zap.String("journal_id", id.String()))
	idempotencyKey, _ := ctx.Value("idempotency_key").(string)

	tx, err := s.pgClient.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("begin tx: %w", err)
	}
	defer tx.Rollback()

	if idempotencyKey != "" {
		var processed bool
		if err := s.idempotencyStore.Get(ctx, tx, idempotencyKey, &processed); err == nil && processed {
			logger.Info("idempotent request, already reversed")
			return nil
		}
	}

	original, err := s.repo.GetByIDForUpdate(ctx, tx, id)
	if err != nil {
		return fmt.Errorf("get entry: %w", err)
	}
	if original == nil {
		return fmt.Errorf("%w: journal entry %s", ErrNotFound, id)
	}
	if original.Status != enums.JournalStatusPosted {
		return fmt.Errorf("%w: only posted entries can be reversed, current status: %s", ErrInvalidState, original.Status)
	}

	reversal := &models.JournalEntry{
		JournalEntryID: uuid.New(),
		CompanyID:      original.CompanyID,
		JournalType:    enums.JournalTypeContra,
		EntryDate:      time.Now(),
		Reference:      stringPtr(fmt.Sprintf("Reversal of %s", original.JournalEntryID.String())),
		Description:    stringPtr(fmt.Sprintf("Reversal: %s", reason)),
		Status:         enums.JournalStatusDraft,
		ReversalOf:     &original.JournalEntryID,
		CreatedBy:      reversedBy,
		UpdatedBy:      reversedBy,
	}
	if err := s.repo.Create(ctx, tx, reversal); err != nil {
		return fmt.Errorf("create reversal entry: %w", err)
	}

	originalLines, err := s.repo.GetLines(ctx, tx, id)
	if err != nil {
		return fmt.Errorf("get original lines: %w", err)
	}

	reversalLines := make([]*models.JournalLine, len(originalLines))
	for i, line := range originalLines {
		reversalLines[i] = &models.JournalLine{
			JournalLineID:  uuid.New(),
			JournalEntryID: reversal.JournalEntryID,
			AccountID:      line.AccountID,
			LineNumber:     i + 1,
			DebitAmount:    line.CreditAmount,
			CreditAmount:   line.DebitAmount,
			Description:    stringPtr(fmt.Sprintf("Reversal: %s", getStringValue(line.Description))),
		}
	}
	if err := s.repo.BulkAddLines(ctx, tx, reversalLines); err != nil {
		return fmt.Errorf("create reversal lines: %w", err)
	}

	if err := s.repo.Post(ctx, tx, reversal.JournalEntryID, reversedBy); err != nil {
		return fmt.Errorf("post reversal: %w", err)
	}

	if err := s.ledgerService.PostJournalToLedger(ctx, tx, reversal, reversalLines); err != nil {
		return fmt.Errorf("post reversal to ledger: %w", err)
	}

	if err := s.repo.UpdateStatus(ctx, tx, original.JournalEntryID, enums.JournalStatusReversed, reversedBy); err != nil {
		return fmt.Errorf("update original status: %w", err)
	}

	payload, _ := json.Marshal(events.JournalEventPayload{
		JournalEntryID: reversal.JournalEntryID.String(),
		CompanyID:      reversal.CompanyID.String(),
		JournalType:    reversal.JournalType,
		EntryDate:      reversal.EntryDate,
		Status:         reversal.Status,
		ReversalOf:     original.JournalEntryID.String(),
	})

	outboxEvent := &outbox.Event{
		EventID:       uuid.New().String(),
		AggregateType: "journal_entry",
		AggregateID:   reversal.JournalEntryID.String(),
		EventType:     events.EventJournalReversed,
		Payload:       payload,
		Status:        "pending",
	}
	if err := s.outboxRepo.Store(ctx, tx, outboxEvent); err != nil {
		return fmt.Errorf("store outbox event: %w", err)
	}

	if idempotencyKey != "" {
		_ = s.idempotencyStore.Store(ctx, tx, idempotencyKey, true)
	}

	if err := tx.Commit(); err != nil {
		return fmt.Errorf("commit tx: %w", err)
	}

	if s.auditService != nil {
		_ = s.auditService.LogAction(ctx, nil, &original.CompanyID, "accounting", "reverse", "journal_entry",
			&id, "user", reversedBy, nil, nil, map[string]interface{}{"reason": reason, "reversal_id": reversal.JournalEntryID.String()})
	}

	logger.Info("journal entry reversed", zap.String("reversal_id", reversal.JournalEntryID.String()))
	return nil
}

// GetByID retrieves a journal entry with its lines
func (s *journalService) GetByID(ctx context.Context, id uuid.UUID) (*models.JournalEntry, error) {
	logger := s.logger.With(zap.String("method", "GetByID"), zap.String("id", id.String()))
	entry, err := s.repo.GetByID(ctx, s.pgClient.DB, id)
	if err != nil {
		return nil, err
	}
	if entry == nil {
		return nil, fmt.Errorf("%w: journal entry %s", ErrNotFound, id)
	}
	lines, err := s.repo.GetLines(ctx, s.pgClient.DB, id)
	if err != nil {
		return nil, fmt.Errorf("get lines: %w", err)
	}
	logger.Debug("journal entry retrieved", zap.Int("line_count", len(lines)))
	return entry, nil
}

// List returns paginated journal entries matching the filter
func (s *journalService) List(ctx context.Context, filter repository.JournalFilter, p Pagination) ([]*models.JournalEntry, int64, error) {
	logger := s.logger.With(zap.String("method", "List"))
	limit, offset := s.validatePagination(p)
	sort := repository.Sort{Field: "entry_date", Direction: "DESC"}

	entries, err := s.repo.List(ctx, s.pgClient.DB, filter, repository.Pagination{Limit: limit, Offset: offset}, sort)
	if err != nil {
		return nil, 0, fmt.Errorf("list entries: %w", err)
	}
	total, err := s.repo.Count(ctx, s.pgClient.DB, filter)
	if err != nil {
		return nil, 0, fmt.Errorf("count entries: %w", err)
	}
	logger.Debug("listed journal entries", zap.Int("count", len(entries)), zap.Int64("total", total))
	return entries, total, nil
}

// Delete performs a soft delete on a draft journal entry
func (s *journalService) Delete(ctx context.Context, id uuid.UUID, deletedBy *uuid.UUID) error {
	logger := s.logger.With(zap.String("method", "Delete"), zap.String("journal_id", id.String()))
	idempotencyKey, _ := ctx.Value("idempotency_key").(string)

	tx, err := s.pgClient.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("begin tx: %w", err)
	}
	defer tx.Rollback()

	if idempotencyKey != "" {
		var processed bool
		if err := s.idempotencyStore.Get(ctx, tx, idempotencyKey, &processed); err == nil && processed {
			logger.Info("idempotent request, already deleted")
			return nil
		}
	}

	entry, err := s.repo.GetByIDForUpdate(ctx, tx, id)
	if err != nil {
		return fmt.Errorf("get entry: %w", err)
	}
	if entry == nil {
		return fmt.Errorf("%w: journal entry %s", ErrNotFound, id)
	}
	if entry.Status != enums.JournalStatusDraft {
		return fmt.Errorf("%w: cannot delete journal entry in status %s", ErrInvalidState, entry.Status)
	}

	// Repository Delete performs soft delete (sets deleted_at and status = 'deleted')
	if err := s.repo.Delete(ctx, tx, id, deletedBy); err != nil {
		return fmt.Errorf("delete entry: %w", err)
	}

	// Emit deletion event
	payload, _ := json.Marshal(events.JournalEventPayload{
		JournalEntryID: entry.JournalEntryID.String(),
		CompanyID:      entry.CompanyID.String(),
		JournalType:    entry.JournalType,
		EntryDate:      entry.EntryDate,
		Status:         "deleted",
	})

	outboxEvent := &outbox.Event{
		EventID:       uuid.New().String(),
		AggregateType: "journal_entry",
		AggregateID:   entry.JournalEntryID.String(),
		EventType:     events.EventJournalDeleted,
		Payload:       payload,
		Status:        "pending",
	}
	if err := s.outboxRepo.Store(ctx, tx, outboxEvent); err != nil {
		return fmt.Errorf("store outbox event: %w", err)
	}

	if idempotencyKey != "" {
		_ = s.idempotencyStore.Store(ctx, tx, idempotencyKey, true)
	}

	if err := tx.Commit(); err != nil {
		return fmt.Errorf("commit tx: %w", err)
	}

	if s.auditService != nil {
		_ = s.auditService.LogAction(ctx, nil, &entry.CompanyID, "accounting", "delete", "journal_entry",
			&id, "user", deletedBy, nil, nil, nil)
	}

	logger.Info("journal entry soft-deleted")
	return nil
}

// validateJournal performs business validation on a create request
func (s *journalService) validateJournal(req CreateJournalRequest) error {
	if req.CompanyID == uuid.Nil {
		return fmt.Errorf("%w: company_id is required", ErrInvalidInput)
	}
	if req.JournalType == "" {
		return fmt.Errorf("%w: journal_type is required", ErrInvalidInput)
	}
	if req.EntryDate.IsZero() {
		return fmt.Errorf("%w: entry_date is required", ErrInvalidInput)
	}
	if len(req.Lines) == 0 {
		return fmt.Errorf("%w: at least one journal line is required", ErrInvalidInput)
	}
	totalDebit := decimal.Zero
	totalCredit := decimal.Zero
	for i, line := range req.Lines {
		if line.AccountID == uuid.Nil {
			return fmt.Errorf("%w: line %d: account_id is required", ErrInvalidInput, i+1)
		}
		if line.DebitAmount.IsNegative() || line.CreditAmount.IsNegative() {
			return fmt.Errorf("%w: line %d: amounts cannot be negative", ErrInvalidInput, i+1)
		}
		if line.DebitAmount.IsZero() && line.CreditAmount.IsZero() {
			return fmt.Errorf("%w: line %d: both debit and credit cannot be zero", ErrInvalidInput, i+1)
		}
		if !line.DebitAmount.IsZero() && !line.CreditAmount.IsZero() {
			return fmt.Errorf("%w: line %d: cannot have both debit and credit", ErrInvalidInput, i+1)
		}
		totalDebit = totalDebit.Add(line.DebitAmount)
		totalCredit = totalCredit.Add(line.CreditAmount)
	}
	if !totalDebit.Equal(totalCredit) {
		return fmt.Errorf("%w: total debits %s do not equal total credits %s", ErrInvalidInput, totalDebit, totalCredit)
	}
	return nil
}

// validatePagination returns sanitized limit and offset
func (s *journalService) validatePagination(p Pagination) (int, int) {
	limit := p.Limit
	if limit <= 0 {
		limit = 50
	}
	if limit > 1000 {
		limit = 1000
	}
	offset := p.Offset
	if offset < 0 {
		offset = 0
	}
	return limit, offset
}

// Helper functions
func stringPtr(s string) *string {
	return &s
}

func getStringValue(s *string) string {
	if s == nil {
		return ""
	}
	return *s
}

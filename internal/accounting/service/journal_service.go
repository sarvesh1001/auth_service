package service

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
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

// =============================================================================
// Interfaces
// =============================================================================

type JournalService interface {
	Create(ctx context.Context, req CreateJournalRequest) (*models.JournalEntry, error)
	CreateWithTx(ctx context.Context, tx *sql.Tx, req CreateJournalRequest) (*models.JournalEntry, error)
	Update(ctx context.Context, req UpdateJournalRequest) (*models.JournalEntry, error)
	Post(ctx context.Context, id uuid.UUID, postedBy *uuid.UUID) error
	PostWithTx(ctx context.Context, tx *sql.Tx, id uuid.UUID, postedBy *uuid.UUID) error
	Reverse(ctx context.Context, id uuid.UUID, reason string, reversedBy *uuid.UUID) error
	GetByID(ctx context.Context, id uuid.UUID) (*models.JournalEntry, error)
	GetSummary(ctx context.Context, id uuid.UUID) (*repository.JournalSummary, error)
	List(ctx context.Context, filter repository.JournalFilter, p Pagination) ([]*models.JournalEntry, int64, error)
	Delete(ctx context.Context, id uuid.UUID, deletedBy *uuid.UUID) error
}

// =============================================================================
// Implementation
// =============================================================================

type journalService struct {
	repo             repository.JournalRepository
	ledgerService    LedgerService
	ruleEngine       AccountingRuleEngine
	pgClient         *client.PostgresClient
	logger           *zap.Logger
	outboxRepo       outbox.Repository
	idempotencyStore idempotency.Store
	auditService     *audit.AuditService
}

func NewJournalService(
	repo repository.JournalRepository,
	ledgerService LedgerService,
	ruleEngine AccountingRuleEngine,
	pgClient *client.PostgresClient,
	logger *zap.Logger,
	outboxRepo outbox.Repository,
	idempotencyStore idempotency.Store,
	auditService *audit.AuditService,
) JournalService {
	return &journalService{
		repo:             repo,
		ledgerService:    ledgerService,
		ruleEngine:       ruleEngine,
		pgClient:         pgClient,
		logger:           logger.Named("journal_service"),
		outboxRepo:       outboxRepo,
		idempotencyStore: idempotencyStore,
		auditService:     auditService,
	}
}

// Helper to check idempotency errors (works with any store)
func isIdempotencyNotFound(err error) bool {
	return errors.Is(err, idempotency.ErrKeyNotFound) || errors.Is(err, sql.ErrNoRows)
}

// =============================================================================
// Public Methods
// =============================================================================

func (s *journalService) Create(ctx context.Context, req CreateJournalRequest) (*models.JournalEntry, error) {
	logger := s.logger.With(zap.String("method", "Create"), zap.String("company_id", req.CompanyID.String()))
	tx, err := s.pgClient.BeginTx(ctx, nil)
	if err != nil {
		return nil, fmt.Errorf("begin tx: %w", err)
	}
	defer tx.Rollback()

	entry, err := s.createWithTxInternal(ctx, tx, req, logger)
	if err != nil {
		return nil, err
	}

	if err := tx.Commit(); err != nil {
		return nil, fmt.Errorf("commit tx: %w", err)
	}

	logger.Info("journal entry created", zap.String("journal_id", entry.JournalEntryID.String()))
	return entry, nil
}

func (s *journalService) CreateWithTx(ctx context.Context, tx *sql.Tx, req CreateJournalRequest) (*models.JournalEntry, error) {
	logger := s.logger.With(zap.String("method", "CreateWithTx"), zap.String("company_id", req.CompanyID.String()))
	return s.createWithTxInternal(ctx, tx, req, logger)
}

func (s *journalService) createWithTxInternal(ctx context.Context, tx *sql.Tx, req CreateJournalRequest, logger *zap.Logger) (*models.JournalEntry, error) {
	// 1. Basic validation (double‑entry, non‑negative, etc.)
	if err := s.validateJournal(req); err != nil {
		return nil, err
	}

	// 2. RULE ENGINE VALIDATION (advanced business rules)
	if err := s.ruleEngine.ValidateJournal(ctx, tx, req); err != nil {
		return nil, err
	}

	// 3. DUPLICATE DETECTION
	dup, err := s.ruleEngine.IsDuplicate(ctx, tx, req)
	if err != nil {
		return nil, err
	}
	if dup {
		s.logger.Warn("duplicate transaction detected", zap.Any("req", req))
		return nil, ErrDuplicateTransaction
	}

	// 4. Idempotency check (fixed error handling)
	idempotencyKey, _ := ctx.Value("idempotency_key").(string)
	if idempotencyKey != "" {
		var existing models.JournalEntry
		err := s.idempotencyStore.Get(ctx, tx, idempotencyKey, &existing)
		if err == nil {
			logger.Info("idempotent request, returning cached response")
			return &existing, nil
		}
		if !isIdempotencyNotFound(err) {
			return nil, fmt.Errorf("idempotency check failed: %w", err)
		}
	}

	// 5. Create journal entry (with or without source)
	var journal *models.JournalEntry
	var created bool

	if req.SourceType != nil && req.SourceID != nil {
		journal, created, err = s.repo.CreateOrGetBySource(
			ctx, tx, req.CompanyID, *req.SourceType, *req.SourceID, // SourceID is *string
			func() *models.JournalEntry {
				return &models.JournalEntry{
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
			},
		)
		if err != nil {
			return nil, fmt.Errorf("create or get by source: %w", err)
		}
		if !created {
			_ = s.idempotencyStore.Store(ctx, tx, idempotencyKey, journal)
			return journal, nil
		}
	} else {
		journal = &models.JournalEntry{
			JournalEntryID: uuid.New(),
			CompanyID:      req.CompanyID,
			JournalType:    req.JournalType,
			EntryDate:      req.EntryDate,
			Reference:      req.Reference,
			Description:    req.Description,
			Status:         enums.JournalStatusDraft,
			CreatedBy:      req.CreatedBy,
			UpdatedBy:      req.UpdatedBy,
		}
		if err := s.repo.Create(ctx, tx, journal); err != nil {
			return nil, fmt.Errorf("create entry: %w", err)
		}
	}

	// 6. Add journal lines
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

	// 7. Outbox event
	payload := s.buildJournalEventPayload(journal, lines)
	outboxEvent := &outbox.Event{
		EventID:       uuid.New().String(),
		AggregateType: "journal_entry",
		AggregateID:   journal.JournalEntryID.String(),
		EventType:     events.EventJournalCreated,
		Topic:         TopicAccountingEvents,
		Payload:       payload,
		Status:        "pending",
	}
	if err := s.outboxRepo.Store(ctx, tx, outboxEvent); err != nil {
		return nil, fmt.Errorf("store outbox event: %w", err)
	}

	// 8. Idempotency storage
	if idempotencyKey != "" {
		_ = s.idempotencyStore.Store(ctx, tx, idempotencyKey, journal)
	}

	// 9. Audit log
	if s.auditService != nil {
		_ = s.auditService.LogAction(ctx, nil, &req.CompanyID, "accounting", "create", "journal_entry",
			&journal.JournalEntryID, "user", req.CreatedBy, nil, nil, nil)
	}

	return journal, nil
}

// =============================================================================
// UPDATE
// =============================================================================

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

	// Idempotency check (fixed)
	if idempotencyKey != "" {
		var existing *models.JournalEntry
		err := s.idempotencyStore.Get(ctx, tx, idempotencyKey, &existing)
		if err == nil && existing != nil {
			logger.Info("idempotent request, returning cached response")
			return existing, nil
		}
		if err != nil && !isIdempotencyNotFound(err) {
			return nil, fmt.Errorf("idempotency check failed: %w", err)
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

	// Apply full validation if lines are being updated
	if req.Lines != nil {
		validationReq := CreateJournalRequest{
			CompanyID:   existing.CompanyID,
			JournalType: existing.JournalType,
			EntryDate:   existing.EntryDate,
			Reference:   existing.Reference,
			Description: existing.Description,
			Lines:       req.Lines,
		}
		if err := s.validateJournal(validationReq); err != nil {
			return nil, err
		}
		if err := s.ruleEngine.ValidateJournal(ctx, tx, validationReq); err != nil {
			return nil, err
		}
	}

	// Apply updates
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

	var lines []*models.JournalLine
	if req.Lines != nil {
		if err := s.repo.ClearLines(ctx, tx, existing.JournalEntryID); err != nil {
			return nil, fmt.Errorf("delete old lines: %w", err)
		}
		lines = make([]*models.JournalLine, len(req.Lines))
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
	} else {
		lines, err = s.repo.GetLines(ctx, tx, existing.JournalEntryID)
		if err != nil {
			return nil, fmt.Errorf("get lines for event: %w", err)
		}
	}

	// Outbox event
	payload := s.buildJournalEventPayload(existing, lines)
	outboxEvent := &outbox.Event{
		EventID:       uuid.New().String(),
		AggregateType: "journal_entry",
		AggregateID:   existing.JournalEntryID.String(),
		EventType:     events.EventJournalUpdated,
		Topic:         TopicAccountingEvents,
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

// =============================================================================
// POST
// =============================================================================

func (s *journalService) Post(ctx context.Context, id uuid.UUID, postedBy *uuid.UUID) error {
	logger := s.logger.With(zap.String("method", "Post"), zap.String("journal_id", id.String()))
	idempotencyKey, _ := ctx.Value("idempotency_key").(string)

	tx, err := s.pgClient.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("begin tx: %w", err)
	}
	defer tx.Rollback()

	// Idempotency check (fixed)
	if idempotencyKey != "" {
		var processed bool
		err := s.idempotencyStore.Get(ctx, tx, idempotencyKey, &processed)
		if err == nil && processed {
			logger.Info("idempotent request, already posted")
			return nil
		}
		if err != nil && !isIdempotencyNotFound(err) {
			return fmt.Errorf("idempotency check failed: %w", err)
		}
	}

	if err := s.postWithTxInternal(ctx, tx, id, postedBy); err != nil {
		return err
	}

	if idempotencyKey != "" {
		type postResult struct {
			JournalID uuid.UUID `json:"journal_id"`
			Status    string    `json:"status"`
		}
		_ = s.idempotencyStore.Store(ctx, tx, idempotencyKey, postResult{JournalID: id, Status: "posted"})
	}

	if err := tx.Commit(); err != nil {
		return fmt.Errorf("commit tx: %w", err)
	}

	logger.Info("journal entry posted")
	return nil
}

// =============================================================================
// REVERSE
// =============================================================================

func (s *journalService) Reverse(ctx context.Context, id uuid.UUID, reason string, reversedBy *uuid.UUID) error {
	logger := s.logger.With(zap.String("method", "Reverse"), zap.String("journal_id", id.String()))
	idempotencyKey, _ := ctx.Value("idempotency_key").(string)

	tx, err := s.pgClient.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("begin tx: %w", err)
	}
	defer tx.Rollback()

	// Idempotency check (fixed)
	if idempotencyKey != "" {
		var processed bool
		err := s.idempotencyStore.Get(ctx, tx, idempotencyKey, &processed)
		if err == nil && processed {
			logger.Info("idempotent request, already reversed")
			return nil
		}
		if err != nil && !isIdempotencyNotFound(err) {
			return fmt.Errorf("idempotency check failed: %w", err)
		}
	}

	// Check existing reversal
	hasRev, err := s.repo.HasReversal(ctx, tx, id)
	if err != nil {
		return fmt.Errorf("check reversal existence: %w", err)
	}
	if hasRev {
		return repository.ErrReversalAlreadyExists
	}

	// Lock & fetch original
	original, err := s.repo.GetByIDForUpdate(ctx, tx, id)
	if err != nil {
		return fmt.Errorf("get original entry: %w", err)
	}
	if original == nil {
		return fmt.Errorf("%w: journal entry %s", repository.ErrNotFound, id)
	}
	if original.Status != enums.JournalStatusPosted {
		return fmt.Errorf("only posted entries can be reversed, status: %s", original.Status)
	}

	// Fetch original lines
	originalLines, err := s.repo.GetLines(ctx, tx, id)
	if err != nil {
		return fmt.Errorf("get original lines: %w", err)
	}
	if len(originalLines) == 0 {
		return fmt.Errorf("original journal has no lines")
	}

	// Create reversal entry (DRAFT)
	reversal := &models.JournalEntry{
		JournalEntryID: uuid.New(),
		CompanyID:      original.CompanyID,
		JournalType:    enums.JournalTypeContra,
		EntryDate:      time.Now(),
		Reference:      stringPtr(fmt.Sprintf("REV-%s", original.JournalEntryID.String())),
		Description:    stringPtr(fmt.Sprintf("Reversal: %s", reason)),
		Status:         enums.JournalStatusDraft,
		ReversalOf:     &original.JournalEntryID,
		CreatedBy:      reversedBy,
		UpdatedBy:      reversedBy,
	}

	if err := s.repo.Reverse(ctx, tx, id, reversal); err != nil {
		return fmt.Errorf("reverse journal: %w", err)
	}

	// Create reversed lines (swap debit/credit)
	reversalLines := make([]*models.JournalLine, len(originalLines))
	for i, l := range originalLines {
		reversalLines[i] = &models.JournalLine{
			JournalLineID:  uuid.New(),
			JournalEntryID: reversal.JournalEntryID,
			AccountID:      l.AccountID,
			LineNumber:     i + 1,
			DebitAmount:    l.CreditAmount,
			CreditAmount:   l.DebitAmount,
			Description:    l.Description,
		}
	}
	if err := s.repo.BulkAddLines(ctx, tx, reversalLines); err != nil {
		return fmt.Errorf("create reversal lines: %w", err)
	}

	// Rule validation before post
	if err := s.ruleEngine.ValidateBeforePost(ctx, tx, reversal, reversalLines); err != nil {
		return err
	}

	// Post to ledger
	if err := s.ledgerService.PostJournalToLedger(ctx, tx, reversal, reversalLines); err != nil {
		return fmt.Errorf("post reversal to ledger: %w", err)
	}

	// Mark as POSTED
	if err := s.repo.Post(ctx, tx, reversal.JournalEntryID, reversedBy); err != nil {
		return fmt.Errorf("post reversal entry: %w", err)
	}

	// Outbox event
	payload := s.buildJournalEventPayload(reversal, reversalLines)
	outboxEvent := &outbox.Event{
		EventID:       uuid.New().String(),
		AggregateType: "journal_entry",
		AggregateID:   reversal.JournalEntryID.String(),
		EventType:     events.EventJournalReversed,
		Topic:         TopicAccountingEvents,
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
			&id, "user", reversedBy, nil, nil, map[string]interface{}{
				"reason":      reason,
				"reversal_id": reversal.JournalEntryID.String(),
			})
	}

	logger.Info("journal entry reversed successfully",
		zap.String("reversal_id", reversal.JournalEntryID.String()))
	return nil
}

// =============================================================================
// DELETE
// =============================================================================

func (s *journalService) Delete(ctx context.Context, id uuid.UUID, deletedBy *uuid.UUID) error {
	logger := s.logger.With(zap.String("method", "Delete"), zap.String("journal_id", id.String()))
	idempotencyKey, _ := ctx.Value("idempotency_key").(string)

	tx, err := s.pgClient.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("begin tx: %w", err)
	}
	defer tx.Rollback()

	// Idempotency check (fixed)
	if idempotencyKey != "" {
		var processed bool
		err := s.idempotencyStore.Get(ctx, tx, idempotencyKey, &processed)
		if err == nil && processed {
			logger.Info("idempotent request, already deleted")
			return nil
		}
		if err != nil && !isIdempotencyNotFound(err) {
			return fmt.Errorf("idempotency check failed: %w", err)
		}
	}

	entry, err := s.repo.GetByIDForUpdate(ctx, tx, id)
	if err != nil {
		return fmt.Errorf("get entry: %w", err)
	}
	if entry == nil {
		return fmt.Errorf("%w: journal entry %s", repository.ErrNotFound, id)
	}
	if entry.Status != enums.JournalStatusDraft {
		return fmt.Errorf("%w: cannot delete journal entry in status %s", ErrInvalidState, entry.Status)
	}

	lines, err := s.repo.GetLines(ctx, tx, id)
	if err != nil {
		return fmt.Errorf("get lines for event: %w", err)
	}

	if err := s.repo.Delete(ctx, tx, id, deletedBy); err != nil {
		return fmt.Errorf("delete entry: %w", err)
	}

	payload := s.buildJournalEventPayload(entry, lines)
	outboxEvent := &outbox.Event{
		EventID:       uuid.New().String(),
		AggregateType: "journal_entry",
		AggregateID:   id.String(),
		EventType:     events.EventJournalDeleted,
		Topic:         TopicAccountingEvents,
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

// =============================================================================
// GETTERS & LIST
// =============================================================================

func (s *journalService) GetByID(ctx context.Context, id uuid.UUID) (*models.JournalEntry, error) {
	entry, err := s.repo.GetByID(ctx, s.pgClient.DB, id)
	if err != nil {
		return nil, err
	}
	if entry == nil {
		return nil, fmt.Errorf("%w: journal entry %s", repository.ErrNotFound, id)
	}
	return entry, nil
}

func (s *journalService) GetSummary(ctx context.Context, id uuid.UUID) (*repository.JournalSummary, error) {
	return s.repo.GetJournalSummary(ctx, s.pgClient.DB, id)
}

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

// =============================================================================
// Private Helpers
// =============================================================================

func (s *journalService) buildJournalEventPayload(entry *models.JournalEntry, lines []*models.JournalLine) []byte {
	type linePayload struct {
		AccountID string `json:"account_id"`
		Debit     string `json:"debit"`
		Credit    string `json:"credit"`
	}
	payloadLines := make([]linePayload, len(lines))
	for i, l := range lines {
		payloadLines[i] = linePayload{
			AccountID: l.AccountID.String(),
			Debit:     l.DebitAmount.String(),
			Credit:    l.CreditAmount.String(),
		}
	}
	payload := struct {
		JournalEntryID string        `json:"journal_entry_id"`
		CompanyID      string        `json:"company_id"`
		JournalType    string        `json:"journal_type"`
		EntryDate      time.Time     `json:"entry_date"`
		Status         string        `json:"status"`
		ReversalOf     *string       `json:"reversal_of,omitempty"`
		Lines          []linePayload `json:"lines"`
	}{
		JournalEntryID: entry.JournalEntryID.String(),
		CompanyID:      entry.CompanyID.String(),
		JournalType:    entry.JournalType,
		EntryDate:      entry.EntryDate,
		Status:         entry.Status,
		Lines:          payloadLines,
	}
	if entry.ReversalOf != nil {
		rev := entry.ReversalOf.String()
		payload.ReversalOf = &rev
	}
	data, _ := json.Marshal(payload)
	return data
}

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
	if len(req.Lines) < 2 {
		return fmt.Errorf("%w: journal must have at least 2 lines (double‑entry)", ErrInvalidInput)
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

func stringPtr(s string) *string {
	return &s
}

// postWithTxInternal performs the actual posting logic using an existing transaction.
func (s *journalService) postWithTxInternal(ctx context.Context, tx *sql.Tx, id uuid.UUID, postedBy *uuid.UUID) error {
	logger := s.logger.With(zap.String("method", "postWithTxInternal"), zap.String("journal_id", id.String()))

	// 1. Get entry for update (with row lock)
	entry, err := s.repo.GetByIDForUpdate(ctx, tx, id)
	if err != nil {
		return fmt.Errorf("get entry: %w", err)
	}
	if entry == nil {
		return fmt.Errorf("%w: journal entry %s", repository.ErrNotFound, id)
	}
	if entry.Status == enums.JournalStatusPosted {
		return fmt.Errorf("journal entry already posted")
	}
	if entry.Status != enums.JournalStatusDraft {
		return fmt.Errorf("cannot post journal with status %s", entry.Status)
	}

	// 2. Validate before post
	if err := s.repo.ValidateBeforePost(ctx, tx, id); err != nil {
		return err
	}

	// 3. Get journal lines
	lines, err := s.repo.GetLines(ctx, tx, id)
	if err != nil {
		return fmt.Errorf("get lines: %w", err)
	}

	// 4. Rule engine validation
	if err := s.ruleEngine.ValidateBeforePost(ctx, tx, entry, lines); err != nil {
		return err
	}

	// 5. Post to ledger
	logger.Info("calling PostJournalToLedger")
	if err := s.ledgerService.PostJournalToLedger(ctx, tx, entry, lines); err != nil {
		logger.Error("PostJournalToLedger failed", zap.Error(err))
		return fmt.Errorf("post to ledger: %w", err)
	}
	logger.Info("PostJournalToLedger completed successfully")

	// 6. Verify ledger entries
	var ledgerCount int
	err = tx.QueryRowContext(ctx, `SELECT COUNT(*) FROM accounting.ledger_entries WHERE journal_entry_id = $1`, id).Scan(&ledgerCount)
	if err != nil {
		logger.Error("failed to query ledger count", zap.Error(err))
	} else {
		logger.Info("ledger entries count after PostJournalToLedger", zap.Int("count", ledgerCount))
	}
	if err := s.repo.ValidateLedgerExists(ctx, tx, id); err != nil {
		logger.Error("ValidateLedgerExists failed", zap.Error(err))
		return fmt.Errorf("ledger validation failed: %w", err)
	}
	logger.Info("ValidateLedgerExists passed")

	// 7. Update journal status
	if err := s.repo.Post(ctx, tx, id, postedBy); err != nil {
		return fmt.Errorf("post journal entry: %w", err)
	}
	logger.Info("journal status updated to posted")

	// 8. Outbox event
	payload := s.buildJournalEventPayload(entry, lines)
	outboxEvent := &outbox.Event{
		EventID:       uuid.New().String(),
		AggregateType: "journal_entry",
		AggregateID:   id.String(),
		EventType:     events.EventJournalPosted,
		Topic:         TopicAccountingEvents,
		Payload:       payload,
		Status:        "pending",
	}
	if err := s.outboxRepo.Store(ctx, tx, outboxEvent); err != nil {
		return fmt.Errorf("store outbox event: %w", err)
	}

	// 9. Audit log
	if s.auditService != nil {
		_ = s.auditService.LogAction(ctx, nil, &entry.CompanyID, "accounting", "post", "journal_entry",
			&id, "user", postedBy, nil, nil, nil)
	}
	return nil
}

// PostWithTx posts a journal entry using an existing transaction.
func (s *journalService) PostWithTx(ctx context.Context, tx *sql.Tx, id uuid.UUID, postedBy *uuid.UUID) error {
	idempotencyKey, _ := ctx.Value("idempotency_key").(string)
	if idempotencyKey != "" {
		var processed bool
		err := s.idempotencyStore.Get(ctx, tx, idempotencyKey, &processed)
		if err == nil && processed {
			s.logger.Info("idempotent request, already posted (PostWithTx)", zap.String("journal_id", id.String()))
			return nil
		}
		if err != nil && !isIdempotencyNotFound(err) {
			return fmt.Errorf("idempotency check failed: %w", err)
		}
	}

	if err := s.postWithTxInternal(ctx, tx, id, postedBy); err != nil {
		return err
	}

	if idempotencyKey != "" {
		type postResult struct {
			JournalID uuid.UUID `json:"journal_id"`
			Status    string    `json:"status"`
		}
		_ = s.idempotencyStore.Store(ctx, tx, idempotencyKey, postResult{JournalID: id, Status: "posted"})
	}
	return nil
}

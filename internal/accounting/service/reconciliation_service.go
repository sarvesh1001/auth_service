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
	"auth-service/internal/accounting/models/analytics"
	"auth-service/internal/accounting/models/enums"
	"auth-service/internal/accounting/repository"
	"auth-service/internal/client"
	"auth-service/internal/infrastructure/audit"
	"auth-service/internal/infrastructure/idempotency"
	"auth-service/internal/infrastructure/outbox"
)

type CreateReconciliationBatchRequest struct {
	CompanyID          uuid.UUID  `json:"company_id"`
	ReconciliationType string     `json:"reconciliation_type"`
	Reference          *string    `json:"reference,omitempty"`
	StartDate          *time.Time `json:"start_date,omitempty"`
	EndDate            *time.Time `json:"end_date,omitempty"`
	CreatedBy          *uuid.UUID `json:"created_by,omitempty"`
}

type ReconciliationFilter struct {
	CompanyID          uuid.UUID  `json:"company_id"`
	ReconciliationType string     `json:"reconciliation_type,omitempty"`
	Status             string     `json:"status,omitempty"`
	FromDate           *time.Time `json:"from_date,omitempty"`
	ToDate             *time.Time `json:"to_date,omitempty"`
}

type ReconciliationItemInput struct {
	SourceType      string           `json:"source_type"`
	SourceID        *string          `json:"source_id,omitempty"`
	Amount          decimal.Decimal  `json:"amount"`
	Currency        string           `json:"currency"`
	TransactionDate time.Time        `json:"transaction_date"`
	Notes           *string          `json:"notes,omitempty"`
	InitialStatus   *string          `json:"initial_status,omitempty"`
	JournalEntryID  *uuid.UUID       `json:"journal_entry_id,omitempty"`
	MatchScore      *decimal.Decimal `json:"match_score,omitempty"`
}

type AutoMatchResult struct {
	TotalCandidates int     `json:"total_candidates"`
	MatchedCount    int     `json:"matched_count"`
	Errors          []error `json:"errors,omitempty"`
}

type CreateDifferenceRequest struct {
	BatchID        uuid.UUID       `json:"batch_id"`
	IssueType      string          `json:"issue_type"`
	ExpectedAmount decimal.Decimal `json:"expected_amount"`
	ActualAmount   decimal.Decimal `json:"actual_amount"`
	SourceID       *string         `json:"source_id,omitempty"`
	JournalEntryID *uuid.UUID      `json:"journal_entry_id,omitempty"`
	Description    *string         `json:"description,omitempty"`
}

type ResolveDifferenceAdjustmentRequest struct {
	CreateAdjustment bool      `json:"create_adjustment"`
	DebitAccountID   uuid.UUID `json:"debit_account_id"`
	CreditAccountID  uuid.UUID `json:"credit_account_id"`
	Description      string    `json:"description"`
}

type CreateAdjustmentRequest struct {
	BatchID          uuid.UUID       `json:"batch_id"`
	JournalEntryID   uuid.UUID       `json:"journal_entry_id"`
	Reason           *string         `json:"reason,omitempty"`
	AdjustmentAmount decimal.Decimal `json:"adjustment_amount"`
	CreatedBy        *uuid.UUID      `json:"created_by,omitempty"`
}

type ReconciliationService interface {
	CreateBatch(ctx context.Context, req CreateReconciliationBatchRequest) (*models.ReconciliationBatch, error)
	GetBatch(ctx context.Context, batchID uuid.UUID) (*models.ReconciliationBatch, error)
	ListBatches(ctx context.Context, filter ReconciliationFilter, p Pagination) ([]*models.ReconciliationBatch, int64, error)
	UpdateBatchStats(ctx context.Context, batchID uuid.UUID) error
	CompleteBatch(ctx context.Context, batchID uuid.UUID) error
	DeleteBatch(ctx context.Context, batchID uuid.UUID) error
	AddItems(ctx context.Context, batchID uuid.UUID, items []ReconciliationItemInput) ([]*models.ReconciliationItem, error)
	GetItems(ctx context.Context, batchID uuid.UUID, status string, limit, offset int) ([]*models.ReconciliationItem, error)
	GetUnmatchedItems(ctx context.Context, batchID uuid.UUID, limit, offset int) ([]*models.ReconciliationItem, error)
	AutoMatch(ctx context.Context, batchID uuid.UUID, threshold decimal.Decimal) (*AutoMatchResult, error)
	ManualMatch(ctx context.Context, itemID, journalEntryID uuid.UUID, score decimal.Decimal) error
	SetItemMatchStatus(ctx context.Context, itemID uuid.UUID, status string, journalEntryID *uuid.UUID, score *decimal.Decimal) error
	UnmatchItem(ctx context.Context, itemID uuid.UUID) error
	CreateDifference(ctx context.Context, req CreateDifferenceRequest) (*models.ReconciliationDifference, error)
	ResolveDifference(ctx context.Context, diffID uuid.UUID, resolvedBy *uuid.UUID, adjustmentReq *ResolveDifferenceAdjustmentRequest) error
	GetDifferences(ctx context.Context, batchID uuid.UUID, unresolvedOnly bool) ([]*models.ReconciliationDifference, error)
	CreateAdjustment(ctx context.Context, req CreateAdjustmentRequest) (*models.ReconciliationAdjustment, error)
	DeleteAdjustment(ctx context.Context, adjID uuid.UUID) error
	GetAdjustments(ctx context.Context, batchID uuid.UUID) ([]*models.ReconciliationAdjustment, error)
}

type reconciliationService struct {
	repo             repository.ReconciliationRepository
	analyticsRepo    repository.AnalyticsRepository
	journalService   JournalService
	pgClient         *client.PostgresClient
	logger           *zap.Logger
	outboxRepo       outbox.Repository
	idempotencyStore idempotency.Store
	auditService     *audit.AuditService
}

func NewReconciliationService(
	repo repository.ReconciliationRepository,
	analyticsRepo repository.AnalyticsRepository,
	journalService JournalService,
	pgClient *client.PostgresClient,
	logger *zap.Logger,
	outboxRepo outbox.Repository,
	idempotencyStore idempotency.Store,
	auditService *audit.AuditService,
) ReconciliationService {
	return &reconciliationService{
		repo:             repo,
		analyticsRepo:    analyticsRepo,
		journalService:   journalService,
		pgClient:         pgClient,
		logger:           logger.Named("reconciliation_service"),
		outboxRepo:       outboxRepo,
		idempotencyStore: idempotencyStore,
		auditService:     auditService,
	}
}

func validatePagination(p Pagination) (int, int) {
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

func nullUUIDFromPtr(ptr *uuid.UUID) uuid.NullUUID {
	if ptr == nil {
		return uuid.NullUUID{Valid: false}
	}
	return uuid.NullUUID{UUID: *ptr, Valid: true}
}

const (
	defaultItemLimit  = 1000
	defaultItemOffset = 0
)

// ----------------------------------------------
// CreateBatch (already has idempotency)
// ----------------------------------------------
func (s *reconciliationService) CreateBatch(ctx context.Context, req CreateReconciliationBatchRequest) (*models.ReconciliationBatch, error) {
	logger := s.logger.With(zap.String("method", "CreateBatch"), zap.String("company_id", req.CompanyID.String()))

	idempotencyKey, _ := ctx.Value("idempotency_key").(string)

	if err := s.validateCreateBatchRequest(req); err != nil {
		return nil, err
	}

	tx, err := s.pgClient.BeginTx(ctx, nil)
	if err != nil {
		return nil, fmt.Errorf("begin tx: %w", err)
	}
	defer tx.Rollback()

	if idempotencyKey != "" {
		var existing *models.ReconciliationBatch
		if err := s.idempotencyStore.Get(ctx, tx, idempotencyKey, &existing); err == nil && existing != nil {
			logger.Info("idempotent request, returning cached batch")
			return existing, nil
		}
	}

	batch := &models.ReconciliationBatch{
		BatchID:            uuid.New(),
		CompanyID:          req.CompanyID,
		ReconciliationType: req.ReconciliationType,
		Reference:          req.Reference,
		StartDate:          req.StartDate,
		EndDate:            req.EndDate,
		Status:             enums.ReconciliationStatusPending,
		TotalRecords:       0,
		MatchedRecords:     0,
		UnmatchedRecords:   0,
		CreatedBy:          req.CreatedBy,
	}

	if err := s.repo.CreateBatch(ctx, tx, batch); err != nil {
		return nil, fmt.Errorf("create batch: %w", err)
	}

	payload, _ := json.Marshal(events.ReconciliationBatchPayload{
		BatchID:            batch.BatchID.String(),
		CompanyID:          batch.CompanyID.String(),
		ReconciliationType: batch.ReconciliationType,
		Status:             batch.Status,
		TotalRecords:       batch.TotalRecords,
		CreatedAt:          batch.CreatedAt,
	})
	outboxEvent := &outbox.Event{
		EventID:       uuid.New().String(),
		AggregateType: "reconciliation_batch",
		AggregateID:   batch.BatchID.String(),
		EventType:     events.EventReconciliationBatchCreated,
		Topic:         TopicAccountingEvents,
		Payload:       payload,
		Status:        "pending",
	}
	if err := s.outboxRepo.Store(ctx, tx, outboxEvent); err != nil {
		return nil, fmt.Errorf("store outbox event: %w", err)
	}

	if idempotencyKey != "" {
		_ = s.idempotencyStore.Store(ctx, tx, idempotencyKey, batch)
	}

	if s.auditService != nil {
		_ = s.auditService.LogAction(ctx, tx, &req.CompanyID, "reconciliation", "create", "reconciliation_batch",
			&batch.BatchID, "user", req.CreatedBy, nil, nil, nil)
	}

	if err := tx.Commit(); err != nil {
		return nil, fmt.Errorf("commit tx: %w", err)
	}

	logger.Info("reconciliation batch created", zap.String("batch_id", batch.BatchID.String()))
	return batch, nil
}

// ----------------------------------------------
// GetBatch (unchanged – read‑only)
// ----------------------------------------------
func (s *reconciliationService) GetBatch(ctx context.Context, batchID uuid.UUID) (*models.ReconciliationBatch, error) {
	batch, err := s.repo.GetBatchByID(ctx, s.pgClient.DB, batchID)
	if err != nil {
		return nil, err
	}
	if batch == nil {
		return nil, fmt.Errorf("%w: batch %s", ErrNotFound, batchID)
	}
	return batch, nil
}

// ----------------------------------------------
// ListBatches (unchanged – read‑only)
// ----------------------------------------------
func (s *reconciliationService) ListBatches(ctx context.Context, filter ReconciliationFilter, p Pagination) ([]*models.ReconciliationBatch, int64, error) {
	limit, offset := validatePagination(p)
	sort := repository.Sort{Field: "created_at", Direction: "DESC"}
	repoFilter := repository.ReconciliationFilter{
		CompanyID:          filter.CompanyID,
		ReconciliationType: filter.ReconciliationType,
		Status:             filter.Status,
		FromDate:           filter.FromDate,
		ToDate:             filter.ToDate,
	}
	batches, err := s.repo.ListBatches(ctx, s.pgClient.DB, repoFilter, repository.Pagination{Limit: limit, Offset: offset}, sort)
	if err != nil {
		return nil, 0, err
	}
	total, err := s.repo.CountBatches(ctx, s.pgClient.DB, repoFilter)
	if err != nil {
		return nil, 0, err
	}
	return batches, total, nil
}

// ----------------------------------------------
// UpdateBatchStats (mutating) – with idempotency
// ----------------------------------------------
func (s *reconciliationService) UpdateBatchStats(ctx context.Context, batchID uuid.UUID) error {
	logger := s.logger.With(zap.String("method", "UpdateBatchStats"), zap.String("batch_id", batchID.String()))
	idempotencyKey, _ := ctx.Value("idempotency_key").(string)

	tx, err := s.pgClient.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("begin tx: %w", err)
	}
	defer tx.Rollback()

	if idempotencyKey != "" {
		var cached bool
		if err := s.idempotencyStore.Get(ctx, tx, idempotencyKey, &cached); err == nil && cached {
			logger.Info("idempotent request, skipping update")
			return nil
		}
	}

	if err := s.updateBatchStatsInternal(ctx, tx, batchID); err != nil {
		return err
	}

	if idempotencyKey != "" {
		_ = s.idempotencyStore.Store(ctx, tx, idempotencyKey, true)
	}

	if err := tx.Commit(); err != nil {
		return fmt.Errorf("commit tx: %w", err)
	}
	return nil
}

// ----------------------------------------------
// CompleteBatch (mutating) – with idempotency
// ----------------------------------------------
func (s *reconciliationService) CompleteBatch(ctx context.Context, batchID uuid.UUID) error {
	logger := s.logger.With(zap.String("method", "CompleteBatch"), zap.String("batch_id", batchID.String()))
	idempotencyKey, _ := ctx.Value("idempotency_key").(string)

	tx, err := s.pgClient.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("begin tx: %w", err)
	}
	defer tx.Rollback()

	if idempotencyKey != "" {
		var cached bool
		if err := s.idempotencyStore.Get(ctx, tx, idempotencyKey, &cached); err == nil && cached {
			logger.Info("idempotent request, batch already completed")
			return nil
		}
	}

	batch, err := s.repo.GetBatchByIDForUpdate(ctx, tx, batchID)
	if err != nil {
		return fmt.Errorf("get batch: %w", err)
	}
	if batch == nil {
		return fmt.Errorf("%w: batch %s", ErrNotFound, batchID)
	}
	if batch.Status == enums.ReconciliationStatusCompleted {
		return fmt.Errorf("%w: batch already completed", ErrInvalidState)
	}

	_, matched, unmatched, err := s.repo.CountItemsByStatus(ctx, tx, batchID)
	if err != nil {
		return fmt.Errorf("count items: %w", err)
	}
	if unmatched > 0 {
		return fmt.Errorf("%w: cannot complete batch with %d unmatched items", ErrInvalidState, unmatched)
	}

	if err := s.repo.CompleteBatch(ctx, tx, batchID, time.Now()); err != nil {
		return fmt.Errorf("complete batch: %w", err)
	}

	payload, _ := json.Marshal(events.ReconciliationBatchPayload{
		BatchID:        batchID.String(),
		CompanyID:      batch.CompanyID.String(),
		Status:         enums.ReconciliationStatusCompleted,
		TotalRecords:   batch.TotalRecords,
		MatchedRecords: matched,
		CompletedAt:    time.Now(),
	})
	outboxEvent := &outbox.Event{
		EventID:       uuid.New().String(),
		AggregateType: "reconciliation_batch",
		AggregateID:   batchID.String(),
		EventType:     events.EventReconciliationBatchCompleted,
		Topic:         TopicAccountingEvents,
		Payload:       payload,
		Status:        "pending",
	}
	if err := s.outboxRepo.Store(ctx, tx, outboxEvent); err != nil {
		return fmt.Errorf("store outbox event: %w", err)
	}

	if s.auditService != nil {
		_ = s.auditService.LogAction(ctx, tx, &batch.CompanyID, "reconciliation", "complete", "reconciliation_batch",
			&batchID, "system", nil, nil, nil, map[string]interface{}{"status": "completed"})
	}

	if idempotencyKey != "" {
		_ = s.idempotencyStore.Store(ctx, tx, idempotencyKey, true)
	}

	if err := tx.Commit(); err != nil {
		return fmt.Errorf("commit tx: %w", err)
	}

	logger.Info("batch completed")
	return nil
}

// ----------------------------------------------
// DeleteBatch (mutating) – with idempotency
// ----------------------------------------------
func (s *reconciliationService) DeleteBatch(ctx context.Context, batchID uuid.UUID) error {
	logger := s.logger.With(zap.String("method", "DeleteBatch"), zap.String("batch_id", batchID.String()))
	idempotencyKey, _ := ctx.Value("idempotency_key").(string)

	tx, err := s.pgClient.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("begin tx: %w", err)
	}
	defer tx.Rollback()

	if idempotencyKey != "" {
		var cached bool
		if err := s.idempotencyStore.Get(ctx, tx, idempotencyKey, &cached); err == nil && cached {
			logger.Info("idempotent request, batch already deleted")
			return nil
		}
	}

	batch, err := s.repo.GetBatchByIDForUpdate(ctx, tx, batchID)
	if err != nil {
		return err
	}
	if batch == nil {
		return fmt.Errorf("%w: batch %s", ErrNotFound, batchID)
	}
	if batch.Status == enums.ReconciliationStatusCompleted {
		return fmt.Errorf("%w: cannot delete completed batch", ErrInvalidState)
	}

	if err := s.repo.DeleteBatch(ctx, tx, batchID); err != nil {
		return fmt.Errorf("delete batch: %w", err)
	}

	if s.auditService != nil {
		_ = s.auditService.LogAction(ctx, tx, &batch.CompanyID, "reconciliation", "delete", "reconciliation_batch",
			&batchID, "system", nil, nil, nil, nil)
	}

	if idempotencyKey != "" {
		_ = s.idempotencyStore.Store(ctx, tx, idempotencyKey, true)
	}

	if err := tx.Commit(); err != nil {
		return fmt.Errorf("commit tx: %w", err)
	}

	logger.Info("batch deleted")
	return nil
}

// ----------------------------------------------
// AddItems (already has idempotency via handler? but we add explicit check)
// Note: idempotency keys are usually per request – here we store the full result.
// ----------------------------------------------
func (s *reconciliationService) AddItems(ctx context.Context, batchID uuid.UUID, items []ReconciliationItemInput) ([]*models.ReconciliationItem, error) {
	logger := s.logger.With(zap.String("method", "AddItems"), zap.String("batch_id", batchID.String()))
	idempotencyKey, _ := ctx.Value("idempotency_key").(string)

	if len(items) == 0 {
		return nil, nil
	}

	tx, err := s.pgClient.BeginTx(ctx, nil)
	if err != nil {
		return nil, fmt.Errorf("begin tx: %w", err)
	}
	defer tx.Rollback()

	if idempotencyKey != "" {
		var existing []*models.ReconciliationItem
		if err := s.idempotencyStore.Get(ctx, tx, idempotencyKey, &existing); err == nil && existing != nil {
			logger.Info("idempotent request, returning cached items")
			return existing, nil
		}
	}

	batch, err := s.repo.GetBatchByIDForUpdate(ctx, tx, batchID)
	if err != nil {
		return nil, fmt.Errorf("get batch for update: %w", err)
	}
	if batch == nil {
		return nil, fmt.Errorf("%w: batch %s", ErrNotFound, batchID)
	}
	if batch.Status == enums.ReconciliationStatusCompleted {
		return nil, fmt.Errorf("%w: cannot add items to completed batch", ErrInvalidState)
	}
	if batch.Status == enums.ReconciliationStatusPending {
		batch.Status = enums.ReconciliationStatusInProgress
		if err := s.repo.UpdateBatch(ctx, tx, batch); err != nil {
			return nil, fmt.Errorf("update batch status: %w", err)
		}
	}

	modelItems := make([]*models.ReconciliationItem, len(items))
	for i, inp := range items {
		var sourceID *string
		if inp.SourceID != nil {
			sourceID = inp.SourceID
		}
		journalEntryID := uuid.NullUUID{}
		if inp.JournalEntryID != nil {
			journalEntryID = uuid.NullUUID{UUID: *inp.JournalEntryID, Valid: true}
		}
		status := enums.MatchStatusUnmatched
		if inp.InitialStatus != nil {
			status = *inp.InitialStatus
		}
		modelItems[i] = &models.ReconciliationItem{
			ItemID:          uuid.New(),
			BatchID:         batchID,
			SourceType:      inp.SourceType,
			SourceID:        sourceID,
			JournalEntryID:  journalEntryID,
			Amount:          inp.Amount,
			Currency:        inp.Currency,
			TransactionDate: inp.TransactionDate,
			MatchStatus:     status,
			MatchScore:      inp.MatchScore,
			Notes:           inp.Notes,
		}
	}

	if err := s.repo.BulkAddItems(ctx, tx, modelItems); err != nil {
		return nil, fmt.Errorf("bulk add items: %w", err)
	}
	if err := s.updateBatchStatsInternal(ctx, tx, batchID); err != nil {
		return nil, fmt.Errorf("update stats: %w", err)
	}

	if s.auditService != nil {
		_ = s.auditService.LogAction(ctx, tx, &batch.CompanyID, "reconciliation", "add_items", "reconciliation_batch",
			&batchID, "system", nil, nil, nil, map[string]interface{}{"items_added": len(modelItems)})
	}

	if idempotencyKey != "" {
		_ = s.idempotencyStore.Store(ctx, tx, idempotencyKey, modelItems)
	}

	if err := tx.Commit(); err != nil {
		return nil, fmt.Errorf("commit tx: %w", err)
	}

	logger.Info("items added to batch", zap.Int("count", len(modelItems)))
	return modelItems, nil
}

// ----------------------------------------------
// GetItems (unchanged – read‑only)
// ----------------------------------------------
func (s *reconciliationService) GetItems(ctx context.Context, batchID uuid.UUID, status string, limit, offset int) ([]*models.ReconciliationItem, error) {
	if limit <= 0 {
		limit = defaultItemLimit
	}
	if offset < 0 {
		offset = defaultItemOffset
	}
	if status != "" {
		return s.repo.GetItemsByStatus(ctx, s.pgClient.DB, batchID, status, limit, offset)
	}
	return s.repo.GetItemsByBatch(ctx, s.pgClient.DB, batchID, limit, offset)
}

// ----------------------------------------------
// GetUnmatchedItems (unchanged – read‑only)
// ----------------------------------------------
func (s *reconciliationService) GetUnmatchedItems(ctx context.Context, batchID uuid.UUID, limit, offset int) ([]*models.ReconciliationItem, error) {
	if limit <= 0 {
		limit = defaultItemLimit
	}
	if offset < 0 {
		offset = defaultItemOffset
	}
	return s.repo.GetUnmatchedItems(ctx, s.pgClient.DB, batchID, limit, offset)
}

// ----------------------------------------------
// AutoMatch (mutating) – with idempotency
// ----------------------------------------------
func (s *reconciliationService) AutoMatch(ctx context.Context, batchID uuid.UUID, threshold decimal.Decimal) (*AutoMatchResult, error) {
	logger := s.logger.With(zap.String("method", "AutoMatch"), zap.String("batch_id", batchID.String()))
	idempotencyKey, _ := ctx.Value("idempotency_key").(string)

	tx, err := s.pgClient.BeginTx(ctx, nil)
	if err != nil {
		return nil, fmt.Errorf("begin tx: %w", err)
	}
	defer tx.Rollback()

	if idempotencyKey != "" {
		var existing *AutoMatchResult
		if err := s.idempotencyStore.Get(ctx, tx, idempotencyKey, &existing); err == nil && existing != nil {
			logger.Info("idempotent request, returning cached auto-match result")
			return existing, nil
		}
	}

	batch, err := s.repo.GetBatchByIDForUpdate(ctx, tx, batchID)
	if err != nil {
		return nil, fmt.Errorf("get batch for update: %w", err)
	}
	if batch == nil {
		return nil, fmt.Errorf("%w: batch %s", ErrNotFound, batchID)
	}
	if batch.Status == enums.ReconciliationStatusCompleted {
		return nil, fmt.Errorf("%w: cannot auto-match completed batch", ErrInvalidState)
	}

	const matchLimit = 1000
	candidates, err := s.repo.FindPotentialMatches(ctx, tx, batchID, threshold, matchLimit)
	if err != nil {
		return nil, fmt.Errorf("find potential matches: %w", err)
	}

	result := &AutoMatchResult{TotalCandidates: len(candidates)}
	matchedCount := 0
	for _, cand := range candidates {
		if err := s.repo.MatchItem(ctx, tx, cand.ItemID, cand.JournalEntryID, cand.Score); err != nil {
			logger.Error("auto-match failed for item",
				zap.String("item_id", cand.ItemID.String()),
				zap.Error(err))
			result.Errors = append(result.Errors, fmt.Errorf("item %s: %w", cand.ItemID, err))
			continue
		}
		matchedCount++
	}
	result.MatchedCount = matchedCount

	if len(result.Errors) > 0 && batch.Status != enums.ReconciliationStatusCompleted {
		batch.Status = enums.ReconciliationStatusFailed
		if err := s.repo.UpdateBatch(ctx, tx, batch); err != nil {
			logger.Error("failed to update batch status to failed", zap.Error(err))
		}
	}

	if err := s.updateBatchStatsInternal(ctx, tx, batchID); err != nil {
		return nil, fmt.Errorf("update stats after auto-match: %w", err)
	}

	payload, _ := json.Marshal(events.ReconciliationAutoMatchPayload{
		BatchID:         batchID.String(),
		MatchedCount:    matchedCount,
		TotalCandidates: len(candidates),
		Threshold:       threshold.String(),
	})
	outboxEvent := &outbox.Event{
		EventID:       uuid.New().String(),
		AggregateType: "reconciliation_batch",
		AggregateID:   batchID.String(),
		EventType:     events.EventReconciliationAutoMatched,
		Topic:         TopicAccountingEvents,
		Payload:       payload,
		Status:        "pending",
	}
	if err := s.outboxRepo.Store(ctx, tx, outboxEvent); err != nil {
		return nil, fmt.Errorf("store outbox event: %w", err)
	}

	if s.auditService != nil {
		_ = s.auditService.LogAction(ctx, tx, &batch.CompanyID, "reconciliation", "auto_match", "reconciliation_batch",
			&batchID, "system", nil, nil, nil, map[string]interface{}{"matched": matchedCount, "candidates": len(candidates)})
	}

	if idempotencyKey != "" {
		_ = s.idempotencyStore.Store(ctx, tx, idempotencyKey, result)
	}

	if err := tx.Commit(); err != nil {
		return nil, fmt.Errorf("commit tx: %w", err)
	}

	logger.Info("auto-match completed", zap.Int("matched", matchedCount), zap.Int("candidates", len(candidates)), zap.Int("errors", len(result.Errors)))
	return result, nil
}

// ----------------------------------------------
// ManualMatch (mutating) – with idempotency
// ----------------------------------------------
func (s *reconciliationService) ManualMatch(ctx context.Context, itemID, journalEntryID uuid.UUID, score decimal.Decimal) error {
	logger := s.logger.With(zap.String("method", "ManualMatch"), zap.String("item_id", itemID.String()))
	idempotencyKey, _ := ctx.Value("idempotency_key").(string)

	tx, err := s.pgClient.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("begin tx: %w", err)
	}
	defer tx.Rollback()

	if idempotencyKey != "" {
		var cached bool
		if err := s.idempotencyStore.Get(ctx, tx, idempotencyKey, &cached); err == nil && cached {
			logger.Info("idempotent request, manual match already performed")
			return nil
		}
	}

	item, err := s.repo.GetItemByID(ctx, tx, itemID)
	if err != nil {
		return fmt.Errorf("get item: %w", err)
	}
	if item == nil {
		return fmt.Errorf("%w: item %s", ErrNotFound, itemID)
	}
	if item.MatchStatus == enums.MatchStatusMatched {
		return fmt.Errorf("%w: item already matched", ErrInvalidState)
	}

	batch, err := s.repo.GetBatchByID(ctx, tx, item.BatchID)
	if err != nil {
		return fmt.Errorf("get batch for audit: %w", err)
	}
	if batch == nil {
		return fmt.Errorf("%w: batch %s for item %s", ErrNotFound, item.BatchID, itemID)
	}

	if err := s.repo.MatchItem(ctx, tx, itemID, journalEntryID, score); err != nil {
		return fmt.Errorf("match item: %w", err)
	}

	if err := s.updateBatchStatsInternal(ctx, tx, item.BatchID); err != nil {
		return fmt.Errorf("update batch stats: %w", err)
	}

	if s.auditService != nil {
		_ = s.auditService.LogAction(ctx, tx, &batch.CompanyID, "reconciliation", "manual_match", "reconciliation_item",
			&itemID, "system", nil, nil, nil, map[string]interface{}{"journal_entry_id": journalEntryID.String()})
	}

	if idempotencyKey != "" {
		_ = s.idempotencyStore.Store(ctx, tx, idempotencyKey, true)
	}

	if err := tx.Commit(); err != nil {
		return fmt.Errorf("commit tx: %w", err)
	}

	logger.Info("manual match completed", zap.String("journal_entry_id", journalEntryID.String()))
	return nil
}

// ----------------------------------------------
// SetItemMatchStatus (mutating) – with idempotency
// ----------------------------------------------
func (s *reconciliationService) SetItemMatchStatus(ctx context.Context, itemID uuid.UUID, status string, journalEntryID *uuid.UUID, score *decimal.Decimal) error {
	logger := s.logger.With(zap.String("method", "SetItemMatchStatus"), zap.String("item_id", itemID.String()), zap.String("status", status))
	idempotencyKey, _ := ctx.Value("idempotency_key").(string)

	tx, err := s.pgClient.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("begin tx: %w", err)
	}
	defer tx.Rollback()

	if idempotencyKey != "" {
		var cached bool
		if err := s.idempotencyStore.Get(ctx, tx, idempotencyKey, &cached); err == nil && cached {
			logger.Info("idempotent request, status already set")
			return nil
		}
	}

	item, err := s.repo.GetItemByID(ctx, tx, itemID)
	if err != nil {
		return fmt.Errorf("get item: %w", err)
	}
	if item == nil {
		return fmt.Errorf("%w: item %s", ErrNotFound, itemID)
	}

	validStatuses := map[string]bool{
		enums.MatchStatusMatched:   true,
		enums.MatchStatusUnmatched: true,
		enums.MatchStatusPartial:   true,
		enums.MatchStatusIgnored:   true,
	}
	if !validStatuses[status] {
		return fmt.Errorf("%w: invalid match status %s", ErrInvalidInput, status)
	}

	if err := s.repo.UpdateItemStatus(ctx, tx, itemID, status, journalEntryID, score); err != nil {
		return fmt.Errorf("update match status: %w", err)
	}

	if err := s.updateBatchStatsInternal(ctx, tx, item.BatchID); err != nil {
		return fmt.Errorf("update batch stats: %w", err)
	}

	if idempotencyKey != "" {
		_ = s.idempotencyStore.Store(ctx, tx, idempotencyKey, true)
	}

	if err := tx.Commit(); err != nil {
		return fmt.Errorf("commit tx: %w", err)
	}

	logger.Info("item match status updated")
	return nil
}

// ----------------------------------------------
// UnmatchItem (mutating) – with idempotency
// ----------------------------------------------
func (s *reconciliationService) UnmatchItem(ctx context.Context, itemID uuid.UUID) error {
	logger := s.logger.With(zap.String("method", "UnmatchItem"), zap.String("item_id", itemID.String()))
	idempotencyKey, _ := ctx.Value("idempotency_key").(string)

	tx, err := s.pgClient.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("begin tx: %w", err)
	}
	defer tx.Rollback()

	if idempotencyKey != "" {
		var cached bool
		if err := s.idempotencyStore.Get(ctx, tx, idempotencyKey, &cached); err == nil && cached {
			logger.Info("idempotent request, item already unmatched")
			return nil
		}
	}

	item, err := s.repo.GetItemByID(ctx, tx, itemID)
	if err != nil {
		return fmt.Errorf("get item: %w", err)
	}
	if item == nil {
		return fmt.Errorf("%w: item %s", ErrNotFound, itemID)
	}
	if item.MatchStatus != enums.MatchStatusMatched {
		return fmt.Errorf("%w: item is not matched", ErrInvalidState)
	}

	if err := s.repo.UnmatchItem(ctx, tx, itemID); err != nil {
		return fmt.Errorf("unmatch item: %w", err)
	}

	if err := s.updateBatchStatsInternal(ctx, tx, item.BatchID); err != nil {
		return fmt.Errorf("update batch stats: %w", err)
	}

	if idempotencyKey != "" {
		_ = s.idempotencyStore.Store(ctx, tx, idempotencyKey, true)
	}

	if err := tx.Commit(); err != nil {
		return fmt.Errorf("commit tx: %w", err)
	}

	logger.Info("item unmatched")
	return nil
}

// ----------------------------------------------
// CreateDifference (already has idempotency)
// ----------------------------------------------
func (s *reconciliationService) CreateDifference(ctx context.Context, req CreateDifferenceRequest) (*models.ReconciliationDifference, error) {
	logger := s.logger.With(zap.String("method", "CreateDifference"), zap.String("batch_id", req.BatchID.String()))

	idempotencyKey, _ := ctx.Value("idempotency_key").(string)

	tx, err := s.pgClient.BeginTx(ctx, nil)
	if err != nil {
		return nil, fmt.Errorf("begin tx: %w", err)
	}
	defer tx.Rollback()

	if idempotencyKey != "" {
		var existing *models.ReconciliationDifference
		if err := s.idempotencyStore.Get(ctx, tx, idempotencyKey, &existing); err == nil && existing != nil {
			logger.Info("idempotent request, returning cached difference")
			return existing, nil
		}
	}

	batch, err := s.repo.GetBatchByID(ctx, tx, req.BatchID)
	if err != nil {
		return nil, fmt.Errorf("get batch: %w", err)
	}
	if batch == nil {
		return nil, fmt.Errorf("%w: batch %s", ErrNotFound, req.BatchID)
	}

	diff := &models.ReconciliationDifference{
		DifferenceID:   uuid.New(),
		BatchID:        req.BatchID,
		IssueType:      req.IssueType,
		ExpectedAmount: req.ExpectedAmount,
		ActualAmount:   req.ActualAmount,
		SourceID:       req.SourceID,
		JournalEntryID: nullUUIDFromPtr(req.JournalEntryID),
		Description:    req.Description,
		Resolved:       false,
	}

	if err := s.repo.AddDifference(ctx, tx, diff); err != nil {
		return nil, fmt.Errorf("add difference: %w", err)
	}

	expectedFloat, _ := req.ExpectedAmount.Float64()
	actualFloat, _ := req.ActualAmount.Float64()
	trend := &analytics.ReconciliationDiffTrends{
		TrendID:             uuid.New(),
		CompanyID:           batch.CompanyID,
		BatchID:             &req.BatchID,
		IssueType:           req.IssueType,
		Date:                time.Now(),
		Count:               1,
		TotalExpectedAmount: expectedFloat,
		TotalActualAmount:   actualFloat,
	}
	if err := s.analyticsRepo.InsertReconciliationDiffTrend(ctx, tx, trend); err != nil {
		logger.Error("failed to insert difference trend", zap.Error(err))
	}

	payload, _ := json.Marshal(events.ReconciliationDifferencePayload{
		DifferenceID:   diff.DifferenceID.String(),
		BatchID:        diff.BatchID.String(),
		IssueType:      diff.IssueType,
		ExpectedAmount: diff.ExpectedAmount.String(),
		ActualAmount:   diff.ActualAmount.String(),
		Resolved:       diff.Resolved,
	})
	outboxEvent := &outbox.Event{
		EventID:       uuid.New().String(),
		AggregateType: "reconciliation_difference",
		AggregateID:   diff.DifferenceID.String(),
		EventType:     events.EventReconciliationDifferenceCreated,
		Topic:         TopicAccountingEvents,
		Payload:       payload,
		Status:        "pending",
	}
	if err := s.outboxRepo.Store(ctx, tx, outboxEvent); err != nil {
		return nil, fmt.Errorf("store outbox event: %w", err)
	}

	if idempotencyKey != "" {
		_ = s.idempotencyStore.Store(ctx, tx, idempotencyKey, diff)
	}

	if s.auditService != nil {
		_ = s.auditService.LogAction(ctx, tx, &batch.CompanyID, "reconciliation", "create_difference", "reconciliation_difference",
			&diff.DifferenceID, "system", nil, nil, nil, map[string]interface{}{"issue_type": diff.IssueType})
	}

	if err := tx.Commit(); err != nil {
		return nil, fmt.Errorf("commit tx: %w", err)
	}

	logger.Info("difference created", zap.String("diff_id", diff.DifferenceID.String()))
	return diff, nil
}

// ----------------------------------------------
// ResolveDifference (mutating) – with idempotency
// ----------------------------------------------
// ResolveDifference marks a reconciliation difference as resolved.
// If adjustmentReq.CreateAdjustment is true, it creates a journal entry,
// posts it to the ledger, and records a reconciliation adjustment –
// all inside the same transaction.
func (s *reconciliationService) ResolveDifference(ctx context.Context, diffID uuid.UUID, resolvedBy *uuid.UUID, adjustmentReq *ResolveDifferenceAdjustmentRequest) error {
	logger := s.logger.With(zap.String("method", "ResolveDifference"), zap.String("diff_id", diffID.String()))
	idempotencyKey, _ := ctx.Value("idempotency_key").(string)

	tx, err := s.pgClient.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("begin tx: %w", err)
	}
	defer tx.Rollback()

	// Idempotency check
	if idempotencyKey != "" {
		var cached bool
		if err := s.idempotencyStore.Get(ctx, tx, idempotencyKey, &cached); err == nil && cached {
			logger.Info("idempotent request, difference already resolved")
			return nil
		}
	}

	// Fetch difference (with lock)
	diff, err := s.repo.GetDifferenceByID(ctx, tx, diffID)
	if err != nil {
		return fmt.Errorf("get difference: %w", err)
	}
	if diff == nil {
		return fmt.Errorf("%w: difference %s", ErrNotFound, diffID)
	}
	if diff.Resolved {
		return fmt.Errorf("%w: difference already resolved", ErrInvalidState)
	}

	// Fetch batch (for company ID and audit)
	batch, err := s.repo.GetBatchByID(ctx, tx, diff.BatchID)
	if err != nil {
		return fmt.Errorf("get batch: %w", err)
	}
	if batch == nil {
		return fmt.Errorf("%w: batch %s not found", ErrNotFound, diff.BatchID)
	}

	var adjustmentID *uuid.UUID

	// Create adjustment journal entry if requested
	if adjustmentReq != nil && adjustmentReq.CreateAdjustment {
		amountDiff := diff.ExpectedAmount.Sub(diff.ActualAmount).Abs()

		// Build journal request
		journalReq := CreateJournalRequest{
			CompanyID:   batch.CompanyID,
			JournalType: "general",
			EntryDate:   time.Now(),
			Reference:   stringPtr(fmt.Sprintf("Reconciliation adjustment for difference %s", diffID.String())),
			Description: stringPtr(adjustmentReq.Description),
			Lines: []JournalLineRequest{
				{
					AccountID:    adjustmentReq.DebitAccountID,
					DebitAmount:  amountDiff,
					CreditAmount: decimal.Zero,
				},
				{
					AccountID:    adjustmentReq.CreditAccountID,
					DebitAmount:  decimal.Zero,
					CreditAmount: amountDiff,
				},
			},
			CreatedBy: resolvedBy,
			UpdatedBy: resolvedBy,
		}

		// CREATE journal entry (DRAFT) using the same transaction
		// tx is already *sql.Tx, no cast needed
		journalEntry, err := s.journalService.CreateWithTx(ctx, tx, journalReq)
		if err != nil {
			return fmt.Errorf("create adjustment journal entry: %w", err)
		}

		// POST the journal entry (updates ledger) using the same transaction
		if err := s.journalService.PostWithTx(ctx, tx, journalEntry.JournalEntryID, resolvedBy); err != nil {
			return fmt.Errorf("post adjustment journal entry: %w", err)
		}

		// Create reconciliation adjustment record (inline to stay in same transaction)
		adj := &models.ReconciliationAdjustment{
			AdjustmentID:     uuid.New(),
			BatchID:          diff.BatchID,
			JournalEntryID:   journalEntry.JournalEntryID,
			Reason:           stringPtr(fmt.Sprintf("Auto-adjustment for difference %s", diffID.String())),
			AdjustmentAmount: amountDiff,
			CreatedBy:        resolvedBy,
		}
		if err := s.repo.AddAdjustment(ctx, tx, adj); err != nil {
			return fmt.Errorf("create adjustment record: %w", err)
		}
		adjustmentID = &adj.AdjustmentID
	}

	// Mark difference as resolved
	if err := s.repo.ResolveDifference(ctx, tx, diffID, resolvedBy); err != nil {
		return fmt.Errorf("resolve difference: %w", err)
	}

	// Update analytics trends (non‑critical, log error only)
	expectedFloat, _ := diff.ExpectedAmount.Float64()
	actualFloat, _ := diff.ActualAmount.Float64()
	trend := &analytics.ReconciliationDiffTrends{
		TrendID:             uuid.New(),
		CompanyID:           batch.CompanyID,
		BatchID:             &diff.BatchID,
		IssueType:           diff.IssueType,
		Date:                time.Now(),
		Count:               1,
		TotalExpectedAmount: expectedFloat,
		TotalActualAmount:   actualFloat,
	}
	if err := s.analyticsRepo.InsertReconciliationDiffTrend(ctx, tx, trend); err != nil {
		logger.Error("failed to insert resolution trend", zap.Error(err))
	}

	// Audit log
	if s.auditService != nil {
		_ = s.auditService.LogAction(ctx, tx, &batch.CompanyID, "reconciliation", "resolve_difference", "reconciliation_difference",
			&diffID, "user", resolvedBy, nil, nil, map[string]interface{}{"adjustment_created": adjustmentID != nil})
	}

	// Idempotency storage
	if idempotencyKey != "" {
		_ = s.idempotencyStore.Store(ctx, tx, idempotencyKey, true)
	}

	// Commit everything atomically
	if err := tx.Commit(); err != nil {
		return fmt.Errorf("commit tx: %w", err)
	}

	logger.Info("difference resolved", zap.Any("adjustment_id", adjustmentID))
	return nil
}

// ----------------------------------------------
// GetDifferences (unchanged – read‑only)
// ----------------------------------------------
func (s *reconciliationService) GetDifferences(ctx context.Context, batchID uuid.UUID, unresolvedOnly bool) ([]*models.ReconciliationDifference, error) {
	return s.repo.GetDifferencesByBatch(ctx, s.pgClient.DB, batchID, unresolvedOnly)
}

// ----------------------------------------------
// CreateAdjustment (mutating) – with idempotency
// ----------------------------------------------
func (s *reconciliationService) CreateAdjustment(ctx context.Context, req CreateAdjustmentRequest) (*models.ReconciliationAdjustment, error) {
	logger := s.logger.With(zap.String("method", "CreateAdjustment"), zap.String("batch_id", req.BatchID.String()))
	idempotencyKey, _ := ctx.Value("idempotency_key").(string)

	tx, err := s.pgClient.BeginTx(ctx, nil)
	if err != nil {
		return nil, fmt.Errorf("begin tx: %w", err)
	}
	defer tx.Rollback()

	if idempotencyKey != "" {
		var existing *models.ReconciliationAdjustment
		if err := s.idempotencyStore.Get(ctx, tx, idempotencyKey, &existing); err == nil && existing != nil {
			logger.Info("idempotent request, returning cached adjustment")
			return existing, nil
		}
	}

	adj := &models.ReconciliationAdjustment{
		AdjustmentID:     uuid.New(),
		BatchID:          req.BatchID,
		JournalEntryID:   req.JournalEntryID,
		Reason:           req.Reason,
		AdjustmentAmount: req.AdjustmentAmount,
		CreatedBy:        req.CreatedBy,
	}

	if err := s.repo.AddAdjustment(ctx, tx, adj); err != nil {
		return nil, fmt.Errorf("add adjustment: %w", err)
	}

	if idempotencyKey != "" {
		_ = s.idempotencyStore.Store(ctx, tx, idempotencyKey, adj)
	}

	if err := tx.Commit(); err != nil {
		return nil, fmt.Errorf("commit tx: %w", err)
	}

	logger.Info("adjustment created", zap.String("adj_id", adj.AdjustmentID.String()))
	return adj, nil
}

// ----------------------------------------------
// DeleteAdjustment (mutating) – with idempotency
// ----------------------------------------------
func (s *reconciliationService) DeleteAdjustment(ctx context.Context, adjID uuid.UUID) error {
	logger := s.logger.With(zap.String("method", "DeleteAdjustment"), zap.String("adj_id", adjID.String()))
	idempotencyKey, _ := ctx.Value("idempotency_key").(string)

	tx, err := s.pgClient.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("begin tx: %w", err)
	}
	defer tx.Rollback()

	if idempotencyKey != "" {
		var cached bool
		if err := s.idempotencyStore.Get(ctx, tx, idempotencyKey, &cached); err == nil && cached {
			logger.Info("idempotent request, adjustment already deleted")
			return nil
		}
	}

	if err := s.repo.DeleteAdjustment(ctx, tx, adjID); err != nil {
		return fmt.Errorf("delete adjustment: %w", err)
	}

	if idempotencyKey != "" {
		_ = s.idempotencyStore.Store(ctx, tx, idempotencyKey, true)
	}

	if err := tx.Commit(); err != nil {
		return fmt.Errorf("commit tx: %w", err)
	}

	logger.Info("adjustment deleted")
	return nil
}

// ----------------------------------------------
// GetAdjustments (unchanged – read‑only)
// ----------------------------------------------
func (s *reconciliationService) GetAdjustments(ctx context.Context, batchID uuid.UUID) ([]*models.ReconciliationAdjustment, error) {
	return s.repo.GetAdjustmentsByBatch(ctx, s.pgClient.DB, batchID)
}

// ----------------------------------------------
// Helper functions (unchanged)
// ----------------------------------------------
func (s *reconciliationService) updateBatchStatsInternal(ctx context.Context, tx repository.DBTX, batchID uuid.UUID) error {
	total, matched, unmatched, err := s.repo.CountItemsByStatus(ctx, tx, batchID)
	if err != nil {
		return err
	}
	return s.repo.UpdateBatchStats(ctx, tx, batchID, total, matched, unmatched)
}

func (s *reconciliationService) validateCreateBatchRequest(req CreateReconciliationBatchRequest) error {
	if req.CompanyID == uuid.Nil {
		return fmt.Errorf("%w: company_id required", ErrInvalidInput)
	}
	if req.ReconciliationType == "" {
		return fmt.Errorf("%w: reconciliation_type required", ErrInvalidInput)
	}
	validTypes := map[string]bool{
		enums.ReconciliationTypeBank:     true,
		enums.ReconciliationTypePayment:  true,
		enums.ReconciliationTypeLedger:   true,
		enums.ReconciliationTypeExternal: true,
	}
	if !validTypes[req.ReconciliationType] {
		return fmt.Errorf("%w: invalid reconciliation_type", ErrInvalidInput)
	}
	if req.StartDate != nil && req.EndDate != nil && req.StartDate.After(*req.EndDate) {
		return fmt.Errorf("%w: start_date cannot be after end_date", ErrInvalidInput)
	}
	return nil
}

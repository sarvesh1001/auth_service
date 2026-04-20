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

// ReconciliationService defines the interface for reconciliation operations
type ReconciliationService interface {
	// Batch management
	CreateBatch(ctx context.Context, req CreateReconciliationBatchRequest) (*models.ReconciliationBatch, error)
	GetBatch(ctx context.Context, batchID uuid.UUID) (*models.ReconciliationBatch, error)
	ListBatches(ctx context.Context, filter ReconciliationFilter, p Pagination) ([]*models.ReconciliationBatch, int64, error)
	UpdateBatchStats(ctx context.Context, batchID uuid.UUID) error
	CompleteBatch(ctx context.Context, batchID uuid.UUID) error
	DeleteBatch(ctx context.Context, batchID uuid.UUID) error

	// Item management
	AddItems(ctx context.Context, batchID uuid.UUID, items []ReconciliationItemInput) ([]*models.ReconciliationItem, error)
	GetItems(ctx context.Context, batchID uuid.UUID, status string) ([]*models.ReconciliationItem, error)
	GetUnmatchedItems(ctx context.Context, batchID uuid.UUID) ([]*models.ReconciliationItem, error)

	// Matching
	AutoMatch(ctx context.Context, batchID uuid.UUID, threshold decimal.Decimal) (*AutoMatchResult, error)
	ManualMatch(ctx context.Context, itemID, journalEntryID uuid.UUID, score decimal.Decimal) error
	SetItemMatchStatus(ctx context.Context, itemID uuid.UUID, status string, journalEntryID *uuid.UUID, score *decimal.Decimal) error
	UnmatchItem(ctx context.Context, itemID uuid.UUID) error

	// Differences
	CreateDifference(ctx context.Context, req CreateDifferenceRequest) (*models.ReconciliationDifference, error)
	ResolveDifference(ctx context.Context, diffID uuid.UUID, resolvedBy *uuid.UUID, adjustmentReq *ResolveDifferenceAdjustmentRequest) error
	GetDifferences(ctx context.Context, batchID uuid.UUID, unresolvedOnly bool) ([]*models.ReconciliationDifference, error)

	// Adjustments
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

// NewReconciliationService creates a new reconciliation service instance
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

// CreateReconciliationBatchRequest defines input for creating a batch
type CreateReconciliationBatchRequest struct {
	CompanyID          uuid.UUID
	ReconciliationType string
	Reference          *string
	StartDate          *time.Time
	EndDate            *time.Time
	CreatedBy          *uuid.UUID
}

// ReconciliationFilter defines filters for listing batches
type ReconciliationFilter struct {
	CompanyID          uuid.UUID
	ReconciliationType string
	Status             string
	FromDate           *time.Time
	ToDate             *time.Time
}

// ReconciliationItemInput defines input for adding items to a batch
type ReconciliationItemInput struct {
	SourceType      string
	SourceID        *uuid.UUID
	Amount          decimal.Decimal
	Currency        string
	TransactionDate time.Time
	Notes           *string
	InitialStatus   *string    // "matched", "unmatched", "partial", "ignored"
	JournalEntryID  *uuid.UUID // if status is matched, optionally link to JE
	MatchScore      *decimal.Decimal
}

// AutoMatchResult holds the result of an auto-match operation
type AutoMatchResult struct {
	TotalCandidates int
	MatchedCount    int
	Errors          []error
}

// CreateDifferenceRequest defines input for creating a difference
type CreateDifferenceRequest struct {
	BatchID        uuid.UUID
	IssueType      string
	ExpectedAmount decimal.Decimal
	ActualAmount   decimal.Decimal
	SourceID       *uuid.UUID
	JournalEntryID *uuid.UUID
	Description    *string
}

// CreateAdjustmentRequest defines input for creating an adjustment
type CreateAdjustmentRequest struct {
	BatchID          uuid.UUID
	JournalEntryID   uuid.UUID
	Reason           *string
	AdjustmentAmount decimal.Decimal
	CreatedBy        *uuid.UUID
}

// ResolveDifferenceAdjustmentRequest defines optional adjustment when resolving a difference
type ResolveDifferenceAdjustmentRequest struct {
	CreateAdjustment bool
	DebitAccountID   uuid.UUID
	CreditAccountID  uuid.UUID
	Description      string
}

// Helper functions
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

// CreateBatch creates a new reconciliation batch
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
		Payload:       payload,
		Status:        "pending",
	}
	if err := s.outboxRepo.Store(ctx, tx, outboxEvent); err != nil {
		return nil, fmt.Errorf("store outbox event: %w", err)
	}

	if idempotencyKey != "" {
		_ = s.idempotencyStore.Store(ctx, tx, idempotencyKey, batch)
	}

	if err := tx.Commit(); err != nil {
		return nil, fmt.Errorf("commit tx: %w", err)
	}

	if s.auditService != nil {
		_ = s.auditService.LogAction(ctx, tx, &req.CompanyID, "reconciliation", "create", "reconciliation_batch",
			&batch.BatchID, "user", req.CreatedBy, nil, nil, nil)
	}

	logger.Info("reconciliation batch created", zap.String("batch_id", batch.BatchID.String()))
	return batch, nil
}

// GetBatch returns a batch by ID
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

// ListBatches returns a paginated list of batches matching the filter
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

// UpdateBatchStats recalculates and updates statistics for a batch
func (s *reconciliationService) UpdateBatchStats(ctx context.Context, batchID uuid.UUID) error {
	tx, err := s.pgClient.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("begin tx: %w", err)
	}
	defer tx.Rollback()
	if err := s.updateBatchStatsInternal(ctx, tx, batchID); err != nil {
		return err
	}
	return tx.Commit()
}

// CompleteBatch marks a batch as completed (only if no unmatched items)
func (s *reconciliationService) CompleteBatch(ctx context.Context, batchID uuid.UUID) error {
	logger := s.logger.With(zap.String("method", "CompleteBatch"), zap.String("batch_id", batchID.String()))
	tx, err := s.pgClient.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("begin tx: %w", err)
	}
	defer tx.Rollback()

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
		Payload:       payload,
		Status:        "pending",
	}
	if err := s.outboxRepo.Store(ctx, tx, outboxEvent); err != nil {
		return fmt.Errorf("store outbox event: %w", err)
	}

	if err := tx.Commit(); err != nil {
		return fmt.Errorf("commit tx: %w", err)
	}

	logger.Info("batch completed")
	return nil
}

// DeleteBatch deletes a batch and all its related data (only if not completed)
func (s *reconciliationService) DeleteBatch(ctx context.Context, batchID uuid.UUID) error {
	logger := s.logger.With(zap.String("method", "DeleteBatch"), zap.String("batch_id", batchID.String()))
	tx, err := s.pgClient.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("begin tx: %w", err)
	}
	defer tx.Rollback()

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

	if err := tx.Commit(); err != nil {
		return fmt.Errorf("commit tx: %w", err)
	}

	logger.Info("batch deleted")
	return nil
}

// AddItems adds reconciliation items to a batch
func (s *reconciliationService) AddItems(ctx context.Context, batchID uuid.UUID, items []ReconciliationItemInput) ([]*models.ReconciliationItem, error) {
	logger := s.logger.With(zap.String("method", "AddItems"), zap.String("batch_id", batchID.String()))
	if len(items) == 0 {
		return nil, nil
	}

	tx, err := s.pgClient.BeginTx(ctx, nil)
	if err != nil {
		return nil, fmt.Errorf("begin tx: %w", err)
	}
	defer tx.Rollback()

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
		sourceID := uuid.NullUUID{}
		if inp.SourceID != nil {
			sourceID = uuid.NullUUID{UUID: *inp.SourceID, Valid: true}
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

	if err := tx.Commit(); err != nil {
		return nil, fmt.Errorf("commit tx: %w", err)
	}

	logger.Info("items added to batch", zap.Int("count", len(modelItems)))
	return modelItems, nil
}

// GetItems returns all items of a batch, optionally filtered by status
func (s *reconciliationService) GetItems(ctx context.Context, batchID uuid.UUID, status string) ([]*models.ReconciliationItem, error) {
	if status != "" {
		return s.repo.GetItemsByStatus(ctx, s.pgClient.DB, batchID, status)
	}
	return s.repo.GetItemsByBatch(ctx, s.pgClient.DB, batchID)
}

// GetUnmatchedItems returns items with status 'unmatched' for a batch
func (s *reconciliationService) GetUnmatchedItems(ctx context.Context, batchID uuid.UUID) ([]*models.ReconciliationItem, error) {
	return s.repo.GetUnmatchedItems(ctx, s.pgClient.DB, batchID)
}

// AutoMatch automatically matches items based on a threshold
func (s *reconciliationService) AutoMatch(ctx context.Context, batchID uuid.UUID, threshold decimal.Decimal) (*AutoMatchResult, error) {
	logger := s.logger.With(zap.String("method", "AutoMatch"), zap.String("batch_id", batchID.String()))
	tx, err := s.pgClient.BeginTx(ctx, nil)
	if err != nil {
		return nil, fmt.Errorf("begin tx: %w", err)
	}
	defer tx.Rollback()

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

	candidates, err := s.repo.FindPotentialMatches(ctx, tx, batchID, threshold)
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

	// If any errors occurred, set batch status to 'failed'
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
		Payload:       payload,
		Status:        "pending",
	}
	if err := s.outboxRepo.Store(ctx, tx, outboxEvent); err != nil {
		return nil, fmt.Errorf("store outbox event: %w", err)
	}

	if err := tx.Commit(); err != nil {
		return nil, fmt.Errorf("commit tx: %w", err)
	}

	logger.Info("auto-match completed", zap.Int("matched", matchedCount), zap.Int("candidates", len(candidates)), zap.Int("errors", len(result.Errors)))
	return result, nil
}

// ManualMatch manually matches an item to a journal entry
func (s *reconciliationService) ManualMatch(ctx context.Context, itemID, journalEntryID uuid.UUID, score decimal.Decimal) error {
	logger := s.logger.With(zap.String("method", "ManualMatch"), zap.String("item_id", itemID.String()))
	tx, err := s.pgClient.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("begin tx: %w", err)
	}
	defer tx.Rollback()

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

	if err := tx.Commit(); err != nil {
		return fmt.Errorf("commit tx: %w", err)
	}

	if s.auditService != nil {
		_ = s.auditService.LogAction(ctx, tx, &batch.CompanyID, "reconciliation", "manual_match", "reconciliation_item",
			&itemID, "system", nil, nil, nil, map[string]interface{}{"journal_entry_id": journalEntryID.String()})
	}

	logger.Info("manual match completed", zap.String("journal_entry_id", journalEntryID.String()))
	return nil
}

// SetItemMatchStatus allows setting any match status (partial, ignored, matched) and optionally linking to a JE
func (s *reconciliationService) SetItemMatchStatus(ctx context.Context, itemID uuid.UUID, status string, journalEntryID *uuid.UUID, score *decimal.Decimal) error {
	logger := s.logger.With(zap.String("method", "SetItemMatchStatus"), zap.String("item_id", itemID.String()), zap.String("status", status))
	tx, err := s.pgClient.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("begin tx: %w", err)
	}
	defer tx.Rollback()

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

	if status == enums.MatchStatusMatched && (journalEntryID == nil || *journalEntryID == uuid.Nil) {
		return fmt.Errorf("%w: journal_entry_id required for matched status", ErrInvalidInput)
	}

	jeID := uuid.NullUUID{}
	if journalEntryID != nil {
		jeID = uuid.NullUUID{UUID: *journalEntryID, Valid: true}
	}
	if err := s.repo.UpdateItemMatch(ctx, tx, itemID, status, jeID, score); err != nil {
		return fmt.Errorf("update match status: %w", err)
	}

	if err := s.updateBatchStatsInternal(ctx, tx, item.BatchID); err != nil {
		return fmt.Errorf("update batch stats: %w", err)
	}

	if err := tx.Commit(); err != nil {
		return fmt.Errorf("commit tx: %w", err)
	}

	logger.Info("item match status updated")
	return nil
}

// UnmatchItem removes a match from an item, setting it back to unmatched
func (s *reconciliationService) UnmatchItem(ctx context.Context, itemID uuid.UUID) error {
	logger := s.logger.With(zap.String("method", "UnmatchItem"), zap.String("item_id", itemID.String()))
	tx, err := s.pgClient.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("begin tx: %w", err)
	}
	defer tx.Rollback()

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

	if err := tx.Commit(); err != nil {
		return fmt.Errorf("commit tx: %w", err)
	}

	logger.Info("item unmatched")
	return nil
}
func (s *reconciliationService) CreateDifference(ctx context.Context, req CreateDifferenceRequest) (*models.ReconciliationDifference, error) {
	logger := s.logger.With(zap.String("method", "CreateDifference"), zap.String("batch_id", req.BatchID.String()))
	tx, err := s.pgClient.BeginTx(ctx, nil)
	if err != nil {
		return nil, fmt.Errorf("begin tx: %w", err)
	}
	defer tx.Rollback()

	// Fetch batch to get companyID for trend
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
		SourceID:       nullUUIDFromPtr(req.SourceID),
		JournalEntryID: nullUUIDFromPtr(req.JournalEntryID),
		Description:    req.Description,
		Resolved:       false,
	}

	if err := s.repo.AddDifference(ctx, tx, diff); err != nil {
		return nil, fmt.Errorf("add difference: %w", err)
	}

	// Convert decimal to float64 for trend
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
		Payload:       payload,
		Status:        "pending",
	}
	if err := s.outboxRepo.Store(ctx, tx, outboxEvent); err != nil {
		return nil, fmt.Errorf("store outbox event: %w", err)
	}

	if err := tx.Commit(); err != nil {
		return nil, fmt.Errorf("commit tx: %w", err)
	}

	logger.Info("difference created", zap.String("diff_id", diff.DifferenceID.String()))
	return diff, nil
}

func (s *reconciliationService) ResolveDifference(ctx context.Context, diffID uuid.UUID, resolvedBy *uuid.UUID, adjustmentReq *ResolveDifferenceAdjustmentRequest) error {
	logger := s.logger.With(zap.String("method", "ResolveDifference"), zap.String("diff_id", diffID.String()))
	tx, err := s.pgClient.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("begin tx: %w", err)
	}
	defer tx.Rollback()

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

	// Fetch batch to get company ID (for journal entry creation)
	batch, err := s.repo.GetBatchByID(ctx, tx, diff.BatchID)
	if err != nil {
		return fmt.Errorf("get batch: %w", err)
	}
	if batch == nil {
		return fmt.Errorf("%w: batch %s not found", ErrNotFound, diff.BatchID)
	}

	var adjustmentID *uuid.UUID
	if adjustmentReq != nil && adjustmentReq.CreateAdjustment {
		// Calculate the absolute difference amount
		amountDiff := diff.ExpectedAmount.Sub(diff.ActualAmount).Abs()
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
		journalEntry, err := s.journalService.Create(ctx, journalReq)
		if err != nil {
			return fmt.Errorf("create adjustment journal entry: %w", err)
		}
		// Create adjustment record
		adjReq := CreateAdjustmentRequest{
			BatchID:          diff.BatchID,
			JournalEntryID:   journalEntry.JournalEntryID,
			Reason:           stringPtr(fmt.Sprintf("Auto-adjustment for difference %s", diffID.String())),
			AdjustmentAmount: amountDiff,
			CreatedBy:        resolvedBy,
		}
		adj, err := s.CreateAdjustment(ctx, adjReq)
		if err != nil {
			return fmt.Errorf("create adjustment record: %w", err)
		}
		adjustmentID = &adj.AdjustmentID
	}

	if err := s.repo.ResolveDifference(ctx, tx, diffID, resolvedBy); err != nil {
		return fmt.Errorf("resolve difference: %w", err)
	}

	// Convert decimal to float64 for resolution trend
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

	if err := tx.Commit(); err != nil {
		return fmt.Errorf("commit tx: %w", err)
	}

	logger.Info("difference resolved", zap.Any("adjustment_id", adjustmentID))
	return nil
}

// GetDifferences returns differences for a batch
func (s *reconciliationService) GetDifferences(ctx context.Context, batchID uuid.UUID, unresolvedOnly bool) ([]*models.ReconciliationDifference, error) {
	return s.repo.GetDifferencesByBatch(ctx, s.pgClient.DB, batchID, unresolvedOnly)
}

// CreateAdjustment creates a new adjustment record
func (s *reconciliationService) CreateAdjustment(ctx context.Context, req CreateAdjustmentRequest) (*models.ReconciliationAdjustment, error) {
	logger := s.logger.With(zap.String("method", "CreateAdjustment"), zap.String("batch_id", req.BatchID.String()))
	tx, err := s.pgClient.BeginTx(ctx, nil)
	if err != nil {
		return nil, fmt.Errorf("begin tx: %w", err)
	}
	defer tx.Rollback()

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

	if err := tx.Commit(); err != nil {
		return nil, fmt.Errorf("commit tx: %w", err)
	}

	logger.Info("adjustment created", zap.String("adj_id", adj.AdjustmentID.String()))
	return adj, nil
}

// DeleteAdjustment deletes an adjustment record
func (s *reconciliationService) DeleteAdjustment(ctx context.Context, adjID uuid.UUID) error {
	logger := s.logger.With(zap.String("method", "DeleteAdjustment"), zap.String("adj_id", adjID.String()))
	tx, err := s.pgClient.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("begin tx: %w", err)
	}
	defer tx.Rollback()

	if err := s.repo.DeleteAdjustment(ctx, tx, adjID); err != nil {
		return fmt.Errorf("delete adjustment: %w", err)
	}

	if err := tx.Commit(); err != nil {
		return fmt.Errorf("commit tx: %w", err)
	}

	logger.Info("adjustment deleted")
	return nil
}

// GetAdjustments returns all adjustments for a batch
func (s *reconciliationService) GetAdjustments(ctx context.Context, batchID uuid.UUID) ([]*models.ReconciliationAdjustment, error) {
	return s.repo.GetAdjustmentsByBatch(ctx, s.pgClient.DB, batchID)
}

// Internal helper to update batch statistics
func (s *reconciliationService) updateBatchStatsInternal(ctx context.Context, tx repository.DBTX, batchID uuid.UUID) error {
	total, matched, unmatched, err := s.repo.CountItemsByStatus(ctx, tx, batchID)
	if err != nil {
		return err
	}
	return s.repo.UpdateBatchStats(ctx, tx, batchID, total, matched, unmatched)
}

// validateCreateBatchRequest validates the request for creating a batch
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

// FILE: ./repository/reconciliation_repository.go
package repository

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/shopspring/decimal"
	"go.uber.org/zap"

	"auth-service/internal/accounting/models"
	"auth-service/internal/accounting/models/enums"
	"auth-service/internal/util"
)

// ReconciliationFilter for listing batches
type ReconciliationFilter struct {
	CompanyID          uuid.UUID
	ReconciliationType string
	Status             string
	FromDate           *time.Time
	ToDate             *time.Time
}

// MatchCandidate represents a potential match between an item and a journal entry
type MatchCandidate struct {
	ItemID         uuid.UUID
	JournalEntryID uuid.UUID
	Score          decimal.Decimal
}

// ReconciliationRepository defines the interface for reconciliation data access
type ReconciliationRepository interface {
	// Batches
	CreateBatch(ctx context.Context, db DBTX, batch *models.ReconciliationBatch) error
	UpdateBatch(ctx context.Context, db DBTX, batch *models.ReconciliationBatch) error
	GetBatchByID(ctx context.Context, db DBTX, batchID uuid.UUID) (*models.ReconciliationBatch, error)
	GetBatchByIDForUpdate(ctx context.Context, db DBTX, batchID uuid.UUID) (*models.ReconciliationBatch, error)
	ListBatches(ctx context.Context, db DBTX, filter ReconciliationFilter, p Pagination, s Sort) ([]*models.ReconciliationBatch, error)
	CountBatches(ctx context.Context, db DBTX, filter ReconciliationFilter) (int64, error)
	UpdateBatchStats(ctx context.Context, db DBTX, batchID uuid.UUID, total, matched, unmatched int) error
	CompleteBatch(ctx context.Context, db DBTX, batchID uuid.UUID, completedAt time.Time) error
	DeleteBatch(ctx context.Context, db DBTX, batchID uuid.UUID) error
	UpdateItemMatch(ctx context.Context, db DBTX, itemID uuid.UUID, status string, journalEntryID uuid.NullUUID, score *decimal.Decimal) error

	// Items
	AddItem(ctx context.Context, db DBTX, item *models.ReconciliationItem) error
	BulkAddItems(ctx context.Context, db DBTX, items []*models.ReconciliationItem) error
	UpdateItem(ctx context.Context, db DBTX, item *models.ReconciliationItem) error
	GetItemByID(ctx context.Context, db DBTX, itemID uuid.UUID) (*models.ReconciliationItem, error)
	GetItemsByBatch(ctx context.Context, db DBTX, batchID uuid.UUID) ([]*models.ReconciliationItem, error)
	GetItemsByStatus(ctx context.Context, db DBTX, batchID uuid.UUID, matchStatus string) ([]*models.ReconciliationItem, error)
	GetUnmatchedItems(ctx context.Context, db DBTX, batchID uuid.UUID) ([]*models.ReconciliationItem, error)
	CountItemsByStatus(ctx context.Context, db DBTX, batchID uuid.UUID) (total int, matched int, unmatched int, err error)

	// Matching operations
	MatchItem(ctx context.Context, db DBTX, itemID, journalEntryID uuid.UUID, score decimal.Decimal) error
	UnmatchItem(ctx context.Context, db DBTX, itemID uuid.UUID) error
	FindPotentialMatches(ctx context.Context, db DBTX, batchID uuid.UUID, threshold decimal.Decimal) ([]*MatchCandidate, error)

	// Differences
	AddDifference(ctx context.Context, db DBTX, diff *models.ReconciliationDifference) error
	BulkAddDifferences(ctx context.Context, db DBTX, diffs []*models.ReconciliationDifference) error
	GetDifferenceByID(ctx context.Context, db DBTX, diffID uuid.UUID) (*models.ReconciliationDifference, error)
	GetDifferencesByBatch(ctx context.Context, db DBTX, batchID uuid.UUID, unresolvedOnly bool) ([]*models.ReconciliationDifference, error)
	ResolveDifference(ctx context.Context, db DBTX, diffID uuid.UUID, resolvedBy *uuid.UUID) error
	DeleteDifference(ctx context.Context, db DBTX, diffID uuid.UUID) error

	// Adjustments
	AddAdjustment(ctx context.Context, db DBTX, adj *models.ReconciliationAdjustment) error
	GetAdjustmentsByBatch(ctx context.Context, db DBTX, batchID uuid.UUID) ([]*models.ReconciliationAdjustment, error)
	GetAdjustmentByID(ctx context.Context, db DBTX, adjID uuid.UUID) (*models.ReconciliationAdjustment, error)
	DeleteAdjustment(ctx context.Context, db DBTX, adjID uuid.UUID) error
}

// reconciliationRepository implements ReconciliationRepository
type reconciliationRepository struct {
	logger *zap.Logger
}

// NewReconciliationRepository creates a new reconciliation repository instance
func NewReconciliationRepository(logger *zap.Logger) ReconciliationRepository {
	return &reconciliationRepository{
		logger: logger.Named("reconciliation_repo"),
	}
}

// allowed sort fields for batches
var allowedReconciliationSortFields = map[string]bool{
	"created_at":          true,
	"completed_at":        true,
	"status":              true,
	"reconciliation_type": true,
	"total_records":       true,
	"matched_records":     true,
}

func (r *reconciliationRepository) validateSort(s Sort) (string, error) {
	field := s.Field
	if field == "" {
		field = "created_at"
	}
	if !allowedReconciliationSortFields[field] {
		return "", fmt.Errorf("invalid sort field: %s", field)
	}
	dir := strings.ToUpper(s.Direction)
	if dir != "ASC" && dir != "DESC" {
		dir = "DESC"
	}
	return fmt.Sprintf("ORDER BY %s %s", field, dir), nil
}

func (r *reconciliationRepository) validatePagination(p Pagination) (int, int) {
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

func (r *reconciliationRepository) buildBatchFilter(filter ReconciliationFilter) (string, []interface{}) {
	var conditions []string
	var args []interface{}
	idx := 1

	if filter.CompanyID != uuid.Nil {
		conditions = append(conditions, fmt.Sprintf("company_id = $%d", idx))
		args = append(args, filter.CompanyID)
		idx++
	}
	if filter.ReconciliationType != "" {
		conditions = append(conditions, fmt.Sprintf("reconciliation_type = $%d", idx))
		args = append(args, filter.ReconciliationType)
		idx++
	}
	if filter.Status != "" {
		conditions = append(conditions, fmt.Sprintf("status = $%d", idx))
		args = append(args, filter.Status)
		idx++
	}
	if filter.FromDate != nil {
		conditions = append(conditions, fmt.Sprintf("created_at >= $%d", idx))
		args = append(args, *filter.FromDate)
		idx++
	}
	if filter.ToDate != nil {
		conditions = append(conditions, fmt.Sprintf("created_at <= $%d", idx))
		args = append(args, *filter.ToDate)
		idx++
	}

	if len(conditions) == 0 {
		return "", args
	}
	return "WHERE " + strings.Join(conditions, " AND "), args
}

func (r *reconciliationRepository) scanBatch(scanner interface {
	Scan(dest ...interface{}) error
}) (*models.ReconciliationBatch, error) {
	var b models.ReconciliationBatch
	var reference, status sql.NullString
	var startDate, endDate, completedAt sql.NullTime
	var createdBy uuid.NullUUID

	err := scanner.Scan(
		&b.BatchID, &b.CompanyID, &b.ReconciliationType, &reference,
		&startDate, &endDate, &status,
		&b.TotalRecords, &b.MatchedRecords, &b.UnmatchedRecords,
		&b.CreatedAt, &completedAt, &createdBy,
	)
	if err != nil {
		return nil, err
	}
	if reference.Valid {
		b.Reference = &reference.String
	}
	if startDate.Valid {
		b.StartDate = &startDate.Time
	}
	if endDate.Valid {
		b.EndDate = &endDate.Time
	}
	if status.Valid {
		b.Status = status.String
	}
	if completedAt.Valid {
		b.CompletedAt = &completedAt.Time
	}
	if createdBy.Valid {
		b.CreatedBy = &createdBy.UUID
	}
	return &b, nil
}

func (r *reconciliationRepository) scanItem(scanner interface {
	Scan(dest ...interface{}) error
}) (*models.ReconciliationItem, error) {
	var i models.ReconciliationItem
	var sourceID, journalEntryID uuid.NullUUID
	var matchScore sql.NullString // decimal stored as numeric
	var notes sql.NullString

	err := scanner.Scan(
		&i.ItemID, &i.BatchID, &i.SourceType, &sourceID, &journalEntryID,
		&i.Amount, &i.Currency, &i.TransactionDate, &i.MatchStatus,
		&matchScore, &notes, &i.CreatedAt, &i.UpdatedAt,
	)
	if err != nil {
		return nil, err
	}
	i.SourceID = sourceID
	i.JournalEntryID = journalEntryID
	if matchScore.Valid {
		score, err := decimal.NewFromString(matchScore.String)
		if err == nil {
			i.MatchScore = &score
		}
	}
	if notes.Valid {
		i.Notes = &notes.String
	}
	return &i, nil
}

func (r *reconciliationRepository) scanDifference(scanner interface {
	Scan(dest ...interface{}) error
}) (*models.ReconciliationDifference, error) {
	var d models.ReconciliationDifference
	var sourceID, journalEntryID uuid.NullUUID
	var description, issueType sql.NullString
	var resolvedBy uuid.NullUUID
	var resolvedAt sql.NullTime

	err := scanner.Scan(
		&d.DifferenceID, &d.BatchID, &issueType,
		&d.ExpectedAmount, &d.ActualAmount, &sourceID, &journalEntryID,
		&description, &d.Resolved, &resolvedBy, &resolvedAt, &d.CreatedAt,
	)
	if err != nil {
		return nil, err
	}
	if issueType.Valid {
		d.IssueType = issueType.String
	}
	d.SourceID = sourceID
	d.JournalEntryID = journalEntryID
	if description.Valid {
		d.Description = &description.String
	}
	if resolvedBy.Valid {
		d.ResolvedBy = &resolvedBy.UUID
	}
	if resolvedAt.Valid {
		d.ResolvedAt = &resolvedAt.Time
	}
	return &d, nil
}

func (r *reconciliationRepository) scanAdjustment(scanner interface {
	Scan(dest ...interface{}) error
}) (*models.ReconciliationAdjustment, error) {
	var a models.ReconciliationAdjustment
	var reason sql.NullString
	var createdBy uuid.NullUUID

	err := scanner.Scan(
		&a.AdjustmentID, &a.BatchID, &a.JournalEntryID,
		&reason, &a.AdjustmentAmount, &a.CreatedAt, &createdBy,
	)
	if err != nil {
		return nil, err
	}
	if reason.Valid {
		a.Reason = &reason.String
	}
	if createdBy.Valid {
		a.CreatedBy = &createdBy.UUID
	}
	return &a, nil
}

// =====================================================
// BATCH OPERATIONS
// =====================================================

func (r *reconciliationRepository) CreateBatch(ctx context.Context, db DBTX, batch *models.ReconciliationBatch) error {
	query := `
		INSERT INTO accounting.reconciliation_batches (
			batch_id, company_id, reconciliation_type, reference,
			start_date, end_date, status, total_records, matched_records,
			unmatched_records, created_at, completed_at, created_by
		) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, NOW(), $11, $12)
		RETURNING created_at
	`
	err := db.QueryRowContext(ctx, query,
		batch.BatchID, batch.CompanyID, batch.ReconciliationType, batch.Reference,
		batch.StartDate, batch.EndDate, batch.Status,
		batch.TotalRecords, batch.MatchedRecords, batch.UnmatchedRecords,
		batch.CompletedAt, batch.CreatedBy,
	).Scan(&batch.CreatedAt)
	if err != nil {
		r.logger.Error("failed to create reconciliation batch",
			util.String("company_id", batch.CompanyID.String()),
			util.String("type", batch.ReconciliationType),
			util.ErrorField(err))
		return fmt.Errorf("create reconciliation batch: %w", err)
	}
	return nil
}

func (r *reconciliationRepository) UpdateBatch(ctx context.Context, db DBTX, batch *models.ReconciliationBatch) error {
	query := `
		UPDATE accounting.reconciliation_batches
		SET reconciliation_type = $2,
		    reference = $3,
		    start_date = $4,
		    end_date = $5,
		    status = $6,
		    total_records = $7,
		    matched_records = $8,
		    unmatched_records = $9,
		    completed_at = $10
		WHERE batch_id = $1
	`
	_, err := db.ExecContext(ctx, query,
		batch.BatchID, batch.ReconciliationType, batch.Reference,
		batch.StartDate, batch.EndDate, batch.Status,
		batch.TotalRecords, batch.MatchedRecords, batch.UnmatchedRecords,
		batch.CompletedAt,
	)
	if err != nil {
		r.logger.Error("failed to update reconciliation batch",
			util.String("batch_id", batch.BatchID.String()),
			util.ErrorField(err))
		return fmt.Errorf("update reconciliation batch: %w", err)
	}
	return nil
}

func (r *reconciliationRepository) GetBatchByID(ctx context.Context, db DBTX, batchID uuid.UUID) (*models.ReconciliationBatch, error) {
	query := `
		SELECT batch_id, company_id, reconciliation_type, reference,
		       start_date, end_date, status, total_records, matched_records,
		       unmatched_records, created_at, completed_at, created_by
		FROM accounting.reconciliation_batches
		WHERE batch_id = $1
	`
	batch, err := r.scanBatch(db.QueryRowContext(ctx, query, batchID))
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, nil
		}
		r.logger.Error("failed to get batch by ID",
			util.String("batch_id", batchID.String()),
			util.ErrorField(err))
		return nil, fmt.Errorf("get batch by ID: %w", err)
	}
	return batch, nil
}

func (r *reconciliationRepository) GetBatchByIDForUpdate(ctx context.Context, db DBTX, batchID uuid.UUID) (*models.ReconciliationBatch, error) {
	query := `
		SELECT batch_id, company_id, reconciliation_type, reference,
		       start_date, end_date, status, total_records, matched_records,
		       unmatched_records, created_at, completed_at, created_by
		FROM accounting.reconciliation_batches
		WHERE batch_id = $1
		FOR UPDATE
	`
	batch, err := r.scanBatch(db.QueryRowContext(ctx, query, batchID))
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, nil
		}
		r.logger.Error("failed to get batch for update",
			util.String("batch_id", batchID.String()),
			util.ErrorField(err))
		return nil, fmt.Errorf("get batch for update: %w", err)
	}
	return batch, nil
}

func (r *reconciliationRepository) ListBatches(ctx context.Context, db DBTX, filter ReconciliationFilter, p Pagination, s Sort) ([]*models.ReconciliationBatch, error) {
	where, args := r.buildBatchFilter(filter)
	orderBy, err := r.validateSort(s)
	if err != nil {
		return nil, err
	}
	limit, offset := r.validatePagination(p)

	query := fmt.Sprintf(`
		SELECT batch_id, company_id, reconciliation_type, reference,
		       start_date, end_date, status, total_records, matched_records,
		       unmatched_records, created_at, completed_at, created_by
		FROM accounting.reconciliation_batches
		%s
		%s
		LIMIT $%d OFFSET $%d
	`, where, orderBy, len(args)+1, len(args)+2)

	args = append(args, limit, offset)
	rows, err := db.QueryContext(ctx, query, args...)
	if err != nil {
		r.logger.Error("failed to list batches",
			util.Any("filter", filter),
			util.ErrorField(err))
		return nil, fmt.Errorf("list batches: %w", err)
	}
	defer rows.Close()

	var result []*models.ReconciliationBatch
	for rows.Next() {
		b, err := r.scanBatch(rows)
		if err != nil {
			return nil, fmt.Errorf("scan batch: %w", err)
		}
		result = append(result, b)
	}
	return result, nil
}

func (r *reconciliationRepository) CountBatches(ctx context.Context, db DBTX, filter ReconciliationFilter) (int64, error) {
	where, args := r.buildBatchFilter(filter)
	query := fmt.Sprintf("SELECT COUNT(*) FROM accounting.reconciliation_batches %s", where)
	var count int64
	err := db.QueryRowContext(ctx, query, args...).Scan(&count)
	if err != nil {
		r.logger.Error("failed to count batches",
			util.Any("filter", filter),
			util.ErrorField(err))
		return 0, fmt.Errorf("count batches: %w", err)
	}
	return count, nil
}

func (r *reconciliationRepository) UpdateBatchStats(ctx context.Context, db DBTX, batchID uuid.UUID, total, matched, unmatched int) error {
	query := `
		UPDATE accounting.reconciliation_batches
		SET total_records = $2, matched_records = $3, unmatched_records = $4
		WHERE batch_id = $1
	`
	_, err := db.ExecContext(ctx, query, batchID, total, matched, unmatched)
	if err != nil {
		r.logger.Error("failed to update batch stats",
			util.String("batch_id", batchID.String()),
			util.ErrorField(err))
		return fmt.Errorf("update batch stats: %w", err)
	}
	return nil
}

func (r *reconciliationRepository) CompleteBatch(ctx context.Context, db DBTX, batchID uuid.UUID, completedAt time.Time) error {
	query := `
		UPDATE accounting.reconciliation_batches
		SET status = 'completed', completed_at = $2
		WHERE batch_id = $1
	`
	_, err := db.ExecContext(ctx, query, batchID, completedAt)
	if err != nil {
		r.logger.Error("failed to complete batch",
			util.String("batch_id", batchID.String()),
			util.ErrorField(err))
		return fmt.Errorf("complete batch: %w", err)
	}
	return nil
}

func (r *reconciliationRepository) DeleteBatch(ctx context.Context, db DBTX, batchID uuid.UUID) error {
	// Delete associated items, differences, adjustments first (cascade handled by FK, but explicit for safety)
	_, err := db.ExecContext(ctx, `DELETE FROM accounting.reconciliation_items WHERE batch_id = $1`, batchID)
	if err != nil {
		return fmt.Errorf("delete batch items: %w", err)
	}
	_, err = db.ExecContext(ctx, `DELETE FROM accounting.reconciliation_differences WHERE batch_id = $1`, batchID)
	if err != nil {
		return fmt.Errorf("delete batch differences: %w", err)
	}
	_, err = db.ExecContext(ctx, `DELETE FROM accounting.reconciliation_adjustments WHERE batch_id = $1`, batchID)
	if err != nil {
		return fmt.Errorf("delete batch adjustments: %w", err)
	}
	_, err = db.ExecContext(ctx, `DELETE FROM accounting.reconciliation_batches WHERE batch_id = $1`, batchID)
	if err != nil {
		r.logger.Error("failed to delete batch",
			util.String("batch_id", batchID.String()),
			util.ErrorField(err))
		return fmt.Errorf("delete batch: %w", err)
	}
	return nil
}

// =====================================================
// ITEM OPERATIONS
// =====================================================

func (r *reconciliationRepository) AddItem(ctx context.Context, db DBTX, item *models.ReconciliationItem) error {
	query := `
		INSERT INTO accounting.reconciliation_items (
			item_id, batch_id, source_type, source_id, journal_entry_id,
			amount, currency, transaction_date, match_status, match_score,
			notes, created_at, updated_at
		) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, NOW(), NOW())
		RETURNING created_at, updated_at
	`
	err := db.QueryRowContext(ctx, query,
		item.ItemID, item.BatchID, item.SourceType, item.SourceID, item.JournalEntryID,
		item.Amount, item.Currency, item.TransactionDate, item.MatchStatus, item.MatchScore,
		item.Notes,
	).Scan(&item.CreatedAt, &item.UpdatedAt)
	if err != nil {
		r.logger.Error("failed to add reconciliation item",
			util.String("batch_id", item.BatchID.String()),
			util.ErrorField(err))
		return fmt.Errorf("add reconciliation item: %w", err)
	}
	return nil
}

func (r *reconciliationRepository) BulkAddItems(ctx context.Context, db DBTX, items []*models.ReconciliationItem) error {
	if len(items) == 0 {
		return nil
	}
	stmt, err := db.PrepareContext(ctx, `
		INSERT INTO accounting.reconciliation_items (
			item_id, batch_id, source_type, source_id, journal_entry_id,
			amount, currency, transaction_date, match_status, match_score,
			notes, created_at, updated_at
		) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, NOW(), NOW())
		RETURNING created_at, updated_at
	`)
	if err != nil {
		return fmt.Errorf("prepare bulk insert items: %w", err)
	}
	defer stmt.Close()

	for _, item := range items {
		err = stmt.QueryRowContext(ctx,
			item.ItemID, item.BatchID, item.SourceType, item.SourceID, item.JournalEntryID,
			item.Amount, item.Currency, item.TransactionDate, item.MatchStatus, item.MatchScore,
			item.Notes,
		).Scan(&item.CreatedAt, &item.UpdatedAt)
		if err != nil {
			r.logger.Error("bulk add item failed",
				util.String("batch_id", item.BatchID.String()),
				util.ErrorField(err))
			return fmt.Errorf("bulk add reconciliation item: %w", err)
		}
	}
	return nil
}

func (r *reconciliationRepository) UpdateItem(ctx context.Context, db DBTX, item *models.ReconciliationItem) error {
	query := `
		UPDATE accounting.reconciliation_items
		SET source_type = $2,
		    source_id = $3,
		    journal_entry_id = $4,
		    amount = $5,
		    currency = $6,
		    transaction_date = $7,
		    match_status = $8,
		    match_score = $9,
		    notes = $10,
		    updated_at = NOW()
		WHERE item_id = $1
		RETURNING updated_at
	`
	err := db.QueryRowContext(ctx, query,
		item.ItemID, item.SourceType, item.SourceID, item.JournalEntryID,
		item.Amount, item.Currency, item.TransactionDate, item.MatchStatus,
		item.MatchScore, item.Notes,
	).Scan(&item.UpdatedAt)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return fmt.Errorf("item %s not found", item.ItemID)
		}
		r.logger.Error("failed to update reconciliation item",
			util.String("item_id", item.ItemID.String()),
			util.ErrorField(err))
		return fmt.Errorf("update reconciliation item: %w", err)
	}
	return nil
}

func (r *reconciliationRepository) GetItemByID(ctx context.Context, db DBTX, itemID uuid.UUID) (*models.ReconciliationItem, error) {
	query := `
		SELECT item_id, batch_id, source_type, source_id, journal_entry_id,
		       amount, currency, transaction_date, match_status, match_score,
		       notes, created_at, updated_at
		FROM accounting.reconciliation_items
		WHERE item_id = $1
	`
	item, err := r.scanItem(db.QueryRowContext(ctx, query, itemID))
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, nil
		}
		r.logger.Error("failed to get item by ID",
			util.String("item_id", itemID.String()),
			util.ErrorField(err))
		return nil, fmt.Errorf("get item by ID: %w", err)
	}
	return item, nil
}

func (r *reconciliationRepository) GetItemsByBatch(ctx context.Context, db DBTX, batchID uuid.UUID) ([]*models.ReconciliationItem, error) {
	query := `
		SELECT item_id, batch_id, source_type, source_id, journal_entry_id,
		       amount, currency, transaction_date, match_status, match_score,
		       notes, created_at, updated_at
		FROM accounting.reconciliation_items
		WHERE batch_id = $1
		ORDER BY transaction_date, created_at
	`
	rows, err := db.QueryContext(ctx, query, batchID)
	if err != nil {
		r.logger.Error("failed to get items by batch",
			util.String("batch_id", batchID.String()),
			util.ErrorField(err))
		return nil, fmt.Errorf("get items by batch: %w", err)
	}
	defer rows.Close()

	var items []*models.ReconciliationItem
	for rows.Next() {
		item, err := r.scanItem(rows)
		if err != nil {
			return nil, fmt.Errorf("scan item: %w", err)
		}
		items = append(items, item)
	}
	return items, nil
}

func (r *reconciliationRepository) GetItemsByStatus(ctx context.Context, db DBTX, batchID uuid.UUID, matchStatus string) ([]*models.ReconciliationItem, error) {
	query := `
		SELECT item_id, batch_id, source_type, source_id, journal_entry_id,
		       amount, currency, transaction_date, match_status, match_score,
		       notes, created_at, updated_at
		FROM accounting.reconciliation_items
		WHERE batch_id = $1 AND match_status = $2
		ORDER BY transaction_date
	`
	rows, err := db.QueryContext(ctx, query, batchID, matchStatus)
	if err != nil {
		r.logger.Error("failed to get items by status",
			util.String("batch_id", batchID.String()),
			util.String("status", matchStatus),
			util.ErrorField(err))
		return nil, fmt.Errorf("get items by status: %w", err)
	}
	defer rows.Close()

	var items []*models.ReconciliationItem
	for rows.Next() {
		item, err := r.scanItem(rows)
		if err != nil {
			return nil, fmt.Errorf("scan item: %w", err)
		}
		items = append(items, item)
	}
	return items, nil
}

func (r *reconciliationRepository) GetUnmatchedItems(ctx context.Context, db DBTX, batchID uuid.UUID) ([]*models.ReconciliationItem, error) {
	return r.GetItemsByStatus(ctx, db, batchID, enums.MatchStatusUnmatched)
}

func (r *reconciliationRepository) CountItemsByStatus(ctx context.Context, db DBTX, batchID uuid.UUID) (total int, matched int, unmatched int, err error) {
	query := `
		SELECT COUNT(*),
		       COUNT(CASE WHEN match_status = 'matched' THEN 1 END),
		       COUNT(CASE WHEN match_status = 'unmatched' THEN 1 END)
		FROM accounting.reconciliation_items
		WHERE batch_id = $1
	`
	err = db.QueryRowContext(ctx, query, batchID).Scan(&total, &matched, &unmatched)
	if err != nil {
		r.logger.Error("failed to count items by status",
			util.String("batch_id", batchID.String()),
			util.ErrorField(err))
		return 0, 0, 0, fmt.Errorf("count items by status: %w", err)
	}
	return total, matched, unmatched, nil
}

// =====================================================
// MATCHING OPERATIONS
// =====================================================

func (r *reconciliationRepository) MatchItem(ctx context.Context, db DBTX, itemID, journalEntryID uuid.UUID, score decimal.Decimal) error {
	query := `
		UPDATE accounting.reconciliation_items
		SET journal_entry_id = $2,
		    match_status = 'matched',
		    match_score = $3,
		    updated_at = NOW()
		WHERE item_id = $1
	`
	_, err := db.ExecContext(ctx, query, itemID, journalEntryID, score)
	if err != nil {
		r.logger.Error("failed to match item",
			util.String("item_id", itemID.String()),
			util.ErrorField(err))
		return fmt.Errorf("match item: %w", err)
	}
	return nil
}

func (r *reconciliationRepository) UnmatchItem(ctx context.Context, db DBTX, itemID uuid.UUID) error {
	query := `
		UPDATE accounting.reconciliation_items
		SET journal_entry_id = NULL,
		    match_status = 'unmatched',
		    match_score = NULL,
		    updated_at = NOW()
		WHERE item_id = $1
	`
	_, err := db.ExecContext(ctx, query, itemID)
	if err != nil {
		r.logger.Error("failed to unmatch item",
			util.String("item_id", itemID.String()),
			util.ErrorField(err))
		return fmt.Errorf("unmatch item: %w", err)
	}
	return nil
}

func (r *reconciliationRepository) FindPotentialMatches(ctx context.Context, db DBTX, batchID uuid.UUID, threshold decimal.Decimal) ([]*MatchCandidate, error) {
	// This is a simplified matching query: match by exact amount and close transaction date.
	// In real implementation, you might use more sophisticated logic (fuzzy matching).
	query := `
		SELECT i.item_id, je.journal_entry_id,
		       100.0 AS score
		FROM accounting.reconciliation_items i
		CROSS JOIN LATERAL (
			SELECT je.journal_entry_id
			FROM accounting.journal_entries je
			INNER JOIN accounting.journal_lines jl ON je.journal_entry_id = jl.journal_entry_id
			WHERE je.company_id = (SELECT company_id FROM accounting.reconciliation_batches WHERE batch_id = $1)
			  AND je.status = 'posted'
			  AND ABS(jl.amount) = i.amount
			  AND je.entry_date BETWEEN i.transaction_date - interval '3 days' AND i.transaction_date + interval '3 days'
			LIMIT 1
		) je ON true
		WHERE i.batch_id = $1
		  AND i.match_status = 'unmatched'
		  AND 100.0 >= $2
	`
	rows, err := db.QueryContext(ctx, query, batchID, threshold)
	if err != nil {
		r.logger.Error("failed to find potential matches",
			util.String("batch_id", batchID.String()),
			util.ErrorField(err))
		return nil, fmt.Errorf("find potential matches: %w", err)
	}
	defer rows.Close()

	var candidates []*MatchCandidate
	for rows.Next() {
		var c MatchCandidate
		if err := rows.Scan(&c.ItemID, &c.JournalEntryID, &c.Score); err != nil {
			return nil, fmt.Errorf("scan candidate: %w", err)
		}
		candidates = append(candidates, &c)
	}
	return candidates, nil
}

// =====================================================
// DIFFERENCE OPERATIONS
// =====================================================

func (r *reconciliationRepository) AddDifference(ctx context.Context, db DBTX, diff *models.ReconciliationDifference) error {
	query := `
		INSERT INTO accounting.reconciliation_differences (
			difference_id, batch_id, issue_type, expected_amount, actual_amount,
			source_id, journal_entry_id, description, resolved, resolved_by,
			resolved_at, created_at
		) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, NOW())
		RETURNING created_at
	`
	err := db.QueryRowContext(ctx, query,
		diff.DifferenceID, diff.BatchID, diff.IssueType, diff.ExpectedAmount, diff.ActualAmount,
		diff.SourceID, diff.JournalEntryID, diff.Description, diff.Resolved,
		diff.ResolvedBy, diff.ResolvedAt,
	).Scan(&diff.CreatedAt)
	if err != nil {
		r.logger.Error("failed to add difference",
			util.String("batch_id", diff.BatchID.String()),
			util.ErrorField(err))
		return fmt.Errorf("add difference: %w", err)
	}
	return nil
}

func (r *reconciliationRepository) BulkAddDifferences(ctx context.Context, db DBTX, diffs []*models.ReconciliationDifference) error {
	if len(diffs) == 0 {
		return nil
	}
	stmt, err := db.PrepareContext(ctx, `
		INSERT INTO accounting.reconciliation_differences (
			difference_id, batch_id, issue_type, expected_amount, actual_amount,
			source_id, journal_entry_id, description, resolved, resolved_by,
			resolved_at, created_at
		) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, NOW())
		RETURNING created_at
	`)
	if err != nil {
		return fmt.Errorf("prepare bulk insert differences: %w", err)
	}
	defer stmt.Close()

	for _, d := range diffs {
		err = stmt.QueryRowContext(ctx,
			d.DifferenceID, d.BatchID, d.IssueType, d.ExpectedAmount, d.ActualAmount,
			d.SourceID, d.JournalEntryID, d.Description, d.Resolved,
			d.ResolvedBy, d.ResolvedAt,
		).Scan(&d.CreatedAt)
		if err != nil {
			r.logger.Error("bulk add difference failed",
				util.String("batch_id", d.BatchID.String()),
				util.ErrorField(err))
			return fmt.Errorf("bulk add difference: %w", err)
		}
	}
	return nil
}

func (r *reconciliationRepository) GetDifferenceByID(ctx context.Context, db DBTX, diffID uuid.UUID) (*models.ReconciliationDifference, error) {
	query := `
		SELECT difference_id, batch_id, issue_type, expected_amount, actual_amount,
		       source_id, journal_entry_id, description, resolved, resolved_by,
		       resolved_at, created_at
		FROM accounting.reconciliation_differences
		WHERE difference_id = $1
	`
	diff, err := r.scanDifference(db.QueryRowContext(ctx, query, diffID))
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, nil
		}
		r.logger.Error("failed to get difference by ID",
			util.String("diff_id", diffID.String()),
			util.ErrorField(err))
		return nil, fmt.Errorf("get difference by ID: %w", err)
	}
	return diff, nil
}

func (r *reconciliationRepository) GetDifferencesByBatch(ctx context.Context, db DBTX, batchID uuid.UUID, unresolvedOnly bool) ([]*models.ReconciliationDifference, error) {
	query := `
		SELECT difference_id, batch_id, issue_type, expected_amount, actual_amount,
		       source_id, journal_entry_id, description, resolved, resolved_by,
		       resolved_at, created_at
		FROM accounting.reconciliation_differences
		WHERE batch_id = $1
	`
	args := []interface{}{batchID}
	if unresolvedOnly {
		query += " AND resolved = false"
	}
	query += " ORDER BY created_at"
	rows, err := db.QueryContext(ctx, query, args...)
	if err != nil {
		r.logger.Error("failed to get differences by batch",
			util.String("batch_id", batchID.String()),
			util.ErrorField(err))
		return nil, fmt.Errorf("get differences by batch: %w", err)
	}
	defer rows.Close()

	var diffs []*models.ReconciliationDifference
	for rows.Next() {
		d, err := r.scanDifference(rows)
		if err != nil {
			return nil, fmt.Errorf("scan difference: %w", err)
		}
		diffs = append(diffs, d)
	}
	return diffs, nil
}

func (r *reconciliationRepository) ResolveDifference(ctx context.Context, db DBTX, diffID uuid.UUID, resolvedBy *uuid.UUID) error {
	query := `
		UPDATE accounting.reconciliation_differences
		SET resolved = true, resolved_by = $2, resolved_at = NOW()
		WHERE difference_id = $1
	`
	_, err := db.ExecContext(ctx, query, diffID, resolvedBy)
	if err != nil {
		r.logger.Error("failed to resolve difference",
			util.String("diff_id", diffID.String()),
			util.ErrorField(err))
		return fmt.Errorf("resolve difference: %w", err)
	}
	return nil
}

func (r *reconciliationRepository) DeleteDifference(ctx context.Context, db DBTX, diffID uuid.UUID) error {
	_, err := db.ExecContext(ctx, `DELETE FROM accounting.reconciliation_differences WHERE difference_id = $1`, diffID)
	if err != nil {
		r.logger.Error("failed to delete difference",
			util.String("diff_id", diffID.String()),
			util.ErrorField(err))
		return fmt.Errorf("delete difference: %w", err)
	}
	return nil
}

// =====================================================
// ADJUSTMENT OPERATIONS
// =====================================================

func (r *reconciliationRepository) AddAdjustment(ctx context.Context, db DBTX, adj *models.ReconciliationAdjustment) error {
	query := `
		INSERT INTO accounting.reconciliation_adjustments (
			adjustment_id, batch_id, journal_entry_id, reason,
			adjustment_amount, created_at, created_by
		) VALUES ($1, $2, $3, $4, $5, NOW(), $6)
		RETURNING created_at
	`
	err := db.QueryRowContext(ctx, query,
		adj.AdjustmentID, adj.BatchID, adj.JournalEntryID, adj.Reason,
		adj.AdjustmentAmount, adj.CreatedBy,
	).Scan(&adj.CreatedAt)
	if err != nil {
		r.logger.Error("failed to add adjustment",
			util.String("batch_id", adj.BatchID.String()),
			util.ErrorField(err))
		return fmt.Errorf("add adjustment: %w", err)
	}
	return nil
}

func (r *reconciliationRepository) GetAdjustmentsByBatch(ctx context.Context, db DBTX, batchID uuid.UUID) ([]*models.ReconciliationAdjustment, error) {
	query := `
		SELECT adjustment_id, batch_id, journal_entry_id, reason,
		       adjustment_amount, created_at, created_by
		FROM accounting.reconciliation_adjustments
		WHERE batch_id = $1
		ORDER BY created_at
	`
	rows, err := db.QueryContext(ctx, query, batchID)
	if err != nil {
		r.logger.Error("failed to get adjustments by batch",
			util.String("batch_id", batchID.String()),
			util.ErrorField(err))
		return nil, fmt.Errorf("get adjustments by batch: %w", err)
	}
	defer rows.Close()

	var adjustments []*models.ReconciliationAdjustment
	for rows.Next() {
		adj, err := r.scanAdjustment(rows)
		if err != nil {
			return nil, fmt.Errorf("scan adjustment: %w", err)
		}
		adjustments = append(adjustments, adj)
	}
	return adjustments, nil
}

func (r *reconciliationRepository) GetAdjustmentByID(ctx context.Context, db DBTX, adjID uuid.UUID) (*models.ReconciliationAdjustment, error) {
	query := `
		SELECT adjustment_id, batch_id, journal_entry_id, reason,
		       adjustment_amount, created_at, created_by
		FROM accounting.reconciliation_adjustments
		WHERE adjustment_id = $1
	`
	adj, err := r.scanAdjustment(db.QueryRowContext(ctx, query, adjID))
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, nil
		}
		r.logger.Error("failed to get adjustment by ID",
			util.String("adj_id", adjID.String()),
			util.ErrorField(err))
		return nil, fmt.Errorf("get adjustment by ID: %w", err)
	}
	return adj, nil
}

func (r *reconciliationRepository) DeleteAdjustment(ctx context.Context, db DBTX, adjID uuid.UUID) error {
	_, err := db.ExecContext(ctx, `DELETE FROM accounting.reconciliation_adjustments WHERE adjustment_id = $1`, adjID)
	if err != nil {
		r.logger.Error("failed to delete adjustment",
			util.String("adj_id", adjID.String()),
			util.ErrorField(err))
		return fmt.Errorf("delete adjustment: %w", err)
	}
	return nil
}
func (r *reconciliationRepository) UpdateItemMatch(ctx context.Context, db DBTX, itemID uuid.UUID, status string, journalEntryID uuid.NullUUID, score *decimal.Decimal) error {
	query := `
		UPDATE accounting.reconciliation_items
		SET match_status = $2,
		    journal_entry_id = $3,
		    match_score = $4,
		    updated_at = NOW()
		WHERE item_id = $1
	`
	_, err := db.ExecContext(ctx, query, itemID, status, journalEntryID, score)
	if err != nil {
		r.logger.Error("failed to update item match status",
			zap.String("item_id", itemID.String()),
			zap.String("status", status),
			zap.Error(err))
		return fmt.Errorf("update item match: %w", err)
	}
	return nil
}

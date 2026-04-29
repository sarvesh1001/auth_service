package repository

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/lib/pq"
	"github.com/shopspring/decimal"
	"go.uber.org/zap"

	"auth-service/internal/accounting/models"
	"auth-service/internal/accounting/models/analytics"
	"auth-service/internal/accounting/models/enums"
	"auth-service/internal/util"
)

type ReconciliationFilter struct {
	CompanyID          uuid.UUID
	ReconciliationType string
	Status             string
	FromDate           *time.Time
	ToDate             *time.Time
}

type MatchCandidate struct {
	ItemID         uuid.UUID
	JournalEntryID uuid.UUID
	Score          decimal.Decimal
}

type ReconciliationRepository interface {
	CreateBatch(ctx context.Context, db DBTX, batch *models.ReconciliationBatch) error
	UpdateBatch(ctx context.Context, db DBTX, batch *models.ReconciliationBatch) error
	GetBatchByID(ctx context.Context, db DBTX, batchID uuid.UUID) (*models.ReconciliationBatch, error)
	GetBatchByIDForUpdate(ctx context.Context, db DBTX, batchID uuid.UUID) (*models.ReconciliationBatch, error)
	GetBatchByReference(ctx context.Context, db DBTX, companyID uuid.UUID, reference string) (*models.ReconciliationBatch, error)
	ListBatches(ctx context.Context, db DBTX, filter ReconciliationFilter, p Pagination, s Sort) ([]*models.ReconciliationBatch, error)
	CountBatches(ctx context.Context, db DBTX, filter ReconciliationFilter) (int64, error)
	StartBatch(ctx context.Context, db DBTX, batchID uuid.UUID) error
	CompleteBatch(ctx context.Context, db DBTX, batchID uuid.UUID, completedAt time.Time) error
	FailBatch(ctx context.Context, db DBTX, batchID uuid.UUID, reason *string) error
	DeleteBatch(ctx context.Context, db DBTX, batchID uuid.UUID) error
	AddItem(ctx context.Context, db DBTX, item *models.ReconciliationItem) error
	BulkAddItems(ctx context.Context, db DBTX, items []*models.ReconciliationItem) error
	UpdateItem(ctx context.Context, db DBTX, item *models.ReconciliationItem) error
	GetItemByID(ctx context.Context, db DBTX, itemID uuid.UUID) (*models.ReconciliationItem, error)
	GetItemForUpdate(ctx context.Context, db DBTX, itemID uuid.UUID) (*models.ReconciliationItem, error)
	GetItemBySource(ctx context.Context, db DBTX, batchID uuid.UUID, sourceType string, sourceID string) (*models.ReconciliationItem, error) // changed: sourceID string
	GetItemsByBatch(ctx context.Context, db DBTX, batchID uuid.UUID, limit, offset int) ([]*models.ReconciliationItem, error)
	GetItemsByStatus(ctx context.Context, db DBTX, batchID uuid.UUID, matchStatus string, limit, offset int) ([]*models.ReconciliationItem, error)
	GetUnmatchedItems(ctx context.Context, db DBTX, batchID uuid.UUID, limit, offset int) ([]*models.ReconciliationItem, error)
	CountItemsByStatus(ctx context.Context, db DBTX, batchID uuid.UUID) (total int, matched int, unmatched int, err error)
	UpdateItemStatus(ctx context.Context, db DBTX, itemID uuid.UUID, status string, journalEntryID *uuid.UUID, score *decimal.Decimal) error
	UpdateBatchStats(ctx context.Context, db DBTX, batchID uuid.UUID, total, matched, unmatched int) error
	MatchItem(ctx context.Context, db DBTX, itemID, journalEntryID uuid.UUID, score decimal.Decimal) error
	BulkMatchItems(ctx context.Context, db DBTX, matches []MatchCandidate) error
	UnmatchItem(ctx context.Context, db DBTX, itemID uuid.UUID) error
	FindPotentialMatches(ctx context.Context, db DBTX, batchID uuid.UUID, threshold decimal.Decimal, limit int) ([]*MatchCandidate, error)
	AddDifference(ctx context.Context, db DBTX, diff *models.ReconciliationDifference) error
	BulkAddDifferences(ctx context.Context, db DBTX, diffs []*models.ReconciliationDifference) error
	GetDifferenceByID(ctx context.Context, db DBTX, diffID uuid.UUID) (*models.ReconciliationDifference, error)
	GetDifferencesByBatch(ctx context.Context, db DBTX, batchID uuid.UUID, unresolvedOnly bool) ([]*models.ReconciliationDifference, error)
	ResolveDifference(ctx context.Context, db DBTX, diffID uuid.UUID, resolvedBy *uuid.UUID) error
	DeleteDifference(ctx context.Context, db DBTX, diffID uuid.UUID) error
	AddAdjustment(ctx context.Context, db DBTX, adj *models.ReconciliationAdjustment) error
	GetAdjustmentsByBatch(ctx context.Context, db DBTX, batchID uuid.UUID) ([]*models.ReconciliationAdjustment, error)
	GetAdjustmentByID(ctx context.Context, db DBTX, adjID uuid.UUID) (*models.ReconciliationAdjustment, error)
	DeleteAdjustment(ctx context.Context, db DBTX, adjID uuid.UUID) error
	GetBatchMetrics(ctx context.Context, db DBTX, batchID uuid.UUID) (*analytics.ReconciliationBatchMetrics, error)
	ListBatchMetrics(ctx context.Context, db DBTX, companyID uuid.UUID, limit, offset int) ([]*analytics.ReconciliationBatchMetrics, error)
	GetDailyStats(ctx context.Context, db DBTX, companyID uuid.UUID, reconciliationType string, date time.Time) (*analytics.ReconciliationDailyStats, error)
	ListDailyStats(ctx context.Context, db DBTX, companyID uuid.UUID, fromDate, toDate time.Time) ([]*analytics.ReconciliationDailyStats, error)
	GetDiffTrends(ctx context.Context, db DBTX, companyID uuid.UUID, fromDate, toDate time.Time) ([]*analytics.ReconciliationDiffTrends, error)
}

type reconciliationRepository struct {
	logger *zap.Logger
}

func NewReconciliationRepository(logger *zap.Logger) ReconciliationRepository {
	return &reconciliationRepository{
		logger: logger.Named("reconciliation_repo"),
	}
}

var allowedReconciliationSortFields = map[string]bool{
	"created_at":          true,
	"completed_at":        true,
	"status":              true,
	"reconciliation_type": true,
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

func isDuplicateKeyError(err error) bool {
	if pqErr, ok := err.(*pq.Error); ok {
		return pqErr.Code == "23505"
	}
	return false
}

func (r *reconciliationRepository) scanBatch(scanner interface {
	Scan(dest ...interface{}) error
}) (*models.ReconciliationBatch, error) {
	var b models.ReconciliationBatch
	var reference, status sql.NullString
	var startDate, endDate, completedAt sql.NullTime
	var createdBy uuid.NullUUID
	var failureReason sql.NullString
	err := scanner.Scan(
		&b.BatchID, &b.CompanyID, &b.ReconciliationType, &reference,
		&startDate, &endDate, &status,
		&b.TotalRecords, &b.MatchedRecords, &b.UnmatchedRecords,
		&b.CreatedAt, &completedAt, &createdBy, &failureReason,
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
	if failureReason.Valid {
		b.FailureReason = &failureReason.String
	}
	return &b, nil
}

// Updated scanItem: source_id as sql.NullString
func (r *reconciliationRepository) scanItem(scanner interface {
	Scan(dest ...interface{}) error
}) (*models.ReconciliationItem, error) {
	var i models.ReconciliationItem
	var sourceID sql.NullString // changed: from uuid.NullUUID
	var journalEntryID uuid.NullUUID
	var matchScore sql.NullString
	var notes sql.NullString
	err := scanner.Scan(
		&i.ItemID, &i.BatchID, &i.SourceType, &sourceID, &journalEntryID,
		&i.Amount, &i.Currency, &i.TransactionDate, &i.MatchStatus,
		&matchScore, &notes, &i.CreatedAt, &i.UpdatedAt,
	)
	if err != nil {
		return nil, err
	}
	if sourceID.Valid {
		i.SourceID = &sourceID.String
	}
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
	var sourceID sql.NullString // ✅ changed from uuid.NullUUID
	var journalEntryID uuid.NullUUID
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
	if sourceID.Valid {
		d.SourceID = &sourceID.String // ✅ assign pointer to string
	}
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

func (r *reconciliationRepository) CreateBatch(ctx context.Context, db DBTX, batch *models.ReconciliationBatch) error {
	batch.TotalRecords = 0
	batch.MatchedRecords = 0
	batch.UnmatchedRecords = 0
	query := `
		INSERT INTO accounting.reconciliation_batches (
			batch_id, company_id, reconciliation_type, reference,
			start_date, end_date, status, total_records, matched_records,
			unmatched_records, created_at, completed_at, created_by, failure_reason
		) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, NOW(), $11, $12, $13)
		RETURNING created_at
	`
	err := db.QueryRowContext(ctx, query,
		batch.BatchID, batch.CompanyID, batch.ReconciliationType, batch.Reference,
		batch.StartDate, batch.EndDate, batch.Status,
		batch.TotalRecords, batch.MatchedRecords, batch.UnmatchedRecords,
		batch.CompletedAt, batch.CreatedBy, batch.FailureReason,
	).Scan(&batch.CreatedAt)
	if err != nil {
		if isDuplicateKeyError(err) {
			return ErrDuplicate
		}
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
		    completed_at = $7,
		    failure_reason = $8
		WHERE batch_id = $1 AND status != 'completed'
	`
	res, err := db.ExecContext(ctx, query,
		batch.BatchID, batch.ReconciliationType, batch.Reference,
		batch.StartDate, batch.EndDate, batch.Status,
		batch.CompletedAt, batch.FailureReason,
	)
	if err != nil {
		r.logger.Error("failed to update reconciliation batch",
			util.String("batch_id", batch.BatchID.String()),
			util.ErrorField(err))
		return fmt.Errorf("update reconciliation batch: %w", err)
	}
	if rows, _ := res.RowsAffected(); rows == 0 {
		return ErrNotFound
	}
	return nil
}

func (r *reconciliationRepository) GetBatchByID(ctx context.Context, db DBTX, batchID uuid.UUID) (*models.ReconciliationBatch, error) {
	query := `
		SELECT batch_id, company_id, reconciliation_type, reference,
		       start_date, end_date, status, total_records, matched_records,
		       unmatched_records, created_at, completed_at, created_by, failure_reason
		FROM accounting.reconciliation_batches
		WHERE batch_id = $1
	`
	batch, err := r.scanBatch(db.QueryRowContext(ctx, query, batchID))
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, ErrNotFound
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
		       unmatched_records, created_at, completed_at, created_by, failure_reason
		FROM accounting.reconciliation_batches
		WHERE batch_id = $1
		FOR UPDATE
	`
	batch, err := r.scanBatch(db.QueryRowContext(ctx, query, batchID))
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, ErrNotFound
		}
		r.logger.Error("failed to get batch for update",
			util.String("batch_id", batchID.String()),
			util.ErrorField(err))
		return nil, fmt.Errorf("get batch for update: %w", err)
	}
	return batch, nil
}

func (r *reconciliationRepository) GetBatchByReference(ctx context.Context, db DBTX, companyID uuid.UUID, reference string) (*models.ReconciliationBatch, error) {
	query := `
		SELECT batch_id, company_id, reconciliation_type, reference,
		       start_date, end_date, status, total_records, matched_records,
		       unmatched_records, created_at, completed_at, created_by, failure_reason
		FROM accounting.reconciliation_batches
		WHERE company_id = $1 AND reference = $2
	`
	batch, err := r.scanBatch(db.QueryRowContext(ctx, query, companyID, reference))
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, ErrNotFound
		}
		r.logger.Error("failed to get batch by reference",
			util.String("company_id", companyID.String()),
			util.String("reference", reference),
			util.ErrorField(err))
		return nil, fmt.Errorf("get batch by reference: %w", err)
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
		       unmatched_records, created_at, completed_at, created_by, failure_reason
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

func (r *reconciliationRepository) StartBatch(ctx context.Context, db DBTX, batchID uuid.UUID) error {
	res, err := db.ExecContext(ctx, `
		UPDATE accounting.reconciliation_batches
		SET status = 'in_progress'
		WHERE batch_id = $1 AND status = 'pending'
	`, batchID)
	if err != nil {
		r.logger.Error("failed to start batch",
			util.String("batch_id", batchID.String()),
			util.ErrorField(err))
		return fmt.Errorf("start batch: %w", err)
	}
	if rows, _ := res.RowsAffected(); rows == 0 {
		return ErrNotFound
	}
	return nil
}

func (r *reconciliationRepository) CompleteBatch(ctx context.Context, db DBTX, batchID uuid.UUID, completedAt time.Time) error {
	res, err := db.ExecContext(ctx, `
		UPDATE accounting.reconciliation_batches
		SET status = 'completed', completed_at = $2
		WHERE batch_id = $1 AND status != 'completed'
	`, batchID, completedAt)
	if err != nil {
		r.logger.Error("failed to complete batch",
			util.String("batch_id", batchID.String()),
			util.ErrorField(err))
		return fmt.Errorf("complete batch: %w", err)
	}
	if rows, _ := res.RowsAffected(); rows == 0 {
		return ErrNotFound
	}
	return nil
}

func (r *reconciliationRepository) FailBatch(ctx context.Context, db DBTX, batchID uuid.UUID, reason *string) error {
	query := `
		UPDATE accounting.reconciliation_batches
		SET status = 'failed', failure_reason = $2
		WHERE batch_id = $1 AND status NOT IN ('completed', 'failed')
	`
	res, err := db.ExecContext(ctx, query, batchID, reason)
	if err != nil {
		r.logger.Error("failed to mark batch as failed",
			util.String("batch_id", batchID.String()),
			util.ErrorField(err))
		return fmt.Errorf("fail batch: %w", err)
	}
	if rows, _ := res.RowsAffected(); rows == 0 {
		return ErrNotFound
	}
	return nil
}

func (r *reconciliationRepository) DeleteBatch(ctx context.Context, db DBTX, batchID uuid.UUID) error {
	res, err := db.ExecContext(ctx, `DELETE FROM accounting.reconciliation_batches WHERE batch_id = $1`, batchID)
	if err != nil {
		r.logger.Error("failed to delete batch",
			util.String("batch_id", batchID.String()),
			util.ErrorField(err))
		return fmt.Errorf("delete batch: %w", err)
	}
	if rows, _ := res.RowsAffected(); rows == 0 {
		return ErrNotFound
	}
	return nil
}

// AddItem: source_id as string
func (r *reconciliationRepository) AddItem(ctx context.Context, db DBTX, item *models.ReconciliationItem) error {
	if item.Amount.LessThanOrEqual(decimal.Zero) {
		return errors.New("amount must be positive")
	}
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
		if isDuplicateKeyError(err) {
			return ErrDuplicate
		}
		r.logger.Error("failed to add reconciliation item",
			util.String("batch_id", item.BatchID.String()),
			util.ErrorField(err))
		return fmt.Errorf("add reconciliation item: %w", err)
	}
	return nil
}

// BulkAddItems: source_id as string
func (r *reconciliationRepository) BulkAddItems(ctx context.Context, db DBTX, items []*models.ReconciliationItem) error {
	if len(items) == 0 {
		return nil
	}
	for _, item := range items {
		if item.Amount.LessThanOrEqual(decimal.Zero) {
			return errors.New("all items must have positive amount")
		}
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
		err := stmt.QueryRowContext(ctx,
			item.ItemID, item.BatchID, item.SourceType, item.SourceID, item.JournalEntryID,
			item.Amount, item.Currency, item.TransactionDate, item.MatchStatus, item.MatchScore,
			item.Notes,
		).Scan(&item.CreatedAt, &item.UpdatedAt)
		if err != nil {
			if isDuplicateKeyError(err) {
				return ErrDuplicate
			}
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
			return ErrNotFound
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
			return nil, ErrNotFound
		}
		r.logger.Error("failed to get item by ID",
			util.String("item_id", itemID.String()),
			util.ErrorField(err))
		return nil, fmt.Errorf("get item by ID: %w", err)
	}
	return item, nil
}

func (r *reconciliationRepository) GetItemForUpdate(ctx context.Context, db DBTX, itemID uuid.UUID) (*models.ReconciliationItem, error) {
	query := `
		SELECT item_id, batch_id, source_type, source_id, journal_entry_id,
		       amount, currency, transaction_date, match_status, match_score,
		       notes, created_at, updated_at
		FROM accounting.reconciliation_items
		WHERE item_id = $1
		FOR UPDATE
	`
	item, err := r.scanItem(db.QueryRowContext(ctx, query, itemID))
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, ErrNotFound
		}
		r.logger.Error("failed to get item for update",
			util.String("item_id", itemID.String()),
			util.ErrorField(err))
		return nil, fmt.Errorf("get item for update: %w", err)
	}
	return item, nil
}

// GetItemBySource: sourceID is now string
func (r *reconciliationRepository) GetItemBySource(ctx context.Context, db DBTX, batchID uuid.UUID, sourceType string, sourceID string) (*models.ReconciliationItem, error) {
	query := `
		SELECT item_id, batch_id, source_type, source_id, journal_entry_id,
		       amount, currency, transaction_date, match_status, match_score,
		       notes, created_at, updated_at
		FROM accounting.reconciliation_items
		WHERE batch_id = $1 AND source_type = $2 AND source_id = $3
	`
	item, err := r.scanItem(db.QueryRowContext(ctx, query, batchID, sourceType, sourceID))
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, ErrNotFound
		}
		r.logger.Error("failed to get item by source",
			util.String("batch_id", batchID.String()),
			util.String("source_type", sourceType),
			util.String("source_id", sourceID),
			util.ErrorField(err))
		return nil, fmt.Errorf("get item by source: %w", err)
	}
	return item, nil
}

func (r *reconciliationRepository) GetItemsByBatch(ctx context.Context, db DBTX, batchID uuid.UUID, limit, offset int) ([]*models.ReconciliationItem, error) {
	if limit <= 0 {
		limit = 100
	}
	query := `
		SELECT item_id, batch_id, source_type, source_id, journal_entry_id,
		       amount, currency, transaction_date, match_status, match_score,
		       notes, created_at, updated_at
		FROM accounting.reconciliation_items
		WHERE batch_id = $1
		ORDER BY transaction_date, created_at
		LIMIT $2 OFFSET $3
	`
	rows, err := db.QueryContext(ctx, query, batchID, limit, offset)
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

func (r *reconciliationRepository) GetItemsByStatus(ctx context.Context, db DBTX, batchID uuid.UUID, matchStatus string, limit, offset int) ([]*models.ReconciliationItem, error) {
	if !util.Contains(enums.ValidMatchStatuses, matchStatus) {
		return nil, fmt.Errorf("invalid match status: %s", matchStatus)
	}
	if limit <= 0 {
		limit = 100
	}
	query := `
		SELECT item_id, batch_id, source_type, source_id, journal_entry_id,
		       amount, currency, transaction_date, match_status, match_score,
		       notes, created_at, updated_at
		FROM accounting.reconciliation_items
		WHERE batch_id = $1 AND match_status = $2
		ORDER BY transaction_date
		LIMIT $3 OFFSET $4
	`
	rows, err := db.QueryContext(ctx, query, batchID, matchStatus, limit, offset)
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

func (r *reconciliationRepository) GetUnmatchedItems(ctx context.Context, db DBTX, batchID uuid.UUID, limit, offset int) ([]*models.ReconciliationItem, error) {
	return r.GetItemsByStatus(ctx, db, batchID, enums.MatchStatusUnmatched, limit, offset)
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

func (r *reconciliationRepository) MatchItem(ctx context.Context, db DBTX, itemID, journalEntryID uuid.UUID, score decimal.Decimal) error {
	res, err := db.ExecContext(ctx, `
		UPDATE accounting.reconciliation_items
		SET journal_entry_id = $2,
		    match_status = 'matched',
		    match_score = $3,
		    updated_at = NOW()
		WHERE item_id = $1 AND match_status != 'matched'
	`, itemID, journalEntryID, score)
	if err != nil {
		r.logger.Error("failed to match item",
			util.String("item_id", itemID.String()),
			util.ErrorField(err))
		return fmt.Errorf("match item: %w", err)
	}
	if rows, _ := res.RowsAffected(); rows == 0 {
		return ErrNotFound
	}
	return nil
}

func (r *reconciliationRepository) BulkMatchItems(ctx context.Context, db DBTX, matches []MatchCandidate) error {
	if len(matches) == 0 {
		return nil
	}
	stmt, err := db.PrepareContext(ctx, `
		UPDATE accounting.reconciliation_items
		SET journal_entry_id = $2,
		    match_status = 'matched',
		    match_score = $3,
		    updated_at = NOW()
		WHERE item_id = $1 AND match_status != 'matched'
	`)
	if err != nil {
		return fmt.Errorf("prepare bulk match: %w", err)
	}
	defer stmt.Close()
	for _, m := range matches {
		res, err := stmt.ExecContext(ctx, m.ItemID, m.JournalEntryID, m.Score)
		if err != nil {
			return fmt.Errorf("bulk match item %s: %w", m.ItemID, err)
		}
		if rows, _ := res.RowsAffected(); rows == 0 {
			return fmt.Errorf("item %s not found or already matched", m.ItemID)
		}
	}
	return nil
}

func (r *reconciliationRepository) UnmatchItem(ctx context.Context, db DBTX, itemID uuid.UUID) error {
	res, err := db.ExecContext(ctx, `
		UPDATE accounting.reconciliation_items
		SET journal_entry_id = NULL,
		    match_status = 'unmatched',
		    match_score = NULL,
		    updated_at = NOW()
		WHERE item_id = $1
	`, itemID)
	if err != nil {
		r.logger.Error("failed to unmatch item",
			util.String("item_id", itemID.String()),
			util.ErrorField(err))
		return fmt.Errorf("unmatch item: %w", err)
	}
	if rows, _ := res.RowsAffected(); rows == 0 {
		return ErrNotFound
	}
	return nil
}

func (r *reconciliationRepository) FindPotentialMatches(ctx context.Context, db DBTX, batchID uuid.UUID, threshold decimal.Decimal, limit int) ([]*MatchCandidate, error) {
	if limit <= 0 {
		limit = 50
	}
	query := `
		SELECT i.item_id, je.journal_entry_id, 100.0 AS score
		FROM accounting.reconciliation_items i
		CROSS JOIN LATERAL (
			SELECT je.journal_entry_id
			FROM accounting.journal_entries je
			INNER JOIN accounting.journal_lines jl ON je.journal_entry_id = jl.journal_entry_id
			WHERE je.company_id = (SELECT company_id FROM accounting.reconciliation_batches WHERE batch_id = $1)
			  AND je.status = 'posted'
			  AND (jl.debit_amount = i.amount OR jl.credit_amount = i.amount)
			  AND je.entry_date BETWEEN i.transaction_date - interval '3 days' AND i.transaction_date + interval '3 days'
			LIMIT 1
		) je
		WHERE i.batch_id = $1
		  AND i.match_status = 'unmatched'
		  AND 100.0 >= $2
		LIMIT $3
	`
	rows, err := db.QueryContext(ctx, query, batchID, threshold, limit)
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
		diff.SourceID, // ✅ directly pass *string (nil is allowed)
		diff.JournalEntryID, diff.Description, diff.Resolved,
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
		err := stmt.QueryRowContext(ctx,
			d.DifferenceID, d.BatchID, d.IssueType, d.ExpectedAmount, d.ActualAmount,
			d.SourceID, // ✅ directly pass *string
			d.JournalEntryID, d.Description, d.Resolved,
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
			return nil, ErrNotFound
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
	res, err := db.ExecContext(ctx, `
		UPDATE accounting.reconciliation_differences
		SET resolved = true, resolved_by = $2, resolved_at = NOW()
		WHERE difference_id = $1
	`, diffID, resolvedBy)
	if err != nil {
		r.logger.Error("failed to resolve difference",
			util.String("diff_id", diffID.String()),
			util.ErrorField(err))
		return fmt.Errorf("resolve difference: %w", err)
	}
	if rows, _ := res.RowsAffected(); rows == 0 {
		return ErrNotFound
	}
	return nil
}

func (r *reconciliationRepository) DeleteDifference(ctx context.Context, db DBTX, diffID uuid.UUID) error {
	res, err := db.ExecContext(ctx, `DELETE FROM accounting.reconciliation_differences WHERE difference_id = $1`, diffID)
	if err != nil {
		r.logger.Error("failed to delete difference",
			util.String("diff_id", diffID.String()),
			util.ErrorField(err))
		return fmt.Errorf("delete difference: %w", err)
	}
	if rows, _ := res.RowsAffected(); rows == 0 {
		return ErrNotFound
	}
	return nil
}

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
			return nil, ErrNotFound
		}
		r.logger.Error("failed to get adjustment by ID",
			util.String("adj_id", adjID.String()),
			util.ErrorField(err))
		return nil, fmt.Errorf("get adjustment by ID: %w", err)
	}
	return adj, nil
}

func (r *reconciliationRepository) DeleteAdjustment(ctx context.Context, db DBTX, adjID uuid.UUID) error {
	res, err := db.ExecContext(ctx, `DELETE FROM accounting.reconciliation_adjustments WHERE adjustment_id = $1`, adjID)
	if err != nil {
		r.logger.Error("failed to delete adjustment",
			util.String("adj_id", adjID.String()),
			util.ErrorField(err))
		return fmt.Errorf("delete adjustment: %w", err)
	}
	if rows, _ := res.RowsAffected(); rows == 0 {
		return ErrNotFound
	}
	return nil
}

func (r *reconciliationRepository) GetBatchMetrics(ctx context.Context, db DBTX, batchID uuid.UUID) (*analytics.ReconciliationBatchMetrics, error) {
	query := `
		SELECT metric_id, batch_id, company_id, reconciliation_type,
		       total_items, matched_items, unmatched_items, ignored_items, match_rate,
		       started_at, completed_at, completion_duration_seconds,
		       total_differences, resolved_differences, total_adjustments, adjustment_amount,
		       created_at, updated_at
		FROM accounting.analytics_reconciliation_batch_metrics
		WHERE batch_id = $1
	`
	var m analytics.ReconciliationBatchMetrics
	err := db.QueryRowContext(ctx, query, batchID).Scan(
		&m.MetricID, &m.BatchID, &m.CompanyID, &m.ReconciliationType,
		&m.TotalItems, &m.MatchedItems, &m.UnmatchedItems, &m.IgnoredItems, &m.MatchRate,
		&m.StartedAt, &m.CompletedAt, &m.CompletionDurationSeconds,
		&m.TotalDifferences, &m.ResolvedDifferences, &m.TotalAdjustments, &m.AdjustmentAmount,
		&m.CreatedAt, &m.UpdatedAt,
	)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, ErrNotFound
		}
		r.logger.Error("failed to get batch metrics",
			util.String("batch_id", batchID.String()),
			util.ErrorField(err))
		return nil, fmt.Errorf("get batch metrics: %w", err)
	}
	return &m, nil
}

func (r *reconciliationRepository) ListBatchMetrics(ctx context.Context, db DBTX, companyID uuid.UUID, limit, offset int) ([]*analytics.ReconciliationBatchMetrics, error) {
	if limit <= 0 {
		limit = 50
	}
	query := `
		SELECT metric_id, batch_id, company_id, reconciliation_type,
		       total_items, matched_items, unmatched_items, ignored_items, match_rate,
		       started_at, completed_at, completion_duration_seconds,
		       total_differences, resolved_differences, total_adjustments, adjustment_amount,
		       created_at, updated_at
		FROM accounting.analytics_reconciliation_batch_metrics
		WHERE company_id = $1
		ORDER BY created_at DESC
		LIMIT $2 OFFSET $3
	`
	rows, err := db.QueryContext(ctx, query, companyID, limit, offset)
	if err != nil {
		r.logger.Error("failed to list batch metrics",
			util.String("company_id", companyID.String()),
			util.ErrorField(err))
		return nil, fmt.Errorf("list batch metrics: %w", err)
	}
	defer rows.Close()
	var results []*analytics.ReconciliationBatchMetrics
	for rows.Next() {
		var m analytics.ReconciliationBatchMetrics
		err := rows.Scan(
			&m.MetricID, &m.BatchID, &m.CompanyID, &m.ReconciliationType,
			&m.TotalItems, &m.MatchedItems, &m.UnmatchedItems, &m.IgnoredItems, &m.MatchRate,
			&m.StartedAt, &m.CompletedAt, &m.CompletionDurationSeconds,
			&m.TotalDifferences, &m.ResolvedDifferences, &m.TotalAdjustments, &m.AdjustmentAmount,
			&m.CreatedAt, &m.UpdatedAt,
		)
		if err != nil {
			return nil, fmt.Errorf("scan batch metrics: %w", err)
		}
		results = append(results, &m)
	}
	return results, nil
}

func (r *reconciliationRepository) GetDailyStats(ctx context.Context, db DBTX, companyID uuid.UUID, reconciliationType string, date time.Time) (*analytics.ReconciliationDailyStats, error) {
	query := `
		SELECT stat_id, company_id, reconciliation_type, date,
		       batches_started, batches_completed,
		       total_items_processed, total_matched, total_unmatched, total_ignored,
		       avg_match_rate, avg_completion_seconds,
		       differences_created, differences_resolved,
		       adjustments_created, total_adjustment_amount,
		       created_at, updated_at
		FROM accounting.analytics_reconciliation_daily_stats
		WHERE company_id = $1 AND reconciliation_type = $2 AND date = $3
	`
	var s analytics.ReconciliationDailyStats
	err := db.QueryRowContext(ctx, query, companyID, reconciliationType, date).Scan(
		&s.StatID, &s.CompanyID, &s.ReconciliationType, &s.Date,
		&s.BatchesStarted, &s.BatchesCompleted,
		&s.TotalItemsProcessed, &s.TotalMatched, &s.TotalUnmatched, &s.TotalIgnored,
		&s.AvgMatchRate, &s.AvgCompletionSeconds,
		&s.DifferencesCreated, &s.DifferencesResolved,
		&s.AdjustmentsCreated, &s.TotalAdjustmentAmount,
		&s.CreatedAt, &s.UpdatedAt,
	)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, ErrNotFound
		}
		r.logger.Error("failed to get daily stats",
			util.String("company_id", companyID.String()),
			util.ErrorField(err))
		return nil, fmt.Errorf("get daily stats: %w", err)
	}
	return &s, nil
}

func (r *reconciliationRepository) ListDailyStats(ctx context.Context, db DBTX, companyID uuid.UUID, fromDate, toDate time.Time) ([]*analytics.ReconciliationDailyStats, error) {
	query := `
		SELECT stat_id, company_id, reconciliation_type, date,
		       batches_started, batches_completed,
		       total_items_processed, total_matched, total_unmatched, total_ignored,
		       avg_match_rate, avg_completion_seconds,
		       differences_created, differences_resolved,
		       adjustments_created, total_adjustment_amount,
		       created_at, updated_at
		FROM accounting.analytics_reconciliation_daily_stats
		WHERE company_id = $1 AND date BETWEEN $2 AND $3
		ORDER BY date DESC
	`
	rows, err := db.QueryContext(ctx, query, companyID, fromDate, toDate)
	if err != nil {
		r.logger.Error("failed to list daily stats",
			util.String("company_id", companyID.String()),
			util.ErrorField(err))
		return nil, fmt.Errorf("list daily stats: %w", err)
	}
	defer rows.Close()
	var results []*analytics.ReconciliationDailyStats
	for rows.Next() {
		var s analytics.ReconciliationDailyStats
		err := rows.Scan(
			&s.StatID, &s.CompanyID, &s.ReconciliationType, &s.Date,
			&s.BatchesStarted, &s.BatchesCompleted,
			&s.TotalItemsProcessed, &s.TotalMatched, &s.TotalUnmatched, &s.TotalIgnored,
			&s.AvgMatchRate, &s.AvgCompletionSeconds,
			&s.DifferencesCreated, &s.DifferencesResolved,
			&s.AdjustmentsCreated, &s.TotalAdjustmentAmount,
			&s.CreatedAt, &s.UpdatedAt,
		)
		if err != nil {
			return nil, fmt.Errorf("scan daily stats: %w", err)
		}
		results = append(results, &s)
	}
	return results, nil
}

func (r *reconciliationRepository) GetDiffTrends(ctx context.Context, db DBTX, companyID uuid.UUID, fromDate, toDate time.Time) ([]*analytics.ReconciliationDiffTrends, error) {
	query := `
		SELECT trend_id, company_id, batch_id, issue_type, date,
		       count, total_expected_amount, total_actual_amount, total_variance, created_at
		FROM accounting.analytics_reconciliation_diff_trends
		WHERE company_id = $1 AND date BETWEEN $2 AND $3
		ORDER BY date DESC
	`
	rows, err := db.QueryContext(ctx, query, companyID, fromDate, toDate)
	if err != nil {
		r.logger.Error("failed to get diff trends",
			util.String("company_id", companyID.String()),
			util.ErrorField(err))
		return nil, fmt.Errorf("get diff trends: %w", err)
	}
	defer rows.Close()
	var results []*analytics.ReconciliationDiffTrends
	for rows.Next() {
		var t analytics.ReconciliationDiffTrends
		err := rows.Scan(
			&t.TrendID, &t.CompanyID, &t.BatchID, &t.IssueType, &t.Date,
			&t.Count, &t.TotalExpectedAmount, &t.TotalActualAmount, &t.TotalVariance, &t.CreatedAt,
		)
		if err != nil {
			return nil, fmt.Errorf("scan diff trend: %w", err)
		}
		results = append(results, &t)
	}
	return results, nil
}

func (r *reconciliationRepository) UpdateItemStatus(ctx context.Context, db DBTX, itemID uuid.UUID, status string, journalEntryID *uuid.UUID, score *decimal.Decimal) error {
	var jeID uuid.NullUUID
	if journalEntryID != nil {
		jeID = uuid.NullUUID{UUID: *journalEntryID, Valid: true}
	}
	query := `
        UPDATE accounting.reconciliation_items
        SET match_status = $2,
            journal_entry_id = $3,
            match_score = $4,
            updated_at = NOW()
        WHERE item_id = $1
    `
	_, err := db.ExecContext(ctx, query, itemID, status, jeID, score)
	if err != nil {
		r.logger.Error("failed to update item status",
			util.String("item_id", itemID.String()),
			util.String("status", status),
			util.ErrorField(err))
		return fmt.Errorf("update item status: %w", err)
	}
	return nil
}

func (r *reconciliationRepository) UpdateBatchStats(ctx context.Context, db DBTX, batchID uuid.UUID, total, matched, unmatched int) error {
	query := `
        UPDATE accounting.reconciliation_batches
        SET total_records = $2,
            matched_records = $3,
            unmatched_records = $4
        WHERE batch_id = $1
    `
	_, err := db.ExecContext(ctx, query, batchID, total, matched, unmatched)
	if err != nil {
		r.logger.Error("failed to update batch stats",
			util.String("batch_id", batchID.String()),
			util.Int("total", total),
			util.Int("matched", matched),
			util.Int("unmatched", unmatched),
			util.ErrorField(err))
		return fmt.Errorf("update batch stats: %w", err)
	}
	return nil
}

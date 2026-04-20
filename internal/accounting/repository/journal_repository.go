package repository

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/google/uuid"
	"go.uber.org/zap"

	"auth-service/internal/accounting/models"
	"auth-service/internal/accounting/models/enums"
	"auth-service/internal/util"
)

// JournalFilter defines filter criteria for listing journal entries
type JournalFilter struct {
	CompanyID   uuid.UUID
	Status      string
	JournalType string
	FromDate    *time.Time
	ToDate      *time.Time
	AccountID   *uuid.UUID // filters entries that have a line with this account
	Search      string     // searches reference and description
}

// JournalWithLines pairs a journal entry with its lines
type JournalWithLines struct {
	Entry *models.JournalEntry
	Lines []*models.JournalLine
}

// JournalRepository defines the interface for journal data access
type JournalRepository interface {
	// =====================================================
	// JOURNAL ENTRY (HEADER)
	// =====================================================
	Create(ctx context.Context, db DBTX, j *models.JournalEntry) error
	Update(ctx context.Context, db DBTX, j *models.JournalEntry) error

	GetByID(ctx context.Context, db DBTX, id uuid.UUID) (*models.JournalEntry, error)
	GetByIDForUpdate(ctx context.Context, db DBTX, id uuid.UUID) (*models.JournalEntry, error)

	GetBySource(ctx context.Context, db DBTX, companyID uuid.UUID, sourceType string, sourceID uuid.UUID) (*models.JournalEntry, error)

	List(ctx context.Context, db DBTX, filter JournalFilter, p Pagination, s Sort) ([]*models.JournalEntry, error)
	ListByCompany(ctx context.Context, db DBTX, companyID uuid.UUID) ([]*models.JournalEntry, error)

	Count(ctx context.Context, db DBTX, filter JournalFilter) (int64, error)

	Delete(ctx context.Context, db DBTX, id uuid.UUID, deletedBy *uuid.UUID) error
	ExistsBySource(ctx context.Context, db DBTX, companyID uuid.UUID, sourceType string, sourceID uuid.UUID) (bool, error)

	// =====================================================
	// STATUS / LIFECYCLE
	// =====================================================
	UpdateStatus(ctx context.Context, db DBTX, id uuid.UUID, status string, updatedBy *uuid.UUID) error

	Post(ctx context.Context, db DBTX, id uuid.UUID, postedBy *uuid.UUID) error
	Reverse(ctx context.Context, db DBTX, originalID uuid.UUID, reversal *models.JournalEntry) error

	// =====================================================
	// JOURNAL LINES
	// =====================================================
	AddLine(ctx context.Context, db DBTX, line *models.JournalLine) error
	BulkAddLines(ctx context.Context, db DBTX, lines []*models.JournalLine) error

	GetLines(ctx context.Context, db DBTX, journalID uuid.UUID) ([]*models.JournalLine, error)

	UpdateLine(ctx context.Context, db DBTX, line *models.JournalLine) error
	DeleteLine(ctx context.Context, db DBTX, lineID uuid.UUID) error

	ClearLines(ctx context.Context, db DBTX, journalID uuid.UUID) error

	// =====================================================
	// VALIDATION (CRITICAL)
	// =====================================================
	IsBalanced(ctx context.Context, db DBTX, journalID uuid.UUID) (bool, float64, float64, error)

	ValidateBeforePost(ctx context.Context, db DBTX, journalID uuid.UUID) error

	HasLines(ctx context.Context, db DBTX, journalID uuid.UUID) (bool, error)

	// =====================================================
	// LOCKING (VERY IMPORTANT)
	// =====================================================
	LockJournal(ctx context.Context, db DBTX, journalID uuid.UUID) error

	// =====================================================
	// SEARCH / REPORT SUPPORT
	// =====================================================
	ListWithLines(ctx context.Context, db DBTX, filter JournalFilter, p Pagination, s Sort) ([]*JournalWithLines, error)

	ListByAccount(ctx context.Context, db DBTX, accountID uuid.UUID, from, to time.Time) ([]*models.JournalLine, error)

	// =====================================================
	// AGGREGATION (USED BY LEDGER)
	// =====================================================
	SumByAccount(ctx context.Context, db DBTX, accountID uuid.UUID, from, to time.Time) (debit float64, credit float64, err error)
}

// journalRepository implements JournalRepository
type journalRepository struct {
	logger *zap.Logger
}

// NewJournalRepository creates a new journal repository instance
func NewJournalRepository(logger *zap.Logger) JournalRepository {
	return &journalRepository{
		logger: logger.Named("journal_repo"),
	}
}

// allowed sort fields for journal entries
var allowedJournalSortFields = map[string]bool{
	"entry_date":   true,
	"created_at":   true,
	"updated_at":   true,
	"journal_type": true,
	"status":       true,
	"reference":    true,
}

// validateSort returns a safe ORDER BY clause
func (r *journalRepository) validateSort(s Sort) (string, error) {
	field := s.Field
	if field == "" {
		field = "entry_date"
	}
	if !allowedJournalSortFields[field] {
		return "", fmt.Errorf("invalid sort field: %s", field)
	}
	dir := strings.ToUpper(s.Direction)
	if dir != "ASC" && dir != "DESC" {
		dir = "DESC"
	}
	return fmt.Sprintf("ORDER BY %s %s", field, dir), nil
}

// validatePagination returns sanitized limit and offset
func (r *journalRepository) validatePagination(p Pagination) (int, int) {
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

// buildJournalFilter constructs WHERE clause and arguments, excluding soft‑deleted rows
func (r *journalRepository) buildJournalFilter(filter JournalFilter) (string, []interface{}) {
	var conditions []string
	var args []interface{}
	idx := 1

	if filter.CompanyID != uuid.Nil {
		conditions = append(conditions, fmt.Sprintf("company_id = $%d", idx))
		args = append(args, filter.CompanyID)
		idx++
	}
	if filter.Status != "" {
		conditions = append(conditions, fmt.Sprintf("status = $%d", idx))
		args = append(args, filter.Status)
		idx++
	}
	if filter.JournalType != "" {
		conditions = append(conditions, fmt.Sprintf("journal_type = $%d", idx))
		args = append(args, filter.JournalType)
		idx++
	}
	if filter.FromDate != nil {
		conditions = append(conditions, fmt.Sprintf("entry_date >= $%d", idx))
		args = append(args, *filter.FromDate)
		idx++
	}
	if filter.ToDate != nil {
		conditions = append(conditions, fmt.Sprintf("entry_date <= $%d", idx))
		args = append(args, *filter.ToDate)
		idx++
	}
	if filter.Search != "" {
		searchPattern := "%" + filter.Search + "%"
		conditions = append(conditions, fmt.Sprintf("(reference ILIKE $%d OR description ILIKE $%d)", idx, idx+1))
		args = append(args, searchPattern, searchPattern)
		idx += 2
	}

	// 🔥 Always exclude soft‑deleted entries
	conditions = append(conditions, "deleted_at IS NULL")

	if len(conditions) == 0 {
		return "", args
	}
	return "WHERE " + strings.Join(conditions, " AND "), args
}

// scanJournalEntry scans a row into a JournalEntry model
func (r *journalRepository) scanJournalEntry(scanner interface {
	Scan(dest ...interface{}) error
}) (*models.JournalEntry, error) {
	var j models.JournalEntry
	var reference, description sql.NullString
	var reversalOf uuid.NullUUID
	var sourceType sql.NullString
	var sourceID uuid.NullUUID
	var postedAt sql.NullTime
	var postedBy, createdBy, updatedBy uuid.NullUUID
	var deletedAt sql.NullTime

	err := scanner.Scan(
		&j.JournalEntryID, &j.CompanyID, &j.JournalType, &j.EntryDate,
		&reference, &description, &j.Status, &reversalOf,
		&sourceType, &sourceID,
		&j.CreatedAt, &postedAt, &postedBy,
		&createdBy, &j.UpdatedAt, &updatedBy, &deletedAt,
	)
	if err != nil {
		return nil, err
	}

	if reference.Valid {
		j.Reference = &reference.String
	}
	if description.Valid {
		j.Description = &description.String
	}
	if reversalOf.Valid {
		j.ReversalOf = &reversalOf.UUID
	}
	if sourceType.Valid {
		j.SourceType = &sourceType.String
	}
	if sourceID.Valid {
		j.SourceID = &sourceID.UUID
	}
	if postedAt.Valid {
		j.PostedAt = &postedAt.Time
	}
	if postedBy.Valid {
		j.PostedBy = &postedBy.UUID
	}
	if createdBy.Valid {
		j.CreatedBy = &createdBy.UUID
	}
	if updatedBy.Valid {
		j.UpdatedBy = &updatedBy.UUID
	}
	if deletedAt.Valid {
		j.DeletedAt = &deletedAt.Time
	}
	return &j, nil
}

// Create inserts a new journal entry
func (r *journalRepository) Create(ctx context.Context, db DBTX, j *models.JournalEntry) error {
	query := `
		INSERT INTO accounting.journal_entries (
			journal_entry_id, company_id, journal_type, entry_date,
			reference, description, status, reversal_of,
			source_type, source_id,
			created_at, posted_at, posted_by, created_by, updated_at, updated_by, deleted_at
		) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, NOW(), $11, $12, NOW(), $13, NULL)
		RETURNING created_at, updated_at
	`
	err := db.QueryRowContext(ctx, query,
		j.JournalEntryID, j.CompanyID, j.JournalType, j.EntryDate,
		j.Reference, j.Description, j.Status, j.ReversalOf,
		j.SourceType, j.SourceID,
		j.PostedAt, j.PostedBy, j.CreatedBy, j.UpdatedBy,
	).Scan(&j.CreatedAt, &j.UpdatedAt)
	if err != nil {
		r.logger.Error("failed to create journal entry",
			util.String("company_id", j.CompanyID.String()),
			util.String("journal_type", j.JournalType),
			util.ErrorField(err))
		return fmt.Errorf("create journal entry: %w", err)
	}
	return nil
}

// Update updates an existing journal entry (only allowed for draft entries, not soft‑deleted)
func (r *journalRepository) Update(ctx context.Context, db DBTX, j *models.JournalEntry) error {
	// First check if status is draft and not deleted
	var status string
	var deletedAt sql.NullTime
	checkQuery := `SELECT status, deleted_at FROM accounting.journal_entries WHERE journal_entry_id = $1`
	err := db.QueryRowContext(ctx, checkQuery, j.JournalEntryID).Scan(&status, &deletedAt)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return fmt.Errorf("journal entry %s not found", j.JournalEntryID)
		}
		return fmt.Errorf("check journal status: %w", err)
	}
	if deletedAt.Valid {
		return fmt.Errorf("cannot update a soft‑deleted journal entry")
	}
	if status != enums.JournalStatusDraft {
		return fmt.Errorf("cannot update journal entry with status %s", status)
	}

	query := `
		UPDATE accounting.journal_entries
		SET entry_date = $2,
		    reference = $3,
		    description = $4,
		    journal_type = $5,
		    updated_by = $6,
		    updated_at = NOW()
		WHERE journal_entry_id = $1 AND status = 'draft' AND deleted_at IS NULL
		RETURNING updated_at
	`
	err = db.QueryRowContext(ctx, query,
		j.JournalEntryID, j.EntryDate, j.Reference, j.Description,
		j.JournalType, j.UpdatedBy,
	).Scan(&j.UpdatedAt)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return fmt.Errorf("journal entry %s not found, not in draft, or soft‑deleted", j.JournalEntryID)
		}
		r.logger.Error("failed to update journal entry",
			util.String("id", j.JournalEntryID.String()),
			util.ErrorField(err))
		return fmt.Errorf("update journal entry: %w", err)
	}
	return nil
}

// GetByID retrieves a journal entry by ID (only non‑deleted)
func (r *journalRepository) GetByID(ctx context.Context, db DBTX, id uuid.UUID) (*models.JournalEntry, error) {
	query := `
		SELECT journal_entry_id, company_id, journal_type, entry_date,
		       reference, description, status, reversal_of,
		       source_type, source_id,
		       created_at, posted_at, posted_by, created_by, updated_at, updated_by, deleted_at
		FROM accounting.journal_entries
		WHERE journal_entry_id = $1 AND deleted_at IS NULL
	`
	j, err := r.scanJournalEntry(db.QueryRowContext(ctx, query, id))
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, nil
		}
		r.logger.Error("failed to get journal entry by ID",
			util.String("id", id.String()),
			util.ErrorField(err))
		return nil, fmt.Errorf("get journal entry by ID: %w", err)
	}
	return j, nil
}

// GetByIDForUpdate retrieves a journal entry with row‑level lock (only non‑deleted)
func (r *journalRepository) GetByIDForUpdate(ctx context.Context, db DBTX, id uuid.UUID) (*models.JournalEntry, error) {
	query := `
		SELECT journal_entry_id, company_id, journal_type, entry_date,
		       reference, description, status, reversal_of,
		       source_type, source_id,
		       created_at, posted_at, posted_by, created_by, updated_at, updated_by, deleted_at
		FROM accounting.journal_entries
		WHERE journal_entry_id = $1 AND deleted_at IS NULL
		FOR UPDATE
	`
	j, err := r.scanJournalEntry(db.QueryRowContext(ctx, query, id))
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, nil
		}
		r.logger.Error("failed to get journal entry for update",
			util.String("id", id.String()),
			util.ErrorField(err))
		return nil, fmt.Errorf("get journal entry for update: %w", err)
	}
	return j, nil
}

// GetBySource retrieves a journal entry by its source (only non‑deleted)
func (r *journalRepository) GetBySource(ctx context.Context, db DBTX, companyID uuid.UUID, sourceType string, sourceID uuid.UUID) (*models.JournalEntry, error) {
	query := `
		SELECT journal_entry_id, company_id, journal_type, entry_date,
		       reference, description, status, reversal_of,
		       source_type, source_id,
		       created_at, posted_at, posted_by, created_by, updated_at, updated_by, deleted_at
		FROM accounting.journal_entries
		WHERE company_id = $1 AND source_type = $2 AND source_id = $3 AND deleted_at IS NULL
	`
	j, err := r.scanJournalEntry(db.QueryRowContext(ctx, query, companyID, sourceType, sourceID))
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, nil
		}
		r.logger.Error("failed to get journal entry by source",
			util.String("company_id", companyID.String()),
			util.String("source_type", sourceType),
			util.String("source_id", sourceID.String()),
			util.ErrorField(err))
		return nil, fmt.Errorf("get journal entry by source: %w", err)
	}
	return j, nil
}

// List returns a paginated list of journal entries matching the filter (non‑deleted only)
func (r *journalRepository) List(ctx context.Context, db DBTX, filter JournalFilter, p Pagination, s Sort) ([]*models.JournalEntry, error) {
	where, args := r.buildJournalFilter(filter) // already includes deleted_at IS NULL
	orderBy, err := r.validateSort(s)
	if err != nil {
		return nil, err
	}
	limit, offset := r.validatePagination(p)

	var query string
	if filter.AccountID != nil {
		subWhere := where
		if subWhere == "" {
			subWhere = "WHERE 1=1 AND deleted_at IS NULL"
		}
		query = fmt.Sprintf(`
			SELECT DISTINCT je.journal_entry_id, je.company_id, je.journal_type, je.entry_date,
			       je.reference, je.description, je.status, je.reversal_of,
			       je.source_type, je.source_id,
			       je.created_at, je.posted_at, je.posted_by, je.created_by, je.updated_at, je.updated_by, je.deleted_at
			FROM accounting.journal_entries je
			INNER JOIN accounting.journal_lines jl ON je.journal_entry_id = jl.journal_entry_id
			%s AND jl.account_id = $%d
			%s
			LIMIT $%d OFFSET $%d
		`, subWhere, len(args)+1, orderBy, len(args)+2, len(args)+3)
		args = append(args, *filter.AccountID, limit, offset)
	} else {
		if where == "" {
			where = "WHERE deleted_at IS NULL"
		}
		query = fmt.Sprintf(`
			SELECT journal_entry_id, company_id, journal_type, entry_date,
			       reference, description, status, reversal_of,
			       source_type, source_id,
			       created_at, posted_at, posted_by, created_by, updated_at, updated_by, deleted_at
			FROM accounting.journal_entries
			%s
			%s
			LIMIT $%d OFFSET $%d
		`, where, orderBy, len(args)+1, len(args)+2)
		args = append(args, limit, offset)
	}

	rows, err := db.QueryContext(ctx, query, args...)
	if err != nil {
		r.logger.Error("failed to list journal entries",
			util.Any("filter", filter),
			util.ErrorField(err))
		return nil, fmt.Errorf("list journal entries: %w", err)
	}
	defer rows.Close()

	var result []*models.JournalEntry
	for rows.Next() {
		j, err := r.scanJournalEntry(rows)
		if err != nil {
			return nil, fmt.Errorf("scan journal entry: %w", err)
		}
		result = append(result, j)
	}
	if err = rows.Err(); err != nil {
		return nil, fmt.Errorf("rows iteration: %w", err)
	}
	return result, nil
}

// ListByCompany returns all journal entries for a company (convenience wrapper)
func (r *journalRepository) ListByCompany(ctx context.Context, db DBTX, companyID uuid.UUID) ([]*models.JournalEntry, error) {
	return r.List(ctx, db, JournalFilter{CompanyID: companyID}, Pagination{Limit: 1000}, Sort{Field: "entry_date", Direction: "DESC"})
}

// Count returns the number of journal entries matching the filter (non‑deleted only)
func (r *journalRepository) Count(ctx context.Context, db DBTX, filter JournalFilter) (int64, error) {
	where, args := r.buildJournalFilter(filter) // includes deleted_at IS NULL
	var query string
	if filter.AccountID != nil {
		subWhere := where
		if subWhere == "" {
			subWhere = "WHERE deleted_at IS NULL"
		}
		query = fmt.Sprintf(`
			SELECT COUNT(DISTINCT je.journal_entry_id)
			FROM accounting.journal_entries je
			INNER JOIN accounting.journal_lines jl ON je.journal_entry_id = jl.journal_entry_id
			%s AND jl.account_id = $%d
		`, subWhere, len(args)+1)
		args = append(args, *filter.AccountID)
	} else {
		if where == "" {
			where = "WHERE deleted_at IS NULL"
		}
		query = fmt.Sprintf("SELECT COUNT(*) FROM accounting.journal_entries %s", where)
	}
	var count int64
	err := db.QueryRowContext(ctx, query, args...).Scan(&count)
	if err != nil {
		r.logger.Error("failed to count journal entries",
			util.Any("filter", filter),
			util.ErrorField(err))
		return 0, fmt.Errorf("count journal entries: %w", err)
	}
	return count, nil
}

// Delete performs a soft delete: sets deleted_at and status = 'deleted'
func (r *journalRepository) Delete(ctx context.Context, db DBTX, id uuid.UUID, deletedBy *uuid.UUID) error {
	// Check status is draft and not already deleted
	var status string
	var deletedAt sql.NullTime
	err := db.QueryRowContext(ctx, `SELECT status, deleted_at FROM accounting.journal_entries WHERE journal_entry_id = $1`, id).Scan(&status, &deletedAt)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return fmt.Errorf("journal entry %s not found", id)
		}
		return fmt.Errorf("check journal status: %w", err)
	}
	if deletedAt.Valid {
		return fmt.Errorf("journal entry %s is already soft‑deleted", id)
	}
	if status != enums.JournalStatusDraft {
		return fmt.Errorf("cannot delete journal entry with status %s", status)
	}

	// Soft delete: set deleted_at and status = 'deleted'
	query := `
		UPDATE accounting.journal_entries
		SET deleted_at = NOW(), status = 'deleted', updated_by = $2, updated_at = NOW()
		WHERE journal_entry_id = $1 AND status = 'draft' AND deleted_at IS NULL
	`
	result, err := db.ExecContext(ctx, query, id, deletedBy)
	if err != nil {
		r.logger.Error("failed to soft delete journal entry",
			util.String("id", id.String()),
			util.ErrorField(err))
		return fmt.Errorf("soft delete journal entry: %w", err)
	}
	rows, _ := result.RowsAffected()
	if rows == 0 {
		return fmt.Errorf("journal entry %s not found, not in draft, or already deleted", id)
	}
	return nil
}

// ExistsBySource checks if a journal entry already exists for the given source (excluding soft‑deleted)
func (r *journalRepository) ExistsBySource(ctx context.Context, db DBTX, companyID uuid.UUID, sourceType string, sourceID uuid.UUID) (bool, error) {
	query := `
		SELECT EXISTS (
			SELECT 1
			FROM accounting.journal_entries
			WHERE company_id = $1
			  AND source_type = $2
			  AND source_id = $3
			  AND deleted_at IS NULL
		)
	`
	var exists bool
	err := db.QueryRowContext(ctx, query, companyID, sourceType, sourceID).Scan(&exists)
	if err != nil {
		r.logger.Error("failed to check existence by source",
			zap.String("company_id", companyID.String()),
			zap.String("source_type", sourceType),
			zap.String("source_id", sourceID.String()),
			zap.Error(err))
		return false, fmt.Errorf("exists by source: %w", err)
	}
	return exists, nil
}

// UpdateStatus changes the status of a journal entry (only if not soft‑deleted)
func (r *journalRepository) UpdateStatus(ctx context.Context, db DBTX, id uuid.UUID, status string, updatedBy *uuid.UUID) error {
	query := `
		UPDATE accounting.journal_entries
		SET status = $2, updated_by = $3, updated_at = NOW()
		WHERE journal_entry_id = $1 AND deleted_at IS NULL
	`
	result, err := db.ExecContext(ctx, query, id, status, updatedBy)
	if err != nil {
		r.logger.Error("failed to update journal status",
			util.String("id", id.String()),
			util.String("status", status),
			util.ErrorField(err))
		return fmt.Errorf("update journal status: %w", err)
	}
	rows, _ := result.RowsAffected()
	if rows == 0 {
		return fmt.Errorf("journal entry %s not found or soft‑deleted", id)
	}
	return nil
}

// Post marks a journal entry as posted (only if draft and not soft‑deleted)
func (r *journalRepository) Post(ctx context.Context, db DBTX, id uuid.UUID, postedBy *uuid.UUID) error {
	// Lock the journal to prevent concurrent modifications
	if err := r.LockJournal(ctx, db, id); err != nil {
		return err
	}

	// Check current status and deleted_at
	var currentStatus string
	var deletedAt sql.NullTime
	err := db.QueryRowContext(ctx, `SELECT status, deleted_at FROM accounting.journal_entries WHERE journal_entry_id = $1`, id).Scan(&currentStatus, &deletedAt)
	if err != nil {
		return fmt.Errorf("get journal status: %w", err)
	}
	if deletedAt.Valid {
		return fmt.Errorf("cannot post a soft‑deleted journal entry")
	}
	if currentStatus != enums.JournalStatusDraft {
		return fmt.Errorf("journal entry %s cannot be posted: current status is %s", id, currentStatus)
	}

	// Validate balance and lines exist
	if err := r.ValidateBeforePost(ctx, db, id); err != nil {
		return err
	}

	// Update status to posted, set posted_at and posted_by
	query := `
		UPDATE accounting.journal_entries
		SET status = 'posted', posted_at = NOW(), posted_by = $2, updated_at = NOW()
		WHERE journal_entry_id = $1 AND status = 'draft' AND deleted_at IS NULL
		RETURNING posted_at
	`
	var postedAt time.Time
	err = db.QueryRowContext(ctx, query, id, postedBy).Scan(&postedAt)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return fmt.Errorf("journal entry %s not found, not in draft, or soft‑deleted", id)
		}
		r.logger.Error("failed to post journal entry",
			util.String("id", id.String()),
			util.ErrorField(err))
		return fmt.Errorf("post journal entry: %w", err)
	}
	return nil
}

// Reverse creates a reversal journal entry for the given original entry.
// It inserts the reversal entry (already populated with swapped lines) and updates the original status to 'reversed'.
func (r *journalRepository) Reverse(ctx context.Context, db DBTX, originalID uuid.UUID, reversal *models.JournalEntry) error {
	// Lock original entry
	if err := r.LockJournal(ctx, db, originalID); err != nil {
		return err
	}

	// Check original status and not deleted
	var originalStatus string
	var deletedAt sql.NullTime
	err := db.QueryRowContext(ctx, `SELECT status, deleted_at FROM accounting.journal_entries WHERE journal_entry_id = $1`, originalID).Scan(&originalStatus, &deletedAt)
	if err != nil {
		return fmt.Errorf("get original journal status: %w", err)
	}
	if deletedAt.Valid {
		return fmt.Errorf("cannot reverse a soft‑deleted journal entry")
	}
	if originalStatus != enums.JournalStatusPosted {
		return fmt.Errorf("only posted journal entries can be reversed, current status: %s", originalStatus)
	}

	// Insert reversal entry (caller must have set ReversalOf = &originalID)
	if reversal.ReversalOf == nil || *reversal.ReversalOf != originalID {
		return errors.New("reversal entry must have ReversalOf set to original journal ID")
	}
	if err := r.Create(ctx, db, reversal); err != nil {
		return fmt.Errorf("create reversal entry: %w", err)
	}

	// Insert reversal lines (caller should have provided lines; we could copy them, but assume caller did)
	// If caller didn't add lines, we can copy from original and swap debits/credits.
	hasLines, err := r.HasLines(ctx, db, reversal.JournalEntryID)
	if err != nil {
		return err
	}
	if !hasLines {
		// Auto-copy lines from original and swap
		originalLines, err := r.GetLines(ctx, db, originalID)
		if err != nil {
			return fmt.Errorf("get original lines for reversal: %w", err)
		}
		var reversalLines []*models.JournalLine
		for i, line := range originalLines {
			revLine := &models.JournalLine{
				JournalLineID:  uuid.New(),
				JournalEntryID: reversal.JournalEntryID,
				AccountID:      line.AccountID,
				LineNumber:     i + 1,
				DebitAmount:    line.CreditAmount,
				CreditAmount:   line.DebitAmount,
				Description:    line.Description,
			}
			reversalLines = append(reversalLines, revLine)
		}
		if err := r.BulkAddLines(ctx, db, reversalLines); err != nil {
			return fmt.Errorf("add reversal lines: %w", err)
		}
	}

	// Update original entry status to 'reversed'
	_, err = db.ExecContext(ctx, `
		UPDATE accounting.journal_entries
		SET status = 'reversed', updated_at = NOW()
		WHERE journal_entry_id = $1 AND deleted_at IS NULL
	`, originalID)
	if err != nil {
		return fmt.Errorf("update original journal status: %w", err)
	}
	return nil
}

// AddLine adds a single journal line (only allowed if entry status is draft and not soft‑deleted)
func (r *journalRepository) AddLine(ctx context.Context, db DBTX, line *models.JournalLine) error {
	// Verify journal entry is draft and not deleted
	var status string
	var deletedAt sql.NullTime
	err := db.QueryRowContext(ctx, `SELECT status, deleted_at FROM accounting.journal_entries WHERE journal_entry_id = $1`, line.JournalEntryID).Scan(&status, &deletedAt)
	if err != nil {
		return fmt.Errorf("get journal status: %w", err)
	}
	if deletedAt.Valid {
		return fmt.Errorf("cannot add line to a soft‑deleted journal entry")
	}
	if status != enums.JournalStatusDraft {
		return fmt.Errorf("cannot add line to journal entry with status %s", status)
	}

	query := `
		INSERT INTO accounting.journal_lines (
			journal_line_id, journal_entry_id, account_id, line_number,
			debit_amount, credit_amount, description, created_at, updated_at
		) VALUES ($1, $2, $3, $4, $5, $6, $7, NOW(), NOW())
		RETURNING created_at, updated_at
	`
	err = db.QueryRowContext(ctx, query,
		line.JournalLineID, line.JournalEntryID, line.AccountID, line.LineNumber,
		line.DebitAmount, line.CreditAmount, line.Description,
	).Scan(&line.CreatedAt, &line.UpdatedAt)
	if err != nil {
		r.logger.Error("failed to add journal line",
			util.String("journal_id", line.JournalEntryID.String()),
			util.ErrorField(err))
		return fmt.Errorf("add journal line: %w", err)
	}
	return nil
}

// BulkAddLines adds multiple lines in a single batch (only allowed if entry is draft and not soft‑deleted)
func (r *journalRepository) BulkAddLines(ctx context.Context, db DBTX, lines []*models.JournalLine) error {
	if len(lines) == 0 {
		return nil
	}
	// Verify all lines belong to same journal entry and that entry is draft and not deleted
	journalID := lines[0].JournalEntryID
	var status string
	var deletedAt sql.NullTime
	err := db.QueryRowContext(ctx, `SELECT status, deleted_at FROM accounting.journal_entries WHERE journal_entry_id = $1`, journalID).Scan(&status, &deletedAt)
	if err != nil {
		return fmt.Errorf("get journal status: %w", err)
	}
	if deletedAt.Valid {
		return fmt.Errorf("cannot add lines to a soft‑deleted journal entry")
	}
	if status != enums.JournalStatusDraft {
		return fmt.Errorf("cannot add lines to journal entry with status %s", status)
	}

	stmt, err := db.PrepareContext(ctx, `
		INSERT INTO accounting.journal_lines (
			journal_line_id, journal_entry_id, account_id, line_number,
			debit_amount, credit_amount, description, created_at, updated_at
		) VALUES ($1, $2, $3, $4, $5, $6, $7, NOW(), NOW())
	`)
	if err != nil {
		return fmt.Errorf("prepare bulk insert lines: %w", err)
	}
	defer stmt.Close()

	for _, line := range lines {
		_, err = stmt.ExecContext(ctx,
			line.JournalLineID, line.JournalEntryID, line.AccountID, line.LineNumber,
			line.DebitAmount, line.CreditAmount, line.Description,
		)
		if err != nil {
			r.logger.Error("bulk add line failed",
				util.String("journal_id", line.JournalEntryID.String()),
				util.ErrorField(err))
			return fmt.Errorf("bulk add journal line: %w", err)
		}
	}
	return nil
}

// GetLines retrieves all lines for a journal entry (even if entry is soft‑deleted, lines are kept)
func (r *journalRepository) GetLines(ctx context.Context, db DBTX, journalID uuid.UUID) ([]*models.JournalLine, error) {
	query := `
		SELECT journal_line_id, journal_entry_id, account_id, line_number,
		       debit_amount, credit_amount, description,
		       created_at, updated_at
		FROM accounting.journal_lines
		WHERE journal_entry_id = $1
		ORDER BY line_number
	`
	rows, err := db.QueryContext(ctx, query, journalID)
	if err != nil {
		r.logger.Error("failed to get journal lines",
			util.String("journal_id", journalID.String()),
			util.ErrorField(err))
		return nil, fmt.Errorf("get journal lines: %w", err)
	}
	defer rows.Close()

	var lines []*models.JournalLine
	for rows.Next() {
		var line models.JournalLine
		var description sql.NullString
		err := rows.Scan(
			&line.JournalLineID, &line.JournalEntryID, &line.AccountID, &line.LineNumber,
			&line.DebitAmount, &line.CreditAmount, &description,
			&line.CreatedAt, &line.UpdatedAt,
		)
		if err != nil {
			return nil, fmt.Errorf("scan journal line: %w", err)
		}
		if description.Valid {
			line.Description = &description.String
		}
		lines = append(lines, &line)
	}
	return lines, nil
}

// UpdateLine updates a single journal line (only allowed if entry is draft and not soft‑deleted)
func (r *journalRepository) UpdateLine(ctx context.Context, db DBTX, line *models.JournalLine) error {
	// Verify journal entry is draft and not deleted
	var status string
	var deletedAt sql.NullTime
	err := db.QueryRowContext(ctx, `
		SELECT je.status, je.deleted_at
		FROM accounting.journal_entries je
		INNER JOIN accounting.journal_lines jl ON je.journal_entry_id = jl.journal_entry_id
		WHERE jl.journal_line_id = $1
	`, line.JournalLineID).Scan(&status, &deletedAt)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return fmt.Errorf("journal line %s not found", line.JournalLineID)
		}
		return fmt.Errorf("get journal status: %w", err)
	}
	if deletedAt.Valid {
		return fmt.Errorf("cannot update line of a soft‑deleted journal entry")
	}
	if status != enums.JournalStatusDraft {
		return fmt.Errorf("cannot update line in journal entry with status %s", status)
	}

	query := `
		UPDATE accounting.journal_lines
		SET account_id = $2, line_number = $3,
		    debit_amount = $4, credit_amount = $5, description = $6,
		    updated_at = NOW()
		WHERE journal_line_id = $1
		RETURNING updated_at
	`
	err = db.QueryRowContext(ctx, query,
		line.JournalLineID, line.AccountID, line.LineNumber,
		line.DebitAmount, line.CreditAmount, line.Description,
	).Scan(&line.UpdatedAt)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return fmt.Errorf("journal line %s not found", line.JournalLineID)
		}
		r.logger.Error("failed to update journal line",
			util.String("line_id", line.JournalLineID.String()),
			util.ErrorField(err))
		return fmt.Errorf("update journal line: %w", err)
	}
	return nil
}

// DeleteLine deletes a single journal line (only allowed if entry is draft and not soft‑deleted)
func (r *journalRepository) DeleteLine(ctx context.Context, db DBTX, lineID uuid.UUID) error {
	// Verify journal entry is draft and not deleted
	var status string
	var deletedAt sql.NullTime
	err := db.QueryRowContext(ctx, `
		SELECT je.status, je.deleted_at
		FROM accounting.journal_entries je
		INNER JOIN accounting.journal_lines jl ON je.journal_entry_id = jl.journal_entry_id
		WHERE jl.journal_line_id = $1
	`, lineID).Scan(&status, &deletedAt)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return fmt.Errorf("journal line %s not found", lineID)
		}
		return fmt.Errorf("get journal status: %w", err)
	}
	if deletedAt.Valid {
		return fmt.Errorf("cannot delete line from a soft‑deleted journal entry")
	}
	if status != enums.JournalStatusDraft {
		return fmt.Errorf("cannot delete line from journal entry with status %s", status)
	}

	result, err := db.ExecContext(ctx, `DELETE FROM accounting.journal_lines WHERE journal_line_id = $1`, lineID)
	if err != nil {
		r.logger.Error("failed to delete journal line",
			util.String("line_id", lineID.String()),
			util.ErrorField(err))
		return fmt.Errorf("delete journal line: %w", err)
	}
	rows, _ := result.RowsAffected()
	if rows == 0 {
		return fmt.Errorf("journal line %s not found", lineID)
	}
	return nil
}

// ClearLines removes all lines from a journal entry (only allowed if draft and not soft‑deleted)
func (r *journalRepository) ClearLines(ctx context.Context, db DBTX, journalID uuid.UUID) error {
	// Verify entry is draft and not deleted
	var status string
	var deletedAt sql.NullTime
	err := db.QueryRowContext(ctx, `SELECT status, deleted_at FROM accounting.journal_entries WHERE journal_entry_id = $1`, journalID).Scan(&status, &deletedAt)
	if err != nil {
		return fmt.Errorf("get journal status: %w", err)
	}
	if deletedAt.Valid {
		return fmt.Errorf("cannot clear lines from a soft‑deleted journal entry")
	}
	if status != enums.JournalStatusDraft {
		return fmt.Errorf("cannot clear lines from journal entry with status %s", status)
	}

	_, err = db.ExecContext(ctx, `DELETE FROM accounting.journal_lines WHERE journal_entry_id = $1`, journalID)
	if err != nil {
		r.logger.Error("failed to clear journal lines",
			util.String("journal_id", journalID.String()),
			util.ErrorField(err))
		return fmt.Errorf("clear journal lines: %w", err)
	}
	return nil
}

// IsBalanced checks if the journal entry's total debits equal total credits
func (r *journalRepository) IsBalanced(ctx context.Context, db DBTX, journalID uuid.UUID) (bool, float64, float64, error) {
	var totalDebit, totalCredit float64
	query := `
		SELECT COALESCE(SUM(debit_amount), 0), COALESCE(SUM(credit_amount), 0)
		FROM accounting.journal_lines
		WHERE journal_entry_id = $1
	`
	err := db.QueryRowContext(ctx, query, journalID).Scan(&totalDebit, &totalCredit)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return true, 0, 0, nil
		}
		return false, 0, 0, fmt.Errorf("calculate balance: %w", err)
	}
	return totalDebit == totalCredit, totalDebit, totalCredit, nil
}

// ValidateBeforePost performs all pre-posting checks: has lines, is balanced, no negative amounts (handled by DB check)
func (r *journalRepository) ValidateBeforePost(ctx context.Context, db DBTX, journalID uuid.UUID) error {
	// Check if lines exist
	hasLines, err := r.HasLines(ctx, db, journalID)
	if err != nil {
		return err
	}
	if !hasLines {
		return fmt.Errorf("journal entry %s has no lines", journalID)
	}
	// Check balance
	balanced, debit, credit, err := r.IsBalanced(ctx, db, journalID)
	if err != nil {
		return err
	}
	if !balanced {
		return fmt.Errorf("journal entry %s is not balanced: debit=%.2f, credit=%.2f", journalID, debit, credit)
	}
	return nil
}

// HasLines returns true if the journal entry has at least one line
func (r *journalRepository) HasLines(ctx context.Context, db DBTX, journalID uuid.UUID) (bool, error) {
	var count int
	err := db.QueryRowContext(ctx, `SELECT COUNT(*) FROM accounting.journal_lines WHERE journal_entry_id = $1`, journalID).Scan(&count)
	if err != nil {
		return false, fmt.Errorf("check lines existence: %w", err)
	}
	return count > 0, nil
}

// LockJournal acquires a row-level lock on a journal entry (only if not soft‑deleted)
func (r *journalRepository) LockJournal(ctx context.Context, db DBTX, journalID uuid.UUID) error {
	var id uuid.UUID
	err := db.QueryRowContext(ctx, `SELECT journal_entry_id FROM accounting.journal_entries WHERE journal_entry_id = $1 AND deleted_at IS NULL FOR UPDATE`, journalID).Scan(&id)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return fmt.Errorf("journal entry %s not found or soft‑deleted", journalID)
		}
		return fmt.Errorf("lock journal entry: %w", err)
	}
	return nil
}

// ListWithLines returns journal entries with their lines in a single query (optimized for reporting)
func (r *journalRepository) ListWithLines(ctx context.Context, db DBTX, filter JournalFilter, p Pagination, s Sort) ([]*JournalWithLines, error) {
	// First get entries using List (which excludes soft‑deleted)
	entries, err := r.List(ctx, db, filter, p, s)
	if err != nil {
		return nil, err
	}
	if len(entries) == 0 {
		return []*JournalWithLines{}, nil
	}

	// Fetch all lines for these entries in one batch
	entryIDs := make([]uuid.UUID, len(entries))
	for i, e := range entries {
		entryIDs[i] = e.JournalEntryID
	}
	// Build placeholders
	placeholders := make([]string, len(entryIDs))
	args := make([]interface{}, len(entryIDs))
	for i, id := range entryIDs {
		placeholders[i] = fmt.Sprintf("$%d", i+1)
		args[i] = id
	}
	query := fmt.Sprintf(`
		SELECT journal_line_id, journal_entry_id, account_id, line_number,
		       debit_amount, credit_amount, description,
		       created_at, updated_at
		FROM accounting.journal_lines
		WHERE journal_entry_id IN (%s)
		ORDER BY journal_entry_id, line_number
	`, strings.Join(placeholders, ","))

	rows, err := db.QueryContext(ctx, query, args...)
	if err != nil {
		return nil, fmt.Errorf("fetch lines for entries: %w", err)
	}
	defer rows.Close()

	// Map lines to entries
	linesMap := make(map[uuid.UUID][]*models.JournalLine)
	for rows.Next() {
		var line models.JournalLine
		var description sql.NullString
		err := rows.Scan(
			&line.JournalLineID, &line.JournalEntryID, &line.AccountID, &line.LineNumber,
			&line.DebitAmount, &line.CreditAmount, &description,
			&line.CreatedAt, &line.UpdatedAt,
		)
		if err != nil {
			return nil, fmt.Errorf("scan line: %w", err)
		}
		if description.Valid {
			line.Description = &description.String
		}
		linesMap[line.JournalEntryID] = append(linesMap[line.JournalEntryID], &line)
	}

	result := make([]*JournalWithLines, len(entries))
	for i, entry := range entries {
		lines := linesMap[entry.JournalEntryID]
		if lines == nil {
			lines = []*models.JournalLine{}
		}
		result[i] = &JournalWithLines{
			Entry: entry,
			Lines: lines,
		}
	}
	return result, nil
}

// ListByAccount returns all journal lines for a given account within a date range (used for ledger)
// Only includes lines from posted, non‑deleted journal entries.
func (r *journalRepository) ListByAccount(ctx context.Context, db DBTX, accountID uuid.UUID, from, to time.Time) ([]*models.JournalLine, error) {
	query := `
		SELECT jl.journal_line_id, jl.journal_entry_id, jl.account_id, jl.line_number,
		       jl.debit_amount, jl.credit_amount, jl.description,
		       jl.created_at, jl.updated_at
		FROM accounting.journal_lines jl
		INNER JOIN accounting.journal_entries je ON jl.journal_entry_id = je.journal_entry_id
		WHERE jl.account_id = $1
		  AND je.status = 'posted'
		  AND je.deleted_at IS NULL
		  AND je.entry_date BETWEEN $2 AND $3
		ORDER BY je.entry_date, jl.line_number
	`
	rows, err := db.QueryContext(ctx, query, accountID, from, to)
	if err != nil {
		r.logger.Error("failed to list lines by account",
			util.String("account_id", accountID.String()),
			util.ErrorField(err))
		return nil, fmt.Errorf("list lines by account: %w", err)
	}
	defer rows.Close()

	var lines []*models.JournalLine
	for rows.Next() {
		var line models.JournalLine
		var description sql.NullString
		err := rows.Scan(
			&line.JournalLineID, &line.JournalEntryID, &line.AccountID, &line.LineNumber,
			&line.DebitAmount, &line.CreditAmount, &description,
			&line.CreatedAt, &line.UpdatedAt,
		)
		if err != nil {
			return nil, fmt.Errorf("scan line: %w", err)
		}
		if description.Valid {
			line.Description = &description.String
		}
		lines = append(lines, &line)
	}
	return lines, nil
}

// SumByAccount returns total debit and credit for an account within a date range (posted, non‑deleted entries only)
func (r *journalRepository) SumByAccount(ctx context.Context, db DBTX, accountID uuid.UUID, from, to time.Time) (debit float64, credit float64, err error) {
	query := `
		SELECT COALESCE(SUM(jl.debit_amount), 0), COALESCE(SUM(jl.credit_amount), 0)
		FROM accounting.journal_lines jl
		INNER JOIN accounting.journal_entries je ON jl.journal_entry_id = je.journal_entry_id
		WHERE jl.account_id = $1
		  AND je.status = 'posted'
		  AND je.deleted_at IS NULL
		  AND je.entry_date BETWEEN $2 AND $3
	`
	err = db.QueryRowContext(ctx, query, accountID, from, to).Scan(&debit, &credit)
	if err != nil {
		r.logger.Error("failed to sum by account",
			util.String("account_id", accountID.String()),
			util.ErrorField(err))
		return 0, 0, fmt.Errorf("sum by account: %w", err)
	}
	return debit, credit, nil
}

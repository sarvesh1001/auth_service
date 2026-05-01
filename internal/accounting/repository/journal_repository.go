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
	"auth-service/internal/accounting/models/enums"
	"auth-service/internal/util"
)

// =============================================================================
// Custom errors (shared with service)
// =============================================================================

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

// JournalSummary aggregates info for a journal (avoid multiple queries)
type JournalSummary struct {
	TotalLines  int
	TotalDebit  decimal.Decimal
	TotalCredit decimal.Decimal
	IsBalanced  bool
}

// JournalRepository defines the interface for journal data access
type JournalRepository interface {
	// =====================================================
	// JOURNAL ENTRY (HEADER)
	// =====================================================
	Create(ctx context.Context, db DBTX, j *models.JournalEntry) error
	CreateOrGetBySource(ctx context.Context, db DBTX, companyID uuid.UUID, sourceType string, sourceID string, builder func() *models.JournalEntry) (*models.JournalEntry, bool, error)

	Update(ctx context.Context, db DBTX, j *models.JournalEntry) error

	GetByID(ctx context.Context, db DBTX, id uuid.UUID) (*models.JournalEntry, error)
	GetByIDForUpdate(ctx context.Context, db DBTX, id uuid.UUID) (*models.JournalEntry, error)
	GetBySource(ctx context.Context, db DBTX, companyID uuid.UUID, sourceType string, sourceID string) (*models.JournalEntry, error)
	GetBySourceForUpdate(ctx context.Context, db DBTX, companyID uuid.UUID, sourceType string, sourceID string) (*models.JournalEntry, error)

	List(ctx context.Context, db DBTX, filter JournalFilter, p Pagination, s Sort) ([]*models.JournalEntry, error)
	ListByCompany(ctx context.Context, db DBTX, companyID uuid.UUID) ([]*models.JournalEntry, error)

	Count(ctx context.Context, db DBTX, filter JournalFilter) (int64, error)

	Delete(ctx context.Context, db DBTX, id uuid.UUID, deletedBy *uuid.UUID) error
	ExistsBySource(ctx context.Context, db DBTX, companyID uuid.UUID, sourceType string, sourceID string) (bool, error)

	// =====================================================
	// STATUS / LIFECYCLE
	// =====================================================
	UpdateStatus(ctx context.Context, db DBTX, id uuid.UUID, status string, updatedBy *uuid.UUID) error

	Post(ctx context.Context, db DBTX, id uuid.UUID, postedBy *uuid.UUID) error
	Reverse(ctx context.Context, db DBTX, originalID uuid.UUID, reversal *models.JournalEntry) error

	// Optimised status checks
	EnsureDraft(ctx context.Context, db DBTX, id uuid.UUID) error
	EnsurePosted(ctx context.Context, db DBTX, id uuid.UUID) error

	HasReversal(ctx context.Context, db DBTX, originalID uuid.UUID) (bool, error)

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
	// VALIDATION (DB‑driven, repo provides helpers)
	// =====================================================
	IsBalanced(ctx context.Context, db DBTX, journalID uuid.UUID) (bool, decimal.Decimal, decimal.Decimal, error)

	ValidateBeforePost(ctx context.Context, db DBTX, journalID uuid.UUID) error

	HasLines(ctx context.Context, db DBTX, journalID uuid.UUID) (bool, error)

	HasLedgerEntries(ctx context.Context, db DBTX, journalID uuid.UUID) (bool, error)
	ValidateLedgerExists(ctx context.Context, db DBTX, journalID uuid.UUID) error

	// =====================================================
	// AGGREGATION / PERFORMANCE HELPERS
	// =====================================================
	GetJournalSummary(ctx context.Context, db DBTX, journalID uuid.UUID) (*JournalSummary, error)

	// =====================================================
	// LOCKING
	// =====================================================
	LockJournal(ctx context.Context, db DBTX, journalID uuid.UUID) error
	GetAndLock(ctx context.Context, db DBTX, id uuid.UUID) (*models.JournalEntry, error)

	// =====================================================
	// POSTING / REPORTING
	// =====================================================
	GetForPosting(ctx context.Context, db DBTX, id uuid.UUID) (*models.JournalEntry, []*models.JournalLine, error)

	ListWithLines(ctx context.Context, db DBTX, filter JournalFilter, p Pagination, s Sort) ([]*JournalWithLines, error)
	ListByAccount(ctx context.Context, db DBTX, accountID uuid.UUID, from, to time.Time) ([]*models.JournalLine, error)

	SumByAccount(ctx context.Context, db DBTX, accountID uuid.UUID, from, to time.Time) (debit decimal.Decimal, credit decimal.Decimal, err error)
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

// =============================================================================
// DB error mapping (centralised, uses PostgreSQL error codes when possible)
// =============================================================================
func (r *journalRepository) mapDBError(err error, operation string) error {
	if err == nil {
		return nil
	}
	// Try to extract PostgreSQL error
	if pqErr, ok := err.(*pq.Error); ok {
		switch pqErr.Constraint {
		case "unique_source":
			return ErrDuplicateSource
		case "trg_ensure_ledger_on_post":
			return ErrLedgerMissing
		case "trg_validate_journal_before_post":
			return ErrJournalNotBalanced
		case "trg_no_delete_posted":
			return ErrCannotDeletePosted
		case "trg_no_update_posted_lines":
			return ErrCannotModifyPosted
		}
	}
	// Fallback to string matching
	errMsg := err.Error()
	switch {
	case strings.Contains(errMsg, "unique_source"):
		return ErrDuplicateSource
	case strings.Contains(errMsg, "ledger_entries missing"):
		return ErrLedgerMissing
	case strings.Contains(errMsg, "not balanced"):
		return ErrJournalNotBalanced
	case strings.Contains(errMsg, "Cannot delete posted"):
		return ErrCannotDeletePosted
	case strings.Contains(errMsg, "Cannot modify or delete"):
		return ErrCannotModifyPosted
	}
	return fmt.Errorf("%s: %w", operation, err)
}

// =============================================================================
// SORT / PAGINATION / FILTER BUILDERS (unchanged)
// =============================================================================
var allowedJournalSortFields = map[string]bool{
	"entry_date":   true,
	"created_at":   true,
	"updated_at":   true,
	"journal_type": true,
	"status":       true,
	"reference":    true,
}

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

	conditions = append(conditions, "deleted_at IS NULL")
	if len(conditions) == 0 {
		return "", args
	}
	return "WHERE " + strings.Join(conditions, " AND "), args
}

// scanJournalEntry – updated to scan source_id as sql.NullString
func (r *journalRepository) scanJournalEntry(scanner interface {
	Scan(dest ...interface{}) error
}) (*models.JournalEntry, error) {
	var j models.JournalEntry
	var reference, description sql.NullString
	var reversalOf uuid.NullUUID
	var sourceType sql.NullString
	var sourceID sql.NullString
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
		j.SourceID = &sourceID.String
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

// =============================================================================
// CREATE (with duplicate source handling)
// =============================================================================
func (r *journalRepository) Create(ctx context.Context, db DBTX, j *models.JournalEntry) error {
	query := `
        INSERT INTO accounting.journal_entries (
            journal_entry_id, company_id, journal_type, entry_date,
            reference, description, status, reversal_of,
            source_type, source_id,
            created_at, posted_at, posted_by, created_by, updated_at, updated_by, deleted_at
        ) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, NOW(), $11, $12, $13, NOW(), $14, NULL)
        RETURNING created_at, updated_at
    `
	err := db.QueryRowContext(ctx, query,
		j.JournalEntryID, j.CompanyID, j.JournalType, j.EntryDate,
		j.Reference, j.Description, j.Status, j.ReversalOf,
		j.SourceType, j.SourceID,
		j.PostedAt, j.PostedBy, j.CreatedBy, j.UpdatedBy,
	).Scan(&j.CreatedAt, &j.UpdatedAt)

	if err != nil {
		return r.mapDBError(err, "create journal entry")
	}
	return nil
}

// CreateOrGetBySource – idempotent creation with string sourceID
func (r *journalRepository) CreateOrGetBySource(ctx context.Context, db DBTX, companyID uuid.UUID, sourceType string, sourceID string, builder func() *models.JournalEntry) (*models.JournalEntry, bool, error) {
	existing, err := r.GetBySourceForUpdate(ctx, db, companyID, sourceType, sourceID)
	if err == nil {
		return existing, false, nil
	}
	if !errors.Is(err, ErrNotFound) {
		return nil, false, err
	}

	newEntry := builder()
	if newEntry.CompanyID != companyID ||
		(newEntry.SourceType == nil || *newEntry.SourceType != sourceType) ||
		(newEntry.SourceID == nil || *newEntry.SourceID != sourceID) {
		return nil, false, errors.New("builder must produce entry with matching company_id, source_type, source_id")
	}
	if err := r.Create(ctx, db, newEntry); err != nil {
		return nil, false, err
	}
	return newEntry, true, nil
}

// Update
func (r *journalRepository) Update(ctx context.Context, db DBTX, j *models.JournalEntry) error {
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

// GetByID, GetByIDForUpdate, GetBySource, GetBySourceForUpdate
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
			return nil, ErrNotFound
		}
		r.logger.Error("failed to get journal entry by ID",
			util.String("id", id.String()),
			util.ErrorField(err))
		return nil, fmt.Errorf("get journal entry by ID: %w", err)
	}
	return j, nil
}

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
			return nil, ErrNotFound
		}
		r.logger.Error("failed to get journal entry for update",
			util.String("id", id.String()),
			util.ErrorField(err))
		return nil, fmt.Errorf("get journal entry for update: %w", err)
	}
	return j, nil
}

func (r *journalRepository) GetBySource(ctx context.Context, db DBTX, companyID uuid.UUID, sourceType string, sourceID string) (*models.JournalEntry, error) {
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
			return nil, ErrNotFound
		}
		r.logger.Error("failed to get journal entry by source",
			util.String("company_id", companyID.String()),
			util.String("source_type", sourceType),
			util.String("source_id", sourceID),
			util.ErrorField(err))
		return nil, fmt.Errorf("get journal entry by source: %w", err)
	}
	return j, nil
}

func (r *journalRepository) GetBySourceForUpdate(ctx context.Context, db DBTX, companyID uuid.UUID, sourceType string, sourceID string) (*models.JournalEntry, error) {
	query := `
		SELECT journal_entry_id, company_id, journal_type, entry_date,
		       reference, description, status, reversal_of,
		       source_type, source_id,
		       created_at, posted_at, posted_by, created_by, updated_at, updated_by, deleted_at
		FROM accounting.journal_entries
		WHERE company_id = $1 AND source_type = $2 AND source_id = $3 AND deleted_at IS NULL
		FOR UPDATE
	`
	j, err := r.scanJournalEntry(db.QueryRowContext(ctx, query, companyID, sourceType, sourceID))
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, ErrNotFound
		}
		r.logger.Error("failed to get journal entry by source with lock",
			util.String("company_id", companyID.String()),
			util.String("source_type", sourceType),
			util.String("source_id", sourceID),
			util.ErrorField(err))
		return nil, fmt.Errorf("get journal entry by source for update: %w", err)
	}
	return j, nil
}

// List unchanged
func (r *journalRepository) List(ctx context.Context, db DBTX, filter JournalFilter, p Pagination, s Sort) ([]*models.JournalEntry, error) {
	where, args := r.buildJournalFilter(filter)
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

func (r *journalRepository) ListByCompany(ctx context.Context, db DBTX, companyID uuid.UUID) ([]*models.JournalEntry, error) {
	return r.List(ctx, db, JournalFilter{CompanyID: companyID}, Pagination{Limit: 1000}, Sort{Field: "entry_date", Direction: "DESC"})
}

func (r *journalRepository) Count(ctx context.Context, db DBTX, filter JournalFilter) (int64, error) {
	where, args := r.buildJournalFilter(filter)
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

// Delete
func (r *journalRepository) Delete(ctx context.Context, db DBTX, id uuid.UUID, deletedBy *uuid.UUID) error {
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

	query := `
		UPDATE accounting.journal_entries
		SET deleted_at = NOW(), status = 'deleted', updated_by = $2, updated_at = NOW()
		WHERE journal_entry_id = $1 AND status = 'draft' AND deleted_at IS NULL
	`
	_, err = db.ExecContext(ctx, query, id, deletedBy)
	if err != nil {
		return r.mapDBError(err, "delete journal entry")
	}
	return nil
}

func (r *journalRepository) ExistsBySource(ctx context.Context, db DBTX, companyID uuid.UUID, sourceType string, sourceID string) (bool, error) {
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
			zap.String("source_id", sourceID),
			zap.Error(err))
		return false, fmt.Errorf("exists by source: %w", err)
	}
	return exists, nil
}

// =============================================================================
// STATUS TRANSITIONS (uses package-level error)
// =============================================================================
var validTransitions = map[string]map[string]bool{
	enums.JournalStatusDraft: {
		enums.JournalStatusPosted:  true,
		enums.JournalStatusDeleted: true,
	},
	enums.JournalStatusPosted: {
		enums.JournalStatusReversed: true,
	},
	enums.JournalStatusReversed: {},
	enums.JournalStatusDeleted:  {},
}

func isValidStatusTransition(from, to string) bool {
	if from == to {
		return true
	}
	allowed, ok := validTransitions[from]
	if !ok {
		return false
	}
	return allowed[to]
}

func (r *journalRepository) UpdateStatus(ctx context.Context, db DBTX, id uuid.UUID, newStatus string, updatedBy *uuid.UUID) error {
	var currentStatus string
	err := db.QueryRowContext(ctx, `SELECT status FROM accounting.journal_entries WHERE journal_entry_id = $1 AND deleted_at IS NULL`, id).Scan(&currentStatus)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return fmt.Errorf("journal entry %s not found", id)
		}
		return fmt.Errorf("get status: %w", err)
	}
	if !isValidStatusTransition(currentStatus, newStatus) {
		return fmt.Errorf("%w: %s -> %s", ErrInvalidStatusTransition, currentStatus, newStatus)
	}

	query := `
		UPDATE accounting.journal_entries
		SET status = $2, updated_by = $3, updated_at = NOW()
		WHERE journal_entry_id = $1 AND deleted_at IS NULL
	`
	result, err := db.ExecContext(ctx, query, id, newStatus, updatedBy)
	if err != nil {
		r.logger.Error("failed to update journal status",
			util.String("id", id.String()),
			util.String("new_status", newStatus),
			util.ErrorField(err))
		return fmt.Errorf("update journal status: %w", err)
	}
	rows, _ := result.RowsAffected()
	if rows == 0 {
		return fmt.Errorf("journal entry %s not found or soft‑deleted", id)
	}
	return nil
}

// Post
func (r *journalRepository) Post(ctx context.Context, db DBTX, id uuid.UUID, postedBy *uuid.UUID) error {
	if err := r.LockJournal(ctx, db, id); err != nil {
		return err
	}

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

	balanced, _, _, err := r.IsBalanced(ctx, db, id)
	if err != nil {
		return err
	}
	if !balanced {
		return ErrJournalNotBalanced
	}

	query := `
		UPDATE accounting.journal_entries
		SET status = 'posted', posted_at = NOW(), posted_by = $2, updated_at = NOW()
		WHERE journal_entry_id = $1 AND status = 'draft' AND deleted_at IS NULL
		RETURNING posted_at
	`
	var postedAt time.Time
	err = db.QueryRowContext(ctx, query, id, postedBy).Scan(&postedAt)
	if err != nil {
		return r.mapDBError(err, "post journal entry")
	}
	return nil
}

// Reverse
func (r *journalRepository) Reverse(ctx context.Context, db DBTX, originalID uuid.UUID, reversal *models.JournalEntry) error {
	if err := r.LockJournal(ctx, db, originalID); err != nil {
		return err
	}

	hasRev, err := r.HasReversal(ctx, db, originalID)
	if err != nil {
		return err
	}
	if hasRev {
		return ErrReversalAlreadyExists
	}

	var originalStatus string
	var deletedAt sql.NullTime
	err = db.QueryRowContext(ctx, `SELECT status, deleted_at FROM accounting.journal_entries WHERE journal_entry_id = $1`, originalID).Scan(&originalStatus, &deletedAt)
	if err != nil {
		return fmt.Errorf("get original journal status: %w", err)
	}
	if deletedAt.Valid {
		return fmt.Errorf("cannot reverse a soft‑deleted journal entry")
	}
	if originalStatus != enums.JournalStatusPosted {
		return fmt.Errorf("only posted journal entries can be reversed, current status: %s", originalStatus)
	}

	if reversal.ReversalOf == nil || *reversal.ReversalOf != originalID {
		return errors.New("reversal entry must have ReversalOf set to original journal ID")
	}

	if err := r.Create(ctx, db, reversal); err != nil {
		return fmt.Errorf("create reversal entry: %w", err)
	}

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

// EnsureDraft, EnsurePosted
func (r *journalRepository) EnsureDraft(ctx context.Context, db DBTX, id uuid.UUID) error {
	var status string
	err := db.QueryRowContext(ctx, `SELECT status FROM accounting.journal_entries WHERE journal_entry_id = $1 AND deleted_at IS NULL`, id).Scan(&status)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return fmt.Errorf("journal entry %s not found", id)
		}
		return err
	}
	if status != enums.JournalStatusDraft {
		return fmt.Errorf("journal entry %s is not in draft status", id)
	}
	return nil
}

func (r *journalRepository) EnsurePosted(ctx context.Context, db DBTX, id uuid.UUID) error {
	var status string
	err := db.QueryRowContext(ctx, `SELECT status FROM accounting.journal_entries WHERE journal_entry_id = $1 AND deleted_at IS NULL`, id).Scan(&status)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return fmt.Errorf("journal entry %s not found", id)
		}
		return err
	}
	if status != enums.JournalStatusPosted {
		return fmt.Errorf("journal entry %s is not posted", id)
	}
	return nil
}

// HasReversal
func (r *journalRepository) HasReversal(ctx context.Context, db DBTX, originalID uuid.UUID) (bool, error) {
	var count int
	err := db.QueryRowContext(ctx, `SELECT COUNT(*) FROM accounting.journal_entries WHERE reversal_of = $1 AND deleted_at IS NULL`, originalID).Scan(&count)
	if err != nil {
		return false, fmt.Errorf("check reversal existence: %w", err)
	}
	return count > 0, nil
}

// =============================================================================
// LINES
// =============================================================================
func (r *journalRepository) AddLine(ctx context.Context, db DBTX, line *models.JournalLine) error {
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

// BulkAddLines – multi‑insert without RETURNING
func (r *journalRepository) BulkAddLines(ctx context.Context, db DBTX, lines []*models.JournalLine) error {
	if len(lines) == 0 {
		return nil
	}
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

	valueStrings := make([]string, 0, len(lines))
	args := make([]interface{}, 0, len(lines)*7)
	for i, l := range lines {
		valueStrings = append(valueStrings, fmt.Sprintf("($%d, $%d, $%d, $%d, $%d, $%d, $%d, NOW(), NOW())",
			i*7+1, i*7+2, i*7+3, i*7+4, i*7+5, i*7+6, i*7+7))
		args = append(args, l.JournalLineID, l.JournalEntryID, l.AccountID, l.LineNumber,
			l.DebitAmount, l.CreditAmount, l.Description)
	}
	query := fmt.Sprintf(`
		INSERT INTO accounting.journal_lines (
			journal_line_id, journal_entry_id, account_id, line_number,
			debit_amount, credit_amount, description, created_at, updated_at
		) VALUES %s
	`, strings.Join(valueStrings, ","))

	_, err = db.ExecContext(ctx, query, args...)
	if err != nil {
		r.logger.Error("bulk add lines failed",
			util.String("journal_id", journalID.String()),
			util.ErrorField(err))
		return fmt.Errorf("bulk add journal lines: %w", err)
	}
	return nil
}

// GetLines
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

func (r *journalRepository) UpdateLine(ctx context.Context, db DBTX, line *models.JournalLine) error {
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
		return r.mapDBError(err, "update journal line")
	}
	return nil
}

func (r *journalRepository) DeleteLine(ctx context.Context, db DBTX, lineID uuid.UUID) error {
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

	_, err = db.ExecContext(ctx, `DELETE FROM accounting.journal_lines WHERE journal_line_id = $1`, lineID)
	if err != nil {
		return r.mapDBError(err, "delete journal line")
	}
	return nil
}

func (r *journalRepository) ClearLines(ctx context.Context, db DBTX, journalID uuid.UUID) error {
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

// =============================================================================
// VALIDATION
// =============================================================================
func (r *journalRepository) IsBalanced(ctx context.Context, db DBTX, journalID uuid.UUID) (bool, decimal.Decimal, decimal.Decimal, error) {
	var totalDebit, totalCredit decimal.Decimal
	query := `
		SELECT COALESCE(SUM(debit_amount), 0), COALESCE(SUM(credit_amount), 0)
		FROM accounting.journal_lines
		WHERE journal_entry_id = $1
	`
	err := db.QueryRowContext(ctx, query, journalID).Scan(&totalDebit, &totalCredit)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return true, decimal.Zero, decimal.Zero, nil
		}
		return false, decimal.Zero, decimal.Zero, fmt.Errorf("calculate balance: %w", err)
	}
	return totalDebit.Equal(totalCredit), totalDebit, totalCredit, nil
}

func (r *journalRepository) ValidateBeforePost(ctx context.Context, db DBTX, journalID uuid.UUID) error {
	hasLines, err := r.HasLines(ctx, db, journalID)
	if err != nil {
		return err
	}
	if !hasLines {
		return fmt.Errorf("journal entry %s has no lines", journalID)
	}
	balanced, debit, credit, err := r.IsBalanced(ctx, db, journalID)
	if err != nil {
		return err
	}
	if !balanced {
		return fmt.Errorf("journal entry %s is not balanced: debit=%s, credit=%s", journalID, debit.String(), credit.String())
	}
	return nil
}

func (r *journalRepository) HasLines(ctx context.Context, db DBTX, journalID uuid.UUID) (bool, error) {
	var count int
	err := db.QueryRowContext(ctx, `SELECT COUNT(*) FROM accounting.journal_lines WHERE journal_entry_id = $1`, journalID).Scan(&count)
	if err != nil {
		return false, fmt.Errorf("check lines existence: %w", err)
	}
	return count > 0, nil
}

func (r *journalRepository) HasLedgerEntries(ctx context.Context, db DBTX, journalID uuid.UUID) (bool, error) {
	var count int
	err := db.QueryRowContext(ctx, `SELECT COUNT(*) FROM accounting.ledger_entries WHERE journal_entry_id = $1`, journalID).Scan(&count)
	if err != nil {
		return false, fmt.Errorf("check ledger entries existence: %w", err)
	}
	return count > 0, nil
}

func (r *journalRepository) ValidateLedgerExists(ctx context.Context, db DBTX, journalID uuid.UUID) error {
	exists, err := r.HasLedgerEntries(ctx, db, journalID)
	if err != nil {
		return err
	}
	if !exists {
		return ErrLedgerMissing
	}
	return nil
}

// =============================================================================
// AGGREGATION / PERFORMANCE
// =============================================================================
func (r *journalRepository) GetJournalSummary(ctx context.Context, db DBTX, journalID uuid.UUID) (*JournalSummary, error) {
	var summary JournalSummary
	row := db.QueryRowContext(ctx, `
		SELECT 
			COUNT(*) AS total_lines,
			COALESCE(SUM(debit_amount), 0) AS total_debit,
			COALESCE(SUM(credit_amount), 0) AS total_credit
		FROM accounting.journal_lines
		WHERE journal_entry_id = $1
	`, journalID)
	err := row.Scan(&summary.TotalLines, &summary.TotalDebit, &summary.TotalCredit)
	if err != nil {
		return nil, fmt.Errorf("get journal summary: %w", err)
	}
	summary.IsBalanced = summary.TotalDebit.Equal(summary.TotalCredit)
	return &summary, nil
}

// =============================================================================
// LOCKING
// =============================================================================
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

func (r *journalRepository) GetAndLock(ctx context.Context, db DBTX, id uuid.UUID) (*models.JournalEntry, error) {
	return r.GetByIDForUpdate(ctx, db, id)
}

// =============================================================================
// POSTING HELPER
// =============================================================================
func (r *journalRepository) GetForPosting(ctx context.Context, db DBTX, id uuid.UUID) (*models.JournalEntry, []*models.JournalLine, error) {
	entry, err := r.GetByIDForUpdate(ctx, db, id)
	if err != nil {
		return nil, nil, err
	}
	lines, err := r.GetLines(ctx, db, id)
	if err != nil {
		return nil, nil, err
	}
	return entry, lines, nil
}

// =============================================================================
// REPORTING
// =============================================================================
func (r *journalRepository) ListWithLines(ctx context.Context, db DBTX, filter JournalFilter, p Pagination, s Sort) ([]*JournalWithLines, error) {
	entries, err := r.List(ctx, db, filter, p, s)
	if err != nil {
		return nil, err
	}
	if len(entries) == 0 {
		return []*JournalWithLines{}, nil
	}

	entryIDs := make([]uuid.UUID, len(entries))
	for i, e := range entries {
		entryIDs[i] = e.JournalEntryID
	}
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

func (r *journalRepository) SumByAccount(ctx context.Context, db DBTX, accountID uuid.UUID, from, to time.Time) (debit decimal.Decimal, credit decimal.Decimal, err error) {
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
		return decimal.Zero, decimal.Zero, fmt.Errorf("sum by account: %w", err)
	}
	return debit, credit, nil
}

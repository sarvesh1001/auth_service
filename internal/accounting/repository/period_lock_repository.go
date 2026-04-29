package repository

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"strings"

	"github.com/google/uuid"
	"go.uber.org/zap"

	"auth-service/internal/accounting/models"
)

// PeriodLockFilter defines filters for listing period locks
type PeriodLockFilter struct {
	CompanyID  uuid.UUID
	FiscalYear *int
	Period     *int
	IsLocked   *bool
}

// PeriodLockRepository defines operations for accounting period locks
type PeriodLockRepository interface {
	LockPeriod(ctx context.Context, db DBTX, companyID uuid.UUID, fiscalYear, period int, lockedBy *uuid.UUID, reason string) error
	UnlockPeriod(ctx context.Context, db DBTX, companyID uuid.UUID, fiscalYear, period int, unlockedBy *uuid.UUID, reason string) error
	IsLocked(ctx context.Context, db DBTX, companyID uuid.UUID, fiscalYear, period int) (bool, error)
	GetLock(ctx context.Context, db DBTX, companyID uuid.UUID, fiscalYear, period int) (*models.PeriodLock, error)
	ListLocks(ctx context.Context, db DBTX, filter PeriodLockFilter, p Pagination, s Sort) ([]*models.PeriodLock, error)
	ListLockedPeriods(ctx context.Context, db DBTX, companyID uuid.UUID) (map[[2]int]string, error)
	DeleteLock(ctx context.Context, db DBTX, lockID uuid.UUID) error
}

type periodLockRepository struct {
	logger *zap.Logger
}

func NewPeriodLockRepository(logger *zap.Logger) PeriodLockRepository {
	return &periodLockRepository{
		logger: logger.Named("period_lock_repo"),
	}
}

var allowedPeriodLockSortFields = map[string]bool{
	"fiscal_year": true,
	"period":      true,
	"locked_at":   true,
	"created_at":  true,
}

func (r *periodLockRepository) validateSort(s Sort) (string, error) {
	field := s.Field
	if field == "" {
		field = "fiscal_year"
	}
	if !allowedPeriodLockSortFields[field] {
		return "", fmt.Errorf("invalid sort field: %s", field)
	}
	dir := strings.ToUpper(s.Direction)
	if dir != "ASC" && dir != "DESC" {
		dir = "ASC"
	}
	return fmt.Sprintf("ORDER BY %s %s", field, dir), nil
}

func (r *periodLockRepository) buildFilter(filter PeriodLockFilter) (string, []interface{}) {
	var conditions []string
	var args []interface{}
	idx := 1

	if filter.CompanyID != uuid.Nil {
		conditions = append(conditions, fmt.Sprintf("company_id = $%d", idx))
		args = append(args, filter.CompanyID)
		idx++
	}
	if filter.FiscalYear != nil {
		conditions = append(conditions, fmt.Sprintf("fiscal_year = $%d", idx))
		args = append(args, *filter.FiscalYear)
		idx++
	}
	if filter.Period != nil {
		conditions = append(conditions, fmt.Sprintf("period = $%d", idx))
		args = append(args, *filter.Period)
		idx++
	}
	if filter.IsLocked != nil {
		conditions = append(conditions, fmt.Sprintf("is_locked = $%d", idx))
		args = append(args, *filter.IsLocked)
		idx++
	}

	if len(conditions) == 0 {
		return "", args
	}
	return "WHERE " + strings.Join(conditions, " AND "), args
}

// scanLock – now without unlocked_at/unlocked_by
func (r *periodLockRepository) scanLock(row interface {
	Scan(dest ...interface{}) error
}) (*models.PeriodLock, error) {
	var lock models.PeriodLock
	var lockedBy uuid.NullUUID

	err := row.Scan(
		&lock.LockID,
		&lock.CompanyID,
		&lock.FiscalYear,
		&lock.Period,
		&lock.IsLocked,
		&lock.LockedAt,
		&lockedBy,
		&lock.Reason,
		&lock.CreatedAt,
		&lock.UpdatedAt,
	)
	if err != nil {
		return nil, err
	}
	if lockedBy.Valid {
		lock.LockedBy = &lockedBy.UUID
	}
	return &lock, nil
}

// LockPeriod – upsert: set is_locked=true, record locked_by, reason, locked_at
func (r *periodLockRepository) LockPeriod(ctx context.Context, db DBTX, companyID uuid.UUID, fiscalYear, period int, lockedBy *uuid.UUID, reason string) error {
	query := `
		INSERT INTO accounting.period_locks (
			lock_id, company_id, fiscal_year, period, is_locked,
			locked_at, locked_by, reason, created_at, updated_at
		) VALUES (
			gen_random_uuid(), $1, $2, $3, true, NOW(), $4, $5, NOW(), NOW()
		)
		ON CONFLICT (company_id, fiscal_year, period)
		DO UPDATE SET
			is_locked = true,
			locked_at = NOW(),
			locked_by = EXCLUDED.locked_by,
			reason = EXCLUDED.reason,
			updated_at = NOW()
	`
	_, err := db.ExecContext(ctx, query, companyID, fiscalYear, period, lockedBy, reason)
	if err != nil {
		r.logger.Error("failed to lock period",
			zap.String("company_id", companyID.String()),
			zap.Int("fiscal_year", fiscalYear),
			zap.Int("period", period),
			zap.Error(err))
		return fmt.Errorf("lock period: %w", err)
	}
	return nil
}

// UnlockPeriod – only set is_locked=false, keep original locked info
func (r *periodLockRepository) UnlockPeriod(ctx context.Context, db DBTX, companyID uuid.UUID, fiscalYear, period int, unlockedBy *uuid.UUID, reason string) error {
	query := `
		UPDATE accounting.period_locks
		SET is_locked = false,
		    updated_at = NOW()
		WHERE company_id = $1 AND fiscal_year = $2 AND period = $3
	`
	// unlockedBy and reason are optional – we ignore them because table lacks columns
	_, err := db.ExecContext(ctx, query, companyID, fiscalYear, period)
	if err != nil {
		r.logger.Error("failed to unlock period",
			zap.String("company_id", companyID.String()),
			zap.Int("fiscal_year", fiscalYear),
			zap.Int("period", period),
			zap.Error(err))
		return fmt.Errorf("unlock period: %w", err)
	}
	return nil
}

// IsLocked – simple check
func (r *periodLockRepository) IsLocked(ctx context.Context, db DBTX, companyID uuid.UUID, fiscalYear, period int) (bool, error) {
	var locked bool
	query := `SELECT is_locked FROM accounting.period_locks WHERE company_id = $1 AND fiscal_year = $2 AND period = $3`
	err := db.QueryRowContext(ctx, query, companyID, fiscalYear, period).Scan(&locked)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return false, nil
		}
		return false, fmt.Errorf("check period locked: %w", err)
	}
	return locked, nil
}

// GetLock – full record (without unlocked fields)
func (r *periodLockRepository) GetLock(ctx context.Context, db DBTX, companyID uuid.UUID, fiscalYear, period int) (*models.PeriodLock, error) {
	query := `
		SELECT lock_id, company_id, fiscal_year, period, is_locked,
		       locked_at, locked_by, reason, created_at, updated_at
		FROM accounting.period_locks
		WHERE company_id = $1 AND fiscal_year = $2 AND period = $3
	`
	return r.scanLock(db.QueryRowContext(ctx, query, companyID, fiscalYear, period))
}

// ListLocks – paginated, filtered
func (r *periodLockRepository) ListLocks(ctx context.Context, db DBTX, filter PeriodLockFilter, p Pagination, s Sort) ([]*models.PeriodLock, error) {
	where, args := r.buildFilter(filter)
	orderBy, err := r.validateSort(s)
	if err != nil {
		return nil, err
	}
	limit, offset := r.validatePagination(p)

	query := fmt.Sprintf(`
		SELECT lock_id, company_id, fiscal_year, period, is_locked,
		       locked_at, locked_by, reason, created_at, updated_at
		FROM accounting.period_locks
		%s
		%s
		LIMIT $%d OFFSET $%d
	`, where, orderBy, len(args)+1, len(args)+2)

	args = append(args, limit, offset)
	rows, err := db.QueryContext(ctx, query, args...)
	if err != nil {
		r.logger.Error("failed to list period locks", zap.Error(err))
		return nil, fmt.Errorf("list period locks: %w", err)
	}
	defer rows.Close()

	var locks []*models.PeriodLock
	for rows.Next() {
		lock, err := r.scanLock(rows)
		if err != nil {
			return nil, fmt.Errorf("scan lock: %w", err)
		}
		locks = append(locks, lock)
	}
	return locks, nil
}

// ListLockedPeriods – map of (fy,period) -> reason
func (r *periodLockRepository) ListLockedPeriods(ctx context.Context, db DBTX, companyID uuid.UUID) (map[[2]int]string, error) {
	rows, err := db.QueryContext(ctx, `
		SELECT fiscal_year, period, reason
		FROM accounting.period_locks
		WHERE company_id = $1 AND is_locked = true
	`, companyID)
	if err != nil {
		return nil, fmt.Errorf("list locked periods: %w", err)
	}
	defer rows.Close()

	result := make(map[[2]int]string)
	for rows.Next() {
		var fy, p int
		var reason string
		if err := rows.Scan(&fy, &p, &reason); err != nil {
			return nil, err
		}
		result[[2]int{fy, p}] = reason
	}
	return result, nil
}

// DeleteLock – hard delete
func (r *periodLockRepository) DeleteLock(ctx context.Context, db DBTX, lockID uuid.UUID) error {
	_, err := db.ExecContext(ctx, `DELETE FROM accounting.period_locks WHERE lock_id = $1`, lockID)
	if err != nil {
		return fmt.Errorf("delete lock: %w", err)
	}
	return nil
}

// validatePagination – helper
func (r *periodLockRepository) validatePagination(p Pagination) (int, int) {
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

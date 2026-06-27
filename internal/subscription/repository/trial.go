// repository/trial_repository.go
package repository

import (
	"context"
	"database/sql"
	"fmt"
	"strings"
	"time"

	"github.com/google/uuid"
	"go.uber.org/zap"

	"auth-service/internal/subscription/errors"
	"auth-service/internal/subscription/models"
)

// ---------------------------------------------------------------------
// Interface
// ---------------------------------------------------------------------

type TrialRepository interface {
	// CRUD
	Create(ctx context.Context, db DBTX, trial *models.Trial) error
	Update(ctx context.Context, db DBTX, trial *models.Trial) error
	Delete(ctx context.Context, db DBTX, companyID, trialID uuid.UUID) error

	// Single Fetch
	GetByID(ctx context.Context, db DBTX, companyID, trialID uuid.UUID) (*models.Trial, error)
	GetBySubscription(ctx context.Context, db DBTX, companyID, subscriptionID uuid.UUID) (*models.Trial, error)
	GetActiveBySubscription(ctx context.Context, db DBTX, companyID, subscriptionID uuid.UUID) (*models.Trial, error)

	// Listing
	List(ctx context.Context, db DBTX, filter TrialFilter, p Pagination, s Sort) ([]*models.Trial, int64, error)
	ListBySubscription(ctx context.Context, db DBTX, companyID, subscriptionID uuid.UUID) ([]*models.Trial, error)
	ListActive(ctx context.Context, db DBTX, companyID uuid.UUID) ([]*models.Trial, error)
	ListExpired(ctx context.Context, db DBTX, companyID uuid.UUID) ([]*models.Trial, error)
	ListExpiringSoon(ctx context.Context, db DBTX, companyID uuid.UUID, before time.Time) ([]*models.Trial, error)

	// Trial Operations
	UpdateStatus(ctx context.Context, db DBTX, companyID, trialID uuid.UUID, status string) error
	Activate(ctx context.Context, db DBTX, companyID, trialID uuid.UUID) error
	Expire(ctx context.Context, db DBTX, companyID, trialID uuid.UUID) error
	Convert(ctx context.Context, db DBTX, companyID, trialID uuid.UUID) error
	ExtendTrial(ctx context.Context, db DBTX, companyID, trialID uuid.UUID, extraDays int) error
	SetEndDate(ctx context.Context, db DBTX, companyID, trialID uuid.UUID, endedAt time.Time) error

	// Validation
	Exists(ctx context.Context, db DBTX, companyID, trialID uuid.UUID) (bool, error)
	ExistsActiveBySubscription(ctx context.Context, db DBTX, companyID, subscriptionID uuid.UUID) (bool, error)
	Search(ctx context.Context, db DBTX, companyID uuid.UUID, query string, limit, offset int) ([]*models.Trial, int64, error)

	// Locking
	GetByIDForUpdate(ctx context.Context, db DBTX, companyID, trialID uuid.UUID) (*models.Trial, error)
}

// ---------------------------------------------------------------------
// Filter
// ---------------------------------------------------------------------

type TrialFilter struct {
	CompanyID      uuid.UUID
	TrialIDs       []uuid.UUID
	SubscriptionID *uuid.UUID
	Status         *string
	StartedFrom    *time.Time
	StartedTo      *time.Time
	EndedFrom      *time.Time
	EndedTo        *time.Time
}

// ---------------------------------------------------------------------
// Implementation
// ---------------------------------------------------------------------

type trialRepository struct {
	logger *zap.Logger
}

func NewTrialRepository(logger *zap.Logger) TrialRepository {
	return &trialRepository{
		logger: logger.Named("subscription_trial_repo"),
	}
}

const trialTable = "subscription.trials"

func (r *trialRepository) scanTrial(s scanner) (*models.Trial, error) {
	var t models.Trial
	var endedAt sql.NullTime
	var featuresEnabled, usageConsumed string

	err := s.Scan(
		&t.TrialID,
		&t.SubscriptionID,
		&t.StartedAt,
		&endedAt,
		&t.TrialDays,
		&featuresEnabled,
		&usageConsumed,
		&t.Status,
		&t.CreatedAt,
		&t.UpdatedAt,
	)
	if err != nil {
		if err == sql.ErrNoRows {
			return nil, errors.ErrNotFound
		}
		return nil, fmt.Errorf("scan trial: %w", err)
	}
	if endedAt.Valid {
		t.EndedAt = &endedAt.Time
	}
	t.FeaturesEnabled = []byte(featuresEnabled)
	t.UsageConsumed = []byte(usageConsumed)
	return &t, nil
}

func (r *trialRepository) buildTrialFilter(filter TrialFilter) (string, []interface{}) {
	var conds []string
	var args []interface{}
	idx := 1

	if filter.CompanyID != uuid.Nil {
		// We'll join with subscriptions to enforce company isolation
	}
	if len(filter.TrialIDs) > 0 {
		placeholders := make([]string, len(filter.TrialIDs))
		for i, id := range filter.TrialIDs {
			placeholders[i] = fmt.Sprintf("$%d", idx)
			args = append(args, id)
			idx++
		}
		conds = append(conds, fmt.Sprintf("tr.trial_id IN (%s)", strings.Join(placeholders, ",")))
	}
	if filter.SubscriptionID != nil {
		conds = append(conds, fmt.Sprintf("tr.subscription_id = $%d", idx))
		args = append(args, *filter.SubscriptionID)
		idx++
	}
	if filter.Status != nil {
		conds = append(conds, fmt.Sprintf("tr.status = $%d", idx))
		args = append(args, *filter.Status)
		idx++
	}
	if filter.StartedFrom != nil {
		conds = append(conds, fmt.Sprintf("tr.started_at >= $%d", idx))
		args = append(args, *filter.StartedFrom)
		idx++
	}
	if filter.StartedTo != nil {
		conds = append(conds, fmt.Sprintf("tr.started_at <= $%d", idx))
		args = append(args, *filter.StartedTo)
		idx++
	}
	if filter.EndedFrom != nil {
		conds = append(conds, fmt.Sprintf("tr.ended_at >= $%d", idx))
		args = append(args, *filter.EndedFrom)
		idx++
	}
	if filter.EndedTo != nil {
		conds = append(conds, fmt.Sprintf("tr.ended_at <= $%d", idx))
		args = append(args, *filter.EndedTo)
		idx++
	}

	if len(conds) == 0 {
		return "", args
	}
	return "WHERE " + strings.Join(conds, " AND "), args
}

var trialAllowedSort = map[string]bool{
	"trial_id":   true,
	"started_at": true,
	"ended_at":   true,
	"trial_days": true,
	"status":     true,
	"created_at": true,
	"updated_at": true,
}

// ---------------------------------------------------------------------
// CRUD
// ---------------------------------------------------------------------

func (r *trialRepository) Create(ctx context.Context, db DBTX, trial *models.Trial) error {
	query := `
		INSERT INTO subscription.trials (
			trial_id, subscription_id, started_at, ended_at, trial_days,
			features_enabled, usage_consumed, status, created_at, updated_at
		) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, NOW(), NOW())
		RETURNING created_at, updated_at
	`
	err := db.QueryRowContext(ctx, query,
		trial.TrialID,
		trial.SubscriptionID,
		trial.StartedAt,
		trial.EndedAt,
		trial.TrialDays,
		trial.FeaturesEnabled,
		trial.UsageConsumed,
		trial.Status,
	).Scan(&trial.CreatedAt, &trial.UpdatedAt)
	if err != nil {
		return fmt.Errorf("create trial: %w", err)
	}
	return nil
}

func (r *trialRepository) Update(ctx context.Context, db DBTX, trial *models.Trial) error {
	query := `
		UPDATE subscription.trials SET
			subscription_id = $2,
			started_at = $3,
			ended_at = $4,
			trial_days = $5,
			features_enabled = $6,
			usage_consumed = $7,
			status = $8,
			updated_at = NOW()
		WHERE trial_id = $1
		RETURNING updated_at
	`
	err := db.QueryRowContext(ctx, query,
		trial.TrialID,
		trial.SubscriptionID,
		trial.StartedAt,
		trial.EndedAt,
		trial.TrialDays,
		trial.FeaturesEnabled,
		trial.UsageConsumed,
		trial.Status,
	).Scan(&trial.UpdatedAt)
	if err != nil {
		if err == sql.ErrNoRows {
			return errors.ErrNotFound
		}
		return fmt.Errorf("update trial: %w", err)
	}
	return nil
}

func (r *trialRepository) Delete(ctx context.Context, db DBTX, companyID, trialID uuid.UUID) error {
	query := `
		DELETE FROM subscription.trials tr
		USING subscription.subscriptions s
		WHERE tr.subscription_id = s.subscription_id
		AND s.company_id = $1
		AND tr.trial_id = $2
	`
	result, err := db.ExecContext(ctx, query, companyID, trialID)
	if err != nil {
		return fmt.Errorf("delete trial: %w", err)
	}
	rows, _ := result.RowsAffected()
	if rows == 0 {
		return errors.ErrNotFound
	}
	return nil
}

// ---------------------------------------------------------------------
// Single Fetch
// ---------------------------------------------------------------------

func (r *trialRepository) GetByID(ctx context.Context, db DBTX, companyID, trialID uuid.UUID) (*models.Trial, error) {
	query := `
		SELECT tr.trial_id, tr.subscription_id, tr.started_at, tr.ended_at,
			tr.trial_days, tr.features_enabled, tr.usage_consumed, tr.status,
			tr.created_at, tr.updated_at
		FROM subscription.trials tr
		JOIN subscription.subscriptions s ON tr.subscription_id = s.subscription_id
		WHERE tr.trial_id = $1 AND s.company_id = $2
	`
	row := db.QueryRowContext(ctx, query, trialID, companyID)
	return r.scanTrial(row)
}

func (r *trialRepository) GetBySubscription(ctx context.Context, db DBTX, companyID, subscriptionID uuid.UUID) (*models.Trial, error) {
	query := `
		SELECT tr.trial_id, tr.subscription_id, tr.started_at, tr.ended_at,
			tr.trial_days, tr.features_enabled, tr.usage_consumed, tr.status,
			tr.created_at, tr.updated_at
		FROM subscription.trials tr
		JOIN subscription.subscriptions s ON tr.subscription_id = s.subscription_id
		WHERE s.company_id = $1 AND tr.subscription_id = $2
		ORDER BY tr.created_at DESC
		LIMIT 1
	`
	row := db.QueryRowContext(ctx, query, companyID, subscriptionID)
	return r.scanTrial(row)
}

func (r *trialRepository) GetActiveBySubscription(ctx context.Context, db DBTX, companyID, subscriptionID uuid.UUID) (*models.Trial, error) {
	query := `
		SELECT tr.trial_id, tr.subscription_id, tr.started_at, tr.ended_at,
			tr.trial_days, tr.features_enabled, tr.usage_consumed, tr.status,
			tr.created_at, tr.updated_at
		FROM subscription.trials tr
		JOIN subscription.subscriptions s ON tr.subscription_id = s.subscription_id
		WHERE s.company_id = $1 AND tr.subscription_id = $2 AND tr.status = 'active'
		ORDER BY tr.created_at DESC
		LIMIT 1
	`
	row := db.QueryRowContext(ctx, query, companyID, subscriptionID)
	return r.scanTrial(row)
}

// ---------------------------------------------------------------------
// Listing
// ---------------------------------------------------------------------

func (r *trialRepository) List(ctx context.Context, db DBTX, filter TrialFilter, p Pagination, s Sort) ([]*models.Trial, int64, error) {
	from := "subscription.trials tr"
	joins := []string{"JOIN subscription.subscriptions s ON tr.subscription_id = s.subscription_id"}
	whereCond := "s.company_id = $1"
	args := []interface{}{filter.CompanyID}
	idx := 2

	if len(filter.TrialIDs) > 0 {
		placeholders := make([]string, len(filter.TrialIDs))
		for i, id := range filter.TrialIDs {
			placeholders[i] = fmt.Sprintf("$%d", idx)
			args = append(args, id)
			idx++
		}
		whereCond += fmt.Sprintf(" AND tr.trial_id IN (%s)", strings.Join(placeholders, ","))
	}
	if filter.SubscriptionID != nil {
		whereCond += fmt.Sprintf(" AND tr.subscription_id = $%d", idx)
		args = append(args, *filter.SubscriptionID)
		idx++
	}
	if filter.Status != nil {
		whereCond += fmt.Sprintf(" AND tr.status = $%d", idx)
		args = append(args, *filter.Status)
		idx++
	}
	if filter.StartedFrom != nil {
		whereCond += fmt.Sprintf(" AND tr.started_at >= $%d", idx)
		args = append(args, *filter.StartedFrom)
		idx++
	}
	if filter.StartedTo != nil {
		whereCond += fmt.Sprintf(" AND tr.started_at <= $%d", idx)
		args = append(args, *filter.StartedTo)
		idx++
	}
	if filter.EndedFrom != nil {
		whereCond += fmt.Sprintf(" AND tr.ended_at >= $%d", idx)
		args = append(args, *filter.EndedFrom)
		idx++
	}
	if filter.EndedTo != nil {
		whereCond += fmt.Sprintf(" AND tr.ended_at <= $%d", idx)
		args = append(args, *filter.EndedTo)
		idx++
	}

	fullFrom := from + " " + strings.Join(joins, " ")
	whereClause := "WHERE " + whereCond

	orderBy, err := validateSort(s, trialAllowedSort)
	if err != nil {
		return nil, 0, err
	}
	if orderBy == "" {
		orderBy = "ORDER BY tr.created_at DESC"
	}

	limit, offset := validatePagination(p)

	// Count
	countQuery := fmt.Sprintf("SELECT COUNT(*) FROM %s %s", fullFrom, whereClause)
	var total int64
	if err := db.QueryRowContext(ctx, countQuery, args...).Scan(&total); err != nil {
		return nil, 0, fmt.Errorf("count trials: %w", err)
	}
	if total == 0 {
		return []*models.Trial{}, 0, nil
	}

	// Data
	query := fmt.Sprintf(`
		SELECT tr.trial_id, tr.subscription_id, tr.started_at, tr.ended_at,
			tr.trial_days, tr.features_enabled, tr.usage_consumed, tr.status,
			tr.created_at, tr.updated_at
		FROM %s
		%s
		%s
		LIMIT $%d OFFSET $%d
	`, fullFrom, whereClause, orderBy, idx, idx+1)
	args = append(args, limit, offset)

	rows, err := db.QueryContext(ctx, query, args...)
	if err != nil {
		return nil, 0, fmt.Errorf("list trials: %w", err)
	}
	defer rows.Close()

	var result []*models.Trial
	for rows.Next() {
		t, err := r.scanTrial(rows)
		if err != nil {
			return nil, 0, err
		}
		result = append(result, t)
	}
	return result, total, rows.Err()
}

func (r *trialRepository) ListBySubscription(ctx context.Context, db DBTX, companyID, subscriptionID uuid.UUID) ([]*models.Trial, error) {
	filter := TrialFilter{
		CompanyID:      companyID,
		SubscriptionID: &subscriptionID,
	}
	trials, _, err := r.List(ctx, db, filter, Pagination{Limit: 1000}, Sort{Field: "created_at", Direction: "DESC"})
	return trials, err
}

func (r *trialRepository) ListActive(ctx context.Context, db DBTX, companyID uuid.UUID) ([]*models.Trial, error) {
	status := "active"
	filter := TrialFilter{
		CompanyID: companyID,
		Status:    &status,
	}
	trials, _, err := r.List(ctx, db, filter, Pagination{Limit: 1000}, Sort{Field: "started_at", Direction: "ASC"})
	return trials, err
}

func (r *trialRepository) ListExpired(ctx context.Context, db DBTX, companyID uuid.UUID) ([]*models.Trial, error) {
	status := "expired"
	filter := TrialFilter{
		CompanyID: companyID,
		Status:    &status,
	}
	trials, _, err := r.List(ctx, db, filter, Pagination{Limit: 1000}, Sort{Field: "ended_at", Direction: "DESC"})
	return trials, err
}

func (r *trialRepository) ListExpiringSoon(ctx context.Context, db DBTX, companyID uuid.UUID, before time.Time) ([]*models.Trial, error) {
	status := "active"
	filter := TrialFilter{
		CompanyID: companyID,
		Status:    &status,
		EndedTo:   &before,
	}
	trials, _, err := r.List(ctx, db, filter, Pagination{Limit: 1000}, Sort{Field: "ended_at", Direction: "ASC"})
	return trials, err
}

// ---------------------------------------------------------------------
// Trial Operations
// ---------------------------------------------------------------------

func (r *trialRepository) UpdateStatus(ctx context.Context, db DBTX, companyID, trialID uuid.UUID, status string) error {
	query := `
		UPDATE subscription.trials tr
		SET status = $3, updated_at = NOW()
		FROM subscription.subscriptions s
		WHERE tr.subscription_id = s.subscription_id
		AND s.company_id = $1
		AND tr.trial_id = $2
	`
	result, err := db.ExecContext(ctx, query, companyID, trialID, status)
	if err != nil {
		return fmt.Errorf("update trial status: %w", err)
	}
	rows, _ := result.RowsAffected()
	if rows == 0 {
		return errors.ErrNotFound
	}
	return nil
}

func (r *trialRepository) Activate(ctx context.Context, db DBTX, companyID, trialID uuid.UUID) error {
	return r.UpdateStatus(ctx, db, companyID, trialID, "active")
}

func (r *trialRepository) Expire(ctx context.Context, db DBTX, companyID, trialID uuid.UUID) error {
	if err := r.UpdateStatus(ctx, db, companyID, trialID, "expired"); err != nil {
		return err
	}
	// Also set ended_at to NOW()
	query := `
		UPDATE subscription.trials tr
		SET ended_at = NOW(), updated_at = NOW()
		FROM subscription.subscriptions s
		WHERE tr.subscription_id = s.subscription_id
		AND s.company_id = $1
		AND tr.trial_id = $2
	`
	_, err := db.ExecContext(ctx, query, companyID, trialID)
	return err
}

func (r *trialRepository) Convert(ctx context.Context, db DBTX, companyID, trialID uuid.UUID) error {
	return r.UpdateStatus(ctx, db, companyID, trialID, "converted")
}

func (r *trialRepository) ExtendTrial(ctx context.Context, db DBTX, companyID, trialID uuid.UUID, extraDays int) error {
	query := `
		UPDATE subscription.trials tr
		SET trial_days = trial_days + $3,
			ended_at = ended_at + INTERVAL '$3 days',
			updated_at = NOW()
		FROM subscription.subscriptions s
		WHERE tr.subscription_id = s.subscription_id
		AND s.company_id = $1
		AND tr.trial_id = $2
	`
	result, err := db.ExecContext(ctx, query, companyID, trialID, extraDays)
	if err != nil {
		return fmt.Errorf("extend trial: %w", err)
	}
	rows, _ := result.RowsAffected()
	if rows == 0 {
		return errors.ErrNotFound
	}
	return nil
}

func (r *trialRepository) SetEndDate(ctx context.Context, db DBTX, companyID, trialID uuid.UUID, endedAt time.Time) error {
	query := `
		UPDATE subscription.trials tr
		SET ended_at = $3, updated_at = NOW()
		FROM subscription.subscriptions s
		WHERE tr.subscription_id = s.subscription_id
		AND s.company_id = $1
		AND tr.trial_id = $2
	`
	result, err := db.ExecContext(ctx, query, companyID, trialID, endedAt)
	if err != nil {
		return fmt.Errorf("set trial end date: %w", err)
	}
	rows, _ := result.RowsAffected()
	if rows == 0 {
		return errors.ErrNotFound
	}
	return nil
}

// ---------------------------------------------------------------------
// Validation
// ---------------------------------------------------------------------

func (r *trialRepository) Exists(ctx context.Context, db DBTX, companyID, trialID uuid.UUID) (bool, error) {
	var exists bool
	query := `
		SELECT EXISTS(
			SELECT 1 FROM subscription.trials tr
			JOIN subscription.subscriptions s ON tr.subscription_id = s.subscription_id
			WHERE tr.trial_id = $1 AND s.company_id = $2
		)
	`
	err := db.QueryRowContext(ctx, query, trialID, companyID).Scan(&exists)
	return exists, err
}

func (r *trialRepository) ExistsActiveBySubscription(ctx context.Context, db DBTX, companyID, subscriptionID uuid.UUID) (bool, error) {
	var exists bool
	query := `
		SELECT EXISTS(
			SELECT 1 FROM subscription.trials tr
			JOIN subscription.subscriptions s ON tr.subscription_id = s.subscription_id
			WHERE s.company_id = $1 AND tr.subscription_id = $2 AND tr.status = 'active'
		)
	`
	err := db.QueryRowContext(ctx, query, companyID, subscriptionID).Scan(&exists)
	return exists, err
}

func (r *trialRepository) Search(ctx context.Context, db DBTX, companyID uuid.UUID, query string, limit, offset int) ([]*models.Trial, int64, error) {
	pattern := "%" + query + "%"
	where := `
		JOIN subscription.subscriptions s ON tr.subscription_id = s.subscription_id
		WHERE s.company_id = $1
		AND (tr.status ILIKE $2 OR tr.trial_days::text ILIKE $2)
	`
	args := []interface{}{companyID, pattern}

	countQuery := fmt.Sprintf("SELECT COUNT(*) FROM subscription.trials tr %s", where)
	var total int64
	if err := db.QueryRowContext(ctx, countQuery, args...).Scan(&total); err != nil {
		return nil, 0, fmt.Errorf("search trials count: %w", err)
	}
	if total == 0 {
		return []*models.Trial{}, 0, nil
	}

	baseQuery := `
		SELECT tr.trial_id, tr.subscription_id, tr.started_at, tr.ended_at,
			tr.trial_days, tr.features_enabled, tr.usage_consumed, tr.status,
			tr.created_at, tr.updated_at
		FROM subscription.trials tr
	`
	querySQL := fmt.Sprintf(`%s %s ORDER BY tr.created_at DESC LIMIT $%d OFFSET $%d`, baseQuery, where, len(args)+1, len(args)+2)
	args = append(args, limit, offset)

	rows, err := db.QueryContext(ctx, querySQL, args...)
	if err != nil {
		return nil, 0, fmt.Errorf("search trials: %w", err)
	}
	defer rows.Close()

	var result []*models.Trial
	for rows.Next() {
		t, err := r.scanTrial(rows)
		if err != nil {
			return nil, 0, err
		}
		result = append(result, t)
	}
	return result, total, rows.Err()
}

// ---------------------------------------------------------------------
// Locking
// ---------------------------------------------------------------------

func (r *trialRepository) GetByIDForUpdate(ctx context.Context, db DBTX, companyID, trialID uuid.UUID) (*models.Trial, error) {
	query := `
		SELECT tr.trial_id, tr.subscription_id, tr.started_at, tr.ended_at,
			tr.trial_days, tr.features_enabled, tr.usage_consumed, tr.status,
			tr.created_at, tr.updated_at
		FROM subscription.trials tr
		JOIN subscription.subscriptions s ON tr.subscription_id = s.subscription_id
		WHERE tr.trial_id = $1 AND s.company_id = $2
		FOR UPDATE
	`
	row := db.QueryRowContext(ctx, query, trialID, companyID)
	return r.scanTrial(row)
}

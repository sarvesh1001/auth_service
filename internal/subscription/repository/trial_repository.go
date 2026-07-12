// FILE: repository/trial_repository.go

package repository

import (
	"context"
	"database/sql"
	"fmt"
	"strings"
	"time"

	"github.com/google/uuid"

	"auth-service/internal/subscription/models"
	"auth-service/internal/subscription/models/enums"

	"go.uber.org/zap"
)

// -------------------------------------------------------------------------
// TrialRepository Interface
// -------------------------------------------------------------------------

type TrialRepository interface {
	// -------------------------------------------------------------------------
	// CRUD
	// -------------------------------------------------------------------------

	Create(ctx context.Context, db DBTX, trial *models.Trial) error
	GetByID(ctx context.Context, db DBTX, trialID uuid.UUID) (*models.Trial, error)
	GetBySubscription(ctx context.Context, db DBTX, subscriptionID uuid.UUID) (*models.Trial, error)
	Update(ctx context.Context, db DBTX, trial *models.Trial) error
	Delete(ctx context.Context, db DBTX, trialID uuid.UUID) error

	// -------------------------------------------------------------------------
	// Lifecycle
	// -------------------------------------------------------------------------

	Start(ctx context.Context, db DBTX, trialID uuid.UUID, startedAt time.Time) error
	Expire(ctx context.Context, db DBTX, trialID uuid.UUID, endedAt time.Time) error
	Convert(ctx context.Context, db DBTX, trialID uuid.UUID, endedAt time.Time) error
	Cancel(ctx context.Context, db DBTX, trialID uuid.UUID, endedAt time.Time) error
	UpdateStatus(ctx context.Context, db DBTX, trialID uuid.UUID, status enums.TrialStatus) error

	// -------------------------------------------------------------------------
	// Usage / Features
	// -------------------------------------------------------------------------

	UpdateUsage(ctx context.Context, db DBTX, trialID uuid.UUID, usage models.JSONB) error
	UpdateFeatures(ctx context.Context, db DBTX, trialID uuid.UUID, features models.JSONB) error

	// -------------------------------------------------------------------------
	// Validation
	// -------------------------------------------------------------------------

	Exists(ctx context.Context, db DBTX, trialID uuid.UUID) (bool, error)
	ExistsBySubscription(ctx context.Context, db DBTX, subscriptionID uuid.UUID) (bool, error)
	IsActive(ctx context.Context, db DBTX, trialID uuid.UUID) (bool, error)

	// -------------------------------------------------------------------------
	// Querying
	// -------------------------------------------------------------------------

	List(ctx context.Context, db DBTX, filter TrialFilter, p Pagination, s Sort) ([]*models.Trial, int64, error)
	Search(ctx context.Context, db DBTX, query string, limit, offset int) ([]*models.Trial, int64, error)
	GetByStatus(ctx context.Context, db DBTX, status enums.TrialStatus) ([]*models.Trial, error)
	GetActive(ctx context.Context, db DBTX) ([]*models.Trial, error)
	GetExpiringBetween(ctx context.Context, db DBTX, from, to time.Time) ([]*models.Trial, error)
	GetExpiredBefore(ctx context.Context, db DBTX, before time.Time) ([]*models.Trial, error)

	// -------------------------------------------------------------------------
	// Recommended: Cron/Scheduler Helper
	// -------------------------------------------------------------------------

	GetExpiringWithin(ctx context.Context, db DBTX, duration time.Duration) ([]*models.Trial, error)

	// -------------------------------------------------------------------------
	// Locking
	// -------------------------------------------------------------------------

	GetByIDForUpdate(ctx context.Context, db DBTX, trialID uuid.UUID) (*models.Trial, error)
	GetBySubscriptionForUpdate(ctx context.Context, db DBTX, subscriptionID uuid.UUID) (*models.Trial, error)
}

// -------------------------------------------------------------------------
// Filter, Pagination, Sort
// -------------------------------------------------------------------------

type TrialFilter struct {
	CompanyID      *uuid.UUID // <-- add this
	TrialIDs       []uuid.UUID
	SubscriptionID *uuid.UUID
	Status         *enums.TrialStatus
	TrialDaysMin   *int
	TrialDaysMax   *int
	StartedFrom    *time.Time
	StartedTo      *time.Time
	EndedFrom      *time.Time
	EndedTo        *time.Time
	CreatedFrom    *time.Time
	CreatedTo      *time.Time
	UpdatedFrom    *time.Time
	UpdatedTo      *time.Time
}

// Pagination and Sort are assumed to be defined elsewhere.
// If not, you can uncomment the definitions below.
//
// type Pagination struct {
// 	Limit  int
// 	Offset int
// }
//
// type Sort struct {
// 	Field     string
// 	Direction string // ASC or DESC
// }

// -------------------------------------------------------------------------
// Implementation
// -------------------------------------------------------------------------

type trialRepository struct {
	logger *zap.Logger
}

// NewTrialRepository creates a new TrialRepository.
func NewTrialRepository(logger *zap.Logger) TrialRepository {
	return &trialRepository{
		logger: logger.Named("subscription_trial_repo"),
	}
}

// -------------------------------------------------------------------------
// CRUD
// -------------------------------------------------------------------------

func (r *trialRepository) Create(ctx context.Context, db DBTX, trial *models.Trial) error {
	query := `
		INSERT INTO subscription.trials (
			trial_id, subscription_id, started_at, ended_at, trial_days,
			features_enabled, usage_consumed, status, created_at, updated_at
		) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10)
	`
	_, err := db.ExecContext(ctx, query,
		trial.TrialID,
		trial.SubscriptionID,
		trial.StartedAt,
		trial.EndedAt,
		trial.TrialDays,
		trial.FeaturesEnabled,
		trial.UsageConsumed,
		trial.Status,
		trial.CreatedAt,
		trial.UpdatedAt,
	)
	if err != nil {
		r.logger.Error("failed to create trial", zap.Error(err))
		return fmt.Errorf("create trial: %w", err)
	}
	return nil
}

func (r *trialRepository) GetByID(ctx context.Context, db DBTX, trialID uuid.UUID) (*models.Trial, error) {
	query := r.buildSelectQuery() + ` WHERE trial_id = $1`
	var trial models.Trial
	err := r.scanTrial(ctx, db, query, &trial, trialID)
	if err != nil {
		if err == sql.ErrNoRows {
			return nil, nil
		}
		return nil, err
	}
	return &trial, nil
}

func (r *trialRepository) GetBySubscription(ctx context.Context, db DBTX, subscriptionID uuid.UUID) (*models.Trial, error) {
	query := r.buildSelectQuery() + ` WHERE subscription_id = $1 ORDER BY created_at DESC LIMIT 1`
	var trial models.Trial
	err := r.scanTrial(ctx, db, query, &trial, subscriptionID)
	if err != nil {
		if err == sql.ErrNoRows {
			return nil, nil
		}
		return nil, err
	}
	return &trial, nil
}

func (r *trialRepository) Update(ctx context.Context, db DBTX, trial *models.Trial) error {
	query := `
		UPDATE subscription.trials
		SET subscription_id = $1,
		    started_at = $2,
		    ended_at = $3,
		    trial_days = $4,
		    features_enabled = $5,
		    usage_consumed = $6,
		    status = $7,
		    updated_at = NOW()
		WHERE trial_id = $8
	`
	_, err := db.ExecContext(ctx, query,
		trial.SubscriptionID,
		trial.StartedAt,
		trial.EndedAt,
		trial.TrialDays,
		trial.FeaturesEnabled,
		trial.UsageConsumed,
		trial.Status,
		trial.TrialID,
	)
	if err != nil {
		r.logger.Error("failed to update trial", zap.Error(err))
		return fmt.Errorf("update trial: %w", err)
	}
	return nil
}

func (r *trialRepository) Delete(ctx context.Context, db DBTX, trialID uuid.UUID) error {
	query := `DELETE FROM subscription.trials WHERE trial_id = $1`
	result, err := db.ExecContext(ctx, query, trialID)
	if err != nil {
		r.logger.Error("failed to delete trial", zap.Error(err))
		return fmt.Errorf("delete trial: %w", err)
	}
	rows, _ := result.RowsAffected()
	if rows == 0 {
		return sql.ErrNoRows
	}
	return nil
}

// -------------------------------------------------------------------------
// Lifecycle
// -------------------------------------------------------------------------

func (r *trialRepository) Start(ctx context.Context, db DBTX, trialID uuid.UUID, startedAt time.Time) error {
	return r.updateStatusAndTime(ctx, db, trialID, enums.TrialActive, &startedAt, nil)
}

func (r *trialRepository) Expire(ctx context.Context, db DBTX, trialID uuid.UUID, endedAt time.Time) error {
	return r.updateStatusAndTime(ctx, db, trialID, enums.TrialExpired, nil, &endedAt)
}

func (r *trialRepository) Convert(ctx context.Context, db DBTX, trialID uuid.UUID, endedAt time.Time) error {
	return r.updateStatusAndTime(ctx, db, trialID, enums.TrialConverted, nil, &endedAt)
}

func (r *trialRepository) Cancel(ctx context.Context, db DBTX, trialID uuid.UUID, endedAt time.Time) error {
	return r.updateStatusAndTime(ctx, db, trialID, enums.TrialCancelled, nil, &endedAt)
}

func (r *trialRepository) UpdateStatus(ctx context.Context, db DBTX, trialID uuid.UUID, status enums.TrialStatus) error {
	return r.updateStatusAndTime(ctx, db, trialID, status, nil, nil)
}

// helper for status updates with optional start/end times
func (r *trialRepository) updateStatusAndTime(ctx context.Context, db DBTX, trialID uuid.UUID, status enums.TrialStatus, startedAt, endedAt *time.Time) error {
	query := `UPDATE subscription.trials SET status = $1, updated_at = NOW()`
	args := []interface{}{status}
	argPos := 2
	if startedAt != nil {
		query += fmt.Sprintf(", started_at = $%d", argPos)
		args = append(args, *startedAt)
		argPos++
	}
	if endedAt != nil {
		query += fmt.Sprintf(", ended_at = $%d", argPos)
		args = append(args, *endedAt)
	}
	query += fmt.Sprintf(" WHERE trial_id = $%d", argPos)
	args = append(args, trialID)

	_, err := db.ExecContext(ctx, query, args...)
	if err != nil {
		r.logger.Error("failed to update trial status/time", zap.Error(err))
		return fmt.Errorf("update trial status: %w", err)
	}
	return nil
}

// -------------------------------------------------------------------------
// Usage / Features
// -------------------------------------------------------------------------

func (r *trialRepository) UpdateUsage(ctx context.Context, db DBTX, trialID uuid.UUID, usage models.JSONB) error {
	query := `UPDATE subscription.trials SET usage_consumed = $1, updated_at = NOW() WHERE trial_id = $2`
	_, err := db.ExecContext(ctx, query, usage, trialID)
	if err != nil {
		r.logger.Error("failed to update trial usage", zap.Error(err))
		return fmt.Errorf("update trial usage: %w", err)
	}
	return nil
}

func (r *trialRepository) UpdateFeatures(ctx context.Context, db DBTX, trialID uuid.UUID, features models.JSONB) error {
	query := `UPDATE subscription.trials SET features_enabled = $1, updated_at = NOW() WHERE trial_id = $2`
	_, err := db.ExecContext(ctx, query, features, trialID)
	if err != nil {
		r.logger.Error("failed to update trial features", zap.Error(err))
		return fmt.Errorf("update trial features: %w", err)
	}
	return nil
}

// -------------------------------------------------------------------------
// Validation
// -------------------------------------------------------------------------

func (r *trialRepository) Exists(ctx context.Context, db DBTX, trialID uuid.UUID) (bool, error) {
	query := `SELECT EXISTS(SELECT 1 FROM subscription.trials WHERE trial_id = $1)`
	var exists bool
	err := db.QueryRowContext(ctx, query, trialID).Scan(&exists)
	if err != nil {
		return false, fmt.Errorf("check exists: %w", err)
	}
	return exists, nil
}

func (r *trialRepository) ExistsBySubscription(ctx context.Context, db DBTX, subscriptionID uuid.UUID) (bool, error) {
	query := `SELECT EXISTS(SELECT 1 FROM subscription.trials WHERE subscription_id = $1)`
	var exists bool
	err := db.QueryRowContext(ctx, query, subscriptionID).Scan(&exists)
	if err != nil {
		return false, fmt.Errorf("check exists by subscription: %w", err)
	}
	return exists, nil
}

func (r *trialRepository) IsActive(ctx context.Context, db DBTX, trialID uuid.UUID) (bool, error) {
	query := `SELECT status = $1 FROM subscription.trials WHERE trial_id = $2`
	var active bool
	err := db.QueryRowContext(ctx, query, enums.TrialActive, trialID).Scan(&active)
	if err != nil {
		if err == sql.ErrNoRows {
			return false, nil
		}
		return false, fmt.Errorf("check active: %w", err)
	}
	return active, nil
}

// -------------------------------------------------------------------------
// Querying
// -------------------------------------------------------------------------

func (r *trialRepository) List(ctx context.Context, db DBTX, filter TrialFilter, p Pagination, s Sort) ([]*models.Trial, int64, error) {
	// Build WHERE conditions (without company) first
	where, args := r.buildFilterConditions(filter)
	whereClause := ""
	if len(where) > 0 {
		whereClause = "WHERE " + strings.Join(where, " AND ")
	}

	// Determine if we need to join with subscriptions
	joinClause := ""
	if filter.CompanyID != nil {
		joinClause = `JOIN subscription.subscriptions s ON t.subscription_id = s.subscription_id`
		// Add company condition to where
		companyCondition := fmt.Sprintf("s.company_id = $%d", len(args)+1)
		if whereClause == "" {
			whereClause = "WHERE " + companyCondition
		} else {
			whereClause += " AND " + companyCondition
		}
		args = append(args, *filter.CompanyID)
	}

	// Build the full select query (use table alias 't' for trials)
	selectQuery := `
        SELECT t.trial_id, t.subscription_id, t.started_at, t.ended_at, t.trial_days,
               t.features_enabled, t.usage_consumed, t.status, t.created_at, t.updated_at
        FROM subscription.trials t
    `

	// Count total
	countQuery := fmt.Sprintf(`SELECT COUNT(*) FROM subscription.trials t %s %s`, joinClause, whereClause)
	var total int64
	err := db.QueryRowContext(ctx, countQuery, args...).Scan(&total)
	if err != nil {
		return nil, 0, fmt.Errorf("count trials: %w", err)
	}
	if total == 0 {
		return []*models.Trial{}, 0, nil
	}

	// Sort
	sortClause := ""
	if s.Field != "" {
		direction := "ASC"
		if strings.ToUpper(s.Direction) == "DESC" {
			direction = "DESC"
		}
		sortClause = fmt.Sprintf("ORDER BY %s %s", s.Field, direction)
	} else {
		sortClause = "ORDER BY t.created_at DESC"
	}

	// Final query with pagination
	query := fmt.Sprintf(`%s %s %s %s LIMIT $%d OFFSET $%d`,
		selectQuery, joinClause, whereClause, sortClause, len(args)+1, len(args)+2)
	limitArgs := append(args, p.Limit, p.Offset)

	rows, err := db.QueryContext(ctx, query, limitArgs...)
	if err != nil {
		return nil, 0, fmt.Errorf("list trials: %w", err)
	}
	defer rows.Close()

	var trials []*models.Trial
	for rows.Next() {
		var t models.Trial
		if err := r.scanTrialRows(rows, &t); err != nil {
			return nil, 0, fmt.Errorf("scan trial: %w", err)
		}
		trials = append(trials, &t)
	}
	if err = rows.Err(); err != nil {
		return nil, 0, fmt.Errorf("rows iteration: %w", err)
	}
	return trials, total, nil
}
func (r *trialRepository) Search(ctx context.Context, db DBTX, query string, limit, offset int) ([]*models.Trial, int64, error) {
	// Search by subscription_id (converted to text) or trial_id? Simpler: search by subscription_id::text or trial_id::text.
	// We'll search by trial_id and subscription_id using ILIKE.
	searchPattern := "%" + query + "%"
	where := "trial_id::text ILIKE $1 OR subscription_id::text ILIKE $1"
	countQuery := fmt.Sprintf(`SELECT COUNT(*) FROM subscription.trials WHERE %s`, where)
	var total int64
	err := db.QueryRowContext(ctx, countQuery, searchPattern).Scan(&total)
	if err != nil {
		return nil, 0, fmt.Errorf("count search: %w", err)
	}
	if total == 0 {
		return []*models.Trial{}, 0, nil
	}

	dataQuery := fmt.Sprintf(`
		%s WHERE %s
		ORDER BY created_at DESC
		LIMIT $%d OFFSET $%d
	`, r.buildSelectQuery(), where, 2, 3)

	rows, err := db.QueryContext(ctx, dataQuery, searchPattern, limit, offset)
	if err != nil {
		return nil, 0, fmt.Errorf("search trials: %w", err)
	}
	defer rows.Close()

	var trials []*models.Trial
	for rows.Next() {
		var t models.Trial
		if err := r.scanTrialRows(rows, &t); err != nil {
			return nil, 0, fmt.Errorf("scan trial: %w", err)
		}
		trials = append(trials, &t)
	}
	return trials, total, rows.Err()
}

func (r *trialRepository) GetByStatus(ctx context.Context, db DBTX, status enums.TrialStatus) ([]*models.Trial, error) {
	query := r.buildSelectQuery() + ` WHERE status = $1 ORDER BY created_at DESC`
	rows, err := db.QueryContext(ctx, query, status)
	if err != nil {
		return nil, fmt.Errorf("get by status: %w", err)
	}
	defer rows.Close()
	return r.collectTrials(rows)
}

func (r *trialRepository) GetActive(ctx context.Context, db DBTX) ([]*models.Trial, error) {
	query := r.buildSelectQuery() + ` WHERE status = $1 ORDER BY created_at DESC`
	rows, err := db.QueryContext(ctx, query, enums.TrialActive)
	if err != nil {
		return nil, fmt.Errorf("get active trials: %w", err)
	}
	defer rows.Close()
	return r.collectTrials(rows)
}

func (r *trialRepository) GetExpiringBetween(ctx context.Context, db DBTX, from, to time.Time) ([]*models.Trial, error) {
	// Assuming we want trials whose ended_at (or computed end) falls between from and to.
	// Since trials have ended_at set only when they finish, we need to compute the expected end based on started_at + trial_days.
	// For active trials, we want those that will end soon.
	query := r.buildSelectQuery() + `
		WHERE status = $1
		  AND started_at + (trial_days * INTERVAL '1 day') BETWEEN $2 AND $3
		ORDER BY started_at + (trial_days * INTERVAL '1 day')
	`
	rows, err := db.QueryContext(ctx, query, enums.TrialActive, from, to)
	if err != nil {
		return nil, fmt.Errorf("get expiring between: %w", err)
	}
	defer rows.Close()
	return r.collectTrials(rows)
}

func (r *trialRepository) GetExpiredBefore(ctx context.Context, db DBTX, before time.Time) ([]*models.Trial, error) {
	// Find trials that should have expired but are still active (i.e., status = 'active' and started_at + trial_days < before)
	query := r.buildSelectQuery() + `
		WHERE status = $1
		  AND started_at + (trial_days * INTERVAL '1 day') < $2
		ORDER BY started_at + (trial_days * INTERVAL '1 day')
	`
	rows, err := db.QueryContext(ctx, query, enums.TrialActive, before)
	if err != nil {
		return nil, fmt.Errorf("get expired before: %w", err)
	}
	defer rows.Close()
	return r.collectTrials(rows)
}

// -------------------------------------------------------------------------
// Recommended: GetExpiringWithin
// -------------------------------------------------------------------------

func (r *trialRepository) GetExpiringWithin(ctx context.Context, db DBTX, duration time.Duration) ([]*models.Trial, error) {
	now := time.Now()
	from := now
	to := now.Add(duration)
	return r.GetExpiringBetween(ctx, db, from, to)
}

// -------------------------------------------------------------------------
// Locking
// -------------------------------------------------------------------------

func (r *trialRepository) GetByIDForUpdate(ctx context.Context, db DBTX, trialID uuid.UUID) (*models.Trial, error) {
	query := r.buildSelectQuery() + ` WHERE trial_id = $1 FOR UPDATE`
	var trial models.Trial
	err := r.scanTrial(ctx, db, query, &trial, trialID)
	if err != nil {
		if err == sql.ErrNoRows {
			return nil, nil
		}
		return nil, err
	}
	return &trial, nil
}

func (r *trialRepository) GetBySubscriptionForUpdate(ctx context.Context, db DBTX, subscriptionID uuid.UUID) (*models.Trial, error) {
	query := r.buildSelectQuery() + ` WHERE subscription_id = $1 FOR UPDATE`
	var trial models.Trial
	err := r.scanTrial(ctx, db, query, &trial, subscriptionID)
	if err != nil {
		if err == sql.ErrNoRows {
			return nil, nil
		}
		return nil, err
	}
	return &trial, nil
}

// -------------------------------------------------------------------------
// Helper functions
// -------------------------------------------------------------------------

// buildSelectQuery returns the SELECT columns for the trial table.
func (r *trialRepository) buildSelectQuery() string {
	return `
		SELECT trial_id, subscription_id, started_at, ended_at, trial_days,
		       features_enabled, usage_consumed, status, created_at, updated_at
		FROM subscription.trials
	`
}

// scanTrial scans a single row into a models.Trial.
func (r *trialRepository) scanTrial(ctx context.Context, db DBTX, query string, trial *models.Trial, args ...interface{}) error {
	return db.QueryRowContext(ctx, query, args...).Scan(
		&trial.TrialID,
		&trial.SubscriptionID,
		&trial.StartedAt,
		&trial.EndedAt,
		&trial.TrialDays,
		&trial.FeaturesEnabled,
		&trial.UsageConsumed,
		&trial.Status,
		&trial.CreatedAt,
		&trial.UpdatedAt,
	)
}

// scanTrialRows scans the current row into a models.Trial.
func (r *trialRepository) scanTrialRows(rows *sql.Rows, trial *models.Trial) error {
	return rows.Scan(
		&trial.TrialID,
		&trial.SubscriptionID,
		&trial.StartedAt,
		&trial.EndedAt,
		&trial.TrialDays,
		&trial.FeaturesEnabled,
		&trial.UsageConsumed,
		&trial.Status,
		&trial.CreatedAt,
		&trial.UpdatedAt,
	)
}

// collectTrials reads all rows into a slice.
func (r *trialRepository) collectTrials(rows *sql.Rows) ([]*models.Trial, error) {
	var trials []*models.Trial
	for rows.Next() {
		var t models.Trial
		if err := r.scanTrialRows(rows, &t); err != nil {
			return nil, fmt.Errorf("scan trial: %w", err)
		}
		trials = append(trials, &t)
	}
	return trials, rows.Err()
}

// buildFilterConditions builds the WHERE clause and arguments from the filter.
func (r *trialRepository) buildFilterConditions(filter TrialFilter) ([]string, []interface{}) {
	var conditions []string
	var args []interface{}
	argPos := 1

	if len(filter.TrialIDs) > 0 {
		placeholders := make([]string, len(filter.TrialIDs))
		for i, id := range filter.TrialIDs {
			placeholders[i] = fmt.Sprintf("$%d", argPos+i)
			args = append(args, id)
		}
		conditions = append(conditions, fmt.Sprintf("trial_id IN (%s)", strings.Join(placeholders, ",")))
		argPos += len(filter.TrialIDs)
	}

	if filter.SubscriptionID != nil {
		conditions = append(conditions, fmt.Sprintf("subscription_id = $%d", argPos))
		args = append(args, *filter.SubscriptionID)
		argPos++
	}

	if filter.Status != nil {
		conditions = append(conditions, fmt.Sprintf("status = $%d", argPos))
		args = append(args, *filter.Status)
		argPos++
	}

	if filter.TrialDaysMin != nil {
		conditions = append(conditions, fmt.Sprintf("trial_days >= $%d", argPos))
		args = append(args, *filter.TrialDaysMin)
		argPos++
	}
	if filter.TrialDaysMax != nil {
		conditions = append(conditions, fmt.Sprintf("trial_days <= $%d", argPos))
		args = append(args, *filter.TrialDaysMax)
		argPos++
	}

	addDateRange(&conditions, &args, &argPos, "started_at", filter.StartedFrom, filter.StartedTo)
	addDateRange(&conditions, &args, &argPos, "ended_at", filter.EndedFrom, filter.EndedTo)
	addDateRange(&conditions, &args, &argPos, "created_at", filter.CreatedFrom, filter.CreatedTo)
	addDateRange(&conditions, &args, &argPos, "updated_at", filter.UpdatedFrom, filter.UpdatedTo)

	return conditions, args
}

// FILE: repository/usage_repository.go

package repository

import (
	"context"
	"database/sql"
	"fmt"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/shopspring/decimal"

	"auth-service/internal/subscription/models"

	"go.uber.org/zap"
)

// -------------------------------------------------------------------------
// UsageRepository Interface
// -------------------------------------------------------------------------

type UsageRepository interface {
	// -------------------------------------------------------------------------
	// CRUD
	// -------------------------------------------------------------------------

	Create(ctx context.Context, db DBTX, usage *models.Usage) error
	BulkCreate(ctx context.Context, db DBTX, usages []*models.Usage) error
	GetByID(ctx context.Context, db DBTX, usageID uuid.UUID) (*models.Usage, error)
	Update(ctx context.Context, db DBTX, usage *models.Usage) error
	Delete(ctx context.Context, db DBTX, usageID uuid.UUID) error

	// -------------------------------------------------------------------------
	// Attendance Links
	// -------------------------------------------------------------------------

	AddAttendanceLink(ctx context.Context, db DBTX, link *models.UsageAttendanceLink) error
	DeleteAttendanceLink(ctx context.Context, db DBTX, linkID uuid.UUID) error
	GetAttendanceLink(ctx context.Context, db DBTX, usageID uuid.UUID) (*models.UsageAttendanceLink, error)
	GetUsageByAttendanceEvent(ctx context.Context, db DBTX, attendanceEventID uuid.UUID) (*models.Usage, error)

	// -------------------------------------------------------------------------
	// Validation
	// -------------------------------------------------------------------------

	Exists(ctx context.Context, db DBTX, usageID uuid.UUID) (bool, error)
	ExistsAttendanceLink(ctx context.Context, db DBTX, attendanceEventID uuid.UUID) (bool, error)

	// -------------------------------------------------------------------------
	// Aggregation
	// -------------------------------------------------------------------------

	GetTotalUsage(ctx context.Context, db DBTX, subscriptionItemID uuid.UUID, featureKey string, periodStart, periodEnd time.Time) (decimal.Decimal, error)
	GetUsageRemaining(ctx context.Context, db DBTX, subscriptionItemID uuid.UUID, featureKey string, periodStart, periodEnd time.Time) (*models.UsageRemaining, error)
	GetCurrentPeriodUsage(ctx context.Context, db DBTX, subscriptionItemID uuid.UUID, featureKey string) (decimal.Decimal, error)

	// -------------------------------------------------------------------------
	// Querying
	// -------------------------------------------------------------------------

	List(ctx context.Context, db DBTX, filter UsageFilter, p Pagination, s Sort) ([]*models.Usage, int64, error)
	Search(ctx context.Context, db DBTX, subscriptionItemID uuid.UUID, query string, limit, offset int) ([]*models.Usage, int64, error)
	GetBySubscriptionItem(ctx context.Context, db DBTX, subscriptionItemID uuid.UUID) ([]*models.Usage, error)
	GetByFeature(ctx context.Context, db DBTX, featureKey string) ([]*models.Usage, error)
	GetBySource(ctx context.Context, db DBTX, sourceType string, sourceID uuid.UUID) ([]*models.Usage, error)
	GetBetween(ctx context.Context, db DBTX, subscriptionItemID uuid.UUID, from, to time.Time) ([]*models.Usage, error)

	// -------------------------------------------------------------------------
	// Analytics
	// -------------------------------------------------------------------------

	GetUsageSummary(ctx context.Context, db DBTX, subscriptionItemID uuid.UUID, from, to time.Time) (decimal.Decimal, error)
	GetFeatureUsageSummary(ctx context.Context, db DBTX, featureKey string, from, to time.Time) (decimal.Decimal, error)

	// -------------------------------------------------------------------------
	// Atomic Increment (high‑throughput UPSERT)
	// -------------------------------------------------------------------------

	IncrementUsage(
		ctx context.Context,
		db DBTX,
		subscriptionItemID uuid.UUID,
		featureKey string,
		quantity decimal.Decimal,
		periodStart, periodEnd time.Time,
		sourceType *string,
		sourceID *uuid.UUID,
		createdBy *uuid.UUID,
	) (*models.Usage, error)

	// -------------------------------------------------------------------------
	// Locking
	// -------------------------------------------------------------------------

	GetByIDForUpdate(ctx context.Context, db DBTX, usageID uuid.UUID) (*models.Usage, error)
}

// -------------------------------------------------------------------------
// Filter, Pagination, Sort
// -------------------------------------------------------------------------

type UsageFilter struct {
	UsageIDs           []uuid.UUID
	SubscriptionItemID *uuid.UUID
	FeatureKey         *string
	SourceType         *string
	SourceID           *uuid.UUID
	CreatedBy          *uuid.UUID
	QuantityMin        *decimal.Decimal
	QuantityMax        *decimal.Decimal
	PeriodStartFrom    *time.Time
	PeriodStartTo      *time.Time
	PeriodEndFrom      *time.Time
	PeriodEndTo        *time.Time
	RecordedFrom       *time.Time
	RecordedTo         *time.Time
}

// -------------------------------------------------------------------------
// Implementation
// -------------------------------------------------------------------------

type usageRepository struct {
	logger *zap.Logger
}

// NewUsageRepository creates a new UsageRepository.
func NewUsageRepository(logger *zap.Logger) UsageRepository {
	return &usageRepository{
		logger: logger.Named("subscription_usage_repo"),
	}
}

// -------------------------------------------------------------------------
// CRUD
// -------------------------------------------------------------------------

func (r *usageRepository) Create(ctx context.Context, db DBTX, usage *models.Usage) error {
	query := `
		INSERT INTO subscription.usages (
			usage_id, subscription_item_id, feature_key, quantity_used,
			period_start, period_end, recorded_at, source_type, source_id, created_by
		) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10)
	`
	_, err := db.ExecContext(ctx, query,
		usage.UsageID,
		usage.SubscriptionItemID,
		usage.FeatureKey,
		usage.QuantityUsed,
		usage.PeriodStart,
		usage.PeriodEnd,
		usage.RecordedAt,
		usage.SourceType,
		usage.SourceID,
		usage.CreatedBy,
	)
	if err != nil {
		r.logger.Error("failed to create usage", zap.Error(err))
		return fmt.Errorf("create usage: %w", err)
	}
	return nil
}

func (r *usageRepository) BulkCreate(ctx context.Context, db DBTX, usages []*models.Usage) error {
	if len(usages) == 0 {
		return nil
	}

	// Build bulk insert with placeholders: 10 columns per row
	valueStrings := make([]string, 0, len(usages))
	args := make([]interface{}, 0, len(usages)*10)
	for i, u := range usages {
		pos := i*10 + 1
		valueStrings = append(valueStrings, fmt.Sprintf(
			"($%d, $%d, $%d, $%d, $%d, $%d, $%d, $%d, $%d, $%d)",
			pos, pos+1, pos+2, pos+3, pos+4, pos+5, pos+6, pos+7, pos+8, pos+9,
		))
		args = append(args,
			u.UsageID,
			u.SubscriptionItemID,
			u.FeatureKey,
			u.QuantityUsed,
			u.PeriodStart,
			u.PeriodEnd,
			u.RecordedAt,
			u.SourceType,
			u.SourceID,
			u.CreatedBy,
		)
	}

	query := fmt.Sprintf(`
		INSERT INTO subscription.usages (
			usage_id, subscription_item_id, feature_key, quantity_used,
			period_start, period_end, recorded_at, source_type, source_id, created_by
		) VALUES %s
	`, strings.Join(valueStrings, ","))

	_, err := db.ExecContext(ctx, query, args...)
	if err != nil {
		r.logger.Error("failed to bulk create usages", zap.Int("count", len(usages)), zap.Error(err))
		return fmt.Errorf("bulk create usages: %w", err)
	}
	return nil
}

func (r *usageRepository) GetByID(ctx context.Context, db DBTX, usageID uuid.UUID) (*models.Usage, error) {
	query := r.buildSelectQuery() + ` WHERE usage_id = $1`
	var usage models.Usage
	err := db.QueryRowContext(ctx, query, usageID).Scan(
		&usage.UsageID,
		&usage.SubscriptionItemID,
		&usage.FeatureKey,
		&usage.QuantityUsed,
		&usage.PeriodStart,
		&usage.PeriodEnd,
		&usage.RecordedAt,
		&usage.SourceType,
		&usage.SourceID,
		&usage.CreatedBy,
	)
	if err != nil {
		if err == sql.ErrNoRows {
			return nil, nil
		}
		r.logger.Error("failed to get usage by ID", zap.Error(err))
		return nil, fmt.Errorf("get usage by ID: %w", err)
	}
	return &usage, nil
}

func (r *usageRepository) Update(ctx context.Context, db DBTX, usage *models.Usage) error {
	query := `
		UPDATE subscription.usages
		SET subscription_item_id = $1,
		    feature_key = $2,
		    quantity_used = $3,
		    period_start = $4,
		    period_end = $5,
		    source_type = $6,
		    source_id = $7,
		    created_by = $8
		WHERE usage_id = $9
	`
	_, err := db.ExecContext(ctx, query,
		usage.SubscriptionItemID,
		usage.FeatureKey,
		usage.QuantityUsed,
		usage.PeriodStart,
		usage.PeriodEnd,
		usage.SourceType,
		usage.SourceID,
		usage.CreatedBy,
		usage.UsageID,
	)
	if err != nil {
		r.logger.Error("failed to update usage", zap.Error(err))
		return fmt.Errorf("update usage: %w", err)
	}
	return nil
}

func (r *usageRepository) Delete(ctx context.Context, db DBTX, usageID uuid.UUID) error {
	query := `DELETE FROM subscription.usages WHERE usage_id = $1`
	result, err := db.ExecContext(ctx, query, usageID)
	if err != nil {
		r.logger.Error("failed to delete usage", zap.Error(err))
		return fmt.Errorf("delete usage: %w", err)
	}
	rows, _ := result.RowsAffected()
	if rows == 0 {
		return sql.ErrNoRows
	}
	return nil
}

// -------------------------------------------------------------------------
// Attendance Links
// -------------------------------------------------------------------------

func (r *usageRepository) AddAttendanceLink(ctx context.Context, db DBTX, link *models.UsageAttendanceLink) error {
	query := `
		INSERT INTO subscription.usage_attendance_link (
			link_id, usage_id, attendance_event_id, created_at
		) VALUES ($1, $2, $3, $4)
	`
	_, err := db.ExecContext(ctx, query,
		link.LinkID,
		link.UsageID,
		link.AttendanceEventID,
		link.CreatedAt,
	)
	if err != nil {
		r.logger.Error("failed to add attendance link", zap.Error(err))
		return fmt.Errorf("add attendance link: %w", err)
	}
	return nil
}

func (r *usageRepository) DeleteAttendanceLink(ctx context.Context, db DBTX, linkID uuid.UUID) error {
	query := `DELETE FROM subscription.usage_attendance_link WHERE link_id = $1`
	_, err := db.ExecContext(ctx, query, linkID)
	if err != nil {
		r.logger.Error("failed to delete attendance link", zap.Error(err))
		return fmt.Errorf("delete attendance link: %w", err)
	}
	return nil
}

func (r *usageRepository) GetAttendanceLink(ctx context.Context, db DBTX, usageID uuid.UUID) (*models.UsageAttendanceLink, error) {
	query := `
		SELECT link_id, usage_id, attendance_event_id, created_at
		FROM subscription.usage_attendance_link
		WHERE usage_id = $1
	`
	var link models.UsageAttendanceLink
	err := db.QueryRowContext(ctx, query, usageID).Scan(
		&link.LinkID,
		&link.UsageID,
		&link.AttendanceEventID,
		&link.CreatedAt,
	)
	if err != nil {
		if err == sql.ErrNoRows {
			return nil, nil
		}
		return nil, fmt.Errorf("get attendance link: %w", err)
	}
	return &link, nil
}

func (r *usageRepository) GetUsageByAttendanceEvent(ctx context.Context, db DBTX, attendanceEventID uuid.UUID) (*models.Usage, error) {
	query := `
		SELECT u.usage_id, u.subscription_item_id, u.feature_key, u.quantity_used,
		       u.period_start, u.period_end, u.recorded_at, u.source_type, u.source_id, u.created_by
		FROM subscription.usages u
		JOIN subscription.usage_attendance_link l ON u.usage_id = l.usage_id
		WHERE l.attendance_event_id = $1
	`
	var usage models.Usage
	err := db.QueryRowContext(ctx, query, attendanceEventID).Scan(
		&usage.UsageID,
		&usage.SubscriptionItemID,
		&usage.FeatureKey,
		&usage.QuantityUsed,
		&usage.PeriodStart,
		&usage.PeriodEnd,
		&usage.RecordedAt,
		&usage.SourceType,
		&usage.SourceID,
		&usage.CreatedBy,
	)
	if err != nil {
		if err == sql.ErrNoRows {
			return nil, nil
		}
		return nil, fmt.Errorf("get usage by attendance event: %w", err)
	}
	return &usage, nil
}

// -------------------------------------------------------------------------
// Validation
// -------------------------------------------------------------------------

func (r *usageRepository) Exists(ctx context.Context, db DBTX, usageID uuid.UUID) (bool, error) {
	query := `SELECT EXISTS(SELECT 1 FROM subscription.usages WHERE usage_id = $1)`
	var exists bool
	err := db.QueryRowContext(ctx, query, usageID).Scan(&exists)
	if err != nil {
		return false, fmt.Errorf("check existence: %w", err)
	}
	return exists, nil
}

func (r *usageRepository) ExistsAttendanceLink(ctx context.Context, db DBTX, attendanceEventID uuid.UUID) (bool, error) {
	query := `SELECT EXISTS(SELECT 1 FROM subscription.usage_attendance_link WHERE attendance_event_id = $1)`
	var exists bool
	err := db.QueryRowContext(ctx, query, attendanceEventID).Scan(&exists)
	if err != nil {
		return false, fmt.Errorf("check attendance link existence: %w", err)
	}
	return exists, nil
}

// -------------------------------------------------------------------------
// Aggregation
// -------------------------------------------------------------------------

func (r *usageRepository) GetTotalUsage(ctx context.Context, db DBTX, subscriptionItemID uuid.UUID, featureKey string, periodStart, periodEnd time.Time) (decimal.Decimal, error) {
	query := `
		SELECT COALESCE(SUM(quantity_used), 0)
		FROM subscription.usages
		WHERE subscription_item_id = $1
		  AND feature_key = $2
		  AND period_start >= $3
		  AND period_end <= $4
	`
	var total decimal.Decimal
	err := db.QueryRowContext(ctx, query, subscriptionItemID, featureKey, periodStart, periodEnd).Scan(&total)
	if err != nil {
		return decimal.Zero, fmt.Errorf("get total usage: %w", err)
	}
	return total, nil
}

func (r *usageRepository) GetUsageRemaining(ctx context.Context, db DBTX, subscriptionItemID uuid.UUID, featureKey string, periodStart, periodEnd time.Time) (*models.UsageRemaining, error) {
	// Query the view subscription.usage_remaining for this specific item and feature.
	query := `
		SELECT sub_item_id, subscription_id, plan_item_id, feature_key,
		       total_allowed, used, remaining
		FROM subscription.usage_remaining
		WHERE sub_item_id = $1 AND feature_key = $2
	`
	var rem models.UsageRemaining
	err := db.QueryRowContext(ctx, query, subscriptionItemID, featureKey).Scan(
		&rem.SubItemID,
		&rem.SubscriptionID,
		&rem.PlanItemID,
		&rem.FeatureKey,
		&rem.TotalAllowed,
		&rem.Used,
		&rem.Remaining,
	)
	if err != nil {
		if err == sql.ErrNoRows {
			return nil, nil
		}
		return nil, fmt.Errorf("get usage remaining: %w", err)
	}
	return &rem, nil
}

func (r *usageRepository) GetCurrentPeriodUsage(ctx context.Context, db DBTX, subscriptionItemID uuid.UUID, featureKey string) (decimal.Decimal, error) {
	// Current period is defined as the current month (could be custom per plan).
	// We'll use month-to-date: period_start >= date_trunc('month', now())
	query := `
		SELECT COALESCE(SUM(quantity_used), 0)
		FROM subscription.usages
		WHERE subscription_item_id = $1
		  AND feature_key = $2
		  AND period_start >= date_trunc('month', NOW())
		  AND period_start < date_trunc('month', NOW()) + interval '1 month'
	`
	var total decimal.Decimal
	err := db.QueryRowContext(ctx, query, subscriptionItemID, featureKey).Scan(&total)
	if err != nil {
		return decimal.Zero, fmt.Errorf("get current period usage: %w", err)
	}
	return total, nil
}

// -------------------------------------------------------------------------
// Querying
// -------------------------------------------------------------------------

func (r *usageRepository) List(ctx context.Context, db DBTX, filter UsageFilter, p Pagination, s Sort) ([]*models.Usage, int64, error) {
	where, args := r.buildFilterConditions(filter)
	whereClause := ""
	if len(where) > 0 {
		whereClause = "WHERE " + strings.Join(where, " AND ")
	}

	// Count total
	countQuery := fmt.Sprintf(`SELECT COUNT(*) FROM subscription.usages %s`, whereClause)
	var total int64
	err := db.QueryRowContext(ctx, countQuery, args...).Scan(&total)
	if err != nil {
		return nil, 0, fmt.Errorf("count usages: %w", err)
	}
	if total == 0 {
		return []*models.Usage{}, 0, nil
	}

	sortClause := "ORDER BY recorded_at DESC"
	if s.Field != "" {
		direction := "ASC"
		if strings.ToUpper(s.Direction) == "DESC" {
			direction = "DESC"
		}
		sortClause = fmt.Sprintf("ORDER BY %s %s", s.Field, direction)
	}

	query := fmt.Sprintf(`
		%s %s %s
		LIMIT $%d OFFSET $%d
	`, r.buildSelectQuery(), whereClause, sortClause, len(args)+1, len(args)+2)

	limitArgs := append(args, p.Limit, p.Offset)
	rows, err := db.QueryContext(ctx, query, limitArgs...)
	if err != nil {
		return nil, 0, fmt.Errorf("list usages: %w", err)
	}
	defer rows.Close()

	var usages []*models.Usage
	for rows.Next() {
		var u models.Usage
		if err := r.scanUsageRows(rows, &u); err != nil {
			return nil, 0, fmt.Errorf("scan usage: %w", err)
		}
		usages = append(usages, &u)
	}
	return usages, total, rows.Err()
}

func (r *usageRepository) Search(ctx context.Context, db DBTX, subscriptionItemID uuid.UUID, query string, limit, offset int) ([]*models.Usage, int64, error) {
	// Search by feature_key (partial match) and maybe source_type.
	searchPattern := "%" + query + "%"
	where := "subscription_item_id = $1 AND (feature_key ILIKE $2 OR source_type ILIKE $2)"
	countQuery := fmt.Sprintf(`SELECT COUNT(*) FROM subscription.usages WHERE %s`, where)
	var total int64
	err := db.QueryRowContext(ctx, countQuery, subscriptionItemID, searchPattern).Scan(&total)
	if err != nil {
		return nil, 0, fmt.Errorf("count search: %w", err)
	}
	if total == 0 {
		return []*models.Usage{}, 0, nil
	}

	dataQuery := fmt.Sprintf(`
		%s WHERE %s
		ORDER BY recorded_at DESC
		LIMIT $%d OFFSET $%d
	`, r.buildSelectQuery(), where, 3, 4)

	rows, err := db.QueryContext(ctx, dataQuery, subscriptionItemID, searchPattern, limit, offset)
	if err != nil {
		return nil, 0, fmt.Errorf("search usages: %w", err)
	}
	defer rows.Close()

	var usages []*models.Usage
	for rows.Next() {
		var u models.Usage
		if err := r.scanUsageRows(rows, &u); err != nil {
			return nil, 0, fmt.Errorf("scan usage: %w", err)
		}
		usages = append(usages, &u)
	}
	return usages, total, rows.Err()
}

func (r *usageRepository) GetBySubscriptionItem(ctx context.Context, db DBTX, subscriptionItemID uuid.UUID) ([]*models.Usage, error) {
	query := r.buildSelectQuery() + ` WHERE subscription_item_id = $1 ORDER BY recorded_at DESC`
	rows, err := db.QueryContext(ctx, query, subscriptionItemID)
	if err != nil {
		return nil, fmt.Errorf("get by subscription item: %w", err)
	}
	defer rows.Close()
	return r.collectUsages(rows)
}

func (r *usageRepository) GetByFeature(ctx context.Context, db DBTX, featureKey string) ([]*models.Usage, error) {
	query := r.buildSelectQuery() + ` WHERE feature_key = $1 ORDER BY recorded_at DESC`
	rows, err := db.QueryContext(ctx, query, featureKey)
	if err != nil {
		return nil, fmt.Errorf("get by feature: %w", err)
	}
	defer rows.Close()
	return r.collectUsages(rows)
}

func (r *usageRepository) GetBySource(ctx context.Context, db DBTX, sourceType string, sourceID uuid.UUID) ([]*models.Usage, error) {
	query := r.buildSelectQuery() + ` WHERE source_type = $1 AND source_id = $2 ORDER BY recorded_at DESC`
	rows, err := db.QueryContext(ctx, query, sourceType, sourceID)
	if err != nil {
		return nil, fmt.Errorf("get by source: %w", err)
	}
	defer rows.Close()
	return r.collectUsages(rows)
}

func (r *usageRepository) GetBetween(ctx context.Context, db DBTX, subscriptionItemID uuid.UUID, from, to time.Time) ([]*models.Usage, error) {
	query := r.buildSelectQuery() + ` WHERE subscription_item_id = $1 AND recorded_at BETWEEN $2 AND $3 ORDER BY recorded_at`
	rows, err := db.QueryContext(ctx, query, subscriptionItemID, from, to)
	if err != nil {
		return nil, fmt.Errorf("get between: %w", err)
	}
	defer rows.Close()
	return r.collectUsages(rows)
}

// -------------------------------------------------------------------------
// Analytics
// -------------------------------------------------------------------------

func (r *usageRepository) GetUsageSummary(ctx context.Context, db DBTX, subscriptionItemID uuid.UUID, from, to time.Time) (decimal.Decimal, error) {
	query := `
		SELECT COALESCE(SUM(quantity_used), 0)
		FROM subscription.usages
		WHERE subscription_item_id = $1 AND recorded_at BETWEEN $2 AND $3
	`
	var total decimal.Decimal
	err := db.QueryRowContext(ctx, query, subscriptionItemID, from, to).Scan(&total)
	if err != nil {
		return decimal.Zero, fmt.Errorf("get usage summary: %w", err)
	}
	return total, nil
}

func (r *usageRepository) GetFeatureUsageSummary(ctx context.Context, db DBTX, featureKey string, from, to time.Time) (decimal.Decimal, error) {
	query := `
		SELECT COALESCE(SUM(quantity_used), 0)
		FROM subscription.usages
		WHERE feature_key = $1 AND recorded_at BETWEEN $2 AND $3
	`
	var total decimal.Decimal
	err := db.QueryRowContext(ctx, query, featureKey, from, to).Scan(&total)
	if err != nil {
		return decimal.Zero, fmt.Errorf("get feature usage summary: %w", err)
	}
	return total, nil
}

// -------------------------------------------------------------------------
// Atomic Increment (High‑throughput UPSERT)
// -------------------------------------------------------------------------

func (r *usageRepository) IncrementUsage(
	ctx context.Context,
	db DBTX,
	subscriptionItemID uuid.UUID,
	featureKey string,
	quantity decimal.Decimal,
	periodStart, periodEnd time.Time,
	sourceType *string,
	sourceID *uuid.UUID,
	createdBy *uuid.UUID,
) (*models.Usage, error) {
	// We use a simple INSERT. If you want idempotent aggregation, create a unique constraint
	// on (subscription_item_id, feature_key, period_start, period_end) and use ON CONFLICT.
	// For this implementation, we create a new row each time.
	// The method is atomic: the insert is a single statement.
	usageID := uuid.New()
	recordedAt := time.Now()

	query := `
		INSERT INTO subscription.usages (
			usage_id, subscription_item_id, feature_key, quantity_used,
			period_start, period_end, recorded_at, source_type, source_id, created_by
		) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10)
		RETURNING usage_id, subscription_item_id, feature_key, quantity_used,
		          period_start, period_end, recorded_at, source_type, source_id, created_by
	`
	var usage models.Usage
	err := db.QueryRowContext(ctx, query,
		usageID,
		subscriptionItemID,
		featureKey,
		quantity,
		periodStart,
		periodEnd,
		recordedAt,
		sourceType,
		sourceID,
		createdBy,
	).Scan(
		&usage.UsageID,
		&usage.SubscriptionItemID,
		&usage.FeatureKey,
		&usage.QuantityUsed,
		&usage.PeriodStart,
		&usage.PeriodEnd,
		&usage.RecordedAt,
		&usage.SourceType,
		&usage.SourceID,
		&usage.CreatedBy,
	)
	if err != nil {
		r.logger.Error("failed to increment usage", zap.Error(err))
		return nil, fmt.Errorf("increment usage: %w", err)
	}
	return &usage, nil
}

// -------------------------------------------------------------------------
// Locking
// -------------------------------------------------------------------------

func (r *usageRepository) GetByIDForUpdate(ctx context.Context, db DBTX, usageID uuid.UUID) (*models.Usage, error) {
	query := r.buildSelectQuery() + ` WHERE usage_id = $1 FOR UPDATE`
	var usage models.Usage
	err := db.QueryRowContext(ctx, query, usageID).Scan(
		&usage.UsageID,
		&usage.SubscriptionItemID,
		&usage.FeatureKey,
		&usage.QuantityUsed,
		&usage.PeriodStart,
		&usage.PeriodEnd,
		&usage.RecordedAt,
		&usage.SourceType,
		&usage.SourceID,
		&usage.CreatedBy,
	)
	if err != nil {
		if err == sql.ErrNoRows {
			return nil, nil
		}
		return nil, fmt.Errorf("get by ID for update: %w", err)
	}
	return &usage, nil
}

// -------------------------------------------------------------------------
// Helpers
// -------------------------------------------------------------------------

func (r *usageRepository) buildSelectQuery() string {
	return `
		SELECT usage_id, subscription_item_id, feature_key, quantity_used,
		       period_start, period_end, recorded_at, source_type, source_id, created_by
		FROM subscription.usages
	`
}

func (r *usageRepository) scanUsageRows(rows *sql.Rows, u *models.Usage) error {
	return rows.Scan(
		&u.UsageID,
		&u.SubscriptionItemID,
		&u.FeatureKey,
		&u.QuantityUsed,
		&u.PeriodStart,
		&u.PeriodEnd,
		&u.RecordedAt,
		&u.SourceType,
		&u.SourceID,
		&u.CreatedBy,
	)
}

func (r *usageRepository) collectUsages(rows *sql.Rows) ([]*models.Usage, error) {
	var usages []*models.Usage
	for rows.Next() {
		var u models.Usage
		if err := r.scanUsageRows(rows, &u); err != nil {
			return nil, fmt.Errorf("scan usage: %w", err)
		}
		usages = append(usages, &u)
	}
	return usages, rows.Err()
}

func (r *usageRepository) buildFilterConditions(filter UsageFilter) ([]string, []interface{}) {
	var conditions []string
	var args []interface{}
	argPos := 1

	if len(filter.UsageIDs) > 0 {
		placeholders := make([]string, len(filter.UsageIDs))
		for i, id := range filter.UsageIDs {
			placeholders[i] = fmt.Sprintf("$%d", argPos+i)
			args = append(args, id)
		}
		conditions = append(conditions, fmt.Sprintf("usage_id IN (%s)", strings.Join(placeholders, ",")))
		argPos += len(filter.UsageIDs)
	}

	if filter.SubscriptionItemID != nil {
		conditions = append(conditions, fmt.Sprintf("subscription_item_id = $%d", argPos))
		args = append(args, *filter.SubscriptionItemID)
		argPos++
	}

	if filter.FeatureKey != nil {
		conditions = append(conditions, fmt.Sprintf("feature_key = $%d", argPos))
		args = append(args, *filter.FeatureKey)
		argPos++
	}

	if filter.SourceType != nil {
		conditions = append(conditions, fmt.Sprintf("source_type = $%d", argPos))
		args = append(args, *filter.SourceType)
		argPos++
	}

	if filter.SourceID != nil {
		conditions = append(conditions, fmt.Sprintf("source_id = $%d", argPos))
		args = append(args, *filter.SourceID)
		argPos++
	}

	if filter.CreatedBy != nil {
		conditions = append(conditions, fmt.Sprintf("created_by = $%d", argPos))
		args = append(args, *filter.CreatedBy)
		argPos++
	}

	if filter.QuantityMin != nil {
		conditions = append(conditions, fmt.Sprintf("quantity_used >= $%d", argPos))
		args = append(args, *filter.QuantityMin)
		argPos++
	}
	if filter.QuantityMax != nil {
		conditions = append(conditions, fmt.Sprintf("quantity_used <= $%d", argPos))
		args = append(args, *filter.QuantityMax)
		argPos++
	}

	addDateRange(&conditions, &args, &argPos, "period_start", filter.PeriodStartFrom, filter.PeriodStartTo)
	addDateRange(&conditions, &args, &argPos, "period_end", filter.PeriodEndFrom, filter.PeriodEndTo)
	addDateRange(&conditions, &args, &argPos, "recorded_at", filter.RecordedFrom, filter.RecordedTo)

	return conditions, args
}

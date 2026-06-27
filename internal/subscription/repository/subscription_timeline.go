// repository/subscription_timeline.go
package repository

import (
	"context"
	"database/sql"
	"fmt"
	"strings"
	"time"

	"github.com/google/uuid"
	"go.uber.org/zap"
	"gorm.io/datatypes"

	"auth-service/internal/subscription/errors"
	"auth-service/internal/subscription/models"
)

// ---------------------------------------------------------------------
// SubscriptionTimelineRepository Interface
// ---------------------------------------------------------------------

type SubscriptionTimelineRepository interface {
	Create(ctx context.Context, db DBTX, timeline *models.SubscriptionTimeline) error
	GetByID(ctx context.Context, db DBTX, timelineID uuid.UUID) (*models.SubscriptionTimeline, error)
	List(ctx context.Context, db DBTX, filter SubscriptionTimelineFilter, p Pagination, s Sort) ([]*models.SubscriptionTimeline, int64, error)
	ListBySubscription(ctx context.Context, db DBTX, subscriptionID uuid.UUID, p Pagination, s Sort) ([]*models.SubscriptionTimeline, int64, error)
	ListByEvent(ctx context.Context, db DBTX, eventType string, limit int) ([]*models.SubscriptionTimeline, error)
	ListRecent(ctx context.Context, db DBTX, subscriptionID uuid.UUID, limit int) ([]*models.SubscriptionTimeline, error)
	Search(ctx context.Context, db DBTX, subscriptionID uuid.UUID, query string, limit, offset int) ([]*models.SubscriptionTimeline, int64, error)
	Exists(ctx context.Context, db DBTX, timelineID uuid.UUID) (bool, error)
	GetByIDForUpdate(ctx context.Context, db DBTX, timelineID uuid.UUID) (*models.SubscriptionTimeline, error)
}

// ---------------------------------------------------------------------
// Filter
// ---------------------------------------------------------------------

type SubscriptionTimelineFilter struct {
	SubscriptionID uuid.UUID
	TimelineIDs    []uuid.UUID
	EventType      *string
	PerformedBy    *uuid.UUID
	OccurredFrom   *time.Time
	OccurredTo     *time.Time
}

// ---------------------------------------------------------------------
// Implementation
// ---------------------------------------------------------------------

type subscriptionTimelineRepository struct {
	logger *zap.Logger
}

func NewSubscriptionTimelineRepository(logger *zap.Logger) SubscriptionTimelineRepository {
	return &subscriptionTimelineRepository{
		logger: logger.Named("subscription_timeline_repo"),
	}
}

const timelineTable = "subscription.subscription_timeline"

func (r *subscriptionTimelineRepository) scanTimeline(s scanner) (*models.SubscriptionTimeline, error) {
	var tl models.SubscriptionTimeline
	var oldStatusID, newStatusID, performedBy sql.NullInt32
	var metadata string

	err := s.Scan(
		&tl.TimelineID,
		&tl.SubscriptionID,
		&tl.EventType,
		&oldStatusID,
		&newStatusID,
		&performedBy,
		&metadata,
		&tl.CreatedAt,
	)
	if err != nil {
		if err == sql.ErrNoRows {
			return nil, errors.ErrNotFound
		}
		return nil, fmt.Errorf("scan timeline: %w", err)
	}

	if oldStatusID.Valid {
		id := int16(oldStatusID.Int32)
		tl.OldStatusID = &id
	}
	if newStatusID.Valid {
		id := int16(newStatusID.Int32)
		tl.NewStatusID = &id
	}
	if performedBy.Valid {
		_ = uuid.UUID{0: byte(performedBy.Int32)}
		// In practice, use a proper UUID conversion.
		// For simplicity, we'll let the repository handle it.
	}
	if metadata != "" {
		tl.Metadata = datatypes.JSON(metadata)
	}
	return &tl, nil
}

func (r *subscriptionTimelineRepository) buildTimelineFilter(filter SubscriptionTimelineFilter) (string, []interface{}) {
	var conds []string
	var args []interface{}
	idx := 1

	if filter.SubscriptionID != uuid.Nil {
		conds = append(conds, fmt.Sprintf("subscription_id = $%d", idx))
		args = append(args, filter.SubscriptionID)
		idx++
	}

	if len(filter.TimelineIDs) > 0 {
		placeholders := make([]string, len(filter.TimelineIDs))
		for i, id := range filter.TimelineIDs {
			placeholders[i] = fmt.Sprintf("$%d", idx)
			args = append(args, id)
			idx++
		}
		conds = append(conds, fmt.Sprintf("timeline_id IN (%s)", strings.Join(placeholders, ",")))
	}

	if filter.EventType != nil {
		conds = append(conds, fmt.Sprintf("event_type = $%d", idx))
		args = append(args, *filter.EventType)
		idx++
	}

	if filter.PerformedBy != nil {
		conds = append(conds, fmt.Sprintf("performed_by = $%d", idx))
		args = append(args, *filter.PerformedBy)
		idx++
	}

	if filter.OccurredFrom != nil {
		conds = append(conds, fmt.Sprintf("created_at >= $%d", idx))
		args = append(args, *filter.OccurredFrom)
		idx++
	}
	if filter.OccurredTo != nil {
		conds = append(conds, fmt.Sprintf("created_at <= $%d", idx))
		args = append(args, *filter.OccurredTo)
		idx++
	}

	if len(conds) == 0 {
		return "", args
	}
	return "WHERE " + strings.Join(conds, " AND "), args
}

var timelineAllowedSort = map[string]bool{
	"timeline_id": true,
	"event_type":  true,
	"created_at":  true,
}

// ---------------------------------------------------------------------
// CRUD
// ---------------------------------------------------------------------

func (r *subscriptionTimelineRepository) Create(ctx context.Context, db DBTX, timeline *models.SubscriptionTimeline) error {
	query := `
		INSERT INTO subscription.subscription_timeline (
			timeline_id, subscription_id, event_type,
			old_status_id, new_status_id, performed_by, metadata, created_at
		) VALUES ($1, $2, $3, $4, $5, $6, $7, NOW())
	`
	_, err := db.ExecContext(ctx, query,
		timeline.TimelineID,
		timeline.SubscriptionID,
		timeline.EventType,
		timeline.OldStatusID,
		timeline.NewStatusID,
		timeline.PerformedBy,
		timeline.Metadata,
	)
	if err != nil {
		return fmt.Errorf("create timeline entry: %w", err)
	}
	return nil
}

// ---------------------------------------------------------------------
// Single Fetch
// ---------------------------------------------------------------------

func (r *subscriptionTimelineRepository) GetByID(ctx context.Context, db DBTX, timelineID uuid.UUID) (*models.SubscriptionTimeline, error) {
	query := `
		SELECT timeline_id, subscription_id, event_type,
			old_status_id, new_status_id, performed_by, metadata, created_at
		FROM subscription.subscription_timeline
		WHERE timeline_id = $1
	`
	row := db.QueryRowContext(ctx, query, timelineID)
	return r.scanTimeline(row)
}

// ---------------------------------------------------------------------
// Listing
// ---------------------------------------------------------------------

func (r *subscriptionTimelineRepository) List(ctx context.Context, db DBTX, filter SubscriptionTimelineFilter, p Pagination, s Sort) ([]*models.SubscriptionTimeline, int64, error) {
	where, args := r.buildTimelineFilter(filter)
	if where == "" {
		return nil, 0, fmt.Errorf("subscription_id is required in filter")
	}

	orderBy, err := validateSort(s, timelineAllowedSort)
	if err != nil {
		return nil, 0, err
	}
	if orderBy == "" {
		orderBy = "ORDER BY created_at DESC"
	}

	limit, offset := validatePagination(p)

	countQuery := fmt.Sprintf("SELECT COUNT(*) FROM %s %s", timelineTable, where)
	var total int64
	err = db.QueryRowContext(ctx, countQuery, args...).Scan(&total)
	if err != nil {
		return nil, 0, fmt.Errorf("count timeline entries: %w", err)
	}
	if total == 0 {
		return []*models.SubscriptionTimeline{}, 0, nil
	}

	query := fmt.Sprintf(`
		SELECT timeline_id, subscription_id, event_type,
			old_status_id, new_status_id, performed_by, metadata, created_at
		FROM %s
		%s
		%s
		LIMIT $%d OFFSET $%d
	`, timelineTable, where, orderBy, len(args)+1, len(args)+2)
	args = append(args, limit, offset)

	rows, err := db.QueryContext(ctx, query, args...)
	if err != nil {
		return nil, 0, fmt.Errorf("list timeline: %w", err)
	}
	defer rows.Close()

	var result []*models.SubscriptionTimeline
	for rows.Next() {
		tl, err := r.scanTimeline(rows)
		if err != nil {
			return nil, 0, err
		}
		result = append(result, tl)
	}
	return result, total, rows.Err()
}

func (r *subscriptionTimelineRepository) ListBySubscription(ctx context.Context, db DBTX, subscriptionID uuid.UUID, p Pagination, s Sort) ([]*models.SubscriptionTimeline, int64, error) {
	filter := SubscriptionTimelineFilter{
		SubscriptionID: subscriptionID,
	}
	return r.List(ctx, db, filter, p, s)
}

func (r *subscriptionTimelineRepository) ListByEvent(ctx context.Context, db DBTX, eventType string, limit int) ([]*models.SubscriptionTimeline, error) {
	filter := SubscriptionTimelineFilter{
		EventType: &eventType,
	}
	timeline, _, err := r.List(ctx, db, filter,
		Pagination{Limit: limit},
		Sort{Field: "created_at", Direction: "DESC"},
	)
	return timeline, err
}

func (r *subscriptionTimelineRepository) ListRecent(ctx context.Context, db DBTX, subscriptionID uuid.UUID, limit int) ([]*models.SubscriptionTimeline, error) {
	timeline, _, err := r.ListBySubscription(ctx, db, subscriptionID,
		Pagination{Limit: limit},
		Sort{Field: "created_at", Direction: "DESC"},
	)
	return timeline, err
}

// ---------------------------------------------------------------------
// Search
// ---------------------------------------------------------------------

func (r *subscriptionTimelineRepository) Search(ctx context.Context, db DBTX, subscriptionID uuid.UUID, query string, limit, offset int) ([]*models.SubscriptionTimeline, int64, error) {
	pattern := "%" + query + "%"
	where := "WHERE subscription_id = $1 AND (event_type ILIKE $2)"
	args := []interface{}{subscriptionID, pattern}

	countQuery := fmt.Sprintf("SELECT COUNT(*) FROM %s %s", timelineTable, where)
	var total int64
	err := db.QueryRowContext(ctx, countQuery, args...).Scan(&total)
	if err != nil {
		return nil, 0, fmt.Errorf("search timeline count: %w", err)
	}
	if total == 0 {
		return []*models.SubscriptionTimeline{}, 0, nil
	}

	baseQuery := `
		SELECT timeline_id, subscription_id, event_type,
			old_status_id, new_status_id, performed_by, metadata, created_at
		FROM subscription.subscription_timeline
	`
	querySQL := fmt.Sprintf(`%s %s ORDER BY created_at DESC LIMIT $%d OFFSET $%d`, baseQuery, where, len(args)+1, len(args)+2)
	args = append(args, limit, offset)

	rows, err := db.QueryContext(ctx, querySQL, args...)
	if err != nil {
		return nil, 0, fmt.Errorf("search timeline: %w", err)
	}
	defer rows.Close()

	var result []*models.SubscriptionTimeline
	for rows.Next() {
		tl, err := r.scanTimeline(rows)
		if err != nil {
			return nil, 0, err
		}
		result = append(result, tl)
	}
	return result, total, rows.Err()
}

// ---------------------------------------------------------------------
// Validation
// ---------------------------------------------------------------------

func (r *subscriptionTimelineRepository) Exists(ctx context.Context, db DBTX, timelineID uuid.UUID) (bool, error) {
	var exists bool
	query := `SELECT EXISTS(SELECT 1 FROM subscription.subscription_timeline WHERE timeline_id = $1)`
	err := db.QueryRowContext(ctx, query, timelineID).Scan(&exists)
	return exists, err
}

// ---------------------------------------------------------------------
// Locking
// ---------------------------------------------------------------------

func (r *subscriptionTimelineRepository) GetByIDForUpdate(ctx context.Context, db DBTX, timelineID uuid.UUID) (*models.SubscriptionTimeline, error) {
	query := `
		SELECT timeline_id, subscription_id, event_type,
			old_status_id, new_status_id, performed_by, metadata, created_at
		FROM subscription.subscription_timeline
		WHERE timeline_id = $1
		FOR UPDATE
	`
	row := db.QueryRowContext(ctx, query, timelineID)
	return r.scanTimeline(row)
}

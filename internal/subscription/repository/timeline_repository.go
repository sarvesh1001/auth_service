// FILE: repository/timeline_repository.go

package repository

import (
	"context"
	"database/sql"
	"fmt"
	"strings"
	"time"

	"github.com/google/uuid"
	"go.uber.org/zap"

	"auth-service/internal/subscription/models"
	"auth-service/internal/subscription/models/enums"
)

// -------------------------------------------------------------------------
// TimelineRepository Interface (append-only)
// -------------------------------------------------------------------------

type TimelineRepository interface {
	// Append Events
	Create(ctx context.Context, db DBTX, event *models.SubscriptionTimeline) error
	BulkCreate(ctx context.Context, db DBTX, events []*models.SubscriptionTimeline) error

	// Retrieval
	GetByID(ctx context.Context, db DBTX, timelineID uuid.UUID) (*models.SubscriptionTimeline, error)

	// Validation
	Exists(ctx context.Context, db DBTX, timelineID uuid.UUID) (bool, error)

	// Querying
	List(ctx context.Context, db DBTX, filter TimelineFilter, p Pagination, s Sort) ([]*models.SubscriptionTimeline, int64, error)
	Search(ctx context.Context, db DBTX, subscriptionID uuid.UUID, query string, limit, offset int) ([]*models.SubscriptionTimeline, int64, error)
	GetBySubscription(ctx context.Context, db DBTX, subscriptionID uuid.UUID) ([]*models.SubscriptionTimeline, error)
	GetByEventType(ctx context.Context, db DBTX, eventType enums.TimelineEvent) ([]*models.SubscriptionTimeline, error)
	GetByActor(ctx context.Context, db DBTX, actorID uuid.UUID) ([]*models.SubscriptionTimeline, error)
	GetBetween(ctx context.Context, db DBTX, subscriptionID uuid.UUID, from, to time.Time) ([]*models.SubscriptionTimeline, error)
	GetLatest(ctx context.Context, db DBTX, subscriptionID uuid.UUID, limit int) ([]*models.SubscriptionTimeline, error)

	// Locking
	GetByIDForUpdate(ctx context.Context, db DBTX, timelineID uuid.UUID) (*models.SubscriptionTimeline, error)
}

// -------------------------------------------------------------------------
// Filter, Pagination, Sort
// -------------------------------------------------------------------------

type TimelineFilter struct {
	TimelineIDs    []uuid.UUID
	SubscriptionID *uuid.UUID
	EventType      *enums.TimelineEvent
	ActorID        *uuid.UUID
	SourceType     *string
	SourceID       *uuid.UUID
	CreatedFrom    *time.Time
	CreatedTo      *time.Time
}

// -------------------------------------------------------------------------
// Implementation
// -------------------------------------------------------------------------

type timelineRepository struct {
	logger *zap.Logger
}

func NewTimelineRepository(logger *zap.Logger) TimelineRepository {
	return &timelineRepository{
		logger: logger.Named("subscription_timeline_repo"),
	}
}

// -------------------------------------------------------------------------
// Helper: status <-> id
// -------------------------------------------------------------------------

// statusToID maps a SubscriptionStatus to its integer ID.
func (r *timelineRepository) statusToID(status enums.SubscriptionStatus) int {
	switch status {
	case enums.SubStatusActive:
		return 1
	case enums.SubStatusPaused:
		return 2
	case enums.SubStatusExpired:
		return 3
	case enums.SubStatusCancelled:
		return 4
	case enums.SubStatusTrial:
		return 5
	case enums.SubStatusPending:
		return 6
	default:
		return 1 // fallback to active
	}
}

// statusPtrToIDPtr converts a *SubscriptionStatus to *int.
func (r *timelineRepository) statusPtrToIDPtr(status *enums.SubscriptionStatus) *int {
	if status == nil {
		return nil
	}
	id := r.statusToID(*status)
	return &id
}

// idToStatus converts an integer status_id to SubscriptionStatus.
func (r *timelineRepository) idToStatus(id *int) *enums.SubscriptionStatus {
	if id == nil {
		return nil
	}
	var status enums.SubscriptionStatus
	switch *id {
	case 1:
		status = enums.SubStatusActive
	case 2:
		status = enums.SubStatusPaused
	case 3:
		status = enums.SubStatusExpired
	case 4:
		status = enums.SubStatusCancelled
	case 5:
		status = enums.SubStatusTrial
	case 6:
		status = enums.SubStatusPending
	default:
		status = enums.SubStatusActive
	}
	return &status
}

// -------------------------------------------------------------------------
// Append Events (no updates/deletes)
// -------------------------------------------------------------------------

func (r *timelineRepository) Create(ctx context.Context, db DBTX, event *models.SubscriptionTimeline) error {
	// Convert status enums to IDs
	oldStatusID := r.statusPtrToIDPtr(event.OldStatus)
	newStatusID := r.statusPtrToIDPtr(event.NewStatus)

	query := `
		INSERT INTO subscription.subscription_timeline (
			timeline_id, subscription_id, event_type,
			old_status_id, new_status_id,
			performed_by, metadata, created_at
		) VALUES ($1, $2, $3, $4, $5, $6, $7, $8)
	`
	_, err := db.ExecContext(ctx, query,
		event.TimelineID,
		event.SubscriptionID,
		event.EventType,
		oldStatusID,
		newStatusID,
		event.PerformedBy,
		event.Metadata,
		event.CreatedAt,
	)
	if err != nil {
		r.logger.Error("failed to create timeline event", zap.Error(err))
		return fmt.Errorf("create timeline event: %w", err)
	}
	return nil
}

func (r *timelineRepository) BulkCreate(ctx context.Context, db DBTX, events []*models.SubscriptionTimeline) error {
	if len(events) == 0 {
		return nil
	}

	valueStrings := make([]string, 0, len(events))
	args := make([]interface{}, 0, len(events)*8)
	argID := 1

	for _, e := range events {
		oldStatusID := r.statusPtrToIDPtr(e.OldStatus)
		newStatusID := r.statusPtrToIDPtr(e.NewStatus)

		valueStrings = append(valueStrings, fmt.Sprintf(
			"($%d, $%d, $%d, $%d, $%d, $%d, $%d, $%d)",
			argID, argID+1, argID+2, argID+3, argID+4, argID+5, argID+6, argID+7,
		))
		args = append(args,
			e.TimelineID,
			e.SubscriptionID,
			e.EventType,
			oldStatusID,
			newStatusID,
			e.PerformedBy,
			e.Metadata,
			e.CreatedAt,
		)
		argID += 8
	}

	query := fmt.Sprintf(`
		INSERT INTO subscription.subscription_timeline (
			timeline_id, subscription_id, event_type,
			old_status_id, new_status_id,
			performed_by, metadata, created_at
		) VALUES %s
	`, strings.Join(valueStrings, ", "))

	_, err := db.ExecContext(ctx, query, args...)
	if err != nil {
		r.logger.Error("failed to bulk create timeline events", zap.Int("count", len(events)), zap.Error(err))
		return fmt.Errorf("bulk create timeline events: %w", err)
	}
	return nil
}

// -------------------------------------------------------------------------
// Retrieval
// -------------------------------------------------------------------------

func (r *timelineRepository) GetByID(ctx context.Context, db DBTX, timelineID uuid.UUID) (*models.SubscriptionTimeline, error) {
	query := `
		SELECT timeline_id, subscription_id, event_type,
		       old_status_id, new_status_id,
		       performed_by, metadata, created_at
		FROM subscription.subscription_timeline
		WHERE timeline_id = $1
	`
	var ev models.SubscriptionTimeline
	var oldStatusID, newStatusID *int

	err := db.QueryRowContext(ctx, query, timelineID).Scan(
		&ev.TimelineID,
		&ev.SubscriptionID,
		&ev.EventType,
		&oldStatusID,
		&newStatusID,
		&ev.PerformedBy,
		&ev.Metadata,
		&ev.CreatedAt,
	)
	if err != nil {
		if err == sql.ErrNoRows {
			return nil, nil
		}
		r.logger.Error("failed to get timeline event by ID", zap.Error(err))
		return nil, fmt.Errorf("get timeline event by ID: %w", err)
	}

	// Convert IDs back to enum statuses
	ev.OldStatus = r.idToStatus(oldStatusID)
	ev.NewStatus = r.idToStatus(newStatusID)

	return &ev, nil
}

// -------------------------------------------------------------------------
// Validation
// -------------------------------------------------------------------------

func (r *timelineRepository) Exists(ctx context.Context, db DBTX, timelineID uuid.UUID) (bool, error) {
	query := `SELECT EXISTS(SELECT 1 FROM subscription.subscription_timeline WHERE timeline_id = $1)`
	var exists bool
	err := db.QueryRowContext(ctx, query, timelineID).Scan(&exists)
	if err != nil {
		return false, fmt.Errorf("check exists: %w", err)
	}
	return exists, nil
}

// -------------------------------------------------------------------------
// Querying
// -------------------------------------------------------------------------

func (r *timelineRepository) List(ctx context.Context, db DBTX, filter TimelineFilter, p Pagination, s Sort) ([]*models.SubscriptionTimeline, int64, error) {
	where, args := r.buildFilterConditions(filter)
	whereClause := ""
	if len(where) > 0 {
		whereClause = "WHERE " + strings.Join(where, " AND ")
	}

	countQuery := fmt.Sprintf(`SELECT COUNT(*) FROM subscription.subscription_timeline %s`, whereClause)
	var total int64
	err := db.QueryRowContext(ctx, countQuery, args...).Scan(&total)
	if err != nil {
		return nil, 0, fmt.Errorf("count timeline events: %w", err)
	}
	if total == 0 {
		return []*models.SubscriptionTimeline{}, 0, nil
	}

	sortClause := ""
	if s.Field != "" {
		direction := "ASC"
		if strings.ToUpper(s.Direction) == "DESC" {
			direction = "DESC"
		}
		sortClause = fmt.Sprintf("ORDER BY %s %s", s.Field, direction)
	} else {
		sortClause = "ORDER BY created_at DESC"
	}

	query := fmt.Sprintf(`
		SELECT timeline_id, subscription_id, event_type,
		       old_status_id, new_status_id,
		       performed_by, metadata, created_at
		FROM subscription.subscription_timeline
		%s %s
		LIMIT $%d OFFSET $%d
	`, whereClause, sortClause, len(args)+1, len(args)+2)

	limitArgs := append(args, p.Limit, p.Offset)
	rows, err := db.QueryContext(ctx, query, limitArgs...)
	if err != nil {
		return nil, 0, fmt.Errorf("list timeline events: %w", err)
	}
	defer rows.Close()

	var events []*models.SubscriptionTimeline
	for rows.Next() {
		var ev models.SubscriptionTimeline
		var oldStatusID, newStatusID *int

		if err := rows.Scan(
			&ev.TimelineID,
			&ev.SubscriptionID,
			&ev.EventType,
			&oldStatusID,
			&newStatusID,
			&ev.PerformedBy,
			&ev.Metadata,
			&ev.CreatedAt,
		); err != nil {
			return nil, 0, fmt.Errorf("scan timeline event: %w", err)
		}

		ev.OldStatus = r.idToStatus(oldStatusID)
		ev.NewStatus = r.idToStatus(newStatusID)

		events = append(events, &ev)
	}
	if err = rows.Err(); err != nil {
		return nil, 0, fmt.Errorf("rows iteration: %w", err)
	}
	return events, total, nil
}

func (r *timelineRepository) Search(ctx context.Context, db DBTX, subscriptionID uuid.UUID, query string, limit, offset int) ([]*models.SubscriptionTimeline, int64, error) {
	searchPattern := "%" + query + "%"
	where := `subscription_id = $1 AND (event_type::text ILIKE $2 OR metadata::text ILIKE $2)`
	countQuery := fmt.Sprintf(`SELECT COUNT(*) FROM subscription.subscription_timeline WHERE %s`, where)
	var total int64
	err := db.QueryRowContext(ctx, countQuery, subscriptionID, searchPattern).Scan(&total)
	if err != nil {
		return nil, 0, fmt.Errorf("count search: %w", err)
	}
	if total == 0 {
		return []*models.SubscriptionTimeline{}, 0, nil
	}

	dataQuery := fmt.Sprintf(`
		SELECT timeline_id, subscription_id, event_type,
		       old_status_id, new_status_id,
		       performed_by, metadata, created_at
		FROM subscription.subscription_timeline
		WHERE %s
		ORDER BY created_at DESC
		LIMIT $%d OFFSET $%d
	`, where, 3, 4)

	rows, err := db.QueryContext(ctx, dataQuery, subscriptionID, searchPattern, limit, offset)
	if err != nil {
		return nil, 0, fmt.Errorf("search timeline events: %w", err)
	}
	defer rows.Close()

	var events []*models.SubscriptionTimeline
	for rows.Next() {
		var ev models.SubscriptionTimeline
		var oldStatusID, newStatusID *int

		if err := rows.Scan(
			&ev.TimelineID,
			&ev.SubscriptionID,
			&ev.EventType,
			&oldStatusID,
			&newStatusID,
			&ev.PerformedBy,
			&ev.Metadata,
			&ev.CreatedAt,
		); err != nil {
			return nil, 0, fmt.Errorf("scan timeline event: %w", err)
		}

		ev.OldStatus = r.idToStatus(oldStatusID)
		ev.NewStatus = r.idToStatus(newStatusID)

		events = append(events, &ev)
	}
	return events, total, rows.Err()
}

func (r *timelineRepository) GetBySubscription(ctx context.Context, db DBTX, subscriptionID uuid.UUID) ([]*models.SubscriptionTimeline, error) {
	query := `
		SELECT timeline_id, subscription_id, event_type,
		       old_status_id, new_status_id,
		       performed_by, metadata, created_at
		FROM subscription.subscription_timeline
		WHERE subscription_id = $1
		ORDER BY created_at ASC
	`
	rows, err := db.QueryContext(ctx, query, subscriptionID)
	if err != nil {
		return nil, fmt.Errorf("get by subscription: %w", err)
	}
	defer rows.Close()
	return r.collectEvents(rows)
}

func (r *timelineRepository) GetByEventType(ctx context.Context, db DBTX, eventType enums.TimelineEvent) ([]*models.SubscriptionTimeline, error) {
	query := `
		SELECT timeline_id, subscription_id, event_type,
		       old_status_id, new_status_id,
		       performed_by, metadata, created_at
		FROM subscription.subscription_timeline
		WHERE event_type = $1
		ORDER BY created_at DESC
	`
	rows, err := db.QueryContext(ctx, query, eventType)
	if err != nil {
		return nil, fmt.Errorf("get by event type: %w", err)
	}
	defer rows.Close()
	return r.collectEvents(rows)
}

func (r *timelineRepository) GetByActor(ctx context.Context, db DBTX, actorID uuid.UUID) ([]*models.SubscriptionTimeline, error) {
	query := `
		SELECT timeline_id, subscription_id, event_type,
		       old_status_id, new_status_id,
		       performed_by, metadata, created_at
		FROM subscription.subscription_timeline
		WHERE performed_by = $1
		ORDER BY created_at DESC
	`
	rows, err := db.QueryContext(ctx, query, actorID)
	if err != nil {
		return nil, fmt.Errorf("get by actor: %w", err)
	}
	defer rows.Close()
	return r.collectEvents(rows)
}

func (r *timelineRepository) GetBetween(ctx context.Context, db DBTX, subscriptionID uuid.UUID, from, to time.Time) ([]*models.SubscriptionTimeline, error) {
	query := `
		SELECT timeline_id, subscription_id, event_type,
		       old_status_id, new_status_id,
		       performed_by, metadata, created_at
		FROM subscription.subscription_timeline
		WHERE subscription_id = $1 AND created_at BETWEEN $2 AND $3
		ORDER BY created_at ASC
	`
	rows, err := db.QueryContext(ctx, query, subscriptionID, from, to)
	if err != nil {
		return nil, fmt.Errorf("get between: %w", err)
	}
	defer rows.Close()
	return r.collectEvents(rows)
}

func (r *timelineRepository) GetLatest(ctx context.Context, db DBTX, subscriptionID uuid.UUID, limit int) ([]*models.SubscriptionTimeline, error) {
	query := `
		SELECT timeline_id, subscription_id, event_type,
		       old_status_id, new_status_id,
		       performed_by, metadata, created_at
		FROM subscription.subscription_timeline
		WHERE subscription_id = $1
		ORDER BY created_at DESC
		LIMIT $2
	`
	rows, err := db.QueryContext(ctx, query, subscriptionID, limit)
	if err != nil {
		return nil, fmt.Errorf("get latest: %w", err)
	}
	defer rows.Close()
	return r.collectEvents(rows)
}

// -------------------------------------------------------------------------
// Locking
// -------------------------------------------------------------------------

func (r *timelineRepository) GetByIDForUpdate(ctx context.Context, db DBTX, timelineID uuid.UUID) (*models.SubscriptionTimeline, error) {
	query := `
		SELECT timeline_id, subscription_id, event_type,
		       old_status_id, new_status_id,
		       performed_by, metadata, created_at
		FROM subscription.subscription_timeline
		WHERE timeline_id = $1
		FOR UPDATE
	`
	var ev models.SubscriptionTimeline
	var oldStatusID, newStatusID *int

	err := db.QueryRowContext(ctx, query, timelineID).Scan(
		&ev.TimelineID,
		&ev.SubscriptionID,
		&ev.EventType,
		&oldStatusID,
		&newStatusID,
		&ev.PerformedBy,
		&ev.Metadata,
		&ev.CreatedAt,
	)
	if err != nil {
		if err == sql.ErrNoRows {
			return nil, nil
		}
		r.logger.Error("failed to get timeline event for update", zap.Error(err))
		return nil, fmt.Errorf("get timeline event for update: %w", err)
	}

	ev.OldStatus = r.idToStatus(oldStatusID)
	ev.NewStatus = r.idToStatus(newStatusID)

	return &ev, nil
}

// -------------------------------------------------------------------------
// Helpers
// -------------------------------------------------------------------------

func (r *timelineRepository) collectEvents(rows *sql.Rows) ([]*models.SubscriptionTimeline, error) {
	var events []*models.SubscriptionTimeline
	for rows.Next() {
		var ev models.SubscriptionTimeline
		var oldStatusID, newStatusID *int

		if err := rows.Scan(
			&ev.TimelineID,
			&ev.SubscriptionID,
			&ev.EventType,
			&oldStatusID,
			&newStatusID,
			&ev.PerformedBy,
			&ev.Metadata,
			&ev.CreatedAt,
		); err != nil {
			return nil, fmt.Errorf("scan timeline event: %w", err)
		}

		ev.OldStatus = r.idToStatus(oldStatusID)
		ev.NewStatus = r.idToStatus(newStatusID)

		events = append(events, &ev)
	}
	return events, rows.Err()
}

func (r *timelineRepository) buildFilterConditions(filter TimelineFilter) ([]string, []interface{}) {
	var conditions []string
	var args []interface{}
	argPos := 1

	if len(filter.TimelineIDs) > 0 {
		placeholders := make([]string, len(filter.TimelineIDs))
		for i, id := range filter.TimelineIDs {
			placeholders[i] = fmt.Sprintf("$%d", argPos+i)
			args = append(args, id)
		}
		conditions = append(conditions, fmt.Sprintf("timeline_id IN (%s)", strings.Join(placeholders, ",")))
		argPos += len(filter.TimelineIDs)
	}

	if filter.SubscriptionID != nil {
		conditions = append(conditions, fmt.Sprintf("subscription_id = $%d", argPos))
		args = append(args, *filter.SubscriptionID)
		argPos++
	}

	if filter.EventType != nil {
		conditions = append(conditions, fmt.Sprintf("event_type = $%d", argPos))
		args = append(args, *filter.EventType)
		argPos++
	}

	if filter.ActorID != nil {
		conditions = append(conditions, fmt.Sprintf("performed_by = $%d", argPos))
		args = append(args, *filter.ActorID)
		argPos++
	}

	if filter.CreatedFrom != nil {
		conditions = append(conditions, fmt.Sprintf("created_at >= $%d", argPos))
		args = append(args, *filter.CreatedFrom)
		argPos++
	}
	if filter.CreatedTo != nil {
		conditions = append(conditions, fmt.Sprintf("created_at <= $%d", argPos))
		args = append(args, *filter.CreatedTo)
		argPos++
	}

	return conditions, args
}

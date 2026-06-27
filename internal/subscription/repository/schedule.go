// repository/schedule_repository.go
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

type ScheduleRepository interface {
	Create(ctx context.Context, db DBTX, schedule *models.Schedule) error
	Update(ctx context.Context, db DBTX, schedule *models.Schedule) error
	Delete(ctx context.Context, db DBTX, companyID, scheduleID uuid.UUID) error

	GetByID(ctx context.Context, db DBTX, companyID, scheduleID uuid.UUID) (*models.Schedule, error)
	GetBySubscription(ctx context.Context, db DBTX, companyID, subscriptionID uuid.UUID) ([]*models.Schedule, error)
	GetByResource(ctx context.Context, db DBTX, companyID uuid.UUID, resourceType string, resourceID uuid.UUID) ([]*models.Schedule, error)

	List(ctx context.Context, db DBTX, filter ScheduleFilter, p Pagination, s Sort) ([]*models.Schedule, int64, error)
	ListUpcoming(ctx context.Context, db DBTX, companyID uuid.UUID) ([]*models.Schedule, error)
	ListToday(ctx context.Context, db DBTX, companyID uuid.UUID) ([]*models.Schedule, error)
	ListActive(ctx context.Context, db DBTX, companyID uuid.UUID) ([]*models.Schedule, error)

	UpdateCapacity(ctx context.Context, db DBTX, companyID, scheduleID uuid.UUID, capacity int) error
	IncrementBookedSeats(ctx context.Context, db DBTX, companyID, scheduleID uuid.UUID) error
	DecrementBookedSeats(ctx context.Context, db DBTX, companyID, scheduleID uuid.UUID) error
	IsFull(ctx context.Context, db DBTX, companyID, scheduleID uuid.UUID) (bool, error)

	UpdateStatus(ctx context.Context, db DBTX, companyID, scheduleID uuid.UUID, statusID int16) error
	Start(ctx context.Context, db DBTX, companyID, scheduleID uuid.UUID) error
	Complete(ctx context.Context, db DBTX, companyID, scheduleID uuid.UUID) error
	Cancel(ctx context.Context, db DBTX, companyID, scheduleID uuid.UUID) error

	Exists(ctx context.Context, db DBTX, companyID, scheduleID uuid.UUID) (bool, error)
	Search(ctx context.Context, db DBTX, companyID uuid.UUID, query string, limit, offset int) ([]*models.Schedule, int64, error)

	GetByIDForUpdate(ctx context.Context, db DBTX, companyID, scheduleID uuid.UUID) (*models.Schedule, error)
}

type ScheduleFilter struct {
	CompanyID      uuid.UUID
	ScheduleIDs    []uuid.UUID
	SubscriptionID *uuid.UUID
	StatusID       *int16
	ScheduleTypeID *int16
	ResourceType   *string
	StartFrom      *time.Time
	StartTo        *time.Time
	EndFrom        *time.Time
	EndTo          *time.Time
}

// ---------------------------------------------------------------------
// Implementation
// ---------------------------------------------------------------------

type scheduleRepository struct {
	logger *zap.Logger
}

func NewScheduleRepository(logger *zap.Logger) ScheduleRepository {
	return &scheduleRepository{
		logger: logger.Named("subscription_schedule_repo"),
	}
}

const scheduleTable = "subscription.schedules"

func (r *scheduleRepository) scanSchedule(s scanner) (*models.Schedule, error) {
	var sch models.Schedule
	var description, location, recurrenceRule, metadata sql.NullString
	var recurrenceEnd, deletedAt sql.NullTime
	var statusID int16

	err := s.Scan(
		&sch.ScheduleID,
		&sch.SubscriptionID,
		&sch.ScheduleTypeID,
		&sch.Title,
		&description,
		&sch.StartTime,
		&sch.EndTime,
		&location,
		&statusID,
		&recurrenceRule,
		&recurrenceEnd,
		&metadata,
		&sch.CreatedAt,
		&sch.UpdatedAt,
		&deletedAt,
	)
	if err != nil {
		if err == sql.ErrNoRows {
			return nil, errors.ErrNotFound
		}
		return nil, fmt.Errorf("scan schedule: %w", err)
	}
	if description.Valid {
		sch.Description = &description.String
	}
	if location.Valid {
		sch.Location = &location.String
	}
	if recurrenceRule.Valid {
		sch.RecurrenceRule = &recurrenceRule.String
	}
	if recurrenceEnd.Valid {
		sch.RecurrenceEnd = &recurrenceEnd.Time
	}
	if metadata.Valid {
		sch.Metadata = []byte(metadata.String)
	}
	if deletedAt.Valid {
		sch.DeletedAt.Time = deletedAt.Time
		sch.DeletedAt.Valid = true
	}
	sch.StatusID = statusID
	return &sch, nil
}

func (r *scheduleRepository) buildScheduleFilter(filter ScheduleFilter) (string, []interface{}) {
	var conds []string
	var args []interface{}
	idx := 1

	if filter.CompanyID != uuid.Nil {
		// We'll join with subscriptions to filter by company
		// Actually we add it later in the list query
	}
	if len(filter.ScheduleIDs) > 0 {
		placeholders := make([]string, len(filter.ScheduleIDs))
		for i, id := range filter.ScheduleIDs {
			placeholders[i] = fmt.Sprintf("$%d", idx)
			args = append(args, id)
			idx++
		}
		conds = append(conds, fmt.Sprintf("s.schedule_id IN (%s)", strings.Join(placeholders, ",")))
	}
	if filter.SubscriptionID != nil {
		conds = append(conds, fmt.Sprintf("s.subscription_id = $%d", idx))
		args = append(args, *filter.SubscriptionID)
		idx++
	}
	if filter.StatusID != nil {
		conds = append(conds, fmt.Sprintf("s.status_id = $%d", idx))
		args = append(args, *filter.StatusID)
		idx++
	}
	if filter.ScheduleTypeID != nil {
		conds = append(conds, fmt.Sprintf("s.schedule_type_id = $%d", idx))
		args = append(args, *filter.ScheduleTypeID)
		idx++
	}
	if filter.ResourceType != nil {
		// Resource type is not directly on schedule – we need to join with resource_assignments
		// We'll handle this in the list query via a join
	}
	if filter.StartFrom != nil {
		conds = append(conds, fmt.Sprintf("s.start_time >= $%d", idx))
		args = append(args, *filter.StartFrom)
		idx++
	}
	if filter.StartTo != nil {
		conds = append(conds, fmt.Sprintf("s.start_time <= $%d", idx))
		args = append(args, *filter.StartTo)
		idx++
	}
	if filter.EndFrom != nil {
		conds = append(conds, fmt.Sprintf("s.end_time >= $%d", idx))
		args = append(args, *filter.EndFrom)
		idx++
	}
	if filter.EndTo != nil {
		conds = append(conds, fmt.Sprintf("s.end_time <= $%d", idx))
		args = append(args, *filter.EndTo)
		idx++
	}
	conds = append(conds, "s.deleted_at IS NULL")
	if len(conds) == 0 {
		return "", args
	}
	return "WHERE " + strings.Join(conds, " AND "), args
}

var scheduleAllowedSort = map[string]bool{
	"schedule_id":      true,
	"title":            true,
	"start_time":       true,
	"end_time":         true,
	"status_id":        true,
	"schedule_type_id": true,
	"created_at":       true,
	"updated_at":       true,
}

func (r *scheduleRepository) Create(ctx context.Context, db DBTX, schedule *models.Schedule) error {
	query := `
		INSERT INTO subscription.schedules (
			schedule_id, subscription_id, schedule_type_id, title,
			description, start_time, end_time, location,
			status_id, recurrence_rule, recurrence_end, metadata,
			created_at, updated_at
		) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, NOW(), NOW())
		RETURNING created_at, updated_at
	`
	err := db.QueryRowContext(ctx, query,
		schedule.ScheduleID,
		schedule.SubscriptionID,
		schedule.ScheduleTypeID,
		schedule.Title,
		schedule.Description,
		schedule.StartTime,
		schedule.EndTime,
		schedule.Location,
		schedule.StatusID,
		schedule.RecurrenceRule,
		schedule.RecurrenceEnd,
		schedule.Metadata,
	).Scan(&schedule.CreatedAt, &schedule.UpdatedAt)
	if err != nil {
		return fmt.Errorf("create schedule: %w", err)
	}
	return nil
}

func (r *scheduleRepository) Update(ctx context.Context, db DBTX, schedule *models.Schedule) error {
	query := `
		UPDATE subscription.schedules SET
			subscription_id = $2,
			schedule_type_id = $3,
			title = $4,
			description = $5,
			start_time = $6,
			end_time = $7,
			location = $8,
			status_id = $9,
			recurrence_rule = $10,
			recurrence_end = $11,
			metadata = $12,
			updated_at = NOW()
		WHERE schedule_id = $1 AND deleted_at IS NULL
		RETURNING updated_at
	`
	err := db.QueryRowContext(ctx, query,
		schedule.ScheduleID,
		schedule.SubscriptionID,
		schedule.ScheduleTypeID,
		schedule.Title,
		schedule.Description,
		schedule.StartTime,
		schedule.EndTime,
		schedule.Location,
		schedule.StatusID,
		schedule.RecurrenceRule,
		schedule.RecurrenceEnd,
		schedule.Metadata,
	).Scan(&schedule.UpdatedAt)
	if err != nil {
		if err == sql.ErrNoRows {
			return errors.ErrNotFound
		}
		return fmt.Errorf("update schedule: %w", err)
	}
	return nil
}

func (r *scheduleRepository) Delete(ctx context.Context, db DBTX, companyID, scheduleID uuid.UUID) error {
	query := `
		UPDATE subscription.schedules s
		SET deleted_at = NOW()
		FROM subscription.subscriptions sub
		WHERE s.subscription_id = sub.subscription_id
		AND sub.company_id = $1
		AND s.schedule_id = $2
		AND s.deleted_at IS NULL
	`
	result, err := db.ExecContext(ctx, query, companyID, scheduleID)
	if err != nil {
		return fmt.Errorf("soft delete schedule: %w", err)
	}
	rows, _ := result.RowsAffected()
	if rows == 0 {
		return errors.ErrNotFound
	}
	return nil
}

func (r *scheduleRepository) GetByID(ctx context.Context, db DBTX, companyID, scheduleID uuid.UUID) (*models.Schedule, error) {
	query := `
		SELECT s.schedule_id, s.subscription_id, s.schedule_type_id, s.title,
			s.description, s.start_time, s.end_time, s.location,
			s.status_id, s.recurrence_rule, s.recurrence_end, s.metadata,
			s.created_at, s.updated_at, s.deleted_at
		FROM subscription.schedules s
		JOIN subscription.subscriptions sub ON s.subscription_id = sub.subscription_id
		WHERE s.schedule_id = $1 AND sub.company_id = $2 AND s.deleted_at IS NULL
	`
	row := db.QueryRowContext(ctx, query, scheduleID, companyID)
	return r.scanSchedule(row)
}

func (r *scheduleRepository) GetBySubscription(ctx context.Context, db DBTX, companyID, subscriptionID uuid.UUID) ([]*models.Schedule, error) {
	query := `
		SELECT s.schedule_id, s.subscription_id, s.schedule_type_id, s.title,
			s.description, s.start_time, s.end_time, s.location,
			s.status_id, s.recurrence_rule, s.recurrence_end, s.metadata,
			s.created_at, s.updated_at, s.deleted_at
		FROM subscription.schedules s
		JOIN subscription.subscriptions sub ON s.subscription_id = sub.subscription_id
		WHERE sub.company_id = $1 AND s.subscription_id = $2 AND s.deleted_at IS NULL
		ORDER BY s.start_time
	`
	rows, err := db.QueryContext(ctx, query, companyID, subscriptionID)
	if err != nil {
		return nil, fmt.Errorf("get schedules by subscription: %w", err)
	}
	defer rows.Close()
	var result []*models.Schedule
	for rows.Next() {
		sch, err := r.scanSchedule(rows)
		if err != nil {
			return nil, err
		}
		result = append(result, sch)
	}
	return result, rows.Err()
}

func (r *scheduleRepository) GetByResource(ctx context.Context, db DBTX, companyID uuid.UUID, resourceType string, resourceID uuid.UUID) ([]*models.Schedule, error) {
	query := `
		SELECT s.schedule_id, s.subscription_id, s.schedule_type_id, s.title,
			s.description, s.start_time, s.end_time, s.location,
			s.status_id, s.recurrence_rule, s.recurrence_end, s.metadata,
			s.created_at, s.updated_at, s.deleted_at
		FROM subscription.schedules s
		JOIN subscription.subscriptions sub ON s.subscription_id = sub.subscription_id
		JOIN subscription.resource_assignments ra ON ra.subscription_id = sub.subscription_id
		WHERE sub.company_id = $1
		AND ra.resource_type = $2
		AND ra.resource_id = $3
		AND s.deleted_at IS NULL
		ORDER BY s.start_time
	`
	rows, err := db.QueryContext(ctx, query, companyID, resourceType, resourceID)
	if err != nil {
		return nil, fmt.Errorf("get schedules by resource: %w", err)
	}
	defer rows.Close()
	var result []*models.Schedule
	for rows.Next() {
		sch, err := r.scanSchedule(rows)
		if err != nil {
			return nil, err
		}
		result = append(result, sch)
	}
	return result, rows.Err()
}

func (r *scheduleRepository) List(ctx context.Context, db DBTX, filter ScheduleFilter, p Pagination, s Sort) ([]*models.Schedule, int64, error) {
	// Build FROM and JOINs
	from := "subscription.schedules s"
	joins := []string{"JOIN subscription.subscriptions sub ON s.subscription_id = sub.subscription_id"}
	whereCond := "sub.company_id = $1"
	args := []interface{}{filter.CompanyID}
	idx := 2

	if len(filter.ScheduleIDs) > 0 {
		placeholders := make([]string, len(filter.ScheduleIDs))
		for i, id := range filter.ScheduleIDs {
			placeholders[i] = fmt.Sprintf("$%d", idx)
			args = append(args, id)
			idx++
		}
		whereCond += fmt.Sprintf(" AND s.schedule_id IN (%s)", strings.Join(placeholders, ","))
	}
	if filter.SubscriptionID != nil {
		whereCond += fmt.Sprintf(" AND s.subscription_id = $%d", idx)
		args = append(args, *filter.SubscriptionID)
		idx++
	}
	if filter.StatusID != nil {
		whereCond += fmt.Sprintf(" AND s.status_id = $%d", idx)
		args = append(args, *filter.StatusID)
		idx++
	}
	if filter.ScheduleTypeID != nil {
		whereCond += fmt.Sprintf(" AND s.schedule_type_id = $%d", idx)
		args = append(args, *filter.ScheduleTypeID)
		idx++
	}
	if filter.ResourceType != nil {
		joins = append(joins, "JOIN subscription.resource_assignments ra ON ra.subscription_id = sub.subscription_id")
		whereCond += fmt.Sprintf(" AND ra.resource_type = $%d", idx)
		args = append(args, *filter.ResourceType)
		idx++
	}
	if filter.StartFrom != nil {
		whereCond += fmt.Sprintf(" AND s.start_time >= $%d", idx)
		args = append(args, *filter.StartFrom)
		idx++
	}
	if filter.StartTo != nil {
		whereCond += fmt.Sprintf(" AND s.start_time <= $%d", idx)
		args = append(args, *filter.StartTo)
		idx++
	}
	if filter.EndFrom != nil {
		whereCond += fmt.Sprintf(" AND s.end_time >= $%d", idx)
		args = append(args, *filter.EndFrom)
		idx++
	}
	if filter.EndTo != nil {
		whereCond += fmt.Sprintf(" AND s.end_time <= $%d", idx)
		args = append(args, *filter.EndTo)
		idx++
	}
	whereCond += " AND s.deleted_at IS NULL"

	fullFrom := from + " " + strings.Join(joins, " ")
	whereClause := "WHERE " + whereCond

	orderBy, err := validateSort(s, scheduleAllowedSort)
	if err != nil {
		return nil, 0, err
	}
	if orderBy == "" {
		orderBy = "ORDER BY s.start_time ASC"
	}

	limit, offset := validatePagination(p)

	// Count
	countQuery := fmt.Sprintf("SELECT COUNT(*) FROM %s %s", fullFrom, whereClause)
	var total int64
	if err := db.QueryRowContext(ctx, countQuery, args...).Scan(&total); err != nil {
		return nil, 0, fmt.Errorf("count schedules: %w", err)
	}
	if total == 0 {
		return []*models.Schedule{}, 0, nil
	}

	// Data
	query := fmt.Sprintf(`
		SELECT s.schedule_id, s.subscription_id, s.schedule_type_id, s.title,
			s.description, s.start_time, s.end_time, s.location,
			s.status_id, s.recurrence_rule, s.recurrence_end, s.metadata,
			s.created_at, s.updated_at, s.deleted_at
		FROM %s
		%s
		%s
		LIMIT $%d OFFSET $%d
	`, fullFrom, whereClause, orderBy, idx, idx+1)
	args = append(args, limit, offset)

	rows, err := db.QueryContext(ctx, query, args...)
	if err != nil {
		return nil, 0, fmt.Errorf("list schedules: %w", err)
	}
	defer rows.Close()
	var result []*models.Schedule
	for rows.Next() {
		sch, err := r.scanSchedule(rows)
		if err != nil {
			return nil, 0, err
		}
		result = append(result, sch)
	}
	return result, total, rows.Err()
}

func (r *scheduleRepository) ListUpcoming(ctx context.Context, db DBTX, companyID uuid.UUID) ([]*models.Schedule, error) {
	now := time.Now()
	filter := ScheduleFilter{
		CompanyID: companyID,
		StartFrom: &now,
	}
	filter.StatusID = ptrInt16(1) // active
	schedules, _, err := r.List(ctx, db, filter, Pagination{Limit: 100}, Sort{Field: "start_time", Direction: "ASC"})
	return schedules, err
}

func (r *scheduleRepository) ListToday(ctx context.Context, db DBTX, companyID uuid.UUID) ([]*models.Schedule, error) {
	now := time.Now()
	startOfDay := time.Date(now.Year(), now.Month(), now.Day(), 0, 0, 0, 0, now.Location())
	endOfDay := startOfDay.Add(24 * time.Hour)
	filter := ScheduleFilter{
		CompanyID: companyID,
		StartFrom: &startOfDay,
		StartTo:   &endOfDay,
	}
	schedules, _, err := r.List(ctx, db, filter, Pagination{Limit: 500}, Sort{Field: "start_time", Direction: "ASC"})
	return schedules, err
}

func (r *scheduleRepository) ListActive(ctx context.Context, db DBTX, companyID uuid.UUID) ([]*models.Schedule, error) {
	filter := ScheduleFilter{
		CompanyID: companyID,
		StatusID:  ptrInt16(1),
	}
	schedules, _, err := r.List(ctx, db, filter, Pagination{Limit: 1000}, Sort{Field: "start_time", Direction: "ASC"})
	return schedules, err
}

func (r *scheduleRepository) UpdateCapacity(ctx context.Context, db DBTX, companyID, scheduleID uuid.UUID, capacity int) error {
	query := `
		UPDATE subscription.schedules s
		SET metadata = jsonb_set(COALESCE(metadata, '{}'::jsonb), '{capacity}', $3::jsonb),
			updated_at = NOW()
		FROM subscription.subscriptions sub
		WHERE s.subscription_id = sub.subscription_id
		AND sub.company_id = $1
		AND s.schedule_id = $2
		AND s.deleted_at IS NULL
	`
	_, err := db.ExecContext(ctx, query, companyID, scheduleID, fmt.Sprintf("%d", capacity))
	if err != nil {
		return fmt.Errorf("update capacity: %w", err)
	}
	return nil
}

func (r *scheduleRepository) IncrementBookedSeats(ctx context.Context, db DBTX, companyID, scheduleID uuid.UUID) error {
	query := `
		UPDATE subscription.schedules s
		SET metadata = jsonb_set(COALESCE(metadata, '{}'::jsonb), '{booked_seats}', 
			COALESCE((metadata->>'booked_seats')::int, 0) + 1),
			updated_at = NOW()
		FROM subscription.subscriptions sub
		WHERE s.subscription_id = sub.subscription_id
		AND sub.company_id = $1
		AND s.schedule_id = $2
		AND s.deleted_at IS NULL
	`
	_, err := db.ExecContext(ctx, query, companyID, scheduleID)
	if err != nil {
		return fmt.Errorf("increment booked seats: %w", err)
	}
	return nil
}

func (r *scheduleRepository) DecrementBookedSeats(ctx context.Context, db DBTX, companyID, scheduleID uuid.UUID) error {
	query := `
		UPDATE subscription.schedules s
		SET metadata = jsonb_set(COALESCE(metadata, '{}'::jsonb), '{booked_seats}', 
			GREATEST(COALESCE((metadata->>'booked_seats')::int, 0) - 1, 0)),
			updated_at = NOW()
		FROM subscription.subscriptions sub
		WHERE s.subscription_id = sub.subscription_id
		AND sub.company_id = $1
		AND s.schedule_id = $2
		AND s.deleted_at IS NULL
	`
	_, err := db.ExecContext(ctx, query, companyID, scheduleID)
	if err != nil {
		return fmt.Errorf("decrement booked seats: %w", err)
	}
	return nil
}

func (r *scheduleRepository) IsFull(ctx context.Context, db DBTX, companyID, scheduleID uuid.UUID) (bool, error) {
	var capacity, booked int
	query := `
		SELECT COALESCE((metadata->>'capacity')::int, 0) AS capacity,
			COALESCE((metadata->>'booked_seats')::int, 0) AS booked
		FROM subscription.schedules s
		JOIN subscription.subscriptions sub ON s.subscription_id = sub.subscription_id
		WHERE sub.company_id = $1 AND s.schedule_id = $2 AND s.deleted_at IS NULL
	`
	err := db.QueryRowContext(ctx, query, companyID, scheduleID).Scan(&capacity, &booked)
	if err != nil {
		if err == sql.ErrNoRows {
			return false, errors.ErrNotFound
		}
		return false, fmt.Errorf("check full: %w", err)
	}
	return capacity > 0 && booked >= capacity, nil
}

func (r *scheduleRepository) UpdateStatus(ctx context.Context, db DBTX, companyID, scheduleID uuid.UUID, statusID int16) error {
	query := `
		UPDATE subscription.schedules s
		SET status_id = $3, updated_at = NOW()
		FROM subscription.subscriptions sub
		WHERE s.subscription_id = sub.subscription_id
		AND sub.company_id = $1
		AND s.schedule_id = $2
		AND s.deleted_at IS NULL
	`
	result, err := db.ExecContext(ctx, query, companyID, scheduleID, statusID)
	if err != nil {
		return fmt.Errorf("update status: %w", err)
	}
	rows, _ := result.RowsAffected()
	if rows == 0 {
		return errors.ErrNotFound
	}
	return nil
}

func (r *scheduleRepository) Start(ctx context.Context, db DBTX, companyID, scheduleID uuid.UUID) error {
	return r.UpdateStatus(ctx, db, companyID, scheduleID, 2) // ongoing
}

func (r *scheduleRepository) Complete(ctx context.Context, db DBTX, companyID, scheduleID uuid.UUID) error {
	return r.UpdateStatus(ctx, db, companyID, scheduleID, 3) // completed
}

func (r *scheduleRepository) Cancel(ctx context.Context, db DBTX, companyID, scheduleID uuid.UUID) error {
	return r.UpdateStatus(ctx, db, companyID, scheduleID, 4) // cancelled
}

func (r *scheduleRepository) Exists(ctx context.Context, db DBTX, companyID, scheduleID uuid.UUID) (bool, error) {
	var exists bool
	query := `
		SELECT EXISTS(
			SELECT 1 FROM subscription.schedules s
			JOIN subscription.subscriptions sub ON s.subscription_id = sub.subscription_id
			WHERE s.schedule_id = $1 AND sub.company_id = $2 AND s.deleted_at IS NULL
		)
	`
	err := db.QueryRowContext(ctx, query, scheduleID, companyID).Scan(&exists)
	return exists, err
}

func (r *scheduleRepository) Search(ctx context.Context, db DBTX, companyID uuid.UUID, query string, limit, offset int) ([]*models.Schedule, int64, error) {
	pattern := "%" + query + "%"
	where := `
		JOIN subscription.subscriptions sub ON s.subscription_id = sub.subscription_id
		WHERE sub.company_id = $1
		AND s.deleted_at IS NULL
		AND (s.title ILIKE $2 OR s.description ILIKE $2)
	`
	args := []interface{}{companyID, pattern}
	countQuery := fmt.Sprintf("SELECT COUNT(*) FROM subscription.schedules s %s", where)
	var total int64
	err := db.QueryRowContext(ctx, countQuery, args...).Scan(&total)
	if err != nil {
		return nil, 0, fmt.Errorf("search schedules count: %w", err)
	}
	if total == 0 {
		return []*models.Schedule{}, 0, nil
	}
	baseQuery := `
		SELECT s.schedule_id, s.subscription_id, s.schedule_type_id, s.title,
			s.description, s.start_time, s.end_time, s.location,
			s.status_id, s.recurrence_rule, s.recurrence_end, s.metadata,
			s.created_at, s.updated_at, s.deleted_at
		FROM subscription.schedules s
	`
	querySQL := fmt.Sprintf(`%s %s ORDER BY s.start_time LIMIT $%d OFFSET $%d`, baseQuery, where, len(args)+1, len(args)+2)
	args = append(args, limit, offset)
	rows, err := db.QueryContext(ctx, querySQL, args...)
	if err != nil {
		return nil, 0, fmt.Errorf("search schedules: %w", err)
	}
	defer rows.Close()
	var result []*models.Schedule
	for rows.Next() {
		sch, err := r.scanSchedule(rows)
		if err != nil {
			return nil, 0, err
		}
		result = append(result, sch)
	}
	return result, total, rows.Err()
}

func (r *scheduleRepository) GetByIDForUpdate(ctx context.Context, db DBTX, companyID, scheduleID uuid.UUID) (*models.Schedule, error) {
	query := `
		SELECT s.schedule_id, s.subscription_id, s.schedule_type_id, s.title,
			s.description, s.start_time, s.end_time, s.location,
			s.status_id, s.recurrence_rule, s.recurrence_end, s.metadata,
			s.created_at, s.updated_at, s.deleted_at
		FROM subscription.schedules s
		JOIN subscription.subscriptions sub ON s.subscription_id = sub.subscription_id
		WHERE s.schedule_id = $1 AND sub.company_id = $2 AND s.deleted_at IS NULL
		FOR UPDATE
	`
	row := db.QueryRowContext(ctx, query, scheduleID, companyID)
	return r.scanSchedule(row)
}

// Helper
func ptrInt16(v int16) *int16 {
	return &v
}

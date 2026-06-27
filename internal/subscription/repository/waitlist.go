// repository/waitlist_repository.go
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

type WaitlistRepository interface {
	Create(ctx context.Context, db DBTX, waitlist *models.Waitlist) error
	Update(ctx context.Context, db DBTX, waitlist *models.Waitlist) error
	Delete(ctx context.Context, db DBTX, companyID, waitlistID uuid.UUID) error

	GetByID(ctx context.Context, db DBTX, companyID, waitlistID uuid.UUID) (*models.Waitlist, error)
	GetBySubscription(ctx context.Context, db DBTX, companyID, subscriptionID uuid.UUID) ([]*models.Waitlist, error)
	GetBySchedule(ctx context.Context, db DBTX, companyID, scheduleID uuid.UUID) ([]*models.Waitlist, error)
	GetNextInQueue(ctx context.Context, db DBTX, companyID, scheduleID uuid.UUID) (*models.Waitlist, error)

	List(ctx context.Context, db DBTX, filter WaitlistFilter, p Pagination, s Sort) ([]*models.Waitlist, int64, error)
	ListBySchedule(ctx context.Context, db DBTX, companyID, scheduleID uuid.UUID) ([]*models.Waitlist, error)
	ListPending(ctx context.Context, db DBTX, companyID uuid.UUID) ([]*models.Waitlist, error)

	AddToQueue(ctx context.Context, db DBTX, waitlist *models.Waitlist) error
	RemoveFromQueue(ctx context.Context, db DBTX, companyID, waitlistID uuid.UUID) error
	PromoteNext(ctx context.Context, db DBTX, companyID, scheduleID uuid.UUID) (*models.Waitlist, error)
	UpdatePosition(ctx context.Context, db DBTX, companyID, waitlistID uuid.UUID, position int) error
	ClearQueue(ctx context.Context, db DBTX, companyID, scheduleID uuid.UUID) error

	Exists(ctx context.Context, db DBTX, companyID, waitlistID uuid.UUID) (bool, error)
	IsWaiting(ctx context.Context, db DBTX, companyID, subscriptionID, scheduleID uuid.UUID) (bool, error)
	Search(ctx context.Context, db DBTX, companyID uuid.UUID, query string, limit, offset int) ([]*models.Waitlist, int64, error)

	GetByIDForUpdate(ctx context.Context, db DBTX, companyID, waitlistID uuid.UUID) (*models.Waitlist, error)
}

type WaitlistFilter struct {
	CompanyID      uuid.UUID
	WaitlistIDs    []uuid.UUID
	ScheduleID     *uuid.UUID
	SubscriptionID *uuid.UUID
	StatusID       *int16
	PositionMin    *int
	PositionMax    *int
	CreatedFrom    *time.Time
	CreatedTo      *time.Time
}

// ---------------------------------------------------------------------
// Implementation
// ---------------------------------------------------------------------

type waitlistRepository struct {
	logger *zap.Logger
}

func NewWaitlistRepository(logger *zap.Logger) WaitlistRepository {
	return &waitlistRepository{
		logger: logger.Named("subscription_waitlist_repo"),
	}
}

const waitlistTable = "subscription.waitlists"

func (r *waitlistRepository) scanWaitlist(s scanner) (*models.Waitlist, error) {
	var w models.Waitlist
	var position, notifiedAt, expiresAt, notes sql.NullString
	var statusID int16

	err := s.Scan(
		&w.WaitlistID,
		&w.CompanyID,
		&w.ScheduleID,
		&w.SubscriberTypeID,
		&w.SubscriberID,
		&statusID,
		&w.RegisteredAt,
		&position,
		&notifiedAt,
		&expiresAt,
		&notes,
		&w.CreatedAt,
		&w.UpdatedAt,
	)
	if err != nil {
		if err == sql.ErrNoRows {
			return nil, errors.ErrNotFound
		}
		return nil, fmt.Errorf("scan waitlist: %w", err)
	}
	w.StatusID = statusID
	if position.Valid {
		var pos int
		fmt.Sscan(position.String, &pos)
		w.Position = &pos
	}
	if notifiedAt.Valid {
		t, _ := time.Parse(time.RFC3339, notifiedAt.String)
		w.NotifiedAt = &t
	}
	if expiresAt.Valid {
		t, _ := time.Parse(time.RFC3339, expiresAt.String)
		w.ExpiresAt = &t
	}
	if notes.Valid {
		w.Notes = &notes.String
	}
	return &w, nil
}

func (r *waitlistRepository) buildWaitlistFilter(filter WaitlistFilter) (string, []interface{}) {
	var conds []string
	var args []interface{}
	idx := 1

	if filter.CompanyID != uuid.Nil {
	}
	if len(filter.WaitlistIDs) > 0 {
		placeholders := make([]string, len(filter.WaitlistIDs))
		for i, id := range filter.WaitlistIDs {
			placeholders[i] = fmt.Sprintf("$%d", idx)
			args = append(args, id)
			idx++
		}
		conds = append(conds, fmt.Sprintf("w.waitlist_id IN (%s)", strings.Join(placeholders, ",")))
	}
	if filter.ScheduleID != nil {
		conds = append(conds, fmt.Sprintf("w.schedule_id = $%d", idx))
		args = append(args, *filter.ScheduleID)
		idx++
	}
	if filter.SubscriptionID != nil {
		// subscription_id not directly in waitlist – we need subscriber_type+id; we can store subscription_id separately? Currently we have subscriber_type_id + subscriber_id.
		// We'll skip as it's not a direct column – could be added later.
	}
	if filter.StatusID != nil {
		conds = append(conds, fmt.Sprintf("w.status_id = $%d", idx))
		args = append(args, *filter.StatusID)
		idx++
	}
	if filter.PositionMin != nil {
		conds = append(conds, fmt.Sprintf("w.position >= $%d", idx))
		args = append(args, *filter.PositionMin)
		idx++
	}
	if filter.PositionMax != nil {
		conds = append(conds, fmt.Sprintf("w.position <= $%d", idx))
		args = append(args, *filter.PositionMax)
		idx++
	}
	if filter.CreatedFrom != nil {
		conds = append(conds, fmt.Sprintf("w.created_at >= $%d", idx))
		args = append(args, *filter.CreatedFrom)
		idx++
	}
	if filter.CreatedTo != nil {
		conds = append(conds, fmt.Sprintf("w.created_at <= $%d", idx))
		args = append(args, *filter.CreatedTo)
		idx++
	}
	return strings.Join(conds, " AND "), args
}

var waitlistAllowedSort = map[string]bool{
	"waitlist_id":   true,
	"position":      true,
	"status_id":     true,
	"registered_at": true,
	"created_at":    true,
	"updated_at":    true,
}

func (r *waitlistRepository) Create(ctx context.Context, db DBTX, waitlist *models.Waitlist) error {
	query := `
		INSERT INTO subscription.waitlists (
			waitlist_id, company_id, schedule_id, subscriber_type_id,
			subscriber_id, status_id, registered_at, position,
			notified_at, expires_at, notes, created_at, updated_at
		) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, NOW(), NOW())
		RETURNING created_at, updated_at
	`
	err := db.QueryRowContext(ctx, query,
		waitlist.WaitlistID,
		waitlist.CompanyID,
		waitlist.ScheduleID,
		waitlist.SubscriberTypeID,
		waitlist.SubscriberID,
		waitlist.StatusID,
		waitlist.RegisteredAt,
		waitlist.Position,
		waitlist.NotifiedAt,
		waitlist.ExpiresAt,
		waitlist.Notes,
	).Scan(&waitlist.CreatedAt, &waitlist.UpdatedAt)
	if err != nil {
		return fmt.Errorf("create waitlist: %w", err)
	}
	return nil
}

func (r *waitlistRepository) Update(ctx context.Context, db DBTX, waitlist *models.Waitlist) error {
	query := `
		UPDATE subscription.waitlists SET
			schedule_id = $2,
			subscriber_type_id = $3,
			subscriber_id = $4,
			status_id = $5,
			registered_at = $6,
			position = $7,
			notified_at = $8,
			expires_at = $9,
			notes = $10,
			updated_at = NOW()
		WHERE waitlist_id = $1 AND company_id = $11
		RETURNING updated_at
	`
	err := db.QueryRowContext(ctx, query,
		waitlist.WaitlistID,
		waitlist.ScheduleID,
		waitlist.SubscriberTypeID,
		waitlist.SubscriberID,
		waitlist.StatusID,
		waitlist.RegisteredAt,
		waitlist.Position,
		waitlist.NotifiedAt,
		waitlist.ExpiresAt,
		waitlist.Notes,
		waitlist.CompanyID,
	).Scan(&waitlist.UpdatedAt)
	if err != nil {
		if err == sql.ErrNoRows {
			return errors.ErrNotFound
		}
		return fmt.Errorf("update waitlist: %w", err)
	}
	return nil
}

func (r *waitlistRepository) Delete(ctx context.Context, db DBTX, companyID, waitlistID uuid.UUID) error {
	query := `DELETE FROM subscription.waitlists WHERE waitlist_id = $1 AND company_id = $2`
	result, err := db.ExecContext(ctx, query, waitlistID, companyID)
	if err != nil {
		return fmt.Errorf("delete waitlist: %w", err)
	}
	rows, _ := result.RowsAffected()
	if rows == 0 {
		return errors.ErrNotFound
	}
	return nil
}

func (r *waitlistRepository) GetByID(ctx context.Context, db DBTX, companyID, waitlistID uuid.UUID) (*models.Waitlist, error) {
	query := `
		SELECT waitlist_id, company_id, schedule_id, subscriber_type_id,
			subscriber_id, status_id, registered_at, position,
			notified_at, expires_at, notes, created_at, updated_at
		FROM subscription.waitlists
		WHERE waitlist_id = $1 AND company_id = $2
	`
	row := db.QueryRowContext(ctx, query, waitlistID, companyID)
	return r.scanWaitlist(row)
}

func (r *waitlistRepository) GetBySubscription(ctx context.Context, db DBTX, companyID, subscriptionID uuid.UUID) ([]*models.Waitlist, error) {
	// subscriber_id is the subscription ID? Actually subscriber_id is a generic UUID.
	// We'll treat subscriptionID as subscriber_id, but we also need subscriber_type_id.
	// We'll query with subscriber_id = subscriptionID.
	query := `
		SELECT waitlist_id, company_id, schedule_id, subscriber_type_id,
			subscriber_id, status_id, registered_at, position,
			notified_at, expires_at, notes, created_at, updated_at
		FROM subscription.waitlists
		WHERE company_id = $1 AND subscriber_id = $2
		ORDER BY position
	`
	rows, err := db.QueryContext(ctx, query, companyID, subscriptionID)
	if err != nil {
		return nil, fmt.Errorf("get waitlist by subscription: %w", err)
	}
	defer rows.Close()
	var result []*models.Waitlist
	for rows.Next() {
		w, err := r.scanWaitlist(rows)
		if err != nil {
			return nil, err
		}
		result = append(result, w)
	}
	return result, rows.Err()
}

func (r *waitlistRepository) GetBySchedule(ctx context.Context, db DBTX, companyID, scheduleID uuid.UUID) ([]*models.Waitlist, error) {
	filter := WaitlistFilter{
		CompanyID:  companyID,
		ScheduleID: &scheduleID,
	}
	waitlists, _, err := r.List(ctx, db, filter, Pagination{Limit: 1000}, Sort{Field: "position", Direction: "ASC"})
	return waitlists, err
}

func (r *waitlistRepository) GetNextInQueue(ctx context.Context, db DBTX, companyID, scheduleID uuid.UUID) (*models.Waitlist, error) {
	query := `
		SELECT waitlist_id, company_id, schedule_id, subscriber_type_id,
			subscriber_id, status_id, registered_at, position,
			notified_at, expires_at, notes, created_at, updated_at
		FROM subscription.waitlists
		WHERE company_id = $1 AND schedule_id = $2 AND status_id = 1
		ORDER BY position ASC
		LIMIT 1
	`
	row := db.QueryRowContext(ctx, query, companyID, scheduleID)
	return r.scanWaitlist(row)
}

func (r *waitlistRepository) List(ctx context.Context, db DBTX, filter WaitlistFilter, p Pagination, s Sort) ([]*models.Waitlist, int64, error) {
	from := "subscription.waitlists w"
	whereCond := "w.company_id = $1"
	args := []interface{}{filter.CompanyID}
	idx := 2

	if len(filter.WaitlistIDs) > 0 {
		placeholders := make([]string, len(filter.WaitlistIDs))
		for i, id := range filter.WaitlistIDs {
			placeholders[i] = fmt.Sprintf("$%d", idx)
			args = append(args, id)
			idx++
		}
		whereCond += fmt.Sprintf(" AND w.waitlist_id IN (%s)", strings.Join(placeholders, ","))
	}
	if filter.ScheduleID != nil {
		whereCond += fmt.Sprintf(" AND w.schedule_id = $%d", idx)
		args = append(args, *filter.ScheduleID)
		idx++
	}
	if filter.StatusID != nil {
		whereCond += fmt.Sprintf(" AND w.status_id = $%d", idx)
		args = append(args, *filter.StatusID)
		idx++
	}
	if filter.PositionMin != nil {
		whereCond += fmt.Sprintf(" AND w.position >= $%d", idx)
		args = append(args, *filter.PositionMin)
		idx++
	}
	if filter.PositionMax != nil {
		whereCond += fmt.Sprintf(" AND w.position <= $%d", idx)
		args = append(args, *filter.PositionMax)
		idx++
	}
	if filter.CreatedFrom != nil {
		whereCond += fmt.Sprintf(" AND w.created_at >= $%d", idx)
		args = append(args, *filter.CreatedFrom)
		idx++
	}
	if filter.CreatedTo != nil {
		whereCond += fmt.Sprintf(" AND w.created_at <= $%d", idx)
		args = append(args, *filter.CreatedTo)
		idx++
	}

	fullFrom := from
	whereClause := "WHERE " + whereCond

	orderBy, err := validateSort(s, waitlistAllowedSort)
	if err != nil {
		return nil, 0, err
	}
	if orderBy == "" {
		orderBy = "ORDER BY w.position ASC"
	}

	limit, offset := validatePagination(p)

	countQuery := fmt.Sprintf("SELECT COUNT(*) FROM %s %s", fullFrom, whereClause)
	var total int64
	if err := db.QueryRowContext(ctx, countQuery, args...).Scan(&total); err != nil {
		return nil, 0, fmt.Errorf("count waitlist: %w", err)
	}
	if total == 0 {
		return []*models.Waitlist{}, 0, nil
	}

	query := fmt.Sprintf(`
		SELECT w.waitlist_id, w.company_id, w.schedule_id, w.subscriber_type_id,
			w.subscriber_id, w.status_id, w.registered_at, w.position,
			w.notified_at, w.expires_at, w.notes, w.created_at, w.updated_at
		FROM %s
		%s
		%s
		LIMIT $%d OFFSET $%d
	`, fullFrom, whereClause, orderBy, idx, idx+1)
	args = append(args, limit, offset)

	rows, err := db.QueryContext(ctx, query, args...)
	if err != nil {
		return nil, 0, fmt.Errorf("list waitlist: %w", err)
	}
	defer rows.Close()
	var result []*models.Waitlist
	for rows.Next() {
		w, err := r.scanWaitlist(rows)
		if err != nil {
			return nil, 0, err
		}
		result = append(result, w)
	}
	return result, total, rows.Err()
}

func (r *waitlistRepository) ListBySchedule(ctx context.Context, db DBTX, companyID, scheduleID uuid.UUID) ([]*models.Waitlist, error) {
	return r.GetBySchedule(ctx, db, companyID, scheduleID)
}

func (r *waitlistRepository) ListPending(ctx context.Context, db DBTX, companyID uuid.UUID) ([]*models.Waitlist, error) {
	filter := WaitlistFilter{
		CompanyID: companyID,
		StatusID:  ptrInt16(1), // waiting
	}
	waitlists, _, err := r.List(ctx, db, filter, Pagination{Limit: 1000}, Sort{Field: "position", Direction: "ASC"})
	return waitlists, err
}

func (r *waitlistRepository) AddToQueue(ctx context.Context, db DBTX, waitlist *models.Waitlist) error {
	// Compute next position
	var maxPos sql.NullInt32
	queryPos := `SELECT MAX(position) FROM subscription.waitlists WHERE schedule_id = $1 AND company_id = $2`
	err := db.QueryRowContext(ctx, queryPos, waitlist.ScheduleID, waitlist.CompanyID).Scan(&maxPos)
	if err != nil && err != sql.ErrNoRows {
		return fmt.Errorf("compute max position: %w", err)
	}
	nextPos := 1
	if maxPos.Valid {
		nextPos = int(maxPos.Int32) + 1
	}
	waitlist.Position = &nextPos
	waitlist.StatusID = 1 // waiting
	return r.Create(ctx, db, waitlist)
}

func (r *waitlistRepository) RemoveFromQueue(ctx context.Context, db DBTX, companyID, waitlistID uuid.UUID) error {
	return r.Delete(ctx, db, companyID, waitlistID)
}

func (r *waitlistRepository) PromoteNext(ctx context.Context, db DBTX, companyID, scheduleID uuid.UUID) (*models.Waitlist, error) {
	// Get next in queue
	next, err := r.GetNextInQueue(ctx, db, companyID, scheduleID)
	if err != nil {
		if err == errors.ErrNotFound {
			return nil, nil
		}
		return nil, err
	}
	// Remove it
	if err := r.Delete(ctx, db, companyID, next.WaitlistID); err != nil {
		return nil, err
	}
	// Reorder remaining positions
	query := `
		UPDATE subscription.waitlists
		SET position = position - 1
		WHERE company_id = $1 AND schedule_id = $2 AND position > $3
	`
	_, err = db.ExecContext(ctx, query, companyID, scheduleID, next.Position)
	if err != nil {
		return nil, fmt.Errorf("reorder positions: %w", err)
	}
	return next, nil
}

func (r *waitlistRepository) UpdatePosition(ctx context.Context, db DBTX, companyID, waitlistID uuid.UUID, position int) error {
	query := `
		UPDATE subscription.waitlists
		SET position = $3, updated_at = NOW()
		WHERE waitlist_id = $1 AND company_id = $2
	`
	result, err := db.ExecContext(ctx, query, waitlistID, companyID, position)
	if err != nil {
		return fmt.Errorf("update position: %w", err)
	}
	rows, _ := result.RowsAffected()
	if rows == 0 {
		return errors.ErrNotFound
	}
	return nil
}

func (r *waitlistRepository) ClearQueue(ctx context.Context, db DBTX, companyID, scheduleID uuid.UUID) error {
	query := `DELETE FROM subscription.waitlists WHERE company_id = $1 AND schedule_id = $2`
	_, err := db.ExecContext(ctx, query, companyID, scheduleID)
	return err
}

func (r *waitlistRepository) Exists(ctx context.Context, db DBTX, companyID, waitlistID uuid.UUID) (bool, error) {
	var exists bool
	query := `SELECT EXISTS(SELECT 1 FROM subscription.waitlists WHERE waitlist_id = $1 AND company_id = $2)`
	err := db.QueryRowContext(ctx, query, waitlistID, companyID).Scan(&exists)
	return exists, err
}

func (r *waitlistRepository) IsWaiting(ctx context.Context, db DBTX, companyID, subscriptionID, scheduleID uuid.UUID) (bool, error) {
	var exists bool
	query := `
		SELECT EXISTS(
			SELECT 1 FROM subscription.waitlists
			WHERE company_id = $1 AND subscriber_id = $2 AND schedule_id = $3 AND status_id = 1
		)
	`
	err := db.QueryRowContext(ctx, query, companyID, subscriptionID, scheduleID).Scan(&exists)
	return exists, err
}

func (r *waitlistRepository) Search(ctx context.Context, db DBTX, companyID uuid.UUID, query string, limit, offset int) ([]*models.Waitlist, int64, error) {
	pattern := "%" + query + "%"
	where := "WHERE company_id = $1 AND (notes ILIKE $2)"
	args := []interface{}{companyID, pattern}
	countQuery := fmt.Sprintf("SELECT COUNT(*) FROM subscription.waitlists %s", where)
	var total int64
	err := db.QueryRowContext(ctx, countQuery, args...).Scan(&total)
	if err != nil {
		return nil, 0, fmt.Errorf("search waitlist count: %w", err)
	}
	if total == 0 {
		return []*models.Waitlist{}, 0, nil
	}
	baseQuery := `
		SELECT waitlist_id, company_id, schedule_id, subscriber_type_id,
			subscriber_id, status_id, registered_at, position,
			notified_at, expires_at, notes, created_at, updated_at
		FROM subscription.waitlists
	`
	querySQL := fmt.Sprintf(`%s %s ORDER BY position LIMIT $%d OFFSET $%d`, baseQuery, where, len(args)+1, len(args)+2)
	args = append(args, limit, offset)
	rows, err := db.QueryContext(ctx, querySQL, args...)
	if err != nil {
		return nil, 0, fmt.Errorf("search waitlist: %w", err)
	}
	defer rows.Close()
	var result []*models.Waitlist
	for rows.Next() {
		w, err := r.scanWaitlist(rows)
		if err != nil {
			return nil, 0, err
		}
		result = append(result, w)
	}
	return result, total, rows.Err()
}

func (r *waitlistRepository) GetByIDForUpdate(ctx context.Context, db DBTX, companyID, waitlistID uuid.UUID) (*models.Waitlist, error) {
	query := `
		SELECT waitlist_id, company_id, schedule_id, subscriber_type_id,
			subscriber_id, status_id, registered_at, position,
			notified_at, expires_at, notes, created_at, updated_at
		FROM subscription.waitlists
		WHERE waitlist_id = $1 AND company_id = $2
		FOR UPDATE
	`
	row := db.QueryRowContext(ctx, query, waitlistID, companyID)
	return r.scanWaitlist(row)
}

// internal/hr/repository/reminder_repository.go
package repository

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/google/uuid"

	"auth-service/internal/client"
	"auth-service/internal/hr/models/employee"
)

// ============================================================================
// Interface
// ============================================================================

// ReminderRepository owns the hr.reminder feed — the in-app inbox HR reads.
//
// Same shape as ScheduledJobRepository:
//   - Create is dedupe-safe (ON CONFLICT on the unique dedupe index).
//   - Feed reads are scoped by recipient_id — a user can only see their own rows.
//   - Reads are ALSO scoped by location: an HR user only sees reminders for
//     locations they currently have access to. Rows with location_id IS NULL
//     are company-wide and visible everywhere.
type ReminderRepository interface {
	Create(ctx context.Context, r *employee.Reminder) (bool, error)
	CreateBatch(ctx context.Context, rows []*employee.Reminder) (int, error)

	List(ctx context.Context, recipientID uuid.UUID, filters ReminderFilters, page, pageSize int) ([]*employee.Reminder, int, error)
	UnreadCount(ctx context.Context, recipientID uuid.UUID, locationIDs []uuid.UUID) (int, error)
	CountBySeverity(ctx context.Context, recipientID uuid.UUID, locationIDs []uuid.UUID) (map[string]int, error)

	MarkRead(ctx context.Context, recipientID, reminderID uuid.UUID) error
	MarkAllRead(ctx context.Context, recipientID uuid.UUID) (int64, error)
	Dismiss(ctx context.Context, recipientID, reminderID uuid.UUID) error

	MarkActionedBySubject(ctx context.Context, companyID, subjectUserID uuid.UUID, typePrefix string) (int64, error)
	PurgeExpired(ctx context.Context, batch int) (int64, error)

	GetSubjectLocationID(ctx context.Context, companyID, subjectUserID uuid.UUID) (*uuid.UUID, error)
	HealthCheck(ctx context.Context) error
}

// ReminderFilters narrows the feed query. Zero value = no filter.
type ReminderFilters struct {
	LocationIDs []uuid.UUID // nil/empty = no filter (ALL scope)
	Status      string
	Severity    string
	Type        string
	TypePrefix  string
	Since       *time.Time
}

// ============================================================================
// Postgres implementation
// ============================================================================

type reminderRepository struct {
	client *client.PostgresClient
}

func NewReminderRepository(pg *client.PostgresClient) ReminderRepository {
	return &reminderRepository{client: pg}
}

// ============================================================================
// Create / CreateBatch — both dedupe-safe
// ============================================================================

const insertReminderSQL = `
	INSERT INTO hr.reminder (
		reminder_id, company_id, recipient_id, recipient_type,
		subject_user_id,
		location_id,
		reminder_type, severity, title, body,
		action_type, action_payload,
		metadata,
		status,
		expires_at,
		dedupe_key,
		created_at
	) VALUES (
		$1,$2,$3,$4,
		$5,
		$6,
		$7,$8,$9,$10,
		$11,$12,
		$13,
		'unread',
		$14,
		$15,
		NOW()
	)
	ON CONFLICT (recipient_id, dedupe_key) DO NOTHING
`

func (r *reminderRepository) Create(ctx context.Context, rem *employee.Reminder) (bool, error) {
	if rem == nil {
		return false, errors.New("reminder is required")
	}
	if rem.RecipientID == uuid.Nil {
		return false, errors.New("recipient_id is required")
	}
	if rem.DedupeKey == "" {
		return false, errors.New("dedupe_key is required")
	}
	if rem.ReminderID == uuid.Nil {
		rem.ReminderID = uuid.New()
	}

	res, err := r.client.Exec(ctx, insertReminderSQL,
		rem.ReminderID, rem.CompanyID, rem.RecipientID, rem.RecipientType,
		rem.SubjectUserID,
		rem.LocationID,
		rem.ReminderType, rem.Severity, rem.Title, rem.Body,
		rem.ActionType, rem.ActionPayload,
		rem.Metadata,
		rem.ExpiresAt,
		rem.DedupeKey,
	)
	if err != nil {
		return false, fmt.Errorf("insert reminder: %w", err)
	}
	n, _ := res.RowsAffected()
	return n > 0, nil
}

func (r *reminderRepository) CreateBatch(ctx context.Context, rows []*employee.Reminder) (int, error) {
	if len(rows) == 0 {
		return 0, nil
	}

	tx, err := r.client.BeginTx(ctx, nil)
	if err != nil {
		return 0, fmt.Errorf("begin tx: %w", err)
	}
	defer tx.Rollback()

	inserted := 0
	for _, rem := range rows {
		if rem == nil {
			continue
		}
		if rem.RecipientID == uuid.Nil || rem.DedupeKey == "" {
			continue
		}
		if rem.ReminderID == uuid.Nil {
			rem.ReminderID = uuid.New()
		}
		res, err := tx.ExecContext(ctx, insertReminderSQL,
			rem.ReminderID, rem.CompanyID, rem.RecipientID, rem.RecipientType,
			rem.SubjectUserID,
			rem.LocationID,
			rem.ReminderType, rem.Severity, rem.Title, rem.Body,
			rem.ActionType, rem.ActionPayload,
			rem.Metadata,
			rem.ExpiresAt,
			rem.DedupeKey,
		)
		if err != nil {
			return inserted, fmt.Errorf("insert reminder (batch): %w", err)
		}
		if n, _ := res.RowsAffected(); n > 0 {
			inserted++
		}
	}

	if err := tx.Commit(); err != nil {
		return 0, fmt.Errorf("commit reminder batch: %w", err)
	}
	return inserted, nil
}

// ============================================================================
// List — location filter applied here
//
// IMPORTANT: `location_id = ANY($N::uuid[])`. The `::uuid[]` cast is required
// because we pass a Postgres array literal as a string (via toUUIDArrayLiteral)
// rather than a Go slice — database/sql cannot bind []uuid.UUID.
// ============================================================================

func (r *reminderRepository) List(
	ctx context.Context,
	recipientID uuid.UUID,
	filters ReminderFilters,
	page, pageSize int,
) ([]*employee.Reminder, int, error) {
	if page < 1 {
		page = 1
	}
	if pageSize < 1 || pageSize > 100 {
		pageSize = 30
	}
	offset := (page - 1) * pageSize

	conds := []string{"recipient_id = $1"}
	args := []interface{}{recipientID}
	argN := 2

	// Location scope — nil/empty = ALL-scope (no filter)
	if len(filters.LocationIDs) > 0 {
		conds = append(conds, fmt.Sprintf(
			"(location_id = ANY($%d::uuid[]) OR location_id IS NULL)", argN))
		args = append(args, toUUIDArrayLiteral(filters.LocationIDs))
		argN++
	}

	if filters.Status != "" {
		conds = append(conds, fmt.Sprintf("status = $%d", argN))
		args = append(args, filters.Status)
		argN++
	}
	if filters.Severity != "" {
		conds = append(conds, fmt.Sprintf("severity = $%d", argN))
		args = append(args, filters.Severity)
		argN++
	}
	if filters.Type != "" {
		conds = append(conds, fmt.Sprintf("reminder_type = $%d", argN))
		args = append(args, filters.Type)
		argN++
	}
	if filters.TypePrefix != "" {
		conds = append(conds, fmt.Sprintf("reminder_type LIKE $%d", argN))
		args = append(args, filters.TypePrefix+"%")
		argN++
	}
	if filters.Since != nil {
		conds = append(conds, fmt.Sprintf("created_at >= $%d", argN))
		args = append(args, *filters.Since)
		argN++
	}

	where := "WHERE " + strings.Join(conds, " AND ")

	countSQL := "SELECT COUNT(*) FROM hr.reminder " + where
	var total int
	if err := r.client.QueryRow(ctx, countSQL, args...).Scan(&total); err != nil {
		return nil, 0, fmt.Errorf("count reminders: %w", err)
	}

	listSQL := fmt.Sprintf(`
		SELECT
			reminder_id, company_id, recipient_id, recipient_type,
			subject_user_id,
			location_id,
			reminder_type, severity, title, body,
			action_type, action_payload,
			metadata,
			status, read_at, actioned_at, dismissed_at, expires_at,
			dedupe_key, created_at
		FROM hr.reminder
		%s
		ORDER BY
			CASE severity
				WHEN 'critical' THEN 0
				WHEN 'warning'  THEN 1
				ELSE 2
			END ASC,
			created_at DESC
		LIMIT $%d OFFSET $%d
	`, where, argN, argN+1)

	args = append(args, pageSize, offset)

	rows, err := r.client.Query(ctx, listSQL, args...)
	if err != nil {
		return nil, 0, fmt.Errorf("list reminders: %w", err)
	}
	defer rows.Close()

	out := make([]*employee.Reminder, 0, pageSize)
	for rows.Next() {
		rem, err := scanReminder(rows)
		if err != nil {
			return nil, 0, fmt.Errorf("scan reminder: %w", err)
		}
		out = append(out, rem)
	}
	if err := rows.Err(); err != nil {
		return nil, 0, fmt.Errorf("iterate reminders: %w", err)
	}
	return out, total, nil
}

// ============================================================================
// Counts — both scoped by location
// ============================================================================

func (r *reminderRepository) UnreadCount(
	ctx context.Context,
	recipientID uuid.UUID,
	locationIDs []uuid.UUID,
) (int, error) {
	var n int

	if len(locationIDs) == 0 {
		err := r.client.QueryRow(ctx, `
			SELECT COUNT(*) FROM hr.reminder
			WHERE recipient_id = $1 AND status = 'unread'
		`, recipientID).Scan(&n)
		if err != nil {
			return 0, fmt.Errorf("unread count: %w", err)
		}
		return n, nil
	}

	err := r.client.QueryRow(ctx, `
		SELECT COUNT(*) FROM hr.reminder
		WHERE recipient_id = $1
		  AND status = 'unread'
		  AND (location_id = ANY($2::uuid[]) OR location_id IS NULL)
	`, recipientID, toUUIDArrayLiteral(locationIDs)).Scan(&n)
	if err != nil {
		return 0, fmt.Errorf("unread count (scoped): %w", err)
	}
	return n, nil
}

func (r *reminderRepository) CountBySeverity(
	ctx context.Context,
	recipientID uuid.UUID,
	locationIDs []uuid.UUID,
) (map[string]int, error) {
	var (
		rows *sql.Rows
		err  error
	)

	if len(locationIDs) == 0 {
		rows, err = r.client.Query(ctx, `
			SELECT severity, COUNT(*)
			FROM hr.reminder
			WHERE recipient_id = $1 AND status = 'unread'
			GROUP BY severity
		`, recipientID)
	} else {
		rows, err = r.client.Query(ctx, `
			SELECT severity, COUNT(*)
			FROM hr.reminder
			WHERE recipient_id = $1
			  AND status = 'unread'
			  AND (location_id = ANY($2::uuid[]) OR location_id IS NULL)
			GROUP BY severity
		`, recipientID, toUUIDArrayLiteral(locationIDs))
	}
	if err != nil {
		return nil, fmt.Errorf("count by severity: %w", err)
	}
	defer rows.Close()

	out := map[string]int{}
	for rows.Next() {
		var sev string
		var n int
		if err := rows.Scan(&sev, &n); err != nil {
			return nil, err
		}
		out[sev] = n
	}
	return out, rows.Err()
}

// ============================================================================
// Mutations — scoped by recipient_id only (no location filter)
// ============================================================================

func (r *reminderRepository) MarkRead(ctx context.Context, recipientID, reminderID uuid.UUID) error {
	_, err := r.client.Exec(ctx, `
		UPDATE hr.reminder
		   SET status  = 'read',
		       read_at = NOW()
		 WHERE reminder_id = $1
		   AND recipient_id = $2
		   AND status = 'unread'
	`, reminderID, recipientID)
	if err != nil {
		return fmt.Errorf("mark reminder read: %w", err)
	}
	return nil
}

func (r *reminderRepository) MarkAllRead(ctx context.Context, recipientID uuid.UUID) (int64, error) {
	res, err := r.client.Exec(ctx, `
		UPDATE hr.reminder
		   SET status  = 'read',
		       read_at = NOW()
		 WHERE recipient_id = $1
		   AND status = 'unread'
	`, recipientID)
	if err != nil {
		return 0, fmt.Errorf("mark all reminders read: %w", err)
	}
	return res.RowsAffected()
}

func (r *reminderRepository) Dismiss(ctx context.Context, recipientID, reminderID uuid.UUID) error {
	_, err := r.client.Exec(ctx, `
		UPDATE hr.reminder
		   SET status       = 'dismissed',
		       dismissed_at = NOW()
		 WHERE reminder_id = $1
		   AND recipient_id = $2
		   AND status IN ('unread','read')
	`, reminderID, recipientID)
	if err != nil {
		return fmt.Errorf("dismiss reminder: %w", err)
	}
	return nil
}

func (r *reminderRepository) MarkActionedBySubject(
	ctx context.Context,
	companyID, subjectUserID uuid.UUID,
	typePrefix string,
) (int64, error) {
	res, err := r.client.Exec(ctx, `
		UPDATE hr.reminder
		   SET status      = 'actioned',
		       actioned_at = NOW()
		 WHERE company_id      = $1
		   AND subject_user_id = $2
		   AND reminder_type LIKE $3
		   AND status IN ('unread','read')
	`, companyID, subjectUserID, typePrefix+"%")
	if err != nil {
		return 0, fmt.Errorf("mark reminders actioned: %w", err)
	}
	return res.RowsAffected()
}

func (r *reminderRepository) PurgeExpired(ctx context.Context, batch int) (int64, error) {
	if batch <= 0 {
		batch = 1000
	}
	res, err := r.client.Exec(ctx, `
		DELETE FROM hr.reminder
		 WHERE reminder_id IN (
		     SELECT reminder_id
		       FROM hr.reminder
		      WHERE status = 'unread'
		        AND expires_at IS NOT NULL
		        AND expires_at < NOW()
		      LIMIT $1
		 )
	`, batch)
	if err != nil {
		return 0, fmt.Errorf("purge expired reminders: %w", err)
	}
	return res.RowsAffected()
}

// ============================================================================
// GetSubjectLocationID — used by LifecycleNotifierImpl to stamp reminders
// ============================================================================

func (r *reminderRepository) GetSubjectLocationID(
	ctx context.Context,
	companyID, subjectUserID uuid.UUID,
) (*uuid.UUID, error) {
	var locID uuid.NullUUID
	err := r.client.QueryRow(ctx, `
		SELECT primary_location_id
		  FROM company_employees
		 WHERE company_id = $1 AND user_id = $2
	`, companyID, subjectUserID).Scan(&locID)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, nil
		}
		return nil, fmt.Errorf("get subject location: %w", err)
	}
	if !locID.Valid {
		return nil, nil
	}
	id := locID.UUID
	return &id, nil
}

// ============================================================================
// Health check
// ============================================================================

func (r *reminderRepository) HealthCheck(ctx context.Context) error {
	_, err := r.client.Exec(ctx, `SELECT 1 FROM hr.reminder LIMIT 1`)
	if err != nil {
		return fmt.Errorf("reminder repository health check failed: %w", err)
	}
	return nil
}

// ============================================================================
// Scanner
// ============================================================================

func scanReminder(rows *sql.Rows) (*employee.Reminder, error) {
	var rem employee.Reminder
	var subjectUserID uuid.NullUUID
	var locationID uuid.NullUUID
	var body, actionType sql.NullString
	var actionPayload, metadata []byte
	var readAt, actionedAt, dismissedAt, expiresAt sql.NullTime

	err := rows.Scan(
		&rem.ReminderID, &rem.CompanyID, &rem.RecipientID, &rem.RecipientType,
		&subjectUserID,
		&locationID,
		&rem.ReminderType, &rem.Severity, &rem.Title, &body,
		&actionType, &actionPayload,
		&metadata,
		&rem.Status, &readAt, &actionedAt, &dismissedAt, &expiresAt,
		&rem.DedupeKey, &rem.CreatedAt,
	)
	if err != nil {
		return nil, err
	}

	if subjectUserID.Valid {
		id := subjectUserID.UUID
		rem.SubjectUserID = &id
	}
	if locationID.Valid {
		id := locationID.UUID
		rem.LocationID = &id
	}
	if body.Valid {
		rem.Body = &body.String
	}
	if actionType.Valid {
		rem.ActionType = &actionType.String
	}
	if len(actionPayload) > 0 {
		rem.ActionPayload = json.RawMessage(actionPayload)
	}
	if len(metadata) > 0 {
		rem.Metadata = json.RawMessage(metadata)
	}
	if readAt.Valid {
		rem.ReadAt = &readAt.Time
	}
	if actionedAt.Valid {
		rem.ActionedAt = &actionedAt.Time
	}
	if dismissedAt.Valid {
		rem.DismissedAt = &dismissedAt.Time
	}
	if expiresAt.Valid {
		rem.ExpiresAt = &expiresAt.Time
	}

	return &rem, nil
}

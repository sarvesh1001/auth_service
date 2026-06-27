// repository/online_session_repository.go
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

type OnlineSessionRepository interface {
	Create(ctx context.Context, db DBTX, session *models.OnlineSession) error
	Update(ctx context.Context, db DBTX, session *models.OnlineSession) error
	Delete(ctx context.Context, db DBTX, companyID, sessionID uuid.UUID) error

	GetByID(ctx context.Context, db DBTX, companyID, sessionID uuid.UUID) (*models.OnlineSession, error)
	GetBySchedule(ctx context.Context, db DBTX, companyID, scheduleID uuid.UUID) (*models.OnlineSession, error)
	GetByMeetingID(ctx context.Context, db DBTX, companyID, meetingID string) (*models.OnlineSession, error)

	List(ctx context.Context, db DBTX, filter OnlineSessionFilter, p Pagination, s Sort) ([]*models.OnlineSession, int64, error)
	ListActive(ctx context.Context, db DBTX, companyID uuid.UUID) ([]*models.OnlineSession, error)

	StartSession(ctx context.Context, db DBTX, companyID, sessionID uuid.UUID) error
	EndSession(ctx context.Context, db DBTX, companyID, sessionID uuid.UUID) error
	UpdateRecording(ctx context.Context, db DBTX, companyID, sessionID uuid.UUID, recordingURL string) error
	UpdateJoinLink(ctx context.Context, db DBTX, companyID, sessionID uuid.UUID, meetingURL string) error

	Exists(ctx context.Context, db DBTX, companyID, sessionID uuid.UUID) (bool, error)
	ExistsByMeetingID(ctx context.Context, db DBTX, companyID, meetingID string) (bool, error)
	Search(ctx context.Context, db DBTX, companyID uuid.UUID, query string, limit, offset int) ([]*models.OnlineSession, int64, error)

	GetByIDForUpdate(ctx context.Context, db DBTX, companyID, sessionID uuid.UUID) (*models.OnlineSession, error)
}

type OnlineSessionFilter struct {
	CompanyID   uuid.UUID
	SessionIDs  []uuid.UUID
	ScheduleID  *uuid.UUID
	ProviderID  *int16
	MeetingID   *string
	StatusID    *int16
	StartedFrom *time.Time
	StartedTo   *time.Time
}

// ---------------------------------------------------------------------
// Implementation
// ---------------------------------------------------------------------

type onlineSessionRepository struct {
	logger *zap.Logger
}

func NewOnlineSessionRepository(logger *zap.Logger) OnlineSessionRepository {
	return &onlineSessionRepository{
		logger: logger.Named("subscription_online_session_repo"),
	}
}

const onlineSessionTable = "subscription.online_sessions"

func (r *onlineSessionRepository) scanOnlineSession(s scanner) (*models.OnlineSession, error) {
	var os models.OnlineSession
	var recordingURL, notes, attachmentKeys, chatLog, resources sql.NullString
	var hostUserID sql.NullString

	err := s.Scan(
		&os.SessionID,
		&os.ScheduleID,
		&os.ProviderID,
		&os.MeetingURL,
		&recordingURL,
		&notes,
		&attachmentKeys,
		&chatLog,
		&resources,
		&hostUserID,
		&os.CreatedAt,
		&os.UpdatedAt,
	)
	if err != nil {
		if err == sql.ErrNoRows {
			return nil, errors.ErrNotFound
		}
		return nil, fmt.Errorf("scan online session: %w", err)
	}
	if recordingURL.Valid {
		os.RecordingURL = &recordingURL.String
	}
	if notes.Valid {
		os.Notes = &notes.String
	}
	if attachmentKeys.Valid {
		// parse array, could be simple comma separated or JSON array; we'll treat as simple array
		keys := strings.Split(attachmentKeys.String, ",")
		os.AttachmentKeys = keys
	}
	if chatLog.Valid {
		os.ChatLog = []byte(chatLog.String)
	}
	if resources.Valid {
		os.Resources = []byte(resources.String)
	}
	if hostUserID.Valid {
		if uid, err := uuid.Parse(hostUserID.String); err == nil {
			os.HostUserID = &uid
		}
	}
	return &os, nil
}

func (r *onlineSessionRepository) buildOnlineSessionFilter(filter OnlineSessionFilter) (string, []interface{}) {
	var conds []string
	var args []interface{}
	idx := 1

	if filter.CompanyID != uuid.Nil {
		// will join later
	}
	if len(filter.SessionIDs) > 0 {
		placeholders := make([]string, len(filter.SessionIDs))
		for i, id := range filter.SessionIDs {
			placeholders[i] = fmt.Sprintf("$%d", idx)
			args = append(args, id)
			idx++
		}
		conds = append(conds, fmt.Sprintf("os.session_id IN (%s)", strings.Join(placeholders, ",")))
	}
	if filter.ScheduleID != nil {
		conds = append(conds, fmt.Sprintf("os.schedule_id = $%d", idx))
		args = append(args, *filter.ScheduleID)
		idx++
	}
	if filter.ProviderID != nil {
		conds = append(conds, fmt.Sprintf("os.provider_id = $%d", idx))
		args = append(args, *filter.ProviderID)
		idx++
	}
	if filter.MeetingID != nil {
		conds = append(conds, fmt.Sprintf("os.meeting_url ILIKE $%d", idx))
		args = append(args, "%"+*filter.MeetingID+"%")
		idx++
	}
	if filter.StatusID != nil {
		// status is not on online_session directly – but we can join schedule status
	}
	if filter.StartedFrom != nil {
		conds = append(conds, fmt.Sprintf("os.created_at >= $%d", idx))
		args = append(args, *filter.StartedFrom)
		idx++
	}
	if filter.StartedTo != nil {
		conds = append(conds, fmt.Sprintf("os.created_at <= $%d", idx))
		args = append(args, *filter.StartedTo)
		idx++
	}
	return strings.Join(conds, " AND "), args
}

var onlineSessionAllowedSort = map[string]bool{
	"session_id":  true,
	"provider_id": true,
	"created_at":  true,
	"updated_at":  true,
}

func (r *onlineSessionRepository) Create(ctx context.Context, db DBTX, session *models.OnlineSession) error {
	query := `
		INSERT INTO subscription.online_sessions (
			session_id, schedule_id, provider_id, meeting_url,
			recording_url, notes, attachment_keys, chat_log, resources,
			host_user_id, created_at, updated_at
		) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, NOW(), NOW())
		RETURNING created_at, updated_at
	`
	attachments := strings.Join(session.AttachmentKeys, ",")
	err := db.QueryRowContext(ctx, query,
		session.SessionID,
		session.ScheduleID,
		session.ProviderID,
		session.MeetingURL,
		session.RecordingURL,
		session.Notes,
		attachments,
		session.ChatLog,
		session.Resources,
		session.HostUserID,
	).Scan(&session.CreatedAt, &session.UpdatedAt)
	if err != nil {
		return fmt.Errorf("create online session: %w", err)
	}
	return nil
}

func (r *onlineSessionRepository) Update(ctx context.Context, db DBTX, session *models.OnlineSession) error {
	attachments := strings.Join(session.AttachmentKeys, ",")
	query := `
		UPDATE subscription.online_sessions SET
			schedule_id = $2,
			provider_id = $3,
			meeting_url = $4,
			recording_url = $5,
			notes = $6,
			attachment_keys = $7,
			chat_log = $8,
			resources = $9,
			host_user_id = $10,
			updated_at = NOW()
		WHERE session_id = $1
		RETURNING updated_at
	`
	err := db.QueryRowContext(ctx, query,
		session.SessionID,
		session.ScheduleID,
		session.ProviderID,
		session.MeetingURL,
		session.RecordingURL,
		session.Notes,
		attachments,
		session.ChatLog,
		session.Resources,
		session.HostUserID,
	).Scan(&session.UpdatedAt)
	if err != nil {
		if err == sql.ErrNoRows {
			return errors.ErrNotFound
		}
		return fmt.Errorf("update online session: %w", err)
	}
	return nil
}

func (r *onlineSessionRepository) Delete(ctx context.Context, db DBTX, companyID, sessionID uuid.UUID) error {
	query := `
		DELETE FROM subscription.online_sessions os
		USING subscription.schedules s
		JOIN subscription.subscriptions sub ON s.subscription_id = sub.subscription_id
		WHERE os.schedule_id = s.schedule_id
		AND sub.company_id = $1
		AND os.session_id = $2
	`
	result, err := db.ExecContext(ctx, query, companyID, sessionID)
	if err != nil {
		return fmt.Errorf("delete online session: %w", err)
	}
	rows, _ := result.RowsAffected()
	if rows == 0 {
		return errors.ErrNotFound
	}
	return nil
}

func (r *onlineSessionRepository) GetByID(ctx context.Context, db DBTX, companyID, sessionID uuid.UUID) (*models.OnlineSession, error) {
	query := `
		SELECT os.session_id, os.schedule_id, os.provider_id, os.meeting_url,
			os.recording_url, os.notes, os.attachment_keys, os.chat_log, os.resources,
			os.host_user_id, os.created_at, os.updated_at
		FROM subscription.online_sessions os
		JOIN subscription.schedules s ON os.schedule_id = s.schedule_id
		JOIN subscription.subscriptions sub ON s.subscription_id = sub.subscription_id
		WHERE os.session_id = $1 AND sub.company_id = $2
	`
	row := db.QueryRowContext(ctx, query, sessionID, companyID)
	return r.scanOnlineSession(row)
}

func (r *onlineSessionRepository) GetBySchedule(ctx context.Context, db DBTX, companyID, scheduleID uuid.UUID) (*models.OnlineSession, error) {
	query := `
		SELECT os.session_id, os.schedule_id, os.provider_id, os.meeting_url,
			os.recording_url, os.notes, os.attachment_keys, os.chat_log, os.resources,
			os.host_user_id, os.created_at, os.updated_at
		FROM subscription.online_sessions os
		JOIN subscription.schedules s ON os.schedule_id = s.schedule_id
		JOIN subscription.subscriptions sub ON s.subscription_id = sub.subscription_id
		WHERE os.schedule_id = $1 AND sub.company_id = $2
		LIMIT 1
	`
	row := db.QueryRowContext(ctx, query, scheduleID, companyID)
	return r.scanOnlineSession(row)
}

func (r *onlineSessionRepository) GetByMeetingID(ctx context.Context, db DBTX, companyID, meetingID string) (*models.OnlineSession, error) {
	query := `
		SELECT os.session_id, os.schedule_id, os.provider_id, os.meeting_url,
			os.recording_url, os.notes, os.attachment_keys, os.chat_log, os.resources,
			os.host_user_id, os.created_at, os.updated_at
		FROM subscription.online_sessions os
		JOIN subscription.schedules s ON os.schedule_id = s.schedule_id
		JOIN subscription.subscriptions sub ON s.subscription_id = sub.subscription_id
		WHERE os.meeting_url = $1 AND sub.company_id = $2
		LIMIT 1
	`
	row := db.QueryRowContext(ctx, query, meetingID, companyID)
	return r.scanOnlineSession(row)
}

func (r *onlineSessionRepository) List(ctx context.Context, db DBTX, filter OnlineSessionFilter, p Pagination, s Sort) ([]*models.OnlineSession, int64, error) {
	from := "subscription.online_sessions os"
	joins := []string{
		"JOIN subscription.schedules s ON os.schedule_id = s.schedule_id",
		"JOIN subscription.subscriptions sub ON s.subscription_id = sub.subscription_id",
	}
	whereCond := "sub.company_id = $1"
	args := []interface{}{filter.CompanyID}
	idx := 2

	if len(filter.SessionIDs) > 0 {
		placeholders := make([]string, len(filter.SessionIDs))
		for i, id := range filter.SessionIDs {
			placeholders[i] = fmt.Sprintf("$%d", idx)
			args = append(args, id)
			idx++
		}
		whereCond += fmt.Sprintf(" AND os.session_id IN (%s)", strings.Join(placeholders, ","))
	}
	if filter.ScheduleID != nil {
		whereCond += fmt.Sprintf(" AND os.schedule_id = $%d", idx)
		args = append(args, *filter.ScheduleID)
		idx++
	}
	if filter.ProviderID != nil {
		whereCond += fmt.Sprintf(" AND os.provider_id = $%d", idx)
		args = append(args, *filter.ProviderID)
		idx++
	}
	if filter.MeetingID != nil {
		whereCond += fmt.Sprintf(" AND os.meeting_url ILIKE $%d", idx)
		args = append(args, "%"+*filter.MeetingID+"%")
		idx++
	}
	if filter.StartedFrom != nil {
		whereCond += fmt.Sprintf(" AND os.created_at >= $%d", idx)
		args = append(args, *filter.StartedFrom)
		idx++
	}
	if filter.StartedTo != nil {
		whereCond += fmt.Sprintf(" AND os.created_at <= $%d", idx)
		args = append(args, *filter.StartedTo)
		idx++
	}

	fullFrom := from + " " + strings.Join(joins, " ")
	whereClause := "WHERE " + whereCond

	orderBy, err := validateSort(s, onlineSessionAllowedSort)
	if err != nil {
		return nil, 0, err
	}
	if orderBy == "" {
		orderBy = "ORDER BY os.created_at DESC"
	}

	limit, offset := validatePagination(p)

	countQuery := fmt.Sprintf("SELECT COUNT(*) FROM %s %s", fullFrom, whereClause)
	var total int64
	if err := db.QueryRowContext(ctx, countQuery, args...).Scan(&total); err != nil {
		return nil, 0, fmt.Errorf("count online sessions: %w", err)
	}
	if total == 0 {
		return []*models.OnlineSession{}, 0, nil
	}

	query := fmt.Sprintf(`
		SELECT os.session_id, os.schedule_id, os.provider_id, os.meeting_url,
			os.recording_url, os.notes, os.attachment_keys, os.chat_log, os.resources,
			os.host_user_id, os.created_at, os.updated_at
		FROM %s
		%s
		%s
		LIMIT $%d OFFSET $%d
	`, fullFrom, whereClause, orderBy, idx, idx+1)
	args = append(args, limit, offset)

	rows, err := db.QueryContext(ctx, query, args...)
	if err != nil {
		return nil, 0, fmt.Errorf("list online sessions: %w", err)
	}
	defer rows.Close()
	var result []*models.OnlineSession
	for rows.Next() {
		os, err := r.scanOnlineSession(rows)
		if err != nil {
			return nil, 0, err
		}
		result = append(result, os)
	}
	return result, total, rows.Err()
}

func (r *onlineSessionRepository) ListActive(ctx context.Context, db DBTX, companyID uuid.UUID) ([]*models.OnlineSession, error) {
	// We'll simply list all with no filter (could add schedule status later)
	filter := OnlineSessionFilter{CompanyID: companyID}
	sessions, _, err := r.List(ctx, db, filter, Pagination{Limit: 1000}, Sort{Field: "created_at", Direction: "DESC"})
	return sessions, err
}

func (r *onlineSessionRepository) StartSession(ctx context.Context, db DBTX, companyID, sessionID uuid.UUID) error {
	// no direct status on online_session, but we can update schedule status via schedule repo
	// We'll just update updated_at
	query := `
		UPDATE subscription.online_sessions os
		SET updated_at = NOW()
		FROM subscription.schedules s
		JOIN subscription.subscriptions sub ON s.subscription_id = sub.subscription_id
		WHERE os.schedule_id = s.schedule_id
		AND sub.company_id = $1
		AND os.session_id = $2
	`
	_, err := db.ExecContext(ctx, query, companyID, sessionID)
	return err
}

func (r *onlineSessionRepository) EndSession(ctx context.Context, db DBTX, companyID, sessionID uuid.UUID) error {
	return r.StartSession(ctx, db, companyID, sessionID) // just update updated_at
}

func (r *onlineSessionRepository) UpdateRecording(ctx context.Context, db DBTX, companyID, sessionID uuid.UUID, recordingURL string) error {
	query := `
		UPDATE subscription.online_sessions os
		SET recording_url = $3, updated_at = NOW()
		FROM subscription.schedules s
		JOIN subscription.subscriptions sub ON s.subscription_id = sub.subscription_id
		WHERE os.schedule_id = s.schedule_id
		AND sub.company_id = $1
		AND os.session_id = $2
	`
	_, err := db.ExecContext(ctx, query, companyID, sessionID, recordingURL)
	return err
}

func (r *onlineSessionRepository) UpdateJoinLink(ctx context.Context, db DBTX, companyID, sessionID uuid.UUID, meetingURL string) error {
	query := `
		UPDATE subscription.online_sessions os
		SET meeting_url = $3, updated_at = NOW()
		FROM subscription.schedules s
		JOIN subscription.subscriptions sub ON s.subscription_id = sub.subscription_id
		WHERE os.schedule_id = s.schedule_id
		AND sub.company_id = $1
		AND os.session_id = $2
	`
	_, err := db.ExecContext(ctx, query, companyID, sessionID, meetingURL)
	return err
}

func (r *onlineSessionRepository) Exists(ctx context.Context, db DBTX, companyID, sessionID uuid.UUID) (bool, error) {
	var exists bool
	query := `
		SELECT EXISTS(
			SELECT 1 FROM subscription.online_sessions os
			JOIN subscription.schedules s ON os.schedule_id = s.schedule_id
			JOIN subscription.subscriptions sub ON s.subscription_id = sub.subscription_id
			WHERE os.session_id = $1 AND sub.company_id = $2
		)
	`
	err := db.QueryRowContext(ctx, query, sessionID, companyID).Scan(&exists)
	return exists, err
}

func (r *onlineSessionRepository) ExistsByMeetingID(ctx context.Context, db DBTX, companyID, meetingID string) (bool, error) {
	var exists bool
	query := `
		SELECT EXISTS(
			SELECT 1 FROM subscription.online_sessions os
			JOIN subscription.schedules s ON os.schedule_id = s.schedule_id
			JOIN subscription.subscriptions sub ON s.subscription_id = sub.subscription_id
			WHERE os.meeting_url = $1 AND sub.company_id = $2
		)
	`
	err := db.QueryRowContext(ctx, query, meetingID, companyID).Scan(&exists)
	return exists, err
}

func (r *onlineSessionRepository) Search(ctx context.Context, db DBTX, companyID uuid.UUID, query string, limit, offset int) ([]*models.OnlineSession, int64, error) {
	pattern := "%" + query + "%"
	where := `
		JOIN subscription.schedules s ON os.schedule_id = s.schedule_id
		JOIN subscription.subscriptions sub ON s.subscription_id = sub.subscription_id
		WHERE sub.company_id = $1
		AND (os.meeting_url ILIKE $2 OR os.notes ILIKE $2)
	`
	args := []interface{}{companyID, pattern}
	countQuery := fmt.Sprintf("SELECT COUNT(*) FROM subscription.online_sessions os %s", where)
	var total int64
	err := db.QueryRowContext(ctx, countQuery, args...).Scan(&total)
	if err != nil {
		return nil, 0, fmt.Errorf("search online sessions count: %w", err)
	}
	if total == 0 {
		return []*models.OnlineSession{}, 0, nil
	}
	baseQuery := `
		SELECT os.session_id, os.schedule_id, os.provider_id, os.meeting_url,
			os.recording_url, os.notes, os.attachment_keys, os.chat_log, os.resources,
			os.host_user_id, os.created_at, os.updated_at
		FROM subscription.online_sessions os
	`
	querySQL := fmt.Sprintf(`%s %s ORDER BY os.created_at DESC LIMIT $%d OFFSET $%d`, baseQuery, where, len(args)+1, len(args)+2)
	args = append(args, limit, offset)
	rows, err := db.QueryContext(ctx, querySQL, args...)
	if err != nil {
		return nil, 0, fmt.Errorf("search online sessions: %w", err)
	}
	defer rows.Close()
	var result []*models.OnlineSession
	for rows.Next() {
		os, err := r.scanOnlineSession(rows)
		if err != nil {
			return nil, 0, err
		}
		result = append(result, os)
	}
	return result, total, rows.Err()
}

func (r *onlineSessionRepository) GetByIDForUpdate(ctx context.Context, db DBTX, companyID, sessionID uuid.UUID) (*models.OnlineSession, error) {
	query := `
		SELECT os.session_id, os.schedule_id, os.provider_id, os.meeting_url,
			os.recording_url, os.notes, os.attachment_keys, os.chat_log, os.resources,
			os.host_user_id, os.created_at, os.updated_at
		FROM subscription.online_sessions os
		JOIN subscription.schedules s ON os.schedule_id = s.schedule_id
		JOIN subscription.subscriptions sub ON s.subscription_id = sub.subscription_id
		WHERE os.session_id = $1 AND sub.company_id = $2
		FOR UPDATE
	`
	row := db.QueryRowContext(ctx, query, sessionID, companyID)
	return r.scanOnlineSession(row)
}

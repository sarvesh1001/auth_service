package postgres

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/lib/pq"
	"go.uber.org/zap"

	"auth-service/internal/attendance/models"
	"auth-service/internal/attendance/repository"
	"auth-service/internal/client"
)

type eventRepository struct {
	client *client.PostgresClient
	logger *zap.Logger
}

// NewEventRepository creates a new event repository
func NewEventRepository(pg *client.PostgresClient, logger *zap.Logger) repository.EventRepository {
	return &eventRepository{
		client: pg,
		logger: logger.Named("event_repo"),
	}
}

func (r *eventRepository) CreateEvent(ctx context.Context, tx *sql.Tx, event *models.AttendanceEvent) error {
	if event.AttendanceEventID == uuid.Nil {
		event.AttendanceEventID = uuid.New()
	}
	if event.CreatedAt.IsZero() {
		event.CreatedAt = time.Now().UTC()
	}

	query := `
		INSERT INTO attendance.attendance_events (
			attendance_event_id, company_id, subject_type, subject_id,
			event_type, event_time, source_type, source_id,
			device_id, device_user_code, ip_address,
			context, metadata, raw_event_payload, created_at, created_by
		) VALUES (
			$1, $2, $3, $4, $5, $6, $7, $8,
			$9, $10, $11, $12, $13, $14, $15, $16
		)
	`

	contextJSON, _ := json.Marshal(event.Context)
	metadataJSON, _ := json.Marshal(event.Metadata)
	rawPayloadJSON, _ := json.Marshal(event.RawEventPayload)

	exec := r.client.Exec
	if tx != nil {
		exec = tx.ExecContext
	}

	_, err := exec(ctx, query,
		event.AttendanceEventID,
		event.CompanyID,
		event.SubjectType,
		event.SubjectID,
		event.EventType,
		event.EventTime,
		event.SourceType,
		event.SourceID,
		event.DeviceID,
		event.DeviceUserCode,
		event.IPAddress,
		contextJSON,
		metadataJSON,
		rawPayloadJSON,
		event.CreatedAt,
		event.CreatedBy,
	)
	if err != nil {
		r.logger.Error("failed to create event",
			zap.String("event_id", event.AttendanceEventID.String()),
			zap.Error(err),
		)
		return fmt.Errorf("create event: %w", err)
	}
	return nil
}

func (r *eventRepository) CreateBulkEvents(ctx context.Context, events []*models.AttendanceEvent) error {
	if len(events) == 0 {
		return nil
	}

	tx, err := r.client.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("begin tx: %w", err)
	}
	defer tx.Rollback()

	for _, ev := range events {
		if err := r.CreateEvent(ctx, tx, ev); err != nil {
			return err
		}
	}

	if err := tx.Commit(); err != nil {
		return fmt.Errorf("commit tx: %w", err)
	}
	return nil
}

func (r *eventRepository) GetEventByID(ctx context.Context, eventID uuid.UUID) (*models.AttendanceEvent, error) {
	query := `
		SELECT
			attendance_event_id, company_id, subject_type, subject_id,
			event_type, event_time, source_type, source_id,
			device_id, device_user_code, ip_address,
			context, metadata, raw_event_payload, created_at, created_by
		FROM attendance.attendance_events
		WHERE attendance_event_id = $1
	`
	row := r.client.QueryRow(ctx, query, eventID)
	return r.scanEvent(row)
}

func (r *eventRepository) GetEventsBySubject(ctx context.Context, companyID, subjectID uuid.UUID, subjectType string, from, to time.Time) ([]*models.AttendanceEvent, error) {
	query := `
		SELECT
			attendance_event_id, company_id, subject_type, subject_id,
			event_type, event_time, source_type, source_id,
			device_id, device_user_code, ip_address,
			context, metadata, raw_event_payload, created_at, created_by
		FROM attendance.attendance_events
		WHERE company_id = $1
			AND subject_type = $2
			AND subject_id = $3
			AND event_time BETWEEN $4 AND $5
		ORDER BY event_time ASC
	`
	rows, err := r.client.Query(ctx, query, companyID, subjectType, subjectID, from, to)
	if err != nil {
		return nil, fmt.Errorf("query events by subject: %w", err)
	}
	defer rows.Close()
	return r.scanEvents(rows)
}

func (r *eventRepository) GetEventsByCompany(ctx context.Context, companyID uuid.UUID, from, to time.Time, page, pageSize int) ([]*models.AttendanceEvent, int64, error) {
	offset := (page - 1) * pageSize

	// Count total
	countQuery := `
		SELECT COUNT(*) FROM attendance.attendance_events
		WHERE company_id = $1 AND event_time BETWEEN $2 AND $3
	`
	var total int64
	err := r.client.QueryRow(ctx, countQuery, companyID, from, to).Scan(&total)
	if err != nil {
		return nil, 0, fmt.Errorf("count events: %w", err)
	}

	query := `
		SELECT
			attendance_event_id, company_id, subject_type, subject_id,
			event_type, event_time, source_type, source_id,
			device_id, device_user_code, ip_address,
			context, metadata, raw_event_payload, created_at, created_by
		FROM attendance.attendance_events
		WHERE company_id = $1 AND event_time BETWEEN $2 AND $3
		ORDER BY event_time DESC
		LIMIT $4 OFFSET $5
	`
	rows, err := r.client.Query(ctx, query, companyID, from, to, pageSize, offset)
	if err != nil {
		return nil, 0, fmt.Errorf("query events: %w", err)
	}
	defer rows.Close()

	events, err := r.scanEvents(rows)
	if err != nil {
		return nil, 0, err
	}
	return events, total, nil
}

func (r *eventRepository) GetEventsByDevice(ctx context.Context, companyID uuid.UUID, deviceID string, from, to time.Time) ([]*models.AttendanceEvent, error) {
	query := `
		SELECT
			attendance_event_id, company_id, subject_type, subject_id,
			event_type, event_time, source_type, source_id,
			device_id, device_user_code, ip_address,
			context, metadata, raw_event_payload, created_at, created_by
		FROM attendance.attendance_events
		WHERE company_id = $1
			AND device_id = $2
			AND event_time BETWEEN $3 AND $4
		ORDER BY event_time ASC
	`
	rows, err := r.client.Query(ctx, query, companyID, deviceID, from, to)
	if err != nil {
		return nil, fmt.Errorf("query events by device: %w", err)
	}
	defer rows.Close()
	return r.scanEvents(rows)
}

func (r *eventRepository) CheckDuplicateRecent(ctx context.Context, companyID, subjectID uuid.UUID, subjectType, eventType string, eventTime time.Time, windowMinutes int) (bool, error) {
	_ = time.Duration(windowMinutes) * time.Minute
	query := `
		SELECT EXISTS (
			SELECT 1
			FROM attendance.attendance_events
			WHERE company_id = $1
				AND subject_type = $2
				AND subject_id = $3
				AND event_type = $4
				AND source_type != 'correction'
				AND ABS(EXTRACT(EPOCH FROM (event_time - $5))) <= $6
			LIMIT 1
		)
	`
	var exists bool
	err := r.client.QueryRow(ctx, query,
		companyID, subjectType, subjectID, eventType, eventTime, windowMinutes*60,
	).Scan(&exists)
	if err != nil {
		return false, fmt.Errorf("check duplicate: %w", err)
	}
	return exists, nil
}

func (r *eventRepository) ListEvents(ctx context.Context, filter repository.EventFilter) ([]*models.AttendanceEvent, int64, error) {
	where, args := r.buildEventFilter(filter)
	orderBy := "ORDER BY event_time DESC"
	limit := filter.PageSize
	if limit <= 0 {
		limit = 50
	}
	if limit > 1000 {
		limit = 1000
	}
	offset := (filter.Page - 1) * limit
	if offset < 0 {
		offset = 0
	}

	// Count
	countQuery := fmt.Sprintf("SELECT COUNT(*) FROM attendance.attendance_events %s", where)
	var total int64
	err := r.client.QueryRow(ctx, countQuery, args...).Scan(&total)
	if err != nil {
		return nil, 0, fmt.Errorf("count events: %w", err)
	}

	query := fmt.Sprintf(`
		SELECT
			attendance_event_id, company_id, subject_type, subject_id,
			event_type, event_time, source_type, source_id,
			device_id, device_user_code, ip_address,
			context, metadata, raw_event_payload, created_at, created_by
		FROM attendance.attendance_events
		%s
		%s
		LIMIT $%d OFFSET $%d
	`, where, orderBy, len(args)+1, len(args)+2)

	args = append(args, limit, offset)
	rows, err := r.client.Query(ctx, query, args...)
	if err != nil {
		return nil, 0, fmt.Errorf("list events: %w", err)
	}
	defer rows.Close()

	events, err := r.scanEvents(rows)
	if err != nil {
		return nil, 0, err
	}
	return events, total, nil
}

func (r *eventRepository) CountEvents(ctx context.Context, filter repository.EventFilter) (int64, error) {
	where, args := r.buildEventFilter(filter)
	query := fmt.Sprintf("SELECT COUNT(*) FROM attendance.attendance_events %s", where)
	var total int64
	err := r.client.QueryRow(ctx, query, args...).Scan(&total)
	if err != nil {
		return 0, fmt.Errorf("count events: %w", err)
	}
	return total, nil
}

func (r *eventRepository) GetDistinctSubjects(ctx context.Context, companyID uuid.UUID, from, to time.Time) ([]repository.SubjectRef, error) {
	query := `
		SELECT DISTINCT subject_type, subject_id
		FROM attendance.attendance_events
		WHERE company_id = $1
			AND event_time BETWEEN $2 AND $3
	`
	rows, err := r.client.Query(ctx, query, companyID, from, to)
	if err != nil {
		return nil, fmt.Errorf("query distinct subjects: %w", err)
	}
	defer rows.Close()

	var refs []repository.SubjectRef
	for rows.Next() {
		var ref repository.SubjectRef
		if err := rows.Scan(&ref.SubjectType, &ref.SubjectID); err != nil {
			return nil, fmt.Errorf("scan subject ref: %w", err)
		}
		refs = append(refs, ref)
	}
	return refs, nil
}

// --- helpers ---

func (r *eventRepository) scanEvent(row *sql.Row) (*models.AttendanceEvent, error) {
	var event models.AttendanceEvent
	var contextJSON, metadataJSON, rawPayloadJSON []byte

	err := row.Scan(
		&event.AttendanceEventID,
		&event.CompanyID,
		&event.SubjectType,
		&event.SubjectID,
		&event.EventType,
		&event.EventTime,
		&event.SourceType,
		&event.SourceID,
		&event.DeviceID,
		&event.DeviceUserCode,
		&event.IPAddress,
		&contextJSON,
		&metadataJSON,
		&rawPayloadJSON,
		&event.CreatedAt,
		&event.CreatedBy,
	)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, nil
		}
		return nil, fmt.Errorf("scan event: %w", err)
	}

	if len(contextJSON) > 0 {
		_ = json.Unmarshal(contextJSON, &event.Context)
	}
	if len(metadataJSON) > 0 {
		_ = json.Unmarshal(metadataJSON, &event.Metadata)
	}
	if len(rawPayloadJSON) > 0 {
		event.RawEventPayload = rawPayloadJSON
	}
	return &event, nil
}

func (r *eventRepository) scanEvents(rows *sql.Rows) ([]*models.AttendanceEvent, error) {
	var events []*models.AttendanceEvent
	for rows.Next() {
		var e models.AttendanceEvent
		var contextJSON, metadataJSON, rawPayloadJSON []byte
		err := rows.Scan(
			&e.AttendanceEventID,
			&e.CompanyID,
			&e.SubjectType,
			&e.SubjectID,
			&e.EventType,
			&e.EventTime,
			&e.SourceType,
			&e.SourceID,
			&e.DeviceID,
			&e.DeviceUserCode,
			&e.IPAddress,
			&contextJSON,
			&metadataJSON,
			&rawPayloadJSON,
			&e.CreatedAt,
			&e.CreatedBy,
		)
		if err != nil {
			return nil, fmt.Errorf("scan row: %w", err)
		}
		if len(contextJSON) > 0 {
			_ = json.Unmarshal(contextJSON, &e.Context)
		}
		if len(metadataJSON) > 0 {
			_ = json.Unmarshal(metadataJSON, &e.Metadata)
		}
		if len(rawPayloadJSON) > 0 {
			e.RawEventPayload = rawPayloadJSON
		}
		events = append(events, &e)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("rows iteration: %w", err)
	}
	return events, nil
}

func (r *eventRepository) buildEventFilter(filter repository.EventFilter) (string, []interface{}) {
	var conditions []string
	var args []interface{}
	idx := 1

	conditions = append(conditions, fmt.Sprintf("company_id = $%d", idx))
	args = append(args, filter.CompanyID)
	idx++

	conditions = append(conditions, fmt.Sprintf("event_time BETWEEN $%d AND $%d", idx, idx+1))
	args = append(args, filter.StartDate, filter.EndDate)
	idx += 2

	if filter.SubjectType != nil && filter.SubjectID != nil {
		conditions = append(conditions, fmt.Sprintf("subject_type = $%d", idx))
		args = append(args, *filter.SubjectType)
		idx++
		conditions = append(conditions, fmt.Sprintf("subject_id = $%d", idx))
		args = append(args, *filter.SubjectID)
		idx++
	} else if filter.SubjectType != nil {
		conditions = append(conditions, fmt.Sprintf("subject_type = $%d", idx))
		args = append(args, *filter.SubjectType)
		idx++
	} else if filter.SubjectID != nil {
		// subject_id without type is not allowed – we'll add a condition that fails
		conditions = append(conditions, "1=0")
	}

	if len(filter.EventTypes) > 0 {
		conditions = append(conditions, fmt.Sprintf("event_type = ANY($%d)", idx))
		args = append(args, pq.Array(filter.EventTypes))
		idx++
	}

	if filter.SourceType != nil {
		conditions = append(conditions, fmt.Sprintf("source_type = $%d", idx))
		args = append(args, *filter.SourceType)
		idx++
	}

	if filter.DeviceID != nil {
		conditions = append(conditions, fmt.Sprintf("device_id = $%d", idx))
		args = append(args, *filter.DeviceID)
		idx++
	}

	whereClause := ""
	if len(conditions) > 0 {
		whereClause = "WHERE " + strings.Join(conditions, " AND ")
	}
	return whereClause, args
}
func (r *eventRepository) BeginTx(ctx context.Context, opts *sql.TxOptions) (*sql.Tx, error) {
	return r.client.BeginTx(ctx, opts)
}

func (r *eventRepository) FindCorrection(ctx context.Context, companyID, subjectID uuid.UUID, subjectType, correctionType string, eventTime time.Time) (*models.AttendanceEvent, error) {
	query := `
		SELECT
			attendance_event_id, company_id, subject_type, subject_id,
			event_type, event_time, source_type, source_id,
			device_id, device_user_code, ip_address,
			context, metadata, raw_event_payload, created_at, created_by
		FROM attendance.attendance_events
		WHERE company_id = $1
			AND subject_type = $2
			AND subject_id = $3
			AND event_type = $4
			AND source_type = 'correction'
			AND event_time = $5
		LIMIT 1
	`
	row := r.client.QueryRow(ctx, query, companyID, subjectType, subjectID, correctionType, eventTime)
	return r.scanEvent(row)
}

func (r *eventRepository) HealthCheck(ctx context.Context) error {
	_, err := r.client.Exec(ctx, `SELECT 1 FROM attendance.attendance_events LIMIT 1`)
	return err
}

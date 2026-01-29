package repository

import (
	"auth-service/internal/client"
	"auth-service/internal/hr/models/attendance"
	"auth-service/internal/util"
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
)

type attendanceRepository struct {
	client *client.PostgresClient
	logger *zap.Logger
}

func NewAttendanceRepository(
	postgresClient *client.PostgresClient,
	logger *zap.Logger,
) AttendanceRepository {
	return &attendanceRepository{
		client: postgresClient,
		logger: logger,
	}
}

func buildNamedQueryArgs(event *attendance.AttendanceEvent) (string, []interface{}) {
	query := `
        INSERT INTO attendance_events (
            attendance_event_id, company_id, user_id, event_type, event_time,
            source_type, source_id, device_id, ip_address, context,
            metadata, created_at, created_by
        ) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13)
    `
	contextJSON, _ := json.Marshal(event.Context)
	metadataJSON, _ := json.Marshal(event.Metadata)
	args := []interface{}{
		event.AttendanceEventID,
		event.CompanyID,
		event.UserID,
		event.EventType,
		event.EventTime,
		event.SourceType,
		event.SourceID,
		event.DeviceID,
		event.IPAddress,
		contextJSON,
		metadataJSON,
		event.CreatedAt,
		event.CreatedBy,
	}
	return query, args
}

func (r *attendanceRepository) CreateAttendanceEvent(
	ctx context.Context,
	event *attendance.AttendanceEvent,
) error {

	// Ensure ID & timestamps
	if event.AttendanceEventID == uuid.Nil {
		event.AttendanceEventID = uuid.New()
	}
	if event.CreatedAt.IsZero() {
		event.CreatedAt = time.Now().UTC()
	}

	// Use transaction for atomicity
	tx, err := r.client.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("failed to begin transaction: %w", err)
	}

	defer func() {
		if err != nil {
			_ = tx.Rollback()
		}
	}()

	// 1️⃣ Insert attendance event
	query := `
		INSERT INTO attendance_events (
			attendance_event_id,
			company_id,
			user_id,
			event_type,
			event_time,
			source_type,
			source_id,
			device_id,
			ip_address,
			context,
			metadata,
			created_at,
			created_by
		) VALUES (
			$1,$2,$3,$4,$5,
			$6,$7,$8,$9,
			$10,$11,$12,$13
		)
	`

	contextJSON, _ := json.Marshal(event.Context)
	metadataJSON, _ := json.Marshal(event.Metadata)

	_, err = tx.ExecContext(ctx, query,
		event.AttendanceEventID,
		event.CompanyID,
		event.UserID,
		event.EventType,
		event.EventTime,
		event.SourceType,
		event.SourceID,
		event.DeviceID,
		event.IPAddress,
		contextJSON,
		metadataJSON,
		event.CreatedAt,
		event.CreatedBy,
	)
	if err != nil {
		return fmt.Errorf("failed to create attendance event: %w", err)
	}

	// 2️⃣ 🔥 FIXED: Insert into outbox (NO mixed uuid/text params)
	outboxPayload := map[string]interface{}{
		"event_id":      event.AttendanceEventID.String(),
		"company_id":    event.CompanyID.String(),
		"user_id":       event.UserID.String(),
		"event_type":    event.EventType,
		"event_time":    event.EventTime,
		"source_type":   event.SourceType,
		"is_correction": event.Metadata.IsCorrection,
	}

	err = r.InsertAttendanceOutboxEvent(
		ctx,
		"attendance.event.created",
		event.AttendanceEventID,
		outboxPayload,
	)
	if err != nil {
		return fmt.Errorf("failed to insert into attendance outbox: %w", err)
	}

	// 3️⃣ Commit transaction
	if err = tx.Commit(); err != nil {
		return fmt.Errorf("failed to commit transaction: %w", err)
	}

	return nil
}

func (r *attendanceRepository) CreateBulkAttendanceEvents(
	ctx context.Context,
	events []*attendance.AttendanceEvent,
) error {
	tx, err := r.client.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("failed to begin transaction: %w", err)
	}
	defer func() {
		if err != nil {
			tx.Rollback()
		}
	}()

	query := `
		INSERT INTO attendance_events (
			attendance_event_id,
			company_id,
			user_id,
			event_type,
			event_time,
			source_type,
			source_id,
			device_id,
			ip_address,
			context,
			metadata,
			created_at,
			created_by
		) VALUES (
			$1,$2,$3,$4,$5,
			$6,$7,$8,$9,
			$10,$11,$12,$13
		)
	`

	stmt, err := tx.Prepare(query)
	if err != nil {
		return fmt.Errorf("failed to prepare statement: %w", err)
	}
	defer stmt.Close()

	for _, event := range events {
		if event.AttendanceEventID == uuid.Nil {
			event.AttendanceEventID = uuid.New()
		}
		if event.CreatedAt.IsZero() {
			event.CreatedAt = time.Now().UTC()
		}

		contextJSON, _ := json.Marshal(event.Context)
		metadataJSON, _ := json.Marshal(event.Metadata)

		_, err := stmt.ExecContext(ctx,
			event.AttendanceEventID,
			event.CompanyID,
			event.UserID,
			event.EventType,
			event.EventTime,
			event.SourceType,
			event.SourceID,
			event.DeviceID,
			event.IPAddress,
			contextJSON,
			metadataJSON,
			event.CreatedAt,
			event.CreatedBy,
		)
		if err != nil {
			return fmt.Errorf("failed to insert event %s: %w", event.AttendanceEventID, err)
		}
	}

	if err := tx.Commit(); err != nil {
		return fmt.Errorf("failed to commit transaction: %w", err)
	}
	return nil
}

func (r *attendanceRepository) GetAttendanceEventsByCompany(
	ctx context.Context,
	companyID uuid.UUID,
	startDate, endDate time.Time,
	page, pageSize int,
) ([]*attendance.AttendanceEvent, int64, error) {
	offset := (page - 1) * pageSize

	countQuery := `
        SELECT COUNT(*) FROM attendance_events
        WHERE company_id = $1
        AND event_time BETWEEN $2 AND $3
    `
	row := r.client.QueryRow(ctx, countQuery, companyID, startDate, endDate)
	var total int64
	err := row.Scan(&total)
	if err != nil {
		return nil, 0, fmt.Errorf("failed to count attendance events: %w", err)
	}

	query := `
        SELECT 
			attendance_event_id,
			company_id,
			user_id,
			event_type,
			event_time,
			source_type,
			source_id,
			device_id,
			ip_address,
			context,
			metadata,
			created_at,
			created_by
        FROM attendance_events
        WHERE company_id = $1
        AND event_time BETWEEN $2 AND $3
        ORDER BY event_time DESC
        LIMIT $4 OFFSET $5
    `

	rows, err := r.client.Query(ctx, query, companyID, startDate, endDate, pageSize, offset)
	if err != nil {
		r.logger.Error("Failed to get attendance events by company",
			util.String("company_id", companyID.String()),
			util.ErrorField(err))
		return nil, 0, fmt.Errorf("failed to get attendance events: %w", err)
	}
	defer rows.Close()

	var events []*attendance.AttendanceEvent
	for rows.Next() {
		var event attendance.AttendanceEvent
		if err := scanAttendanceEvent(rows, &event); err != nil {
			return nil, 0, fmt.Errorf("failed to scan event: %w", err)
		}
		events = append(events, &event)
	}

	if err = rows.Err(); err != nil {
		return nil, 0, fmt.Errorf("rows iteration error: %w", err)
	}
	return events, total, nil
}

func (r *attendanceRepository) SearchAttendanceEvents(
	ctx context.Context,
	filter AttendanceEventFilter,
) ([]*attendance.AttendanceEvent, int64, error) {
	var conditions []string
	var args []interface{}
	argIdx := 1

	conditions = append(conditions, fmt.Sprintf("company_id = $%d", argIdx))
	args = append(args, filter.CompanyID)
	argIdx++

	conditions = append(conditions, fmt.Sprintf("event_time BETWEEN $%d AND $%d", argIdx, argIdx+1))
	args = append(args, filter.StartDate, filter.EndDate)
	argIdx += 2

	if filter.UserID != nil {
		conditions = append(conditions, fmt.Sprintf("user_id = $%d", argIdx))
		args = append(args, *filter.UserID)
		argIdx++
	}

	if filter.EventType != nil {
		conditions = append(conditions, fmt.Sprintf("event_type = $%d", argIdx))
		args = append(args, *filter.EventType)
		argIdx++
	}

	if filter.SourceType != nil {
		conditions = append(conditions, fmt.Sprintf("source_type = $%d", argIdx))
		args = append(args, *filter.SourceType)
		argIdx++
	}

	whereClause := ""
	if len(conditions) > 0 {
		whereClause = "WHERE " + strings.Join(conditions, " AND ")
	}

	countQuery := fmt.Sprintf(`
        SELECT COUNT(*) FROM attendance_events
        %s
    `, whereClause)

	row := r.client.QueryRow(ctx, countQuery, args...)
	var total int64
	err := row.Scan(&total)
	if err != nil {
		return nil, 0, fmt.Errorf("failed to count attendance events: %w", err)
	}

	offset := (filter.Page - 1) * filter.PageSize
	query := fmt.Sprintf(`
        SELECT 
			attendance_event_id,
			company_id,
			user_id,
			event_type,
			event_time,
			source_type,
			source_id,
			device_id,
			ip_address,
			context,
			metadata,
			created_at,
			created_by
        FROM attendance_events
        %s
        ORDER BY event_time DESC
        LIMIT $%d OFFSET $%d
    `, whereClause, argIdx, argIdx+1)

	args = append(args, filter.PageSize, offset)

	rows, err := r.client.Query(ctx, query, args...)
	if err != nil {
		return nil, 0, fmt.Errorf("failed to search attendance events: %w", err)
	}
	defer rows.Close()

	var events []*attendance.AttendanceEvent
	for rows.Next() {
		var event attendance.AttendanceEvent
		if err := scanAttendanceEvent(rows, &event); err != nil {
			return nil, 0, fmt.Errorf("failed to scan event: %w", err)
		}
		events = append(events, &event)
	}

	if err = rows.Err(); err != nil {
		return nil, 0, fmt.Errorf("rows iteration error: %w", err)
	}
	return events, total, nil
}

func (r *attendanceRepository) GetAttendanceEventsByUser(
	ctx context.Context,
	userID uuid.UUID,
	startDate, endDate time.Time,
	limit int,
) ([]*attendance.AttendanceEvent, error) {
	query := `
        SELECT 
			attendance_event_id,
			company_id,
			user_id,
			event_type,
			event_time,
			source_type,
			source_id,
			device_id,
			ip_address,
			context,
			metadata,
			created_at,
			created_by
        FROM attendance_events
        WHERE user_id = $1
          AND event_time BETWEEN $2 AND $3
        ORDER BY event_time ASC
    `

	rows, err := r.client.Query(ctx, query, userID, startDate, endDate)
	if err != nil {
		r.logger.Error("Failed to get attendance events by user",
			util.String("user_id", userID.String()),
			util.ErrorField(err))
		return nil, fmt.Errorf("failed to get attendance events: %w", err)
	}
	defer rows.Close()

	var events []*attendance.AttendanceEvent
	for rows.Next() {
		var event attendance.AttendanceEvent
		if err := scanAttendanceEvent(rows, &event); err != nil {
			return nil, fmt.Errorf("failed to scan event: %w", err)
		}
		events = append(events, &event)
	}

	if err = rows.Err(); err != nil {
		return nil, fmt.Errorf("rows iteration error: %w", err)
	}
	return events, nil
}

func (r *attendanceRepository) GetAttendanceEventByID(
	ctx context.Context,
	eventID uuid.UUID,
) (*attendance.AttendanceEvent, error) {
	query := `
        SELECT 
			attendance_event_id,
			company_id,
			user_id,
			event_type,
			event_time,
			source_type,
			source_id,
			device_id,
			ip_address,
			context,
			metadata,
			created_at,
			created_by
        FROM attendance_events
        WHERE attendance_event_id = $1
    `

	row := r.client.QueryRow(ctx, query, eventID)
	var event attendance.AttendanceEvent
	var contextJSON []byte
	var metadataJSON []byte

	err := row.Scan(
		&event.AttendanceEventID,
		&event.CompanyID,
		&event.UserID,
		&event.EventType,
		&event.EventTime,
		&event.SourceType,
		&event.SourceID,
		&event.DeviceID,
		&event.IPAddress,
		&contextJSON,
		&metadataJSON,
		&event.CreatedAt,
		&event.CreatedBy,
	)

	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, nil
		}
		r.logger.Error("Failed to get attendance event",
			util.String("event_id", eventID.String()),
			util.ErrorField(err))
		return nil, fmt.Errorf("failed to get attendance event: %w", err)
	}

	if len(contextJSON) > 0 {
		err = json.Unmarshal(contextJSON, &event.Context)
		if err != nil {
			return nil, fmt.Errorf("failed to unmarshal context: %w", err)
		}
	}

	if len(metadataJSON) > 0 {
		err = json.Unmarshal(metadataJSON, &event.Metadata)
		if err != nil {
			return nil, fmt.Errorf("failed to unmarshal metadata: %w", err)
		}
	}

	return &event, nil
}

func (r *attendanceRepository) FindExistingCorrection(
	ctx context.Context,
	companyID, userID uuid.UUID,
	eventType string,
	eventTime time.Time,
) (*attendance.AttendanceEvent, error) {
	query := `
		SELECT
			attendance_event_id,
			company_id,
			user_id,
			event_type,
			event_time,
			source_type,
			source_id,
			device_id,
			ip_address,
			context,
			metadata,
			created_at,
			created_by
		FROM attendance_events
		WHERE company_id = $1
		  AND user_id = $2
		  AND event_type = $3
		  AND event_time = $4
		  AND source_type = 'correction'
		LIMIT 1
	`

	row := r.client.QueryRow(ctx, query, companyID, userID, eventType, eventTime)
	var event attendance.AttendanceEvent
	var contextJSON []byte
	var metadataJSON []byte

	err := row.Scan(
		&event.AttendanceEventID,
		&event.CompanyID,
		&event.UserID,
		&event.EventType,
		&event.EventTime,
		&event.SourceType,
		&event.SourceID,
		&event.DeviceID,
		&event.IPAddress,
		&contextJSON,
		&metadataJSON,
		&event.CreatedAt,
		&event.CreatedBy,
	)

	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, nil
		}
		r.logger.Error(
			"Failed to find existing correction",
			util.String("company_id", companyID.String()),
			util.String("user_id", userID.String()),
			util.String("event_type", eventType),
			util.Time("event_time", eventTime),
			util.ErrorField(err),
		)
		return nil, fmt.Errorf("failed to find existing correction: %w", err)
	}

	if len(contextJSON) > 0 {
		if err := json.Unmarshal(contextJSON, &event.Context); err != nil {
			return nil, fmt.Errorf("failed to unmarshal context: %w", err)
		}
	}

	if len(metadataJSON) > 0 {
		if err := json.Unmarshal(metadataJSON, &event.Metadata); err != nil {
			return nil, fmt.Errorf("failed to unmarshal metadata: %w", err)
		}
	}

	return &event, nil
}

func (r *attendanceRepository) GetLastAttendanceEvent(
	ctx context.Context,
	companyID, userID uuid.UUID,
	eventType string,
	since time.Time,
) (*attendance.AttendanceEvent, error) {
	query := `
		SELECT
			attendance_event_id,
			company_id,
			user_id,
			event_type,
			event_time,
			source_type,
			source_id,
			device_id,
			ip_address,
			context,
			metadata,
			created_at,
			created_by
		FROM attendance_events
		WHERE company_id = $1
		  AND user_id = $2
		  AND event_type = $3
		  AND event_time >= $4
		  AND source_type != 'correction'
		ORDER BY event_time DESC
		LIMIT 1
	`

	row := r.client.QueryRow(ctx, query, companyID, userID, eventType, since)
	var event attendance.AttendanceEvent
	var contextJSON []byte
	var metadataJSON []byte

	err := row.Scan(
		&event.AttendanceEventID,
		&event.CompanyID,
		&event.UserID,
		&event.EventType,
		&event.EventTime,
		&event.SourceType,
		&event.SourceID,
		&event.DeviceID,
		&event.IPAddress,
		&contextJSON,
		&metadataJSON,
		&event.CreatedAt,
		&event.CreatedBy,
	)

	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, nil
		}
		r.logger.Error(
			"Failed to get last attendance event",
			util.String("company_id", companyID.String()),
			util.String("user_id", userID.String()),
			util.String("event_type", eventType),
			util.Time("since", since),
			util.ErrorField(err),
		)
		return nil, fmt.Errorf("failed to get last attendance event: %w", err)
	}

	if len(contextJSON) > 0 {
		if err := json.Unmarshal(contextJSON, &event.Context); err != nil {
			return nil, fmt.Errorf("failed to unmarshal context: %w", err)
		}
	}

	if len(metadataJSON) > 0 {
		if err := json.Unmarshal(metadataJSON, &event.Metadata); err != nil {
			return nil, fmt.Errorf("failed to unmarshal metadata: %w", err)
		}
	}

	return &event, nil
}

func scanAttendanceEvent(row *sql.Rows, event *attendance.AttendanceEvent) error {
	var contextJSON []byte
	var metadataJSON []byte

	err := row.Scan(
		&event.AttendanceEventID,
		&event.CompanyID,
		&event.UserID,
		&event.EventType,
		&event.EventTime,
		&event.SourceType,
		&event.SourceID,
		&event.DeviceID,
		&event.IPAddress,
		&contextJSON,
		&metadataJSON,
		&event.CreatedAt,
		&event.CreatedBy,
	)
	if err != nil {
		return err
	}

	if len(contextJSON) > 0 {
		_ = json.Unmarshal(contextJSON, &event.Context)
	}
	if len(metadataJSON) > 0 {
		_ = json.Unmarshal(metadataJSON, &event.Metadata)
	}
	return nil
}

func (r *attendanceRepository) GetAttendanceDailySummariesByUser(
	ctx context.Context,
	userID uuid.UUID,
	startDate, endDate time.Time,
) ([]*attendance.AttendanceDailySummary, error) {
	query := `
        SELECT * FROM attendance_daily_summary
        WHERE user_id = $1
        AND attendance_date BETWEEN $2 AND $3
        ORDER BY attendance_date DESC
    `
	rows, err := r.client.Query(ctx, query, userID, startDate, endDate)
	if err != nil {
		r.logger.Error("Failed to get attendance daily summaries",
			util.String("user_id", userID.String()),
			util.ErrorField(err))
		return nil, fmt.Errorf("failed to get attendance daily summaries: %w", err)
	}
	defer rows.Close()
	var summaries []*attendance.AttendanceDailySummary
	for rows.Next() {
		var summary attendance.AttendanceDailySummary
		if err := scanAttendanceDailySummary(rows, &summary); err != nil {
			return nil, fmt.Errorf("failed to scan summary: %w", err)
		}
		summaries = append(summaries, &summary)
	}
	if err = rows.Err(); err != nil {
		return nil, fmt.Errorf("rows iteration error: %w", err)
	}
	return summaries, nil
}

func (r *attendanceRepository) GetAttendanceDailySummariesByCompany(
	ctx context.Context,
	companyID uuid.UUID,
	startDate, endDate time.Time,
	page, pageSize int,
) ([]*attendance.AttendanceDailySummary, int64, error) {
	offset := (page - 1) * pageSize
	countQuery := `
        SELECT COUNT(*) FROM attendance_daily_summary
        WHERE company_id = $1
        AND attendance_date BETWEEN $2 AND $3
    `
	row := r.client.QueryRow(ctx, countQuery, companyID, startDate, endDate)
	var total int64
	err := row.Scan(&total)
	if err != nil {
		return nil, 0, fmt.Errorf("failed to count attendance summaries: %w", err)
	}
	query := `
        SELECT * FROM attendance_daily_summary
        WHERE company_id = $1
        AND attendance_date BETWEEN $2 AND $3
        ORDER BY attendance_date DESC, user_id
        LIMIT $4 OFFSET $5
    `
	rows, err := r.client.Query(ctx, query, companyID, startDate, endDate, pageSize, offset)
	if err != nil {
		r.logger.Error("Failed to get attendance daily summaries by company",
			util.String("company_id", companyID.String()),
			util.ErrorField(err))
		return nil, 0, fmt.Errorf("failed to get attendance summaries: %w", err)
	}
	defer rows.Close()
	var summaries []*attendance.AttendanceDailySummary
	for rows.Next() {
		var summary attendance.AttendanceDailySummary
		if err := scanAttendanceDailySummary(rows, &summary); err != nil {
			return nil, 0, fmt.Errorf("failed to scan summary: %w", err)
		}
		summaries = append(summaries, &summary)
	}
	if err = rows.Err(); err != nil {
		return nil, 0, fmt.Errorf("rows iteration error: %w", err)
	}
	return summaries, total, nil
}

func (r *attendanceRepository) DeleteAttendanceDailySummary(
	ctx context.Context,
	summaryID uuid.UUID,
) error {
	query := `
        DELETE FROM attendance_daily_summary
        WHERE attendance_summary_id = $1
    `
	result, err := r.client.Exec(ctx, query, summaryID)
	if err != nil {
		r.logger.Error("Failed to delete attendance daily summary",
			util.String("summary_id", summaryID.String()),
			util.ErrorField(err))
		return fmt.Errorf("failed to delete attendance daily summary: %w", err)
	}
	rowsAffected, _ := result.RowsAffected()
	if rowsAffected == 0 {
		return fmt.Errorf("attendance daily summary not found")
	}
	return nil
}

func (r *attendanceRepository) GetAttendanceEventTypes(
	ctx context.Context,
) ([]*attendance.AttendanceEventType, error) {
	query := `
        SELECT
            event_type,
            category,
            description,
            is_user_triggered,
            is_system_generated,
            is_active
        FROM attendance_event_types
        WHERE is_active = true
        ORDER BY event_type
    `
	rows, err := r.client.Query(ctx, query)
	if err != nil {
		return nil, fmt.Errorf("failed to get attendance event types: %w", err)
	}
	defer rows.Close()
	var eventTypes []*attendance.AttendanceEventType
	for rows.Next() {
		var et attendance.AttendanceEventType
		if err := rows.Scan(
			&et.EventType,
			&et.Category,
			&et.Description,
			&et.IsUserTriggered,
			&et.IsSystemGenerated,
			&et.IsActive,
		); err != nil {
			return nil, fmt.Errorf("failed to scan event type: %w", err)
		}
		eventTypes = append(eventTypes, &et)
	}
	return eventTypes, nil
}

func (r *attendanceRepository) GetAttendanceSourceTypes(
	ctx context.Context,
) ([]*attendance.AttendanceSourceType, error) {

	query := `
        SELECT
            source_type,
            description,
            requires_device
        FROM attendance_source_types
        ORDER BY source_type
    `

	rows, err := r.client.Query(ctx, query)
	if err != nil {
		return nil, fmt.Errorf("failed to get attendance source types: %w", err)
	}
	defer rows.Close()

	var sourceTypes []*attendance.AttendanceSourceType

	for rows.Next() {
		var st attendance.AttendanceSourceType
		if err := rows.Scan(
			&st.SourceType,
			&st.Description,
			&st.RequiresDevice,
		); err != nil {
			return nil, fmt.Errorf("failed to scan source type: %w", err)
		}
		sourceTypes = append(sourceTypes, &st)
	}

	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("rows iteration error: %w", err)
	}

	return sourceTypes, nil
}

func (r *attendanceRepository) GetCompanyAttendanceRules(
	ctx context.Context,
	companyID uuid.UUID,
) (*attendance.CompanyAttendanceRules, error) {
	query := `
        SELECT
            company_id,
            allowed_source_types,
            allow_multiple_checkins,
            timezone,
            created_at
        FROM company_attendance_rules
        WHERE company_id = $1
    `
	row := r.client.QueryRow(ctx, query, companyID)
	var rules attendance.CompanyAttendanceRules
	var allowedSources []string
	err := row.Scan(
		&rules.CompanyID,
		pq.Array(&allowedSources),
		&rules.AllowMultipleCheckins,
		&rules.Timezone,
		&rules.CreatedAt,
	)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return &attendance.CompanyAttendanceRules{
				CompanyID:             companyID,
				AllowedSourceTypes:    []string{"mobile", "web", "biometric", "rfid"},
				AllowMultipleCheckins: true,
				Timezone:              "UTC",
				CreatedAt:             time.Now().UTC(),
			}, nil
		}
		r.logger.Error(
			"Failed to get company attendance rules",
			util.String("company_id", companyID.String()),
			util.ErrorField(err),
		)
		return nil, fmt.Errorf("failed to get company attendance rules: %w", err)
	}
	rules.AllowedSourceTypes = allowedSources
	return &rules, nil
}

func (r *attendanceRepository) UpsertCompanyAttendanceRules(
	ctx context.Context,
	rules *attendance.CompanyAttendanceRules,
) error {
	query := `
        INSERT INTO company_attendance_rules (
            company_id, allowed_source_types, allow_multiple_checkins, timezone, created_at
        ) VALUES ($1, $2, $3, $4, $5)
        ON CONFLICT (company_id) DO UPDATE SET
            allowed_source_types = EXCLUDED.allowed_source_types,
            allow_multiple_checkins = EXCLUDED.allow_multiple_checkins,
            timezone = EXCLUDED.timezone
    `
	if rules.CreatedAt.IsZero() {
		rules.CreatedAt = time.Now().UTC()
	}
	_, err := r.client.Exec(ctx, query,
		rules.CompanyID,
		pq.Array(rules.AllowedSourceTypes),
		rules.AllowMultipleCheckins,
		rules.Timezone,
		rules.CreatedAt,
	)
	if err != nil {
		r.logger.Error("Failed to upsert company attendance rules",
			util.String("company_id", rules.CompanyID.String()),
			util.ErrorField(err))
		return fmt.Errorf("failed to upsert company attendance rules: %w", err)
	}
	return nil
}

func (r *attendanceRepository) GetDepartmentAttendanceRules(
	ctx context.Context,
	companyID uuid.UUID,
	departmentID uuid.UUID,
) (*attendance.DepartmentAttendanceRules, error) {
	query := `
        SELECT
            rule_id,
            company_id,
            department_id,
            allowed_source_types,
            allowed_event_types,
            require_location,
            require_device,
            created_at
        FROM department_attendance_rules
        WHERE company_id = $1 AND department_id = $2
    `
	row := r.client.QueryRow(ctx, query, companyID, departmentID)
	var rules attendance.DepartmentAttendanceRules
	var allowedSources []string
	var allowedEvents []string
	err := row.Scan(
		&rules.RuleID,
		&rules.CompanyID,
		&rules.DepartmentID,
		pq.Array(&allowedSources),
		pq.Array(&allowedEvents),
		&rules.RequireLocation,
		&rules.RequireDevice,
		&rules.CreatedAt,
	)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, nil
		}
		r.logger.Error("Failed to get department attendance rules",
			util.String("company_id", companyID.String()),
			util.String("department_id", departmentID.String()),
			util.ErrorField(err))
		return nil, fmt.Errorf("failed to get department attendance rules: %w", err)
	}
	rules.AllowedSourceTypes = allowedSources
	rules.AllowedEventTypes = allowedEvents
	return &rules, nil
}

func (r *attendanceRepository) UpsertDepartmentAttendanceRules(
	ctx context.Context,
	rules *attendance.DepartmentAttendanceRules,
) error {
	if rules.RuleID == uuid.Nil {
		rules.RuleID = uuid.New()
	}
	query := `
        INSERT INTO department_attendance_rules (
            rule_id,
            company_id,
            department_id,
            allowed_source_types,
            allowed_event_types,
            require_location,
            require_device,
            created_at
        ) VALUES ($1, $2, $3, $4, $5, $6, $7, $8)
        ON CONFLICT (company_id, department_id) DO UPDATE SET
            allowed_source_types = EXCLUDED.allowed_source_types,
            allowed_event_types = EXCLUDED.allowed_event_types,
            require_location = EXCLUDED.require_location,
            require_device = EXCLUDED.require_device
    `
	if rules.CreatedAt.IsZero() {
		rules.CreatedAt = time.Now().UTC()
	}
	_, err := r.client.Exec(ctx, query,
		rules.RuleID,
		rules.CompanyID,
		rules.DepartmentID,
		pq.Array(rules.AllowedSourceTypes),
		pq.Array(rules.AllowedEventTypes),
		rules.RequireLocation,
		rules.RequireDevice,
		rules.CreatedAt,
	)
	if err != nil {
		r.logger.Error(
			"Failed to upsert department attendance rules",
			util.String("company_id", rules.CompanyID.String()),
			util.String("department_id", rules.DepartmentID.String()),
			util.ErrorField(err),
		)
		return fmt.Errorf("failed to upsert department attendance rules: %w", err)
	}
	return nil
}

func (r *attendanceRepository) GetUserAttendanceProfile(
	ctx context.Context,
	userID uuid.UUID,
) (*attendance.UserAttendanceProfile, error) {
	query := `
        SELECT
            user_id,
            company_id,
            override_source_types,
            override_event_types,
            created_at
        FROM user_attendance_profiles
        WHERE user_id = $1
    `
	row := r.client.QueryRow(ctx, query, userID)
	var profile attendance.UserAttendanceProfile
	var overrideSources []string
	var overrideEvents []string
	err := row.Scan(
		&profile.UserID,
		&profile.CompanyID,
		pq.Array(&overrideSources),
		pq.Array(&overrideEvents),
		&profile.CreatedAt,
	)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, nil
		}
		r.logger.Error(
			"Failed to get user attendance profile",
			util.String("user_id", userID.String()),
			util.ErrorField(err),
		)
		return nil, fmt.Errorf("failed to get user attendance profile: %w", err)
	}
	profile.OverrideSourceTypes = overrideSources
	profile.OverrideEventTypes = overrideEvents
	return &profile, nil
}

func (r *attendanceRepository) UpsertUserAttendanceProfile(
	ctx context.Context,
	profile *attendance.UserAttendanceProfile,
) error {
	query := `
        INSERT INTO user_attendance_profiles (
            user_id,
            company_id,
            override_source_types,
            override_event_types,
            created_at
        ) VALUES ($1, $2, $3, $4, $5)
        ON CONFLICT (user_id) DO UPDATE SET
            override_source_types = EXCLUDED.override_source_types,
            override_event_types = EXCLUDED.override_event_types
    `
	if profile.CreatedAt.IsZero() {
		profile.CreatedAt = time.Now().UTC()
	}
	_, err := r.client.Exec(ctx, query,
		profile.UserID,
		profile.CompanyID,
		pq.Array(profile.OverrideSourceTypes),
		pq.Array(profile.OverrideEventTypes),
		profile.CreatedAt,
	)
	if err != nil {
		r.logger.Error(
			"Failed to upsert user attendance profile",
			util.String("user_id", profile.UserID.String()),
			util.ErrorField(err),
		)
		return fmt.Errorf("failed to upsert user attendance profile: %w", err)
	}
	return nil
}

func (r *attendanceRepository) CreateAttendanceSource(
	ctx context.Context,
	source *attendance.AttendanceSource,
) error {
	query := `
        INSERT INTO attendance_sources (
            source_id, company_id, source_type, name,
            reference_type, reference_id, is_active,
            created_at, created_by
        ) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)
    `
	if source.SourceID == uuid.Nil {
		source.SourceID = uuid.New()
	}
	if source.CreatedAt.IsZero() {
		source.CreatedAt = time.Now().UTC()
	}
	_, err := r.client.Exec(ctx, query,
		source.SourceID,
		source.CompanyID,
		source.SourceType,
		source.Name,
		source.ReferenceType,
		source.ReferenceID,
		source.IsActive,
		source.CreatedAt,
		source.CreatedBy,
	)
	if err != nil {
		r.logger.Error("Failed to create attendance source",
			util.String("source_id", source.SourceID.String()),
			util.String("name", source.Name),
			util.ErrorField(err))
		return fmt.Errorf("failed to create attendance source: %w", err)
	}
	return nil
}

func (r *attendanceRepository) GetAttendanceSourceByID(
	ctx context.Context,
	sourceID uuid.UUID,
) (*attendance.AttendanceSource, error) {
	query := `
        SELECT * FROM attendance_sources
        WHERE source_id = $1
    `
	row := r.client.QueryRow(ctx, query, sourceID)
	var source attendance.AttendanceSource
	err := row.Scan(
		&source.SourceID,
		&source.CompanyID,
		&source.SourceType,
		&source.Name,
		&source.ReferenceType,
		&source.ReferenceID,
		&source.IsActive,
		&source.CreatedAt,
		&source.CreatedBy,
	)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, nil
		}
		r.logger.Error("Failed to get attendance source",
			util.String("source_id", sourceID.String()),
			util.ErrorField(err))
		return nil, fmt.Errorf("failed to get attendance source: %w", err)
	}
	return &source, nil
}

func (r *attendanceRepository) GetAttendanceSourcesByCompany(
	ctx context.Context,
	companyID uuid.UUID,
	activeOnly bool,
) ([]*attendance.AttendanceSource, error) {
	query := `
        SELECT * FROM attendance_sources
        WHERE company_id = $1
        ORDER BY name
    `
	if activeOnly {
		query = `
            SELECT * FROM attendance_sources
            WHERE company_id = $1 AND is_active = true
            ORDER BY name
        `
	}
	rows, err := r.client.Query(ctx, query, companyID)
	if err != nil {
		r.logger.Error("Failed to get attendance sources",
			util.String("company_id", companyID.String()),
			util.ErrorField(err))
		return nil, fmt.Errorf("failed to get attendance sources: %w", err)
	}
	defer rows.Close()
	var sources []*attendance.AttendanceSource
	for rows.Next() {
		var source attendance.AttendanceSource
		err := rows.Scan(
			&source.SourceID,
			&source.CompanyID,
			&source.SourceType,
			&source.Name,
			&source.ReferenceType,
			&source.ReferenceID,
			&source.IsActive,
			&source.CreatedAt,
			&source.CreatedBy,
		)
		if err != nil {
			return nil, fmt.Errorf("failed to scan source: %w", err)
		}
		sources = append(sources, &source)
	}
	if err = rows.Err(); err != nil {
		return nil, fmt.Errorf("rows iteration error: %w", err)
	}
	return sources, nil
}

func (r *attendanceRepository) UpdateAttendanceSource(
	ctx context.Context,
	source *attendance.AttendanceSource,
) error {
	query := `
        UPDATE attendance_sources SET
            source_type = $1,
            name = $2,
            reference_type = $3,
            reference_id = $4,
            is_active = $5
        WHERE source_id = $6
    `
	result, err := r.client.Exec(ctx, query,
		source.SourceType,
		source.Name,
		source.ReferenceType,
		source.ReferenceID,
		source.IsActive,
		source.SourceID,
	)
	if err != nil {
		r.logger.Error("Failed to update attendance source",
			util.String("source_id", source.SourceID.String()),
			util.ErrorField(err))
		return fmt.Errorf("failed to update attendance source: %w", err)
	}
	rowsAffected, _ := result.RowsAffected()
	if rowsAffected == 0 {
		return fmt.Errorf("attendance source not found")
	}
	return nil
}

func (r *attendanceRepository) CreateAttendanceLocation(
	ctx context.Context,
	location *attendance.AttendanceLocation,
) error {
	query := `
        INSERT INTO attendance_locations (
            location_id, company_id, name, location_type,
            geo_lat, geo_lng, location_code, zone, is_active
        ) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)
    `
	if location.LocationID == uuid.Nil {
		location.LocationID = uuid.New()
	}
	_, err := r.client.Exec(ctx, query,
		location.LocationID,
		location.CompanyID,
		location.Name,
		location.LocationType,
		location.GeoLat,
		location.GeoLng,
		location.LocationCode,
		location.Zone,
		location.IsActive,
	)
	if err != nil {
		r.logger.Error("Failed to create attendance location",
			util.String("location_id", location.LocationID.String()),
			util.ErrorField(err))
		return fmt.Errorf("failed to create attendance location: %w", err)
	}
	return nil
}

func (r *attendanceRepository) GetAttendanceLocationByID(
	ctx context.Context,
	locationID uuid.UUID,
) (*attendance.AttendanceLocation, error) {
	query := `
        SELECT * FROM attendance_locations
        WHERE location_id = $1
    `
	row := r.client.QueryRow(ctx, query, locationID)
	var location attendance.AttendanceLocation
	err := row.Scan(
		&location.LocationID,
		&location.CompanyID,
		&location.Name,
		&location.LocationType,
		&location.GeoLat,
		&location.GeoLng,
		&location.LocationCode,
		&location.Zone,
		&location.IsActive,
	)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, nil
		}
		r.logger.Error("Failed to get attendance location",
			util.String("location_id", locationID.String()),
			util.ErrorField(err))
		return nil, fmt.Errorf("failed to get attendance location: %w", err)
	}
	return &location, nil
}

func (r *attendanceRepository) GetAttendanceLocationsByCompany(
	ctx context.Context,
	companyID uuid.UUID,
	activeOnly bool,
) ([]*attendance.AttendanceLocation, error) {
	query := `
        SELECT * FROM attendance_locations
        WHERE company_id = $1
        ORDER BY name
    `
	if activeOnly {
		query = `
            SELECT * FROM attendance_locations
            WHERE company_id = $1 AND is_active = true
            ORDER BY name
        `
	}
	rows, err := r.client.Query(ctx, query, companyID)
	if err != nil {
		r.logger.Error("Failed to get attendance locations",
			util.String("company_id", companyID.String()),
			util.ErrorField(err))
		return nil, fmt.Errorf("failed to get attendance locations: %w", err)
	}
	defer rows.Close()
	var locations []*attendance.AttendanceLocation
	for rows.Next() {
		var location attendance.AttendanceLocation
		err := rows.Scan(
			&location.LocationID,
			&location.CompanyID,
			&location.Name,
			&location.LocationType,
			&location.GeoLat,
			&location.GeoLng,
			&location.LocationCode,
			&location.Zone,
			&location.IsActive,
		)
		if err != nil {
			return nil, fmt.Errorf("failed to scan location: %w", err)
		}
		locations = append(locations, &location)
	}
	if err = rows.Err(); err != nil {
		return nil, fmt.Errorf("rows iteration error: %w", err)
	}
	return locations, nil
}

func (r *attendanceRepository) CreateEmployeeRFIDMapping(
	ctx context.Context,
	mapping *attendance.EmployeeRFIDMapping,
) error {
	query := `
        INSERT INTO employee_rfid_mappings (
            rfid_id, user_id, company_id, rfid_tag,
            is_active, assigned_at, unassigned_at,
            created_at, updated_at
        ) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)
    `
	if mapping.RFIDID == uuid.Nil {
		mapping.RFIDID = uuid.New()
	}
	if mapping.AssignedAt.IsZero() {
		now := time.Now().UTC()
		mapping.AssignedAt = now
		mapping.CreatedAt = now
		mapping.UpdatedAt = now
	}
	_, err := r.client.Exec(ctx, query,
		mapping.RFIDID,
		mapping.UserID,
		mapping.CompanyID,
		mapping.RFIDTag,
		mapping.IsActive,
		mapping.AssignedAt,
		mapping.UnassignedAt,
		mapping.CreatedAt,
		mapping.UpdatedAt,
	)
	if err != nil {
		r.logger.Error("Failed to create employee RFID mapping",
			util.String("rfid_id", mapping.RFIDID.String()),
			util.String("user_id", mapping.UserID.String()),
			util.ErrorField(err))
		return fmt.Errorf("failed to create employee RFID mapping: %w", err)
	}
	return nil
}

func (r *attendanceRepository) GetEmployeeRFIDMappingByUser(
	ctx context.Context,
	userID uuid.UUID,
) (*attendance.EmployeeRFIDMapping, error) {
	query := `
        SELECT * FROM employee_rfid_mappings
        WHERE user_id = $1
        AND is_active = true
        AND unassigned_at IS NULL
        ORDER BY assigned_at DESC
        LIMIT 1
    `
	row := r.client.QueryRow(ctx, query, userID)
	var mapping attendance.EmployeeRFIDMapping
	err := row.Scan(
		&mapping.RFIDID,
		&mapping.UserID,
		&mapping.CompanyID,
		&mapping.RFIDTag,
		&mapping.IsActive,
		&mapping.AssignedAt,
		&mapping.UnassignedAt,
		&mapping.CreatedAt,
		&mapping.UpdatedAt,
	)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, nil
		}
		r.logger.Error("Failed to get employee RFID mapping by user",
			util.String("user_id", userID.String()),
			util.ErrorField(err))
		return nil, fmt.Errorf("failed to get employee RFID mapping: %w", err)
	}
	return &mapping, nil
}

func (r *attendanceRepository) GetEmployeeRFIDMapping(
	ctx context.Context,
	rfidTag string,
) (*attendance.EmployeeRFIDMapping, error) {
	query := `
        SELECT * FROM employee_rfid_mappings
        WHERE rfid_tag = $1
        AND is_active = true
        AND unassigned_at IS NULL
        ORDER BY assigned_at DESC
        LIMIT 1
    `
	row := r.client.QueryRow(ctx, query, rfidTag)
	var mapping attendance.EmployeeRFIDMapping
	err := row.Scan(
		&mapping.RFIDID,
		&mapping.UserID,
		&mapping.CompanyID,
		&mapping.RFIDTag,
		&mapping.IsActive,
		&mapping.AssignedAt,
		&mapping.UnassignedAt,
		&mapping.CreatedAt,
		&mapping.UpdatedAt,
	)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, nil
		}
		r.logger.Error("Failed to get employee RFID mapping",
			util.String("rfid_tag", rfidTag),
			util.ErrorField(err))
		return nil, fmt.Errorf("failed to get employee RFID mapping: %w", err)
	}
	return &mapping, nil
}

func (r *attendanceRepository) UpdateEmployeeRFIDMapping(
	ctx context.Context,
	mapping *attendance.EmployeeRFIDMapping,
) error {
	mapping.UpdatedAt = time.Now().UTC()
	query := `
        UPDATE employee_rfid_mappings SET
            user_id = $1,
            company_id = $2,
            rfid_tag = $3,
            is_active = $4,
            assigned_at = $5,
            unassigned_at = $6,
            updated_at = $7
        WHERE rfid_id = $8
    `
	result, err := r.client.Exec(ctx, query,
		mapping.UserID,
		mapping.CompanyID,
		mapping.RFIDTag,
		mapping.IsActive,
		mapping.AssignedAt,
		mapping.UnassignedAt,
		mapping.UpdatedAt,
		mapping.RFIDID,
	)
	if err != nil {
		r.logger.Error("Failed to update employee RFID mapping",
			util.String("rfid_id", mapping.RFIDID.String()),
			util.ErrorField(err))
		return fmt.Errorf("failed to update employee RFID mapping: %w", err)
	}
	rowsAffected, _ := result.RowsAffected()
	if rowsAffected == 0 {
		return fmt.Errorf("employee RFID mapping not found")
	}
	return nil
}

func (r *attendanceRepository) DeactivateEmployeeRFIDMapping(
	ctx context.Context,
	rfidID uuid.UUID,
) error {
	query := `
        UPDATE employee_rfid_mappings
        SET is_active = false, unassigned_at = $1
        WHERE rfid_id = $2
    `
	result, err := r.client.Exec(ctx, query, time.Now().UTC(), rfidID)
	if err != nil {
		r.logger.Error("Failed to deactivate employee RFID mapping",
			util.String("rfid_id", rfidID.String()),
			util.ErrorField(err))
		return fmt.Errorf("failed to deactivate employee RFID mapping: %w", err)
	}
	rowsAffected, _ := result.RowsAffected()
	if rowsAffected == 0 {
		return fmt.Errorf("employee RFID mapping not found")
	}
	return nil
}

func (r *attendanceRepository) UpsertAttendanceDailySummary(
	ctx context.Context,
	summary *attendance.AttendanceDailySummary,
) error {
	query := `
		INSERT INTO attendance_daily_summary (
			attendance_summary_id,
			company_id,
			user_id,
			attendance_date,
			status,
			worked_minutes,
			overtime_minutes,
			late_minutes,
			metadata,
			generated_at,
			generated_by
		) VALUES (
			$1, $2, $3, $4, $5,
			$6, $7, $8, $9,
			$10, $11
		)
		ON CONFLICT (company_id, user_id, attendance_date)
		DO UPDATE SET
			status           = EXCLUDED.status,
			worked_minutes   = EXCLUDED.worked_minutes,
			overtime_minutes = EXCLUDED.overtime_minutes,
			late_minutes     = EXCLUDED.late_minutes,
			metadata         = EXCLUDED.metadata,
			generated_at     = EXCLUDED.generated_at,
			generated_by     = EXCLUDED.generated_by
	`
	if summary.AttendanceSummaryID == uuid.Nil {
		summary.AttendanceSummaryID = uuid.New()
	}
	if summary.GeneratedAt.IsZero() {
		summary.GeneratedAt = time.Now().UTC()
	}
	metadataJSON, _ := json.Marshal(summary.Metadata)
	_, err := r.client.Exec(ctx, query,
		summary.AttendanceSummaryID,
		summary.CompanyID,
		summary.UserID,
		summary.AttendanceDate,
		summary.Status,
		summary.WorkedMinutes,
		summary.OvertimeMinutes,
		summary.LateMinutes,
		metadataJSON,
		summary.GeneratedAt,
		summary.GeneratedBy,
	)
	if err != nil {
		r.logger.Error(
			"Failed to upsert attendance daily summary",
			util.String("company_id", summary.CompanyID.String()),
			util.String("user_id", summary.UserID.String()),
			util.String("date", summary.AttendanceDate.Format("2006-01-02")),
			util.ErrorField(err),
		)
		return fmt.Errorf("failed to upsert attendance daily summary: %w", err)
	}
	return nil
}

func (r *attendanceRepository) GetDistinctUsersWithEvents(
	ctx context.Context,
	companyID uuid.UUID,
	startDate, endDate time.Time,
) ([]uuid.UUID, error) {
	query := `
		SELECT DISTINCT user_id
		FROM attendance_events
		WHERE company_id = $1
		  AND event_time BETWEEN $2 AND $3
	`
	rows, err := r.client.Query(ctx, query, companyID, startDate, endDate)
	if err != nil {
		r.logger.Error(
			"Failed to get distinct users with attendance events",
			util.String("company_id", companyID.String()),
			util.ErrorField(err),
		)
		return nil, fmt.Errorf("failed to get distinct users with events: %w", err)
	}
	defer rows.Close()
	var userIDs []uuid.UUID
	for rows.Next() {
		var userID uuid.UUID
		if err := rows.Scan(&userID); err != nil {
			return nil, fmt.Errorf("failed to scan user_id: %w", err)
		}
		userIDs = append(userIDs, userID)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("rows iteration error: %w", err)
	}
	return userIDs, nil
}

func (r *attendanceRepository) GetAttendanceStats(
	ctx context.Context,
	companyID uuid.UUID,
	startDate, endDate time.Time,
) (*attendance.AttendanceStats, error) {
	query := `
        SELECT
            COUNT(DISTINCT user_id) as total_employees,
            SUM(CASE WHEN status = 'present' THEN 1 ELSE 0 END) as present_count,
            SUM(CASE WHEN status = 'absent' THEN 1 ELSE 0 END) as absent_count,
            SUM(CASE WHEN status = 'late' THEN 1 ELSE 0 END) as late_count,
            SUM(CASE WHEN status = 'half_day' THEN 1 ELSE 0 END) as half_day_count,
            SUM(CASE WHEN status = 'leave' THEN 1 ELSE 0 END) as leave_count,
            SUM(CASE WHEN status = 'holiday' THEN 1 ELSE 0 END) as holiday_count,
            COALESCE(SUM(worked_minutes), 0) / 60.0 as total_worked_hours,
            COALESCE(SUM(overtime_minutes), 0) / 60.0 as total_overtime_hours
        FROM attendance_daily_summary
        WHERE company_id = $1
        AND attendance_date BETWEEN $2 AND $3
    `
	row := r.client.QueryRow(ctx, query, companyID, startDate, endDate)
	var stats attendance.AttendanceStats
	err := row.Scan(
		&stats.TotalEmployees,
		&stats.PresentCount,
		&stats.AbsentCount,
		&stats.LateCount,
		&stats.HalfDayCount,
		&stats.LeaveCount,
		&stats.HolidayCount,
		&stats.TotalWorkedHours,
		&stats.TotalOvertimeHours,
	)
	if err != nil {
		r.logger.Error("Failed to get attendance stats",
			util.String("company_id", companyID.String()),
			util.ErrorField(err))
		return nil, fmt.Errorf("failed to get attendance stats: %w", err)
	}
	stats.CompanyID = companyID
	stats.StartDate = startDate
	stats.EndDate = endDate
	if stats.TotalEmployees > 0 {
		stats.AverageAttendance = (float64(stats.PresentCount) / float64(stats.TotalEmployees)) * 100
	}
	return &stats, nil
}

func (r *attendanceRepository) GetUserAttendanceStats(
	ctx context.Context,
	userID uuid.UUID,
	startDate, endDate time.Time,
) (*attendance.UserAttendanceStats, error) {
	query := `
        SELECT
            SUM(CASE WHEN status = 'present' THEN 1 ELSE 0 END) as present_days,
            SUM(CASE WHEN status = 'absent' THEN 1 ELSE 0 END) as absent_days,
            SUM(CASE WHEN status = 'late' THEN 1 ELSE 0 END) as late_days,
            SUM(CASE WHEN status = 'half_day' THEN 1 ELSE 0 END) as half_days,
            SUM(CASE WHEN status = 'leave' THEN 1 ELSE 0 END) as leave_days,
            COALESCE(SUM(worked_minutes), 0) / 60.0 as total_worked_hours,
            COALESCE(SUM(overtime_minutes), 0) / 60.0 as total_overtime_hours
        FROM attendance_daily_summary
        WHERE user_id = $1
        AND attendance_date BETWEEN $2 AND $3
    `
	row := r.client.QueryRow(ctx, query, userID, startDate, endDate)
	var stats attendance.UserAttendanceStats
	err := row.Scan(
		&stats.PresentDays,
		&stats.AbsentDays,
		&stats.LateDays,
		&stats.HalfDays,
		&stats.LeaveDays,
		&stats.TotalWorkedHours,
		&stats.TotalOvertimeHours,
	)
	if err != nil {
		r.logger.Error("Failed to get user attendance stats",
			util.String("user_id", userID.String()),
			util.ErrorField(err))
		return nil, fmt.Errorf("failed to get user attendance stats: %w", err)
	}
	stats.UserID = userID
	stats.StartDate = startDate
	stats.EndDate = endDate
	totalDays := float64(stats.PresentDays + stats.AbsentDays + stats.LeaveDays)
	if totalDays > 0 {
		stats.AttendancePercent = (float64(stats.PresentDays) / totalDays) * 100
	}
	avgTimesQuery := `
        SELECT
            AVG(EXTRACT(HOUR FROM (metadata->>'check_in_time')::timestamp)) as avg_in_hour,
            AVG(EXTRACT(HOUR FROM (metadata->>'check_out_time')::timestamp)) as avg_out_hour
        FROM attendance_daily_summary
        WHERE user_id = $1
        AND attendance_date BETWEEN $2 AND $3
        AND metadata->>'check_in_time' IS NOT NULL
        AND metadata->>'check_out_time' IS NOT NULL
    `
	row = r.client.QueryRow(ctx, avgTimesQuery, userID, startDate, endDate)
	var avgInHour, avgOutHour sql.NullFloat64
	err = row.Scan(&avgInHour, &avgOutHour)
	if err == nil {
		if avgInHour.Valid && avgInHour.Float64 > 0 {
			stats.AverageInTime = fmt.Sprintf("%02.0f:%02.0f", avgInHour.Float64, (avgInHour.Float64-float64(int(avgInHour.Float64)))*60)
		}
		if avgOutHour.Valid && avgOutHour.Float64 > 0 {
			stats.AverageOutTime = fmt.Sprintf("%02.0f:%02.0f", avgOutHour.Float64, (avgOutHour.Float64-float64(int(avgOutHour.Float64)))*60)
		}
	}
	return &stats, nil
}

func (r *attendanceRepository) HealthCheck(ctx context.Context) error {
	query := `SELECT 1`
	var result int
	row := r.client.QueryRow(ctx, query)
	err := row.Scan(&result)
	if err != nil {
		r.logger.Error("Attendance repository health check failed",
			util.ErrorField(err))
		return fmt.Errorf("attendance repository health check failed: %w", err)
	}
	return nil
}

func scanAttendanceDailySummary(row *sql.Rows, summary *attendance.AttendanceDailySummary) error {
	var metadataJSON []byte
	err := row.Scan(
		&summary.AttendanceSummaryID,
		&summary.CompanyID,
		&summary.UserID,
		&summary.AttendanceDate,
		&summary.Status,
		&summary.WorkedMinutes,
		&summary.OvertimeMinutes,
		&summary.LateMinutes,
		&metadataJSON,
		&summary.GeneratedAt,
		&summary.GeneratedBy,
	)
	if err != nil {
		return err
	}
	if len(metadataJSON) > 0 {
		err = json.Unmarshal(metadataJSON, &summary.Metadata)
		if err != nil {
			return fmt.Errorf("failed to unmarshal metadata: %w", err)
		}
	}
	return nil
}

// ============================================================
// POLICY-BASED METHODS WITH WORK CENTER UPDATES
// ============================================================

func (r *attendanceRepository) CreateAttendancePolicy(
	ctx context.Context,
	policy *attendance.AttendancePolicy,
) error {
	query := `
        INSERT INTO attendance_policies (
            policy_id,
            company_id,
            work_center_code,
            position_id,
            policy_code,
            policy_type,
            rules,
            is_active,
            created_at,
            updated_at
        ) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10)
    `
	if policy.PolicyID == uuid.Nil {
		policy.PolicyID = uuid.New()
	}
	if policy.CreatedAt.IsZero() {
		now := time.Now().UTC()
		policy.CreatedAt = now
		policy.UpdatedAt = now
	}
	rulesJSON, _ := json.Marshal(policy.Rules)
	_, err := r.client.Exec(ctx, query,
		policy.PolicyID,
		policy.CompanyID,
		policy.WorkCenterCode, // 🔥 NEW
		policy.PositionID,
		policy.PolicyCode,
		policy.PolicyType,
		rulesJSON,
		policy.IsActive,
		policy.CreatedAt,
		policy.UpdatedAt,
	)
	if err != nil {
		r.logger.Error("Failed to create attendance policy",
			util.String("policy_id", policy.PolicyID.String()),
			util.String("policy_code", policy.PolicyCode),
			util.ErrorField(err))
		return fmt.Errorf("failed to create attendance policy: %w", err)
	}
	return nil
}

func (r *attendanceRepository) GetAttendancePolicyByID(
	ctx context.Context,
	policyID uuid.UUID,
) (*attendance.AttendancePolicy, error) {
	query := `
        SELECT * FROM attendance_policies
        WHERE policy_id = $1
    `
	row := r.client.QueryRow(ctx, query, policyID)
	var policy attendance.AttendancePolicy
	var rulesJSON []byte
	err := row.Scan(
		&policy.PolicyID,
		&policy.CompanyID,
		&policy.WorkCenterCode, // 🔥 NEW
		&policy.PositionID,
		&policy.PolicyCode,
		&policy.PolicyType,
		&rulesJSON,
		&policy.IsActive,
		&policy.CreatedAt,
		&policy.UpdatedAt,
	)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, nil
		}
		r.logger.Error("Failed to get attendance policy",
			util.String("policy_id", policyID.String()),
			util.ErrorField(err))
		return nil, fmt.Errorf("failed to get attendance policy: %w", err)
	}
	if len(rulesJSON) > 0 {
		err = json.Unmarshal(rulesJSON, &policy.Rules)
		if err != nil {
			return nil, fmt.Errorf("failed to unmarshal rules: %w", err)
		}
	}
	return &policy, nil
}

func (r *attendanceRepository) GetAttendancePoliciesByCompany(
	ctx context.Context,
	companyID uuid.UUID,
	activeOnly bool,
) ([]*attendance.AttendancePolicy, error) {
	query := `
        SELECT * FROM attendance_policies
        WHERE company_id = $1
        ORDER BY policy_code
    `
	if activeOnly {
		query = `
            SELECT * FROM attendance_policies
            WHERE company_id = $1 AND is_active = true
            ORDER BY policy_code
        `
	}
	rows, err := r.client.Query(ctx, query, companyID)
	if err != nil {
		r.logger.Error("Failed to get attendance policies",
			util.String("company_id", companyID.String()),
			util.ErrorField(err))
		return nil, fmt.Errorf("failed to get attendance policies: %w", err)
	}
	defer rows.Close()
	var policies []*attendance.AttendancePolicy
	for rows.Next() {
		var policy attendance.AttendancePolicy
		var rulesJSON []byte
		err := rows.Scan(
			&policy.PolicyID,
			&policy.CompanyID,
			&policy.WorkCenterCode, // 🔥 NEW
			&policy.PositionID,
			&policy.PolicyCode,
			&policy.PolicyType,
			&rulesJSON,
			&policy.IsActive,
			&policy.CreatedAt,
			&policy.UpdatedAt,
		)
		if err != nil {
			return nil, fmt.Errorf("failed to scan policy: %w", err)
		}
		if len(rulesJSON) > 0 {
			err = json.Unmarshal(rulesJSON, &policy.Rules)
			if err != nil {
				return nil, fmt.Errorf("failed to unmarshal rules: %w", err)
			}
		}
		policies = append(policies, &policy)
	}
	if err = rows.Err(); err != nil {
		return nil, fmt.Errorf("rows iteration error: %w", err)
	}
	return policies, nil
}

func (r *attendanceRepository) UpdateAttendancePolicy(
	ctx context.Context,
	policy *attendance.AttendancePolicy,
) error {
	policy.UpdatedAt = time.Now().UTC()
	query := `
        UPDATE attendance_policies SET
            work_center_code = $1,
            position_id = $2,
            policy_code = $3,
            policy_type = $4,
            rules = $5,
            is_active = $6,
            updated_at = $7
        WHERE policy_id = $8
    `
	rulesJSON, _ := json.Marshal(policy.Rules)
	result, err := r.client.Exec(ctx, query,
		policy.WorkCenterCode, // 🔥 NEW
		policy.PositionID,
		policy.PolicyCode,
		policy.PolicyType,
		rulesJSON,
		policy.IsActive,
		policy.UpdatedAt,
		policy.PolicyID,
	)
	if err != nil {
		r.logger.Error("Failed to update attendance policy",
			util.String("policy_id", policy.PolicyID.String()),
			util.ErrorField(err))
		return fmt.Errorf("failed to update attendance policy: %w", err)
	}
	rowsAffected, _ := result.RowsAffected()
	if rowsAffected == 0 {
		return fmt.Errorf("attendance policy not found")
	}
	return nil
}

func (r *attendanceRepository) DeleteAttendancePolicy(
	ctx context.Context,
	policyID uuid.UUID,
) error {
	query := `
        DELETE FROM attendance_policies
        WHERE policy_id = $1
    `
	result, err := r.client.Exec(ctx, query, policyID)
	if err != nil {
		r.logger.Error("Failed to delete attendance policy",
			util.String("policy_id", policyID.String()),
			util.ErrorField(err))
		return fmt.Errorf("failed to delete attendance policy: %w", err)
	}
	rowsAffected, _ := result.RowsAffected()
	if rowsAffected == 0 {
		return fmt.Errorf("attendance policy not found")
	}
	return nil
}

func (r *attendanceRepository) AssignUserAttendancePolicy(
	ctx context.Context,
	assignment *attendance.UserAttendancePolicy,
) error {
	query := `
        INSERT INTO user_attendance_policies (
            user_id, policy_id, effective_from, effective_to,
            assigned_by, created_at
        ) VALUES ($1, $2, $3, $4, $5, $6)
    `
	if assignment.CreatedAt.IsZero() {
		assignment.CreatedAt = time.Now().UTC()
	}
	_, err := r.client.Exec(ctx, query,
		assignment.UserID,
		assignment.PolicyID,
		assignment.EffectiveFrom,
		assignment.EffectiveTo,
		assignment.AssignedBy,
		assignment.CreatedAt,
	)
	if err != nil {
		r.logger.Error("Failed to assign user attendance policy",
			util.String("user_id", assignment.UserID.String()),
			util.String("policy_id", assignment.PolicyID.String()),
			util.ErrorField(err))
		return fmt.Errorf("failed to assign user attendance policy: %w", err)
	}
	return nil
}

func (r *attendanceRepository) GetUserActiveAttendancePolicy(
	ctx context.Context,
	userID uuid.UUID,
	at time.Time,
) (*attendance.AttendancePolicy, error) {
	query := `
        SELECT ap.*
        FROM user_attendance_policies uap
        JOIN attendance_policies ap ON uap.policy_id = ap.policy_id
        WHERE uap.user_id = $1
        AND uap.effective_from <= $2
        AND (uap.effective_to IS NULL OR uap.effective_to >= $2)
        AND ap.is_active = true
        ORDER BY uap.effective_from DESC
        LIMIT 1
    `
	row := r.client.QueryRow(ctx, query, userID, at)
	var policy attendance.AttendancePolicy
	var rulesJSON []byte
	err := row.Scan(
		&policy.PolicyID,
		&policy.CompanyID,
		&policy.WorkCenterCode, // 🔥 NEW (must be included in SELECT ap.*)
		&policy.PositionID,
		&policy.PolicyCode,
		&policy.PolicyType,
		&rulesJSON,
		&policy.IsActive,
		&policy.CreatedAt,
		&policy.UpdatedAt,
	)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, nil
		}
		r.logger.Error("Failed to get user active attendance policy",
			util.String("user_id", userID.String()),
			util.ErrorField(err))
		return nil, fmt.Errorf("failed to get user active attendance policy: %w", err)
	}
	if len(rulesJSON) > 0 {
		err = json.Unmarshal(rulesJSON, &policy.Rules)
		if err != nil {
			return nil, fmt.Errorf("failed to unmarshal rules: %w", err)
		}
	}
	return &policy, nil
}

func (r *attendanceRepository) EndUserAttendancePolicy(
	ctx context.Context,
	userID, policyID uuid.UUID,
	endDate time.Time,
) error {
	query := `
        UPDATE user_attendance_policies
        SET effective_to = $1
        WHERE user_id = $2 AND policy_id = $3
        AND effective_to IS NULL
    `
	result, err := r.client.Exec(ctx, query, endDate, userID, policyID)
	if err != nil {
		r.logger.Error("Failed to end user attendance policy",
			util.String("user_id", userID.String()),
			util.String("policy_id", policyID.String()),
			util.ErrorField(err))
		return fmt.Errorf("failed to end user attendance policy: %w", err)
	}
	rowsAffected, _ := result.RowsAffected()
	if rowsAffected == 0 {
		return fmt.Errorf("active user attendance policy not found")
	}
	return nil
}

func (r *attendanceRepository) GetPositionAttendancePolicy(
	ctx context.Context,
	positionID uuid.UUID,
) (*attendance.AttendancePolicy, error) {
	query := `
        SELECT * FROM attendance_policies
        WHERE position_id = $1
        AND is_active = true
        ORDER BY created_at DESC
        LIMIT 1
    `
	row := r.client.QueryRow(ctx, query, positionID)
	var policy attendance.AttendancePolicy
	var rulesJSON []byte
	err := row.Scan(
		&policy.PolicyID,
		&policy.CompanyID,
		&policy.WorkCenterCode, // 🔥 NEW
		&policy.PositionID,
		&policy.PolicyCode,
		&policy.PolicyType,
		&rulesJSON,
		&policy.IsActive,
		&policy.CreatedAt,
		&policy.UpdatedAt,
	)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, nil
		}
		r.logger.Error("Failed to get position attendance policy",
			util.String("position_id", positionID.String()),
			util.ErrorField(err))
		return nil, fmt.Errorf("failed to get position attendance policy: %w", err)
	}
	if len(rulesJSON) > 0 {
		err = json.Unmarshal(rulesJSON, &policy.Rules)
		if err != nil {
			return nil, fmt.Errorf("failed to unmarshal rules: %w", err)
		}
	}
	return &policy, nil
}

// 🔥 6️⃣ ADD NEW METHOD: Work Center Policy Lookup
func (r *attendanceRepository) GetWorkCenterAttendancePolicy(
	ctx context.Context,
	companyID uuid.UUID,
	workCenterCode string,
) (*attendance.AttendancePolicy, error) {

	query := `
		SELECT *
		FROM attendance_policies
		WHERE company_id = $1
		  AND work_center_code = $2
		  AND is_active = true
		ORDER BY created_at DESC
		LIMIT 1
	`

	row := r.client.QueryRow(ctx, query, companyID, workCenterCode)

	var policy attendance.AttendancePolicy
	var rulesJSON []byte

	err := row.Scan(
		&policy.PolicyID,
		&policy.CompanyID,
		&policy.WorkCenterCode,
		&policy.PositionID,
		&policy.PolicyCode,
		&policy.PolicyType,
		&rulesJSON,
		&policy.IsActive,
		&policy.CreatedAt,
		&policy.UpdatedAt,
	)

	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, nil
		}
		return nil, fmt.Errorf("failed to get work center attendance policy: %w", err)
	}

	if len(rulesJSON) > 0 {
		_ = json.Unmarshal(rulesJSON, &policy.Rules)
	}

	return &policy, nil
}

func (r *attendanceRepository) GetUsersByAttendancePolicy(
	ctx context.Context,
	policyID uuid.UUID,
	effectiveDate time.Time,
) ([]uuid.UUID, error) {
	query := `
        SELECT uap.user_id
        FROM user_attendance_policies uap
        WHERE uap.policy_id = $1
        AND uap.effective_from <= $2
        AND (uap.effective_to IS NULL OR uap.effective_to >= $2)
        ORDER BY uap.user_id
    `
	rows, err := r.client.Query(ctx, query, policyID, effectiveDate)
	if err != nil {
		r.logger.Error("Failed to get users by attendance policy",
			util.String("policy_id", policyID.String()),
			util.ErrorField(err))
		return nil, fmt.Errorf("failed to get users by attendance policy: %w", err)
	}
	defer rows.Close()

	var userIDs []uuid.UUID
	for rows.Next() {
		var userID uuid.UUID
		if err := rows.Scan(&userID); err != nil {
			return nil, fmt.Errorf("failed to scan user_id: %w", err)
		}
		userIDs = append(userIDs, userID)
	}

	if err = rows.Err(); err != nil {
		return nil, fmt.Errorf("rows iteration error: %w", err)
	}
	return userIDs, nil
}

func (r *attendanceRepository) CreateAttendanceDailySummary(
	ctx context.Context,
	summary *attendance.AttendanceDailySummary,
) error {
	query := `
        INSERT INTO attendance_daily_summary (
            attendance_summary_id, company_id, user_id, attendance_date,
            status, worked_minutes, overtime_minutes, late_minutes,
            metadata, generated_at, generated_by
        ) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11)
    `
	if summary.AttendanceSummaryID == uuid.Nil {
		summary.AttendanceSummaryID = uuid.New()
	}
	if summary.GeneratedAt.IsZero() {
		summary.GeneratedAt = time.Now().UTC()
	}
	metadataJSON, _ := json.Marshal(summary.Metadata)
	_, err := r.client.Exec(ctx, query,
		summary.AttendanceSummaryID,
		summary.CompanyID,
		summary.UserID,
		summary.AttendanceDate,
		summary.Status,
		summary.WorkedMinutes,
		summary.OvertimeMinutes,
		summary.LateMinutes,
		metadataJSON,
		summary.GeneratedAt,
		summary.GeneratedBy,
	)
	if err != nil {
		r.logger.Error("Failed to create attendance daily summary",
			util.String("summary_id", summary.AttendanceSummaryID.String()),
			util.String("user_id", summary.UserID.String()),
			util.ErrorField(err))
		return fmt.Errorf("failed to create attendance daily summary: %w", err)
	}
	return nil
}

func (r *attendanceRepository) UpdateAttendanceDailySummary(
	ctx context.Context,
	summary *attendance.AttendanceDailySummary,
) error {
	query := `
        UPDATE attendance_daily_summary SET
            status = $1,
            worked_minutes = $2,
            overtime_minutes = $3,
            late_minutes = $4,
            metadata = $5,
            generated_at = $6,
            generated_by = $7
        WHERE attendance_summary_id = $8
    `
	metadataJSON, _ := json.Marshal(summary.Metadata)
	result, err := r.client.Exec(ctx, query,
		summary.Status,
		summary.WorkedMinutes,
		summary.OvertimeMinutes,
		summary.LateMinutes,
		metadataJSON,
		summary.GeneratedAt,
		summary.GeneratedBy,
		summary.AttendanceSummaryID,
	)
	if err != nil {
		r.logger.Error("Failed to update attendance daily summary",
			util.String("summary_id", summary.AttendanceSummaryID.String()),
			util.ErrorField(err))
		return fmt.Errorf("failed to update attendance daily summary: %w", err)
	}
	rowsAffected, _ := result.RowsAffected()
	if rowsAffected == 0 {
		return fmt.Errorf("attendance daily summary not found")
	}
	return nil
}

func (r *attendanceRepository) GetAttendanceDailySummaryByUserDate(
	ctx context.Context,
	userID uuid.UUID,
	date time.Time,
) (*attendance.AttendanceDailySummary, error) {
	query := `
        SELECT * FROM attendance_daily_summary
        WHERE user_id = $1
        AND attendance_date = $2
    `
	row := r.client.QueryRow(ctx, query, userID, date)
	var summary attendance.AttendanceDailySummary
	var metadataJSON []byte
	err := row.Scan(
		&summary.AttendanceSummaryID,
		&summary.CompanyID,
		&summary.UserID,
		&summary.AttendanceDate,
		&summary.Status,
		&summary.WorkedMinutes,
		&summary.OvertimeMinutes,
		&summary.LateMinutes,
		&metadataJSON,
		&summary.GeneratedAt,
		&summary.GeneratedBy,
	)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, nil
		}
		r.logger.Error("Failed to get attendance daily summary",
			util.String("user_id", userID.String()),
			util.String("date", date.Format("2006-01-02")),
			util.ErrorField(err))
		return nil, fmt.Errorf("failed to get attendance daily summary: %w", err)
	}
	if len(metadataJSON) > 0 {
		err = json.Unmarshal(metadataJSON, &summary.Metadata)
		if err != nil {
			return nil, fmt.Errorf("failed to unmarshal metadata: %w", err)
		}
	}
	return &summary, nil
}

func (r *attendanceRepository) InsertAttendanceOutboxEvent(
	ctx context.Context,
	eventType string,
	aggregateID uuid.UUID,
	payload map[string]interface{},
) error {
	query := `
        INSERT INTO attendance.attendance_events_outbox
        (event_type, aggregate_id, payload)
        VALUES ($1, $2, $3)
    `
	payloadJSON, _ := json.Marshal(payload)
	_, err := r.client.Exec(ctx, query,
		eventType,
		aggregateID,
		payloadJSON,
	)
	return err
}

type CompanyEmployee struct {
	CompanyID  uuid.UUID
	UserID     uuid.UUID
	PositionID *uuid.UUID
}

type Position struct {
	PositionID     uuid.UUID
	Title          string
	DepartmentID   uuid.UUID
	WorkCenterCode *string
}

type EmployeeDepartment struct {
	DepartmentID uuid.UUID
}

type Department struct {
	DepartmentID   uuid.UUID
	DepartmentName string
}

func (r *attendanceRepository) GetCompanyEmployee(
	ctx context.Context,
	companyID uuid.UUID,
	userID uuid.UUID,
) (*CompanyEmployee, error) {
	query := `
		SELECT
			company_id,
			user_id,
			position_id
		FROM company_employees
		WHERE company_id = $1
		  AND user_id = $2
		  AND is_active = true
		LIMIT 1
	`

	var ce CompanyEmployee
	err := r.client.QueryRow(ctx, query, companyID, userID).Scan(
		&ce.CompanyID,
		&ce.UserID,
		&ce.PositionID,
	)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, nil
		}
		r.logger.Error(
			"Failed to get company employee",
			util.String("company_id", companyID.String()),
			util.String("user_id", userID.String()),
			util.ErrorField(err),
		)
		return nil, err
	}

	return &ce, nil
}

func (r *attendanceRepository) GetPosition(
	ctx context.Context,
	positionID uuid.UUID,
) (*Position, error) {
	query := `
		SELECT
			position_id,
			title,
			department_id,
			work_center_code
		FROM positions
		WHERE position_id = $1
		  AND is_active = true
	`

	var p Position
	err := r.client.QueryRow(ctx, query, positionID).Scan(
		&p.PositionID,
		&p.Title,
		&p.DepartmentID,
		&p.WorkCenterCode,
	)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, nil
		}
		r.logger.Error(
			"Failed to get position",
			util.String("position_id", positionID.String()),
			util.ErrorField(err),
		)
		return nil, err
	}

	return &p, nil
}

func (r *attendanceRepository) GetEmployeeActiveDepartment(
	ctx context.Context,
	userID uuid.UUID,
) (*EmployeeDepartment, error) {
	query := `
		SELECT
			department_id
		FROM employee_department_history
		WHERE user_id = $1
		  AND effective_from <= now()
		  AND (effective_to IS NULL OR effective_to >= now())
		ORDER BY effective_from DESC
		LIMIT 1
	`

	var ed EmployeeDepartment
	err := r.client.QueryRow(ctx, query, userID).Scan(
		&ed.DepartmentID,
	)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, nil
		}
		r.logger.Error(
			"Failed to get employee active department",
			util.String("user_id", userID.String()),
			util.ErrorField(err),
		)
		return nil, err
	}

	return &ed, nil
}

func (r *attendanceRepository) GetDepartment(
	ctx context.Context,
	departmentID uuid.UUID,
) (*Department, error) {
	query := `
		SELECT
			department_id,
			department_name
		FROM departments
		WHERE department_id = $1
		  AND is_active = true
	`

	var d Department
	err := r.client.QueryRow(ctx, query, departmentID).Scan(
		&d.DepartmentID,
		&d.DepartmentName,
	)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, nil
		}
		r.logger.Error(
			"Failed to get department",
			util.String("department_id", departmentID.String()),
			util.ErrorField(err),
		)
		return nil, err
	}

	return &d, nil
}

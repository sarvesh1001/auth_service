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
	"auth-service/internal/util"
)

type calendarRepository struct {
	client *client.PostgresClient
	logger *zap.Logger
}

func NewCalendarRepository(pg *client.PostgresClient, logger *zap.Logger) repository.CalendarRepository {
	return &calendarRepository{
		client: pg,
		logger: logger.Named("calendar_repo"),
	}
}

// calendarColumns — timezone removed. The operational tz now lives on the
// location (locations.timezone) or, for company-wide calendars, comes from
// the company default via TimezoneProvider. A calendar is a date set; it
// has no tz of its own.
const calendarColumns = `
	calendar_id, company_id, location_id, year, name,
	working_days, holidays, is_active, created_at
`

func (r *calendarRepository) Create(ctx context.Context, calendar *models.WorkCalendar) error {
	if calendar.CalendarID == uuid.Nil {
		calendar.CalendarID = uuid.New()
	}
	if calendar.CreatedAt.IsZero() {
		calendar.CreatedAt = time.Now().UTC()
	}

	query := `
		INSERT INTO attendance.work_calendars (
			calendar_id, company_id, location_id, year, name,
			working_days, holidays, is_active, created_at
		) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)`

	// Holidays is a plain map — marshal it explicitly. pq cannot handle a
	// raw map for a JSONB column on the write path either.
	holidaysJSON, err := json.Marshal(calendar.Holidays)
	if err != nil {
		return fmt.Errorf("marshal holidays: %w", err)
	}

	_, err = r.client.Exec(ctx, query,
		calendar.CalendarID,
		calendar.CompanyID,
		calendar.LocationID,
		calendar.Year,
		calendar.Name,
		pq.Array(calendar.WorkingDays),
		holidaysJSON,
		calendar.IsActive,
		calendar.CreatedAt,
	)
	if err != nil {
		r.logger.Error("failed to create calendar",
			util.String("company_id", calendar.CompanyID.String()),
			util.Int("year", calendar.Year),
			util.ErrorField(err))
		return fmt.Errorf("create calendar: %w", err)
	}
	return nil
}

func (r *calendarRepository) GetByID(ctx context.Context, calendarID uuid.UUID) (*models.WorkCalendar, error) {
	row := r.client.QueryRow(ctx, `SELECT `+calendarColumns+`
		FROM attendance.work_calendars WHERE calendar_id = $1`, calendarID)
	return r.scanCalendar(row)
}

func (r *calendarRepository) GetByCompanyAndYear(ctx context.Context, companyID uuid.UUID, year int) (*models.WorkCalendar, error) {
	row := r.client.QueryRow(ctx, `SELECT `+calendarColumns+`
		FROM attendance.work_calendars
		WHERE company_id = $1 AND year = $2
		ORDER BY location_id NULLS LAST, created_at DESC
		LIMIT 1`, companyID, year)
	return r.scanCalendar(row)
}

func (r *calendarRepository) GetByCompany(ctx context.Context, companyID uuid.UUID, activeOnly bool) ([]*models.WorkCalendar, error) {
	query := `SELECT ` + calendarColumns + `
		FROM attendance.work_calendars WHERE company_id = $1`
	if activeOnly {
		query += " AND is_active = true"
	}
	query += " ORDER BY year DESC"
	rows, err := r.client.Query(ctx, query, companyID)
	if err != nil {
		return nil, fmt.Errorf("query calendars: %w", err)
	}
	defer rows.Close()
	return r.scanCalendars(rows)
}

func (r *calendarRepository) Update(ctx context.Context, calendar *models.WorkCalendar) error {
	query := `
		UPDATE attendance.work_calendars
		SET location_id = $1, name = $2,
			working_days = $3, holidays = $4, is_active = $5
		WHERE calendar_id = $6`

	holidaysJSON, err := json.Marshal(calendar.Holidays)
	if err != nil {
		return fmt.Errorf("marshal holidays: %w", err)
	}
	result, err := r.client.Exec(ctx, query,
		calendar.LocationID,
		calendar.Name,
		pq.Array(calendar.WorkingDays),
		holidaysJSON,
		calendar.IsActive,
		calendar.CalendarID,
	)
	if err != nil {
		return fmt.Errorf("update calendar: %w", err)
	}
	if rows, _ := result.RowsAffected(); rows == 0 {
		return fmt.Errorf("calendar %s not found", calendar.CalendarID)
	}
	return nil
}

func (r *calendarRepository) Delete(ctx context.Context, calendarID uuid.UUID) error {
	result, err := r.client.Exec(ctx,
		`DELETE FROM attendance.work_calendars WHERE calendar_id = $1`, calendarID)
	if err != nil {
		return fmt.Errorf("delete calendar: %w", err)
	}
	if rows, _ := result.RowsAffected(); rows == 0 {
		return fmt.Errorf("calendar %s not found", calendarID)
	}
	return nil
}

func (r *calendarRepository) Exists(ctx context.Context, companyID uuid.UUID, year int) (bool, error) {
	var exists bool
	err := r.client.QueryRow(ctx,
		`SELECT EXISTS(SELECT 1 FROM attendance.work_calendars WHERE company_id = $1 AND year = $2)`,
		companyID, year).Scan(&exists)
	if err != nil {
		return false, fmt.Errorf("check existence: %w", err)
	}
	return exists, nil
}

func (r *calendarRepository) List(ctx context.Context, companyID uuid.UUID, filter repository.CalendarFilter, pagination repository.Pagination) ([]*models.WorkCalendar, int64, error) {
	var conditions []string
	var args []interface{}
	argIdx := 1

	conditions = append(conditions, fmt.Sprintf("company_id = $%d", argIdx))
	args = append(args, companyID)
	argIdx++

	if filter.Year != nil {
		conditions = append(conditions, fmt.Sprintf("year = $%d", argIdx))
		args = append(args, *filter.Year)
		argIdx++
	}
	if filter.IsActive != nil {
		conditions = append(conditions, fmt.Sprintf("is_active = $%d", argIdx))
		args = append(args, *filter.IsActive)
		argIdx++
	}
	if filter.Name != "" {
		conditions = append(conditions, fmt.Sprintf("name ILIKE $%d", argIdx))
		args = append(args, "%"+filter.Name+"%")
		argIdx++
	}
	if filter.LocationID != nil {
		conditions = append(conditions, fmt.Sprintf("location_id = $%d", argIdx))
		args = append(args, *filter.LocationID)
		argIdx++
	}

	where := "WHERE " + strings.Join(conditions, " AND ")

	var total int64
	if err := r.client.QueryRow(ctx,
		fmt.Sprintf(`SELECT COUNT(*) FROM attendance.work_calendars %s`, where), args...).Scan(&total); err != nil {
		return nil, 0, fmt.Errorf("count calendars: %w", err)
	}

	limit := pagination.Limit
	if limit <= 0 {
		limit = 50
	}
	if limit > 1000 {
		limit = 1000
	}
	offset := pagination.Offset
	if offset < 0 {
		offset = 0
	}

	query := fmt.Sprintf(`SELECT %s FROM attendance.work_calendars %s
		ORDER BY year DESC, name
		LIMIT $%d OFFSET $%d`, calendarColumns, where, argIdx, argIdx+1)
	args = append(args, limit, offset)

	rows, err := r.client.Query(ctx, query, args...)
	if err != nil {
		return nil, 0, fmt.Errorf("list calendars: %w", err)
	}
	defer rows.Close()
	cals, err := r.scanCalendars(rows)
	if err != nil {
		return nil, 0, err
	}
	return cals, total, nil
}

// scanCalendar — working_days is decoded as []int64 (pq's Int64Array path)
// then narrowed. Holidays is a plain map; unmarshal from JSON directly.
func (r *calendarRepository) scanCalendar(row *sql.Row) (*models.WorkCalendar, error) {
	var cal models.WorkCalendar
	var holidaysJSON []byte
	var workingDays []int64
	var locationID sql.NullString

	err := row.Scan(
		&cal.CalendarID,
		&cal.CompanyID,
		&locationID,
		&cal.Year,
		&cal.Name,
		pq.Array(&workingDays),
		&holidaysJSON,
		&cal.IsActive,
		&cal.CreatedAt,
	)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, nil
		}
		return nil, fmt.Errorf("scan calendar: %w", err)
	}

	cal.WorkingDays = int64SliceToInt(workingDays)

	if locationID.Valid && locationID.String != "" {
		if id, err := uuid.Parse(locationID.String); err == nil {
			cal.LocationID = &id
		}
	}

	if len(holidaysJSON) > 0 {
		if err := json.Unmarshal(holidaysJSON, &cal.Holidays); err != nil {
			return nil, fmt.Errorf("unmarshal holidays: %w", err)
		}
	}
	return &cal, nil
}

func (r *calendarRepository) scanCalendars(rows *sql.Rows) ([]*models.WorkCalendar, error) {
	var cals []*models.WorkCalendar
	for rows.Next() {
		var cal models.WorkCalendar
		var holidaysJSON []byte
		var workingDays []int64
		var locationID sql.NullString

		err := rows.Scan(
			&cal.CalendarID,
			&cal.CompanyID,
			&locationID,
			&cal.Year,
			&cal.Name,
			pq.Array(&workingDays),
			&holidaysJSON,
			&cal.IsActive,
			&cal.CreatedAt,
		)
		if err != nil {
			return nil, fmt.Errorf("scan calendar: %w", err)
		}

		cal.WorkingDays = int64SliceToInt(workingDays)

		if locationID.Valid && locationID.String != "" {
			if id, err := uuid.Parse(locationID.String); err == nil {
				cal.LocationID = &id
			}
		}

		if len(holidaysJSON) > 0 {
			if err := json.Unmarshal(holidaysJSON, &cal.Holidays); err != nil {
				return nil, fmt.Errorf("unmarshal holidays: %w", err)
			}
		}
		cals = append(cals, &cal)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("rows iteration: %w", err)
	}
	return cals, nil
}

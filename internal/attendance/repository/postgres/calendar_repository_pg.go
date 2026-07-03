package postgres

import (
	"context"
	"database/sql"
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

type calendarRepository struct {
	client *client.PostgresClient
	logger *zap.Logger
}

// NewCalendarRepository creates a new calendar repository
func NewCalendarRepository(pg *client.PostgresClient, logger *zap.Logger) repository.CalendarRepository {
	return &calendarRepository{
		client: pg,
		logger: logger.Named("calendar_repo"),
	}
}

func (r *calendarRepository) Create(ctx context.Context, calendar *models.WorkCalendar) error {
	if calendar.CalendarID == uuid.Nil {
		calendar.CalendarID = uuid.New()
	}
	if calendar.CreatedAt.IsZero() {
		calendar.CreatedAt = time.Now().UTC()
	}

	query := `
		INSERT INTO attendance.work_calendars (
			calendar_id, company_id, year, name, timezone,
			working_days, holidays, is_active, created_at
		) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)
	`
	holidaysJSON, err := calendar.Holidays.Value()
	if err != nil {
		return fmt.Errorf("marshal holidays: %w", err)
	}

	_, err = r.client.Exec(ctx, query,
		calendar.CalendarID,
		calendar.CompanyID,
		calendar.Year,
		calendar.Name,
		calendar.Timezone,
		pq.Array(calendar.WorkingDays),
		holidaysJSON,
		calendar.IsActive,
		calendar.CreatedAt,
	)
	if err != nil {
		r.logger.Error("failed to create calendar",
			zap.String("company_id", calendar.CompanyID.String()),
			zap.Int("year", calendar.Year),
			zap.Error(err),
		)
		return fmt.Errorf("create calendar: %w", err)
	}
	return nil
}

func (r *calendarRepository) GetByID(ctx context.Context, calendarID uuid.UUID) (*models.WorkCalendar, error) {
	query := `
		SELECT calendar_id, company_id, year, name, timezone,
			working_days, holidays, is_active, created_at
		FROM attendance.work_calendars
		WHERE calendar_id = $1
	`
	row := r.client.QueryRow(ctx, query, calendarID)
	return r.scanCalendar(row)
}

func (r *calendarRepository) GetByCompanyAndYear(ctx context.Context, companyID uuid.UUID, year int) (*models.WorkCalendar, error) {
	query := `
		SELECT calendar_id, company_id, year, name, timezone,
			working_days, holidays, is_active, created_at
		FROM attendance.work_calendars
		WHERE company_id = $1 AND year = $2
	`
	row := r.client.QueryRow(ctx, query, companyID, year)
	return r.scanCalendar(row)
}

func (r *calendarRepository) GetByCompany(ctx context.Context, companyID uuid.UUID, activeOnly bool) ([]*models.WorkCalendar, error) {
	query := `
		SELECT calendar_id, company_id, year, name, timezone,
			working_days, holidays, is_active, created_at
		FROM attendance.work_calendars
		WHERE company_id = $1
	`
	if activeOnly {
		query += " AND is_active = true"
	}
	query += " ORDER BY year DESC"

	rows, err := r.client.Query(ctx, query, companyID)
	if err != nil {
		return nil, fmt.Errorf("query calendars: %w", err)
	}
	defer rows.Close()

	var calendars []*models.WorkCalendar
	for rows.Next() {
		cal, err := r.scanCalendarFromRows(rows)
		if err != nil {
			return nil, err
		}
		calendars = append(calendars, cal)
	}
	if err = rows.Err(); err != nil {
		return nil, fmt.Errorf("rows iteration: %w", err)
	}
	return calendars, nil
}

func (r *calendarRepository) Update(ctx context.Context, calendar *models.WorkCalendar) error {
	query := `
		UPDATE attendance.work_calendars
		SET name = $1, timezone = $2, working_days = $3,
			holidays = $4, is_active = $5
		WHERE calendar_id = $6
	`
	holidaysJSON, err := calendar.Holidays.Value()
	if err != nil {
		return fmt.Errorf("marshal holidays: %w", err)
	}
	result, err := r.client.Exec(ctx, query,
		calendar.Name,
		calendar.Timezone,
		pq.Array(calendar.WorkingDays),
		holidaysJSON,
		calendar.IsActive,
		calendar.CalendarID,
	)
	if err != nil {
		r.logger.Error("failed to update calendar",
			zap.String("calendar_id", calendar.CalendarID.String()),
			zap.Error(err),
		)
		return fmt.Errorf("update calendar: %w", err)
	}
	rows, _ := result.RowsAffected()
	if rows == 0 {
		return fmt.Errorf("calendar %s not found", calendar.CalendarID)
	}
	return nil
}

func (r *calendarRepository) Delete(ctx context.Context, calendarID uuid.UUID) error {
	// Hard delete (since we have is_active flag, we could also soft-delete)
	query := `DELETE FROM attendance.work_calendars WHERE calendar_id = $1`
	result, err := r.client.Exec(ctx, query, calendarID)
	if err != nil {
		return fmt.Errorf("delete calendar: %w", err)
	}
	rows, _ := result.RowsAffected()
	if rows == 0 {
		return fmt.Errorf("calendar %s not found", calendarID)
	}
	return nil
}

func (r *calendarRepository) Exists(ctx context.Context, companyID uuid.UUID, year int) (bool, error) {
	query := `SELECT EXISTS(SELECT 1 FROM attendance.work_calendars WHERE company_id = $1 AND year = $2)`
	var exists bool
	err := r.client.QueryRow(ctx, query, companyID, year).Scan(&exists)
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

	whereClause := ""
	if len(conditions) > 0 {
		whereClause = "WHERE " + strings.Join(conditions, " AND ")
	}

	// Count total
	countQuery := fmt.Sprintf(`SELECT COUNT(*) FROM attendance.work_calendars %s`, whereClause)
	var total int64
	err := r.client.QueryRow(ctx, countQuery, args...).Scan(&total)
	if err != nil {
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

	query := fmt.Sprintf(`
		SELECT calendar_id, company_id, year, name, timezone,
			working_days, holidays, is_active, created_at
		FROM attendance.work_calendars
		%s
		ORDER BY year DESC, name
		LIMIT $%d OFFSET $%d
	`, whereClause, argIdx, argIdx+1)
	args = append(args, limit, offset)

	rows, err := r.client.Query(ctx, query, args...)
	if err != nil {
		return nil, 0, fmt.Errorf("list calendars: %w", err)
	}
	defer rows.Close()

	var calendars []*models.WorkCalendar
	for rows.Next() {
		cal, err := r.scanCalendarFromRows(rows)
		if err != nil {
			return nil, 0, err
		}
		calendars = append(calendars, cal)
	}
	if err = rows.Err(); err != nil {
		return nil, 0, fmt.Errorf("rows iteration: %w", err)
	}
	return calendars, total, nil
}

// scanCalendar scans a single row (sql.Row)
func (r *calendarRepository) scanCalendar(row *sql.Row) (*models.WorkCalendar, error) {
	var cal models.WorkCalendar
	var holidaysJSON []byte
	var workingDays []int

	err := row.Scan(
		&cal.CalendarID,
		&cal.CompanyID,
		&cal.Year,
		&cal.Name,
		&cal.Timezone,
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
	cal.WorkingDays = workingDays
	if err := cal.Holidays.Scan(holidaysJSON); err != nil {
		return nil, fmt.Errorf("scan holidays: %w", err)
	}
	return &cal, nil
}

// scanCalendarFromRows scans from *sql.Rows (for list queries)
func (r *calendarRepository) scanCalendarFromRows(rows *sql.Rows) (*models.WorkCalendar, error) {
	var cal models.WorkCalendar
	var holidaysJSON []byte
	var workingDays []int

	err := rows.Scan(
		&cal.CalendarID,
		&cal.CompanyID,
		&cal.Year,
		&cal.Name,
		&cal.Timezone,
		pq.Array(&workingDays),
		&holidaysJSON,
		&cal.IsActive,
		&cal.CreatedAt,
	)
	if err != nil {
		return nil, fmt.Errorf("scan calendar: %w", err)
	}
	cal.WorkingDays = workingDays
	if err := cal.Holidays.Scan(holidaysJSON); err != nil {
		return nil, fmt.Errorf("scan holidays: %w", err)
	}
	return &cal, nil
}

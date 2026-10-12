package postgres

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/google/uuid"
	"github.com/lib/pq"
	"go.uber.org/zap"

	"auth-service/internal/attendance/models"
	"auth-service/internal/attendance/repository"
	"auth-service/internal/client"
)

type scheduleRepository struct {
	client *client.PostgresClient
	logger *zap.Logger
}

func NewScheduleRepository(pg *client.PostgresClient, logger *zap.Logger) repository.ScheduleRepository {
	return &scheduleRepository{
		client: pg,
		logger: logger.Named("schedule_repo"),
	}
}

// ── Column lists ──

const workCenterCols = `
	work_center_code, company_id, location_id, name, description,
	timezone, is_active, created_at, updated_at
`

const workCalendarCols = `
	calendar_id, company_id, location_id, year, name,
	working_days, holidays, is_active, created_at
`
const scheduleTemplateCols = `
	schedule_template_id, company_id, calendar_id, location_id, position_id,
	template_type, name, rules, is_active, created_at
`

// ── Work Centers ──

func (r *scheduleRepository) GetWorkCenter(ctx context.Context, companyID uuid.UUID, workCenterCode string) (*models.WorkCenter, error) {
	query := `SELECT ` + workCenterCols + `
		FROM attendance.work_centers
		WHERE company_id = $1 AND work_center_code = $2`
	row := r.client.QueryRow(ctx, query, companyID, workCenterCode)
	return r.scanWorkCenter(row)
}

func (r *scheduleRepository) GetWorkCentersByCompany(ctx context.Context, companyID uuid.UUID, activeOnly bool) ([]*models.WorkCenter, error) {
	query := `SELECT ` + workCenterCols + `
		FROM attendance.work_centers
		WHERE company_id = $1`
	if activeOnly {
		query += " AND is_active = true"
	}
	query += " ORDER BY name"
	rows, err := r.client.Query(ctx, query, companyID)
	if err != nil {
		return nil, fmt.Errorf("query work centers: %w", err)
	}
	defer rows.Close()
	return r.scanWorkCenters(rows)
}

// ── Work Calendars ──

func (r *scheduleRepository) GetWorkCalendar(ctx context.Context, companyID uuid.UUID, year int) (*models.WorkCalendar, error) {
	query := `SELECT ` + workCalendarCols + `
		FROM attendance.work_calendars
		WHERE company_id = $1 AND year = $2
		ORDER BY location_id NULLS LAST, created_at DESC
		LIMIT 1`
	row := r.client.QueryRow(ctx, query, companyID, year)
	return r.scanWorkCalendar(row)
}

func (r *scheduleRepository) GetWorkCalendarsByCompany(
	ctx context.Context,
	companyID uuid.UUID,
	locationID *uuid.UUID,
) ([]*models.WorkCalendar, error) {
	var locArg interface{}
	if locationID != nil {
		locArg = *locationID
	}
	query := `SELECT ` + workCalendarCols + `
		FROM attendance.work_calendars
		WHERE company_id = $1
		  AND ($2::uuid IS NULL OR location_id = $2 OR location_id IS NULL)
		ORDER BY year DESC, location_id NULLS FIRST, name`
	rows, err := r.client.Query(ctx, query, companyID, locArg)
	if err != nil {
		return nil, fmt.Errorf("query work calendars: %w", err)
	}
	defer rows.Close()
	return r.scanCalendars(rows)
}

func (r *scheduleRepository) GetWorkCalendarByID(ctx context.Context, calendarID uuid.UUID) (*models.WorkCalendar, error) {
	query := `SELECT ` + workCalendarCols + `
		FROM attendance.work_calendars
		WHERE calendar_id = $1`
	row := r.client.QueryRow(ctx, query, calendarID)
	return r.scanWorkCalendar(row)
}

func (r *scheduleRepository) GetWorkCalendarByLocation(
	ctx context.Context,
	companyID, locationID uuid.UUID,
	year int,
) (*models.WorkCalendar, error) {
	if companyID == uuid.Nil || locationID == uuid.Nil {
		return nil, nil
	}
	query := `SELECT ` + workCalendarCols + `
		FROM attendance.work_calendars
		WHERE company_id = $1
		  AND location_id = $2
		  AND year = $3
		  AND is_active = true
		ORDER BY created_at DESC
		LIMIT 1`
	row := r.client.QueryRow(ctx, query, companyID, locationID, year)
	return r.scanWorkCalendar(row)
}

func (r *scheduleRepository) GetWorkCalendarCompanyWide(
	ctx context.Context,
	companyID uuid.UUID,
	year int,
) (*models.WorkCalendar, error) {
	if companyID == uuid.Nil {
		return nil, nil
	}
	query := `SELECT ` + workCalendarCols + `
		FROM attendance.work_calendars
		WHERE company_id = $1
		  AND location_id IS NULL
		  AND year = $2
		  AND is_active = true
		ORDER BY created_at DESC
		LIMIT 1`
	row := r.client.QueryRow(ctx, query, companyID, year)
	return r.scanWorkCalendar(row)
}

// ── Schedule Templates ──

func (r *scheduleRepository) GetScheduleTemplate(ctx context.Context, templateID uuid.UUID) (*models.ScheduleTemplate, error) {
	query := `SELECT ` + scheduleTemplateCols + `
		FROM attendance.schedule_templates
		WHERE schedule_template_id = $1
		ORDER BY effective_from DESC
		LIMIT 1`
	row := r.client.QueryRow(ctx, query, templateID)
	return r.scanScheduleTemplate(row)
}

// ── Schedule Instances — removed ──

// ── Work Center Shifts ──

func (r *scheduleRepository) GetWorkCenterShift(ctx context.Context, companyID uuid.UUID, workCenterCode string, at time.Time) (*models.WorkCenterShift, error) {
	query := `
		SELECT mapping_id, company_id, work_center_code, shift_id,
		       effective_from, effective_to, is_active, created_at, updated_at
		FROM attendance.work_center_shifts
		WHERE company_id = $1
		  AND work_center_code = $2
		  AND effective_from::date <= $3::date
		  AND (effective_to IS NULL OR effective_to::date >= $3::date)
		ORDER BY effective_from DESC
		LIMIT 1`
	row := r.client.QueryRow(ctx, query, companyID, workCenterCode, at)
	return r.scanWorkCenterShift(row)
}

func (r *scheduleRepository) GetWorkCenterShifts(ctx context.Context, companyID uuid.UUID, workCenterCode string) ([]*models.WorkCenterShift, error) {
	query := `
		SELECT mapping_id, company_id, work_center_code, shift_id,
		       effective_from, effective_to, is_active, created_at, updated_at
		FROM attendance.work_center_shifts
		WHERE company_id = $1 AND work_center_code = $2
		ORDER BY effective_from DESC`
	rows, err := r.client.Query(ctx, query, companyID, workCenterCode)
	if err != nil {
		return nil, fmt.Errorf("query work center shifts: %w", err)
	}
	defer rows.Close()
	var shifts []*models.WorkCenterShift
	for rows.Next() {
		shift, err := r.scanWorkCenterShiftFromRows(rows)
		if err != nil {
			return nil, err
		}
		shifts = append(shifts, shift)
	}
	return shifts, nil
}

// ── Off Entitlements ──

func (r *scheduleRepository) GetUserOffEntitlement(ctx context.Context, userID uuid.UUID, at time.Time) (*models.UserOffEntitlement, error) {
	query := `
		SELECT entitlement_id, company_id, user_id, period_type, off_count,
		       requires_approval, effective_from, effective_to, created_at
		FROM attendance.user_off_entitlements
		WHERE user_id = $1
		  AND effective_from <= $2
		  AND (effective_to IS NULL OR effective_to >= $2)
		ORDER BY effective_from DESC
		LIMIT 1`
	row := r.client.QueryRow(ctx, query, userID, at)
	return r.scanUserOffEntitlement(row)
}

// ── Off Requests ──

func (r *scheduleRepository) GetOffRequests(ctx context.Context, userID uuid.UUID, startDate, endDate time.Time) ([]*models.OffRequest, error) {
	rows, err := r.client.Query(ctx, `
		SELECT off_request_id, company_id, user_id, request_dates, status,
		       requested_by, approved_by, approved_at, created_at
		FROM attendance.off_requests
		WHERE user_id = $1
		  AND status = 'approved'`, userID)
	if err != nil {
		return nil, fmt.Errorf("query off requests: %w", err)
	}
	defer rows.Close()
	var requests []*models.OffRequest
	for rows.Next() {
		var req models.OffRequest
		var dateStrs pq.StringArray
		var requestedBy, approvedBy uuid.NullUUID
		var approvedAt sql.NullTime
		err := rows.Scan(
			&req.OffRequestID,
			&req.CompanyID,
			&req.UserID,
			&dateStrs,
			&req.Status,
			&requestedBy,
			&approvedBy,
			&approvedAt,
			&req.CreatedAt,
		)
		if err != nil {
			return nil, err
		}
		req.RequestDates = []string(dateStrs)
		if requestedBy.Valid {
			req.RequestedBy = &requestedBy.UUID
		}
		if approvedBy.Valid {
			req.ApprovedBy = &approvedBy.UUID
		}
		if approvedAt.Valid {
			req.ApprovedAt = &approvedAt.Time
		}
		requests = append(requests, &req)
	}
	return requests, nil
}

// ── Date-Scoped Reads ──

func (r *scheduleRepository) GetEmployeeAssignmentOnDate(
	ctx context.Context,
	companyID, userID uuid.UUID,
	date time.Time,
) (*models.EmployeeAssignment, error) {
	query := `
		SELECT position_id, primary_location_id
		FROM hr.employee_assignment_history
		WHERE company_id = $1
		  AND user_id = $2
		  AND effective_from <= $3::date
		  AND (effective_to IS NULL OR effective_to >= $3::date)
		ORDER BY effective_from DESC
		LIMIT 1
	`
	var a models.EmployeeAssignment
	err := r.client.QueryRow(ctx, query, companyID, userID, date).Scan(
		&a.PositionID,
		&a.PrimaryLocationID,
	)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, nil
		}
		return nil, fmt.Errorf("get employee assignment on date: %w", err)
	}
	return &a, nil
}

func (r *scheduleRepository) GetPositionOnDate(
	ctx context.Context,
	positionID uuid.UUID,
	date time.Time,
) (*models.PositionHistoryRow, error) {
	query := `
		SELECT position_id, work_center_code, location_id
		FROM hr.position_history
		WHERE position_id = $1
		  AND effective_from <= $2::date
		  AND (effective_to IS NULL OR effective_to >= $2::date)
		ORDER BY effective_from DESC
		LIMIT 1
	`
	var p models.PositionHistoryRow
	err := r.client.QueryRow(ctx, query, positionID, date).Scan(
		&p.PositionID,
		&p.WorkCenterCode,
		&p.LocationID,
	)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, nil
		}
		return nil, fmt.Errorf("get position on date: %w", err)
	}
	return &p, nil
}

func (r *scheduleRepository) GetScheduleTemplateOnDate(
	ctx context.Context,
	templateID uuid.UUID,
	date time.Time,
) (*models.ScheduleTemplate, error) {
	query := `SELECT ` + scheduleTemplateCols + `
		FROM attendance.schedule_templates
		WHERE schedule_template_id = $1
		  AND effective_from <= $2::date
		  AND (effective_to IS NULL OR effective_to >= $2::date)
		ORDER BY effective_from DESC
		LIMIT 1
	`
	row := r.client.QueryRow(ctx, query, templateID, date)
	return r.scanScheduleTemplate(row)
}

func (r *scheduleRepository) GetCompanyRulesOnDate(
	ctx context.Context,
	companyID uuid.UUID,
	date time.Time,
) (*models.CompanyAttendanceRules, error) {
	query := `
		SELECT company_id, allowed_source_types, allow_multiple_checkins,
		       timezone, created_at
		FROM attendance.company_attendance_rules
		WHERE company_id = $1
		  AND effective_from <= $2::date
		  AND (effective_to IS NULL OR effective_to >= $2::date)
		ORDER BY effective_from DESC
		LIMIT 1
	`
	var rules models.CompanyAttendanceRules
	var allowed []string
	err := r.client.QueryRow(ctx, query, companyID, date).Scan(
		&rules.CompanyID,
		pq.Array(&allowed),
		&rules.AllowMultipleCheckins,
		&rules.Timezone,
		&rules.CreatedAt,
	)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, nil
		}
		return nil, fmt.Errorf("get company rules on date: %w", err)
	}
	rules.AllowedSourceTypes = allowed
	return &rules, nil
}

// ── Health Check ──

func (r *scheduleRepository) HealthCheck(ctx context.Context) error {
	_, err := r.client.Exec(ctx, `SELECT 1 FROM attendance.work_centers LIMIT 1`)
	if err != nil {
		return fmt.Errorf("schedule repository health check failed: %w", err)
	}
	return nil
}

// ── Scan Helpers ──

func (r *scheduleRepository) scanWorkCenter(row *sql.Row) (*models.WorkCenter, error) {
	var wc models.WorkCenter
	var desc, locationID sql.NullString
	err := row.Scan(
		&wc.WorkCenterCode,
		&wc.CompanyID,
		&locationID,
		&wc.Name,
		&desc,
		&wc.Timezone,
		&wc.IsActive,
		&wc.CreatedAt,
		&wc.UpdatedAt,
	)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, nil
		}
		return nil, err
	}
	if desc.Valid {
		wc.Description = &desc.String
	}
	if locationID.Valid && locationID.String != "" {
		if id, err := uuid.Parse(locationID.String); err == nil {
			wc.LocationID = &id
		}
	}
	return &wc, nil
}

func (r *scheduleRepository) scanWorkCenters(rows *sql.Rows) ([]*models.WorkCenter, error) {
	var wcs []*models.WorkCenter
	for rows.Next() {
		var wc models.WorkCenter
		var desc, locationID sql.NullString
		if err := rows.Scan(
			&wc.WorkCenterCode,
			&wc.CompanyID,
			&locationID,
			&wc.Name,
			&desc,
			&wc.Timezone,
			&wc.IsActive,
			&wc.CreatedAt,
			&wc.UpdatedAt,
		); err != nil {
			return nil, err
		}
		if desc.Valid {
			wc.Description = &desc.String
		}
		if locationID.Valid && locationID.String != "" {
			if id, err := uuid.Parse(locationID.String); err == nil {
				wc.LocationID = &id
			}
		}
		wcs = append(wcs, &wc)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("rows iteration: %w", err)
	}
	return wcs, nil
}

func (r *scheduleRepository) scanWorkCalendar(row *sql.Row) (*models.WorkCalendar, error) {
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
		return nil, err
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

func (r *scheduleRepository) scanCalendars(rows *sql.Rows) ([]*models.WorkCalendar, error) {
	var cals []*models.WorkCalendar
	for rows.Next() {
		var cal models.WorkCalendar
		var holidaysJSON []byte
		var workingDays []int64
		var locationID sql.NullString

		if err := rows.Scan(
			&cal.CalendarID,
			&cal.CompanyID,
			&locationID,
			&cal.Year,
			&cal.Name,
			pq.Array(&workingDays),
			&holidaysJSON,
			&cal.IsActive,
			&cal.CreatedAt,
		); err != nil {
			return nil, err
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

func (r *scheduleRepository) scanScheduleTemplate(row *sql.Row) (*models.ScheduleTemplate, error) {
	var tmpl models.ScheduleTemplate
	var rulesJSON []byte
	var locationID, positionID sql.NullString

	err := row.Scan(
		&tmpl.ScheduleTemplateID,
		&tmpl.CompanyID,
		&tmpl.CalendarID,
		&locationID,
		&positionID,
		&tmpl.TemplateType,
		&tmpl.Name,
		&rulesJSON,
		&tmpl.IsActive,
		&tmpl.CreatedAt,
	)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, nil
		}
		return nil, err
	}
	if locationID.Valid && locationID.String != "" {
		if id, err := uuid.Parse(locationID.String); err == nil {
			tmpl.LocationID = &id
		}
	}
	if positionID.Valid && positionID.String != "" {
		if id, err := uuid.Parse(positionID.String); err == nil {
			tmpl.PositionID = &id
		}
	}
	if len(rulesJSON) > 0 {
		if err := json.Unmarshal(rulesJSON, &tmpl.Rules); err != nil {
			return nil, fmt.Errorf("unmarshal rules: %w", err)
		}
	}
	return &tmpl, nil
}
func (r *scheduleRepository) scanScheduleTemplates(rows *sql.Rows) ([]*models.ScheduleTemplate, error) {
	var tmpls []*models.ScheduleTemplate
	for rows.Next() {
		var tmpl models.ScheduleTemplate
		var rulesJSON []byte
		var locationID, positionID sql.NullString

		if err := rows.Scan(
			&tmpl.ScheduleTemplateID,
			&tmpl.CompanyID,
			&tmpl.CalendarID,
			&locationID,
			&positionID,
			&tmpl.TemplateType,
			&tmpl.Name,
			&rulesJSON,
			&tmpl.IsActive,
			&tmpl.CreatedAt,
		); err != nil {
			return nil, err
		}
		if locationID.Valid && locationID.String != "" {
			if id, err := uuid.Parse(locationID.String); err == nil {
				tmpl.LocationID = &id
			}
		}
		if positionID.Valid && positionID.String != "" {
			if id, err := uuid.Parse(positionID.String); err == nil {
				tmpl.PositionID = &id
			}
		}
		if len(rulesJSON) > 0 {
			if err := json.Unmarshal(rulesJSON, &tmpl.Rules); err != nil {
				return nil, fmt.Errorf("unmarshal rules: %w", err)
			}
		}
		tmpls = append(tmpls, &tmpl)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("rows iteration: %w", err)
	}
	return tmpls, nil
}
func (r *scheduleRepository) scanWorkCenterShift(row *sql.Row) (*models.WorkCenterShift, error) {
	var shift models.WorkCenterShift
	var effectiveTo sql.NullTime
	err := row.Scan(
		&shift.MappingID,
		&shift.CompanyID,
		&shift.WorkCenterCode,
		&shift.ShiftID,
		&shift.EffectiveFrom,
		&effectiveTo,
		&shift.IsActive,
		&shift.CreatedAt,
		&shift.UpdatedAt,
	)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, nil
		}
		return nil, err
	}
	if effectiveTo.Valid {
		shift.EffectiveTo = &effectiveTo.Time
	}
	return &shift, nil
}

func (r *scheduleRepository) scanWorkCenterShiftFromRows(rows *sql.Rows) (*models.WorkCenterShift, error) {
	var shift models.WorkCenterShift
	var effectiveTo sql.NullTime
	err := rows.Scan(
		&shift.MappingID,
		&shift.CompanyID,
		&shift.WorkCenterCode,
		&shift.ShiftID,
		&shift.EffectiveFrom,
		&effectiveTo,
		&shift.IsActive,
		&shift.CreatedAt,
		&shift.UpdatedAt,
	)
	if err != nil {
		return nil, err
	}
	if effectiveTo.Valid {
		shift.EffectiveTo = &effectiveTo.Time
	}
	return &shift, nil
}

func (r *scheduleRepository) scanUserOffEntitlement(row *sql.Row) (*models.UserOffEntitlement, error) {
	var ent models.UserOffEntitlement
	var effectiveTo sql.NullTime
	err := row.Scan(
		&ent.EntitlementID,
		&ent.CompanyID,
		&ent.UserID,
		&ent.PeriodType,
		&ent.OffCount,
		&ent.RequiresApproval,
		&ent.EffectiveFrom,
		&effectiveTo,
		&ent.CreatedAt,
	)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, nil
		}
		return nil, err
	}
	if effectiveTo.Valid {
		ent.EffectiveTo = &effectiveTo.Time
	}
	return &ent, nil
}

func (r *scheduleRepository) scanScheduleOverride(row *sql.Row) (*models.ScheduleOverride, error) {
	var ov models.ScheduleOverride
	var reason sql.NullString
	var createdBy uuid.NullUUID
	var expectedStart, expectedEnd sql.NullTime // ← was sql.NullString

	err := row.Scan(
		&ov.OverrideID,
		&ov.CompanyID,
		&ov.UserID,
		&ov.OverrideDate,
		&ov.OverrideType,
		&expectedStart,
		&expectedEnd,
		&reason,
		&createdBy,
		&ov.CreatedAt,
	)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, nil
		}
		return nil, err
	}
	if expectedStart.Valid {
		s := expectedStart.Time.Format("15:04:05")
		ov.ExpectedStart = &s
	}
	if expectedEnd.Valid {
		s := expectedEnd.Time.Format("15:04:05")
		ov.ExpectedEnd = &s
	}
	if reason.Valid {
		ov.Reason = &reason.String
	}
	if createdBy.Valid {
		ov.CreatedBy = &createdBy.UUID
	}
	return &ov, nil
}

// ============================================================
// WORK CALENDARS — CRUD
// ============================================================

func (r *scheduleRepository) CreateWorkCalendar(ctx context.Context, calendar *models.WorkCalendar) error {
	if calendar.CalendarID == uuid.Nil {
		calendar.CalendarID = uuid.New()
	}
	if calendar.CreatedAt.IsZero() {
		calendar.CreatedAt = time.Now().UTC()
	}
	holidaysJSON, _ := json.Marshal(calendar.Holidays)
	query := `
		INSERT INTO attendance.work_calendars (
			calendar_id, company_id, location_id, year, name,
			working_days, holidays, is_active, created_at
		) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)`
	_, err := r.client.Exec(ctx, query,
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
	return err
}

func (r *scheduleRepository) UpdateWorkCalendar(ctx context.Context, calendar *models.WorkCalendar) error {
	holidaysJSON, _ := json.Marshal(calendar.Holidays)
	query := `
		UPDATE attendance.work_calendars
		SET location_id = $1, name = $2,
		    working_days = $3, holidays = $4, is_active = $5
		WHERE calendar_id = $6`
	_, err := r.client.Exec(ctx, query,
		calendar.LocationID,
		calendar.Name,
		pq.Array(calendar.WorkingDays),
		holidaysJSON,
		calendar.IsActive,
		calendar.CalendarID,
	)
	return err
}

func (r *scheduleRepository) DeleteWorkCalendar(ctx context.Context, calendarID uuid.UUID) error {
	_, err := r.client.Exec(ctx,
		`DELETE FROM attendance.work_calendars WHERE calendar_id = $1`, calendarID)
	return err
}

// ============================================================
// SCHEDULE TEMPLATES — CRUD
// ============================================================

func (r *scheduleRepository) CreateScheduleTemplate(ctx context.Context, template *models.ScheduleTemplate) error {
	if template.ScheduleTemplateID == uuid.Nil {
		template.ScheduleTemplateID = uuid.New()
	}
	if template.CreatedAt.IsZero() {
		template.CreatedAt = time.Now().UTC()
	}
	rulesJSON, _ := json.Marshal(template.Rules)
	query := `
		INSERT INTO attendance.schedule_templates (
			schedule_template_id, company_id, calendar_id, location_id, position_id,
			template_type, name, rules, is_active, created_at, effective_from
		) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11)`
	_, err := r.client.Exec(ctx, query,
		template.ScheduleTemplateID,
		template.CompanyID,
		template.CalendarID,
		template.LocationID,
		template.PositionID,
		template.TemplateType,
		template.Name,
		rulesJSON,
		template.IsActive,
		template.CreatedAt,
		template.CreatedAt.UTC().Truncate(24*time.Hour),
	)
	return err
}

func (r *scheduleRepository) UpdateScheduleTemplate(ctx context.Context, template *models.ScheduleTemplate) error {
	tx, err := r.client.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("begin tx: %w", err)
	}
	defer tx.Rollback()

	rulesJSON, _ := json.Marshal(template.Rules)

	// Case 1: the open version was created today. Collapse the edit into it.
	res, err := tx.ExecContext(ctx, `
		UPDATE attendance.schedule_templates
		SET location_id = $1, position_id = $2, name = $3, calendar_id = $4,
		    template_type = $5, rules = $6, is_active = $7
		WHERE schedule_template_id = $8
		  AND effective_to IS NULL
		  AND effective_from = CURRENT_DATE
	`,
		template.LocationID, template.PositionID, template.Name, template.CalendarID,
		template.TemplateType, rulesJSON, template.IsActive,
		template.ScheduleTemplateID,
	)
	if err != nil {
		return fmt.Errorf("update same-day template version: %w", err)
	}

	affected, _ := res.RowsAffected()
	if affected == 0 {
		// Case 2: close the open version, insert a new one starting today.
		if _, err := tx.ExecContext(ctx, `
			UPDATE attendance.schedule_templates
			SET effective_to = CURRENT_DATE - 1
			WHERE schedule_template_id = $1
			  AND effective_to IS NULL
		`, template.ScheduleTemplateID); err != nil {
			return fmt.Errorf("close old template version: %w", err)
		}

		if _, err := tx.ExecContext(ctx, `
			INSERT INTO attendance.schedule_templates (
				schedule_template_id, company_id, calendar_id, location_id, position_id,
				template_type, name, rules, is_active, created_at, effective_from
			) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, CURRENT_DATE)
		`,
			template.ScheduleTemplateID, template.CompanyID, template.CalendarID,
			template.LocationID, template.PositionID,
			template.TemplateType, template.Name,
			rulesJSON, template.IsActive, time.Now().UTC(),
		); err != nil {
			return fmt.Errorf("insert new template version: %w", err)
		}
	}

	return tx.Commit()
}

func (r *scheduleRepository) DeleteScheduleTemplate(ctx context.Context, templateID uuid.UUID) error {
	_, err := r.client.Exec(ctx,
		`DELETE FROM attendance.schedule_templates WHERE schedule_template_id = $1`, templateID)
	return err
}

// ============================================================
// SCHEDULE OVERRIDES — CRUD
// ============================================================

func (r *scheduleRepository) CreateScheduleOverride(ctx context.Context, override *models.ScheduleOverride) error {
	if override.OverrideID == uuid.Nil {
		override.OverrideID = uuid.New()
	}
	if override.CreatedAt.IsZero() {
		override.CreatedAt = time.Now().UTC()
	}
	query := `
		INSERT INTO attendance.schedule_overrides (
			override_id, company_id, user_id, override_date, override_type,
			expected_start, expected_end,
			reason, created_by, created_at
		) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10)`
	_, err := r.client.Exec(ctx, query,
		override.OverrideID,
		override.CompanyID,
		override.UserID,
		override.OverrideDate,
		override.OverrideType,
		override.ExpectedStart,
		override.ExpectedEnd,
		override.Reason,
		override.CreatedBy,
		override.CreatedAt,
	)
	return err
}

func (r *scheduleRepository) GetScheduleOverrideByID(ctx context.Context, overrideID uuid.UUID) (*models.ScheduleOverride, error) {
	query := `
		SELECT override_id, company_id, user_id, override_date, override_type,
		       expected_start, expected_end,
		       reason, created_by, created_at
		FROM attendance.schedule_overrides
		WHERE override_id = $1`
	row := r.client.QueryRow(ctx, query, overrideID)
	return r.scanScheduleOverride(row)
}

func (r *scheduleRepository) GetScheduleOverridesByUser(ctx context.Context, userID uuid.UUID, startDate, endDate *time.Time, overrideType *string) ([]*models.ScheduleOverride, error) {
	query := `
		SELECT override_id, company_id, user_id, override_date, override_type,
		       expected_start, expected_end,
		       reason, created_by, created_at
		FROM attendance.schedule_overrides
		WHERE user_id = $1`
	args := []interface{}{userID}
	argPos := 2
	if startDate != nil {
		query += fmt.Sprintf(" AND override_date >= $%d", argPos)
		args = append(args, *startDate)
		argPos++
	}
	if endDate != nil {
		query += fmt.Sprintf(" AND override_date <= $%d", argPos)
		args = append(args, *endDate)
		argPos++
	}
	if overrideType != nil {
		query += fmt.Sprintf(" AND override_type = $%d", argPos)
		args = append(args, *overrideType)
		argPos++
	}
	query += " ORDER BY override_date"
	rows, err := r.client.Query(ctx, query, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var overrides []*models.ScheduleOverride
	for rows.Next() {
		ov, err := r.scanScheduleOverrideFromRows(rows)
		if err != nil {
			return nil, err
		}
		overrides = append(overrides, ov)
	}
	return overrides, nil
}

func (r *scheduleRepository) GetScheduleOverridesByCompany(ctx context.Context, companyID uuid.UUID, startDate, endDate *time.Time, overrideType *string) ([]*models.ScheduleOverride, error) {
	query := `
		SELECT override_id, company_id, user_id, override_date, override_type,
		       expected_start, expected_end,
		       reason, created_by, created_at
		FROM attendance.schedule_overrides
		WHERE company_id = $1`
	args := []interface{}{companyID}
	argPos := 2
	if startDate != nil {
		query += fmt.Sprintf(" AND override_date >= $%d", argPos)
		args = append(args, *startDate)
		argPos++
	}
	if endDate != nil {
		query += fmt.Sprintf(" AND override_date <= $%d", argPos)
		args = append(args, *endDate)
		argPos++
	}
	if overrideType != nil {
		query += fmt.Sprintf(" AND override_type = $%d", argPos)
		args = append(args, *overrideType)
		argPos++
	}
	query += " ORDER BY override_date"
	rows, err := r.client.Query(ctx, query, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var overrides []*models.ScheduleOverride
	for rows.Next() {
		ov, err := r.scanScheduleOverrideFromRows(rows)
		if err != nil {
			return nil, err
		}
		overrides = append(overrides, ov)
	}
	return overrides, nil
}

func (r *scheduleRepository) GetScheduleOverrideByUserDate(ctx context.Context, userID uuid.UUID, date time.Time) (*models.ScheduleOverride, error) {
	query := `
		SELECT override_id, company_id, user_id, override_date, override_type,
		       expected_start, expected_end,
		       reason, created_by, created_at
		FROM attendance.schedule_overrides
		WHERE user_id = $1 AND override_date = $2`
	row := r.client.QueryRow(ctx, query, userID, date)
	return r.scanScheduleOverride(row)
}

func (r *scheduleRepository) UpdateScheduleOverride(ctx context.Context, override *models.ScheduleOverride) error {
	query := `
		UPDATE attendance.schedule_overrides
		SET override_type = $1, reason = $2,
		    expected_start = $3, expected_end = $4
		WHERE override_id = $5`
	_, err := r.client.Exec(ctx, query,
		override.OverrideType,
		override.Reason,
		override.ExpectedStart,
		override.ExpectedEnd,
		override.OverrideID,
	)
	return err
}

func (r *scheduleRepository) DeleteScheduleOverride(ctx context.Context, overrideID uuid.UUID) error {
	_, err := r.client.Exec(ctx,
		`DELETE FROM attendance.schedule_overrides WHERE override_id = $1`, overrideID)
	return err
}

func (r *scheduleRepository) DeleteScheduleOverridesByReason(ctx context.Context, companyID, userID uuid.UUID, reason string) error {
	query := `
		DELETE FROM attendance.schedule_overrides
		WHERE company_id = $1 AND user_id = $2 AND reason = $3`
	_, err := r.client.Exec(ctx, query, companyID, userID, reason)
	return err
}

// ============================================================
// WORK CENTER SHIFT MAPPINGS
// ============================================================

func (r *scheduleRepository) CreateWorkCenterShiftMapping(ctx context.Context, mapping *models.WorkCenterShift) error {
	if mapping.MappingID == uuid.Nil {
		mapping.MappingID = uuid.New()
	}
	if mapping.CreatedAt.IsZero() {
		mapping.CreatedAt = time.Now().UTC()
	}
	query := `
		INSERT INTO attendance.work_center_shifts (
			mapping_id, company_id, work_center_code, shift_id,
			effective_from, effective_to, is_active, created_at, updated_at
		) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)`
	_, err := r.client.Exec(ctx, query,
		mapping.MappingID,
		mapping.CompanyID,
		mapping.WorkCenterCode,
		mapping.ShiftID,
		mapping.EffectiveFrom,
		mapping.EffectiveTo,
		mapping.IsActive,
		mapping.CreatedAt,
		mapping.UpdatedAt,
	)
	return err
}

func (r *scheduleRepository) GetWorkCenterShiftByCode(ctx context.Context, companyID uuid.UUID, workCenterCode string, date time.Time) (*models.WorkCenterShift, error) {
	query := `
		SELECT mapping_id, company_id, work_center_code, shift_id,
		       effective_from, effective_to, is_active, created_at, updated_at
		FROM attendance.work_center_shifts
		WHERE company_id = $1 AND work_center_code = $2
		  AND effective_from::date <= $3::date
		  AND (effective_to IS NULL OR effective_to::date >= $3::date)
		ORDER BY effective_from DESC
		LIMIT 1`
	row := r.client.QueryRow(ctx, query, companyID, workCenterCode, date)
	return r.scanWorkCenterShift(row)
}

func (r *scheduleRepository) GetWorkCenterShiftMappingsByShift(ctx context.Context, shiftID uuid.UUID) ([]*models.WorkCenterShift, error) {
	query := `
		SELECT mapping_id, company_id, work_center_code, shift_id,
		       effective_from, effective_to, is_active, created_at, updated_at
		FROM attendance.work_center_shifts
		WHERE shift_id = $1
		ORDER BY effective_from DESC`
	rows, err := r.client.Query(ctx, query, shiftID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var mappings []*models.WorkCenterShift
	for rows.Next() {
		m, err := r.scanWorkCenterShiftFromRows(rows)
		if err != nil {
			return nil, err
		}
		mappings = append(mappings, m)
	}
	return mappings, nil
}

func (r *scheduleRepository) UpdateWorkCenterShiftMapping(ctx context.Context, mapping *models.WorkCenterShift) error {
	mapping.UpdatedAt = time.Now().UTC()
	query := `
		UPDATE attendance.work_center_shifts
		SET shift_id = $1, effective_to = $2, is_active = $3, updated_at = $4
		WHERE mapping_id = $5`
	_, err := r.client.Exec(ctx, query,
		mapping.ShiftID,
		mapping.EffectiveTo,
		mapping.IsActive,
		mapping.UpdatedAt,
		mapping.MappingID,
	)
	return err
}

func (r *scheduleRepository) scanScheduleOverrideFromRows(rows *sql.Rows) (*models.ScheduleOverride, error) {
	var ov models.ScheduleOverride
	var reason sql.NullString
	var createdBy uuid.NullUUID
	var expectedStart, expectedEnd sql.NullTime // ← was sql.NullString

	err := rows.Scan(
		&ov.OverrideID,
		&ov.CompanyID,
		&ov.UserID,
		&ov.OverrideDate,
		&ov.OverrideType,
		&expectedStart,
		&expectedEnd,
		&reason,
		&createdBy,
		&ov.CreatedAt,
	)
	if err != nil {
		return nil, err
	}
	if expectedStart.Valid {
		s := expectedStart.Time.Format("15:04:05")
		ov.ExpectedStart = &s
	}
	if expectedEnd.Valid {
		s := expectedEnd.Time.Format("15:04:05")
		ov.ExpectedEnd = &s
	}
	if reason.Valid {
		ov.Reason = &reason.String
	}
	if createdBy.Valid {
		ov.CreatedBy = &createdBy.UUID
	}
	return &ov, nil
}

// BeginTx starts a transaction on the underlying Postgres client.
func (r *scheduleRepository) BeginTx(ctx context.Context, opts *sql.TxOptions) (*sql.Tx, error) {
	return r.client.BeginTx(ctx, opts)
}

// GetScheduleTemplateForLocationOnDate returns the effective template for
// a location on a given date. When locationID is nil (or uuid.Nil), only
// the company-wide row (location_id IS NULL) is considered.
//
// Precedence:
//  1. exact location match
//  2. company-wide fallback (location_id IS NULL)
//
// Only is_active = true rows are considered, and only rows whose
// effective_from/effective_to window covers the date.

func (r *scheduleRepository) GetScheduleTemplateForLocationOnDate(
	ctx context.Context,
	companyID uuid.UUID,
	locationID *uuid.UUID,
	date time.Time,
) (*models.ScheduleTemplate, error) {
	var locArg interface{}
	if locationID != nil && *locationID != uuid.Nil {
		locArg = *locationID
	}

	query := `SELECT ` + scheduleTemplateCols + `
        FROM attendance.schedule_templates
        WHERE company_id = $1
          AND position_id IS NULL
          AND is_active = true
          AND (
                ($2::uuid IS NULL AND location_id IS NULL)
             OR ($2::uuid IS NOT NULL AND (location_id = $2 OR location_id IS NULL))
          )
          AND effective_from <= $3::date
          AND (effective_to IS NULL OR effective_to >= $3::date)
        ORDER BY
          CASE WHEN $2::uuid IS NOT NULL AND location_id = $2 THEN 0 ELSE 1 END,
          effective_from DESC
        LIMIT 1
    `
	row := r.client.QueryRow(ctx, query, companyID, locArg, date)
	return r.scanScheduleTemplate(row)
}

// GetScheduleTemplateForPositionOnDate returns the effective position-scoped
// template for a position on a given date. Only rows with
// position_id = positionID AND location_id IS NULL are considered, per the
// chk_template_scope constraint.
//
// Returns (nil, nil) when no position-scoped row exists — the caller is
// expected to fall through to the next tier (WC mapping, location, company).
func (r *scheduleRepository) GetScheduleTemplateForPositionOnDate(
	ctx context.Context,
	companyID uuid.UUID,
	positionID uuid.UUID,
	date time.Time,
) (*models.ScheduleTemplate, error) {
	if positionID == uuid.Nil {
		return nil, nil
	}
	query := `SELECT ` + scheduleTemplateCols + `
		FROM attendance.schedule_templates
		WHERE company_id = $1
		  AND position_id = $2
		  AND location_id IS NULL
		  AND is_active = true
		  AND effective_from <= $3::date
		  AND (effective_to IS NULL OR effective_to >= $3::date)
		ORDER BY effective_from DESC
		LIMIT 1
	`
	row := r.client.QueryRow(ctx, query, companyID, positionID, date)
	return r.scanScheduleTemplate(row)
}
func (r *scheduleRepository) GetScheduleTemplatesByCompany(
	ctx context.Context,
	companyID uuid.UUID,
	locationID *uuid.UUID,
	activeOnly bool,
) ([]*models.ScheduleTemplate, error) {
	var locArg interface{}
	if locationID != nil {
		locArg = *locationID
	}
	query := `SELECT ` + scheduleTemplateCols + `
		FROM attendance.schedule_templates
		WHERE company_id = $1
		  AND effective_from <= CURRENT_DATE
		  AND (effective_to IS NULL OR effective_to >= CURRENT_DATE)
		  AND ($2::uuid IS NULL OR location_id = $2 OR location_id IS NULL)`
	if activeOnly {
		query += " AND is_active = true"
	}
	query += " ORDER BY location_id NULLS FIRST, name"
	rows, err := r.client.Query(ctx, query, companyID, locArg)
	if err != nil {
		return nil, fmt.Errorf("query schedule templates: %w", err)
	}
	defer rows.Close()
	return r.scanScheduleTemplates(rows)
}
func (r *scheduleRepository) GetScheduleTemplatesByCalendar(ctx context.Context, calendarID uuid.UUID) ([]*models.ScheduleTemplate, error) {
	query := `SELECT ` + scheduleTemplateCols + `
		FROM attendance.schedule_templates
		WHERE calendar_id = $1
		  AND effective_from <= CURRENT_DATE
		  AND (effective_to IS NULL OR effective_to >= CURRENT_DATE)
		ORDER BY name`
	rows, err := r.client.Query(ctx, query, calendarID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	return r.scanScheduleTemplates(rows)
}

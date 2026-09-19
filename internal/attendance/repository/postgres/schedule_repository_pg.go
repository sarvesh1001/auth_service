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
	calendar_id, company_id, location_id, year, name, timezone,
	working_days, holidays, is_active, created_at
`

const scheduleTemplateCols = `
	schedule_template_id, company_id, calendar_id, location_id,
	template_type, name, rules, is_active, created_at
`

const scheduleInstanceCols = `
	schedule_instance_id, company_id, user_id, location_id,
	schedule_date, schedule_template_id,
	expected_start, expected_end, timezone, metadata, work_center_code,
	generated_at, status, cancel_reason, cancelled_at
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

// GetWorkCalendarsByCompany — locationID == nil means no filter.
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
		  AND ($2::uuid IS NULL OR location_id = $2)
		ORDER BY year DESC`
	rows, err := r.client.Query(ctx, query, companyID, locArg)
	if err != nil {
		return nil, fmt.Errorf("query work calendars: %w", err)
	}
	defer rows.Close()
	return r.scanCalendars(rows)
}

// ── Schedule Templates ──

func (r *scheduleRepository) GetScheduleTemplate(ctx context.Context, templateID uuid.UUID) (*models.ScheduleTemplate, error) {
	query := `SELECT ` + scheduleTemplateCols + `
		FROM attendance.schedule_templates
		WHERE schedule_template_id = $1`
	row := r.client.QueryRow(ctx, query, templateID)
	return r.scanScheduleTemplate(row)
}

// GetScheduleTemplatesByCompany — locationID == nil means no filter.
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
		  AND ($2::uuid IS NULL OR location_id = $2)`
	if activeOnly {
		query += " AND is_active = true"
	}
	query += " ORDER BY name"
	rows, err := r.client.Query(ctx, query, companyID, locArg)
	if err != nil {
		return nil, fmt.Errorf("query schedule templates: %w", err)
	}
	defer rows.Close()
	return r.scanScheduleTemplates(rows)
}

// ── User Schedule Assignments ──

func (r *scheduleRepository) GetUserActiveScheduleAssignment(ctx context.Context, userID uuid.UUID, at time.Time) (*models.UserScheduleAssignment, error) {
	query := `
		SELECT user_id, schedule_template_id, effective_from, effective_to, assigned_by, created_at
		FROM attendance.user_schedule_assignments
		WHERE user_id = $1
		  AND effective_from <= $2
		  AND (effective_to IS NULL OR effective_to >= $2)
		ORDER BY effective_from DESC
		LIMIT 1`
	row := r.client.QueryRow(ctx, query, userID, at)
	return r.scanUserScheduleAssignment(row)
}

func (r *scheduleRepository) GetUserScheduleAssignments(ctx context.Context, userID uuid.UUID, from, to time.Time) ([]*models.UserScheduleAssignment, error) {
	query := `
		SELECT user_id, schedule_template_id, effective_from, effective_to, assigned_by, created_at
		FROM attendance.user_schedule_assignments
		WHERE user_id = $1
		  AND effective_from <= $2
		  AND (effective_to IS NULL OR effective_to >= $3)
		ORDER BY effective_from DESC`
	rows, err := r.client.Query(ctx, query, userID, to, from)
	if err != nil {
		return nil, fmt.Errorf("query user schedule assignments: %w", err)
	}
	defer rows.Close()
	var assignments []*models.UserScheduleAssignment
	for rows.Next() {
		ass, err := r.scanUserScheduleAssignmentFromRows(rows)
		if err != nil {
			return nil, err
		}
		assignments = append(assignments, ass)
	}
	return assignments, nil
}

// ── Schedule Instances ──

func (r *scheduleRepository) GetScheduleInstance(ctx context.Context, instanceID uuid.UUID) (*models.ScheduleInstance, error) {
	query := `SELECT ` + scheduleInstanceCols + `
		FROM attendance.schedule_instances
		WHERE schedule_instance_id = $1`
	row := r.client.QueryRow(ctx, query, instanceID)
	return r.scanScheduleInstance(row)
}

func (r *scheduleRepository) GetScheduleInstancesByUserDate(ctx context.Context, userID uuid.UUID, date time.Time) ([]*models.ScheduleInstance, error) {
	query := `SELECT ` + scheduleInstanceCols + `
		FROM attendance.schedule_instances
		WHERE user_id = $1
		  AND schedule_date = $2
		  AND status = 'active'
		ORDER BY expected_start`
	rows, err := r.client.Query(ctx, query, userID, date)
	if err != nil {
		return nil, fmt.Errorf("query schedule instances: %w", err)
	}
	defer rows.Close()
	return r.scanScheduleInstances(rows)
}

func (r *scheduleRepository) CreateScheduleInstance(ctx context.Context, tx *sql.Tx, instance *models.ScheduleInstance) error {
	if instance.ScheduleInstanceID == uuid.Nil {
		instance.ScheduleInstanceID = uuid.New()
	}
	if instance.GeneratedAt.IsZero() {
		instance.GeneratedAt = time.Now().UTC()
	}
	if instance.Timezone == "" {
		instance.Timezone = "UTC"
	}
	metadataJSON, _ := json.Marshal(instance.Metadata)

	query := `
		INSERT INTO attendance.schedule_instances (
			schedule_instance_id, company_id, user_id, location_id,
			schedule_date, schedule_template_id,
			expected_start, expected_end, timezone, metadata, work_center_code,
			generated_at, status, cancel_reason, cancelled_at
		) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15)`
	exec := func(q string, args ...interface{}) (sql.Result, error) {
		if tx != nil {
			return tx.ExecContext(ctx, q, args...)
		}
		return r.client.Exec(ctx, q, args...)
	}
	_, err := exec(query,
		instance.ScheduleInstanceID,
		instance.CompanyID,
		instance.UserID,
		instance.LocationID,
		instance.ScheduleDate,
		instance.ScheduleTemplateID,
		instance.ExpectedStart,
		instance.ExpectedEnd,
		instance.Timezone,
		metadataJSON,
		instance.WorkCenterCode,
		instance.GeneratedAt,
		instance.Status,
		instance.CancelReason,
		instance.CancelledAt,
	)
	return err
}

func (r *scheduleRepository) UpdateScheduleInstanceStatus(ctx context.Context, tx *sql.Tx, instanceID uuid.UUID, status string, cancelReason *string) error {
	query := `
		UPDATE attendance.schedule_instances
		SET status = $1, cancel_reason = $2,
		    cancelled_at = CASE WHEN $1 = 'cancelled' THEN NOW() ELSE NULL END
		WHERE schedule_instance_id = $3`
	exec := func(q string, args ...interface{}) (sql.Result, error) {
		if tx != nil {
			return tx.ExecContext(ctx, q, args...)
		}
		return r.client.Exec(ctx, q, args...)
	}
	_, err := exec(query, status, cancelReason, instanceID)
	return err
}

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
		  AND is_active = true
		ORDER BY effective_from DESC
		LIMIT 1`
	row := r.client.QueryRow(ctx, query, companyID, workCenterCode, at)
	shift, err := r.scanWorkCenterShift(row)
	if err != nil {
		return nil, err
	}
	if shift == nil {
		r.logger.Debug("No work center shift mapping found (date-casted)",
			zap.String("work_center", workCenterCode),
			zap.String("date", at.Format("2006-01-02")),
		)
	} else {
		r.logger.Debug("Work center shift mapping found (date-casted)",
			zap.String("work_center", workCenterCode),
			zap.String("shift_id", shift.ShiftID.String()),
			zap.Time("effective_from", shift.EffectiveFrom),
		)
	}
	return shift, nil
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

// ── User Work Center Assignments ──

func (r *scheduleRepository) GetUserWorkCenterAssignment(ctx context.Context, userID uuid.UUID, at time.Time) (*models.UserWorkCenterAssignment, error) {
	query := `
		SELECT assignment_id, company_id, user_id, work_center_code,
		       effective_from, effective_to, is_active, created_at, updated_at
		FROM attendance.user_work_center_assignments
		WHERE user_id = $1
		  AND effective_from <= $2
		  AND (effective_to IS NULL OR effective_to >= $2)
		  AND is_active = true
		ORDER BY effective_from DESC
		LIMIT 1`
	row := r.client.QueryRow(ctx, query, userID, at)
	return r.scanUserWorkCenterAssignment(row)
}

func (r *scheduleRepository) GetUserWorkCenterAssignments(ctx context.Context, userID uuid.UUID) ([]*models.UserWorkCenterAssignment, error) {
	query := `
		SELECT assignment_id, company_id, user_id, work_center_code,
		       effective_from, effective_to, is_active, created_at, updated_at
		FROM attendance.user_work_center_assignments
		WHERE user_id = $1
		ORDER BY effective_from DESC`
	rows, err := r.client.Query(ctx, query, userID)
	if err != nil {
		return nil, fmt.Errorf("query user work center assignments: %w", err)
	}
	defer rows.Close()
	var assignments []*models.UserWorkCenterAssignment
	for rows.Next() {
		ass, err := r.scanUserWorkCenterAssignmentFromRows(rows)
		if err != nil {
			return nil, err
		}
		assignments = append(assignments, ass)
	}
	return assignments, nil
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

// ── Schedule Overrides (legacy) ──

func (r *scheduleRepository) GetScheduleOverride(ctx context.Context, userID uuid.UUID, date time.Time) (*models.ScheduleOverride, error) {
	query := `
		SELECT override_id, company_id, user_id, override_date, override_type,
		       reason, created_by, created_at
		FROM attendance.schedule_overrides
		WHERE user_id = $1 AND override_date = $2`
	row := r.client.QueryRow(ctx, query, userID, date)
	return r.scanScheduleOverride(row)
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
	var workingDays []int
	var locationID sql.NullString

	err := row.Scan(
		&cal.CalendarID,
		&cal.CompanyID,
		&locationID,
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
		return nil, err
	}
	cal.WorkingDays = workingDays
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
		var workingDays []int
		var locationID sql.NullString

		if err := rows.Scan(
			&cal.CalendarID,
			&cal.CompanyID,
			&locationID,
			&cal.Year,
			&cal.Name,
			&cal.Timezone,
			pq.Array(&workingDays),
			&holidaysJSON,
			&cal.IsActive,
			&cal.CreatedAt,
		); err != nil {
			return nil, err
		}
		cal.WorkingDays = workingDays
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
	var locationID sql.NullString

	err := row.Scan(
		&tmpl.ScheduleTemplateID,
		&tmpl.CompanyID,
		&tmpl.CalendarID,
		&locationID,
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
		var locationID sql.NullString

		if err := rows.Scan(
			&tmpl.ScheduleTemplateID,
			&tmpl.CompanyID,
			&tmpl.CalendarID,
			&locationID,
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

func (r *scheduleRepository) scanUserScheduleAssignment(row *sql.Row) (*models.UserScheduleAssignment, error) {
	var ass models.UserScheduleAssignment
	var assignedBy uuid.NullUUID
	var effectiveTo sql.NullTime
	err := row.Scan(
		&ass.UserID,
		&ass.ScheduleTemplateID,
		&ass.EffectiveFrom,
		&effectiveTo,
		&assignedBy,
		&ass.CreatedAt,
	)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, nil
		}
		return nil, err
	}
	if effectiveTo.Valid {
		ass.EffectiveTo = &effectiveTo.Time
	}
	if assignedBy.Valid {
		ass.AssignedBy = &assignedBy.UUID
	}
	return &ass, nil
}

func (r *scheduleRepository) scanUserScheduleAssignmentFromRows(rows *sql.Rows) (*models.UserScheduleAssignment, error) {
	var ass models.UserScheduleAssignment
	var assignedBy uuid.NullUUID
	var effectiveTo sql.NullTime
	err := rows.Scan(
		&ass.UserID,
		&ass.ScheduleTemplateID,
		&ass.EffectiveFrom,
		&effectiveTo,
		&assignedBy,
		&ass.CreatedAt,
	)
	if err != nil {
		return nil, err
	}
	if effectiveTo.Valid {
		ass.EffectiveTo = &effectiveTo.Time
	}
	if assignedBy.Valid {
		ass.AssignedBy = &assignedBy.UUID
	}
	return &ass, nil
}

func (r *scheduleRepository) scanScheduleInstance(row *sql.Row) (*models.ScheduleInstance, error) {
	var inst models.ScheduleInstance
	var metadataJSON []byte
	var expectedStart, expectedEnd sql.NullTime
	var workCenterCode, cancelReason, locationID sql.NullString
	var cancelledAt sql.NullTime

	err := row.Scan(
		&inst.ScheduleInstanceID,
		&inst.CompanyID,
		&inst.UserID,
		&locationID,
		&inst.ScheduleDate,
		&inst.ScheduleTemplateID,
		&expectedStart,
		&expectedEnd,
		&inst.Timezone,
		&metadataJSON,
		&workCenterCode,
		&inst.GeneratedAt,
		&inst.Status,
		&cancelReason,
		&cancelledAt,
	)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, nil
		}
		return nil, err
	}
	r.assignScheduleInstanceNulls(&inst, locationID, expectedStart, expectedEnd, workCenterCode, cancelReason, cancelledAt, metadataJSON)
	return &inst, nil
}

func (r *scheduleRepository) scanScheduleInstances(rows *sql.Rows) ([]*models.ScheduleInstance, error) {
	var instances []*models.ScheduleInstance
	for rows.Next() {
		var inst models.ScheduleInstance
		var metadataJSON []byte
		var expectedStart, expectedEnd sql.NullTime
		var workCenterCode, cancelReason, locationID sql.NullString
		var cancelledAt sql.NullTime

		if err := rows.Scan(
			&inst.ScheduleInstanceID,
			&inst.CompanyID,
			&inst.UserID,
			&locationID,
			&inst.ScheduleDate,
			&inst.ScheduleTemplateID,
			&expectedStart,
			&expectedEnd,
			&inst.Timezone,
			&metadataJSON,
			&workCenterCode,
			&inst.GeneratedAt,
			&inst.Status,
			&cancelReason,
			&cancelledAt,
		); err != nil {
			return nil, err
		}
		r.assignScheduleInstanceNulls(&inst, locationID, expectedStart, expectedEnd, workCenterCode, cancelReason, cancelledAt, metadataJSON)
		instances = append(instances, &inst)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("rows iteration: %w", err)
	}
	return instances, nil
}

func (r *scheduleRepository) assignScheduleInstanceNulls(
	inst *models.ScheduleInstance,
	locationID sql.NullString,
	expectedStart, expectedEnd sql.NullTime,
	workCenterCode, cancelReason sql.NullString,
	cancelledAt sql.NullTime,
	metadataJSON []byte,
) {
	if locationID.Valid && locationID.String != "" {
		if id, err := uuid.Parse(locationID.String); err == nil {
			inst.LocationID = &id
		}
	}
	if expectedStart.Valid {
		inst.ExpectedStart = &expectedStart.Time
	}
	if expectedEnd.Valid {
		inst.ExpectedEnd = &expectedEnd.Time
	}
	if workCenterCode.Valid {
		inst.WorkCenterCode = &workCenterCode.String
	}
	if cancelReason.Valid {
		inst.CancelReason = &cancelReason.String
	}
	if cancelledAt.Valid {
		inst.CancelledAt = &cancelledAt.Time
	}
	if len(metadataJSON) > 0 {
		_ = json.Unmarshal(metadataJSON, &inst.Metadata)
	}
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

func (r *scheduleRepository) scanUserWorkCenterAssignment(row *sql.Row) (*models.UserWorkCenterAssignment, error) {
	var ass models.UserWorkCenterAssignment
	var effectiveTo sql.NullTime
	err := row.Scan(
		&ass.AssignmentID,
		&ass.CompanyID,
		&ass.UserID,
		&ass.WorkCenterCode,
		&ass.EffectiveFrom,
		&effectiveTo,
		&ass.IsActive,
		&ass.CreatedAt,
		&ass.UpdatedAt,
	)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, nil
		}
		return nil, err
	}
	if effectiveTo.Valid {
		ass.EffectiveTo = &effectiveTo.Time
	}
	return &ass, nil
}

func (r *scheduleRepository) scanUserWorkCenterAssignmentFromRows(rows *sql.Rows) (*models.UserWorkCenterAssignment, error) {
	var ass models.UserWorkCenterAssignment
	var effectiveTo sql.NullTime
	err := rows.Scan(
		&ass.AssignmentID,
		&ass.CompanyID,
		&ass.UserID,
		&ass.WorkCenterCode,
		&ass.EffectiveFrom,
		&effectiveTo,
		&ass.IsActive,
		&ass.CreatedAt,
		&ass.UpdatedAt,
	)
	if err != nil {
		return nil, err
	}
	if effectiveTo.Valid {
		ass.EffectiveTo = &effectiveTo.Time
	}
	return &ass, nil
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
	err := row.Scan(
		&ov.OverrideID,
		&ov.CompanyID,
		&ov.UserID,
		&ov.OverrideDate,
		&ov.OverrideType,
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
	if reason.Valid {
		ov.Reason = &reason.String
	}
	if createdBy.Valid {
		ov.CreatedBy = &createdBy.UUID
	}
	return &ov, nil
}

// ============================================================
// WORK CALENDARS — CRUD (extended)
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
			calendar_id, company_id, location_id, year, name, timezone,
			working_days, holidays, is_active, created_at
		) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10)`
	_, err := r.client.Exec(ctx, query,
		calendar.CalendarID,
		calendar.CompanyID,
		calendar.LocationID,
		calendar.Year,
		calendar.Name,
		calendar.Timezone,
		pq.Array(calendar.WorkingDays),
		holidaysJSON,
		calendar.IsActive,
		calendar.CreatedAt,
	)
	return err
}

func (r *scheduleRepository) GetWorkCalendarByID(ctx context.Context, calendarID uuid.UUID) (*models.WorkCalendar, error) {
	query := `SELECT ` + workCalendarCols + `
		FROM attendance.work_calendars
		WHERE calendar_id = $1`
	row := r.client.QueryRow(ctx, query, calendarID)
	return r.scanWorkCalendar(row)
}

func (r *scheduleRepository) UpdateWorkCalendar(ctx context.Context, calendar *models.WorkCalendar) error {
	holidaysJSON, _ := json.Marshal(calendar.Holidays)
	query := `
		UPDATE attendance.work_calendars
		SET location_id = $1, name = $2, timezone = $3,
		    working_days = $4, holidays = $5, is_active = $6
		WHERE calendar_id = $7`
	_, err := r.client.Exec(ctx, query,
		calendar.LocationID,
		calendar.Name,
		calendar.Timezone,
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
// SCHEDULE TEMPLATES — CRUD (extended)
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
			schedule_template_id, company_id, calendar_id, location_id,
			template_type, name, rules, is_active, created_at
		) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)`
	_, err := r.client.Exec(ctx, query,
		template.ScheduleTemplateID,
		template.CompanyID,
		template.CalendarID,
		template.LocationID,
		template.TemplateType,
		template.Name,
		rulesJSON,
		template.IsActive,
		template.CreatedAt,
	)
	return err
}

func (r *scheduleRepository) GetScheduleTemplatesByCalendar(ctx context.Context, calendarID uuid.UUID) ([]*models.ScheduleTemplate, error) {
	query := `SELECT ` + scheduleTemplateCols + `
		FROM attendance.schedule_templates
		WHERE calendar_id = $1
		ORDER BY name`
	rows, err := r.client.Query(ctx, query, calendarID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	return r.scanScheduleTemplates(rows)
}

func (r *scheduleRepository) UpdateScheduleTemplate(ctx context.Context, template *models.ScheduleTemplate) error {
	rulesJSON, _ := json.Marshal(template.Rules)
	query := `
		UPDATE attendance.schedule_templates
		SET location_id = $1, name = $2, calendar_id = $3,
		    template_type = $4, rules = $5, is_active = $6
		WHERE schedule_template_id = $7`
	_, err := r.client.Exec(ctx, query,
		template.LocationID,
		template.Name,
		template.CalendarID,
		template.TemplateType,
		rulesJSON,
		template.IsActive,
		template.ScheduleTemplateID,
	)
	return err
}

func (r *scheduleRepository) DeleteScheduleTemplate(ctx context.Context, templateID uuid.UUID) error {
	_, err := r.client.Exec(ctx,
		`DELETE FROM attendance.schedule_templates WHERE schedule_template_id = $1`, templateID)
	return err
}

// ============================================================
// SCHEDULE INSTANCES — extended
// ============================================================

func (r *scheduleRepository) GetScheduleInstancesByUser(ctx context.Context, userID uuid.UUID, startDate, endDate time.Time) ([]*models.ScheduleInstance, error) {
	query := `SELECT ` + scheduleInstanceCols + `
		FROM attendance.schedule_instances
		WHERE user_id = $1 AND schedule_date BETWEEN $2 AND $3
		ORDER BY schedule_date, expected_start`
	rows, err := r.client.Query(ctx, query, userID, startDate, endDate)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	return r.scanScheduleInstances(rows)
}

// GetScheduleInstancesByCompany — locationID == nil means no filter.
func (r *scheduleRepository) GetScheduleInstancesByCompany(
	ctx context.Context,
	companyID uuid.UUID,
	locationID *uuid.UUID,
	startDate, endDate time.Time,
) ([]*models.ScheduleInstance, error) {
	var locArg interface{}
	if locationID != nil {
		locArg = *locationID
	}
	query := `SELECT ` + scheduleInstanceCols + `
		FROM attendance.schedule_instances
		WHERE company_id = $1
		  AND ($2::uuid IS NULL OR location_id = $2)
		  AND schedule_date BETWEEN $3 AND $4
		ORDER BY schedule_date, user_id`
	rows, err := r.client.Query(ctx, query, companyID, locArg, startDate, endDate)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	return r.scanScheduleInstances(rows)
}

func (r *scheduleRepository) GetScheduleInstancesByTemplate(ctx context.Context, templateID uuid.UUID, startDate, endDate time.Time) ([]*models.ScheduleInstance, error) {
	query := `SELECT ` + scheduleInstanceCols + `
		FROM attendance.schedule_instances
		WHERE schedule_template_id = $1 AND schedule_date BETWEEN $2 AND $3
		ORDER BY schedule_date, user_id`
	rows, err := r.client.Query(ctx, query, templateID, startDate, endDate)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	return r.scanScheduleInstances(rows)
}

func (r *scheduleRepository) GetScheduleInstancesByWorkCenter(ctx context.Context, companyID uuid.UUID, workCenterCode string, startDate, endDate time.Time) ([]*models.ScheduleInstance, error) {
	query := `SELECT ` + scheduleInstanceCols + `
		FROM attendance.schedule_instances
		WHERE company_id = $1 AND work_center_code = $2
		  AND schedule_date BETWEEN $3 AND $4
		ORDER BY schedule_date, user_id`
	rows, err := r.client.Query(ctx, query, companyID, workCenterCode, startDate, endDate)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	return r.scanScheduleInstances(rows)
}

func (r *scheduleRepository) UpdateScheduleInstance(ctx context.Context, instance *models.ScheduleInstance) error {
	metadataJSON, _ := json.Marshal(instance.Metadata)
	query := `
		UPDATE attendance.schedule_instances
		SET location_id = $1, expected_start = $2, expected_end = $3,
		    timezone = $4, metadata = $5, status = $6,
		    cancel_reason = $7, cancelled_at = $8
		WHERE schedule_instance_id = $9`
	_, err := r.client.Exec(ctx, query,
		instance.LocationID,
		instance.ExpectedStart,
		instance.ExpectedEnd,
		instance.Timezone,
		metadataJSON,
		instance.Status,
		instance.CancelReason,
		instance.CancelledAt,
		instance.ScheduleInstanceID,
	)
	return err
}

func (r *scheduleRepository) DeleteScheduleInstance(ctx context.Context, instanceID uuid.UUID) error {
	_, err := r.client.Exec(ctx,
		`DELETE FROM attendance.schedule_instances WHERE schedule_instance_id = $1`, instanceID)
	return err
}

func (r *scheduleRepository) CancelScheduleInstance(ctx context.Context, instanceID uuid.UUID, reason string) error {
	query := `
		UPDATE attendance.schedule_instances
		SET status = 'cancelled', cancel_reason = $1, cancelled_at = NOW()
		WHERE schedule_instance_id = $2`
	_, err := r.client.Exec(ctx, query, reason, instanceID)
	return err
}

func (r *scheduleRepository) HasActiveSchedule(ctx context.Context, companyID, userID uuid.UUID, date time.Time) (bool, error) {
	var exists bool
	query := `
		SELECT EXISTS (
			SELECT 1 FROM attendance.schedule_instances
			WHERE company_id = $1 AND user_id = $2
			  AND schedule_date = $3 AND status = 'active'
		)`
	err := r.client.QueryRow(ctx, query, companyID, userID, date).Scan(&exists)
	return exists, err
}

// ============================================================
// SCHEDULE OVERRIDES — CRUD (extended)
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
			reason, created_by, created_at
		) VALUES ($1, $2, $3, $4, $5, $6, $7, $8)`
	_, err := r.client.Exec(ctx, query,
		override.OverrideID,
		override.CompanyID,
		override.UserID,
		override.OverrideDate,
		override.OverrideType,
		override.Reason,
		override.CreatedBy,
		override.CreatedAt,
	)
	return err
}

func (r *scheduleRepository) GetScheduleOverrideByID(ctx context.Context, overrideID uuid.UUID) (*models.ScheduleOverride, error) {
	query := `
		SELECT override_id, company_id, user_id, override_date, override_type,
		       reason, created_by, created_at
		FROM attendance.schedule_overrides
		WHERE override_id = $1`
	row := r.client.QueryRow(ctx, query, overrideID)
	return r.scanScheduleOverride(row)
}

func (r *scheduleRepository) GetScheduleOverridesByUser(ctx context.Context, userID uuid.UUID, startDate, endDate *time.Time, overrideType *string) ([]*models.ScheduleOverride, error) {
	query := `
		SELECT override_id, company_id, user_id, override_date, override_type,
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
		       reason, created_by, created_at
		FROM attendance.schedule_overrides
		WHERE user_id = $1 AND override_date = $2`
	row := r.client.QueryRow(ctx, query, userID, date)
	return r.scanScheduleOverride(row)
}

func (r *scheduleRepository) UpdateScheduleOverride(ctx context.Context, override *models.ScheduleOverride) error {
	query := `
		UPDATE attendance.schedule_overrides
		SET override_type = $1, reason = $2
		WHERE override_id = $3`
	_, err := r.client.Exec(ctx, query,
		override.OverrideType,
		override.Reason,
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
	r.logger.Info("GetWorkCenterShiftByCode",
		zap.String("company_id", companyID.String()),
		zap.String("work_center_code", workCenterCode),
		zap.Time("date", date),
	)
	query := `
		SELECT mapping_id, company_id, work_center_code, shift_id,
		       effective_from, effective_to, is_active, created_at, updated_at
		FROM attendance.work_center_shifts
		WHERE company_id = $1 AND work_center_code = $2
		  AND effective_from::date <= $3::date
		  AND (effective_to IS NULL OR effective_to::date >= $3::date)
		  AND is_active = true
		ORDER BY effective_from DESC
		LIMIT 1`
	row := r.client.QueryRow(ctx, query, companyID, workCenterCode, date)
	return r.scanWorkCenterShiftMapping(row)
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
		m, err := r.scanWorkCenterShiftMappingFromRows(rows)
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

func (r *scheduleRepository) scanWorkCenterShiftMapping(row *sql.Row) (*models.WorkCenterShift, error) {
	var m models.WorkCenterShift
	var effectiveTo sql.NullTime
	err := row.Scan(
		&m.MappingID,
		&m.CompanyID,
		&m.WorkCenterCode,
		&m.ShiftID,
		&m.EffectiveFrom,
		&effectiveTo,
		&m.IsActive,
		&m.CreatedAt,
		&m.UpdatedAt,
	)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, nil
		}
		return nil, err
	}
	if effectiveTo.Valid {
		m.EffectiveTo = &effectiveTo.Time
	}
	return &m, nil
}

func (r *scheduleRepository) scanWorkCenterShiftMappingFromRows(rows *sql.Rows) (*models.WorkCenterShift, error) {
	var m models.WorkCenterShift
	var effectiveTo sql.NullTime
	err := rows.Scan(
		&m.MappingID,
		&m.CompanyID,
		&m.WorkCenterCode,
		&m.ShiftID,
		&m.EffectiveFrom,
		&effectiveTo,
		&m.IsActive,
		&m.CreatedAt,
		&m.UpdatedAt,
	)
	if err != nil {
		return nil, err
	}
	if effectiveTo.Valid {
		m.EffectiveTo = &effectiveTo.Time
	}
	return &m, nil
}

func (r *scheduleRepository) scanScheduleOverrideFromRows(rows *sql.Rows) (*models.ScheduleOverride, error) {
	var ov models.ScheduleOverride
	var reason sql.NullString
	var createdBy uuid.NullUUID
	err := rows.Scan(
		&ov.OverrideID,
		&ov.CompanyID,
		&ov.UserID,
		&ov.OverrideDate,
		&ov.OverrideType,
		&reason,
		&createdBy,
		&ov.CreatedAt,
	)
	if err != nil {
		return nil, err
	}
	if reason.Valid {
		ov.Reason = &reason.String
	}
	if createdBy.Valid {
		ov.CreatedBy = &createdBy.UUID
	}
	return &ov, nil
}

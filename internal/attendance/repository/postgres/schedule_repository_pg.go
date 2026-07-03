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

// ── Work Centers ──

func (r *scheduleRepository) GetWorkCenter(ctx context.Context, companyID uuid.UUID, workCenterCode string) (*models.WorkCenter, error) {
	query := `
		SELECT work_center_code, company_id, name, description, timezone, is_active, created_at, updated_at
		FROM attendance.work_centers
		WHERE company_id = $1 AND work_center_code = $2
	`
	row := r.client.QueryRow(ctx, query, companyID, workCenterCode)
	return r.scanWorkCenter(row)
}

func (r *scheduleRepository) GetWorkCentersByCompany(ctx context.Context, companyID uuid.UUID, activeOnly bool) ([]*models.WorkCenter, error) {
	query := `
		SELECT work_center_code, company_id, name, description, timezone, is_active, created_at, updated_at
		FROM attendance.work_centers
		WHERE company_id = $1
	`
	if activeOnly {
		query += " AND is_active = true"
	}
	query += " ORDER BY name"
	rows, err := r.client.Query(ctx, query, companyID)
	if err != nil {
		return nil, fmt.Errorf("query work centers: %w", err)
	}
	defer rows.Close()
	var centers []*models.WorkCenter
	for rows.Next() {
		wc, err := r.scanWorkCenterFromRows(rows)
		if err != nil {
			return nil, err
		}
		centers = append(centers, wc)
	}
	return centers, nil
}

// ── Work Calendars ──

func (r *scheduleRepository) GetWorkCalendar(ctx context.Context, companyID uuid.UUID, year int) (*models.WorkCalendar, error) {
	query := `
		SELECT calendar_id, company_id, year, name, timezone, working_days, holidays, is_active, created_at
		FROM attendance.work_calendars
		WHERE company_id = $1 AND year = $2
	`
	row := r.client.QueryRow(ctx, query, companyID, year)
	return r.scanWorkCalendar(row)
}

func (r *scheduleRepository) GetWorkCalendarsByCompany(ctx context.Context, companyID uuid.UUID) ([]*models.WorkCalendar, error) {
	query := `
		SELECT calendar_id, company_id, year, name, timezone, working_days, holidays, is_active, created_at
		FROM attendance.work_calendars
		WHERE company_id = $1
		ORDER BY year DESC
	`
	rows, err := r.client.Query(ctx, query, companyID)
	if err != nil {
		return nil, fmt.Errorf("query work calendars: %w", err)
	}
	defer rows.Close()
	var calendars []*models.WorkCalendar
	for rows.Next() {
		cal, err := r.scanWorkCalendarFromRows(rows)
		if err != nil {
			return nil, err
		}
		calendars = append(calendars, cal)
	}
	return calendars, nil
}

// ── Schedule Templates ──

func (r *scheduleRepository) GetScheduleTemplate(ctx context.Context, templateID uuid.UUID) (*models.ScheduleTemplate, error) {
	query := `
		SELECT schedule_template_id, company_id, calendar_id, template_type, name, rules, is_active, created_at
		FROM attendance.schedule_templates
		WHERE schedule_template_id = $1
	`
	row := r.client.QueryRow(ctx, query, templateID)
	return r.scanScheduleTemplate(row)
}

func (r *scheduleRepository) GetScheduleTemplatesByCompany(ctx context.Context, companyID uuid.UUID, activeOnly bool) ([]*models.ScheduleTemplate, error) {
	query := `
		SELECT schedule_template_id, company_id, calendar_id, template_type, name, rules, is_active, created_at
		FROM attendance.schedule_templates
		WHERE company_id = $1
	`
	if activeOnly {
		query += " AND is_active = true"
	}
	query += " ORDER BY name"
	rows, err := r.client.Query(ctx, query, companyID)
	if err != nil {
		return nil, fmt.Errorf("query schedule templates: %w", err)
	}
	defer rows.Close()
	var templates []*models.ScheduleTemplate
	for rows.Next() {
		tmpl, err := r.scanScheduleTemplateFromRows(rows)
		if err != nil {
			return nil, err
		}
		templates = append(templates, tmpl)
	}
	return templates, nil
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
		LIMIT 1
	`
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
		ORDER BY effective_from DESC
	`
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
	query := `
		SELECT schedule_instance_id, company_id, user_id, schedule_date, schedule_template_id,
		       expected_start, expected_end, timezone, metadata, work_center_code,
		       generated_at, status, cancel_reason, cancelled_at
		FROM attendance.schedule_instances
		WHERE schedule_instance_id = $1
	`
	row := r.client.QueryRow(ctx, query, instanceID)
	return r.scanScheduleInstance(row)
}

func (r *scheduleRepository) GetScheduleInstancesByUserDate(ctx context.Context, userID uuid.UUID, date time.Time) ([]*models.ScheduleInstance, error) {
	query := `
		SELECT schedule_instance_id, company_id, user_id, schedule_date, schedule_template_id,
		       expected_start, expected_end, timezone, metadata, work_center_code,
		       generated_at, status, cancel_reason, cancelled_at
		FROM attendance.schedule_instances
		WHERE user_id = $1
		  AND schedule_date = $2
		  AND status = 'active'
		ORDER BY expected_start
	`
	rows, err := r.client.Query(ctx, query, userID, date)
	if err != nil {
		return nil, fmt.Errorf("query schedule instances: %w", err)
	}
	defer rows.Close()
	var instances []*models.ScheduleInstance
	for rows.Next() {
		inst, err := r.scanScheduleInstanceFromRows(rows)
		if err != nil {
			return nil, err
		}
		instances = append(instances, inst)
	}
	return instances, nil
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
			schedule_instance_id, company_id, user_id, schedule_date, schedule_template_id,
			expected_start, expected_end, timezone, metadata, work_center_code,
			generated_at, status, cancel_reason, cancelled_at
		) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14)
	`
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
		SET status = $1, cancel_reason = $2, cancelled_at = CASE WHEN $1 = 'cancelled' THEN NOW() ELSE NULL END
		WHERE schedule_instance_id = $3
	`
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

// GetWorkCenterShift – used in older code; now also date‑casted for safety.
func (r *scheduleRepository) GetWorkCenterShift(ctx context.Context, companyID uuid.UUID, workCenterCode string, at time.Time) (*models.WorkCenterShift, error) {
	query := `
		SELECT mapping_id, company_id, work_center_code, shift_id, effective_from, effective_to, is_active, created_at, updated_at
		FROM attendance.work_center_shifts
		WHERE company_id = $1
		  AND work_center_code = $2
		  AND effective_from::date <= $3::date
		  AND (effective_to IS NULL OR effective_to::date >= $3::date)
		  AND is_active = true
		ORDER BY effective_from DESC
		LIMIT 1
	`
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
		SELECT mapping_id, company_id, work_center_code, shift_id, effective_from, effective_to, is_active, created_at, updated_at
		FROM attendance.work_center_shifts
		WHERE company_id = $1 AND work_center_code = $2
		ORDER BY effective_from DESC
	`
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
		SELECT assignment_id, company_id, user_id, work_center_code, effective_from, effective_to, is_active, created_at, updated_at
		FROM attendance.user_work_center_assignments
		WHERE user_id = $1
		  AND effective_from <= $2
		  AND (effective_to IS NULL OR effective_to >= $2)
		  AND is_active = true
		ORDER BY effective_from DESC
		LIMIT 1
	`
	row := r.client.QueryRow(ctx, query, userID, at)
	return r.scanUserWorkCenterAssignment(row)
}

func (r *scheduleRepository) GetUserWorkCenterAssignments(ctx context.Context, userID uuid.UUID) ([]*models.UserWorkCenterAssignment, error) {
	query := `
		SELECT assignment_id, company_id, user_id, work_center_code, effective_from, effective_to, is_active, created_at, updated_at
		FROM attendance.user_work_center_assignments
		WHERE user_id = $1
		ORDER BY effective_from DESC
	`
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
		SELECT entitlement_id, company_id, user_id, period_type, off_count, requires_approval, effective_from, effective_to, created_at
		FROM attendance.user_off_entitlements
		WHERE user_id = $1
		  AND effective_from <= $2
		  AND (effective_to IS NULL OR effective_to >= $2)
		ORDER BY effective_from DESC
		LIMIT 1
	`
	row := r.client.QueryRow(ctx, query, userID, at)
	return r.scanUserOffEntitlement(row)
}

// ── Off Requests ──

func (r *scheduleRepository) GetOffRequests(ctx context.Context, userID uuid.UUID, startDate, endDate time.Time) ([]*models.OffRequest, error) {
	rows, err := r.client.Query(ctx, `
		SELECT off_request_id, company_id, user_id, request_dates, status, requested_by, approved_by, approved_at, created_at
		FROM attendance.off_requests
		WHERE user_id = $1
		  AND status = 'approved'
	`, userID)
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

// ── Schedule Overrides ──

func (r *scheduleRepository) GetScheduleOverride(ctx context.Context, userID uuid.UUID, date time.Time) (*models.ScheduleOverride, error) {
	query := `
		SELECT override_id, company_id, user_id, override_date, override_type, reason, created_by, created_at
		FROM attendance.schedule_overrides
		WHERE user_id = $1 AND override_date = $2
	`
	row := r.client.QueryRow(ctx, query, userID, date)
	return r.scanScheduleOverride(row)
}

// ── Health Check ──

func (r *scheduleRepository) HealthCheck(ctx context.Context) error {
	query := `SELECT 1 FROM attendance.work_centers LIMIT 1`
	_, err := r.client.Exec(ctx, query)
	if err != nil {
		return fmt.Errorf("schedule repository health check failed: %w", err)
	}
	return nil
}

// ── Scan Helpers ──

func (r *scheduleRepository) scanWorkCenter(row *sql.Row) (*models.WorkCenter, error) {
	var wc models.WorkCenter
	var desc sql.NullString
	err := row.Scan(
		&wc.WorkCenterCode,
		&wc.CompanyID,
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
	return &wc, nil
}

func (r *scheduleRepository) scanWorkCenterFromRows(rows *sql.Rows) (*models.WorkCenter, error) {
	var wc models.WorkCenter
	var desc sql.NullString
	err := rows.Scan(
		&wc.WorkCenterCode,
		&wc.CompanyID,
		&wc.Name,
		&desc,
		&wc.Timezone,
		&wc.IsActive,
		&wc.CreatedAt,
		&wc.UpdatedAt,
	)
	if err != nil {
		return nil, err
	}
	if desc.Valid {
		wc.Description = &desc.String
	}
	return &wc, nil
}

func (r *scheduleRepository) scanWorkCalendar(row *sql.Row) (*models.WorkCalendar, error) {
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
		return nil, err
	}
	cal.WorkingDays = workingDays
	if len(holidaysJSON) > 0 {
		if err := json.Unmarshal(holidaysJSON, &cal.Holidays); err != nil {
			return nil, fmt.Errorf("unmarshal holidays: %w", err)
		}
	}
	return &cal, nil
}

func (r *scheduleRepository) scanWorkCalendarFromRows(rows *sql.Rows) (*models.WorkCalendar, error) {
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
		return nil, err
	}
	cal.WorkingDays = workingDays
	if len(holidaysJSON) > 0 {
		if err := json.Unmarshal(holidaysJSON, &cal.Holidays); err != nil {
			return nil, fmt.Errorf("unmarshal holidays: %w", err)
		}
	}
	return &cal, nil
}

func (r *scheduleRepository) scanScheduleTemplate(row *sql.Row) (*models.ScheduleTemplate, error) {
	var tmpl models.ScheduleTemplate
	var rulesJSON []byte
	err := row.Scan(
		&tmpl.ScheduleTemplateID,
		&tmpl.CompanyID,
		&tmpl.CalendarID,
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
	if len(rulesJSON) > 0 {
		if err := json.Unmarshal(rulesJSON, &tmpl.Rules); err != nil {
			return nil, fmt.Errorf("unmarshal rules: %w", err)
		}
	}
	return &tmpl, nil
}

func (r *scheduleRepository) scanScheduleTemplateFromRows(rows *sql.Rows) (*models.ScheduleTemplate, error) {
	var tmpl models.ScheduleTemplate
	var rulesJSON []byte
	err := rows.Scan(
		&tmpl.ScheduleTemplateID,
		&tmpl.CompanyID,
		&tmpl.CalendarID,
		&tmpl.TemplateType,
		&tmpl.Name,
		&rulesJSON,
		&tmpl.IsActive,
		&tmpl.CreatedAt,
	)
	if err != nil {
		return nil, err
	}
	if len(rulesJSON) > 0 {
		if err := json.Unmarshal(rulesJSON, &tmpl.Rules); err != nil {
			return nil, fmt.Errorf("unmarshal rules: %w", err)
		}
	}
	return &tmpl, nil
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
	var workCenterCode sql.NullString
	var cancelReason sql.NullString
	var cancelledAt sql.NullTime
	err := row.Scan(
		&inst.ScheduleInstanceID,
		&inst.CompanyID,
		&inst.UserID,
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
		if err := json.Unmarshal(metadataJSON, &inst.Metadata); err != nil {
			return nil, fmt.Errorf("unmarshal metadata: %w", err)
		}
	}
	return &inst, nil
}

func (r *scheduleRepository) scanScheduleInstanceFromRows(rows *sql.Rows) (*models.ScheduleInstance, error) {
	var inst models.ScheduleInstance
	var metadataJSON []byte
	var expectedStart, expectedEnd sql.NullTime
	var workCenterCode sql.NullString
	var cancelReason sql.NullString
	var cancelledAt sql.NullTime
	err := rows.Scan(
		&inst.ScheduleInstanceID,
		&inst.CompanyID,
		&inst.UserID,
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
		return nil, err
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
		if err := json.Unmarshal(metadataJSON, &inst.Metadata); err != nil {
			return nil, fmt.Errorf("unmarshal metadata: %w", err)
		}
	}
	return &inst, nil
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
// NEW METHODS (to be added to scheduleRepository)
// ============================================================

// ── Work Calendars CRUD ──

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
			calendar_id, company_id, year, name, timezone, working_days, holidays, is_active, created_at
		) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)
	`
	_, err := r.client.Exec(ctx, query,
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
	return err
}

func (r *scheduleRepository) GetWorkCalendarByID(ctx context.Context, calendarID uuid.UUID) (*models.WorkCalendar, error) {
	query := `
		SELECT calendar_id, company_id, year, name, timezone, working_days, holidays, is_active, created_at
		FROM attendance.work_calendars
		WHERE calendar_id = $1
	`
	row := r.client.QueryRow(ctx, query, calendarID)
	return r.scanWorkCalendar(row)
}

func (r *scheduleRepository) UpdateWorkCalendar(ctx context.Context, calendar *models.WorkCalendar) error {
	holidaysJSON, _ := json.Marshal(calendar.Holidays)
	query := `
		UPDATE attendance.work_calendars
		SET name = $1, timezone = $2, working_days = $3, holidays = $4, is_active = $5
		WHERE calendar_id = $6
	`
	_, err := r.client.Exec(ctx, query,
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
	query := `DELETE FROM attendance.work_calendars WHERE calendar_id = $1`
	_, err := r.client.Exec(ctx, query, calendarID)
	return err
}

// ── Schedule Templates CRUD ──

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
			schedule_template_id, company_id, calendar_id, template_type, name, rules, is_active, created_at
		) VALUES ($1, $2, $3, $4, $5, $6, $7, $8)
	`
	_, err := r.client.Exec(ctx, query,
		template.ScheduleTemplateID,
		template.CompanyID,
		template.CalendarID,
		template.TemplateType,
		template.Name,
		rulesJSON,
		template.IsActive,
		template.CreatedAt,
	)
	return err
}

func (r *scheduleRepository) GetScheduleTemplatesByCalendar(ctx context.Context, calendarID uuid.UUID) ([]*models.ScheduleTemplate, error) {
	query := `
		SELECT schedule_template_id, company_id, calendar_id, template_type, name, rules, is_active, created_at
		FROM attendance.schedule_templates
		WHERE calendar_id = $1
		ORDER BY name
	`
	rows, err := r.client.Query(ctx, query, calendarID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var templates []*models.ScheduleTemplate
	for rows.Next() {
		tmpl, err := r.scanScheduleTemplateFromRows(rows)
		if err != nil {
			return nil, err
		}
		templates = append(templates, tmpl)
	}
	return templates, nil
}

func (r *scheduleRepository) UpdateScheduleTemplate(ctx context.Context, template *models.ScheduleTemplate) error {
	rulesJSON, _ := json.Marshal(template.Rules)
	query := `
		UPDATE attendance.schedule_templates
		SET name = $1, calendar_id = $2, template_type = $3, rules = $4, is_active = $5
		WHERE schedule_template_id = $6
	`
	_, err := r.client.Exec(ctx, query,
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
	query := `DELETE FROM attendance.schedule_templates WHERE schedule_template_id = $1`
	_, err := r.client.Exec(ctx, query, templateID)
	return err
}

// ── Schedule Instances extended ──

func (r *scheduleRepository) GetScheduleInstancesByUser(ctx context.Context, userID uuid.UUID, startDate, endDate time.Time) ([]*models.ScheduleInstance, error) {
	query := `
		SELECT schedule_instance_id, company_id, user_id, schedule_date, schedule_template_id,
		       expected_start, expected_end, timezone, metadata, work_center_code,
		       generated_at, status, cancel_reason, cancelled_at
		FROM attendance.schedule_instances
		WHERE user_id = $1 AND schedule_date BETWEEN $2 AND $3
		ORDER BY schedule_date, expected_start
	`
	rows, err := r.client.Query(ctx, query, userID, startDate, endDate)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var instances []*models.ScheduleInstance
	for rows.Next() {
		inst, err := r.scanScheduleInstanceFromRows(rows)
		if err != nil {
			return nil, err
		}
		instances = append(instances, inst)
	}
	return instances, nil
}

func (r *scheduleRepository) GetScheduleInstancesByCompany(ctx context.Context, companyID uuid.UUID, startDate, endDate time.Time) ([]*models.ScheduleInstance, error) {
	query := `
		SELECT schedule_instance_id, company_id, user_id, schedule_date, schedule_template_id,
		       expected_start, expected_end, timezone, metadata, work_center_code,
		       generated_at, status, cancel_reason, cancelled_at
		FROM attendance.schedule_instances
		WHERE company_id = $1 AND schedule_date BETWEEN $2 AND $3
		ORDER BY schedule_date, user_id
	`
	rows, err := r.client.Query(ctx, query, companyID, startDate, endDate)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var instances []*models.ScheduleInstance
	for rows.Next() {
		inst, err := r.scanScheduleInstanceFromRows(rows)
		if err != nil {
			return nil, err
		}
		instances = append(instances, inst)
	}
	return instances, nil
}

func (r *scheduleRepository) GetScheduleInstancesByTemplate(ctx context.Context, templateID uuid.UUID, startDate, endDate time.Time) ([]*models.ScheduleInstance, error) {
	query := `
		SELECT schedule_instance_id, company_id, user_id, schedule_date, schedule_template_id,
		       expected_start, expected_end, timezone, metadata, work_center_code,
		       generated_at, status, cancel_reason, cancelled_at
		FROM attendance.schedule_instances
		WHERE schedule_template_id = $1 AND schedule_date BETWEEN $2 AND $3
		ORDER BY schedule_date, user_id
	`
	rows, err := r.client.Query(ctx, query, templateID, startDate, endDate)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var instances []*models.ScheduleInstance
	for rows.Next() {
		inst, err := r.scanScheduleInstanceFromRows(rows)
		if err != nil {
			return nil, err
		}
		instances = append(instances, inst)
	}
	return instances, nil
}

func (r *scheduleRepository) GetScheduleInstancesByWorkCenter(ctx context.Context, companyID uuid.UUID, workCenterCode string, startDate, endDate time.Time) ([]*models.ScheduleInstance, error) {
	query := `
		SELECT schedule_instance_id, company_id, user_id, schedule_date, schedule_template_id,
		       expected_start, expected_end, timezone, metadata, work_center_code,
		       generated_at, status, cancel_reason, cancelled_at
		FROM attendance.schedule_instances
		WHERE company_id = $1 AND work_center_code = $2 AND schedule_date BETWEEN $3 AND $4
		ORDER BY schedule_date, user_id
	`
	rows, err := r.client.Query(ctx, query, companyID, workCenterCode, startDate, endDate)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var instances []*models.ScheduleInstance
	for rows.Next() {
		inst, err := r.scanScheduleInstanceFromRows(rows)
		if err != nil {
			return nil, err
		}
		instances = append(instances, inst)
	}
	return instances, nil
}

func (r *scheduleRepository) UpdateScheduleInstance(ctx context.Context, instance *models.ScheduleInstance) error {
	metadataJSON, _ := json.Marshal(instance.Metadata)
	query := `
		UPDATE attendance.schedule_instances
		SET expected_start = $1, expected_end = $2, timezone = $3, metadata = $4,
		    status = $5, cancel_reason = $6, cancelled_at = $7
		WHERE schedule_instance_id = $8
	`
	_, err := r.client.Exec(ctx, query,
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
	query := `DELETE FROM attendance.schedule_instances WHERE schedule_instance_id = $1`
	_, err := r.client.Exec(ctx, query, instanceID)
	return err
}

func (r *scheduleRepository) CancelScheduleInstance(ctx context.Context, instanceID uuid.UUID, reason string) error {
	query := `
		UPDATE attendance.schedule_instances
		SET status = 'cancelled', cancel_reason = $1, cancelled_at = NOW()
		WHERE schedule_instance_id = $2
	`
	_, err := r.client.Exec(ctx, query, reason, instanceID)
	return err
}

func (r *scheduleRepository) HasActiveSchedule(ctx context.Context, companyID, userID uuid.UUID, date time.Time) (bool, error) {
	var exists bool
	query := `
		SELECT EXISTS (
			SELECT 1 FROM attendance.schedule_instances
			WHERE company_id = $1 AND user_id = $2 AND schedule_date = $3 AND status = 'active'
		)
	`
	err := r.client.QueryRow(ctx, query, companyID, userID, date).Scan(&exists)
	return exists, err
}

// ── Schedule Overrides CRUD ──

func (r *scheduleRepository) CreateScheduleOverride(ctx context.Context, override *models.ScheduleOverride) error {
	if override.OverrideID == uuid.Nil {
		override.OverrideID = uuid.New()
	}
	if override.CreatedAt.IsZero() {
		override.CreatedAt = time.Now().UTC()
	}
	query := `
		INSERT INTO attendance.schedule_overrides (
			override_id, company_id, user_id, override_date, override_type, reason, created_by, created_at
		) VALUES ($1, $2, $3, $4, $5, $6, $7, $8)
	`
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
		SELECT override_id, company_id, user_id, override_date, override_type, reason, created_by, created_at
		FROM attendance.schedule_overrides
		WHERE override_id = $1
	`
	row := r.client.QueryRow(ctx, query, overrideID)
	return r.scanScheduleOverride(row)
}

func (r *scheduleRepository) GetScheduleOverridesByUser(ctx context.Context, userID uuid.UUID, startDate, endDate *time.Time, overrideType *string) ([]*models.ScheduleOverride, error) {
	query := `
		SELECT override_id, company_id, user_id, override_date, override_type, reason, created_by, created_at
		FROM attendance.schedule_overrides
		WHERE user_id = $1
	`
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
		SELECT override_id, company_id, user_id, override_date, override_type, reason, created_by, created_at
		FROM attendance.schedule_overrides
		WHERE company_id = $1
	`
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
		SELECT override_id, company_id, user_id, override_date, override_type, reason, created_by, created_at
		FROM attendance.schedule_overrides
		WHERE user_id = $1 AND override_date = $2
	`
	row := r.client.QueryRow(ctx, query, userID, date)
	return r.scanScheduleOverride(row)
}

func (r *scheduleRepository) UpdateScheduleOverride(ctx context.Context, override *models.ScheduleOverride) error {
	query := `
		UPDATE attendance.schedule_overrides
		SET override_type = $1, reason = $2
		WHERE override_id = $3
	`
	_, err := r.client.Exec(ctx, query,
		override.OverrideType,
		override.Reason,
		override.OverrideID,
	)
	return err
}

func (r *scheduleRepository) DeleteScheduleOverride(ctx context.Context, overrideID uuid.UUID) error {
	query := `DELETE FROM attendance.schedule_overrides WHERE override_id = $1`
	_, err := r.client.Exec(ctx, query, overrideID)
	return err
}

func (r *scheduleRepository) DeleteScheduleOverridesByReason(ctx context.Context, companyID, userID uuid.UUID, reason string) error {
	query := `
		DELETE FROM attendance.schedule_overrides
		WHERE company_id = $1 AND user_id = $2 AND reason = $3
	`
	_, err := r.client.Exec(ctx, query, companyID, userID, reason)
	return err
}

// ── Work Center Shift Mappings ──

func (r *scheduleRepository) CreateWorkCenterShiftMapping(ctx context.Context, mapping *models.WorkCenterShift) error {
	if mapping.MappingID == uuid.Nil {
		mapping.MappingID = uuid.New()
	}
	if mapping.CreatedAt.IsZero() {
		mapping.CreatedAt = time.Now().UTC()
	}
	query := `
		INSERT INTO attendance.work_center_shifts (
			mapping_id, company_id, work_center_code, shift_id, effective_from, effective_to, is_active, created_at, updated_at
		) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)
	`
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

// GetWorkCenterShiftByCode – FIXED with date casting for production reliability.
func (r *scheduleRepository) GetWorkCenterShiftByCode(ctx context.Context, companyID uuid.UUID, workCenterCode string, date time.Time) (*models.WorkCenterShift, error) {
	r.logger.Info("GetWorkCenterShiftByCode",
		zap.String("company_id", companyID.String()),
		zap.String("work_center_code", workCenterCode),
		zap.Time("date", date),
	)
	query := `
		SELECT mapping_id, company_id, work_center_code, shift_id, effective_from, effective_to, is_active, created_at, updated_at
		FROM attendance.work_center_shifts
		WHERE company_id = $1 AND work_center_code = $2
		  AND effective_from::date <= $3::date
		  AND (effective_to IS NULL OR effective_to::date >= $3::date)
		  AND is_active = true
		ORDER BY effective_from DESC
		LIMIT 1
	`
	row := r.client.QueryRow(ctx, query, companyID, workCenterCode, date)
	mapping, err := r.scanWorkCenterShiftMapping(row)
	if err != nil {
		return nil, err
	}
	if mapping == nil {
		r.logger.Info("No work center shift mapping found (date-casted)",
			zap.String("work_center", workCenterCode),
			zap.String("date", date.Format("2006-01-02")),
		)
	} else {
		r.logger.Info("Work center shift mapping found (date-casted)",
			zap.String("work_center", workCenterCode),
			zap.String("shift_id", mapping.ShiftID.String()),
			zap.Time("effective_from", mapping.EffectiveFrom),
		)
	}
	return mapping, nil
}

func (r *scheduleRepository) GetWorkCenterShiftMappingsByShift(ctx context.Context, shiftID uuid.UUID) ([]*models.WorkCenterShift, error) {
	query := `
		SELECT mapping_id, company_id, work_center_code, shift_id, effective_from, effective_to, is_active, created_at, updated_at
		FROM attendance.work_center_shifts
		WHERE shift_id = $1
		ORDER BY effective_from DESC
	`
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
		WHERE mapping_id = $5
	`
	_, err := r.client.Exec(ctx, query,
		mapping.ShiftID,
		mapping.EffectiveTo,
		mapping.IsActive,
		mapping.UpdatedAt,
		mapping.MappingID,
	)
	return err
}

// Helper scan functions for the new types

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

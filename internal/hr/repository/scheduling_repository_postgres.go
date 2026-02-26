package repository

import (
	"auth-service/internal/client"
	"auth-service/internal/hr/models/scheduling"
	"auth-service/internal/hr/models/workcenter"
	"auth-service/internal/util"
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"sync"
	"time"

	"github.com/google/uuid"
	"github.com/lib/pq"
	"go.uber.org/zap"
)

type SchedulingRepositoryImpl struct {
	client    *client.PostgresClient
	logger    *zap.Logger
	stmtCache map[string]*sql.Stmt
	stmtMutex sync.RWMutex
}

func NewSchedulingRepository(postgresClient *client.PostgresClient, logger *zap.Logger) SchedulingRepository {
	repo := &SchedulingRepositoryImpl{
		client:    postgresClient,
		logger:    logger,
		stmtCache: make(map[string]*sql.Stmt),
	}
	go repo.initializePreparedStatements(context.Background())
	return repo
}

func (r *SchedulingRepositoryImpl) CreateWorkCalendar(
	ctx context.Context,
	calendar *scheduling.WorkCalendar,
) error {
	startTime := time.Now()
	holidaysJSON, err := json.Marshal(calendar.Holidays)
	if err != nil {
		return fmt.Errorf("failed to marshal holidays: %w", err)
	}
	query := `
		INSERT INTO work_calendars (
			calendar_id,
			company_id,
			year,
			name,
			timezone,
			working_days,
			holidays,
			is_active,
			created_at
		) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9)
	`
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
		r.logger.Error("Failed to create work calendar",
			util.String("company_id", calendar.CompanyID.String()),
			util.Int("year", calendar.Year),
			util.ErrorField(err),
		)
		return fmt.Errorf("failed to create work calendar: %w", err)
	}
	r.logger.Debug("Work calendar created",
		util.String("calendar_id", calendar.CalendarID.String()),
		util.Duration("duration", time.Since(startTime)),
	)
	return nil
}

func (r *SchedulingRepositoryImpl) GetWorkCalendarByID(
	ctx context.Context,
	calendarID uuid.UUID,
) (*scheduling.WorkCalendar, error) {
	stmt, ok := r.getStmt("get_work_calendar_by_id")
	if !ok {
		query := `
			SELECT
				calendar_id,
				company_id,
				year,
				name,
				timezone,
				working_days,
				holidays,
				is_active,
				created_at
			FROM work_calendars
			WHERE calendar_id = $1
		`
		rows, err := r.client.Query(ctx, query, calendarID)
		if err != nil {
			return nil, fmt.Errorf("failed to get work calendar: %w", err)
		}
		defer rows.Close()
		if rows.Next() {
			return r.scanWorkCalendar(rows)
		}
		return nil, fmt.Errorf("work calendar not found: %s", calendarID)
	}
	rows, err := stmt.QueryContext(ctx, calendarID)
	if err != nil {
		return nil, fmt.Errorf("failed to get work calendar: %w", err)
	}
	defer rows.Close()
	if rows.Next() {
		return r.scanWorkCalendar(rows)
	}
	return nil, fmt.Errorf("work calendar not found: %s", calendarID)
}

func (r *SchedulingRepositoryImpl) GetWorkCalendarsByCompany(
	ctx context.Context,
	companyID uuid.UUID,
) ([]*scheduling.WorkCalendar, error) {
	query := `
		SELECT
			calendar_id,
			company_id,
			year,
			name,
			timezone,
			working_days,
			holidays,
			is_active,
			created_at
		FROM work_calendars
		WHERE company_id = $1
		ORDER BY year DESC
	`
	rows, err := r.client.Query(ctx, query, companyID)
	if err != nil {
		return nil, fmt.Errorf("failed to get work calendars: %w", err)
	}
	defer rows.Close()
	calendars := make([]*scheduling.WorkCalendar, 0)
	for rows.Next() {
		calendar, err := r.scanWorkCalendar(rows)
		if err != nil {
			r.logger.Warn("Failed to scan work calendar", util.ErrorField(err))
			continue
		}
		calendars = append(calendars, calendar)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("error iterating work calendars: %w", err)
	}
	return calendars, nil
}

func (r *SchedulingRepositoryImpl) DeleteWorkCalendar(ctx context.Context, calendarID uuid.UUID) error {
	query := `DELETE FROM work_calendars WHERE calendar_id = $1`
	result, err := r.client.Exec(ctx, query, calendarID)
	if err != nil {
		return fmt.Errorf("failed to delete work calendar: %w", err)
	}
	rowsAffected, _ := result.RowsAffected()
	if rowsAffected == 0 {
		return fmt.Errorf("work calendar not found: %s", calendarID)
	}
	return nil
}

func (r *SchedulingRepositoryImpl) CreateScheduleTemplate(ctx context.Context, template *scheduling.ScheduleTemplate) error {
	startTime := time.Now()
	rulesJSON, err := json.Marshal(template.Rules)
	if err != nil {
		return fmt.Errorf("failed to marshal template rules: %w", err)
	}
	query := `
		INSERT INTO schedule_templates (
			schedule_template_id, company_id, calendar_id, template_type, name,
			rules, is_active, created_at
		) VALUES ($1, $2, $3, $4, $5, $6, $7, $8)`
	_, err = r.client.Exec(ctx, query,
		template.ScheduleTemplateID,
		template.CompanyID,
		template.CalendarID,
		template.TemplateType,
		template.Name,
		rulesJSON,
		template.IsActive,
		template.CreatedAt,
	)
	if err != nil {
		r.logger.Error("Failed to create schedule template",
			util.String("company_id", template.CompanyID.String()),
			util.String("name", template.Name),
			util.ErrorField(err))
		return fmt.Errorf("failed to create schedule template: %w", err)
	}
	r.logger.Debug("Schedule template created",
		util.String("template_id", template.ScheduleTemplateID.String()),
		util.Duration("duration", time.Since(startTime)))
	return nil
}

func (r *SchedulingRepositoryImpl) GetScheduleTemplateByID(ctx context.Context, templateID uuid.UUID) (*scheduling.ScheduleTemplate, error) {
	stmt, ok := r.getStmt("get_schedule_template_by_id")
	if !ok {
		query := `
			SELECT schedule_template_id, company_id, calendar_id, template_type, name,
				   rules, is_active, created_at
			FROM schedule_templates WHERE schedule_template_id = $1`
		rows, err := r.client.Query(ctx, query, templateID)
		if err != nil {
			return nil, fmt.Errorf("failed to get schedule template: %w", err)
		}
		defer rows.Close()
		if rows.Next() {
			return r.scanScheduleTemplate(rows)
		}
		return nil, fmt.Errorf("schedule template not found: %s", templateID)
	}
	rows, err := stmt.QueryContext(ctx, templateID)
	if err != nil {
		return nil, fmt.Errorf("failed to get schedule template: %w", err)
	}
	defer rows.Close()
	if rows.Next() {
		return r.scanScheduleTemplate(rows)
	}
	return nil, fmt.Errorf("schedule template not found: %s", templateID)
}

func (r *SchedulingRepositoryImpl) GetScheduleTemplatesByCompany(ctx context.Context, companyID uuid.UUID) ([]*scheduling.ScheduleTemplate, error) {
	query := `
		SELECT schedule_template_id, company_id, calendar_id, template_type, name,
		       rules, is_active, created_at
		FROM schedule_templates
		WHERE company_id = $1
		ORDER BY name`
	rows, err := r.client.Query(ctx, query, companyID)
	if err != nil {
		return nil, fmt.Errorf("failed to get schedule templates: %w", err)
	}
	defer rows.Close()
	templates := make([]*scheduling.ScheduleTemplate, 0)
	for rows.Next() {
		template, err := r.scanScheduleTemplate(rows)
		if err != nil {
			r.logger.Warn("Failed to scan schedule template", util.ErrorField(err))
			continue
		}
		templates = append(templates, template)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("error iterating schedule templates: %w", err)
	}
	return templates, nil
}

func (r *SchedulingRepositoryImpl) GetScheduleTemplatesByCalendar(ctx context.Context, calendarID uuid.UUID) ([]*scheduling.ScheduleTemplate, error) {
	query := `
		SELECT schedule_template_id, company_id, calendar_id, template_type, name,
		       rules, is_active, created_at
		FROM schedule_templates
		WHERE calendar_id = $1 AND is_active = true
		ORDER BY name`
	rows, err := r.client.Query(ctx, query, calendarID)
	if err != nil {
		return nil, fmt.Errorf("failed to get schedule templates by calendar: %w", err)
	}
	defer rows.Close()
	templates := make([]*scheduling.ScheduleTemplate, 0)
	for rows.Next() {
		template, err := r.scanScheduleTemplate(rows)
		if err != nil {
			r.logger.Warn("Failed to scan schedule template", util.ErrorField(err))
			continue
		}
		templates = append(templates, template)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("error iterating schedule templates: %w", err)
	}
	return templates, nil
}

func (r *SchedulingRepositoryImpl) GetActiveTemplatesByType(ctx context.Context, companyID uuid.UUID, templateType string) ([]*scheduling.ScheduleTemplate, error) {
	query := `
		SELECT schedule_template_id, company_id, calendar_id, template_type, name,
		       rules, is_active, created_at
		FROM schedule_templates
		WHERE company_id = $1 AND template_type = $2 AND is_active = true
		ORDER BY name`
	rows, err := r.client.Query(ctx, query, companyID, templateType)
	if err != nil {
		return nil, fmt.Errorf("failed to get active templates by type: %w", err)
	}
	defer rows.Close()
	templates := make([]*scheduling.ScheduleTemplate, 0)
	for rows.Next() {
		template, err := r.scanScheduleTemplate(rows)
		if err != nil {
			r.logger.Warn("Failed to scan schedule template", util.ErrorField(err))
			continue
		}
		templates = append(templates, template)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("error iterating schedule templates: %w", err)
	}
	return templates, nil
}

func (r *SchedulingRepositoryImpl) UpdateScheduleTemplate(ctx context.Context, template *scheduling.ScheduleTemplate) error {
	rulesJSON, err := json.Marshal(template.Rules)
	if err != nil {
		return fmt.Errorf("failed to marshal template rules: %w", err)
	}
	query := `
		UPDATE schedule_templates SET
			name = $1, calendar_id = $2, template_type = $3, rules = $4,
			is_active = $5
		WHERE schedule_template_id = $6`
	result, err := r.client.Exec(ctx, query,
		template.Name,
		template.CalendarID,
		template.TemplateType,
		rulesJSON,
		template.IsActive,
		template.ScheduleTemplateID,
	)
	if err != nil {
		return fmt.Errorf("failed to update schedule template: %w", err)
	}
	rowsAffected, _ := result.RowsAffected()
	if rowsAffected == 0 {
		return fmt.Errorf("schedule template not found: %s", template.ScheduleTemplateID)
	}
	return nil
}

func (r *SchedulingRepositoryImpl) DeleteScheduleTemplate(ctx context.Context, templateID uuid.UUID) error {
	query := `DELETE FROM schedule_templates WHERE schedule_template_id = $1`
	result, err := r.client.Exec(ctx, query, templateID)
	if err != nil {
		return fmt.Errorf("failed to delete schedule template: %w", err)
	}
	rowsAffected, _ := result.RowsAffected()
	if rowsAffected == 0 {
		return fmt.Errorf("schedule template not found: %s", templateID)
	}
	return nil
}

func (r *SchedulingRepositoryImpl) CreateUserScheduleAssignment(ctx context.Context, assignment *scheduling.UserScheduleAssignment) error {
	query := `
		INSERT INTO user_schedule_assignments (
			user_id, schedule_template_id, effective_from, effective_to,
			assigned_by, created_at
		) VALUES ($1, $2, $3, $4, $5, $6)`
	_, err := r.client.Exec(ctx, query,
		assignment.UserID,
		assignment.ScheduleTemplateID,
		assignment.EffectiveFrom,
		assignment.EffectiveTo,
		assignment.AssignedBy,
		assignment.CreatedAt,
	)
	if err != nil {
		r.logger.Error("Failed to create user schedule assignment",
			util.String("user_id", assignment.UserID.String()),
			util.String("template_id", assignment.ScheduleTemplateID.String()),
			util.ErrorField(err))
		return fmt.Errorf("failed to create user schedule assignment: %w", err)
	}
	return nil
}

func (r *SchedulingRepositoryImpl) GetUserScheduleAssignment(ctx context.Context, userID, templateID uuid.UUID, effectiveFrom time.Time) (*scheduling.UserScheduleAssignment, error) {
	query := `
		SELECT user_id, schedule_template_id, effective_from, effective_to,
		       assigned_by, created_at
		FROM user_schedule_assignments
		WHERE user_id = $1 AND schedule_template_id = $2 AND effective_from = $3`
	rows, err := r.client.Query(ctx, query, userID, templateID, effectiveFrom)
	if err != nil {
		return nil, fmt.Errorf("failed to get user schedule assignment: %w", err)
	}
	defer rows.Close()
	if rows.Next() {
		return r.scanUserScheduleAssignment(rows)
	}
	return nil, fmt.Errorf("user schedule assignment not found")
}

func (r *SchedulingRepositoryImpl) GetUserCurrentScheduleAssignment(ctx context.Context, userID uuid.UUID, date time.Time) (*scheduling.UserScheduleAssignment, error) {
	stmt, ok := r.getStmt("get_user_current_schedule_assignment")
	if !ok {
		query := `
			SELECT user_id, schedule_template_id, effective_from, effective_to,
				   assigned_by, created_at
			FROM user_schedule_assignments
			WHERE user_id = $1
			  AND effective_from <= $2
			  AND (effective_to IS NULL OR effective_to >= $2)
			ORDER BY effective_from DESC
			LIMIT 1`
		rows, err := r.client.Query(ctx, query, userID, date)
		if err != nil {
			return nil, fmt.Errorf("failed to get current schedule assignment: %w", err)
		}
		defer rows.Close()
		if rows.Next() {
			return r.scanUserScheduleAssignment(rows)
		}
		return nil, fmt.Errorf("no active schedule assignment found for user: %s", userID)
	}
	rows, err := stmt.QueryContext(ctx, userID, date)
	if err != nil {
		return nil, fmt.Errorf("failed to get current schedule assignment: %w", err)
	}
	defer rows.Close()
	if rows.Next() {
		return r.scanUserScheduleAssignment(rows)
	}
	return nil, fmt.Errorf("no active schedule assignment found for user: %s", userID)
}

func (r *SchedulingRepositoryImpl) GetUserScheduleAssignments(ctx context.Context, userID uuid.UUID, startDate, endDate *time.Time) ([]*scheduling.UserScheduleAssignment, error) {
	var query string
	var args []interface{}
	args = append(args, userID)
	if startDate != nil && endDate != nil {
		query = `
			SELECT user_id, schedule_template_id, effective_from, effective_to,
			       assigned_by, created_at
			FROM user_schedule_assignments
			WHERE user_id = $1
			  AND ((effective_from BETWEEN $2 AND $3)
			    OR (effective_to BETWEEN $2 AND $3)
			    OR (effective_from <= $2 AND (effective_to IS NULL OR effective_to >= $3)))
			ORDER BY effective_from DESC`
		args = append(args, startDate, endDate)
	} else {
		query = `
			SELECT user_id, schedule_template_id, effective_from, effective_to,
			       assigned_by, created_at
			FROM user_schedule_assignments
			WHERE user_id = $1
			ORDER BY effective_from DESC`
	}
	rows, err := r.client.Query(ctx, query, args...)
	if err != nil {
		return nil, fmt.Errorf("failed to get user schedule assignments: %w", err)
	}
	defer rows.Close()
	assignments := make([]*scheduling.UserScheduleAssignment, 0)
	for rows.Next() {
		assignment, err := r.scanUserScheduleAssignment(rows)
		if err != nil {
			r.logger.Warn("Failed to scan schedule assignment", util.ErrorField(err))
			continue
		}
		assignments = append(assignments, assignment)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("error iterating schedule assignments: %w", err)
	}
	return assignments, nil
}

func (r *SchedulingRepositoryImpl) GetAssignmentsByTemplate(ctx context.Context, templateID uuid.UUID, activeOnly bool) ([]*scheduling.UserScheduleAssignment, error) {
	var query string
	if activeOnly {
		query = `
			SELECT user_id, schedule_template_id, effective_from, effective_to,
			       assigned_by, created_at
			FROM user_schedule_assignments
			WHERE schedule_template_id = $1
			  AND (effective_to IS NULL OR effective_to >= CURRENT_DATE)
			ORDER BY effective_from DESC`
	} else {
		query = `
			SELECT user_id, schedule_template_id, effective_from, effective_to,
			       assigned_by, created_at
			FROM user_schedule_assignments
			WHERE schedule_template_id = $1
			ORDER BY effective_from DESC`
	}
	rows, err := r.client.Query(ctx, query, templateID)
	if err != nil {
		return nil, fmt.Errorf("failed to get assignments by template: %w", err)
	}
	defer rows.Close()
	assignments := make([]*scheduling.UserScheduleAssignment, 0)
	for rows.Next() {
		assignment, err := r.scanUserScheduleAssignment(rows)
		if err != nil {
			r.logger.Warn("Failed to scan schedule assignment", util.ErrorField(err))
			continue
		}
		assignments = append(assignments, assignment)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("error iterating schedule assignments: %w", err)
	}
	return assignments, nil
}

func (r *SchedulingRepositoryImpl) UpdateUserScheduleAssignment(ctx context.Context, assignment *scheduling.UserScheduleAssignment) error {
	query := `
		UPDATE user_schedule_assignments SET
			effective_to = $1, assigned_by = $2
		WHERE user_id = $3 AND schedule_template_id = $4 AND effective_from = $5`
	result, err := r.client.Exec(ctx, query,
		assignment.EffectiveTo,
		assignment.AssignedBy,
		assignment.UserID,
		assignment.ScheduleTemplateID,
		assignment.EffectiveFrom,
	)
	if err != nil {
		return fmt.Errorf("failed to update user schedule assignment: %w", err)
	}
	rowsAffected, _ := result.RowsAffected()
	if rowsAffected == 0 {
		return fmt.Errorf("user schedule assignment not found")
	}
	return nil
}

func (r *SchedulingRepositoryImpl) EndUserScheduleAssignment(ctx context.Context, userID, templateID uuid.UUID, endDate time.Time) error {
	query := `
		UPDATE user_schedule_assignments
		SET effective_to = $1
		WHERE user_id = $2 AND schedule_template_id = $3 AND effective_to IS NULL`
	result, err := r.client.Exec(ctx, query, endDate, userID, templateID)
	if err != nil {
		return fmt.Errorf("failed to end user schedule assignment: %w", err)
	}
	rowsAffected, _ := result.RowsAffected()
	if rowsAffected == 0 {
		return fmt.Errorf("no active schedule assignment found")
	}
	return nil
}

func (r *SchedulingRepositoryImpl) DeleteUserScheduleAssignment(ctx context.Context, userID, templateID uuid.UUID, effectiveFrom time.Time) error {
	query := `
		DELETE FROM user_schedule_assignments
		WHERE user_id = $1 AND schedule_template_id = $2 AND effective_from = $3`
	result, err := r.client.Exec(ctx, query, userID, templateID, effectiveFrom)
	if err != nil {
		return fmt.Errorf("failed to delete user schedule assignment: %w", err)
	}
	rowsAffected, _ := result.RowsAffected()
	if rowsAffected == 0 {
		return fmt.Errorf("user schedule assignment not found")
	}
	return nil
}

func (r *SchedulingRepositoryImpl) GetScheduleInstanceByID(ctx context.Context, instanceID uuid.UUID) (*scheduling.ScheduleInstance, error) {
	stmt, ok := r.getStmt("get_schedule_instance_by_id")
	if !ok {
		query := `
			SELECT schedule_instance_id, company_id, user_id, schedule_date,
				   schedule_template_id, expected_start, expected_end, timezone,
				   metadata, generated_at, status, cancel_reason, cancelled_at
			FROM schedule_instances WHERE schedule_instance_id = $1`
		rows, err := r.client.Query(ctx, query, instanceID)
		if err != nil {
			return nil, fmt.Errorf("failed to get schedule instance: %w", err)
		}
		defer rows.Close()
		if rows.Next() {
			return r.scanScheduleInstance(rows)
		}
		return nil, fmt.Errorf("schedule instance not found: %s", instanceID)
	}
	rows, err := stmt.QueryContext(ctx, instanceID)
	if err != nil {
		return nil, fmt.Errorf("failed to get schedule instance: %w", err)
	}
	defer rows.Close()
	if rows.Next() {
		return r.scanScheduleInstance(rows)
	}
	return nil, fmt.Errorf("schedule instance not found: %s", instanceID)
}

func (r *SchedulingRepositoryImpl) GetScheduleInstancesByUser(ctx context.Context, userID uuid.UUID, startDate, endDate time.Time) ([]*scheduling.ScheduleInstance, error) {
	query := `
		SELECT schedule_instance_id, company_id, user_id, schedule_date,
		       schedule_template_id, expected_start, expected_end, timezone,
		       metadata, generated_at, status, cancel_reason, cancelled_at
		FROM schedule_instances
		WHERE user_id = $1 AND schedule_date BETWEEN $2 AND $3 AND status = 'active'
		ORDER BY schedule_date`
	rows, err := r.client.Query(ctx, query, userID, startDate, endDate)
	if err != nil {
		return nil, fmt.Errorf("failed to get schedule instances by user: %w", err)
	}
	defer rows.Close()
	instances := make([]*scheduling.ScheduleInstance, 0)
	for rows.Next() {
		instance, err := r.scanScheduleInstance(rows)
		if err != nil {
			r.logger.Warn("Failed to scan schedule instance", util.ErrorField(err))
			continue
		}
		instances = append(instances, instance)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("error iterating schedule instances: %w", err)
	}
	return instances, nil
}

func (r *SchedulingRepositoryImpl) GetScheduleInstancesByCompany(ctx context.Context, companyID uuid.UUID, startDate, endDate time.Time) ([]*scheduling.ScheduleInstance, error) {
	query := `
		SELECT schedule_instance_id, company_id, user_id, schedule_date,
		       schedule_template_id, expected_start, expected_end, timezone,
		       metadata, generated_at, status, cancel_reason, cancelled_at
		FROM schedule_instances
		WHERE company_id = $1 AND schedule_date BETWEEN $2 AND $3 AND status = 'active'
		ORDER BY schedule_date, user_id`
	rows, err := r.client.Query(ctx, query, companyID, startDate, endDate)
	if err != nil {
		return nil, fmt.Errorf("failed to get schedule instances by company: %w", err)
	}
	defer rows.Close()
	instances := make([]*scheduling.ScheduleInstance, 0)
	for rows.Next() {
		instance, err := r.scanScheduleInstance(rows)
		if err != nil {
			r.logger.Warn("Failed to scan schedule instance", util.ErrorField(err))
			continue
		}
		instances = append(instances, instance)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("error iterating schedule instances: %w", err)
	}
	return instances, nil
}

func (r *SchedulingRepositoryImpl) GetScheduleInstancesByTemplate(ctx context.Context, templateID uuid.UUID, startDate, endDate time.Time) ([]*scheduling.ScheduleInstance, error) {
	query := `
		SELECT schedule_instance_id, company_id, user_id, schedule_date,
		       schedule_template_id, expected_start, expected_end, timezone,
		       metadata, generated_at, status, cancel_reason, cancelled_at
		FROM schedule_instances
		WHERE schedule_template_id = $1 AND schedule_date BETWEEN $2 AND $3 AND status = 'active'
		ORDER BY schedule_date, user_id`
	rows, err := r.client.Query(ctx, query, templateID, startDate, endDate)
	if err != nil {
		return nil, fmt.Errorf("failed to get schedule instances by template: %w", err)
	}
	defer rows.Close()
	instances := make([]*scheduling.ScheduleInstance, 0)
	for rows.Next() {
		instance, err := r.scanScheduleInstance(rows)
		if err != nil {
			r.logger.Warn("Failed to scan schedule instance", util.ErrorField(err))
			continue
		}
		instances = append(instances, instance)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("error iterating schedule instances: %w", err)
	}
	return instances, nil
}

func (r *SchedulingRepositoryImpl) UpdateScheduleInstance(ctx context.Context, instance *scheduling.ScheduleInstance) error {
	metadataJSON, err := json.Marshal(instance.Metadata)
	if err != nil {
		return fmt.Errorf("failed to marshal metadata: %w", err)
	}
	query := `
		UPDATE schedule_instances SET
			expected_start = $1, expected_end = $2, metadata = $3, timezone = $4
		WHERE schedule_instance_id = $5 AND status = 'active'`
	result, err := r.client.Exec(ctx, query,
		instance.ExpectedStart,
		instance.ExpectedEnd,
		metadataJSON,
		instance.Timezone,
		instance.ScheduleInstanceID,
	)
	if err != nil {
		return fmt.Errorf("failed to update schedule instance: %w", err)
	}
	rowsAffected, _ := result.RowsAffected()
	if rowsAffected == 0 {
		return fmt.Errorf("schedule instance not found or is cancelled: %s", instance.ScheduleInstanceID)
	}
	return nil
}

func (r *SchedulingRepositoryImpl) CancelScheduleInstance(
	ctx context.Context,
	instanceID uuid.UUID,
	reason string,
) error {
	query := `
		UPDATE schedule_instances
		SET status = 'cancelled',
		    cancel_reason = $2,
		    cancelled_at = NOW()
		WHERE schedule_instance_id = $1
		  AND status = 'active'
	`
	result, err := r.client.Exec(ctx, query, instanceID, reason)
	if err != nil {
		return fmt.Errorf("failed to cancel schedule instance: %w", err)
	}
	rowsAffected, _ := result.RowsAffected()
	if rowsAffected == 0 {
		return fmt.Errorf("schedule instance not found or already cancelled")
	}
	return nil
}

func (r *SchedulingRepositoryImpl) DeleteScheduleInstance(ctx context.Context, instanceID uuid.UUID) error {
	query := `DELETE FROM schedule_instances WHERE schedule_instance_id = $1`
	result, err := r.client.Exec(ctx, query, instanceID)
	if err != nil {
		return fmt.Errorf("failed to delete schedule instance: %w", err)
	}
	rowsAffected, _ := result.RowsAffected()
	if rowsAffected == 0 {
		return fmt.Errorf("schedule instance not found: %s", instanceID)
	}
	return nil
}

func (r *SchedulingRepositoryImpl) BulkCreateScheduleInstances(
	ctx context.Context,
	instances []*scheduling.ScheduleInstance,
) error {
	if len(instances) == 0 {
		return nil
	}

	tx, err := r.client.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("failed to begin transaction: %w", err)
	}
	defer tx.Rollback()

	query := `
		INSERT INTO schedule_instances (
			schedule_instance_id, company_id, user_id, schedule_date,
			schedule_template_id, expected_start, expected_end, timezone,
			metadata, generated_at, status, work_center_code
		) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, 'active', $11)
		ON CONFLICT (user_id, schedule_date)
		WHERE status = 'active'
		DO NOTHING
		RETURNING schedule_instance_id
	`

	stmt, err := tx.PrepareContext(ctx, query)
	if err != nil {
		return fmt.Errorf("failed to prepare batch statement: %w", err)
	}
	defer stmt.Close()

	createdCount := 0
	skippedCount := 0

	for _, instance := range instances {
		metadataJSON, err := json.Marshal(instance.Metadata)
		if err != nil {
			return fmt.Errorf(
				"failed to marshal metadata for instance %s: %w",
				instance.ScheduleInstanceID,
				err,
			)
		}

		var workCenterCode *string
		if instance.WorkCenterCode != nil && *instance.WorkCenterCode != "" {
			workCenterCode = instance.WorkCenterCode
		}

		var returnedID uuid.UUID
		err = stmt.QueryRowContext(ctx,
			instance.ScheduleInstanceID,
			instance.CompanyID,
			instance.UserID,
			instance.ScheduleDate,
			instance.ScheduleTemplateID,
			instance.ExpectedStart,
			instance.ExpectedEnd,
			instance.Timezone,
			metadataJSON,
			instance.GeneratedAt,
			workCenterCode,
		).Scan(&returnedID)

		// DO NOTHING → no row returned → skipped
		if err == sql.ErrNoRows {
			skippedCount++
			continue
		}

		if err != nil {
			return fmt.Errorf(
				"failed to insert schedule instance %s: %w",
				instance.ScheduleInstanceID,
				err,
			)
		}

		createdCount++
	}

	if err := tx.Commit(); err != nil {
		return fmt.Errorf("failed to commit batch transaction: %w", err)
	}

	r.logger.Info(
		"Batch schedule instances creation completed",
		util.Int("instances_created", createdCount),
		util.Int("instances_skipped", skippedCount),
	)

	return nil
}

func (r *SchedulingRepositoryImpl) GetScheduleCoverage(
	ctx context.Context,
	companyID uuid.UUID,
	startDate, endDate time.Time,
) (map[string]interface{}, error) {

	stats := make(map[string]interface{})

	// 1️⃣ Total scheduled days
	var totalScheduledDays int
	err := r.client.QueryRow(ctx, `
		SELECT COUNT(DISTINCT schedule_date)
		FROM schedule_instances
		WHERE company_id = $1
		  AND schedule_date BETWEEN $2 AND $3
		  AND status = 'active'
	`, companyID, startDate, endDate).Scan(&totalScheduledDays)
	if err != nil {
		return nil, fmt.Errorf("failed to get total scheduled days: %w", err)
	}
	stats["total_scheduled_days"] = totalScheduledDays

	// 2️⃣ Total scheduled users
	var totalScheduledUsers int
	err = r.client.QueryRow(ctx, `
		SELECT COUNT(DISTINCT user_id)
		FROM schedule_instances
		WHERE company_id = $1
		  AND schedule_date BETWEEN $2 AND $3
		  AND status = 'active'
	`, companyID, startDate, endDate).Scan(&totalScheduledUsers)
	if err != nil {
		return nil, fmt.Errorf("failed to get total scheduled users: %w", err)
	}
	stats["total_scheduled_users"] = totalScheduledUsers

	// 3️⃣ Template distribution
	templateRows, err := r.client.Query(ctx, `
		SELECT st.template_type, COUNT(si.schedule_instance_id)
		FROM schedule_instances si
		JOIN schedule_templates st
		  ON si.schedule_template_id = st.schedule_template_id
		WHERE si.company_id = $1
		  AND si.schedule_date BETWEEN $2 AND $3
		  AND si.status = 'active'
		GROUP BY st.template_type
	`, companyID, startDate, endDate)
	if err != nil {
		return nil, fmt.Errorf("failed to get template distribution: %w", err)
	}
	defer templateRows.Close()

	templateStats := make(map[string]int)
	for templateRows.Next() {
		var templateType string
		var count int
		if err := templateRows.Scan(&templateType, &count); err == nil {
			templateStats[templateType] = count
		}
	}
	stats["template_distribution"] = templateStats

	// 4️⃣ ✅ Work center distribution (FIXED – uses schedule_instances)
	wcRows, err := r.client.Query(ctx, `
		SELECT
			si.work_center_code,
			COUNT(DISTINCT si.user_id)
		FROM schedule_instances si
		WHERE si.company_id = $1
		  AND si.schedule_date BETWEEN $2 AND $3
		  AND si.status = 'active'
		  AND si.work_center_code IS NOT NULL
		GROUP BY si.work_center_code
	`, companyID, startDate, endDate)
	if err != nil {
		return nil, fmt.Errorf("failed to get work center distribution: %w", err)
	}
	defer wcRows.Close()

	workCenterStats := make(map[string]int)
	for wcRows.Next() {
		var workCenterCode string
		var count int
		if err := wcRows.Scan(&workCenterCode, &count); err == nil {
			workCenterStats[workCenterCode] = count
		}
	}
	stats["work_center_distribution"] = workCenterStats

	return stats, nil
}

func (r *SchedulingRepositoryImpl) GetUserScheduleSummary(ctx context.Context, userID uuid.UUID, startDate, endDate time.Time) (map[string]interface{}, error) {
	stats := make(map[string]interface{})
	var totalScheduledDays int
	err := r.client.QueryRow(ctx, `
		SELECT COUNT(*)
		FROM schedule_instances
		WHERE user_id = $1 AND schedule_date BETWEEN $2 AND $3 AND status = 'active'`,
		userID, startDate, endDate).Scan(&totalScheduledDays)
	if err != nil {
		return nil, fmt.Errorf("failed to get total scheduled days: %w", err)
	}
	stats["total_scheduled_days"] = totalScheduledDays
	currentAssignment, err := r.GetUserCurrentScheduleAssignment(ctx, userID, time.Now())
	if err == nil {
		stats["current_assignment"] = map[string]interface{}{
			"template_id":    currentAssignment.ScheduleTemplateID,
			"effective_from": currentAssignment.EffectiveFrom,
			"effective_to":   currentAssignment.EffectiveTo,
		}
	}
	query := `
		SELECT st.template_type, COUNT(*) as count
		FROM schedule_instances si
		JOIN schedule_templates st ON si.schedule_template_id = st.schedule_template_id
		WHERE si.user_id = $1 AND si.schedule_date BETWEEN $2 AND $3 AND si.status = 'active'
		GROUP BY st.template_type`
	rows, err := r.client.Query(ctx, query, userID, startDate, endDate)
	if err != nil {
		return nil, fmt.Errorf("failed to get schedule by template type: %w", err)
	}
	defer rows.Close()
	templateStats := make(map[string]int)
	for rows.Next() {
		var templateType string
		var count int
		if err := rows.Scan(&templateType, &count); err != nil {
			continue
		}
		templateStats[templateType] = count
	}
	stats["schedule_by_type"] = templateStats
	return stats, nil
}

func (r *SchedulingRepositoryImpl) GetTemplateUtilization(ctx context.Context, templateID uuid.UUID, startDate, endDate time.Time) (map[string]interface{}, error) {
	stats := make(map[string]interface{})
	template, err := r.GetScheduleTemplateByID(ctx, templateID)
	if err != nil {
		return nil, fmt.Errorf("failed to get template: %w", err)
	}
	stats["template"] = map[string]interface{}{
		"name":      template.Name,
		"type":      template.TemplateType,
		"is_active": template.IsActive,
	}
	var totalInstances int
	err = r.client.QueryRow(ctx, `
		SELECT COUNT(*)
		FROM schedule_instances
		WHERE schedule_template_id = $1 AND schedule_date BETWEEN $2 AND $3 AND status = 'active'`,
		templateID, startDate, endDate).Scan(&totalInstances)
	if err != nil {
		return nil, fmt.Errorf("failed to get total instances: %w", err)
	}
	stats["total_instances"] = totalInstances
	var uniqueUsers int
	err = r.client.QueryRow(ctx, `
		SELECT COUNT(DISTINCT user_id)
		FROM schedule_instances
		WHERE schedule_template_id = $1 AND schedule_date BETWEEN $2 AND $3 AND status = 'active'`,
		templateID, startDate, endDate).Scan(&uniqueUsers)
	if err != nil {
		return nil, fmt.Errorf("failed to get unique users: %w", err)
	}
	stats["unique_users"] = uniqueUsers
	query := `
		SELECT schedule_date, COUNT(*) as count
		FROM schedule_instances
		WHERE schedule_template_id = $1 AND schedule_date BETWEEN $2 AND $3 AND status = 'active'
		GROUP BY schedule_date
		ORDER BY schedule_date`
	rows, err := r.client.Query(ctx, query, templateID, startDate, endDate)
	if err != nil {
		return nil, fmt.Errorf("failed to get daily utilization: %w", err)
	}
	defer rows.Close()
	dailyStats := make([]map[string]interface{}, 0)
	for rows.Next() {
		var date time.Time
		var count int
		if err := rows.Scan(&date, &count); err != nil {
			continue
		}
		dailyStats = append(dailyStats, map[string]interface{}{
			"date":  date.Format("2006-01-02"),
			"count": count,
		})
	}
	stats["daily_utilization"] = dailyStats
	return stats, nil
}

func (r *SchedulingRepositoryImpl) scanWorkCalendar(
	rows *sql.Rows,
) (*scheduling.WorkCalendar, error) {
	var calendar scheduling.WorkCalendar
	var holidaysJSON []byte
	var workingDays pq.Int64Array
	err := rows.Scan(
		&calendar.CalendarID,
		&calendar.CompanyID,
		&calendar.Year,
		&calendar.Name,
		&calendar.Timezone,
		&workingDays,
		&holidaysJSON,
		&calendar.IsActive,
		&calendar.CreatedAt,
	)
	if err != nil {
		return nil, err
	}
	calendar.WorkingDays = make([]int, len(workingDays))
	for i, day := range workingDays {
		calendar.WorkingDays[i] = int(day)
	}
	if len(holidaysJSON) > 0 {
		if err := json.Unmarshal(holidaysJSON, &calendar.Holidays); err != nil {
			r.logger.Warn("Failed to unmarshal holidays", util.ErrorField(err))
			calendar.Holidays = []scheduling.Holiday{}
		}
	} else {
		calendar.Holidays = []scheduling.Holiday{}
	}
	return &calendar, nil
}

func (r *SchedulingRepositoryImpl) scanScheduleTemplate(rows *sql.Rows) (*scheduling.ScheduleTemplate, error) {
	var template scheduling.ScheduleTemplate
	var rulesJSON []byte
	err := rows.Scan(
		&template.ScheduleTemplateID,
		&template.CompanyID,
		&template.CalendarID,
		&template.TemplateType,
		&template.Name,
		&rulesJSON,
		&template.IsActive,
		&template.CreatedAt,
	)
	if err != nil {
		return nil, err
	}
	if len(rulesJSON) > 0 {
		if err := json.Unmarshal(rulesJSON, &template.Rules); err != nil {
			r.logger.Warn("Failed to unmarshal template rules", util.ErrorField(err))
			template.Rules = scheduling.TemplateRules{}
		}
	} else {
		template.Rules = scheduling.TemplateRules{}
	}
	return &template, nil
}

func (r *SchedulingRepositoryImpl) scanUserScheduleAssignment(rows *sql.Rows) (*scheduling.UserScheduleAssignment, error) {
	var assignment scheduling.UserScheduleAssignment
	var assignedBy sql.NullString
	err := rows.Scan(
		&assignment.UserID,
		&assignment.ScheduleTemplateID,
		&assignment.EffectiveFrom,
		&assignment.EffectiveTo,
		&assignedBy,
		&assignment.CreatedAt,
	)
	if err != nil {
		return nil, err
	}
	if assignedBy.Valid && assignedBy.String != "" {
		parsedUUID, err := uuid.Parse(assignedBy.String)
		if err == nil {
			assignment.AssignedBy = &parsedUUID
		}
	}
	return &assignment, nil
}

func (r *SchedulingRepositoryImpl) initializePreparedStatements(ctx context.Context) {
	statements := map[string]string{
		"get_work_calendar_by_id": `
			SELECT
				calendar_id,
				company_id,
				year,
				name,
				timezone,
				working_days,
				holidays,
				is_active,
				created_at
			FROM work_calendars
			WHERE calendar_id = $1
		`,
		"get_schedule_template_by_id": `
			SELECT schedule_template_id, company_id, calendar_id, template_type, name,
			       rules, is_active, created_at
			FROM schedule_templates WHERE schedule_template_id = $1
		`,
		"get_schedule_instance_by_id": `
			SELECT schedule_instance_id, company_id, user_id, schedule_date,
			       schedule_template_id, expected_start, expected_end, timezone,
			       metadata, generated_at, status, cancel_reason, cancelled_at
			FROM schedule_instances WHERE schedule_instance_id = $1
		`,
		"get_user_current_schedule_assignment": `
			SELECT user_id, schedule_template_id, effective_from, effective_to,
			       assigned_by, created_at
			FROM user_schedule_assignments
			WHERE user_id = $1
			  AND effective_from <= $2
			  AND (effective_to IS NULL OR effective_to >= $2)
			ORDER BY effective_from DESC
			LIMIT 1
		`,
	}
	for name, query := range statements {
		stmt, err := r.client.DB.PrepareContext(ctx, query)
		if err != nil {
			r.logger.Warn("Failed to prepare statement",
				util.String("statement", name),
				util.ErrorField(err),
			)
			continue
		}
		r.stmtMutex.Lock()
		r.stmtCache[name] = stmt
		r.stmtMutex.Unlock()
	}
	r.logger.Info("Scheduling prepared statements initialized",
		util.Int("statements", len(r.stmtCache)),
	)
}

func (r *SchedulingRepositoryImpl) UpdateWorkCalendar(
	ctx context.Context,
	calendar *scheduling.WorkCalendar,
) error {
	holidaysJSON, err := json.Marshal(calendar.Holidays)
	if err != nil {
		return fmt.Errorf("failed to marshal holidays: %w", err)
	}
	query := `
		UPDATE work_calendars SET
			name = $1,
			timezone = $2,
			working_days = $3,
			holidays = $4,
			is_active = $5
		WHERE calendar_id = $6
	`
	result, err := r.client.Exec(ctx, query,
		calendar.Name,
		calendar.Timezone,
		pq.Array(calendar.WorkingDays),
		holidaysJSON,
		calendar.IsActive,
		calendar.CalendarID,
	)
	if err != nil {
		return fmt.Errorf("failed to update work calendar: %w", err)
	}
	rowsAffected, err := result.RowsAffected()
	if err != nil {
		return fmt.Errorf("failed to read affected rows: %w", err)
	}
	if rowsAffected == 0 {
		return fmt.Errorf("work calendar not found: %s", calendar.CalendarID)
	}
	return nil
}

func (r *SchedulingRepositoryImpl) getStmt(name string) (*sql.Stmt, bool) {
	r.stmtMutex.RLock()
	defer r.stmtMutex.RUnlock()
	stmt, exists := r.stmtCache[name]
	return stmt, exists
}

func (r *SchedulingRepositoryImpl) HealthCheck(ctx context.Context) error {
	query := `SELECT 1 FROM work_calendars LIMIT 1`
	_, err := r.client.Exec(ctx, query)
	if err != nil {
		return fmt.Errorf("scheduling repository health check failed: %w", err)
	}
	return nil
}

func (r *SchedulingRepositoryImpl) CreateScheduleOverride(ctx context.Context, override *scheduling.ScheduleOverride) error {
	query := `
        INSERT INTO schedule_overrides (
            override_id, company_id, user_id, override_date, override_type,
            reason, created_by, created_at
        ) VALUES ($1, $2, $3, $4, $5, $6, $7, $8)
        ON CONFLICT (user_id, override_date) 
        DO NOTHING`

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

	if err != nil {
		r.logger.Error("Failed to create schedule override",
			util.String("user_id", override.UserID.String()),
			util.String("override_date", override.OverrideDate.Format("2006-01-02")),
			util.ErrorField(err))
		return fmt.Errorf("failed to create schedule override: %w", err)
	}

	return nil
}

func (r *SchedulingRepositoryImpl) GetScheduleOverrideByUserDate(
	ctx context.Context,
	userID uuid.UUID,
	date time.Time,
) (*scheduling.ScheduleOverride, error) {

	query := `
		SELECT override_id, company_id, user_id, override_date, override_type,
			   reason, created_by, created_at
		FROM schedule_overrides
		WHERE user_id = $1
		  AND override_date = $2::date
		LIMIT 1
	`

	rows, err := r.client.Query(ctx, query, userID, date)
	if err != nil {
		return nil, fmt.Errorf("failed to get schedule override: %w", err)
	}
	defer rows.Close()

	if rows.Next() {
		return r.scanScheduleOverride(rows)
	}

	// ✅ IMPORTANT: not found is NOT an error in your service logic
	return nil, nil
}

func (r *SchedulingRepositoryImpl) CheckScheduleOverrideConflict(ctx context.Context, userID uuid.UUID, date time.Time, excludeOverrideID *uuid.UUID) (bool, error) {
	query := `
		SELECT EXISTS(
			SELECT 1 FROM schedule_overrides
			WHERE user_id = $1 AND override_date = $2`
	args := []interface{}{userID, date}
	argIndex := 3
	if excludeOverrideID != nil {
		query += fmt.Sprintf(" AND override_id != $%d", argIndex)
		args = append(args, *excludeOverrideID)
	}
	query += ")"
	var exists bool
	err := r.client.QueryRow(ctx, query, args...).Scan(&exists)
	if err != nil {
		return false, fmt.Errorf("failed to check schedule override conflict: %w", err)
	}
	return exists, nil
}

func (r *SchedulingRepositoryImpl) scanScheduleOverride(rows *sql.Rows) (*scheduling.ScheduleOverride, error) {
	var override scheduling.ScheduleOverride
	var reason sql.NullString
	var createdBy sql.NullString
	err := rows.Scan(
		&override.OverrideID,
		&override.CompanyID,
		&override.UserID,
		&override.OverrideDate,
		&override.OverrideType,
		&reason,
		&createdBy,
		&override.CreatedAt,
	)
	if err != nil {
		return nil, err
	}
	if reason.Valid {
		override.Reason = &reason.String
	}
	if createdBy.Valid && createdBy.String != "" {
		parsedUUID, err := uuid.Parse(createdBy.String)
		if err == nil {
			override.CreatedBy = &parsedUUID
		}
	}
	return &override, nil
}

func (r *SchedulingRepositoryImpl) IsUserActiveInCompany(ctx context.Context, companyID, userID uuid.UUID) (bool, error) {
	query := `
        SELECT EXISTS(
            SELECT 1
            FROM company_employees
            WHERE company_id = $1 AND user_id = $2 AND is_active = true
        )`
	var exists bool
	err := r.client.QueryRow(ctx, query, companyID, userID).Scan(&exists)
	if err != nil {
		return false, fmt.Errorf("failed to check user in company: %w", err)
	}
	return exists, nil
}

func (r *SchedulingRepositoryImpl) GetUserCurrentWorkCenter(
	ctx context.Context,
	userID uuid.UUID,
	date time.Time,
) (*scheduling.UserWorkCenterAssignment, error) {
	businessDate := date.UTC().Truncate(24 * time.Hour)
	query := `
		SELECT
			assignment_id, company_id, user_id, work_center_code,
			effective_from, effective_to, is_active, created_at, updated_at
		FROM user_work_center_assignments
		WHERE user_id = $1
		  AND effective_from <= $2
		  AND (effective_to IS NULL OR effective_to >= $2)
		  AND is_active = true
		ORDER BY effective_from DESC
		LIMIT 1
	`
	rows, err := r.client.Query(ctx, query, userID, businessDate)
	if err != nil {
		return nil, fmt.Errorf("failed to get user work center: %w", err)
	}
	defer rows.Close()
	if rows.Next() {
		return r.scanUserWorkCenterAssignment(rows)
	}
	return nil, nil
}

func (r *SchedulingRepositoryImpl) GetWorkCenterShiftByCode(
	ctx context.Context,
	companyID uuid.UUID,
	workCenterCode string,
	date time.Time,
) (*scheduling.WorkCenterShiftMapping, error) {
	businessDate := date.UTC().Truncate(24 * time.Hour)
	query := `
		SELECT
			mapping_id, company_id, work_center_code,
			shift_id, effective_from, effective_to,
			is_active, created_at
		FROM work_center_shifts
		WHERE company_id = $1
		  AND work_center_code = $2
		  AND effective_from <= $3
		  AND (effective_to IS NULL OR effective_to >= $3)
		  AND is_active = true
		ORDER BY effective_from DESC
		LIMIT 1
	`
	row := r.client.QueryRow(ctx, query, companyID, workCenterCode, businessDate)
	var m scheduling.WorkCenterShiftMapping
	err := row.Scan(
		&m.MappingID,
		&m.CompanyID,
		&m.WorkCenterCode,
		&m.ShiftID,
		&m.EffectiveFrom,
		&m.EffectiveTo,
		&m.IsActive,
		&m.CreatedAt,
	)
	if err != nil {
		return nil, err
	}
	return &m, nil
}

func (r *SchedulingRepositoryImpl) CreateScheduleInstance(
	ctx context.Context,
	instance *scheduling.ScheduleInstance,
) error {

	metadataJSON, err := json.Marshal(instance.Metadata)
	if err != nil {
		return fmt.Errorf("failed to marshal metadata: %w", err)
	}

	var workCenterCode *string
	if instance.WorkCenterCode != nil && *instance.WorkCenterCode != "" {
		workCenterCode = instance.WorkCenterCode
	}

	query := `
		INSERT INTO schedule_instances (
			schedule_instance_id,
			company_id,
			user_id,
			schedule_date,
			schedule_template_id,
			expected_start,
			expected_end,
			timezone,
			metadata,
			generated_at,
			status,
			work_center_code
		)
		VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,'active',$11)
		ON CONFLICT (user_id, schedule_date)
		WHERE status = 'active'
		DO NOTHING
		RETURNING schedule_instance_id
	`

	var returnedID uuid.UUID
	err = r.client.QueryRow(
		ctx,
		query,
		instance.ScheduleInstanceID,
		instance.CompanyID,
		instance.UserID,
		instance.ScheduleDate.UTC().Truncate(24*time.Hour),
		instance.ScheduleTemplateID,
		instance.ExpectedStart,
		instance.ExpectedEnd,
		instance.Timezone,
		metadataJSON,
		instance.GeneratedAt,
		workCenterCode,
	).Scan(&returnedID)

	// 👇 DO NOTHING → no row returned → safe skip
	if err == sql.ErrNoRows {
		return nil
	}

	if err != nil {
		return fmt.Errorf("failed to create schedule instance: %w", err)
	}

	instance.ScheduleInstanceID = returnedID
	return nil
}

func (r *SchedulingRepositoryImpl) GetScheduleInstanceByUserDate(
	ctx context.Context,
	userID uuid.UUID,
	date time.Time,
) (*scheduling.ScheduleInstance, error) {
	businessDate := date.UTC().Truncate(24 * time.Hour)
	query := `
		SELECT
			schedule_instance_id, company_id, user_id, schedule_date,
			schedule_template_id, expected_start, expected_end, timezone,
			metadata, generated_at, status, cancel_reason, cancelled_at
		FROM schedule_instances
		WHERE user_id = $1
		  AND schedule_date = $2
		  AND status = 'active'
	`
	rows, err := r.client.Query(ctx, query, userID, businessDate)
	if err != nil {
		return nil, fmt.Errorf("failed to get schedule instance by user date: %w", err)
	}
	defer rows.Close()
	if rows.Next() {
		return r.scanScheduleInstance(rows)
	}
	return nil, nil
}

func (r *SchedulingRepositoryImpl) scanUserWorkCenterAssignment(
	rows *sql.Rows,
) (*scheduling.UserWorkCenterAssignment, error) {
	var a scheduling.UserWorkCenterAssignment
	var effectiveTo sql.NullTime
	err := rows.Scan(
		&a.AssignmentID,
		&a.CompanyID,
		&a.UserID,
		&a.WorkCenterCode,
		&a.EffectiveFrom,
		&effectiveTo,
		&a.IsActive,
		&a.CreatedAt,
	)
	if err != nil {
		return nil, err
	}
	if effectiveTo.Valid {
		a.EffectiveTo = &effectiveTo.Time
	}
	return &a, nil
}

func (r *SchedulingRepositoryImpl) scanScheduleInstance(
	rows *sql.Rows,
) (*scheduling.ScheduleInstance, error) {

	var instance scheduling.ScheduleInstance

	var expectedStart, expectedEnd, cancelledAt sql.NullTime
	var metadataJSON []byte
	var cancelReason sql.NullString
	var status sql.NullString
	var workCenterCode sql.NullString // ✅ NEW

	err := rows.Scan(
		&instance.ScheduleInstanceID,
		&instance.CompanyID,
		&instance.UserID,
		&instance.ScheduleDate,
		&instance.ScheduleTemplateID,
		&expectedStart,
		&expectedEnd,
		&instance.Timezone,
		&metadataJSON,
		&instance.GeneratedAt,
		&status,
		&cancelReason,
		&cancelledAt,
		&workCenterCode, // ✅ FIX
	)
	if err != nil {
		return nil, err
	}

	if expectedStart.Valid {
		instance.ExpectedStart = &expectedStart.Time
	}
	if expectedEnd.Valid {
		instance.ExpectedEnd = &expectedEnd.Time
	}

	if status.Valid {
		instance.Status = status.String
	} else {
		instance.Status = "active"
	}

	if cancelReason.Valid {
		instance.CancelReason = &cancelReason.String
	}
	if cancelledAt.Valid {
		instance.CancelledAt = &cancelledAt.Time
	}

	if workCenterCode.Valid {
		instance.WorkCenterCode = &workCenterCode.String
	}

	if len(metadataJSON) > 0 {
		if err := json.Unmarshal(metadataJSON, &instance.Metadata); err != nil {
			r.logger.Warn("Failed to unmarshal instance metadata", util.ErrorField(err))
			instance.Metadata = scheduling.InstanceMetadata{}
		}
	} else {
		instance.Metadata = scheduling.InstanceMetadata{}
	}

	return &instance, nil
}

func (r *SchedulingRepositoryImpl) DeactivateWorkCenterShift(
	ctx context.Context,
	mappingID uuid.UUID,
) error {
	query := `
		UPDATE work_center_shifts
		SET is_active = false
			updated_at = NOW()
		WHERE mapping_id = $1
	`
	_, err := r.client.Exec(ctx, query, mappingID)
	return err
}

func (r *SchedulingRepositoryImpl) CreateUserWorkCenterAssignment(
	ctx context.Context,
	a *scheduling.UserWorkCenterAssignment,
) error {
	if a.AssignmentID == uuid.Nil {
		a.AssignmentID = uuid.New()
	}
	now := time.Now().UTC()
	a.CreatedAt = now
	a.IsActive = true
	query := `
		INSERT INTO user_work_center_assignments (
			assignment_id, company_id, user_id, work_center_code,
			effective_from, effective_to, is_active, created_at, updated_at
		) VALUES ($1,$2,$3,$4,$5,$6,true,$7,$8)
	`
	_, err := r.client.Exec(ctx, query,
		a.AssignmentID,
		a.CompanyID,
		a.UserID,
		a.WorkCenterCode,
		a.EffectiveFrom,
		a.EffectiveTo,
		a.CreatedAt,
		now,
	)
	return err
}

func (r *SchedulingRepositoryImpl) EndUserWorkCenterAssignment(
	ctx context.Context,
	assignmentID uuid.UUID,
	endDate time.Time,
) error {
	query := `
		UPDATE user_work_center_assignments
		SET effective_to = $1, is_active = false, updated_at = NOW()
		WHERE assignment_id = $2
	`
	_, err := r.client.Exec(ctx, query, endDate, assignmentID)
	return err
}

func (r *SchedulingRepositoryImpl) GetUserWorkCenterAssignments(
	ctx context.Context,
	userID uuid.UUID,
	startDate, endDate *time.Time,
) ([]*scheduling.UserWorkCenterAssignment, error) {
	args := []interface{}{userID}
	var query string
	if startDate != nil && endDate != nil {
		query = `
			SELECT
				assignment_id, company_id, user_id, work_center_code,
				effective_from, effective_to, is_active, created_at, updated_at
			FROM user_work_center_assignments
			WHERE user_id = $1
			  AND (
			       (effective_from BETWEEN $2 AND $3)
			    OR (effective_to BETWEEN $2 AND $3)
			    OR (effective_from <= $2 AND (effective_to IS NULL OR effective_to >= $3))
			  )
			ORDER BY effective_from DESC
		`
		args = append(args, *startDate, *endDate)
	} else {
		query = `
			SELECT
				assignment_id, company_id, user_id, work_center_code,
				effective_from, effective_to, is_active, created_at, updated_at
			FROM user_work_center_assignments
			WHERE user_id = $1
			ORDER BY effective_from DESC
		`
	}
	rows, err := r.client.Query(ctx, query, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var list []*scheduling.UserWorkCenterAssignment
	for rows.Next() {
		a, err := r.scanUserWorkCenterAssignment(rows)
		if err != nil {
			continue
		}
		list = append(list, a)
	}
	return list, nil
}

func (r *SchedulingRepositoryImpl) CreateWorkCenterShiftMapping(
	ctx context.Context,
	m *scheduling.WorkCenterShiftMapping,
) error {
	query := `
		INSERT INTO work_center_shifts (
			mapping_id, company_id, work_center_code,
			shift_id, effective_from, effective_to,
			is_active, created_at
		)
		VALUES ($1,$2,$3,$4,$5,$6,$7,$8)
	`
	_, err := r.client.Exec(ctx, query,
		m.MappingID,
		m.CompanyID,
		m.WorkCenterCode,
		m.ShiftID,
		m.EffectiveFrom,
		m.EffectiveTo,
		m.IsActive,
		m.CreatedAt,
	)
	return err
}

func (r *SchedulingRepositoryImpl) GetWorkCenterShiftMappingByID(
	ctx context.Context,
	mappingID uuid.UUID,
) (*scheduling.WorkCenterShiftMapping, error) {
	query := `
		SELECT
			mapping_id, company_id, work_center_code,
			shift_id, effective_from, effective_to,
			is_active, created_at
		FROM work_center_shifts
		WHERE mapping_id = $1
	`
	row := r.client.QueryRow(ctx, query, mappingID)
	var m scheduling.WorkCenterShiftMapping
	err := row.Scan(
		&m.MappingID,
		&m.CompanyID,
		&m.WorkCenterCode,
		&m.ShiftID,
		&m.EffectiveFrom,
		&m.EffectiveTo,
		&m.IsActive,
		&m.CreatedAt,
	)
	if err != nil {
		return nil, err
	}
	return &m, nil
}

func (r *SchedulingRepositoryImpl) UpdateWorkCenterShiftMapping(
	ctx context.Context,
	m *scheduling.WorkCenterShiftMapping,
) error {
	query := `
		UPDATE work_center_shifts
		SET
			shift_id = $1,
			effective_to = $2,
			is_active = $3,
			updated_at = NOW()
		WHERE mapping_id = $4
	`
	_, err := r.client.Exec(
		ctx,
		query,
		m.ShiftID,
		m.EffectiveTo,
		m.IsActive,
		m.MappingID,
	)
	return err
}

func (r *SchedulingRepositoryImpl) GetActiveEmployeesByCompany(
	ctx context.Context,
	companyID uuid.UUID,
) ([]*scheduling.CompanyEmployee, error) {
	query := `
        SELECT
            company_id,
            user_id,
            employee_id,
            role_id,
            hire_date,
            is_active,
            reports_to,
            position_id,
            created_at,
            updated_at
        FROM company_employees
        WHERE company_id = $1 AND is_active = true
        ORDER BY hire_date DESC
    `
	rows, err := r.client.Query(ctx, query, companyID)
	if err != nil {
		return nil, fmt.Errorf("failed to get active employees: %w", err)
	}
	defer rows.Close()
	employees := make([]*scheduling.CompanyEmployee, 0)
	for rows.Next() {
		employee, err := r.scanCompanyEmployee(rows)
		if err != nil {
			r.logger.Warn("Failed to scan company employee", util.ErrorField(err))
			continue
		}
		employees = append(employees, employee)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("error iterating company employees: %w", err)
	}
	return employees, nil
}

func (r *SchedulingRepositoryImpl) GetCompanyEmployee(
	ctx context.Context,
	companyID, userID uuid.UUID,
) (*scheduling.CompanyEmployee, error) {
	query := `
		SELECT
			company_id,
			user_id,
			employee_id,
			role_id,
			hire_date,
			is_active,
			reports_to,
			position_id,
			created_at,
			updated_at
		FROM company_employees
		WHERE company_id = $1
		  AND user_id = $2
		  AND is_active = true
		LIMIT 1
	`
	rows, err := r.client.Query(ctx, query, companyID, userID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	if rows.Next() {
		return r.scanCompanyEmployee(rows)
	}
	return nil, sql.ErrNoRows
}

func (r *SchedulingRepositoryImpl) scanCompanyEmployee(
	rows *sql.Rows,
) (*scheduling.CompanyEmployee, error) {
	var e scheduling.CompanyEmployee
	var reportsTo sql.NullString
	err := rows.Scan(
		&e.CompanyID,
		&e.UserID,
		&e.EmployeeID,
		&e.RoleID,
		&e.HireDate,
		&e.IsActive,
		&reportsTo,
		&e.PositionID,
		&e.CreatedAt,
		&e.UpdatedAt,
	)
	if err != nil {
		return nil, err
	}
	if reportsTo.Valid {
		id, err := uuid.Parse(reportsTo.String)
		if err == nil {
			e.ReportsTo = &id
		}
	}
	return &e, nil
}

func (r *SchedulingRepositoryImpl) GetPositionByID(
	ctx context.Context,
	positionID uuid.UUID,
) (*scheduling.Position, error) {
	query := `
		SELECT
			position_id,
			company_id,
			department_id,
			title,
			is_schedulable,
			attendance_required,
			overtime_allowed,
			work_center_code,
			is_open,
			created_at,
			updated_at
		FROM positions
		WHERE position_id = $1
		LIMIT 1
	`
	rows, err := r.client.Query(ctx, query, positionID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	if rows.Next() {
		return r.scanPosition(rows)
	}
	return nil, sql.ErrNoRows
}

func (r *SchedulingRepositoryImpl) scanPosition(
	rows *sql.Rows,
) (*scheduling.Position, error) {
	var p scheduling.Position
	err := rows.Scan(
		&p.PositionID,
		&p.CompanyID,
		&p.DepartmentID,
		&p.Title,
		&p.IsSchedulable,
		&p.AttendanceRequired,
		&p.OvertimeAllowed,
		&p.WorkCenterCode,
		&p.IsOpen,
		&p.CreatedAt,
		&p.UpdatedAt,
	)
	if err != nil {
		return nil, err
	}
	return &p, nil
}

func (r *SchedulingRepositoryImpl) GetUserCompany(
	ctx context.Context,
	userID uuid.UUID,
) (*scheduling.CompanyEmployee, error) {
	query := `
		SELECT
			company_id,
			user_id,
			employee_id,
			role_id,
			hire_date,
			is_active,
			reports_to,
			position_id,
			created_at,
			updated_at
		FROM company_employees
		WHERE user_id = $1
		  AND is_active = true
		ORDER BY created_at DESC
		LIMIT 1
	`
	rows, err := r.client.Query(ctx, query, userID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	if rows.Next() {
		return r.scanCompanyEmployee(rows)
	}
	return nil, sql.ErrNoRows
}

func (r *SchedulingRepositoryImpl) GetUserWorkCenterAssignment(
	ctx context.Context,
	userID uuid.UUID,
	date time.Time,
) (*scheduling.UserWorkCenterAssignment, error) {
	businessDate := date.UTC().Truncate(24 * time.Hour)
	query := `
		SELECT
			assignment_id,
			company_id,
			user_id,
			work_center_code,
			effective_from,
			effective_to,
			is_active,
			created_at,
			updated_at
		FROM user_work_center_assignments
		WHERE user_id = $1
		  AND effective_from <= $2
		  AND (effective_to IS NULL OR effective_to >= $2)
		  AND is_active = true
		ORDER BY effective_from DESC
		LIMIT 1
	`
	rows, err := r.client.Query(ctx, query, userID, businessDate)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	if rows.Next() {
		return r.scanUserWorkCenterAssignment(rows)
	}
	return nil, nil
}

func (r *SchedulingRepositoryImpl) GetWorkCenterByCode(
	ctx context.Context,
	companyID uuid.UUID,
	workCenterCode string,
) (*workcenter.WorkCenter, error) {
	query := `
		SELECT
			work_center_code,
			company_id,
			name,
			description,
			timezone,
			is_active,
			created_at,
			updated_at
		FROM work_centers
		WHERE company_id = $1
		  AND work_center_code = $2
		LIMIT 1
	`
	row := r.client.QueryRow(ctx, query, companyID, workCenterCode)
	var wc workcenter.WorkCenter
	err := row.Scan(
		&wc.WorkCenterCode,
		&wc.CompanyID,
		&wc.Name,
		&wc.Description,
		&wc.Timezone,
		&wc.IsActive,
		&wc.CreatedAt,
		&wc.UpdatedAt,
	)
	if err != nil {
		if err == sql.ErrNoRows {
			return nil, nil
		}
		return nil, err
	}
	return &wc, nil
}

func (r *SchedulingRepositoryImpl) GetWorkCenterShiftMappingsByShift(
	ctx context.Context,
	shiftID uuid.UUID,
) ([]*scheduling.WorkCenterShiftMapping, error) {
	query := `
		SELECT
			mapping_id,
			company_id,
			work_center_code,
			shift_id,
			effective_from,
			effective_to,
			is_active,
			created_at
		FROM work_center_shifts
		WHERE shift_id = $1
		  AND is_active = true
		ORDER BY work_center_code, effective_from DESC
	`
	rows, err := r.client.Query(ctx, query, shiftID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	mappings := make([]*scheduling.WorkCenterShiftMapping, 0)
	for rows.Next() {
		var m scheduling.WorkCenterShiftMapping
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
		)
		if err != nil {
			return nil, err
		}
		if effectiveTo.Valid {
			m.EffectiveTo = &effectiveTo.Time
		}
		mappings = append(mappings, &m)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	return mappings, nil
}

func (r *SchedulingRepositoryImpl) GetWorkCentersByCompany(
	ctx context.Context,
	companyID uuid.UUID,
	activeOnly bool,
) ([]*workcenter.WorkCenter, error) {
	query := `
		SELECT
			work_center_code,
			company_id,
			name,
			description,
			timezone,
			is_active,
			created_at,
			updated_at
		FROM work_centers
		WHERE company_id = $1
	`
	args := []interface{}{companyID}
	if activeOnly {
		query += ` AND is_active = TRUE`
	}
	query += ` ORDER BY name ASC`
	rows, err := r.client.Query(ctx, query, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var result []*workcenter.WorkCenter
	for rows.Next() {
		var wc workcenter.WorkCenter
		err := rows.Scan(
			&wc.WorkCenterCode,
			&wc.CompanyID,
			&wc.Name,
			&wc.Description,
			&wc.Timezone,
			&wc.IsActive,
			&wc.CreatedAt,
			&wc.UpdatedAt,
		)
		if err != nil {
			return nil, err
		}
		result = append(result, &wc)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	return result, nil
}

func (r *SchedulingRepositoryImpl) GetWorkCenterShifts(
	ctx context.Context,
	companyID uuid.UUID,
	workCenterCode string,
	startDate, endDate *time.Time,
) ([]*scheduling.WorkCenterShiftMapping, error) {
	query := `
        SELECT mapping_id, company_id, work_center_code,
               shift_id, effective_from, effective_to,
               is_active, created_at
        FROM work_center_shifts
        WHERE company_id = $1 AND work_center_code = $2
          AND is_active = true
    `
	args := []interface{}{companyID, workCenterCode}
	argIdx := 3

	if startDate != nil && endDate != nil {
		query += fmt.Sprintf(`
            AND (
                (effective_from <= $%d AND (effective_to IS NULL OR effective_to >= $%d))
                OR (effective_from BETWEEN $%d AND $%d)
                OR ($%d BETWEEN effective_from AND COALESCE(effective_to, $%d))
            )
        `, argIdx, argIdx, argIdx, argIdx+1, argIdx, argIdx+1)
		args = append(args, *endDate, *startDate) // ← FIXED: Only 2 values
		argIdx += 2
	}

	query += " ORDER BY effective_from DESC"

	rows, err := r.client.Query(ctx, query, args...)
	if err != nil {
		return nil, fmt.Errorf("failed to get work center shifts: %w", err)
	}
	defer rows.Close()

	var shifts []*scheduling.WorkCenterShiftMapping
	for rows.Next() {
		var shift scheduling.WorkCenterShiftMapping
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
		)
		if err != nil {
			return nil, err
		}
		if effectiveTo.Valid {
			shift.EffectiveTo = &effectiveTo.Time
		}
		shifts = append(shifts, &shift)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("error iterating work center shifts: %w", err)
	}
	return shifts, nil
}
func (r *SchedulingRepositoryImpl) GetPositionsByWorkCenter(
	ctx context.Context,
	companyID uuid.UUID,
	workCenterCode string,
) ([]*scheduling.Position, error) {
	query := `
		SELECT position_id, company_id, department_id, title,
			   is_schedulable, attendance_required, overtime_allowed,
			   work_center_code, is_open, created_at, updated_at
		FROM positions
		WHERE company_id = $1 AND work_center_code = $2
		  AND is_open = true
		ORDER BY title
	`
	rows, err := r.client.Query(ctx, query, companyID, workCenterCode)
	if err != nil {
		return nil, fmt.Errorf("failed to get positions by work center: %w", err)
	}
	defer rows.Close()
	var positions []*scheduling.Position
	for rows.Next() {
		var pos scheduling.Position
		var workCenterCode sql.NullString
		err := rows.Scan(
			&pos.PositionID,
			&pos.CompanyID,
			&pos.DepartmentID,
			&pos.Title,
			&pos.IsSchedulable,
			&pos.AttendanceRequired,
			&pos.OvertimeAllowed,
			&workCenterCode,
			&pos.IsOpen,
			&pos.CreatedAt,
			&pos.UpdatedAt,
		)
		if err != nil {
			return nil, err
		}
		if workCenterCode.Valid {
			pos.WorkCenterCode = &workCenterCode.String
		}
		positions = append(positions, &pos)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("error iterating positions: %w", err)
	}
	return positions, nil
}

func (r *SchedulingRepositoryImpl) GetUsersByPosition(
	ctx context.Context,
	positionID uuid.UUID,
) ([]uuid.UUID, error) {
	query := `
		SELECT user_id
		FROM company_employees
		WHERE position_id = $1 AND is_active = true
	`
	rows, err := r.client.Query(ctx, query, positionID)
	if err != nil {
		return nil, fmt.Errorf("failed to get users by position: %w", err)
	}
	defer rows.Close()
	var userIDs []uuid.UUID
	for rows.Next() {
		var userID uuid.UUID
		if err := rows.Scan(&userID); err != nil {
			return nil, err
		}
		userIDs = append(userIDs, userID)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("error iterating users: %w", err)
	}
	return userIDs, nil
}

func (r *SchedulingRepositoryImpl) GetDepartmentByID(
	ctx context.Context,
	departmentID uuid.UUID,
) (*struct {
	DepartmentID   uuid.UUID `db:"department_id"`
	DepartmentName string    `db:"department_name"`
	CompanyID      uuid.UUID `db:"company_id"`
}, error) {
	query := `
		SELECT department_id, department_name, company_id
		FROM departments
		WHERE department_id = $1 AND is_active = true
	`
	row := r.client.QueryRow(ctx, query, departmentID)
	var result struct {
		DepartmentID   uuid.UUID `db:"department_id"`
		DepartmentName string    `db:"department_name"`
		CompanyID      uuid.UUID `db:"company_id"`
	}
	err := row.Scan(&result.DepartmentID, &result.DepartmentName, &result.CompanyID)
	if err != nil {
		if err == sql.ErrNoRows {
			return nil, nil
		}
		return nil, fmt.Errorf("failed to get department by ID: %w", err)
	}
	return &result, nil
}

func (r *SchedulingRepositoryImpl) GetPositionsByCompany(
	ctx context.Context,
	companyID uuid.UUID,
) ([]*scheduling.Position, error) {
	query := `
		SELECT position_id, company_id, department_id, title,
			   is_schedulable, attendance_required, overtime_allowed,
			   work_center_code, is_open, created_at, updated_at
		FROM positions
		WHERE company_id = $1 AND is_open = true
		ORDER BY department_id, title
	`
	rows, err := r.client.Query(ctx, query, companyID)
	if err != nil {
		return nil, fmt.Errorf("failed to get positions by company: %w", err)
	}
	defer rows.Close()
	var positions []*scheduling.Position
	for rows.Next() {
		var pos scheduling.Position
		var workCenterCode sql.NullString
		err := rows.Scan(
			&pos.PositionID,
			&pos.CompanyID,
			&pos.DepartmentID,
			&pos.Title,
			&pos.IsSchedulable,
			&pos.AttendanceRequired,
			&pos.OvertimeAllowed,
			&workCenterCode,
			&pos.IsOpen,
			&pos.CreatedAt,
			&pos.UpdatedAt,
		)
		if err != nil {
			return nil, err
		}
		if workCenterCode.Valid {
			pos.WorkCenterCode = &workCenterCode.String
		}
		positions = append(positions, &pos)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("error iterating positions: %w", err)
	}
	return positions, nil
}

func (r *SchedulingRepositoryImpl) GetCompanyEmployeeByUserID(
	ctx context.Context,
	userID uuid.UUID,
) (*scheduling.CompanyEmployee, error) {
	query := `
		SELECT company_id, user_id, employee_id, role_id,
			   hire_date, is_active, reports_to, position_id,
			   created_at, updated_at
		FROM company_employees
		WHERE user_id = $1 AND is_active = true
		ORDER BY created_at DESC
		LIMIT 1
	`
	rows, err := r.client.Query(ctx, query, userID)
	if err != nil {
		return nil, fmt.Errorf("failed to get company employee by user ID: %w", err)
	}
	defer rows.Close()
	if rows.Next() {
		var emp scheduling.CompanyEmployee
		var reportsTo sql.NullString
		var positionID sql.NullString
		err := rows.Scan(
			&emp.CompanyID,
			&emp.UserID,
			&emp.EmployeeID,
			&emp.RoleID,
			&emp.HireDate,
			&emp.IsActive,
			&reportsTo,
			&positionID,
			&emp.CreatedAt,
			&emp.UpdatedAt,
		)
		if err != nil {
			return nil, err
		}
		if reportsTo.Valid && reportsTo.String != "" {
			parsedUUID, err := uuid.Parse(reportsTo.String)
			if err == nil {
				emp.ReportsTo = &parsedUUID
			}
		}
		if positionID.Valid && positionID.String != "" {
			parsedUUID, err := uuid.Parse(positionID.String)
			if err == nil {
				emp.PositionID = &parsedUUID
			}
		}
		return &emp, nil
	}
	return nil, nil
}

func (r *SchedulingRepositoryImpl) GetScheduleInstancesByPosition(
	ctx context.Context,
	positionID uuid.UUID,
	startDate, endDate time.Time,
) ([]*scheduling.ScheduleInstance, error) {
	query := `
		SELECT si.schedule_instance_id, si.company_id, si.user_id, si.schedule_date,
			   si.schedule_template_id, si.expected_start, si.expected_end, si.timezone,
			   si.metadata, si.generated_at, si.status, si.cancel_reason, si.cancelled_at,
			   si.work_center_code
		FROM schedule_instances si
		JOIN company_employees ce ON si.user_id = ce.user_id AND si.company_id = ce.company_id
		WHERE ce.position_id = $1
		  AND si.schedule_date BETWEEN $2 AND $3
		  AND si.status = 'active'
		  AND ce.is_active = true
		ORDER BY si.schedule_date, si.user_id
	`
	rows, err := r.client.Query(ctx, query, positionID, startDate, endDate)
	if err != nil {
		return nil, fmt.Errorf("failed to get schedule instances by position: %w", err)
	}
	defer rows.Close()
	var instances []*scheduling.ScheduleInstance
	for rows.Next() {
		instance, err := r.scanScheduleInstance(rows)
		if err != nil {
			r.logger.Warn("Failed to scan schedule instance", util.ErrorField(err))
			continue
		}
		instances = append(instances, instance)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("error iterating schedule instances: %w", err)
	}
	return instances, nil
}

func (r *SchedulingRepositoryImpl) GetScheduleInstancesByWorkCenter(
	ctx context.Context,
	companyID uuid.UUID,
	workCenterCode string,
	startDate, endDate time.Time,
) ([]*scheduling.ScheduleInstance, error) {
	query := `
		SELECT si.schedule_instance_id, si.company_id, si.user_id, si.schedule_date,
			   si.schedule_template_id, si.expected_start, si.expected_end, si.timezone,
			   si.metadata, si.generated_at, si.status, si.cancel_reason, si.cancelled_at,
			   si.work_center_code
		FROM schedule_instances si
		WHERE si.company_id = $1
		  AND si.schedule_date BETWEEN $2 AND $3
		  AND si.status = 'active'
		  AND si.work_center_code = $4
		ORDER BY si.schedule_date, si.user_id
	`
	rows, err := r.client.Query(ctx, query, companyID, startDate, endDate, workCenterCode)
	if err != nil {
		return nil, fmt.Errorf("failed to get schedule instances by work center: %w", err)
	}
	defer rows.Close()
	var instances []*scheduling.ScheduleInstance
	for rows.Next() {
		instance, err := r.scanScheduleInstance(rows)
		if err != nil {
			r.logger.Warn("Failed to scan schedule instance", util.ErrorField(err))
			continue
		}
		instances = append(instances, instance)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("error iterating schedule instances: %w", err)
	}
	return instances, nil
}

func (r *SchedulingRepositoryImpl) SearchScheduleInstances(
	ctx context.Context,
	filters map[string]interface{},
	page, pageSize int,
) ([]*scheduling.ScheduleInstance, int, error) {
	whereClause := "WHERE 1=1"
	var args []interface{}
	argIdx := 1
	_ = func(field string, value interface{}, operator string) {
		whereClause += fmt.Sprintf(" AND %s %s $%d", field, operator, argIdx)
		args = append(args, value)
		argIdx++
	}
	if userID, ok := filters["user_id"].(uuid.UUID); ok {
		whereClause += fmt.Sprintf(" AND user_id = $%d", argIdx)
		args = append(args, userID)
		argIdx++
	}
	if userIDs, ok := filters["user_ids"].([]uuid.UUID); ok && len(userIDs) > 0 {
		whereClause += fmt.Sprintf(" AND user_id = ANY($%d)", argIdx)
		args = append(args, pq.Array(userIDs))
		argIdx++
	}
	if companyID, ok := filters["company_id"].(uuid.UUID); ok {
		whereClause += fmt.Sprintf(" AND company_id = $%d", argIdx)
		args = append(args, companyID)
		argIdx++
	}
	if templateID, ok := filters["schedule_template_id"].(uuid.UUID); ok {
		whereClause += fmt.Sprintf(" AND schedule_template_id = $%d", argIdx)
		args = append(args, templateID)
		argIdx++
	}
	if templateIDs, ok := filters["schedule_template_ids"].([]uuid.UUID); ok && len(templateIDs) > 0 {
		whereClause += fmt.Sprintf(" AND schedule_template_id = ANY($%d)", argIdx)
		args = append(args, pq.Array(templateIDs))
		argIdx++
	}
	if startDate, ok := filters["start_date"].(time.Time); ok {
		whereClause += fmt.Sprintf(" AND schedule_date >= $%d", argIdx)
		args = append(args, startDate)
		argIdx++
	}
	if endDate, ok := filters["end_date"].(time.Time); ok {
		whereClause += fmt.Sprintf(" AND schedule_date <= $%d", argIdx)
		args = append(args, endDate)
		argIdx++
	}
	if timezone, ok := filters["timezone"].(string); ok {
		whereClause += fmt.Sprintf(" AND timezone = $%d", argIdx)
		args = append(args, timezone)
		argIdx++
	}
	var joinClause string
	if positionID, ok := filters["position_id"].(uuid.UUID); ok {
		joinClause = " JOIN company_employees ce ON si.user_id = ce.user_id AND si.company_id = ce.company_id"
		whereClause += fmt.Sprintf(" AND ce.position_id = $%d AND ce.is_active = true", argIdx)
		args = append(args, positionID)
		argIdx++
	}
	if workCenterCode, ok := filters["work_center_code"].(string); ok {
		if joinClause == "" {
			joinClause = `
				JOIN company_employees ce
				  ON si.user_id = ce.user_id
				 AND si.company_id = ce.company_id
			`
		}
		whereClause += fmt.Sprintf(" AND ce.work_center_code = $%d AND ce.is_active = true", argIdx)
		args = append(args, workCenterCode)
		argIdx++
	}
	whereClause += " AND status = 'active'"
	countQuery := fmt.Sprintf(`
		SELECT COUNT(*)
		FROM schedule_instances si
		%s
		%s
	`, joinClause, whereClause)
	var totalCount int
	err := r.client.QueryRow(ctx, countQuery, args...).Scan(&totalCount)
	if err != nil {
		return nil, 0, fmt.Errorf("failed to count schedule instances: %w", err)
	}
	dataQuery := fmt.Sprintf(`
		SELECT si.schedule_instance_id, si.company_id, si.user_id, si.schedule_date,
			   si.schedule_template_id, si.expected_start, si.expected_end, si.timezone,
			   si.metadata, si.generated_at, si.status, si.cancel_reason, si.cancelled_at,
			   si.work_center_code
		FROM schedule_instances si
		%s
		%s
		ORDER BY si.schedule_date DESC, si.user_id
		LIMIT $%d OFFSET $%d
	`, joinClause, whereClause, argIdx, argIdx+1)
	offset := (page - 1) * pageSize
	args = append(args, pageSize, offset)
	rows, err := r.client.Query(ctx, dataQuery, args...)
	if err != nil {
		return nil, 0, fmt.Errorf("failed to search schedule instances: %w", err)
	}
	defer rows.Close()
	var instances []*scheduling.ScheduleInstance
	for rows.Next() {
		instance, err := r.scanScheduleInstance(rows)
		if err != nil {
			r.logger.Warn("Failed to scan schedule instance", util.ErrorField(err))
			continue
		}
		instances = append(instances, instance)
	}
	if err := rows.Err(); err != nil {
		return nil, 0, fmt.Errorf("error iterating schedule instances: %w", err)
	}
	return instances, totalCount, nil
}

func (r *SchedulingRepositoryImpl) GetPositionCoverage(
	ctx context.Context,
	positionID uuid.UUID,
	startDate, endDate time.Time,
) (map[string]interface{}, error) {
	result := make(map[string]interface{})
	var totalEmployees int
	err := r.client.QueryRow(ctx, `
		SELECT COUNT(*)
		FROM company_employees
		WHERE position_id = $1 AND is_active = true
	`, positionID).Scan(&totalEmployees)
	if err != nil {
		return nil, fmt.Errorf("failed to get total employees: %w", err)
	}
	result["total_employees"] = totalEmployees
	var scheduledDays int
	err = r.client.QueryRow(ctx, `
		SELECT COUNT(DISTINCT si.schedule_date)
		FROM schedule_instances si
		JOIN company_employees ce ON si.user_id = ce.user_id
		WHERE ce.position_id = $1
		  AND si.schedule_date BETWEEN $2 AND $3
		  AND si.status = 'active'
		  AND ce.is_active = true
	`, positionID, startDate, endDate).Scan(&scheduledDays)
	if err != nil {
		return nil, fmt.Errorf("failed to get scheduled days: %w", err)
	}
	result["scheduled_days"] = scheduledDays
	var uniqueScheduledUsers int
	err = r.client.QueryRow(ctx, `
		SELECT COUNT(DISTINCT si.user_id)
		FROM schedule_instances si
		JOIN company_employees ce ON si.user_id = ce.user_id
		WHERE ce.position_id = $1
		  AND si.schedule_date BETWEEN $2 AND $3
		  AND si.status = 'active'
		  AND ce.is_active = true
	`, positionID, startDate, endDate).Scan(&uniqueScheduledUsers)
	if err != nil {
		return nil, fmt.Errorf("failed to get unique scheduled users: %w", err)
	}
	result["scheduled_users"] = uniqueScheduledUsers
	coveragePercent := 0.0
	if totalEmployees > 0 {
		coveragePercent = float64(uniqueScheduledUsers) / float64(totalEmployees) * 100
	}
	result["coverage_percent"] = coveragePercent
	query := `
		SELECT si.schedule_date, COUNT(DISTINCT si.user_id) as scheduled_count
		FROM schedule_instances si
		JOIN company_employees ce ON si.user_id = ce.user_id
		WHERE ce.position_id = $1
		  AND si.schedule_date BETWEEN $2 AND $3
		  AND si.status = 'active'
		  AND ce.is_active = true
		GROUP BY si.schedule_date
		ORDER BY si.schedule_date
	`
	rows, err := r.client.Query(ctx, query, positionID, startDate, endDate)
	if err != nil {
		return nil, fmt.Errorf("failed to get daily coverage: %w", err)
	}
	defer rows.Close()
	dailyCoverage := make(map[string]int)
	for rows.Next() {
		var date time.Time
		var count int
		if err := rows.Scan(&date, &count); err != nil {
			continue
		}
		dailyCoverage[date.Format("2006-01-02")] = count
	}
	result["daily_coverage"] = dailyCoverage
	return result, nil
}

func (r *SchedulingRepositoryImpl) GetWorkCenterUtilization(
	ctx context.Context,
	companyID uuid.UUID,
	workCenterCode string,
	startDate, endDate time.Time,
) (map[string]interface{}, error) {
	result := make(map[string]interface{})
	workCenter, err := r.GetWorkCenterByCode(ctx, companyID, workCenterCode)
	if err != nil {
		return nil, fmt.Errorf("failed to get work center: %w", err)
	}
	if workCenter == nil {
		return nil, fmt.Errorf("work center not found: %s", workCenterCode)
	}
	result["work_center"] = workCenter
	var totalEmployees int
	err = r.client.QueryRow(ctx, `
		SELECT COUNT(DISTINCT uwa.user_id)
		FROM user_work_center_assignments uwa
		WHERE uwa.company_id = $1
		  AND uwa.work_center_code = $2
		  AND uwa.is_active = true
		  AND uwa.effective_from <= $3
		  AND (uwa.effective_to IS NULL OR uwa.effective_to >= $3)
	`, companyID, workCenterCode, endDate).Scan(&totalEmployees)
	if err != nil {
		totalEmployees = 0
	}
	result["total_employees"] = totalEmployees
	var scheduledDays int
	err = r.client.QueryRow(ctx, `
		SELECT COUNT(*)
		FROM schedule_instances si
		WHERE si.company_id = $1
		  AND si.work_center_code = $2
		  AND si.schedule_date BETWEEN $3 AND $4
		  AND si.status = 'active'
	`, companyID, workCenterCode, startDate, endDate).Scan(&scheduledDays)
	if err != nil {
		scheduledDays = 0
	}
	result["scheduled_days"] = scheduledDays
	var uniqueScheduledUsers int
	err = r.client.QueryRow(ctx, `
		SELECT COUNT(DISTINCT si.user_id)
		FROM schedule_instances si
		WHERE si.company_id = $1
		  AND si.work_center_code = $2
		  AND si.schedule_date BETWEEN $3 AND $4
		  AND si.status = 'active'
	`, companyID, workCenterCode, startDate, endDate).Scan(&uniqueScheduledUsers)
	if err != nil {
		uniqueScheduledUsers = 0
	}
	result["scheduled_users"] = uniqueScheduledUsers
	utilization := 0.0
	totalDays := int(endDate.Sub(startDate).Hours()/24) + 1
	if totalEmployees > 0 && totalDays > 0 {
		maxPossibleDays := totalEmployees * totalDays
		if maxPossibleDays > 0 {
			utilization = float64(scheduledDays) / float64(maxPossibleDays) * 100
		}
	}
	result["utilization_percent"] = utilization
	query := `
		SELECT si.schedule_date, COUNT(*) as scheduled_count
		FROM schedule_instances si
		WHERE si.company_id = $1
		  AND si.work_center_code = $2
		  AND si.schedule_date BETWEEN $3 AND $4
		  AND si.status = 'active'
		GROUP BY si.schedule_date
		ORDER BY si.schedule_date
	`
	rows, err := r.client.Query(ctx, query, companyID, workCenterCode, startDate, endDate)
	if err != nil {
		return result, nil
	}
	defer rows.Close()
	dailyUtilization := make(map[string]int)
	for rows.Next() {
		var date time.Time
		var count int
		if err := rows.Scan(&date, &count); err != nil {
			continue
		}
		dailyUtilization[date.Format("2006-01-02")] = count
	}
	result["daily_utilization"] = dailyUtilization
	shiftQuery := `
		SELECT st.template_type, COUNT(*) as count
		FROM schedule_instances si
		JOIN schedule_templates st ON si.schedule_template_id = st.schedule_template_id
		WHERE si.company_id = $1
		  AND si.work_center_code = $2
		  AND si.schedule_date BETWEEN $3 AND $4
		  AND si.status = 'active'
		GROUP BY st.template_type
	`
	shiftRows, err := r.client.Query(ctx, shiftQuery, companyID, workCenterCode, startDate, endDate)
	if err == nil {
		defer shiftRows.Close()
		shiftDistribution := make(map[string]int)
		for shiftRows.Next() {
			var templateType string
			var count int
			if err := shiftRows.Scan(&templateType, &count); err != nil {
				continue
			}
			shiftDistribution[templateType] = count
		}
		result["shift_distribution"] = shiftDistribution
	}
	return result, nil
}

func (r *SchedulingRepositoryImpl) GetScheduleOverrideByID(ctx context.Context, overrideID uuid.UUID) (*scheduling.ScheduleOverride, error) {
	query := `
		SELECT override_id, company_id, user_id, override_date, override_type,
			   reason, created_by, created_at
		FROM schedule_overrides
		WHERE override_id = $1`
	rows, err := r.client.Query(ctx, query, overrideID)
	if err != nil {
		return nil, fmt.Errorf("failed to get schedule override: %w", err)
	}
	defer rows.Close()
	if rows.Next() {
		return r.scanScheduleOverride(rows)
	}
	return nil, fmt.Errorf("schedule override not found: %s", overrideID)
}

func (r *SchedulingRepositoryImpl) GetScheduleOverridesByUser(
	ctx context.Context,
	userID uuid.UUID,
	startDate, endDate *time.Time,
	overrideType *string,
) ([]*scheduling.ScheduleOverride, error) {

	query := `
		SELECT override_id, company_id, user_id, override_date, override_type,
			   reason, created_by, created_at
		FROM schedule_overrides
		WHERE user_id = $1
	`

	args := []interface{}{userID}
	argIndex := 2

	// 🔑 FIX: CAST PARAMS TO DATE
	if startDate != nil && endDate != nil {
		query += fmt.Sprintf(
			" AND override_date BETWEEN $%d::date AND $%d::date",
			argIndex,
			argIndex+1,
		)
		args = append(args, *startDate, *endDate)
		argIndex += 2
	}

	if overrideType != nil {
		query += fmt.Sprintf(" AND override_type = $%d", argIndex)
		args = append(args, *overrideType)
		argIndex++
	}

	query += " ORDER BY override_date"

	rows, err := r.client.Query(ctx, query, args...)
	if err != nil {
		return nil, fmt.Errorf("failed to get schedule overrides by user: %w", err)
	}
	defer rows.Close()

	overrides := make([]*scheduling.ScheduleOverride, 0)
	for rows.Next() {
		override, err := r.scanScheduleOverride(rows)
		if err != nil {
			r.logger.Warn("Failed to scan schedule override", util.ErrorField(err))
			continue
		}
		overrides = append(overrides, override)
	}

	return overrides, nil
}

func (r *SchedulingRepositoryImpl) GetScheduleOverridesByCompany(ctx context.Context, companyID uuid.UUID, startDate, endDate *time.Time, overrideType *string) ([]*scheduling.ScheduleOverride, error) {
	query := `
		SELECT override_id, company_id, user_id, override_date, override_type,
			   reason, created_by, created_at
		FROM schedule_overrides
		WHERE company_id = $1`
	args := []interface{}{companyID}
	argIndex := 2
	if startDate != nil && endDate != nil {
		query += fmt.Sprintf(" AND override_date BETWEEN $%d AND $%d", argIndex, argIndex+1)
		args = append(args, *startDate, *endDate)
		argIndex += 2
	}
	if overrideType != nil {
		query += fmt.Sprintf(" AND override_type = $%d", argIndex)
		args = append(args, *overrideType)
	}
	query += " ORDER BY user_id, override_date"
	rows, err := r.client.Query(ctx, query, args...)
	if err != nil {
		return nil, fmt.Errorf("failed to get schedule overrides by company: %w", err)
	}
	defer rows.Close()
	overrides := make([]*scheduling.ScheduleOverride, 0)
	for rows.Next() {
		override, err := r.scanScheduleOverride(rows)
		if err != nil {
			r.logger.Warn("Failed to scan schedule override", util.ErrorField(err))
			continue
		}
		overrides = append(overrides, override)
	}
	return overrides, nil
}

func (r *SchedulingRepositoryImpl) UpdateScheduleOverride(ctx context.Context, override *scheduling.ScheduleOverride) error {
	query := `
		UPDATE schedule_overrides SET
			override_type = $1, reason = $2
		WHERE override_id = $3`
	result, err := r.client.Exec(ctx, query,
		override.OverrideType,
		override.Reason,
		override.OverrideID,
	)
	if err != nil {
		return fmt.Errorf("failed to update schedule override: %w", err)
	}
	rowsAffected, _ := result.RowsAffected()
	if rowsAffected == 0 {
		return fmt.Errorf("schedule override not found: %s", override.OverrideID)
	}
	return nil
}

func (r *SchedulingRepositoryImpl) DeleteScheduleOverride(ctx context.Context, overrideID uuid.UUID) error {
	query := `DELETE FROM schedule_overrides WHERE override_id = $1`
	result, err := r.client.Exec(ctx, query, overrideID)
	if err != nil {
		return fmt.Errorf("failed to delete schedule override: %w", err)
	}
	rowsAffected, _ := result.RowsAffected()
	if rowsAffected == 0 {
		return fmt.Errorf("schedule override not found: %s", overrideID)
	}
	return nil
}
func (r *SchedulingRepositoryImpl) GetWorkCalendarTimezoneForUser(
	ctx context.Context,
	companyID uuid.UUID,
	userID uuid.UUID,
) (string, error) {

	var timezone string

	query := `
		SELECT wc.timezone
		FROM company_employees ce
		JOIN positions p
		  ON p.position_id = ce.position_id
		JOIN work_centers wc
		  ON wc.company_id = p.company_id
		 AND wc.work_center_code = p.work_center_code
		WHERE ce.company_id = $1
		  AND ce.user_id = $2
		  AND ce.is_active = true
		  AND wc.is_active = true
		LIMIT 1
	`

	err := r.client.QueryRow(
		ctx,
		query,
		companyID,
		userID,
	).Scan(&timezone)

	// Safe fallback
	if err != nil || timezone == "" {
		return "UTC", nil
	}

	return timezone, nil
}

func (r *SchedulingRepositoryImpl) HasActiveSchedule(
	ctx context.Context,
	companyID uuid.UUID,
	userID uuid.UUID,
	date time.Time,
) (bool, error) {

	businessDate := date.UTC().Truncate(24 * time.Hour)

	var exists bool
	err := r.client.QueryRow(
		ctx,
		`
		SELECT EXISTS (
			SELECT 1
			FROM schedule_instances
			WHERE company_id = $1
			  AND user_id = $2
			  AND schedule_date = $3
			  AND status = 'active'
		)
		`,
		companyID,
		userID,
		businessDate,
	).Scan(&exists)

	if err != nil {
		return false, err
	}

	return exists, nil
}
func (r *SchedulingRepositoryImpl) DeleteScheduleOverridesByReason(
	ctx context.Context,
	companyID uuid.UUID,
	userID uuid.UUID,
	reason string,
) error {

	query := `
		DELETE FROM schedule_overrides
		WHERE company_id = $1
		  AND user_id = $2
		  AND reason = $3
		  AND override_type = 'off'
	`

	_, err := r.client.Exec(
		ctx,
		query,
		companyID,
		userID,
		reason,
	)

	if err != nil {
		return fmt.Errorf("failed to delete schedule overrides by reason: %w", err)
	}

	return nil
}

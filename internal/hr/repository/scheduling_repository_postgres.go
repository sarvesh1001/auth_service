package repository

import (
	"auth-service/internal/client"
	"auth-service/internal/hr/models/scheduling"
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

// SchedulingRepositoryImpl handles PostgreSQL scheduling operations
type SchedulingRepositoryImpl struct {
	client    *client.PostgresClient
	logger    *zap.Logger
	stmtCache map[string]*sql.Stmt
	stmtMutex sync.RWMutex
}

// NewSchedulingRepository creates a new PostgreSQL scheduling repository
func NewSchedulingRepository(postgresClient *client.PostgresClient, logger *zap.Logger) SchedulingRepository {
	repo := &SchedulingRepositoryImpl{
		client:    postgresClient,
		logger:    logger,
		stmtCache: make(map[string]*sql.Stmt),
	}

	go repo.initializePreparedStatements(context.Background())
	return repo
}

// ============================================================================
// WORK CALENDAR METHODS
// ============================================================================

func (r *SchedulingRepositoryImpl) CreateWorkCalendar(ctx context.Context, calendar *scheduling.WorkCalendar) error {
	startTime := time.Now()

	// Marshal holidays to JSONB
	holidaysJSON, err := json.Marshal(calendar.Holidays)
	if err != nil {
		return fmt.Errorf("failed to marshal holidays: %w", err)
	}

	query := `
		INSERT INTO work_calendars (
			calendar_id, company_id, name, timezone, working_days, holidays, 
			is_active, created_at
		) VALUES ($1, $2, $3, $4, $5, $6, $7, $8)`

	_, err = r.client.Exec(ctx, query,
		calendar.CalendarID,
		calendar.CompanyID,
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
			util.String("name", calendar.Name),
			util.ErrorField(err))
		return fmt.Errorf("failed to create work calendar: %w", err)
	}

	r.logger.Debug("Work calendar created",
		util.String("calendar_id", calendar.CalendarID.String()),
		util.Duration("duration", time.Since(startTime)))

	return nil
}

func (r *SchedulingRepositoryImpl) GetWorkCalendarByID(ctx context.Context, calendarID uuid.UUID) (*scheduling.WorkCalendar, error) {
	stmt, ok := r.getStmt("get_work_calendar_by_id")
	if !ok {
		// Fallback to regular query if prepared statement not found
		query := `
			SELECT calendar_id, company_id, name, timezone, working_days, holidays, 
				   is_active, created_at
			FROM work_calendars WHERE calendar_id = $1`

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

func (r *SchedulingRepositoryImpl) GetWorkCalendarsByCompany(ctx context.Context, companyID uuid.UUID) ([]*scheduling.WorkCalendar, error) {
	query := `
		SELECT calendar_id, company_id, name, timezone, working_days, holidays, 
		       is_active, created_at
		FROM work_calendars 
		WHERE company_id = $1
		ORDER BY name`

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

func (r *SchedulingRepositoryImpl) UpdateWorkCalendar(ctx context.Context, calendar *scheduling.WorkCalendar) error {
	// Marshal holidays to JSONB
	holidaysJSON, err := json.Marshal(calendar.Holidays)
	if err != nil {
		return fmt.Errorf("failed to marshal holidays: %w", err)
	}

	query := `
		UPDATE work_calendars SET
			name = $1, timezone = $2, working_days = $3, holidays = $4, 
			is_active = $5
		WHERE calendar_id = $6`

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

	rowsAffected, _ := result.RowsAffected()
	if rowsAffected == 0 {
		return fmt.Errorf("work calendar not found: %s", calendar.CalendarID)
	}

	return nil
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

// ============================================================================
// SCHEDULE TEMPLATE METHODS
// ============================================================================

func (r *SchedulingRepositoryImpl) CreateScheduleTemplate(ctx context.Context, template *scheduling.ScheduleTemplate) error {
	startTime := time.Now()

	// Marshal rules to JSONB
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
		// Fallback to regular query
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
	// Marshal rules to JSONB
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

// ============================================================================
// USER SCHEDULE ASSIGNMENT METHODS
// ============================================================================

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
		// Fallback to regular query
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

// ============================================================================
// SCHEDULE INSTANCE METHODS
// ============================================================================

func (r *SchedulingRepositoryImpl) CreateScheduleInstance(ctx context.Context, instance *scheduling.ScheduleInstance) error {
	// Marshal metadata to JSONB
	metadataJSON, err := json.Marshal(instance.Metadata)
	if err != nil {
		return fmt.Errorf("failed to marshal metadata: %w", err)
	}

	query := `
		INSERT INTO schedule_instances (
			schedule_instance_id, company_id, user_id, schedule_date, 
			schedule_template_id, expected_start, expected_end, timezone,
			metadata, generated_at
		) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10)`

	_, err = r.client.Exec(ctx, query,
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
	)

	if err != nil {
		r.logger.Error("Failed to create schedule instance",
			util.String("user_id", instance.UserID.String()),
			util.String("date", instance.ScheduleDate.Format("2006-01-02")),
			util.ErrorField(err))
		return fmt.Errorf("failed to create schedule instance: %w", err)
	}

	return nil
}

func (r *SchedulingRepositoryImpl) GetScheduleInstanceByID(ctx context.Context, instanceID uuid.UUID) (*scheduling.ScheduleInstance, error) {
	stmt, ok := r.getStmt("get_schedule_instance_by_id")
	if !ok {
		// Fallback to regular query
		query := `
			SELECT schedule_instance_id, company_id, user_id, schedule_date, 
				   schedule_template_id, expected_start, expected_end, timezone,
				   metadata, generated_at
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

func (r *SchedulingRepositoryImpl) GetScheduleInstanceByUserDate(ctx context.Context, userID uuid.UUID, date time.Time) (*scheduling.ScheduleInstance, error) {
	query := `
		SELECT schedule_instance_id, company_id, user_id, schedule_date, 
		       schedule_template_id, expected_start, expected_end, timezone,
		       metadata, generated_at
		FROM schedule_instances 
		WHERE user_id = $1 AND schedule_date = $2`

	rows, err := r.client.Query(ctx, query, userID, date)
	if err != nil {
		return nil, fmt.Errorf("failed to get schedule instance by user date: %w", err)
	}
	defer rows.Close()

	if rows.Next() {
		return r.scanScheduleInstance(rows)
	}

	return nil, fmt.Errorf("schedule instance not found for user: %s on date: %s", userID, date.Format("2006-01-02"))
}

func (r *SchedulingRepositoryImpl) GetScheduleInstancesByUser(ctx context.Context, userID uuid.UUID, startDate, endDate time.Time) ([]*scheduling.ScheduleInstance, error) {
	query := `
		SELECT schedule_instance_id, company_id, user_id, schedule_date, 
		       schedule_template_id, expected_start, expected_end, timezone,
		       metadata, generated_at
		FROM schedule_instances 
		WHERE user_id = $1 AND schedule_date BETWEEN $2 AND $3
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
		       metadata, generated_at
		FROM schedule_instances 
		WHERE company_id = $1 AND schedule_date BETWEEN $2 AND $3
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
		       metadata, generated_at
		FROM schedule_instances 
		WHERE schedule_template_id = $1 AND schedule_date BETWEEN $2 AND $3
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
	// Marshal metadata to JSONB
	metadataJSON, err := json.Marshal(instance.Metadata)
	if err != nil {
		return fmt.Errorf("failed to marshal metadata: %w", err)
	}

	query := `
		UPDATE schedule_instances SET
			expected_start = $1, expected_end = $2, metadata = $3, timezone = $4
		WHERE schedule_instance_id = $5`

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
		return fmt.Errorf("schedule instance not found: %s", instance.ScheduleInstanceID)
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

func (r *SchedulingRepositoryImpl) BulkCreateScheduleInstances(ctx context.Context, instances []*scheduling.ScheduleInstance) error {
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
			metadata, generated_at
		) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10)`

	stmt, err := tx.PrepareContext(ctx, query)
	if err != nil {
		return fmt.Errorf("failed to prepare batch statement: %w", err)
	}
	defer stmt.Close()

	for _, instance := range instances {
		// Marshal metadata to JSONB
		metadataJSON, err := json.Marshal(instance.Metadata)
		if err != nil {
			return fmt.Errorf("failed to marshal metadata for instance %s: %w", instance.ScheduleInstanceID, err)
		}

		_, err = stmt.ExecContext(ctx,
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
		)
		if err != nil {
			return fmt.Errorf("failed to insert schedule instance %s: %w", instance.ScheduleInstanceID, err)
		}
	}

	if err := tx.Commit(); err != nil {
		return fmt.Errorf("failed to commit batch transaction: %w", err)
	}

	r.logger.Info("Batch schedule instances creation completed",
		util.Int("instances_created", len(instances)))
	return nil
}

// ============================================================================
// ANALYTICS METHODS
// ============================================================================

func (r *SchedulingRepositoryImpl) GetScheduleCoverage(ctx context.Context, companyID uuid.UUID, startDate, endDate time.Time) (map[string]interface{}, error) {
	stats := make(map[string]interface{})

	// Total scheduled days
	var totalScheduledDays int
	err := r.client.QueryRow(ctx, `
		SELECT COUNT(DISTINCT schedule_date) 
		FROM schedule_instances 
		WHERE company_id = $1 AND schedule_date BETWEEN $2 AND $3`,
		companyID, startDate, endDate).Scan(&totalScheduledDays)
	if err != nil {
		return nil, fmt.Errorf("failed to get total scheduled days: %w", err)
	}
	stats["total_scheduled_days"] = totalScheduledDays

	// Total scheduled users
	var totalScheduledUsers int
	err = r.client.QueryRow(ctx, `
		SELECT COUNT(DISTINCT user_id) 
		FROM schedule_instances 
		WHERE company_id = $1 AND schedule_date BETWEEN $2 AND $3`,
		companyID, startDate, endDate).Scan(&totalScheduledUsers)
	if err != nil {
		return nil, fmt.Errorf("failed to get total scheduled users: %w", err)
	}
	stats["total_scheduled_users"] = totalScheduledUsers

	// Template distribution
	query := `
		SELECT st.template_type, COUNT(si.schedule_instance_id) as count
		FROM schedule_instances si
		JOIN schedule_templates st ON si.schedule_template_id = st.schedule_template_id
		WHERE si.company_id = $1 AND si.schedule_date BETWEEN $2 AND $3
		GROUP BY st.template_type`

	rows, err := r.client.Query(ctx, query, companyID, startDate, endDate)
	if err != nil {
		return nil, fmt.Errorf("failed to get template distribution: %w", err)
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
	stats["template_distribution"] = templateStats

	return stats, nil
}

func (r *SchedulingRepositoryImpl) GetUserScheduleSummary(ctx context.Context, userID uuid.UUID, startDate, endDate time.Time) (map[string]interface{}, error) {
	stats := make(map[string]interface{})

	// Total scheduled days for user
	var totalScheduledDays int
	err := r.client.QueryRow(ctx, `
		SELECT COUNT(*) 
		FROM schedule_instances 
		WHERE user_id = $1 AND schedule_date BETWEEN $2 AND $3`,
		userID, startDate, endDate).Scan(&totalScheduledDays)
	if err != nil {
		return nil, fmt.Errorf("failed to get total scheduled days: %w", err)
	}
	stats["total_scheduled_days"] = totalScheduledDays

	// Current assignment
	currentAssignment, err := r.GetUserCurrentScheduleAssignment(ctx, userID, time.Now())
	if err == nil {
		stats["current_assignment"] = map[string]interface{}{
			"template_id":    currentAssignment.ScheduleTemplateID,
			"effective_from": currentAssignment.EffectiveFrom,
			"effective_to":   currentAssignment.EffectiveTo,
		}
	}

	// Schedule by template type
	query := `
		SELECT st.template_type, COUNT(*) as count
		FROM schedule_instances si
		JOIN schedule_templates st ON si.schedule_template_id = st.schedule_template_id
		WHERE si.user_id = $1 AND si.schedule_date BETWEEN $2 AND $3
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

	// Get template info
	template, err := r.GetScheduleTemplateByID(ctx, templateID)
	if err != nil {
		return nil, fmt.Errorf("failed to get template: %w", err)
	}
	stats["template"] = map[string]interface{}{
		"name":      template.Name,
		"type":      template.TemplateType,
		"is_active": template.IsActive,
	}

	// Total instances
	var totalInstances int
	err = r.client.QueryRow(ctx, `
		SELECT COUNT(*) 
		FROM schedule_instances 
		WHERE schedule_template_id = $1 AND schedule_date BETWEEN $2 AND $3`,
		templateID, startDate, endDate).Scan(&totalInstances)
	if err != nil {
		return nil, fmt.Errorf("failed to get total instances: %w", err)
	}
	stats["total_instances"] = totalInstances

	// Unique users
	var uniqueUsers int
	err = r.client.QueryRow(ctx, `
		SELECT COUNT(DISTINCT user_id) 
		FROM schedule_instances 
		WHERE schedule_template_id = $1 AND schedule_date BETWEEN $2 AND $3`,
		templateID, startDate, endDate).Scan(&uniqueUsers)
	if err != nil {
		return nil, fmt.Errorf("failed to get unique users: %w", err)
	}
	stats["unique_users"] = uniqueUsers

	// Daily utilization
	query := `
		SELECT schedule_date, COUNT(*) as count
		FROM schedule_instances 
		WHERE schedule_template_id = $1 AND schedule_date BETWEEN $2 AND $3
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

// ============================================================================
// HELPER METHODS - SCANNING
// ============================================================================

func (r *SchedulingRepositoryImpl) scanWorkCalendar(rows *sql.Rows) (*scheduling.WorkCalendar, error) {
	var calendar scheduling.WorkCalendar
	var holidaysJSON []byte
	var workingDays pq.Int64Array

	err := rows.Scan(
		&calendar.CalendarID,
		&calendar.CompanyID,
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

	// Convert working days
	calendar.WorkingDays = make([]int, len(workingDays))
	for i, day := range workingDays {
		calendar.WorkingDays[i] = int(day)
	}

	// Unmarshal holidays
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

	// Unmarshal rules
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

	// Handle nullable assigned_by
	if assignedBy.Valid && assignedBy.String != "" {
		parsedUUID, err := uuid.Parse(assignedBy.String)
		if err == nil {
			assignment.AssignedBy = &parsedUUID
		}
	}

	return &assignment, nil
}

func (r *SchedulingRepositoryImpl) scanScheduleInstance(rows *sql.Rows) (*scheduling.ScheduleInstance, error) {
	var instance scheduling.ScheduleInstance
	var expectedStart, expectedEnd sql.NullTime
	var metadataJSON []byte

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
	)

	if err != nil {
		return nil, err
	}

	// Handle nullable times
	if expectedStart.Valid {
		instance.ExpectedStart = &expectedStart.Time
	}
	if expectedEnd.Valid {
		instance.ExpectedEnd = &expectedEnd.Time
	}

	// Unmarshal metadata
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

// ============================================================================
// PREPARED STATEMENTS
// ============================================================================

func (r *SchedulingRepositoryImpl) initializePreparedStatements(ctx context.Context) {
	statements := map[string]string{
		"get_work_calendar_by_id": `
			SELECT calendar_id, company_id, name, timezone, working_days, holidays, 
			       is_active, created_at
			FROM work_calendars WHERE calendar_id = $1`,

		"get_schedule_template_by_id": `
			SELECT schedule_template_id, company_id, calendar_id, template_type, name, 
			       rules, is_active, created_at
			FROM schedule_templates WHERE schedule_template_id = $1`,

		"get_schedule_instance_by_id": `
			SELECT schedule_instance_id, company_id, user_id, schedule_date, 
			       schedule_template_id, expected_start, expected_end, timezone,
			       metadata, generated_at
			FROM schedule_instances WHERE schedule_instance_id = $1`,

		"get_user_current_schedule_assignment": `
			SELECT user_id, schedule_template_id, effective_from, effective_to, 
			       assigned_by, created_at
			FROM user_schedule_assignments 
			WHERE user_id = $1 
			  AND effective_from <= $2 
			  AND (effective_to IS NULL OR effective_to >= $2)
			ORDER BY effective_from DESC
			LIMIT 1`,
	}

	for name, query := range statements {
		stmt, err := r.client.DB.PrepareContext(ctx, query)
		if err != nil {
			r.logger.Warn("Failed to prepare statement",
				util.String("statement", name),
				util.ErrorField(err))
			continue
		}

		r.stmtMutex.Lock()
		r.stmtCache[name] = stmt
		r.stmtMutex.Unlock()
	}

	r.logger.Info("Scheduling prepared statements initialized",
		util.Int("statements", len(r.stmtCache)))
}

// getStmt retrieves a prepared statement from the cache
func (r *SchedulingRepositoryImpl) getStmt(name string) (*sql.Stmt, bool) {
	r.stmtMutex.RLock()
	defer r.stmtMutex.RUnlock()
	stmt, exists := r.stmtCache[name]
	return stmt, exists
}

// ============================================================================
// HEALTH CHECK
// ============================================================================

func (r *SchedulingRepositoryImpl) HealthCheck(ctx context.Context) error {
	// Simple query to check database connectivity
	query := `SELECT 1 FROM work_calendars LIMIT 1`
	_, err := r.client.Exec(ctx, query)
	if err != nil {
		return fmt.Errorf("scheduling repository health check failed: %w", err)
	}
	return nil
}

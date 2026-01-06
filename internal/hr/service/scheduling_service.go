// service/scheduling_service.go
package service

import (
	"auth-service/internal/hr/models/scheduling"
	"auth-service/internal/hr/repository"
	"auth-service/internal/util"
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"sync"
	"time"

	"github.com/google/uuid"
	"go.uber.org/zap"
)

// ============================================================================
// SERVICE TYPES
// ============================================================================

// WorkCalendarUpdate represents updates to a work calendar
type WorkCalendarUpdate struct {
	Name        *string              `json:"name,omitempty"`
	Timezone    *string              `json:"timezone,omitempty"`
	WorkingDays []int                `json:"working_days,omitempty"`
	Holidays    []scheduling.Holiday `json:"holidays,omitempty"`
	IsActive    *bool                `json:"is_active,omitempty"`
}

// ScheduleTemplateUpdate represents updates to a schedule template
type ScheduleTemplateUpdate struct {
	Name         *string                   `json:"name,omitempty"`
	CalendarID   *uuid.UUID                `json:"calendar_id,omitempty"`
	TemplateType *string                   `json:"template_type,omitempty"`
	Rules        *scheduling.TemplateRules `json:"rules,omitempty"`
	IsActive     *bool                     `json:"is_active,omitempty"`
}

// ScheduleInstanceUpdate represents updates to a schedule instance
type ScheduleInstanceUpdate struct {
	ExpectedStart *time.Time                   `json:"expected_start,omitempty"`
	ExpectedEnd   *time.Time                   `json:"expected_end,omitempty"`
	Timezone      *string                      `json:"timezone,omitempty"`
	Metadata      *scheduling.InstanceMetadata `json:"metadata,omitempty"`
}

// UserScheduleAssignmentUpdate represents updates to a user schedule assignment
type UserScheduleAssignmentUpdate struct {
	EffectiveTo *time.Time `json:"effective_to,omitempty"`
	AssignedBy  *uuid.UUID `json:"assigned_by,omitempty"`
}

// ScheduleGenerationConfig configuration for generating schedule instances
type ScheduleGenerationConfig struct {
	StartDate       time.Time `json:"start_date"`
	EndDate         time.Time `json:"end_date"`
	Timezone        string    `json:"timezone"`
	IncludeHolidays bool      `json:"include_holidays"`
	Overwrite       bool      `json:"overwrite"`
	BatchSize       int       `json:"batch_size"`
}

// ============================================================================
// SERVICE INTERFACE
// ============================================================================

// SchedulingService defines operations for scheduling management
type SchedulingService interface {
	// Work Calendar Management
	CreateWorkCalendar(ctx context.Context, calendar *scheduling.WorkCalendar, actorType string, actorID uuid.UUID, metadata map[string]interface{}) (*scheduling.WorkCalendar, error)
	UpdateWorkCalendar(ctx context.Context, calendarID uuid.UUID, update WorkCalendarUpdate, actorType string, actorID uuid.UUID, metadata map[string]interface{}) (*scheduling.WorkCalendar, error)
	DeleteWorkCalendar(ctx context.Context, calendarID uuid.UUID, actorType string, actorID uuid.UUID, metadata map[string]interface{}) error
	ValidateWorkCalendar(ctx context.Context, calendar *scheduling.WorkCalendar) error

	// Schedule Template Management
	CreateScheduleTemplate(ctx context.Context, template *scheduling.ScheduleTemplate, actorType string, actorID uuid.UUID, metadata map[string]interface{}) (*scheduling.ScheduleTemplate, error)
	UpdateScheduleTemplate(ctx context.Context, templateID uuid.UUID, update ScheduleTemplateUpdate, actorType string, actorID uuid.UUID, metadata map[string]interface{}) (*scheduling.ScheduleTemplate, error)
	DeleteScheduleTemplate(ctx context.Context, templateID uuid.UUID, actorType string, actorID uuid.UUID, metadata map[string]interface{}) error
	ValidateScheduleTemplate(ctx context.Context, template *scheduling.ScheduleTemplate) error

	// User Schedule Assignment Management
	AssignUserToTemplate(ctx context.Context, assignment *scheduling.UserScheduleAssignment, actorType string, actorID uuid.UUID, metadata map[string]interface{}) error
	UpdateUserScheduleAssignment(ctx context.Context, userID, templateID uuid.UUID, effectiveFrom time.Time, update UserScheduleAssignmentUpdate, actorType string, actorID uuid.UUID, metadata map[string]interface{}) error
	EndUserScheduleAssignment(ctx context.Context, userID, templateID uuid.UUID, endDate time.Time, actorType string, actorID uuid.UUID, metadata map[string]interface{}) error
	RemoveUserScheduleAssignment(ctx context.Context, userID, templateID uuid.UUID, effectiveFrom time.Time, actorType string, actorID uuid.UUID, metadata map[string]interface{}) error

	// Schedule Instance Management
	CreateScheduleInstance(ctx context.Context, instance *scheduling.ScheduleInstance, actorType string, actorID uuid.UUID, metadata map[string]interface{}) (*scheduling.ScheduleInstance, error)
	UpdateScheduleInstance(ctx context.Context, instanceID uuid.UUID, update ScheduleInstanceUpdate, actorType string, actorID uuid.UUID, metadata map[string]interface{}) (*scheduling.ScheduleInstance, error)
	DeleteScheduleInstance(ctx context.Context, instanceID uuid.UUID, actorType string, actorID uuid.UUID, metadata map[string]interface{}) error
	BulkCreateScheduleInstances(ctx context.Context, instances []*scheduling.ScheduleInstance, actorType string, actorID uuid.UUID, metadata map[string]interface{}) error

	// Schedule Generation
	GenerateScheduleForUser(ctx context.Context, userID uuid.UUID, config ScheduleGenerationConfig, actorType string, actorID uuid.UUID) ([]*scheduling.ScheduleInstance, error)
	GenerateScheduleForCompany(ctx context.Context, companyID uuid.UUID, config ScheduleGenerationConfig, actorType string, actorID uuid.UUID) ([]*scheduling.ScheduleInstance, error)
	GenerateScheduleForTemplate(ctx context.Context, templateID uuid.UUID, config ScheduleGenerationConfig, actorType string, actorID uuid.UUID) ([]*scheduling.ScheduleInstance, error)

	// Schedule Validation
	ValidateScheduleConflict(ctx context.Context, userID uuid.UUID, startTime, endTime time.Time, excludeInstanceID *uuid.UUID) (bool, error)
	CheckScheduleAvailability(ctx context.Context, userID uuid.UUID, date time.Time, timezone string) ([]time.Time, error)

	// Health Check
	HealthCheck(ctx context.Context) error
}

// ============================================================================
// SERVICE IMPLEMENTATION
// ============================================================================

type schedulingServiceImpl struct {
	schedulingRepo repository.SchedulingRepository
	auditService   *AuditService
	logger         *zap.Logger
	mu             sync.RWMutex
}

// NewSchedulingService creates a new scheduling service
func NewSchedulingService(
	schedulingRepo repository.SchedulingRepository,
	auditService *AuditService,
	logger *zap.Logger,
) SchedulingService {
	return &schedulingServiceImpl{
		schedulingRepo: schedulingRepo,
		auditService:   auditService,
		logger:         logger,
	}
}

// ============================================================================
// WORK CALENDAR MANAGEMENT
// ============================================================================

func (s *schedulingServiceImpl) CreateWorkCalendar(
	ctx context.Context,
	calendar *scheduling.WorkCalendar,
	actorType string,
	actorID uuid.UUID,
	metadata map[string]interface{},
) (*scheduling.WorkCalendar, error) {
	startTime := time.Now()

	// Validate calendar
	if err := s.validateWorkCalendar(calendar); err != nil {
		return nil, fmt.Errorf("work calendar validation failed: %w", err)
	}

	// Generate calendar ID if not provided
	if calendar.CalendarID == uuid.Nil {
		calendar.CalendarID = uuid.New()
	}

	// Set timestamps
	now := time.Now().UTC()
	if calendar.CreatedAt.IsZero() {
		calendar.CreatedAt = now
	}

	// Check for duplicate name in company
	existingCalendars, err := s.schedulingRepo.GetWorkCalendarsByCompany(ctx, calendar.CompanyID)
	if err == nil {
		for _, existing := range existingCalendars {
			if strings.EqualFold(existing.Name, calendar.Name) {
				return nil, fmt.Errorf("work calendar with name '%s' already exists", calendar.Name)
			}
		}
	}

	// Validate working days
	if err := s.validateWorkingDays(calendar.WorkingDays); err != nil {
		return nil, fmt.Errorf("invalid working days: %w", err)
	}

	// Validate holidays
	if err := s.validateHolidays(calendar.Holidays); err != nil {
		return nil, fmt.Errorf("invalid holidays: %w", err)
	}

	// Validate timezone
	if err := s.validateTimezone(calendar.Timezone); err != nil {
		return nil, fmt.Errorf("invalid timezone: %w", err)
	}

	// Create calendar in repository
	err = s.schedulingRepo.CreateWorkCalendar(ctx, calendar)
	if err != nil {
		s.logger.Error("Failed to create work calendar",
			util.String("company_id", calendar.CompanyID.String()),
			util.String("name", calendar.Name),
			util.ErrorField(err))
		return nil, fmt.Errorf("failed to create work calendar: %w", err)
	}

	// Log audit action
	if s.auditService != nil {
		go func() {
			auditCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()

			calendarJSON, _ := json.Marshal(calendar)
			s.auditService.LogAction(auditCtx,
				&calendar.CompanyID,
				"scheduling",
				"work_calendar.create",
				"work_calendar",
				&calendar.CalendarID,
				actorType,
				&actorID,
				nil,
				calendarJSON,
				metadata,
			)
		}()
	}

	s.logger.Info("Work calendar created",
		util.String("calendar_id", calendar.CalendarID.String()),
		util.String("company_id", calendar.CompanyID.String()),
		util.String("name", calendar.Name),
		util.String("timezone", calendar.Timezone),
		util.Int("working_days", len(calendar.WorkingDays)),
		util.Int("holidays", len(calendar.Holidays)),
		util.Duration("duration", time.Since(startTime)))

	return calendar, nil
}

func (s *schedulingServiceImpl) UpdateWorkCalendar(
	ctx context.Context,
	calendarID uuid.UUID,
	update WorkCalendarUpdate,
	actorType string,
	actorID uuid.UUID,
	metadata map[string]interface{},
) (*scheduling.WorkCalendar, error) {
	startTime := time.Now()

	// Get existing calendar
	calendar, err := s.schedulingRepo.GetWorkCalendarByID(ctx, calendarID)
	if err != nil {
		return nil, fmt.Errorf("work calendar not found: %w", err)
	}

	// Store before state for audit
	beforeState, _ := json.Marshal(calendar)

	// Apply updates
	if update.Name != nil {
		calendar.Name = *update.Name
	}
	if update.Timezone != nil {
		if err := s.validateTimezone(*update.Timezone); err != nil {
			return nil, fmt.Errorf("invalid timezone: %w", err)
		}
		calendar.Timezone = *update.Timezone
	}
	if update.WorkingDays != nil {
		if err := s.validateWorkingDays(update.WorkingDays); err != nil {
			return nil, fmt.Errorf("invalid working days: %w", err)
		}
		calendar.WorkingDays = update.WorkingDays
	}
	if update.Holidays != nil {
		if err := s.validateHolidays(update.Holidays); err != nil {
			return nil, fmt.Errorf("invalid holidays: %w", err)
		}
		calendar.Holidays = update.Holidays
	}
	if update.IsActive != nil {
		calendar.IsActive = *update.IsActive
	}

	// Validate updated calendar
	if err := s.validateWorkCalendar(calendar); err != nil {
		return nil, fmt.Errorf("work calendar validation failed: %w", err)
	}

	// Check for duplicate name (if name changed)
	if update.Name != nil && *update.Name != calendar.Name {
		existingCalendars, err := s.schedulingRepo.GetWorkCalendarsByCompany(ctx, calendar.CompanyID)
		if err == nil {
			for _, existing := range existingCalendars {
				if existing.CalendarID != calendarID && strings.EqualFold(existing.Name, *update.Name) {
					return nil, fmt.Errorf("work calendar with name '%s' already exists", *update.Name)
				}
			}
		}
	}

	// Update calendar in repository
	err = s.schedulingRepo.UpdateWorkCalendar(ctx, calendar)
	if err != nil {
		s.logger.Error("Failed to update work calendar",
			util.String("calendar_id", calendarID.String()),
			util.ErrorField(err))
		return nil, fmt.Errorf("failed to update work calendar: %w", err)
	}

	// Log audit action
	if s.auditService != nil {
		go func() {
			auditCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()

			afterState, _ := json.Marshal(calendar)
			s.auditService.LogAction(auditCtx,
				&calendar.CompanyID,
				"scheduling",
				"work_calendar.update",
				"work_calendar",
				&calendarID,
				actorType,
				&actorID,
				beforeState,
				afterState,
				metadata,
			)
		}()
	}

	s.logger.Info("Work calendar updated",
		util.String("calendar_id", calendarID.String()),
		util.String("company_id", calendar.CompanyID.String()),
		util.String("name", calendar.Name),
		util.Duration("duration", time.Since(startTime)))

	return calendar, nil
}

func (s *schedulingServiceImpl) DeleteWorkCalendar(
	ctx context.Context,
	calendarID uuid.UUID,
	actorType string,
	actorID uuid.UUID,
	metadata map[string]interface{},
) error {
	startTime := time.Now()

	// Get calendar for audit logging
	calendar, err := s.schedulingRepo.GetWorkCalendarByID(ctx, calendarID)
	if err != nil {
		return fmt.Errorf("work calendar not found: %w", err)
	}

	// Check if calendar is used by any schedule templates
	templates, err := s.schedulingRepo.GetScheduleTemplatesByCalendar(ctx, calendarID)
	if err == nil && len(templates) > 0 {
		return fmt.Errorf("cannot delete calendar used by %d schedule templates", len(templates))
	}

	// Store before state for audit
	beforeState, _ := json.Marshal(calendar)

	// Delete calendar
	err = s.schedulingRepo.DeleteWorkCalendar(ctx, calendarID)
	if err != nil {
		s.logger.Error("Failed to delete work calendar",
			util.String("calendar_id", calendarID.String()),
			util.ErrorField(err))
		return fmt.Errorf("failed to delete work calendar: %w", err)
	}

	// Log audit action
	if s.auditService != nil {
		go func() {
			auditCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()

			s.auditService.LogAction(auditCtx,
				&calendar.CompanyID,
				"scheduling",
				"work_calendar.delete",
				"work_calendar",
				&calendarID,
				actorType,
				&actorID,
				beforeState,
				nil,
				metadata,
			)
		}()
	}

	s.logger.Info("Work calendar deleted",
		util.String("calendar_id", calendarID.String()),
		util.String("company_id", calendar.CompanyID.String()),
		util.String("name", calendar.Name),
		util.Duration("duration", time.Since(startTime)))

	return nil
}

func (s *schedulingServiceImpl) ValidateWorkCalendar(ctx context.Context, calendar *scheduling.WorkCalendar) error {
	return s.validateWorkCalendar(calendar)
}

// ============================================================================
// SCHEDULE TEMPLATE MANAGEMENT
// ============================================================================

func (s *schedulingServiceImpl) CreateScheduleTemplate(
	ctx context.Context,
	template *scheduling.ScheduleTemplate,
	actorType string,
	actorID uuid.UUID,
	metadata map[string]interface{},
) (*scheduling.ScheduleTemplate, error) {
	startTime := time.Now()

	// Validate template
	if err := s.validateScheduleTemplate(template); err != nil {
		return nil, fmt.Errorf("schedule template validation failed: %w", err)
	}

	// Generate template ID if not provided
	if template.ScheduleTemplateID == uuid.Nil {
		template.ScheduleTemplateID = uuid.New()
	}

	// Set timestamps
	now := time.Now().UTC()
	if template.CreatedAt.IsZero() {
		template.CreatedAt = now
	}

	// Check for duplicate name in company
	existingTemplates, err := s.schedulingRepo.GetScheduleTemplatesByCompany(ctx, template.CompanyID)
	if err == nil {
		for _, existing := range existingTemplates {
			if strings.EqualFold(existing.Name, template.Name) {
				return nil, fmt.Errorf("schedule template with name '%s' already exists", template.Name)
			}
		}
	}

	// Validate calendar exists and belongs to same company
	calendar, err := s.schedulingRepo.GetWorkCalendarByID(ctx, template.CalendarID)
	if err != nil {
		return nil, fmt.Errorf("work calendar not found: %w", err)
	}
	if calendar.CompanyID != template.CompanyID {
		return nil, fmt.Errorf("calendar does not belong to company")
	}

	// Validate template rules
	if err := s.validateTemplateRules(template.TemplateType, &template.Rules); err != nil {
		return nil, fmt.Errorf("template rules validation failed: %w", err)
	}

	// Create template in repository
	err = s.schedulingRepo.CreateScheduleTemplate(ctx, template)
	if err != nil {
		s.logger.Error("Failed to create schedule template",
			util.String("company_id", template.CompanyID.String()),
			util.String("name", template.Name),
			util.ErrorField(err))
		return nil, fmt.Errorf("failed to create schedule template: %w", err)
	}

	// Log audit action
	if s.auditService != nil {
		go func() {
			auditCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()

			templateJSON, _ := json.Marshal(template)
			s.auditService.LogAction(auditCtx,
				&template.CompanyID,
				"scheduling",
				"schedule_template.create",
				"schedule_template",
				&template.ScheduleTemplateID,
				actorType,
				&actorID,
				nil,
				templateJSON,
				metadata,
			)
		}()
	}

	s.logger.Info("Schedule template created",
		util.String("template_id", template.ScheduleTemplateID.String()),
		util.String("company_id", template.CompanyID.String()),
		util.String("name", template.Name),
		util.String("template_type", template.TemplateType),
		util.String("calendar_id", template.CalendarID.String()),
		util.Duration("duration", time.Since(startTime)))

	return template, nil
}

func (s *schedulingServiceImpl) UpdateScheduleTemplate(
	ctx context.Context,
	templateID uuid.UUID,
	update ScheduleTemplateUpdate,
	actorType string,
	actorID uuid.UUID,
	metadata map[string]interface{},
) (*scheduling.ScheduleTemplate, error) {
	startTime := time.Now()

	// Get existing template
	template, err := s.schedulingRepo.GetScheduleTemplateByID(ctx, templateID)
	if err != nil {
		return nil, fmt.Errorf("schedule template not found: %w", err)
	}

	// Store before state for audit
	beforeState, _ := json.Marshal(template)

	// Apply updates
	if update.Name != nil {
		template.Name = *update.Name
	}
	if update.CalendarID != nil {
		// Validate calendar exists and belongs to same company
		calendar, err := s.schedulingRepo.GetWorkCalendarByID(ctx, *update.CalendarID)
		if err != nil {
			return nil, fmt.Errorf("work calendar not found: %w", err)
		}
		if calendar.CompanyID != template.CompanyID {
			return nil, fmt.Errorf("calendar does not belong to company")
		}
		template.CalendarID = *update.CalendarID
	}
	if update.TemplateType != nil {
		template.TemplateType = *update.TemplateType
	}
	if update.Rules != nil {
		if err := s.validateTemplateRules(template.TemplateType, update.Rules); err != nil {
			return nil, fmt.Errorf("template rules validation failed: %w", err)
		}
		template.Rules = *update.Rules
	}
	if update.IsActive != nil {
		template.IsActive = *update.IsActive
	}

	// Validate updated template
	if err := s.validateScheduleTemplate(template); err != nil {
		return nil, fmt.Errorf("schedule template validation failed: %w", err)
	}

	// Check for duplicate name (if name changed)
	if update.Name != nil && *update.Name != template.Name {
		existingTemplates, err := s.schedulingRepo.GetScheduleTemplatesByCompany(ctx, template.CompanyID)
		if err == nil {
			for _, existing := range existingTemplates {
				if existing.ScheduleTemplateID != templateID && strings.EqualFold(existing.Name, *update.Name) {
					return nil, fmt.Errorf("schedule template with name '%s' already exists", *update.Name)
				}
			}
		}
	}

	// Update template in repository
	err = s.schedulingRepo.UpdateScheduleTemplate(ctx, template)
	if err != nil {
		s.logger.Error("Failed to update schedule template",
			util.String("template_id", templateID.String()),
			util.ErrorField(err))
		return nil, fmt.Errorf("failed to update schedule template: %w", err)
	}

	// Log audit action
	if s.auditService != nil {
		go func() {
			auditCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()

			afterState, _ := json.Marshal(template)
			s.auditService.LogAction(auditCtx,
				&template.CompanyID,
				"scheduling",
				"schedule_template.update",
				"schedule_template",
				&templateID,
				actorType,
				&actorID,
				beforeState,
				afterState,
				metadata,
			)
		}()
	}

	s.logger.Info("Schedule template updated",
		util.String("template_id", templateID.String()),
		util.String("company_id", template.CompanyID.String()),
		util.String("name", template.Name),
		util.Duration("duration", time.Since(startTime)))

	return template, nil
}

func (s *schedulingServiceImpl) DeleteScheduleTemplate(
	ctx context.Context,
	templateID uuid.UUID,
	actorType string,
	actorID uuid.UUID,
	metadata map[string]interface{},
) error {
	startTime := time.Now()

	// Get template for audit logging
	template, err := s.schedulingRepo.GetScheduleTemplateByID(ctx, templateID)
	if err != nil {
		return fmt.Errorf("schedule template not found: %w", err)
	}

	// Check if template has active assignments
	assignments, err := s.schedulingRepo.GetAssignmentsByTemplate(ctx, templateID, true)
	if err == nil && len(assignments) > 0 {
		return fmt.Errorf("cannot delete template with %d active user assignments", len(assignments))
	}

	// Check if template has schedule instances
	instances, err := s.schedulingRepo.GetScheduleInstancesByTemplate(ctx, templateID,
		time.Now().AddDate(0, -1, 0), time.Now())
	if err == nil && len(instances) > 0 {
		return fmt.Errorf("cannot delete template with schedule instances")
	}

	// Store before state for audit
	beforeState, _ := json.Marshal(template)

	// Delete template
	err = s.schedulingRepo.DeleteScheduleTemplate(ctx, templateID)
	if err != nil {
		s.logger.Error("Failed to delete schedule template",
			util.String("template_id", templateID.String()),
			util.ErrorField(err))
		return fmt.Errorf("failed to delete schedule template: %w", err)
	}

	// Log audit action
	if s.auditService != nil {
		go func() {
			auditCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()

			s.auditService.LogAction(auditCtx,
				&template.CompanyID,
				"scheduling",
				"schedule_template.delete",
				"schedule_template",
				&templateID,
				actorType,
				&actorID,
				beforeState,
				nil,
				metadata,
			)
		}()
	}

	s.logger.Info("Schedule template deleted",
		util.String("template_id", templateID.String()),
		util.String("company_id", template.CompanyID.String()),
		util.String("name", template.Name),
		util.Duration("duration", time.Since(startTime)))

	return nil
}

func (s *schedulingServiceImpl) ValidateScheduleTemplate(ctx context.Context, template *scheduling.ScheduleTemplate) error {
	return s.validateScheduleTemplate(template)
}

// ============================================================================
// USER SCHEDULE ASSIGNMENT MANAGEMENT
// ============================================================================

func (s *schedulingServiceImpl) AssignUserToTemplate(
	ctx context.Context,
	assignment *scheduling.UserScheduleAssignment,
	actorType string,
	actorID uuid.UUID,
	metadata map[string]interface{},
) error {
	startTime := time.Now()

	// Validate assignment
	if assignment.UserID == uuid.Nil {
		return fmt.Errorf("user ID is required")
	}
	if assignment.ScheduleTemplateID == uuid.Nil {
		return fmt.Errorf("schedule template ID is required")
	}
	if assignment.EffectiveFrom.IsZero() {
		assignment.EffectiveFrom = time.Now().UTC()
	}

	// Check if template exists
	template, err := s.schedulingRepo.GetScheduleTemplateByID(ctx, assignment.ScheduleTemplateID)
	if err != nil {
		return fmt.Errorf("schedule template not found: %w", err)
	}

	// Check if user already has an active assignment
	currentAssignment, err := s.schedulingRepo.GetUserCurrentScheduleAssignment(ctx, assignment.UserID, assignment.EffectiveFrom)
	if err == nil && currentAssignment != nil {
		// End the current assignment if it's for a different template
		if currentAssignment.ScheduleTemplateID != assignment.ScheduleTemplateID {
			now := time.Now().UTC()
			currentAssignment.EffectiveTo = &now
			if err := s.schedulingRepo.UpdateUserScheduleAssignment(ctx, currentAssignment); err != nil {
				s.logger.Warn("Failed to end previous schedule assignment",
					util.String("user_id", assignment.UserID.String()),
					util.ErrorField(err))
			}
		} else {
			// Same template, check for overlapping assignment
			if currentAssignment.EffectiveFrom.Before(assignment.EffectiveFrom) &&
				(currentAssignment.EffectiveTo == nil || currentAssignment.EffectiveTo.After(assignment.EffectiveFrom)) {
				return fmt.Errorf("user already has an active assignment to this template")
			}
		}
	}

	// Set timestamps
	assignment.CreatedAt = time.Now().UTC()
	if assignment.AssignedBy == nil {
		assignment.AssignedBy = &actorID
	}

	// Create assignment
	err = s.schedulingRepo.CreateUserScheduleAssignment(ctx, assignment)
	if err != nil {
		s.logger.Error("Failed to assign user to schedule template",
			util.String("user_id", assignment.UserID.String()),
			util.String("template_id", assignment.ScheduleTemplateID.String()),
			util.ErrorField(err))
		return fmt.Errorf("failed to assign user to schedule template: %w", err)
	}

	// Log audit action
	if s.auditService != nil {
		go func() {
			auditCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()

			assignmentJSON, _ := json.Marshal(assignment)
			s.auditService.LogAction(auditCtx,
				&template.CompanyID,
				"scheduling",
				"user_schedule_assignment.create",
				"user_schedule_assignment",
				nil, // Composite key, no single entity ID
				actorType,
				&actorID,
				nil,
				assignmentJSON,
				metadata,
			)
		}()
	}

	s.logger.Info("User assigned to schedule template",
		util.String("user_id", assignment.UserID.String()),
		util.String("template_id", assignment.ScheduleTemplateID.String()),
		util.String("template_name", template.Name),
		util.Time("effective_from", assignment.EffectiveFrom),
		util.Duration("duration", time.Since(startTime)))

	return nil
}

func (s *schedulingServiceImpl) UpdateUserScheduleAssignment(
	ctx context.Context,
	userID, templateID uuid.UUID,
	effectiveFrom time.Time,
	update UserScheduleAssignmentUpdate,
	actorType string,
	actorID uuid.UUID,
	metadata map[string]interface{},
) error {
	startTime := time.Now()

	// Get existing assignment
	assignment, err := s.schedulingRepo.GetUserScheduleAssignment(ctx, userID, templateID, effectiveFrom)
	if err != nil {
		return fmt.Errorf("user schedule assignment not found: %w", err)
	}

	// Store before state for audit
	beforeState, _ := json.Marshal(assignment)

	// Apply updates
	if update.EffectiveTo != nil {
		// Validate effective to date is after effective from
		if !update.EffectiveTo.After(assignment.EffectiveFrom) {
			return fmt.Errorf("effective to date must be after effective from date")
		}
		assignment.EffectiveTo = update.EffectiveTo
	}
	if update.AssignedBy != nil {
		assignment.AssignedBy = update.AssignedBy
	}

	// Update assignment
	err = s.schedulingRepo.UpdateUserScheduleAssignment(ctx, assignment)
	if err != nil {
		s.logger.Error("Failed to update user schedule assignment",
			util.String("user_id", userID.String()),
			util.String("template_id", templateID.String()),
			util.ErrorField(err))
		return fmt.Errorf("failed to update user schedule assignment: %w", err)
	}

	// Log audit action
	if s.auditService != nil {
		go func() {
			auditCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()

			afterState, _ := json.Marshal(assignment)
			s.auditService.LogAction(auditCtx,
				nil, // Company ID not directly available
				"scheduling",
				"user_schedule_assignment.update",
				"user_schedule_assignment",
				nil,
				actorType,
				&actorID,
				beforeState,
				afterState,
				metadata,
			)
		}()
	}

	s.logger.Info("User schedule assignment updated",
		util.String("user_id", userID.String()),
		util.String("template_id", templateID.String()),
		util.Time("effective_from", effectiveFrom),
		util.Duration("duration", time.Since(startTime)))

	return nil
}

func (s *schedulingServiceImpl) EndUserScheduleAssignment(
	ctx context.Context,
	userID, templateID uuid.UUID,
	endDate time.Time,
	actorType string,
	actorID uuid.UUID,
	metadata map[string]interface{},
) error {
	startTime := time.Now()

	// Get template for audit logging
	template, err := s.schedulingRepo.GetScheduleTemplateByID(ctx, templateID)
	if err != nil {
		return fmt.Errorf("schedule template not found: %w", err)
	}

	// End the assignment
	err = s.schedulingRepo.EndUserScheduleAssignment(ctx, userID, templateID, endDate)
	if err != nil {
		s.logger.Error("Failed to end user schedule assignment",
			util.String("user_id", userID.String()),
			util.String("template_id", templateID.String()),
			util.ErrorField(err))
		return fmt.Errorf("failed to end user schedule assignment: %w", err)
	}

	// Log audit action
	if s.auditService != nil {
		go func() {
			auditCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()

			s.auditService.LogAction(auditCtx,
				&template.CompanyID,
				"scheduling",
				"user_schedule_assignment.end",
				"user_schedule_assignment",
				nil,
				actorType,
				&actorID,
				nil,
				nil,
				metadata,
			)
		}()
	}

	s.logger.Info("User schedule assignment ended",
		util.String("user_id", userID.String()),
		util.String("template_id", templateID.String()),
		util.Time("end_date", endDate),
		util.Duration("duration", time.Since(startTime)))

	return nil
}

func (s *schedulingServiceImpl) RemoveUserScheduleAssignment(
	ctx context.Context,
	userID, templateID uuid.UUID,
	effectiveFrom time.Time,
	actorType string,
	actorID uuid.UUID,
	metadata map[string]interface{},
) error {
	startTime := time.Now()

	// Get assignment for audit logging
	assignment, err := s.schedulingRepo.GetUserScheduleAssignment(ctx, userID, templateID, effectiveFrom)
	if err != nil {
		return fmt.Errorf("user schedule assignment not found: %w", err)
	}

	// Store before state for audit
	beforeState, _ := json.Marshal(assignment)

	// Delete assignment
	err = s.schedulingRepo.DeleteUserScheduleAssignment(ctx, userID, templateID, effectiveFrom)
	if err != nil {
		s.logger.Error("Failed to remove user schedule assignment",
			util.String("user_id", userID.String()),
			util.String("template_id", templateID.String()),
			util.ErrorField(err))
		return fmt.Errorf("failed to remove user schedule assignment: %w", err)
	}

	// Log audit action
	if s.auditService != nil {
		go func() {
			auditCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()

			s.auditService.LogAction(auditCtx,
				nil,
				"scheduling",
				"user_schedule_assignment.delete",
				"user_schedule_assignment",
				nil,
				actorType,
				&actorID,
				beforeState,
				nil,
				metadata,
			)
		}()
	}

	s.logger.Info("User schedule assignment removed",
		util.String("user_id", userID.String()),
		util.String("template_id", templateID.String()),
		util.Time("effective_from", effectiveFrom),
		util.Duration("duration", time.Since(startTime)))

	return nil
}

// ============================================================================
// SCHEDULE INSTANCE MANAGEMENT
// ============================================================================

func (s *schedulingServiceImpl) CreateScheduleInstance(
	ctx context.Context,
	instance *scheduling.ScheduleInstance,
	actorType string,
	actorID uuid.UUID,
	metadata map[string]interface{},
) (*scheduling.ScheduleInstance, error) {
	startTime := time.Now()

	// Validate instance
	if err := s.validateScheduleInstance(instance); err != nil {
		return nil, fmt.Errorf("schedule instance validation failed: %w", err)
	}

	// Generate instance ID if not provided
	if instance.ScheduleInstanceID == uuid.Nil {
		instance.ScheduleInstanceID = uuid.New()
	}

	// Set timestamps
	now := time.Now().UTC()
	if instance.GeneratedAt.IsZero() {
		instance.GeneratedAt = now
	}

	// Check for duplicate instance for user on same date
	existingInstance, err := s.schedulingRepo.GetScheduleInstanceByUserDate(ctx, instance.UserID, instance.ScheduleDate)
	if err == nil && existingInstance != nil {
		return nil, fmt.Errorf("schedule instance already exists for user on %s",
			instance.ScheduleDate.Format("2006-01-02"))
	}

	// Validate template exists
	template, err := s.schedulingRepo.GetScheduleTemplateByID(ctx, instance.ScheduleTemplateID)
	if err != nil {
		return nil, fmt.Errorf("schedule template not found: %w", err)
	}

	// Validate template belongs to same company
	if template.CompanyID != instance.CompanyID {
		return nil, fmt.Errorf("template does not belong to company")
	}

	// Validate timezone
	if err := s.validateTimezone(instance.Timezone); err != nil {
		return nil, fmt.Errorf("invalid timezone: %w", err)
	}

	// Calculate expected start/end times if not provided
	if instance.ExpectedStart == nil || instance.ExpectedEnd == nil {
		if err := s.calculateExpectedTimes(instance, template); err != nil {
			return nil, fmt.Errorf("failed to calculate expected times: %w", err)
		}
	}

	// Check for schedule conflicts
	hasConflict, err := s.ValidateScheduleConflict(ctx, instance.UserID, *instance.ExpectedStart, *instance.ExpectedEnd, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to check schedule conflict: %w", err)
	}
	if hasConflict {
		return nil, fmt.Errorf("schedule conflict detected")
	}

	// Create instance
	err = s.schedulingRepo.CreateScheduleInstance(ctx, instance)
	if err != nil {
		s.logger.Error("Failed to create schedule instance",
			util.String("user_id", instance.UserID.String()),
			util.String("date", instance.ScheduleDate.Format("2006-01-02")),
			util.ErrorField(err))
		return nil, fmt.Errorf("failed to create schedule instance: %w", err)
	}

	// Log audit action
	if s.auditService != nil {
		go func() {
			auditCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()

			instanceJSON, _ := json.Marshal(instance)
			s.auditService.LogAction(auditCtx,
				&instance.CompanyID,
				"scheduling",
				"schedule_instance.create",
				"schedule_instance",
				&instance.ScheduleInstanceID,
				actorType,
				&actorID,
				nil,
				instanceJSON,
				metadata,
			)
		}()
	}

	s.logger.Info("Schedule instance created",
		util.String("instance_id", instance.ScheduleInstanceID.String()),
		util.String("user_id", instance.UserID.String()),
		util.String("template_id", instance.ScheduleTemplateID.String()),
		util.String("date", instance.ScheduleDate.Format("2006-01-02")),
		util.Duration("duration", time.Since(startTime)))

	return instance, nil
}

func (s *schedulingServiceImpl) UpdateScheduleInstance(
	ctx context.Context,
	instanceID uuid.UUID,
	update ScheduleInstanceUpdate,
	actorType string,
	actorID uuid.UUID,
	metadata map[string]interface{},
) (*scheduling.ScheduleInstance, error) {
	startTime := time.Now()

	// Get existing instance
	instance, err := s.schedulingRepo.GetScheduleInstanceByID(ctx, instanceID)
	if err != nil {
		return nil, fmt.Errorf("schedule instance not found: %w", err)
	}

	// Store before state for audit
	beforeState, _ := json.Marshal(instance)

	// Apply updates
	if update.ExpectedStart != nil {
		instance.ExpectedStart = update.ExpectedStart
	}
	if update.ExpectedEnd != nil {
		instance.ExpectedEnd = update.ExpectedEnd
	}
	if update.Timezone != nil {
		if err := s.validateTimezone(*update.Timezone); err != nil {
			return nil, fmt.Errorf("invalid timezone: %w", err)
		}
		instance.Timezone = *update.Timezone
	}
	if update.Metadata != nil {
		instance.Metadata = *update.Metadata
	}

	// Validate updated instance
	if err := s.validateScheduleInstance(instance); err != nil {
		return nil, fmt.Errorf("schedule instance validation failed: %w", err)
	}

	// Check for schedule conflicts (excluding this instance)
	if instance.ExpectedStart != nil && instance.ExpectedEnd != nil {
		hasConflict, err := s.ValidateScheduleConflict(ctx, instance.UserID, *instance.ExpectedStart, *instance.ExpectedEnd, &instanceID)
		if err != nil {
			return nil, fmt.Errorf("failed to check schedule conflict: %w", err)
		}
		if hasConflict {
			return nil, fmt.Errorf("schedule conflict detected")
		}
	}

	// Update instance
	err = s.schedulingRepo.UpdateScheduleInstance(ctx, instance)
	if err != nil {
		s.logger.Error("Failed to update schedule instance",
			util.String("instance_id", instanceID.String()),
			util.ErrorField(err))
		return nil, fmt.Errorf("failed to update schedule instance: %w", err)
	}

	// Log audit action
	if s.auditService != nil {
		go func() {
			auditCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()

			afterState, _ := json.Marshal(instance)
			s.auditService.LogAction(auditCtx,
				&instance.CompanyID,
				"scheduling",
				"schedule_instance.update",
				"schedule_instance",
				&instanceID,
				actorType,
				&actorID,
				beforeState,
				afterState,
				metadata,
			)
		}()
	}

	s.logger.Info("Schedule instance updated",
		util.String("instance_id", instanceID.String()),
		util.String("user_id", instance.UserID.String()),
		util.Duration("duration", time.Since(startTime)))

	return instance, nil
}

func (s *schedulingServiceImpl) DeleteScheduleInstance(
	ctx context.Context,
	instanceID uuid.UUID,
	actorType string,
	actorID uuid.UUID,
	metadata map[string]interface{},
) error {
	startTime := time.Now()

	// Get instance for audit logging
	instance, err := s.schedulingRepo.GetScheduleInstanceByID(ctx, instanceID)
	if err != nil {
		return fmt.Errorf("schedule instance not found: %w", err)
	}

	// Store before state for audit
	beforeState, _ := json.Marshal(instance)

	// Delete instance
	err = s.schedulingRepo.DeleteScheduleInstance(ctx, instanceID)
	if err != nil {
		s.logger.Error("Failed to delete schedule instance",
			util.String("instance_id", instanceID.String()),
			util.ErrorField(err))
		return fmt.Errorf("failed to delete schedule instance: %w", err)
	}

	// Log audit action
	if s.auditService != nil {
		go func() {
			auditCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()

			s.auditService.LogAction(auditCtx,
				&instance.CompanyID,
				"scheduling",
				"schedule_instance.delete",
				"schedule_instance",
				&instanceID,
				actorType,
				&actorID,
				beforeState,
				nil,
				metadata,
			)
		}()
	}

	s.logger.Info("Schedule instance deleted",
		util.String("instance_id", instanceID.String()),
		util.String("user_id", instance.UserID.String()),
		util.String("date", instance.ScheduleDate.Format("2006-01-02")),
		util.Duration("duration", time.Since(startTime)))

	return nil
}

func (s *schedulingServiceImpl) BulkCreateScheduleInstances(
	ctx context.Context,
	instances []*scheduling.ScheduleInstance,
	actorType string,
	actorID uuid.UUID,
	metadata map[string]interface{},
) error {
	startTime := time.Now()

	if len(instances) == 0 {
		return fmt.Errorf("no instances provided for bulk creation")
	}

	companyID := instances[0].CompanyID

	// Validate all instances before batch insert
	for i, instance := range instances {
		// Validate each instance
		if err := s.validateScheduleInstance(instance); err != nil {
			return fmt.Errorf("instance %d validation failed: %w", i, err)
		}

		// Generate instance ID if not provided
		if instance.ScheduleInstanceID == uuid.Nil {
			instance.ScheduleInstanceID = uuid.New()
		}

		// Set timestamps
		now := time.Now().UTC()
		if instance.GeneratedAt.IsZero() {
			instance.GeneratedAt = now
		}

		// Check for duplicate instance for user on same date
		existingInstance, err := s.schedulingRepo.GetScheduleInstanceByUserDate(ctx, instance.UserID, instance.ScheduleDate)
		if err == nil && existingInstance != nil {
			return fmt.Errorf("instance %d: schedule already exists for user %s on %s",
				i, instance.UserID, instance.ScheduleDate.Format("2006-01-02"))
		}
	}

	// Create instances in batch
	err := s.schedulingRepo.BulkCreateScheduleInstances(ctx, instances)
	if err != nil {
		s.logger.Error("Failed to create bulk schedule instances",
			util.Int("instance_count", len(instances)),
			util.String("company_id", companyID.String()),
			util.ErrorField(err))
		return fmt.Errorf("failed to create bulk schedule instances: %w", err)
	}

	// Log audit action (single audit for bulk operation)
	if s.auditService != nil {
		go func() {
			auditCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()

			s.auditService.LogAction(auditCtx,
				&companyID,
				"scheduling",
				"schedule_instance.bulk_create",
				"schedule_instance",
				nil,
				actorType,
				&actorID,
				nil,
				nil,
				map[string]interface{}{
					"instance_count": len(instances),
					"company_id":     companyID.String(),
					"metadata":       metadata,
				},
			)
		}()
	}

	s.logger.Info("Bulk schedule instances created",
		util.Int("instance_count", len(instances)),
		util.String("company_id", companyID.String()),
		util.String("actor_type", actorType),
		util.String("actor_id", actorID.String()),
		util.Duration("duration", time.Since(startTime)))

	return nil
}

// ============================================================================
// SCHEDULE GENERATION
// ============================================================================

func (s *schedulingServiceImpl) GenerateScheduleForUser(
	ctx context.Context,
	userID uuid.UUID,
	config ScheduleGenerationConfig,
	actorType string,
	actorID uuid.UUID,
) ([]*scheduling.ScheduleInstance, error) {
	startTime := time.Now()

	// Validate configuration
	if err := s.validateScheduleGenerationConfig(config); err != nil {
		return nil, fmt.Errorf("invalid schedule generation config: %w", err)
	}

	// Get user's current schedule assignment
	assignment, err := s.schedulingRepo.GetUserCurrentScheduleAssignment(ctx, userID, config.StartDate)
	if err != nil {
		return nil, fmt.Errorf("no active schedule assignment found for user: %w", err)
	}

	// Get schedule template
	template, err := s.schedulingRepo.GetScheduleTemplateByID(ctx, assignment.ScheduleTemplateID)
	if err != nil {
		return nil, fmt.Errorf("schedule template not found: %w", err)
	}

	// Get work calendar
	calendar, err := s.schedulingRepo.GetWorkCalendarByID(ctx, template.CalendarID)
	if err != nil {
		return nil, fmt.Errorf("work calendar not found: %w", err)
	}

	// Generate schedule instances
	instances, err := s.generateScheduleInstances(ctx, userID, template, calendar, config)
	if err != nil {
		return nil, fmt.Errorf("failed to generate schedule instances: %w", err)
	}

	// Create instances
	if !config.Overwrite {
		// Check for existing instances
		for _, instance := range instances {
			existing, err := s.schedulingRepo.GetScheduleInstanceByUserDate(ctx, userID, instance.ScheduleDate)
			if err == nil && existing != nil {
				return nil, fmt.Errorf("schedule already exists for %s",
					instance.ScheduleDate.Format("2006-01-02"))
			}
		}
	} else {
		// Delete existing instances for the date range
		existingInstances, err := s.schedulingRepo.GetScheduleInstancesByUser(ctx, userID,
			config.StartDate, config.EndDate)
		if err == nil && len(existingInstances) > 0 {
			for _, existing := range existingInstances {
				if err := s.schedulingRepo.DeleteScheduleInstance(ctx, existing.ScheduleInstanceID); err != nil {
					s.logger.Warn("Failed to delete existing schedule instance",
						util.String("instance_id", existing.ScheduleInstanceID.String()),
						util.ErrorField(err))
				}
			}
		}
	}

	// Create instances in batches
	batchSize := config.BatchSize
	if batchSize <= 0 {
		batchSize = 100
	}

	for i := 0; i < len(instances); i += batchSize {
		end := i + batchSize
		if end > len(instances) {
			end = len(instances)
		}

		batch := instances[i:end]
		if err := s.schedulingRepo.BulkCreateScheduleInstances(ctx, batch); err != nil {
			return nil, fmt.Errorf("failed to create batch of schedule instances: %w", err)
		}
	}

	s.logger.Info("Schedule generated for user",
		util.String("user_id", userID.String()),
		util.String("template_id", template.ScheduleTemplateID.String()),
		util.Time("start_date", config.StartDate),
		util.Time("end_date", config.EndDate),
		util.Int("instance_count", len(instances)),
		util.Duration("duration", time.Since(startTime)))

	return instances, nil
}

func (s *schedulingServiceImpl) GenerateScheduleForCompany(
	ctx context.Context,
	companyID uuid.UUID,
	config ScheduleGenerationConfig,
	actorType string,
	actorID uuid.UUID,
) ([]*scheduling.ScheduleInstance, error) {
	// TODO: Implement company-wide schedule generation
	// This would involve getting all users with schedule assignments and generating schedules for each
	s.logger.Info("Company schedule generation requested",
		util.String("company_id", companyID.String()),
		util.Time("start_date", config.StartDate),
		util.Time("end_date", config.EndDate))

	return nil, fmt.Errorf("company schedule generation not yet implemented")
}

func (s *schedulingServiceImpl) GenerateScheduleForTemplate(
	ctx context.Context,
	templateID uuid.UUID,
	config ScheduleGenerationConfig,
	actorType string,
	actorID uuid.UUID,
) ([]*scheduling.ScheduleInstance, error) {
	// TODO: Implement template-based schedule generation
	// This would involve getting all users assigned to the template and generating schedules for each
	s.logger.Info("Template schedule generation requested",
		util.String("template_id", templateID.String()),
		util.Time("start_date", config.StartDate),
		util.Time("end_date", config.EndDate))

	return nil, fmt.Errorf("template schedule generation not yet implemented")
}

// ============================================================================
// SCHEDULE VALIDATION
// ============================================================================

func (s *schedulingServiceImpl) ValidateScheduleConflict(
	ctx context.Context,
	userID uuid.UUID,
	startTime, endTime time.Time,
	excludeInstanceID *uuid.UUID,
) (bool, error) {
	// Get all schedule instances for the user that overlap with the time range
	// This is a simplified check - in production, you'd want to check against
	// existing schedule instances for overlapping times

	s.logger.Debug("Checking schedule conflict",
		util.String("user_id", userID.String()),
		util.Time("start_time", startTime),
		util.Time("end_time", endTime))

	// TODO: Implement proper schedule conflict checking
	// This would involve querying the database for overlapping schedule instances

	return false, nil
}

func (s *schedulingServiceImpl) CheckScheduleAvailability(
	ctx context.Context,
	userID uuid.UUID,
	date time.Time,
	timezone string,
) ([]time.Time, error) {
	// Get schedule instance for the date
	instance, err := s.schedulingRepo.GetScheduleInstanceByUserDate(ctx, userID, date)
	if err != nil {
		// No schedule for this date
		return []time.Time{}, nil
	}

	if instance.ExpectedStart == nil || instance.ExpectedEnd == nil {
		return []time.Time{}, nil
	}

	// Convert times to local timezone
	loc, err := time.LoadLocation(timezone)
	if err != nil {
		loc = time.UTC
	}

	startLocal := instance.ExpectedStart.In(loc)
	endLocal := instance.ExpectedEnd.In(loc)

	// Return the scheduled time slot
	return []time.Time{startLocal, endLocal}, nil
}

// ============================================================================
// HELPER METHODS
// ============================================================================

func (s *schedulingServiceImpl) validateWorkCalendar(calendar *scheduling.WorkCalendar) error {
	if calendar.CompanyID == uuid.Nil {
		return fmt.Errorf("company ID is required")
	}
	if calendar.Name == "" {
		return fmt.Errorf("name is required")
	}
	if calendar.Timezone == "" {
		return fmt.Errorf("timezone is required")
	}
	if len(calendar.WorkingDays) == 0 {
		return fmt.Errorf("working days are required")
	}
	return nil
}

func (s *schedulingServiceImpl) validateWorkingDays(days []int) error {
	validDays := map[int]bool{0: true, 1: true, 2: true, 3: true, 4: true, 5: true, 6: true}

	for _, day := range days {
		if day < 0 || day > 6 {
			return fmt.Errorf("invalid day number: %d (must be 0-6)", day)
		}
		if !validDays[day] {
			return fmt.Errorf("invalid day: %d", day)
		}
	}
	return nil
}

func (s *schedulingServiceImpl) validateHolidays(holidays []scheduling.Holiday) error {
	for _, holiday := range holidays {
		if holiday.Date == "" {
			return fmt.Errorf("holiday date is required")
		}
		if holiday.Name == "" {
			return fmt.Errorf("holiday name is required")
		}

		// Validate date format (YYYY-MM-DD)
		_, err := time.Parse("2006-01-02", holiday.Date)
		if err != nil {
			return fmt.Errorf("invalid holiday date format: %s (must be YYYY-MM-DD)", holiday.Date)
		}
	}
	return nil
}

func (s *schedulingServiceImpl) validateTimezone(timezone string) error {
	_, err := time.LoadLocation(timezone)
	if err != nil {
		return fmt.Errorf("invalid timezone: %s", timezone)
	}
	return nil
}

func (s *schedulingServiceImpl) validateScheduleTemplate(template *scheduling.ScheduleTemplate) error {
	if template.CompanyID == uuid.Nil {
		return fmt.Errorf("company ID is required")
	}
	if template.CalendarID == uuid.Nil {
		return fmt.Errorf("calendar ID is required")
	}
	if template.TemplateType == "" {
		return fmt.Errorf("template type is required")
	}
	if template.Name == "" {
		return fmt.Errorf("name is required")
	}

	// Validate template type
	validTypes := map[string]bool{
		"office": true,
		"shift":  true,
		"class":  true,
	}
	if !validTypes[template.TemplateType] {
		return fmt.Errorf("invalid template type: %s", template.TemplateType)
	}

	return nil
}

func (s *schedulingServiceImpl) validateTemplateRules(templateType string, rules *scheduling.TemplateRules) error {
	switch templateType {
	case "office":
		if rules.StartTime == nil || *rules.StartTime == "" {
			return fmt.Errorf("start time is required for office template")
		}
		if rules.EndTime == nil || *rules.EndTime == "" {
			return fmt.Errorf("end time is required for office template")
		}

		// Validate time format (HH:MM)
		if _, err := time.Parse("15:04", *rules.StartTime); err != nil {
			return fmt.Errorf("invalid start time format: %s", *rules.StartTime)
		}
		if _, err := time.Parse("15:04", *rules.EndTime); err != nil {
			return fmt.Errorf("invalid end time format: %s", *rules.EndTime)
		}

	case "shift":
		if rules.BreakMinutes == nil {
			return fmt.Errorf("break minutes are required for shift template")
		}
		if *rules.BreakMinutes < 0 {
			return fmt.Errorf("break minutes cannot be negative")
		}

	case "class":
		if len(rules.Periods) == 0 {
			return fmt.Errorf("periods are required for class template")
		}

		// Validate periods
		for i, period := range rules.Periods {
			if period.Period <= 0 {
				return fmt.Errorf("period number must be positive for period %d", i)
			}
			if period.Start == "" {
				return fmt.Errorf("start time is required for period %d", i)
			}
			if period.End == "" {
				return fmt.Errorf("end time is required for period %d", i)
			}

			// Validate time format
			if _, err := time.Parse("15:04", period.Start); err != nil {
				return fmt.Errorf("invalid start time format for period %d: %s", i, period.Start)
			}
			if _, err := time.Parse("15:04", period.End); err != nil {
				return fmt.Errorf("invalid end time format for period %d: %s", i, period.End)
			}
		}
	}
	return nil
}

func (s *schedulingServiceImpl) validateScheduleInstance(instance *scheduling.ScheduleInstance) error {
	if instance.CompanyID == uuid.Nil {
		return fmt.Errorf("company ID is required")
	}
	if instance.UserID == uuid.Nil {
		return fmt.Errorf("user ID is required")
	}
	if instance.ScheduleTemplateID == uuid.Nil {
		return fmt.Errorf("schedule template ID is required")
	}
	if instance.ScheduleDate.IsZero() {
		return fmt.Errorf("schedule date is required")
	}
	if instance.Timezone == "" {
		return fmt.Errorf("timezone is required")
	}

	// Validate date is not in the past (optional business rule)
	if instance.ScheduleDate.Before(time.Now().AddDate(0, 0, -1)) {
		return fmt.Errorf("cannot schedule in the past")
	}

	return nil
}

func (s *schedulingServiceImpl) validateScheduleGenerationConfig(config ScheduleGenerationConfig) error {
	if config.StartDate.IsZero() {
		return fmt.Errorf("start date is required")
	}
	if config.EndDate.IsZero() {
		return fmt.Errorf("end date is required")
	}
	if config.StartDate.After(config.EndDate) {
		return fmt.Errorf("start date cannot be after end date")
	}

	// Limit date range (e.g., 90 days max)
	maxDays := 90
	if config.EndDate.Sub(config.StartDate).Hours()/24 > float64(maxDays) {
		return fmt.Errorf("date range cannot exceed %d days", maxDays)
	}

	if config.Timezone == "" {
		config.Timezone = "UTC"
	}

	if err := s.validateTimezone(config.Timezone); err != nil {
		return fmt.Errorf("invalid timezone: %w", err)
	}

	return nil
}

func (s *schedulingServiceImpl) calculateExpectedTimes(instance *scheduling.ScheduleInstance, template *scheduling.ScheduleTemplate) error {
	loc, err := time.LoadLocation(instance.Timezone)
	if err != nil {
		loc = time.UTC
	}

	// Parse the schedule date in the instance timezone
	scheduleDate := time.Date(instance.ScheduleDate.Year(), instance.ScheduleDate.Month(),
		instance.ScheduleDate.Day(), 0, 0, 0, 0, loc)

	switch template.TemplateType {
	case "office":
		if template.Rules.StartTime != nil && template.Rules.EndTime != nil {
			startTime, _ := time.Parse("15:04", *template.Rules.StartTime)
			endTime, _ := time.Parse("15:04", *template.Rules.EndTime)

			expectedStart := time.Date(scheduleDate.Year(), scheduleDate.Month(), scheduleDate.Day(),
				startTime.Hour(), startTime.Minute(), 0, 0, loc)
			expectedEnd := time.Date(scheduleDate.Year(), scheduleDate.Month(), scheduleDate.Day(),
				endTime.Hour(), endTime.Minute(), 0, 0, loc)

			instance.ExpectedStart = &expectedStart
			instance.ExpectedEnd = &expectedEnd
		}

	case "shift":
		// For shift templates, we might need additional logic
		// This is a simplified example
		defaultStart := time.Date(scheduleDate.Year(), scheduleDate.Month(), scheduleDate.Day(),
			9, 0, 0, 0, loc)
		defaultEnd := time.Date(scheduleDate.Year(), scheduleDate.Month(), scheduleDate.Day(),
			17, 0, 0, 0, loc)

		instance.ExpectedStart = &defaultStart
		instance.ExpectedEnd = &defaultEnd

	case "class":
		// For class templates, use the first period as default
		if len(template.Rules.Periods) > 0 {
			period := template.Rules.Periods[0]
			startTime, _ := time.Parse("15:04", period.Start)
			endTime, _ := time.Parse("15:04", period.End)

			expectedStart := time.Date(scheduleDate.Year(), scheduleDate.Month(), scheduleDate.Day(),
				startTime.Hour(), startTime.Minute(), 0, 0, loc)
			expectedEnd := time.Date(scheduleDate.Year(), scheduleDate.Month(), scheduleDate.Day(),
				endTime.Hour(), endTime.Minute(), 0, 0, loc)

			instance.ExpectedStart = &expectedStart
			instance.ExpectedEnd = &expectedEnd
		}
	}

	return nil
}

func (s *schedulingServiceImpl) generateScheduleInstances(
	ctx context.Context,
	userID uuid.UUID,
	template *scheduling.ScheduleTemplate,
	calendar *scheduling.WorkCalendar,
	config ScheduleGenerationConfig,
) ([]*scheduling.ScheduleInstance, error) {
	var instances []*scheduling.ScheduleInstance

	loc, err := time.LoadLocation(config.Timezone)
	if err != nil {
		loc = time.UTC
	}

	// Convert holidays to map for quick lookup
	holidayMap := make(map[string]bool)
	if !config.IncludeHolidays {
		for _, holiday := range calendar.Holidays {
			holidayMap[holiday.Date] = true
		}
	}

	// Generate instances for each day in the range
	for currentDate := config.StartDate; !currentDate.After(config.EndDate); currentDate = currentDate.AddDate(0, 0, 1) {
		// Check if it's a working day
		currentDateInLoc := currentDate.In(loc)
		weekday := int(currentDateInLoc.Weekday())

		isWorkingDay := false
		for _, day := range calendar.WorkingDays {
			if day == weekday {
				isWorkingDay = true
				break
			}
		}

		if !isWorkingDay {
			continue
		}

		// Check if it's a holiday
		dateStr := currentDateInLoc.Format("2006-01-02")
		if holidayMap[dateStr] {
			continue
		}

		// Create schedule instance
		instance := &scheduling.ScheduleInstance{
			ScheduleInstanceID: uuid.New(),
			CompanyID:          template.CompanyID,
			UserID:             userID,
			ScheduleDate:       currentDate,
			ScheduleTemplateID: template.ScheduleTemplateID,
			Timezone:           config.Timezone,
			Metadata:           scheduling.InstanceMetadata{},
			GeneratedAt:        time.Now().UTC(),
		}

		// Calculate expected times
		if err := s.calculateExpectedTimes(instance, template); err != nil {
			s.logger.Warn("Failed to calculate expected times",
				util.String("user_id", userID.String()),
				util.String("date", dateStr),
				util.ErrorField(err))
			continue
		}

		instances = append(instances, instance)
	}

	return instances, nil
}

// ============================================================================
// HEALTH CHECK
// ============================================================================

func (s *schedulingServiceImpl) HealthCheck(ctx context.Context) error {
	if err := s.schedulingRepo.HealthCheck(ctx); err != nil {
		return fmt.Errorf("scheduling repository health check failed: %w", err)
	}
	return nil
}

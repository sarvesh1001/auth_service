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
	AssignUserToTemplate(
		ctx context.Context,
		companyID uuid.UUID, // Add company ID parameter
		assignment *scheduling.UserScheduleAssignment,
		actorType string,
		actorID uuid.UUID,
		metadata map[string]interface{},
	) error

	// User Schedule Assignment Management
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
	CreateOffEntitlement(ctx context.Context, companyID uuid.UUID, entitlement *scheduling.UserOffEntitlement, actorType string, actorID uuid.UUID, metadata map[string]interface{}) (*scheduling.UserOffEntitlement, error)
	UpdateOffEntitlement(ctx context.Context, entitlementID uuid.UUID, update scheduling.OffEntitlementUpdate, actorType string, actorID uuid.UUID, metadata map[string]interface{}) (*scheduling.UserOffEntitlement, error)
	DeleteOffEntitlement(ctx context.Context, entitlementID uuid.UUID, actorType string, actorID uuid.UUID, metadata map[string]interface{}) error
	GetUserOffBalance(ctx context.Context, userID uuid.UUID, periodType string, startDate, endDate time.Time) (map[string]interface{}, error)

	// Off Requests
	CreateOffRequest(ctx context.Context, companyID uuid.UUID, request *scheduling.OffRequest, actorType string, actorID uuid.UUID, metadata map[string]interface{}) (*scheduling.OffRequest, error)
	UpdateOffRequest(ctx context.Context, requestID uuid.UUID, update scheduling.OffRequestUpdate, actorType string, actorID uuid.UUID, metadata map[string]interface{}) (*scheduling.OffRequest, error)
	DeleteOffRequest(ctx context.Context, requestID uuid.UUID, actorType string, actorID uuid.UUID, metadata map[string]interface{}) error
	ApproveOffRequest(ctx context.Context, requestID uuid.UUID, approvedBy uuid.UUID, actorType string, actorID uuid.UUID, metadata map[string]interface{}) error
	RejectOffRequest(ctx context.Context, requestID uuid.UUID, rejectedBy uuid.UUID, actorType string, actorID uuid.UUID, metadata map[string]interface{}) error
	ValidateOffRequest(ctx context.Context, userID uuid.UUID, requestDates []string, excludeRequestID *uuid.UUID) error

	// Schedule Overrides
	CreateScheduleOverride(ctx context.Context, companyID uuid.UUID, override *scheduling.ScheduleOverride, actorType string, actorID uuid.UUID, metadata map[string]interface{}) (*scheduling.ScheduleOverride, error)
	UpdateScheduleOverride(ctx context.Context, overrideID uuid.UUID, update scheduling.ScheduleOverrideUpdate, actorType string, actorID uuid.UUID, metadata map[string]interface{}) (*scheduling.ScheduleOverride, error)
	DeleteScheduleOverride(ctx context.Context, overrideID uuid.UUID, actorType string, actorID uuid.UUID, metadata map[string]interface{}) error
	GetScheduleOverridesByUser(ctx context.Context, userID uuid.UUID, startDate, endDate time.Time) ([]*scheduling.ScheduleOverride, error)

	// Combined Operations
	RequestTimeOff(ctx context.Context, companyID, userID uuid.UUID, requestDates []string, reason string, actorType string, actorID uuid.UUID) (*scheduling.OffRequest, error)
	GetUserTimeOffSummary(ctx context.Context, userID uuid.UUID, startDate, endDate time.Time) (map[string]interface{}, error)
	// Health Check
	CheckDateAvailability(ctx context.Context, userID uuid.UUID, date time.Time) (map[string]interface{}, error) // CHANGED: removed timezone parameter, changed return type

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

	// Validate calendar (now includes Year)
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

	// Enforce UNIQUE (company_id, year)
	existingCalendars, err := s.schedulingRepo.GetWorkCalendarsByCompany(ctx, calendar.CompanyID)
	if err == nil {
		for _, existing := range existingCalendars {
			if existing.Year == calendar.Year {
				return nil, fmt.Errorf(
					"work calendar already exists for year %d",
					calendar.Year,
				)
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

	// Create calendar
	if err := s.schedulingRepo.CreateWorkCalendar(ctx, calendar); err != nil {
		s.logger.Error("Failed to create work calendar",
			util.String("company_id", calendar.CompanyID.String()),
			util.String("name", calendar.Name),
			util.Int("year", calendar.Year),
			util.ErrorField(err))
		return nil, fmt.Errorf("failed to create work calendar: %w", err)
	}

	// Audit
	if s.auditService != nil {
		go func() {
			auditCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()

			calendarJSON, _ := json.Marshal(calendar)
			s.auditService.LogAction(
				auditCtx,
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
		util.Int("year", calendar.Year),
		util.String("name", calendar.Name),
		util.Duration("duration", time.Since(startTime)),
	)

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

	// Load existing calendar
	calendar, err := s.schedulingRepo.GetWorkCalendarByID(ctx, calendarID)
	if err != nil {
		return nil, fmt.Errorf("work calendar not found: %w", err)
	}

	beforeState, _ := json.Marshal(calendar)

	// Track old name for uniqueness check
	oldName := calendar.Name

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

	// Re-validate calendar
	if err := s.validateWorkCalendar(calendar); err != nil {
		return nil, fmt.Errorf("work calendar validation failed: %w", err)
	}

	// Check name uniqueness ONLY if name actually changed
	if update.Name != nil && *update.Name != oldName {
		existingCalendars, err := s.schedulingRepo.GetWorkCalendarsByCompany(ctx, calendar.CompanyID)
		if err == nil {
			for _, existing := range existingCalendars {
				if existing.CalendarID != calendarID &&
					strings.EqualFold(existing.Name, *update.Name) {
					return nil, fmt.Errorf(
						"work calendar with name '%s' already exists",
						*update.Name,
					)
				}
			}
		}
	}

	// Persist update
	if err := s.schedulingRepo.UpdateWorkCalendar(ctx, calendar); err != nil {
		s.logger.Error("Failed to update work calendar",
			util.String("calendar_id", calendarID.String()),
			util.ErrorField(err))
		return nil, fmt.Errorf("failed to update work calendar: %w", err)
	}

	// Audit
	if s.auditService != nil {
		go func() {
			auditCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()

			afterState, _ := json.Marshal(calendar)
			s.auditService.LogAction(
				auditCtx,
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
		util.Int("year", calendar.Year),
		util.Duration("duration", time.Since(startTime)),
	)

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
	companyID uuid.UUID,
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

	// Check if template exists and belongs to the company
	template, err := s.schedulingRepo.GetScheduleTemplateByID(ctx, assignment.ScheduleTemplateID)
	if err != nil {
		return fmt.Errorf("schedule template not found: %w", err)
	}

	// Verify template belongs to the requested company
	if template.CompanyID != companyID {
		return fmt.Errorf("schedule template does not belong to company %s", companyID)
	}

	// ✅ Check if user exists and is active in the company
	userExists, err := s.schedulingRepo.IsUserActiveInCompany(ctx, companyID, assignment.UserID)
	if err != nil {
		return fmt.Errorf("failed to validate user: %w", err)
	}
	if !userExists {
		return fmt.Errorf("user %s not found or not an active employee in this company", assignment.UserID)
	}

	// ✅ NEW: Check if assignment already exists (same user, template, and effective_from)
	existingAssignment, err := s.schedulingRepo.GetUserScheduleAssignment(
		ctx,
		assignment.UserID,
		assignment.ScheduleTemplateID,
		assignment.EffectiveFrom,
	)

	// If assignment already exists, update it instead of creating a new one
	if err == nil && existingAssignment != nil {
		// Update the existing assignment
		existingAssignment.EffectiveTo = assignment.EffectiveTo
		existingAssignment.AssignedBy = &actorID

		err = s.schedulingRepo.UpdateUserScheduleAssignment(ctx, existingAssignment)
		if err != nil {
			s.logger.Error("Failed to update existing schedule assignment",
				util.String("user_id", assignment.UserID.String()),
				util.String("template_id", assignment.ScheduleTemplateID.String()),
				util.ErrorField(err))
			return fmt.Errorf("failed to update schedule assignment: %w", err)
		}

		s.logger.Info("Schedule assignment updated",
			util.String("user_id", assignment.UserID.String()),
			util.String("template_id", assignment.ScheduleTemplateID.String()),
			util.String("company_id", companyID.String()))

		return nil
	}

	// Check if user already has an active assignment on the effective date
	currentAssignment, err := s.schedulingRepo.GetUserCurrentScheduleAssignment(ctx, assignment.UserID, assignment.EffectiveFrom)
	if err == nil && currentAssignment != nil {
		// If the current assignment is for a different template, end it
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
				&companyID,
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
		util.String("company_id", companyID.String()),
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

	// Get user's current schedule assignment for the given date
	assignment, err := s.schedulingRepo.GetUserCurrentScheduleAssignment(ctx, instance.UserID, instance.ScheduleDate)
	if err != nil {
		return nil, fmt.Errorf("failed to get user schedule assignment: %w", err)
	}
	if assignment == nil {
		return nil, fmt.Errorf("no active schedule assignment found for user on %s",
			instance.ScheduleDate.Format("2006-01-02"))
	}

	instance.ScheduleTemplateID = assignment.ScheduleTemplateID

	// Get template and calendar
	template, err := s.schedulingRepo.GetScheduleTemplateByID(ctx, instance.ScheduleTemplateID)
	if err != nil {
		return nil, fmt.Errorf("schedule template not found: %w", err)
	}

	calendar, err := s.schedulingRepo.GetWorkCalendarByID(ctx, template.CalendarID)
	if err != nil {
		return nil, fmt.Errorf("work calendar not found: %w", err)
	}

	instance.Timezone = calendar.Timezone
	instance.Metadata = scheduling.InstanceMetadata{}

	// Validate the instance
	if err := s.validateScheduleInstance(instance); err != nil {
		return nil, fmt.Errorf("schedule instance validation failed: %w", err)
	}

	// Set UUID if not provided
	if instance.ScheduleInstanceID == uuid.Nil {
		instance.ScheduleInstanceID = uuid.New()
	}

	// Set generation timestamp if not provided
	now := time.Now().UTC()
	if instance.GeneratedAt.IsZero() {
		instance.GeneratedAt = now
	}

	// Check for existing instance
	existingInstance, err := s.schedulingRepo.GetScheduleInstanceByUserDate(ctx, instance.UserID, instance.ScheduleDate)
	if err == nil && existingInstance != nil {
		// ============================================
		// UPDATE EXISTING INSTANCE (OVERWRITE)
		// ============================================
		beforeState, _ := json.Marshal(existingInstance)

		// Update the existing instance with new values
		// Keep the original ScheduleInstanceID, CompanyID, UserID, ScheduleDate, and GeneratedAt
		existingInstance.ScheduleTemplateID = instance.ScheduleTemplateID
		existingInstance.ExpectedStart = instance.ExpectedStart
		existingInstance.ExpectedEnd = instance.ExpectedEnd
		existingInstance.Timezone = instance.Timezone

		// Merge metadata instead of replacing if you want to preserve existing metadata
		// For now, we'll replace with empty metadata as per original behavior
		existingInstance.Metadata = scheduling.InstanceMetadata{}

		// Calculate expected times if not provided
		if existingInstance.ExpectedStart == nil || existingInstance.ExpectedEnd == nil {
			if err := s.calculateExpectedTimes(existingInstance, template); err != nil {
				return nil, fmt.Errorf("failed to calculate expected times: %w", err)
			}
		}

		// Validate the updated instance
		if err := s.validateScheduleInstance(existingInstance); err != nil {
			return nil, fmt.Errorf("schedule instance validation failed: %w", err)
		}

		// Check for schedule conflict, excluding the current instance
		if existingInstance.ExpectedStart != nil && existingInstance.ExpectedEnd != nil {
			hasConflict, err := s.ValidateScheduleConflict(ctx, existingInstance.UserID,
				*existingInstance.ExpectedStart, *existingInstance.ExpectedEnd,
				&existingInstance.ScheduleInstanceID)
			if err != nil {
				return nil, fmt.Errorf("failed to check schedule conflict: %w", err)
			}
			if hasConflict {
				return nil, fmt.Errorf("schedule conflict detected")
			}
		}

		// Update in repository
		err = s.schedulingRepo.UpdateScheduleInstance(ctx, existingInstance)
		if err != nil {
			s.logger.Error("Failed to update schedule instance",
				util.String("instance_id", existingInstance.ScheduleInstanceID.String()),
				util.ErrorField(err))
			return nil, fmt.Errorf("failed to update schedule instance: %w", err)
		}

		// Audit log for update
		if s.auditService != nil {
			go func() {
				auditCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
				defer cancel()
				afterState, _ := json.Marshal(existingInstance)
				s.auditService.LogAction(auditCtx,
					&existingInstance.CompanyID,
					"scheduling",
					"schedule_instance.update",
					"schedule_instance",
					&existingInstance.ScheduleInstanceID,
					actorType,
					&actorID,
					beforeState,
					afterState,
					metadata,
				)
			}()
		}

		s.logger.Info("Schedule instance updated (overwritten)",
			util.String("instance_id", existingInstance.ScheduleInstanceID.String()),
			util.String("user_id", existingInstance.UserID.String()),
			util.String("template_id", existingInstance.ScheduleTemplateID.String()),
			util.String("date", existingInstance.ScheduleDate.Format("2006-01-02")),
			util.Duration("duration", time.Since(startTime)))

		return existingInstance, nil
	}

	// ============================================
	// CREATE NEW INSTANCE (NO EXISTING INSTANCE)
	// ============================================

	// Validate template belongs to company
	if template.CompanyID != instance.CompanyID {
		return nil, fmt.Errorf("template does not belong to company")
	}

	// Calculate expected times if not provided
	if instance.ExpectedStart == nil || instance.ExpectedEnd == nil {
		if err := s.calculateExpectedTimes(instance, template); err != nil {
			return nil, fmt.Errorf("failed to calculate expected times: %w", err)
		}
	}

	// Check for schedule conflict
	if instance.ExpectedStart != nil && instance.ExpectedEnd != nil {
		hasConflict, err := s.ValidateScheduleConflict(ctx, instance.UserID, *instance.ExpectedStart, *instance.ExpectedEnd, nil)
		if err != nil {
			return nil, fmt.Errorf("failed to check schedule conflict: %w", err)
		}
		if hasConflict {
			return nil, fmt.Errorf("schedule conflict detected")
		}
	}

	// Create new instance
	err = s.schedulingRepo.CreateScheduleInstance(ctx, instance)
	if err != nil {
		s.logger.Error("Failed to create schedule instance",
			util.String("user_id", instance.UserID.String()),
			util.String("date", instance.ScheduleDate.Format("2006-01-02")),
			util.ErrorField(err))
		return nil, fmt.Errorf("failed to create schedule instance: %w", err)
	}

	// Audit log for create
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

	// Process each instance
	for i, instance := range instances {
		if err := s.validateScheduleInstance(instance); err != nil {
			return fmt.Errorf("instance %d validation failed: %w", i, err)
		}

		if instance.ScheduleInstanceID == uuid.Nil {
			instance.ScheduleInstanceID = uuid.New()
		}

		now := time.Now().UTC()
		if instance.GeneratedAt.IsZero() {
			instance.GeneratedAt = now
		}

		// Check if instance already exists
		existingInstance, err := s.schedulingRepo.GetScheduleInstanceByUserDate(ctx, instance.UserID, instance.ScheduleDate)
		if err == nil && existingInstance != nil {
			// Update existing instance
			existingInstance.ExpectedStart = instance.ExpectedStart
			existingInstance.ExpectedEnd = instance.ExpectedEnd
			existingInstance.Timezone = instance.Timezone
			existingInstance.Metadata = instance.Metadata

			if err := s.schedulingRepo.UpdateScheduleInstance(ctx, existingInstance); err != nil {
				return fmt.Errorf("instance %d: failed to update existing schedule: %w", i, err)
			}
		} else {
			// Create new instance
			if err := s.schedulingRepo.CreateScheduleInstance(ctx, instance); err != nil {
				return fmt.Errorf("instance %d: failed to create schedule: %w", i, err)
			}
		}
	}

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

	s.logger.Info("Bulk schedule instances created/updated",
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
	if calendar.Year < 2000 || calendar.Year > 2100 {
		return fmt.Errorf("invalid calendar year")
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
		defaultStart := time.Date(scheduleDate.Year(), scheduleDate.Month(), scheduleDate.Day(),
			9, 0, 0, 0, loc)
		defaultEnd := time.Date(scheduleDate.Year(), scheduleDate.Month(), scheduleDate.Day(),
			17, 0, 0, 0, loc)
		instance.ExpectedStart = &defaultStart
		instance.ExpectedEnd = &defaultEnd
	case "class":
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

	// Enforce calendar year
	if config.StartDate.Year() != calendar.Year ||
		config.EndDate.Year() != calendar.Year {
		return nil, fmt.Errorf(
			"schedule generation dates must be within calendar year %d",
			calendar.Year,
		)
	}

	var instances []*scheduling.ScheduleInstance

	loc, err := time.LoadLocation(config.Timezone)
	if err != nil {
		loc = time.UTC
	}

	holidayMap := make(map[string]bool)
	if !config.IncludeHolidays {
		for _, holiday := range calendar.Holidays {
			holidayMap[holiday.Date] = true
		}
	}

	for currentDate := config.StartDate; !currentDate.After(config.EndDate); currentDate = currentDate.AddDate(0, 0, 1) {
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

		dateStr := currentDateInLoc.Format("2006-01-02")
		if holidayMap[dateStr] {
			continue
		}

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

// Off Entitlement Methods
func (s *schedulingServiceImpl) CreateOffEntitlement(
	ctx context.Context,
	companyID uuid.UUID,
	entitlement *scheduling.UserOffEntitlement,
	actorType string,
	actorID uuid.UUID,
	metadata map[string]interface{},
) (*scheduling.UserOffEntitlement, error) {
	startTime := time.Now()

	// Validation
	if err := s.validateOffEntitlement(entitlement); err != nil {
		return nil, fmt.Errorf("off entitlement validation failed: %w", err)
	}

	if entitlement.EntitlementID == uuid.Nil {
		entitlement.EntitlementID = uuid.New()
	}

	entitlement.CompanyID = companyID
	entitlement.CreatedAt = time.Now().UTC()

	// Check for overlapping entitlements
	existingEntitlements, err := s.schedulingRepo.GetOffEntitlementsByUser(ctx, entitlement.UserID, true)
	if err == nil {
		for _, existing := range existingEntitlements {
			if s.entitlementsOverlap(existing, entitlement) {
				return nil, fmt.Errorf("overlapping off entitlement exists for user")
			}
		}
	}

	// Save to repository
	err = s.schedulingRepo.CreateOffEntitlement(ctx, entitlement)
	if err != nil {
		s.logger.Error("Failed to create off entitlement",
			util.String("user_id", entitlement.UserID.String()),
			util.ErrorField(err))
		return nil, fmt.Errorf("failed to create off entitlement: %w", err)
	}

	// Audit log
	if s.auditService != nil {
		go s.logAuditAction(ctx, companyID, "off_entitlement.create", entitlement.EntitlementID, actorType, actorID, nil, entitlement, metadata)
	}

	s.logger.Info("Off entitlement created",
		util.String("entitlement_id", entitlement.EntitlementID.String()),
		util.String("user_id", entitlement.UserID.String()),
		util.String("period_type", entitlement.PeriodType),
		util.Int("off_count", entitlement.OffCount),
		util.Duration("duration", time.Since(startTime)))

	return entitlement, nil
}

func (s *schedulingServiceImpl) validateOffEntitlement(entitlement *scheduling.UserOffEntitlement) error {
	if entitlement.CompanyID == uuid.Nil {
		return fmt.Errorf("company ID is required")
	}
	if entitlement.UserID == uuid.Nil {
		return fmt.Errorf("user ID is required")
	}
	if entitlement.PeriodType != "weekly" && entitlement.PeriodType != "monthly" {
		return fmt.Errorf("period type must be 'weekly' or 'monthly'")
	}
	if entitlement.OffCount < 1 {
		return fmt.Errorf("off count must be at least 1")
	}
	if entitlement.EffectiveFrom.IsZero() {
		return fmt.Errorf("effective from date is required")
	}
	return nil
}

func (s *schedulingServiceImpl) entitlementsOverlap(e1, e2 *scheduling.UserOffEntitlement) bool {
	e1To := time.Now().AddDate(100, 0, 0) // Far future
	if e1.EffectiveTo != nil {
		e1To = *e1.EffectiveTo
	}

	e2To := time.Now().AddDate(100, 0, 0)
	if e2.EffectiveTo != nil {
		e2To = *e2.EffectiveTo
	}

	return e1.EffectiveFrom.Before(e2To) && e2.EffectiveFrom.Before(e1To)
}

// Off Request Methods
func (s *schedulingServiceImpl) CreateOffRequest(
	ctx context.Context,
	companyID uuid.UUID,
	request *scheduling.OffRequest,
	actorType string,
	actorID uuid.UUID,
	metadata map[string]interface{},
) (*scheduling.OffRequest, error) {
	startTime := time.Now()

	// Validation
	if err := s.validateOffRequest(request); err != nil {
		return nil, fmt.Errorf("off request validation failed: %w", err)
	}

	if request.OffRequestID == uuid.Nil {
		request.OffRequestID = uuid.New()
	}

	request.CompanyID = companyID
	if request.Status == "" {
		request.Status = "pending"
	}
	request.CreatedAt = time.Now().UTC()

	// Check for conflicts with existing overrides
	for _, dateStr := range request.RequestDates {
		date, err := time.Parse("2006-01-02", dateStr)
		if err != nil {
			return nil, fmt.Errorf("invalid date format in request dates: %s", dateStr)
		}

		override, err := s.schedulingRepo.GetScheduleOverrideByUserDate(ctx, request.UserID, date)
		if err == nil && override != nil {
			if override.OverrideType == "force_work" {
				return nil, fmt.Errorf("user is scheduled to work on %s", dateStr)
			}
		}
	}

	// Check if approval is required
	entitlement, err := s.schedulingRepo.GetCurrentOffEntitlement(ctx, request.UserID, time.Now())
	if err == nil && entitlement != nil && entitlement.RequiresApproval && request.Status == "pending" {
		// Request needs approval
		request.Status = "pending"
	} else if err == nil && entitlement != nil && !entitlement.RequiresApproval {
		// Auto-approve if no approval required
		request.Status = "approved"
		now := time.Now().UTC()
		request.ApprovedAt = &now
		request.ApprovedBy = &actorID
	}

	// Save to repository
	err = s.schedulingRepo.CreateOffRequest(ctx, request)
	if err != nil {
		s.logger.Error("Failed to create off request",
			util.String("user_id", request.UserID.String()),
			util.ErrorField(err))
		return nil, fmt.Errorf("failed to create off request: %w", err)
	}

	// Create schedule overrides for approved requests
	if request.Status == "approved" {
		for _, dateStr := range request.RequestDates {
			date, _ := time.Parse("2006-01-02", dateStr)
			override := &scheduling.ScheduleOverride{
				OverrideID:   uuid.New(),
				CompanyID:    companyID,
				UserID:       request.UserID,
				OverrideDate: date,
				OverrideType: "off",
				CreatedBy:    &actorID,
				CreatedAt:    time.Now().UTC(),
			}

			if err := s.schedulingRepo.CreateScheduleOverride(ctx, override); err != nil {
				s.logger.Warn("Failed to create schedule override for off request",
					util.String("user_id", request.UserID.String()),
					util.String("date", dateStr),
					util.ErrorField(err))
			}
		}
	}

	// Audit log
	if s.auditService != nil {
		go s.logAuditAction(ctx, companyID, "off_request.create", request.OffRequestID, actorType, actorID, nil, request, metadata)
	}

	s.logger.Info("Off request created",
		util.String("request_id", request.OffRequestID.String()),
		util.String("user_id", request.UserID.String()),
		util.String("status", request.Status),
		util.Int("days_requested", len(request.RequestDates)),
		util.Duration("duration", time.Since(startTime)))

	return request, nil
}

func (s *schedulingServiceImpl) ApproveOffRequest(
	ctx context.Context,
	requestID uuid.UUID,
	approvedBy uuid.UUID,
	actorType string,
	actorID uuid.UUID,
	metadata map[string]interface{},
) error {
	startTime := time.Now()

	// Get the request
	request, err := s.schedulingRepo.GetOffRequestByID(ctx, requestID)
	if err != nil {
		return fmt.Errorf("off request not found: %w", err)
	}

	if request.Status != "pending" {
		return fmt.Errorf("cannot approve a request with status: %s", request.Status)
	}

	beforeState, _ := json.Marshal(request)

	// Update in repository
	err = s.schedulingRepo.ApproveOffRequest(ctx, requestID, approvedBy)
	if err != nil {
		return fmt.Errorf("failed to approve off request: %w", err)
	}

	// Create schedule overrides
	for _, dateStr := range request.RequestDates {
		date, _ := time.Parse("2006-01-02", dateStr)
		override := &scheduling.ScheduleOverride{
			OverrideID:   uuid.New(),
			CompanyID:    request.CompanyID,
			UserID:       request.UserID,
			OverrideDate: date,
			OverrideType: "off",
			CreatedBy:    &approvedBy,
			CreatedAt:    time.Now().UTC(),
		}

		if err := s.schedulingRepo.CreateScheduleOverride(ctx, override); err != nil {
			s.logger.Warn("Failed to create schedule override for approved off request",
				util.String("user_id", request.UserID.String()),
				util.String("date", dateStr),
				util.ErrorField(err))
		}
	}

	// Audit log
	if s.auditService != nil {
		afterState, _ := json.Marshal(map[string]interface{}{
			"status":      "approved",
			"approved_by": approvedBy,
			"approved_at": time.Now().UTC(),
		})

		go s.logAuditAction(ctx, request.CompanyID, "off_request.approve", requestID, actorType, actorID, beforeState, afterState, metadata)
	}

	s.logger.Info("Off request approved",
		util.String("request_id", requestID.String()),
		util.String("user_id", request.UserID.String()),
		util.String("approved_by", approvedBy.String()),
		util.Duration("duration", time.Since(startTime)))

	return nil
}

// Schedule Override Methods
func (s *schedulingServiceImpl) CreateScheduleOverride(
	ctx context.Context,
	companyID uuid.UUID,
	override *scheduling.ScheduleOverride,
	actorType string,
	actorID uuid.UUID,
	metadata map[string]interface{},
) (*scheduling.ScheduleOverride, error) {
	startTime := time.Now()

	// Validation
	if err := s.validateScheduleOverride(override); err != nil {
		return nil, fmt.Errorf("schedule override validation failed: %w", err)
	}

	if override.OverrideID == uuid.Nil {
		override.OverrideID = uuid.New()
	}

	override.CompanyID = companyID
	override.CreatedAt = time.Now().UTC()

	// Check for conflicts
	conflict, err := s.schedulingRepo.CheckScheduleOverrideConflict(ctx, override.UserID, override.OverrideDate, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to check schedule override conflict: %w", err)
	}

	if conflict {
		return nil, fmt.Errorf("schedule override already exists for user on %s", override.OverrideDate.Format("2006-01-02"))
	}

	// Save to repository
	err = s.schedulingRepo.CreateScheduleOverride(ctx, override)
	if err != nil {
		s.logger.Error("Failed to create schedule override",
			util.String("user_id", override.UserID.String()),
			util.ErrorField(err))
		return nil, fmt.Errorf("failed to create schedule override: %w", err)
	}

	// Audit log
	if s.auditService != nil {
		go s.logAuditAction(ctx, companyID, "schedule_override.create", override.OverrideID, actorType, actorID, nil, override, metadata)
	}

	s.logger.Info("Schedule override created",
		util.String("override_id", override.OverrideID.String()),
		util.String("user_id", override.UserID.String()),
		util.String("override_type", override.OverrideType),
		util.String("date", override.OverrideDate.Format("2006-01-02")),
		util.Duration("duration", time.Since(startTime)))

	return override, nil
}

func (s *schedulingServiceImpl) validateScheduleOverride(override *scheduling.ScheduleOverride) error {
	if override.CompanyID == uuid.Nil {
		return fmt.Errorf("company ID is required")
	}
	if override.UserID == uuid.Nil {
		return fmt.Errorf("user ID is required")
	}
	if override.OverrideDate.IsZero() {
		return fmt.Errorf("override date is required")
	}
	if override.OverrideType != "off" && override.OverrideType != "force_work" && override.OverrideType != "holiday_override" {
		return fmt.Errorf("override type must be 'off', 'force_work', or 'holiday_override'")
	}
	return nil
}

// Combined Operations
func (s *schedulingServiceImpl) RequestTimeOff(
	ctx context.Context,
	companyID, userID uuid.UUID,
	requestDates []string,
	reason string,
	actorType string,
	actorID uuid.UUID,
) (*scheduling.OffRequest, error) {
	// Validate dates
	for _, dateStr := range requestDates {
		if _, err := time.Parse("2006-01-02", dateStr); err != nil {
			return nil, fmt.Errorf("invalid date format: %s", dateStr)
		}
	}

	// Check user's current entitlement
	entitlement, err := s.schedulingRepo.GetCurrentOffEntitlement(ctx, userID, time.Now())
	if err != nil {
		return nil, fmt.Errorf("no active off entitlement found: %w", err)
	}

	// Calculate used days in current period
	usedDays, err := s.schedulingRepo.GetOffBalance(ctx, userID, entitlement.PeriodType, entitlement.EffectiveFrom, time.Now())
	if err != nil {
		usedDays = 0
	}

	// Check if user has enough balance
	remaining := entitlement.OffCount - usedDays
	if remaining < len(requestDates) {
		return nil, fmt.Errorf("insufficient off balance: %d days remaining, requested %d days", remaining, len(requestDates))
	}

	// Create off request
	request := &scheduling.OffRequest{
		OffRequestID: uuid.New(),
		CompanyID:    companyID,
		UserID:       userID,
		RequestDates: requestDates,
		Status:       "pending",
		RequestedBy:  &actorID,
		CreatedAt:    time.Now().UTC(),
	}

	// Auto-approve if no approval required
	if !entitlement.RequiresApproval {
		request.Status = "approved"
		now := time.Now().UTC()
		request.ApprovedAt = &now
		request.ApprovedBy = &actorID
	}

	// Save to repository
	err = s.schedulingRepo.CreateOffRequest(ctx, request)
	if err != nil {
		return nil, fmt.Errorf("failed to create off request: %w", err)
	}

	// Create schedule overrides for approved requests
	if request.Status == "approved" {
		for _, dateStr := range requestDates {
			date, _ := time.Parse("2006-01-02", dateStr)
			override := &scheduling.ScheduleOverride{
				OverrideID:   uuid.New(),
				CompanyID:    companyID,
				UserID:       userID,
				OverrideDate: date,
				OverrideType: "off",
				Reason:       &reason,
				CreatedBy:    &actorID,
				CreatedAt:    time.Now().UTC(),
			}

			if err := s.schedulingRepo.CreateScheduleOverride(ctx, override); err != nil {
				s.logger.Warn("Failed to create schedule override for time off",
					util.String("user_id", userID.String()),
					util.String("date", dateStr),
					util.ErrorField(err))
			}
		}
	}

	return request, nil
}

// Helper method for audit logging
// func (s *schedulingServiceImpl) logAuditAction(
// 	ctx context.Context,
// 	companyID uuid.UUID,
// 	action string,
// 	resourceID uuid.UUID,
// 	actorType string,
// 	actorID uuid.UUID,
// 	beforeState, afterState []byte,
// 	metadata map[string]interface{},
// ) {
// 	if s.auditService != nil {
// 		auditCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
// 		defer cancel()

// 		s.auditService.LogAction(auditCtx,
// 			&companyID,
// 			"scheduling",
// 			action,
// 			strings.Split(action, ".")[0],
// 			&resourceID,
// 			actorType,
// 			&actorID,
// 			beforeState,
// 			afterState,
// 			metadata,
// 		)
// 	}
// }

// Update CheckDateAvailability to match the interface
func (s *schedulingServiceImpl) CheckDateAvailability(
	ctx context.Context,
	userID uuid.UUID,
	date time.Time,
) (map[string]interface{}, error) {
	startTime := time.Now()

	result := map[string]interface{}{
		"user_id":   userID,
		"date":      date.Format("2006-01-02"),
		"available": true,
		"reasons":   []string{},
	}

	// Check schedule override
	override, err := s.schedulingRepo.GetScheduleOverrideByUserDate(ctx, userID, date)
	if err == nil && override != nil {
		result["schedule_override"] = override

		switch override.OverrideType {
		case "off":
			result["available"] = false
			result["is_off_day"] = true
			reasons := result["reasons"].([]string)
			reasons = append(reasons, "Schedule override: off day")
			result["reasons"] = reasons
		case "force_work":
			result["available"] = true
			result["forced_work"] = true
			reasons := result["reasons"].([]string)
			reasons = append(reasons, "Schedule override: forced work")
			result["reasons"] = reasons
		case "holiday_override":
			result["available"] = true
			result["holiday_work"] = true
			reasons := result["reasons"].([]string)
			reasons = append(reasons, "Schedule override: holiday work")
			result["reasons"] = reasons
		}
	}

	// Check off requests
	statusApproved := "approved"
	offRequests, err := s.schedulingRepo.GetOffRequestsByUser(ctx, userID, &date, &date, &statusApproved)
	if err == nil && len(offRequests) > 0 {
		result["available"] = false
		result["off_request"] = offRequests[0]
		reasons := result["reasons"].([]string)
		reasons = append(reasons, "Approved off request")
		result["reasons"] = reasons
		result["is_off_day"] = true
	}

	// Check pending requests
	statusPending := "pending"
	pendingRequests, err := s.schedulingRepo.GetOffRequestsByUser(ctx, userID, &date, &date, &statusPending)
	if err == nil && len(pendingRequests) > 0 {
		result["pending_request"] = pendingRequests[0]
		if result["available"] == true {
			// If still available (no approved off), add note about pending request
			reasons := result["reasons"].([]string)
			reasons = append(reasons, "Pending off request awaiting approval")
			result["reasons"] = reasons
		}
	}

	// Check schedule instance
	instance, err := s.schedulingRepo.GetScheduleInstanceByUserDate(ctx, userID, date)
	if err == nil && instance != nil {
		result["schedule_instance"] = instance
		if instance.ExpectedStart != nil && instance.ExpectedEnd != nil {
			result["scheduled_hours"] = map[string]interface{}{
				"start": instance.ExpectedStart.Format("15:04"),
				"end":   instance.ExpectedEnd.Format("15:04"),
			}
		}
	}

	s.logger.Debug("Date availability checked",
		util.String("user_id", userID.String()),
		util.String("date", date.Format("2006-01-02")),
		util.Bool("available", result["available"].(bool)),
		util.Duration("duration", time.Since(startTime)))

	return result, nil
}

// Implement missing validation method
func (s *schedulingServiceImpl) validateOffRequest(request *scheduling.OffRequest) error {
	if request.CompanyID == uuid.Nil {
		return fmt.Errorf("company ID is required")
	}
	if request.UserID == uuid.Nil {
		return fmt.Errorf("user ID is required")
	}
	if len(request.RequestDates) == 0 {
		return fmt.Errorf("at least one request date is required")
	}

	// Validate date format
	for i, dateStr := range request.RequestDates {
		if _, err := time.Parse("2006-01-02", dateStr); err != nil {
			return fmt.Errorf("invalid date format at index %d: %s", i, dateStr)
		}
	}

	// Validate status
	if request.Status != "" && request.Status != "pending" && request.Status != "approved" && request.Status != "rejected" {
		return fmt.Errorf("invalid status: %s", request.Status)
	}

	return nil
}

// Update the logAuditAction method to handle marshaling
func (s *schedulingServiceImpl) logAuditAction(
	ctx context.Context,
	companyID uuid.UUID,
	action string,
	resourceID uuid.UUID,
	actorType string,
	actorID uuid.UUID,
	beforeState, afterState interface{},
	metadata map[string]interface{},
) {
	if s.auditService != nil {
		go func() {
			auditCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()

			var beforeJSON, afterJSON []byte
			if beforeState != nil {
				beforeJSON, _ = json.Marshal(beforeState)
			}
			if afterState != nil {
				afterJSON, _ = json.Marshal(afterState)
			}

			s.auditService.LogAction(auditCtx,
				&companyID,
				"scheduling",
				action,
				strings.Split(action, ".")[0],
				&resourceID,
				actorType,
				&actorID,
				beforeJSON,
				afterJSON,
				metadata,
			)
		}()
	}
}

// Implement other missing methods from the interface
func (s *schedulingServiceImpl) UpdateOffEntitlement(
	ctx context.Context,
	entitlementID uuid.UUID,
	update scheduling.OffEntitlementUpdate,
	actorType string,
	actorID uuid.UUID,
	metadata map[string]interface{},
) (*scheduling.UserOffEntitlement, error) {
	startTime := time.Now()

	entitlement, err := s.schedulingRepo.GetOffEntitlementByID(ctx, entitlementID)
	if err != nil {
		return nil, fmt.Errorf("off entitlement not found: %w", err)
	}

	beforeState, _ := json.Marshal(entitlement)

	if update.PeriodType != nil {
		entitlement.PeriodType = *update.PeriodType
	}
	if update.OffCount != nil {
		entitlement.OffCount = *update.OffCount
	}
	if update.RequiresApproval != nil {
		entitlement.RequiresApproval = *update.RequiresApproval
	}
	if update.EffectiveFrom != nil {
		entitlement.EffectiveFrom = *update.EffectiveFrom
	}
	if update.EffectiveTo != nil {
		entitlement.EffectiveTo = update.EffectiveTo
	}

	// Validate
	if err := s.validateOffEntitlement(entitlement); err != nil {
		return nil, fmt.Errorf("off entitlement validation failed: %w", err)
	}

	err = s.schedulingRepo.UpdateOffEntitlement(ctx, entitlement)
	if err != nil {
		s.logger.Error("Failed to update off entitlement",
			util.String("entitlement_id", entitlementID.String()),
			util.ErrorField(err))
		return nil, fmt.Errorf("failed to update off entitlement: %w", err)
	}

	s.logAuditAction(ctx, entitlement.CompanyID, "off_entitlement.update", entitlementID,
		actorType, actorID, beforeState, entitlement, metadata)

	s.logger.Info("Off entitlement updated",
		util.String("entitlement_id", entitlementID.String()),
		util.Duration("duration", time.Since(startTime)))

	return entitlement, nil
}

func (s *schedulingServiceImpl) DeleteOffEntitlement(
	ctx context.Context,
	entitlementID uuid.UUID,
	actorType string,
	actorID uuid.UUID,
	metadata map[string]interface{},
) error {
	startTime := time.Now()

	entitlement, err := s.schedulingRepo.GetOffEntitlementByID(ctx, entitlementID)
	if err != nil {
		return fmt.Errorf("off entitlement not found: %w", err)
	}

	beforeState, _ := json.Marshal(entitlement)

	err = s.schedulingRepo.DeleteOffEntitlement(ctx, entitlementID)
	if err != nil {
		s.logger.Error("Failed to delete off entitlement",
			util.String("entitlement_id", entitlementID.String()),
			util.ErrorField(err))
		return fmt.Errorf("failed to delete off entitlement: %w", err)
	}

	s.logAuditAction(ctx, entitlement.CompanyID, "off_entitlement.delete", entitlementID,
		actorType, actorID, beforeState, nil, metadata)

	s.logger.Info("Off entitlement deleted",
		util.String("entitlement_id", entitlementID.String()),
		util.Duration("duration", time.Since(startTime)))

	return nil
}

func (s *schedulingServiceImpl) GetUserOffBalance(
	ctx context.Context,
	userID uuid.UUID,
	periodType string,
	startDate, endDate time.Time,
) (map[string]interface{}, error) {
	balance, err := s.schedulingRepo.GetOffBalance(ctx, userID, periodType, startDate, endDate)
	if err != nil {
		return nil, fmt.Errorf("failed to get off balance: %w", err)
	}

	entitlement, err := s.schedulingRepo.GetCurrentOffEntitlement(ctx, userID, time.Now())
	if err != nil {
		return nil, fmt.Errorf("failed to get current entitlement: %w", err)
	}

	result := map[string]interface{}{
		"user_id":     userID,
		"period_type": periodType,
		"start_date":  startDate,
		"end_date":    endDate,
		"used_days":   balance,
		"total_days":  entitlement.OffCount,
		"remaining":   entitlement.OffCount - balance,
		"entitlement": entitlement,
	}

	return result, nil
}

func (s *schedulingServiceImpl) UpdateOffRequest(
	ctx context.Context,
	requestID uuid.UUID,
	update scheduling.OffRequestUpdate,
	actorType string,
	actorID uuid.UUID,
	metadata map[string]interface{},
) (*scheduling.OffRequest, error) {
	startTime := time.Now()

	request, err := s.schedulingRepo.GetOffRequestByID(ctx, requestID)
	if err != nil {
		return nil, fmt.Errorf("off request not found: %w", err)
	}

	beforeState, _ := json.Marshal(request)

	if update.RequestDates != nil {
		request.RequestDates = *update.RequestDates
	}
	if update.Status != nil {
		request.Status = *update.Status
	}
	if update.ApprovedBy != nil {
		request.ApprovedBy = update.ApprovedBy
	}
	if update.ApprovedAt != nil {
		request.ApprovedAt = update.ApprovedAt
	}

	// Validate
	if err := s.validateOffRequest(request); err != nil {
		return nil, fmt.Errorf("off request validation failed: %w", err)
	}

	err = s.schedulingRepo.UpdateOffRequest(ctx, request)
	if err != nil {
		s.logger.Error("Failed to update off request",
			util.String("request_id", requestID.String()),
			util.ErrorField(err))
		return nil, fmt.Errorf("failed to update off request: %w", err)
	}

	s.logAuditAction(ctx, request.CompanyID, "off_request.update", requestID,
		actorType, actorID, beforeState, request, metadata)

	s.logger.Info("Off request updated",
		util.String("request_id", requestID.String()),
		util.Duration("duration", time.Since(startTime)))

	return request, nil
}

func (s *schedulingServiceImpl) DeleteOffRequest(
	ctx context.Context,
	requestID uuid.UUID,
	actorType string,
	actorID uuid.UUID,
	metadata map[string]interface{},
) error {
	startTime := time.Now()

	request, err := s.schedulingRepo.GetOffRequestByID(ctx, requestID)
	if err != nil {
		return fmt.Errorf("off request not found: %w", err)
	}

	beforeState, _ := json.Marshal(request)

	err = s.schedulingRepo.DeleteOffRequest(ctx, requestID)
	if err != nil {
		s.logger.Error("Failed to delete off request",
			util.String("request_id", requestID.String()),
			util.ErrorField(err))
		return fmt.Errorf("failed to delete off request: %w", err)
	}

	s.logAuditAction(ctx, request.CompanyID, "off_request.delete", requestID,
		actorType, actorID, beforeState, nil, metadata)

	s.logger.Info("Off request deleted",
		util.String("request_id", requestID.String()),
		util.Duration("duration", time.Since(startTime)))

	return nil
}

func (s *schedulingServiceImpl) RejectOffRequest(
	ctx context.Context,
	requestID uuid.UUID,
	rejectedBy uuid.UUID,
	actorType string,
	actorID uuid.UUID,
	metadata map[string]interface{},
) error {
	startTime := time.Now()

	request, err := s.schedulingRepo.GetOffRequestByID(ctx, requestID)
	if err != nil {
		return fmt.Errorf("off request not found: %w", err)
	}

	if request.Status != "pending" {
		return fmt.Errorf("cannot reject a request with status: %s", request.Status)
	}

	beforeState, _ := json.Marshal(request)

	now := time.Now().UTC()
	request.Status = "rejected"
	request.ApprovedBy = &rejectedBy
	request.ApprovedAt = &now

	err = s.schedulingRepo.UpdateOffRequest(ctx, request)
	if err != nil {
		return fmt.Errorf("failed to reject off request: %w", err)
	}

	s.logAuditAction(ctx, request.CompanyID, "off_request.reject", requestID,
		actorType, actorID, beforeState, request, metadata)

	s.logger.Info("Off request rejected",
		util.String("request_id", requestID.String()),
		util.String("rejected_by", rejectedBy.String()),
		util.Duration("duration", time.Since(startTime)))

	return nil
}

func (s *schedulingServiceImpl) ValidateOffRequest(
	ctx context.Context,
	userID uuid.UUID,
	requestDates []string,
	excludeRequestID *uuid.UUID,
) error {
	// Check for existing schedule overrides
	for _, dateStr := range requestDates {
		date, err := time.Parse("2006-01-02", dateStr)
		if err != nil {
			return fmt.Errorf("invalid date format: %s", dateStr)
		}

		override, err := s.schedulingRepo.GetScheduleOverrideByUserDate(ctx, userID, date)
		if err == nil && override != nil {
			if override.OverrideType == "force_work" {
				return fmt.Errorf("user is scheduled to work on %s", dateStr)
			}
		}
	}

	// Check for duplicate requests
	statusPending := "pending"
	statusApproved := "approved"
	existingRequests, err := s.schedulingRepo.GetOffRequestsByUser(ctx, userID, nil, nil, &statusPending)
	if err == nil {
		for _, existing := range existingRequests {
			if excludeRequestID != nil && existing.OffRequestID == *excludeRequestID {
				continue
			}
			for _, existingDate := range existing.RequestDates {
				for _, newDate := range requestDates {
					if existingDate == newDate {
						return fmt.Errorf("duplicate request for date: %s", newDate)
					}
				}
			}
		}
	}

	approvedRequests, err := s.schedulingRepo.GetOffRequestsByUser(ctx, userID, nil, nil, &statusApproved)
	if err == nil {
		for _, existing := range approvedRequests {
			if excludeRequestID != nil && existing.OffRequestID == *excludeRequestID {
				continue
			}
			for _, existingDate := range existing.RequestDates {
				for _, newDate := range requestDates {
					if existingDate == newDate {
						return fmt.Errorf("already has approved request for date: %s", newDate)
					}
				}
			}
		}
	}

	return nil
}

func (s *schedulingServiceImpl) UpdateScheduleOverride(
	ctx context.Context,
	overrideID uuid.UUID,
	update scheduling.ScheduleOverrideUpdate,
	actorType string,
	actorID uuid.UUID,
	metadata map[string]interface{},
) (*scheduling.ScheduleOverride, error) {
	startTime := time.Now()

	override, err := s.schedulingRepo.GetScheduleOverrideByID(ctx, overrideID)
	if err != nil {
		return nil, fmt.Errorf("schedule override not found: %w", err)
	}

	beforeState, _ := json.Marshal(override)

	if update.OverrideType != nil {
		override.OverrideType = *update.OverrideType
	}
	if update.Reason != nil {
		override.Reason = update.Reason
	}

	// Validate
	if err := s.validateScheduleOverride(override); err != nil {
		return nil, fmt.Errorf("schedule override validation failed: %w", err)
	}

	err = s.schedulingRepo.UpdateScheduleOverride(ctx, override)
	if err != nil {
		s.logger.Error("Failed to update schedule override",
			util.String("override_id", overrideID.String()),
			util.ErrorField(err))
		return nil, fmt.Errorf("failed to update schedule override: %w", err)
	}

	s.logAuditAction(ctx, override.CompanyID, "schedule_override.update", overrideID,
		actorType, actorID, beforeState, override, metadata)

	s.logger.Info("Schedule override updated",
		util.String("override_id", overrideID.String()),
		util.Duration("duration", time.Since(startTime)))

	return override, nil
}

func (s *schedulingServiceImpl) DeleteScheduleOverride(
	ctx context.Context,
	overrideID uuid.UUID,
	actorType string,
	actorID uuid.UUID,
	metadata map[string]interface{},
) error {
	startTime := time.Now()

	override, err := s.schedulingRepo.GetScheduleOverrideByID(ctx, overrideID)
	if err != nil {
		return fmt.Errorf("schedule override not found: %w", err)
	}

	beforeState, _ := json.Marshal(override)

	err = s.schedulingRepo.DeleteScheduleOverride(ctx, overrideID)
	if err != nil {
		s.logger.Error("Failed to delete schedule override",
			util.String("override_id", overrideID.String()),
			util.ErrorField(err))
		return fmt.Errorf("failed to delete schedule override: %w", err)
	}

	s.logAuditAction(ctx, override.CompanyID, "schedule_override.delete", overrideID,
		actorType, actorID, beforeState, nil, metadata)

	s.logger.Info("Schedule override deleted",
		util.String("override_id", overrideID.String()),
		util.Duration("duration", time.Since(startTime)))

	return nil
}

func (s *schedulingServiceImpl) GetScheduleOverridesByUser(
	ctx context.Context,
	userID uuid.UUID,
	startDate, endDate time.Time,
) ([]*scheduling.ScheduleOverride, error) {
	return s.schedulingRepo.GetScheduleOverridesByUser(ctx, userID, &startDate, &endDate, nil)
}

func (s *schedulingServiceImpl) GetUserTimeOffSummary(
	ctx context.Context,
	userID uuid.UUID,
	startDate, endDate time.Time,
) (map[string]interface{}, error) {
	// Get current entitlement
	entitlement, err := s.schedulingRepo.GetCurrentOffEntitlement(ctx, userID, time.Now())

	// Get approved off requests in date range
	statusApproved := "approved"
	offRequests, err := s.schedulingRepo.GetOffRequestsByUser(ctx, userID, &startDate, &endDate, &statusApproved)
	if err != nil {
		offRequests = []*scheduling.OffRequest{}
	}

	// Get schedule overrides in date range
	overrides, err := s.schedulingRepo.GetScheduleOverridesByUser(ctx, userID, &startDate, &endDate, nil)
	if err != nil {
		overrides = []*scheduling.ScheduleOverride{}
	}

	// Calculate used days
	usedDays := 0
	for _, req := range offRequests {
		usedDays += len(req.RequestDates)
	}

	result := map[string]interface{}{
		"user_id":            userID,
		"start_date":         startDate.Format("2006-01-02"),
		"end_date":           endDate.Format("2006-01-02"),
		"off_requests":       offRequests,
		"schedule_overrides": overrides,
		"used_days":          usedDays,
	}

	if entitlement != nil {
		result["entitlement"] = entitlement
		result["total_days"] = entitlement.OffCount
		result["remaining_days"] = entitlement.OffCount - usedDays
	}

	return result, nil
}

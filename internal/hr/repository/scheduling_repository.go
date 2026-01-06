package repository

import (
	"auth-service/internal/hr/models/scheduling"
	"context"
	"time"

	"github.com/google/uuid"
)

// SchedulingRepository defines the interface for scheduling operations
type SchedulingRepository interface {
	// WorkCalendar methods
	CreateWorkCalendar(ctx context.Context, calendar *scheduling.WorkCalendar) error
	GetWorkCalendarByID(ctx context.Context, calendarID uuid.UUID) (*scheduling.WorkCalendar, error)
	GetWorkCalendarsByCompany(ctx context.Context, companyID uuid.UUID) ([]*scheduling.WorkCalendar, error)
	UpdateWorkCalendar(ctx context.Context, calendar *scheduling.WorkCalendar) error
	DeleteWorkCalendar(ctx context.Context, calendarID uuid.UUID) error

	// ScheduleTemplate methods
	CreateScheduleTemplate(ctx context.Context, template *scheduling.ScheduleTemplate) error
	GetScheduleTemplateByID(ctx context.Context, templateID uuid.UUID) (*scheduling.ScheduleTemplate, error)
	GetScheduleTemplatesByCompany(ctx context.Context, companyID uuid.UUID) ([]*scheduling.ScheduleTemplate, error)
	GetScheduleTemplatesByCalendar(ctx context.Context, calendarID uuid.UUID) ([]*scheduling.ScheduleTemplate, error)
	GetActiveTemplatesByType(ctx context.Context, companyID uuid.UUID, templateType string) ([]*scheduling.ScheduleTemplate, error)
	UpdateScheduleTemplate(ctx context.Context, template *scheduling.ScheduleTemplate) error
	DeleteScheduleTemplate(ctx context.Context, templateID uuid.UUID) error

	// UserScheduleAssignment methods
	CreateUserScheduleAssignment(ctx context.Context, assignment *scheduling.UserScheduleAssignment) error
	GetUserScheduleAssignment(ctx context.Context, userID, templateID uuid.UUID, effectiveFrom time.Time) (*scheduling.UserScheduleAssignment, error)
	GetUserCurrentScheduleAssignment(ctx context.Context, userID uuid.UUID, date time.Time) (*scheduling.UserScheduleAssignment, error)
	GetUserScheduleAssignments(ctx context.Context, userID uuid.UUID, startDate, endDate *time.Time) ([]*scheduling.UserScheduleAssignment, error)
	GetAssignmentsByTemplate(ctx context.Context, templateID uuid.UUID, activeOnly bool) ([]*scheduling.UserScheduleAssignment, error)
	UpdateUserScheduleAssignment(ctx context.Context, assignment *scheduling.UserScheduleAssignment) error
	EndUserScheduleAssignment(ctx context.Context, userID, templateID uuid.UUID, endDate time.Time) error
	DeleteUserScheduleAssignment(ctx context.Context, userID, templateID uuid.UUID, effectiveFrom time.Time) error

	// ScheduleInstance methods
	CreateScheduleInstance(ctx context.Context, instance *scheduling.ScheduleInstance) error
	GetScheduleInstanceByID(ctx context.Context, instanceID uuid.UUID) (*scheduling.ScheduleInstance, error)
	GetScheduleInstanceByUserDate(ctx context.Context, userID uuid.UUID, date time.Time) (*scheduling.ScheduleInstance, error)
	GetScheduleInstancesByUser(ctx context.Context, userID uuid.UUID, startDate, endDate time.Time) ([]*scheduling.ScheduleInstance, error)
	GetScheduleInstancesByCompany(ctx context.Context, companyID uuid.UUID, startDate, endDate time.Time) ([]*scheduling.ScheduleInstance, error)
	GetScheduleInstancesByTemplate(ctx context.Context, templateID uuid.UUID, startDate, endDate time.Time) ([]*scheduling.ScheduleInstance, error)
	UpdateScheduleInstance(ctx context.Context, instance *scheduling.ScheduleInstance) error
	DeleteScheduleInstance(ctx context.Context, instanceID uuid.UUID) error
	BulkCreateScheduleInstances(ctx context.Context, instances []*scheduling.ScheduleInstance) error

	// Analytics methods
	GetScheduleCoverage(ctx context.Context, companyID uuid.UUID, startDate, endDate time.Time) (map[string]interface{}, error)
	GetUserScheduleSummary(ctx context.Context, userID uuid.UUID, startDate, endDate time.Time) (map[string]interface{}, error)
	GetTemplateUtilization(ctx context.Context, templateID uuid.UUID, startDate, endDate time.Time) (map[string]interface{}, error)

	// Health check
	HealthCheck(ctx context.Context) error
}

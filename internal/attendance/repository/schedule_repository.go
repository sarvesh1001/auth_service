package repository

import (
	"context"
	"database/sql"
	"time"

	"github.com/google/uuid"

	"auth-service/internal/attendance/models"
)

type ScheduleRepository interface {
	// ── Work Centers ──
	GetWorkCenter(ctx context.Context, companyID uuid.UUID, workCenterCode string) (*models.WorkCenter, error)
	GetWorkCentersByCompany(ctx context.Context, companyID uuid.UUID, activeOnly bool) ([]*models.WorkCenter, error)

	// ── Work Calendars ──
	GetWorkCalendar(ctx context.Context, companyID uuid.UUID, year int) (*models.WorkCalendar, error)
	GetWorkCalendarsByCompany(ctx context.Context, companyID uuid.UUID, locationID *uuid.UUID) ([]*models.WorkCalendar, error)
	CreateWorkCalendar(ctx context.Context, calendar *models.WorkCalendar) error
	GetWorkCalendarByID(ctx context.Context, calendarID uuid.UUID) (*models.WorkCalendar, error)
	UpdateWorkCalendar(ctx context.Context, calendar *models.WorkCalendar) error
	DeleteWorkCalendar(ctx context.Context, calendarID uuid.UUID) error

	// ── Schedule Templates ──
	GetScheduleTemplate(ctx context.Context, templateID uuid.UUID) (*models.ScheduleTemplate, error)
	GetScheduleTemplatesByCompany(ctx context.Context, companyID uuid.UUID, locationID *uuid.UUID, activeOnly bool) ([]*models.ScheduleTemplate, error)
	CreateScheduleTemplate(ctx context.Context, template *models.ScheduleTemplate) error
	GetScheduleTemplatesByCalendar(ctx context.Context, calendarID uuid.UUID) ([]*models.ScheduleTemplate, error)
	UpdateScheduleTemplate(ctx context.Context, template *models.ScheduleTemplate) error
	DeleteScheduleTemplate(ctx context.Context, templateID uuid.UUID) error

	// ── Schedule Instances ──
	GetScheduleInstance(ctx context.Context, instanceID uuid.UUID) (*models.ScheduleInstance, error)
	GetScheduleInstancesByUserDate(ctx context.Context, userID uuid.UUID, date time.Time) ([]*models.ScheduleInstance, error)
	CreateScheduleInstance(ctx context.Context, tx *sql.Tx, instance *models.ScheduleInstance) error
	UpdateScheduleInstanceStatus(ctx context.Context, tx *sql.Tx, instanceID uuid.UUID, status string, cancelReason *string) error
	GetScheduleInstancesByUser(ctx context.Context, userID uuid.UUID, startDate, endDate time.Time) ([]*models.ScheduleInstance, error)

	// GetScheduleInstancesByCompany returns instances for a company, optionally
	// scoped to a single location (snapshot from the instance row).
	GetScheduleInstancesByCompany(ctx context.Context, companyID uuid.UUID, locationID *uuid.UUID, startDate, endDate time.Time) ([]*models.ScheduleInstance, error)

	GetScheduleInstancesByTemplate(ctx context.Context, templateID uuid.UUID, startDate, endDate time.Time) ([]*models.ScheduleInstance, error)
	GetScheduleInstancesByWorkCenter(ctx context.Context, companyID uuid.UUID, workCenterCode string, startDate, endDate time.Time) ([]*models.ScheduleInstance, error)
	UpdateScheduleInstance(ctx context.Context, instance *models.ScheduleInstance) error
	DeleteScheduleInstance(ctx context.Context, instanceID uuid.UUID) error
	CancelScheduleInstance(ctx context.Context, instanceID uuid.UUID, reason string) error
	HasActiveSchedule(ctx context.Context, companyID, userID uuid.UUID, date time.Time) (bool, error)

	// ── Schedule Overrides ──
	CreateScheduleOverride(ctx context.Context, override *models.ScheduleOverride) error
	GetScheduleOverrideByID(ctx context.Context, overrideID uuid.UUID) (*models.ScheduleOverride, error)
	GetScheduleOverridesByUser(ctx context.Context, userID uuid.UUID, startDate, endDate *time.Time, overrideType *string) ([]*models.ScheduleOverride, error)
	GetScheduleOverridesByCompany(ctx context.Context, companyID uuid.UUID, startDate, endDate *time.Time, overrideType *string) ([]*models.ScheduleOverride, error)
	GetScheduleOverrideByUserDate(ctx context.Context, userID uuid.UUID, date time.Time) (*models.ScheduleOverride, error)
	UpdateScheduleOverride(ctx context.Context, override *models.ScheduleOverride) error
	DeleteScheduleOverride(ctx context.Context, overrideID uuid.UUID) error
	DeleteScheduleOverridesByReason(ctx context.Context, companyID, userID uuid.UUID, reason string) error

	// ── Work Center Shift Mappings ──
	CreateWorkCenterShiftMapping(ctx context.Context, mapping *models.WorkCenterShift) error
	GetWorkCenterShiftByCode(ctx context.Context, companyID uuid.UUID, workCenterCode string, date time.Time) (*models.WorkCenterShift, error)
	GetWorkCenterShiftMappingsByShift(ctx context.Context, shiftID uuid.UUID) ([]*models.WorkCenterShift, error)
	UpdateWorkCenterShiftMapping(ctx context.Context, mapping *models.WorkCenterShift) error

	// ── User Work Center Assignments ──
	GetUserWorkCenterAssignment(ctx context.Context, userID uuid.UUID, at time.Time) (*models.UserWorkCenterAssignment, error)
	GetUserWorkCenterAssignments(ctx context.Context, userID uuid.UUID) ([]*models.UserWorkCenterAssignment, error)

	// ── Off Entitlements ──
	GetUserOffEntitlement(ctx context.Context, userID uuid.UUID, at time.Time) (*models.UserOffEntitlement, error)

	// ── Off Requests ──
	GetOffRequests(ctx context.Context, userID uuid.UUID, startDate, endDate time.Time) ([]*models.OffRequest, error)

	// ── Legacy ──
	GetScheduleOverride(ctx context.Context, userID uuid.UUID, date time.Time) (*models.ScheduleOverride, error)

	HealthCheck(ctx context.Context) error
}

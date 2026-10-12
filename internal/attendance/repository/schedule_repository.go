package repository

import (
	"context"
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
	GetWorkCalendarByLocation(ctx context.Context, companyID, locationID uuid.UUID, year int) (*models.WorkCalendar, error)
	GetWorkCalendarCompanyWide(ctx context.Context, companyID uuid.UUID, year int) (*models.WorkCalendar, error)
	UpdateWorkCalendar(ctx context.Context, calendar *models.WorkCalendar) error
	DeleteWorkCalendar(ctx context.Context, calendarID uuid.UUID) error

	// ── Schedule Templates ──
	GetScheduleTemplate(ctx context.Context, templateID uuid.UUID) (*models.ScheduleTemplate, error)
	GetScheduleTemplatesByCompany(ctx context.Context, companyID uuid.UUID, locationID *uuid.UUID, activeOnly bool) ([]*models.ScheduleTemplate, error)
	CreateScheduleTemplate(ctx context.Context, template *models.ScheduleTemplate) error
	GetScheduleTemplatesByCalendar(ctx context.Context, calendarID uuid.UUID) ([]*models.ScheduleTemplate, error)
	UpdateScheduleTemplate(ctx context.Context, template *models.ScheduleTemplate) error
	DeleteScheduleTemplate(ctx context.Context, templateID uuid.UUID) error

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

	// ── Off Entitlements ──
	GetUserOffEntitlement(ctx context.Context, userID uuid.UUID, at time.Time) (*models.UserOffEntitlement, error)

	// ── Off Requests ──
	GetOffRequests(ctx context.Context, userID uuid.UUID, startDate, endDate time.Time) ([]*models.OffRequest, error)

	// ── Date-Scoped Reads (SAP-style effective dating) ──
	GetEmployeeAssignmentOnDate(ctx context.Context, companyID, userID uuid.UUID, date time.Time) (*models.EmployeeAssignment, error)
	GetPositionOnDate(ctx context.Context, positionID uuid.UUID, date time.Time) (*models.PositionHistoryRow, error)
	GetScheduleTemplateOnDate(ctx context.Context, templateID uuid.UUID, date time.Time) (*models.ScheduleTemplate, error)
	GetCompanyRulesOnDate(ctx context.Context, companyID uuid.UUID, date time.Time) (*models.CompanyAttendanceRules, error)

	// GetScheduleTemplateForPositionOnDate returns the effective
	// position-scoped template for a position on a given date. Only rows
	// with position_id = positionID AND location_id IS NULL are
	// considered, per the chk_template_scope constraint. Returns nil when
	// no position-scoped row exists — the caller falls through to broader
	// scopes (WC, location, company).
	GetScheduleTemplateForPositionOnDate(
		ctx context.Context,
		companyID uuid.UUID,
		positionID uuid.UUID,
		date time.Time,
	) (*models.ScheduleTemplate, error)

	// GetScheduleTemplateForLocationOnDate returns the effective template
	// for a location (or the company-wide template when locationID is nil)
	// on a given date. Precedence: exact location match, then company-wide.
	// Only position_id IS NULL rows are considered.
	GetScheduleTemplateForLocationOnDate(
		ctx context.Context,
		companyID uuid.UUID,
		locationID *uuid.UUID,
		date time.Time,
	) (*models.ScheduleTemplate, error)

	HealthCheck(ctx context.Context) error
}

// internal/hr/repository/attendance/interface.go
package repository

import (
	"context"
	"time"

	"auth-service/internal/hr/models/attendance"

	"github.com/google/uuid"
)

type AttendanceRepository interface {
	// ============================================================
	// ATTENDANCE EVENTS (FACTS)
	// ============================================================
	CreateAttendanceEvent(
		ctx context.Context,
		event *attendance.AttendanceEvent,
	) error

	CreateBulkAttendanceEvents(
		ctx context.Context,
		events []*attendance.AttendanceEvent,
	) error

	GetAttendanceEventByID(
		ctx context.Context,
		eventID uuid.UUID,
	) (*attendance.AttendanceEvent, error)

	GetAttendanceEventsByUser(
		ctx context.Context,
		userID uuid.UUID,
		startDate, endDate time.Time,
		limit int,
	) ([]*attendance.AttendanceEvent, error)

	GetAttendanceEventsByCompany(
		ctx context.Context,
		companyID uuid.UUID,
		startDate, endDate time.Time,
		page, pageSize int,
	) ([]*attendance.AttendanceEvent, int64, error)

	SearchAttendanceEvents(
		ctx context.Context,
		filter AttendanceEventFilter,
	) ([]*attendance.AttendanceEvent, int64, error)

	// ============================================================
	// DAILY ATTENDANCE SUMMARY (DERIVED DATA)
	// ============================================================
	CreateAttendanceDailySummary(
		ctx context.Context,
		summary *attendance.AttendanceDailySummary,
	) error

	UpdateAttendanceDailySummary(
		ctx context.Context,
		summary *attendance.AttendanceDailySummary,
	) error

	GetAttendanceDailySummaryByUserDate(
		ctx context.Context,
		userID uuid.UUID,
		date time.Time,
	) (*attendance.AttendanceDailySummary, error)

	GetAttendanceDailySummariesByUser(
		ctx context.Context,
		userID uuid.UUID,
		startDate, endDate time.Time,
	) ([]*attendance.AttendanceDailySummary, error)

	GetAttendanceDailySummariesByCompany(
		ctx context.Context,
		companyID uuid.UUID,
		startDate, endDate time.Time,
		page, pageSize int,
	) ([]*attendance.AttendanceDailySummary, int64, error)

	DeleteAttendanceDailySummary(
		ctx context.Context,
		summaryID uuid.UUID,
	) error

	// ============================================================
	// ATTENDANCE RULES (STORAGE ONLY)
	// ============================================================
	// Event & source masters
	GetAttendanceEventTypes(
		ctx context.Context,
	) ([]*attendance.AttendanceEventType, error)

	GetAttendanceSourceTypes(
		ctx context.Context,
	) ([]*attendance.AttendanceSourceType, error)

	// Company-level rules
	GetCompanyAttendanceRules(
		ctx context.Context,
		companyID uuid.UUID,
	) (*attendance.CompanyAttendanceRules, error)

	UpsertCompanyAttendanceRules(
		ctx context.Context,
		rules *attendance.CompanyAttendanceRules,
	) error

	// Department-level rules
	GetDepartmentAttendanceRules(
		ctx context.Context,
		companyID uuid.UUID,
		departmentID uuid.UUID,
	) (*attendance.DepartmentAttendanceRules, error)

	UpsertDepartmentAttendanceRules(
		ctx context.Context,
		rules *attendance.DepartmentAttendanceRules,
	) error

	// User overrides
	GetUserAttendanceProfile(
		ctx context.Context,
		userID uuid.UUID,
	) (*attendance.UserAttendanceProfile, error)

	UpsertUserAttendanceProfile(
		ctx context.Context,
		profile *attendance.UserAttendanceProfile,
	) error

	// ============================================================
	// ATTENDANCE POLICIES (STORAGE ONLY)
	// ============================================================
	CreateAttendancePolicy(
		ctx context.Context,
		policy *attendance.AttendancePolicy,
	) error

	GetAttendancePolicyByID(
		ctx context.Context,
		policyID uuid.UUID,
	) (*attendance.AttendancePolicy, error)

	GetAttendancePoliciesByCompany(
		ctx context.Context,
		companyID uuid.UUID,
		activeOnly bool,
	) ([]*attendance.AttendancePolicy, error)

	UpdateAttendancePolicy(
		ctx context.Context,
		policy *attendance.AttendancePolicy,
	) error

	DeleteAttendancePolicy(
		ctx context.Context,
		policyID uuid.UUID,
	) error

	AssignUserAttendancePolicy(
		ctx context.Context,
		assignment *attendance.UserAttendancePolicy,
	) error

	GetUserActiveAttendancePolicy(
		ctx context.Context,
		userID uuid.UUID,
		at time.Time,
	) (*attendance.AttendancePolicy, error)

	EndUserAttendancePolicy(
		ctx context.Context,
		userID, policyID uuid.UUID,
		endDate time.Time,
	) error

	// ============================================================
	// INFRASTRUCTURE (RFID, SOURCES, WORK CENTERS)
	// ============================================================
	CreateAttendanceSource(
		ctx context.Context,
		source *attendance.AttendanceSource,
	) error

	GetAttendanceSourceByID(
		ctx context.Context,
		sourceID uuid.UUID,
	) (*attendance.AttendanceSource, error)

	GetAttendanceSourcesByCompany(
		ctx context.Context,
		companyID uuid.UUID,
		activeOnly bool,
	) ([]*attendance.AttendanceSource, error)

	UpdateAttendanceSource(
		ctx context.Context,
		source *attendance.AttendanceSource,
	) error

	CreateAttendanceLocation(
		ctx context.Context,
		location *attendance.AttendanceLocation,
	) error

	GetAttendanceLocationByID(
		ctx context.Context,
		locationID uuid.UUID,
	) (*attendance.AttendanceLocation, error)

	GetAttendanceLocationsByCompany(
		ctx context.Context,
		companyID uuid.UUID,
		activeOnly bool,
	) ([]*attendance.AttendanceLocation, error)

	CreateEmployeeRFIDMapping(
		ctx context.Context,
		mapping *attendance.EmployeeRFIDMapping,
	) error

	GetEmployeeRFIDMappingByUser(
		ctx context.Context,
		userID uuid.UUID,
	) (*attendance.EmployeeRFIDMapping, error)

	GetEmployeeRFIDMapping(
		ctx context.Context,
		rfidTag string,
	) (*attendance.EmployeeRFIDMapping, error)

	UpdateEmployeeRFIDMapping(
		ctx context.Context,
		mapping *attendance.EmployeeRFIDMapping,
	) error

	DeactivateEmployeeRFIDMapping(
		ctx context.Context,
		rfidID uuid.UUID,
	) error

	CreateWorkCenterShift(
		ctx context.Context,
		mapping *attendance.WorkCenterShift,
	) error

	GetWorkCenterShiftByCode(
		ctx context.Context,
		companyID uuid.UUID,
		workCenterCode string,
	) (*attendance.WorkCenterShift, error)

	GetWorkCenterShiftsByCompany(
		ctx context.Context,
		companyID uuid.UUID,
		activeOnly bool,
	) ([]*attendance.WorkCenterShift, error)

	UpdateWorkCenterShift(
		ctx context.Context,
		mapping *attendance.WorkCenterShift,
	) error

	DeactivateWorkCenterShift(
		ctx context.Context,
		mappingID uuid.UUID,
	) error

	// ============================================================
	// SAP BUSINESS RULES
	// ============================================================
	GetSAPBusinessRules(
		ctx context.Context,
		companyID uuid.UUID,
	) (*attendance.SAPBusinessRules, error)

	UpdateSAPBusinessRules(
		ctx context.Context,
		companyID uuid.UUID,
		rules *attendance.SAPBusinessRules,
	) error

	// ============================================================
	// ANALYTICS
	// ============================================================
	GetAttendanceStats(
		ctx context.Context,
		companyID uuid.UUID,
		startDate, endDate time.Time,
	) (*attendance.AttendanceStats, error)

	GetUserAttendanceStats(
		ctx context.Context,
		userID uuid.UUID,
		startDate, endDate time.Time,
	) (*attendance.UserAttendanceStats, error)

	// ============================================================
	// HEALTH
	// ============================================================
	HealthCheck(ctx context.Context) error
}

type AttendanceEventFilter struct {
	CompanyID  uuid.UUID
	UserID     *uuid.UUID
	StartDate  time.Time
	EndDate    time.Time
	EventType  *string
	SourceType *string
	Page       int
	PageSize   int
}

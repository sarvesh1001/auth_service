package repository

import (
	"auth-service/internal/hr/models/attendance"
	"context"
	"time"

	"github.com/google/uuid"
)

// AttendanceRepository defines the interface for attendance-related operations
type AttendanceRepository interface {
	// ==================== Attendance Events ====================
	CreateAttendanceEvent(ctx context.Context, event *attendance.AttendanceEvent) error
	GetAttendanceEventByID(ctx context.Context, eventID uuid.UUID) (*attendance.AttendanceEvent, error)
	GetAttendanceEventsByUser(ctx context.Context, userID uuid.UUID, startDate, endDate time.Time, limit int) ([]*attendance.AttendanceEvent, error)
	GetAttendanceEventsByCompany(ctx context.Context, companyID uuid.UUID, startDate, endDate time.Time, limit, offset int) ([]*attendance.AttendanceEvent, int, error)
	SearchAttendanceEvents(ctx context.Context, companyID uuid.UUID, filters map[string]interface{}, limit, offset int) ([]*attendance.AttendanceEvent, int, error)
	UpdateAttendanceEvent(ctx context.Context, event *attendance.AttendanceEvent) error
	DeleteAttendanceEvent(ctx context.Context, eventID uuid.UUID) error
	GetRecentAttendanceEvents(ctx context.Context, companyID uuid.UUID, limit int) ([]*attendance.AttendanceEvent, error)

	// ==================== Attendance Policies ====================
	CreateAttendancePolicy(ctx context.Context, policy *attendance.AttendancePolicy) error
	GetAttendancePolicyByID(ctx context.Context, policyID uuid.UUID) (*attendance.AttendancePolicy, error)
	GetAttendancePolicyByCode(ctx context.Context, companyID uuid.UUID, policyCode string) (*attendance.AttendancePolicy, error)
	GetAttendancePoliciesByCompany(ctx context.Context, companyID uuid.UUID, activeOnly bool) ([]*attendance.AttendancePolicy, error)
	UpdateAttendancePolicy(ctx context.Context, policy *attendance.AttendancePolicy) error
	DeleteAttendancePolicy(ctx context.Context, policyID uuid.UUID) error

	// ==================== User Attendance Policies ====================
	AssignUserAttendancePolicy(ctx context.Context, userPolicy *attendance.UserAttendancePolicy) error
	GetUserAttendancePolicy(ctx context.Context, userID uuid.UUID, policyID uuid.UUID) (*attendance.UserAttendancePolicy, error)
	GetUserCurrentAttendancePolicy(ctx context.Context, userID uuid.UUID, asOfDate time.Time) (*attendance.AttendancePolicy, error)
	GetUserAttendancePolicyHistory(ctx context.Context, userID uuid.UUID) ([]*attendance.UserAttendancePolicy, error)
	UpdateUserAttendancePolicy(ctx context.Context, userPolicy *attendance.UserAttendancePolicy) error
	RemoveUserAttendancePolicy(ctx context.Context, userID, policyID uuid.UUID) error

	// ==================== Attendance Sources ====================
	CreateAttendanceSource(ctx context.Context, source *attendance.AttendanceSource) error
	GetAttendanceSourceByID(ctx context.Context, sourceID uuid.UUID) (*attendance.AttendanceSource, error)
	GetAttendanceSourcesByCompany(ctx context.Context, companyID uuid.UUID, activeOnly bool) ([]*attendance.AttendanceSource, error)
	UpdateAttendanceSource(ctx context.Context, source *attendance.AttendanceSource) error
	DeleteAttendanceSource(ctx context.Context, sourceID uuid.UUID) error

	// ==================== Attendance Daily Summary ====================
	CreateAttendanceDailySummary(ctx context.Context, summary *attendance.AttendanceDailySummary) error
	GetAttendanceDailySummaryByID(ctx context.Context, summaryID uuid.UUID) (*attendance.AttendanceDailySummary, error)
	GetAttendanceDailySummaryByUserDate(ctx context.Context, userID uuid.UUID, date time.Time) (*attendance.AttendanceDailySummary, error)
	GetAttendanceDailySummariesByUser(ctx context.Context, userID uuid.UUID, startDate, endDate time.Time) ([]*attendance.AttendanceDailySummary, error)
	GetAttendanceDailySummariesByCompany(ctx context.Context, companyID uuid.UUID, date time.Time) ([]*attendance.AttendanceDailySummary, error)
	UpdateAttendanceDailySummary(ctx context.Context, summary *attendance.AttendanceDailySummary) error
	DeleteAttendanceDailySummary(ctx context.Context, summaryID uuid.UUID) error
	GetAttendanceSummaryStats(ctx context.Context, companyID uuid.UUID, startDate, endDate time.Time) (map[string]interface{}, error)

	// ==================== Attendance Locations ====================
	CreateAttendanceLocation(ctx context.Context, location *attendance.AttendanceLocation) error
	GetAttendanceLocationByID(ctx context.Context, locationID uuid.UUID) (*attendance.AttendanceLocation, error)
	GetAttendanceLocationsByCompany(ctx context.Context, companyID uuid.UUID, activeOnly bool) ([]*attendance.AttendanceLocation, error)
	UpdateAttendanceLocation(ctx context.Context, location *attendance.AttendanceLocation) error
	DeleteAttendanceLocation(ctx context.Context, locationID uuid.UUID) error

	// ==================== Batch Operations ====================
	CreateAttendanceEventsBatch(ctx context.Context, events []*attendance.AttendanceEvent) error
	CreateAttendanceDailySummariesBatch(ctx context.Context, summaries []*attendance.AttendanceDailySummary) error

	// ==================== Analytics & Reports ====================
	GetAttendanceReportByDepartment(ctx context.Context, companyID uuid.UUID, startDate, endDate time.Time) (map[string]interface{}, error)
	GetLateArrivalsReport(ctx context.Context, companyID uuid.UUID, startDate, endDate time.Time) ([]map[string]interface{}, error)
	GetAbsenceReport(ctx context.Context, companyID uuid.UUID, startDate, endDate time.Time) ([]map[string]interface{}, error)
	GetOvertimeReport(ctx context.Context, companyID uuid.UUID, startDate, endDate time.Time) ([]map[string]interface{}, error)

	// ==================== Health Check ====================
	HealthCheck(ctx context.Context) error
	// New methods for user/location/shift lookups
	GetUserIDByEmployeeID(ctx context.Context, employeeID string, companyID uuid.UUID) (uuid.UUID, error)
	GetUserIDByRFID(ctx context.Context, rfid string, companyID uuid.UUID) (uuid.UUID, error)
	GetLocationIDByCode(ctx context.Context, locationCode string, companyID uuid.UUID) (uuid.UUID, error)
	GetLocationIDByFactoryZone(ctx context.Context, zone string, companyID uuid.UUID) (uuid.UUID, error)
	GetShiftIDByWorkCenter(ctx context.Context, workCenter string, companyID uuid.UUID) (uuid.UUID, error)

	CreateRFIDMapping(ctx context.Context, mapping *attendance.EmployeeRFIDMapping) error
	GetRFIDMappingByTag(ctx context.Context, rfidTag string, companyID uuid.UUID) (*attendance.EmployeeRFIDMapping, error)
	GetRFIDMappingByUser(ctx context.Context, userID uuid.UUID, companyID uuid.UUID) (*attendance.EmployeeRFIDMapping, error)
	UpdateRFIDMapping(ctx context.Context, mapping *attendance.EmployeeRFIDMapping) error
	DeactivateRFIDMapping(ctx context.Context, rfidID uuid.UUID) error
	GetActiveRFIDMappingsByCompany(ctx context.Context, companyID uuid.UUID) ([]*attendance.EmployeeRFIDMapping, error)

	// New methods for work center shifts
	CreateWorkCenterShift(ctx context.Context, wcShift *attendance.WorkCenterShift) error
	GetWorkCenterShiftByCode(ctx context.Context, workCenterCode string, companyID uuid.UUID) (*attendance.WorkCenterShift, error)
	GetWorkCenterShiftsByCompany(ctx context.Context, companyID uuid.UUID, activeOnly bool) ([]*attendance.WorkCenterShift, error)
	UpdateWorkCenterShift(ctx context.Context, wcShift *attendance.WorkCenterShift) error
	DeactivateWorkCenterShift(ctx context.Context, mappingID uuid.UUID) error

	// SAP business rules
	GetSAPBusinessRules(ctx context.Context, companyID uuid.UUID) (*attendance.SAPBusinessRules, error)
	SaveSAPBusinessRules(ctx context.Context, companyID uuid.UUID, rules *attendance.SAPBusinessRules) error

	// GetAttendanceEventType fetches a single attendance event type by key
	GetAttendanceEventType(
		ctx context.Context,
		eventType string,
	) (*attendance.AttendanceEventType, error)

	// ListAttendanceEventTypes lists all attendance event types
	// If activeOnly is true, only active types are returned
	ListAttendanceEventTypes(
		ctx context.Context,
		activeOnly bool,
	) ([]*attendance.AttendanceEventType, error)

	// =========================================================================
	// ATTENDANCE SOURCE TYPES
	// =========================================================================

	// GetAttendanceSourceType fetches a single source type
	GetAttendanceSourceType(
		ctx context.Context,
		sourceType string,
	) (*attendance.AttendanceSourceType, error)

	// ListAttendanceSourceTypes lists all available source types
	ListAttendanceSourceTypes(
		ctx context.Context,
	) ([]*attendance.AttendanceSourceType, error)

	// =========================================================================
	// COMPANY ATTENDANCE RULES
	// =========================================================================

	// GetCompanyAttendanceRules fetches company-level attendance rules.
	// If rules do not exist, implementation should return defaults.
	GetCompanyAttendanceRules(
		ctx context.Context,
		companyID uuid.UUID,
	) (*attendance.CompanyAttendanceRules, error)

	// UpsertCompanyAttendanceRules creates or updates company attendance rules
	UpsertCompanyAttendanceRules(
		ctx context.Context,
		rules *attendance.CompanyAttendanceRules,
	) error

	// =========================================================================
	// DEPARTMENT ATTENDANCE RULES
	// =========================================================================

	// GetDepartmentAttendanceRules fetches department-specific rules.
	// Returns nil if no department override exists.
	GetDepartmentAttendanceRules(
		ctx context.Context,
		companyID uuid.UUID,
		departmentID uuid.UUID,
	) (*attendance.DepartmentAttendanceRules, error)

	// =========================================================================
	// USER ATTENDANCE PROFILE
	// =========================================================================

	// GetUserAttendanceProfile fetches user-specific attendance overrides.
	// Returns nil if no user override exists.
	GetUserAttendanceProfile(
		ctx context.Context,
		userID uuid.UUID,
	) (*attendance.UserAttendanceProfile, error)

	// Department-level attendance rules
	UpsertDepartmentAttendanceRules(
		ctx context.Context,
		rules *attendance.DepartmentAttendanceRules,
	) error

	// User-level attendance overrides
	UpsertUserAttendanceProfile(
		ctx context.Context,
		profile *attendance.UserAttendanceProfile,
	) error
	GetEmployeeDepartment(ctx context.Context, userID uuid.UUID, companyID uuid.UUID) (*uuid.UUID, error)
}

package attendance

import (
	"time"

	"github.com/google/uuid"
)

// AttendanceSourceType represents a valid attendance source type

// CompanyAttendanceRules represents company-level attendance rules
type CompanyAttendanceRules struct {
	CompanyID             uuid.UUID `json:"company_id"`
	AllowedSourceTypes    []string  `json:"allowed_source_types"`
	AllowMultipleCheckins bool      `json:"allow_multiple_checkins"`
	Timezone              string    `json:"timezone"`
	CreatedAt             time.Time `json:"created_at"`
}

// DepartmentAttendanceRules represents department-level attendance rules
type DepartmentAttendanceRules struct {
	RuleID             uuid.UUID `json:"rule_id"`
	CompanyID          uuid.UUID `json:"company_id"`
	DepartmentID       uuid.UUID `json:"department_id"`
	AllowedSourceTypes []string  `json:"allowed_source_types"`
	AllowedEventTypes  []string  `json:"allowed_event_types"`
	RequireLocation    bool      `json:"require_location"`
	RequireDevice      bool      `json:"require_device"`
	CreatedAt          time.Time `json:"created_at"`
}

// UserAttendanceProfile represents user-level attendance overrides
type UserAttendanceProfile struct {
	UserID              uuid.UUID `json:"user_id"`
	CompanyID           uuid.UUID `json:"company_id"`
	OverrideSourceTypes []string  `json:"override_source_types,omitempty"`
	OverrideEventTypes  []string  `json:"override_event_types,omitempty"`
	CreatedAt           time.Time `json:"created_at"`
}

type ResolvedAttendanceRules struct {
	// Company
	CompanyID             uuid.UUID
	Timezone              string
	AllowMultipleCheckins bool

	// Internal (fast validation)
	AllowedSourceTypesMap map[string]bool
	AllowedEventTypesMap  map[string]bool
	AllowAllEventTypes    bool

	// API output
	AllowedSourceTypes []string
	AllowedEventTypes  []string

	// Requirements
	RequireLocation  bool
	RequireDevice    bool
	RequireReference bool

	// Metadata
	SourceLevel string // company | work_center | position | user_override
	AppliedAt   time.Time

	// New fields for work-center and position-based policies
	PolicyID       *uuid.UUID   `json:"policy_id,omitempty"`
	PolicyRules    *PolicyRules `json:"policy_rules,omitempty"`
	WorkCenterCode *string      `json:"work_center_code,omitempty"`
	PositionID     *uuid.UUID   `json:"position_id,omitempty"`
	PolicySource   string       `json:"policy_source"` // user | work_center | position | default
}

// AttendanceStats for analytics
type AttendanceStats struct {
	CompanyID          uuid.UUID `json:"company_id"`
	StartDate          time.Time `json:"start_date"`
	EndDate            time.Time `json:"end_date"`
	TotalEmployees     int       `json:"total_employees"`
	PresentCount       int       `json:"present_count"`
	AbsentCount        int       `json:"absent_count"`
	LateCount          int       `json:"late_count"`
	HalfDayCount       int       `json:"half_day_count"`
	LeaveCount         int       `json:"leave_count"`
	HolidayCount       int       `json:"holiday_count"`
	TotalWorkedHours   float64   `json:"total_worked_hours"`
	TotalOvertimeHours float64   `json:"total_overtime_hours"`
	AverageAttendance  float64   `json:"average_attendance"`
}

// UserAttendanceStats for user analytics
type UserAttendanceStats struct {
	UserID             uuid.UUID `json:"user_id"`
	StartDate          time.Time `json:"start_date"`
	EndDate            time.Time `json:"end_date"`
	PresentDays        int       `json:"present_days"`
	AbsentDays         int       `json:"absent_days"`
	LateDays           int       `json:"late_days"`
	HalfDays           int       `json:"half_days"`
	LeaveDays          int       `json:"leave_days"`
	TotalWorkedHours   float64   `json:"total_worked_hours"`
	TotalOvertimeHours float64   `json:"total_overtime_hours"`
	AverageInTime      string    `json:"average_in_time"`
	AverageOutTime     string    `json:"average_out_time"`
	AttendancePercent  float64   `json:"attendance_percent"`
}

// WorkCenterShift maps work centers to shifts
type WorkCenterShift struct {
	MappingID      uuid.UUID  `json:"mapping_id" db:"mapping_id"`
	CompanyID      uuid.UUID  `json:"company_id" db:"company_id"`
	WorkCenterCode string     `json:"work_center_code" db:"work_center_code"`
	ShiftID        uuid.UUID  `json:"shift_id" db:"shift_id"` // References schedule_templates
	EffectiveFrom  time.Time  `json:"effective_from" db:"effective_from"`
	EffectiveTo    *time.Time `json:"effective_to" db:"effective_to"`
	IsActive       bool       `json:"is_active" db:"is_active"`
	CreatedAt      time.Time  `json:"created_at" db:"created_at"`
	UpdatedAt      time.Time  `json:"updated_at" db:"updated_at"`
}

// SAPBusinessRules contains SAP-specific business rules
type SAPBusinessRules struct {
	// Work Center Validation
	MinWorkCenterHours *int `json:"min_work_center_hours,omitempty"`
	MaxWorkCenterHours *int `json:"max_work_center_hours,omitempty"`

	// Overtime Rules
	OvertimeThreshold   *int  `json:"overtime_threshold,omitempty"` // Minutes
	AutoApproveOvertime *bool `json:"auto_approve_overtime,omitempty"`

	// Shift Overlap Rules
	AllowShiftOverlap *bool `json:"allow_shift_overlap,omitempty"`
	MaxOverlapMinutes *int  `json:"max_overlap_minutes,omitempty"`

	// Late Arrival Rules
	GracePeriodMinutes *int `json:"grace_period_minutes,omitempty"`
	MaxLateAllowed     *int `json:"max_late_allowed,omitempty"`

	// Validation Flags
	ValidateWorkCenter *bool `json:"validate_work_center,omitempty"`
	ValidateCostCenter *bool `json:"validate_cost_center,omitempty"`
	ValidateEmployeeID *bool `json:"validate_employee_id,omitempty"`
}

// AttendanceEventType represents a valid attendance event type
type AttendanceEventType struct {
	EventType         string  `json:"event_type"`
	Category          string  `json:"category"`
	Description       *string `json:"description,omitempty"`
	IsUserTriggered   bool    `json:"is_user_triggered"`
	IsSystemGenerated bool    `json:"is_system_generated"`
	IsActive          bool    `json:"is_active"`
}

// AttendanceSourceType represents a valid attendance source type

// AttendanceEvent represents an attendance event
type AttendanceEvent struct {
	AttendanceEventID uuid.UUID `json:"attendance_event_id" db:"attendance_event_id"`
	CompanyID         uuid.UUID `json:"company_id" db:"company_id"`
	UserID            uuid.UUID `json:"user_id" db:"user_id"`
	EventType         string    `json:"event_type" db:"event_type"`
	EventTime         time.Time `json:"event_time" db:"event_time"`

	// Source
	SourceType string     `json:"source_type" db:"source_type"`
	SourceID   *uuid.UUID `json:"source_id,omitempty" db:"source_id"`
	DeviceID   *string    `json:"device_id,omitempty" db:"device_id"`
	IPAddress  *string    `json:"ip_address,omitempty" db:"ip_address"`

	// NEW
	Context  EventContext  `json:"context,omitempty" db:"context"`
	Metadata EventMetadata `json:"metadata,omitempty" db:"metadata"`

	CreatedAt time.Time  `json:"created_at" db:"created_at"`
	CreatedBy *uuid.UUID `json:"created_by,omitempty" db:"created_by"`
}
type EventContext struct {
	WorkCenterCode   *string    `json:"work_center_code,omitempty"`
	LocationID       *uuid.UUID `json:"location_id,omitempty"`
	Reason           *string    `json:"reason,omitempty"`
	ExternalRef      *string    `json:"external_ref,omitempty"`
	CorrectionReason *string    `json:"correction_reason,omitempty"`
}

type EventMetadata struct {
	ShiftID *uuid.UUID `json:"shift_id,omitempty"`
	ClassID *uuid.UUID `json:"class_id,omitempty"`

	// system derived
	IsAutoGenerated *bool      `json:"is_auto_generated,omitempty"`
	IsCorrection    *bool      `json:"is_correction,omitempty"`
	OverrideStatus  *string    `json:"override_status,omitempty"`
	CorrectedBy     *uuid.UUID `json:"corrected_by,omitempty"`
}

// AttendancePolicy - Updated for position-based policies
// Add to your attendance/models.go file or update the existing AttendancePolicy struct:

// AttendancePolicy - Updated for work center and position-based policies
type AttendancePolicy struct {
	PolicyID       uuid.UUID   `json:"policy_id" db:"policy_id"`
	CompanyID      uuid.UUID   `json:"company_id" db:"company_id"`
	WorkCenterCode *string     `json:"work_center_code,omitempty" db:"work_center_code"`
	PositionID     *uuid.UUID  `json:"position_id,omitempty" db:"position_id"`
	PolicyCode     string      `json:"policy_code" db:"policy_code"`
	PolicyType     string      `json:"policy_type" db:"policy_type"`
	Rules          PolicyRules `json:"rules" db:"rules"`
	IsActive       bool        `json:"is_active" db:"is_active"`
	CreatedAt      time.Time   `json:"created_at" db:"created_at"`
	UpdatedAt      time.Time   `json:"updated_at" db:"updated_at"`
}
type PolicyRules struct {
	GracePeriod    *int  `json:"grace_period,omitempty"`     // minutes
	MaxLateAllowed *int  `json:"max_late_allowed,omitempty"` // minutes
	HalfDayAfter   *int  `json:"half_day_after,omitempty"`   // hours
	AutoCheckout   *bool `json:"auto_checkout,omitempty"`
	// Work center specific rules
	RequireWorkCenter  *bool    `json:"require_work_center,omitempty"`
	AllowedWorkCenters []string `json:"allowed_work_centers,omitempty"`
	// Shift rules
	AllowShiftOverlap *bool `json:"allow_shift_overlap,omitempty"`
	MaxOverlapMinutes *int  `json:"max_overlap_minutes,omitempty"`
	// Overtime rules
	OvertimeThreshold   *int  `json:"overtime_threshold,omitempty"`
	AutoApproveOvertime *bool `json:"auto_approve_overtime,omitempty"`
}

// UserAttendancePolicy links users to attendance policies
type UserAttendancePolicy struct {
	UserID        uuid.UUID  `json:"user_id" db:"user_id"`
	PolicyID      uuid.UUID  `json:"policy_id" db:"policy_id"`
	EffectiveFrom time.Time  `json:"effective_from" db:"effective_from"`
	EffectiveTo   *time.Time `json:"effective_to" db:"effective_to"`
	AssignedBy    *uuid.UUID `json:"assigned_by" db:"assigned_by"`
	CreatedAt     time.Time  `json:"created_at" db:"created_at"`
}

// EmployeeRFIDMapping maps RFID tags to employees
type EmployeeRFIDMapping struct {
	RFIDID       uuid.UUID  `json:"rfid_id" db:"rfid_id"`
	UserID       uuid.UUID  `json:"user_id" db:"user_id"`
	CompanyID    uuid.UUID  `json:"company_id" db:"company_id"`
	RFIDTag      string     `json:"rfid_tag" db:"rfid_tag"`
	IsActive     bool       `json:"is_active" db:"is_active"`
	AssignedAt   time.Time  `json:"assigned_at" db:"assigned_at"`
	UnassignedAt *time.Time `json:"unassigned_at" db:"unassigned_at"`
	CreatedAt    time.Time  `json:"created_at" db:"created_at"`
	UpdatedAt    time.Time  `json:"updated_at" db:"updated_at"`
}

type AttendanceSource struct {
	SourceID      uuid.UUID  `json:"source_id" db:"source_id"`
	CompanyID     uuid.UUID  `json:"company_id" db:"company_id"`
	SourceType    string     `json:"source_type" db:"source_type"`
	Name          string     `json:"name" db:"name"`
	ReferenceType *string    `json:"reference_type" db:"reference_type"`
	ReferenceID   *uuid.UUID `json:"reference_id" db:"reference_id"`
	IsActive      bool       `json:"is_active" db:"is_active"`
	CreatedAt     time.Time  `json:"created_at" db:"created_at"`
	CreatedBy     *uuid.UUID `json:"created_by" db:"created_by"`
}

type AttendanceDailySummary struct {
	AttendanceSummaryID uuid.UUID       `json:"attendance_summary_id" db:"attendance_summary_id"`
	CompanyID           uuid.UUID       `json:"company_id" db:"company_id"`
	UserID              uuid.UUID       `json:"user_id" db:"user_id"`
	AttendanceDate      time.Time       `json:"attendance_date" db:"attendance_date"`
	Status              string          `json:"status" db:"status"`
	WorkedMinutes       *int            `json:"worked_minutes" db:"worked_minutes"`
	OvertimeMinutes     *int            `json:"overtime_minutes" db:"overtime_minutes"`
	LateMinutes         *int            `json:"late_minutes" db:"late_minutes"`
	Metadata            SummaryMetadata `json:"metadata" db:"metadata"`
	GeneratedAt         time.Time       `json:"generated_at" db:"generated_at"`
	GeneratedBy         string          `json:"generated_by" db:"generated_by"`
}

// type SummaryMetadata struct {
// 	ClassesAttended *int       `json:"classes_attended,omitempty"`
// 	PeriodsTaken    *int       `json:"periods_taken,omitempty"`
// 	ShiftID         *uuid.UUID `json:"shift_id,omitempty"`
// 	PolicyID        *uuid.UUID `json:"policy_id,omitempty"`
// 	WorkCenterCode  *string    `json:"work_center_code,omitempty"`
// }

type AttendanceLocation struct {
	LocationID   uuid.UUID `json:"location_id" db:"location_id"`
	CompanyID    uuid.UUID `json:"company_id" db:"company_id"`
	Name         *string   `json:"name" db:"name"`
	LocationCode *string   `json:"location_code,omitempty" db:"location_code"`
	LocationType *string   `json:"location_type" db:"location_type"`
	Zone         *string   `json:"zone,omitempty" db:"zone"`
	GeoLat       *float64  `json:"geo_lat" db:"geo_lat"`
	GeoLng       *float64  `json:"geo_lng" db:"geo_lng"`
	IsActive     bool      `json:"is_active" db:"is_active"`
}

// PositionBasedPolicy represents a policy applied to a position
type PositionBasedPolicy struct {
	PolicyID       uuid.UUID   `json:"policy_id"`
	PositionID     uuid.UUID   `json:"position_id"`
	PositionTitle  string      `json:"position_title"`
	DepartmentID   uuid.UUID   `json:"department_id"`
	DepartmentName string      `json:"department_name"`
	PolicyCode     string      `json:"policy_code"`
	PolicyType     string      `json:"policy_type"`
	Rules          PolicyRules `json:"rules"`
	IsActive       bool        `json:"is_active"`
	TotalEmployees int         `json:"total_employees,omitempty"`
}

// UserPolicyAssignment represents a user's current policy assignment
type UserPolicyAssignment struct {
	UserID         uuid.UUID  `json:"user_id"`
	Username       string     `json:"username"`
	FullName       string     `json:"full_name"`
	PositionID     uuid.UUID  `json:"position_id"`
	PositionTitle  string     `json:"position_title"`
	PolicyID       uuid.UUID  `json:"policy_id"`
	PolicyCode     string     `json:"policy_code"`
	PolicyType     string     `json:"policy_type"`
	EffectiveFrom  time.Time  `json:"effective_from"`
	EffectiveTo    *time.Time `json:"effective_to,omitempty"`
	AssignedBy     *uuid.UUID `json:"assigned_by,omitempty"`
	AssignedByName *string    `json:"assigned_by_name,omitempty"`
}

type AttendanceDevice struct {
	DeviceID string `json:"device_id" db:"device_id"`

	CompanyID  uuid.UUID `json:"company_id" db:"company_id"`
	SourceType string    `json:"source_type" db:"source_type"`

	DeviceCode string  `json:"device_code" db:"device_code"`
	DeviceName *string `json:"device_name,omitempty" db:"device_name"`

	Manufacturer *string `json:"manufacturer,omitempty" db:"manufacturer"`
	Model        *string `json:"model,omitempty" db:"model"`

	WorkCenterCode *string    `json:"work_center_code,omitempty" db:"work_center_code"`
	LocationID     *uuid.UUID `json:"location_id,omitempty" db:"location_id"`

	IPAddress  *string `json:"ip_address,omitempty" db:"ip_address"`
	MacAddress *string `json:"mac_address,omitempty" db:"mac_address"`

	IsActive  bool `json:"is_active" db:"is_active"`
	IsTrusted bool `json:"is_trusted" db:"is_trusted"`

	LastSeenAt  *time.Time `json:"last_seen_at,omitempty" db:"last_seen_at"`
	InstalledAt *time.Time `json:"installed_at,omitempty" db:"installed_at"`

	Metadata map[string]interface{} `json:"metadata,omitempty" db:"metadata"`

	CreatedAt time.Time `json:"created_at" db:"created_at"`
}

type AttendanceIdentity struct {
	MappingID uuid.UUID `json:"mapping_id" db:"mapping_id"`

	CompanyID uuid.UUID `json:"company_id" db:"company_id"`
	UserID    uuid.UUID `json:"user_id" db:"user_id"`

	DeviceID   string `json:"device_id" db:"device_id"`
	SourceType string `json:"source_type" db:"source_type"`

	DeviceUserCode string `json:"device_user_code" db:"device_user_code"`

	IsActive bool `json:"is_active" db:"is_active"`

	EnrolledAt   time.Time  `json:"enrolled_at" db:"enrolled_at"`
	UnenrolledAt *time.Time `json:"unenrolled_at,omitempty" db:"unenrolled_at"`

	CreatedBy *uuid.UUID `json:"created_by,omitempty" db:"created_by"`
}

type AttendanceSourceType struct {
	SourceType  string  `json:"source_type" db:"source_type"`
	Description *string `json:"description,omitempty" db:"description"`

	Category       string `json:"category" db:"category"`
	RequiresDevice bool   `json:"requires_device" db:"requires_device"`
	IsSystem       bool   `json:"is_system" db:"is_system"`

	AllowBackdated bool `json:"allow_backdated" db:"allow_backdated"`
	AllowFuture    bool `json:"allow_future" db:"allow_future"`

	TrustLevel    int16 `json:"trust_level" db:"trust_level"`
	IsSelfService bool  `json:"is_self_service" db:"is_self_service"`

	CreatedAt time.Time `json:"created_at" db:"created_at"`
}

// Add to your attendance/models.go:

// AttendanceResolutionRequest represents a request to resolve attendance
type AttendanceResolutionRequest struct {
	EventID     *uuid.UUID `json:"event_id,omitempty"`
	UserID      *uuid.UUID `json:"user_id,omitempty"`
	CompanyID   *uuid.UUID `json:"company_id,omitempty"`
	Date        *time.Time `json:"date,omitempty"`
	Recalculate bool       `json:"recalculate"`
} // Add to your attendance/models.go:

// ShiftContext contains all shift information needed for resolution
type ShiftContext struct {
	ShiftID        *uuid.UUID `json:"shift_id,omitempty"`
	ShiftName      *string    `json:"shift_name,omitempty"`
	ExpectedStart  *time.Time `json:"expected_start,omitempty"`
	ExpectedEnd    *time.Time `json:"expected_end,omitempty"`
	ScheduleDate   time.Time  `json:"schedule_date"`
	ScheduleStatus string     `json:"schedule_status"`
	Timezone       string     `json:"timezone"`
	IsOnLeave      bool       `json:"is_on_leave"`
	IsOverride     bool       `json:"is_override"`
	OverrideType   *string    `json:"override_type,omitempty"`
	WorkCenterCode *string    `json:"work_center_code,omitempty"`
	PositionID     *uuid.UUID `json:"position_id,omitempty"`
	DepartmentID   *uuid.UUID `json:"department_id,omitempty"`
}

// Update SummaryMetadata to include anomalies:
type SummaryMetadata struct {
	ClassesAttended *int          `json:"classes_attended,omitempty"`
	PeriodsTaken    *int          `json:"periods_taken,omitempty"`
	ShiftID         *uuid.UUID    `json:"shift_id,omitempty"`
	PolicyID        *uuid.UUID    `json:"policy_id,omitempty"`
	WorkCenterCode  *string       `json:"work_center_code,omitempty"`
	CheckInTime     *time.Time    `json:"check_in_time,omitempty"`
	CheckOutTime    *time.Time    `json:"check_out_time,omitempty"`
	TotalCheckIns   *int          `json:"total_checkins,omitempty"`
	TotalCheckOuts  *int          `json:"total_checkouts,omitempty"`
	BreakMinutes    *int          `json:"break_minutes,omitempty"`
	ScheduleStatus  *string       `json:"schedule_status,omitempty"`
	Timezone        *string       `json:"timezone,omitempty"`
	Anomalies       []string      `json:"anomalies,omitempty"`
	PairedEvents    []PairedEvent `json:"paired_events,omitempty"`
}

type PairedEvent struct {
	CheckInEventID  uuid.UUID  `json:"check_in_event_id"`
	CheckOutEventID *uuid.UUID `json:"check_out_event_id,omitempty"`

	CheckInTime  time.Time  `json:"check_in_time"`
	CheckOutTime *time.Time `json:"check_out_time,omitempty"`

	WorkedMinutes *int `json:"worked_minutes,omitempty"`

	// Flags
	IsAutoClosed bool     `json:"is_auto_closed"`
	Anomalies    []string `json:"anomalies,omitempty"`
}

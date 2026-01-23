package attendance

import (
	"time"

	"github.com/google/uuid"
)

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
type AttendanceSourceType struct {
	SourceType        string  `json:"source_type"`
	Description       *string `json:"description,omitempty"`
	RequiresReference bool    `json:"requires_reference"`
}

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
	SourceLevel string // company | department | user_override
	AppliedAt   time.Time
}

type AttendanceEvent struct {
	AttendanceEventID uuid.UUID     `json:"attendance_event_id" db:"attendance_event_id"`
	CompanyID         uuid.UUID     `json:"company_id" db:"company_id"`
	UserID            uuid.UUID     `json:"user_id" db:"user_id"`
	EventType         string        `json:"event_type" db:"event_type"`
	EventTime         time.Time     `json:"event_time" db:"event_time"`
	SourceType        string        `json:"source_type" db:"source_type"`
	SourceID          *uuid.UUID    `json:"source_id" db:"source_id"`
	DeviceID          *string       `json:"device_id" db:"device_id"`
	IPAddress         *string       `json:"ip_address" db:"ip_address"`
	Metadata          EventMetadata `json:"metadata" db:"metadata"`
	CreatedAt         time.Time     `json:"created_at" db:"created_at"`
	CreatedBy         *uuid.UUID    `json:"created_by" db:"created_by"`
}

type EventMetadata struct {
	ShiftID    *uuid.UUID `json:"shift_id,omitempty"`
	ClassID    *uuid.UUID `json:"class_id,omitempty"`
	Reason     *string    `json:"reason,omitempty"`
	LocationID *uuid.UUID `json:"location_id,omitempty"`
}

type AttendancePolicy struct {
	PolicyID     uuid.UUID   `json:"policy_id" db:"policy_id"`
	CompanyID    uuid.UUID   `json:"company_id" db:"company_id"`
	DepartmentID *uuid.UUID  `json:"department_id" db:"department_id"`
	PolicyCode   string      `json:"policy_code" db:"policy_code"`
	PolicyType   string      `json:"policy_type" db:"policy_type"`
	Rules        PolicyRules `json:"rules" db:"rules"`
	IsActive     bool        `json:"is_active" db:"is_active"`
	CreatedAt    time.Time   `json:"created_at" db:"created_at"`
	UpdatedAt    time.Time   `json:"updated_at" db:"updated_at"`
}

type PolicyRules struct {
	GracePeriod    *int  `json:"grace_period,omitempty"`     // minutes
	MaxLateAllowed *int  `json:"max_late_allowed,omitempty"` // minutes
	HalfDayAfter   *int  `json:"half_day_after,omitempty"`   // hours
	AutoCheckout   *bool `json:"auto_checkout,omitempty"`
	// Add more policy rules as needed
}

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

type SummaryMetadata struct {
	ClassesAttended *int       `json:"classes_attended,omitempty"`
	PeriodsTaken    *int       `json:"periods_taken,omitempty"`
	ShiftID         *uuid.UUID `json:"shift_id,omitempty"`
}

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

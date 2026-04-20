// models/attendance.go
package models

import (
	"time"

	"github.com/google/uuid"
)

type AttendanceStatus string

const (
	StatusPresent  AttendanceStatus = "present"
	StatusAbsent   AttendanceStatus = "absent"
	StatusLate     AttendanceStatus = "late"
	StatusHalfDay  AttendanceStatus = "half-day"
	StatusHoliday  AttendanceStatus = "holiday"
	StatusExempted AttendanceStatus = "exempted"
)

// AttendanceSourceType defines how the attendance was marked
type AttendanceSourceType string

const (
	SourceWeb       AttendanceSourceType = "web"
	SourceBiometric AttendanceSourceType = "biometric"
	SourceManual    AttendanceSourceType = "manual"
	SourceClassroom AttendanceSourceType = "classroom"
)

func IsValidAttendanceStatus(s string) bool {
	switch AttendanceStatus(s) {
	case StatusPresent, StatusAbsent, StatusLate, StatusHalfDay, StatusHoliday, StatusExempted:
		return true
	default:
		return false
	}
}

// StudentAttendance represents daily attendance record for a student in a section.
type StudentAttendance struct {
	AttendanceID   uuid.UUID             `json:"attendance_id"`
	EnrollmentID   uuid.UUID             `json:"enrollment_id"`
	AttendanceDate time.Time             `json:"attendance_date"`
	Status         AttendanceStatus      `json:"status"`
	MarkedBy       *uuid.UUID            `json:"marked_by,omitempty"`
	Remarks        string                `json:"remarks,omitempty"`
	SourceType     *AttendanceSourceType `json:"source_type,omitempty"` // web, biometric, manual, classroom
	DeviceID       *string               `json:"device_id,omitempty"`   // device identifier
	CreatedAt      time.Time             `json:"created_at"`
	UpdatedAt      time.Time             `json:"updated_at"`
	CreatedBy      *uuid.UUID            `json:"created_by,omitempty"`
}

// StudentAttendanceSummary represents aggregated attendance summary.
type StudentAttendanceSummary struct {
	SummaryID            uuid.UUID  `json:"summary_id"`
	StudentID            uuid.UUID  `json:"student_id"`
	AcademicYearID       uuid.UUID  `json:"academic_year_id"`
	TermID               *uuid.UUID `json:"term_id,omitempty"`
	TotalPresent         int        `json:"total_present"`
	TotalAbsent          int        `json:"total_absent"`
	TotalLate            int        `json:"total_late"`
	TotalHalfDay         int        `json:"total_half_day"`
	TotalWorkingDays     int        `json:"total_working_days"`
	AttendancePercentage float64    `json:"attendance_percentage"` // read‑only (computed)
	CreatedAt            time.Time  `json:"created_at"`
	UpdatedAt            time.Time  `json:"updated_at"`
}

// StudentAttendanceExemption represents leave/exemption from attendance.
type StudentAttendanceExemption struct {
	ExemptionID uuid.UUID  `json:"exemption_id"`
	StudentID   uuid.UUID  `json:"student_id"`
	FromDate    time.Time  `json:"from_date"`
	ToDate      time.Time  `json:"to_date"`
	Reason      string     `json:"reason,omitempty"`
	ApprovedBy  *uuid.UUID `json:"approved_by,omitempty"`
	CreatedAt   time.Time  `json:"created_at"`
	UpdatedAt   time.Time  `json:"updated_at"`
	CreatedBy   *uuid.UUID `json:"created_by,omitempty"`
}

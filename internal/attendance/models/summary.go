package models

import (
	"time"

	"github.com/google/uuid"
)

type PairedEvent struct {
	CheckInEventID  uuid.UUID  `json:"check_in_event_id"`
	CheckOutEventID *uuid.UUID `json:"check_out_event_id,omitempty"`
	CheckInTime     time.Time  `json:"check_in_time"`
	CheckOutTime    *time.Time `json:"check_out_time,omitempty"`
	WorkedMinutes   *int       `json:"worked_minutes,omitempty"`
	IsAutoClosed    bool       `json:"is_auto_closed"`
	Anomalies       []string   `json:"anomalies,omitempty"`
}

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
	LeaveTypeID     *uuid.UUID    `json:"leave_type_id,omitempty"`
	LeaveRequestID  *uuid.UUID    `json:"leave_request_id,omitempty"`
	IsLeavePaid     *bool         `json:"is_leave_paid,omitempty"`
}

type AttendanceDailySummary struct {
	AttendanceSummaryID uuid.UUID       `json:"attendance_summary_id" db:"attendance_summary_id"`
	CompanyID           uuid.UUID       `json:"company_id" db:"company_id"`
	SubjectType         string          `json:"subject_type" db:"subject_type"`
	SubjectID           uuid.UUID       `json:"subject_id" db:"subject_id"`
	AttendanceDate      time.Time       `json:"attendance_date" db:"attendance_date"`
	Status              string          `json:"status" db:"status"`
	WorkedMinutes       *int            `json:"worked_minutes" db:"worked_minutes"`
	ExpectedMinutes     *int            `json:"expected_minutes" db:"expected_minutes"`
	OvertimeMinutes     *int            `json:"overtime_minutes" db:"overtime_minutes"`
	LateMinutes         *int            `json:"late_minutes" db:"late_minutes"`
	IsFinalized         bool            `json:"is_finalized" db:"is_finalized"`
	IsPayable           bool            `json:"is_payable" db:"is_payable"`
	IsPayrollLocked     bool            `json:"is_payroll_locked" db:"is_payroll_locked"`
	Metadata            SummaryMetadata `json:"metadata" db:"metadata"`
	GeneratedAt         time.Time       `json:"generated_at" db:"generated_at"`
	GeneratedBy         string          `json:"generated_by" db:"generated_by"`
}

// AttendanceStats represents aggregated attendance statistics for a company.
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

// UserAttendanceStats represents attendance statistics for a single subject.
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

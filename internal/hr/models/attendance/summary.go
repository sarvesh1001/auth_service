package attendance

import (
	"time"

	"github.com/google/uuid"
)

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

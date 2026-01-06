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

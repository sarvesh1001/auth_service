package models

import (
	"time"

	"github.com/google/uuid"
)

// AttendanceSessionSummary represents attendance for a single session
// (e.g. a class period). One row per (company, subject_type, subject_id, session_id).
//
// EmploymentLocationID is a snapshot at write time, sourced from the
// subject's location (via SubjectLocationResolver) or from the section's
// location if one exists. It lets location-scoped queries filter without
// joining back to students.
type AttendanceSessionSummary struct {
	SummaryID   uuid.UUID `db:"summary_id"`
	CompanyID   uuid.UUID `db:"company_id"`
	SubjectType string    `db:"subject_type"`
	SubjectID   uuid.UUID `db:"subject_id"`

	// Snapshot at write time.
	EmploymentLocationID *uuid.UUID `db:"employment_location_id"`

	SessionID   uuid.UUID  `db:"session_id"`
	SessionDate time.Time  `db:"session_date"`
	Status      string     `db:"status"` // present, absent, late, excused
	MarkedAt    time.Time  `db:"marked_at"`
	MarkedBy    *uuid.UUID `db:"marked_by"`
	SourceType  string     `db:"source_type"`
	DeviceID    *string    `db:"device_id"`
	IsAuto      bool       `db:"is_auto"`
	Remarks     *string    `db:"remarks"`
	Metadata    JSONB      `db:"metadata"`
	CreatedAt   time.Time  `db:"created_at"`
	UpdatedAt   time.Time  `db:"updated_at"`
}

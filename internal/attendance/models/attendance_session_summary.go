package models

import (
	"time"

	"github.com/google/uuid"
)

type AttendanceSessionSummary struct {
	SummaryID   uuid.UUID  `db:"summary_id"`
	CompanyID   uuid.UUID  `db:"company_id"`
	SubjectType string     `db:"subject_type"`
	SubjectID   uuid.UUID  `db:"subject_id"`
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

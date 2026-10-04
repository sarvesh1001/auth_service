package models

import (
	"time"

	"github.com/google/uuid"
)

// models/attendance_exemption.go
type AttendanceExemption struct {
	ExemptionID uuid.UUID  `json:"exemption_id"     db:"exemption_id"`
	CompanyID   uuid.UUID  `json:"company_id"       db:"company_id"`
	SubjectType string     `json:"subject_type"     db:"subject_type"`
	SubjectID   uuid.UUID  `json:"subject_id"       db:"subject_id"`
	FromDate    time.Time  `json:"from_date"        db:"from_date"`
	ToDate      time.Time  `json:"to_date"          db:"to_date"`
	Reason      *string    `json:"reason,omitempty" db:"reason"`
	ApprovedBy  *uuid.UUID `json:"approved_by,omitempty" db:"approved_by"`
	CreatedAt   time.Time  `json:"created_at"       db:"created_at"`
	UpdatedAt   time.Time  `json:"updated_at"       db:"updated_at"`
	CreatedBy   *uuid.UUID `json:"created_by,omitempty" db:"created_by"`
}

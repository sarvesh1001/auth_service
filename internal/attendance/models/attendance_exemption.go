package models

import (
	"time"

	"github.com/google/uuid"
)

type AttendanceExemption struct {
	ExemptionID uuid.UUID  `db:"exemption_id"`
	CompanyID   uuid.UUID  `db:"company_id"`
	SubjectType string     `db:"subject_type"`
	SubjectID   uuid.UUID  `db:"subject_id"`
	FromDate    time.Time  `db:"from_date"`
	ToDate      time.Time  `db:"to_date"`
	Reason      *string    `db:"reason"`
	ApprovedBy  *uuid.UUID `db:"approved_by"`
	CreatedAt   time.Time  `db:"created_at"`
	UpdatedAt   time.Time  `db:"updated_at"`
	CreatedBy   *uuid.UUID `db:"created_by"`
}

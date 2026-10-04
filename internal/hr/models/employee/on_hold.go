package employee

import (
	"time"

	"github.com/google/uuid"
)

type EmployeeOnHold struct {
	OnHoldID       uuid.UUID  `json:"on_hold_id"       db:"on_hold_id"`
	CompanyID      uuid.UUID  `json:"company_id"       db:"company_id"`
	UserID         uuid.UUID  `json:"user_id"          db:"user_id"`
	StartDate      time.Time  `json:"start_date"       db:"start_date"`
	EndDate        *time.Time `json:"end_date,omitempty" db:"end_date"` // NULL = open-ended
	Reason         string     `json:"reason"           db:"reason"`
	PreviousStatus string     `json:"previous_status"  db:"previous_status"`
	PayPercentage  float64    `json:"pay_percentage"   db:"pay_percentage"`
	Status         string     `json:"status"           db:"status"` // active|ended
	EndedAt        *time.Time `json:"ended_at,omitempty"    db:"ended_at"`
	EndedBy        *uuid.UUID `json:"ended_by,omitempty"    db:"ended_by"`
	CreatedAt      time.Time  `json:"created_at"       db:"created_at"`
	CreatedBy      *uuid.UUID `json:"created_by,omitempty" db:"created_by"`
}

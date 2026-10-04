package employee

import (
	"time"

	"github.com/google/uuid"
)

type EmployeeProbation struct {
	ProbationID    uuid.UUID  `json:"probation_id"    db:"probation_id"`
	CompanyID      uuid.UUID  `json:"company_id"      db:"company_id"`
	UserID         uuid.UUID  `json:"user_id"         db:"user_id"`
	StartDate      time.Time  `json:"start_date"      db:"start_date"`
	EndDate        time.Time  `json:"end_date"        db:"end_date"`
	ExtensionCount int        `json:"extension_count" db:"extension_count"`
	PayPercentage  float64    `json:"pay_percentage"  db:"pay_percentage"`
	Status         string     `json:"status"          db:"status"` // pending|confirmed|extended|failed
	OutcomeReason  *string    `json:"outcome_reason,omitempty" db:"outcome_reason"`
	ConfirmedAt    *time.Time `json:"confirmed_at,omitempty"   db:"confirmed_at"`
	ConfirmedBy    *uuid.UUID `json:"confirmed_by,omitempty"   db:"confirmed_by"`
	CreatedAt      time.Time  `json:"created_at"      db:"created_at"`
	UpdatedAt      time.Time  `json:"updated_at"      db:"updated_at"`
}

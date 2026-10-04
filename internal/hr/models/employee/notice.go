package employee

import (
	"time"

	"github.com/google/uuid"
)

type EmployeeNotice struct {
	NoticeID      uuid.UUID  `json:"notice_id"      db:"notice_id"`
	CompanyID     uuid.UUID  `json:"company_id"     db:"company_id"`
	UserID        uuid.UUID  `json:"user_id"        db:"user_id"`
	StartDate     time.Time  `json:"start_date"     db:"start_date"`
	EndDate       time.Time  `json:"end_date"       db:"end_date"`
	Reason        *string    `json:"reason,omitempty"      db:"reason"`
	InitiatedBy   string     `json:"initiated_by"   db:"initiated_by"` // employee|employer
	Served        bool       `json:"served"         db:"served"`
	PayPercentage float64    `json:"pay_percentage" db:"pay_percentage"`
	Status        string     `json:"status"         db:"status"` // active|completed|cancelled
	ExitID        *uuid.UUID `json:"exit_id,omitempty" db:"exit_id"`
	CreatedAt     time.Time  `json:"created_at"     db:"created_at"`
	CreatedBy     *uuid.UUID `json:"created_by,omitempty" db:"created_by"`

	// Computed for the API, never persisted.
	DaysTotal     int `json:"days_total,omitempty"`
	DaysServed    int `json:"days_served,omitempty"`
	DaysRemaining int `json:"days_remaining,omitempty"`
}

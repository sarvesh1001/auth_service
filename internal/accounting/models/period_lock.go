package models

import (
	"time"

	"github.com/google/uuid"
)

type PeriodLock struct {
	LockID     uuid.UUID  `json:"lock_id"`
	CompanyID  uuid.UUID  `json:"company_id"`
	FiscalYear int        `json:"fiscal_year"`
	Period     int        `json:"period"`
	IsLocked   bool       `json:"is_locked"`
	LockedAt   *time.Time `json:"locked_at,omitempty"`
	LockedBy   *uuid.UUID `json:"locked_by,omitempty"`
	Reason     string     `json:"reason"`
	CreatedAt  time.Time  `json:"created_at"`
	UpdatedAt  time.Time  `json:"updated_at"`
}

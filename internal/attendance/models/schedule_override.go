package models

import (
	"time"

	"github.com/google/uuid"
)

type ScheduleOverride struct {
	OverrideID   uuid.UUID  `json:"override_id" db:"override_id"`
	CompanyID    uuid.UUID  `json:"company_id" db:"company_id"`
	UserID       uuid.UUID  `json:"user_id" db:"user_id"`
	OverrideDate time.Time  `json:"override_date" db:"override_date"`
	OverrideType string     `json:"override_type" db:"override_type"`
	Reason       *string    `json:"reason,omitempty" db:"reason"`
	CreatedBy    *uuid.UUID `json:"created_by,omitempty" db:"created_by"`
	CreatedAt    time.Time  `json:"created_at" db:"created_at"`
}

package models

import (
	"time"

	"github.com/google/uuid"
)

type UserOffEntitlement struct {
	EntitlementID    uuid.UUID  `json:"entitlement_id" db:"entitlement_id"`
	CompanyID        uuid.UUID  `json:"company_id" db:"company_id"`
	UserID           uuid.UUID  `json:"user_id" db:"user_id"`
	PeriodType       string     `json:"period_type" db:"period_type"`
	OffCount         int        `json:"off_count" db:"off_count"`
	RequiresApproval bool       `json:"requires_approval" db:"requires_approval"`
	EffectiveFrom    time.Time  `json:"effective_from" db:"effective_from"`
	EffectiveTo      *time.Time `json:"effective_to,omitempty" db:"effective_to"`
	CreatedAt        time.Time  `json:"created_at" db:"created_at"`
}

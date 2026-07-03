package models

import (
	"time"

	"github.com/google/uuid"
)

type WorkCenterShift struct {
	MappingID      uuid.UUID  `json:"mapping_id" db:"mapping_id"`
	CompanyID      uuid.UUID  `json:"company_id" db:"company_id"`
	WorkCenterCode string     `json:"work_center_code" db:"work_center_code"`
	ShiftID        uuid.UUID  `json:"shift_id" db:"shift_id"`
	EffectiveFrom  time.Time  `json:"effective_from" db:"effective_from"`
	EffectiveTo    *time.Time `json:"effective_to,omitempty" db:"effective_to"`
	IsActive       bool       `json:"is_active" db:"is_active"`
	CreatedAt      time.Time  `json:"created_at" db:"created_at"`
	UpdatedAt      time.Time  `json:"updated_at" db:"updated_at"`
}

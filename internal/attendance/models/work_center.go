package models

import (
	"time"

	"github.com/google/uuid"
)

type WorkCenter struct {
	WorkCenterCode string    `json:"work_center_code" db:"work_center_code"`
	CompanyID      uuid.UUID `json:"company_id" db:"company_id"`
	Name           string    `json:"name" db:"name"`
	Description    *string   `json:"description,omitempty" db:"description"`
	Timezone       string    `json:"timezone" db:"timezone"`
	IsActive       bool      `json:"is_active" db:"is_active"`
	CreatedAt      time.Time `json:"created_at" db:"created_at"`
	UpdatedAt      time.Time `json:"updated_at" db:"updated_at"`
}

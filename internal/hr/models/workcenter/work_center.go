package workcenter

import (
	"time"

	"github.com/google/uuid"
)

type WorkCenter struct {
	WorkCenterCode string    `json:"work_center_code" db:"work_center_code"`
	CompanyID      uuid.UUID `json:"company_id" db:"company_id"`
	Name           string    `json:"name" db:"name"`
	Description    *string   `json:"description" db:"description"`
	Timezone       string    `json:"timezone" db:"timezone"`
	IsActive       bool      `json:"is_active" db:"is_active"`
	CreatedAt      time.Time `json:"created_at" db:"created_at"`
	UpdatedAt      time.Time `json:"updated_at" db:"updated_at"`
}

type CreateWorkCenterRequest struct {
	WorkCenterCode string  `json:"work_center_code" validate:"required,max=100"`
	Name           string  `json:"name" validate:"required,max=255"`
	Description    *string `json:"description,omitempty"`
	Timezone       string  `json:"timezone" validate:"required"`
	IsActive       bool    `json:"is_active"`
}

type UpdateWorkCenterRequest struct {
	Name        *string `json:"name,omitempty" validate:"omitempty,max=255"`
	Description *string `json:"description,omitempty"`
	Timezone    *string `json:"timezone,omitempty" validate:"omitempty"`
	IsActive    *bool   `json:"is_active,omitempty"`
}

type WorkCenterFilter struct {
	Name     *string `json:"name,omitempty"`
	IsActive *bool   `json:"is_active,omitempty"`
}

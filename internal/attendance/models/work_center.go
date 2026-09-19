package models

import (
	"time"

	"github.com/google/uuid"
)

// WorkCenter represents a physical or logical grouping of work.
//
// LocationID is an optional scope. When NULL, the work center is a
// company-wide construct. When set, it belongs to a specific employment
// location — useful when a company has work centers at multiple sites with
// different operating rules.
type WorkCenter struct {
	WorkCenterCode string    `json:"work_center_code" db:"work_center_code"`
	CompanyID      uuid.UUID `json:"company_id" db:"company_id"`

	// Optional scope. nil = company-wide work center.
	LocationID *uuid.UUID `json:"location_id,omitempty" db:"location_id"`

	Name        string    `json:"name" db:"name"`
	Description *string   `json:"description,omitempty" db:"description"`
	Timezone    string    `json:"timezone" db:"timezone"`
	IsActive    bool      `json:"is_active" db:"is_active"`
	CreatedAt   time.Time `json:"created_at" db:"created_at"`
	UpdatedAt   time.Time `json:"updated_at" db:"updated_at"`
}

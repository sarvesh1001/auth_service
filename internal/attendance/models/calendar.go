package models

import (
	"time"

	"github.com/google/uuid"
)

// WorkCalendar represents the working days and holidays for a year.
//
// LocationID is an optional scope. When NULL, this is the company-wide
// default calendar. When set, this calendar is specific to a location
// (useful when different branches observe different holidays).
type WorkCalendar struct {
	CalendarID uuid.UUID `json:"calendar_id" db:"calendar_id"`
	CompanyID  uuid.UUID `json:"company_id" db:"company_id"`

	// Optional scope. nil = company-wide default calendar.
	LocationID *uuid.UUID `json:"location_id,omitempty" db:"location_id"`

	Year        int       `json:"year" db:"year"`
	Name        string    `json:"name" db:"name"`
	Timezone    string    `json:"timezone" db:"timezone"`
	WorkingDays []int     `json:"working_days" db:"working_days"`
	Holidays    JSONB     `json:"holidays" db:"holidays"`
	IsActive    bool      `json:"is_active" db:"is_active"`
	CreatedAt   time.Time `json:"created_at" db:"created_at"`
}

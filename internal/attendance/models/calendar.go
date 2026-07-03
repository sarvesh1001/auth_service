package models

import (
	"time"

	"github.com/google/uuid"
)

type WorkCalendar struct {
	CalendarID  uuid.UUID `json:"calendar_id" db:"calendar_id"`
	CompanyID   uuid.UUID `json:"company_id" db:"company_id"`
	Year        int       `json:"year" db:"year"`
	Name        string    `json:"name" db:"name"`
	Timezone    string    `json:"timezone" db:"timezone"`
	WorkingDays []int     `json:"working_days" db:"working_days"`
	Holidays    JSONB     `json:"holidays" db:"holidays"`
	IsActive    bool      `json:"is_active" db:"is_active"`
	CreatedAt   time.Time `json:"created_at" db:"created_at"`
}

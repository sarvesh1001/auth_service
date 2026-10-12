package models

import (
	"time"

	"github.com/google/uuid"
)

// WorkCalendar declares which weekdays are working days and which
// specific dates are holidays for a scope.
//
// Scope:
//   - LocationID != nil → applies to that location
//   - LocationID == nil → company-wide (applies everywhere)
//
// There is NO timezone field. The calendar is a set of dates; the
// operational timezone comes from the location the calendar resolves
// for, or from the company default when the calendar is company-wide.
type WorkCalendar struct {
	CalendarID  uuid.UUID              `json:"calendar_id"`
	CompanyID   uuid.UUID              `json:"company_id"`
	LocationID  *uuid.UUID             `json:"location_id,omitempty"`
	Year        int                    `json:"year"`
	Name        string                 `json:"name"`
	WorkingDays []int                  `json:"working_days"` // 0=Sun..6=Sat
	Holidays    map[string]interface{} `json:"holidays"`     // "YYYY-MM-DD" → {date, name}
	IsActive    bool                   `json:"is_active"`
	CreatedAt   time.Time              `json:"created_at"`
}

// IsHoliday reports whether the given date appears in the holiday map.
// Nil-safe.
func (c *WorkCalendar) IsHoliday(date time.Time) bool {
	if c == nil || c.Holidays == nil {
		return false
	}
	_, ok := c.Holidays[date.Format("2006-01-02")]
	return ok
}

// IsWorkingDay reports whether the given date's weekday is in WorkingDays.
// Nil-safe: a nil calendar has no working-day constraint.
func (c *WorkCalendar) IsWorkingDay(date time.Time) bool {
	if c == nil {
		return false
	}
	wd := int(date.Weekday())
	for _, d := range c.WorkingDays {
		if d == wd {
			return true
		}
	}
	return false
}

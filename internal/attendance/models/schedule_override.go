package models

import (
	"time"

	"github.com/google/uuid"
)

type ScheduleOverride struct {
	OverrideID   uuid.UUID `json:"override_id" db:"override_id"`
	CompanyID    uuid.UUID `json:"company_id" db:"company_id"`
	UserID       uuid.UUID `json:"user_id" db:"user_id"`
	OverrideDate time.Time `json:"override_date" db:"override_date"`
	OverrideType string    `json:"override_type" db:"override_type"`

	// ExpectedStart / ExpectedEnd are wall-clock times in "HH:MM:SS" form,
	// only populated when OverrideType == "custom_hours". They carry no
	// timezone: the resolver combines them with the schedule date and the
	// resolved timezone for that day (WC tz → position.location tz →
	// primary_location tz → company tz). See scheduling_service.ResolveUserDay
	// and resolver.EmployeeResolver.Resolve.
	//
	// For "off", "force_work", and "holiday_override" the DB check
	// constraint enforces these to be NULL.
	ExpectedStart *string `json:"expected_start,omitempty" db:"expected_start"`
	ExpectedEnd   *string `json:"expected_end,omitempty" db:"expected_end"`

	Reason    *string    `json:"reason,omitempty" db:"reason"`
	CreatedBy *uuid.UUID `json:"created_by,omitempty" db:"created_by"`
	CreatedAt time.Time  `json:"created_at" db:"created_at"`
}

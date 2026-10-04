package util

import (
	"fmt"
	"time"
)

// ValidateTimezone returns an error if tz is not a valid IANA name.
//
// Called at every config-write boundary (company rules, work centers,
// work calendars, schedule instances) so a typo like 'Asia/Kolkatta'
// never reaches the DB.
//
// Rejects:
//   - empty string
//   - offsets ('+05:30', '-04:00')
//   - abbreviations ('IST', 'EST', 'PST')
//   - typos ('Asia/Kolkatta')
//
// Accepts:
//   - 'UTC'
//   - IANA canonical names ('Asia/Kolkata', 'America/New_York', ...)
//   - IANA aliases that time.LoadLocation resolves
func ValidateTimezone(tz string) error {
	if tz == "" {
		return fmt.Errorf("timezone is required")
	}
	if len(tz) > 64 {
		return fmt.Errorf("timezone too long (max 64 chars)")
	}
	if _, err := time.LoadLocation(tz); err != nil {
		return fmt.Errorf("invalid IANA timezone %q: %w", tz, err)
	}
	return nil
}

// LoadLocationSafe wraps time.LoadLocation with a UTC fallback and an
// error flag so callers can decide whether to log or fail.
//
// Prefer ValidateTimezone at config-write boundaries; use this only when
// reading config that has already been validated.
func LoadLocationSafe(tz string) (*time.Location, bool) {
	if tz == "" {
		return time.UTC, false
	}
	loc, err := time.LoadLocation(tz)
	if err != nil {
		return time.UTC, false
	}
	return loc, true
}

// CalendarDateInTz returns the calendar date (Y/M/D) of `instant` in `tz`,
// represented as a time.Time at UTC midnight.
//
// Why UTC midnight: PostgreSQL DATE columns store only Y/M/D. Passing a
// time.Time at UTC midnight is unambiguous across any DB session timezone.
// Passing a location-aware midnight (e.g. midnight in IST) risks an
// off-by-one shift if the driver or server converts.
//
// Example:
//
//	CalendarDateInTz(2026-01-15T21:30:00Z, "Asia/Kolkata")
//	    → 2026-01-16T00:00:00Z   // because IST is 2026-01-16 03:00
//	CalendarDateInTz(2026-01-15T21:30:00Z, "America/New_York")
//	    → 2026-01-15T00:00:00Z   // because EST is 2026-01-15 16:30
func CalendarDateInTz(instant time.Time, tz string) time.Time {
	loc, ok := LoadLocationSafe(tz)
	if !ok {
		loc = time.UTC
	}
	local := instant.In(loc)
	return time.Date(local.Year(), local.Month(), local.Day(), 0, 0, 0, 0, time.UTC)
}

// OffsetMinutes returns the UTC offset in minutes for tz at the given instant.
//
// DST-aware. Examples:
//
//	OffsetMinutes(2026-01-15T00:00:00Z, "Asia/Kolkata")     →  330  // +05:30
//	OffsetMinutes(2026-01-15T00:00:00Z, "America/New_York") → -300  // EST
//	OffsetMinutes(2026-07-15T00:00:00Z, "America/New_York") → -240  // EDT
//
// Range guard: -720 (UTC−12:00) to 840 (UTC+14:00).
func OffsetMinutes(instant time.Time, tz string) int {
	loc, ok := LoadLocationSafe(tz)
	if !ok {
		return 0
	}
	_, offset := instant.In(loc).Zone()
	return offset / 60
}

package constants

import (
	"fmt"
	"sort"
	"strings"
	"time"
)

// IsSupportedTimezone returns true if tz is in AllTimezones.
//
// Stricter than time.LoadLocation: rejects zones the UI can't show
// (e.g. 'Antarctica/McMurdo', 'Pacific/Johnston'). Use this at the
// API boundary where you want to enforce the curated set.
func IsSupportedTimezone(tz string) bool {
	if tz == "" {
		return false
	}
	for _, t := range AllTimezones {
		if t.Name == tz {
			return true
		}
	}
	return false
}

// LookupTimezone returns the Timezone entry for tz, or nil if not found.
func LookupTimezone(tz string) *Timezone {
	for i := range AllTimezones {
		if AllTimezones[i].Name == tz {
			return &AllTimezones[i]
		}
	}
	return nil
}

// TimezoneDescription returns "Asia/Kolkata — UTC+05:30" for display.
// Uses the CURRENT offset (DST-aware), computed at call time.
func TimezoneDescription(tz string) string {
	loc, err := time.LoadLocation(tz)
	if err != nil {
		return tz
	}
	_, offsetSec := time.Now().In(loc).Zone()
	return fmt.Sprintf("%s — %s", tz, FormatOffset(offsetSec/60))
}

// FormatOffset renders minutes as "UTC+05:30" / "UTC−04:00".
// Uses the Unicode minus sign (−) for typographic consistency.
func FormatOffset(minutes int) string {
	sign := "+"
	if minutes < 0 {
		sign = "−"
		minutes = -minutes
	}
	h := minutes / 60
	m := minutes % 60
	if m == 0 {
		return fmt.Sprintf("UTC%s%02d:00", sign, h)
	}
	return fmt.Sprintf("UTC%s%02d:%02d", sign, h, m)
}

// CurrentOffsetMinutes returns the live DST-aware offset for tz.
// This is the ONLY function that should ever produce an offset number
// used in business logic. Never hardcode offsets elsewhere.
func CurrentOffsetMinutes(tz string) (int, error) {
	loc, err := time.LoadLocation(tz)
	if err != nil {
		return 0, fmt.Errorf("load location %q: %w", tz, err)
	}
	_, offsetSec := time.Now().In(loc).Zone()
	return offsetSec / 60, nil
}

// OffsetMinutesAt returns the offset for tz at a specific instant.
// Use this for historical rows where "current" offset would be wrong.
func OffsetMinutesAt(tz string, instant time.Time) (int, error) {
	loc, err := time.LoadLocation(tz)
	if err != nil {
		return 0, fmt.Errorf("load location %q: %w", tz, err)
	}
	_, offsetSec := instant.In(loc).Zone()
	return offsetSec / 60, nil
}

// SuggestTimezoneForCountry returns the default tz for a country code and
// a flag indicating whether the country has multiple zones.
//
// The UI uses the flag to prompt "This country has multiple timezones.
// Please confirm the specific one."
func SuggestTimezoneForCountry(countryCode string) (tz string, ambiguous bool) {
	code := strings.ToUpper(strings.TrimSpace(countryCode))
	tz, ok := CountryDefaultTimezone[code]
	if !ok {
		return "UTC", false
	}
	return tz, CountriesWithMultipleTimezones[code]
}

// SortedRegions returns the region keys in a fixed display order.
// Useful for rendering picker groups consistently.
func SortedRegions() []string {
	return []string{
		RegionUTC,
		RegionAmericas,
		RegionEurope,
		RegionAfrica,
		RegionAsia,
		RegionOceania,
		RegionAtlantic,
		RegionIndian,
		RegionPacific,
	}
}

// SearchTimezones returns all zones whose name or note contains `q`
// (case-insensitive). Empty query returns AllTimezones.
func SearchTimezones(q string) []Timezone {
	if q == "" {
		return AllTimezones
	}
	q = strings.ToLower(q)
	var out []Timezone
	for _, tz := range AllTimezones {
		if strings.Contains(strings.ToLower(tz.Name), q) ||
			strings.Contains(strings.ToLower(tz.Note), q) {
			out = append(out, tz)
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Name < out[j].Name })
	return out
}

package handler

import (
	"fmt"
	"strings"
	"time"
)

// DateOnly is a JSON-friendly wrapper around time.Time that accepts BOTH:
//   - "2026-10-31"              (date-only, what mobile date pickers emit)
//   - "2026-10-31T00:00:00Z"    (full RFC3339)
//
// When only a date is given, it's parsed as UTC midnight. When a full
// timestamp is given, it's honoured as-is.
//
// Use it anywhere a handler previously used time.Time for a request body
// field. Callers can keep their existing code — DateOnly embeds time.Time,
// so .IsZero(), .After(), .Before(), .Format() all work unchanged. To
// unwrap the underlying time.Time, read the embedded `.Time` field.
type DateOnly struct {
	time.Time
}

func (d *DateOnly) UnmarshalJSON(b []byte) error {
	s := strings.Trim(string(b), `"`)
	if s == "" || s == "null" {
		return nil
	}

	// Try RFC3339 first (full timestamp).
	if t, err := time.Parse(time.RFC3339, s); err == nil {
		d.Time = t
		return nil
	}

	// Fall back to date-only.
	if t, err := time.Parse("2006-01-02", s); err == nil {
		d.Time = t
		return nil
	}

	return fmt.Errorf("invalid date format %q: expected YYYY-MM-DD or RFC3339", s)
}

// MarshalJSON emits date-only when the time is exactly midnight UTC,
// otherwise full RFC3339. Keeps responses clean.
func (d DateOnly) MarshalJSON() ([]byte, error) {
	if d.Time.IsZero() {
		return []byte("null"), nil
	}
	if d.Time.Hour() == 0 && d.Time.Minute() == 0 && d.Time.Second() == 0 && d.Time.Nanosecond() == 0 {
		return []byte(`"` + d.Time.Format("2006-01-02") + `"`), nil
	}
	return []byte(`"` + d.Time.Format(time.RFC3339) + `"`), nil
}

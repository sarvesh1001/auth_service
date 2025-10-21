package models
type OTPRateLimit struct {
    PhoneHash   string `db:"phone_hash"`
    WindowType  string `db:"window_type"` // '1min', '5min', etc.
    TimeWindow  int64  `db:"time_window"`
    AttemptCount int64 `db:"attempt_count"` // counter
}

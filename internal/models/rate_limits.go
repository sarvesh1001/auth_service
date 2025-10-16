package models

import "time"

type RateLimit struct {
	Bucket      int       `db:"bucket"`
	Identifier  string    `db:"identifier"`
	WindowType  string    `db:"window_type"`
	TimeWindow  int64     `db:"time_window"`
	Attempts    int64     `db:"attempts"` // counter
	LastAttempt time.Time `db:"last_attempt"`
}

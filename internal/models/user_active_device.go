package models

import "time"

type UserActiveDevice struct {
	UserID    string    `db:"user_id"`
	DeviceID  string    `db:"device_id"`
	SessionID string    `db:"session_id"`
	BoundAt   time.Time `db:"bound_at"`
	BindToken string    `db:"bind_token"`
}

package models

import "time"

type OTPAccountLockout struct {
    PhoneHash    string    `db:"phone_hash"`
    LockedAt     time.Time `db:"locked_at"`
    LockedUntil  time.Time `db:"locked_until"`
    Reason       string    `db:"reason"`
    AttemptCount int       `db:"attempt_count"`
}

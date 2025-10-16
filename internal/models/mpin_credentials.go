package models

import "time"

type MPINCredential struct {
	UserID         string     `db:"user_id"`
	MPINHash       string     `db:"mpin_hash"`
	MPINSalt       string     `db:"mpin_salt"`
	PepperVersion  int        `db:"pepper_version"`
	HashAlgorithm  string     `db:"hash_algorithm"`
	DeviceID       string     `db:"device_id"`
	LastChanged    *time.Time `db:"last_changed"`
	FailedAttempts int        `db:"failed_attempts"`
	IsLocked       bool       `db:"is_locked"`
	LockedUntil    *time.Time `db:"locked_until"`
}

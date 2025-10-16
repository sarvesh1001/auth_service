package models

import (
	"net"
	"time"
)

type OTPVerification struct {
	PhoneHash     string    `db:"phone_hash"`
	TimeBucket    int64     `db:"time_bucket"`
	CreatedAt     time.Time `db:"created_at"`
	OTPHash       string    `db:"otp_hash"`
	OTPSalt       string    `db:"otp_salt"`
	HashAlgorithm string    `db:"hash_algorithm"`
	PepperVersion int       `db:"pepper_version"`
	Purpose       string    `db:"purpose"`
	Attempts      int       `db:"attempts"`
	ExpiresAt     time.Time `db:"expires_at"`
	IPAddress     net.IP    `db:"ip_address"`
	ProviderUsed  string    `db:"provider_used"`
}

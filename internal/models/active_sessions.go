package models

import (
	"net"
	"time"
)

type ActiveSession struct {
	UserID            string    `db:"user_id"`
	SessionToken      string    `db:"session_token"`
	DeviceID          string    `db:"device_id"`
	DeviceFingerprint string    `db:"device_fingerprint"`
	KYCVerified       bool      `db:"kyc_verified"`
	CreatedAt         time.Time `db:"created_at"`
	LastActivity      time.Time `db:"last_activity"`
	ExpiresAt         time.Time `db:"expires_at"`
	IPAddress         net.IP    `db:"ip_address"`
	EncryptionKey     []byte    `db:"encryption_key"`
}

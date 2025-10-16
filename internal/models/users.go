package models

import "time"

type User struct {
	UserBucket        int        `db:"user_bucket"`
	UserID            string     `db:"user_id"`
	PhoneHash         string     `db:"phone_hash"`
	PhoneEncrypted    []byte     `db:"phone_encrypted"`
	PhoneKeyID        string     `db:"phone_key_id"`
	DeviceID          string     `db:"device_id"`
	DeviceFingerprint string     `db:"device_fingerprint"`
	KYCStatus         string     `db:"kyc_status"`
	KYCLevel          string     `db:"kyc_level"`
	KYCVerifiedAt     *time.Time `db:"kyc_verified_at"`
	KYCVerifiedBy     string     `db:"kyc_verified_by"`
	ProfileServiceID  string     `db:"profile_service_id"`
	IsVerified        bool       `db:"is_verified"`
	IsBlocked         bool       `db:"is_blocked"`
	IsBanned          bool       `db:"is_banned"`
	BannedBy          string     `db:"banned_by"`
	BannedReason      string     `db:"banned_reason"`
	BannedAt          *time.Time `db:"banned_at"`
	CreatedAt         time.Time  `db:"created_at"`
	LastLogin         *time.Time `db:"last_login"`
	UpdatedAt         *time.Time `db:"updated_at"`
	ConsentAgreed     bool       `db:"consent_agreed"`
	ConsentVersion    string     `db:"consent_version"`
	DataRegion        string     `db:"data_region"`
}

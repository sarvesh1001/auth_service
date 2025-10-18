package models
import ("github.com/google/uuid"
"time"
)
type User struct {
    UserBucket        int        `db:"user_bucket"`
    UserID            uuid.UUID  `db:"user_id"`
    PhoneHash         string     `db:"phone_hash"`
    PhoneEncrypted    []byte     `db:"phone_encrypted"`
    PhoneKeyID        uuid.UUID  `db:"phone_key_id"`
    DeviceID          string     `db:"device_id"`
    DeviceFingerprint string     `db:"device_fingerprint"`
    KYCStatus         string     `db:"kyc_status"`
    KYCLevel          string     `db:"kyc_level"`
    KYCVerifiedAt     *time.Time `db:"kyc_verified_at"`
    KYCVerifiedBy     uuid.UUID  `db:"kyc_verified_by"`
    ProfileServiceID  uuid.UUID  `db:"profile_service_id"`
    IsVerified        bool       `db:"is_verified"`
    IsBlocked         bool       `db:"is_blocked"`
    IsBanned          bool       `db:"is_banned"`
    BannedBy          uuid.UUID  `db:"banned_by"`
    BannedReason      string     `db:"banned_reason"`
    BannedAt          *time.Time `db:"banned_at"`
    CreatedAt         time.Time  `db:"created_at"`
    LastLogin         *time.Time `db:"last_login"`
    UpdatedAt         *time.Time `db:"updated_at"`
    ConsentAgreed     bool       `db:"consent_agreed"`
    ConsentVersion    string     `db:"consent_version"`
    DataRegion        string     `db:"data_region"`
    PhoneEncryptedDEK string    `db:"phone_encrypted_dek"`

}
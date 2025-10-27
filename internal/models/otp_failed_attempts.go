package models
import ( "net"
"time")
type OTPFailedAttempt struct {
    PhoneHash   string    `db:"phone_hash"`
    TimeBucket  int64     `db:"time_bucket"`
    AttemptedAt time.Time `db:"attempted_at"`
    IPAddress   net.IP    `db:"ipaddress"`        // <--- PATCHED: robust to null/empty
    Purpose     string    `db:"purpose"`
    Reason      string    `db:"reason"`
}

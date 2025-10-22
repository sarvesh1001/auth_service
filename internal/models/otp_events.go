package models

import ("github.com/google/uuid"
        "net"
        "time"
    )


type OTPEvent struct {
    EventID      uuid.UUID         `db:"event_id"`
    EventType    string             `db:"event_type"`
    PhoneHash    string             `db:"phone_hash"`
    Purpose      string             `db:"purpose"`
    IPAddress    net.IP             `db:"ip_address"`
    UserAgent    string             `db:"user_agent"`
    ProviderUsed string             `db:"provider_used"`
    Timestamp    time.Time          `db:"timestamp"`
    Metadata     map[string]string  `db:"metadata"`
}

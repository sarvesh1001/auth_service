package models

import (
	"net"
	"time"
)

type SecurityEvent struct {
	EventBucket  int       `db:"event_bucket"`
	UserID       string    `db:"user_id"`
	EventDate    string    `db:"event_date"`
	EventTime    time.Time `db:"event_time"`
	EventType    string    `db:"event_type"`
	DeviceID     string    `db:"device_id"`
	IPAddress    net.IP    `db:"ip_address"`
	RiskScore    int       `db:"risk_score"`
	SessionID    string    `db:"session_id"`
	Details      string    `db:"details"`
	CDCProcessed bool      `db:"cdc_processed"`
}

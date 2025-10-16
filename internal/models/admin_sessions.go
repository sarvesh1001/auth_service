package models

import (
	"net"
	"time"
)

type AdminSession struct {
	AdminID      string    `db:"admin_id"`
	SessionToken string    `db:"session_token"`
	RoleLevel    string    `db:"role_level"`
	Permissions  []string  `db:"permissions"`
	MFAVerified  bool      `db:"mfa_verified"`
	CreatedAt    time.Time `db:"created_at"`
	LastActivity time.Time `db:"last_activity"`
	ExpiresAt    time.Time `db:"expires_at"`
	IPAddress    net.IP    `db:"ip_address"`
}

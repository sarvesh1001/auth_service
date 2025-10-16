package models

import (
	"time"
)

type AdminUser struct {
	AdminID         string    `db:"admin_id"`
	Username        string    `db:"username"`
	RoleLevel       string    `db:"role_level"`
	Permissions     []string  `db:"permissions"`
	PasswordHash    string    `db:"password_hash"`
	MFASecret       string    `db:"mfa_secret"`
	MFAType         string    `db:"mfa_type"`
	IsActive        bool      `db:"is_active"`
	FailedAttempts  int       `db:"failed_attempts"`
	IPWhitelist     []string  `db:"ip_whitelist"`
	DataAccessScope string    `db:"data_access_scope"`
	CreatedBy       string    `db:"created_by"`
	CreatedAt       time.Time `db:"created_at"`
}

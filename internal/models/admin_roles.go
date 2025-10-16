package models

type AdminRole struct {
	RoleLevel   string   `db:"role_level"`
	RoleName    string   `db:"role_name"`
	Permissions []string `db:"permissions"`
	MFARequired bool     `db:"mfa_required"`
}

package repository

import (
	"context"
	"database/sql"

	"github.com/google/uuid"

	"auth-service/internal/attendance/models"
)

// RuleRepository defines operations for attendance rules and profiles.
type RuleRepository interface {
	// ── Company Rules ──
	GetCompanyRules(ctx context.Context, companyID uuid.UUID) (*models.CompanyAttendanceRules, error)
	UpsertCompanyRules(ctx context.Context, tx *sql.Tx, rules *models.CompanyAttendanceRules) error

	// ── Department Rules ──
	GetDepartmentRules(ctx context.Context, companyID, departmentID uuid.UUID) (*models.DepartmentAttendanceRules, error)
	UpsertDepartmentRules(ctx context.Context, tx *sql.Tx, rules *models.DepartmentAttendanceRules) error

	// ── User Attendance Profile ──
	GetUserProfile(ctx context.Context, userID uuid.UUID) (*models.UserAttendanceProfile, error)
	UpsertUserProfile(ctx context.Context, tx *sql.Tx, profile *models.UserAttendanceProfile) error

	HealthCheck(ctx context.Context) error
}

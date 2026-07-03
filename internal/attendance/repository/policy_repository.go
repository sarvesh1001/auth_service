package repository

import (
	"context"
	"database/sql"
	"time"

	"github.com/google/uuid"

	"auth-service/internal/attendance/models"
)

// PolicyRepository defines operations for attendance policies.
type PolicyRepository interface {
	// Legacy employee-only methods (kept for backward compatibility)
	CreatePolicy(ctx context.Context, tx *sql.Tx, policy *models.AttendancePolicy) error
	GetPolicyByID(ctx context.Context, policyID uuid.UUID) (*models.AttendancePolicy, error)
	GetPoliciesByCompany(ctx context.Context, companyID uuid.UUID, activeOnly bool) ([]*models.AttendancePolicy, error)
	GetPolicyByCode(ctx context.Context, companyID uuid.UUID, policyCode string) (*models.AttendancePolicy, error)
	GetPositionPolicy(ctx context.Context, positionID uuid.UUID) (*models.AttendancePolicy, error)
	GetWorkCenterPolicy(ctx context.Context, companyID uuid.UUID, workCenterCode string) (*models.AttendancePolicy, error)
	UpdatePolicy(ctx context.Context, tx *sql.Tx, policy *models.AttendancePolicy) error
	DeletePolicy(ctx context.Context, policyID uuid.UUID) error

	// AssignUserPolicy (legacy) – creates a user-policy assignment for an employee (sets subject_type='employee')
	AssignUserPolicy(ctx context.Context, tx *sql.Tx, assignment *models.UserAttendancePolicy) error

	// GetUserActivePolicy (legacy) – retrieves the active policy for an employee at a given date
	GetUserActivePolicy(ctx context.Context, userID uuid.UUID, at time.Time) (*models.AttendancePolicy, error)

	// EndUserPolicy (legacy) – ends an active user-policy assignment for an employee
	EndUserPolicy(ctx context.Context, userID, policyID uuid.UUID, endDate time.Time) error

	// GetUsersByPolicy (legacy) – retrieves user IDs assigned to a policy at a given date
	GetUsersByPolicy(ctx context.Context, policyID uuid.UUID, effectiveDate time.Time) ([]uuid.UUID, error)

	// GetUserPolicyAssignment (legacy) – retrieves a specific user-policy assignment
	GetUserPolicyAssignment(ctx context.Context, userID, policyID uuid.UUID, effectiveFrom time.Time) (*models.UserAttendancePolicy, error)

	// --- NEW POLYMORPHIC METHODS ---

	// AssignPolicyToSubject assigns a policy to any subject (employee, student, etc.)
	AssignPolicyToSubject(ctx context.Context, tx *sql.Tx, subjectType string, subjectID uuid.UUID, policyID uuid.UUID, effectiveFrom, effectiveTo *time.Time, assignedBy *uuid.UUID) error

	// GetActivePolicyBySubject retrieves the active policy for a subject at a given date
	GetActivePolicyBySubject(ctx context.Context, subjectType string, subjectID uuid.UUID, at time.Time) (*models.AttendancePolicy, error)

	// EndPolicyForSubject ends an active subject-policy assignment
	EndPolicyForSubject(ctx context.Context, subjectType string, subjectID uuid.UUID, policyID uuid.UUID, endDate time.Time) error

	// GetSubjectsByPolicy retrieves subject IDs of a given type assigned to a policy at a given date
	GetSubjectsByPolicy(ctx context.Context, policyID uuid.UUID, subjectType string, effectiveDate time.Time) ([]uuid.UUID, error)

	// HealthCheck verifies database connectivity.
	HealthCheck(ctx context.Context) error
}

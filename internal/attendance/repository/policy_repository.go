package repository

import (
	"context"
	"database/sql"
	"time"

	"github.com/google/uuid"

	"auth-service/internal/attendance/models"
)

type PolicyRepository interface {
	CreatePolicy(ctx context.Context, tx *sql.Tx, policy *models.AttendancePolicy) error
	GetPolicyByID(ctx context.Context, policyID uuid.UUID) (*models.AttendancePolicy, error)
	GetPoliciesByCompany(ctx context.Context, companyID uuid.UUID, activeOnly bool) ([]*models.AttendancePolicy, error)
	GetPolicyByCode(ctx context.Context, companyID uuid.UUID, policyCode string) (*models.AttendancePolicy, error)

	// Date-scoped variants — same policies as above, but as of the given date.
	// Use these in the resolver; the plain methods above return the current
	// version and are for admin views only.
	GetPolicyByIDOnDate(ctx context.Context, policyID uuid.UUID, date time.Time) (*models.AttendancePolicy, error)
	GetPositionPolicyOnDate(ctx context.Context, positionID uuid.UUID, date time.Time) (*models.AttendancePolicy, error)
	GetWorkCenterPolicyOnDate(ctx context.Context, companyID uuid.UUID, workCenterCode string, date time.Time) (*models.AttendancePolicy, error)

	GetPositionPolicy(ctx context.Context, positionID uuid.UUID) (*models.AttendancePolicy, error)
	GetWorkCenterPolicy(ctx context.Context, companyID uuid.UUID, workCenterCode string) (*models.AttendancePolicy, error)
	UpdatePolicy(ctx context.Context, tx *sql.Tx, policy *models.AttendancePolicy) error
	DeletePolicy(ctx context.Context, policyID uuid.UUID) error
	AssignUserPolicy(ctx context.Context, tx *sql.Tx, assignment *models.UserAttendancePolicy) error
	GetUserActivePolicy(ctx context.Context, userID uuid.UUID, at time.Time) (*models.AttendancePolicy, error)
	EndUserPolicy(ctx context.Context, userID, policyID uuid.UUID, endDate time.Time) error
	GetUsersByPolicy(ctx context.Context, policyID uuid.UUID, effectiveDate time.Time) ([]uuid.UUID, error)
	GetUserPolicyAssignment(ctx context.Context, userID, policyID uuid.UUID, effectiveFrom time.Time) (*models.UserAttendancePolicy, error)
	AssignPolicyToSubject(ctx context.Context, tx *sql.Tx, subjectType string, subjectID uuid.UUID, policyID uuid.UUID, effectiveFrom, effectiveTo *time.Time, assignedBy *uuid.UUID) error
	GetActivePolicyBySubject(ctx context.Context, subjectType string, subjectID uuid.UUID, at time.Time) (*models.AttendancePolicy, error)
	EndPolicyForSubject(ctx context.Context, subjectType string, subjectID uuid.UUID, policyID uuid.UUID, endDate time.Time) error
	GetSubjectsByPolicy(ctx context.Context, policyID uuid.UUID, subjectType string, effectiveDate time.Time) ([]uuid.UUID, error)
	HealthCheck(ctx context.Context) error
}

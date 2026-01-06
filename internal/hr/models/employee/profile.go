package employee

import (
	"time"

	"github.com/google/uuid"
)

type EmployeeProfile struct {
	EmployeeProfileID uuid.UUID `json:"employee_profile_id" db:"employee_profile_id"`
	UserID            uuid.UUID `json:"user_id" db:"user_id"`
	CompanyID         uuid.UUID `json:"company_id" db:"company_id"`

	// Personal
	DateOfBirth   *time.Time `json:"date_of_birth" db:"date_of_birth"`
	Gender        *string    `json:"gender" db:"gender"`
	MaritalStatus *string    `json:"marital_status" db:"marital_status"`
	Nationality   *string    `json:"nationality" db:"nationality"`

	// Employment
	EmploymentType   *string    `json:"employment_type" db:"employment_type"`
	EmploymentStatus *string    `json:"employment_status" db:"employment_status"`
	ProbationEndDate *time.Time `json:"probation_end_date" db:"probation_end_date"`
	ConfirmationDate *time.Time `json:"confirmation_date" db:"confirmation_date"`

	// Job
	JobTitle   *string `json:"job_title" db:"job_title"`
	Grade      *string `json:"grade" db:"grade"`
	CostCenter *string `json:"cost_center" db:"cost_center"`

	// Legal
	TaxID            *string `json:"tax_id" db:"tax_id"`
	SocialSecurityID *string `json:"social_security_id" db:"social_security_id"`

	CreatedAt time.Time `json:"created_at" db:"created_at"`
	UpdatedAt time.Time `json:"updated_at" db:"updated_at"`
}

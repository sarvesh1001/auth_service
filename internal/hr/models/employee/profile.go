package employee

import (
	"time"

	"github.com/google/uuid"
)

// EmployeeProfile — PII handling.
//
// All PII (email, tax_id, social_security_id, date_of_birth, nationality,
// marital_status) is persisted EXCLUSIVELY in the *Encrypted siblings below.
// The plaintext fields are NOT DB columns — they are ephemeral carriers:
//
//   - On write: the handler decodes the request body into these fields;
//     EmployeeService.encryptPIIFields consumes them and populates the
//     *Encrypted / *EncryptedDEK / *KeyID siblings; then the repository
//     writes only the encrypted siblings.
//
//   - On read: the repository scans only the encrypted siblings;
//     EmployeeService.decryptPIIFields populates these plaintext fields
//     for the response payload.
//
// No code may read or write these plaintext fields against the database.
type EmployeeProfile struct {
	EmployeeProfileID uuid.UUID `json:"employee_profile_id"`
	UserID            uuid.UUID `json:"user_id"`
	CompanyID         uuid.UUID `json:"company_id"`

	// ---- Ephemeral plaintext PII (NEVER persisted) ----
	DateOfBirth      *time.Time `json:"date_of_birth,omitempty"`
	MaritalStatus    *string    `json:"marital_status,omitempty"`
	Nationality      *string    `json:"nationality,omitempty"`
	TaxID            *string    `json:"tax_id,omitempty"`
	SocialSecurityID *string    `json:"social_security_id,omitempty"`
	Email            *string    `json:"email,omitempty"`

	// ---- Non-PII (plaintext columns) ----
	// gender remains plaintext — it is not part of the encryption scheme.
	Gender           *string    `json:"gender,omitempty"`
	EmploymentType   *string    `json:"employment_type,omitempty"`
	EmploymentStatus *string    `json:"employment_status,omitempty"`
	ProbationEndDate *time.Time `json:"probation_end_date,omitempty"`
	ConfirmationDate *time.Time `json:"confirmation_date,omitempty"`
	JobTitle         *string    `json:"job_title,omitempty"`
	Grade            *string    `json:"grade,omitempty"`
	CostCenter       *string    `json:"cost_center,omitempty"`
	CostCenterID     *uuid.UUID `json:"cost_center_id,omitempty"`

	// ---- Encrypted PII (persisted) ----
	EmailHash         *string    `json:"-"`
	EmailEncrypted    []byte     `json:"-"`
	EmailEncryptedDEK *string    `json:"-"`
	EmailKeyID        *uuid.UUID `json:"-"`

	TaxIDEncrypted    []byte     `json:"-"`
	TaxIDEncryptedDEK *string    `json:"-"`
	TaxIDKeyID        *uuid.UUID `json:"-"`

	SocialSecurityIDEncrypted    []byte     `json:"-"`
	SocialSecurityIDEncryptedDEK *string    `json:"-"`
	SocialSecurityIDKeyID        *uuid.UUID `json:"-"`

	DateOfBirthEncrypted    []byte     `json:"-"`
	DateOfBirthEncryptedDEK *string    `json:"-"`
	DateOfBirthKeyID        *uuid.UUID `json:"-"`

	NationalityEncrypted    []byte     `json:"-"`
	NationalityEncryptedDEK *string    `json:"-"`
	NationalityKeyID        *uuid.UUID `json:"-"`

	MaritalStatusEncrypted    []byte     `json:"-"`
	MaritalStatusEncryptedDEK *string    `json:"-"`
	MaritalStatusKeyID        *uuid.UUID `json:"-"`

	CreatedAt time.Time `json:"created_at"`
	UpdatedAt time.Time `json:"updated_at"`
}

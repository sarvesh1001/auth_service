package models

import (
	"time"

	"github.com/google/uuid"
)

type StudentStatus string

const (
	StudentActive      StudentStatus = "active"
	StudentInactive    StudentStatus = "inactive"
	StudentAlumni      StudentStatus = "alumni"
	StudentTransferred StudentStatus = "transferred"
)

func IsValidStudentStatus(s string) bool {
	switch StudentStatus(s) {
	case StudentActive, StudentInactive, StudentAlumni, StudentTransferred:
		return true
	default:
		return false
	}
}

type Student struct {
	StudentID uuid.UUID `json:"student_id"`
	CompanyID uuid.UUID `json:"company_id"`

	FirstName string `json:"first_name"`
	LastName  string `json:"last_name,omitempty"`

	AdmissionNo string `json:"admission_no,omitempty"`

	// NEW: email and phone (plaintext in model)
	Email string `json:"email,omitempty"`
	Phone string `json:"phone,omitempty"`

	DateOfBirth *time.Time `json:"date_of_birth,omitempty"`
	Gender      string     `json:"gender,omitempty"`
	BloodGroup  string     `json:"blood_group,omitempty"`
	Nationality string     `json:"nationality,omitempty"`
	Religion    string     `json:"religion,omitempty"`
	Category    string     `json:"category,omitempty"`

	AadharNo string `json:"aadhar_no,omitempty"`

	EmergencyContactName  string `json:"emergency_contact_name,omitempty"`
	EmergencyContactPhone string `json:"emergency_contact_phone,omitempty"`
	MedicalConditions     string `json:"medical_conditions,omitempty"`

	Status StudentStatus `json:"status"`

	Version int `json:"version"`

	CreatedAt time.Time  `json:"created_at"`
	UpdatedAt time.Time  `json:"updated_at"`
	CreatedBy *uuid.UUID `json:"created_by,omitempty"`
	UpdatedBy *uuid.UUID `json:"updated_by,omitempty"`
	DeletedAt *time.Time `json:"delete"`
}

type StudentAuth struct {
	StudentAuthID uuid.UUID `json:"student_auth_id"`
	StudentID     uuid.UUID `json:"student_id"`

	// Encrypted password fields (stored as ciphertext)
	Password      *string `json:"password,omitempty"`        // encrypted password
	PasswordDEK   *string `json:"password_dek,omitempty"`    // data encryption key
	PasswordKeyID *string `json:"password_key_id,omitempty"` // key identifier

	// Security tracking
	LastLoginAt   *time.Time `json:"last_login_at,omitempty"`
	LoginAttempts int        `json:"login_attempts"`
	LockedUntil   *time.Time `json:"locked_until,omitempty"`

	// Audit fields
	CreatedAt time.Time  `json:"created_at"`
	UpdatedAt time.Time  `json:"updated_at"`
	CreatedBy *uuid.UUID `json:"created_by,omitempty"`
	UpdatedBy *uuid.UUID `json:"updated_by,omitempty"`
	DeletedAt *time.Time `json:"deleted_at,omitempty"`
}

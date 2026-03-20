package service

import (
	"errors"
	"time"

	"github.com/google/uuid"
)

// Common errors
var (
	ErrNotFound         = errors.New("resource not found")
	ErrDuplicate        = errors.New("resource already exists")
	ErrOverlap          = errors.New("date range overlaps with existing record")
	ErrInvalidInput     = errors.New("invalid input")
	ErrNotInTransaction = errors.New("operation must be run in a transaction")
	ErrHasDependencies  = errors.New("resource has dependent records and cannot be deleted")
	ErrDependencyExists = errors.New("operation blocked due to existing dependencies")
	ErrCapacityExceeded = errors.New("capacity exceeded")
	ErrConcurrentUpdate = errors.New("concurrent update detected")
)

// Request DTOs

type CreateAcademicYearRequest struct {
	CompanyID uuid.UUID
	Name      string
	StartDate time.Time
	EndDate   time.Time
	IsCurrent bool
	CreatedBy *uuid.UUID
	UpdatedBy *uuid.UUID // should match CreatedBy on create
}

type UpdateAcademicYearRequest struct {
	AcademicYearID uuid.UUID
	Name           string
	StartDate      time.Time
	EndDate        time.Time
	IsCurrent      bool
	UpdatedBy      *uuid.UUID
}

type CreateTermRequest struct {
	AcademicYearID uuid.UUID
	Name           string
	StartDate      time.Time
	EndDate        time.Time
	IsCurrent      bool
	CreatedBy      *uuid.UUID
	UpdatedBy      *uuid.UUID
}

type UpdateTermRequest struct {
	TermID    uuid.UUID
	Name      string
	StartDate time.Time
	EndDate   time.Time
	IsCurrent bool
	UpdatedBy *uuid.UUID
}

type CreateCourseRequest struct {
	CompanyID   uuid.UUID
	Code        string
	Name        string
	Description string
	Credits     int
	IsActive    bool
	CreatedBy   *uuid.UUID
	UpdatedBy   *uuid.UUID
}

type UpdateCourseRequest struct {
	CourseID    uuid.UUID
	Code        string
	Name        string
	Description string
	Credits     int
	IsActive    bool
	UpdatedBy   *uuid.UUID
}

type CreateSubjectRequest struct {
	CompanyID   uuid.UUID
	Code        string
	Name        string
	Description string
	Credits     int
	IsActive    bool
	CreatedBy   *uuid.UUID
	UpdatedBy   *uuid.UUID
}

type UpdateSubjectRequest struct {
	SubjectID   uuid.UUID
	Code        string
	Name        string
	Description string
	Credits     int
	IsActive    bool
	UpdatedBy   *uuid.UUID
}

type CreateSectionRequest struct {
	CourseID  uuid.UUID
	TermID    uuid.UUID
	Name      string
	Capacity  int
	IsActive  bool
	CreatedBy *uuid.UUID
	UpdatedBy *uuid.UUID
}

type UpdateSectionRequest struct {
	SectionID uuid.UUID
	Name      string
	Capacity  int
	IsActive  bool
	UpdatedBy *uuid.UUID
}

type AssignSubjectRequest struct {
	CourseID     uuid.UUID
	SubjectID    uuid.UUID
	TermNumber   int
	IsCompulsory bool
	// No audit fields – mapping table has no audit columns
}

// CreateStudentRequest holds data for creating a student.
type CreateStudentRequest struct {
	CompanyID             uuid.UUID  `json:"company_id"`
	FirstName             string     `json:"first_name"`
	LastName              string     `json:"last_name,omitempty"`
	AdmissionNo           string     `json:"admission_no"`
	Email                 string     `json:"email,omitempty"` // NEW
	Phone                 string     `json:"phone,omitempty"` // NEW
	DateOfBirth           *time.Time `json:"date_of_birth,omitempty"`
	Gender                string     `json:"gender,omitempty"`
	BloodGroup            string     `json:"blood_group,omitempty"`
	Nationality           string     `json:"nationality,omitempty"`
	Religion              string     `json:"religion,omitempty"`
	Category              string     `json:"category,omitempty"`
	AadharNo              string     `json:"aadhar_no,omitempty"`
	EmergencyContactName  string     `json:"emergency_contact_name,omitempty"`
	EmergencyContactPhone string     `json:"emergency_contact_phone,omitempty"`
	MedicalConditions     string     `json:"medical_conditions,omitempty"`
	Status                string     `json:"status"` // "active","inactive","alumni","transferred"
	CreatedBy             *uuid.UUID `json:"created_by,omitempty"`
	UpdatedBy             *uuid.UUID `json:"updated_by,omitempty"`
}

// UpdateStudentRequest holds data for updating a student.
type UpdateStudentRequest struct {
	StudentID             uuid.UUID  `json:"student_id"`
	FirstName             string     `json:"first_name,omitempty"`
	LastName              string     `json:"last_name,omitempty"`
	AdmissionNo           string     `json:"admission_no"`
	Email                 string     `json:"email,omitempty"` // NEW
	Phone                 string     `json:"phone,omitempty"` // NEW
	DateOfBirth           *time.Time `json:"date_of_birth,omitempty"`
	Gender                string     `json:"gender,omitempty"`
	BloodGroup            string     `json:"blood_group,omitempty"`
	Nationality           string     `json:"nationality,omitempty"`
	Religion              string     `json:"religion,omitempty"`
	Category              string     `json:"category,omitempty"`
	AadharNo              string     `json:"aadhar_no,omitempty"`
	EmergencyContactName  string     `json:"emergency_contact_name,omitempty"`
	EmergencyContactPhone string     `json:"emergency_contact_phone,omitempty"`
	MedicalConditions     string     `json:"medical_conditions,omitempty"`
	Status                string     `json:"status,omitempty"`
	UpdatedBy             *uuid.UUID `json:"updated_by,omitempty"`
}

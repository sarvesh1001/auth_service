package service

import (
	"auth-service/internal/academics/models"
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

	// New errors
	ErrInactiveEnrollment = errors.New("enrollment is inactive")
	ErrNotEnrolled        = errors.New("student is not enrolled")
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
type CreateTeacherRequest struct {
	CompanyID      uuid.UUID  `json:"company_id"`
	UserID         uuid.UUID  `json:"user_id"`
	EmployeeCode   string     `json:"employee_code"`
	Qualification  string     `json:"qualification"`
	Specialization string     `json:"specialization"`
	JoiningDate    *time.Time `json:"joining_date"`
	Status         string     `json:"status"`
	CreatedBy      *uuid.UUID `json:"created_by,omitempty"`
	UpdatedBy      *uuid.UUID `json:"updated_by,omitempty"`
}

type UpdateTeacherRequest struct {
	TeacherID      uuid.UUID  `json:"teacher_id"`
	UserID         uuid.UUID  `json:"user_id"`
	EmployeeCode   string     `json:"employee_code"`
	Qualification  string     `json:"qualification"`
	Specialization string     `json:"specialization"`
	JoiningDate    *time.Time `json:"joining_date"`
	Status         string     `json:"status"`
	UpdatedBy      *uuid.UUID `json:"updated_by,omitempty"`
}

type CreateRoomRequest struct {
	CompanyID uuid.UUID
	RoomCode  string
	RoomName  string
	Capacity  int
	Building  string
	Floor     int
	IsActive  bool
	CreatedBy *uuid.UUID
	UpdatedBy *uuid.UUID
}

type UpdateRoomRequest struct {
	RoomID    uuid.UUID
	RoomCode  string
	RoomName  string
	Capacity  int
	Building  string
	Floor     int
	IsActive  bool
	UpdatedBy *uuid.UUID
}

// Guardian requests
type CreateGuardianRequest struct {
	StudentID    uuid.UUID  `json:"student_id"`
	GuardianName string     `json:"guardian_name"`
	Relation     string     `json:"relation"`
	Phone        string     `json:"phone,omitempty"`
	Email        string     `json:"email,omitempty"`
	Address      string     `json:"address,omitempty"`
	IsPrimary    bool       `json:"is_primary"`
	Occupation   string     `json:"occupation,omitempty"`
	Income       *float64   `json:"income,omitempty"`
	CreatedBy    *uuid.UUID `json:"created_by,omitempty"`
	UpdatedBy    *uuid.UUID `json:"updated_by,omitempty"`
}

type UpdateGuardianRequest struct {
	GuardianID   uuid.UUID  `json:"guardian_id"`
	GuardianName string     `json:"guardian_name"`
	Relation     string     `json:"relation"`
	Phone        string     `json:"phone,omitempty"`
	Email        string     `json:"email,omitempty"`
	Address      string     `json:"address,omitempty"`
	IsPrimary    bool       `json:"is_primary"`
	Occupation   string     `json:"occupation,omitempty"`
	Income       *float64   `json:"income,omitempty"`
	UpdatedBy    *uuid.UUID `json:"updated_by,omitempty"`
}

// Filter for listing guardians
type GuardianFilter struct {
	StudentID uuid.UUID `json:"student_id,omitempty"`
	IsPrimary *bool     `json:"is_primary,omitempty"`
	Relation  string    `json:"relation,omitempty"`
	Search    string    `json:"search,omitempty"`
}

// Attendance request DTOs
type MarkAttendanceRequest struct {
	EnrollmentID uuid.UUID               `json:"enrollment_id"`
	Date         time.Time               `json:"date"`
	Status       models.AttendanceStatus `json:"status"`
	Remarks      string                  `json:"remarks,omitempty"`
	MarkedBy     *uuid.UUID              `json:"marked_by,omitempty"`
	CreatedBy    *uuid.UUID              `json:"created_by,omitempty"`
}

type BulkMarkAttendanceRequest struct {
	Attendances []MarkAttendanceRequest `json:"attendances"`
	CreatedBy   *uuid.UUID              `json:"created_by,omitempty"`
}

type ListAttendanceRequest struct {
	EnrollmentID   *uuid.UUID `json:"enrollment_id,omitempty"`
	StudentID      *uuid.UUID `json:"student_id,omitempty"`
	SectionID      *uuid.UUID `json:"section_id,omitempty"`
	TermID         *uuid.UUID `json:"term_id,omitempty"`
	AcademicYearID *uuid.UUID `json:"academic_year_id,omitempty"`
	FromDate       *time.Time `json:"from_date,omitempty"`
	ToDate         *time.Time `json:"to_date,omitempty"`
	Status         *string    `json:"status,omitempty"`
	MarkedBy       *uuid.UUID `json:"marked_by,omitempty"`
	Limit          int        `json:"limit,omitempty"`
	Offset         int        `json:"offset,omitempty"`
	SortField      string     `json:"sort_field,omitempty"`
	SortDirection  string     `json:"sort_direction,omitempty"`
}

type AttendanceSummaryResponse struct {
	SummaryID            uuid.UUID  `json:"summary_id"`
	StudentID            uuid.UUID  `json:"student_id"`
	AcademicYearID       uuid.UUID  `json:"academic_year_id"`
	TermID               *uuid.UUID `json:"term_id,omitempty"`
	TotalPresent         int        `json:"total_present"`
	TotalAbsent          int        `json:"total_absent"`
	TotalLate            int        `json:"total_late"`
	TotalHalfDay         int        `json:"total_half_day"`
	TotalWorkingDays     int        `json:"total_working_days"`
	AttendancePercentage float64    `json:"attendance_percentage"`
	CreatedAt            time.Time  `json:"created_at"`
	UpdatedAt            time.Time  `json:"updated_at"`
}

type CreateAttendanceExemptionRequest struct {
	StudentID  uuid.UUID  `json:"student_id"`
	FromDate   time.Time  `json:"from_date"`
	ToDate     time.Time  `json:"to_date"`
	Reason     string     `json:"reason,omitempty"`
	ApprovedBy *uuid.UUID `json:"approved_by,omitempty"`
	CreatedBy  *uuid.UUID `json:"created_by,omitempty"`
}

type UpdateAttendanceExemptionRequest struct {
	ExemptionID uuid.UUID  `json:"exemption_id"`
	FromDate    time.Time  `json:"from_date"`
	ToDate      time.Time  `json:"to_date"`
	Reason      string     `json:"reason,omitempty"`
	ApprovedBy  *uuid.UUID `json:"approved_by,omitempty"`
	UpdatedBy   *uuid.UUID `json:"updated_by,omitempty"`
}

// Fee structure
type CreateFeeStructureRequest struct {
	CompanyID        uuid.UUID
	AcademicYearID   uuid.UUID
	CourseID         uuid.UUID
	SectionID        *uuid.UUID
	FeeStructureName string
	TotalAmount      float64
	IsActive         bool
	CreatedBy        *uuid.UUID
	UpdatedBy        *uuid.UUID
}

type UpdateFeeStructureRequest struct {
	FeeStructureID   uuid.UUID
	AcademicYearID   uuid.UUID
	CourseID         uuid.UUID
	SectionID        *uuid.UUID
	FeeStructureName string
	TotalAmount      float64
	IsActive         bool
	UpdatedBy        *uuid.UUID
}

type CreateFeeStructureItemRequest struct {
	FeeHead     string
	Amount      float64
	IsMandatory bool
	Description string
	CreatedBy   *uuid.UUID
}

type UpdateFeeStructureItemRequest struct {
	ItemID         uuid.UUID
	FeeStructureID uuid.UUID
	FeeHead        string
	Amount         float64
	IsMandatory    bool
	Description    string
}

// Invoice
type CreateInvoiceRequest struct {
	StudentID      uuid.UUID
	FeeStructureID uuid.UUID
	InvoiceNo      string
	DueDate        time.Time
	TotalAmount    float64
	Items          []CreateInvoiceItemRequest
	CreatedBy      *uuid.UUID
}

type CreateInvoiceItemRequest struct {
	FeeHead     string
	Amount      float64
	IsMandatory bool
}

// Payment
type CreatePaymentRequest struct {
	InvoiceID     uuid.UUID
	PaymentDate   time.Time
	Amount        float64
	PaymentMode   string
	TransactionID string
	ReceiptNo     string
	Remarks       string
	CreatedBy     *uuid.UUID
}

// Discount
type CreateDiscountRequest struct {
	StudentID     uuid.UUID
	DiscountType  string
	DiscountValue float64
	Reason        string
	ApprovedBy    *uuid.UUID
	ValidFrom     *time.Time
	ValidUntil    *time.Time
	CreatedBy     *uuid.UUID
}

type UpdateDiscountRequest struct {
	DiscountID    uuid.UUID
	DiscountType  string
	DiscountValue float64
	Reason        string
	ApprovedBy    *uuid.UUID
	ValidFrom     *time.Time
	ValidUntil    *time.Time
	UpdatedBy     *uuid.UUID
}

// Penalty
type CreatePenaltyRequest struct {
	InvoiceID   uuid.UUID
	PenaltyDate time.Time
	Amount      float64
	Reason      string
	Waived      bool
	WaivedBy    *uuid.UUID
	CreatedBy   *uuid.UUID
}

type UpdatePenaltyRequest struct {
	PenaltyID   uuid.UUID
	PenaltyDate time.Time
	Amount      float64
	Reason      string
	Waived      bool
	WaivedBy    *uuid.UUID
}

// Transport Route
type CreateTransportRouteRequest struct {
	CompanyID  uuid.UUID
	RouteName  string
	StartPoint string
	EndPoint   string
	DistanceKm *float64
	IsActive   bool
	CreatedBy  *uuid.UUID
	UpdatedBy  *uuid.UUID
}

type UpdateTransportRouteRequest struct {
	RouteID    uuid.UUID
	RouteName  string
	StartPoint string
	EndPoint   string
	DistanceKm *float64
	IsActive   bool
	UpdatedBy  *uuid.UUID
}

// Transport Stop
type CreateTransportStopRequest struct {
	RouteID    uuid.UUID
	StopName   string
	StopOrder  int
	Latitude   *float64
	Longitude  *float64
	PickupTime *time.Time
	DropTime   *time.Time
	CreatedBy  *uuid.UUID
	UpdatedBy  *uuid.UUID
}

type UpdateTransportStopRequest struct {
	StopID     uuid.UUID
	StopName   string
	StopOrder  int
	Latitude   *float64
	Longitude  *float64
	PickupTime *time.Time
	DropTime   *time.Time
	UpdatedBy  *uuid.UUID
}

// Transport Vehicle
type CreateTransportVehicleRequest struct {
	CompanyID       uuid.UUID
	VehicleNo       string
	VehicleType     string
	Capacity        *int
	InsuranceExpiry *time.Time
	FitnessExpiry   *time.Time
	IsActive        bool
	CreatedBy       *uuid.UUID
	UpdatedBy       *uuid.UUID
}

type UpdateTransportVehicleRequest struct {
	VehicleID       uuid.UUID
	VehicleNo       string
	VehicleType     string
	Capacity        *int
	InsuranceExpiry *time.Time
	FitnessExpiry   *time.Time
	IsActive        bool
	UpdatedBy       *uuid.UUID
}

// Driver Assignment
type CreateDriverAssignmentRequest struct {
	VehicleID      uuid.UUID
	DriverName     string
	DriverPhone    string
	DriverLicense  string
	AssignmentDate time.Time
	EndDate        *time.Time
	IsActive       bool
	CreatedBy      *uuid.UUID
	UpdatedBy      *uuid.UUID
}

type UpdateDriverAssignmentRequest struct {
	AssignmentID   uuid.UUID
	DriverName     string
	DriverPhone    string
	DriverLicense  string
	AssignmentDate time.Time
	EndDate        *time.Time
	IsActive       bool
	UpdatedBy      *uuid.UUID
}

// Student Transport Assignment
type CreateStudentAssignmentRequest struct {
	StudentID     uuid.UUID
	RouteID       uuid.UUID
	StopID        uuid.UUID
	PickupPoint   string
	DropPoint     string
	EffectiveFrom time.Time
	EffectiveTo   *time.Time
	IsActive      bool
	CreatedBy     *uuid.UUID
	UpdatedBy     *uuid.UUID
}

type UpdateStudentAssignmentRequest struct {
	AssignmentID  uuid.UUID
	StudentID     uuid.UUID
	RouteID       uuid.UUID
	StopID        uuid.UUID
	PickupPoint   string
	DropPoint     string
	EffectiveFrom time.Time
	EffectiveTo   *time.Time
	IsActive      bool
	UpdatedBy     *uuid.UUID
}

// GetAcademicYearMetricsResponse represents the response for academic year metrics.
type GetAcademicYearMetricsResponse struct {
	AcademicYearID uuid.UUID `json:"academic_year_id"`
	TotalStudents  int       `json:"total_students"`
	ActiveStudents int       `json:"active_students"`
	TotalTerms     int       `json:"total_terms"`
	TotalSections  int       `json:"total_sections"`
	TotalCourses   int       `json:"total_courses"`
	TotalSubjects  int       `json:"total_subjects"`
	LastUpdated    time.Time `json:"last_updated"`
}

// ListAcademicYearMetricsRequest defines pagination parameters.
type ListAcademicYearMetricsRequest struct {
	Limit  int `json:"limit"`
	Offset int `json:"offset"`
}

// ListAcademicYearMetricsResponse includes the list and total count.
type ListAcademicYearMetricsResponse struct {
	Metrics []*GetAcademicYearMetricsResponse `json:"metrics"`
	Total   int                               `json:"total"`
}

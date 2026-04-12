package service

import (
	"errors"
	"time"

	"github.com/google/uuid"

	"auth-service/internal/academics/models"
)

// Common errors (keep as is)
var (
	ErrNotFound           = errors.New("resource not found")
	ErrDuplicate          = errors.New("resource already exists")
	ErrOverlap            = errors.New("date range overlaps with existing record")
	ErrInvalidInput       = errors.New("invalid input")
	ErrNotInTransaction   = errors.New("operation must be run in a transaction")
	ErrHasDependencies    = errors.New("resource has dependent records and cannot be deleted")
	ErrDependencyExists   = errors.New("operation blocked due to existing dependencies")
	ErrCapacityExceeded   = errors.New("capacity exceeded")
	ErrConcurrentUpdate   = errors.New("concurrent update detected")
	ErrInactiveEnrollment = errors.New("enrollment is inactive")
	ErrNotEnrolled        = errors.New("student is not enrolled")
)

// ---------- Request DTOs ----------

type CreateAcademicYearRequest struct {
	CompanyID uuid.UUID  `json:"company_id"`
	Name      string     `json:"name"`
	StartDate time.Time  `json:"start_date"`
	EndDate   time.Time  `json:"end_date"`
	IsCurrent bool       `json:"is_current"`
	CreatedBy *uuid.UUID `json:"created_by,omitempty"`
	UpdatedBy *uuid.UUID `json:"updated_by,omitempty"`
}

type UpdateAcademicYearRequest struct {
	AcademicYearID uuid.UUID  `json:"academic_year_id"`
	Name           string     `json:"name"`
	StartDate      time.Time  `json:"start_date"`
	EndDate        time.Time  `json:"end_date"`
	IsCurrent      bool       `json:"is_current"`
	UpdatedBy      *uuid.UUID `json:"updated_by,omitempty"`
}

type CreateTermRequest struct {
	AcademicYearID uuid.UUID  `json:"academic_year_id"`
	Name           string     `json:"name"`
	StartDate      time.Time  `json:"start_date"`
	EndDate        time.Time  `json:"end_date"`
	IsCurrent      bool       `json:"is_current"`
	CreatedBy      *uuid.UUID `json:"created_by,omitempty"`
	UpdatedBy      *uuid.UUID `json:"updated_by,omitempty"`
}

type UpdateTermRequest struct {
	TermID    uuid.UUID  `json:"term_id"`
	Name      string     `json:"name"`
	StartDate time.Time  `json:"start_date"`
	EndDate   time.Time  `json:"end_date"`
	IsCurrent bool       `json:"is_current"`
	UpdatedBy *uuid.UUID `json:"updated_by,omitempty"`
}

type CreateCourseRequest struct {
	CompanyID   uuid.UUID  `json:"company_id"`
	Code        string     `json:"code"`
	Name        string     `json:"name"`
	Description string     `json:"description"`
	Credits     int        `json:"credits"`
	IsActive    bool       `json:"is_active"`
	CreatedBy   *uuid.UUID `json:"created_by,omitempty"`
	UpdatedBy   *uuid.UUID `json:"updated_by,omitempty"`
}

type UpdateCourseRequest struct {
	CourseID    uuid.UUID  `json:"course_id"`
	Code        string     `json:"code"`
	Name        string     `json:"name"`
	Description string     `json:"description"`
	Credits     int        `json:"credits"`
	IsActive    bool       `json:"is_active"`
	UpdatedBy   *uuid.UUID `json:"updated_by,omitempty"`
}

type CreateSubjectRequest struct {
	CompanyID   uuid.UUID  `json:"company_id"`
	Code        string     `json:"code"`
	Name        string     `json:"name"`
	Description string     `json:"description"`
	Credits     int        `json:"credits"`
	IsActive    bool       `json:"is_active"`
	CreatedBy   *uuid.UUID `json:"created_by,omitempty"`
	UpdatedBy   *uuid.UUID `json:"updated_by,omitempty"`
}

type UpdateSubjectRequest struct {
	SubjectID   uuid.UUID  `json:"subject_id"`
	Code        string     `json:"code"`
	Name        string     `json:"name"`
	Description string     `json:"description"`
	Credits     int        `json:"credits"`
	IsActive    bool       `json:"is_active"`
	UpdatedBy   *uuid.UUID `json:"updated_by,omitempty"`
}

type CreateSectionRequest struct {
	CourseID  uuid.UUID  `json:"course_id"`
	TermID    uuid.UUID  `json:"term_id"`
	Name      string     `json:"name"`
	Capacity  int        `json:"capacity"`
	IsActive  bool       `json:"is_active"`
	CreatedBy *uuid.UUID `json:"created_by,omitempty"`
	UpdatedBy *uuid.UUID `json:"updated_by,omitempty"`
}

type UpdateSectionRequest struct {
	SectionID uuid.UUID  `json:"section_id"`
	Name      string     `json:"name"`
	Capacity  int        `json:"capacity"`
	IsActive  bool       `json:"is_active"`
	UpdatedBy *uuid.UUID `json:"updated_by,omitempty"`
}

type AssignSubjectRequest struct {
	CourseID     uuid.UUID `json:"course_id"`
	SubjectID    uuid.UUID `json:"subject_id"`
	TermNumber   int       `json:"term_number"`
	IsCompulsory bool      `json:"is_compulsory"`
}

type CreateStudentRequest struct {
	CompanyID             uuid.UUID  `json:"company_id"`
	FirstName             string     `json:"first_name"`
	LastName              string     `json:"last_name,omitempty"`
	AdmissionNo           string     `json:"admission_no"`
	Email                 string     `json:"email,omitempty"`
	Phone                 string     `json:"phone,omitempty"`
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
	Status                string     `json:"status"`
	CreatedBy             *uuid.UUID `json:"created_by,omitempty"`
	UpdatedBy             *uuid.UUID `json:"updated_by,omitempty"`
}

type UpdateStudentRequest struct {
	StudentID             uuid.UUID  `json:"student_id"`
	FirstName             string     `json:"first_name,omitempty"`
	LastName              string     `json:"last_name,omitempty"`
	AdmissionNo           string     `json:"admission_no"`
	Email                 string     `json:"email,omitempty"`
	Phone                 string     `json:"phone,omitempty"`
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
	CompanyID uuid.UUID  `json:"company_id"`
	RoomCode  string     `json:"room_code"`
	RoomName  string     `json:"room_name"`
	Capacity  int        `json:"capacity"`
	Building  string     `json:"building"`
	Floor     int        `json:"floor"`
	IsActive  bool       `json:"is_active"`
	CreatedBy *uuid.UUID `json:"created_by,omitempty"`
	UpdatedBy *uuid.UUID `json:"updated_by,omitempty"`
}

type UpdateRoomRequest struct {
	RoomID    uuid.UUID  `json:"room_id"`
	RoomCode  string     `json:"room_code"`
	RoomName  string     `json:"room_name"`
	Capacity  int        `json:"capacity"`
	Building  string     `json:"building"`
	Floor     int        `json:"floor"`
	IsActive  bool       `json:"is_active"`
	UpdatedBy *uuid.UUID `json:"updated_by,omitempty"`
}

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

type GuardianFilter struct {
	StudentID uuid.UUID `json:"student_id,omitempty"`
	IsPrimary *bool     `json:"is_primary,omitempty"`
	Relation  string    `json:"relation,omitempty"`
	Search    string    `json:"search,omitempty"`
}

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

type CreateFeeStructureRequest struct {
	CompanyID        uuid.UUID  `json:"company_id"`
	AcademicYearID   uuid.UUID  `json:"academic_year_id"`
	CourseID         uuid.UUID  `json:"course_id"`
	SectionID        *uuid.UUID `json:"section_id,omitempty"`
	FeeStructureName string     `json:"fee_structure_name"`
	TotalAmount      float64    `json:"total_amount"`
	IsActive         bool       `json:"is_active"`
	CreatedBy        *uuid.UUID `json:"created_by,omitempty"`
	UpdatedBy        *uuid.UUID `json:"updated_by,omitempty"`
}

type UpdateFeeStructureRequest struct {
	FeeStructureID   uuid.UUID  `json:"fee_structure_id"`
	AcademicYearID   uuid.UUID  `json:"academic_year_id"`
	CourseID         uuid.UUID  `json:"course_id"`
	SectionID        *uuid.UUID `json:"section_id,omitempty"`
	FeeStructureName string     `json:"fee_structure_name"`
	TotalAmount      float64    `json:"total_amount"`
	IsActive         bool       `json:"is_active"`
	UpdatedBy        *uuid.UUID `json:"updated_by,omitempty"`
}

type CreateFeeStructureItemRequest struct {
	FeeHead     string     `json:"fee_head"`
	Amount      float64    `json:"amount"`
	IsMandatory bool       `json:"is_mandatory"`
	Description string     `json:"description"`
	CreatedBy   *uuid.UUID `json:"created_by,omitempty"`
}

type UpdateFeeStructureItemRequest struct {
	ItemID         uuid.UUID `json:"item_id"`
	FeeStructureID uuid.UUID `json:"fee_structure_id"`
	FeeHead        string    `json:"fee_head"`
	Amount         float64   `json:"amount"`
	IsMandatory    bool      `json:"is_mandatory"`
	Description    string    `json:"description"`
}

type CreateInvoiceRequest struct {
	StudentID      uuid.UUID                  `json:"student_id"`
	FeeStructureID uuid.UUID                  `json:"fee_structure_id"`
	InvoiceNo      string                     `json:"invoice_no"`
	DueDate        time.Time                  `json:"due_date"`
	TotalAmount    float64                    `json:"total_amount"`
	Items          []CreateInvoiceItemRequest `json:"items"`
	CreatedBy      *uuid.UUID                 `json:"created_by,omitempty"`
}

type CreateInvoiceItemRequest struct {
	FeeHead     string  `json:"fee_head"`
	Amount      float64 `json:"amount"`
	IsMandatory bool    `json:"is_mandatory"`
}

type CreatePaymentRequest struct {
	InvoiceID     uuid.UUID  `json:"invoice_id"`
	PaymentDate   time.Time  `json:"payment_date"`
	Amount        float64    `json:"amount"`
	PaymentMode   string     `json:"payment_mode"`
	TransactionID string     `json:"transaction_id"`
	ReceiptNo     string     `json:"receipt_no"`
	Remarks       string     `json:"remarks"`
	CreatedBy     *uuid.UUID `json:"created_by,omitempty"`
}

type CreateDiscountRequest struct {
	StudentID     uuid.UUID  `json:"student_id"`
	DiscountType  string     `json:"discount_type"`
	DiscountValue float64    `json:"discount_value"`
	Reason        string     `json:"reason"`
	ApprovedBy    *uuid.UUID `json:"approved_by,omitempty"`
	ValidFrom     *time.Time `json:"valid_from,omitempty"`
	ValidUntil    *time.Time `json:"valid_until,omitempty"`
	CreatedBy     *uuid.UUID `json:"created_by,omitempty"`
}

type UpdateDiscountRequest struct {
	DiscountID    uuid.UUID  `json:"discount_id"`
	DiscountType  string     `json:"discount_type"`
	DiscountValue float64    `json:"discount_value"`
	Reason        string     `json:"reason"`
	ApprovedBy    *uuid.UUID `json:"approved_by,omitempty"`
	ValidFrom     *time.Time `json:"valid_from,omitempty"`
	ValidUntil    *time.Time `json:"valid_until,omitempty"`
	UpdatedBy     *uuid.UUID `json:"updated_by,omitempty"`
}

type CreatePenaltyRequest struct {
	InvoiceID   uuid.UUID  `json:"invoice_id"`
	PenaltyDate time.Time  `json:"penalty_date"`
	Amount      float64    `json:"amount"`
	Reason      string     `json:"reason"`
	Waived      bool       `json:"waived"`
	WaivedBy    *uuid.UUID `json:"waived_by,omitempty"`
	CreatedBy   *uuid.UUID `json:"created_by,omitempty"`
}

type UpdatePenaltyRequest struct {
	PenaltyID   uuid.UUID  `json:"penalty_id"`
	PenaltyDate time.Time  `json:"penalty_date"`
	Amount      float64    `json:"amount"`
	Reason      string     `json:"reason"`
	Waived      bool       `json:"waived"`
	WaivedBy    *uuid.UUID `json:"waived_by,omitempty"`
}

type CreateTransportRouteRequest struct {
	CompanyID  uuid.UUID  `json:"company_id"`
	RouteName  string     `json:"route_name"`
	StartPoint string     `json:"start_point"`
	EndPoint   string     `json:"end_point"`
	DistanceKm *float64   `json:"distance_km,omitempty"`
	IsActive   bool       `json:"is_active"`
	CreatedBy  *uuid.UUID `json:"created_by,omitempty"`
	UpdatedBy  *uuid.UUID `json:"updated_by,omitempty"`
}

type UpdateTransportRouteRequest struct {
	RouteID    uuid.UUID  `json:"route_id"`
	RouteName  string     `json:"route_name"`
	StartPoint string     `json:"start_point"`
	EndPoint   string     `json:"end_point"`
	DistanceKm *float64   `json:"distance_km,omitempty"`
	IsActive   bool       `json:"is_active"`
	UpdatedBy  *uuid.UUID `json:"updated_by,omitempty"`
}

type CreateTransportStopRequest struct {
	RouteID    uuid.UUID  `json:"route_id"`
	StopName   string     `json:"stop_name"`
	StopOrder  int        `json:"stop_order"`
	Latitude   *float64   `json:"latitude,omitempty"`
	Longitude  *float64   `json:"longitude,omitempty"`
	PickupTime *time.Time `json:"pickup_time,omitempty"`
	DropTime   *time.Time `json:"drop_time,omitempty"`
	CreatedBy  *uuid.UUID `json:"created_by,omitempty"`
	UpdatedBy  *uuid.UUID `json:"updated_by,omitempty"`
}

type UpdateTransportStopRequest struct {
	StopID     uuid.UUID  `json:"stop_id"`
	StopName   string     `json:"stop_name"`
	StopOrder  int        `json:"stop_order"`
	Latitude   *float64   `json:"latitude,omitempty"`
	Longitude  *float64   `json:"longitude,omitempty"`
	PickupTime *time.Time `json:"pickup_time,omitempty"`
	DropTime   *time.Time `json:"drop_time,omitempty"`
	UpdatedBy  *uuid.UUID `json:"updated_by,omitempty"`
}

type CreateTransportVehicleRequest struct {
	CompanyID       uuid.UUID  `json:"company_id"`
	VehicleNo       string     `json:"vehicle_no"`
	VehicleType     string     `json:"vehicle_type"`
	Capacity        *int       `json:"capacity,omitempty"`
	InsuranceExpiry *time.Time `json:"insurance_expiry,omitempty"`
	FitnessExpiry   *time.Time `json:"fitness_expiry,omitempty"`
	IsActive        bool       `json:"is_active"`
	CreatedBy       *uuid.UUID `json:"created_by,omitempty"`
	UpdatedBy       *uuid.UUID `json:"updated_by,omitempty"`
}

type UpdateTransportVehicleRequest struct {
	VehicleID       uuid.UUID  `json:"vehicle_id"`
	VehicleNo       string     `json:"vehicle_no"`
	VehicleType     string     `json:"vehicle_type"`
	Capacity        *int       `json:"capacity,omitempty"`
	InsuranceExpiry *time.Time `json:"insurance_expiry,omitempty"`
	FitnessExpiry   *time.Time `json:"fitness_expiry,omitempty"`
	IsActive        bool       `json:"is_active"`
	UpdatedBy       *uuid.UUID `json:"updated_by,omitempty"`
}

type CreateDriverAssignmentRequest struct {
	VehicleID      uuid.UUID  `json:"vehicle_id"`
	DriverName     string     `json:"driver_name"`
	DriverPhone    string     `json:"driver_phone"`
	DriverLicense  string     `json:"driver_license"`
	AssignmentDate time.Time  `json:"assignment_date"`
	EndDate        *time.Time `json:"end_date,omitempty"`
	IsActive       bool       `json:"is_active"`
	CreatedBy      *uuid.UUID `json:"created_by,omitempty"`
	UpdatedBy      *uuid.UUID `json:"updated_by,omitempty"`
}

type UpdateDriverAssignmentRequest struct {
	AssignmentID   uuid.UUID  `json:"assignment_id"`
	DriverName     string     `json:"driver_name"`
	DriverPhone    string     `json:"driver_phone"`
	DriverLicense  string     `json:"driver_license"`
	AssignmentDate time.Time  `json:"assignment_date"`
	EndDate        *time.Time `json:"end_date,omitempty"`
	IsActive       bool       `json:"is_active"`
	UpdatedBy      *uuid.UUID `json:"updated_by,omitempty"`
}

type CreateStudentAssignmentRequest struct {
	StudentID     uuid.UUID  `json:"student_id"`
	RouteID       uuid.UUID  `json:"route_id"`
	StopID        uuid.UUID  `json:"stop_id"`
	PickupPoint   string     `json:"pickup_point"`
	DropPoint     string     `json:"drop_point"`
	EffectiveFrom time.Time  `json:"effective_from"`
	EffectiveTo   *time.Time `json:"effective_to,omitempty"`
	IsActive      bool       `json:"is_active"`
	CreatedBy     *uuid.UUID `json:"created_by,omitempty"`
	UpdatedBy     *uuid.UUID `json:"updated_by,omitempty"`
}

type UpdateStudentAssignmentRequest struct {
	AssignmentID  uuid.UUID  `json:"assignment_id"`
	StudentID     uuid.UUID  `json:"student_id"`
	RouteID       uuid.UUID  `json:"route_id"`
	StopID        uuid.UUID  `json:"stop_id"`
	PickupPoint   string     `json:"pickup_point"`
	DropPoint     string     `json:"drop_point"`
	EffectiveFrom time.Time  `json:"effective_from"`
	EffectiveTo   *time.Time `json:"effective_to,omitempty"`
	IsActive      bool       `json:"is_active"`
	UpdatedBy     *uuid.UUID `json:"updated_by,omitempty"`
}

// ---------- Response DTOs (optional snake_case tags) ----------

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

type ListAcademicYearMetricsRequest struct {
	Limit  int `json:"limit"`
	Offset int `json:"offset"`
}

type ListAcademicYearMetricsResponse struct {
	Metrics []*GetAcademicYearMetricsResponse `json:"metrics"`
	Total   int                               `json:"total"`
}

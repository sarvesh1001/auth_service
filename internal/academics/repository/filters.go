package repository

import (
	"auth-service/internal/academics/models"
	"time"

	"github.com/google/uuid"
)

// Pagination holds pagination parameters.
type Pagination struct {
	Limit  int
	Offset int
}

// Sort holds sorting parameters.
type Sort struct {
	Field     string
	Direction string
}

// AcademicYearFilter represents filtering options for academic years.
type AcademicYearFilter struct {
	CompanyID uuid.UUID
	IsCurrent *bool
	StartFrom *time.Time
	EndTo     *time.Time
	Search    string
}

// TermFilter represents filtering options for terms.
type TermFilter struct {
	AcademicYearID uuid.UUID
	IsCurrent      *bool
	StartFrom      *time.Time
	EndTo          *time.Time
	Search         string
}

// CourseFilter represents filtering options for courses.
type CourseFilter struct {
	CompanyID uuid.UUID
	IsActive  *bool
	Search    string
	Code      string
}

// SectionFilter represents filtering options for sections.
type SectionFilter struct {
	CourseIDs []uuid.UUID // changed from single CourseID to slice
	TermIDs   []uuid.UUID // changed from single TermID to slice
	IsActive  *bool
	Search    string
}

// SubjectFilter represents filtering options for subjects.
type SubjectFilter struct {
	CompanyID uuid.UUID
	IsActive  *bool
	Search    string
	Code      string
}

// SubjectCourseMappingFilter represents filtering options for subject-course mappings.
type SubjectCourseMappingFilter struct {
	CourseID   uuid.UUID
	SubjectID  uuid.UUID
	TermNumber *int
}

// StudentFilter holds filtering criteria for students.
type StudentFilter struct {
	CompanyID       uuid.UUID
	Search          string // searches admission_no and user's name (requires user join)
	AdmissionNumber string
	Status          *string
	CourseID        *uuid.UUID // filters by active enrollment in that course
	SectionID       *uuid.UUID // filters by active enrollment in that section
	TermID          *uuid.UUID // filters by active enrollment in a term (via section)
	JoinedFrom      *time.Time // filters by enrollment_date >= value
	JoinedTo        *time.Time // filters by enrollment_date <= value
	IsActive        *bool      // if true, status = 'active'; if false, status != 'active'
}

// filters.go (excerpt)
type EnrollmentFilter struct {
	CompanyID          uuid.UUID // <-- add this field
	StudentID          uuid.UUID
	AcademicYearID     uuid.UUID
	SectionID          uuid.UUID
	Status             *string
	EnrollmentDateFrom *time.Time
	EnrollmentDateTo   *time.Time
	Search             string
}

// TeacherFilter holds filtering criteria for teachers.
type TeacherFilter struct {
	CompanyID      uuid.UUID
	UserID         *uuid.UUID
	EmployeeCode   string
	Status         *string // active, inactive, resigned
	IsActive       *bool   // if true: status='active'; if false: status!='active'
	Specialization string
	Search         string // matches employee_code, user's name (if joined), but we'll only search on employee_code for simplicity (or we can join users)
}

// GuardianFilter holds filtering options for guardians.
type GuardianFilter struct {
	StudentID uuid.UUID
	IsPrimary *bool
	Relation  string
	Search    string // searches guardian_name
}

// RoomFilter holds filtering criteria for rooms.
type RoomFilter struct {
	CompanyID   uuid.UUID
	RoomCode    string
	IsActive    *bool
	Building    string
	MinCapacity *int
	MaxCapacity *int
	Search      string // searches room_code, room_name
}

// AssignmentFilter holds filtering criteria for assignments.
type AssignmentFilter struct {
	SectionID   *uuid.UUID
	SubjectID   *uuid.UUID
	TeacherID   *uuid.UUID
	IsPublished *bool
	DueDateFrom *time.Time
	DueDateTo   *time.Time
	Search      string // title, description
}

// SubmissionFilter holds filtering criteria for submissions.
type SubmissionFilter struct {
	AssignmentID  *uuid.UUID
	StudentID     *uuid.UUID
	Status        *string
	Graded        *bool // true: status='graded', false: status IN ('submitted','late')
	SubmittedFrom *time.Time
	SubmittedTo   *time.Time
}

// ExamFilter holds filtering criteria for exams.
type ExamFilter struct {
	AcademicYearID uuid.UUID
	TermID         *uuid.UUID
	IsActive       *bool
	Search         string // search in exam_name
	StartDateFrom  *time.Time
	StartDateTo    *time.Time
	EndDateFrom    *time.Time
	EndDateTo      *time.Time
}

// ExamScheduleFilter holds filtering criteria for exam schedules.
type ExamScheduleFilter struct {
	ExamID    uuid.UUID
	SubjectID *uuid.UUID
	RoomID    *uuid.UUID
	DateFrom  *time.Time
	DateTo    *time.Time
}

// ExamResultFilter holds filtering criteria for exam results.
type ExamResultFilter struct {
	ExamID       uuid.UUID
	EnrollmentID *uuid.UUID
	SubjectID    *uuid.UUID
	Grade        *string
	MarksMin     *float64
	MarksMax     *float64
}

// ExamGradeFilter holds filtering criteria for exam grades.
type ExamGradeFilter struct {
	ExamID uuid.UUID
}

// GradingPolicyFilter holds filtering options for grading policies.
type GradingPolicyFilter struct {
	CompanyID    uuid.UUID
	PolicyName   string
	GradingScale *string // percentage, grade_point, letter_grade
	IsDefault    *bool
	Search       string // searches policy_name
}

// GradeBoundaryFilter holds filtering options for grade boundaries.
type GradeBoundaryFilter struct {
	PolicyID uuid.UUID
}

// AttendanceFilter holds filtering criteria for attendance records.
type AttendanceFilter struct {
	EnrollmentID   *uuid.UUID
	StudentID      *uuid.UUID // joins with enrollments
	AcademicYearID *uuid.UUID // joins with enrollments
	SectionID      *uuid.UUID // joins with enrollments → section
	TermID         *uuid.UUID // joins with enrollments → section
	FromDate       *time.Time
	ToDate         *time.Time
	Status         *string
	MarkedBy       *uuid.UUID
}

// FeeStructureFilter
type FeeStructureFilter struct {
	AcademicYearID *uuid.UUID
	CourseID       *uuid.UUID
	SectionID      *uuid.UUID
	IsActive       *bool
	Search         string // search in name
}

// InvoiceFilter
type InvoiceFilter struct {
	StudentID      *uuid.UUID
	FeeStructureID *uuid.UUID
	Status         *string // unpaid, partial, paid, overdue, cancelled
	DueDateFrom    *time.Time
	DueDateTo      *time.Time
	InvoiceNo      string
}

// PaymentFilter
type PaymentFilter struct {
	InvoiceID       *uuid.UUID
	StudentID       *uuid.UUID
	PaymentDateFrom *time.Time
	PaymentDateTo   *time.Time
	PaymentMode     *string
	ReceiptNo       string
}

// TimetableFilter holds filtering criteria for timetables.
type TimetableFilter struct {
	TermID         *uuid.UUID
	SectionID      *uuid.UUID
	AcademicYearID *uuid.UUID
	IsActive       *bool
	EffectiveFrom  *time.Time
	EffectiveTo    *time.Time
}

// LibraryCategoryFilter
type LibraryCategoryFilter struct {
	CompanyID uuid.UUID
	Search    string // matches category_name or description
}

// LibraryBookFilter
type LibraryBookFilter struct {
	CompanyID  uuid.UUID
	CategoryID *uuid.UUID
	Title      string
	Author     string
	ISBN       string
	Language   string
	Search     string // matches title, author, isbn, publisher
}

// LibraryCopyFilter
type LibraryCopyFilter struct {
	BookID      *uuid.UUID
	Status      *string
	AccessionNo string
	Search      string // matches accession_no, shelf_location
}

// LibraryIssueFilter
type LibraryIssueFilter struct {
	StudentID *uuid.UUID
	CopyID    *uuid.UUID
	Status    *string
	FromDate  *time.Time // issue_date >=
	ToDate    *time.Time // issue_date <=
	Overdue   *bool      // true: due_date < now() and status = 'issued'
}

// TransportRouteFilter holds filtering criteria for transport routes.
type TransportRouteFilter struct {
	CompanyID uuid.UUID
	IsActive  *bool
	Search    string // matches route_name, start_point, end_point
}

// TransportStopFilter holds filtering criteria for transport stops.
type TransportStopFilter struct {
	RouteID uuid.UUID
	Search  string // matches stop_name
}

// TransportVehicleFilter holds filtering criteria for vehicles.
type TransportVehicleFilter struct {
	CompanyID uuid.UUID
	IsActive  *bool
	Search    string // matches vehicle_no, vehicle_type
}

// TransportDriverAssignmentFilter holds filtering criteria for driver assignments.
type TransportDriverAssignmentFilter struct {
	VehicleID uuid.UUID
	IsActive  *bool
	Date      *time.Time // assignments active on this date
}

// StudentTransportAssignmentFilter holds filtering criteria for student assignments.
type StudentTransportAssignmentFilter struct {
	StudentID     uuid.UUID
	RouteID       uuid.UUID
	StopID        uuid.UUID
	IsActive      *bool
	EffectiveDate *time.Time // assignments effective on this date
}

// AdmissionFilter holds filtering criteria for admissions.
type AdmissionFilter struct {
	StudentID       *uuid.UUID
	AcademicYearID  *uuid.UUID
	AdmissionStatus *string // pending, approved, rejected
	FromDate        *time.Time
	ToDate          *time.Time
	Search          string // searches student name? but admission doesn't have name, so maybe search on remarks or class_applied_for
}

// NotificationFilter holds filtering criteria for notifications.
type NotificationFilter struct {
	CompanyID   uuid.UUID
	Types       []models.NotificationType // e.g., info, warning, alert, event, announcement
	Priorities  []models.NotificationPriority
	CreatedBy   *uuid.UUID
	ExpiresFrom *time.Time
	ExpiresTo   *time.Time
	CreatedFrom *time.Time
	CreatedTo   *time.Time
	Search      string // search in title and message
	// For read status filtering – may require join with notification_reads
	UserID     *uuid.UUID // if set, returns notifications targeted to this user or read/unread status
	ReadStatus *bool      // true = read, false = unread (only valid if UserID is set)
}

// StudentPerformanceSummaryFilter filters student performance summaries.
type StudentPerformanceSummaryFilter struct {
	StudentID      *uuid.UUID
	AcademicYearID *uuid.UUID
	TermID         *uuid.UUID // NULL for yearly summary
	Search         string     // optional: search by student name? (would require join)
	// If you need joins, add fields like StudentName, etc.
}

// ClassPerformanceSummaryFilter filters class performance summaries.
type ClassPerformanceSummaryFilter struct {
	SectionID      *uuid.UUID
	AcademicYearID *uuid.UUID
	TermID         *uuid.UUID
	Search         string
}

// StudentRankingFilter filters student rankings.
type StudentRankingFilter struct {
	StudentID      *uuid.UUID
	AcademicYearID *uuid.UUID
	TermID         *uuid.UUID
	RankFrom       *int
	RankTo         *int
}

package models

import (
	"time"

	"github.com/google/uuid"
)

// -----------------------------------------------------------------------------
// Academic Year Metrics (aggregated across various domains)
// -----------------------------------------------------------------------------

type AcademicYearMetrics struct {
	AcademicYearID         uuid.UUID `db:"academic_year_id" json:"academic_year_id"`
	TotalStudents          int       `db:"total_students" json:"total_students"`
	ActiveStudents         int       `db:"active_students" json:"active_students"`
	TotalTerms             int       `db:"total_terms" json:"total_terms"`
	TotalSections          int       `db:"total_sections" json:"total_sections"`
	TotalCourses           int       `db:"total_courses" json:"total_courses"`
	TotalSubjects          int       `db:"total_subjects" json:"total_subjects"`
	TotalAdmissions        int       `db:"total_admissions" json:"total_admissions"`
	ApprovedAdmissions     int       `db:"approved_admissions" json:"approved_admissions"`
	PendingAdmissions      int       `db:"pending_admissions" json:"pending_admissions"`
	RejectedAdmissions     int       `db:"rejected_admissions" json:"rejected_admissions"`
	TotalAssignments       int       `db:"total_assignments" json:"total_assignments"`
	PublishedAssignments   int       `db:"published_assignments" json:"published_assignments"`
	TotalAttendanceRecords int       `db:"total_attendance_records" json:"total_attendance_records"`
	TotalAbsentRecords     int       `db:"total_absent_records" json:"total_absent_records"`
	TotalLateRecords       int       `db:"total_late_records" json:"total_late_records"`
	TotalHalfDayRecords    int       `db:"total_half_day_records" json:"total_half_day_records"`
	TotalExemptions        int       `db:"total_exemptions" json:"total_exemptions"`
	TotalSubjectMappings   int       `db:"total_subject_mappings" json:"total_subject_mappings"`
	CoursesWithCurriculum  int       `db:"courses_with_curriculum" json:"courses_with_curriculum"`
	TotalEnrollments       int       `db:"total_enrollments" json:"total_enrollments"`
	ActiveEnrollments      int       `db:"active_enrollments" json:"active_enrollments"`
	CompletedEnrollments   int       `db:"completed_enrollments" json:"completed_enrollments"`
	WithdrawnEnrollments   int       `db:"withdrawn_enrollments" json:"withdrawn_enrollments"`

	// Period‑attendance (session) metrics
	TotalSessionsGenerated       int `db:"total_sessions_generated" json:"total_sessions_generated"`
	TotalPeriodAttendances       int `db:"total_period_attendances" json:"total_period_attendances"`
	TotalBiometricAttendances    int `db:"total_biometric_attendances" json:"total_biometric_attendances"`
	TotalManualPeriodAttendances int `db:"total_manual_period_attendances" json:"total_manual_period_attendances"`

	LastUpdated time.Time `db:"last_updated" json:"last_updated"`
}

type AcademicYearMetricsUpdate struct {
	AcademicYearID             uuid.UUID
	DeltaStudents              int
	DeltaActive                int
	DeltaTerms                 int
	DeltaSections              int
	DeltaCourses               int
	DeltaSubjects              int
	DeltaTotalAdm              int
	DeltaApprovedAdm           int
	DeltaPendingAdm            int
	DeltaRejectedAdm           int
	DeltaTotalAssignments      int
	DeltaPublishedAssignments  int
	DeltaAttendanceRecords     int
	DeltaAbsentRecords         int
	DeltaLateRecords           int
	DeltaHalfDayRecords        int
	DeltaExemptions            int
	DeltaTotalSubjectMappings  int
	DeltaCoursesWithCurriculum int
	DeltaTotalEnrollments      int
	DeltaActiveEnrollments     int
	DeltaCompletedEnrollments  int
	DeltaWithdrawnEnrollments  int
	// Period‑attendance deltas
	DeltaSessionsGenerated       int
	DeltaPeriodAttendances       int
	DeltaBiometricAttendances    int
	DeltaManualPeriodAttendances int
}

// -----------------------------------------------------------------------------
// Student Session Summary (period attendance per student per term/year)
// -----------------------------------------------------------------------------

type StudentSessionSummary struct {
	StudentID            uuid.UUID  `db:"student_id" json:"student_id"`
	AcademicYearID       uuid.UUID  `db:"academic_year_id" json:"academic_year_id"`
	TermID               *uuid.UUID `db:"term_id" json:"term_id,omitempty"`
	TotalSessions        int        `db:"total_sessions" json:"total_sessions"`
	PresentSessions      int        `db:"present_sessions" json:"present_sessions"`
	AbsentSessions       int        `db:"absent_sessions" json:"absent_sessions"`
	LateSessions         int        `db:"late_sessions" json:"late_sessions"`
	ExcusedSessions      int        `db:"excused_sessions" json:"excused_sessions"`
	AttendancePercentage float64    `db:"attendance_percentage" json:"attendance_percentage"` // generated
	LastUpdated          time.Time  `db:"last_updated" json:"last_updated"`
}

// -----------------------------------------------------------------------------
// Section Session Metrics (daily metrics per section)
// -----------------------------------------------------------------------------

type SectionSessionMetrics struct {
	SectionID         uuid.UUID `db:"section_id" json:"section_id"`
	SessionDate       time.Time `db:"session_date" json:"session_date"`
	TotalEnrolled     int       `db:"total_enrolled" json:"total_enrolled"`
	PresentCount      int       `db:"present_count" json:"present_count"`
	AbsentCount       int       `db:"absent_count" json:"absent_count"`
	LateCount         int       `db:"late_count" json:"late_count"`
	MarkedByTeacher   *int      `db:"marked_by_teacher" json:"marked_by_teacher,omitempty"`     // count marked manually
	MarkedByBiometric *int      `db:"marked_by_biometric" json:"marked_by_biometric,omitempty"` // count auto‑marked
}

// -----------------------------------------------------------------------------
// Teacher Session Metrics (teacher performance on marking attendance)
// -----------------------------------------------------------------------------

type TeacherSessionMetrics struct {
	TeacherID             uuid.UUID `db:"teacher_id" json:"teacher_id"`
	AcademicYearID        uuid.UUID `db:"academic_year_id" json:"academic_year_id"`
	TotalSessionsTaught   int       `db:"total_sessions_taught" json:"total_sessions_taught"`
	SessionsMarked        int       `db:"sessions_marked" json:"sessions_marked"`                 // teacher marked at least one student
	SessionsWithBiometric int       `db:"sessions_with_biometric" json:"sessions_with_biometric"` // biometric used
	LastUpdated           time.Time `db:"last_updated" json:"last_updated"`
}

// -----------------------------------------------------------------------------
// Biometric Device Usage Analytics
// -----------------------------------------------------------------------------

type BiometricUsageMetrics struct {
	DeviceID          string    `db:"device_id" json:"device_id"`
	CompanyID         uuid.UUID `db:"company_id" json:"company_id"`
	Date              time.Time `db:"date" json:"date"`
	TotalPunches      int       `db:"total_punches" json:"total_punches"`
	SuccessfulMatches int       `db:"successful_matches" json:"successful_matches"`
	FailedMatches     int       `db:"failed_matches" json:"failed_matches"`
	UniqueStudents    int       `db:"unique_students" json:"unique_students"`
}

// -----------------------------------------------------------------------------
// Exam Metrics
// -----------------------------------------------------------------------------

type ExamMetrics struct {
	AcademicYearID uuid.UUID `db:"academic_year_id" json:"academic_year_id"`
	TotalExams     int       `db:"total_exams" json:"total_exams"`
	TotalSchedules int       `db:"total_schedules" json:"total_schedules"`
	TotalResults   int       `db:"total_results" json:"total_results"`
	TotalGrades    int       `db:"total_grades" json:"total_grades"`
	LastUpdated    time.Time `db:"last_updated" json:"last_updated"`
}

type ExamMetricsUpdate struct {
	AcademicYearID uuid.UUID
	DeltaExams     int
	DeltaSchedules int
	DeltaResults   int
	DeltaGrades    int
}

// -----------------------------------------------------------------------------
// Fee Metrics
// -----------------------------------------------------------------------------

type FeeMetrics struct {
	AcademicYearID      uuid.UUID `db:"academic_year_id" json:"academic_year_id"`
	TotalFeeStructures  int       `db:"total_fee_structures" json:"total_fee_structures"`
	TotalInvoices       int       `db:"total_invoices" json:"total_invoices"`
	TotalPayments       int       `db:"total_payments" json:"total_payments"`
	TotalDiscounts      int       `db:"total_discounts" json:"total_discounts"`
	TotalPenalties      int       `db:"total_penalties" json:"total_penalties"`
	TotalReceipts       int       `db:"total_receipts" json:"total_receipts"`
	TotalInvoiceAmount  float64   `db:"total_invoice_amount" json:"total_invoice_amount"`
	TotalPaidAmount     float64   `db:"total_paid_amount" json:"total_paid_amount"`
	TotalDiscountAmount float64   `db:"total_discount_amount" json:"total_discount_amount"`
	TotalPenaltyAmount  float64   `db:"total_penalty_amount" json:"total_penalty_amount"`
	LastUpdated         time.Time `db:"last_updated" json:"last_updated"`
}

type FeeMetricsUpdate struct {
	AcademicYearID      uuid.UUID
	DeltaFeeStructures  int
	DeltaInvoices       int
	DeltaPayments       int
	DeltaDiscounts      int
	DeltaPenalties      int
	DeltaReceipts       int
	DeltaInvoiceAmount  float64
	DeltaPaidAmount     float64
	DeltaDiscountAmount float64
	DeltaPenaltyAmount  float64
}

// -----------------------------------------------------------------------------
// Grading Metrics
// -----------------------------------------------------------------------------

type GradingMetrics struct {
	AcademicYearID  uuid.UUID `db:"academic_year_id" json:"academic_year_id"`
	TotalPolicies   int       `db:"total_policies" json:"total_policies"`
	TotalBoundaries int       `db:"total_boundaries" json:"total_boundaries"`
	LastUpdated     time.Time `db:"last_updated" json:"last_updated"`
}

type GradingMetricsUpdate struct {
	AcademicYearID  uuid.UUID
	DeltaPolicies   int
	DeltaBoundaries int
}

// -----------------------------------------------------------------------------
// Guardian Metrics
// -----------------------------------------------------------------------------

type GuardianMetrics struct {
	AcademicYearID        uuid.UUID `db:"academic_year_id" json:"academic_year_id"`
	TotalGuardians        int       `db:"total_guardians" json:"total_guardians"`
	TotalPrimaryGuardians int       `db:"total_primary_guardians" json:"total_primary_guardians"`
	LastUpdated           time.Time `db:"last_updated" json:"last_updated"`
}

type GuardianMetricsUpdate struct {
	AcademicYearID        uuid.UUID
	DeltaGuardians        int
	DeltaPrimaryGuardians int
}

// -----------------------------------------------------------------------------
// Library Metrics
// -----------------------------------------------------------------------------

type LibraryMetrics struct {
	AcademicYearID  uuid.UUID `db:"academic_year_id" json:"academic_year_id"`
	TotalCategories int       `db:"total_categories" json:"total_categories"`
	TotalBooks      int       `db:"total_books" json:"total_books"`
	TotalCopies     int       `db:"total_copies" json:"total_copies"`
	TotalIssues     int       `db:"total_issues" json:"total_issues"`
	TotalReturns    int       `db:"total_returns" json:"total_returns"`
	TotalFines      int       `db:"total_fines" json:"total_fines"`
	TotalFineAmount float64   `db:"total_fine_amount" json:"total_fine_amount"`
	LastUpdated     time.Time `db:"last_updated" json:"last_updated"`
}

type LibraryMetricsUpdate struct {
	AcademicYearID  uuid.UUID
	DeltaCategories int
	DeltaBooks      int
	DeltaCopies     int
	DeltaIssues     int
	DeltaReturns    int
	DeltaFines      int
	DeltaFineAmount float64
}

// -----------------------------------------------------------------------------
// Room Metrics
// -----------------------------------------------------------------------------

type RoomMetrics struct {
	AcademicYearID uuid.UUID `db:"academic_year_id" json:"academic_year_id"`
	TotalRooms     int       `db:"total_rooms" json:"total_rooms"`
	ActiveRooms    int       `db:"active_rooms" json:"active_rooms"`
	LastUpdated    time.Time `db:"last_updated" json:"last_updated"`
}

type RoomMetricsUpdate struct {
	AcademicYearID uuid.UUID
	DeltaRooms     int
	DeltaActive    int
}

// -----------------------------------------------------------------------------
// Section Metrics
// -----------------------------------------------------------------------------

type SectionMetrics struct {
	AcademicYearID uuid.UUID `db:"academic_year_id" json:"academic_year_id"`
	TotalSections  int       `db:"total_sections" json:"total_sections"`
	ActiveSections int       `db:"active_sections" json:"active_sections"`
	TotalCapacity  int       `db:"total_capacity" json:"total_capacity"`
	UsedCapacity   int       `db:"used_capacity" json:"used_capacity"`
	LastUpdated    time.Time `db:"last_updated" json:"last_updated"`
}

type SectionMetricsUpdate struct {
	AcademicYearID uuid.UUID
	DeltaSections  int
	DeltaActive    int
	DeltaTotalCap  int
	DeltaUsedCap   int
}

// -----------------------------------------------------------------------------
// Student Metrics
// -----------------------------------------------------------------------------

type StudentMetrics struct {
	AcademicYearID uuid.UUID `db:"academic_year_id" json:"academic_year_id"`
	TotalStudents  int       `db:"total_students" json:"total_students"`
	ActiveStudents int       `db:"active_students" json:"active_students"`
	MaleStudents   int       `db:"male_students" json:"male_students"`
	FemaleStudents int       `db:"female_students" json:"female_students"`
	LastUpdated    time.Time `db:"last_updated" json:"last_updated"`
}

type StudentMetricsUpdate struct {
	AcademicYearID uuid.UUID
	DeltaTotal     int
	DeltaActive    int
	DeltaMale      int
	DeltaFemale    int
}

// -----------------------------------------------------------------------------
// Subject Metrics
// -----------------------------------------------------------------------------

type SubjectMetrics struct {
	AcademicYearID uuid.UUID `db:"academic_year_id" json:"academic_year_id"`
	TotalSubjects  int       `db:"total_subjects" json:"total_subjects"`
	ActiveSubjects int       `db:"active_subjects" json:"active_subjects"`
	TotalCredits   int       `db:"total_credits" json:"total_credits"`
	LastUpdated    time.Time `db:"last_updated" json:"last_updated"`
}

type SubjectMetricsUpdate struct {
	AcademicYearID uuid.UUID
	DeltaTotal     int
	DeltaActive    int
	DeltaCredits   int
}

// -----------------------------------------------------------------------------
// Submission Metrics
// -----------------------------------------------------------------------------

type SubmissionMetrics struct {
	AcademicYearID    uuid.UUID `db:"academic_year_id" json:"academic_year_id"`
	TotalSubmissions  int       `db:"total_submissions" json:"total_submissions"`
	LateSubmissions   int       `db:"late_submissions" json:"late_submissions"`
	GradedSubmissions int       `db:"graded_submissions" json:"graded_submissions"`
	LastUpdated       time.Time `db:"last_updated" json:"last_updated"`
}

type SubmissionMetricsUpdate struct {
	AcademicYearID uuid.UUID
	DeltaTotal     int
	DeltaLate      int
	DeltaGraded    int
}

// -----------------------------------------------------------------------------
// Teacher Metrics
// -----------------------------------------------------------------------------

type TeacherMetrics struct {
	AcademicYearID uuid.UUID `db:"academic_year_id" json:"academic_year_id"`
	TotalTeachers  int       `db:"total_teachers" json:"total_teachers"`
	ActiveTeachers int       `db:"active_teachers" json:"active_teachers"`
	LastUpdated    time.Time `db:"last_updated" json:"last_updated"`
}

type TeacherMetricsUpdate struct {
	AcademicYearID uuid.UUID
	DeltaTotal     int
	DeltaActive    int
}

// -----------------------------------------------------------------------------
// Timetable Metrics
// -----------------------------------------------------------------------------

type TimetableMetrics struct {
	AcademicYearID   uuid.UUID `db:"academic_year_id" json:"academic_year_id"`
	TotalTimetables  int       `db:"total_timetables" json:"total_timetables"`
	ActiveTimetables int       `db:"active_timetables" json:"active_timetables"`
	TotalSlots       int       `db:"total_slots" json:"total_slots"`
	TotalEntries     int       `db:"total_entries" json:"total_entries"`
	TotalChanges     int       `db:"total_changes" json:"total_changes"`
	LastUpdated      time.Time `db:"last_updated" json:"last_updated"`
}

type TimetableMetricsUpdate struct {
	AcademicYearID  uuid.UUID
	DeltaTimetables int
	DeltaActive     int
	DeltaSlots      int
	DeltaEntries    int
	DeltaChanges    int
}

// -----------------------------------------------------------------------------
// Transport Metrics
// -----------------------------------------------------------------------------

type TransportMetrics struct {
	AcademicYearID          uuid.UUID `db:"academic_year_id" json:"academic_year_id"`
	TotalRoutes             int       `db:"total_routes" json:"total_routes"`
	TotalStops              int       `db:"total_stops" json:"total_stops"`
	TotalVehicles           int       `db:"total_vehicles" json:"total_vehicles"`
	ActiveVehicles          int       `db:"active_vehicles" json:"active_vehicles"`
	TotalDriverAssignments  int       `db:"total_driver_assignments" json:"total_driver_assignments"`
	TotalStudentAssignments int       `db:"total_student_assignments" json:"total_student_assignments"`
	LastUpdated             time.Time `db:"last_updated" json:"last_updated"`
}

type TransportMetricsUpdate struct {
	AcademicYearID          uuid.UUID
	DeltaRoutes             int
	DeltaStops              int
	DeltaVehicles           int
	DeltaActiveVehicles     int
	DeltaDriverAssignments  int
	DeltaStudentAssignments int
}

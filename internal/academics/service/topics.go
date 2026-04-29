package service

// Kafka topics for academics module outbox events
// All events are now published to a single topic "academics-events"
const (
	// Core academics events
	TopicAcademicYear         = "academics-events"
	TopicTerm                 = "academics-events"
	TopicCourse               = "academics-events"
	TopicSubject              = "academics-events"
	TopicSection              = "academics-events"
	TopicRoom                 = "academics-events"
	TopicExam                 = "academics-events"
	TopicExamSchedule         = "academics-events"
	TopicExamResult           = "academics-events"
	TopicExamGrade            = "academics-events"
	TopicGradingPolicy        = "academics-events"
	TopicGradeBoundary        = "academics-events"
	TopicTimetable            = "academics-events"
	TopicAcademicSession      = "academics-events"
	TopicBiometricMapping     = "academics-events"
	TopicStudentFaceEmbedding = "academics-events"

	// Library events
	TopicLibraryCategory = "academics-events"
	TopicLibraryBook     = "academics-events"
	TopicLibraryCopy     = "academics-events"
	TopicLibraryIssue    = "academics-events"
	TopicLibraryFine     = "academics-events"

	// Student specific
	TopicStudent = "academics-events"

	// Teacher specific
	TopicTeacher = "academics-events"

	// Guardian specific
	TopicGuardian = "academics-events"

	// Admission specific
	TopicAdmission = "academics-events"

	// Assignment specific
	TopicAssignment = "academics-events"

	// Submission specific
	TopicSubmission = "academics-events"

	// Attendance events
	TopicAttendance       = "academics-events"
	TopicPeriodAttendance = "academics-events"

	// Fee events
	TopicFeeStructure = "academics-events"
	TopicFeeInvoice   = "academics-events"
	TopicFeePayment   = "academics-events"
	TopicFeeDiscount  = "academics-events"
	TopicFeePenalty   = "academics-events"

	// Transport events
	TopicTransportRoute   = "academics-events"
	TopicTransportStop    = "academics-events"
	TopicTransportVehicle = "academics-events"
	TopicTransportDriver  = "academics-events"
	TopicTransportStudent = "academics-events"

	// Notification events
	TopicNotification = "academics-events"
)

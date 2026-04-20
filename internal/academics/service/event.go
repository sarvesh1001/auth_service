package service

import (
	"context"

	"go.uber.org/zap"
)

type EventType string

const (
	EventSectionCreated         EventType = "section.created"
	EventSectionUpdated         EventType = "section.updated"
	EventSectionDeleted         EventType = "section.deleted"
	EventCourseCreated          EventType = "course.created"
	EventCourseUpdated          EventType = "course.updated"
	EventCourseDeleted          EventType = "course.deleted"
	EventAcademicYearCreated    EventType = "academic_year.created"
	EventAcademicYearUpdated    EventType = "academic_year.updated"
	EventAcademicYearDeleted    EventType = "academic_year.deleted"
	EventAcademicYearSetCurrent EventType = "academic_year.set_current"
	EventSubjectCreated         EventType = "subject.created"
	EventSubjectUpdated         EventType = "subject.updated"
	EventSubjectDeleted         EventType = "subject.deleted"
	EventSubjectAssigned        EventType = "subject.assigned"
	EventSubjectUnassigned      EventType = "subject.unassigned"
	EventTermCreated            EventType = "term.created"
	EventTermUpdated            EventType = "term.updated"
	EventTermDeleted            EventType = "term.deleted"
	EventTermSetCurrent         EventType = "term.set_current"
	EventStudentCreated         EventType = "student.created"
	EventStudentUpdated         EventType = "student.updated"
	EventStudentDeleted         EventType = "student.deleted"
	EventStudentPromoted        EventType = "student.promoted"
	EventStudentGraduated       EventType = "student.graduated"
	EventStudentDroppedOut      EventType = "student.dropped_out"
	EventStudentBulkPromoted    EventType = "student.bulk_promoted"
	EventNotificationCreated    EventType = "notification.created"
	EventNotificationUpdated    EventType = "notification.updated"
	EventNotificationDeleted    EventType = "notification.deleted"
	EventNotificationRead       EventType = "notification.read"
	EventNotificationAllRead    EventType = "notification.all_read"
	EventTimetableCreated       EventType = "timetable.created"
	EventTimetableUpdated       EventType = "timetable.updated"
	EventTimetableDeleted       EventType = "timetable.deleted"
	EventTimetableSlotAdded     EventType = "timetable.slot_added"
	EventTimetableSlotUpdated   EventType = "timetable.slot_updated"
	EventTimetableSlotDeleted   EventType = "timetable.slot_deleted"
	EventTimetableEntryAdded    EventType = "timetable.entry_added"
	EventTimetableEntryUpdated  EventType = "timetable.entry_updated"
	EventTimetableEntryDeleted  EventType = "timetable.entry_deleted"
	EventTimetableChangeAdded   EventType = "timetable.change_added"
	EventFeeStructureCreated    EventType = "fee_structure.created"
	EventFeeStructureUpdated    EventType = "fee_structure.updated"
	EventFeeStructureDeleted    EventType = "fee_structure.deleted"
	EventFeeInvoiceCreated      EventType = "fee_invoice.created"
	EventFeeInvoiceUpdated      EventType = "fee_invoice.updated"
	EventFeePaymentCreated      EventType = "fee_payment.created"
	EventFeePaymentUpdated      EventType = "fee_payment.updated"
	EventFeeDiscountCreated     EventType = "fee_discount.created"
	EventFeeDiscountUpdated     EventType = "fee_discount.updated"
	EventFeePenaltyCreated      EventType = "fee_penalty.created"
	EventFeeReceiptGenerated    EventType = "fee_receipt.generated"
	// Additional student events used in student_service.go
	EventStudentContactUpdated             EventType = "student.contact_updated"
	EventStudentActivated                  EventType = "student.activated"
	EventStudentDeactivated                EventType = "student.deactivated"
	EventStudentBulkStatusUpdated          EventType = "student.bulk_status_updated"
	EventTeacherCreated                    EventType = "teacher.created"
	EventTeacherUpdated                    EventType = "teacher.updated"
	EventTeacherDeleted                    EventType = "teacher.deleted"
	EventTeacherStatusUpdated              EventType = "teacher.status_updated"
	EventTeacherSubjectAssigned            EventType = "teacher.subject_assigned"
	EventTeacherSubjectRemoved             EventType = "teacher.subject_removed"
	EventTeacherSubjectUpdated             EventType = "teacher.subject_updated"
	EventTeacherSectionAssigned            EventType = "teacher.section_assigned"
	EventTeacherSectionRemoved             EventType = "teacher.section_removed"
	EventTeacherClassTeacherUpdated        EventType = "teacher.class_teacher_updated"
	EventTeacherSchedulePreferenceSet      EventType = "teacher.schedule_preference_set"
	EventTeacherSchedulePreferenceUpdated  EventType = "teacher.schedule_preference_updated"
	EventTeacherSchedulePreferenceDeleted  EventType = "teacher.schedule_preference_deleted"
	EventTeacherSchedulePreferencesCleared EventType = "teacher.schedule_preferences_cleared"
	EventTeacherBulkStatusUpdated          EventType = "teacher.bulk_status_updated"
	EventRoomCreated                       EventType = "room.created"
	EventRoomUpdated                       EventType = "room.updated"
	EventRoomDeleted                       EventType = "room.deleted"
	EventRoomActivated                     EventType = "room.activated"
	EventRoomDeactivated                   EventType = "room.deactivated"
	EventGuardianCreated                   EventType = "guardian.created"
	EventGuardianUpdated                   EventType = "guardian.updated"
	EventGuardianDeleted                   EventType = "guardian.deleted"
	EventGuardianPrimarySet                EventType = "guardian.primary_set"
	EventAdmissionCreated                  EventType = "admission.created"
	EventAdmissionUpdated                  EventType = "admission.updated"
	EventAdmissionStatusUpdated            EventType = "admission.status_updated"
	EventAdmissionDeleted                  EventType = "admission.deleted"
	EventAssignmentCreated                 EventType = "assignment.created"
	EventAssignmentUpdated                 EventType = "assignment.updated"
	EventAssignmentDeleted                 EventType = "assignment.deleted"
	EventAssignmentPublished               EventType = "assignment.published"
	EventSubmissionCreated                 EventType = "submission.created"
	EventSubmissionUpdated                 EventType = "submission.updated"
	EventSubmissionDeleted                 EventType = "submission.deleted"
	EventSubmissionGraded                  EventType = "submission.graded"
	EventSubmissionCommentAdded            EventType = "submission.comment_added"
	EventAttendanceMarked                  EventType = "attendance.marked"
	EventAttendanceBulkMarked              EventType = "attendance.bulk_marked"
	EventAttendanceSummaryUpdated          EventType = "attendance.summary_updated"
	EventAttendanceExemptionCreated        EventType = "attendance.exemption_created"
	EventAttendanceExemptionUpdated        EventType = "attendance.exemption_updated"
	EventAttendanceExemptionDeleted        EventType = "attendance.exemption_deleted"
	EventExamCreated                       EventType = "exam.created"
	EventExamUpdated                       EventType = "exam.updated"
	EventExamDeleted                       EventType = "exam.deleted"
	EventExamScheduleCreated               EventType = "exam_schedule.created"
	EventExamScheduleUpdated               EventType = "exam_schedule.updated"
	EventExamScheduleDeleted               EventType = "exam_schedule.deleted"
	EventExamResultCreated                 EventType = "exam_result.created"
	EventExamResultUpdated                 EventType = "exam_result.updated"
	EventExamResultDeleted                 EventType = "exam_result.deleted"
	EventExamGradeCreated                  EventType = "exam_grade.created"
	EventExamGradeUpdated                  EventType = "exam_grade.updated"
	EventExamGradeDeleted                  EventType = "exam_grade.deleted"
	// Grading events
	EventLibraryCategoryCreated EventType = "library_category.created"
	EventLibraryCategoryUpdated EventType = "library_category.updated"
	EventLibraryCategoryDeleted EventType = "library_category.deleted"

	EventLibraryBookCreated EventType = "library_book.created"
	EventLibraryBookUpdated EventType = "library_book.updated"
	EventLibraryBookDeleted EventType = "library_book.deleted"

	EventLibraryCopyCreated EventType = "library_copy.created"
	EventLibraryCopyUpdated EventType = "library_copy.updated"
	EventLibraryCopyDeleted EventType = "library_copy.deleted"

	EventLibraryBookIssued   EventType = "library_book.issued"
	EventLibraryBookReturned EventType = "library_book.returned"

	EventLibraryFineCreated EventType = "library_fine.created"
	EventLibraryFinePaid    EventType = "library_fine.paid"

	EventGradingPolicyCreated   EventType = "grading_policy.created"
	EventGradingPolicyUpdated   EventType = "grading_policy.updated"
	EventGradingPolicyDeleted   EventType = "grading_policy.deleted"
	EventGradeBoundaryCreated   EventType = "grade_boundary.created"
	EventGradeBoundaryUpdated   EventType = "grade_boundary.updated"
	EventGradeBoundaryDeleted   EventType = "grade_boundary.deleted"
	EventPeriodAttendanceMarked           = "period_attendance.marked"
	EventSessionsGenerated      EventType = "academic_sessions.generated"
	// Add to existing event.go

	EventBiometricPunchProcessed EventType = "biometric_punch.processed"

	EventBiometricMappingCreated   EventType = "biometric_mapping.created"
	EventBiometricMappingUpdated   EventType = "biometric_mapping.updated"
	EventBiometricMappingDeleted   EventType = "biometric_mapping.deleted"
	EventBiometricMappingActivated EventType = "biometric_mapping.activated"
	// Transport events
	EventTransportRouteCreated             EventType = "transport.route.created"
	EventTransportRouteUpdated             EventType = "transport.route.updated"
	EventTransportRouteDeleted             EventType = "transport.route.deleted"
	EventTransportStopCreated              EventType = "transport.stop.created"
	EventTransportStopUpdated              EventType = "transport.stop.updated"
	EventTransportStopDeleted              EventType = "transport.stop.deleted"
	EventTransportVehicleCreated           EventType = "transport.vehicle.created"
	EventTransportVehicleUpdated           EventType = "transport.vehicle.updated"
	EventTransportVehicleDeleted           EventType = "transport.vehicle.deleted"
	EventTransportDriverAssignmentCreated  EventType = "transport.driver_assignment.created"
	EventTransportDriverAssignmentUpdated  EventType = "transport.driver_assignment.updated"
	EventTransportDriverAssignmentDeleted  EventType = "transport.driver_assignment.deleted"
	EventTransportStudentAssignmentCreated EventType = "transport.student_assignment.created"
	EventTransportStudentAssignmentUpdated EventType = "transport.student_assignment.updated"
	EventTransportStudentAssignmentDeleted EventType = "transport.student_assignment.deleted"
	// add others as needed
	EventStudentFaceEmbeddingCreated     EventType = "student_face_embedding.created"
	EventStudentFaceEmbeddingUpdated     EventType = "student_face_embedding.updated"
	EventStudentFaceEmbeddingDeleted     EventType = "student_face_embedding.deleted"
	EventStudentFaceEmbeddingDeactivated EventType = "student_face_embedding.deactivated"

	EventBiometricFullPunchProcessed = "biometric_full_punch.processed"
)

type Event struct {
	Type EventType
	Data interface{}
}

type EventPublisher interface {
	Publish(ctx context.Context, event Event) error
}

type noopEventPublisher struct {
	logger *zap.Logger
}

func NewNoopEventPublisher(logger *zap.Logger) EventPublisher {
	return &noopEventPublisher{logger: logger}
}

func (p *noopEventPublisher) Publish(ctx context.Context, event Event) error {
	p.logger.Info("event published", zap.String("type", string(event.Type)), zap.Any("data", event.Data))
	return nil
}

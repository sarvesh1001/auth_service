package consumer

import (
	"context"
	"encoding/json"
	"fmt"
	"time"

	"github.com/google/uuid"
	"github.com/segmentio/kafka-go"
	"go.uber.org/zap"

	"auth-service/internal/academics/models"
	"auth-service/internal/academics/repository"
	"auth-service/internal/academics/service"
	"auth-service/internal/client"
	"auth-service/internal/util"
)

// -----------------------------------------------------------------------------
// AnalyticsConsumer – listens to domain events and updates analytics fact tables.
// -----------------------------------------------------------------------------

type AnalyticsConsumer struct {
	analyticsSvc service.AnalyticsService
	repo         repository.AnalyticsRepository // kept for potential future direct calls
	pgClient     *client.PostgresClient
	logger       *zap.Logger
	consumer     *client.KafkaConsumer
	topic        string
	maxRetries   int
	producer     *kafka.Writer // for retries and DLQ
}

// NewAnalyticsConsumer creates a new analytics consumer.
func NewAnalyticsConsumer(
	analyticsSvc service.AnalyticsService,
	repo repository.AnalyticsRepository,
	pgClient *client.PostgresClient,
	logger *zap.Logger,
	consumer *client.KafkaConsumer,
	topic string,
	brokers []string,
) *AnalyticsConsumer {
	return &AnalyticsConsumer{
		analyticsSvc: analyticsSvc,
		repo:         repo,
		pgClient:     pgClient,
		logger:       logger.Named("analytics_consumer"),
		consumer:     consumer,
		topic:        topic,
		maxRetries:   3,
		producer: &kafka.Writer{
			Addr:         kafka.TCP(brokers...),
			Balancer:     &kafka.LeastBytes{},
			RequiredAcks: kafka.RequireOne,
			Async:        false,
		},
	}
}

// Start begins consuming messages from the topic.
func (c *AnalyticsConsumer) Start(ctx context.Context) {
	c.logger.Info("starting analytics consumer", zap.String("topic", c.topic))

	for {
		msg, err := c.consumer.ConsumeMessage(ctx)
		if err != nil {
			if ctx.Err() != nil {
				return
			}
			c.logger.Error("failed to consume message", zap.Error(err))
			continue
		}

		eventType := c.extractEventType(msg)
		if eventType == "" {
			c.logger.Warn("message has no event_type header", zap.ByteString("key", msg.Key))
			// No event type → cannot process, commit to avoid infinite loop
			_ = c.consumer.CommitMessage(ctx, msg)
			continue
		}

		retryCount := c.getRetryCount(msg)
		err = c.handleEvent(ctx, eventType, msg.Value)

		if err != nil {
			c.logger.Error("failed to process event",
				zap.String("event_type", eventType),
				zap.Int("retry", retryCount),
				zap.Error(err),
			)

			if retryCount < c.maxRetries {
				// Try to publish retry message
				if pubErr := c.publishRetry(ctx, msg, retryCount+1); pubErr != nil {
					c.logger.Error("failed to publish retry message, will retry original later",
						zap.Error(pubErr))
					// Do NOT commit the original message – it will be redelivered
					continue
				}
				// Retry published successfully – now we can commit the original
				c.logger.Info("retry message published, committing original",
					zap.String("event_type", eventType),
					zap.Int("next_retry", retryCount+1))
			} else {
				// Max retries exceeded – send to DLQ
				if dlqErr := c.sendToDLQ(ctx, msg, err); dlqErr != nil {
					c.logger.Error("failed to send to DLQ, will retry original later",
						zap.Error(dlqErr))
					// Do NOT commit – keep original for later retry
					continue
				}
				c.logger.Warn("message sent to DLQ, committing original",
					zap.String("event_type", eventType))
			}
		}

		// Commit original message only if:
		// - processing succeeded, OR
		// - processing failed but retry/DLQ was successfully published
		if err := c.consumer.CommitMessage(ctx, msg); err != nil {
			c.logger.Error("failed to commit message", zap.Error(err))
		}
	}
}

// handleEvent routes the event to the appropriate update method.
func (c *AnalyticsConsumer) handleEvent(ctx context.Context, eventType string, payload []byte) error {
	switch eventType {
	// Admission events
	case "admission.created":
		return c.analyticsSvc.ProcessAdmissionCreated(ctx, payload)
	case "admission.status_updated":
		return c.analyticsSvc.ProcessAdmissionStatusUpdated(ctx, payload)

	// Term events
	case "term.created":
		return c.analyticsSvc.ProcessTermCreated(ctx, payload)

	// Section events
	case "section.created":
		return c.analyticsSvc.ProcessSectionCreated(ctx, payload)
	case "section.updated":
		return c.analyticsSvc.ProcessSectionUpdated(ctx, payload)
	case "section.activated":
		return c.analyticsSvc.ProcessSectionActivated(ctx, payload)
	case "section.deactivated":
		return c.analyticsSvc.ProcessSectionDeactivated(ctx, payload)
	case "section.deleted":
		return c.analyticsSvc.ProcessSectionDeleted(ctx, payload)

	// Assignment events
	case "assignment.created":
		return c.analyticsSvc.ProcessAssignmentCreated(ctx, payload)
	case "assignment.updated":
		return c.analyticsSvc.ProcessAssignmentUpdated(ctx, payload)
	case "assignment.deleted":
		return c.analyticsSvc.ProcessAssignmentDeleted(ctx, payload)
	case "assignment.published":
		return c.analyticsSvc.ProcessAssignmentPublished(ctx, payload)

	// Attendance events
	case "attendance.marked":
		return c.analyticsSvc.ProcessAttendanceMarked(ctx, payload)
	case "attendance.bulk_marked":
		return c.analyticsSvc.ProcessAttendanceBulkMarked(ctx, payload)
	case "attendance.exemption_created":
		return c.analyticsSvc.ProcessAttendanceExemptionCreated(ctx, payload)
	case "attendance.exemption_deleted":
		return c.analyticsSvc.ProcessAttendanceExemptionDeleted(ctx, payload)

	// Curriculum events
	case "subject.assigned":
		return c.analyticsSvc.ProcessSubjectAssigned(ctx, payload)
	case "subject.unassigned":
		return c.analyticsSvc.ProcessSubjectUnassigned(ctx, payload)

	// Enrollment events
	case "enrollment.created":
		return c.analyticsSvc.ProcessEnrollmentCreated(ctx, payload)
	case "enrollment.updated":
		return c.analyticsSvc.ProcessEnrollmentUpdated(ctx, payload)
	case "enrollment.deleted":
		return c.analyticsSvc.ProcessEnrollmentDeleted(ctx, payload)

	// Exam domain events
	case "exam.created":
		return c.analyticsSvc.ProcessExamCreated(ctx, payload)
	case "exam.updated":
		return c.analyticsSvc.ProcessExamUpdated(ctx, payload)
	case "exam.deleted":
		return c.analyticsSvc.ProcessExamDeleted(ctx, payload)
	case "exam_schedule.created":
		return c.analyticsSvc.ProcessExamScheduleCreated(ctx, payload)
	case "exam_schedule.deleted":
		return c.analyticsSvc.ProcessExamScheduleDeleted(ctx, payload)
	case "exam_result.created":
		return c.analyticsSvc.ProcessExamResultCreated(ctx, payload)
	case "exam_result.deleted":
		return c.analyticsSvc.ProcessExamResultDeleted(ctx, payload)
	case "exam_grade.created":
		return c.analyticsSvc.ProcessExamGradeCreated(ctx, payload)
	case "exam_grade.deleted":
		return c.analyticsSvc.ProcessExamGradeDeleted(ctx, payload)

	// Fee domain events
	case "fee_structure.created":
		return c.analyticsSvc.ProcessFeeStructureCreated(ctx, payload)
	case "fee_structure.updated":
		return c.analyticsSvc.ProcessFeeStructureUpdated(ctx, payload)
	case "fee_structure.deleted":
		return c.analyticsSvc.ProcessFeeStructureDeleted(ctx, payload)
	case "fee_invoice.created":
		return c.analyticsSvc.ProcessFeeInvoiceCreated(ctx, payload)
	case "fee_payment.created":
		return c.analyticsSvc.ProcessFeePaymentCreated(ctx, payload)
	case "fee_discount.created":
		return c.analyticsSvc.ProcessFeeDiscountCreated(ctx, payload)
	case "fee_discount.updated":
		return c.analyticsSvc.ProcessFeeDiscountUpdated(ctx, payload)
	case "fee_discount.deleted":
		return c.analyticsSvc.ProcessFeeDiscountDeleted(ctx, payload)
	case "fee_penalty.created":
		return c.analyticsSvc.ProcessFeePenaltyCreated(ctx, payload)
	case "fee_penalty.updated":
		return c.analyticsSvc.ProcessFeePenaltyUpdated(ctx, payload)
	case "fee_receipt.generated":
		return c.analyticsSvc.ProcessFeeReceiptGenerated(ctx, payload)

	// Grading domain events
	case "grading_policy.created":
		return c.analyticsSvc.ProcessGradingPolicyCreated(ctx, payload)
	case "grading_policy.deleted":
		return c.analyticsSvc.ProcessGradingPolicyDeleted(ctx, payload)
	case "grade_boundary.created":
		return c.analyticsSvc.ProcessGradeBoundaryCreated(ctx, payload)
	case "grade_boundary.deleted":
		return c.analyticsSvc.ProcessGradeBoundaryDeleted(ctx, payload)

	// Guardian domain events
	case "guardian.created":
		return c.analyticsSvc.ProcessGuardianCreated(ctx, payload)
	case "guardian.updated":
		return c.analyticsSvc.ProcessGuardianUpdated(ctx, payload)
	case "guardian.deleted":
		return c.analyticsSvc.ProcessGuardianDeleted(ctx, payload)
	case "guardian.primary_set":
		return c.analyticsSvc.ProcessGuardianPrimarySet(ctx, payload)

	// Library domain events
	case "library_category.created":
		return c.analyticsSvc.ProcessLibraryCategoryCreated(ctx, payload)
	case "library_category.deleted":
		return c.analyticsSvc.ProcessLibraryCategoryDeleted(ctx, payload)
	case "library_book.created":
		return c.analyticsSvc.ProcessLibraryBookCreated(ctx, payload)
	case "library_book.deleted":
		return c.analyticsSvc.ProcessLibraryBookDeleted(ctx, payload)
	case "library_copy.created":
		return c.analyticsSvc.ProcessLibraryCopyCreated(ctx, payload)
	case "library_copy.deleted":
		return c.analyticsSvc.ProcessLibraryCopyDeleted(ctx, payload)
	case "library_book.issued":
		return c.analyticsSvc.ProcessLibraryBookIssued(ctx, payload)
	case "library_book.returned":
		return c.analyticsSvc.ProcessLibraryBookReturned(ctx, payload)
	case "library_fine.created":
		return c.analyticsSvc.ProcessLibraryFineCreated(ctx, payload)
	case "library_fine.paid":
		return c.analyticsSvc.ProcessLibraryFinePaid(ctx, payload)

	// Room events
	case "room.created":
		return c.analyticsSvc.ProcessRoomCreated(ctx, payload)
	case "room.updated":
		return c.analyticsSvc.ProcessRoomUpdated(ctx, payload)
	case "room.activated":
		return c.analyticsSvc.ProcessRoomActivated(ctx, payload)
	case "room.deactivated":
		return c.analyticsSvc.ProcessRoomDeactivated(ctx, payload)
	case "room.deleted":
		return c.analyticsSvc.ProcessRoomDeleted(ctx, payload)

	// Student events
	case "student.created":
		return c.analyticsSvc.ProcessStudentCreated(ctx, payload)
	case "student.updated":
		return c.analyticsSvc.ProcessStudentUpdated(ctx, payload)
	case "student.activated":
		return c.analyticsSvc.ProcessStudentActivated(ctx, payload)
	case "student.deactivated":
		return c.analyticsSvc.ProcessStudentDeactivated(ctx, payload)
	case "student.deleted":
		return c.analyticsSvc.ProcessStudentDeleted(ctx, payload)

	// Subject events
	case "subject.created":
		return c.analyticsSvc.ProcessSubjectCreated(ctx, payload)
	case "subject.updated":
		return c.analyticsSvc.ProcessSubjectUpdated(ctx, payload)
	case "subject.activated":
		return c.analyticsSvc.ProcessSubjectActivated(ctx, payload)
	case "subject.deactivated":
		return c.analyticsSvc.ProcessSubjectDeactivated(ctx, payload)
	case "subject.deleted":
		return c.analyticsSvc.ProcessSubjectDeleted(ctx, payload)

	// Submission events
	case "submission.created":
		return c.analyticsSvc.ProcessSubmissionCreated(ctx, payload)
	case "submission.updated":
		return c.analyticsSvc.ProcessSubmissionUpdated(ctx, payload)
	case "submission.deleted":
		return c.analyticsSvc.ProcessSubmissionDeleted(ctx, payload)
	case "submission.graded":
		return c.analyticsSvc.ProcessSubmissionGraded(ctx, payload)

	// Teacher events
	case "teacher.created":
		return c.analyticsSvc.ProcessTeacherCreated(ctx, payload)
	case "teacher.updated":
		return c.analyticsSvc.ProcessTeacherUpdated(ctx, payload)
	case "teacher.activated":
		return c.analyticsSvc.ProcessTeacherActivated(ctx, payload)
	case "teacher.deactivated":
		return c.analyticsSvc.ProcessTeacherDeactivated(ctx, payload)
	case "teacher.deleted":
		return c.analyticsSvc.ProcessTeacherDeleted(ctx, payload)

	// Timetable events
	case "timetable.created":
		return c.analyticsSvc.ProcessTimetableCreated(ctx, payload)
	case "timetable.updated":
		return c.analyticsSvc.ProcessTimetableUpdated(ctx, payload)
	case "timetable.deleted":
		return c.analyticsSvc.ProcessTimetableDeleted(ctx, payload)
	case "timetable_slot.added":
		return c.analyticsSvc.ProcessTimetableSlotAdded(ctx, payload)
	case "timetable_slot.updated":
		return c.analyticsSvc.ProcessTimetableSlotUpdated(ctx, payload)
	case "timetable_slot.deleted":
		return c.analyticsSvc.ProcessTimetableSlotDeleted(ctx, payload)
	case "timetable_entry.added":
		return c.analyticsSvc.ProcessTimetableEntryAdded(ctx, payload)
	case "timetable_entry.updated":
		return c.analyticsSvc.ProcessTimetableEntryUpdated(ctx, payload)
	case "timetable_entry.deleted":
		return c.analyticsSvc.ProcessTimetableEntryDeleted(ctx, payload)
	case "timetable_change.added":
		return c.analyticsSvc.ProcessTimetableChangeAdded(ctx, payload)

	// Transport events
	case "transport_route.created":
		return c.analyticsSvc.ProcessTransportRouteCreated(ctx, payload)
	case "transport_route.updated":
		return c.analyticsSvc.ProcessTransportRouteUpdated(ctx, payload)
	case "transport_route.deleted":
		return c.analyticsSvc.ProcessTransportRouteDeleted(ctx, payload)
	case "transport_stop.created":
		return c.analyticsSvc.ProcessTransportStopCreated(ctx, payload)
	case "transport_stop.updated":
		return c.analyticsSvc.ProcessTransportStopUpdated(ctx, payload)
	case "transport_stop.deleted":
		return c.analyticsSvc.ProcessTransportStopDeleted(ctx, payload)
	case "transport_vehicle.created":
		return c.analyticsSvc.ProcessTransportVehicleCreated(ctx, payload)
	case "transport_vehicle.updated":
		return c.analyticsSvc.ProcessTransportVehicleUpdated(ctx, payload)
	case "transport_vehicle.deleted":
		return c.analyticsSvc.ProcessTransportVehicleDeleted(ctx, payload)
	case "transport_driver_assignment.created":
		return c.analyticsSvc.ProcessTransportDriverAssignmentCreated(ctx, payload)
	case "transport_driver_assignment.updated":
		return c.analyticsSvc.ProcessTransportDriverAssignmentUpdated(ctx, payload)
	case "transport_driver_assignment.deleted":
		return c.analyticsSvc.ProcessTransportDriverAssignmentDeleted(ctx, payload)
	case "transport_student_assignment.created":
		return c.analyticsSvc.ProcessTransportStudentAssignmentCreated(ctx, payload)
	case "transport_student_assignment.updated":
		return c.analyticsSvc.ProcessTransportStudentAssignmentUpdated(ctx, payload)
	case "transport_student_assignment.deleted":
		return c.analyticsSvc.ProcessTransportStudentAssignmentDeleted(ctx, payload)

	// Period attendance & session generation events
	case "academic_sessions.generated":
		return c.analyticsSvc.ProcessSessionsGenerated(ctx, payload)
	case "period_attendance.marked":
		return c.analyticsSvc.ProcessPeriodAttendanceMarked(ctx, payload)
	case "biometric_punch.processed":
		return c.analyticsSvc.ProcessBiometricPunchProcessed(ctx, payload)

	default:
		c.logger.Debug("ignored event type", zap.String("event_type", eventType))
		return nil
	}
}

func (c *AnalyticsConsumer) extractEventType(msg *kafka.Message) string {
	for _, h := range msg.Headers {
		if h.Key == "event_type" {
			return string(h.Value)
		}
	}
	return ""
}

func (c *AnalyticsConsumer) getRetryCount(msg *kafka.Message) int {
	for _, h := range msg.Headers {
		if h.Key == "retry_count" {
			var count int
			fmt.Sscanf(string(h.Value), "%d", &count)
			return count
		}
	}
	return 0
}

func (c *AnalyticsConsumer) publishRetry(ctx context.Context, original *kafka.Message, newRetryCount int) error {
	headers := make([]kafka.Header, 0, len(original.Headers)+1)
	found := false
	for _, h := range original.Headers {
		if h.Key == "retry_count" {
			headers = append(headers, kafka.Header{
				Key:   "retry_count",
				Value: []byte(fmt.Sprintf("%d", newRetryCount)),
			})
			found = true
		} else {
			headers = append(headers, h)
		}
	}
	if !found {
		headers = append(headers, kafka.Header{
			Key:   "retry_count",
			Value: []byte(fmt.Sprintf("%d", newRetryCount)),
		})
	}
	retryMsg := kafka.Message{
		Topic:   original.Topic,
		Key:     original.Key,
		Value:   original.Value,
		Headers: headers,
		Time:    time.Now(),
	}
	return c.producer.WriteMessages(ctx, retryMsg)
}

func (c *AnalyticsConsumer) sendToDLQ(ctx context.Context, original *kafka.Message, processErr error) error {
	dlqTopic := original.Topic + ".dlq"
	headers := append(original.Headers,
		kafka.Header{Key: "error", Value: []byte(processErr.Error())},
		kafka.Header{Key: "failed_at", Value: []byte(time.Now().Format(time.RFC3339))},
	)
	dlqMsg := kafka.Message{
		Topic:   dlqTopic,
		Key:     original.Key,
		Value:   original.Value,
		Headers: headers,
		Time:    time.Now(),
	}
	return c.producer.WriteMessages(ctx, dlqMsg)
}

// Close shuts down the consumer and producer.
func (c *AnalyticsConsumer) Close() error {
	if err := c.consumer.Close(); err != nil {
		c.logger.Error("failed to close consumer", zap.Error(err))
	}
	return c.producer.Close()
}

// -----------------------------------------------------------------------------
// StudentConsumer – listens to domain events and updates student-related data.
// -----------------------------------------------------------------------------

type StudentConsumer struct {
	kafkaConsumers map[string]*client.KafkaConsumer
	logger         *zap.Logger
	maxRetries     int
	producer       *kafka.Writer
}

func NewStudentConsumer(
	kafkaConsumers map[string]*client.KafkaConsumer,
	brokers []string,
) *StudentConsumer {
	logger := util.Get().Named("student_consumer")
	topics := make([]string, 0, len(kafkaConsumers))
	for t := range kafkaConsumers {
		topics = append(topics, t)
	}
	producer := &kafka.Writer{
		Addr:         kafka.TCP(brokers...),
		Balancer:     &kafka.LeastBytes{},
		RequiredAcks: kafka.RequireOne,
		Async:        false,
	}
	logger.Info("Student consumer initialized",
		zap.Strings("topics", topics),
		zap.Int("topic_count", len(topics)),
		zap.Int("max_retries", 3),
	)
	return &StudentConsumer{
		kafkaConsumers: kafkaConsumers,
		logger:         logger,
		maxRetries:     3,
		producer:       producer,
	}
}

func (c *StudentConsumer) Start(ctx context.Context) error {
	c.logger.Info("Student consumer started")
	for topic, kc := range c.kafkaConsumers {
		go c.consumeTopic(ctx, topic, kc)
	}
	<-ctx.Done()
	c.logger.Info("Student consumer stopped")
	return ctx.Err()
}

func (c *StudentConsumer) consumeTopic(
	ctx context.Context,
	topic string,
	kc *client.KafkaConsumer,
) {
	c.logger.Info("started topic consumer", zap.String("topic", topic))

	for {
		msg, err := kc.ConsumeMessage(ctx)
		if err != nil {
			if ctx.Err() != nil {
				return
			}
			c.logger.Error("failed to consume message",
				zap.String("topic", topic),
				zap.Error(err),
			)
			time.Sleep(time.Second)
			continue
		}

		eventType := c.extractEventType(msg)
		retryCount := c.getRetryCount(msg)
		err = c.handleEvent(ctx, eventType, msg.Value)

		if err != nil {
			c.logger.Error("event processing failed",
				zap.String("event_type", eventType),
				zap.Int("retry", retryCount),
				zap.Error(err),
			)

			if retryCount < c.maxRetries {
				c.logger.Warn("retrying event",
					zap.String("event_type", eventType),
					zap.Int("attempt", retryCount+1),
				)
				if pubErr := c.publishRetry(ctx, msg, retryCount+1); pubErr != nil {
					c.logger.Error("failed to publish retry message, will retry original later",
						zap.Error(pubErr))
					// Do NOT commit – original stays in Kafka
					continue
				}
				// Retry published successfully
				c.logger.Info("retry message published, committing original",
					zap.String("event_type", eventType))
			} else {
				c.logger.Error("max retries exceeded, sending to DLQ",
					zap.String("event_type", eventType),
				)
				if dlqErr := c.sendToDLQ(ctx, msg, err); dlqErr != nil {
					c.logger.Error("failed to send message to DLQ, will retry original later",
						zap.Error(dlqErr))
					continue
				}
				c.logger.Warn("message sent to DLQ, committing original",
					zap.String("event_type", eventType))
			}
		}

		// Commit original message only after successful processing or successful retry/DLQ publish
		if commitErr := kc.CommitMessage(ctx, msg); commitErr != nil {
			c.logger.Error("failed to commit message",
				zap.String("topic", topic),
				zap.Error(commitErr),
			)
		}
	}
}
func (c *StudentConsumer) handleEvent(ctx context.Context, eventType string, payload []byte) error {
	switch eventType {
	case "student.created":
		return c.handleStudentCreated(ctx, payload)
	case "student.updated":
		return c.handleStudentUpdated(ctx, payload)
	case "student.deleted":
		return c.handleStudentDeleted(ctx, payload)
	case "student.promoted":
		return c.handleStudentPromoted(ctx, payload)
	case "student.bulk_promoted":
		return c.handleStudentBulkPromoted(ctx, payload)
	case "student.graduated":
		return c.handleStudentGraduated(ctx, payload)
	case "student.dropped_out":
		return c.handleStudentDroppedOut(ctx, payload)
	case "student.activated":
		return c.handleStudentActivated(ctx, payload)
	case "student.deactivated":
		return c.handleStudentDeactivated(ctx, payload)
	case "student.bulk_status_updated":
		return c.handleStudentBulkStatusUpdated(ctx, payload)
	case "academic_year.created":
		return c.handleAcademicYearCreated(ctx, payload)
	case "academic_year.updated":
		return c.handleAcademicYearUpdated(ctx, payload)
	case "academic_year.deleted":
		return c.handleAcademicYearDeleted(ctx, payload)
	case "academic_year.set_current":
		return c.handleAcademicYearSetCurrent(ctx, payload)
	case "notification.created":
		return c.handleNotificationCreated(ctx, payload)
	case "notification.updated":
		return c.handleNotificationUpdated(ctx, payload)
	case "notification.deleted":
		return c.handleNotificationDeleted(ctx, payload)
	case "notification.read":
		return c.handleNotificationRead(ctx, payload)
	case "notification.all_read":
		return c.handleNotificationAllRead(ctx, payload)
	case "teacher.created":
		return c.handleTeacherCreated(ctx, payload)
	case "teacher.updated":
		return c.handleTeacherUpdated(ctx, payload)
	case "teacher.deleted":
		return c.handleTeacherDeleted(ctx, payload)
	case "teacher.status_updated":
		return c.handleTeacherStatusUpdated(ctx, payload)
	case "teacher.subject_assigned":
		return c.handleTeacherSubjectAssigned(ctx, payload)
	case "teacher.subject_removed":
		return c.handleTeacherSubjectRemoved(ctx, payload)
	case "teacher.subject_updated":
		return c.handleTeacherSubjectUpdated(ctx, payload)
	case "teacher.section_assigned":
		return c.handleTeacherSectionAssigned(ctx, payload)
	case "teacher.section_removed":
		return c.handleTeacherSectionRemoved(ctx, payload)
	case "teacher.class_teacher_updated":
		return c.handleTeacherClassTeacherUpdated(ctx, payload)
	case "teacher.schedule_preference_set":
		return c.handleTeacherSchedulePreferenceSet(ctx, payload)
	case "teacher.schedule_preference_updated":
		return c.handleTeacherSchedulePreferenceUpdated(ctx, payload)
	case "teacher.schedule_preference_deleted":
		return c.handleTeacherSchedulePreferenceDeleted(ctx, payload)
	case "teacher.schedule_preferences_cleared":
		return c.handleTeacherSchedulePreferencesCleared(ctx, payload)
	case "teacher.bulk_status_updated":
		return c.handleTeacherBulkStatusUpdated(ctx, payload)
	case "room.created":
		return c.handleRoomCreated(ctx, payload)
	case "room.updated":
		return c.handleRoomUpdated(ctx, payload)
	case "room.deleted":
		return c.handleRoomDeleted(ctx, payload)
	case "room.activated":
		return c.handleRoomActivated(ctx, payload)
	case "room.deactivated":
		return c.handleRoomDeactivated(ctx, payload)
	case "course.created":
		return c.handleCourseCreated(ctx, payload)
	case "course.updated":
		return c.handleCourseUpdated(ctx, payload)
	case "course.deleted":
		return c.handleCourseDeleted(ctx, payload)
	case "guardian.created":
		return c.handleGuardianCreated(ctx, payload)
	case "guardian.updated":
		return c.handleGuardianUpdated(ctx, payload)
	case "guardian.deleted":
		return c.handleGuardianDeleted(ctx, payload)
	case "guardian.primary_set":
		return c.handleGuardianPrimarySet(ctx, payload)
	case "admission.created":
		return c.handleAdmissionCreated(ctx, payload)
	case "admission.updated":
		return c.handleAdmissionUpdated(ctx, payload)
	case "admission.status_updated":
		return c.handleAdmissionStatusUpdated(ctx, payload)
	case "admission.deleted":
		return c.handleAdmissionDeleted(ctx, payload)
	case "assignment.created":
		return c.handleAssignmentCreated(ctx, payload)
	case "assignment.updated":
		return c.handleAssignmentUpdated(ctx, payload)
	case "assignment.deleted":
		return c.handleAssignmentDeleted(ctx, payload)
	case "assignment.published":
		return c.handleAssignmentPublished(ctx, payload)
	case "submission.created":
		return c.handleSubmissionCreated(ctx, payload)
	case "submission.updated":
		return c.handleSubmissionUpdated(ctx, payload)
	case "submission.deleted":
		return c.handleSubmissionDeleted(ctx, payload)
	case "submission.graded":
		return c.handleSubmissionGraded(ctx, payload)
	case "submission.comment_added":
		return c.handleSubmissionCommentAdded(ctx, payload)
	case "attendance.marked":
		return c.handleAttendanceMarked(ctx, payload)
	case "attendance.bulk_marked":
		return c.handleAttendanceBulkMarked(ctx, payload)
	case "attendance.summary_updated":
		return c.handleAttendanceSummaryUpdated(ctx, payload)
	case "attendance.exemption_created":
		return c.handleAttendanceExemptionCreated(ctx, payload)
	case "attendance.exemption_updated":
		return c.handleAttendanceExemptionUpdated(ctx, payload)
	case "attendance.exemption_deleted":
		return c.handleAttendanceExemptionDeleted(ctx, payload)
	case "exam.created":
		return c.handleExamCreated(ctx, payload)
	case "exam.updated":
		return c.handleExamUpdated(ctx, payload)
	case "exam.deleted":
		return c.handleExamDeleted(ctx, payload)
	case "exam_schedule.created":
		return c.handleExamScheduleCreated(ctx, payload)
	case "exam_schedule.updated":
		return c.handleExamScheduleUpdated(ctx, payload)
	case "exam_schedule.deleted":
		return c.handleExamScheduleDeleted(ctx, payload)
	case "exam_result.created":
		return c.handleExamResultCreated(ctx, payload)
	case "exam_result.updated":
		return c.handleExamResultUpdated(ctx, payload)
	case "exam_result.deleted":
		return c.handleExamResultDeleted(ctx, payload)
	case "exam_grade.created":
		return c.handleExamGradeCreated(ctx, payload)
	case "exam_grade.updated":
		return c.handleExamGradeUpdated(ctx, payload)
	case "exam_grade.deleted":
		return c.handleExamGradeDeleted(ctx, payload)
	case "grading_policy.created":
		return c.handleGradingPolicyCreated(ctx, payload)
	case "grading_policy.updated":
		return c.handleGradingPolicyUpdated(ctx, payload)
	case "grading_policy.deleted":
		return c.handleGradingPolicyDeleted(ctx, payload)
	case "grade_boundary.created":
		return c.handleGradeBoundaryCreated(ctx, payload)
	case "grade_boundary.updated":
		return c.handleGradeBoundaryUpdated(ctx, payload)
	case "grade_boundary.deleted":
		return c.handleGradeBoundaryDeleted(ctx, payload)
	case "fee_structure.created":
		return c.handleFeeStructureCreated(ctx, payload)
	case "fee_structure.updated":
		return c.handleFeeStructureUpdated(ctx, payload)
	case "fee_structure.deleted":
		return c.handleFeeStructureDeleted(ctx, payload)
	case "fee_invoice.created":
		return c.handleFeeInvoiceCreated(ctx, payload)
	case "fee_invoice.updated":
		return c.handleFeeInvoiceUpdated(ctx, payload)
	case "fee_payment.created":
		return c.handleFeePaymentCreated(ctx, payload)
	case "fee_payment.updated":
		return c.handleFeePaymentUpdated(ctx, payload)
	case "fee_discount.created":
		return c.handleFeeDiscountCreated(ctx, payload)
	case "fee_discount.updated":
		return c.handleFeeDiscountUpdated(ctx, payload)
	case "fee_penalty.created":
		return c.handleFeePenaltyCreated(ctx, payload)
	case "fee_receipt.generated":
		return c.handleFeeReceiptGenerated(ctx, payload)
	case "library_category.created":
		return c.handleLibraryCategoryCreated(ctx, payload)
	case "library_category.updated":
		return c.handleLibraryCategoryUpdated(ctx, payload)
	case "library_category.deleted":
		return c.handleLibraryCategoryDeleted(ctx, payload)
	case "library_book.created":
		return c.handleLibraryBookCreated(ctx, payload)
	case "library_book.updated":
		return c.handleLibraryBookUpdated(ctx, payload)
	case "library_book.deleted":
		return c.handleLibraryBookDeleted(ctx, payload)
	case "library_copy.created":
		return c.handleLibraryCopyCreated(ctx, payload)
	case "library_copy.updated":
		return c.handleLibraryCopyUpdated(ctx, payload)
	case "library_copy.deleted":
		return c.handleLibraryCopyDeleted(ctx, payload)
	case "library_book.issued":
		return c.handleLibraryBookIssued(ctx, payload)
	case "library_book.returned":
		return c.handleLibraryBookReturned(ctx, payload)
	case "library_fine.paid":
		return c.handleLibraryFinePaid(ctx, payload)
	case "transport.route.created":
		return c.handleTransportRouteCreated(ctx, payload)
	case "transport.route.updated":
		return c.handleTransportRouteUpdated(ctx, payload)
	case "transport.route.deleted":
		return c.handleTransportRouteDeleted(ctx, payload)
	case "transport.stop.created":
		return c.handleTransportStopCreated(ctx, payload)
	case "transport.stop.updated":
		return c.handleTransportStopUpdated(ctx, payload)
	case "transport.stop.deleted":
		return c.handleTransportStopDeleted(ctx, payload)
	case "transport.vehicle.created":
		return c.handleTransportVehicleCreated(ctx, payload)
	case "transport.vehicle.updated":
		return c.handleTransportVehicleUpdated(ctx, payload)
	case "transport.vehicle.deleted":
		return c.handleTransportVehicleDeleted(ctx, payload)
	case "transport.driver_assignment.created":
		return c.handleTransportDriverAssignmentCreated(ctx, payload)
	case "transport.driver_assignment.updated":
		return c.handleTransportDriverAssignmentUpdated(ctx, payload)
	case "transport.driver_assignment.deleted":
		return c.handleTransportDriverAssignmentDeleted(ctx, payload)
	case "transport.student_assignment.created":
		return c.handleTransportStudentAssignmentCreated(ctx, payload)
	case "transport.student_assignment.updated":
		return c.handleTransportStudentAssignmentUpdated(ctx, payload)
	case "transport.student_assignment.deleted":
		return c.handleTransportStudentAssignmentDeleted(ctx, payload)
	case "section.created":
		return c.handleSectionCreated(ctx, payload)
	case "section.updated":
		return c.handleSectionUpdated(ctx, payload)
	case "section.deleted":
		return c.handleSectionDeleted(ctx, payload)
	case "subject.created":
		return c.handleSubjectCreated(ctx, payload)
	case "subject.updated":
		return c.handleSubjectUpdated(ctx, payload)
	case "subject.deleted":
		return c.handleSubjectDeleted(ctx, payload)
	case "subject.assigned":
		return c.handleSubjectAssigned(ctx, payload)
	case "subject.unassigned":
		return c.handleSubjectUnassigned(ctx, payload)
	case "enrollment.created":
		return c.handleEnrollmentCreated(ctx, payload)
	case "enrollment.updated":
		return c.handleEnrollmentUpdated(ctx, payload)
	case "enrollment.deleted":
		return c.handleEnrollmentDeleted(ctx, payload)
	case "enrollment.activated":
		return c.handleEnrollmentActivated(ctx, payload)
	case "enrollment.completed":
		return c.handleEnrollmentCompleted(ctx, payload)
	case "enrollment.withdrawn":
		return c.handleEnrollmentWithdrawn(ctx, payload)
	case "enrollment.transferred":
		return c.handleEnrollmentTransferred(ctx, payload)
	case "enrollment.promoted":
		return c.handleEnrollmentPromoted(ctx, payload)
	// Ignored events
	case "term.created", "term.updated", "term.deleted", "term.set_current":
		return nil
	default:
		c.logger.Warn("unknown event type", zap.String("event_type", eventType))
		return nil
	}
}

// ---------- Student Event Handlers ----------
func (c *StudentConsumer) handleStudentCreated(ctx context.Context, payload []byte) error {
	var student models.Student
	if err := json.Unmarshal(payload, &student); err != nil {
		return err
	}
	c.logger.Info("student created event",
		zap.String("student_id", student.StudentID.String()),
		zap.String("name", student.FirstName+" "+student.LastName),
	)
	return nil
}

func (c *StudentConsumer) handleStudentUpdated(ctx context.Context, payload []byte) error {
	var data map[string]interface{}
	if err := json.Unmarshal(payload, &data); err != nil {
		return err
	}
	c.logger.Info("student updated event")
	return nil
}

func (c *StudentConsumer) handleStudentDeleted(ctx context.Context, payload []byte) error {
	var data map[string]interface{}
	if err := json.Unmarshal(payload, &data); err != nil {
		return err
	}
	c.logger.Info("student deleted event")
	return nil
}

func (c *StudentConsumer) handleStudentPromoted(ctx context.Context, payload []byte) error {
	var data map[string]interface{}
	if err := json.Unmarshal(payload, &data); err != nil {
		return err
	}
	c.logger.Info("student promoted event")
	return nil
}

func (c *StudentConsumer) handleStudentBulkPromoted(ctx context.Context, payload []byte) error {
	var data map[string]interface{}
	if err := json.Unmarshal(payload, &data); err != nil {
		return err
	}
	c.logger.Info("student bulk promoted event")
	return nil
}

func (c *StudentConsumer) handleStudentGraduated(ctx context.Context, payload []byte) error {
	var data map[string]interface{}
	if err := json.Unmarshal(payload, &data); err != nil {
		return err
	}
	c.logger.Info("student graduated event")
	return nil
}

func (c *StudentConsumer) handleStudentDroppedOut(ctx context.Context, payload []byte) error {
	var data map[string]interface{}
	if err := json.Unmarshal(payload, &data); err != nil {
		return err
	}
	c.logger.Info("student dropped out event")
	return nil
}

func (c *StudentConsumer) handleStudentActivated(ctx context.Context, payload []byte) error {
	var data map[string]interface{}
	if err := json.Unmarshal(payload, &data); err != nil {
		return err
	}
	c.logger.Info("student activated event")
	return nil
}

func (c *StudentConsumer) handleStudentDeactivated(ctx context.Context, payload []byte) error {
	var data map[string]interface{}
	if err := json.Unmarshal(payload, &data); err != nil {
		return err
	}
	c.logger.Info("student deactivated event")
	return nil
}

func (c *StudentConsumer) handleStudentBulkStatusUpdated(ctx context.Context, payload []byte) error {
	var data map[string]interface{}
	if err := json.Unmarshal(payload, &data); err != nil {
		return err
	}
	c.logger.Info("student bulk status updated event")
	return nil
}

// ---------- Academic Year Event Handlers ----------
func (c *StudentConsumer) handleAcademicYearCreated(ctx context.Context, payload []byte) error {
	var ay models.AcademicYear
	if err := json.Unmarshal(payload, &ay); err != nil {
		return err
	}
	c.logger.Info("academic year created event",
		zap.String("id", ay.AcademicYearID.String()),
		zap.String("company_id", ay.CompanyID.String()),
		zap.String("name", ay.Name),
	)
	return nil
}

func (c *StudentConsumer) handleAcademicYearUpdated(ctx context.Context, payload []byte) error {
	var ay models.AcademicYear
	if err := json.Unmarshal(payload, &ay); err != nil {
		return err
	}
	c.logger.Info("academic year updated event",
		zap.String("id", ay.AcademicYearID.String()),
	)
	return nil
}

func (c *StudentConsumer) handleAcademicYearDeleted(ctx context.Context, payload []byte) error {
	var ay models.AcademicYear
	if err := json.Unmarshal(payload, &ay); err != nil {
		return err
	}
	c.logger.Info("academic year deleted event",
		zap.String("id", ay.AcademicYearID.String()),
	)
	return nil
}

func (c *StudentConsumer) handleAcademicYearSetCurrent(ctx context.Context, payload []byte) error {
	var ay models.AcademicYear
	if err := json.Unmarshal(payload, &ay); err != nil {
		return err
	}
	c.logger.Info("academic year set as current event",
		zap.String("id", ay.AcademicYearID.String()),
		zap.String("company_id", ay.CompanyID.String()),
	)
	return nil
}

// ---------- Notification Event Handlers ----------
type NotificationEvent struct {
	NotificationID uuid.UUID `json:"notification_id"`
	Title          string    `json:"title"`
	Message        string    `json:"message"`
	Type           string    `json:"type"`
	Priority       string    `json:"priority"`
	CompanyID      uuid.UUID `json:"company_id"`
	Targets        []struct {
		TargetType string    `json:"target_type"`
		EntityID   uuid.UUID `json:"entity_id"`
	} `json:"targets"`
	CreatedAt time.Time `json:"created_at"`
}

func (c *StudentConsumer) handleNotificationCreated(ctx context.Context, payload []byte) error {
	var event NotificationEvent
	if err := json.Unmarshal(payload, &event); err != nil {
		return err
	}
	c.logger.Info("notification created event",
		zap.String("notification_id", event.NotificationID.String()),
		zap.String("title", event.Title),
		zap.String("type", event.Type),
		zap.String("priority", event.Priority),
	)
	return nil
}

func (c *StudentConsumer) handleNotificationUpdated(ctx context.Context, payload []byte) error {
	var event NotificationEvent
	if err := json.Unmarshal(payload, &event); err != nil {
		return err
	}
	c.logger.Info("notification updated event",
		zap.String("notification_id", event.NotificationID.String()),
	)
	return nil
}

func (c *StudentConsumer) handleNotificationDeleted(ctx context.Context, payload []byte) error {
	var data map[string]interface{}
	if err := json.Unmarshal(payload, &data); err != nil {
		return err
	}
	c.logger.Info("notification deleted event")
	return nil
}

func (c *StudentConsumer) handleNotificationRead(ctx context.Context, payload []byte) error {
	var data map[string]interface{}
	if err := json.Unmarshal(payload, &data); err != nil {
		return err
	}
	c.logger.Info("notification read event")
	return nil
}

func (c *StudentConsumer) handleNotificationAllRead(ctx context.Context, payload []byte) error {
	var data map[string]interface{}
	if err := json.Unmarshal(payload, &data); err != nil {
		return err
	}
	c.logger.Info("notification all read event")
	return nil
}

// ---------- Teacher Event Handlers ----------
func (c *StudentConsumer) handleTeacherCreated(ctx context.Context, payload []byte) error {
	var teacher models.Teacher
	if err := json.Unmarshal(payload, &teacher); err != nil {
		return err
	}
	c.logger.Info("teacher created event",
		zap.String("teacher_id", teacher.TeacherID.String()),
		zap.String("employee_code", teacher.EmployeeCode),
	)
	return nil
}

func (c *StudentConsumer) handleTeacherUpdated(ctx context.Context, payload []byte) error {
	var teacher models.Teacher
	if err := json.Unmarshal(payload, &teacher); err != nil {
		return err
	}
	c.logger.Info("teacher updated event",
		zap.String("teacher_id", teacher.TeacherID.String()),
	)
	return nil
}

func (c *StudentConsumer) handleTeacherDeleted(ctx context.Context, payload []byte) error {
	var data map[string]interface{}
	if err := json.Unmarshal(payload, &data); err != nil {
		return err
	}
	c.logger.Info("teacher deleted event")
	return nil
}

func (c *StudentConsumer) handleTeacherStatusUpdated(ctx context.Context, payload []byte) error {
	var data map[string]interface{}
	if err := json.Unmarshal(payload, &data); err != nil {
		return err
	}
	c.logger.Info("teacher status updated event")
	return nil
}

func (c *StudentConsumer) handleTeacherSubjectAssigned(ctx context.Context, payload []byte) error {
	var data map[string]interface{}
	if err := json.Unmarshal(payload, &data); err != nil {
		return err
	}
	c.logger.Info("teacher subject assigned event")
	return nil
}

func (c *StudentConsumer) handleTeacherSubjectRemoved(ctx context.Context, payload []byte) error {
	var data map[string]interface{}
	if err := json.Unmarshal(payload, &data); err != nil {
		return err
	}
	c.logger.Info("teacher subject removed event")
	return nil
}

func (c *StudentConsumer) handleTeacherSubjectUpdated(ctx context.Context, payload []byte) error {
	var data map[string]interface{}
	if err := json.Unmarshal(payload, &data); err != nil {
		return err
	}
	c.logger.Info("teacher subject updated event")
	return nil
}

func (c *StudentConsumer) handleTeacherSectionAssigned(ctx context.Context, payload []byte) error {
	var data map[string]interface{}
	if err := json.Unmarshal(payload, &data); err != nil {
		return err
	}
	c.logger.Info("teacher section assigned event")
	return nil
}

func (c *StudentConsumer) handleTeacherSectionRemoved(ctx context.Context, payload []byte) error {
	var data map[string]interface{}
	if err := json.Unmarshal(payload, &data); err != nil {
		return err
	}
	c.logger.Info("teacher section removed event")
	return nil
}

func (c *StudentConsumer) handleTeacherClassTeacherUpdated(ctx context.Context, payload []byte) error {
	var data map[string]interface{}
	if err := json.Unmarshal(payload, &data); err != nil {
		return err
	}
	c.logger.Info("teacher class teacher updated event")
	return nil
}

func (c *StudentConsumer) handleTeacherSchedulePreferenceSet(ctx context.Context, payload []byte) error {
	var pref models.TeacherSchedulePreference
	if err := json.Unmarshal(payload, &pref); err != nil {
		return err
	}
	c.logger.Info("teacher schedule preference set event",
		zap.String("teacher_id", pref.TeacherID.String()),
		zap.Int("day_of_week", pref.DayOfWeek),
	)
	return nil
}

func (c *StudentConsumer) handleTeacherSchedulePreferenceUpdated(ctx context.Context, payload []byte) error {
	var pref models.TeacherSchedulePreference
	if err := json.Unmarshal(payload, &pref); err != nil {
		return err
	}
	c.logger.Info("teacher schedule preference updated event",
		zap.String("preference_id", pref.PreferenceID.String()),
	)
	return nil
}

func (c *StudentConsumer) handleTeacherSchedulePreferenceDeleted(ctx context.Context, payload []byte) error {
	var data map[string]interface{}
	if err := json.Unmarshal(payload, &data); err != nil {
		return err
	}
	c.logger.Info("teacher schedule preference deleted event")
	return nil
}

func (c *StudentConsumer) handleTeacherSchedulePreferencesCleared(ctx context.Context, payload []byte) error {
	var data map[string]interface{}
	if err := json.Unmarshal(payload, &data); err != nil {
		return err
	}
	c.logger.Info("teacher schedule preferences cleared event")
	return nil
}

func (c *StudentConsumer) handleTeacherBulkStatusUpdated(ctx context.Context, payload []byte) error {
	var data map[string]interface{}
	if err := json.Unmarshal(payload, &data); err != nil {
		return err
	}
	c.logger.Info("teacher bulk status updated event")
	return nil
}

// ---------- Room Event Handlers ----------
func (c *StudentConsumer) handleRoomCreated(ctx context.Context, payload []byte) error {
	var room models.Room
	if err := json.Unmarshal(payload, &room); err != nil {
		return err
	}
	c.logger.Info("room created event",
		zap.String("room_id", room.RoomID.String()),
		zap.String("room_code", room.RoomCode),
		zap.String("building", room.Building),
	)
	return nil
}

func (c *StudentConsumer) handleRoomUpdated(ctx context.Context, payload []byte) error {
	var room models.Room
	if err := json.Unmarshal(payload, &room); err != nil {
		return err
	}
	c.logger.Info("room updated event",
		zap.String("room_id", room.RoomID.String()),
		zap.String("room_code", room.RoomCode),
	)
	return nil
}

func (c *StudentConsumer) handleRoomDeleted(ctx context.Context, payload []byte) error {
	var data map[string]interface{}
	if err := json.Unmarshal(payload, &data); err != nil {
		return err
	}
	c.logger.Info("room deleted event")
	return nil
}

func (c *StudentConsumer) handleRoomActivated(ctx context.Context, payload []byte) error {
	var data map[string]interface{}
	if err := json.Unmarshal(payload, &data); err != nil {
		return err
	}
	c.logger.Info("room activated event")
	return nil
}

func (c *StudentConsumer) handleRoomDeactivated(ctx context.Context, payload []byte) error {
	var data map[string]interface{}
	if err := json.Unmarshal(payload, &data); err != nil {
		return err
	}
	c.logger.Info("room deactivated event")
	return nil
}

// ---------- Course Event Handlers ----------
func (c *StudentConsumer) handleCourseCreated(ctx context.Context, payload []byte) error {
	var course models.Course
	if err := json.Unmarshal(payload, &course); err != nil {
		return err
	}
	c.logger.Info("course created event",
		zap.String("course_id", course.CourseID.String()),
		zap.String("company_id", course.CompanyID.String()),
		zap.String("code", course.Code),
		zap.String("name", course.Name),
	)
	return nil
}

func (c *StudentConsumer) handleCourseUpdated(ctx context.Context, payload []byte) error {
	var course models.Course
	if err := json.Unmarshal(payload, &course); err != nil {
		return err
	}
	c.logger.Info("course updated event",
		zap.String("course_id", course.CourseID.String()),
		zap.String("code", course.Code),
		zap.String("name", course.Name),
		zap.Bool("is_active", course.IsActive),
	)
	return nil
}

func (c *StudentConsumer) handleCourseDeleted(ctx context.Context, payload []byte) error {
	var data map[string]interface{}
	if err := json.Unmarshal(payload, &data); err != nil {
		return err
	}
	c.logger.Info("course deleted event", zap.Any("data", data))
	return nil
}

// ---------- Guardian Event Handlers ----------
func (c *StudentConsumer) handleGuardianCreated(ctx context.Context, payload []byte) error {
	var guardian models.Guardian
	if err := json.Unmarshal(payload, &guardian); err != nil {
		return err
	}
	c.logger.Info("guardian created event",
		zap.String("guardian_id", guardian.GuardianID.String()),
		zap.String("student_id", guardian.StudentID.String()),
		zap.String("guardian_name", guardian.GuardianName),
		zap.String("relation", guardian.Relation),
	)
	return nil
}

func (c *StudentConsumer) handleGuardianUpdated(ctx context.Context, payload []byte) error {
	var guardian models.Guardian
	if err := json.Unmarshal(payload, &guardian); err != nil {
		return err
	}
	c.logger.Info("guardian updated event",
		zap.String("guardian_id", guardian.GuardianID.String()),
		zap.String("student_id", guardian.StudentID.String()),
	)
	return nil
}

func (c *StudentConsumer) handleGuardianDeleted(ctx context.Context, payload []byte) error {
	var data map[string]interface{}
	if err := json.Unmarshal(payload, &data); err != nil {
		return err
	}
	c.logger.Info("guardian deleted event",
		zap.Any("data", data),
	)
	return nil
}

func (c *StudentConsumer) handleGuardianPrimarySet(ctx context.Context, payload []byte) error {
	var data struct {
		StudentID  uuid.UUID  `json:"student_id"`
		GuardianID uuid.UUID  `json:"guardian_id"`
		UpdatedBy  *uuid.UUID `json:"updated_by"`
	}
	if err := json.Unmarshal(payload, &data); err != nil {
		return err
	}
	c.logger.Info("guardian primary set event",
		zap.String("student_id", data.StudentID.String()),
		zap.String("guardian_id", data.GuardianID.String()),
	)
	return nil
}

// ---------- Admission Event Handlers ----------
func (c *StudentConsumer) handleAdmissionCreated(ctx context.Context, payload []byte) error {
	var admission models.Admission
	if err := json.Unmarshal(payload, &admission); err != nil {
		return err
	}
	c.logger.Info("admission created event",
		zap.String("admission_id", admission.AdmissionID.String()),
		zap.String("student_id", admission.StudentID.String()),
		zap.String("academic_year_id", admission.AcademicYearID.String()),
		zap.String("status", string(admission.AdmissionStatus)),
	)
	return nil
}

func (c *StudentConsumer) handleAdmissionUpdated(ctx context.Context, payload []byte) error {
	var admission models.Admission
	if err := json.Unmarshal(payload, &admission); err != nil {
		return err
	}
	c.logger.Info("admission updated event",
		zap.String("admission_id", admission.AdmissionID.String()),
		zap.String("student_id", admission.StudentID.String()),
	)
	return nil
}

func (c *StudentConsumer) handleAdmissionStatusUpdated(ctx context.Context, payload []byte) error {
	var admission models.Admission
	if err := json.Unmarshal(payload, &admission); err != nil {
		return err
	}
	c.logger.Info("admission status updated event",
		zap.String("admission_id", admission.AdmissionID.String()),
		zap.String("new_status", string(admission.AdmissionStatus)),
	)
	return nil
}

func (c *StudentConsumer) handleAdmissionDeleted(ctx context.Context, payload []byte) error {
	var admission models.Admission
	if err := json.Unmarshal(payload, &admission); err != nil {
		return err
	}
	c.logger.Info("admission deleted event",
		zap.String("admission_id", admission.AdmissionID.String()),
		zap.String("student_id", admission.StudentID.String()),
	)
	return nil
}

// ---------- Assignment Event Handlers ----------
func (c *StudentConsumer) handleAssignmentCreated(ctx context.Context, payload []byte) error {
	var assignment models.Assignment
	if err := json.Unmarshal(payload, &assignment); err != nil {
		return err
	}
	c.logger.Info("assignment created event",
		zap.String("assignment_id", assignment.AssignmentID.String()),
		zap.String("title", assignment.Title),
		zap.String("section_id", assignment.SectionID.String()),
		zap.String("subject_id", assignment.SubjectID.String()),
		zap.String("teacher_id", assignment.TeacherID.String()),
	)
	return nil
}

func (c *StudentConsumer) handleAssignmentUpdated(ctx context.Context, payload []byte) error {
	var assignment models.Assignment
	if err := json.Unmarshal(payload, &assignment); err != nil {
		return err
	}
	c.logger.Info("assignment updated event",
		zap.String("assignment_id", assignment.AssignmentID.String()),
		zap.String("title", assignment.Title),
	)
	return nil
}

func (c *StudentConsumer) handleAssignmentDeleted(ctx context.Context, payload []byte) error {
	var data map[string]interface{}
	if err := json.Unmarshal(payload, &data); err != nil {
		return err
	}
	c.logger.Info("assignment deleted event",
		zap.Any("data", data),
	)
	return nil
}

func (c *StudentConsumer) handleAssignmentPublished(ctx context.Context, payload []byte) error {
	var data map[string]interface{}
	if err := json.Unmarshal(payload, &data); err != nil {
		return err
	}
	c.logger.Info("assignment published event",
		zap.Any("data", data),
	)
	return nil
}

// ---------- Submission Event Handlers ----------
type SubmissionEvent struct {
	SubmissionID uuid.UUID  `json:"submission_id"`
	AssignmentID uuid.UUID  `json:"assignment_id"`
	StudentID    uuid.UUID  `json:"student_id"`
	Status       string     `json:"status"`
	SubmittedAt  time.Time  `json:"submitted_at,omitempty"`
	Marks        *float64   `json:"marks,omitempty"`
	Feedback     string     `json:"feedback,omitempty"`
	GradedBy     *uuid.UUID `json:"graded_by,omitempty"`
	CommentID    uuid.UUID  `json:"comment_id,omitempty"`
	Comment      string     `json:"comment,omitempty"`
	CommentBy    *uuid.UUID `json:"comment_by,omitempty"`
	DeletedBy    *uuid.UUID `json:"deleted_by,omitempty"`
}

func (c *StudentConsumer) handleSubmissionCreated(ctx context.Context, payload []byte) error {
	var event SubmissionEvent
	if err := json.Unmarshal(payload, &event); err != nil {
		return err
	}
	c.logger.Info("submission created event",
		zap.String("submission_id", event.SubmissionID.String()),
		zap.String("assignment_id", event.AssignmentID.String()),
		zap.String("student_id", event.StudentID.String()),
		zap.String("status", event.Status),
	)
	return nil
}

func (c *StudentConsumer) handleSubmissionUpdated(ctx context.Context, payload []byte) error {
	var event SubmissionEvent
	if err := json.Unmarshal(payload, &event); err != nil {
		return err
	}
	c.logger.Info("submission updated event",
		zap.String("submission_id", event.SubmissionID.String()),
		zap.String("status", event.Status),
	)
	return nil
}

func (c *StudentConsumer) handleSubmissionDeleted(ctx context.Context, payload []byte) error {
	var event SubmissionEvent
	if err := json.Unmarshal(payload, &event); err != nil {
		return err
	}
	c.logger.Info("submission deleted event",
		zap.String("submission_id", event.SubmissionID.String()),
	)
	return nil
}

func (c *StudentConsumer) handleSubmissionGraded(ctx context.Context, payload []byte) error {
	var event SubmissionEvent
	if err := json.Unmarshal(payload, &event); err != nil {
		return err
	}
	var marks float64
	if event.Marks != nil {
		marks = *event.Marks
	}
	c.logger.Info("submission graded event",
		zap.String("submission_id", event.SubmissionID.String()),
		zap.Float64("marks", marks),
	)
	return nil
}

func (c *StudentConsumer) handleSubmissionCommentAdded(ctx context.Context, payload []byte) error {
	var event SubmissionEvent
	if err := json.Unmarshal(payload, &event); err != nil {
		return err
	}
	c.logger.Info("submission comment added event",
		zap.String("submission_id", event.SubmissionID.String()),
		zap.String("comment_id", event.CommentID.String()),
		zap.String("comment", event.Comment),
	)
	return nil
}

// ---------- Attendance Event Handlers ----------
type AttendanceEvent struct {
	AttendanceID   uuid.UUID  `json:"attendance_id,omitempty"`
	EnrollmentID   uuid.UUID  `json:"enrollment_id"`
	AttendanceDate time.Time  `json:"attendance_date"`
	Status         string     `json:"status"`
	Remarks        string     `json:"remarks,omitempty"`
	MarkedBy       *uuid.UUID `json:"marked_by,omitempty"`
	CreatedBy      *uuid.UUID `json:"created_by,omitempty"`
	StudentID      uuid.UUID  `json:"student_id,omitempty"`
	AcademicYearID uuid.UUID  `json:"academic_year_id,omitempty"`
	TermID         *uuid.UUID `json:"term_id,omitempty"`
	ExemptionID    uuid.UUID  `json:"exemption_id,omitempty"`
	FromDate       time.Time  `json:"from_date,omitempty"`
	ToDate         time.Time  `json:"to_date,omitempty"`
	Reason         string     `json:"reason,omitempty"`
	ApprovedBy     *uuid.UUID `json:"approved_by,omitempty"`
}

func (c *StudentConsumer) handleAttendanceMarked(ctx context.Context, payload []byte) error {
	var event AttendanceEvent
	if err := json.Unmarshal(payload, &event); err != nil {
		return err
	}
	c.logger.Info("attendance marked event",
		zap.String("attendance_id", event.AttendanceID.String()),
		zap.String("enrollment_id", event.EnrollmentID.String()),
		zap.Time("date", event.AttendanceDate),
		zap.String("status", event.Status),
	)
	return nil
}

func (c *StudentConsumer) handleAttendanceBulkMarked(ctx context.Context, payload []byte) error {
	var data map[string]interface{}
	if err := json.Unmarshal(payload, &data); err != nil {
		return err
	}
	c.logger.Info("attendance bulk marked event", zap.Any("data", data))
	return nil
}

func (c *StudentConsumer) handleAttendanceSummaryUpdated(ctx context.Context, payload []byte) error {
	var event AttendanceEvent
	if err := json.Unmarshal(payload, &event); err != nil {
		return err
	}
	c.logger.Info("attendance summary updated event",
		zap.String("student_id", event.StudentID.String()),
		zap.String("academic_year_id", event.AcademicYearID.String()),
	)
	return nil
}

func (c *StudentConsumer) handleAttendanceExemptionCreated(ctx context.Context, payload []byte) error {
	var event AttendanceEvent
	if err := json.Unmarshal(payload, &event); err != nil {
		return err
	}
	c.logger.Info("attendance exemption created event",
		zap.String("exemption_id", event.ExemptionID.String()),
		zap.String("student_id", event.StudentID.String()),
		zap.Time("from_date", event.FromDate),
		zap.Time("to_date", event.ToDate),
	)
	return nil
}

func (c *StudentConsumer) handleAttendanceExemptionUpdated(ctx context.Context, payload []byte) error {
	var event AttendanceEvent
	if err := json.Unmarshal(payload, &event); err != nil {
		return err
	}
	c.logger.Info("attendance exemption updated event",
		zap.String("exemption_id", event.ExemptionID.String()),
	)
	return nil
}

func (c *StudentConsumer) handleAttendanceExemptionDeleted(ctx context.Context, payload []byte) error {
	var event AttendanceEvent
	if err := json.Unmarshal(payload, &event); err != nil {
		return err
	}
	c.logger.Info("attendance exemption deleted event",
		zap.String("exemption_id", event.ExemptionID.String()),
	)
	return nil
}

// ---------- Exam Event Handlers ----------
func (c *StudentConsumer) handleExamCreated(ctx context.Context, payload []byte) error {
	var exam models.Exam
	if err := json.Unmarshal(payload, &exam); err != nil {
		return err
	}
	c.logger.Info("exam created event",
		zap.String("exam_id", exam.ExamID.String()),
		zap.String("exam_name", exam.ExamName),
		zap.String("academic_year_id", exam.AcademicYearID.String()),
		zap.String("term_id", exam.TermID.String()),
	)
	return nil
}

func (c *StudentConsumer) handleExamUpdated(ctx context.Context, payload []byte) error {
	var data map[string]interface{}
	if err := json.Unmarshal(payload, &data); err != nil {
		return err
	}
	c.logger.Info("exam updated event", zap.Any("data", data))
	return nil
}

func (c *StudentConsumer) handleExamDeleted(ctx context.Context, payload []byte) error {
	var data map[string]interface{}
	if err := json.Unmarshal(payload, &data); err != nil {
		return err
	}
	c.logger.Info("exam deleted event", zap.Any("data", data))
	return nil
}

func (c *StudentConsumer) handleExamScheduleCreated(ctx context.Context, payload []byte) error {
	var schedule models.ExamSchedule
	if err := json.Unmarshal(payload, &schedule); err != nil {
		return err
	}
	c.logger.Info("exam schedule created event",
		zap.String("schedule_id", schedule.ScheduleID.String()),
		zap.String("exam_id", schedule.ExamID.String()),
		zap.String("subject_id", schedule.SubjectID.String()),
		zap.Time("date", schedule.Date),
	)
	return nil
}

func (c *StudentConsumer) handleExamScheduleUpdated(ctx context.Context, payload []byte) error {
	var data map[string]interface{}
	if err := json.Unmarshal(payload, &data); err != nil {
		return err
	}
	c.logger.Info("exam schedule updated event", zap.Any("data", data))
	return nil
}

func (c *StudentConsumer) handleExamScheduleDeleted(ctx context.Context, payload []byte) error {
	var data map[string]interface{}
	if err := json.Unmarshal(payload, &data); err != nil {
		return err
	}
	c.logger.Info("exam schedule deleted event", zap.Any("data", data))
	return nil
}

func (c *StudentConsumer) handleExamResultCreated(ctx context.Context, payload []byte) error {
	var result models.ExamResult
	if err := json.Unmarshal(payload, &result); err != nil {
		return err
	}
	c.logger.Info("exam result created event",
		zap.String("result_id", result.ResultID.String()),
		zap.String("exam_id", result.ExamID.String()),
		zap.String("enrollment_id", result.EnrollmentID.String()),
		zap.String("subject_id", result.SubjectID.String()),
	)
	return nil
}

func (c *StudentConsumer) handleExamResultUpdated(ctx context.Context, payload []byte) error {
	var data map[string]interface{}
	if err := json.Unmarshal(payload, &data); err != nil {
		return err
	}
	c.logger.Info("exam result updated event", zap.Any("data", data))
	return nil
}

func (c *StudentConsumer) handleExamResultDeleted(ctx context.Context, payload []byte) error {
	var data map[string]interface{}
	if err := json.Unmarshal(payload, &data); err != nil {
		return err
	}
	c.logger.Info("exam result deleted event", zap.Any("data", data))
	return nil
}

func (c *StudentConsumer) handleExamGradeCreated(ctx context.Context, payload []byte) error {
	var grade models.ExamGrade
	if err := json.Unmarshal(payload, &grade); err != nil {
		return err
	}
	c.logger.Info("exam grade created event",
		zap.String("grade_id", grade.GradeID.String()),
		zap.String("exam_id", grade.ExamID.String()),
		zap.String("grade_name", grade.GradeName),
	)
	return nil
}

func (c *StudentConsumer) handleExamGradeUpdated(ctx context.Context, payload []byte) error {
	var data map[string]interface{}
	if err := json.Unmarshal(payload, &data); err != nil {
		return err
	}
	c.logger.Info("exam grade updated event", zap.Any("data", data))
	return nil
}

func (c *StudentConsumer) handleExamGradeDeleted(ctx context.Context, payload []byte) error {
	var data map[string]interface{}
	if err := json.Unmarshal(payload, &data); err != nil {
		return err
	}
	c.logger.Info("exam grade deleted event", zap.Any("data", data))
	return nil
}

// ---------- Grading Policy & Boundary Event Handlers ----------
func (c *StudentConsumer) handleGradingPolicyCreated(ctx context.Context, payload []byte) error {
	var policy models.GradingPolicy
	if err := json.Unmarshal(payload, &policy); err != nil {
		return err
	}
	c.logger.Info("grading policy created event",
		zap.String("policy_id", policy.PolicyID.String()),
		zap.String("policy_name", policy.PolicyName),
		zap.String("company_id", policy.CompanyID.String()),
		zap.String("grading_scale", string(policy.GradingScale)),
	)
	return nil
}

func (c *StudentConsumer) handleGradingPolicyUpdated(ctx context.Context, payload []byte) error {
	var policy models.GradingPolicy
	if err := json.Unmarshal(payload, &policy); err != nil {
		return err
	}
	c.logger.Info("grading policy updated event",
		zap.String("policy_id", policy.PolicyID.String()),
		zap.String("policy_name", policy.PolicyName),
	)
	return nil
}

func (c *StudentConsumer) handleGradingPolicyDeleted(ctx context.Context, payload []byte) error {
	var data map[string]interface{}
	if err := json.Unmarshal(payload, &data); err != nil {
		return err
	}
	c.logger.Info("grading policy deleted event",
		zap.Any("data", data),
	)
	return nil
}

func (c *StudentConsumer) handleGradeBoundaryCreated(ctx context.Context, payload []byte) error {
	var boundary models.GradeBoundary
	if err := json.Unmarshal(payload, &boundary); err != nil {
		return err
	}
	c.logger.Info("grade boundary created event",
		zap.String("boundary_id", boundary.BoundaryID.String()),
		zap.String("policy_id", boundary.PolicyID.String()),
		zap.String("grade", boundary.Grade),
		zap.Float64("min_percentage", boundary.MinPercentage),
		zap.Float64("max_percentage", boundary.MaxPercentage),
	)
	return nil
}

func (c *StudentConsumer) handleGradeBoundaryUpdated(ctx context.Context, payload []byte) error {
	var boundary models.GradeBoundary
	if err := json.Unmarshal(payload, &boundary); err != nil {
		return err
	}
	c.logger.Info("grade boundary updated event",
		zap.String("boundary_id", boundary.BoundaryID.String()),
		zap.String("grade", boundary.Grade),
	)
	return nil
}

func (c *StudentConsumer) handleGradeBoundaryDeleted(ctx context.Context, payload []byte) error {
	var data map[string]interface{}
	if err := json.Unmarshal(payload, &data); err != nil {
		return err
	}
	c.logger.Info("grade boundary deleted event",
		zap.Any("data", data),
	)
	return nil
}

// ---------- Fee Event Handlers ----------
func (c *StudentConsumer) handleFeeStructureCreated(ctx context.Context, payload []byte) error {
	var fs models.FeeStructure
	if err := json.Unmarshal(payload, &fs); err != nil {
		return err
	}
	c.logger.Info("fee structure created event",
		zap.String("fee_structure_id", fs.FeeStructureID.String()),
		zap.String("name", fs.FeeStructureName),
		zap.String("academic_year_id", fs.AcademicYearID.String()),
		zap.String("course_id", fs.CourseID.String()),
		zap.Float64("total_amount", fs.TotalAmount),
	)
	return nil
}

func (c *StudentConsumer) handleFeeStructureUpdated(ctx context.Context, payload []byte) error {
	var fs models.FeeStructure
	if err := json.Unmarshal(payload, &fs); err != nil {
		return err
	}
	c.logger.Info("fee structure updated event",
		zap.String("fee_structure_id", fs.FeeStructureID.String()),
		zap.String("name", fs.FeeStructureName),
	)
	return nil
}

func (c *StudentConsumer) handleFeeStructureDeleted(ctx context.Context, payload []byte) error {
	var data map[string]interface{}
	if err := json.Unmarshal(payload, &data); err != nil {
		return err
	}
	c.logger.Info("fee structure deleted event", zap.Any("data", data))
	return nil
}

func (c *StudentConsumer) handleFeeInvoiceCreated(ctx context.Context, payload []byte) error {
	var inv models.StudentFeeInvoice
	if err := json.Unmarshal(payload, &inv); err != nil {
		return err
	}
	c.logger.Info("fee invoice created event",
		zap.String("invoice_id", inv.InvoiceID.String()),
		zap.String("invoice_no", inv.InvoiceNo),
		zap.String("student_id", inv.StudentID.String()),
		zap.Float64("total_amount", inv.TotalAmount),
		zap.Time("due_date", inv.DueDate),
	)
	return nil
}

func (c *StudentConsumer) handleFeeInvoiceUpdated(ctx context.Context, payload []byte) error {
	var inv models.StudentFeeInvoice
	if err := json.Unmarshal(payload, &inv); err != nil {
		return err
	}
	c.logger.Info("fee invoice updated event",
		zap.String("invoice_id", inv.InvoiceID.String()),
		zap.String("status", inv.Status),
	)
	return nil
}

func (c *StudentConsumer) handleFeePaymentCreated(ctx context.Context, payload []byte) error {
	var payment models.StudentFeePayment
	if err := json.Unmarshal(payload, &payment); err != nil {
		return err
	}
	c.logger.Info("fee payment created event",
		zap.String("payment_id", payment.PaymentID.String()),
		zap.String("invoice_id", payment.InvoiceID.String()),
		zap.Float64("amount", payment.Amount),
		zap.String("payment_mode", payment.PaymentMode),
	)
	return nil
}

func (c *StudentConsumer) handleFeePaymentUpdated(ctx context.Context, payload []byte) error {
	var payment models.StudentFeePayment
	if err := json.Unmarshal(payload, &payment); err != nil {
		return err
	}
	c.logger.Info("fee payment updated event",
		zap.String("payment_id", payment.PaymentID.String()),
		zap.String("receipt_no", payment.ReceiptNo),
	)
	return nil
}

func (c *StudentConsumer) handleFeeDiscountCreated(ctx context.Context, payload []byte) error {
	var discount models.FeeDiscount
	if err := json.Unmarshal(payload, &discount); err != nil {
		return err
	}
	c.logger.Info("fee discount created event",
		zap.String("discount_id", discount.DiscountID.String()),
		zap.String("student_id", discount.StudentID.String()),
		zap.String("discount_type", discount.DiscountType),
		zap.Float64("discount_value", discount.DiscountValue),
	)
	return nil
}

func (c *StudentConsumer) handleFeeDiscountUpdated(ctx context.Context, payload []byte) error {
	var discount models.FeeDiscount
	if err := json.Unmarshal(payload, &discount); err != nil {
		return err
	}
	c.logger.Info("fee discount updated event",
		zap.String("discount_id", discount.DiscountID.String()),
	)
	return nil
}

func (c *StudentConsumer) handleFeePenaltyCreated(ctx context.Context, payload []byte) error {
	var penalty models.FeePenalty
	if err := json.Unmarshal(payload, &penalty); err != nil {
		return err
	}
	c.logger.Info("fee penalty created event",
		zap.String("penalty_id", penalty.PenaltyID.String()),
		zap.String("invoice_id", penalty.InvoiceID.String()),
		zap.Float64("amount", penalty.Amount),
		zap.String("reason", penalty.Reason),
	)
	return nil
}

func (c *StudentConsumer) handleFeeReceiptGenerated(ctx context.Context, payload []byte) error {
	var receipt models.FeeReceipt
	if err := json.Unmarshal(payload, &receipt); err != nil {
		return err
	}
	c.logger.Info("fee receipt generated event",
		zap.String("receipt_id", receipt.ReceiptID.String()),
		zap.String("receipt_no", receipt.ReceiptNo),
		zap.String("payment_id", receipt.PaymentID.String()),
	)
	return nil
}

// ---------- Library Event Handlers ----------
func (c *StudentConsumer) handleLibraryCategoryCreated(ctx context.Context, payload []byte) error {
	var cat models.LibraryCategory
	if err := json.Unmarshal(payload, &cat); err != nil {
		return err
	}
	c.logger.Info("library category created event",
		zap.String("category_id", cat.CategoryID.String()),
		zap.String("company_id", cat.CompanyID.String()),
		zap.String("category_name", cat.CategoryName),
	)
	return nil
}

func (c *StudentConsumer) handleLibraryCategoryUpdated(ctx context.Context, payload []byte) error {
	var cat models.LibraryCategory
	if err := json.Unmarshal(payload, &cat); err != nil {
		return err
	}
	c.logger.Info("library category updated event",
		zap.String("category_id", cat.CategoryID.String()),
		zap.String("category_name", cat.CategoryName),
	)
	return nil
}

func (c *StudentConsumer) handleLibraryCategoryDeleted(ctx context.Context, payload []byte) error {
	var data map[string]interface{}
	if err := json.Unmarshal(payload, &data); err != nil {
		return err
	}
	c.logger.Info("library category deleted event",
		zap.Any("data", data),
	)
	return nil
}

func (c *StudentConsumer) handleLibraryBookCreated(ctx context.Context, payload []byte) error {
	var book models.LibraryBook
	if err := json.Unmarshal(payload, &book); err != nil {
		return err
	}
	c.logger.Info("library book created event",
		zap.String("book_id", book.BookID.String()),
		zap.String("title", book.Title),
		zap.String("author", book.Author),
		zap.String("isbn", book.ISBN),
	)
	return nil
}

func (c *StudentConsumer) handleLibraryBookUpdated(ctx context.Context, payload []byte) error {
	var book models.LibraryBook
	if err := json.Unmarshal(payload, &book); err != nil {
		return err
	}
	c.logger.Info("library book updated event",
		zap.String("book_id", book.BookID.String()),
		zap.String("title", book.Title),
	)
	return nil
}

func (c *StudentConsumer) handleLibraryBookDeleted(ctx context.Context, payload []byte) error {
	var data map[string]interface{}
	if err := json.Unmarshal(payload, &data); err != nil {
		return err
	}
	c.logger.Info("library book deleted event",
		zap.Any("data", data),
	)
	return nil
}

func (c *StudentConsumer) handleLibraryCopyCreated(ctx context.Context, payload []byte) error {
	var copy models.LibraryBookCopy
	if err := json.Unmarshal(payload, &copy); err != nil {
		return err
	}
	c.logger.Info("library copy created event",
		zap.String("copy_id", copy.CopyID.String()),
		zap.String("book_id", copy.BookID.String()),
		zap.String("accession_no", copy.AccessionNo),
		zap.String("status", string(copy.Status)),
	)
	return nil
}

func (c *StudentConsumer) handleLibraryCopyUpdated(ctx context.Context, payload []byte) error {
	var copy models.LibraryBookCopy
	if err := json.Unmarshal(payload, &copy); err != nil {
		return err
	}
	c.logger.Info("library copy updated event",
		zap.String("copy_id", copy.CopyID.String()),
		zap.String("status", string(copy.Status)),
	)
	return nil
}

func (c *StudentConsumer) handleLibraryCopyDeleted(ctx context.Context, payload []byte) error {
	var data map[string]interface{}
	if err := json.Unmarshal(payload, &data); err != nil {
		return err
	}
	c.logger.Info("library copy deleted event",
		zap.Any("data", data),
	)
	return nil
}

func (c *StudentConsumer) handleLibraryBookIssued(ctx context.Context, payload []byte) error {
	var issue models.LibraryIssue
	if err := json.Unmarshal(payload, &issue); err != nil {
		return err
	}
	c.logger.Info("library book issued event",
		zap.String("issue_id", issue.IssueID.String()),
		zap.String("copy_id", issue.CopyID.String()),
		zap.String("student_id", issue.StudentID.String()),
		zap.Time("issue_date", issue.IssueDate),
		zap.Time("due_date", issue.DueDate),
	)
	return nil
}

func (c *StudentConsumer) handleLibraryBookReturned(ctx context.Context, payload []byte) error {
	var ret models.LibraryReturn
	if err := json.Unmarshal(payload, &ret); err != nil {
		return err
	}
	c.logger.Info("library book returned event",
		zap.String("return_id", ret.ReturnID.String()),
		zap.String("issue_id", ret.IssueID.String()),
		zap.Time("return_date", ret.ReturnDate),
		zap.Float64p("fine_amount", ret.FineAmount),
	)
	return nil
}

func (c *StudentConsumer) handleLibraryFinePaid(ctx context.Context, payload []byte) error {
	var fine models.LibraryFine
	if err := json.Unmarshal(payload, &fine); err != nil {
		return err
	}
	c.logger.Info("library fine paid event",
		zap.String("fine_id", fine.FineID.String()),
		zap.String("issue_id", fine.IssueID.String()),
		zap.Float64("fine_amount", fine.FineAmount),
		zap.Timep("paid_date", fine.PaidDate),
		zap.String("payment_mode", fine.PaymentMode),
	)
	return nil
}

// ---------- Transport Event Handlers ----------
func (c *StudentConsumer) handleTransportRouteCreated(ctx context.Context, payload []byte) error {
	var route models.TransportRoute
	if err := json.Unmarshal(payload, &route); err != nil {
		return err
	}
	c.logger.Info("transport route created",
		zap.String("route_id", route.RouteID.String()),
		zap.String("route_name", route.RouteName),
		zap.String("company_id", route.CompanyID.String()),
	)
	return nil
}

func (c *StudentConsumer) handleTransportRouteUpdated(ctx context.Context, payload []byte) error {
	var route models.TransportRoute
	if err := json.Unmarshal(payload, &route); err != nil {
		return err
	}
	c.logger.Info("transport route updated",
		zap.String("route_id", route.RouteID.String()),
		zap.String("route_name", route.RouteName),
	)
	return nil
}

func (c *StudentConsumer) handleTransportRouteDeleted(ctx context.Context, payload []byte) error {
	var data map[string]interface{}
	if err := json.Unmarshal(payload, &data); err != nil {
		return err
	}
	c.logger.Info("transport route deleted", zap.Any("data", data))
	return nil
}

func (c *StudentConsumer) handleTransportStopCreated(ctx context.Context, payload []byte) error {
	var stop models.TransportStop
	if err := json.Unmarshal(payload, &stop); err != nil {
		return err
	}
	c.logger.Info("transport stop created",
		zap.String("stop_id", stop.StopID.String()),
		zap.String("stop_name", stop.StopName),
		zap.String("route_id", stop.RouteID.String()),
	)
	return nil
}

func (c *StudentConsumer) handleTransportStopUpdated(ctx context.Context, payload []byte) error {
	var stop models.TransportStop
	if err := json.Unmarshal(payload, &stop); err != nil {
		return err
	}
	c.logger.Info("transport stop updated",
		zap.String("stop_id", stop.StopID.String()),
		zap.String("stop_name", stop.StopName),
	)
	return nil
}

func (c *StudentConsumer) handleTransportStopDeleted(ctx context.Context, payload []byte) error {
	var data map[string]interface{}
	if err := json.Unmarshal(payload, &data); err != nil {
		return err
	}
	c.logger.Info("transport stop deleted", zap.Any("data", data))
	return nil
}

func (c *StudentConsumer) handleTransportVehicleCreated(ctx context.Context, payload []byte) error {
	var vehicle models.TransportVehicle
	if err := json.Unmarshal(payload, &vehicle); err != nil {
		return err
	}
	c.logger.Info("transport vehicle created",
		zap.String("vehicle_id", vehicle.VehicleID.String()),
		zap.String("vehicle_no", vehicle.VehicleNo),
		zap.String("company_id", vehicle.CompanyID.String()),
	)
	return nil
}

func (c *StudentConsumer) handleTransportVehicleUpdated(ctx context.Context, payload []byte) error {
	var vehicle models.TransportVehicle
	if err := json.Unmarshal(payload, &vehicle); err != nil {
		return err
	}
	c.logger.Info("transport vehicle updated",
		zap.String("vehicle_id", vehicle.VehicleID.String()),
		zap.String("vehicle_no", vehicle.VehicleNo),
	)
	return nil
}

func (c *StudentConsumer) handleTransportVehicleDeleted(ctx context.Context, payload []byte) error {
	var data map[string]interface{}
	if err := json.Unmarshal(payload, &data); err != nil {
		return err
	}
	c.logger.Info("transport vehicle deleted", zap.Any("data", data))
	return nil
}

func (c *StudentConsumer) handleTransportDriverAssignmentCreated(ctx context.Context, payload []byte) error {
	var da models.TransportDriverAssignment
	if err := json.Unmarshal(payload, &da); err != nil {
		return err
	}
	c.logger.Info("transport driver assignment created",
		zap.String("assignment_id", da.AssignmentID.String()),
		zap.String("driver_name", da.DriverName),
		zap.String("vehicle_id", da.VehicleID.String()),
	)
	return nil
}

func (c *StudentConsumer) handleTransportDriverAssignmentUpdated(ctx context.Context, payload []byte) error {
	var da models.TransportDriverAssignment
	if err := json.Unmarshal(payload, &da); err != nil {
		return err
	}
	c.logger.Info("transport driver assignment updated",
		zap.String("assignment_id", da.AssignmentID.String()),
		zap.String("driver_name", da.DriverName),
	)
	return nil
}

func (c *StudentConsumer) handleTransportDriverAssignmentDeleted(ctx context.Context, payload []byte) error {
	var data map[string]interface{}
	if err := json.Unmarshal(payload, &data); err != nil {
		return err
	}
	c.logger.Info("transport driver assignment deleted", zap.Any("data", data))
	return nil
}

func (c *StudentConsumer) handleTransportStudentAssignmentCreated(ctx context.Context, payload []byte) error {
	var sa models.StudentTransportAssignment
	if err := json.Unmarshal(payload, &sa); err != nil {
		return err
	}
	c.logger.Info("transport student assignment created",
		zap.String("assignment_id", sa.AssignmentID.String()),
		zap.String("student_id", sa.StudentID.String()),
		zap.String("route_id", sa.RouteID.String()),
	)
	return nil
}

func (c *StudentConsumer) handleTransportStudentAssignmentUpdated(ctx context.Context, payload []byte) error {
	var sa models.StudentTransportAssignment
	if err := json.Unmarshal(payload, &sa); err != nil {
		return err
	}
	c.logger.Info("transport student assignment updated",
		zap.String("assignment_id", sa.AssignmentID.String()),
		zap.String("student_id", sa.StudentID.String()),
	)
	return nil
}

func (c *StudentConsumer) handleTransportStudentAssignmentDeleted(ctx context.Context, payload []byte) error {
	var data map[string]interface{}
	if err := json.Unmarshal(payload, &data); err != nil {
		return err
	}
	c.logger.Info("transport student assignment deleted", zap.Any("data", data))
	return nil
}

// ---------- Section Event Handlers ----------
type SectionEvent struct {
	SectionID uuid.UUID `json:"section_id"`
	CourseID  uuid.UUID `json:"course_id"`
	TermID    uuid.UUID `json:"term_id"`
	Name      string    `json:"name"`
	Capacity  int       `json:"capacity"`
	IsActive  bool      `json:"is_active"`
	CreatedAt time.Time `json:"created_at"`
	UpdatedAt time.Time `json:"updated_at"`
}

func (c *StudentConsumer) handleSectionCreated(ctx context.Context, payload []byte) error {
	var event SectionEvent
	if err := json.Unmarshal(payload, &event); err != nil {
		var data map[string]interface{}
		if err2 := json.Unmarshal(payload, &data); err2 != nil {
			return err
		}
		c.logger.Info("section created event (generic)", zap.Any("data", data))
		return nil
	}
	c.logger.Info("section created event",
		zap.String("section_id", event.SectionID.String()),
		zap.String("course_id", event.CourseID.String()),
		zap.String("term_id", event.TermID.String()),
		zap.String("name", event.Name),
		zap.Int("capacity", event.Capacity),
		zap.Bool("is_active", event.IsActive),
	)
	return nil
}

func (c *StudentConsumer) handleSectionUpdated(ctx context.Context, payload []byte) error {
	var update struct {
		Old SectionEvent `json:"old"`
		New SectionEvent `json:"new"`
	}
	if err := json.Unmarshal(payload, &update); err == nil && update.New.SectionID != uuid.Nil {
		c.logger.Info("section updated event",
			zap.String("section_id", update.New.SectionID.String()),
			zap.String("old_name", update.Old.Name),
			zap.String("new_name", update.New.Name),
			zap.Int("old_capacity", update.Old.Capacity),
			zap.Int("new_capacity", update.New.Capacity),
		)
		return nil
	}
	var event SectionEvent
	if err := json.Unmarshal(payload, &event); err != nil {
		var data map[string]interface{}
		if err2 := json.Unmarshal(payload, &data); err2 != nil {
			return err
		}
		c.logger.Info("section updated event (generic)", zap.Any("data", data))
		return nil
	}
	c.logger.Info("section updated event (direct)",
		zap.String("section_id", event.SectionID.String()),
		zap.String("name", event.Name),
	)
	return nil
}

func (c *StudentConsumer) handleSectionDeleted(ctx context.Context, payload []byte) error {
	var data map[string]interface{}
	if err := json.Unmarshal(payload, &data); err != nil {
		return err
	}
	sectionID, _ := data["section_id"].(string)
	deletedBy, _ := data["deleted_by"].(string)
	c.logger.Info("section deleted event",
		zap.String("section_id", sectionID),
		zap.String("deleted_by", deletedBy),
	)
	return nil
}

// ---------- Subject Event Handlers ----------
func (c *StudentConsumer) handleSubjectCreated(ctx context.Context, payload []byte) error {
	var subject models.Subject
	if err := json.Unmarshal(payload, &subject); err != nil {
		return err
	}
	c.logger.Info("subject created event",
		zap.String("subject_id", subject.SubjectID.String()),
		zap.String("company_id", subject.CompanyID.String()),
		zap.String("code", subject.Code),
		zap.String("name", subject.Name),
		zap.Int("credits", subject.Credits),
	)
	return nil
}

func (c *StudentConsumer) handleSubjectUpdated(ctx context.Context, payload []byte) error {
	var update struct {
		Old models.Subject `json:"old"`
		New models.Subject `json:"new"`
	}
	if err := json.Unmarshal(payload, &update); err == nil && update.New.SubjectID != uuid.Nil {
		c.logger.Info("subject updated event",
			zap.String("subject_id", update.New.SubjectID.String()),
			zap.String("old_code", update.Old.Code),
			zap.String("new_code", update.New.Code),
			zap.String("old_name", update.Old.Name),
			zap.String("new_name", update.New.Name),
		)
		return nil
	}
	var subject models.Subject
	if err := json.Unmarshal(payload, &subject); err != nil {
		return err
	}
	c.logger.Info("subject updated event (direct)",
		zap.String("subject_id", subject.SubjectID.String()),
		zap.String("code", subject.Code),
		zap.String("name", subject.Name),
	)
	return nil
}

func (c *StudentConsumer) handleSubjectDeleted(ctx context.Context, payload []byte) error {
	var data map[string]interface{}
	if err := json.Unmarshal(payload, &data); err != nil {
		return err
	}
	subjectID, _ := data["subject_id"].(string)
	deletedBy, _ := data["deleted_by"].(string)
	c.logger.Info("subject deleted event",
		zap.String("subject_id", subjectID),
		zap.String("deleted_by", deletedBy),
	)
	return nil
}

func (c *StudentConsumer) handleSubjectAssigned(ctx context.Context, payload []byte) error {
	var mapping models.SubjectCourseMapping
	if err := json.Unmarshal(payload, &mapping); err != nil {
		return err
	}
	c.logger.Info("subject assigned to course",
		zap.String("mapping_id", mapping.MappingID.String()),
		zap.String("course_id", mapping.CourseID.String()),
		zap.String("subject_id", mapping.SubjectID.String()),
		zap.Int("term_number", mapping.TermNumber),
	)
	return nil
}

func (c *StudentConsumer) handleSubjectUnassigned(ctx context.Context, payload []byte) error {
	var mapping models.SubjectCourseMapping
	if err := json.Unmarshal(payload, &mapping); err != nil {
		return err
	}
	c.logger.Info("subject unassigned from course",
		zap.String("mapping_id", mapping.MappingID.String()),
		zap.String("course_id", mapping.CourseID.String()),
		zap.String("subject_id", mapping.SubjectID.String()),
	)
	return nil
}

// ---------- Enrollment Event Handlers ----------
func (c *StudentConsumer) handleEnrollmentCreated(ctx context.Context, payload []byte) error {
	var enrollment models.Enrollment
	if err := json.Unmarshal(payload, &enrollment); err != nil {
		return err
	}
	c.logger.Info("enrollment created event",
		zap.String("enrollment_id", enrollment.EnrollmentID.String()),
		zap.String("student_id", enrollment.StudentID.String()),
		zap.String("section_id", enrollment.SectionID.String()),
		zap.String("academic_year_id", enrollment.AcademicYearID.String()),
		zap.String("status", enrollment.Status),
	)
	return nil
}

func (c *StudentConsumer) handleEnrollmentUpdated(ctx context.Context, payload []byte) error {
	var enrollment models.Enrollment
	if err := json.Unmarshal(payload, &enrollment); err != nil {
		return err
	}
	c.logger.Info("enrollment updated event",
		zap.String("enrollment_id", enrollment.EnrollmentID.String()),
		zap.String("status", enrollment.Status),
	)
	return nil
}

func (c *StudentConsumer) handleEnrollmentDeleted(ctx context.Context, payload []byte) error {
	var data map[string]interface{}
	if err := json.Unmarshal(payload, &data); err != nil {
		return err
	}
	c.logger.Info("enrollment deleted event",
		zap.Any("data", data),
	)
	return nil
}

func (c *StudentConsumer) handleEnrollmentActivated(ctx context.Context, payload []byte) error {
	var data map[string]interface{}
	if err := json.Unmarshal(payload, &data); err != nil {
		return err
	}
	c.logger.Info("enrollment activated event",
		zap.Any("data", data),
	)
	return nil
}

func (c *StudentConsumer) handleEnrollmentCompleted(ctx context.Context, payload []byte) error {
	var data map[string]interface{}
	if err := json.Unmarshal(payload, &data); err != nil {
		return err
	}
	c.logger.Info("enrollment completed event",
		zap.Any("data", data),
	)
	return nil
}

func (c *StudentConsumer) handleEnrollmentWithdrawn(ctx context.Context, payload []byte) error {
	var data map[string]interface{}
	if err := json.Unmarshal(payload, &data); err != nil {
		return err
	}
	c.logger.Info("enrollment withdrawn event",
		zap.Any("data", data),
	)
	return nil
}

func (c *StudentConsumer) handleEnrollmentTransferred(ctx context.Context, payload []byte) error {
	var enrollment models.Enrollment
	if err := json.Unmarshal(payload, &enrollment); err != nil {
		// Fallback to generic data
		var data map[string]interface{}
		if err2 := json.Unmarshal(payload, &data); err2 != nil {
			return err
		}
		c.logger.Info("enrollment transferred event (generic)", zap.Any("data", data))
		return nil
	}
	c.logger.Info("enrollment transferred event",
		zap.String("enrollment_id", enrollment.EnrollmentID.String()),
		zap.String("student_id", enrollment.StudentID.String()),
		zap.String("section_id", enrollment.SectionID.String()),
	)
	return nil
}

func (c *StudentConsumer) handleEnrollmentPromoted(ctx context.Context, payload []byte) error {
	var data map[string]interface{}
	if err := json.Unmarshal(payload, &data); err != nil {
		return err
	}
	c.logger.Info("enrollment promoted event",
		zap.Any("data", data),
	)
	return nil
}

// ---------- Helper Methods ----------
func (c *StudentConsumer) extractEventType(msg *kafka.Message) string {
	for _, h := range msg.Headers {
		if h.Key == "event_type" {
			return string(h.Value)
		}
	}
	return ""
}

func (c *StudentConsumer) getRetryCount(msg *kafka.Message) int {
	for _, h := range msg.Headers {
		if h.Key == "retry_count" {
			var count int
			fmt.Sscanf(string(h.Value), "%d", &count)
			return count
		}
	}
	return 0
}

func (c *StudentConsumer) publishRetry(ctx context.Context, original *kafka.Message, newRetryCount int) error {
	headers := make([]kafka.Header, 0, len(original.Headers)+1)
	found := false
	for _, h := range original.Headers {
		if h.Key == "retry_count" {
			headers = append(headers, kafka.Header{
				Key:   "retry_count",
				Value: []byte(fmt.Sprintf("%d", newRetryCount)),
			})
			found = true
		} else {
			headers = append(headers, h)
		}
	}
	if !found {
		headers = append(headers, kafka.Header{
			Key:   "retry_count",
			Value: []byte(fmt.Sprintf("%d", newRetryCount)),
		})
	}
	retryMsg := kafka.Message{
		Topic:   original.Topic,
		Key:     original.Key,
		Value:   original.Value,
		Headers: headers,
		Time:    time.Now(),
	}
	return c.producer.WriteMessages(ctx, retryMsg)
}

func (c *StudentConsumer) sendToDLQ(ctx context.Context, original *kafka.Message, processErr error) error {
	dlqTopic := original.Topic + ".dlq"
	headers := append(original.Headers,
		kafka.Header{
			Key:   "error",
			Value: []byte(processErr.Error()),
		},
		kafka.Header{
			Key:   "failed_at",
			Value: []byte(time.Now().Format(time.RFC3339)),
		},
	)
	dlqMsg := kafka.Message{
		Topic:   dlqTopic,
		Key:     original.Key,
		Value:   original.Value,
		Headers: headers,
		Time:    time.Now(),
	}
	return c.producer.WriteMessages(ctx, dlqMsg)
}

func (c *StudentConsumer) Close() error {
	c.logger.Info("closing student consumer")
	for topic, kc := range c.kafkaConsumers {
		c.logger.Info("closing kafka consumer", zap.String("topic", topic))
		if err := kc.Close(); err != nil {
			c.logger.Error("failed to close kafka consumer", zap.Error(err))
		}
	}
	if err := c.producer.Close(); err != nil {
		c.logger.Error("failed to close producer", zap.Error(err))
	}
	return nil
}

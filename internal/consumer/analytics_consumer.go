package consumer

import (
	"context"
	"fmt"
	"time"

	"github.com/segmentio/kafka-go"
	"go.uber.org/zap"

	"auth-service/internal/academics/repository"
	"auth-service/internal/academics/service"
	"auth-service/internal/client"
)

// AnalyticsConsumer listens to domain events and updates analytics fact tables.
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
				if pubErr := c.publishRetry(ctx, msg, retryCount+1); pubErr != nil {
					c.logger.Error("failed to publish retry", zap.Error(pubErr))
				}
			} else {
				if dlqErr := c.sendToDLQ(ctx, msg, err); dlqErr != nil {
					c.logger.Error("failed to send to DLQ", zap.Error(dlqErr))
				}
			}
		}

		if err := c.consumer.CommitMessage(ctx, msg); err != nil {
			c.logger.Error("failed to commit message", zap.Error(err))
		}
	}
}

// handleEvent routes the event to the appropriate update method.
func (c *AnalyticsConsumer) handleEvent(ctx context.Context, eventType string, payload []byte) error {
	switch eventType {
	// =========================================================================
	// Admission events
	// =========================================================================
	case "admission.created":
		return c.analyticsSvc.ProcessAdmissionCreated(ctx, payload)
	case "admission.status_updated":
		return c.analyticsSvc.ProcessAdmissionStatusUpdated(ctx, payload)

	// =========================================================================
	// Term events
	// =========================================================================
	case "term.created":
		return c.analyticsSvc.ProcessTermCreated(ctx, payload)

	// =========================================================================
	// Section events
	// =========================================================================
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

	// =========================================================================
	// Assignment events
	// =========================================================================
	case "assignment.created":
		return c.analyticsSvc.ProcessAssignmentCreated(ctx, payload)
	case "assignment.updated":
		return c.analyticsSvc.ProcessAssignmentUpdated(ctx, payload)
	case "assignment.deleted":
		return c.analyticsSvc.ProcessAssignmentDeleted(ctx, payload)
	case "assignment.published":
		return c.analyticsSvc.ProcessAssignmentPublished(ctx, payload)

	// =========================================================================
	// Attendance events
	// =========================================================================
	case "attendance.marked":
		return c.analyticsSvc.ProcessAttendanceMarked(ctx, payload)
	case "attendance.bulk_marked":
		return c.analyticsSvc.ProcessAttendanceBulkMarked(ctx, payload)
	case "attendance.exemption_created":
		return c.analyticsSvc.ProcessAttendanceExemptionCreated(ctx, payload)
	case "attendance.exemption_deleted":
		return c.analyticsSvc.ProcessAttendanceExemptionDeleted(ctx, payload)

	// =========================================================================
	// Curriculum events
	// =========================================================================
	case "subject.assigned":
		return c.analyticsSvc.ProcessSubjectAssigned(ctx, payload)
	case "subject.unassigned":
		return c.analyticsSvc.ProcessSubjectUnassigned(ctx, payload)

	// =========================================================================
	// Enrollment events
	// =========================================================================
	case "enrollment.created":
		return c.analyticsSvc.ProcessEnrollmentCreated(ctx, payload)
	case "enrollment.updated":
		return c.analyticsSvc.ProcessEnrollmentUpdated(ctx, payload)
	case "enrollment.deleted":
		return c.analyticsSvc.ProcessEnrollmentDeleted(ctx, payload)

	// =========================================================================
	// Exam domain events
	// =========================================================================
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

	// =========================================================================
	// Fee domain events
	// =========================================================================
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

	// =========================================================================
	// Grading domain events
	// =========================================================================
	case "grading_policy.created":
		return c.analyticsSvc.ProcessGradingPolicyCreated(ctx, payload)
	case "grading_policy.deleted":
		return c.analyticsSvc.ProcessGradingPolicyDeleted(ctx, payload)
	case "grade_boundary.created":
		return c.analyticsSvc.ProcessGradeBoundaryCreated(ctx, payload)
	case "grade_boundary.deleted":
		return c.analyticsSvc.ProcessGradeBoundaryDeleted(ctx, payload)

	// =========================================================================
	// Guardian domain events
	// =========================================================================
	case "guardian.created":
		return c.analyticsSvc.ProcessGuardianCreated(ctx, payload)
	case "guardian.updated":
		return c.analyticsSvc.ProcessGuardianUpdated(ctx, payload)
	case "guardian.deleted":
		return c.analyticsSvc.ProcessGuardianDeleted(ctx, payload)
	case "guardian.primary_set":
		return c.analyticsSvc.ProcessGuardianPrimarySet(ctx, payload)

	// =========================================================================
	// Library domain events
	// =========================================================================
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

	// =========================================================================
	// Room events
	// =========================================================================
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

	// =========================================================================
	// Student events (replacing old placeholders with real service calls)
	// =========================================================================
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

	// =========================================================================
	// Subject events
	// =========================================================================
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

	// =========================================================================
	// Submission events
	// =========================================================================
	case "submission.created":
		return c.analyticsSvc.ProcessSubmissionCreated(ctx, payload)
	case "submission.updated":
		return c.analyticsSvc.ProcessSubmissionUpdated(ctx, payload)
	case "submission.deleted":
		return c.analyticsSvc.ProcessSubmissionDeleted(ctx, payload)
	case "submission.graded":
		return c.analyticsSvc.ProcessSubmissionGraded(ctx, payload)

	// =========================================================================
	// Teacher events
	// =========================================================================
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

	// =========================================================================
	// Timetable events
	// =========================================================================
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

	// =========================================================================
	// Transport events
	// =========================================================================
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

	// =========================================================================
	// Ignored events
	// =========================================================================
	default:
		c.logger.Debug("ignored event type", zap.String("event_type", eventType))
		return nil
	}
}

// ----------------------------------------------------------------------
// Kafka helper methods
// ----------------------------------------------------------------------

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

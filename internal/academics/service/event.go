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

	// Additional student events used in student_service.go
	EventStudentContactUpdated    EventType = "student.contact_updated"
	EventStudentActivated         EventType = "student.activated"
	EventStudentDeactivated       EventType = "student.deactivated"
	EventStudentBulkStatusUpdated EventType = "student.bulk_status_updated"

	// add others as needed
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

package resolver

import (
	"context"
	"fmt"
	"time"

	"github.com/google/uuid"
	"go.uber.org/zap"

	"auth-service/internal/attendance/repository"
)

type StudentDataProvider interface {
	GetStudent(ctx context.Context, companyID, studentID uuid.UUID) (active bool, err error)
}

type EnrollmentDataProvider interface {
	GetActiveEnrollment(ctx context.Context, companyID, studentID uuid.UUID, date time.Time) (sectionID *uuid.UUID, academicYearID *uuid.UUID, err error)
}

type TimetableEntry struct {
	EntryID   uuid.UUID
	SubjectID uuid.UUID
	TeacherID uuid.UUID
	RoomID    *uuid.UUID
	StartTime time.Time // only time part (date portion is zero)
	EndTime   time.Time // only time part (date portion is zero)
	SlotID    uuid.UUID
	DayOfWeek int
}

type TimetableDataProvider interface {
	GetTimetableForSection(ctx context.Context, sectionID uuid.UUID, date time.Time) (timetableID *uuid.UUID, entries []TimetableEntry, err error)
}

type SessionDataProvider interface {
	GetAcademicSession(ctx context.Context, timetableEntryID uuid.UUID, date time.Time) (sessionID *uuid.UUID, startTime, endTime *time.Time, err error)
}

type StudentResolver struct {
	studentRepo    StudentDataProvider
	enrollmentRepo EnrollmentDataProvider
	timetableRepo  TimetableDataProvider
	sessionRepo    SessionDataProvider
	workCenterRepo repository.WorkCenterRepository
	logger         *zap.Logger
}

func NewStudentResolver(
	studentRepo StudentDataProvider,
	enrollmentRepo EnrollmentDataProvider,
	timetableRepo TimetableDataProvider,
	sessionRepo SessionDataProvider,
	workCenterRepo repository.WorkCenterRepository,
	logger *zap.Logger,
) *StudentResolver {
	return &StudentResolver{
		studentRepo:    studentRepo,
		enrollmentRepo: enrollmentRepo,
		timetableRepo:  timetableRepo,
		sessionRepo:    sessionRepo,
		workCenterRepo: workCenterRepo,
		logger:         logger,
	}
}

func (r *StudentResolver) Resolve(ctx context.Context, companyID uuid.UUID, subjectType string, subjectID uuid.UUID, date time.Time) (*ResolvedSubject, error) {
	if subjectType != SubjectTypeStudent {
		return nil, fmt.Errorf("student resolver called with subject_type=%s", subjectType)
	}

	active, err := r.studentRepo.GetStudent(ctx, companyID, subjectID)
	if err != nil || !active {
		return &ResolvedSubject{IsActive: active}, err
	}

	sectionID, _, err := r.enrollmentRepo.GetActiveEnrollment(ctx, companyID, subjectID, date)
	if err != nil || sectionID == nil {
		return &ResolvedSubject{
			IsActive:       true,
			Timezone:       "UTC",
			ScheduleStatus: "not_schedulable",
		}, nil
	}

	_, entries, err := r.timetableRepo.GetTimetableForSection(ctx, *sectionID, date)
	if err != nil || len(entries) == 0 {
		return &ResolvedSubject{
			IsActive:       true,
			Timezone:       "UTC",
			ScheduleStatus: "not_schedulable",
		}, nil
	}

	// Combine the date from the input `date` with the time from each entry.
	// Both are in UTC; the business date is already a UTC timestamp at midnight.
	var earliestStart, latestEnd *time.Time
	for _, e := range entries {
		start := time.Date(date.Year(), date.Month(), date.Day(),
			e.StartTime.Hour(), e.StartTime.Minute(), e.StartTime.Second(), e.StartTime.Nanosecond(), time.UTC)
		end := time.Date(date.Year(), date.Month(), date.Day(),
			e.EndTime.Hour(), e.EndTime.Minute(), e.EndTime.Second(), e.EndTime.Nanosecond(), time.UTC)

		if earliestStart == nil || start.Before(*earliestStart) {
			earliestStart = &start
		}
		if latestEnd == nil || end.After(*latestEnd) {
			latestEnd = &end
		}
	}

	var sessionID *uuid.UUID
	if len(entries) > 0 {
		sess, _, _, err := r.sessionRepo.GetAcademicSession(ctx, entries[0].EntryID, date)
		if err == nil && sess != nil {
			sessionID = sess
		}
	}

	// TODO: fetch company timezone for proper localisation, but UTC works for now.
	timezone := "UTC"

	return &ResolvedSubject{
		IsActive:           true,
		Timezone:           timezone,
		ScheduleStatus:     "working",
		ExpectedStart:      earliestStart,
		ExpectedEnd:        latestEnd,
		ScheduleInstanceID: sessionID,
		IsOnLeave:          false,
		IsLeavePaid:        false,
	}, nil
}

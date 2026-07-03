package resolver

import (
	"context"
	"database/sql"
	"time"

	"github.com/google/uuid"
	"go.uber.org/zap"

	academicsRepo "auth-service/internal/academics/repository"
)

// sessionDataProvider implements SessionDataProvider using the academics session repository.
type sessionDataProvider struct {
	db          *sql.DB
	sessionRepo academicsRepo.AcademicSessionRepository
	logger      *zap.Logger
}

// NewSessionDataProvider creates a new session data provider.
func NewSessionDataProvider(
	db *sql.DB,
	sessionRepo academicsRepo.AcademicSessionRepository,
	logger *zap.Logger,
) SessionDataProvider {
	return &sessionDataProvider{
		db:          db,
		sessionRepo: sessionRepo,
		logger:      logger,
	}
}

// GetAcademicSession retrieves the academic session for a given timetable entry and date.
// Returns the session ID, start time, end time, and any error.
// If no session exists, returns (nil, nil, nil, nil).
func (p *sessionDataProvider) GetAcademicSession(
	ctx context.Context,
	timetableEntryID uuid.UUID,
	date time.Time,
) (sessionID *uuid.UUID, startTime, endTime *time.Time, err error) {
	p.logger.Info("GetAcademicSession called",
		zap.String("timetable_entry_id", timetableEntryID.String()),
		zap.String("date", date.Format("2006-01-02")),
	)

	session, err := p.sessionRepo.GetByTimetableEntryAndDate(ctx, p.db, timetableEntryID, date)
	if err != nil {
		p.logger.Error("GetByTimetableEntryAndDate failed", zap.Error(err))
		return nil, nil, nil, err
	}
	if session == nil {
		p.logger.Warn("No academic session found for timetable entry",
			zap.String("timetable_entry_id", timetableEntryID.String()),
		)
		return nil, nil, nil, nil
	}

	p.logger.Info("Academic session found",
		zap.String("session_id", session.SessionID.String()),
		zap.Time("start_time", session.StartTime),
		zap.Time("end_time", session.EndTime),
	)
	return &session.SessionID, &session.StartTime, &session.EndTime, nil
}

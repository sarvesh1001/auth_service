package resolver

import (
	"context"
	"database/sql"
	"time"

	"github.com/google/uuid"
	"go.uber.org/zap"

	academicsRepo "auth-service/internal/academics/repository"
)

type timetableDataProvider struct {
	db            *sql.DB
	timetableRepo academicsRepo.TimetableRepository
	logger        *zap.Logger
}

func NewTimetableDataProvider(db *sql.DB, timetableRepo academicsRepo.TimetableRepository, logger *zap.Logger) TimetableDataProvider {
	return &timetableDataProvider{
		db:            db,
		timetableRepo: timetableRepo,
		logger:        logger,
	}
}

func (p *timetableDataProvider) GetTimetableForSection(ctx context.Context, sectionID uuid.UUID, date time.Time) (timetableID *uuid.UUID, entries []TimetableEntry, err error) {
	// Fetch all active entries for the exact date range (single day)
	entriesWithDetails, err := p.timetableRepo.GetActiveTimetableEntriesForDateRange(ctx, p.db, date, date)
	if err != nil {
		p.logger.Error("GetActiveTimetableEntriesForDateRange failed", zap.Error(err))
		return nil, nil, err
	}

	// Filter by sectionID
	var filtered []*academicsRepo.TimetableEntryWithDetails
	var firstTimetableID *uuid.UUID
	for _, e := range entriesWithDetails {
		if e.SectionID == sectionID {
			filtered = append(filtered, e)
			if firstTimetableID == nil {
				firstTimetableID = &e.TimetableID
			}
		}
	}
	if len(filtered) == 0 {
		p.logger.Warn("No timetable entries for section on date")
		return nil, nil, nil
	}

	// Convert to the resolver's TimetableEntry type
	entries = make([]TimetableEntry, len(filtered))
	for i, e := range filtered {
		entries[i] = TimetableEntry{
			EntryID:   e.EntryID,
			SubjectID: e.SubjectID,
			TeacherID: e.TeacherID,
			RoomID:    e.RoomID,
			StartTime: e.StartTime,
			EndTime:   e.EndTime,
			SlotID:    e.SlotID,
			DayOfWeek: e.DayOfWeek,
		}
	}
	return firstTimetableID, entries, nil
}

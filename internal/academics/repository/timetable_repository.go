package repository

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/google/uuid"
	"go.uber.org/zap"

	"auth-service/internal/academics/models"
	"auth-service/internal/util"
)

type TimetableRepository interface {
	CreateTimetable(ctx context.Context, db DBTX, tt *models.Timetable) error
	GetTimetableByID(ctx context.Context, db DBTX, id uuid.UUID) (*models.Timetable, error)
	ListTimetables(ctx context.Context, db DBTX, filter TimetableFilter, p Pagination, s Sort) ([]*models.Timetable, error)
	CountTimetables(ctx context.Context, db DBTX, filter TimetableFilter) (int64, error)
	UpdateTimetable(ctx context.Context, db DBTX, tt *models.Timetable) error
	DeleteTimetable(ctx context.Context, db DBTX, id uuid.UUID, deletedBy *uuid.UUID) error
	GetActiveTimetableForSection(ctx context.Context, db DBTX, termID, sectionID uuid.UUID) (*models.Timetable, error)

	// New method for period attendance session generation
	GetActiveTimetableEntriesForDateRange(ctx context.Context, db DBTX, startDate, endDate time.Time) ([]*TimetableEntryWithDetails, error)

	AddSlot(ctx context.Context, db DBTX, slot *models.TimetableSlot) error
	UpdateSlot(ctx context.Context, db DBTX, slot *models.TimetableSlot) error
	RemoveSlot(ctx context.Context, db DBTX, slotID uuid.UUID) error
	GetSlotsForTimetable(ctx context.Context, db DBTX, timetableID uuid.UUID) ([]*models.TimetableSlot, error)
	GetSlotByID(ctx context.Context, db DBTX, slotID uuid.UUID) (*models.TimetableSlot, error)

	AddEntry(ctx context.Context, db DBTX, entry *models.TimetableEntry) error
	UpdateEntry(ctx context.Context, db DBTX, entry *models.TimetableEntry) error
	RemoveEntry(ctx context.Context, db DBTX, entryID uuid.UUID) error
	GetEntriesForSlot(ctx context.Context, db DBTX, slotID uuid.UUID) ([]*models.TimetableEntry, error)
	GetEntryByID(ctx context.Context, db DBTX, entryID uuid.UUID) (*models.TimetableEntry, error)

	AddChange(ctx context.Context, db DBTX, change *models.TimetableChange) error
	GetChangesForEntry(ctx context.Context, db DBTX, entryID uuid.UUID) ([]*models.TimetableChange, error)
}

// TimetableEntryWithDetails combines a timetable entry with its slot and timetable info
type TimetableEntryWithDetails struct {
	EntryID        uuid.UUID
	SlotID         uuid.UUID
	TimetableID    uuid.UUID
	SectionID      uuid.UUID
	SubjectID      uuid.UUID
	TeacherID      uuid.UUID
	RoomID         *uuid.UUID
	DayOfWeek      int
	StartTime      time.Time // only time part (stored as TIME in DB)
	EndTime        time.Time
	EffectiveFrom  time.Time
	EffectiveTo    *time.Time
	TermID         uuid.UUID
	AcademicYearID uuid.UUID
}

type timetableRepository struct {
	logger *zap.Logger
}

func NewTimetableRepository(logger *zap.Logger) TimetableRepository {
	return &timetableRepository{
		logger: logger.Named("timetable_repo"),
	}
}

var allowedTimetableSortFields = map[string]bool{
	"created_at":     true,
	"updated_at":     true,
	"effective_from": true,
	"version":        true,
}

func (r *timetableRepository) validateSort(s Sort) (string, error) {
	field := s.Field
	if field == "" {
		field = "created_at"
	}
	if !allowedTimetableSortFields[field] {
		return "", fmt.Errorf("invalid sort field: %s", field)
	}
	dir := strings.ToUpper(s.Direction)
	if dir != "ASC" && dir != "DESC" {
		dir = "DESC"
	}
	return fmt.Sprintf("ORDER BY t.%s %s", field, dir), nil
}

func (r *timetableRepository) validatePagination(p Pagination) (int, int) {
	limit := p.Limit
	if limit <= 0 {
		limit = 50
	}
	if limit > 1000 {
		limit = 1000
	}
	offset := p.Offset
	if offset < 0 {
		offset = 0
	}
	return limit, offset
}

func (r *timetableRepository) buildTimetableFilter(filter TimetableFilter) (string, []interface{}) {
	var conditions []string
	var args []interface{}
	idx := 1

	if filter.TermID != nil {
		conditions = append(conditions, fmt.Sprintf("t.term_id = $%d", idx))
		args = append(args, *filter.TermID)
		idx++
	}
	if filter.SectionID != nil {
		conditions = append(conditions, fmt.Sprintf("t.section_id = $%d", idx))
		args = append(args, *filter.SectionID)
		idx++
	}
	if filter.AcademicYearID != nil {
		conditions = append(conditions, fmt.Sprintf("t.academic_year_id = $%d", idx))
		args = append(args, *filter.AcademicYearID)
		idx++
	}
	if filter.IsActive != nil {
		conditions = append(conditions, fmt.Sprintf("t.is_active = $%d", idx))
		args = append(args, *filter.IsActive)
		idx++
	}
	if filter.EffectiveFrom != nil {
		conditions = append(conditions, fmt.Sprintf("t.effective_from >= $%d", idx))
		args = append(args, *filter.EffectiveFrom)
		idx++
	}
	if filter.EffectiveTo != nil {
		conditions = append(conditions, fmt.Sprintf("t.effective_to <= $%d", idx))
		args = append(args, *filter.EffectiveTo)
		idx++
	}
	conditions = append(conditions, "t.deleted_at IS NULL")

	if len(conditions) == 0 {
		return "", args
	}
	return "WHERE " + strings.Join(conditions, " AND "), args
}

// GetActiveTimetableEntriesForDateRange returns all timetable entries that are active
// for any day in the given date range. It joins timetables, slots, and entries,
// respecting effective_from/effective_to and is_active flags.
func (r *timetableRepository) GetActiveTimetableEntriesForDateRange(ctx context.Context, db DBTX, startDate, endDate time.Time) ([]*TimetableEntryWithDetails, error) {
	query := `
		SELECT
			e.entry_id,
			e.slot_id,
			t.timetable_id,
			t.section_id,
			e.subject_id,
			e.teacher_id,
			e.room_id,
			s.day_of_week,
			s.start_time,
			s.end_time,
			t.effective_from,
			t.effective_to,
			t.term_id,
			t.academic_year_id
		FROM academics.timetable_entries e
		INNER JOIN academics.timetable_slots s ON e.slot_id = s.slot_id
		INNER JOIN academics.timetables t ON s.timetable_id = t.timetable_id
		WHERE t.is_active = true
		  AND t.deleted_at IS NULL
		  AND t.effective_from <= $2
		  AND (t.effective_to IS NULL OR t.effective_to >= $1)
		ORDER BY t.section_id, s.day_of_week, s.start_time
	`
	rows, err := db.QueryContext(ctx, query, startDate, endDate)
	if err != nil {
		r.logger.Error("failed to get active timetable entries for date range",
			util.Time("start", startDate),
			util.Time("end", endDate),
			util.ErrorField(err))
		return nil, fmt.Errorf("get active entries: %w", err)
	}
	defer rows.Close()

	var result []*TimetableEntryWithDetails
	for rows.Next() {
		var entry TimetableEntryWithDetails
		var roomID uuid.NullUUID
		var effectiveTo sql.NullTime
		err := rows.Scan(
			&entry.EntryID,
			&entry.SlotID,
			&entry.TimetableID,
			&entry.SectionID,
			&entry.SubjectID,
			&entry.TeacherID,
			&roomID,
			&entry.DayOfWeek,
			&entry.StartTime,
			&entry.EndTime,
			&entry.EffectiveFrom,
			&effectiveTo,
			&entry.TermID,
			&entry.AcademicYearID,
		)
		if err != nil {
			return nil, fmt.Errorf("scan entry: %w", err)
		}
		if roomID.Valid {
			entry.RoomID = &roomID.UUID
		}
		if effectiveTo.Valid {
			entry.EffectiveTo = &effectiveTo.Time
		}
		result = append(result, &entry)
	}
	if err = rows.Err(); err != nil {
		return nil, fmt.Errorf("rows iteration: %w", err)
	}
	return result, nil
}

// ----------------------------------------------------------------------------
// The rest of the file remains unchanged from your original (CreateTimetable, etc.)
// ----------------------------------------------------------------------------

func (r *timetableRepository) CreateTimetable(ctx context.Context, db DBTX, tt *models.Timetable) error {
	query := `
        INSERT INTO academics.timetables (
            academic_year_id, term_id, section_id, version, effective_from, effective_to, is_active,
            created_by, updated_by, created_at, updated_at
        ) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, NOW(), NOW())
        RETURNING timetable_id, created_at, updated_at, version
    `
	err := db.QueryRowContext(ctx, query,
		tt.AcademicYearID, tt.TermID, tt.SectionID, 0, tt.EffectiveFrom, tt.EffectiveTo, tt.IsActive,
		tt.CreatedBy, tt.UpdatedBy,
	).Scan(&tt.TimetableID, &tt.CreatedAt, &tt.UpdatedAt, &tt.Version)
	if err != nil {
		r.logger.Error("failed to create timetable",
			util.String("section_id", tt.SectionID.String()),
			util.ErrorField(err))
		return fmt.Errorf("create timetable: %w", err)
	}
	return nil
}

func (r *timetableRepository) GetTimetableByID(ctx context.Context, db DBTX, id uuid.UUID) (*models.Timetable, error) {
	query := `
        SELECT
            timetable_id, academic_year_id, term_id, section_id, version,
            effective_from, effective_to, is_active,
            created_at, updated_at, created_by, updated_by
        FROM academics.timetables
        WHERE timetable_id = $1 AND deleted_at IS NULL
    `
	row := db.QueryRowContext(ctx, query, id)
	return r.scanTimetable(row)
}

func (r *timetableRepository) ListTimetables(ctx context.Context, db DBTX, filter TimetableFilter, p Pagination, s Sort) ([]*models.Timetable, error) {
	where, args := r.buildTimetableFilter(filter)
	orderBy, err := r.validateSort(s)
	if err != nil {
		return nil, err
	}
	limit, offset := r.validatePagination(p)

	query := fmt.Sprintf(`
        SELECT
            timetable_id, academic_year_id, term_id, section_id, version,
            effective_from, effective_to, is_active,
            created_at, updated_at, created_by, updated_by
        FROM academics.timetables t
        %s
        %s
        LIMIT $%d OFFSET $%d
    `, where, orderBy, len(args)+1, len(args)+2)
	args = append(args, limit, offset)

	rows, err := db.QueryContext(ctx, query, args...)
	if err != nil {
		r.logger.Error("failed to list timetables",
			util.Any("filter", filter),
			util.ErrorField(err))
		return nil, fmt.Errorf("list timetables: %w", err)
	}
	defer rows.Close()

	var result []*models.Timetable
	for rows.Next() {
		tt, err := r.scanTimetable(rows)
		if err != nil {
			return nil, err
		}
		result = append(result, tt)
	}
	if err = rows.Err(); err != nil {
		return nil, fmt.Errorf("rows iteration: %w", err)
	}
	return result, nil
}

func (r *timetableRepository) CountTimetables(ctx context.Context, db DBTX, filter TimetableFilter) (int64, error) {
	where, args := r.buildTimetableFilter(filter)
	query := fmt.Sprintf("SELECT COUNT(*) FROM academics.timetables t %s", where)
	var count int64
	err := db.QueryRowContext(ctx, query, args...).Scan(&count)
	if err != nil {
		r.logger.Error("failed to count timetables",
			util.Any("filter", filter),
			util.ErrorField(err))
		return 0, fmt.Errorf("count timetables: %w", err)
	}
	return count, nil
}

func (r *timetableRepository) UpdateTimetable(ctx context.Context, db DBTX, tt *models.Timetable) error {
	query := `
        UPDATE academics.timetables
        SET
            academic_year_id = $2,
            term_id = $3,
            section_id = $4,
            effective_from = $5,
            effective_to = $6,
            is_active = $7,
            updated_by = $8,
            version = version + 1,
            updated_at = NOW()
        WHERE timetable_id = $1 AND version = $9 AND deleted_at IS NULL
        RETURNING updated_at, version
    `
	err := db.QueryRowContext(ctx, query,
		tt.TimetableID,
		tt.AcademicYearID,
		tt.TermID,
		tt.SectionID,
		tt.EffectiveFrom,
		tt.EffectiveTo,
		tt.IsActive,
		tt.UpdatedBy,
		tt.Version,
	).Scan(&tt.UpdatedAt, &tt.Version)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			var exists bool
			checkQuery := `SELECT EXISTS(SELECT 1 FROM academics.timetables WHERE timetable_id = $1 AND deleted_at IS NULL)`
			_ = db.QueryRowContext(ctx, checkQuery, tt.TimetableID).Scan(&exists)
			if exists {
				return fmt.Errorf("%w: timetable %s version mismatch", ErrVersionConflict, tt.TimetableID)
			}
			return fmt.Errorf("%w: timetable %s", ErrNotFound, tt.TimetableID)
		}
		r.logger.Error("failed to update timetable",
			util.String("id", tt.TimetableID.String()),
			util.ErrorField(err))
		return fmt.Errorf("update timetable: %w", err)
	}
	return nil
}

func (r *timetableRepository) DeleteTimetable(ctx context.Context, db DBTX, id uuid.UUID, deletedBy *uuid.UUID) error {
	query := `UPDATE academics.timetables SET deleted_at = NOW(), updated_by = $2, updated_at = NOW() WHERE timetable_id = $1 AND deleted_at IS NULL`
	result, err := db.ExecContext(ctx, query, id, deletedBy)
	if err != nil {
		r.logger.Error("failed to delete timetable",
			util.String("id", id.String()),
			util.ErrorField(err))
		return fmt.Errorf("delete timetable: %w", err)
	}
	rows, err := result.RowsAffected()
	if err != nil {
		return fmt.Errorf("rows affected: %w", err)
	}
	if rows == 0 {
		return fmt.Errorf("timetable %s not found or already deleted", id)
	}
	return nil
}

func (r *timetableRepository) GetActiveTimetableForSection(ctx context.Context, db DBTX, termID, sectionID uuid.UUID) (*models.Timetable, error) {
	query := `
        SELECT
            timetable_id, academic_year_id, term_id, section_id, version,
            effective_from, effective_to, is_active,
            created_at, updated_at, created_by, updated_by
        FROM academics.timetables
        WHERE term_id = $1 AND section_id = $2 AND is_active = true AND deleted_at IS NULL
        ORDER BY effective_from DESC
        LIMIT 1
    `
	row := db.QueryRowContext(ctx, query, termID, sectionID)
	return r.scanTimetable(row)
}

func (r *timetableRepository) AddSlot(ctx context.Context, db DBTX, slot *models.TimetableSlot) error {
	query := `
        INSERT INTO academics.timetable_slots (
            timetable_id, day_of_week, start_time, end_time, slot_number,
            created_by, created_at, updated_at
        ) VALUES ($1, $2, $3, $4, $5, $6, NOW(), NOW())
        RETURNING slot_id, created_at, updated_at
    `
	err := db.QueryRowContext(ctx, query,
		slot.TimetableID, slot.DayOfWeek, slot.StartTime, slot.EndTime, slot.SlotNumber,
		slot.CreatedBy,
	).Scan(&slot.SlotID, &slot.CreatedAt, &slot.UpdatedAt)
	if err != nil {
		r.logger.Error("failed to add slot",
			util.String("timetable_id", slot.TimetableID.String()),
			util.ErrorField(err))
		return fmt.Errorf("add slot: %w", err)
	}
	return nil
}

func (r *timetableRepository) UpdateSlot(ctx context.Context, db DBTX, slot *models.TimetableSlot) error {
	query := `
        UPDATE academics.timetable_slots
        SET
            day_of_week = $2,
            start_time = $3,
            end_time = $4,
            slot_number = $5,
            updated_at = NOW()
        WHERE slot_id = $1
        RETURNING updated_at
    `
	err := db.QueryRowContext(ctx, query,
		slot.SlotID, slot.DayOfWeek, slot.StartTime, slot.EndTime, slot.SlotNumber,
	).Scan(&slot.UpdatedAt)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return fmt.Errorf("%w: slot %s", ErrNotFound, slot.SlotID)
		}
		r.logger.Error("failed to update slot",
			util.String("slot_id", slot.SlotID.String()),
			util.ErrorField(err))
		return fmt.Errorf("update slot: %w", err)
	}
	return nil
}

func (r *timetableRepository) RemoveSlot(ctx context.Context, db DBTX, slotID uuid.UUID) error {
	query := `DELETE FROM academics.timetable_slots WHERE slot_id = $1`
	result, err := db.ExecContext(ctx, query, slotID)
	if err != nil {
		r.logger.Error("failed to remove slot",
			util.String("slot_id", slotID.String()),
			util.ErrorField(err))
		return fmt.Errorf("remove slot: %w", err)
	}
	rows, err := result.RowsAffected()
	if err != nil {
		return fmt.Errorf("rows affected: %w", err)
	}
	if rows == 0 {
		return fmt.Errorf("slot %s not found", slotID)
	}
	return nil
}

func (r *timetableRepository) GetSlotsForTimetable(ctx context.Context, db DBTX, timetableID uuid.UUID) ([]*models.TimetableSlot, error) {
	query := `
        SELECT
            slot_id, timetable_id, day_of_week, start_time, end_time, slot_number,
            created_at, updated_at, created_by
        FROM academics.timetable_slots
        WHERE timetable_id = $1
        ORDER BY day_of_week, start_time
    `
	rows, err := db.QueryContext(ctx, query, timetableID)
	if err != nil {
		r.logger.Error("failed to get slots for timetable",
			util.String("timetable_id", timetableID.String()),
			util.ErrorField(err))
		return nil, fmt.Errorf("get slots: %w", err)
	}
	defer rows.Close()

	var result []*models.TimetableSlot
	for rows.Next() {
		slot, err := r.scanSlot(rows)
		if err != nil {
			return nil, err
		}
		result = append(result, slot)
	}
	if err = rows.Err(); err != nil {
		return nil, fmt.Errorf("rows iteration: %w", err)
	}
	return result, nil
}

func (r *timetableRepository) GetSlotByID(ctx context.Context, db DBTX, slotID uuid.UUID) (*models.TimetableSlot, error) {
	query := `
        SELECT
            slot_id, timetable_id, day_of_week, start_time, end_time, slot_number,
            created_at, updated_at, created_by
        FROM academics.timetable_slots
        WHERE slot_id = $1
    `
	row := db.QueryRowContext(ctx, query, slotID)
	return r.scanSlot(row)
}

func (r *timetableRepository) AddEntry(ctx context.Context, db DBTX, entry *models.TimetableEntry) error {
	query := `
        INSERT INTO academics.timetable_entries (
            slot_id, subject_id, teacher_id, room_id,
            created_by, created_at, updated_at
        ) VALUES ($1, $2, $3, $4, $5, NOW(), NOW())
        RETURNING entry_id, created_at, updated_at
    `
	err := db.QueryRowContext(ctx, query,
		entry.SlotID, entry.SubjectID, entry.TeacherID, entry.RoomID,
		entry.CreatedBy,
	).Scan(&entry.EntryID, &entry.CreatedAt, &entry.UpdatedAt)
	if err != nil {
		r.logger.Error("failed to add entry",
			util.String("slot_id", entry.SlotID.String()),
			util.ErrorField(err))
		return fmt.Errorf("add entry: %w", err)
	}
	return nil
}

func (r *timetableRepository) UpdateEntry(ctx context.Context, db DBTX, entry *models.TimetableEntry) error {
	query := `
        UPDATE academics.timetable_entries
        SET
            subject_id = $2,
            teacher_id = $3,
            room_id = $4,
            updated_at = NOW()
        WHERE entry_id = $1
        RETURNING updated_at
    `
	err := db.QueryRowContext(ctx, query,
		entry.EntryID, entry.SubjectID, entry.TeacherID, entry.RoomID,
	).Scan(&entry.UpdatedAt)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return fmt.Errorf("%w: entry %s", ErrNotFound, entry.EntryID)
		}
		r.logger.Error("failed to update entry",
			util.String("entry_id", entry.EntryID.String()),
			util.ErrorField(err))
		return fmt.Errorf("update entry: %w", err)
	}
	return nil
}

func (r *timetableRepository) RemoveEntry(ctx context.Context, db DBTX, entryID uuid.UUID) error {
	query := `DELETE FROM academics.timetable_entries WHERE entry_id = $1`
	result, err := db.ExecContext(ctx, query, entryID)
	if err != nil {
		r.logger.Error("failed to remove entry",
			util.String("entry_id", entryID.String()),
			util.ErrorField(err))
		return fmt.Errorf("remove entry: %w", err)
	}
	rows, err := result.RowsAffected()
	if err != nil {
		return fmt.Errorf("rows affected: %w", err)
	}
	if rows == 0 {
		return fmt.Errorf("entry %s not found", entryID)
	}
	return nil
}

func (r *timetableRepository) GetEntriesForSlot(ctx context.Context, db DBTX, slotID uuid.UUID) ([]*models.TimetableEntry, error) {
	query := `
        SELECT
            entry_id, slot_id, subject_id, teacher_id, room_id,
            created_at, updated_at, created_by
        FROM academics.timetable_entries
        WHERE slot_id = $1
    `
	rows, err := db.QueryContext(ctx, query, slotID)
	if err != nil {
		r.logger.Error("failed to get entries for slot",
			util.String("slot_id", slotID.String()),
			util.ErrorField(err))
		return nil, fmt.Errorf("get entries: %w", err)
	}
	defer rows.Close()

	var result []*models.TimetableEntry
	for rows.Next() {
		entry, err := r.scanEntry(rows)
		if err != nil {
			return nil, err
		}
		result = append(result, entry)
	}
	if err = rows.Err(); err != nil {
		return nil, fmt.Errorf("rows iteration: %w", err)
	}
	return result, nil
}

func (r *timetableRepository) GetEntryByID(ctx context.Context, db DBTX, entryID uuid.UUID) (*models.TimetableEntry, error) {
	query := `
        SELECT
            entry_id, slot_id, subject_id, teacher_id, room_id,
            created_at, updated_at, created_by
        FROM academics.timetable_entries
        WHERE entry_id = $1
    `
	row := db.QueryRowContext(ctx, query, entryID)
	return r.scanEntry(row)
}

func (r *timetableRepository) AddChange(ctx context.Context, db DBTX, change *models.TimetableChange) error {
	query := `
        INSERT INTO academics.timetable_changes (
            entry_id, change_date, new_teacher_id, new_room_id, reason,
            created_by, created_at
        ) VALUES ($1, $2, $3, $4, $5, $6, NOW())
        RETURNING change_id, created_at
    `
	err := db.QueryRowContext(ctx, query,
		change.EntryID, change.ChangeDate, change.NewTeacherID, change.NewRoomID, change.Reason,
		change.CreatedBy,
	).Scan(&change.ChangeID, &change.CreatedAt)
	if err != nil {
		r.logger.Error("failed to add change",
			util.String("entry_id", change.EntryID.String()),
			util.ErrorField(err))
		return fmt.Errorf("add change: %w", err)
	}
	return nil
}

func (r *timetableRepository) GetChangesForEntry(ctx context.Context, db DBTX, entryID uuid.UUID) ([]*models.TimetableChange, error) {
	query := `
        SELECT
            change_id, entry_id, change_date, new_teacher_id, new_room_id, reason,
            created_at, created_by
        FROM academics.timetable_changes
        WHERE entry_id = $1
        ORDER BY change_date DESC
    `
	rows, err := db.QueryContext(ctx, query, entryID)
	if err != nil {
		r.logger.Error("failed to get changes for entry",
			util.String("entry_id", entryID.String()),
			util.ErrorField(err))
		return nil, fmt.Errorf("get changes: %w", err)
	}
	defer rows.Close()

	var result []*models.TimetableChange
	for rows.Next() {
		change, err := r.scanChange(rows)
		if err != nil {
			return nil, err
		}
		result = append(result, change)
	}
	if err = rows.Err(); err != nil {
		return nil, fmt.Errorf("rows iteration: %w", err)
	}
	return result, nil
}

// scanning helpers (unchanged)
func (r *timetableRepository) scanTimetable(row scanner) (*models.Timetable, error) {
	var tt models.Timetable
	var effectiveTo sql.NullTime
	var createdBy, updatedBy uuid.NullUUID
	err := row.Scan(
		&tt.TimetableID,
		&tt.AcademicYearID,
		&tt.TermID,
		&tt.SectionID,
		&tt.Version,
		&tt.EffectiveFrom,
		&effectiveTo,
		&tt.IsActive,
		&tt.CreatedAt,
		&tt.UpdatedAt,
		&createdBy,
		&updatedBy,
	)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, nil
		}
		return nil, fmt.Errorf("scan timetable: %w", err)
	}
	if effectiveTo.Valid {
		tt.EffectiveTo = &effectiveTo.Time
	}
	if createdBy.Valid {
		tt.CreatedBy = &createdBy.UUID
	}
	if updatedBy.Valid {
		tt.UpdatedBy = &updatedBy.UUID
	}
	return &tt, nil
}

func (r *timetableRepository) scanSlot(row scanner) (*models.TimetableSlot, error) {
	var slot models.TimetableSlot
	var createdBy uuid.NullUUID
	err := row.Scan(
		&slot.SlotID,
		&slot.TimetableID,
		&slot.DayOfWeek,
		&slot.StartTime,
		&slot.EndTime,
		&slot.SlotNumber,
		&slot.CreatedAt,
		&slot.UpdatedAt,
		&createdBy,
	)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, nil
		}
		return nil, fmt.Errorf("scan slot: %w", err)
	}
	if createdBy.Valid {
		slot.CreatedBy = &createdBy.UUID
	}
	return &slot, nil
}

func (r *timetableRepository) scanEntry(row scanner) (*models.TimetableEntry, error) {
	var entry models.TimetableEntry
	var roomID uuid.NullUUID
	var createdBy uuid.NullUUID
	err := row.Scan(
		&entry.EntryID,
		&entry.SlotID,
		&entry.SubjectID,
		&entry.TeacherID,
		&roomID,
		&entry.CreatedAt,
		&entry.UpdatedAt,
		&createdBy,
	)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, nil
		}
		return nil, fmt.Errorf("scan entry: %w", err)
	}
	if roomID.Valid {
		entry.RoomID = &roomID.UUID
	}
	if createdBy.Valid {
		entry.CreatedBy = &createdBy.UUID
	}
	return &entry, nil
}

func (r *timetableRepository) scanChange(row scanner) (*models.TimetableChange, error) {
	var change models.TimetableChange
	var newTeacherID, newRoomID uuid.NullUUID
	var createdBy uuid.NullUUID
	err := row.Scan(
		&change.ChangeID,
		&change.EntryID,
		&change.ChangeDate,
		&newTeacherID,
		&newRoomID,
		&change.Reason,
		&change.CreatedAt,
		&createdBy,
	)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, nil
		}
		return nil, fmt.Errorf("scan change: %w", err)
	}
	if newTeacherID.Valid {
		change.NewTeacherID = &newTeacherID.UUID
	}
	if newRoomID.Valid {
		change.NewRoomID = &newRoomID.UUID
	}
	if createdBy.Valid {
		change.CreatedBy = &createdBy.UUID
	}
	return &change, nil
}

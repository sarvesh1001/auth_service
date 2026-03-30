package service

import (
	"context"
	"fmt"
	"time"

	"github.com/google/uuid"
	"go.uber.org/zap"

	"auth-service/internal/academics/models"
	"auth-service/internal/academics/repository"
	"auth-service/internal/client"
)

// ============================================================================
// Service interface and struct
// ============================================================================

type TimetableService interface {
	// Timetable operations
	CreateTimetable(ctx context.Context, req CreateTimetableRequest, idempotencyKey string) (*models.Timetable, error)
	GetTimetableByID(ctx context.Context, id uuid.UUID) (*models.Timetable, error)
	ListTimetables(ctx context.Context, filter repository.TimetableFilter, pagination repository.Pagination, sort repository.Sort) ([]*models.Timetable, error)
	UpdateTimetable(ctx context.Context, req UpdateTimetableRequest) (*models.Timetable, error)
	DeleteTimetable(ctx context.Context, id uuid.UUID, deletedBy *uuid.UUID) error
	GetActiveTimetableForSection(ctx context.Context, termID, sectionID uuid.UUID) (*models.Timetable, error)

	// Slot operations
	AddSlot(ctx context.Context, req AddSlotRequest) (*models.TimetableSlot, error)
	UpdateSlot(ctx context.Context, req UpdateSlotRequest) (*models.TimetableSlot, error)
	RemoveSlot(ctx context.Context, slotID uuid.UUID, deletedBy *uuid.UUID) error
	GetSlotsForTimetable(ctx context.Context, timetableID uuid.UUID) ([]*models.TimetableSlot, error)

	// Entry operations
	AddEntry(ctx context.Context, req AddEntryRequest) (*models.TimetableEntry, error)
	UpdateEntry(ctx context.Context, req UpdateEntryRequest) (*models.TimetableEntry, error)
	RemoveEntry(ctx context.Context, entryID uuid.UUID, deletedBy *uuid.UUID) error
	GetEntriesForSlot(ctx context.Context, slotID uuid.UUID) ([]*models.TimetableEntry, error)

	// Change tracking
	AddChange(ctx context.Context, req AddChangeRequest) (*models.TimetableChange, error)
	GetChangesForEntry(ctx context.Context, entryID uuid.UUID) ([]*models.TimetableChange, error)
}

type timetableService struct {
	repo             repository.TimetableRepository
	sectionRepo      repository.SectionRepository
	subjectRepo      repository.SubjectRepository
	teacherRepo      repository.TeacherRepository
	roomRepo         repository.RoomRepository
	idempotencyStore IdempotencyStore
	auditLogger      AuditLogger
	outboxStore      OutboxStore
	eventPublisher   EventPublisher
	pgClient         *client.PostgresClient
	logger           *zap.Logger
	notificationSvc  NotificationService
}

func NewTimetableService(
	repo repository.TimetableRepository,
	sectionRepo repository.SectionRepository,
	subjectRepo repository.SubjectRepository,
	teacherRepo repository.TeacherRepository,
	roomRepo repository.RoomRepository,
	idempotencyStore IdempotencyStore,
	auditLogger AuditLogger,
	outboxStore OutboxStore,
	eventPublisher EventPublisher,
	pgClient *client.PostgresClient,
	logger *zap.Logger,
	notificationSvc NotificationService,
) TimetableService {
	return &timetableService{
		repo:             repo,
		sectionRepo:      sectionRepo,
		subjectRepo:      subjectRepo,
		teacherRepo:      teacherRepo,
		roomRepo:         roomRepo,
		idempotencyStore: idempotencyStore,
		auditLogger:      auditLogger,
		outboxStore:      outboxStore,
		eventPublisher:   eventPublisher,
		pgClient:         pgClient,
		logger:           logger.Named("timetable_service"),
		notificationSvc:  notificationSvc,
	}
}

// ============================================================================
// Request DTOs
// ============================================================================

type CreateTimetableRequest struct {
	AcademicYearID uuid.UUID  `json:"academic_year_id"`
	TermID         uuid.UUID  `json:"term_id"`
	SectionID      uuid.UUID  `json:"section_id"`
	EffectiveFrom  time.Time  `json:"effective_from"`
	EffectiveTo    *time.Time `json:"effective_to,omitempty"`
	IsActive       bool       `json:"is_active"`
	CreatedBy      *uuid.UUID `json:"created_by,omitempty"`
	UpdatedBy      *uuid.UUID `json:"updated_by,omitempty"`
}

type UpdateTimetableRequest struct {
	TimetableID    uuid.UUID  `json:"timetable_id"`
	AcademicYearID uuid.UUID  `json:"academic_year_id"`
	TermID         uuid.UUID  `json:"term_id"`
	SectionID      uuid.UUID  `json:"section_id"`
	EffectiveFrom  time.Time  `json:"effective_from"`
	EffectiveTo    *time.Time `json:"effective_to,omitempty"`
	IsActive       bool       `json:"is_active"`
	UpdatedBy      *uuid.UUID `json:"updated_by,omitempty"`
}

type AddSlotRequest struct {
	TimetableID uuid.UUID  `json:"timetable_id"`
	DayOfWeek   int        `json:"day_of_week"` // 0-6 (Monday-Sunday)
	StartTime   time.Time  `json:"start_time"`
	EndTime     time.Time  `json:"end_time"`
	SlotNumber  int        `json:"slot_number,omitempty"`
	CreatedBy   *uuid.UUID `json:"created_by,omitempty"`
}

type UpdateSlotRequest struct {
	SlotID     uuid.UUID  `json:"slot_id"`
	DayOfWeek  int        `json:"day_of_week"`
	StartTime  time.Time  `json:"start_time"`
	EndTime    time.Time  `json:"end_time"`
	SlotNumber int        `json:"slot_number,omitempty"`
	UpdatedBy  *uuid.UUID `json:"updated_by,omitempty"`
}

type AddEntryRequest struct {
	SlotID    uuid.UUID  `json:"slot_id"`
	SubjectID uuid.UUID  `json:"subject_id"`
	TeacherID uuid.UUID  `json:"teacher_id"`
	RoomID    *uuid.UUID `json:"room_id,omitempty"`
	CreatedBy *uuid.UUID `json:"created_by,omitempty"`
}

type UpdateEntryRequest struct {
	EntryID   uuid.UUID  `json:"entry_id"`
	SubjectID uuid.UUID  `json:"subject_id"`
	TeacherID uuid.UUID  `json:"teacher_id"`
	RoomID    *uuid.UUID `json:"room_id,omitempty"`
	UpdatedBy *uuid.UUID `json:"updated_by,omitempty"`
}

type AddChangeRequest struct {
	EntryID      uuid.UUID  `json:"entry_id"`
	ChangeDate   time.Time  `json:"change_date"`
	NewTeacherID *uuid.UUID `json:"new_teacher_id,omitempty"`
	NewRoomID    *uuid.UUID `json:"new_room_id,omitempty"`
	Reason       string     `json:"reason,omitempty"`
	CreatedBy    *uuid.UUID `json:"created_by,omitempty"`
}

// ============================================================================
// Validation helpers
// ============================================================================

func (s *timetableService) validateTimetableInput(req CreateTimetableRequest) error {
	if req.AcademicYearID == uuid.Nil {
		return fmt.Errorf("%w: academic_year_id is required", ErrInvalidInput)
	}
	if req.TermID == uuid.Nil {
		return fmt.Errorf("%w: term_id is required", ErrInvalidInput)
	}
	if req.SectionID == uuid.Nil {
		return fmt.Errorf("%w: section_id is required", ErrInvalidInput)
	}
	if req.EffectiveFrom.IsZero() {
		return fmt.Errorf("%w: effective_from is required", ErrInvalidInput)
	}
	if req.EffectiveTo != nil && req.EffectiveTo.Before(req.EffectiveFrom) {
		return fmt.Errorf("%w: effective_to cannot be before effective_from", ErrInvalidInput)
	}
	return nil
}

func (s *timetableService) validateSlotInput(req AddSlotRequest) error {
	if req.TimetableID == uuid.Nil {
		return fmt.Errorf("%w: timetable_id is required", ErrInvalidInput)
	}
	if req.DayOfWeek < 0 || req.DayOfWeek > 6 {
		return fmt.Errorf("%w: day_of_week must be 0-6", ErrInvalidInput)
	}
	if req.StartTime.IsZero() || req.EndTime.IsZero() {
		return fmt.Errorf("%w: start_time and end_time are required", ErrInvalidInput)
	}
	if req.EndTime.Before(req.StartTime) {
		return fmt.Errorf("%w: end_time cannot be before start_time", ErrInvalidInput)
	}
	return nil
}

func (s *timetableService) validateEntryInput(req AddEntryRequest) error {
	if req.SlotID == uuid.Nil {
		return fmt.Errorf("%w: slot_id is required", ErrInvalidInput)
	}
	if req.SubjectID == uuid.Nil {
		return fmt.Errorf("%w: subject_id is required", ErrInvalidInput)
	}
	if req.TeacherID == uuid.Nil {
		return fmt.Errorf("%w: teacher_id is required", ErrInvalidInput)
	}
	return nil
}

// ============================================================================
// Timetable CRUD
// ============================================================================

func (s *timetableService) CreateTimetable(ctx context.Context, req CreateTimetableRequest, idempotencyKey string) (*models.Timetable, error) {
	logger := s.logger.With(
		zap.String("method", "CreateTimetable"),
		zap.String("section_id", req.SectionID.String()),
		zap.String("idempotency_key", idempotencyKey),
	)

	if err := s.validateTimetableInput(req); err != nil {
		return nil, err
	}

	tx, err := s.pgClient.BeginTx(ctx, nil)
	if err != nil {
		return nil, fmt.Errorf("begin tx: %w", err)
	}
	defer tx.Rollback()

	if idempotencyKey != "" {
		exists, err := s.idempotencyStore.Exists(ctx, tx, idempotencyKey)
		if err != nil {
			return nil, fmt.Errorf("idempotency check: %w", err)
		}
		if exists {
			var tt models.Timetable
			if err := s.idempotencyStore.Get(ctx, tx, idempotencyKey, &tt); err != nil {
				return nil, fmt.Errorf("failed to retrieve idempotent response: %w", err)
			}
			logger.Info("returning idempotent response")
			return &tt, nil
		}
	}

	// Validate section existence and permissions
	section, err := s.sectionRepo.GetByID(ctx, tx, req.SectionID)
	if err != nil {
		return nil, err
	}
	if section == nil {
		return nil, fmt.Errorf("%w: section %s", ErrNotFound, req.SectionID)
	}

	// Check if another active timetable exists for the same section/term (optional)
	existing, err := s.repo.GetActiveTimetableForSection(ctx, tx, req.TermID, req.SectionID)
	if err != nil && err != repository.ErrNotFound {
		return nil, err
	}
	if existing != nil && req.IsActive {
		return nil, fmt.Errorf("%w: an active timetable already exists for section %s in term %s", ErrDuplicate, req.SectionID, req.TermID)
	}

	tt := &models.Timetable{
		AcademicYearID: req.AcademicYearID,
		TermID:         req.TermID,
		SectionID:      req.SectionID,
		EffectiveFrom:  req.EffectiveFrom,
		EffectiveTo:    req.EffectiveTo,
		IsActive:       req.IsActive,
		CreatedBy:      req.CreatedBy,
		UpdatedBy:      req.UpdatedBy,
	}

	if err := s.repo.CreateTimetable(ctx, tx, tt); err != nil {
		return nil, err
	}

	if idempotencyKey != "" {
		if err := s.idempotencyStore.Store(ctx, tx, idempotencyKey, tt); err != nil {
			logger.Error("failed to store idempotency key", zap.Error(err))
			return nil, fmt.Errorf("failed to store idempotency key: %w", err)
		}
	}

	if err := s.auditLogger.Log(ctx, tx, "TIMETABLE_CREATE", tt.TimetableID, nil, tt, req.CreatedBy); err != nil {
		logger.Error("audit log failed", zap.Error(err))
	}

	if err := s.outboxStore.Store(ctx, tx, string(EventTimetableCreated), tt); err != nil {
		logger.Error("failed to store outbox event", zap.Error(err))
		return nil, fmt.Errorf("failed to store outbox event: %w", err)
	}

	if err := tx.Commit(); err != nil {
		return nil, fmt.Errorf("commit tx: %w", err)
	}

	logger.Info("timetable created", zap.String("id", tt.TimetableID.String()))

	// Send notification (async)
	go s.sendTimetableNotification(ctx, tt, "created", req.CreatedBy)

	return tt, nil
}

func (s *timetableService) GetTimetableByID(ctx context.Context, id uuid.UUID) (*models.Timetable, error) {
	tt, err := s.repo.GetTimetableByID(ctx, s.pgClient.DB, id)
	if err != nil {
		return nil, err
	}
	if tt == nil {
		return nil, fmt.Errorf("%w: timetable %s", ErrNotFound, id)
	}
	return tt, nil
}

func (s *timetableService) ListTimetables(ctx context.Context, filter repository.TimetableFilter, pagination repository.Pagination, sort repository.Sort) ([]*models.Timetable, error) {
	return s.repo.ListTimetables(ctx, s.pgClient.DB, filter, pagination, sort)
}

func (s *timetableService) UpdateTimetable(ctx context.Context, req UpdateTimetableRequest) (*models.Timetable, error) {
	logger := s.logger.With(zap.String("method", "UpdateTimetable"), zap.String("timetable_id", req.TimetableID.String()))

	if req.TimetableID == uuid.Nil {
		return nil, fmt.Errorf("%w: timetable_id is required", ErrInvalidInput)
	}

	tx, err := s.pgClient.BeginTx(ctx, nil)
	if err != nil {
		return nil, fmt.Errorf("begin tx: %w", err)
	}
	defer tx.Rollback()

	tt, err := s.repo.GetTimetableByID(ctx, tx, req.TimetableID)
	if err != nil {
		return nil, err
	}
	if tt == nil {
		return nil, fmt.Errorf("%w: timetable %s", ErrNotFound, req.TimetableID)
	}

	oldTT := *tt
	tt.AcademicYearID = req.AcademicYearID
	tt.TermID = req.TermID
	tt.SectionID = req.SectionID
	tt.EffectiveFrom = req.EffectiveFrom
	tt.EffectiveTo = req.EffectiveTo
	tt.IsActive = req.IsActive
	tt.UpdatedBy = req.UpdatedBy

	if err := s.repo.UpdateTimetable(ctx, tx, tt); err != nil {
		return nil, err
	}

	if err := s.auditLogger.Log(ctx, tx, "TIMETABLE_UPDATE", req.TimetableID, oldTT, tt, req.UpdatedBy); err != nil {
		logger.Error("audit log failed", zap.Error(err))
	}

	if err := s.outboxStore.Store(ctx, tx, string(EventTimetableUpdated), map[string]interface{}{
		"old": oldTT,
		"new": tt,
	}); err != nil {
		logger.Error("failed to store outbox event", zap.Error(err))
		return nil, fmt.Errorf("failed to store outbox event: %w", err)
	}

	if err := tx.Commit(); err != nil {
		return nil, fmt.Errorf("commit tx: %w", err)
	}

	logger.Info("timetable updated")

	go s.sendTimetableNotification(ctx, tt, "updated", req.UpdatedBy)

	return tt, nil
}

func (s *timetableService) DeleteTimetable(ctx context.Context, id uuid.UUID, deletedBy *uuid.UUID) error {
	logger := s.logger.With(zap.String("method", "DeleteTimetable"), zap.String("timetable_id", id.String()))

	tx, err := s.pgClient.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("begin tx: %w", err)
	}
	defer tx.Rollback()

	tt, _ := s.repo.GetTimetableByID(ctx, tx, id)

	if err := s.repo.DeleteTimetable(ctx, tx, id, deletedBy); err != nil {
		return err
	}

	if err := s.auditLogger.Log(ctx, tx, "TIMETABLE_DELETE", id, nil, nil, deletedBy); err != nil {
		logger.Error("audit log failed", zap.Error(err))
	}

	if err := s.outboxStore.Store(ctx, tx, string(EventTimetableDeleted), map[string]interface{}{
		"timetable_id": id,
		"deleted_by":   deletedBy,
	}); err != nil {
		logger.Error("failed to store outbox event", zap.Error(err))
		return fmt.Errorf("failed to store outbox event: %w", err)
	}

	if err := tx.Commit(); err != nil {
		return fmt.Errorf("commit tx: %w", err)
	}

	logger.Info("timetable deleted")

	if tt != nil {
		go s.sendTimetableNotification(ctx, tt, "deleted", deletedBy)
	}
	return nil
}

func (s *timetableService) GetActiveTimetableForSection(ctx context.Context, termID, sectionID uuid.UUID) (*models.Timetable, error) {
	return s.repo.GetActiveTimetableForSection(ctx, s.pgClient.DB, termID, sectionID)
}

// ============================================================================
// Slot operations
// ============================================================================

func (s *timetableService) AddSlot(ctx context.Context, req AddSlotRequest) (*models.TimetableSlot, error) {
	logger := s.logger.With(
		zap.String("method", "AddSlot"),
		zap.String("timetable_id", req.TimetableID.String()),
	)

	if err := s.validateSlotInput(req); err != nil {
		return nil, err
	}

	tx, err := s.pgClient.BeginTx(ctx, nil)
	if err != nil {
		return nil, fmt.Errorf("begin tx: %w", err)
	}
	defer tx.Rollback()

	tt, err := s.repo.GetTimetableByID(ctx, tx, req.TimetableID)
	if err != nil {
		return nil, err
	}
	if tt == nil {
		return nil, fmt.Errorf("%w: timetable %s", ErrNotFound, req.TimetableID)
	}

	slot := &models.TimetableSlot{
		TimetableID: req.TimetableID,
		DayOfWeek:   req.DayOfWeek,
		StartTime:   req.StartTime,
		EndTime:     req.EndTime,
		SlotNumber:  req.SlotNumber,
		CreatedBy:   req.CreatedBy,
	}

	if err := s.repo.AddSlot(ctx, tx, slot); err != nil {
		return nil, err
	}

	if err := s.auditLogger.Log(ctx, tx, "TIMETABLE_SLOT_ADD", slot.SlotID, nil, slot, req.CreatedBy); err != nil {
		logger.Error("audit log failed", zap.Error(err))
	}

	if err := s.outboxStore.Store(ctx, tx, string(EventTimetableSlotAdded), slot); err != nil {
		logger.Error("failed to store outbox event", zap.Error(err))
		return nil, fmt.Errorf("failed to store outbox event: %w", err)
	}

	if err := tx.Commit(); err != nil {
		return nil, fmt.Errorf("commit tx: %w", err)
	}

	logger.Info("slot added", zap.String("slot_id", slot.SlotID.String()))

	go s.sendSlotNotification(ctx, slot, "added", req.CreatedBy)

	return slot, nil
}

func (s *timetableService) UpdateSlot(ctx context.Context, req UpdateSlotRequest) (*models.TimetableSlot, error) {
	logger := s.logger.With(zap.String("method", "UpdateSlot"), zap.String("slot_id", req.SlotID.String()))

	if req.SlotID == uuid.Nil {
		return nil, fmt.Errorf("%w: slot_id is required", ErrInvalidInput)
	}

	tx, err := s.pgClient.BeginTx(ctx, nil)
	if err != nil {
		return nil, fmt.Errorf("begin tx: %w", err)
	}
	defer tx.Rollback()

	slot, err := s.repo.GetSlotByID(ctx, tx, req.SlotID)
	if err != nil {
		return nil, err
	}
	if slot == nil {
		return nil, fmt.Errorf("%w: slot %s", ErrNotFound, req.SlotID)
	}

	oldSlot := *slot
	slot.DayOfWeek = req.DayOfWeek
	slot.StartTime = req.StartTime
	slot.EndTime = req.EndTime
	slot.SlotNumber = req.SlotNumber

	if err := s.repo.UpdateSlot(ctx, tx, slot); err != nil {
		return nil, err
	}

	if err := s.auditLogger.Log(ctx, tx, "TIMETABLE_SLOT_UPDATE", req.SlotID, oldSlot, slot, req.UpdatedBy); err != nil {
		logger.Error("audit log failed", zap.Error(err))
	}

	if err := s.outboxStore.Store(ctx, tx, string(EventTimetableSlotUpdated), map[string]interface{}{
		"old": oldSlot,
		"new": slot,
	}); err != nil {
		logger.Error("failed to store outbox event", zap.Error(err))
		return nil, fmt.Errorf("failed to store outbox event: %w", err)
	}

	if err := tx.Commit(); err != nil {
		return nil, fmt.Errorf("commit tx: %w", err)
	}

	logger.Info("slot updated")

	go s.sendSlotNotification(ctx, slot, "updated", req.UpdatedBy)

	return slot, nil
}

func (s *timetableService) RemoveSlot(ctx context.Context, slotID uuid.UUID, deletedBy *uuid.UUID) error {
	logger := s.logger.With(zap.String("method", "RemoveSlot"), zap.String("slot_id", slotID.String()))

	tx, err := s.pgClient.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("begin tx: %w", err)
	}
	defer tx.Rollback()

	slot, _ := s.repo.GetSlotByID(ctx, tx, slotID)

	if err := s.repo.RemoveSlot(ctx, tx, slotID); err != nil {
		return err
	}

	if err := s.auditLogger.Log(ctx, tx, "TIMETABLE_SLOT_DELETE", slotID, nil, nil, deletedBy); err != nil {
		logger.Error("audit log failed", zap.Error(err))
	}

	if err := s.outboxStore.Store(ctx, tx, string(EventTimetableSlotDeleted), map[string]interface{}{
		"slot_id":    slotID,
		"deleted_by": deletedBy,
	}); err != nil {
		logger.Error("failed to store outbox event", zap.Error(err))
		return fmt.Errorf("failed to store outbox event: %w", err)
	}

	if err := tx.Commit(); err != nil {
		return fmt.Errorf("commit tx: %w", err)
	}

	logger.Info("slot removed")

	if slot != nil {
		go s.sendSlotNotification(ctx, slot, "deleted", deletedBy)
	}
	return nil
}

func (s *timetableService) GetSlotsForTimetable(ctx context.Context, timetableID uuid.UUID) ([]*models.TimetableSlot, error) {
	return s.repo.GetSlotsForTimetable(ctx, s.pgClient.DB, timetableID)
}

// ============================================================================
// Entry operations
// ============================================================================

func (s *timetableService) AddEntry(ctx context.Context, req AddEntryRequest) (*models.TimetableEntry, error) {
	logger := s.logger.With(
		zap.String("method", "AddEntry"),
		zap.String("slot_id", req.SlotID.String()),
	)

	if err := s.validateEntryInput(req); err != nil {
		return nil, err
	}

	tx, err := s.pgClient.BeginTx(ctx, nil)
	if err != nil {
		return nil, fmt.Errorf("begin tx: %w", err)
	}
	defer tx.Rollback()

	slot, err := s.repo.GetSlotByID(ctx, tx, req.SlotID)
	if err != nil {
		return nil, err
	}
	if slot == nil {
		return nil, fmt.Errorf("%w: slot %s", ErrNotFound, req.SlotID)
	}

	// Validate subject and teacher exist and are active
	subject, err := s.subjectRepo.GetByID(ctx, tx, req.SubjectID)
	if err != nil {
		return nil, err
	}
	if subject == nil {
		return nil, fmt.Errorf("%w: subject %s", ErrNotFound, req.SubjectID)
	}
	if !subject.IsActive {
		return nil, fmt.Errorf("subject %s is inactive", req.SubjectID)
	}

	teacher, err := s.teacherRepo.GetByID(ctx, tx, req.TeacherID)
	if err != nil {
		return nil, err
	}
	if teacher == nil {
		return nil, fmt.Errorf("%w: teacher %s", ErrNotFound, req.TeacherID)
	}
	if teacher.Status != models.TeacherActive {
		return nil, fmt.Errorf("teacher %s is not active", req.TeacherID)
	}

	// Validate room if provided
	if req.RoomID != nil && *req.RoomID != uuid.Nil {
		room, err := s.roomRepo.GetByID(ctx, tx, *req.RoomID)
		if err != nil {
			return nil, err
		}
		if room == nil {
			return nil, fmt.Errorf("%w: room %s", ErrNotFound, *req.RoomID)
		}
		if !room.IsActive {
			return nil, fmt.Errorf("room %s is inactive", *req.RoomID)
		}
	}

	entry := &models.TimetableEntry{
		SlotID:    req.SlotID,
		SubjectID: req.SubjectID,
		TeacherID: req.TeacherID,
		RoomID:    req.RoomID,
		CreatedBy: req.CreatedBy,
	}

	if err := s.repo.AddEntry(ctx, tx, entry); err != nil {
		return nil, err
	}

	if err := s.auditLogger.Log(ctx, tx, "TIMETABLE_ENTRY_ADD", entry.EntryID, nil, entry, req.CreatedBy); err != nil {
		logger.Error("audit log failed", zap.Error(err))
	}

	if err := s.outboxStore.Store(ctx, tx, string(EventTimetableEntryAdded), entry); err != nil {
		logger.Error("failed to store outbox event", zap.Error(err))
		return nil, fmt.Errorf("failed to store outbox event: %w", err)
	}

	if err := tx.Commit(); err != nil {
		return nil, fmt.Errorf("commit tx: %w", err)
	}

	logger.Info("entry added", zap.String("entry_id", entry.EntryID.String()))

	go s.sendEntryNotification(ctx, entry, "added", req.CreatedBy)

	return entry, nil
}

func (s *timetableService) UpdateEntry(ctx context.Context, req UpdateEntryRequest) (*models.TimetableEntry, error) {
	logger := s.logger.With(zap.String("method", "UpdateEntry"), zap.String("entry_id", req.EntryID.String()))

	if req.EntryID == uuid.Nil {
		return nil, fmt.Errorf("%w: entry_id is required", ErrInvalidInput)
	}

	tx, err := s.pgClient.BeginTx(ctx, nil)
	if err != nil {
		return nil, fmt.Errorf("begin tx: %w", err)
	}
	defer tx.Rollback()

	entry, err := s.repo.GetEntryByID(ctx, tx, req.EntryID)
	if err != nil {
		return nil, err
	}
	if entry == nil {
		return nil, fmt.Errorf("%w: entry %s", ErrNotFound, req.EntryID)
	}

	oldEntry := *entry

	// Validate new subject/teacher/room as before
	subject, err := s.subjectRepo.GetByID(ctx, tx, req.SubjectID)
	if err != nil {
		return nil, err
	}
	if subject == nil {
		return nil, fmt.Errorf("%w: subject %s", ErrNotFound, req.SubjectID)
	}
	if !subject.IsActive {
		return nil, fmt.Errorf("subject %s is inactive", req.SubjectID)
	}

	teacher, err := s.teacherRepo.GetByID(ctx, tx, req.TeacherID)
	if err != nil {
		return nil, err
	}
	if teacher == nil {
		return nil, fmt.Errorf("%w: teacher %s", ErrNotFound, req.TeacherID)
	}
	if teacher.Status != models.TeacherActive {
		return nil, fmt.Errorf("teacher %s is not active", req.TeacherID)
	}

	if req.RoomID != nil && *req.RoomID != uuid.Nil {
		room, err := s.roomRepo.GetByID(ctx, tx, *req.RoomID)
		if err != nil {
			return nil, err
		}
		if room == nil {
			return nil, fmt.Errorf("%w: room %s", ErrNotFound, *req.RoomID)
		}
		if !room.IsActive {
			return nil, fmt.Errorf("room %s is inactive", *req.RoomID)
		}
	}

	entry.SubjectID = req.SubjectID
	entry.TeacherID = req.TeacherID
	entry.RoomID = req.RoomID

	if err := s.repo.UpdateEntry(ctx, tx, entry); err != nil {
		return nil, err
	}

	if err := s.auditLogger.Log(ctx, tx, "TIMETABLE_ENTRY_UPDATE", req.EntryID, oldEntry, entry, req.UpdatedBy); err != nil {
		logger.Error("audit log failed", zap.Error(err))
	}

	if err := s.outboxStore.Store(ctx, tx, string(EventTimetableEntryUpdated), map[string]interface{}{
		"old": oldEntry,
		"new": entry,
	}); err != nil {
		logger.Error("failed to store outbox event", zap.Error(err))
		return nil, fmt.Errorf("failed to store outbox event: %w", err)
	}

	if err := tx.Commit(); err != nil {
		return nil, fmt.Errorf("commit tx: %w", err)
	}

	logger.Info("entry updated")

	go s.sendEntryNotification(ctx, entry, "updated", req.UpdatedBy)

	return entry, nil
}

func (s *timetableService) RemoveEntry(ctx context.Context, entryID uuid.UUID, deletedBy *uuid.UUID) error {
	logger := s.logger.With(zap.String("method", "RemoveEntry"), zap.String("entry_id", entryID.String()))

	tx, err := s.pgClient.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("begin tx: %w", err)
	}
	defer tx.Rollback()

	entry, _ := s.repo.GetEntryByID(ctx, tx, entryID)

	if err := s.repo.RemoveEntry(ctx, tx, entryID); err != nil {
		return err
	}

	if err := s.auditLogger.Log(ctx, tx, "TIMETABLE_ENTRY_DELETE", entryID, nil, nil, deletedBy); err != nil {
		logger.Error("audit log failed", zap.Error(err))
	}

	if err := s.outboxStore.Store(ctx, tx, string(EventTimetableEntryDeleted), map[string]interface{}{
		"entry_id":   entryID,
		"deleted_by": deletedBy,
	}); err != nil {
		logger.Error("failed to store outbox event", zap.Error(err))
		return fmt.Errorf("failed to store outbox event: %w", err)
	}

	if err := tx.Commit(); err != nil {
		return fmt.Errorf("commit tx: %w", err)
	}

	logger.Info("entry removed")

	if entry != nil {
		go s.sendEntryNotification(ctx, entry, "deleted", deletedBy)
	}
	return nil
}

func (s *timetableService) GetEntriesForSlot(ctx context.Context, slotID uuid.UUID) ([]*models.TimetableEntry, error) {
	return s.repo.GetEntriesForSlot(ctx, s.pgClient.DB, slotID)
}

// ============================================================================
// Change tracking
// ============================================================================

func (s *timetableService) AddChange(ctx context.Context, req AddChangeRequest) (*models.TimetableChange, error) {
	logger := s.logger.With(zap.String("method", "AddChange"), zap.String("entry_id", req.EntryID.String()))

	if req.EntryID == uuid.Nil {
		return nil, fmt.Errorf("%w: entry_id is required", ErrInvalidInput)
	}
	if req.ChangeDate.IsZero() {
		req.ChangeDate = time.Now().UTC()
	}

	tx, err := s.pgClient.BeginTx(ctx, nil)
	if err != nil {
		return nil, fmt.Errorf("begin tx: %w", err)
	}
	defer tx.Rollback()

	entry, err := s.repo.GetEntryByID(ctx, tx, req.EntryID)
	if err != nil {
		return nil, err
	}
	if entry == nil {
		return nil, fmt.Errorf("%w: entry %s", ErrNotFound, req.EntryID)
	}

	change := &models.TimetableChange{
		EntryID:      req.EntryID,
		ChangeDate:   req.ChangeDate,
		NewTeacherID: req.NewTeacherID,
		NewRoomID:    req.NewRoomID,
		Reason:       req.Reason,
		CreatedBy:    req.CreatedBy,
	}

	if err := s.repo.AddChange(ctx, tx, change); err != nil {
		return nil, err
	}

	if err := s.auditLogger.Log(ctx, tx, "TIMETABLE_CHANGE_ADD", change.ChangeID, nil, change, req.CreatedBy); err != nil {
		logger.Error("audit log failed", zap.Error(err))
	}

	if err := s.outboxStore.Store(ctx, tx, string(EventTimetableChangeAdded), change); err != nil {
		logger.Error("failed to store outbox event", zap.Error(err))
		return nil, fmt.Errorf("failed to store outbox event: %w", err)
	}

	if err := tx.Commit(); err != nil {
		return nil, fmt.Errorf("commit tx: %w", err)
	}

	logger.Info("change added", zap.String("change_id", change.ChangeID.String()))

	go s.sendChangeNotification(ctx, change, req.CreatedBy)

	return change, nil
}

func (s *timetableService) GetChangesForEntry(ctx context.Context, entryID uuid.UUID) ([]*models.TimetableChange, error) {
	return s.repo.GetChangesForEntry(ctx, s.pgClient.DB, entryID)
}

// ============================================================================
// Notification helpers
// ============================================================================

func (s *timetableService) sendTimetableNotification(ctx context.Context, tt *models.Timetable, action string, actor *uuid.UUID) {
	// Fetch section to get course/term info (optional)
	section, err := s.sectionRepo.GetByID(ctx, nil, tt.SectionID)
	if err != nil || section == nil {
		s.logger.Error("failed to fetch section for notification", zap.Error(err))
		return
	}

	// Target all teachers assigned to this section? Or just the class teacher?
	// For simplicity, we target the created_by user (admin) and the class teacher.
	// In a real system you would target all teachers and students in the section.

	title := fmt.Sprintf("Timetable %s", action)
	message := fmt.Sprintf("The timetable for section %s has been %s.", section.Name, action)

	targets := []NotificationTargetInput{}

	if actor != nil && *actor != uuid.Nil {
		targets = append(targets, NotificationTargetInput{
			TargetType:     models.TargetUser,
			TargetEntityID: *actor,
		})
	}

	// Optionally fetch class teacher for the section and notify them
	teachers, err := s.teacherRepo.GetTeachersBySection(ctx, nil, tt.SectionID)
	if err == nil {
		for _, t := range teachers {
			if t.Status == models.TeacherActive {
				targets = append(targets, NotificationTargetInput{
					TargetType:     models.TargetUser,
					TargetEntityID: t.UserID,
				})
			}
		}
	}

	if len(targets) == 0 {
		return
	}

	notifReq := CreateNotificationRequest{
		CompanyID: section.CourseID, // Not ideal, but companyID is needed. We can get company from section's course.
		Title:     title,
		Message:   message,
		Type:      models.NotificationTypeInfo,
		Priority:  models.PriorityNormal,
		Targets:   targets,
		CreatedBy: actor,
	}
	// Use a new context with timeout to avoid blocking
	notifyCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if _, err := s.notificationSvc.Create(notifyCtx, notifReq, fmt.Sprintf("timetable.%s:%s", action, tt.TimetableID.String())); err != nil {
		s.logger.Error("failed to create timetable notification", zap.Error(err))
	}
}

func (s *timetableService) sendSlotNotification(ctx context.Context, slot *models.TimetableSlot, action string, actor *uuid.UUID) {
	tt, err := s.repo.GetTimetableByID(ctx, nil, slot.TimetableID)
	if err != nil || tt == nil {
		return
	}
	section, err := s.sectionRepo.GetByID(ctx, nil, tt.SectionID)
	if err != nil || section == nil {
		return
	}

	title := fmt.Sprintf("Timetable slot %s", action)
	message := fmt.Sprintf("A slot on day %d from %s to %s has been %s in section %s.",
		slot.DayOfWeek, slot.StartTime.Format("15:04"), slot.EndTime.Format("15:04"), action, section.Name)

	targets := []NotificationTargetInput{}
	if actor != nil && *actor != uuid.Nil {
		targets = append(targets, NotificationTargetInput{
			TargetType:     models.TargetUser,
			TargetEntityID: *actor,
		})
	}
	// Notify class teachers etc. as above...

	if len(targets) == 0 {
		return
	}

	notifReq := CreateNotificationRequest{
		CompanyID: section.CourseID, // Again, need proper company
		Title:     title,
		Message:   message,
		Type:      models.NotificationTypeInfo,
		Priority:  models.PriorityNormal,
		Targets:   targets,
		CreatedBy: actor,
	}
	notifyCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if _, err := s.notificationSvc.Create(notifyCtx, notifReq, fmt.Sprintf("slot.%s:%s", action, slot.SlotID.String())); err != nil {
		s.logger.Error("failed to create slot notification", zap.Error(err))
	}
}

func (s *timetableService) sendEntryNotification(ctx context.Context, entry *models.TimetableEntry, action string, actor *uuid.UUID) {
	slot, err := s.repo.GetSlotByID(ctx, nil, entry.SlotID)
	if err != nil || slot == nil {
		return
	}
	tt, err := s.repo.GetTimetableByID(ctx, nil, slot.TimetableID)
	if err != nil || tt == nil {
		return
	}
	section, err := s.sectionRepo.GetByID(ctx, nil, tt.SectionID)
	if err != nil || section == nil {
		return
	}
	subject, err := s.subjectRepo.GetByID(ctx, nil, entry.SubjectID)
	if err != nil || subject == nil {
		return
	}
	teacher, err := s.teacherRepo.GetByID(ctx, nil, entry.TeacherID)
	if err != nil || teacher == nil {
		return
	}

	title := fmt.Sprintf("Timetable entry %s", action)
	message := fmt.Sprintf("The entry for subject %s with teacher %s at slot %d on day %d has been %s in section %s.",
		subject.Name, teacher.EmployeeCode, slot.SlotNumber, slot.DayOfWeek, action, section.Name)

	targets := []NotificationTargetInput{}
	if actor != nil && *actor != uuid.Nil {
		targets = append(targets, NotificationTargetInput{
			TargetType:     models.TargetUser,
			TargetEntityID: *actor,
		})
	}
	// Notify teacher and class teacher
	targets = append(targets, NotificationTargetInput{
		TargetType:     models.TargetUser,
		TargetEntityID: teacher.UserID,
	})

	notifReq := CreateNotificationRequest{
		CompanyID: section.CourseID,
		Title:     title,
		Message:   message,
		Type:      models.NotificationTypeInfo,
		Priority:  models.PriorityNormal,
		Targets:   targets,
		CreatedBy: actor,
	}
	notifyCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if _, err := s.notificationSvc.Create(notifyCtx, notifReq, fmt.Sprintf("entry.%s:%s", action, entry.EntryID.String())); err != nil {
		s.logger.Error("failed to create entry notification", zap.Error(err))
	}
}

func (s *timetableService) sendChangeNotification(ctx context.Context, change *models.TimetableChange, actor *uuid.UUID) {
	entry, err := s.repo.GetEntryByID(ctx, nil, change.EntryID)
	if err != nil || entry == nil {
		return
	}
	slot, err := s.repo.GetSlotByID(ctx, nil, entry.SlotID)
	if err != nil || slot == nil {
		return
	}
	tt, err := s.repo.GetTimetableByID(ctx, nil, slot.TimetableID)
	if err != nil || tt == nil {
		return
	}
	section, err := s.sectionRepo.GetByID(ctx, nil, tt.SectionID)
	if err != nil || section == nil {
		return
	}

	title := "Timetable change recorded"
	message := fmt.Sprintf("A change was recorded for entry on day %d slot %d: %s", slot.DayOfWeek, slot.SlotNumber, change.Reason)

	targets := []NotificationTargetInput{}
	if actor != nil && *actor != uuid.Nil {
		targets = append(targets, NotificationTargetInput{
			TargetType:     models.TargetUser,
			TargetEntityID: *actor,
		})
	}
	// Notify teacher
	if entry.TeacherID != uuid.Nil {
		teacher, err := s.teacherRepo.GetByID(ctx, nil, entry.TeacherID)
		if err == nil && teacher != nil {
			targets = append(targets, NotificationTargetInput{
				TargetType:     models.TargetUser,
				TargetEntityID: teacher.UserID,
			})
		}
	}

	notifReq := CreateNotificationRequest{
		CompanyID: section.CourseID,
		Title:     title,
		Message:   message,
		Type:      models.NotificationTypeInfo,
		Priority:  models.PriorityNormal,
		Targets:   targets,
		CreatedBy: actor,
	}
	notifyCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if _, err := s.notificationSvc.Create(notifyCtx, notifReq, fmt.Sprintf("change.%s", change.ChangeID.String())); err != nil {
		s.logger.Error("failed to create change notification", zap.Error(err))
	}
}

package service

import (
	"context"
	"encoding/json"
	"fmt"
	"time"

	"github.com/google/uuid"
	"go.uber.org/zap"

	"auth-service/internal/academics/models"
	"auth-service/internal/academics/repository"
	"auth-service/internal/client"
	"auth-service/internal/infrastructure/audit"
	"auth-service/internal/infrastructure/idempotency"
	"auth-service/internal/infrastructure/outbox"
)

// ---------- Request types ----------

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
	DayOfWeek   int        `json:"day_of_week"`
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

// ---------- Service Interface ----------

type TimetableService interface {
	CreateTimetable(ctx context.Context, req CreateTimetableRequest) (*models.Timetable, error)
	GetTimetableByID(ctx context.Context, id uuid.UUID) (*models.Timetable, error)
	ListTimetables(ctx context.Context, filter repository.TimetableFilter, pagination repository.Pagination, sort repository.Sort) ([]*models.Timetable, error)
	UpdateTimetable(ctx context.Context, req UpdateTimetableRequest) (*models.Timetable, error)
	DeleteTimetable(ctx context.Context, id uuid.UUID, deletedBy *uuid.UUID) error
	GetActiveTimetableForSection(ctx context.Context, termID, sectionID uuid.UUID) (*models.Timetable, error)
	AddSlot(ctx context.Context, req AddSlotRequest) (*models.TimetableSlot, error)
	UpdateSlot(ctx context.Context, req UpdateSlotRequest) (*models.TimetableSlot, error)
	RemoveSlot(ctx context.Context, slotID uuid.UUID, deletedBy *uuid.UUID) error
	GetSlotsForTimetable(ctx context.Context, timetableID uuid.UUID) ([]*models.TimetableSlot, error)
	AddEntry(ctx context.Context, req AddEntryRequest) (*models.TimetableEntry, error)
	UpdateEntry(ctx context.Context, req UpdateEntryRequest) (*models.TimetableEntry, error)
	RemoveEntry(ctx context.Context, entryID uuid.UUID, deletedBy *uuid.UUID) error
	GetEntriesForSlot(ctx context.Context, slotID uuid.UUID) ([]*models.TimetableEntry, error)
	AddChange(ctx context.Context, req AddChangeRequest) (*models.TimetableChange, error)
	GetChangesForEntry(ctx context.Context, entryID uuid.UUID) ([]*models.TimetableChange, error)
}

// ---------- Service Implementation ----------

type timetableService struct {
	repo             repository.TimetableRepository
	sectionRepo      repository.SectionRepository
	courseRepo       repository.CourseRepository // ✅ Added
	subjectRepo      repository.SubjectRepository
	teacherRepo      repository.TeacherRepository
	roomRepo         repository.RoomRepository
	idempotencyStore idempotency.Store
	auditService     *audit.AuditService
	outboxRepo       outbox.Repository
	pgClient         *client.PostgresClient
	logger           *zap.Logger
	notificationSvc  NotificationService
}

// ✅ Updated constructor to include courseRepo
func NewTimetableService(
	repo repository.TimetableRepository,
	sectionRepo repository.SectionRepository,
	courseRepo repository.CourseRepository,
	subjectRepo repository.SubjectRepository,
	teacherRepo repository.TeacherRepository,
	roomRepo repository.RoomRepository,
	idempotencyStore idempotency.Store,
	auditService *audit.AuditService,
	outboxRepo outbox.Repository,
	pgClient *client.PostgresClient,
	logger *zap.Logger,
	notificationSvc NotificationService,
) TimetableService {
	return &timetableService{
		repo:             repo,
		sectionRepo:      sectionRepo,
		courseRepo:       courseRepo,
		subjectRepo:      subjectRepo,
		teacherRepo:      teacherRepo,
		roomRepo:         roomRepo,
		idempotencyStore: idempotencyStore,
		auditService:     auditService,
		outboxRepo:       outboxRepo,
		pgClient:         pgClient,
		logger:           logger.Named("timetable_service"),
		notificationSvc:  notificationSvc,
	}
}

// ---------- Validation Helpers ----------

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

// ---------- Core Business Methods ----------

func (s *timetableService) CreateTimetable(ctx context.Context, req CreateTimetableRequest) (*models.Timetable, error) {
	logger := s.logger.With(
		zap.String("method", "CreateTimetable"),
		zap.String("section_id", req.SectionID.String()),
	)

	idempotencyKey, _ := ctx.Value("idempotency_key").(string)

	if err := s.validateTimetableInput(req); err != nil {
		return nil, err
	}

	tx, err := s.pgClient.BeginTx(ctx, nil)
	if err != nil {
		return nil, fmt.Errorf("begin tx: %w", err)
	}
	defer tx.Rollback()

	if idempotencyKey != "" {
		var existing models.Timetable
		if err := s.idempotencyStore.Get(ctx, tx, idempotencyKey, &existing); err == nil && existing.TimetableID != uuid.Nil {
			logger.Info("idempotent request, returning cached response")
			return &existing, nil
		}
	}

	section, err := s.sectionRepo.GetByID(ctx, tx, req.SectionID)
	if err != nil {
		return nil, err
	}
	if section == nil {
		return nil, fmt.Errorf("%w: section %s", ErrNotFound, req.SectionID)
	}

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
		}
	}

	if s.auditService != nil {
		_ = s.auditService.LogAction(ctx, nil, &section.CourseID, "academics", "create", "timetable",
			&tt.TimetableID, "user", req.CreatedBy, nil, nil, map[string]interface{}{
				"section_id": req.SectionID,
				"term_id":    req.TermID,
			})
	}

	payload, _ := json.Marshal(tt)
	outboxEvent := &outbox.Event{
		EventID:       uuid.New().String(),
		AggregateType: "timetable",
		AggregateID:   tt.TimetableID.String(),
		EventType:     string(EventTimetableCreated),
		Payload:       payload,
		Headers:       map[string]string{},
		Status:        "pending",
	}
	if err := s.outboxRepo.Store(ctx, tx, outboxEvent); err != nil {
		return nil, fmt.Errorf("store outbox event: %w", err)
	}

	if err := tx.Commit(); err != nil {
		return nil, fmt.Errorf("commit tx: %w", err)
	}

	logger.Info("timetable created", zap.String("id", tt.TimetableID.String()))

	// Launch notification in a goroutine with recovery
	go func() {
		defer func() {
			if r := recover(); r != nil {
				s.logger.Error("panic in sendTimetableNotification", zap.Any("recover", r))
			}
		}()
		s.sendTimetableNotification(tt, "created", req.CreatedBy)
	}()

	return tt, nil
}

func (s *timetableService) GetTimetableByID(ctx context.Context, id uuid.UUID) (*models.Timetable, error) {
	logger := s.logger.With(zap.String("method", "GetTimetableByID"), zap.String("id", id.String()))
	tt, err := s.repo.GetTimetableByID(ctx, s.pgClient.DB, id)
	if err != nil {
		return nil, err
	}
	if tt == nil {
		return nil, fmt.Errorf("%w: timetable %s", ErrNotFound, id)
	}
	logger.Debug("timetable retrieved")
	return tt, nil
}

func (s *timetableService) ListTimetables(ctx context.Context, filter repository.TimetableFilter, pagination repository.Pagination, sort repository.Sort) ([]*models.Timetable, error) {
	logger := s.logger.With(zap.String("method", "ListTimetables"))
	logger.Debug("listing timetables")
	return s.repo.ListTimetables(ctx, s.pgClient.DB, filter, pagination, sort)
}

func (s *timetableService) UpdateTimetable(ctx context.Context, req UpdateTimetableRequest) (*models.Timetable, error) {
	logger := s.logger.With(zap.String("method", "UpdateTimetable"), zap.String("timetable_id", req.TimetableID.String()))

	idempotencyKey, _ := ctx.Value("idempotency_key").(string)

	if req.TimetableID == uuid.Nil {
		return nil, fmt.Errorf("%w: timetable_id is required", ErrInvalidInput)
	}

	tx, err := s.pgClient.BeginTx(ctx, nil)
	if err != nil {
		return nil, fmt.Errorf("begin tx: %w", err)
	}
	defer tx.Rollback()

	if idempotencyKey != "" {
		var existing models.Timetable
		if err := s.idempotencyStore.Get(ctx, tx, idempotencyKey, &existing); err == nil && existing.TimetableID != uuid.Nil {
			logger.Info("idempotent request, returning cached response")
			return &existing, nil
		}
	}

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

	if idempotencyKey != "" {
		if err := s.idempotencyStore.Store(ctx, tx, idempotencyKey, tt); err != nil {
			logger.Error("failed to store idempotency key", zap.Error(err))
		}
	}

	if s.auditService != nil {
		_ = s.auditService.LogAction(ctx, nil, nil, "academics", "update", "timetable",
			&req.TimetableID, "user", req.UpdatedBy, nil, nil, map[string]interface{}{
				"old": oldTT,
				"new": tt,
			})
	}

	payload, _ := json.Marshal(map[string]interface{}{"old": oldTT, "new": tt})
	outboxEvent := &outbox.Event{
		EventID:       uuid.New().String(),
		AggregateType: "timetable",
		AggregateID:   tt.TimetableID.String(),
		EventType:     string(EventTimetableUpdated),
		Payload:       payload,
		Headers:       map[string]string{},
		Status:        "pending",
	}
	if err := s.outboxRepo.Store(ctx, tx, outboxEvent); err != nil {
		return nil, fmt.Errorf("store outbox event: %w", err)
	}

	if err := tx.Commit(); err != nil {
		return nil, fmt.Errorf("commit tx: %w", err)
	}

	logger.Info("timetable updated")
	go func() {
		defer func() { recover() }()
		s.sendTimetableNotification(tt, "updated", req.UpdatedBy)
	}()
	return tt, nil
}

func (s *timetableService) DeleteTimetable(ctx context.Context, id uuid.UUID, deletedBy *uuid.UUID) error {
	logger := s.logger.With(zap.String("method", "DeleteTimetable"), zap.String("timetable_id", id.String()))

	tx, err := s.pgClient.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("begin tx: %w", err)
	}
	defer tx.Rollback()

	tt, err := s.repo.GetTimetableByID(ctx, tx, id)
	if err != nil {
		return err
	}
	if tt == nil {
		return fmt.Errorf("%w: timetable %s", ErrNotFound, id)
	}

	if err := s.repo.DeleteTimetable(ctx, tx, id, deletedBy); err != nil {
		return err
	}

	if s.auditService != nil {
		_ = s.auditService.LogAction(ctx, nil, nil, "academics", "delete", "timetable",
			&id, "user", deletedBy, nil, nil, nil)
	}

	payload, _ := json.Marshal(map[string]interface{}{
		"timetable_id": id,
		"deleted_by":   deletedBy,
	})
	outboxEvent := &outbox.Event{
		EventID:       uuid.New().String(),
		AggregateType: "timetable",
		AggregateID:   id.String(),
		EventType:     string(EventTimetableDeleted),
		Payload:       payload,
		Headers:       map[string]string{},
		Status:        "pending",
	}
	if err := s.outboxRepo.Store(ctx, tx, outboxEvent); err != nil {
		return fmt.Errorf("store outbox event: %w", err)
	}

	if err := tx.Commit(); err != nil {
		return fmt.Errorf("commit tx: %w", err)
	}

	logger.Info("timetable deleted")
	go func() {
		defer func() { recover() }()
		s.sendTimetableNotification(tt, "deleted", deletedBy)
	}()
	return nil
}

func (s *timetableService) GetActiveTimetableForSection(ctx context.Context, termID, sectionID uuid.UUID) (*models.Timetable, error) {
	logger := s.logger.With(zap.String("method", "GetActiveTimetableForSection"), zap.String("term_id", termID.String()), zap.String("section_id", sectionID.String()))
	tt, err := s.repo.GetActiveTimetableForSection(ctx, s.pgClient.DB, termID, sectionID)
	if err != nil {
		return nil, err
	}
	if tt == nil {
		return nil, fmt.Errorf("%w: no active timetable for section %s in term %s", ErrNotFound, sectionID, termID)
	}
	logger.Debug("active timetable retrieved")
	return tt, nil
}

func (s *timetableService) AddSlot(ctx context.Context, req AddSlotRequest) (*models.TimetableSlot, error) {
	logger := s.logger.With(
		zap.String("method", "AddSlot"),
		zap.String("timetable_id", req.TimetableID.String()),
	)

	idempotencyKey, _ := ctx.Value("idempotency_key").(string)

	if err := s.validateSlotInput(req); err != nil {
		return nil, err
	}

	tx, err := s.pgClient.BeginTx(ctx, nil)
	if err != nil {
		return nil, fmt.Errorf("begin tx: %w", err)
	}
	defer tx.Rollback()

	if idempotencyKey != "" {
		var existing models.TimetableSlot
		if err := s.idempotencyStore.Get(ctx, tx, idempotencyKey, &existing); err == nil && existing.SlotID != uuid.Nil {
			logger.Info("idempotent request, returning cached response")
			return &existing, nil
		}
	}

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

	if idempotencyKey != "" {
		if err := s.idempotencyStore.Store(ctx, tx, idempotencyKey, slot); err != nil {
			logger.Error("failed to store idempotency key", zap.Error(err))
		}
	}

	if s.auditService != nil {
		_ = s.auditService.LogAction(ctx, nil, nil, "academics", "add", "timetable_slot",
			&slot.SlotID, "user", req.CreatedBy, nil, nil, map[string]interface{}{
				"timetable_id": req.TimetableID,
				"day_of_week":  req.DayOfWeek,
			})
	}

	payload, _ := json.Marshal(slot)
	outboxEvent := &outbox.Event{
		EventID:       uuid.New().String(),
		AggregateType: "timetable_slot",
		AggregateID:   slot.SlotID.String(),
		EventType:     string(EventTimetableSlotAdded),
		Payload:       payload,
		Headers:       map[string]string{},
		Status:        "pending",
	}
	if err := s.outboxRepo.Store(ctx, tx, outboxEvent); err != nil {
		return nil, fmt.Errorf("store outbox event: %w", err)
	}

	if err := tx.Commit(); err != nil {
		return nil, fmt.Errorf("commit tx: %w", err)
	}

	logger.Info("slot added", zap.String("slot_id", slot.SlotID.String()))
	go func() {
		defer func() { recover() }()
		s.sendSlotNotification(slot, "added", req.CreatedBy)
	}()
	return slot, nil
}

func (s *timetableService) UpdateSlot(ctx context.Context, req UpdateSlotRequest) (*models.TimetableSlot, error) {
	logger := s.logger.With(zap.String("method", "UpdateSlot"), zap.String("slot_id", req.SlotID.String()))

	idempotencyKey, _ := ctx.Value("idempotency_key").(string)

	if req.SlotID == uuid.Nil {
		return nil, fmt.Errorf("%w: slot_id is required", ErrInvalidInput)
	}

	tx, err := s.pgClient.BeginTx(ctx, nil)
	if err != nil {
		return nil, fmt.Errorf("begin tx: %w", err)
	}
	defer tx.Rollback()

	if idempotencyKey != "" {
		var existing models.TimetableSlot
		if err := s.idempotencyStore.Get(ctx, tx, idempotencyKey, &existing); err == nil && existing.SlotID != uuid.Nil {
			logger.Info("idempotent request, returning cached response")
			return &existing, nil
		}
	}

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

	if idempotencyKey != "" {
		if err := s.idempotencyStore.Store(ctx, tx, idempotencyKey, slot); err != nil {
			logger.Error("failed to store idempotency key", zap.Error(err))
		}
	}

	if s.auditService != nil {
		_ = s.auditService.LogAction(ctx, nil, nil, "academics", "update", "timetable_slot",
			&req.SlotID, "user", req.UpdatedBy, nil, nil, map[string]interface{}{
				"old": oldSlot,
				"new": slot,
			})
	}

	payload, _ := json.Marshal(map[string]interface{}{"old": oldSlot, "new": slot})
	outboxEvent := &outbox.Event{
		EventID:       uuid.New().String(),
		AggregateType: "timetable_slot",
		AggregateID:   slot.SlotID.String(),
		EventType:     string(EventTimetableSlotUpdated),
		Payload:       payload,
		Headers:       map[string]string{},
		Status:        "pending",
	}
	if err := s.outboxRepo.Store(ctx, tx, outboxEvent); err != nil {
		return nil, fmt.Errorf("store outbox event: %w", err)
	}

	if err := tx.Commit(); err != nil {
		return nil, fmt.Errorf("commit tx: %w", err)
	}

	logger.Info("slot updated")
	go func() {
		defer func() { recover() }()
		s.sendSlotNotification(slot, "updated", req.UpdatedBy)
	}()
	return slot, nil
}

func (s *timetableService) RemoveSlot(ctx context.Context, slotID uuid.UUID, deletedBy *uuid.UUID) error {
	logger := s.logger.With(zap.String("method", "RemoveSlot"), zap.String("slot_id", slotID.String()))

	tx, err := s.pgClient.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("begin tx: %w", err)
	}
	defer tx.Rollback()

	slot, err := s.repo.GetSlotByID(ctx, tx, slotID)
	if err != nil {
		return err
	}
	if slot == nil {
		return fmt.Errorf("%w: slot %s", ErrNotFound, slotID)
	}

	if err := s.repo.RemoveSlot(ctx, tx, slotID); err != nil {
		return err
	}

	if s.auditService != nil {
		_ = s.auditService.LogAction(ctx, nil, nil, "academics", "delete", "timetable_slot",
			&slotID, "user", deletedBy, nil, nil, nil)
	}

	payload, _ := json.Marshal(map[string]interface{}{
		"slot_id":    slotID,
		"deleted_by": deletedBy,
	})
	outboxEvent := &outbox.Event{
		EventID:       uuid.New().String(),
		AggregateType: "timetable_slot",
		AggregateID:   slotID.String(),
		EventType:     string(EventTimetableSlotDeleted),
		Payload:       payload,
		Headers:       map[string]string{},
		Status:        "pending",
	}
	if err := s.outboxRepo.Store(ctx, tx, outboxEvent); err != nil {
		return fmt.Errorf("store outbox event: %w", err)
	}

	if err := tx.Commit(); err != nil {
		return fmt.Errorf("commit tx: %w", err)
	}

	logger.Info("slot removed")
	go func() {
		defer func() { recover() }()
		s.sendSlotNotification(slot, "deleted", deletedBy)
	}()
	return nil
}

func (s *timetableService) GetSlotsForTimetable(ctx context.Context, timetableID uuid.UUID) ([]*models.TimetableSlot, error) {
	logger := s.logger.With(zap.String("method", "GetSlotsForTimetable"), zap.String("timetable_id", timetableID.String()))
	slots, err := s.repo.GetSlotsForTimetable(ctx, s.pgClient.DB, timetableID)
	if err != nil {
		return nil, err
	}
	logger.Debug("slots retrieved", zap.Int("count", len(slots)))
	return slots, nil
}

func (s *timetableService) AddEntry(ctx context.Context, req AddEntryRequest) (*models.TimetableEntry, error) {
	logger := s.logger.With(
		zap.String("method", "AddEntry"),
		zap.String("slot_id", req.SlotID.String()),
	)

	idempotencyKey, _ := ctx.Value("idempotency_key").(string)

	if err := s.validateEntryInput(req); err != nil {
		return nil, err
	}

	tx, err := s.pgClient.BeginTx(ctx, nil)
	if err != nil {
		return nil, fmt.Errorf("begin tx: %w", err)
	}
	defer tx.Rollback()

	if idempotencyKey != "" {
		var existing models.TimetableEntry
		if err := s.idempotencyStore.Get(ctx, tx, idempotencyKey, &existing); err == nil && existing.EntryID != uuid.Nil {
			logger.Info("idempotent request, returning cached response")
			return &existing, nil
		}
	}

	slot, err := s.repo.GetSlotByID(ctx, tx, req.SlotID)
	if err != nil {
		return nil, err
	}
	if slot == nil {
		return nil, fmt.Errorf("%w: slot %s", ErrNotFound, req.SlotID)
	}

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

	if idempotencyKey != "" {
		if err := s.idempotencyStore.Store(ctx, tx, idempotencyKey, entry); err != nil {
			logger.Error("failed to store idempotency key", zap.Error(err))
		}
	}

	if s.auditService != nil {
		_ = s.auditService.LogAction(ctx, nil, nil, "academics", "add", "timetable_entry",
			&entry.EntryID, "user", req.CreatedBy, nil, nil, map[string]interface{}{
				"slot_id":    req.SlotID,
				"subject_id": req.SubjectID,
			})
	}

	payload, _ := json.Marshal(entry)
	outboxEvent := &outbox.Event{
		EventID:       uuid.New().String(),
		AggregateType: "timetable_entry",
		AggregateID:   entry.EntryID.String(),
		EventType:     string(EventTimetableEntryAdded),
		Payload:       payload,
		Headers:       map[string]string{},
		Status:        "pending",
	}
	if err := s.outboxRepo.Store(ctx, tx, outboxEvent); err != nil {
		return nil, fmt.Errorf("store outbox event: %w", err)
	}

	if err := tx.Commit(); err != nil {
		return nil, fmt.Errorf("commit tx: %w", err)
	}

	logger.Info("entry added", zap.String("entry_id", entry.EntryID.String()))
	go func() {
		defer func() { recover() }()
		s.sendEntryNotification(entry, "added", req.CreatedBy)
	}()
	return entry, nil
}

func (s *timetableService) UpdateEntry(ctx context.Context, req UpdateEntryRequest) (*models.TimetableEntry, error) {
	logger := s.logger.With(zap.String("method", "UpdateEntry"), zap.String("entry_id", req.EntryID.String()))

	idempotencyKey, _ := ctx.Value("idempotency_key").(string)

	if req.EntryID == uuid.Nil {
		return nil, fmt.Errorf("%w: entry_id is required", ErrInvalidInput)
	}

	tx, err := s.pgClient.BeginTx(ctx, nil)
	if err != nil {
		return nil, fmt.Errorf("begin tx: %w", err)
	}
	defer tx.Rollback()

	if idempotencyKey != "" {
		var existing models.TimetableEntry
		if err := s.idempotencyStore.Get(ctx, tx, idempotencyKey, &existing); err == nil && existing.EntryID != uuid.Nil {
			logger.Info("idempotent request, returning cached response")
			return &existing, nil
		}
	}

	entry, err := s.repo.GetEntryByID(ctx, tx, req.EntryID)
	if err != nil {
		return nil, err
	}
	if entry == nil {
		return nil, fmt.Errorf("%w: entry %s", ErrNotFound, req.EntryID)
	}

	oldEntry := *entry

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

	if idempotencyKey != "" {
		if err := s.idempotencyStore.Store(ctx, tx, idempotencyKey, entry); err != nil {
			logger.Error("failed to store idempotency key", zap.Error(err))
		}
	}

	if s.auditService != nil {
		_ = s.auditService.LogAction(ctx, nil, nil, "academics", "update", "timetable_entry",
			&req.EntryID, "user", req.UpdatedBy, nil, nil, map[string]interface{}{
				"old": oldEntry,
				"new": entry,
			})
	}

	payload, _ := json.Marshal(map[string]interface{}{"old": oldEntry, "new": entry})
	outboxEvent := &outbox.Event{
		EventID:       uuid.New().String(),
		AggregateType: "timetable_entry",
		AggregateID:   entry.EntryID.String(),
		EventType:     string(EventTimetableEntryUpdated),
		Payload:       payload,
		Headers:       map[string]string{},
		Status:        "pending",
	}
	if err := s.outboxRepo.Store(ctx, tx, outboxEvent); err != nil {
		return nil, fmt.Errorf("store outbox event: %w", err)
	}

	if err := tx.Commit(); err != nil {
		return nil, fmt.Errorf("commit tx: %w", err)
	}

	logger.Info("entry updated")
	go func() {
		defer func() { recover() }()
		s.sendEntryNotification(entry, "updated", req.UpdatedBy)
	}()
	return entry, nil
}

func (s *timetableService) RemoveEntry(ctx context.Context, entryID uuid.UUID, deletedBy *uuid.UUID) error {
	logger := s.logger.With(zap.String("method", "RemoveEntry"), zap.String("entry_id", entryID.String()))

	tx, err := s.pgClient.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("begin tx: %w", err)
	}
	defer tx.Rollback()

	entry, err := s.repo.GetEntryByID(ctx, tx, entryID)
	if err != nil {
		return err
	}
	if entry == nil {
		return fmt.Errorf("%w: entry %s", ErrNotFound, entryID)
	}

	if err := s.repo.RemoveEntry(ctx, tx, entryID); err != nil {
		return err
	}

	if s.auditService != nil {
		_ = s.auditService.LogAction(ctx, nil, nil, "academics", "delete", "timetable_entry",
			&entryID, "user", deletedBy, nil, nil, nil)
	}

	payload, _ := json.Marshal(map[string]interface{}{
		"entry_id":   entryID,
		"deleted_by": deletedBy,
	})
	outboxEvent := &outbox.Event{
		EventID:       uuid.New().String(),
		AggregateType: "timetable_entry",
		AggregateID:   entryID.String(),
		EventType:     string(EventTimetableEntryDeleted),
		Payload:       payload,
		Headers:       map[string]string{},
		Status:        "pending",
	}
	if err := s.outboxRepo.Store(ctx, tx, outboxEvent); err != nil {
		return fmt.Errorf("store outbox event: %w", err)
	}

	if err := tx.Commit(); err != nil {
		return fmt.Errorf("commit tx: %w", err)
	}

	logger.Info("entry removed")
	go func() {
		defer func() { recover() }()
		s.sendEntryNotification(entry, "deleted", deletedBy)
	}()
	return nil
}

func (s *timetableService) GetEntriesForSlot(ctx context.Context, slotID uuid.UUID) ([]*models.TimetableEntry, error) {
	logger := s.logger.With(zap.String("method", "GetEntriesForSlot"), zap.String("slot_id", slotID.String()))
	entries, err := s.repo.GetEntriesForSlot(ctx, s.pgClient.DB, slotID)
	if err != nil {
		return nil, err
	}
	logger.Debug("entries retrieved", zap.Int("count", len(entries)))
	return entries, nil
}

func (s *timetableService) AddChange(ctx context.Context, req AddChangeRequest) (*models.TimetableChange, error) {
	logger := s.logger.With(zap.String("method", "AddChange"), zap.String("entry_id", req.EntryID.String()))

	idempotencyKey, _ := ctx.Value("idempotency_key").(string)

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

	if idempotencyKey != "" {
		var existing models.TimetableChange
		if err := s.idempotencyStore.Get(ctx, tx, idempotencyKey, &existing); err == nil && existing.ChangeID != uuid.Nil {
			logger.Info("idempotent request, returning cached response")
			return &existing, nil
		}
	}

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

	if idempotencyKey != "" {
		if err := s.idempotencyStore.Store(ctx, tx, idempotencyKey, change); err != nil {
			logger.Error("failed to store idempotency key", zap.Error(err))
		}
	}

	if s.auditService != nil {
		_ = s.auditService.LogAction(ctx, nil, nil, "academics", "add", "timetable_change",
			&change.ChangeID, "user", req.CreatedBy, nil, nil, map[string]interface{}{
				"entry_id": req.EntryID,
				"reason":   req.Reason,
			})
	}

	payload, _ := json.Marshal(change)
	outboxEvent := &outbox.Event{
		EventID:       uuid.New().String(),
		AggregateType: "timetable_change",
		AggregateID:   change.ChangeID.String(),
		EventType:     string(EventTimetableChangeAdded),
		Payload:       payload,
		Headers:       map[string]string{},
		Status:        "pending",
	}
	if err := s.outboxRepo.Store(ctx, tx, outboxEvent); err != nil {
		return nil, fmt.Errorf("store outbox event: %w", err)
	}

	if err := tx.Commit(); err != nil {
		return nil, fmt.Errorf("commit tx: %w", err)
	}

	logger.Info("change added", zap.String("change_id", change.ChangeID.String()))
	go func() {
		defer func() { recover() }()
		s.sendChangeNotification(change, req.CreatedBy)
	}()
	return change, nil
}

func (s *timetableService) GetChangesForEntry(ctx context.Context, entryID uuid.UUID) ([]*models.TimetableChange, error) {
	logger := s.logger.With(zap.String("method", "GetChangesForEntry"), zap.String("entry_id", entryID.String()))
	changes, err := s.repo.GetChangesForEntry(ctx, s.pgClient.DB, entryID)
	if err != nil {
		return nil, err
	}
	logger.Debug("changes retrieved", zap.Int("count", len(changes)))
	return changes, nil
}

// ---------- NOTIFICATION METHODS (FIXED) ----------
// All now use a detached background context, a valid DB connection (s.pgClient.DB),
// and fetch the course to get the real company ID.

func (s *timetableService) sendTimetableNotification(tt *models.Timetable, action string, actor *uuid.UUID) {
	if s.notificationSvc == nil {
		return
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	section, err := s.sectionRepo.GetByID(ctx, s.pgClient.DB, tt.SectionID)
	if err != nil || section == nil {
		s.logger.Error("failed to fetch section for timetable notification", zap.Error(err))
		return
	}

	// ✅ Fetch the course to get the real company ID
	course, err := s.courseRepo.GetByID(ctx, s.pgClient.DB, section.CourseID)
	if err != nil || course == nil {
		s.logger.Error("failed to fetch course for timetable notification", zap.Error(err))
		return
	}

	title := fmt.Sprintf("Timetable %s", action)
	message := fmt.Sprintf("The timetable for section %s has been %s.", section.Name, action)

	var targets []NotificationTargetInput
	if actor != nil && *actor != uuid.Nil {
		targets = append(targets, NotificationTargetInput{
			TargetType:     models.TargetUser,
			TargetEntityID: *actor,
		})
	}
	if len(targets) == 0 {
		return
	}

	notifReq := CreateNotificationRequest{
		CompanyID: course.CompanyID, // ✅ Use the real company ID
		Title:     title,
		Message:   message,
		Type:      models.NotificationTypeInfo,
		Priority:  models.PriorityNormal,
		Targets:   targets,
		CreatedBy: actor,
	}

	if _, err := s.notificationSvc.Create(ctx, notifReq, fmt.Sprintf("timetable.%s:%s", action, tt.TimetableID.String())); err != nil {
		s.logger.Error("failed to send timetable notification", zap.Error(err))
	}
}

func (s *timetableService) sendSlotNotification(slot *models.TimetableSlot, action string, actor *uuid.UUID) {
	if s.notificationSvc == nil {
		return
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	tt, err := s.repo.GetTimetableByID(ctx, s.pgClient.DB, slot.TimetableID)
	if err != nil || tt == nil {
		s.logger.Error("failed to fetch timetable for slot notification", zap.Error(err))
		return
	}
	section, err := s.sectionRepo.GetByID(ctx, s.pgClient.DB, tt.SectionID)
	if err != nil || section == nil {
		s.logger.Error("failed to fetch section for slot notification", zap.Error(err))
		return
	}
	// ✅ Fetch course for company ID
	course, err := s.courseRepo.GetByID(ctx, s.pgClient.DB, section.CourseID)
	if err != nil || course == nil {
		s.logger.Error("failed to fetch course for slot notification", zap.Error(err))
		return
	}

	title := fmt.Sprintf("Timetable slot %s", action)
	message := fmt.Sprintf("A slot on day %d from %s to %s has been %s in section %s.",
		slot.DayOfWeek, slot.StartTime.Format("15:04"), slot.EndTime.Format("15:04"), action, section.Name)

	var targets []NotificationTargetInput
	if actor != nil && *actor != uuid.Nil {
		targets = append(targets, NotificationTargetInput{
			TargetType:     models.TargetUser,
			TargetEntityID: *actor,
		})
	}
	if len(targets) == 0 {
		return
	}

	notifReq := CreateNotificationRequest{
		CompanyID: course.CompanyID,
		Title:     title,
		Message:   message,
		Type:      models.NotificationTypeInfo,
		Priority:  models.PriorityNormal,
		Targets:   targets,
		CreatedBy: actor,
	}

	if _, err := s.notificationSvc.Create(ctx, notifReq, fmt.Sprintf("slot.%s:%s", action, slot.SlotID.String())); err != nil {
		s.logger.Error("failed to send slot notification", zap.Error(err))
	}
}

func (s *timetableService) sendEntryNotification(entry *models.TimetableEntry, action string, actor *uuid.UUID) {
	if s.notificationSvc == nil {
		return
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	slot, err := s.repo.GetSlotByID(ctx, s.pgClient.DB, entry.SlotID)
	if err != nil || slot == nil {
		s.logger.Error("failed to fetch slot for entry notification", zap.Error(err))
		return
	}
	tt, err := s.repo.GetTimetableByID(ctx, s.pgClient.DB, slot.TimetableID)
	if err != nil || tt == nil {
		s.logger.Error("failed to fetch timetable for entry notification", zap.Error(err))
		return
	}
	section, err := s.sectionRepo.GetByID(ctx, s.pgClient.DB, tt.SectionID)
	if err != nil || section == nil {
		s.logger.Error("failed to fetch section for entry notification", zap.Error(err))
		return
	}
	// ✅ Fetch course for company ID
	course, err := s.courseRepo.GetByID(ctx, s.pgClient.DB, section.CourseID)
	if err != nil || course == nil {
		s.logger.Error("failed to fetch course for entry notification", zap.Error(err))
		return
	}
	subject, err := s.subjectRepo.GetByID(ctx, s.pgClient.DB, entry.SubjectID)
	if err != nil || subject == nil {
		s.logger.Error("failed to fetch subject for entry notification", zap.Error(err))
		return
	}
	teacher, err := s.teacherRepo.GetByID(ctx, s.pgClient.DB, entry.TeacherID)
	if err != nil || teacher == nil {
		s.logger.Error("failed to fetch teacher for entry notification", zap.Error(err))
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
	targets = append(targets, NotificationTargetInput{
		TargetType:     models.TargetUser,
		TargetEntityID: teacher.UserID,
	})

	notifReq := CreateNotificationRequest{
		CompanyID: course.CompanyID,
		Title:     title,
		Message:   message,
		Type:      models.NotificationTypeInfo,
		Priority:  models.PriorityNormal,
		Targets:   targets,
		CreatedBy: actor,
	}

	if _, err := s.notificationSvc.Create(ctx, notifReq, fmt.Sprintf("entry.%s:%s", action, entry.EntryID.String())); err != nil {
		s.logger.Error("failed to send entry notification", zap.Error(err))
	}
}

func (s *timetableService) sendChangeNotification(change *models.TimetableChange, actor *uuid.UUID) {
	if s.notificationSvc == nil {
		return
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	entry, err := s.repo.GetEntryByID(ctx, s.pgClient.DB, change.EntryID)
	if err != nil || entry == nil {
		s.logger.Error("failed to fetch entry for change notification", zap.Error(err))
		return
	}
	slot, err := s.repo.GetSlotByID(ctx, s.pgClient.DB, entry.SlotID)
	if err != nil || slot == nil {
		s.logger.Error("failed to fetch slot for change notification", zap.Error(err))
		return
	}
	tt, err := s.repo.GetTimetableByID(ctx, s.pgClient.DB, slot.TimetableID)
	if err != nil || tt == nil {
		s.logger.Error("failed to fetch timetable for change notification", zap.Error(err))
		return
	}
	section, err := s.sectionRepo.GetByID(ctx, s.pgClient.DB, tt.SectionID)
	if err != nil || section == nil {
		s.logger.Error("failed to fetch section for change notification", zap.Error(err))
		return
	}
	// ✅ Fetch course for company ID
	course, err := s.courseRepo.GetByID(ctx, s.pgClient.DB, section.CourseID)
	if err != nil || course == nil {
		s.logger.Error("failed to fetch course for change notification", zap.Error(err))
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
	if entry.TeacherID != uuid.Nil {
		teacher, err := s.teacherRepo.GetByID(ctx, s.pgClient.DB, entry.TeacherID)
		if err == nil && teacher != nil {
			targets = append(targets, NotificationTargetInput{
				TargetType:     models.TargetUser,
				TargetEntityID: teacher.UserID,
			})
		}
	}
	if len(targets) == 0 {
		return
	}

	notifReq := CreateNotificationRequest{
		CompanyID: course.CompanyID,
		Title:     title,
		Message:   message,
		Type:      models.NotificationTypeInfo,
		Priority:  models.PriorityNormal,
		Targets:   targets,
		CreatedBy: actor,
	}

	if _, err := s.notificationSvc.Create(ctx, notifReq, fmt.Sprintf("change.%s", change.ChangeID.String())); err != nil {
		s.logger.Error("failed to send change notification", zap.Error(err))
	}
}

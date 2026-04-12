package service

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"strings"
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

// ---------------------------------------------------------------------
// Service interface (updated with idempotency keys)
// ---------------------------------------------------------------------

type RoomService interface {
	Create(ctx context.Context, req CreateRoomRequest, idempotencyKey string) (*models.Room, error)
	BulkCreate(ctx context.Context, reqs []CreateRoomRequest, idempotencyKey string) ([]*models.Room, error)
	GetByID(ctx context.Context, id uuid.UUID) (*models.Room, error)
	GetByCode(ctx context.Context, companyID uuid.UUID, code string) (*models.Room, error)
	List(ctx context.Context, filter repository.RoomFilter, p repository.Pagination, s repository.Sort) ([]*models.Room, error)
	Count(ctx context.Context, filter repository.RoomFilter) (int64, error)
	Update(ctx context.Context, req UpdateRoomRequest, idempotencyKey string) (*models.Room, error)
	Delete(ctx context.Context, id uuid.UUID, deletedBy *uuid.UUID, idempotencyKey string) error
	Activate(ctx context.Context, id uuid.UUID, updatedBy *uuid.UUID, idempotencyKey string) error
	Deactivate(ctx context.Context, id uuid.UUID, updatedBy *uuid.UUID, idempotencyKey string) error
	ExistsByCode(ctx context.Context, companyID uuid.UUID, code string) (bool, error)
	ListByBuilding(ctx context.Context, companyID uuid.UUID, building string) ([]*models.Room, error)
}

// ---------------------------------------------------------------------
// Service implementation
// ---------------------------------------------------------------------

type roomService struct {
	repo            repository.RoomRepository
	pgClient        *client.PostgresClient
	logger          *zap.Logger
	notificationSvc NotificationService

	// Infrastructure dependencies (same pattern as assignment/attendance/curriculum)
	idempotencyStore idempotency.Store
	auditService     *audit.AuditService
	outboxRepo       outbox.Repository
}

// ---------------------------------------------------------------------
// Constructor (updated)
// ---------------------------------------------------------------------

func NewRoomService(
	repo repository.RoomRepository,
	pgClient *client.PostgresClient,
	logger *zap.Logger,
	notificationSvc NotificationService,
	idempotencyStore idempotency.Store,
	auditService *audit.AuditService,
	outboxRepo outbox.Repository,
) RoomService {
	return &roomService{
		repo:             repo,
		pgClient:         pgClient,
		logger:           logger.Named("room_service"),
		notificationSvc:  notificationSvc,
		idempotencyStore: idempotencyStore,
		auditService:     auditService,
		outboxRepo:       outboxRepo,
	}
}

// ---------------------------------------------------------------------
// Helper: store outbox event for room
// ---------------------------------------------------------------------

func (s *roomService) storeOutboxEvent(ctx context.Context, tx *sql.Tx, eventType EventType, aggregateID uuid.UUID, payload interface{}) error {
	var data []byte
	var err error
	if payload != nil {
		data, err = json.Marshal(payload)
		if err != nil {
			return fmt.Errorf("marshal outbox payload: %w", err)
		}
	}

	outboxEvent := &outbox.Event{
		EventID:       uuid.New().String(),
		AggregateType: "room",
		AggregateID:   aggregateID.String(),
		EventType:     string(eventType),
		Payload:       data,
		Headers:       map[string]string{},
		Status:        "pending",
	}
	return s.outboxRepo.Store(ctx, tx, outboxEvent)
}

// ---------------------------------------------------------------------
// Sanitization & validation
// ---------------------------------------------------------------------

func (s *roomService) sanitizeCreate(req *CreateRoomRequest) {
	req.RoomCode = strings.TrimSpace(strings.ToUpper(req.RoomCode))
	req.RoomName = strings.TrimSpace(req.RoomName)
	req.Building = strings.TrimSpace(req.Building)
}

func (s *roomService) validateCreateInput(req CreateRoomRequest) error {
	if req.CompanyID == uuid.Nil {
		return fmt.Errorf("%w: company_id is required", ErrInvalidInput)
	}
	if req.RoomCode == "" {
		return fmt.Errorf("%w: room_code is required", ErrInvalidInput)
	}
	return nil
}

func (s *roomService) validateUpdateInput(req UpdateRoomRequest) error {
	if req.RoomID == uuid.Nil {
		return fmt.Errorf("%w: room_id is required", ErrInvalidInput)
	}
	if req.RoomCode == "" {
		return fmt.Errorf("%w: room_code is required", ErrInvalidInput)
	}
	return nil
}

// ---------------------------------------------------------------------
// Create (with idempotency, audit, outbox)
// ---------------------------------------------------------------------

func (s *roomService) Create(ctx context.Context, req CreateRoomRequest, idempotencyKey string) (*models.Room, error) {
	logger := s.logger.With(
		zap.String("method", "Create"),
		zap.String("company_id", req.CompanyID.String()),
		zap.String("room_code", req.RoomCode),
		zap.String("idempotency_key", idempotencyKey),
	)
	s.sanitizeCreate(&req)

	if err := s.validateCreateInput(req); err != nil {
		return nil, err
	}

	tx, err := s.pgClient.BeginTx(ctx, nil)
	if err != nil {
		return nil, fmt.Errorf("begin tx: %w", err)
	}
	defer tx.Rollback()

	// Idempotency check (same pattern as assignment service)
	if idempotencyKey != "" {
		var existing models.Room
		if err := s.idempotencyStore.Get(ctx, tx, idempotencyKey, &existing); err == nil && existing.RoomID != uuid.Nil {
			logger.Info("returning idempotent response")
			return &existing, nil
		}
	}

	// Check for duplicate room code
	exists, err := s.repo.ExistsByCode(ctx, tx, req.CompanyID, req.RoomCode)
	if err != nil {
		return nil, err
	}
	if exists {
		return nil, fmt.Errorf("%w: room code %s already exists", ErrDuplicate, req.RoomCode)
	}

	room := &models.Room{
		CompanyID: req.CompanyID,
		RoomCode:  req.RoomCode,
		RoomName:  req.RoomName,
		Capacity:  req.Capacity,
		Building:  req.Building,
		Floor:     req.Floor,
		IsActive:  req.IsActive,
		CreatedBy: req.CreatedBy,
		UpdatedBy: req.UpdatedBy,
	}

	if err := s.repo.Create(ctx, tx, room); err != nil {
		return nil, err
	}

	// Store idempotency key inside transaction
	if idempotencyKey != "" {
		if err := s.idempotencyStore.Store(ctx, tx, idempotencyKey, room); err != nil {
			logger.Error("failed to store idempotency key", zap.Error(err))
		}
	}

	// Audit log
	if s.auditService != nil {
		_ = s.auditService.LogAction(ctx, nil, nil, "academics", "create", "room",
			&room.RoomID, "user", req.CreatedBy, nil, nil, map[string]interface{}{
				"room_code": room.RoomCode,
				"building":  room.Building,
			})
	}

	// Outbox event
	if err := s.storeOutboxEvent(ctx, tx, EventRoomCreated, room.RoomID, room); err != nil {
		return nil, fmt.Errorf("outbox store: %w", err)
	}

	if err := tx.Commit(); err != nil {
		return nil, fmt.Errorf("commit tx: %w", err)
	}

	logger.Info("room created", zap.String("id", room.RoomID.String()))

	// Notify the actor about room creation (after commit)
	if req.CreatedBy != nil && *req.CreatedBy != uuid.Nil {
		go func() {
			notifyCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			notifReq := CreateNotificationRequest{
				CompanyID: room.CompanyID,
				Title:     "Room Created",
				Message:   fmt.Sprintf("Room %s (%s) has been created.", room.RoomName, room.RoomCode),
				Type:      models.NotificationTypeInfo,
				Priority:  models.PriorityNormal,
				Targets: []NotificationTargetInput{
					{
						TargetType:     models.TargetUser,
						TargetEntityID: *req.CreatedBy,
					},
				},
				CreatedBy: req.CreatedBy,
			}
			if _, err := s.notificationSvc.Create(notifyCtx, notifReq, "room.created:"+room.RoomID.String()); err != nil {
				logger.Error("failed to create notification for room creation", zap.Error(err))
			}
		}()
	}

	return room, nil
}

// ---------------------------------------------------------------------
// GetByID, GetByCode, List, Count, ExistsByCode, ListByBuilding (read-only, no idempotency)
// ---------------------------------------------------------------------

func (s *roomService) GetByID(ctx context.Context, id uuid.UUID) (*models.Room, error) {
	room, err := s.repo.GetByID(ctx, s.pgClient.DB, id)
	if err != nil {
		return nil, err
	}
	if room == nil {
		return nil, fmt.Errorf("%w: room %s", ErrNotFound, id)
	}
	return room, nil
}

func (s *roomService) GetByCode(ctx context.Context, companyID uuid.UUID, code string) (*models.Room, error) {
	code = strings.TrimSpace(strings.ToUpper(code))
	room, err := s.repo.GetByCode(ctx, s.pgClient.DB, companyID, code)
	if err != nil {
		return nil, err
	}
	if room == nil {
		return nil, fmt.Errorf("%w: room code %s for company %s", ErrNotFound, code, companyID)
	}
	return room, nil
}

func (s *roomService) List(ctx context.Context, filter repository.RoomFilter, p repository.Pagination, srt repository.Sort) ([]*models.Room, error) {
	return s.repo.List(ctx, s.pgClient.DB, filter, p, srt)
}

func (s *roomService) Count(ctx context.Context, filter repository.RoomFilter) (int64, error) {
	return s.repo.Count(ctx, s.pgClient.DB, filter)
}

func (s *roomService) ExistsByCode(ctx context.Context, companyID uuid.UUID, code string) (bool, error) {
	code = strings.TrimSpace(strings.ToUpper(code))
	return s.repo.ExistsByCode(ctx, s.pgClient.DB, companyID, code)
}

func (s *roomService) ListByBuilding(ctx context.Context, companyID uuid.UUID, building string) ([]*models.Room, error) {
	return s.repo.ListByBuilding(ctx, s.pgClient.DB, companyID, building)
}

// ---------------------------------------------------------------------
// Update (with idempotency, audit, outbox)
// ---------------------------------------------------------------------

func (s *roomService) Update(ctx context.Context, req UpdateRoomRequest, idempotencyKey string) (*models.Room, error) {
	logger := s.logger.With(
		zap.String("method", "Update"),
		zap.String("room_id", req.RoomID.String()),
		zap.String("idempotency_key", idempotencyKey),
	)

	if err := s.validateUpdateInput(req); err != nil {
		return nil, err
	}

	tx, err := s.pgClient.BeginTx(ctx, nil)
	if err != nil {
		return nil, fmt.Errorf("begin tx: %w", err)
	}
	defer tx.Rollback()

	// Idempotency check
	if idempotencyKey != "" {
		var existing models.Room
		if err := s.idempotencyStore.Get(ctx, tx, idempotencyKey, &existing); err == nil && existing.RoomID != uuid.Nil {
			logger.Info("returning idempotent response")
			return &existing, nil
		}
	}

	room, err := s.repo.GetByID(ctx, tx, req.RoomID)
	if err != nil {
		return nil, err
	}
	if room == nil {
		return nil, fmt.Errorf("%w: room %s", ErrNotFound, req.RoomID)
	}

	// If room code is changing, check for uniqueness
	if req.RoomCode != room.RoomCode {
		exists, err := s.repo.ExistsByCode(ctx, tx, room.CompanyID, req.RoomCode)
		if err != nil {
			return nil, err
		}
		if exists {
			return nil, fmt.Errorf("%w: room code %s already exists", ErrDuplicate, req.RoomCode)
		}
	}

	oldRoom := *room
	room.RoomCode = req.RoomCode
	room.RoomName = req.RoomName
	room.Capacity = req.Capacity
	room.Building = req.Building
	room.Floor = req.Floor
	room.IsActive = req.IsActive
	room.UpdatedBy = req.UpdatedBy

	if err := s.repo.Update(ctx, tx, room); err != nil {
		return nil, err
	}

	// Store idempotency key
	if idempotencyKey != "" {
		if err := s.idempotencyStore.Store(ctx, tx, idempotencyKey, room); err != nil {
			logger.Error("failed to store idempotency key", zap.Error(err))
		}
	}

	// Audit log
	if s.auditService != nil {
		_ = s.auditService.LogAction(ctx, nil, nil, "academics", "update", "room",
			&req.RoomID, "user", req.UpdatedBy, nil, nil, map[string]interface{}{
				"old_room_code": oldRoom.RoomCode,
				"new_room_code": room.RoomCode,
				"old_capacity":  oldRoom.Capacity,
				"new_capacity":  room.Capacity,
			})
	}

	// Outbox event
	if err := s.storeOutboxEvent(ctx, tx, EventRoomUpdated, room.RoomID, map[string]interface{}{
		"old": oldRoom,
		"new": room,
	}); err != nil {
		return nil, fmt.Errorf("outbox store: %w", err)
	}

	if err := tx.Commit(); err != nil {
		return nil, fmt.Errorf("commit tx: %w", err)
	}

	logger.Info("room updated")

	// Notify the actor about room update (after commit)
	if req.UpdatedBy != nil && *req.UpdatedBy != uuid.Nil {
		go func() {
			notifyCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			notifReq := CreateNotificationRequest{
				CompanyID: room.CompanyID,
				Title:     "Room Updated",
				Message:   fmt.Sprintf("Room %s (%s) has been updated.", room.RoomName, room.RoomCode),
				Type:      models.NotificationTypeInfo,
				Priority:  models.PriorityNormal,
				Targets: []NotificationTargetInput{
					{
						TargetType:     models.TargetUser,
						TargetEntityID: *req.UpdatedBy,
					},
				},
				CreatedBy: req.UpdatedBy,
			}
			if _, err := s.notificationSvc.Create(notifyCtx, notifReq, "room.updated:"+room.RoomID.String()); err != nil {
				logger.Error("failed to create notification for room update", zap.Error(err))
			}
		}()
	}

	return room, nil
}

// ---------------------------------------------------------------------
// Delete (with idempotency, audit, outbox)
// ---------------------------------------------------------------------

func (s *roomService) Delete(ctx context.Context, id uuid.UUID, deletedBy *uuid.UUID, idempotencyKey string) error {
	logger := s.logger.With(
		zap.String("method", "Delete"),
		zap.String("room_id", id.String()),
		zap.String("idempotency_key", idempotencyKey),
	)

	tx, err := s.pgClient.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("begin tx: %w", err)
	}
	defer tx.Rollback()

	// Idempotency check
	if idempotencyKey != "" {
		var dummy struct{}
		if err := s.idempotencyStore.Get(ctx, tx, idempotencyKey, &dummy); err == nil {
			logger.Info("idempotent operation: already processed")
			return nil
		}
	}

	// Fetch room for audit and notification (before delete)
	room, err := s.repo.GetByID(ctx, tx, id)
	if err != nil {
		return err
	}
	if room == nil {
		return fmt.Errorf("%w: room %s", ErrNotFound, id)
	}

	if err := s.repo.Delete(ctx, tx, id, deletedBy); err != nil {
		return err
	}

	// Store idempotency key
	if idempotencyKey != "" {
		if err := s.idempotencyStore.Store(ctx, tx, idempotencyKey, struct{}{}); err != nil {
			logger.Error("failed to store idempotency key", zap.Error(err))
		}
	}

	// Audit log
	if s.auditService != nil {
		_ = s.auditService.LogAction(ctx, nil, nil, "academics", "delete", "room",
			&id, "user", deletedBy, nil, nil, map[string]interface{}{
				"room_code": room.RoomCode,
			})
	}

	// Outbox event
	if err := s.storeOutboxEvent(ctx, tx, EventRoomDeleted, id, map[string]interface{}{
		"room_id":    id,
		"deleted_by": deletedBy,
	}); err != nil {
		return fmt.Errorf("outbox store: %w", err)
	}

	if err := tx.Commit(); err != nil {
		return fmt.Errorf("commit tx: %w", err)
	}

	logger.Info("room deleted")

	// Notify the actor about room deletion (after commit)
	if deletedBy != nil && *deletedBy != uuid.Nil {
		go func() {
			notifyCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			notifReq := CreateNotificationRequest{
				CompanyID: room.CompanyID,
				Title:     "Room Deleted",
				Message:   fmt.Sprintf("Room %s (%s) has been deleted.", room.RoomName, room.RoomCode),
				Type:      models.NotificationTypeWarning,
				Priority:  models.PriorityHigh,
				Targets: []NotificationTargetInput{
					{
						TargetType:     models.TargetUser,
						TargetEntityID: *deletedBy,
					},
				},
				CreatedBy: deletedBy,
			}
			if _, err := s.notificationSvc.Create(notifyCtx, notifReq, "room.deleted:"+id.String()); err != nil {
				logger.Error("failed to create notification for room deletion", zap.Error(err))
			}
		}()
	}

	return nil
}

// ---------------------------------------------------------------------
// Activate (with idempotency, audit, outbox)
// ---------------------------------------------------------------------

func (s *roomService) Activate(ctx context.Context, id uuid.UUID, updatedBy *uuid.UUID, idempotencyKey string) error {
	logger := s.logger.With(
		zap.String("method", "Activate"),
		zap.String("room_id", id.String()),
		zap.String("idempotency_key", idempotencyKey),
	)

	tx, err := s.pgClient.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("begin tx: %w", err)
	}
	defer tx.Rollback()

	// Idempotency check
	if idempotencyKey != "" {
		var dummy struct{}
		if err := s.idempotencyStore.Get(ctx, tx, idempotencyKey, &dummy); err == nil {
			logger.Info("idempotent operation: already processed")
			return nil
		}
	}

	// Fetch room for notification
	room, err := s.repo.GetByID(ctx, tx, id)
	if err != nil {
		return err
	}
	if room == nil {
		return fmt.Errorf("%w: room %s", ErrNotFound, id)
	}

	if err := s.repo.Activate(ctx, tx, id, updatedBy); err != nil {
		return err
	}

	// Store idempotency key
	if idempotencyKey != "" {
		if err := s.idempotencyStore.Store(ctx, tx, idempotencyKey, struct{}{}); err != nil {
			logger.Error("failed to store idempotency key", zap.Error(err))
		}
	}

	// Audit log
	if s.auditService != nil {
		_ = s.auditService.LogAction(ctx, nil, nil, "academics", "activate", "room",
			&id, "user", updatedBy, nil, nil, map[string]interface{}{
				"room_code": room.RoomCode,
			})
	}

	// Outbox event
	if err := s.storeOutboxEvent(ctx, tx, EventRoomActivated, id, map[string]interface{}{
		"room_id":    id,
		"updated_by": updatedBy,
	}); err != nil {
		return fmt.Errorf("outbox store: %w", err)
	}

	if err := tx.Commit(); err != nil {
		return fmt.Errorf("commit tx: %w", err)
	}

	logger.Info("room activated")

	// Notify the actor about room activation (after commit)
	if updatedBy != nil && *updatedBy != uuid.Nil {
		go func() {
			notifyCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			notifReq := CreateNotificationRequest{
				CompanyID: room.CompanyID,
				Title:     "Room Activated",
				Message:   fmt.Sprintf("Room %s (%s) has been activated.", room.RoomName, room.RoomCode),
				Type:      models.NotificationTypeInfo,
				Priority:  models.PriorityNormal,
				Targets: []NotificationTargetInput{
					{
						TargetType:     models.TargetUser,
						TargetEntityID: *updatedBy,
					},
				},
				CreatedBy: updatedBy,
			}
			if _, err := s.notificationSvc.Create(notifyCtx, notifReq, "room.activated:"+id.String()); err != nil {
				logger.Error("failed to create notification for room activation", zap.Error(err))
			}
		}()
	}

	return nil
}

// ---------------------------------------------------------------------
// Deactivate (with idempotency, audit, outbox)
// ---------------------------------------------------------------------

func (s *roomService) Deactivate(ctx context.Context, id uuid.UUID, updatedBy *uuid.UUID, idempotencyKey string) error {
	logger := s.logger.With(
		zap.String("method", "Deactivate"),
		zap.String("room_id", id.String()),
		zap.String("idempotency_key", idempotencyKey),
	)

	tx, err := s.pgClient.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("begin tx: %w", err)
	}
	defer tx.Rollback()

	// Idempotency check
	if idempotencyKey != "" {
		var dummy struct{}
		if err := s.idempotencyStore.Get(ctx, tx, idempotencyKey, &dummy); err == nil {
			logger.Info("idempotent operation: already processed")
			return nil
		}
	}

	// Fetch room for notification
	room, err := s.repo.GetByID(ctx, tx, id)
	if err != nil {
		return err
	}
	if room == nil {
		return fmt.Errorf("%w: room %s", ErrNotFound, id)
	}

	if err := s.repo.Deactivate(ctx, tx, id, updatedBy); err != nil {
		return err
	}

	// Store idempotency key
	if idempotencyKey != "" {
		if err := s.idempotencyStore.Store(ctx, tx, idempotencyKey, struct{}{}); err != nil {
			logger.Error("failed to store idempotency key", zap.Error(err))
		}
	}

	// Audit log
	if s.auditService != nil {
		_ = s.auditService.LogAction(ctx, nil, nil, "academics", "deactivate", "room",
			&id, "user", updatedBy, nil, nil, map[string]interface{}{
				"room_code": room.RoomCode,
			})
	}

	// Outbox event
	if err := s.storeOutboxEvent(ctx, tx, EventRoomDeactivated, id, map[string]interface{}{
		"room_id":    id,
		"updated_by": updatedBy,
	}); err != nil {
		return fmt.Errorf("outbox store: %w", err)
	}

	if err := tx.Commit(); err != nil {
		return fmt.Errorf("commit tx: %w", err)
	}

	logger.Info("room deactivated")

	// Notify the actor about room deactivation (after commit)
	if updatedBy != nil && *updatedBy != uuid.Nil {
		go func() {
			notifyCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			notifReq := CreateNotificationRequest{
				CompanyID: room.CompanyID,
				Title:     "Room Deactivated",
				Message:   fmt.Sprintf("Room %s (%s) has been deactivated.", room.RoomName, room.RoomCode),
				Type:      models.NotificationTypeInfo,
				Priority:  models.PriorityNormal,
				Targets: []NotificationTargetInput{
					{
						TargetType:     models.TargetUser,
						TargetEntityID: *updatedBy,
					},
				},
				CreatedBy: updatedBy,
			}
			if _, err := s.notificationSvc.Create(notifyCtx, notifReq, "room.deactivated:"+id.String()); err != nil {
				logger.Error("failed to create notification for room deactivation", zap.Error(err))
			}
		}()
	}

	return nil
}

// ---------------------------------------------------------------------
// BulkCreate (with idempotency, audit, outbox)
// ---------------------------------------------------------------------

func (s *roomService) BulkCreate(ctx context.Context, reqs []CreateRoomRequest, idempotencyKey string) ([]*models.Room, error) {
	if len(reqs) == 0 {
		return nil, nil
	}

	logger := s.logger.With(
		zap.String("method", "BulkCreate"),
		zap.Int("count", len(reqs)),
		zap.String("idempotency_key", idempotencyKey),
	)

	tx, err := s.pgClient.BeginTx(ctx, nil)
	if err != nil {
		return nil, fmt.Errorf("begin tx: %w", err)
	}
	defer tx.Rollback()

	// Idempotency check
	if idempotencyKey != "" {
		var existing []*models.Room
		if err := s.idempotencyStore.Get(ctx, tx, idempotencyKey, &existing); err == nil && len(existing) > 0 {
			logger.Info("returning idempotent response")
			return existing, nil
		}
	}

	// Sanitize and validate each request
	type key struct {
		companyID uuid.UUID
		code      string
	}
	batchKeys := make(map[key]int)
	rooms := make([]*models.Room, 0, len(reqs))

	for i, req := range reqs {
		s.sanitizeCreate(&req)
		if err := s.validateCreateInput(req); err != nil {
			return nil, fmt.Errorf("item %d: %w", i, err)
		}
		k := key{companyID: req.CompanyID, code: req.RoomCode}
		if _, dup := batchKeys[k]; dup {
			return nil, fmt.Errorf("item %d: %w: duplicate room code %s in batch", i, ErrDuplicate, req.RoomCode)
		}
		batchKeys[k] = i

		rooms = append(rooms, &models.Room{
			CompanyID: req.CompanyID,
			RoomCode:  req.RoomCode,
			RoomName:  req.RoomName,
			Capacity:  req.Capacity,
			Building:  req.Building,
			Floor:     req.Floor,
			IsActive:  req.IsActive,
			CreatedBy: req.CreatedBy,
			UpdatedBy: req.UpdatedBy,
		})
	}

	// Check for duplicates against existing rooms
	for k := range batchKeys {
		exists, err := s.repo.ExistsByCode(ctx, tx, k.companyID, k.code)
		if err != nil {
			return nil, err
		}
		if exists {
			return nil, fmt.Errorf("%w: room code %s already exists", ErrDuplicate, k.code)
		}
	}

	if err := s.repo.BulkCreate(ctx, tx, rooms); err != nil {
		return nil, err
	}

	// Store idempotency key
	if idempotencyKey != "" {
		if err := s.idempotencyStore.Store(ctx, tx, idempotencyKey, rooms); err != nil {
			logger.Error("failed to store idempotency key", zap.Error(err))
		}
	}

	// Audit and outbox for each room
	for _, room := range rooms {
		if s.auditService != nil {
			_ = s.auditService.LogAction(ctx, nil, nil, "academics", "bulk_create", "room",
				&room.RoomID, "user", room.CreatedBy, nil, nil, map[string]interface{}{
					"room_code": room.RoomCode,
				})
		}
		if err := s.storeOutboxEvent(ctx, tx, EventRoomCreated, room.RoomID, room); err != nil {
			return nil, fmt.Errorf("outbox store for room %s: %w", room.RoomID, err)
		}
	}

	if err := tx.Commit(); err != nil {
		return nil, fmt.Errorf("commit tx: %w", err)
	}

	logger.Info("bulk created rooms", zap.Int("count", len(rooms)))

	// Notify each actor (after commit)
	for _, room := range rooms {
		if room.CreatedBy != nil && *room.CreatedBy != uuid.Nil {
			go func(r *models.Room) {
				notifyCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
				defer cancel()
				notifReq := CreateNotificationRequest{
					CompanyID: r.CompanyID,
					Title:     "Room Created (Bulk)",
					Message:   fmt.Sprintf("Room %s (%s) has been created.", r.RoomName, r.RoomCode),
					Type:      models.NotificationTypeInfo,
					Priority:  models.PriorityNormal,
					Targets: []NotificationTargetInput{
						{
							TargetType:     models.TargetUser,
							TargetEntityID: *r.CreatedBy,
						},
					},
					CreatedBy: r.CreatedBy,
				}
				if _, err := s.notificationSvc.Create(notifyCtx, notifReq, "room.created:"+r.RoomID.String()); err != nil {
					logger.Error("failed to create notification for bulk room creation",
						zap.String("room_id", r.RoomID.String()),
						zap.Error(err))
				}
			}(room)
		}
	}

	return rooms, nil
}

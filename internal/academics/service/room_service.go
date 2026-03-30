package service

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/google/uuid"
	"go.uber.org/zap"

	"auth-service/internal/academics/models"
	"auth-service/internal/academics/repository"
	"auth-service/internal/client"
)

type RoomService interface {
	Create(ctx context.Context, req CreateRoomRequest, idempotencyKey string) (*models.Room, error)
	GetByID(ctx context.Context, id uuid.UUID) (*models.Room, error)
	GetByCode(ctx context.Context, companyID uuid.UUID, code string) (*models.Room, error)
	List(ctx context.Context, filter repository.RoomFilter, p repository.Pagination, s repository.Sort) ([]*models.Room, error)
	Count(ctx context.Context, filter repository.RoomFilter) (int64, error)
	Update(ctx context.Context, req UpdateRoomRequest) (*models.Room, error)
	Delete(ctx context.Context, id uuid.UUID, deletedBy *uuid.UUID) error
	Activate(ctx context.Context, id uuid.UUID, updatedBy *uuid.UUID) error
	Deactivate(ctx context.Context, id uuid.UUID, updatedBy *uuid.UUID) error
	BulkCreate(ctx context.Context, reqs []CreateRoomRequest) ([]*models.Room, error)
	ExistsByCode(ctx context.Context, companyID uuid.UUID, code string) (bool, error)
	ListByBuilding(ctx context.Context, companyID uuid.UUID, building string) ([]*models.Room, error)
}

type roomService struct {
	repo             repository.RoomRepository
	idempotencyStore IdempotencyStore
	auditLogger      AuditLogger
	outboxStore      OutboxStore
	eventPublisher   EventPublisher
	pgClient         *client.PostgresClient
	logger           *zap.Logger
	notificationSvc  NotificationService // Added for notifications
}

func NewRoomService(
	repo repository.RoomRepository,
	idempotencyStore IdempotencyStore,
	auditLogger AuditLogger,
	outboxStore OutboxStore,
	eventPublisher EventPublisher,
	pgClient *client.PostgresClient,
	logger *zap.Logger,
	notificationSvc NotificationService, // New parameter
) RoomService {
	return &roomService{
		repo:             repo,
		idempotencyStore: idempotencyStore,
		auditLogger:      auditLogger,
		outboxStore:      outboxStore,
		eventPublisher:   eventPublisher,
		pgClient:         pgClient,
		logger:           logger.Named("room_service"),
		notificationSvc:  notificationSvc,
	}
}

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

// Create creates a new room with optional idempotency key.
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

	if idempotencyKey != "" {
		exists, err := s.idempotencyStore.Exists(ctx, tx, idempotencyKey)
		if err != nil {
			return nil, fmt.Errorf("idempotency check: %w", err)
		}
		if exists {
			var room models.Room
			if err := s.idempotencyStore.Get(ctx, tx, idempotencyKey, &room); err != nil {
				return nil, fmt.Errorf("failed to retrieve idempotent response: %w", err)
			}
			logger.Info("returning idempotent response")
			return &room, nil
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

	if idempotencyKey != "" {
		if err := s.idempotencyStore.Store(ctx, tx, idempotencyKey, room); err != nil {
			logger.Error("failed to store idempotency key", zap.Error(err))
			return nil, fmt.Errorf("failed to store idempotency key: %w", err)
		}
	}

	// Audit log
	if err := s.auditLogger.Log(ctx, tx, "CREATE", room.RoomID, nil, room, req.CreatedBy); err != nil {
		logger.Error("audit log failed", zap.Error(err))
	}

	// Outbox event
	if err := s.outboxStore.Store(ctx, tx, string(EventRoomCreated), room); err != nil {
		logger.Error("failed to store outbox event", zap.Error(err))
		return nil, fmt.Errorf("failed to store outbox event: %w", err)
	}

	if err := tx.Commit(); err != nil {
		return nil, fmt.Errorf("commit tx: %w", err)
	}

	logger.Info("room created", zap.String("id", room.RoomID.String()))

	// Notify the actor about room creation
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

// GetByID retrieves a room by ID.
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

// GetByCode retrieves a room by company and room code.
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

// List returns rooms matching the filter.
func (s *roomService) List(ctx context.Context, filter repository.RoomFilter, p repository.Pagination, srt repository.Sort) ([]*models.Room, error) {
	return s.repo.List(ctx, s.pgClient.DB, filter, p, srt)
}

// Count returns the number of rooms matching the filter.
func (s *roomService) Count(ctx context.Context, filter repository.RoomFilter) (int64, error) {
	return s.repo.Count(ctx, s.pgClient.DB, filter)
}

// Update updates an existing room.
func (s *roomService) Update(ctx context.Context, req UpdateRoomRequest) (*models.Room, error) {
	logger := s.logger.With(zap.String("method", "Update"), zap.String("room_id", req.RoomID.String()))

	if err := s.validateUpdateInput(req); err != nil {
		return nil, err
	}

	tx, err := s.pgClient.BeginTx(ctx, nil)
	if err != nil {
		return nil, fmt.Errorf("begin tx: %w", err)
	}
	defer tx.Rollback()

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

	if err := s.auditLogger.Log(ctx, tx, "UPDATE", room.RoomID, oldRoom, room, req.UpdatedBy); err != nil {
		logger.Error("audit log failed", zap.Error(err))
	}

	if err := s.outboxStore.Store(ctx, tx, string(EventRoomUpdated), map[string]interface{}{
		"old": oldRoom,
		"new": room,
	}); err != nil {
		logger.Error("failed to store outbox event", zap.Error(err))
		return nil, fmt.Errorf("failed to store outbox event: %w", err)
	}

	if err := tx.Commit(); err != nil {
		return nil, fmt.Errorf("commit tx: %w", err)
	}

	logger.Info("room updated")

	// Notify the actor about room update
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

// Delete soft-deletes a room.
func (s *roomService) Delete(ctx context.Context, id uuid.UUID, deletedBy *uuid.UUID) error {
	logger := s.logger.With(zap.String("method", "Delete"), zap.String("room_id", id.String()))

	// TODO: Check for dependencies (e.g., timetables) before deletion.
	// For now, assume it's allowed.

	tx, err := s.pgClient.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("begin tx: %w", err)
	}
	defer tx.Rollback()

	// Fetch room for notification (before delete)
	room, _ := s.repo.GetByID(ctx, tx, id)

	if err := s.repo.Delete(ctx, tx, id, deletedBy); err != nil {
		return err
	}

	if err := s.auditLogger.Log(ctx, tx, "DELETE", id, nil, nil, deletedBy); err != nil {
		logger.Error("audit log failed", zap.Error(err))
	}

	if err := s.outboxStore.Store(ctx, tx, string(EventRoomDeleted), map[string]interface{}{
		"room_id":    id,
		"deleted_by": deletedBy,
	}); err != nil {
		logger.Error("failed to store outbox event", zap.Error(err))
		return fmt.Errorf("failed to store outbox event: %w", err)
	}

	if err := tx.Commit(); err != nil {
		return fmt.Errorf("commit tx: %w", err)
	}

	logger.Info("room deleted")

	// Notify the actor about room deletion
	if room != nil && deletedBy != nil && *deletedBy != uuid.Nil {
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

// Activate sets a room as active.
func (s *roomService) Activate(ctx context.Context, id uuid.UUID, updatedBy *uuid.UUID) error {
	logger := s.logger.With(zap.String("method", "Activate"), zap.String("room_id", id.String()))

	tx, err := s.pgClient.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("begin tx: %w", err)
	}
	defer tx.Rollback()

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

	if err := s.auditLogger.Log(ctx, tx, "ACTIVATE", id, nil, nil, updatedBy); err != nil {
		logger.Error("audit log failed", zap.Error(err))
	}

	if err := s.outboxStore.Store(ctx, tx, string(EventRoomActivated), map[string]interface{}{
		"room_id":    id,
		"updated_by": updatedBy,
	}); err != nil {
		logger.Error("failed to store outbox event", zap.Error(err))
		return fmt.Errorf("failed to store outbox event: %w", err)
	}

	if err := tx.Commit(); err != nil {
		return fmt.Errorf("commit tx: %w", err)
	}

	logger.Info("room activated")

	// Notify the actor about room activation
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

// Deactivate sets a room as inactive.
func (s *roomService) Deactivate(ctx context.Context, id uuid.UUID, updatedBy *uuid.UUID) error {
	logger := s.logger.With(zap.String("method", "Deactivate"), zap.String("room_id", id.String()))

	tx, err := s.pgClient.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("begin tx: %w", err)
	}
	defer tx.Rollback()

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

	if err := s.auditLogger.Log(ctx, tx, "DEACTIVATE", id, nil, nil, updatedBy); err != nil {
		logger.Error("audit log failed", zap.Error(err))
	}

	if err := s.outboxStore.Store(ctx, tx, string(EventRoomDeactivated), map[string]interface{}{
		"room_id":    id,
		"updated_by": updatedBy,
	}); err != nil {
		logger.Error("failed to store outbox event", zap.Error(err))
		return fmt.Errorf("failed to store outbox event: %w", err)
	}

	if err := tx.Commit(); err != nil {
		return fmt.Errorf("commit tx: %w", err)
	}

	logger.Info("room deactivated")

	// Notify the actor about room deactivation
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

// BulkCreate creates multiple rooms in one transaction.
func (s *roomService) BulkCreate(ctx context.Context, reqs []CreateRoomRequest) ([]*models.Room, error) {
	if len(reqs) == 0 {
		return nil, nil
	}

	logger := s.logger.With(zap.String("method", "BulkCreate"), zap.Int("count", len(reqs)))

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

	tx, err := s.pgClient.BeginTx(ctx, nil)
	if err != nil {
		return nil, fmt.Errorf("begin tx: %w", err)
	}
	defer tx.Rollback()

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

	// Audit and outbox for each room
	for _, room := range rooms {
		if err := s.auditLogger.Log(ctx, tx, "CREATE", room.RoomID, nil, room, room.CreatedBy); err != nil {
			logger.Error("audit log failed", zap.String("room_id", room.RoomID.String()), zap.Error(err))
		}
		if err := s.outboxStore.Store(ctx, tx, string(EventRoomCreated), room); err != nil {
			logger.Error("failed to store outbox event", zap.String("room_id", room.RoomID.String()), zap.Error(err))
			return nil, fmt.Errorf("failed to store outbox event for room %s: %w", room.RoomID, err)
		}
	}

	if err := tx.Commit(); err != nil {
		return nil, fmt.Errorf("commit tx: %w", err)
	}

	logger.Info("bulk created rooms", zap.Int("count", len(rooms)))

	// Notify each actor (if different)
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

// ExistsByCode checks if a room code exists for a company.
func (s *roomService) ExistsByCode(ctx context.Context, companyID uuid.UUID, code string) (bool, error) {
	code = strings.TrimSpace(strings.ToUpper(code))
	return s.repo.ExistsByCode(ctx, s.pgClient.DB, companyID, code)
}

// ListByBuilding lists rooms in a building.
func (s *roomService) ListByBuilding(ctx context.Context, companyID uuid.UUID, building string) ([]*models.Room, error) {
	return s.repo.ListByBuilding(ctx, s.pgClient.DB, companyID, building)
}

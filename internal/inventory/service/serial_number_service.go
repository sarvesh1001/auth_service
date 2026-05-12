package service

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"time"

	"github.com/google/uuid"
	"go.uber.org/zap"

	"auth-service/internal/client"
	"auth-service/internal/infrastructure/audit"
	"auth-service/internal/infrastructure/idempotency"
	"auth-service/internal/infrastructure/outbox"
	"auth-service/internal/inventory/events"
	"auth-service/internal/inventory/inventory_errors"
	"auth-service/internal/inventory/models"
	"auth-service/internal/inventory/repository"
)

type SerialNumberService interface {
	RegisterSerialNumbers(ctx context.Context, req RegisterSerialNumbersRequest, idempotencyKey string) ([]*models.SerialNumber, error)
	AssignSerialToWarehouse(ctx context.Context, serialID, warehouseID uuid.UUID, companyID uuid.UUID, updatedBy *uuid.UUID, idempotencyKey string) error
	AssignSerialToBatch(ctx context.Context, serialID, batchID uuid.UUID, companyID uuid.UUID, updatedBy *uuid.UUID, idempotencyKey string) error
	UpdateSerialStatus(ctx context.Context, serialID uuid.UUID, companyID uuid.UUID, status string, updatedBy *uuid.UUID, idempotencyKey string) error
	GetSerialByNumber(ctx context.Context, companyID uuid.UUID, serialNumber string) (*models.SerialNumber, error)
	GetSerialByID(ctx context.Context, serialID uuid.UUID, companyID uuid.UUID) (*models.SerialNumber, error)
	ListSerials(ctx context.Context, filter repository.SerialFilter, page, pageSize int) ([]*models.SerialNumber, int64, error)
}

type RegisterSerialNumbersRequest struct {
	CompanyID     uuid.UUID
	ItemID        uuid.UUID
	SerialNumbers []string
	WarehouseID   *uuid.UUID
	BatchID       *uuid.UUID
	Status        *string
	CreatedBy     *uuid.UUID
}

type serialNumberService struct {
	serialRepo       repository.SerialRepository
	itemRepo         repository.ItemRepository
	warehouseRepo    repository.WarehouseRepository
	batchRepo        repository.BatchRepository
	txnSvc           SerialNumberTransactionService // NEW: transaction logging
	pgClient         *client.PostgresClient
	outboxRepo       outbox.Repository
	idempotencyStore idempotency.Store
	auditService     *audit.AuditService
	logger           *zap.Logger
}

func NewSerialNumberService(
	serialRepo repository.SerialRepository,
	itemRepo repository.ItemRepository,
	warehouseRepo repository.WarehouseRepository,
	batchRepo repository.BatchRepository,
	txnSvc SerialNumberTransactionService, // NEW parameter
	pgClient *client.PostgresClient,
	outboxRepo outbox.Repository,
	idempotencyStore idempotency.Store,
	auditService *audit.AuditService,
	logger *zap.Logger,
) SerialNumberService {
	return &serialNumberService{
		serialRepo:       serialRepo,
		itemRepo:         itemRepo,
		warehouseRepo:    warehouseRepo,
		batchRepo:        batchRepo,
		txnSvc:           txnSvc,
		pgClient:         pgClient,
		outboxRepo:       outboxRepo,
		idempotencyStore: idempotencyStore,
		auditService:     auditService,
		logger:           logger.Named("serial_number_service"),
	}
}

func (s *serialNumberService) RegisterSerialNumbers(ctx context.Context, req RegisterSerialNumbersRequest, idempotencyKey string) ([]*models.SerialNumber, error) {
	logger := s.logger.With(zap.String("method", "RegisterSerialNumbers"), zap.String("idempotency_key", idempotencyKey))
	if err := s.validateRegisterRequest(req); err != nil {
		return nil, err
	}

	tx, err := s.pgClient.BeginTx(ctx, nil)
	if err != nil {
		return nil, fmt.Errorf("begin tx: %w", err)
	}
	defer tx.Rollback()

	var cached []*models.SerialNumber
	if err := s.idempotencyStore.Get(ctx, tx, idempotencyKey, &cached); err == nil && cached != nil {
		logger.Info("idempotent request – returning cached serials")
		return cached, nil
	}

	item, err := s.itemRepo.GetByID(ctx, tx, req.ItemID)
	if err != nil {
		return nil, fmt.Errorf("get item: %w", err)
	}
	if !item.IsSerialTracked {
		return nil, fmt.Errorf("%w: item %s is not serial tracked", inventory_errors.ErrInvalidInput, req.ItemID)
	}

	if req.WarehouseID != nil {
		if _, err := s.warehouseRepo.GetByID(ctx, tx, req.CompanyID, *req.WarehouseID); err != nil {
			return nil, fmt.Errorf("warehouse validation: %w", err)
		}
	}
	if req.BatchID != nil {
		batch, err := s.batchRepo.GetByID(ctx, tx, *req.BatchID)
		if err != nil {
			return nil, fmt.Errorf("batch validation: %w", err)
		}
		if batch.ItemID != req.ItemID {
			return nil, fmt.Errorf("%w: batch does not belong to item %s", inventory_errors.ErrInvalidInput, req.ItemID)
		}
	}

	status := "available"
	if req.Status != nil {
		status = *req.Status
	}

	createdSerials := make([]*models.SerialNumber, 0, len(req.SerialNumbers))
	for _, sn := range req.SerialNumbers {
		exists, err := s.serialRepo.GetBySerialNumber(ctx, tx, req.CompanyID, sn)
		if err == nil && exists != nil {
			return nil, fmt.Errorf("%w: serial number %s already exists", inventory_errors.ErrDuplicate, sn)
		}

		serial := &models.SerialNumber{
			SerialID:     uuid.New(),
			CompanyID:    req.CompanyID,
			ItemID:       req.ItemID,
			SerialNumber: sn,
			WarehouseID:  req.WarehouseID,
			BatchID:      req.BatchID,
			Status:       &status,
			CreatedAt:    time.Now(),
		}
		if err := s.serialRepo.Create(ctx, tx, serial); err != nil {
			return nil, fmt.Errorf("create serial %s: %w", sn, err)
		}

		// Log "created" transaction
		if err := s.txnSvc.LogCustom(ctx, tx, LogCustomRequest{
			CompanyID:       req.CompanyID,
			SerialID:        serial.SerialID,
			TransactionType: "created",
			ToWarehouseID:   req.WarehouseID,
			ToBatchID:       req.BatchID,
			NewStatus:       &status,
			MovementID:      nil,
			CreatedBy:       req.CreatedBy,
			Notes:           stringPtr("Serial number registered"),
		}, idempotencyKey+":txn:"+serial.SerialID.String()); err != nil {
			logger.Warn("failed to log serial creation transaction", zap.Error(err))
		}

		createdSerials = append(createdSerials, serial)
	}

	_ = s.emitSerialEvent(ctx, tx, req.CompanyID, req.ItemID, len(createdSerials), events.EventSerialNumbersRegistered)
	_ = s.idempotencyStore.Store(ctx, tx, idempotencyKey, createdSerials)

	if err := tx.Commit(); err != nil {
		return nil, fmt.Errorf("commit tx: %w", err)
	}

	if s.auditService != nil {
		_ = s.auditService.LogAction(ctx, nil, &req.CompanyID, "inventory", "register_serials", "serial_numbers",
			nil, "user", req.CreatedBy, nil, nil, map[string]interface{}{
				"item_id":      req.ItemID.String(),
				"count":        len(req.SerialNumbers),
				"first_serial": req.SerialNumbers[0],
			})
	}
	logger.Info("serial numbers registered", zap.Int("count", len(createdSerials)))
	return createdSerials, nil
}

func (s *serialNumberService) AssignSerialToWarehouse(ctx context.Context, serialID, warehouseID uuid.UUID, companyID uuid.UUID, updatedBy *uuid.UUID, idempotencyKey string) error {
	logger := s.logger.With(zap.String("method", "AssignSerialToWarehouse"), zap.String("idempotency_key", idempotencyKey))
	tx, err := s.pgClient.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("begin tx: %w", err)
	}
	defer tx.Rollback()

	var processed bool
	if err := s.idempotencyStore.Get(ctx, tx, idempotencyKey, &processed); err == nil && processed {
		logger.Info("idempotent – already assigned")
		return nil
	}

	serial, err := s.serialRepo.GetByID(ctx, tx, serialID)
	if err != nil {
		return err
	}
	if serial.CompanyID != companyID {
		return inventory_errors.ErrPermissionDenied
	}

	if _, err := s.warehouseRepo.GetByID(ctx, tx, companyID, warehouseID); err != nil {
		return fmt.Errorf("warehouse validation: %w", err)
	}

	if err := s.serialRepo.AssignToWarehouse(ctx, tx, serialID, warehouseID); err != nil {
		return fmt.Errorf("assign to warehouse: %w", err)
	}

	// Log assignment transaction
	if err := s.txnSvc.LogAssignment(ctx, tx, LogAssignmentRequest{
		CompanyID:     companyID,
		SerialID:      serialID,
		ToWarehouseID: &warehouseID,
		ToBatchID:     nil,
		OldStatus:     serial.Status,
		NewStatus:     serial.Status,
		MovementID:    nil,
		CreatedBy:     updatedBy,
		Notes:         stringPtr("Assigned to warehouse"),
	}, idempotencyKey+":txn"); err != nil {
		logger.Warn("failed to log assignment transaction", zap.Error(err))
	}

	_ = s.idempotencyStore.Store(ctx, tx, idempotencyKey, true)
	if err := tx.Commit(); err != nil {
		return fmt.Errorf("commit tx: %w", err)
	}

	if s.auditService != nil {
		_ = s.auditService.LogAction(ctx, nil, &companyID, "inventory", "assign_serial_warehouse", "serial_number",
			&serialID, "user", updatedBy, nil, nil, map[string]interface{}{
				"warehouse_id": warehouseID.String(),
			})
	}
	return nil
}

func (s *serialNumberService) AssignSerialToBatch(ctx context.Context, serialID, batchID uuid.UUID, companyID uuid.UUID, updatedBy *uuid.UUID, idempotencyKey string) error {
	logger := s.logger.With(zap.String("method", "AssignSerialToBatch"), zap.String("idempotency_key", idempotencyKey))
	tx, err := s.pgClient.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("begin tx: %w", err)
	}
	defer tx.Rollback()

	var processed bool
	if err := s.idempotencyStore.Get(ctx, tx, idempotencyKey, &processed); err == nil && processed {
		logger.Info("idempotent – already assigned")
		return nil
	}

	serial, err := s.serialRepo.GetByID(ctx, tx, serialID)
	if err != nil {
		return err
	}
	if serial.CompanyID != companyID {
		return inventory_errors.ErrPermissionDenied
	}

	batch, err := s.batchRepo.GetByID(ctx, tx, batchID)
	if err != nil {
		return err
	}
	if batch.ItemID != serial.ItemID {
		return fmt.Errorf("%w: batch item does not match serial item", inventory_errors.ErrInvalidInput)
	}

	if err := s.serialRepo.AssignToBatch(ctx, tx, serialID, batchID); err != nil {
		return fmt.Errorf("assign to batch: %w", err)
	}

	// Log assignment transaction
	if err := s.txnSvc.LogAssignment(ctx, tx, LogAssignmentRequest{
		CompanyID:     companyID,
		SerialID:      serialID,
		ToWarehouseID: nil,
		ToBatchID:     &batchID,
		OldStatus:     serial.Status,
		NewStatus:     serial.Status,
		MovementID:    nil,
		CreatedBy:     updatedBy,
		Notes:         stringPtr("Assigned to batch"),
	}, idempotencyKey+":txn"); err != nil {
		logger.Warn("failed to log assignment transaction", zap.Error(err))
	}

	_ = s.idempotencyStore.Store(ctx, tx, idempotencyKey, true)
	if err := tx.Commit(); err != nil {
		return fmt.Errorf("commit tx: %w", err)
	}

	if s.auditService != nil {
		_ = s.auditService.LogAction(ctx, nil, &companyID, "inventory", "assign_serial_batch", "serial_number",
			&serialID, "user", updatedBy, nil, nil, map[string]interface{}{
				"batch_id": batchID.String(),
			})
	}
	return nil
}

func (s *serialNumberService) UpdateSerialStatus(ctx context.Context, serialID uuid.UUID, companyID uuid.UUID, status string, updatedBy *uuid.UUID, idempotencyKey string) error {
	logger := s.logger.With(zap.String("method", "UpdateSerialStatus"), zap.String("idempotency_key", idempotencyKey))
	if status == "" {
		return fmt.Errorf("%w: status cannot be empty", inventory_errors.ErrInvalidInput)
	}

	tx, err := s.pgClient.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("begin tx: %w", err)
	}
	defer tx.Rollback()

	var processed bool
	if err := s.idempotencyStore.Get(ctx, tx, idempotencyKey, &processed); err == nil && processed {
		logger.Info("idempotent – already updated")
		return nil
	}

	serial, err := s.serialRepo.GetByID(ctx, tx, serialID)
	if err != nil {
		return err
	}
	if serial.CompanyID != companyID {
		return inventory_errors.ErrPermissionDenied
	}

	oldStatus := serial.Status
	if err := s.serialRepo.UpdateStatus(ctx, tx, serialID, status); err != nil {
		return fmt.Errorf("update status: %w", err)
	}

	// Log status change transaction
	if err := s.txnSvc.LogStatusChange(ctx, tx, LogStatusChangeRequest{
		CompanyID:  companyID,
		SerialID:   serialID,
		OldStatus:  oldStatus,
		NewStatus:  status,
		MovementID: nil,
		CreatedBy:  updatedBy,
		Notes:      stringPtr("Status changed"),
	}, idempotencyKey+":txn"); err != nil {
		logger.Warn("failed to log status change transaction", zap.Error(err))
	}

	_ = s.idempotencyStore.Store(ctx, tx, idempotencyKey, true)
	if err := tx.Commit(); err != nil {
		return fmt.Errorf("commit tx: %w", err)
	}

	if s.auditService != nil {
		_ = s.auditService.LogAction(ctx, nil, &companyID, "inventory", "update_serial_status", "serial_number",
			&serialID, "user", updatedBy, nil, nil, map[string]interface{}{
				"new_status": status,
			})
	}
	return nil
}

func (s *serialNumberService) GetSerialByNumber(ctx context.Context, companyID uuid.UUID, serialNumber string) (*models.SerialNumber, error) {
	if serialNumber == "" {
		return nil, fmt.Errorf("%w: serial_number required", inventory_errors.ErrInvalidInput)
	}
	return s.serialRepo.GetBySerialNumber(ctx, s.pgClient.DB, companyID, serialNumber)
}

func (s *serialNumberService) GetSerialByID(ctx context.Context, serialID uuid.UUID, companyID uuid.UUID) (*models.SerialNumber, error) {
	serial, err := s.serialRepo.GetByID(ctx, s.pgClient.DB, serialID)
	if err != nil {
		return nil, err
	}
	if serial.CompanyID != companyID {
		return nil, inventory_errors.ErrPermissionDenied
	}
	return serial, nil
}

func (s *serialNumberService) ListSerials(ctx context.Context, filter repository.SerialFilter, page, pageSize int) ([]*models.SerialNumber, int64, error) {
	if page < 1 {
		page = 1
	}
	if pageSize < 1 {
		pageSize = 20
	}
	if pageSize > 100 {
		pageSize = 100
	}
	p := repository.Pagination{Limit: pageSize, Offset: (page - 1) * pageSize}
	sort := repository.Sort{Field: "created_at", Direction: "DESC"}
	return s.serialRepo.List(ctx, s.pgClient.DB, filter, p, sort)
}

func (s *serialNumberService) validateRegisterRequest(req RegisterSerialNumbersRequest) error {
	if req.CompanyID == uuid.Nil {
		return fmt.Errorf("%w: company_id required", inventory_errors.ErrInvalidInput)
	}
	if req.ItemID == uuid.Nil {
		return fmt.Errorf("%w: item_id required", inventory_errors.ErrInvalidInput)
	}
	if len(req.SerialNumbers) == 0 {
		return fmt.Errorf("%w: at least one serial number required", inventory_errors.ErrInvalidInput)
	}
	for _, sn := range req.SerialNumbers {
		if sn == "" {
			return fmt.Errorf("%w: serial number cannot be empty", inventory_errors.ErrInvalidInput)
		}
	}
	return nil
}

func (s *serialNumberService) emitSerialEvent(ctx context.Context, tx *sql.Tx, companyID, itemID uuid.UUID, count int, eventType string) error {
	payload := map[string]interface{}{
		"company_id": companyID.String(),
		"item_id":    itemID.String(),
		"count":      count,
		"timestamp":  time.Now(),
	}
	data, err := json.Marshal(payload)
	if err != nil {
		return err
	}
	event := &outbox.Event{
		EventID:       uuid.New().String(),
		AggregateType: "serial_numbers",
		AggregateID:   itemID.String(),
		EventType:     eventType,
		Topic:         events.TopicInventoryEvents,
		Payload:       data,
	}
	return s.outboxRepo.Store(ctx, tx, event)
}

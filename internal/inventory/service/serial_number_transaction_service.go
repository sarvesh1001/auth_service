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

// SerialNumberTransactionService defines the audit trail operations for serial numbers.
type SerialNumberTransactionService interface {
	// LogAssignment records when a serial number is assigned to a warehouse and/or batch.
	LogAssignment(ctx context.Context, db repository.DBTX, req LogAssignmentRequest, idempotencyKey string) error

	// LogStatusChange records when a serial number's status changes.
	LogStatusChange(ctx context.Context, db repository.DBTX, req LogStatusChangeRequest, idempotencyKey string) error

	// LogShipment records when a serial number is shipped out (sold).
	LogShipment(ctx context.Context, db repository.DBTX, req LogShipmentRequest, idempotencyKey string) error

	// LogTransfer records when a serial number moves between warehouses and/or batches.
	LogTransfer(ctx context.Context, db repository.DBTX, req LogTransferRequest, idempotencyKey string) error

	// LogCustom records a generic transaction with a custom type and notes.
	LogCustom(ctx context.Context, db repository.DBTX, req LogCustomRequest, idempotencyKey string) error

	// GetTransactionHistory retrieves transactions for a given serial number.
	GetTransactionHistory(ctx context.Context, db repository.DBTX, serialID uuid.UUID, limit, offset int) ([]*models.SerialNumberTransaction, error)

	// ListTransactions lists transactions by company with filters.
	ListTransactions(ctx context.Context, db repository.DBTX, filter repository.SerialNumberTransactionFilter, page, pageSize int) ([]*models.SerialNumberTransaction, int64, error)
}

// Request structs
type LogAssignmentRequest struct {
	CompanyID     uuid.UUID
	SerialID      uuid.UUID
	ToWarehouseID *uuid.UUID
	ToBatchID     *uuid.UUID
	OldStatus     *string
	NewStatus     *string
	MovementID    *uuid.UUID
	CreatedBy     *uuid.UUID
	Notes         *string
}

type LogStatusChangeRequest struct {
	CompanyID  uuid.UUID
	SerialID   uuid.UUID
	OldStatus  *string
	NewStatus  string
	MovementID *uuid.UUID
	CreatedBy  *uuid.UUID
	Notes      *string
}

type LogShipmentRequest struct {
	CompanyID  uuid.UUID
	SerialID   uuid.UUID
	MovementID uuid.UUID
	CreatedBy  *uuid.UUID
	Notes      *string
}

type LogTransferRequest struct {
	CompanyID       uuid.UUID
	SerialID        uuid.UUID
	FromWarehouseID *uuid.UUID
	ToWarehouseID   *uuid.UUID
	FromBatchID     *uuid.UUID
	ToBatchID       *uuid.UUID
	MovementID      *uuid.UUID
	CreatedBy       *uuid.UUID
	Notes           *string
}

type LogCustomRequest struct {
	CompanyID       uuid.UUID
	SerialID        uuid.UUID
	TransactionType string
	FromWarehouseID *uuid.UUID
	ToWarehouseID   *uuid.UUID
	FromBatchID     *uuid.UUID
	ToBatchID       *uuid.UUID
	OldStatus       *string
	NewStatus       *string
	MovementID      *uuid.UUID
	CreatedBy       *uuid.UUID
	Notes           *string
}

type serialNumberTransactionService struct {
	txnRepo          repository.SerialNumberTransactionRepository
	serialRepo       repository.SerialRepository
	pgClient         *client.PostgresClient
	outboxRepo       outbox.Repository
	idempotencyStore idempotency.Store
	auditService     *audit.AuditService
	logger           *zap.Logger
}

// NewSerialNumberTransactionService creates a new instance.
func NewSerialNumberTransactionService(
	txnRepo repository.SerialNumberTransactionRepository,
	serialRepo repository.SerialRepository,
	pgClient *client.PostgresClient,
	outboxRepo outbox.Repository,
	idempotencyStore idempotency.Store,
	auditService *audit.AuditService,
	logger *zap.Logger,
) SerialNumberTransactionService {
	return &serialNumberTransactionService{
		txnRepo:          txnRepo,
		serialRepo:       serialRepo,
		pgClient:         pgClient,
		outboxRepo:       outboxRepo,
		idempotencyStore: idempotencyStore,
		auditService:     auditService,
		logger:           logger.Named("serial_number_txn_service"),
	}
}

// LogAssignment implements SerialNumberTransactionService.
func (s *serialNumberTransactionService) LogAssignment(ctx context.Context, db repository.DBTX, req LogAssignmentRequest, idempotencyKey string) error {
	logger := s.logger.With(zap.String("method", "LogAssignment"), zap.String("key", idempotencyKey))
	return s.logTransaction(ctx, db, &transactionInput{
		CompanyID:       req.CompanyID,
		SerialID:        req.SerialID,
		TransactionType: "assigned",
		ToWarehouseID:   req.ToWarehouseID,
		ToBatchID:       req.ToBatchID,
		OldStatus:       req.OldStatus,
		NewStatus:       req.NewStatus,
		MovementID:      req.MovementID,
		CreatedBy:       req.CreatedBy,
		Notes:           req.Notes,
	}, idempotencyKey, logger, "assignment")
}

// LogStatusChange implements SerialNumberTransactionService.
func (s *serialNumberTransactionService) LogStatusChange(ctx context.Context, db repository.DBTX, req LogStatusChangeRequest, idempotencyKey string) error {
	logger := s.logger.With(zap.String("method", "LogStatusChange"), zap.String("key", idempotencyKey))
	return s.logTransaction(ctx, db, &transactionInput{
		CompanyID:       req.CompanyID,
		SerialID:        req.SerialID,
		TransactionType: "status_change",
		OldStatus:       req.OldStatus,
		NewStatus:       &req.NewStatus,
		MovementID:      req.MovementID,
		CreatedBy:       req.CreatedBy,
		Notes:           req.Notes,
	}, idempotencyKey, logger, "status change")
}

// LogShipment implements SerialNumberTransactionService.
func (s *serialNumberTransactionService) LogShipment(ctx context.Context, db repository.DBTX, req LogShipmentRequest, idempotencyKey string) error {
	logger := s.logger.With(zap.String("method", "LogShipment"), zap.String("key", idempotencyKey))
	return s.logTransaction(ctx, db, &transactionInput{
		CompanyID:       req.CompanyID,
		SerialID:        req.SerialID,
		TransactionType: "sold",
		MovementID:      &req.MovementID,
		CreatedBy:       req.CreatedBy,
		Notes:           req.Notes,
	}, idempotencyKey, logger, "shipment")
}

// LogTransfer implements SerialNumberTransactionService.
func (s *serialNumberTransactionService) LogTransfer(ctx context.Context, db repository.DBTX, req LogTransferRequest, idempotencyKey string) error {
	logger := s.logger.With(zap.String("method", "LogTransfer"), zap.String("key", idempotencyKey))
	return s.logTransaction(ctx, db, &transactionInput{
		CompanyID:       req.CompanyID,
		SerialID:        req.SerialID,
		TransactionType: "transferred",
		FromWarehouseID: req.FromWarehouseID,
		ToWarehouseID:   req.ToWarehouseID,
		FromBatchID:     req.FromBatchID,
		ToBatchID:       req.ToBatchID,
		MovementID:      req.MovementID,
		CreatedBy:       req.CreatedBy,
		Notes:           req.Notes,
	}, idempotencyKey, logger, "transfer")
}

// LogCustom implements SerialNumberTransactionService.
func (s *serialNumberTransactionService) LogCustom(ctx context.Context, db repository.DBTX, req LogCustomRequest, idempotencyKey string) error {
	logger := s.logger.With(zap.String("method", "LogCustom"), zap.String("key", idempotencyKey))
	if req.TransactionType == "" {
		return fmt.Errorf("%w: transaction_type is required", inventory_errors.ErrInvalidInput)
	}
	return s.logTransaction(ctx, db, &transactionInput{
		CompanyID:       req.CompanyID,
		SerialID:        req.SerialID,
		TransactionType: req.TransactionType,
		FromWarehouseID: req.FromWarehouseID,
		ToWarehouseID:   req.ToWarehouseID,
		FromBatchID:     req.FromBatchID,
		ToBatchID:       req.ToBatchID,
		OldStatus:       req.OldStatus,
		NewStatus:       req.NewStatus,
		MovementID:      req.MovementID,
		CreatedBy:       req.CreatedBy,
		Notes:           req.Notes,
	}, idempotencyKey, logger, "custom")
}

// GetTransactionHistory retrieves transactions for a serial number.
func (s *serialNumberTransactionService) GetTransactionHistory(ctx context.Context, db repository.DBTX, serialID uuid.UUID, limit, offset int) ([]*models.SerialNumberTransaction, error) {
	if limit <= 0 {
		limit = 50
	}
	if limit > 1000 {
		limit = 1000
	}
	if offset < 0 {
		offset = 0
	}
	return s.txnRepo.GetBySerialID(ctx, db, serialID, limit, offset)
}

// ListTransactions lists company transactions with filters.
func (s *serialNumberTransactionService) ListTransactions(ctx context.Context, db repository.DBTX, filter repository.SerialNumberTransactionFilter, page, pageSize int) ([]*models.SerialNumberTransaction, int64, error) {
	if page < 1 {
		page = 1
	}
	if pageSize < 1 {
		pageSize = 20
	}
	if pageSize > 100 {
		pageSize = 100
	}
	pagination := repository.Pagination{
		Limit:  pageSize,
		Offset: (page - 1) * pageSize,
	}
	sort := repository.Sort{Field: "transaction_date", Direction: "DESC"}
	return s.txnRepo.ListByCompany(ctx, db, filter, pagination, sort)
}

// ----- internal helpers -----

type transactionInput struct {
	CompanyID       uuid.UUID
	SerialID        uuid.UUID
	TransactionType string
	FromWarehouseID *uuid.UUID
	ToWarehouseID   *uuid.UUID
	FromBatchID     *uuid.UUID
	ToBatchID       *uuid.UUID
	OldStatus       *string
	NewStatus       *string
	MovementID      *uuid.UUID
	CreatedBy       *uuid.UUID
	Notes           *string
}

func (s *serialNumberTransactionService) logTransaction(ctx context.Context, db repository.DBTX, input *transactionInput, idempotencyKey string, logger *zap.Logger, actionName string) error {
	if input.CompanyID == uuid.Nil || input.SerialID == uuid.Nil {
		return fmt.Errorf("%w: company_id and serial_id required", inventory_errors.ErrInvalidInput)
	}

	// Validate serial exists and belongs to company
	serial, err := s.serialRepo.GetByID(ctx, db, input.SerialID)
	if err != nil {
		return fmt.Errorf("serial not found: %w", err)
	}
	if serial.CompanyID != input.CompanyID {
		return inventory_errors.ErrPermissionDenied
	}

	// Prepare transaction record
	txn := &models.SerialNumberTransaction{
		TransactionID:   uuid.New(),
		SerialID:        input.SerialID,
		CompanyID:       input.CompanyID,
		MovementID:      input.MovementID,
		FromWarehouseID: input.FromWarehouseID,
		ToWarehouseID:   input.ToWarehouseID,
		FromBatchID:     input.FromBatchID,
		ToBatchID:       input.ToBatchID,
		OldStatus:       input.OldStatus,
		NewStatus:       input.NewStatus,
		TransactionType: input.TransactionType,
		TransactionDate: time.Now(),
		CreatedBy:       input.CreatedBy,
		Notes:           input.Notes,
	}

	// Idempotency check (create a unique key per transaction input)
	if idempotencyKey == "" {
		idempotencyKey = fmt.Sprintf("serial_txn:%s:%s:%d", input.SerialID.String(), input.TransactionType, time.Now().UnixNano())
	}

	sqlTx, ok := db.(*sql.Tx)
	if !ok {
		return fmt.Errorf("db is not a *sql.Tx; call this method within a transaction")
	}

	var processed bool
	if err := s.idempotencyStore.Get(ctx, sqlTx, idempotencyKey, &processed); err == nil && processed {
		logger.Info("idempotent – transaction already logged")
		return nil
	}

	if err := s.txnRepo.Create(ctx, db, txn); err != nil {
		return fmt.Errorf("failed to create serial transaction: %w", err)
	}

	// Emit outbox event for external consumers (e.g., compliance, analytics)
	if err := s.emitSerialTransactionEvent(ctx, sqlTx, txn); err != nil {
		logger.Warn("failed to emit transaction event", zap.Error(err))
	}

	if err := s.idempotencyStore.Store(ctx, sqlTx, idempotencyKey, true); err != nil {
		logger.Warn("failed to store idempotency key", zap.Error(err))
	}

	if s.auditService != nil {
		_ = s.auditService.LogAction(ctx, nil, &input.CompanyID, "inventory", "serial_txn_"+actionName, "serial_number",
			&input.SerialID, "user", input.CreatedBy, nil, nil, map[string]interface{}{
				"transaction_type": input.TransactionType,
				"notes":            input.Notes,
			})
	}

	logger.Info("serial number transaction logged",
		zap.String("serial_id", input.SerialID.String()),
		zap.String("type", input.TransactionType))
	return nil
}

func (s *serialNumberTransactionService) emitSerialTransactionEvent(ctx context.Context, tx *sql.Tx, txn *models.SerialNumberTransaction) error {
	payload := map[string]interface{}{
		"transaction_id":   txn.TransactionID.String(),
		"serial_id":        txn.SerialID.String(),
		"company_id":       txn.CompanyID.String(),
		"transaction_type": txn.TransactionType,
		"transaction_date": txn.TransactionDate,
	}
	if txn.MovementID != nil {
		payload["movement_id"] = txn.MovementID.String()
	}
	if txn.FromWarehouseID != nil {
		payload["from_warehouse_id"] = txn.FromWarehouseID.String()
	}
	if txn.ToWarehouseID != nil {
		payload["to_warehouse_id"] = txn.ToWarehouseID.String()
	}
	if txn.FromBatchID != nil {
		payload["from_batch_id"] = txn.FromBatchID.String()
	}
	if txn.ToBatchID != nil {
		payload["to_batch_id"] = txn.ToBatchID.String()
	}
	if txn.OldStatus != nil {
		payload["old_status"] = *txn.OldStatus
	}
	if txn.NewStatus != nil {
		payload["new_status"] = *txn.NewStatus
	}
	if txn.Notes != nil {
		payload["notes"] = *txn.Notes
	}
	data, err := json.Marshal(payload)
	if err != nil {
		return err
	}
	event := &outbox.Event{
		EventID:       uuid.New().String(),
		AggregateType: "serial_number_transaction",
		AggregateID:   txn.SerialID.String(),
		EventType:     events.EventSerialNumberTransaction,
		Topic:         events.TopicInventoryEvents,
		Payload:       data,
	}
	return s.outboxRepo.Store(ctx, tx, event)
}

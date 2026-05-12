package service

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"time"

	"github.com/google/uuid"
	"github.com/shopspring/decimal"
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

// PickingService defines operations for warehouse picking lists.
type PickingService interface {
	GeneratePickingList(ctx context.Context, req GeneratePickingListRequest, idempotencyKey string) (*models.PickingList, error)
	AssignPicker(ctx context.Context, pickingListID, pickerID uuid.UUID, companyID uuid.UUID, idempotencyKey string) error
	PickItem(ctx context.Context, pickingItemID uuid.UUID, pickedQty decimal.Decimal, companyID uuid.UUID, idempotencyKey string) error
	CompletePicking(ctx context.Context, pickingListID uuid.UUID, companyID uuid.UUID, idempotencyKey string) error
	GetPickingList(ctx context.Context, pickingListID, companyID uuid.UUID) (*models.PickingList, []*models.PickingListItem, error)
	ListPickingListsByCompany(ctx context.Context, companyID uuid.UUID, status *string, page, pageSize int) ([]*models.PickingList, int64, error)
}

type GeneratePickingListRequest struct {
	CompanyID          uuid.UUID
	FulfillmentOrderID uuid.UUID
	WarehouseID        uuid.UUID
	GeneratedBy        *uuid.UUID
}

type pickingService struct {
	pickingListRepo     repository.PickingListRepository
	pickingListItemRepo repository.PickingListItemRepository
	fulfillmentRepo     repository.FulfillmentRepository
	warehouseRepo       repository.WarehouseRepository
	pgClient            *client.PostgresClient
	outboxRepo          outbox.Repository
	idempotencyStore    idempotency.Store
	auditService        *audit.AuditService
	logger              *zap.Logger
}

func NewPickingService(
	pickingListRepo repository.PickingListRepository,
	pickingListItemRepo repository.PickingListItemRepository,
	fulfillmentRepo repository.FulfillmentRepository,
	warehouseRepo repository.WarehouseRepository,
	pgClient *client.PostgresClient,
	outboxRepo outbox.Repository,
	idempotencyStore idempotency.Store,
	auditService *audit.AuditService,
	logger *zap.Logger,
) PickingService {
	return &pickingService{
		pickingListRepo:     pickingListRepo,
		pickingListItemRepo: pickingListItemRepo,
		fulfillmentRepo:     fulfillmentRepo,
		warehouseRepo:       warehouseRepo,
		pgClient:            pgClient,
		outboxRepo:          outboxRepo,
		idempotencyStore:    idempotencyStore,
		auditService:        auditService,
		logger:              logger.Named("picking_service"),
	}
}

func (s *pickingService) GeneratePickingList(ctx context.Context, req GeneratePickingListRequest, idempotencyKey string) (*models.PickingList, error) {
	logger := s.logger.With(zap.String("method", "GeneratePickingList"), zap.String("idempotency_key", idempotencyKey))

	if err := s.validateGenerateRequest(req); err != nil {
		return nil, err
	}

	tx, err := s.pgClient.BeginTx(ctx, nil)
	if err != nil {
		return nil, fmt.Errorf("begin tx: %w", err)
	}
	defer tx.Rollback()

	var cached *models.PickingList
	if err := s.idempotencyStore.Get(ctx, tx, idempotencyKey, &cached); err == nil && cached != nil {
		logger.Info("idempotent request – returning cached picking list")
		return cached, nil
	}

	warehouse, err := s.warehouseRepo.GetByID(ctx, tx, req.CompanyID, req.WarehouseID)
	if err != nil {
		return nil, fmt.Errorf("warehouse validation: %w", err)
	}
	if warehouse.CompanyID != req.CompanyID {
		return nil, inventory_errors.ErrPermissionDenied
	}

	fulfillmentItems, err := s.fulfillmentRepo.GetOrderItems(ctx, tx, req.FulfillmentOrderID)
	if err != nil {
		return nil, fmt.Errorf("get fulfillment order items: %w", err)
	}
	if len(fulfillmentItems) == 0 {
		return nil, fmt.Errorf("%w: no items in fulfillment order", inventory_errors.ErrInvalidInput)
	}

	pickingList := &models.PickingList{
		PickingListID:      uuid.New(),
		CompanyID:          req.CompanyID,
		FulfillmentOrderID: req.FulfillmentOrderID,
		WarehouseID:        req.WarehouseID,
		Status:             "created",
		CreatedAt:          time.Now(),
	}
	if err := s.pickingListRepo.Create(ctx, tx, pickingList); err != nil {
		return nil, fmt.Errorf("create picking list: %w", err)
	}

	pickingItems := make([]*models.PickingListItem, 0, len(fulfillmentItems))
	for _, fi := range fulfillmentItems {
		remaining := fi.OrderedQty.Sub(fi.FulfilledQty).Sub(fi.BackorderedQty)
		if remaining.LessThanOrEqual(decimal.Zero) {
			continue
		}
		pickingItems = append(pickingItems, &models.PickingListItem{
			PickingItemID:     uuid.New(),
			PickingListID:     pickingList.PickingListID,
			FulfillmentItemID: fi.FulfillmentItemID,
			OrderedQty:        remaining,
			PickedQty:         decimal.Zero,
			CreatedAt:         time.Now(),
		})
	}
	if len(pickingItems) == 0 {
		_ = s.pickingListRepo.Delete(ctx, tx, pickingList.PickingListID)
		return nil, fmt.Errorf("%w: no items left to pick", inventory_errors.ErrInvalidInput)
	}
	if err := s.pickingListItemRepo.BulkCreate(ctx, tx, pickingItems); err != nil {
		return nil, fmt.Errorf("create picking list items: %w", err)
	}

	if err := s.emitPickingEvent(ctx, tx, pickingList, events.EventPickingListCreated); err != nil {
		logger.Warn("failed to emit picking list created event", zap.Error(err))
	}

	_ = s.idempotencyStore.Store(ctx, tx, idempotencyKey, pickingList)

	if err := tx.Commit(); err != nil {
		return nil, fmt.Errorf("commit tx: %w", err)
	}

	if s.auditService != nil {
		_ = s.auditService.LogAction(ctx, nil, &req.CompanyID, "inventory", "generate_picking_list", "picking_list",
			&pickingList.PickingListID, "user", req.GeneratedBy, []byte(nil), []byte(nil), map[string]interface{}{
				"fulfillment_order_id": req.FulfillmentOrderID.String(),
				"items_count":          len(pickingItems),
			})
	}

	logger.Info("picking list generated", zap.String("picking_list_id", pickingList.PickingListID.String()))
	return pickingList, nil
}

func (s *pickingService) AssignPicker(ctx context.Context, pickingListID, pickerID uuid.UUID, companyID uuid.UUID, idempotencyKey string) error {
	logger := s.logger.With(zap.String("method", "AssignPicker"), zap.String("idempotency_key", idempotencyKey))

	if pickingListID == uuid.Nil || pickerID == uuid.Nil || companyID == uuid.Nil {
		return inventory_errors.ErrInvalidInput
	}

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

	list, err := s.pickingListRepo.GetByID(ctx, tx, pickingListID)
	if err != nil {
		return err
	}
	if list.CompanyID != companyID {
		return inventory_errors.ErrPermissionDenied
	}
	if list.Status != "created" && list.Status != "assigned" {
		return fmt.Errorf("%w: picking list in status %s cannot be assigned", inventory_errors.ErrInvalidTransition, list.Status)
	}

	if err := s.pickingListRepo.AssignPicker(ctx, tx, pickingListID, pickerID); err != nil {
		return fmt.Errorf("assign picker: %w", err)
	}
	if list.Status == "created" {
		if err := s.pickingListRepo.UpdateStatus(ctx, tx, pickingListID, "assigned", nil, nil); err != nil {
			logger.Warn("failed to update status to assigned", zap.Error(err))
		}
	}

	_ = s.idempotencyStore.Store(ctx, tx, idempotencyKey, true)
	if err := tx.Commit(); err != nil {
		return fmt.Errorf("commit tx: %w", err)
	}

	if s.auditService != nil {
		_ = s.auditService.LogAction(ctx, nil, &companyID, "inventory", "assign_picker", "picking_list",
			&pickingListID, "user", &pickerID, []byte(nil), []byte(nil), nil)
	}
	logger.Info("picker assigned", zap.String("picking_list_id", pickingListID.String()), zap.String("picker_id", pickerID.String()))
	return nil
}

func (s *pickingService) PickItem(ctx context.Context, pickingItemID uuid.UUID, pickedQty decimal.Decimal, companyID uuid.UUID, idempotencyKey string) error {
	logger := s.logger.With(zap.String("method", "PickItem"), zap.String("idempotency_key", idempotencyKey))

	if pickingItemID == uuid.Nil || companyID == uuid.Nil {
		return inventory_errors.ErrInvalidInput
	}
	if pickedQty.LessThanOrEqual(decimal.Zero) {
		return fmt.Errorf("%w: picked quantity must be positive", inventory_errors.ErrInvalidInput)
	}

	tx, err := s.pgClient.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("begin tx: %w", err)
	}
	defer tx.Rollback()

	var processed bool
	if err := s.idempotencyStore.Get(ctx, tx, idempotencyKey, &processed); err == nil && processed {
		logger.Info("idempotent – pick already recorded")
		return nil
	}

	item, err := s.pickingListItemRepo.GetByID(ctx, tx, pickingItemID)
	if err != nil {
		return err
	}
	list, err := s.pickingListRepo.GetByID(ctx, tx, item.PickingListID)
	if err != nil {
		return err
	}
	if list.CompanyID != companyID {
		return inventory_errors.ErrPermissionDenied
	}
	if list.Status == "completed" || list.Status == "picked" {
		return fmt.Errorf("%w: picking list already %s", inventory_errors.ErrInvalidTransition, list.Status)
	}

	remaining := item.OrderedQty.Sub(item.PickedQty)
	if pickedQty.GreaterThan(remaining) {
		return fmt.Errorf("%w: cannot pick more than remaining quantity (remaining %s, attempted %s)",
			inventory_errors.ErrInvalidInput, remaining.String(), pickedQty.String())
	}

	newPicked := item.PickedQty.Add(pickedQty)
	if err := s.pickingListItemRepo.UpdatePickedQty(ctx, tx, pickingItemID, newPicked); err != nil {
		return err
	}

	allItems, err := s.pickingListItemRepo.GetByPickingList(ctx, tx, list.PickingListID)
	if err != nil {
		return err
	}
	allPicked := true
	for _, it := range allItems {
		if it.PickedQty.LessThan(it.OrderedQty) {
			allPicked = false
			break
		}
	}
	if allPicked {
		now := time.Now()
		if err := s.pickingListRepo.UpdateStatus(ctx, tx, list.PickingListID, "picked", &now, nil); err != nil {
			logger.Warn("failed to update picking list status to picked", zap.Error(err))
		}
	}

	_ = s.idempotencyStore.Store(ctx, tx, idempotencyKey, true)
	if err := tx.Commit(); err != nil {
		return fmt.Errorf("commit tx: %w", err)
	}

	if s.auditService != nil {
		_ = s.auditService.LogAction(ctx, nil, &companyID, "inventory", "pick_item", "picking_list_item",
			&pickingItemID, "system", nil, []byte(nil), []byte(nil), map[string]interface{}{
				"picked_qty": pickedQty.String(),
			})
	}
	logger.Info("item picked", zap.String("picking_item_id", pickingItemID.String()), zap.String("picked_qty", pickedQty.String()))
	return nil
}

func (s *pickingService) CompletePicking(ctx context.Context, pickingListID uuid.UUID, companyID uuid.UUID, idempotencyKey string) error {
	logger := s.logger.With(zap.String("method", "CompletePicking"), zap.String("idempotency_key", idempotencyKey))

	if pickingListID == uuid.Nil || companyID == uuid.Nil {
		return inventory_errors.ErrInvalidInput
	}

	tx, err := s.pgClient.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("begin tx: %w", err)
	}
	defer tx.Rollback()

	var processed bool
	if err := s.idempotencyStore.Get(ctx, tx, idempotencyKey, &processed); err == nil && processed {
		logger.Info("idempotent – already completed")
		return nil
	}

	list, err := s.pickingListRepo.GetByID(ctx, tx, pickingListID)
	if err != nil {
		return err
	}
	if list.CompanyID != companyID {
		return inventory_errors.ErrPermissionDenied
	}
	if list.Status != "picked" {
		return fmt.Errorf("%w: picking list must be in 'picked' state to complete (current: %s)",
			inventory_errors.ErrInvalidTransition, list.Status)
	}

	now := time.Now()
	if err := s.pickingListRepo.UpdateStatus(ctx, tx, pickingListID, "completed", nil, &now); err != nil {
		return fmt.Errorf("complete picking: %w", err)
	}

	if err := s.emitPickingEvent(ctx, tx, list, events.EventPickingListCompleted); err != nil {
		logger.Warn("failed to emit picking completed event", zap.Error(err))
	}

	_ = s.idempotencyStore.Store(ctx, tx, idempotencyKey, true)
	if err := tx.Commit(); err != nil {
		return fmt.Errorf("commit tx: %w", err)
	}

	if s.auditService != nil {
		_ = s.auditService.LogAction(ctx, nil, &companyID, "inventory", "complete_picking", "picking_list",
			&pickingListID, "system", nil, []byte(nil), []byte(nil), nil)
	}
	logger.Info("picking completed", zap.String("picking_list_id", pickingListID.String()))
	return nil
}

func (s *pickingService) GetPickingList(ctx context.Context, pickingListID, companyID uuid.UUID) (*models.PickingList, []*models.PickingListItem, error) {
	list, err := s.pickingListRepo.GetByID(ctx, s.pgClient.DB, pickingListID)
	if err != nil {
		return nil, nil, err
	}
	if list.CompanyID != companyID {
		return nil, nil, inventory_errors.ErrPermissionDenied
	}
	items, err := s.pickingListItemRepo.GetByPickingList(ctx, s.pgClient.DB, pickingListID)
	if err != nil {
		return nil, nil, err
	}
	return list, items, nil
}

func (s *pickingService) ListPickingListsByCompany(ctx context.Context, companyID uuid.UUID, status *string, page, pageSize int) ([]*models.PickingList, int64, error) {
	if page < 1 {
		page = 1
	}
	if pageSize < 1 {
		pageSize = 20
	}
	if pageSize > 100 {
		pageSize = 100
	}
	offset := (page - 1) * pageSize
	lists, total, err := s.pickingListRepo.ListByCompany(ctx, s.pgClient.DB, companyID, status, pageSize, offset)
	if err != nil {
		return nil, 0, fmt.Errorf("list picking lists: %w", err)
	}
	return lists, total, nil
}

func (s *pickingService) validateGenerateRequest(req GeneratePickingListRequest) error {
	if req.CompanyID == uuid.Nil {
		return fmt.Errorf("%w: company_id required", inventory_errors.ErrInvalidInput)
	}
	if req.FulfillmentOrderID == uuid.Nil {
		return fmt.Errorf("%w: fulfillment_order_id required", inventory_errors.ErrInvalidInput)
	}
	if req.WarehouseID == uuid.Nil {
		return fmt.Errorf("%w: warehouse_id required", inventory_errors.ErrInvalidInput)
	}
	return nil
}

func (s *pickingService) emitPickingEvent(ctx context.Context, tx *sql.Tx, list *models.PickingList, eventType string) error {
	payload := map[string]interface{}{
		"picking_list_id":      list.PickingListID.String(),
		"company_id":           list.CompanyID.String(),
		"fulfillment_order_id": list.FulfillmentOrderID.String(),
		"warehouse_id":         list.WarehouseID.String(),
		"status":               list.Status,
		"assigned_to":          nil,
	}
	if list.AssignedTo != nil {
		payload["assigned_to"] = list.AssignedTo.String()
	}
	data, err := json.Marshal(payload)
	if err != nil {
		return err
	}
	event := &outbox.Event{
		EventID:       uuid.New().String(),
		AggregateType: "picking_list",
		AggregateID:   list.PickingListID.String(),
		EventType:     eventType,
		Topic:         events.TopicInventoryEvents,
		Payload:       data,
	}
	return s.outboxRepo.Store(ctx, tx, event)
}

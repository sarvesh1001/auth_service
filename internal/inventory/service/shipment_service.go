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

// ShipmentService manages shipment lifecycle
type ShipmentService interface {
	// CreateShipment creates a new shipment record.
	CreateShipment(ctx context.Context, req CreateShipmentRequest, idempotencyKey string) (*models.Shipment, error)

	// GetShipmentByID retrieves a shipment by its ID.
	GetShipmentByID(ctx context.Context, shipmentID uuid.UUID) (*models.Shipment, error)

	// UpdateShipmentStatus updates the status and timestamps of a shipment.
	UpdateShipmentStatus(ctx context.Context, req UpdateShipmentStatusRequest, idempotencyKey string) (*models.Shipment, error)

	// GetShipmentsByFulfillmentOrder returns all shipments for a given fulfillment order.
	GetShipmentsByFulfillmentOrder(ctx context.Context, fulfillmentOrderID uuid.UUID) ([]*models.Shipment, error)

	// ListShipments returns paginated shipments for a company, optionally filtered by status.
	ListShipments(ctx context.Context, companyID uuid.UUID, status *string, page, pageSize int) ([]*models.Shipment, int64, error)
}

// CreateShipmentRequest defines input for creating a shipment.
type CreateShipmentRequest struct {
	CompanyID          uuid.UUID
	FulfillmentOrderID uuid.UUID
	WarehouseID        uuid.UUID
	ShipmentNumber     string // optional; will be generated if empty
	ShipmentStatus     string // defaults to "draft"
	ShippedAt          *time.Time
	DeliveredAt        *time.Time
	CreatedBy          *uuid.UUID
}

// UpdateShipmentStatusRequest defines input for updating shipment status.
type UpdateShipmentStatusRequest struct {
	ShipmentID  uuid.UUID
	CompanyID   uuid.UUID
	Status      string // "draft", "shipped", "delivered", "cancelled"
	ShippedAt   *time.Time
	DeliveredAt *time.Time
	UpdatedBy   *uuid.UUID
}

type shipmentService struct {
	shipmentRepo     repository.ShipmentRepository
	pgClient         *client.PostgresClient
	outboxRepo       outbox.Repository
	idempotencyStore idempotency.Store
	auditService     *audit.AuditService
	logger           *zap.Logger
}

// NewShipmentService creates a new ShipmentService instance.
func NewShipmentService(
	shipmentRepo repository.ShipmentRepository,
	pgClient *client.PostgresClient,
	outboxRepo outbox.Repository,
	idempotencyStore idempotency.Store,
	auditService *audit.AuditService,
	logger *zap.Logger,
) ShipmentService {
	return &shipmentService{
		shipmentRepo:     shipmentRepo,
		pgClient:         pgClient,
		outboxRepo:       outboxRepo,
		idempotencyStore: idempotencyStore,
		auditService:     auditService,
		logger:           logger.Named("shipment_service"),
	}
}

// CreateShipment creates a new shipment with idempotency and event emission.
func (s *shipmentService) CreateShipment(ctx context.Context, req CreateShipmentRequest, idempotencyKey string) (*models.Shipment, error) {
	logger := s.logger.With(zap.String("method", "CreateShipment"), zap.String("idempotency_key", idempotencyKey))

	// Validate required fields
	if err := s.validateCreateRequest(req); err != nil {
		return nil, err
	}

	tx, err := s.pgClient.BeginTx(ctx, nil)
	if err != nil {
		return nil, fmt.Errorf("begin tx: %w", err)
	}
	defer tx.Rollback()

	// Idempotency check
	var cached *models.Shipment
	if err := s.idempotencyStore.Get(ctx, tx, idempotencyKey, &cached); err == nil && cached != nil {
		logger.Info("idempotent request – returning cached shipment")
		return cached, nil
	}

	// Generate shipment number if not provided
	shipmentNumber := req.ShipmentNumber
	if shipmentNumber == "" {
		shipmentNumber = generateShipmentNumber()
	}

	// Ensure uniqueness of shipment number
	exists, err := s.shipmentRepo.ExistsByShipmentNumber(ctx, tx, req.CompanyID, shipmentNumber)
	if err != nil {
		return nil, fmt.Errorf("check shipment number exists: %w", err)
	}
	if exists {
		return nil, fmt.Errorf("%w: shipment number %s already exists", inventory_errors.ErrDuplicate, shipmentNumber)
	}

	status := req.ShipmentStatus
	if status == "" {
		status = "draft"
	}

	shipment := &models.Shipment{
		ShipmentID:         uuid.New(),
		CompanyID:          req.CompanyID,
		FulfillmentOrderID: req.FulfillmentOrderID,
		WarehouseID:        req.WarehouseID,
		ShipmentNumber:     shipmentNumber,
		ShipmentStatus:     status,
		ShippedAt:          req.ShippedAt,
		DeliveredAt:        req.DeliveredAt,
		CreatedAt:          time.Now(),
	}

	if err := s.shipmentRepo.Create(ctx, tx, shipment); err != nil {
		return nil, fmt.Errorf("create shipment: %w", err)
	}

	// Emit event
	if err := s.emitShipmentEvent(ctx, tx, shipment, events.EventShipmentCreated); err != nil {
		logger.Warn("failed to emit shipment created event", zap.Error(err))
	}

	// Store idempotency result
	_ = s.idempotencyStore.Store(ctx, tx, idempotencyKey, shipment)

	if err := tx.Commit(); err != nil {
		return nil, fmt.Errorf("commit tx: %w", err)
	}

	// Audit log
	if s.auditService != nil {
		_ = s.auditService.LogAction(ctx, nil, &req.CompanyID, "inventory", "create_shipment", "shipment",
			&shipment.ShipmentID, "user", req.CreatedBy, nil, nil, map[string]interface{}{
				"shipment_number": shipment.ShipmentNumber,
				"status":          shipment.ShipmentStatus,
				"fulfillment_id":  shipment.FulfillmentOrderID.String(),
			})
	}

	logger.Info("shipment created", zap.String("shipment_id", shipment.ShipmentID.String()))
	return shipment, nil
}

// GetShipmentByID retrieves a shipment by ID.
func (s *shipmentService) GetShipmentByID(ctx context.Context, shipmentID uuid.UUID) (*models.Shipment, error) {
	return s.shipmentRepo.GetByID(ctx, s.pgClient.DB, shipmentID)
}

// UpdateShipmentStatus updates the status and timestamps of a shipment.
func (s *shipmentService) UpdateShipmentStatus(ctx context.Context, req UpdateShipmentStatusRequest, idempotencyKey string) (*models.Shipment, error) {
	logger := s.logger.With(zap.String("method", "UpdateShipmentStatus"), zap.String("idempotency_key", idempotencyKey))

	if req.ShipmentID == uuid.Nil || req.CompanyID == uuid.Nil {
		return nil, fmt.Errorf("%w: shipment_id and company_id are required", inventory_errors.ErrInvalidInput)
	}

	tx, err := s.pgClient.BeginTx(ctx, nil)
	if err != nil {
		return nil, fmt.Errorf("begin tx: %w", err)
	}
	defer tx.Rollback()

	// Idempotency check
	var processed bool
	if err := s.idempotencyStore.Get(ctx, tx, idempotencyKey, &processed); err == nil && processed {
		logger.Info("idempotent – status update already processed")
		// Return current shipment state
		shipment, err := s.shipmentRepo.GetByID(ctx, tx, req.ShipmentID)
		if err != nil {
			return nil, err
		}
		return shipment, nil
	}

	// Fetch existing shipment to verify ownership and current status
	shipment, err := s.shipmentRepo.GetByID(ctx, tx, req.ShipmentID)
	if err != nil {
		return nil, err
	}
	if shipment.CompanyID != req.CompanyID {
		return nil, inventory_errors.ErrPermissionDenied
	}

	// Validate status transition
	if !isValidShipmentStatusTransition(shipment.ShipmentStatus, req.Status) {
		return nil, fmt.Errorf("%w: cannot transition from %s to %s", inventory_errors.ErrInvalidTransition, shipment.ShipmentStatus, req.Status)
	}

	// Prepare timestamps
	var shippedAt, deliveredAt *time.Time
	switch req.Status {
	case "shipped":
		shippedAt = nowPtr()
		deliveredAt = nil
	case "delivered":
		deliveredAt = nowPtr()
		// If transitioning from shipped to delivered, keep existing shippedAt
		if shipment.ShipmentStatus == "shipped" {
			shippedAt = shipment.ShippedAt
		} else {
			shippedAt = nowPtr() // fallback
		}
	case "cancelled":
		shippedAt = nil
		deliveredAt = nil
	default:
		shippedAt = req.ShippedAt
		deliveredAt = req.DeliveredAt
	}

	if err := s.shipmentRepo.UpdateStatus(ctx, tx, req.ShipmentID, req.Status, shippedAt, deliveredAt); err != nil {
		return nil, fmt.Errorf("update shipment status: %w", err)
	}

	// Refresh shipment data
	updatedShipment, err := s.shipmentRepo.GetByID(ctx, tx, req.ShipmentID)
	if err != nil {
		return nil, err
	}

	// Emit appropriate event
	eventType := events.EventShipmentUpdated
	switch req.Status {
	case "shipped":
		eventType = events.EventShipmentShipped
	case "delivered":
		eventType = events.EventShipmentDelivered
	case "cancelled":
		eventType = events.EventShipmentCancelled
	}
	if err := s.emitShipmentEvent(ctx, tx, updatedShipment, eventType); err != nil {
		logger.Warn("failed to emit shipment status event", zap.Error(err))
	}

	_ = s.idempotencyStore.Store(ctx, tx, idempotencyKey, true)

	if err := tx.Commit(); err != nil {
		return nil, fmt.Errorf("commit tx: %w", err)
	}

	if s.auditService != nil {
		_ = s.auditService.LogAction(ctx, nil, &req.CompanyID, "inventory", "update_shipment_status", "shipment",
			&req.ShipmentID, "user", req.UpdatedBy, nil, nil, map[string]interface{}{
				"old_status": shipment.ShipmentStatus,
				"new_status": req.Status,
			})
	}

	logger.Info("shipment status updated", zap.String("shipment_id", req.ShipmentID.String()), zap.String("new_status", req.Status))
	return updatedShipment, nil
}

// GetShipmentsByFulfillmentOrder returns all shipments for a fulfillment order.
func (s *shipmentService) GetShipmentsByFulfillmentOrder(ctx context.Context, fulfillmentOrderID uuid.UUID) ([]*models.Shipment, error) {
	return s.shipmentRepo.GetByFulfillmentOrder(ctx, s.pgClient.DB, fulfillmentOrderID)
}

// ListShipments returns paginated shipments for a company.
func (s *shipmentService) ListShipments(ctx context.Context, companyID uuid.UUID, status *string, page, pageSize int) ([]*models.Shipment, int64, error) {
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
	sort := repository.Sort{Field: "created_at", Direction: "DESC"}
	return s.shipmentRepo.ListByCompany(ctx, s.pgClient.DB, companyID, status, pagination, sort)
}

// Helper validation
func (s *shipmentService) validateCreateRequest(req CreateShipmentRequest) error {
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

// generateShipmentNumber creates a unique shipment number.
func generateShipmentNumber() string {
	return fmt.Sprintf("SHP-%d-%s", time.Now().UnixNano(), uuid.New().String()[:8])
}

// isValidShipmentStatusTransition checks allowed transitions.
func isValidShipmentStatusTransition(current, next string) bool {
	allowed := map[string][]string{
		"draft":     {"shipped", "cancelled"},
		"shipped":   {"delivered", "cancelled"},
		"delivered": {},
		"cancelled": {},
	}
	nextStates, ok := allowed[current]
	if !ok {
		return false
	}
	for _, s := range nextStates {
		if s == next {
			return true
		}
	}
	return false
}

func nowPtr() *time.Time {
	t := time.Now()
	return &t
}

// emitShipmentEvent publishes shipment event to outbox.
func (s *shipmentService) emitShipmentEvent(ctx context.Context, tx *sql.Tx, shipment *models.Shipment, eventType string) error {
	payload := map[string]interface{}{
		"shipment_id":          shipment.ShipmentID.String(),
		"company_id":           shipment.CompanyID.String(),
		"fulfillment_order_id": shipment.FulfillmentOrderID.String(),
		"warehouse_id":         shipment.WarehouseID.String(),
		"shipment_number":      shipment.ShipmentNumber,
		"shipment_status":      shipment.ShipmentStatus,
		"shipped_at":           shipment.ShippedAt,
		"delivered_at":         shipment.DeliveredAt,
		"created_at":           shipment.CreatedAt,
	}
	data, err := json.Marshal(payload)
	if err != nil {
		return err
	}
	event := &outbox.Event{
		EventID:       uuid.New().String(),
		AggregateType: "shipment",
		AggregateID:   shipment.ShipmentID.String(),
		EventType:     eventType,
		Topic:         events.TopicInventoryEvents,
		Payload:       data,
	}
	return s.outboxRepo.Store(ctx, tx, event)
}

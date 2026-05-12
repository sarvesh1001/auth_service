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

// ReservationService defines the interface for reservation operations.
type ReservationService interface {
	CreateReservation(ctx context.Context, db repository.DBTX, req CreateReservationRequest, idempotencyKey string) (*models.Reservation, error)

	// GetActiveReservationByReference returns the active (or partially fulfilled) reservation for a given reference and item.
	GetActiveReservationByReference(ctx context.Context, db repository.DBTX, companyID uuid.UUID, reservationType string, referenceID, itemID uuid.UUID) (*models.Reservation, error)

	// PartialFulfillReservation fulfills a part of a reservation.
	PartialFulfillReservation(ctx context.Context, db repository.DBTX, reservationID, companyID uuid.UUID, quantityFulfilled decimal.Decimal, idempotencyKey string) error

	// FulfillReservation fulfills the entire reservation.
	FulfillReservation(ctx context.Context, db repository.DBTX, reservationID, companyID uuid.UUID, idempotencyKey string) error

	CancelReservation(ctx context.Context, db repository.DBTX, reservationID, companyID uuid.UUID, idempotencyKey string) error
	ExpireReservations(ctx context.Context, db repository.DBTX, companyID uuid.UUID) (int64, error)
}

// CreateReservationRequest holds data for creating a new reservation.
type CreateReservationRequest struct {
	CompanyID       uuid.UUID
	ReservationType string
	ReferenceID     uuid.UUID
	WarehouseID     uuid.UUID
	ItemID          uuid.UUID
	BatchID         *uuid.UUID
	Quantity        decimal.Decimal
	ExpiresAt       *time.Time
	CreatedBy       *uuid.UUID
}

type reservationService struct {
	reservationRepo  repository.ReservationRepository
	balanceRepo      repository.StockBalanceRepository
	pgClient         *client.PostgresClient
	outboxRepo       outbox.Repository
	idempotencyStore idempotency.Store
	auditService     *audit.AuditService
	logger           *zap.Logger
}

// NewReservationService creates a new reservation service.
func NewReservationService(
	reservationRepo repository.ReservationRepository,
	balanceRepo repository.StockBalanceRepository,
	pgClient *client.PostgresClient,
	outboxRepo outbox.Repository,
	idempotencyStore idempotency.Store,
	auditService *audit.AuditService,
	logger *zap.Logger,
) ReservationService {
	return &reservationService{
		reservationRepo:  reservationRepo,
		balanceRepo:      balanceRepo,
		pgClient:         pgClient,
		outboxRepo:       outboxRepo,
		idempotencyStore: idempotencyStore,
		auditService:     auditService,
		logger:           logger.Named("reservation_service"),
	}
}

// CreateReservation creates a new reservation and reserves stock.
func (s *reservationService) CreateReservation(ctx context.Context, db repository.DBTX, req CreateReservationRequest, idempotencyKey string) (*models.Reservation, error) {
	logger := s.logger.With(zap.String("method", "CreateReservation"), zap.String("idempotency_key", idempotencyKey))

	if err := s.validateCreateRequest(req); err != nil {
		return nil, err
	}

	sqlTx, ok := db.(*sql.Tx)
	if !ok {
		return nil, fmt.Errorf("db is not a *sql.Tx; cannot use idempotency store")
	}

	var cached *models.Reservation
	if err := s.idempotencyStore.Get(ctx, sqlTx, idempotencyKey, &cached); err == nil && cached != nil {
		logger.Info("idempotent request – returning cached reservation")
		return cached, nil
	}

	qtyFloat, _ := req.Quantity.Float64()
	if err := s.balanceRepo.ReserveStock(ctx, db, req.CompanyID, req.WarehouseID, req.ItemID, req.BatchID, qtyFloat); err != nil {
		if err == inventory_errors.ErrNotFound {
			return nil, fmt.Errorf("%w: insufficient stock for item %s", inventory_errors.ErrInsufficientStock, req.ItemID)
		}
		return nil, fmt.Errorf("reserve stock: %w", err)
	}

	reservation := &models.Reservation{
		ReservationID:     uuid.New(),
		CompanyID:         req.CompanyID,
		ReservationType:   req.ReservationType,
		ReferenceID:       req.ReferenceID,
		WarehouseID:       req.WarehouseID,
		ItemID:            req.ItemID,
		BatchID:           req.BatchID,
		Quantity:          req.Quantity,
		Status:            "active",
		CreatedAt:         time.Now(),
		ExpiresAt:         req.ExpiresAt,
		CreatedBy:         req.CreatedBy,
		FulfilledQuantity: decimal.Zero,
	}

	if err := s.reservationRepo.Create(ctx, db, reservation); err != nil {
		return nil, fmt.Errorf("create reservation: %w", err)
	}

	if err := s.emitReservationEvent(ctx, sqlTx, reservation, events.EventReservationCreated); err != nil {
		logger.Warn("failed to emit reservation created event", zap.Error(err))
	}

	_ = s.idempotencyStore.Store(ctx, sqlTx, idempotencyKey, reservation)

	if s.auditService != nil {
		_ = s.auditService.LogAction(ctx, nil, &req.CompanyID, "inventory", "create_reservation", "reservation",
			&reservation.ReservationID, "user", req.CreatedBy, nil, nil, map[string]interface{}{
				"item_id":      req.ItemID.String(),
				"warehouse_id": req.WarehouseID.String(),
				"quantity":     qtyFloat,
				"reserve_type": req.ReservationType,
			})
	}

	logger.Info("reservation created", zap.String("reservation_id", reservation.ReservationID.String()))
	return reservation, nil
}

// GetActiveReservationByReference returns the first active (or partially_fulfilled) reservation matching the reference and item.
func (s *reservationService) GetActiveReservationByReference(ctx context.Context, db repository.DBTX, companyID uuid.UUID, reservationType string, referenceID, itemID uuid.UUID) (*models.Reservation, error) {
	// Get all reservations for this reference (including non-active)
	reservations, err := s.reservationRepo.GetByReference(ctx, db, reservationType, referenceID)
	if err != nil {
		return nil, err
	}

	for _, res := range reservations {
		if res.CompanyID == companyID && res.ItemID == itemID && (res.Status == "active" || res.Status == "partially_fulfilled") {
			return res, nil
		}
	}
	return nil, fmt.Errorf("%w: no active reservation found for reference %s, item %s", inventory_errors.ErrNotFound, referenceID, itemID)
}

// PartialFulfillReservation fulfills a portion of an active reservation.
func (s *reservationService) PartialFulfillReservation(ctx context.Context, db repository.DBTX, reservationID, companyID uuid.UUID, quantityFulfilled decimal.Decimal, idempotencyKey string) error {
	logger := s.logger.With(
		zap.String("method", "PartialFulfillReservation"),
		zap.String("idempotency_key", idempotencyKey),
		zap.String("reservation_id", reservationID.String()),
	)

	sqlTx, ok := db.(*sql.Tx)
	if !ok {
		return fmt.Errorf("db is not a *sql.Tx")
	}

	var processed bool
	if err := s.idempotencyStore.Get(ctx, sqlTx, idempotencyKey, &processed); err == nil && processed {
		logger.Info("idempotent – already processed")
		return nil
	}

	// Lock the reservation row for update
	res, err := s.reservationRepo.GetForUpdate(ctx, db, reservationID)
	if err != nil {
		return fmt.Errorf("get reservation: %w", err)
	}
	if res.CompanyID != companyID {
		return inventory_errors.ErrPermissionDenied
	}
	if res.Status != "active" && res.Status != "partially_fulfilled" {
		return fmt.Errorf("reservation cannot be fulfilled (status=%s)", res.Status)
	}
	if quantityFulfilled.LessThanOrEqual(decimal.Zero) {
		return fmt.Errorf("%w: quantity fulfilled must be positive", inventory_errors.ErrInvalidInput)
	}

	remaining := res.Quantity.Sub(res.FulfilledQuantity)
	if quantityFulfilled.GreaterThan(remaining) {
		return fmt.Errorf("%w: cannot fulfill more than remaining quantity (remaining %s, requested %s)",
			inventory_errors.ErrInvalidInput, remaining.String(), quantityFulfilled.String())
	}

	// Update the reservation's fulfilled quantity and status
	if err := s.reservationRepo.UpdateFulfilledQuantity(ctx, db, reservationID, quantityFulfilled); err != nil {
		return fmt.Errorf("update fulfilled quantity: %w", err)
	}

	// Reload the reservation to get updated status
	updated, err := s.reservationRepo.GetByID(ctx, db, reservationID)
	if err != nil {
		logger.Warn("failed to reload reservation after update", zap.Error(err))
	}

	// Emit event based on final status
	eventType := events.EventReservationPartiallyFulfilled
	if updated != nil && updated.Status == "fulfilled" {
		eventType = events.EventReservationFulfilled
	}
	if err := s.emitReservationEvent(ctx, sqlTx, res, eventType); err != nil {
		logger.Warn("failed to emit reservation event", zap.Error(err))
	}

	_ = s.idempotencyStore.Store(ctx, sqlTx, idempotencyKey, true)

	if s.auditService != nil {
		_ = s.auditService.LogAction(ctx, nil, &companyID, "inventory", "partial_fulfill_reservation", "reservation",
			&reservationID, "system", nil, nil, nil, map[string]interface{}{
				"fulfilled_quantity": toFloat64(quantityFulfilled),
				"new_status":         eventType,
			})
	}

	logger.Info("reservation partially fulfilled", zap.String("reservation_id", reservationID.String()), zap.String("fulfilled_qty", quantityFulfilled.String()))
	return nil
}

// FulfillReservation fulfills the entire reservation (convenience wrapper).
func (s *reservationService) FulfillReservation(ctx context.Context, db repository.DBTX, reservationID, companyID uuid.UUID, idempotencyKey string) error {
	// Get the reservation to know the full quantity
	sqlTx, ok := db.(*sql.Tx)
	if !ok {
		return fmt.Errorf("db is not a *sql.Tx")
	}
	res, err := s.reservationRepo.GetByID(ctx, sqlTx, reservationID)
	if err != nil {
		return fmt.Errorf("get reservation: %w", err)
	}
	if res.CompanyID != companyID {
		return inventory_errors.ErrPermissionDenied
	}
	return s.PartialFulfillReservation(ctx, db, reservationID, companyID, res.Quantity.Sub(res.FulfilledQuantity), idempotencyKey)
}

// CancelReservation cancels an active reservation and releases the reserved stock.
func (s *reservationService) CancelReservation(ctx context.Context, db repository.DBTX, reservationID, companyID uuid.UUID, idempotencyKey string) error {
	logger := s.logger.With(zap.String("method", "CancelReservation"), zap.String("idempotency_key", idempotencyKey))

	sqlTx, ok := db.(*sql.Tx)
	if !ok {
		return fmt.Errorf("db is not a *sql.Tx")
	}

	var processed bool
	if err := s.idempotencyStore.Get(ctx, sqlTx, idempotencyKey, &processed); err == nil && processed {
		logger.Info("idempotent – already cancelled")
		return nil
	}

	res, err := s.reservationRepo.GetForUpdate(ctx, db, reservationID)
	if err != nil {
		return fmt.Errorf("get reservation: %w", err)
	}

	if res.CompanyID != companyID {
		return inventory_errors.ErrPermissionDenied
	}
	if res.Status != "active" && res.Status != "partially_fulfilled" {
		return fmt.Errorf("reservation cannot be cancelled (status=%s)", res.Status)
	}

	// Release the remaining reserved stock (total quantity - already fulfilled)
	remaining := res.Quantity.Sub(res.FulfilledQuantity)
	if remaining.GreaterThan(decimal.Zero) {
		qtyFloat, _ := remaining.Float64()
		if err := s.balanceRepo.ReleaseReservation(ctx, db, res.CompanyID, res.WarehouseID, res.ItemID, res.BatchID, qtyFloat); err != nil {
			return fmt.Errorf("release remaining reserved stock: %w", err)
		}
	}

	if err := s.reservationRepo.Cancel(ctx, db, reservationID, time.Now()); err != nil {
		return fmt.Errorf("cancel reservation: %w", err)
	}

	if err := s.emitReservationEvent(ctx, sqlTx, res, events.EventReservationCancelled); err != nil {
		logger.Warn("failed to emit cancelled event", zap.Error(err))
	}

	_ = s.idempotencyStore.Store(ctx, sqlTx, idempotencyKey, true)

	if s.auditService != nil {
		_ = s.auditService.LogAction(ctx, nil, &companyID, "inventory", "cancel_reservation", "reservation",
			&reservationID, "user", nil, nil, nil, map[string]interface{}{
				"reason": "manual_cancel",
			})
	}

	logger.Info("reservation cancelled", zap.String("reservation_id", reservationID.String()))
	return nil
}

// ExpireReservations finds and expires reservations that have passed their expiry time.
func (s *reservationService) ExpireReservations(ctx context.Context, db repository.DBTX, companyID uuid.UUID) (int64, error) {
	logger := s.logger.With(zap.String("method", "ExpireReservations"), zap.String("company_id", companyID.String()))

	sqlTx, ok := db.(*sql.Tx)
	if !ok {
		return 0, fmt.Errorf("db is not a *sql.Tx")
	}

	expired, err := s.reservationRepo.GetExpiredActive(ctx, db, companyID, time.Now())
	if err != nil {
		return 0, fmt.Errorf("get expired reservations: %w", err)
	}

	if len(expired) == 0 {
		return 0, nil
	}

	for _, res := range expired {
		remaining := res.Quantity.Sub(res.FulfilledQuantity)
		if remaining.GreaterThan(decimal.Zero) {
			qtyFloat, _ := remaining.Float64()
			if err := s.balanceRepo.ReleaseReservation(ctx, db, res.CompanyID, res.WarehouseID, res.ItemID, res.BatchID, qtyFloat); err != nil {
				logger.Error("failed to release stock for expired reservation", zap.String("reservation_id", res.ReservationID.String()), zap.Error(err))
				return 0, fmt.Errorf("release stock for %s: %w", res.ReservationID, err)
			}
		}
		if err := s.reservationRepo.Cancel(ctx, db, res.ReservationID, time.Now()); err != nil {
			return 0, fmt.Errorf("cancel expired reservation %s: %w", res.ReservationID, err)
		}
		_ = s.emitReservationEvent(ctx, sqlTx, res, events.EventReservationExpired)
	}

	logger.Info("expired reservations processed", zap.Int("count", len(expired)))
	return int64(len(expired)), nil
}

// validateCreateRequest validates the creation request.
func (s *reservationService) validateCreateRequest(req CreateReservationRequest) error {
	if req.CompanyID == uuid.Nil || req.ItemID == uuid.Nil || req.WarehouseID == uuid.Nil {
		return fmt.Errorf("%w: company_id, item_id, warehouse_id required", inventory_errors.ErrInvalidInput)
	}
	if req.Quantity.LessThanOrEqual(decimal.Zero) {
		return fmt.Errorf("%w: quantity must be positive", inventory_errors.ErrInvalidInput)
	}
	if req.ReservationType == "" {
		return fmt.Errorf("%w: reservation_type required", inventory_errors.ErrInvalidInput)
	}
	if req.ReferenceID == uuid.Nil {
		return fmt.Errorf("%w: reference_id required", inventory_errors.ErrInvalidInput)
	}
	if req.ExpiresAt != nil && req.ExpiresAt.Before(time.Now()) {
		return inventory_errors.ErrExpiryInPast
	}
	return nil
}

// emitReservationEvent sends an outbox event for the reservation.
func (s *reservationService) emitReservationEvent(ctx context.Context, tx *sql.Tx, res *models.Reservation, eventType string) error {
	var batchIDStr *string
	if res.BatchID != nil {
		s := res.BatchID.String()
		batchIDStr = &s
	}
	payload := events.ReservationPayload{
		ReservationID:   res.ReservationID.String(),
		CompanyID:       res.CompanyID.String(),
		ReservationType: res.ReservationType,
		ReferenceID:     res.ReferenceID.String(),
		WarehouseID:     res.WarehouseID.String(),
		ItemID:          res.ItemID.String(),
		BatchID:         batchIDStr,
		Quantity:        toFloat64(res.Quantity),
		Status:          res.Status,
		CreatedAt:       res.CreatedAt,
		ExpiresAt:       res.ExpiresAt,
	}
	data, err := json.Marshal(payload)
	if err != nil {
		return err
	}
	event := &outbox.Event{
		EventID:       uuid.New().String(),
		AggregateType: "reservation",
		AggregateID:   res.ReservationID.String(),
		EventType:     eventType,
		Topic:         events.TopicInventoryEvents,
		Payload:       data,
	}
	return s.outboxRepo.Store(ctx, tx, event)
}

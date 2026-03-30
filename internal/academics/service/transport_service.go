package service

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"strings"

	"github.com/google/uuid"
	"go.uber.org/zap"

	"auth-service/internal/academics/models"
	"auth-service/internal/academics/repository"
	"auth-service/internal/client"
)

// TransportService defines the interface for transport domain operations.
type TransportService interface {
	// Route operations
	CreateRoute(ctx context.Context, req CreateTransportRouteRequest, idempotencyKey string) (*models.TransportRoute, error)
	GetRouteByID(ctx context.Context, id uuid.UUID) (*models.TransportRoute, error)
	ListRoutes(ctx context.Context, filter repository.TransportRouteFilter, p repository.Pagination, s repository.Sort) ([]*models.TransportRoute, error)
	CountRoutes(ctx context.Context, filter repository.TransportRouteFilter) (int64, error)
	UpdateRoute(ctx context.Context, req UpdateTransportRouteRequest) (*models.TransportRoute, error)
	DeleteRoute(ctx context.Context, id uuid.UUID, deletedBy *uuid.UUID) error

	// Stop operations
	CreateStop(ctx context.Context, req CreateTransportStopRequest, idempotencyKey string) (*models.TransportStop, error)
	GetStopByID(ctx context.Context, id uuid.UUID) (*models.TransportStop, error)
	ListStops(ctx context.Context, filter repository.TransportStopFilter, p repository.Pagination, s repository.Sort) ([]*models.TransportStop, error)
	CountStops(ctx context.Context, filter repository.TransportStopFilter) (int64, error)
	UpdateStop(ctx context.Context, req UpdateTransportStopRequest) (*models.TransportStop, error)
	DeleteStop(ctx context.Context, id uuid.UUID) error

	// Vehicle operations
	CreateVehicle(ctx context.Context, req CreateTransportVehicleRequest, idempotencyKey string) (*models.TransportVehicle, error)
	GetVehicleByID(ctx context.Context, id uuid.UUID) (*models.TransportVehicle, error)
	GetVehicleByNumber(ctx context.Context, companyID uuid.UUID, number string) (*models.TransportVehicle, error)
	ListVehicles(ctx context.Context, filter repository.TransportVehicleFilter, p repository.Pagination, s repository.Sort) ([]*models.TransportVehicle, error)
	CountVehicles(ctx context.Context, filter repository.TransportVehicleFilter) (int64, error)
	UpdateVehicle(ctx context.Context, req UpdateTransportVehicleRequest) (*models.TransportVehicle, error)
	DeleteVehicle(ctx context.Context, id uuid.UUID, deletedBy *uuid.UUID) error

	// Driver Assignment operations
	CreateDriverAssignment(ctx context.Context, req CreateDriverAssignmentRequest, idempotencyKey string) (*models.TransportDriverAssignment, error)
	GetDriverAssignmentByID(ctx context.Context, id uuid.UUID) (*models.TransportDriverAssignment, error)
	ListDriverAssignments(ctx context.Context, filter repository.TransportDriverAssignmentFilter, p repository.Pagination, s repository.Sort) ([]*models.TransportDriverAssignment, error)
	CountDriverAssignments(ctx context.Context, filter repository.TransportDriverAssignmentFilter) (int64, error)
	UpdateDriverAssignment(ctx context.Context, req UpdateDriverAssignmentRequest) (*models.TransportDriverAssignment, error)
	DeleteDriverAssignment(ctx context.Context, id uuid.UUID) error

	// Student Assignment operations
	CreateStudentAssignment(ctx context.Context, req CreateStudentAssignmentRequest, idempotencyKey string) (*models.StudentTransportAssignment, error)
	GetStudentAssignmentByID(ctx context.Context, id uuid.UUID) (*models.StudentTransportAssignment, error)
	ListStudentAssignments(ctx context.Context, filter repository.StudentTransportAssignmentFilter, p repository.Pagination, s repository.Sort) ([]*models.StudentTransportAssignment, error)
	CountStudentAssignments(ctx context.Context, filter repository.StudentTransportAssignmentFilter) (int64, error)
	UpdateStudentAssignment(ctx context.Context, req UpdateStudentAssignmentRequest) (*models.StudentTransportAssignment, error)
	DeleteStudentAssignment(ctx context.Context, id uuid.UUID) error
}

type transportService struct {
	repo             repository.TransportRepository
	idempotencyStore IdempotencyStore
	auditLogger      AuditLogger
	outboxStore      OutboxStore
	eventPublisher   EventPublisher
	pgClient         *client.PostgresClient
	logger           *zap.Logger
	notifSvc         NotificationService
}

func NewTransportService(
	repo repository.TransportRepository,
	idempotencyStore IdempotencyStore,
	auditLogger AuditLogger,
	outboxStore OutboxStore,
	eventPublisher EventPublisher,
	pgClient *client.PostgresClient,
	logger *zap.Logger,
	notifSvc NotificationService,
) TransportService {
	return &transportService{
		repo:             repo,
		idempotencyStore: idempotencyStore,
		auditLogger:      auditLogger,
		outboxStore:      outboxStore,
		eventPublisher:   eventPublisher,
		pgClient:         pgClient,
		logger:           logger.Named("transport_service"),
		notifSvc:         notifSvc,
	}
}

// ----- Helper functions -----
func (s *transportService) sendNotification(ctx context.Context, studentID, companyID uuid.UUID, title, message string, notifType models.NotificationType, priority models.NotificationPriority, createdBy *uuid.UUID) {
	if s.notifSvc == nil {
		return
	}
	targets := []NotificationTargetInput{
		{TargetType: models.TargetStudent, TargetEntityID: studentID},
	}
	req := CreateNotificationRequest{
		CompanyID: companyID,
		Title:     title,
		Message:   message,
		Type:      notifType,
		Priority:  priority,
		Targets:   targets,
		CreatedBy: createdBy,
	}
	_, err := s.notifSvc.Create(context.Background(), req, "")
	if err != nil {
		s.logger.Error("failed to send notification", zap.Error(err))
	}
}

// ----- Route Methods -----
func (s *transportService) CreateRoute(ctx context.Context, req CreateTransportRouteRequest, idempotencyKey string) (*models.TransportRoute, error) {
	logger := s.logger.With(
		zap.String("method", "CreateRoute"),
		zap.String("company_id", req.CompanyID.String()),
		zap.String("route_name", req.RouteName),
		zap.String("idempotency_key", idempotencyKey),
	)
	s.sanitizeRoute(&req)
	if err := s.validateCreateRoute(req); err != nil {
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
			var route models.TransportRoute
			if err := s.idempotencyStore.Get(ctx, tx, idempotencyKey, &route); err != nil {
				return nil, fmt.Errorf("failed to retrieve idempotent response: %w", err)
			}
			logger.Info("returning idempotent response")
			return &route, nil
		}
	}

	route := &models.TransportRoute{
		CompanyID:  req.CompanyID,
		RouteName:  req.RouteName,
		StartPoint: req.StartPoint,
		EndPoint:   req.EndPoint,
		DistanceKm: req.DistanceKm,
		IsActive:   req.IsActive,
		CreatedBy:  req.CreatedBy,
		UpdatedBy:  req.UpdatedBy,
	}
	if err := s.repo.CreateRoute(ctx, tx, route); err != nil {
		return nil, err
	}

	if idempotencyKey != "" {
		if err := s.idempotencyStore.Store(ctx, tx, idempotencyKey, route); err != nil {
			logger.Error("failed to store idempotency key", zap.Error(err))
			return nil, fmt.Errorf("failed to store idempotency key: %w", err)
		}
	}
	if err := s.auditLogger.Log(ctx, tx, "CREATE", route.RouteID, nil, route, req.CreatedBy); err != nil {
		logger.Error("audit log failed", zap.Error(err))
	}
	if err := s.outboxStore.Store(ctx, tx, string(EventTransportRouteCreated), route); err != nil {
		logger.Error("failed to store outbox event", zap.Error(err))
		return nil, fmt.Errorf("failed to store outbox event: %w", err)
	}
	if err := tx.Commit(); err != nil {
		return nil, fmt.Errorf("commit tx: %w", err)
	}

	logger.Info("transport route created", zap.String("id", route.RouteID.String()))
	return route, nil
}

func (s *transportService) GetRouteByID(ctx context.Context, id uuid.UUID) (*models.TransportRoute, error) {
	route, err := s.repo.GetRouteByID(ctx, s.pgClient.DB, id)
	if err != nil {
		return nil, err
	}
	if route == nil {
		return nil, fmt.Errorf("%w: route %s", ErrNotFound, id)
	}
	return route, nil
}

func (s *transportService) ListRoutes(ctx context.Context, filter repository.TransportRouteFilter, p repository.Pagination, srt repository.Sort) ([]*models.TransportRoute, error) {
	return s.repo.ListRoutes(ctx, s.pgClient.DB, filter, p, srt)
}

func (s *transportService) CountRoutes(ctx context.Context, filter repository.TransportRouteFilter) (int64, error) {
	return s.repo.CountRoutes(ctx, s.pgClient.DB, filter)
}

func (s *transportService) UpdateRoute(ctx context.Context, req UpdateTransportRouteRequest) (*models.TransportRoute, error) {
	logger := s.logger.With(
		zap.String("method", "UpdateRoute"),
		zap.String("route_id", req.RouteID.String()),
	)
	if err := s.validateUpdateRoute(req); err != nil {
		return nil, err
	}
	tx, err := s.pgClient.BeginTx(ctx, nil)
	if err != nil {
		return nil, fmt.Errorf("begin tx: %w", err)
	}
	defer tx.Rollback()

	route, err := s.repo.GetRouteByID(ctx, tx, req.RouteID)
	if err != nil {
		return nil, err
	}
	if route == nil {
		return nil, fmt.Errorf("%w: route %s", ErrNotFound, req.RouteID)
	}

	oldRoute := *route
	route.RouteName = req.RouteName
	route.StartPoint = req.StartPoint
	route.EndPoint = req.EndPoint
	route.DistanceKm = req.DistanceKm
	route.IsActive = req.IsActive
	route.UpdatedBy = req.UpdatedBy

	if err := s.repo.UpdateRoute(ctx, tx, route); err != nil {
		return nil, err
	}

	if err := s.auditLogger.Log(ctx, tx, "UPDATE", route.RouteID, &oldRoute, route, req.UpdatedBy); err != nil {
		logger.Error("audit log failed", zap.Error(err))
	}
	if err := s.outboxStore.Store(ctx, tx, string(EventTransportRouteUpdated), map[string]interface{}{
		"old": oldRoute,
		"new": route,
	}); err != nil {
		logger.Error("failed to store outbox event", zap.Error(err))
		return nil, fmt.Errorf("failed to store outbox event: %w", err)
	}
	if err := tx.Commit(); err != nil {
		return nil, fmt.Errorf("commit tx: %w", err)
	}

	logger.Info("transport route updated")
	return route, nil
}

func (s *transportService) DeleteRoute(ctx context.Context, id uuid.UUID, deletedBy *uuid.UUID) error {
	logger := s.logger.With(
		zap.String("method", "DeleteRoute"),
		zap.String("route_id", id.String()),
	)
	tx, err := s.pgClient.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("begin tx: %w", err)
	}
	defer tx.Rollback()

	if err := s.repo.DeleteRoute(ctx, tx, id, deletedBy); err != nil {
		return err
	}
	if err := s.auditLogger.Log(ctx, tx, "DELETE", id, nil, nil, deletedBy); err != nil {
		logger.Error("audit log failed", zap.Error(err))
	}
	if err := s.outboxStore.Store(ctx, tx, string(EventTransportRouteDeleted), map[string]interface{}{
		"route_id":   id,
		"deleted_by": deletedBy,
	}); err != nil {
		logger.Error("failed to store outbox event", zap.Error(err))
		return fmt.Errorf("failed to store outbox event: %w", err)
	}
	if err := tx.Commit(); err != nil {
		return fmt.Errorf("commit tx: %w", err)
	}
	logger.Info("transport route deleted")
	return nil
}

// Helper validation for route
func (s *transportService) sanitizeRoute(req *CreateTransportRouteRequest) {
	req.RouteName = strings.TrimSpace(req.RouteName)
	req.StartPoint = strings.TrimSpace(req.StartPoint)
	req.EndPoint = strings.TrimSpace(req.EndPoint)
}
func (s *transportService) validateCreateRoute(req CreateTransportRouteRequest) error {
	if req.CompanyID == uuid.Nil {
		return fmt.Errorf("%w: company_id is required", ErrInvalidInput)
	}
	if req.RouteName == "" {
		return fmt.Errorf("%w: route_name is required", ErrInvalidInput)
	}
	return nil
}
func (s *transportService) validateUpdateRoute(req UpdateTransportRouteRequest) error {
	if req.RouteID == uuid.Nil {
		return fmt.Errorf("%w: route_id is required", ErrInvalidInput)
	}
	if req.RouteName == "" {
		return fmt.Errorf("%w: route_name is required", ErrInvalidInput)
	}
	return nil
}

// ----- Stop Methods -----
func (s *transportService) CreateStop(ctx context.Context, req CreateTransportStopRequest, idempotencyKey string) (*models.TransportStop, error) {
	logger := s.logger.With(
		zap.String("method", "CreateStop"),
		zap.String("route_id", req.RouteID.String()),
		zap.String("stop_name", req.StopName),
		zap.String("idempotency_key", idempotencyKey),
	)
	s.sanitizeStop(&req)
	if err := s.validateCreateStop(req); err != nil {
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
			var stop models.TransportStop
			if err := s.idempotencyStore.Get(ctx, tx, idempotencyKey, &stop); err != nil {
				return nil, fmt.Errorf("failed to retrieve idempotent response: %w", err)
			}
			logger.Info("returning idempotent response")
			return &stop, nil
		}
	}

	stop := &models.TransportStop{
		RouteID:    req.RouteID,
		StopName:   req.StopName,
		StopOrder:  req.StopOrder,
		Latitude:   req.Latitude,
		Longitude:  req.Longitude,
		PickupTime: req.PickupTime,
		DropTime:   req.DropTime,
		CreatedBy:  req.CreatedBy,
		UpdatedBy:  req.UpdatedBy,
	}
	if err := s.repo.CreateStop(ctx, tx, stop); err != nil {
		return nil, err
	}

	if idempotencyKey != "" {
		if err := s.idempotencyStore.Store(ctx, tx, idempotencyKey, stop); err != nil {
			logger.Error("failed to store idempotency key", zap.Error(err))
			return nil, fmt.Errorf("failed to store idempotency key: %w", err)
		}
	}
	if err := s.auditLogger.Log(ctx, tx, "CREATE", stop.StopID, nil, stop, req.CreatedBy); err != nil {
		logger.Error("audit log failed", zap.Error(err))
	}
	if err := s.outboxStore.Store(ctx, tx, string(EventTransportStopCreated), stop); err != nil {
		logger.Error("failed to store outbox event", zap.Error(err))
		return nil, fmt.Errorf("failed to store outbox event: %w", err)
	}
	if err := tx.Commit(); err != nil {
		return nil, fmt.Errorf("commit tx: %w", err)
	}

	logger.Info("transport stop created", zap.String("id", stop.StopID.String()))
	return stop, nil
}

func (s *transportService) GetStopByID(ctx context.Context, id uuid.UUID) (*models.TransportStop, error) {
	stop, err := s.repo.GetStopByID(ctx, s.pgClient.DB, id)
	if err != nil {
		return nil, err
	}
	if stop == nil {
		return nil, fmt.Errorf("%w: stop %s", ErrNotFound, id)
	}
	return stop, nil
}

func (s *transportService) ListStops(ctx context.Context, filter repository.TransportStopFilter, p repository.Pagination, srt repository.Sort) ([]*models.TransportStop, error) {
	return s.repo.ListStops(ctx, s.pgClient.DB, filter, p, srt)
}

func (s *transportService) CountStops(ctx context.Context, filter repository.TransportStopFilter) (int64, error) {
	return s.repo.CountStops(ctx, s.pgClient.DB, filter)
}

func (s *transportService) UpdateStop(ctx context.Context, req UpdateTransportStopRequest) (*models.TransportStop, error) {
	logger := s.logger.With(
		zap.String("method", "UpdateStop"),
		zap.String("stop_id", req.StopID.String()),
	)
	if err := s.validateUpdateStop(req); err != nil {
		return nil, err
	}
	tx, err := s.pgClient.BeginTx(ctx, nil)
	if err != nil {
		return nil, fmt.Errorf("begin tx: %w", err)
	}
	defer tx.Rollback()

	stop, err := s.repo.GetStopByID(ctx, tx, req.StopID)
	if err != nil {
		return nil, err
	}
	if stop == nil {
		return nil, fmt.Errorf("%w: stop %s", ErrNotFound, req.StopID)
	}

	oldStop := *stop
	stop.StopName = req.StopName
	stop.StopOrder = req.StopOrder
	stop.Latitude = req.Latitude
	stop.Longitude = req.Longitude
	stop.PickupTime = req.PickupTime
	stop.DropTime = req.DropTime
	stop.UpdatedBy = req.UpdatedBy

	if err := s.repo.UpdateStop(ctx, tx, stop); err != nil {
		return nil, err
	}

	if err := s.auditLogger.Log(ctx, tx, "UPDATE", stop.StopID, &oldStop, stop, req.UpdatedBy); err != nil {
		logger.Error("audit log failed", zap.Error(err))
	}
	if err := s.outboxStore.Store(ctx, tx, string(EventTransportStopUpdated), map[string]interface{}{
		"old": oldStop,
		"new": stop,
	}); err != nil {
		logger.Error("failed to store outbox event", zap.Error(err))
		return nil, fmt.Errorf("failed to store outbox event: %w", err)
	}
	if err := tx.Commit(); err != nil {
		return nil, fmt.Errorf("commit tx: %w", err)
	}

	logger.Info("transport stop updated")
	return stop, nil
}

func (s *transportService) DeleteStop(ctx context.Context, id uuid.UUID) error {
	logger := s.logger.With(
		zap.String("method", "DeleteStop"),
		zap.String("stop_id", id.String()),
	)
	tx, err := s.pgClient.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("begin tx: %w", err)
	}
	defer tx.Rollback()

	if err := s.repo.DeleteStop(ctx, tx, id); err != nil {
		return err
	}
	if err := s.auditLogger.Log(ctx, tx, "DELETE", id, nil, nil, nil); err != nil {
		logger.Error("audit log failed", zap.Error(err))
	}
	if err := s.outboxStore.Store(ctx, tx, string(EventTransportStopDeleted), map[string]interface{}{
		"stop_id": id,
	}); err != nil {
		logger.Error("failed to store outbox event", zap.Error(err))
		return fmt.Errorf("failed to store outbox event: %w", err)
	}
	if err := tx.Commit(); err != nil {
		return fmt.Errorf("commit tx: %w", err)
	}
	logger.Info("transport stop deleted")
	return nil
}

// Helper validation for stop
func (s *transportService) sanitizeStop(req *CreateTransportStopRequest) {
	req.StopName = strings.TrimSpace(req.StopName)
}
func (s *transportService) validateCreateStop(req CreateTransportStopRequest) error {
	if req.RouteID == uuid.Nil {
		return fmt.Errorf("%w: route_id is required", ErrInvalidInput)
	}
	if req.StopName == "" {
		return fmt.Errorf("%w: stop_name is required", ErrInvalidInput)
	}
	return nil
}
func (s *transportService) validateUpdateStop(req UpdateTransportStopRequest) error {
	if req.StopID == uuid.Nil {
		return fmt.Errorf("%w: stop_id is required", ErrInvalidInput)
	}
	if req.StopName == "" {
		return fmt.Errorf("%w: stop_name is required", ErrInvalidInput)
	}
	return nil
}

// ----- Vehicle Methods -----
func (s *transportService) CreateVehicle(ctx context.Context, req CreateTransportVehicleRequest, idempotencyKey string) (*models.TransportVehicle, error) {
	logger := s.logger.With(
		zap.String("method", "CreateVehicle"),
		zap.String("company_id", req.CompanyID.String()),
		zap.String("vehicle_no", req.VehicleNo),
		zap.String("idempotency_key", idempotencyKey),
	)
	s.sanitizeVehicle(&req)
	if err := s.validateCreateVehicle(req); err != nil {
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
			var vehicle models.TransportVehicle
			if err := s.idempotencyStore.Get(ctx, tx, idempotencyKey, &vehicle); err != nil {
				return nil, fmt.Errorf("failed to retrieve idempotent response: %w", err)
			}
			logger.Info("returning idempotent response")
			return &vehicle, nil
		}
	}

	// Check duplicate vehicle number
	existing, err := s.repo.GetVehicleByNumber(ctx, tx, req.CompanyID, req.VehicleNo)
	if err != nil && !errors.Is(err, sql.ErrNoRows) {
		return nil, err
	}
	if existing != nil {
		return nil, fmt.Errorf("%w: vehicle with number %s already exists", ErrDuplicate, req.VehicleNo)
	}

	vehicle := &models.TransportVehicle{
		CompanyID:       req.CompanyID,
		VehicleNo:       req.VehicleNo,
		VehicleType:     req.VehicleType,
		Capacity:        req.Capacity,
		InsuranceExpiry: req.InsuranceExpiry,
		FitnessExpiry:   req.FitnessExpiry,
		IsActive:        req.IsActive,
		CreatedBy:       req.CreatedBy,
		UpdatedBy:       req.UpdatedBy,
	}
	if err := s.repo.CreateVehicle(ctx, tx, vehicle); err != nil {
		return nil, err
	}

	if idempotencyKey != "" {
		if err := s.idempotencyStore.Store(ctx, tx, idempotencyKey, vehicle); err != nil {
			logger.Error("failed to store idempotency key", zap.Error(err))
			return nil, fmt.Errorf("failed to store idempotency key: %w", err)
		}
	}
	if err := s.auditLogger.Log(ctx, tx, "CREATE", vehicle.VehicleID, nil, vehicle, req.CreatedBy); err != nil {
		logger.Error("audit log failed", zap.Error(err))
	}
	if err := s.outboxStore.Store(ctx, tx, string(EventTransportVehicleCreated), vehicle); err != nil {
		logger.Error("failed to store outbox event", zap.Error(err))
		return nil, fmt.Errorf("failed to store outbox event: %w", err)
	}
	if err := tx.Commit(); err != nil {
		return nil, fmt.Errorf("commit tx: %w", err)
	}

	logger.Info("transport vehicle created", zap.String("id", vehicle.VehicleID.String()))
	return vehicle, nil
}

func (s *transportService) GetVehicleByID(ctx context.Context, id uuid.UUID) (*models.TransportVehicle, error) {
	vehicle, err := s.repo.GetVehicleByID(ctx, s.pgClient.DB, id)
	if err != nil {
		return nil, err
	}
	if vehicle == nil {
		return nil, fmt.Errorf("%w: vehicle %s", ErrNotFound, id)
	}
	return vehicle, nil
}

func (s *transportService) GetVehicleByNumber(ctx context.Context, companyID uuid.UUID, number string) (*models.TransportVehicle, error) {
	vehicle, err := s.repo.GetVehicleByNumber(ctx, s.pgClient.DB, companyID, number)
	if err != nil {
		return nil, err
	}
	if vehicle == nil {
		return nil, fmt.Errorf("%w: vehicle with number %s", ErrNotFound, number)
	}
	return vehicle, nil
}

func (s *transportService) ListVehicles(ctx context.Context, filter repository.TransportVehicleFilter, p repository.Pagination, srt repository.Sort) ([]*models.TransportVehicle, error) {
	return s.repo.ListVehicles(ctx, s.pgClient.DB, filter, p, srt)
}

func (s *transportService) CountVehicles(ctx context.Context, filter repository.TransportVehicleFilter) (int64, error) {
	return s.repo.CountVehicles(ctx, s.pgClient.DB, filter)
}

func (s *transportService) UpdateVehicle(ctx context.Context, req UpdateTransportVehicleRequest) (*models.TransportVehicle, error) {
	logger := s.logger.With(
		zap.String("method", "UpdateVehicle"),
		zap.String("vehicle_id", req.VehicleID.String()),
	)
	if err := s.validateUpdateVehicle(req); err != nil {
		return nil, err
	}
	tx, err := s.pgClient.BeginTx(ctx, nil)
	if err != nil {
		return nil, fmt.Errorf("begin tx: %w", err)
	}
	defer tx.Rollback()

	vehicle, err := s.repo.GetVehicleByID(ctx, tx, req.VehicleID)
	if err != nil {
		return nil, err
	}
	if vehicle == nil {
		return nil, fmt.Errorf("%w: vehicle %s", ErrNotFound, req.VehicleID)
	}

	// If vehicle number changed, check for duplicate
	if vehicle.VehicleNo != req.VehicleNo {
		existing, err := s.repo.GetVehicleByNumber(ctx, tx, vehicle.CompanyID, req.VehicleNo)
		if err != nil && !errors.Is(err, sql.ErrNoRows) {
			return nil, err
		}
		if existing != nil && existing.VehicleID != req.VehicleID {
			return nil, fmt.Errorf("%w: vehicle with number %s already exists", ErrDuplicate, req.VehicleNo)
		}
	}

	oldVehicle := *vehicle
	vehicle.VehicleNo = req.VehicleNo
	vehicle.VehicleType = req.VehicleType
	vehicle.Capacity = req.Capacity
	vehicle.InsuranceExpiry = req.InsuranceExpiry
	vehicle.FitnessExpiry = req.FitnessExpiry
	vehicle.IsActive = req.IsActive
	vehicle.UpdatedBy = req.UpdatedBy

	if err := s.repo.UpdateVehicle(ctx, tx, vehicle); err != nil {
		return nil, err
	}

	if err := s.auditLogger.Log(ctx, tx, "UPDATE", vehicle.VehicleID, &oldVehicle, vehicle, req.UpdatedBy); err != nil {
		logger.Error("audit log failed", zap.Error(err))
	}
	if err := s.outboxStore.Store(ctx, tx, string(EventTransportVehicleUpdated), map[string]interface{}{
		"old": oldVehicle,
		"new": vehicle,
	}); err != nil {
		logger.Error("failed to store outbox event", zap.Error(err))
		return nil, fmt.Errorf("failed to store outbox event: %w", err)
	}
	if err := tx.Commit(); err != nil {
		return nil, fmt.Errorf("commit tx: %w", err)
	}

	logger.Info("transport vehicle updated")
	return vehicle, nil
}

func (s *transportService) DeleteVehicle(ctx context.Context, id uuid.UUID, deletedBy *uuid.UUID) error {
	logger := s.logger.With(
		zap.String("method", "DeleteVehicle"),
		zap.String("vehicle_id", id.String()),
	)
	tx, err := s.pgClient.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("begin tx: %w", err)
	}
	defer tx.Rollback()

	if err := s.repo.DeleteVehicle(ctx, tx, id, deletedBy); err != nil {
		return err
	}
	if err := s.auditLogger.Log(ctx, tx, "DELETE", id, nil, nil, deletedBy); err != nil {
		logger.Error("audit log failed", zap.Error(err))
	}
	if err := s.outboxStore.Store(ctx, tx, string(EventTransportVehicleDeleted), map[string]interface{}{
		"vehicle_id": id,
		"deleted_by": deletedBy,
	}); err != nil {
		logger.Error("failed to store outbox event", zap.Error(err))
		return fmt.Errorf("failed to store outbox event: %w", err)
	}
	if err := tx.Commit(); err != nil {
		return fmt.Errorf("commit tx: %w", err)
	}
	logger.Info("transport vehicle deleted")
	return nil
}

// Helper validation for vehicle
func (s *transportService) sanitizeVehicle(req *CreateTransportVehicleRequest) {
	req.VehicleNo = strings.TrimSpace(strings.ToUpper(req.VehicleNo))
	req.VehicleType = strings.TrimSpace(req.VehicleType)
}
func (s *transportService) validateCreateVehicle(req CreateTransportVehicleRequest) error {
	if req.CompanyID == uuid.Nil {
		return fmt.Errorf("%w: company_id is required", ErrInvalidInput)
	}
	if req.VehicleNo == "" {
		return fmt.Errorf("%w: vehicle_no is required", ErrInvalidInput)
	}
	return nil
}
func (s *transportService) validateUpdateVehicle(req UpdateTransportVehicleRequest) error {
	if req.VehicleID == uuid.Nil {
		return fmt.Errorf("%w: vehicle_id is required", ErrInvalidInput)
	}
	if req.VehicleNo == "" {
		return fmt.Errorf("%w: vehicle_no is required", ErrInvalidInput)
	}
	return nil
}

// ----- Driver Assignment Methods -----
func (s *transportService) CreateDriverAssignment(ctx context.Context, req CreateDriverAssignmentRequest, idempotencyKey string) (*models.TransportDriverAssignment, error) {
	logger := s.logger.With(
		zap.String("method", "CreateDriverAssignment"),
		zap.String("vehicle_id", req.VehicleID.String()),
		zap.String("driver_name", req.DriverName),
		zap.String("idempotency_key", idempotencyKey),
	)
	s.sanitizeDriverAssignment(&req)
	if err := s.validateCreateDriverAssignment(req); err != nil {
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
			var da models.TransportDriverAssignment
			if err := s.idempotencyStore.Get(ctx, tx, idempotencyKey, &da); err != nil {
				return nil, fmt.Errorf("failed to retrieve idempotent response: %w", err)
			}
			logger.Info("returning idempotent response")
			return &da, nil
		}
	}

	da := &models.TransportDriverAssignment{
		VehicleID:      req.VehicleID,
		DriverName:     req.DriverName,
		DriverPhone:    req.DriverPhone,
		DriverLicense:  req.DriverLicense,
		AssignmentDate: req.AssignmentDate,
		EndDate:        req.EndDate,
		IsActive:       req.IsActive,
		CreatedBy:      req.CreatedBy,
		UpdatedBy:      req.UpdatedBy,
	}
	if err := s.repo.CreateDriverAssignment(ctx, tx, da); err != nil {
		return nil, err
	}

	if idempotencyKey != "" {
		if err := s.idempotencyStore.Store(ctx, tx, idempotencyKey, da); err != nil {
			logger.Error("failed to store idempotency key", zap.Error(err))
			return nil, fmt.Errorf("failed to store idempotency key: %w", err)
		}
	}
	if err := s.auditLogger.Log(ctx, tx, "CREATE", da.AssignmentID, nil, da, req.CreatedBy); err != nil {
		logger.Error("audit log failed", zap.Error(err))
	}
	if err := s.outboxStore.Store(ctx, tx, string(EventTransportDriverAssignmentCreated), da); err != nil {
		logger.Error("failed to store outbox event", zap.Error(err))
		return nil, fmt.Errorf("failed to store outbox event: %w", err)
	}
	if err := tx.Commit(); err != nil {
		return nil, fmt.Errorf("commit tx: %w", err)
	}

	logger.Info("driver assignment created", zap.String("id", da.AssignmentID.String()))
	return da, nil
}

func (s *transportService) GetDriverAssignmentByID(ctx context.Context, id uuid.UUID) (*models.TransportDriverAssignment, error) {
	da, err := s.repo.GetDriverAssignmentByID(ctx, s.pgClient.DB, id)
	if err != nil {
		return nil, err
	}
	if da == nil {
		return nil, fmt.Errorf("%w: driver assignment %s", ErrNotFound, id)
	}
	return da, nil
}

func (s *transportService) ListDriverAssignments(ctx context.Context, filter repository.TransportDriverAssignmentFilter, p repository.Pagination, srt repository.Sort) ([]*models.TransportDriverAssignment, error) {
	return s.repo.ListDriverAssignments(ctx, s.pgClient.DB, filter, p, srt)
}

func (s *transportService) CountDriverAssignments(ctx context.Context, filter repository.TransportDriverAssignmentFilter) (int64, error) {
	return s.repo.CountDriverAssignments(ctx, s.pgClient.DB, filter)
}

func (s *transportService) UpdateDriverAssignment(ctx context.Context, req UpdateDriverAssignmentRequest) (*models.TransportDriverAssignment, error) {
	logger := s.logger.With(
		zap.String("method", "UpdateDriverAssignment"),
		zap.String("assignment_id", req.AssignmentID.String()),
	)
	if err := s.validateUpdateDriverAssignment(req); err != nil {
		return nil, err
	}
	tx, err := s.pgClient.BeginTx(ctx, nil)
	if err != nil {
		return nil, fmt.Errorf("begin tx: %w", err)
	}
	defer tx.Rollback()

	da, err := s.repo.GetDriverAssignmentByID(ctx, tx, req.AssignmentID)
	if err != nil {
		return nil, err
	}
	if da == nil {
		return nil, fmt.Errorf("%w: driver assignment %s", ErrNotFound, req.AssignmentID)
	}

	oldDa := *da
	da.DriverName = req.DriverName
	da.DriverPhone = req.DriverPhone
	da.DriverLicense = req.DriverLicense
	da.AssignmentDate = req.AssignmentDate
	da.EndDate = req.EndDate
	da.IsActive = req.IsActive
	da.UpdatedBy = req.UpdatedBy

	if err := s.repo.UpdateDriverAssignment(ctx, tx, da); err != nil {
		return nil, err
	}

	if err := s.auditLogger.Log(ctx, tx, "UPDATE", da.AssignmentID, &oldDa, da, req.UpdatedBy); err != nil {
		logger.Error("audit log failed", zap.Error(err))
	}
	if err := s.outboxStore.Store(ctx, tx, string(EventTransportDriverAssignmentUpdated), map[string]interface{}{
		"old": oldDa,
		"new": da,
	}); err != nil {
		logger.Error("failed to store outbox event", zap.Error(err))
		return nil, fmt.Errorf("failed to store outbox event: %w", err)
	}
	if err := tx.Commit(); err != nil {
		return nil, fmt.Errorf("commit tx: %w", err)
	}

	logger.Info("driver assignment updated")
	return da, nil
}

func (s *transportService) DeleteDriverAssignment(ctx context.Context, id uuid.UUID) error {
	logger := s.logger.With(
		zap.String("method", "DeleteDriverAssignment"),
		zap.String("assignment_id", id.String()),
	)
	tx, err := s.pgClient.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("begin tx: %w", err)
	}
	defer tx.Rollback()

	if err := s.repo.DeleteDriverAssignment(ctx, tx, id); err != nil {
		return err
	}
	if err := s.auditLogger.Log(ctx, tx, "DELETE", id, nil, nil, nil); err != nil {
		logger.Error("audit log failed", zap.Error(err))
	}
	if err := s.outboxStore.Store(ctx, tx, string(EventTransportDriverAssignmentDeleted), map[string]interface{}{
		"assignment_id": id,
	}); err != nil {
		logger.Error("failed to store outbox event", zap.Error(err))
		return fmt.Errorf("failed to store outbox event: %w", err)
	}
	if err := tx.Commit(); err != nil {
		return fmt.Errorf("commit tx: %w", err)
	}
	logger.Info("driver assignment deleted")
	return nil
}

// Helper validation for driver assignment
func (s *transportService) sanitizeDriverAssignment(req *CreateDriverAssignmentRequest) {
	req.DriverName = strings.TrimSpace(req.DriverName)
	req.DriverPhone = strings.TrimSpace(req.DriverPhone)
	req.DriverLicense = strings.TrimSpace(req.DriverLicense)
}
func (s *transportService) validateCreateDriverAssignment(req CreateDriverAssignmentRequest) error {
	if req.VehicleID == uuid.Nil {
		return fmt.Errorf("%w: vehicle_id is required", ErrInvalidInput)
	}
	if req.DriverName == "" {
		return fmt.Errorf("%w: driver_name is required", ErrInvalidInput)
	}
	return nil
}
func (s *transportService) validateUpdateDriverAssignment(req UpdateDriverAssignmentRequest) error {
	if req.AssignmentID == uuid.Nil {
		return fmt.Errorf("%w: assignment_id is required", ErrInvalidInput)
	}
	if req.DriverName == "" {
		return fmt.Errorf("%w: driver_name is required", ErrInvalidInput)
	}
	return nil
}

// ----- Student Assignment Methods -----
func (s *transportService) CreateStudentAssignment(ctx context.Context, req CreateStudentAssignmentRequest, idempotencyKey string) (*models.StudentTransportAssignment, error) {
	logger := s.logger.With(
		zap.String("method", "CreateStudentAssignment"),
		zap.String("student_id", req.StudentID.String()),
		zap.String("route_id", req.RouteID.String()),
		zap.String("stop_id", req.StopID.String()),
		zap.String("idempotency_key", idempotencyKey),
	)
	s.sanitizeStudentAssignment(&req)
	if err := s.validateCreateStudentAssignment(req); err != nil {
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
			var sa models.StudentTransportAssignment
			if err := s.idempotencyStore.Get(ctx, tx, idempotencyKey, &sa); err != nil {
				return nil, fmt.Errorf("failed to retrieve idempotent response: %w", err)
			}
			logger.Info("returning idempotent response")
			return &sa, nil
		}
	}

	sa := &models.StudentTransportAssignment{
		StudentID:     req.StudentID,
		RouteID:       req.RouteID,
		StopID:        req.StopID,
		PickupPoint:   req.PickupPoint,
		DropPoint:     req.DropPoint,
		EffectiveFrom: req.EffectiveFrom,
		EffectiveTo:   req.EffectiveTo,
		IsActive:      req.IsActive,
		CreatedBy:     req.CreatedBy,
		UpdatedBy:     req.UpdatedBy,
	}
	if err := s.repo.CreateStudentAssignment(ctx, tx, sa); err != nil {
		return nil, err
	}

	if idempotencyKey != "" {
		if err := s.idempotencyStore.Store(ctx, tx, idempotencyKey, sa); err != nil {
			logger.Error("failed to store idempotency key", zap.Error(err))
			return nil, fmt.Errorf("failed to store idempotency key: %w", err)
		}
	}
	if err := s.auditLogger.Log(ctx, tx, "CREATE", sa.AssignmentID, nil, sa, req.CreatedBy); err != nil {
		logger.Error("audit log failed", zap.Error(err))
	}
	if err := s.outboxStore.Store(ctx, tx, string(EventTransportStudentAssignmentCreated), sa); err != nil {
		logger.Error("failed to store outbox event", zap.Error(err))
		return nil, fmt.Errorf("failed to store outbox event: %w", err)
	}
	if err := tx.Commit(); err != nil {
		return nil, fmt.Errorf("commit tx: %w", err)
	}

	// Send notification to student
	title := "Transport Assignment Created"
	message := fmt.Sprintf("You have been assigned to transport route %s. Pickup point: %s", req.RouteID.String(), req.PickupPoint)
	s.sendNotification(ctx, req.StudentID, uuid.Nil, title, message, models.NotificationTypeInfo, models.PriorityNormal, req.CreatedBy)

	logger.Info("student transport assignment created", zap.String("id", sa.AssignmentID.String()))
	return sa, nil
}

func (s *transportService) GetStudentAssignmentByID(ctx context.Context, id uuid.UUID) (*models.StudentTransportAssignment, error) {
	sa, err := s.repo.GetStudentAssignmentByID(ctx, s.pgClient.DB, id)
	if err != nil {
		return nil, err
	}
	if sa == nil {
		return nil, fmt.Errorf("%w: student assignment %s", ErrNotFound, id)
	}
	return sa, nil
}

func (s *transportService) ListStudentAssignments(ctx context.Context, filter repository.StudentTransportAssignmentFilter, p repository.Pagination, srt repository.Sort) ([]*models.StudentTransportAssignment, error) {
	return s.repo.ListStudentAssignments(ctx, s.pgClient.DB, filter, p, srt)
}

func (s *transportService) CountStudentAssignments(ctx context.Context, filter repository.StudentTransportAssignmentFilter) (int64, error) {
	return s.repo.CountStudentAssignments(ctx, s.pgClient.DB, filter)
}

func (s *transportService) UpdateStudentAssignment(ctx context.Context, req UpdateStudentAssignmentRequest) (*models.StudentTransportAssignment, error) {
	logger := s.logger.With(
		zap.String("method", "UpdateStudentAssignment"),
		zap.String("assignment_id", req.AssignmentID.String()),
	)
	if err := s.validateUpdateStudentAssignment(req); err != nil {
		return nil, err
	}
	tx, err := s.pgClient.BeginTx(ctx, nil)
	if err != nil {
		return nil, fmt.Errorf("begin tx: %w", err)
	}
	defer tx.Rollback()

	sa, err := s.repo.GetStudentAssignmentByID(ctx, tx, req.AssignmentID)
	if err != nil {
		return nil, err
	}
	if sa == nil {
		return nil, fmt.Errorf("%w: student assignment %s", ErrNotFound, req.AssignmentID)
	}

	oldSa := *sa
	sa.StudentID = req.StudentID
	sa.RouteID = req.RouteID
	sa.StopID = req.StopID
	sa.PickupPoint = req.PickupPoint
	sa.DropPoint = req.DropPoint
	sa.EffectiveFrom = req.EffectiveFrom
	sa.EffectiveTo = req.EffectiveTo
	sa.IsActive = req.IsActive
	sa.UpdatedBy = req.UpdatedBy

	if err := s.repo.UpdateStudentAssignment(ctx, tx, sa); err != nil {
		return nil, err
	}

	if err := s.auditLogger.Log(ctx, tx, "UPDATE", sa.AssignmentID, &oldSa, sa, req.UpdatedBy); err != nil {
		logger.Error("audit log failed", zap.Error(err))
	}
	if err := s.outboxStore.Store(ctx, tx, string(EventTransportStudentAssignmentUpdated), map[string]interface{}{
		"old": oldSa,
		"new": sa,
	}); err != nil {
		logger.Error("failed to store outbox event", zap.Error(err))
		return nil, fmt.Errorf("failed to store outbox event: %w", err)
	}
	if err := tx.Commit(); err != nil {
		return nil, fmt.Errorf("commit tx: %w", err)
	}

	// Send notification if significant changes occurred (optional)
	title := "Transport Assignment Updated"
	message := "Your transport assignment has been updated."
	s.sendNotification(ctx, sa.StudentID, uuid.Nil, title, message, models.NotificationTypeInfo, models.PriorityNormal, req.UpdatedBy)

	logger.Info("student transport assignment updated")
	return sa, nil
}

func (s *transportService) DeleteStudentAssignment(ctx context.Context, id uuid.UUID) error {
	logger := s.logger.With(
		zap.String("method", "DeleteStudentAssignment"),
		zap.String("assignment_id", id.String()),
	)
	tx, err := s.pgClient.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("begin tx: %w", err)
	}
	defer tx.Rollback()

	if err := s.repo.DeleteStudentAssignment(ctx, tx, id); err != nil {
		return err
	}
	if err := s.auditLogger.Log(ctx, tx, "DELETE", id, nil, nil, nil); err != nil {
		logger.Error("audit log failed", zap.Error(err))
	}
	if err := s.outboxStore.Store(ctx, tx, string(EventTransportStudentAssignmentDeleted), map[string]interface{}{
		"assignment_id": id,
	}); err != nil {
		logger.Error("failed to store outbox event", zap.Error(err))
		return fmt.Errorf("failed to store outbox event: %w", err)
	}
	if err := tx.Commit(); err != nil {
		return fmt.Errorf("commit tx: %w", err)
	}
	logger.Info("student transport assignment deleted")
	return nil
}

// Helper validation for student assignment
func (s *transportService) sanitizeStudentAssignment(req *CreateStudentAssignmentRequest) {
	req.PickupPoint = strings.TrimSpace(req.PickupPoint)
	req.DropPoint = strings.TrimSpace(req.DropPoint)
}
func (s *transportService) validateCreateStudentAssignment(req CreateStudentAssignmentRequest) error {
	if req.StudentID == uuid.Nil {
		return fmt.Errorf("%w: student_id is required", ErrInvalidInput)
	}
	if req.RouteID == uuid.Nil {
		return fmt.Errorf("%w: route_id is required", ErrInvalidInput)
	}
	if req.StopID == uuid.Nil {
		return fmt.Errorf("%w: stop_id is required", ErrInvalidInput)
	}
	return nil
}
func (s *transportService) validateUpdateStudentAssignment(req UpdateStudentAssignmentRequest) error {
	if req.AssignmentID == uuid.Nil {
		return fmt.Errorf("%w: assignment_id is required", ErrInvalidInput)
	}
	if req.StudentID == uuid.Nil {
		return fmt.Errorf("%w: student_id is required", ErrInvalidInput)
	}
	if req.RouteID == uuid.Nil {
		return fmt.Errorf("%w: route_id is required", ErrInvalidInput)
	}
	if req.StopID == uuid.Nil {
		return fmt.Errorf("%w: stop_id is required", ErrInvalidInput)
	}
	return nil
}

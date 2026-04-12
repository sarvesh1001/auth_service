package service

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"strings"

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
// Request DTOs (matching types.go)
// ---------------------------------------------------------------------

// ---------------------------------------------------------------------
// Service interface
// ---------------------------------------------------------------------

type TransportService interface {
	CreateRoute(ctx context.Context, req CreateTransportRouteRequest) (*models.TransportRoute, error)
	GetRouteByID(ctx context.Context, id uuid.UUID) (*models.TransportRoute, error)
	ListRoutes(ctx context.Context, filter repository.TransportRouteFilter, p repository.Pagination, s repository.Sort) ([]*models.TransportRoute, error)
	CountRoutes(ctx context.Context, filter repository.TransportRouteFilter) (int64, error)
	UpdateRoute(ctx context.Context, req UpdateTransportRouteRequest) (*models.TransportRoute, error)
	DeleteRoute(ctx context.Context, id uuid.UUID, deletedBy *uuid.UUID) error

	CreateStop(ctx context.Context, req CreateTransportStopRequest) (*models.TransportStop, error)
	GetStopByID(ctx context.Context, id uuid.UUID) (*models.TransportStop, error)
	ListStops(ctx context.Context, filter repository.TransportStopFilter, p repository.Pagination, s repository.Sort) ([]*models.TransportStop, error)
	CountStops(ctx context.Context, filter repository.TransportStopFilter) (int64, error)
	UpdateStop(ctx context.Context, req UpdateTransportStopRequest) (*models.TransportStop, error)
	DeleteStop(ctx context.Context, id uuid.UUID) error

	CreateVehicle(ctx context.Context, req CreateTransportVehicleRequest) (*models.TransportVehicle, error)
	GetVehicleByID(ctx context.Context, id uuid.UUID) (*models.TransportVehicle, error)
	GetVehicleByNumber(ctx context.Context, companyID uuid.UUID, number string) (*models.TransportVehicle, error)
	ListVehicles(ctx context.Context, filter repository.TransportVehicleFilter, p repository.Pagination, s repository.Sort) ([]*models.TransportVehicle, error)
	CountVehicles(ctx context.Context, filter repository.TransportVehicleFilter) (int64, error)
	UpdateVehicle(ctx context.Context, req UpdateTransportVehicleRequest) (*models.TransportVehicle, error)
	DeleteVehicle(ctx context.Context, id uuid.UUID, deletedBy *uuid.UUID) error

	CreateDriverAssignment(ctx context.Context, req CreateDriverAssignmentRequest) (*models.TransportDriverAssignment, error)
	GetDriverAssignmentByID(ctx context.Context, id uuid.UUID) (*models.TransportDriverAssignment, error)
	ListDriverAssignments(ctx context.Context, filter repository.TransportDriverAssignmentFilter, p repository.Pagination, s repository.Sort) ([]*models.TransportDriverAssignment, error)
	CountDriverAssignments(ctx context.Context, filter repository.TransportDriverAssignmentFilter) (int64, error)
	UpdateDriverAssignment(ctx context.Context, req UpdateDriverAssignmentRequest) (*models.TransportDriverAssignment, error)
	DeleteDriverAssignment(ctx context.Context, id uuid.UUID) error

	CreateStudentAssignment(ctx context.Context, req CreateStudentAssignmentRequest) (*models.StudentTransportAssignment, error)
	GetStudentAssignmentByID(ctx context.Context, id uuid.UUID) (*models.StudentTransportAssignment, error)
	ListStudentAssignments(ctx context.Context, filter repository.StudentTransportAssignmentFilter, p repository.Pagination, s repository.Sort) ([]*models.StudentTransportAssignment, error)
	CountStudentAssignments(ctx context.Context, filter repository.StudentTransportAssignmentFilter) (int64, error)
	UpdateStudentAssignment(ctx context.Context, req UpdateStudentAssignmentRequest) (*models.StudentTransportAssignment, error)
	DeleteStudentAssignment(ctx context.Context, id uuid.UUID) error
}

// ---------------------------------------------------------------------
// Service implementation
// ---------------------------------------------------------------------

type transportService struct {
	repo             repository.TransportRepository
	idempotencyStore idempotency.Store
	auditService     *audit.AuditService
	outboxRepo       outbox.Repository
	pgClient         *client.PostgresClient
	logger           *zap.Logger
	notifSvc         NotificationService
}

func NewTransportService(
	repo repository.TransportRepository,
	idempotencyStore idempotency.Store,
	auditService *audit.AuditService,
	outboxRepo outbox.Repository,
	pgClient *client.PostgresClient,
	logger *zap.Logger,
	notifSvc NotificationService,
) TransportService {
	return &transportService{
		repo:             repo,
		idempotencyStore: idempotencyStore,
		auditService:     auditService,
		outboxRepo:       outboxRepo,
		pgClient:         pgClient,
		logger:           logger.Named("transport_service"),
		notifSvc:         notifSvc,
	}
}

// ---------------------------------------------------------------------
// Validation helpers (sanitization and required fields)
// ---------------------------------------------------------------------

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

// ---------------------------------------------------------------------
// Helper: send notification to student (used in student assignment)
// ---------------------------------------------------------------------

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
	// Use background context to avoid blocking
	_, _ = s.notifSvc.Create(context.Background(), req, "")
}

// ---------------------------------------------------------------------
// Route Methods
// ---------------------------------------------------------------------

func (s *transportService) CreateRoute(ctx context.Context, req CreateTransportRouteRequest) (*models.TransportRoute, error) {
	logger := s.logger.With(
		zap.String("method", "CreateRoute"),
		zap.String("company_id", req.CompanyID.String()),
		zap.String("route_name", req.RouteName),
	)
	idempotencyKey, _ := ctx.Value("idempotency_key").(string)

	s.sanitizeRoute(&req)
	if err := s.validateCreateRoute(req); err != nil {
		return nil, err
	}

	tx, err := s.pgClient.BeginTx(ctx, nil)
	if err != nil {
		return nil, fmt.Errorf("begin tx: %w", err)
	}
	defer tx.Rollback()

	// Idempotency check
	if idempotencyKey != "" {
		var existing models.TransportRoute
		if err := s.idempotencyStore.Get(ctx, tx, idempotencyKey, &existing); err == nil && existing.RouteID != uuid.Nil {
			logger.Info("idempotent request, returning cached response")
			return &existing, nil
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

	// Store idempotency key
	if idempotencyKey != "" {
		if err := s.idempotencyStore.Store(ctx, tx, idempotencyKey, route); err != nil {
			logger.Error("failed to store idempotency key", zap.Error(err))
		}
	}

	// Audit log
	if s.auditService != nil {
		_ = s.auditService.LogAction(ctx, nil, &req.CompanyID, "transport", "create", "route",
			&route.RouteID, "user", req.CreatedBy, nil, nil, map[string]interface{}{
				"route_name": route.RouteName,
			})
	}

	// Outbox event
	payload, _ := json.Marshal(route)
	outboxEvent := &outbox.Event{
		EventID:       uuid.New().String(),
		AggregateType: "transport_route",
		AggregateID:   route.RouteID.String(),
		EventType:     string(EventTransportRouteCreated),
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

	logger.Info("transport route created", zap.String("id", route.RouteID.String()))
	return route, nil
}

func (s *transportService) GetRouteByID(ctx context.Context, id uuid.UUID) (*models.TransportRoute, error) {
	logger := s.logger.With(zap.String("method", "GetRouteByID"), zap.String("id", id.String()))
	route, err := s.repo.GetRouteByID(ctx, s.pgClient.DB, id)
	if err != nil {
		return nil, err
	}
	if route == nil {
		return nil, fmt.Errorf("%w: route %s", ErrNotFound, id)
	}
	logger.Debug("route retrieved")
	return route, nil
}

func (s *transportService) ListRoutes(ctx context.Context, filter repository.TransportRouteFilter, p repository.Pagination, srt repository.Sort) ([]*models.TransportRoute, error) {
	logger := s.logger.With(zap.String("method", "ListRoutes"))
	logger.Debug("listing routes")
	return s.repo.ListRoutes(ctx, s.pgClient.DB, filter, p, srt)
}

func (s *transportService) CountRoutes(ctx context.Context, filter repository.TransportRouteFilter) (int64, error) {
	logger := s.logger.With(zap.String("method", "CountRoutes"))
	logger.Debug("counting routes")
	return s.repo.CountRoutes(ctx, s.pgClient.DB, filter)
}

func (s *transportService) UpdateRoute(ctx context.Context, req UpdateTransportRouteRequest) (*models.TransportRoute, error) {
	logger := s.logger.With(
		zap.String("method", "UpdateRoute"),
		zap.String("route_id", req.RouteID.String()),
	)
	idempotencyKey, _ := ctx.Value("idempotency_key").(string)

	if err := s.validateUpdateRoute(req); err != nil {
		return nil, err
	}

	tx, err := s.pgClient.BeginTx(ctx, nil)
	if err != nil {
		return nil, fmt.Errorf("begin tx: %w", err)
	}
	defer tx.Rollback()

	if idempotencyKey != "" {
		var existing models.TransportRoute
		if err := s.idempotencyStore.Get(ctx, tx, idempotencyKey, &existing); err == nil && existing.RouteID != uuid.Nil {
			logger.Info("idempotent request, returning cached response")
			return &existing, nil
		}
	}

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

	if idempotencyKey != "" {
		if err := s.idempotencyStore.Store(ctx, tx, idempotencyKey, route); err != nil {
			logger.Error("failed to store idempotency key", zap.Error(err))
		}
	}

	if s.auditService != nil {
		_ = s.auditService.LogAction(ctx, nil, &route.CompanyID, "transport", "update", "route",
			&req.RouteID, "user", req.UpdatedBy, nil, nil, map[string]interface{}{
				"old": oldRoute,
				"new": route,
			})
	}

	payload, _ := json.Marshal(map[string]interface{}{"old": oldRoute, "new": route})
	outboxEvent := &outbox.Event{
		EventID:       uuid.New().String(),
		AggregateType: "transport_route",
		AggregateID:   route.RouteID.String(),
		EventType:     string(EventTransportRouteUpdated),
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

	route, err := s.repo.GetRouteByID(ctx, tx, id)
	if err != nil {
		return err
	}
	if route == nil {
		return fmt.Errorf("%w: route %s", ErrNotFound, id)
	}

	if err := s.repo.DeleteRoute(ctx, tx, id, deletedBy); err != nil {
		return err
	}

	if s.auditService != nil {
		_ = s.auditService.LogAction(ctx, nil, &route.CompanyID, "transport", "delete", "route",
			&id, "user", deletedBy, nil, nil, nil)
	}

	payload, _ := json.Marshal(map[string]interface{}{
		"route_id":   id,
		"deleted_by": deletedBy,
	})
	outboxEvent := &outbox.Event{
		EventID:       uuid.New().String(),
		AggregateType: "transport_route",
		AggregateID:   id.String(),
		EventType:     string(EventTransportRouteDeleted),
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

	logger.Info("transport route deleted")
	return nil
}

// ---------------------------------------------------------------------
// Stop Methods
// ---------------------------------------------------------------------

func (s *transportService) CreateStop(ctx context.Context, req CreateTransportStopRequest) (*models.TransportStop, error) {
	logger := s.logger.With(
		zap.String("method", "CreateStop"),
		zap.String("route_id", req.RouteID.String()),
		zap.String("stop_name", req.StopName),
	)
	idempotencyKey, _ := ctx.Value("idempotency_key").(string)

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
		var existing models.TransportStop
		if err := s.idempotencyStore.Get(ctx, tx, idempotencyKey, &existing); err == nil && existing.StopID != uuid.Nil {
			logger.Info("idempotent request, returning cached response")
			return &existing, nil
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
		}
	}

	if s.auditService != nil {
		_ = s.auditService.LogAction(ctx, nil, nil, "transport", "create", "stop",
			&stop.StopID, "user", req.CreatedBy, nil, nil, map[string]interface{}{
				"route_id":  req.RouteID,
				"stop_name": stop.StopName,
			})
	}

	payload, _ := json.Marshal(stop)
	outboxEvent := &outbox.Event{
		EventID:       uuid.New().String(),
		AggregateType: "transport_stop",
		AggregateID:   stop.StopID.String(),
		EventType:     string(EventTransportStopCreated),
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

	logger.Info("transport stop created", zap.String("id", stop.StopID.String()))
	return stop, nil
}

func (s *transportService) GetStopByID(ctx context.Context, id uuid.UUID) (*models.TransportStop, error) {
	logger := s.logger.With(zap.String("method", "GetStopByID"), zap.String("id", id.String()))
	stop, err := s.repo.GetStopByID(ctx, s.pgClient.DB, id)
	if err != nil {
		return nil, err
	}
	if stop == nil {
		return nil, fmt.Errorf("%w: stop %s", ErrNotFound, id)
	}
	logger.Debug("stop retrieved")
	return stop, nil
}

func (s *transportService) ListStops(ctx context.Context, filter repository.TransportStopFilter, p repository.Pagination, srt repository.Sort) ([]*models.TransportStop, error) {
	logger := s.logger.With(zap.String("method", "ListStops"))
	logger.Debug("listing stops")
	return s.repo.ListStops(ctx, s.pgClient.DB, filter, p, srt)
}

func (s *transportService) CountStops(ctx context.Context, filter repository.TransportStopFilter) (int64, error) {
	logger := s.logger.With(zap.String("method", "CountStops"))
	logger.Debug("counting stops")
	return s.repo.CountStops(ctx, s.pgClient.DB, filter)
}

func (s *transportService) UpdateStop(ctx context.Context, req UpdateTransportStopRequest) (*models.TransportStop, error) {
	logger := s.logger.With(
		zap.String("method", "UpdateStop"),
		zap.String("stop_id", req.StopID.String()),
	)
	idempotencyKey, _ := ctx.Value("idempotency_key").(string)

	if err := s.validateUpdateStop(req); err != nil {
		return nil, err
	}

	tx, err := s.pgClient.BeginTx(ctx, nil)
	if err != nil {
		return nil, fmt.Errorf("begin tx: %w", err)
	}
	defer tx.Rollback()

	if idempotencyKey != "" {
		var existing models.TransportStop
		if err := s.idempotencyStore.Get(ctx, tx, idempotencyKey, &existing); err == nil && existing.StopID != uuid.Nil {
			logger.Info("idempotent request, returning cached response")
			return &existing, nil
		}
	}

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

	if idempotencyKey != "" {
		if err := s.idempotencyStore.Store(ctx, tx, idempotencyKey, stop); err != nil {
			logger.Error("failed to store idempotency key", zap.Error(err))
		}
	}

	if s.auditService != nil {
		_ = s.auditService.LogAction(ctx, nil, nil, "transport", "update", "stop",
			&req.StopID, "user", req.UpdatedBy, nil, nil, map[string]interface{}{
				"old": oldStop,
				"new": stop,
			})
	}

	payload, _ := json.Marshal(map[string]interface{}{"old": oldStop, "new": stop})
	outboxEvent := &outbox.Event{
		EventID:       uuid.New().String(),
		AggregateType: "transport_stop",
		AggregateID:   stop.StopID.String(),
		EventType:     string(EventTransportStopUpdated),
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

	stop, err := s.repo.GetStopByID(ctx, tx, id)
	if err != nil {
		return err
	}
	if stop == nil {
		return fmt.Errorf("%w: stop %s", ErrNotFound, id)
	}

	if err := s.repo.DeleteStop(ctx, tx, id); err != nil {
		return err
	}

	if s.auditService != nil {
		_ = s.auditService.LogAction(ctx, nil, nil, "transport", "delete", "stop",
			&id, "user", nil, nil, nil, nil)
	}

	payload, _ := json.Marshal(map[string]interface{}{
		"stop_id": id,
	})
	outboxEvent := &outbox.Event{
		EventID:       uuid.New().String(),
		AggregateType: "transport_stop",
		AggregateID:   id.String(),
		EventType:     string(EventTransportStopDeleted),
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

	logger.Info("transport stop deleted")
	return nil
}

// ---------------------------------------------------------------------
// Vehicle Methods
// ---------------------------------------------------------------------

func (s *transportService) CreateVehicle(ctx context.Context, req CreateTransportVehicleRequest) (*models.TransportVehicle, error) {
	logger := s.logger.With(
		zap.String("method", "CreateVehicle"),
		zap.String("company_id", req.CompanyID.String()),
		zap.String("vehicle_no", req.VehicleNo),
	)
	idempotencyKey, _ := ctx.Value("idempotency_key").(string)

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
		var existing models.TransportVehicle
		if err := s.idempotencyStore.Get(ctx, tx, idempotencyKey, &existing); err == nil && existing.VehicleID != uuid.Nil {
			logger.Info("idempotent request, returning cached response")
			return &existing, nil
		}
	}

	// Check duplicate vehicle number
	existingVehicle, err := s.repo.GetVehicleByNumber(ctx, tx, req.CompanyID, req.VehicleNo)
	if err != nil && !errors.Is(err, sql.ErrNoRows) {
		return nil, err
	}
	if existingVehicle != nil {
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
		}
	}

	if s.auditService != nil {
		_ = s.auditService.LogAction(ctx, nil, &req.CompanyID, "transport", "create", "vehicle",
			&vehicle.VehicleID, "user", req.CreatedBy, nil, nil, map[string]interface{}{
				"vehicle_no": vehicle.VehicleNo,
			})
	}

	payload, _ := json.Marshal(vehicle)
	outboxEvent := &outbox.Event{
		EventID:       uuid.New().String(),
		AggregateType: "transport_vehicle",
		AggregateID:   vehicle.VehicleID.String(),
		EventType:     string(EventTransportVehicleCreated),
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

	logger.Info("transport vehicle created", zap.String("id", vehicle.VehicleID.String()))
	return vehicle, nil
}

func (s *transportService) GetVehicleByID(ctx context.Context, id uuid.UUID) (*models.TransportVehicle, error) {
	logger := s.logger.With(zap.String("method", "GetVehicleByID"), zap.String("id", id.String()))
	vehicle, err := s.repo.GetVehicleByID(ctx, s.pgClient.DB, id)
	if err != nil {
		return nil, err
	}
	if vehicle == nil {
		return nil, fmt.Errorf("%w: vehicle %s", ErrNotFound, id)
	}
	logger.Debug("vehicle retrieved")
	return vehicle, nil
}

func (s *transportService) GetVehicleByNumber(ctx context.Context, companyID uuid.UUID, number string) (*models.TransportVehicle, error) {
	logger := s.logger.With(zap.String("method", "GetVehicleByNumber"), zap.String("company_id", companyID.String()), zap.String("number", number))
	vehicle, err := s.repo.GetVehicleByNumber(ctx, s.pgClient.DB, companyID, number)
	if err != nil {
		return nil, err
	}
	if vehicle == nil {
		return nil, fmt.Errorf("%w: vehicle with number %s", ErrNotFound, number)
	}
	logger.Debug("vehicle retrieved by number")
	return vehicle, nil
}

func (s *transportService) ListVehicles(ctx context.Context, filter repository.TransportVehicleFilter, p repository.Pagination, srt repository.Sort) ([]*models.TransportVehicle, error) {
	logger := s.logger.With(zap.String("method", "ListVehicles"))
	logger.Debug("listing vehicles")
	return s.repo.ListVehicles(ctx, s.pgClient.DB, filter, p, srt)
}

func (s *transportService) CountVehicles(ctx context.Context, filter repository.TransportVehicleFilter) (int64, error) {
	logger := s.logger.With(zap.String("method", "CountVehicles"))
	logger.Debug("counting vehicles")
	return s.repo.CountVehicles(ctx, s.pgClient.DB, filter)
}

func (s *transportService) UpdateVehicle(ctx context.Context, req UpdateTransportVehicleRequest) (*models.TransportVehicle, error) {
	logger := s.logger.With(
		zap.String("method", "UpdateVehicle"),
		zap.String("vehicle_id", req.VehicleID.String()),
	)
	idempotencyKey, _ := ctx.Value("idempotency_key").(string)

	if err := s.validateUpdateVehicle(req); err != nil {
		return nil, err
	}

	tx, err := s.pgClient.BeginTx(ctx, nil)
	if err != nil {
		return nil, fmt.Errorf("begin tx: %w", err)
	}
	defer tx.Rollback()

	if idempotencyKey != "" {
		var existing models.TransportVehicle
		if err := s.idempotencyStore.Get(ctx, tx, idempotencyKey, &existing); err == nil && existing.VehicleID != uuid.Nil {
			logger.Info("idempotent request, returning cached response")
			return &existing, nil
		}
	}

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

	if idempotencyKey != "" {
		if err := s.idempotencyStore.Store(ctx, tx, idempotencyKey, vehicle); err != nil {
			logger.Error("failed to store idempotency key", zap.Error(err))
		}
	}

	if s.auditService != nil {
		_ = s.auditService.LogAction(ctx, nil, &vehicle.CompanyID, "transport", "update", "vehicle",
			&req.VehicleID, "user", req.UpdatedBy, nil, nil, map[string]interface{}{
				"old": oldVehicle,
				"new": vehicle,
			})
	}

	payload, _ := json.Marshal(map[string]interface{}{"old": oldVehicle, "new": vehicle})
	outboxEvent := &outbox.Event{
		EventID:       uuid.New().String(),
		AggregateType: "transport_vehicle",
		AggregateID:   vehicle.VehicleID.String(),
		EventType:     string(EventTransportVehicleUpdated),
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

	vehicle, err := s.repo.GetVehicleByID(ctx, tx, id)
	if err != nil {
		return err
	}
	if vehicle == nil {
		return fmt.Errorf("%w: vehicle %s", ErrNotFound, id)
	}

	if err := s.repo.DeleteVehicle(ctx, tx, id, deletedBy); err != nil {
		return err
	}

	if s.auditService != nil {
		_ = s.auditService.LogAction(ctx, nil, &vehicle.CompanyID, "transport", "delete", "vehicle",
			&id, "user", deletedBy, nil, nil, nil)
	}

	payload, _ := json.Marshal(map[string]interface{}{
		"vehicle_id": id,
		"deleted_by": deletedBy,
	})
	outboxEvent := &outbox.Event{
		EventID:       uuid.New().String(),
		AggregateType: "transport_vehicle",
		AggregateID:   id.String(),
		EventType:     string(EventTransportVehicleDeleted),
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

	logger.Info("transport vehicle deleted")
	return nil
}

// ---------------------------------------------------------------------
// Driver Assignment Methods
// ---------------------------------------------------------------------

func (s *transportService) CreateDriverAssignment(ctx context.Context, req CreateDriverAssignmentRequest) (*models.TransportDriverAssignment, error) {
	logger := s.logger.With(
		zap.String("method", "CreateDriverAssignment"),
		zap.String("vehicle_id", req.VehicleID.String()),
		zap.String("driver_name", req.DriverName),
	)
	idempotencyKey, _ := ctx.Value("idempotency_key").(string)

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
		var existing models.TransportDriverAssignment
		if err := s.idempotencyStore.Get(ctx, tx, idempotencyKey, &existing); err == nil && existing.AssignmentID != uuid.Nil {
			logger.Info("idempotent request, returning cached response")
			return &existing, nil
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
		}
	}

	if s.auditService != nil {
		_ = s.auditService.LogAction(ctx, nil, nil, "transport", "create", "driver_assignment",
			&da.AssignmentID, "user", req.CreatedBy, nil, nil, map[string]interface{}{
				"vehicle_id":  req.VehicleID,
				"driver_name": da.DriverName,
			})
	}

	payload, _ := json.Marshal(da)
	outboxEvent := &outbox.Event{
		EventID:       uuid.New().String(),
		AggregateType: "transport_driver_assignment",
		AggregateID:   da.AssignmentID.String(),
		EventType:     string(EventTransportDriverAssignmentCreated),
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

	logger.Info("driver assignment created", zap.String("id", da.AssignmentID.String()))
	return da, nil
}

func (s *transportService) GetDriverAssignmentByID(ctx context.Context, id uuid.UUID) (*models.TransportDriverAssignment, error) {
	logger := s.logger.With(zap.String("method", "GetDriverAssignmentByID"), zap.String("id", id.String()))
	da, err := s.repo.GetDriverAssignmentByID(ctx, s.pgClient.DB, id)
	if err != nil {
		return nil, err
	}
	if da == nil {
		return nil, fmt.Errorf("%w: driver assignment %s", ErrNotFound, id)
	}
	logger.Debug("driver assignment retrieved")
	return da, nil
}

func (s *transportService) ListDriverAssignments(ctx context.Context, filter repository.TransportDriverAssignmentFilter, p repository.Pagination, srt repository.Sort) ([]*models.TransportDriverAssignment, error) {
	logger := s.logger.With(zap.String("method", "ListDriverAssignments"))
	logger.Debug("listing driver assignments")
	return s.repo.ListDriverAssignments(ctx, s.pgClient.DB, filter, p, srt)
}

func (s *transportService) CountDriverAssignments(ctx context.Context, filter repository.TransportDriverAssignmentFilter) (int64, error) {
	logger := s.logger.With(zap.String("method", "CountDriverAssignments"))
	logger.Debug("counting driver assignments")
	return s.repo.CountDriverAssignments(ctx, s.pgClient.DB, filter)
}

func (s *transportService) UpdateDriverAssignment(ctx context.Context, req UpdateDriverAssignmentRequest) (*models.TransportDriverAssignment, error) {
	logger := s.logger.With(
		zap.String("method", "UpdateDriverAssignment"),
		zap.String("assignment_id", req.AssignmentID.String()),
	)
	idempotencyKey, _ := ctx.Value("idempotency_key").(string)

	if err := s.validateUpdateDriverAssignment(req); err != nil {
		return nil, err
	}

	tx, err := s.pgClient.BeginTx(ctx, nil)
	if err != nil {
		return nil, fmt.Errorf("begin tx: %w", err)
	}
	defer tx.Rollback()

	if idempotencyKey != "" {
		var existing models.TransportDriverAssignment
		if err := s.idempotencyStore.Get(ctx, tx, idempotencyKey, &existing); err == nil && existing.AssignmentID != uuid.Nil {
			logger.Info("idempotent request, returning cached response")
			return &existing, nil
		}
	}

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

	if idempotencyKey != "" {
		if err := s.idempotencyStore.Store(ctx, tx, idempotencyKey, da); err != nil {
			logger.Error("failed to store idempotency key", zap.Error(err))
		}
	}

	if s.auditService != nil {
		_ = s.auditService.LogAction(ctx, nil, nil, "transport", "update", "driver_assignment",
			&req.AssignmentID, "user", req.UpdatedBy, nil, nil, map[string]interface{}{
				"old": oldDa,
				"new": da,
			})
	}

	payload, _ := json.Marshal(map[string]interface{}{"old": oldDa, "new": da})
	outboxEvent := &outbox.Event{
		EventID:       uuid.New().String(),
		AggregateType: "transport_driver_assignment",
		AggregateID:   da.AssignmentID.String(),
		EventType:     string(EventTransportDriverAssignmentUpdated),
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

	da, err := s.repo.GetDriverAssignmentByID(ctx, tx, id)
	if err != nil {
		return err
	}
	if da == nil {
		return fmt.Errorf("%w: driver assignment %s", ErrNotFound, id)
	}

	if err := s.repo.DeleteDriverAssignment(ctx, tx, id); err != nil {
		return err
	}

	if s.auditService != nil {
		_ = s.auditService.LogAction(ctx, nil, nil, "transport", "delete", "driver_assignment",
			&id, "user", nil, nil, nil, nil)
	}

	payload, _ := json.Marshal(map[string]interface{}{
		"assignment_id": id,
	})
	outboxEvent := &outbox.Event{
		EventID:       uuid.New().String(),
		AggregateType: "transport_driver_assignment",
		AggregateID:   id.String(),
		EventType:     string(EventTransportDriverAssignmentDeleted),
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

	logger.Info("driver assignment deleted")
	return nil
}

// ---------------------------------------------------------------------
// Student Assignment Methods
// ---------------------------------------------------------------------

func (s *transportService) CreateStudentAssignment(ctx context.Context, req CreateStudentAssignmentRequest) (*models.StudentTransportAssignment, error) {
	logger := s.logger.With(
		zap.String("method", "CreateStudentAssignment"),
		zap.String("student_id", req.StudentID.String()),
		zap.String("route_id", req.RouteID.String()),
	)
	idempotencyKey, _ := ctx.Value("idempotency_key").(string)

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
		var existing models.StudentTransportAssignment
		if err := s.idempotencyStore.Get(ctx, tx, idempotencyKey, &existing); err == nil && existing.AssignmentID != uuid.Nil {
			logger.Info("idempotent request, returning cached response")
			return &existing, nil
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
		}
	}

	if s.auditService != nil {
		_ = s.auditService.LogAction(ctx, nil, nil, "transport", "create", "student_assignment",
			&sa.AssignmentID, "user", req.CreatedBy, nil, nil, map[string]interface{}{
				"student_id": req.StudentID,
				"route_id":   req.RouteID,
			})
	}

	payload, _ := json.Marshal(sa)
	outboxEvent := &outbox.Event{
		EventID:       uuid.New().String(),
		AggregateType: "transport_student_assignment",
		AggregateID:   sa.AssignmentID.String(),
		EventType:     string(EventTransportStudentAssignmentCreated),
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

	logger.Info("student transport assignment created", zap.String("id", sa.AssignmentID.String()))

	// Send notification to student (async)
	go s.sendNotification(ctx, req.StudentID, uuid.Nil, "Transport Assignment Created",
		fmt.Sprintf("You have been assigned to transport route. Pickup: %s", req.PickupPoint),
		models.NotificationTypeInfo, models.PriorityNormal, req.CreatedBy)

	return sa, nil
}

func (s *transportService) GetStudentAssignmentByID(ctx context.Context, id uuid.UUID) (*models.StudentTransportAssignment, error) {
	logger := s.logger.With(zap.String("method", "GetStudentAssignmentByID"), zap.String("id", id.String()))
	sa, err := s.repo.GetStudentAssignmentByID(ctx, s.pgClient.DB, id)
	if err != nil {
		return nil, err
	}
	if sa == nil {
		return nil, fmt.Errorf("%w: student assignment %s", ErrNotFound, id)
	}
	logger.Debug("student assignment retrieved")
	return sa, nil
}

func (s *transportService) ListStudentAssignments(ctx context.Context, filter repository.StudentTransportAssignmentFilter, p repository.Pagination, srt repository.Sort) ([]*models.StudentTransportAssignment, error) {
	logger := s.logger.With(zap.String("method", "ListStudentAssignments"))
	logger.Debug("listing student assignments")
	return s.repo.ListStudentAssignments(ctx, s.pgClient.DB, filter, p, srt)
}

func (s *transportService) CountStudentAssignments(ctx context.Context, filter repository.StudentTransportAssignmentFilter) (int64, error) {
	logger := s.logger.With(zap.String("method", "CountStudentAssignments"))
	logger.Debug("counting student assignments")
	return s.repo.CountStudentAssignments(ctx, s.pgClient.DB, filter)
}

func (s *transportService) UpdateStudentAssignment(ctx context.Context, req UpdateStudentAssignmentRequest) (*models.StudentTransportAssignment, error) {
	logger := s.logger.With(
		zap.String("method", "UpdateStudentAssignment"),
		zap.String("assignment_id", req.AssignmentID.String()),
	)
	idempotencyKey, _ := ctx.Value("idempotency_key").(string)

	if err := s.validateUpdateStudentAssignment(req); err != nil {
		return nil, err
	}

	tx, err := s.pgClient.BeginTx(ctx, nil)
	if err != nil {
		return nil, fmt.Errorf("begin tx: %w", err)
	}
	defer tx.Rollback()

	if idempotencyKey != "" {
		var existing models.StudentTransportAssignment
		if err := s.idempotencyStore.Get(ctx, tx, idempotencyKey, &existing); err == nil && existing.AssignmentID != uuid.Nil {
			logger.Info("idempotent request, returning cached response")
			return &existing, nil
		}
	}

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

	if idempotencyKey != "" {
		if err := s.idempotencyStore.Store(ctx, tx, idempotencyKey, sa); err != nil {
			logger.Error("failed to store idempotency key", zap.Error(err))
		}
	}

	if s.auditService != nil {
		_ = s.auditService.LogAction(ctx, nil, nil, "transport", "update", "student_assignment",
			&req.AssignmentID, "user", req.UpdatedBy, nil, nil, map[string]interface{}{
				"old": oldSa,
				"new": sa,
			})
	}

	payload, _ := json.Marshal(map[string]interface{}{"old": oldSa, "new": sa})
	outboxEvent := &outbox.Event{
		EventID:       uuid.New().String(),
		AggregateType: "transport_student_assignment",
		AggregateID:   sa.AssignmentID.String(),
		EventType:     string(EventTransportStudentAssignmentUpdated),
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

	logger.Info("student transport assignment updated")

	// Send notification about update (async)
	go s.sendNotification(ctx, sa.StudentID, uuid.Nil, "Transport Assignment Updated",
		"Your transport assignment has been updated.",
		models.NotificationTypeInfo, models.PriorityNormal, req.UpdatedBy)

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

	sa, err := s.repo.GetStudentAssignmentByID(ctx, tx, id)
	if err != nil {
		return err
	}
	if sa == nil {
		return fmt.Errorf("%w: student assignment %s", ErrNotFound, id)
	}

	if err := s.repo.DeleteStudentAssignment(ctx, tx, id); err != nil {
		return err
	}

	if s.auditService != nil {
		_ = s.auditService.LogAction(ctx, nil, nil, "transport", "delete", "student_assignment",
			&id, "user", nil, nil, nil, nil)
	}

	payload, _ := json.Marshal(map[string]interface{}{
		"assignment_id": id,
	})
	outboxEvent := &outbox.Event{
		EventID:       uuid.New().String(),
		AggregateType: "transport_student_assignment",
		AggregateID:   id.String(),
		EventType:     string(EventTransportStudentAssignmentDeleted),
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

	logger.Info("student transport assignment deleted")
	return nil
}

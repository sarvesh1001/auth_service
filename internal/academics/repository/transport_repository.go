package repository

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"strings"

	"github.com/google/uuid"
	"go.uber.org/zap"

	"auth-service/internal/academics/models"
	"auth-service/internal/util"
)

// TransportRepository defines all transport-related persistence methods.
type TransportRepository interface {
	// Routes
	CreateRoute(ctx context.Context, db DBTX, r *models.TransportRoute) error
	GetRouteByID(ctx context.Context, db DBTX, id uuid.UUID) (*models.TransportRoute, error)
	ListRoutes(ctx context.Context, db DBTX, filter TransportRouteFilter, p Pagination, s Sort) ([]*models.TransportRoute, error)
	CountRoutes(ctx context.Context, db DBTX, filter TransportRouteFilter) (int64, error)
	UpdateRoute(ctx context.Context, db DBTX, r *models.TransportRoute) error
	DeleteRoute(ctx context.Context, db DBTX, id uuid.UUID, deletedBy *uuid.UUID) error

	// Stops (no updated_by column)
	CreateStop(ctx context.Context, db DBTX, s *models.TransportStop) error
	GetStopByID(ctx context.Context, db DBTX, id uuid.UUID) (*models.TransportStop, error)
	ListStops(ctx context.Context, db DBTX, filter TransportStopFilter, p Pagination, s Sort) ([]*models.TransportStop, error)
	CountStops(ctx context.Context, db DBTX, filter TransportStopFilter) (int64, error)
	UpdateStop(ctx context.Context, db DBTX, s *models.TransportStop) error
	DeleteStop(ctx context.Context, db DBTX, id uuid.UUID) error

	// Vehicles (have updated_by)
	CreateVehicle(ctx context.Context, db DBTX, v *models.TransportVehicle) error
	GetVehicleByID(ctx context.Context, db DBTX, id uuid.UUID) (*models.TransportVehicle, error)
	GetVehicleByNumber(ctx context.Context, db DBTX, companyID uuid.UUID, number string) (*models.TransportVehicle, error)
	ListVehicles(ctx context.Context, db DBTX, filter TransportVehicleFilter, p Pagination, s Sort) ([]*models.TransportVehicle, error)
	CountVehicles(ctx context.Context, db DBTX, filter TransportVehicleFilter) (int64, error)
	UpdateVehicle(ctx context.Context, db DBTX, v *models.TransportVehicle) error
	DeleteVehicle(ctx context.Context, db DBTX, id uuid.UUID, deletedBy *uuid.UUID) error

	// Driver assignments (no updated_by)
	CreateDriverAssignment(ctx context.Context, db DBTX, da *models.TransportDriverAssignment) error
	GetDriverAssignmentByID(ctx context.Context, db DBTX, id uuid.UUID) (*models.TransportDriverAssignment, error)
	ListDriverAssignments(ctx context.Context, db DBTX, filter TransportDriverAssignmentFilter, p Pagination, s Sort) ([]*models.TransportDriverAssignment, error)
	CountDriverAssignments(ctx context.Context, db DBTX, filter TransportDriverAssignmentFilter) (int64, error)
	UpdateDriverAssignment(ctx context.Context, db DBTX, da *models.TransportDriverAssignment) error
	DeleteDriverAssignment(ctx context.Context, db DBTX, id uuid.UUID) error

	// Student transport assignments (no updated_by)
	CreateStudentAssignment(ctx context.Context, db DBTX, sa *models.StudentTransportAssignment) error
	GetStudentAssignmentByID(ctx context.Context, db DBTX, id uuid.UUID) (*models.StudentTransportAssignment, error)
	ListStudentAssignments(ctx context.Context, db DBTX, filter StudentTransportAssignmentFilter, p Pagination, s Sort) ([]*models.StudentTransportAssignment, error)
	CountStudentAssignments(ctx context.Context, db DBTX, filter StudentTransportAssignmentFilter) (int64, error)
	UpdateStudentAssignment(ctx context.Context, db DBTX, sa *models.StudentTransportAssignment) error
	DeleteStudentAssignment(ctx context.Context, db DBTX, id uuid.UUID) error
}

type transportRepository struct {
	logger *zap.Logger
}

// NewTransportRepository creates a new transport repository.
func NewTransportRepository(logger *zap.Logger) TransportRepository {
	return &transportRepository{
		logger: logger.Named("transport_repo"),
	}
}

// ---------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------

func (r *transportRepository) validatePagination(p Pagination) (int, int) {
	limit := p.Limit
	if limit <= 0 {
		limit = 50
	}
	if limit > 1000 {
		limit = 1000
	}
	offset := p.Offset
	if offset < 0 {
		offset = 0
	}
	return limit, offset
}

func (r *transportRepository) validateSort(s Sort, allowed map[string]bool, defaultField string) (string, error) {
	field := s.Field
	if field == "" {
		field = defaultField
	}
	if !allowed[field] {
		return "", fmt.Errorf("invalid sort field: %s", field)
	}
	dir := strings.ToUpper(s.Direction)
	if dir != "ASC" && dir != "DESC" {
		dir = "DESC"
	}
	return fmt.Sprintf("ORDER BY %s %s", field, dir), nil
}

// ---------------------------------------------------------------------
// Routes (have updated_by)
// ---------------------------------------------------------------------

var allowedRouteSortFields = map[string]bool{
	"created_at":  true,
	"updated_at":  true,
	"route_name":  true,
	"distance_km": true,
}

func (r *transportRepository) buildRouteFilter(filter TransportRouteFilter) (string, []interface{}) {
	var conditions []string
	var args []interface{}
	idx := 1

	if filter.CompanyID != uuid.Nil {
		conditions = append(conditions, fmt.Sprintf("company_id = $%d", idx))
		args = append(args, filter.CompanyID)
		idx++
	}
	if filter.IsActive != nil {
		conditions = append(conditions, fmt.Sprintf("is_active = $%d", idx))
		args = append(args, *filter.IsActive)
		idx++
	}
	if filter.Search != "" {
		conditions = append(conditions, fmt.Sprintf("(route_name ILIKE $%d OR start_point ILIKE $%d OR end_point ILIKE $%d)", idx, idx, idx))
		args = append(args, "%"+filter.Search+"%")
		idx++
	}
	conditions = append(conditions, "deleted_at IS NULL")

	if len(conditions) == 0 {
		return "", args
	}
	return "WHERE " + strings.Join(conditions, " AND "), args
}

func (r *transportRepository) CreateRoute(ctx context.Context, db DBTX, route *models.TransportRoute) error {
	query := `
        INSERT INTO academics.transport_routes (
            company_id, route_name, start_point, end_point, distance_km, is_active,
            created_by, updated_by, created_at, updated_at
        ) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, NOW(), NOW())
        RETURNING route_id, created_at, updated_at
    `
	err := db.QueryRowContext(ctx, query,
		route.CompanyID, route.RouteName, route.StartPoint, route.EndPoint, route.DistanceKm, route.IsActive,
		route.CreatedBy, route.UpdatedBy,
	).Scan(&route.RouteID, &route.CreatedAt, &route.UpdatedAt)
	if err != nil {
		r.logger.Error("failed to create transport route", util.ErrorField(err))
		return fmt.Errorf("create route: %w", err)
	}
	return nil
}

func (r *transportRepository) GetRouteByID(ctx context.Context, db DBTX, id uuid.UUID) (*models.TransportRoute, error) {
	query := `
        SELECT route_id, company_id, route_name, start_point, end_point, distance_km, is_active,
               created_at, updated_at, created_by, updated_by
        FROM academics.transport_routes
        WHERE route_id = $1 AND deleted_at IS NULL
    `
	row := db.QueryRowContext(ctx, query, id)
	return r.scanRoute(row)
}

func (r *transportRepository) ListRoutes(ctx context.Context, db DBTX, filter TransportRouteFilter, p Pagination, s Sort) ([]*models.TransportRoute, error) {
	where, args := r.buildRouteFilter(filter)
	orderBy, err := r.validateSort(s, allowedRouteSortFields, "created_at")
	if err != nil {
		return nil, err
	}
	limit, offset := r.validatePagination(p)

	query := fmt.Sprintf(`
        SELECT route_id, company_id, route_name, start_point, end_point, distance_km, is_active,
               created_at, updated_at, created_by, updated_by
        FROM academics.transport_routes
        %s
        %s
        LIMIT $%d OFFSET $%d
    `, where, orderBy, len(args)+1, len(args)+2)
	args = append(args, limit, offset)

	rows, err := db.QueryContext(ctx, query, args...)
	if err != nil {
		r.logger.Error("failed to list transport routes", util.ErrorField(err))
		return nil, fmt.Errorf("list routes: %w", err)
	}
	defer rows.Close()

	var routes []*models.TransportRoute
	for rows.Next() {
		rt, err := r.scanRoute(rows)
		if err != nil {
			return nil, err
		}
		routes = append(routes, rt)
	}
	if err = rows.Err(); err != nil {
		return nil, fmt.Errorf("rows iteration: %w", err)
	}
	return routes, nil
}

func (r *transportRepository) CountRoutes(ctx context.Context, db DBTX, filter TransportRouteFilter) (int64, error) {
	where, args := r.buildRouteFilter(filter)
	query := fmt.Sprintf("SELECT COUNT(*) FROM academics.transport_routes %s", where)
	var count int64
	err := db.QueryRowContext(ctx, query, args...).Scan(&count)
	if err != nil {
		r.logger.Error("failed to count transport routes", util.ErrorField(err))
		return 0, fmt.Errorf("count routes: %w", err)
	}
	return count, nil
}

func (r *transportRepository) UpdateRoute(ctx context.Context, db DBTX, route *models.TransportRoute) error {
	query := `
        UPDATE academics.transport_routes
        SET route_name = $2, start_point = $3, end_point = $4, distance_km = $5, is_active = $6,
            updated_by = $7, updated_at = NOW()
        WHERE route_id = $1 AND deleted_at IS NULL
        RETURNING updated_at
    `
	err := db.QueryRowContext(ctx, query,
		route.RouteID, route.RouteName, route.StartPoint, route.EndPoint, route.DistanceKm, route.IsActive,
		route.UpdatedBy,
	).Scan(&route.UpdatedAt)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return fmt.Errorf("%w: route %s", ErrNotFound, route.RouteID)
		}
		r.logger.Error("failed to update transport route", util.ErrorField(err))
		return fmt.Errorf("update route: %w", err)
	}
	return nil
}

func (r *transportRepository) DeleteRoute(ctx context.Context, db DBTX, id uuid.UUID, deletedBy *uuid.UUID) error {
	query := `UPDATE academics.transport_routes SET deleted_at = NOW(), updated_by = $2, updated_at = NOW() WHERE route_id = $1 AND deleted_at IS NULL`
	result, err := db.ExecContext(ctx, query, id, deletedBy)
	if err != nil {
		r.logger.Error("failed to delete transport route", util.ErrorField(err))
		return fmt.Errorf("delete route: %w", err)
	}
	rows, err := result.RowsAffected()
	if err != nil {
		return fmt.Errorf("rows affected: %w", err)
	}
	if rows == 0 {
		return fmt.Errorf("route %s not found or already deleted", id)
	}
	return nil
}

func (r *transportRepository) scanRoute(row scanner) (*models.TransportRoute, error) {
	var route models.TransportRoute
	var createdBy, updatedBy uuid.NullUUID
	var distanceKm sql.NullFloat64

	err := row.Scan(
		&route.RouteID, &route.CompanyID, &route.RouteName, &route.StartPoint, &route.EndPoint,
		&distanceKm, &route.IsActive,
		&route.CreatedAt, &route.UpdatedAt,
		&createdBy, &updatedBy,
	)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, nil
		}
		return nil, fmt.Errorf("scan route: %w", err)
	}
	if distanceKm.Valid {
		route.DistanceKm = &distanceKm.Float64
	}
	if createdBy.Valid {
		route.CreatedBy = &createdBy.UUID
	}
	if updatedBy.Valid {
		route.UpdatedBy = &updatedBy.UUID
	}
	return &route, nil
}

// ---------------------------------------------------------------------
// Stops (no updated_by column)
// ---------------------------------------------------------------------

var allowedStopSortFields = map[string]bool{
	"created_at": true,
	"updated_at": true,
	"stop_name":  true,
	"stop_order": true,
}

func (r *transportRepository) buildStopFilter(filter TransportStopFilter) (string, []interface{}) {
	var conditions []string
	var args []interface{}
	idx := 1

	if filter.RouteID != uuid.Nil {
		conditions = append(conditions, fmt.Sprintf("route_id = $%d", idx))
		args = append(args, filter.RouteID)
		idx++
	}
	if filter.Search != "" {
		conditions = append(conditions, fmt.Sprintf("stop_name ILIKE $%d", idx))
		args = append(args, "%"+filter.Search+"%")
		idx++
	}
	if len(conditions) == 0 {
		return "", args
	}
	return "WHERE " + strings.Join(conditions, " AND "), args
}

func (r *transportRepository) CreateStop(ctx context.Context, db DBTX, stop *models.TransportStop) error {
	// Note: table has NO updated_by column
	query := `
        INSERT INTO academics.transport_stops (
            route_id, stop_name, stop_order, latitude, longitude, pickup_time, drop_time,
            created_by, created_at, updated_at
        ) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, NOW(), NOW())
        RETURNING stop_id, created_at, updated_at
    `
	err := db.QueryRowContext(ctx, query,
		stop.RouteID, stop.StopName, stop.StopOrder, stop.Latitude, stop.Longitude,
		stop.PickupTime, stop.DropTime,
		stop.CreatedBy,
	).Scan(&stop.StopID, &stop.CreatedAt, &stop.UpdatedAt)
	if err != nil {
		r.logger.Error("failed to create transport stop", util.ErrorField(err))
		return fmt.Errorf("create stop: %w", err)
	}
	return nil
}

func (r *transportRepository) GetStopByID(ctx context.Context, db DBTX, id uuid.UUID) (*models.TransportStop, error) {
	query := `
        SELECT stop_id, route_id, stop_name, stop_order, latitude, longitude, pickup_time, drop_time,
               created_at, updated_at, created_by
        FROM academics.transport_stops
        WHERE stop_id = $1
    `
	row := db.QueryRowContext(ctx, query, id)
	return r.scanStop(row)
}

func (r *transportRepository) ListStops(ctx context.Context, db DBTX, filter TransportStopFilter, p Pagination, s Sort) ([]*models.TransportStop, error) {
	where, args := r.buildStopFilter(filter)
	orderBy, err := r.validateSort(s, allowedStopSortFields, "stop_order")
	if err != nil {
		return nil, err
	}
	limit, offset := r.validatePagination(p)

	query := fmt.Sprintf(`
        SELECT stop_id, route_id, stop_name, stop_order, latitude, longitude, pickup_time, drop_time,
               created_at, updated_at, created_by
        FROM academics.transport_stops
        %s
        %s
        LIMIT $%d OFFSET $%d
    `, where, orderBy, len(args)+1, len(args)+2)
	args = append(args, limit, offset)

	rows, err := db.QueryContext(ctx, query, args...)
	if err != nil {
		r.logger.Error("failed to list transport stops", util.ErrorField(err))
		return nil, fmt.Errorf("list stops: %w", err)
	}
	defer rows.Close()

	var stops []*models.TransportStop
	for rows.Next() {
		s, err := r.scanStop(rows)
		if err != nil {
			return nil, err
		}
		stops = append(stops, s)
	}
	if err = rows.Err(); err != nil {
		return nil, fmt.Errorf("rows iteration: %w", err)
	}
	return stops, nil
}

func (r *transportRepository) CountStops(ctx context.Context, db DBTX, filter TransportStopFilter) (int64, error) {
	where, args := r.buildStopFilter(filter)
	query := fmt.Sprintf("SELECT COUNT(*) FROM academics.transport_stops %s", where)
	var count int64
	err := db.QueryRowContext(ctx, query, args...).Scan(&count)
	if err != nil {
		r.logger.Error("failed to count transport stops", util.ErrorField(err))
		return 0, fmt.Errorf("count stops: %w", err)
	}
	return count, nil
}

func (r *transportRepository) UpdateStop(ctx context.Context, db DBTX, stop *models.TransportStop) error {
	// Table has no updated_by column; we only update the stop's data and updated_at.
	query := `
        UPDATE academics.transport_stops
        SET stop_name = $2, stop_order = $3, latitude = $4, longitude = $5,
            pickup_time = $6, drop_time = $7, updated_at = NOW()
        WHERE stop_id = $1
        RETURNING updated_at
    `
	err := db.QueryRowContext(ctx, query,
		stop.StopID, stop.StopName, stop.StopOrder, stop.Latitude, stop.Longitude,
		stop.PickupTime, stop.DropTime,
	).Scan(&stop.UpdatedAt)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return fmt.Errorf("%w: stop %s", ErrNotFound, stop.StopID)
		}
		r.logger.Error("failed to update transport stop", util.ErrorField(err))
		return fmt.Errorf("update stop: %w", err)
	}
	return nil
}

func (r *transportRepository) DeleteStop(ctx context.Context, db DBTX, id uuid.UUID) error {
	query := `DELETE FROM academics.transport_stops WHERE stop_id = $1`
	result, err := db.ExecContext(ctx, query, id)
	if err != nil {
		r.logger.Error("failed to delete transport stop", util.ErrorField(err))
		return fmt.Errorf("delete stop: %w", err)
	}
	rows, err := result.RowsAffected()
	if err != nil {
		return fmt.Errorf("rows affected: %w", err)
	}
	if rows == 0 {
		return fmt.Errorf("stop %s not found", id)
	}
	return nil
}

func (r *transportRepository) scanStop(row scanner) (*models.TransportStop, error) {
	var stop models.TransportStop
	var createdBy uuid.NullUUID
	var latitude, longitude sql.NullFloat64
	var pickupTime, dropTime sql.NullTime

	err := row.Scan(
		&stop.StopID, &stop.RouteID, &stop.StopName, &stop.StopOrder,
		&latitude, &longitude, &pickupTime, &dropTime,
		&stop.CreatedAt, &stop.UpdatedAt,
		&createdBy,
	)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, nil
		}
		return nil, fmt.Errorf("scan stop: %w", err)
	}
	if latitude.Valid {
		stop.Latitude = &latitude.Float64
	}
	if longitude.Valid {
		stop.Longitude = &longitude.Float64
	}
	if pickupTime.Valid {
		stop.PickupTime = &pickupTime.Time
	}
	if dropTime.Valid {
		stop.DropTime = &dropTime.Time
	}
	if createdBy.Valid {
		stop.CreatedBy = &createdBy.UUID
	}
	return &stop, nil
}

// ---------------------------------------------------------------------
// Vehicles (have updated_by)
// ---------------------------------------------------------------------

var allowedVehicleSortFields = map[string]bool{
	"created_at":   true,
	"updated_at":   true,
	"vehicle_no":   true,
	"vehicle_type": true,
	"capacity":     true,
}

func (r *transportRepository) buildVehicleFilter(filter TransportVehicleFilter) (string, []interface{}) {
	var conditions []string
	var args []interface{}
	idx := 1

	if filter.CompanyID != uuid.Nil {
		conditions = append(conditions, fmt.Sprintf("company_id = $%d", idx))
		args = append(args, filter.CompanyID)
		idx++
	}
	if filter.IsActive != nil {
		conditions = append(conditions, fmt.Sprintf("is_active = $%d", idx))
		args = append(args, *filter.IsActive)
		idx++
	}
	if filter.Search != "" {
		conditions = append(conditions, fmt.Sprintf("(vehicle_no ILIKE $%d OR vehicle_type ILIKE $%d)", idx, idx))
		args = append(args, "%"+filter.Search+"%")
		idx++
	}
	conditions = append(conditions, "deleted_at IS NULL")

	if len(conditions) == 0 {
		return "", args
	}
	return "WHERE " + strings.Join(conditions, " AND "), args
}

func (r *transportRepository) CreateVehicle(ctx context.Context, db DBTX, v *models.TransportVehicle) error {
	query := `
        INSERT INTO academics.transport_vehicles (
            company_id, vehicle_no, vehicle_type, capacity, insurance_expiry, fitness_expiry,
            is_active, created_by, updated_by, created_at, updated_at
        ) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, NOW(), NOW())
        RETURNING vehicle_id, created_at, updated_at
    `
	err := db.QueryRowContext(ctx, query,
		v.CompanyID, v.VehicleNo, v.VehicleType, v.Capacity,
		v.InsuranceExpiry, v.FitnessExpiry, v.IsActive,
		v.CreatedBy, v.UpdatedBy,
	).Scan(&v.VehicleID, &v.CreatedAt, &v.UpdatedAt)
	if err != nil {
		r.logger.Error("failed to create transport vehicle", util.ErrorField(err))
		return fmt.Errorf("create vehicle: %w", err)
	}
	return nil
}

func (r *transportRepository) GetVehicleByID(ctx context.Context, db DBTX, id uuid.UUID) (*models.TransportVehicle, error) {
	query := `
        SELECT vehicle_id, company_id, vehicle_no, vehicle_type, capacity,
               insurance_expiry, fitness_expiry, is_active,
               created_at, updated_at, created_by, updated_by
        FROM academics.transport_vehicles
        WHERE vehicle_id = $1 AND deleted_at IS NULL
    `
	row := db.QueryRowContext(ctx, query, id)
	return r.scanVehicle(row)
}

func (r *transportRepository) GetVehicleByNumber(ctx context.Context, db DBTX, companyID uuid.UUID, number string) (*models.TransportVehicle, error) {
	query := `
        SELECT vehicle_id, company_id, vehicle_no, vehicle_type, capacity,
               insurance_expiry, fitness_expiry, is_active,
               created_at, updated_at, created_by, updated_by
        FROM academics.transport_vehicles
        WHERE company_id = $1 AND vehicle_no = $2 AND deleted_at IS NULL
    `
	row := db.QueryRowContext(ctx, query, companyID, number)
	return r.scanVehicle(row)
}

func (r *transportRepository) ListVehicles(ctx context.Context, db DBTX, filter TransportVehicleFilter, p Pagination, s Sort) ([]*models.TransportVehicle, error) {
	where, args := r.buildVehicleFilter(filter)
	orderBy, err := r.validateSort(s, allowedVehicleSortFields, "created_at")
	if err != nil {
		return nil, err
	}
	limit, offset := r.validatePagination(p)

	query := fmt.Sprintf(`
        SELECT vehicle_id, company_id, vehicle_no, vehicle_type, capacity,
               insurance_expiry, fitness_expiry, is_active,
               created_at, updated_at, created_by, updated_by
        FROM academics.transport_vehicles
        %s
        %s
        LIMIT $%d OFFSET $%d
    `, where, orderBy, len(args)+1, len(args)+2)
	args = append(args, limit, offset)

	rows, err := db.QueryContext(ctx, query, args...)
	if err != nil {
		r.logger.Error("failed to list transport vehicles", util.ErrorField(err))
		return nil, fmt.Errorf("list vehicles: %w", err)
	}
	defer rows.Close()

	var vehicles []*models.TransportVehicle
	for rows.Next() {
		v, err := r.scanVehicle(rows)
		if err != nil {
			return nil, err
		}
		vehicles = append(vehicles, v)
	}
	if err = rows.Err(); err != nil {
		return nil, fmt.Errorf("rows iteration: %w", err)
	}
	return vehicles, nil
}

func (r *transportRepository) CountVehicles(ctx context.Context, db DBTX, filter TransportVehicleFilter) (int64, error) {
	where, args := r.buildVehicleFilter(filter)
	query := fmt.Sprintf("SELECT COUNT(*) FROM academics.transport_vehicles %s", where)
	var count int64
	err := db.QueryRowContext(ctx, query, args...).Scan(&count)
	if err != nil {
		r.logger.Error("failed to count transport vehicles", util.ErrorField(err))
		return 0, fmt.Errorf("count vehicles: %w", err)
	}
	return count, nil
}

func (r *transportRepository) UpdateVehicle(ctx context.Context, db DBTX, v *models.TransportVehicle) error {
	query := `
        UPDATE academics.transport_vehicles
        SET vehicle_no = $2, vehicle_type = $3, capacity = $4,
            insurance_expiry = $5, fitness_expiry = $6, is_active = $7,
            updated_by = $8, updated_at = NOW()
        WHERE vehicle_id = $1 AND deleted_at IS NULL
        RETURNING updated_at
    `
	err := db.QueryRowContext(ctx, query,
		v.VehicleID, v.VehicleNo, v.VehicleType, v.Capacity,
		v.InsuranceExpiry, v.FitnessExpiry, v.IsActive,
		v.UpdatedBy,
	).Scan(&v.UpdatedAt)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return fmt.Errorf("%w: vehicle %s", ErrNotFound, v.VehicleID)
		}
		r.logger.Error("failed to update transport vehicle", util.ErrorField(err))
		return fmt.Errorf("update vehicle: %w", err)
	}
	return nil
}

func (r *transportRepository) DeleteVehicle(ctx context.Context, db DBTX, id uuid.UUID, deletedBy *uuid.UUID) error {
	query := `UPDATE academics.transport_vehicles SET deleted_at = NOW(), updated_by = $2, updated_at = NOW() WHERE vehicle_id = $1 AND deleted_at IS NULL`
	result, err := db.ExecContext(ctx, query, id, deletedBy)
	if err != nil {
		r.logger.Error("failed to delete transport vehicle", util.ErrorField(err))
		return fmt.Errorf("delete vehicle: %w", err)
	}
	rows, err := result.RowsAffected()
	if err != nil {
		return fmt.Errorf("rows affected: %w", err)
	}
	if rows == 0 {
		return fmt.Errorf("vehicle %s not found or already deleted", id)
	}
	return nil
}

func (r *transportRepository) scanVehicle(row scanner) (*models.TransportVehicle, error) {
	var v models.TransportVehicle
	var createdBy, updatedBy uuid.NullUUID
	var capacity sql.NullInt32
	var insuranceExpiry, fitnessExpiry sql.NullTime

	err := row.Scan(
		&v.VehicleID, &v.CompanyID, &v.VehicleNo, &v.VehicleType,
		&capacity, &insuranceExpiry, &fitnessExpiry, &v.IsActive,
		&v.CreatedAt, &v.UpdatedAt,
		&createdBy, &updatedBy,
	)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, nil
		}
		return nil, fmt.Errorf("scan vehicle: %w", err)
	}
	if capacity.Valid {
		v.Capacity = new(int)
		*v.Capacity = int(capacity.Int32)
	}
	if insuranceExpiry.Valid {
		v.InsuranceExpiry = &insuranceExpiry.Time
	}
	if fitnessExpiry.Valid {
		v.FitnessExpiry = &fitnessExpiry.Time
	}
	if createdBy.Valid {
		v.CreatedBy = &createdBy.UUID
	}
	if updatedBy.Valid {
		v.UpdatedBy = &updatedBy.UUID
	}
	return &v, nil
}

// ---------------------------------------------------------------------
// Driver Assignments (no updated_by column)
// ---------------------------------------------------------------------

var allowedDriverAssignmentSortFields = map[string]bool{
	"created_at":      true,
	"updated_at":      true,
	"driver_name":     true,
	"assignment_date": true,
	"end_date":        true,
}

func (r *transportRepository) buildDriverAssignmentFilter(filter TransportDriverAssignmentFilter) (string, []interface{}) {
	var conditions []string
	var args []interface{}
	idx := 1

	if filter.VehicleID != uuid.Nil {
		conditions = append(conditions, fmt.Sprintf("vehicle_id = $%d", idx))
		args = append(args, filter.VehicleID)
		idx++
	}
	if filter.IsActive != nil {
		conditions = append(conditions, fmt.Sprintf("is_active = $%d", idx))
		args = append(args, *filter.IsActive)
		idx++
	}
	if filter.Date != nil {
		conditions = append(conditions, fmt.Sprintf("assignment_date <= $%d AND (end_date IS NULL OR end_date >= $%d)", idx, idx))
		args = append(args, *filter.Date)
		idx++
	}
	if len(conditions) == 0 {
		return "", args
	}
	return "WHERE " + strings.Join(conditions, " AND "), args
}

func (r *transportRepository) CreateDriverAssignment(ctx context.Context, db DBTX, da *models.TransportDriverAssignment) error {
	// Table has NO updated_by column
	query := `
        INSERT INTO academics.transport_driver_assignments (
            vehicle_id, driver_name, driver_phone, driver_license, assignment_date, end_date, is_active,
            created_by, created_at, updated_at
        ) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, NOW(), NOW())
        RETURNING assignment_id, created_at, updated_at
    `
	err := db.QueryRowContext(ctx, query,
		da.VehicleID, da.DriverName, da.DriverPhone, da.DriverLicense,
		da.AssignmentDate, da.EndDate, da.IsActive,
		da.CreatedBy,
	).Scan(&da.AssignmentID, &da.CreatedAt, &da.UpdatedAt)
	if err != nil {
		r.logger.Error("failed to create driver assignment", util.ErrorField(err))
		return fmt.Errorf("create driver assignment: %w", err)
	}
	return nil
}

func (r *transportRepository) GetDriverAssignmentByID(ctx context.Context, db DBTX, id uuid.UUID) (*models.TransportDriverAssignment, error) {
	query := `
        SELECT assignment_id, vehicle_id, driver_name, driver_phone, driver_license,
               assignment_date, end_date, is_active,
               created_at, updated_at, created_by
        FROM academics.transport_driver_assignments
        WHERE assignment_id = $1
    `
	row := db.QueryRowContext(ctx, query, id)
	return r.scanDriverAssignment(row)
}

func (r *transportRepository) ListDriverAssignments(ctx context.Context, db DBTX, filter TransportDriverAssignmentFilter, p Pagination, s Sort) ([]*models.TransportDriverAssignment, error) {
	where, args := r.buildDriverAssignmentFilter(filter)
	orderBy, err := r.validateSort(s, allowedDriverAssignmentSortFields, "assignment_date")
	if err != nil {
		return nil, err
	}
	limit, offset := r.validatePagination(p)

	query := fmt.Sprintf(`
        SELECT assignment_id, vehicle_id, driver_name, driver_phone, driver_license,
               assignment_date, end_date, is_active,
               created_at, updated_at, created_by
        FROM academics.transport_driver_assignments
        %s
        %s
        LIMIT $%d OFFSET $%d
    `, where, orderBy, len(args)+1, len(args)+2)
	args = append(args, limit, offset)

	rows, err := db.QueryContext(ctx, query, args...)
	if err != nil {
		r.logger.Error("failed to list driver assignments", util.ErrorField(err))
		return nil, fmt.Errorf("list driver assignments: %w", err)
	}
	defer rows.Close()

	var assignments []*models.TransportDriverAssignment
	for rows.Next() {
		da, err := r.scanDriverAssignment(rows)
		if err != nil {
			return nil, err
		}
		assignments = append(assignments, da)
	}
	if err = rows.Err(); err != nil {
		return nil, fmt.Errorf("rows iteration: %w", err)
	}
	return assignments, nil
}

func (r *transportRepository) CountDriverAssignments(ctx context.Context, db DBTX, filter TransportDriverAssignmentFilter) (int64, error) {
	where, args := r.buildDriverAssignmentFilter(filter)
	query := fmt.Sprintf("SELECT COUNT(*) FROM academics.transport_driver_assignments %s", where)
	var count int64
	err := db.QueryRowContext(ctx, query, args...).Scan(&count)
	if err != nil {
		r.logger.Error("failed to count driver assignments", util.ErrorField(err))
		return 0, fmt.Errorf("count driver assignments: %w", err)
	}
	return count, nil
}

func (r *transportRepository) UpdateDriverAssignment(ctx context.Context, db DBTX, da *models.TransportDriverAssignment) error {
	// Table has NO updated_by column; we only update the assignment data and updated_at.
	query := `
        UPDATE academics.transport_driver_assignments
        SET driver_name = $2, driver_phone = $3, driver_license = $4,
            assignment_date = $5, end_date = $6, is_active = $7,
            updated_at = NOW()
        WHERE assignment_id = $1
        RETURNING updated_at
    `
	err := db.QueryRowContext(ctx, query,
		da.AssignmentID, da.DriverName, da.DriverPhone, da.DriverLicense,
		da.AssignmentDate, da.EndDate, da.IsActive,
	).Scan(&da.UpdatedAt)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return fmt.Errorf("%w: driver assignment %s", ErrNotFound, da.AssignmentID)
		}
		r.logger.Error("failed to update driver assignment", util.ErrorField(err))
		return fmt.Errorf("update driver assignment: %w", err)
	}
	return nil
}

func (r *transportRepository) DeleteDriverAssignment(ctx context.Context, db DBTX, id uuid.UUID) error {
	query := `DELETE FROM academics.transport_driver_assignments WHERE assignment_id = $1`
	result, err := db.ExecContext(ctx, query, id)
	if err != nil {
		r.logger.Error("failed to delete driver assignment", util.ErrorField(err))
		return fmt.Errorf("delete driver assignment: %w", err)
	}
	rows, err := result.RowsAffected()
	if err != nil {
		return fmt.Errorf("rows affected: %w", err)
	}
	if rows == 0 {
		return fmt.Errorf("driver assignment %s not found", id)
	}
	return nil
}

func (r *transportRepository) scanDriverAssignment(row scanner) (*models.TransportDriverAssignment, error) {
	var da models.TransportDriverAssignment
	var createdBy uuid.NullUUID
	var endDate sql.NullTime

	err := row.Scan(
		&da.AssignmentID, &da.VehicleID, &da.DriverName, &da.DriverPhone, &da.DriverLicense,
		&da.AssignmentDate, &endDate, &da.IsActive,
		&da.CreatedAt, &da.UpdatedAt,
		&createdBy,
	)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, nil
		}
		return nil, fmt.Errorf("scan driver assignment: %w", err)
	}
	if endDate.Valid {
		da.EndDate = &endDate.Time
	}
	if createdBy.Valid {
		da.CreatedBy = &createdBy.UUID
	}
	return &da, nil
}

// ---------------------------------------------------------------------
// Student Transport Assignments (no updated_by column)
// ---------------------------------------------------------------------

var allowedStudentAssignmentSortFields = map[string]bool{
	"created_at":     true,
	"updated_at":     true,
	"effective_from": true,
	"effective_to":   true,
}

func (r *transportRepository) buildStudentAssignmentFilter(filter StudentTransportAssignmentFilter) (string, []interface{}) {
	var conditions []string
	var args []interface{}
	idx := 1

	if filter.StudentID != uuid.Nil {
		conditions = append(conditions, fmt.Sprintf("student_id = $%d", idx))
		args = append(args, filter.StudentID)
		idx++
	}
	if filter.RouteID != uuid.Nil {
		conditions = append(conditions, fmt.Sprintf("route_id = $%d", idx))
		args = append(args, filter.RouteID)
		idx++
	}
	if filter.StopID != uuid.Nil {
		conditions = append(conditions, fmt.Sprintf("stop_id = $%d", idx))
		args = append(args, filter.StopID)
		idx++
	}
	if filter.IsActive != nil {
		conditions = append(conditions, fmt.Sprintf("is_active = $%d", idx))
		args = append(args, *filter.IsActive)
		idx++
	}
	if filter.EffectiveDate != nil {
		conditions = append(conditions, fmt.Sprintf("effective_from <= $%d AND (effective_to IS NULL OR effective_to >= $%d)", idx, idx))
		args = append(args, *filter.EffectiveDate)
		idx++
	}
	if len(conditions) == 0 {
		return "", args
	}
	return "WHERE " + strings.Join(conditions, " AND "), args
}

func (r *transportRepository) CreateStudentAssignment(ctx context.Context, db DBTX, sa *models.StudentTransportAssignment) error {
	// Table has NO updated_by column
	query := `
        INSERT INTO academics.student_transport_assignments (
            student_id, route_id, stop_id, pickup_point, drop_point,
            effective_from, effective_to, is_active,
            created_by, created_at, updated_at
        ) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, NOW(), NOW())
        RETURNING assignment_id, created_at, updated_at
    `
	err := db.QueryRowContext(ctx, query,
		sa.StudentID, sa.RouteID, sa.StopID, sa.PickupPoint, sa.DropPoint,
		sa.EffectiveFrom, sa.EffectiveTo, sa.IsActive,
		sa.CreatedBy,
	).Scan(&sa.AssignmentID, &sa.CreatedAt, &sa.UpdatedAt)
	if err != nil {
		r.logger.Error("failed to create student transport assignment", util.ErrorField(err))
		return fmt.Errorf("create student assignment: %w", err)
	}
	return nil
}

func (r *transportRepository) GetStudentAssignmentByID(ctx context.Context, db DBTX, id uuid.UUID) (*models.StudentTransportAssignment, error) {
	query := `
        SELECT assignment_id, student_id, route_id, stop_id, pickup_point, drop_point,
               effective_from, effective_to, is_active,
               created_at, updated_at, created_by
        FROM academics.student_transport_assignments
        WHERE assignment_id = $1
    `
	row := db.QueryRowContext(ctx, query, id)
	return r.scanStudentAssignment(row)
}

func (r *transportRepository) ListStudentAssignments(ctx context.Context, db DBTX, filter StudentTransportAssignmentFilter, p Pagination, s Sort) ([]*models.StudentTransportAssignment, error) {
	where, args := r.buildStudentAssignmentFilter(filter)
	orderBy, err := r.validateSort(s, allowedStudentAssignmentSortFields, "effective_from")
	if err != nil {
		return nil, err
	}
	limit, offset := r.validatePagination(p)

	query := fmt.Sprintf(`
        SELECT assignment_id, student_id, route_id, stop_id, pickup_point, drop_point,
               effective_from, effective_to, is_active,
               created_at, updated_at, created_by
        FROM academics.student_transport_assignments
        %s
        %s
        LIMIT $%d OFFSET $%d
    `, where, orderBy, len(args)+1, len(args)+2)
	args = append(args, limit, offset)

	rows, err := db.QueryContext(ctx, query, args...)
	if err != nil {
		r.logger.Error("failed to list student transport assignments", util.ErrorField(err))
		return nil, fmt.Errorf("list student assignments: %w", err)
	}
	defer rows.Close()

	var assignments []*models.StudentTransportAssignment
	for rows.Next() {
		sa, err := r.scanStudentAssignment(rows)
		if err != nil {
			return nil, err
		}
		assignments = append(assignments, sa)
	}
	if err = rows.Err(); err != nil {
		return nil, fmt.Errorf("rows iteration: %w", err)
	}
	return assignments, nil
}

func (r *transportRepository) CountStudentAssignments(ctx context.Context, db DBTX, filter StudentTransportAssignmentFilter) (int64, error) {
	where, args := r.buildStudentAssignmentFilter(filter)
	query := fmt.Sprintf("SELECT COUNT(*) FROM academics.student_transport_assignments %s", where)
	var count int64
	err := db.QueryRowContext(ctx, query, args...).Scan(&count)
	if err != nil {
		r.logger.Error("failed to count student transport assignments", util.ErrorField(err))
		return 0, fmt.Errorf("count student assignments: %w", err)
	}
	return count, nil
}

func (r *transportRepository) UpdateStudentAssignment(ctx context.Context, db DBTX, sa *models.StudentTransportAssignment) error {
	// Table has NO updated_by column
	query := `
        UPDATE academics.student_transport_assignments
        SET student_id = $2, route_id = $3, stop_id = $4, pickup_point = $5, drop_point = $6,
            effective_from = $7, effective_to = $8, is_active = $9,
            updated_at = NOW()
        WHERE assignment_id = $1
        RETURNING updated_at
    `
	err := db.QueryRowContext(ctx, query,
		sa.AssignmentID, sa.StudentID, sa.RouteID, sa.StopID, sa.PickupPoint, sa.DropPoint,
		sa.EffectiveFrom, sa.EffectiveTo, sa.IsActive,
	).Scan(&sa.UpdatedAt)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return fmt.Errorf("%w: student assignment %s", ErrNotFound, sa.AssignmentID)
		}
		r.logger.Error("failed to update student transport assignment", util.ErrorField(err))
		return fmt.Errorf("update student assignment: %w", err)
	}
	return nil
}

func (r *transportRepository) DeleteStudentAssignment(ctx context.Context, db DBTX, id uuid.UUID) error {
	query := `DELETE FROM academics.student_transport_assignments WHERE assignment_id = $1`
	result, err := db.ExecContext(ctx, query, id)
	if err != nil {
		r.logger.Error("failed to delete student transport assignment", util.ErrorField(err))
		return fmt.Errorf("delete student assignment: %w", err)
	}
	rows, err := result.RowsAffected()
	if err != nil {
		return fmt.Errorf("rows affected: %w", err)
	}
	if rows == 0 {
		return fmt.Errorf("student assignment %s not found", id)
	}
	return nil
}

func (r *transportRepository) scanStudentAssignment(row scanner) (*models.StudentTransportAssignment, error) {
	var sa models.StudentTransportAssignment
	var createdBy uuid.NullUUID
	var effectiveTo sql.NullTime

	err := row.Scan(
		&sa.AssignmentID, &sa.StudentID, &sa.RouteID, &sa.StopID,
		&sa.PickupPoint, &sa.DropPoint,
		&sa.EffectiveFrom, &effectiveTo, &sa.IsActive,
		&sa.CreatedAt, &sa.UpdatedAt,
		&createdBy,
	)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, nil
		}
		return nil, fmt.Errorf("scan student assignment: %w", err)
	}
	if effectiveTo.Valid {
		sa.EffectiveTo = &effectiveTo.Time
	}
	if createdBy.Valid {
		sa.CreatedBy = &createdBy.UUID
	}
	return &sa, nil
}

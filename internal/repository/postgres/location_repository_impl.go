package postgres

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"time"

	"github.com/google/uuid"
	"github.com/lib/pq"

	"auth-service/internal/client"
	apperrors "auth-service/internal/errors"
	"auth-service/internal/models"
)

type LocationRepositoryImpl struct {
	client *client.PostgresClient
}

func NewLocationRepository(pgClient *client.PostgresClient) *LocationRepositoryImpl {
	return &LocationRepositoryImpl{client: pgClient}
}

// ---------- Location CRUD ----------

func (r *LocationRepositoryImpl) CreateLocation(
	ctx context.Context,
	db client.DBTX,
	loc *models.Location,
) error {
	query := `
		INSERT INTO locations (
			location_id, company_id, location_code, location_name,
			address_line1, address_line2, city, state, country, pincode,
			is_active, created_at, updated_at
		) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13)
	`
	_, err := db.ExecContext(ctx, query,
		loc.LocationID, loc.CompanyID, loc.LocationCode, loc.LocationName,
		loc.AddressLine1, loc.AddressLine2, loc.City, loc.State, loc.Country, loc.Pincode,
		loc.IsActive, loc.CreatedAt, loc.UpdatedAt,
	)
	if err != nil {
		if pgErr, ok := err.(*pq.Error); ok && pgErr.Code == "23505" { // unique violation
			return apperrors.ErrDuplicate
		}
		return fmt.Errorf("failed to create location: %w", err)
	}
	return nil
}

func (r *LocationRepositoryImpl) GetLocation(
	ctx context.Context,
	db client.DBTX,
	locationID uuid.UUID,
) (*models.Location, error) {
	query := `
		SELECT location_id, company_id, location_code, location_name,
			address_line1, address_line2, city, state, country, pincode,
			is_active, created_at, updated_at
		FROM locations WHERE location_id = $1
	`
	var loc models.Location
	err := db.QueryRowContext(ctx, query, locationID).Scan(
		&loc.LocationID, &loc.CompanyID, &loc.LocationCode, &loc.LocationName,
		&loc.AddressLine1, &loc.AddressLine2, &loc.City, &loc.State, &loc.Country, &loc.Pincode,
		&loc.IsActive, &loc.CreatedAt, &loc.UpdatedAt,
	)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, apperrors.ErrNotFound
		}
		return nil, fmt.Errorf("failed to get location: %w", err)
	}
	return &loc, nil
}

func (r *LocationRepositoryImpl) UpdateLocation(
	ctx context.Context,
	db client.DBTX,
	loc *models.Location,
) error {
	query := `
		UPDATE locations SET
			location_code = $1, location_name = $2,
			address_line1 = $3, address_line2 = $4, city = $5,
			state = $6, country = $7, pincode = $8,
			is_active = $9, updated_at = $10
		WHERE location_id = $11
	`
	result, err := db.ExecContext(ctx, query,
		loc.LocationCode, loc.LocationName,
		loc.AddressLine1, loc.AddressLine2, loc.City,
		loc.State, loc.Country, loc.Pincode,
		loc.IsActive, loc.UpdatedAt, loc.LocationID,
	)
	if err != nil {
		if pgErr, ok := err.(*pq.Error); ok && pgErr.Code == "23505" {
			return apperrors.ErrDuplicate
		}
		return fmt.Errorf("failed to update location: %w", err)
	}
	rows, _ := result.RowsAffected()
	if rows == 0 {
		return apperrors.ErrNotFound
	}
	return nil
}

func (r *LocationRepositoryImpl) DeleteLocation(
	ctx context.Context,
	db client.DBTX,
	locationID uuid.UUID,
) error {
	query := `UPDATE locations SET is_active = false, updated_at = NOW() WHERE location_id = $1 AND is_active = true`
	result, err := db.ExecContext(ctx, query, locationID)
	if err != nil {
		return fmt.Errorf("failed to delete location: %w", err)
	}
	rows, _ := result.RowsAffected()
	if rows == 0 {
		return apperrors.ErrNotFound
	}
	return nil
}

func (r *LocationRepositoryImpl) ListLocations(
	ctx context.Context,
	db client.DBTX,
	companyID uuid.UUID,
	limit, offset int,
) ([]*models.Location, int, error) {
	// Count total
	var total int
	countQuery := `SELECT COUNT(*) FROM locations WHERE company_id = $1 AND is_active = true`
	err := db.QueryRowContext(ctx, countQuery, companyID).Scan(&total)
	if err != nil {
		return nil, 0, fmt.Errorf("failed to count locations: %w", err)
	}

	if limit <= 0 || limit > 1000 {
		limit = 50
	}
	if offset < 0 {
		offset = 0
	}

	query := `
		SELECT location_id, company_id, location_code, location_name,
			address_line1, address_line2, city, state, country, pincode,
			is_active, created_at, updated_at
		FROM locations
		WHERE company_id = $1 AND is_active = true
		ORDER BY location_code ASC
		LIMIT $2 OFFSET $3
	`
	rows, err := db.QueryContext(ctx, query, companyID, limit, offset)
	if err != nil {
		return nil, 0, fmt.Errorf("failed to list locations: %w", err)
	}
	defer rows.Close()

	locations := make([]*models.Location, 0, limit)
	for rows.Next() {
		var loc models.Location
		err := rows.Scan(
			&loc.LocationID, &loc.CompanyID, &loc.LocationCode, &loc.LocationName,
			&loc.AddressLine1, &loc.AddressLine2, &loc.City, &loc.State, &loc.Country, &loc.Pincode,
			&loc.IsActive, &loc.CreatedAt, &loc.UpdatedAt,
		)
		if err != nil {
			return nil, 0, fmt.Errorf("failed to scan location: %w", err)
		}
		locations = append(locations, &loc)
	}
	return locations, total, rows.Err()
}

// ---------- Location Access ----------

func (r *LocationRepositoryImpl) AddLocationAccess(
	ctx context.Context,
	db client.DBTX,
	access *models.EmployeeLocationAccess,
) error {
	query := `
		INSERT INTO employee_location_access (company_id, user_id, location_id, access_level, granted_at, granted_by)
		VALUES ($1, $2, $3, $4, $5, $6)
		ON CONFLICT (company_id, user_id, location_id) DO UPDATE SET
			access_level = EXCLUDED.access_level,
			granted_at = EXCLUDED.granted_at,
			granted_by = EXCLUDED.granted_by
	`
	_, err := db.ExecContext(ctx, query,
		access.CompanyID, access.UserID, access.LocationID,
		access.AccessLevel, access.GrantedAt, access.GrantedBy,
	)
	if err != nil {
		return fmt.Errorf("failed to add location access: %w", err)
	}
	return nil
}

func (r *LocationRepositoryImpl) RemoveLocationAccess(
	ctx context.Context,
	db client.DBTX,
	companyID, userID, locationID uuid.UUID,
) error {
	query := `DELETE FROM employee_location_access WHERE company_id = $1 AND user_id = $2 AND location_id = $3`
	result, err := db.ExecContext(ctx, query, companyID, userID, locationID)
	if err != nil {
		return fmt.Errorf("failed to remove location access: %w", err)
	}
	rows, _ := result.RowsAffected()
	if rows == 0 {
		return apperrors.ErrNotFound
	}
	return nil
}

func (r *LocationRepositoryImpl) GetLocationAccessForEmployee(
	ctx context.Context,
	db client.DBTX,
	companyID, userID uuid.UUID,
) ([]*models.EmployeeLocationAccess, error) {
	query := `
		SELECT company_id, user_id, location_id, access_level, granted_at, granted_by
		FROM employee_location_access
		WHERE company_id = $1 AND user_id = $2
	`
	rows, err := db.QueryContext(ctx, query, companyID, userID)
	if err != nil {
		return nil, fmt.Errorf("failed to get location access: %w", err)
	}
	defer rows.Close()

	var accesses []*models.EmployeeLocationAccess
	for rows.Next() {
		var a models.EmployeeLocationAccess
		err := rows.Scan(&a.CompanyID, &a.UserID, &a.LocationID, &a.AccessLevel, &a.GrantedAt, &a.GrantedBy)
		if err != nil {
			return nil, fmt.Errorf("failed to scan access: %w", err)
		}
		accesses = append(accesses, &a)
	}
	return accesses, rows.Err()
}

func (r *LocationRepositoryImpl) GetEmployeeLocationsWithAccess(
	ctx context.Context,
	db client.DBTX,
	companyID, userID uuid.UUID,
) ([]*models.LocationWithAccess, error) {
	query := `
		SELECT
			l.location_id, l.company_id, l.location_code, l.location_name,
			l.address_line1, l.address_line2, l.city, l.state, l.country, l.pincode,
			l.is_active, l.created_at, l.updated_at,
			COALESCE(ela.access_level, '') AS access_level
		FROM locations l
		LEFT JOIN employee_location_access ela
			ON l.location_id = ela.location_id AND ela.company_id = $1 AND ela.user_id = $2
		WHERE l.company_id = $1 AND l.is_active = true
		ORDER BY l.location_code
	`
	rows, err := db.QueryContext(ctx, query, companyID, userID)
	if err != nil {
		return nil, fmt.Errorf("failed to get employee locations with access: %w", err)
	}
	defer rows.Close()

	var result []*models.LocationWithAccess
	for rows.Next() {
		var loc models.Location
		var accessLevel string
		err := rows.Scan(
			&loc.LocationID, &loc.CompanyID, &loc.LocationCode, &loc.LocationName,
			&loc.AddressLine1, &loc.AddressLine2, &loc.City, &loc.State, &loc.Country, &loc.Pincode,
			&loc.IsActive, &loc.CreatedAt, &loc.UpdatedAt,
			&accessLevel,
		)
		if err != nil {
			return nil, fmt.Errorf("failed to scan location with access: %w", err)
		}
		result = append(result, &models.LocationWithAccess{
			Location:    loc,
			AccessLevel: accessLevel,
		})
	}
	return result, rows.Err()
}

// ---------- Employee location fields ----------

func (r *LocationRepositoryImpl) SetEmployeePrimaryLocation(
	ctx context.Context,
	db client.DBTX,
	companyID, userID, locationID uuid.UUID,
) error {
	query := `UPDATE company_employees SET primary_location_id = $1 WHERE company_id = $2 AND user_id = $3`
	result, err := db.ExecContext(ctx, query, locationID, companyID, userID)
	if err != nil {
		return fmt.Errorf("failed to set primary location: %w", err)
	}
	rows, _ := result.RowsAffected()
	if rows == 0 {
		return apperrors.ErrNotFound
	}
	return nil
}

func (r *LocationRepositoryImpl) UpdateEmployeeLocationScope(
	ctx context.Context,
	db client.DBTX,
	companyID, userID uuid.UUID,
	scope string,
) error {
	query := `UPDATE company_employees SET location_access_scope = $1 WHERE company_id = $2 AND user_id = $3`
	result, err := db.ExecContext(ctx, query, scope, companyID, userID)
	if err != nil {
		return fmt.Errorf("failed to update location scope: %w", err)
	}
	rows, _ := result.RowsAffected()
	if rows == 0 {
		return apperrors.ErrNotFound
	}
	return nil
}

// ---------- Location History ----------

func (r *LocationRepositoryImpl) AddLocationHistory(
	ctx context.Context,
	db client.DBTX,
	history *models.EmployeeLocationHistory,
) error {
	query := `
		INSERT INTO employee_location_history (
			id, user_id, company_id, location_id, start_date, end_date, change_reason, created_at
		) VALUES ($1, $2, $3, $4, $5, $6, $7, $8)
	`
	_, err := db.ExecContext(ctx, query,
		history.ID, history.UserID, history.CompanyID, history.LocationID,
		history.StartDate, history.EndDate, history.ChangeReason, history.CreatedAt,
	)
	if err != nil {
		return fmt.Errorf("failed to add location history: %w", err)
	}
	return nil
}

func (r *LocationRepositoryImpl) CloseActiveLocationHistory(
	ctx context.Context,
	db client.DBTX,
	companyID, userID uuid.UUID,
	endDate time.Time,
) error {
	query := `
		UPDATE employee_location_history
		SET end_date = $1
		WHERE company_id = $2 AND user_id = $3 AND end_date IS NULL
	`
	_, err := db.ExecContext(ctx, query, endDate, companyID, userID)
	if err != nil {
		return fmt.Errorf("failed to close location history: %w", err)
	}
	return nil
}

func (r *LocationRepositoryImpl) GetLocationHistory(
	ctx context.Context,
	db client.DBTX,
	companyID, userID uuid.UUID,
) ([]*models.EmployeeLocationHistory, error) {
	query := `
		SELECT id, user_id, company_id, location_id, start_date, end_date, change_reason, created_at
		FROM employee_location_history
		WHERE company_id = $1 AND user_id = $2
		ORDER BY start_date DESC
	`
	rows, err := db.QueryContext(ctx, query, companyID, userID)
	if err != nil {
		return nil, fmt.Errorf("failed to get location history: %w", err)
	}
	defer rows.Close()

	var history []*models.EmployeeLocationHistory
	for rows.Next() {
		var h models.EmployeeLocationHistory
		err := rows.Scan(&h.ID, &h.UserID, &h.CompanyID, &h.LocationID, &h.StartDate, &h.EndDate, &h.ChangeReason, &h.CreatedAt)
		if err != nil {
			return nil, fmt.Errorf("failed to scan history: %w", err)
		}
		history = append(history, &h)
	}
	return history, rows.Err()
}

// ---------- Count Active Locations ----------

func (r *LocationRepositoryImpl) CountActiveLocations(
	ctx context.Context,
	db client.DBTX,
	companyID uuid.UUID,
) (int, error) {
	var count int
	query := `SELECT COUNT(*) FROM locations WHERE company_id = $1 AND is_active = true`
	err := db.QueryRowContext(ctx, query, companyID).Scan(&count)
	if err != nil {
		return 0, fmt.Errorf("failed to count active locations: %w", err)
	}
	return count, nil
}

// GetEmployeeLocationDetails retrieves the primary location and scope for an employee.
func (r *LocationRepositoryImpl) GetEmployeeLocationDetails(
	ctx context.Context,
	db client.DBTX,
	companyID, userID uuid.UUID,
) (*models.EmployeeLocationDetails, error) {
	query := `
		SELECT primary_location_id, location_access_scope
		FROM company_employees
		WHERE company_id = $1 AND user_id = $2
	`
	var details models.EmployeeLocationDetails
	var primaryLoc uuid.NullUUID
	var scope string

	err := db.QueryRowContext(ctx, query, companyID, userID).Scan(&primaryLoc, &scope)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, apperrors.ErrNotFound
		}
		return nil, fmt.Errorf("failed to get employee location details: %w", err)
	}

	if primaryLoc.Valid {
		details.PrimaryLocationID = primaryLoc.UUID
	}
	details.LocationScope = scope
	return &details, nil
}

// IsLocationAccessible checks if a user has access to a specific location
// (used for SELECTED scope).
func (r *LocationRepositoryImpl) IsLocationAccessible(
	ctx context.Context,
	db client.DBTX,
	companyID, userID, locationID uuid.UUID,
) (bool, error) {
	var count int
	query := `SELECT COUNT(1) FROM employee_location_access
              WHERE company_id = $1 AND user_id = $2 AND location_id = $3`
	err := db.QueryRowContext(ctx, query, companyID, userID, locationID).Scan(&count)
	if err != nil {
		return false, fmt.Errorf("failed to check location access: %w", err)
	}
	return count > 0, nil
}

func (r *LocationRepositoryImpl) GetLocationAccessLevel(
	ctx context.Context,
	db client.DBTX,
	companyID, userID, locationID uuid.UUID,
) (string, error) {
	var level string
	query := `SELECT access_level FROM employee_location_access
              WHERE company_id = $1 AND user_id = $2 AND location_id = $3`
	err := db.QueryRowContext(ctx, query, companyID, userID, locationID).Scan(&level)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return "", apperrors.ErrNotFound
		}
		return "", fmt.Errorf("failed to get location access level: %w", err)
	}
	return level, nil
}

func (r *LocationRepositoryImpl) DeleteAllLocationAccessForUser(
	ctx context.Context,
	db client.DBTX,
	companyID, userID uuid.UUID,
) error {
	const query = `
		DELETE FROM employee_location_access
		WHERE company_id = $1 AND user_id = $2`
	_, err := db.ExecContext(ctx, query, companyID, userID)
	if err != nil {
		return fmt.Errorf("failed to delete employee location access: %w", err)
	}
	return nil
}

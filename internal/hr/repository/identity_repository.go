package repository

import (
	"auth-service/internal/client"
	"auth-service/internal/hr/models/attendance"
	"auth-service/internal/util"
	"context"
	"database/sql"
	"errors"
	"fmt"
	"time"

	"github.com/google/uuid"
	"go.uber.org/zap"
)

type AttendanceIdentityRepository interface {
	// Identity Resolution
	ResolveUserByDeviceCode(
		ctx context.Context,
		companyID uuid.UUID,
		deviceID string,
		sourceType string,
		deviceUserCode string,
	) (uuid.UUID, error)

	// Identity Management
	CreateIdentity(
		ctx context.Context,
		identity *attendance.AttendanceIdentity,
	) error

	DeactivateIdentity(
		ctx context.Context,
		mappingID uuid.UUID,
	) error

	GetActiveIdentitiesByUser(
		ctx context.Context,
		companyID, userID uuid.UUID,
	) ([]*attendance.AttendanceIdentity, error)

	GetIdentityByID(
		ctx context.Context,
		mappingID uuid.UUID,
	) (*attendance.AttendanceIdentity, error)

	GetIdentityByDeviceUserCode(
		ctx context.Context,
		deviceID string,
		deviceUserCode string,
	) (*attendance.AttendanceIdentity, error)

	GetIdentitiesByDevice(
		ctx context.Context,
		deviceID string,
		activeOnly bool,
	) ([]*attendance.AttendanceIdentity, error)

	UpdateIdentity(
		ctx context.Context,
		identity *attendance.AttendanceIdentity,
	) error

	GetUserIdentitiesBySourceType(
		ctx context.Context,
		userID uuid.UUID,
		sourceType string,
		activeOnly bool,
	) ([]*attendance.AttendanceIdentity, error)

	CountActiveIdentitiesByUser(
		ctx context.Context,
		userID uuid.UUID,
	) (int, error)

	HealthCheck(ctx context.Context) error
}

type attendanceIdentityRepository struct {
	client *client.PostgresClient
	logger *zap.Logger
}

func NewAttendanceIdentityRepository(
	postgresClient *client.PostgresClient,
	logger *zap.Logger,
) AttendanceIdentityRepository {
	return &attendanceIdentityRepository{
		client: postgresClient,
		logger: logger,
	}
}

// ResolveUserByDeviceCode resolves a user by device-specific identifier
func (r *attendanceIdentityRepository) ResolveUserByDeviceCode(
	ctx context.Context,
	companyID uuid.UUID,
	deviceID string,
	sourceType string,
	deviceUserCode string,
) (uuid.UUID, error) {
	query := `
		SELECT a.user_id
		FROM attendance_user_device_identifiers a
		JOIN attendance_devices d ON a.device_id = d.device_id
		WHERE a.device_id = $1
		  AND a.source_type = $2
		  AND a.device_user_code = $3
		  AND a.is_active = true
		  AND d.company_id = $4
		  AND d.is_active = true
		  AND d.is_trusted = true
		LIMIT 1
	`

	row := r.client.QueryRow(ctx, query, deviceID, sourceType, deviceUserCode, companyID)
	var userID uuid.UUID
	err := row.Scan(&userID)

	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			r.logger.Debug("No active identity found for device code",
				util.String("device_id", deviceID),
				util.String("source_type", sourceType),
				util.String("device_user_code", deviceUserCode),
				util.String("company_id", companyID.String()))
			return uuid.Nil, fmt.Errorf("identity not found or inactive")
		}
		r.logger.Error("Failed to resolve user by device code",
			util.String("device_id", deviceID),
			util.String("device_user_code", deviceUserCode),
			util.ErrorField(err))
		return uuid.Nil, fmt.Errorf("failed to resolve user identity: %w", err)
	}

	return userID, nil
}

// CreateIdentity creates a new device-user identity mapping
func (r *attendanceIdentityRepository) CreateIdentity(
	ctx context.Context,
	identity *attendance.AttendanceIdentity,
) error {
	query := `
		INSERT INTO attendance_user_device_identifiers (
			mapping_id,
			company_id,
			user_id,
			device_id,
			source_type,
			device_user_code,
			is_active,
			enrolled_at,
			unenrolled_at,
			created_by
		) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10)
	`

	if identity.MappingID == uuid.Nil {
		identity.MappingID = uuid.New()
	}

	if identity.EnrolledAt.IsZero() {
		identity.EnrolledAt = time.Now().UTC()
	}

	_, err := r.client.Exec(ctx, query,
		identity.MappingID,
		identity.CompanyID,
		identity.UserID,
		identity.DeviceID,
		identity.SourceType,
		identity.DeviceUserCode,
		identity.IsActive,
		identity.EnrolledAt,
		identity.UnenrolledAt,
		identity.CreatedBy,
	)

	if err != nil {
		r.logger.Error("Failed to create attendance identity",
			util.String("mapping_id", identity.MappingID.String()),
			util.String("user_id", identity.UserID.String()),
			util.String("device_id", identity.DeviceID),
			util.ErrorField(err))
		return fmt.Errorf("failed to create attendance identity: %w", err)
	}

	return nil
}

// DeactivateIdentity marks an identity as inactive
func (r *attendanceIdentityRepository) DeactivateIdentity(
	ctx context.Context,
	mappingID uuid.UUID,
) error {
	query := `
		UPDATE attendance_user_device_identifiers
		SET is_active = false,
			unenrolled_at = $1
		WHERE mapping_id = $2
		  AND is_active = true
	`

	result, err := r.client.Exec(ctx, query, time.Now().UTC(), mappingID)
	if err != nil {
		r.logger.Error("Failed to deactivate attendance identity",
			util.String("mapping_id", mappingID.String()),
			util.ErrorField(err))
		return fmt.Errorf("failed to deactivate attendance identity: %w", err)
	}

	rowsAffected, _ := result.RowsAffected()
	if rowsAffected == 0 {
		return fmt.Errorf("active attendance identity not found")
	}

	return nil
}

// GetActiveIdentitiesByUser retrieves all active identities for a user
func (r *attendanceIdentityRepository) GetActiveIdentitiesByUser(
	ctx context.Context,
	companyID, userID uuid.UUID,
) ([]*attendance.AttendanceIdentity, error) {
	query := `
		SELECT
			mapping_id,
			company_id,
			user_id,
			device_id,
			source_type,
			device_user_code,
			is_active,
			enrolled_at,
			unenrolled_at,
			created_by
		FROM attendance_user_device_identifiers
		WHERE company_id = $1
		  AND user_id = $2
		  AND is_active = true
		ORDER BY enrolled_at DESC
	`

	rows, err := r.client.Query(ctx, query, companyID, userID)
	if err != nil {
		r.logger.Error("Failed to get active identities by user",
			util.String("company_id", companyID.String()),
			util.String("user_id", userID.String()),
			util.ErrorField(err))
		return nil, fmt.Errorf("failed to get active identities: %w", err)
	}
	defer rows.Close()

	var identities []*attendance.AttendanceIdentity
	for rows.Next() {
		var identity attendance.AttendanceIdentity
		err := rows.Scan(
			&identity.MappingID,
			&identity.CompanyID,
			&identity.UserID,
			&identity.DeviceID,
			&identity.SourceType,
			&identity.DeviceUserCode,
			&identity.IsActive,
			&identity.EnrolledAt,
			&identity.UnenrolledAt,
			&identity.CreatedBy,
		)
		if err != nil {
			return nil, fmt.Errorf("failed to scan identity: %w", err)
		}
		identities = append(identities, &identity)
	}

	if err = rows.Err(); err != nil {
		return nil, fmt.Errorf("rows iteration error: %w", err)
	}

	return identities, nil
}

// GetIdentityByID retrieves a specific identity by its mapping ID
func (r *attendanceIdentityRepository) GetIdentityByID(
	ctx context.Context,
	mappingID uuid.UUID,
) (*attendance.AttendanceIdentity, error) {
	query := `
		SELECT
			mapping_id,
			company_id,
			user_id,
			device_id,
			source_type,
			device_user_code,
			is_active,
			enrolled_at,
			unenrolled_at,
			created_by
		FROM attendance_user_device_identifiers
		WHERE mapping_id = $1
	`

	row := r.client.QueryRow(ctx, query, mappingID)
	var identity attendance.AttendanceIdentity
	err := row.Scan(
		&identity.MappingID,
		&identity.CompanyID,
		&identity.UserID,
		&identity.DeviceID,
		&identity.SourceType,
		&identity.DeviceUserCode,
		&identity.IsActive,
		&identity.EnrolledAt,
		&identity.UnenrolledAt,
		&identity.CreatedBy,
	)

	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, nil
		}
		r.logger.Error("Failed to get identity by ID",
			util.String("mapping_id", mappingID.String()),
			util.ErrorField(err))
		return nil, fmt.Errorf("failed to get identity: %w", err)
	}

	return &identity, nil
}

// GetIdentityByDeviceUserCode finds identity by device ID and user code
func (r *attendanceIdentityRepository) GetIdentityByDeviceUserCode(
	ctx context.Context,
	deviceID string,
	deviceUserCode string,
) (*attendance.AttendanceIdentity, error) {
	query := `
		SELECT
			mapping_id,
			company_id,
			user_id,
			device_id,
			source_type,
			device_user_code,
			is_active,
			enrolled_at,
			unenrolled_at,
			created_by
		FROM attendance_user_device_identifiers
		WHERE device_id = $1
		  AND device_user_code = $2
		ORDER BY is_active DESC, enrolled_at DESC
		LIMIT 1
	`

	row := r.client.QueryRow(ctx, query, deviceID, deviceUserCode)
	var identity attendance.AttendanceIdentity
	err := row.Scan(
		&identity.MappingID,
		&identity.CompanyID,
		&identity.UserID,
		&identity.DeviceID,
		&identity.SourceType,
		&identity.DeviceUserCode,
		&identity.IsActive,
		&identity.EnrolledAt,
		&identity.UnenrolledAt,
		&identity.CreatedBy,
	)

	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, nil
		}
		r.logger.Error("Failed to get identity by device user code",
			util.String("device_id", deviceID),
			util.String("device_user_code", deviceUserCode),
			util.ErrorField(err))
		return nil, fmt.Errorf("failed to get identity: %w", err)
	}

	return &identity, nil
}

// GetIdentitiesByDevice retrieves all identities for a specific device
func (r *attendanceIdentityRepository) GetIdentitiesByDevice(
	ctx context.Context,
	deviceID string,
	activeOnly bool,
) ([]*attendance.AttendanceIdentity, error) {
	query := `
		SELECT
			mapping_id,
			company_id,
			user_id,
			device_id,
			source_type,
			device_user_code,
			is_active,
			enrolled_at,
			unenrolled_at,
			created_by
		FROM attendance_user_device_identifiers
		WHERE device_id = $1
		ORDER BY enrolled_at DESC
	`

	if activeOnly {
		query = `
			SELECT
				mapping_id,
				company_id,
				user_id,
				device_id,
				source_type,
				device_user_code,
				is_active,
				enrolled_at,
				unenrolled_at,
				created_by
			FROM attendance_user_device_identifiers
			WHERE device_id = $1
			  AND is_active = true
			ORDER BY enrolled_at DESC
		`
	}

	rows, err := r.client.Query(ctx, query, deviceID)
	if err != nil {
		r.logger.Error("Failed to get identities by device",
			util.String("device_id", deviceID),
			util.ErrorField(err))
		return nil, fmt.Errorf("failed to get identities: %w", err)
	}
	defer rows.Close()

	var identities []*attendance.AttendanceIdentity
	for rows.Next() {
		var identity attendance.AttendanceIdentity
		err := rows.Scan(
			&identity.MappingID,
			&identity.CompanyID,
			&identity.UserID,
			&identity.DeviceID,
			&identity.SourceType,
			&identity.DeviceUserCode,
			&identity.IsActive,
			&identity.EnrolledAt,
			&identity.UnenrolledAt,
			&identity.CreatedBy,
		)
		if err != nil {
			return nil, fmt.Errorf("failed to scan identity: %w", err)
		}
		identities = append(identities, &identity)
	}

	if err = rows.Err(); err != nil {
		return nil, fmt.Errorf("rows iteration error: %w", err)
	}

	return identities, nil
}

// UpdateIdentity updates an existing identity
func (r *attendanceIdentityRepository) UpdateIdentity(
	ctx context.Context,
	identity *attendance.AttendanceIdentity,
) error {
	query := `
		UPDATE attendance_user_device_identifiers
		SET is_active = $1,
			unenrolled_at = $2
		WHERE mapping_id = $3
	`

	_, err := r.client.Exec(ctx, query,
		identity.IsActive,
		identity.UnenrolledAt,
		identity.MappingID,
	)

	if err != nil {
		r.logger.Error("Failed to update attendance identity",
			util.String("mapping_id", identity.MappingID.String()),
			util.ErrorField(err))
		return fmt.Errorf("failed to update attendance identity: %w", err)
	}

	return nil
}

// GetUserIdentitiesBySourceType gets user identities filtered by source type
func (r *attendanceIdentityRepository) GetUserIdentitiesBySourceType(
	ctx context.Context,
	userID uuid.UUID,
	sourceType string,
	activeOnly bool,
) ([]*attendance.AttendanceIdentity, error) {
	query := `
		SELECT
			mapping_id,
			company_id,
			user_id,
			device_id,
			source_type,
			device_user_code,
			is_active,
			enrolled_at,
			unenrolled_at,
			created_by
		FROM attendance_user_device_identifiers
		WHERE user_id = $1
		  AND source_type = $2
		ORDER BY enrolled_at DESC
	`

	if activeOnly {
		query = `
			SELECT
				mapping_id,
				company_id,
				user_id,
				device_id,
				source_type,
				device_user_code,
				is_active,
				enrolled_at,
				unenrolled_at,
				created_by
			FROM attendance_user_device_identifiers
			WHERE user_id = $1
			  AND source_type = $2
			  AND is_active = true
			ORDER BY enrolled_at DESC
		`
	}

	rows, err := r.client.Query(ctx, query, userID, sourceType)
	if err != nil {
		r.logger.Error("Failed to get user identities by source type",
			util.String("user_id", userID.String()),
			util.String("source_type", sourceType),
			util.ErrorField(err))
		return nil, fmt.Errorf("failed to get identities: %w", err)
	}
	defer rows.Close()

	var identities []*attendance.AttendanceIdentity
	for rows.Next() {
		var identity attendance.AttendanceIdentity
		err := rows.Scan(
			&identity.MappingID,
			&identity.CompanyID,
			&identity.UserID,
			&identity.DeviceID,
			&identity.SourceType,
			&identity.DeviceUserCode,
			&identity.IsActive,
			&identity.EnrolledAt,
			&identity.UnenrolledAt,
			&identity.CreatedBy,
		)
		if err != nil {
			return nil, fmt.Errorf("failed to scan identity: %w", err)
		}
		identities = append(identities, &identity)
	}

	if err = rows.Err(); err != nil {
		return nil, fmt.Errorf("rows iteration error: %w", err)
	}

	return identities, nil
}

// CountActiveIdentitiesByUser counts active identities for a user
func (r *attendanceIdentityRepository) CountActiveIdentitiesByUser(
	ctx context.Context,
	userID uuid.UUID,
) (int, error) {
	query := `
		SELECT COUNT(*)
		FROM attendance_user_device_identifiers
		WHERE user_id = $1
		  AND is_active = true
	`

	row := r.client.QueryRow(ctx, query, userID)
	var count int
	err := row.Scan(&count)

	if err != nil {
		r.logger.Error("Failed to count active identities by user",
			util.String("user_id", userID.String()),
			util.ErrorField(err))
		return 0, fmt.Errorf("failed to count active identities: %w", err)
	}

	return count, nil
}

// HealthCheck performs a health check on the repository
func (r *attendanceIdentityRepository) HealthCheck(ctx context.Context) error {
	query := `SELECT 1 FROM attendance_user_device_identifiers LIMIT 1`
	var result int
	row := r.client.QueryRow(ctx, query)
	err := row.Scan(&result)
	if err != nil && !errors.Is(err, sql.ErrNoRows) {
		r.logger.Error("Identity repository health check failed",
			util.ErrorField(err))
		return fmt.Errorf("identity repository health check failed: %w", err)
	}
	return nil
}

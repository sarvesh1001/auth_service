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

type deviceEnrollmentRepository struct {
	client *client.PostgresClient
	logger *zap.Logger
}

func NewDeviceEnrollmentRepository(
	client *client.PostgresClient,
	logger *zap.Logger,
) DeviceEnrollmentRepository {
	return &deviceEnrollmentRepository{
		client: client,
		logger: logger,
	}
}

// =====================================================
// CREATE
// =====================================================

func (r *deviceEnrollmentRepository) Create(
	ctx context.Context,
	enrollment *attendance.UserDeviceIdentifier,
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
			enrollment_version,
			enrolled_at,
			unenrolled_at,
			revoked_reason,
			created_by
		) VALUES (
			$1, $2, $3, $4, $5, $6,
			$7, $8, $9, $10, $11, $12
		)
	`

	if enrollment.MappingID == uuid.Nil {
		enrollment.MappingID = uuid.New()
	}
	if enrollment.EnrollmentVersion == 0 {
		enrollment.EnrollmentVersion = 1
	}
	if enrollment.EnrolledAt.IsZero() {
		enrollment.EnrolledAt = time.Now().UTC()
	}

	_, err := r.client.Exec(
		ctx,
		query,
		enrollment.MappingID,
		enrollment.CompanyID,
		enrollment.UserID,
		enrollment.DeviceID,
		enrollment.SourceType,
		enrollment.DeviceUserCode,
		enrollment.IsActive,
		enrollment.EnrollmentVersion,
		enrollment.EnrolledAt,
		enrollment.UnenrolledAt,
		enrollment.RevokedReason,
		enrollment.CreatedBy,
	)

	if err != nil {
		r.logger.Error(
			"Failed to create device enrollment",
			util.String("mapping_id", enrollment.MappingID.String()),
			util.ErrorField(err),
		)
		return fmt.Errorf("failed to create device enrollment: %w", err)
	}

	return nil
}

// =====================================================
// GET ACTIVE (STRICT)
// =====================================================

func (r *deviceEnrollmentRepository) GetActive(
	ctx context.Context,
	companyID uuid.UUID,
	deviceID string,
	sourceType string,
	deviceUserCode string,
) (*attendance.UserDeviceIdentifier, error) {

	query := `
		SELECT
			mapping_id,
			company_id,
			user_id,
			device_id,
			source_type,
			device_user_code,
			is_active,
			enrollment_version,
			enrolled_at,
			unenrolled_at,
			revoked_reason,
			created_by
		FROM attendance_user_device_identifiers
		WHERE company_id = $1
		  AND device_id = $2
		  AND source_type = $3
		  AND device_user_code = $4
		  AND is_active = true
	`

	row := r.client.QueryRow(
		ctx,
		query,
		companyID,
		deviceID,
		sourceType,
		deviceUserCode,
	)

	var enrollment attendance.UserDeviceIdentifier
	err := row.Scan(
		&enrollment.MappingID,
		&enrollment.CompanyID,
		&enrollment.UserID,
		&enrollment.DeviceID,
		&enrollment.SourceType,
		&enrollment.DeviceUserCode,
		&enrollment.IsActive,
		&enrollment.EnrollmentVersion,
		&enrollment.EnrolledAt,
		&enrollment.UnenrolledAt,
		&enrollment.RevokedReason,
		&enrollment.CreatedBy,
	)

	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, nil
		}
		r.logger.Error(
			"Failed to get active device enrollment",
			util.String("company_id", companyID.String()),
			util.String("device_id", deviceID),
			util.String("device_user_code", deviceUserCode),
			util.ErrorField(err),
		)
		return nil, fmt.Errorf("failed to get active device enrollment: %w", err)
	}

	return &enrollment, nil
}

// =====================================================
// REVOKE (BY MAPPING ID — SAFE)
// =====================================================

func (r *deviceEnrollmentRepository) Revoke(
	ctx context.Context,
	mappingID uuid.UUID,
	reason string,
	revokedBy *uuid.UUID,
) error {

	query := `
		UPDATE attendance_user_device_identifiers
		SET is_active = false,
		    unenrolled_at = NOW(),
		    revoked_reason = $2,
		    enrollment_version = enrollment_version + 1,
		    revoked_by = $3
		WHERE mapping_id = $1
		  AND is_active = true
	`

	result, err := r.client.Exec(
		ctx,
		query,
		mappingID,
		reason,
		revokedBy,
	)
	if err != nil {
		r.logger.Error(
			"Failed to revoke device enrollment",
			util.String("mapping_id", mappingID.String()),
			util.ErrorField(err),
		)
		return fmt.Errorf("failed to revoke device enrollment: %w", err)
	}

	rowsAffected, _ := result.RowsAffected()
	if rowsAffected == 0 {
		return errors.New("no active enrollment found to revoke")
	}

	return nil
}

// =====================================================
// EXISTS ACTIVE ENROLLMENT
// =====================================================

func (r *deviceEnrollmentRepository) ExistsActiveEnrollment(
	ctx context.Context,
	companyID uuid.UUID,
	deviceID string,
	sourceType string,
	deviceUserCode string,
) (bool, error) {

	query := `
		SELECT EXISTS (
			SELECT 1
			FROM attendance_user_device_identifiers
			WHERE company_id = $1
			  AND device_id = $2
			  AND source_type = $3
			  AND device_user_code = $4
			  AND is_active = true
		)
	`

	var exists bool
	err := r.client.QueryRow(
		ctx,
		query,
		companyID,
		deviceID,
		sourceType,
		deviceUserCode,
	).Scan(&exists)

	if err != nil {
		return false, fmt.Errorf("failed to check enrollment existence: %w", err)
	}

	return exists, nil
}

// =====================================================
// QUERIES
// =====================================================

func (r *deviceEnrollmentRepository) GetEnrollmentsByDevice(
	ctx context.Context,
	companyID uuid.UUID,
	deviceID string,
) ([]*attendance.UserDeviceIdentifier, error) {

	query := `
		SELECT
			mapping_id,
			company_id,
			user_id,
			device_id,
			source_type,
			device_user_code,
			is_active,
			enrollment_version,
			enrolled_at,
			unenrolled_at,
			revoked_reason,
			created_by
		FROM attendance_user_device_identifiers
		WHERE company_id = $1
		  AND device_id = $2
		ORDER BY enrolled_at DESC
	`

	rows, err := r.client.Query(ctx, query, companyID, deviceID)
	if err != nil {
		return nil, fmt.Errorf("failed to get enrollments by device: %w", err)
	}
	defer rows.Close()

	var result []*attendance.UserDeviceIdentifier
	for rows.Next() {
		var e attendance.UserDeviceIdentifier
		if err := rows.Scan(
			&e.MappingID,
			&e.CompanyID,
			&e.UserID,
			&e.DeviceID,
			&e.SourceType,
			&e.DeviceUserCode,
			&e.IsActive,
			&e.EnrollmentVersion,
			&e.EnrolledAt,
			&e.UnenrolledAt,
			&e.RevokedReason,
			&e.CreatedBy,
		); err != nil {
			return nil, err
		}
		result = append(result, &e)
	}

	return result, nil
}

func (r *deviceEnrollmentRepository) GetEnrollmentsByUser(
	ctx context.Context,
	companyID uuid.UUID,
	userID uuid.UUID,
) ([]*attendance.UserDeviceIdentifier, error) {

	query := `
		SELECT
			mapping_id,
			company_id,
			user_id,
			device_id,
			source_type,
			device_user_code,
			is_active,
			enrollment_version,
			enrolled_at,
			unenrolled_at,
			revoked_reason,
			created_by
		FROM attendance_user_device_identifiers
		WHERE company_id = $1
		  AND user_id = $2
		ORDER BY enrolled_at DESC
	`

	rows, err := r.client.Query(ctx, query, companyID, userID)
	if err != nil {
		return nil, fmt.Errorf("failed to get enrollments by user: %w", err)
	}
	defer rows.Close()

	var result []*attendance.UserDeviceIdentifier
	for rows.Next() {
		var e attendance.UserDeviceIdentifier
		if err := rows.Scan(
			&e.MappingID,
			&e.CompanyID,
			&e.UserID,
			&e.DeviceID,
			&e.SourceType,
			&e.DeviceUserCode,
			&e.IsActive,
			&e.EnrollmentVersion,
			&e.EnrolledAt,
			&e.UnenrolledAt,
			&e.RevokedReason,
			&e.CreatedBy,
		); err != nil {
			return nil, err
		}
		result = append(result, &e)
	}

	return result, nil
}

// =====================================================
// LAST USED
// =====================================================

func (r *deviceEnrollmentRepository) UpdateLastUsed(
	ctx context.Context,
	mappingID uuid.UUID,
) error {
	query := `
		UPDATE attendance_user_device_identifiers
		SET enrollment_version = enrollment_version + 1
		WHERE mapping_id = $1
	`
	_, err := r.client.Exec(ctx, query, mappingID)
	return err
}
func (r *deviceEnrollmentRepository) IncrementVersion(
	ctx context.Context,
	mappingID uuid.UUID,
) error {

	query := `
		UPDATE attendance_user_device_identifiers
		SET enrollment_version = enrollment_version + 1
		WHERE mapping_id = $1
	`

	_, err := r.client.Exec(ctx, query, mappingID)
	if err != nil {
		r.logger.Error(
			"Failed to increment enrollment version",
			util.String("mapping_id", mappingID.String()),
			util.ErrorField(err),
		)
		return err
	}

	return nil
}

func (r *deviceEnrollmentRepository) UnrevokeEnrollment(
	ctx context.Context,
	companyID uuid.UUID,
	deviceID string,
	deviceUserCode string,
	sourceType string,
	actedBy *uuid.UUID,
	reason string,
) (*attendance.UserDeviceIdentifier, error) {

	query := `
		UPDATE attendance_user_device_identifiers
		SET
			is_active = true,
			unenrolled_at = NULL,
			revoked_reason = NULL,
			revoked_by = NULL,
			enrollment_version = enrollment_version + 1
		WHERE company_id = $1
			AND device_id = $2
			AND device_user_code = $3
			AND source_type = $4
			AND is_active = false
		RETURNING
			mapping_id,
			company_id,
			user_id,
			device_id,
			source_type,
			device_user_code,
			is_active,
			enrollment_version,
			enrolled_at,
			unenrolled_at,
			revoked_reason,
			created_by,
			revoked_by
	`

	row := r.client.QueryRow(
		ctx,
		query,
		companyID,
		deviceID,
		deviceUserCode,
		sourceType,
	)

	return r.scanEnrollment(row)
}

func (r *deviceEnrollmentRepository) GetRevokedEnrollmentsByDevice(
	ctx context.Context,
	companyID uuid.UUID,
	deviceID string,
) ([]*attendance.UserDeviceIdentifier, error) {

	query := `
		SELECT
			mapping_id,
			company_id,
			user_id,
			device_id,
			source_type,
			device_user_code,
			is_active,
			enrollment_version,
			enrolled_at,
			unenrolled_at,
			revoked_reason,
			created_by,
			revoked_by
		FROM attendance_user_device_identifiers
		WHERE company_id = $1
			AND device_id = $2
			AND is_active = false
		ORDER BY unenrolled_at DESC
	`

	rows, err := r.client.Query(ctx, query, companyID, deviceID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var result []*attendance.UserDeviceIdentifier
	for rows.Next() {
		enr, err := r.scanEnrollmentFromRows(rows)
		if err != nil {
			return nil, err
		}
		result = append(result, enr)
	}

	return result, nil
}

func (r *deviceEnrollmentRepository) scanEnrollment(
	row *sql.Row,
) (*attendance.UserDeviceIdentifier, error) {

	var e attendance.UserDeviceIdentifier
	var revokedReason sql.NullString
	var unenrolledAt sql.NullTime
	var createdBy sql.NullString
	var revokedBy sql.NullString

	err := row.Scan(
		&e.MappingID,
		&e.CompanyID,
		&e.UserID,
		&e.DeviceID,
		&e.SourceType,
		&e.DeviceUserCode,
		&e.IsActive,
		&e.EnrollmentVersion,
		&e.EnrolledAt,
		&unenrolledAt,
		&revokedReason,
		&createdBy,
		&revokedBy,
	)
	if err != nil {
		return nil, err
	}

	if unenrolledAt.Valid {
		e.UnenrolledAt = &unenrolledAt.Time
	}
	if revokedReason.Valid {
		e.RevokedReason = &revokedReason.String
	}
	if createdBy.Valid {
		if v, err := uuid.Parse(createdBy.String); err == nil {
			e.CreatedBy = &v
		}
	}
	if revokedBy.Valid {
		if v, err := uuid.Parse(revokedBy.String); err == nil {
			e.RevokedBy = &v
		}
	}

	return &e, nil
}

func (r *deviceEnrollmentRepository) scanEnrollmentFromRows(
	rows *sql.Rows,
) (*attendance.UserDeviceIdentifier, error) {

	var e attendance.UserDeviceIdentifier
	var revokedReason sql.NullString
	var unenrolledAt sql.NullTime
	var createdBy sql.NullString
	var revokedBy sql.NullString

	err := rows.Scan(
		&e.MappingID,
		&e.CompanyID,
		&e.UserID,
		&e.DeviceID,
		&e.SourceType,
		&e.DeviceUserCode,
		&e.IsActive,
		&e.EnrollmentVersion,
		&e.EnrolledAt,
		&unenrolledAt,
		&revokedReason,
		&createdBy,
		&revokedBy,
	)
	if err != nil {
		return nil, err
	}

	if unenrolledAt.Valid {
		e.UnenrolledAt = &unenrolledAt.Time
	}
	if revokedReason.Valid {
		e.RevokedReason = &revokedReason.String
	}
	if createdBy.Valid {
		if v, err := uuid.Parse(createdBy.String); err == nil {
			e.CreatedBy = &v
		}
	}
	if revokedBy.Valid {
		if v, err := uuid.Parse(revokedBy.String); err == nil {
			e.RevokedBy = &v
		}
	}

	return &e, nil
}

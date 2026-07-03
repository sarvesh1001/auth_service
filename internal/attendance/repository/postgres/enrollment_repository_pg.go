package postgres

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"time"

	"github.com/google/uuid"
	"go.uber.org/zap"

	"auth-service/internal/attendance/models"
	"auth-service/internal/attendance/repository"
	"auth-service/internal/client"
)

type enrollmentRepository struct {
	client *client.PostgresClient
	logger *zap.Logger
}

func NewDeviceEnrollmentRepository(pg *client.PostgresClient, logger *zap.Logger) repository.DeviceEnrollmentRepository {
	return &enrollmentRepository{
		client: pg,
		logger: logger.Named("enrollment_repo"),
	}
}

func (r *enrollmentRepository) Create(ctx context.Context, enrollment *models.DeviceEnrollment) error {
	if enrollment.MappingID == uuid.Nil {
		enrollment.MappingID = uuid.New()
	}
	if enrollment.EnrollmentVersion == 0 {
		enrollment.EnrollmentVersion = 1
	}
	if enrollment.EnrolledAt.IsZero() {
		enrollment.EnrolledAt = time.Now().UTC()
	}

	query := `
		INSERT INTO attendance.device_enrollments (
			mapping_id, company_id, subject_type, subject_id,
			device_id, source_type, device_user_code,
			is_active, enrollment_version,
			enrolled_at, unenrolled_at, revoked_reason, revoked_by, created_by, last_used_at
		) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15)
	`
	_, err := r.client.Exec(ctx, query,
		enrollment.MappingID,
		enrollment.CompanyID,
		enrollment.SubjectType,
		enrollment.SubjectID,
		enrollment.DeviceID,
		enrollment.SourceType,
		enrollment.DeviceUserCode,
		enrollment.IsActive,
		enrollment.EnrollmentVersion,
		enrollment.EnrolledAt,
		enrollment.UnenrolledAt,
		enrollment.RevokedReason,
		enrollment.RevokedBy,
		enrollment.CreatedBy,
		enrollment.LastUsedAt,
	)
	if err != nil {
		r.logger.Error("failed to create enrollment",
			zap.String("mapping_id", enrollment.MappingID.String()),
			zap.Error(err),
		)
		return fmt.Errorf("create enrollment: %w", err)
	}
	return nil
}

func (r *enrollmentRepository) GetActive(ctx context.Context, companyID uuid.UUID, deviceID, sourceType, deviceUserCode string) (*models.DeviceEnrollment, error) {
	query := `
		SELECT
			mapping_id, company_id, subject_type, subject_id,
			device_id, source_type, device_user_code,
			is_active, enrollment_version,
			enrolled_at, unenrolled_at, revoked_reason, revoked_by, created_by, last_used_at
		FROM attendance.device_enrollments
		WHERE company_id = $1
			AND device_id = $2
			AND source_type = $3
			AND device_user_code = $4
			AND is_active = true
	`
	row := r.client.QueryRow(ctx, query, companyID, deviceID, sourceType, deviceUserCode)
	return r.scanEnrollment(row)
}

// GetRevoked retrieves a single revoked enrollment matching the device+code+source
func (r *enrollmentRepository) GetRevoked(ctx context.Context, companyID uuid.UUID, deviceID, sourceType, deviceUserCode string) (*models.DeviceEnrollment, error) {
	query := `
		SELECT
			mapping_id, company_id, subject_type, subject_id,
			device_id, source_type, device_user_code,
			is_active, enrollment_version,
			enrolled_at, unenrolled_at, revoked_reason, revoked_by, created_by, last_used_at
		FROM attendance.device_enrollments
		WHERE company_id = $1
			AND device_id = $2
			AND source_type = $3
			AND device_user_code = $4
			AND is_active = false
		LIMIT 1
	`
	row := r.client.QueryRow(ctx, query, companyID, deviceID, sourceType, deviceUserCode)
	return r.scanEnrollment(row)
}

func (r *enrollmentRepository) GetActiveBySubject(ctx context.Context, companyID, subjectID uuid.UUID, subjectType string) ([]*models.DeviceEnrollment, error) {
	query := `
		SELECT
			mapping_id, company_id, subject_type, subject_id,
			device_id, source_type, device_user_code,
			is_active, enrollment_version,
			enrolled_at, unenrolled_at, revoked_reason, revoked_by, created_by, last_used_at
		FROM attendance.device_enrollments
		WHERE company_id = $1
			AND subject_type = $2
			AND subject_id = $3
			AND is_active = true
		ORDER BY enrolled_at DESC
	`
	rows, err := r.client.Query(ctx, query, companyID, subjectType, subjectID)
	if err != nil {
		return nil, fmt.Errorf("get active by subject: %w", err)
	}
	defer rows.Close()
	return r.scanEnrollments(rows)
}

func (r *enrollmentRepository) GetByDevice(ctx context.Context, companyID uuid.UUID, deviceID string) ([]*models.DeviceEnrollment, error) {
	query := `
		SELECT
			mapping_id, company_id, subject_type, subject_id,
			device_id, source_type, device_user_code,
			is_active, enrollment_version,
			enrolled_at, unenrolled_at, revoked_reason, revoked_by, created_by, last_used_at
		FROM attendance.device_enrollments
		WHERE company_id = $1 AND device_id = $2
		ORDER BY enrolled_at DESC
	`
	rows, err := r.client.Query(ctx, query, companyID, deviceID)
	if err != nil {
		return nil, fmt.Errorf("get by device: %w", err)
	}
	defer rows.Close()
	return r.scanEnrollments(rows)
}

func (r *enrollmentRepository) GetRevokedByDevice(ctx context.Context, companyID uuid.UUID, deviceID string) ([]*models.DeviceEnrollment, error) {
	query := `
		SELECT
			mapping_id, company_id, subject_type, subject_id,
			device_id, source_type, device_user_code,
			is_active, enrollment_version,
			enrolled_at, unenrolled_at, revoked_reason, revoked_by, created_by, last_used_at
		FROM attendance.device_enrollments
		WHERE company_id = $1 AND device_id = $2 AND is_active = false
		ORDER BY unenrolled_at DESC
	`
	rows, err := r.client.Query(ctx, query, companyID, deviceID)
	if err != nil {
		return nil, fmt.Errorf("get revoked by device: %w", err)
	}
	defer rows.Close()
	return r.scanEnrollments(rows)
}

func (r *enrollmentRepository) Revoke(ctx context.Context, mappingID uuid.UUID, reason string, revokedBy *uuid.UUID) error {
	query := `
		UPDATE attendance.device_enrollments
		SET is_active = false,
			unenrolled_at = NOW(),
			revoked_reason = $2,
			revoked_by = $3,
			enrollment_version = enrollment_version + 1
		WHERE mapping_id = $1 AND is_active = true
	`
	result, err := r.client.Exec(ctx, query, mappingID, reason, revokedBy)
	if err != nil {
		return fmt.Errorf("revoke: %w", err)
	}
	rows, _ := result.RowsAffected()
	if rows == 0 {
		return errors.New("no active enrollment found to revoke")
	}
	return nil
}

func (r *enrollmentRepository) Unrevoke(ctx context.Context, mappingID uuid.UUID, reason string, actedBy *uuid.UUID) error {
	query := `
		UPDATE attendance.device_enrollments
		SET is_active = true,
			unenrolled_at = NULL,
			revoked_reason = NULL,
			revoked_by = NULL,
			enrollment_version = enrollment_version + 1
		WHERE mapping_id = $1 AND is_active = false
	`
	result, err := r.client.Exec(ctx, query, mappingID)
	if err != nil {
		return fmt.Errorf("unrevoke: %w", err)
	}
	rows, _ := result.RowsAffected()
	if rows == 0 {
		return errors.New("no revoked enrollment found to unrevoke")
	}
	return nil
}

func (r *enrollmentRepository) UpdateLastUsed(ctx context.Context, mappingID uuid.UUID) error {
	query := `
		UPDATE attendance.device_enrollments
		SET last_used_at = NOW()
		WHERE mapping_id = $1
	`
	_, err := r.client.Exec(ctx, query, mappingID)
	return err
}

func (r *enrollmentRepository) ExistsActive(ctx context.Context, companyID uuid.UUID, deviceID, sourceType, deviceUserCode string) (bool, error) {
	query := `
		SELECT EXISTS (
			SELECT 1
			FROM attendance.device_enrollments
			WHERE company_id = $1
				AND device_id = $2
				AND source_type = $3
				AND device_user_code = $4
				AND is_active = true
		)
	`
	var exists bool
	err := r.client.QueryRow(ctx, query, companyID, deviceID, sourceType, deviceUserCode).Scan(&exists)
	if err != nil {
		return false, fmt.Errorf("exists active: %w", err)
	}
	return exists, nil
}

func (r *enrollmentRepository) IncrementVersion(ctx context.Context, mappingID uuid.UUID) error {
	query := `
		UPDATE attendance.device_enrollments
		SET enrollment_version = enrollment_version + 1
		WHERE mapping_id = $1
	`
	_, err := r.client.Exec(ctx, query, mappingID)
	if err != nil {
		return fmt.Errorf("increment version: %w", err)
	}
	return nil
}

// scanEnrollment scans a single row into models.DeviceEnrollment
func (r *enrollmentRepository) scanEnrollment(row *sql.Row) (*models.DeviceEnrollment, error) {
	var e models.DeviceEnrollment
	var unenrolledAt, lastUsedAt sql.NullTime
	var revokedReason, revokedBy, createdBy sql.NullString
	err := row.Scan(
		&e.MappingID,
		&e.CompanyID,
		&e.SubjectType,
		&e.SubjectID,
		&e.DeviceID,
		&e.SourceType,
		&e.DeviceUserCode,
		&e.IsActive,
		&e.EnrollmentVersion,
		&e.EnrolledAt,
		&unenrolledAt,
		&revokedReason,
		&revokedBy,
		&createdBy,
		&lastUsedAt,
	)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, nil
		}
		return nil, fmt.Errorf("scan enrollment: %w", err)
	}
	if unenrolledAt.Valid {
		e.UnenrolledAt = &unenrolledAt.Time
	}
	if lastUsedAt.Valid {
		e.LastUsedAt = &lastUsedAt.Time
	}
	if revokedReason.Valid {
		e.RevokedReason = &revokedReason.String
	}
	if revokedBy.Valid {
		if uid, err := uuid.Parse(revokedBy.String); err == nil {
			e.RevokedBy = &uid
		}
	}
	if createdBy.Valid {
		if uid, err := uuid.Parse(createdBy.String); err == nil {
			e.CreatedBy = &uid
		}
	}
	return &e, nil
}

// scanEnrollments scans multiple rows into []*models.DeviceEnrollment
func (r *enrollmentRepository) scanEnrollments(rows *sql.Rows) ([]*models.DeviceEnrollment, error) {
	var enrollments []*models.DeviceEnrollment
	for rows.Next() {
		var e models.DeviceEnrollment
		var unenrolledAt, lastUsedAt sql.NullTime
		var revokedReason, revokedBy, createdBy sql.NullString
		err := rows.Scan(
			&e.MappingID,
			&e.CompanyID,
			&e.SubjectType,
			&e.SubjectID,
			&e.DeviceID,
			&e.SourceType,
			&e.DeviceUserCode,
			&e.IsActive,
			&e.EnrollmentVersion,
			&e.EnrolledAt,
			&unenrolledAt,
			&revokedReason,
			&revokedBy,
			&createdBy,
			&lastUsedAt,
		)
		if err != nil {
			return nil, fmt.Errorf("scan enrollment row: %w", err)
		}
		if unenrolledAt.Valid {
			e.UnenrolledAt = &unenrolledAt.Time
		}
		if lastUsedAt.Valid {
			e.LastUsedAt = &lastUsedAt.Time
		}
		if revokedReason.Valid {
			e.RevokedReason = &revokedReason.String
		}
		if revokedBy.Valid {
			if uid, err := uuid.Parse(revokedBy.String); err == nil {
				e.RevokedBy = &uid
			}
		}
		if createdBy.Valid {
			if uid, err := uuid.Parse(createdBy.String); err == nil {
				e.CreatedBy = &uid
			}
		}
		enrollments = append(enrollments, &e)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("rows iteration: %w", err)
	}
	return enrollments, nil
}

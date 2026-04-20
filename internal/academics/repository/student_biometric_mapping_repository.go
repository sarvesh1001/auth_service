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

type StudentBiometricMappingRepository interface {
	// Create adds a new mapping.
	Create(ctx context.Context, db DBTX, m *models.StudentBiometricMapping) error

	// GetByID retrieves a mapping by its primary key.
	GetByID(ctx context.Context, db DBTX, mappingID uuid.UUID) (*models.StudentBiometricMapping, error)

	// GetByDeviceAndUserCode finds the active mapping for a given device and user code.
	GetByDeviceAndUserCode(ctx context.Context, db DBTX, deviceID, deviceUserCode string) (*models.StudentBiometricMapping, error)

	// GetActiveByStudent returns the active mapping for a student (across any device).
	GetActiveByStudent(ctx context.Context, db DBTX, studentID uuid.UUID) (*models.StudentBiometricMapping, error)

	// List returns mappings with optional filters.
	List(ctx context.Context, db DBTX, filter BiometricMappingFilter, p Pagination, s Sort) ([]*models.StudentBiometricMapping, error)

	// Count returns the number of mappings matching the filter.
	Count(ctx context.Context, db DBTX, filter BiometricMappingFilter) (int64, error)

	// Update updates an existing mapping (only certain fields).
	Update(ctx context.Context, db DBTX, m *models.StudentBiometricMapping) error

	// Delete soft‑deletes? Hard delete? We'll do hard delete as per pattern.
	Delete(ctx context.Context, db DBTX, mappingID uuid.UUID) error

	// DeactivateByStudent sets is_active=false for all mappings of a student.
	DeactivateByStudent(ctx context.Context, db DBTX, studentID uuid.UUID) error
}

// BiometricMappingFilter used for List/Count.
type BiometricMappingFilter struct {
	StudentID      *uuid.UUID
	CompanyID      *uuid.UUID
	DeviceID       *string
	DeviceUserCode *string
	IsActive       *bool
}

type studentBiometricMappingRepository struct {
	logger *zap.Logger
}

func NewStudentBiometricMappingRepository(logger *zap.Logger) StudentBiometricMappingRepository {
	return &studentBiometricMappingRepository{
		logger: logger.Named("student_biometric_repo"),
	}
}

var allowedBiometricMappingSortFields = map[string]bool{
	"created_at":  true,
	"enrolled_at": true,
	"device_id":   true,
	"student_id":  true,
	"company_id":  true,
	"is_active":   true,
}

func (r *studentBiometricMappingRepository) validateSort(s Sort) (string, error) {
	field := s.Field
	if field == "" {
		field = "created_at"
	}
	if !allowedBiometricMappingSortFields[field] {
		return "", fmt.Errorf("invalid sort field: %s", field)
	}
	dir := strings.ToUpper(s.Direction)
	if dir != "ASC" && dir != "DESC" {
		dir = "DESC"
	}
	return fmt.Sprintf("ORDER BY m.%s %s", field, dir), nil
}

func (r *studentBiometricMappingRepository) validatePagination(p Pagination) (int, int) {
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

func (r *studentBiometricMappingRepository) buildFilter(filter BiometricMappingFilter) (string, []interface{}) {
	var conditions []string
	var args []interface{}
	idx := 1

	if filter.StudentID != nil {
		conditions = append(conditions, fmt.Sprintf("m.student_id = $%d", idx))
		args = append(args, *filter.StudentID)
		idx++
	}
	if filter.CompanyID != nil {
		conditions = append(conditions, fmt.Sprintf("m.company_id = $%d", idx))
		args = append(args, *filter.CompanyID)
		idx++
	}
	if filter.DeviceID != nil {
		conditions = append(conditions, fmt.Sprintf("m.device_id = $%d", idx))
		args = append(args, *filter.DeviceID)
		idx++
	}
	if filter.DeviceUserCode != nil {
		conditions = append(conditions, fmt.Sprintf("m.device_user_code = $%d", idx))
		args = append(args, *filter.DeviceUserCode)
		idx++
	}
	if filter.IsActive != nil {
		conditions = append(conditions, fmt.Sprintf("m.is_active = $%d", idx))
		args = append(args, *filter.IsActive)
		idx++
	}

	if len(conditions) == 0 {
		return "", args
	}
	return "WHERE " + strings.Join(conditions, " AND "), args
}

func (r *studentBiometricMappingRepository) Create(ctx context.Context, db DBTX, m *models.StudentBiometricMapping) error {
	query := `
		INSERT INTO academics.student_biometric_mapping (
			student_id, company_id, device_id, device_user_code, is_active, enrolled_at, enrolled_by
		) VALUES ($1, $2, $3, $4, $5, $6, $7)
		RETURNING mapping_id
	`
	err := db.QueryRowContext(ctx, query,
		m.StudentID, m.CompanyID, m.DeviceID, m.DeviceUserCode,
		m.IsActive, m.EnrolledAt, m.EnrolledBy,
	).Scan(&m.MappingID)
	if err != nil {
		r.logger.Error("failed to create biometric mapping",
			util.String("student_id", m.StudentID.String()),
			util.String("device_id", m.DeviceID),
			util.ErrorField(err))
		return fmt.Errorf("create biometric mapping: %w", err)
	}
	return nil
}

func (r *studentBiometricMappingRepository) GetByID(ctx context.Context, db DBTX, mappingID uuid.UUID) (*models.StudentBiometricMapping, error) {
	query := `
		SELECT mapping_id, student_id, company_id, device_id, device_user_code,
		       is_active, enrolled_at, enrolled_by
		FROM academics.student_biometric_mapping
		WHERE mapping_id = $1
	`
	row := db.QueryRowContext(ctx, query, mappingID)
	return r.scanMapping(row)
}

func (r *studentBiometricMappingRepository) GetByDeviceAndUserCode(ctx context.Context, db DBTX, deviceID, deviceUserCode string) (*models.StudentBiometricMapping, error) {
	query := `
		SELECT mapping_id, student_id, company_id, device_id, device_user_code,
		       is_active, enrolled_at, enrolled_by
		FROM academics.student_biometric_mapping
		WHERE device_id = $1 AND device_user_code = $2 AND is_active = true
		LIMIT 1
	`
	row := db.QueryRowContext(ctx, query, deviceID, deviceUserCode)
	return r.scanMapping(row)
}

func (r *studentBiometricMappingRepository) GetActiveByStudent(ctx context.Context, db DBTX, studentID uuid.UUID) (*models.StudentBiometricMapping, error) {
	query := `
		SELECT mapping_id, student_id, company_id, device_id, device_user_code,
		       is_active, enrolled_at, enrolled_by
		FROM academics.student_biometric_mapping
		WHERE student_id = $1 AND is_active = true
		LIMIT 1
	`
	row := db.QueryRowContext(ctx, query, studentID)
	return r.scanMapping(row)
}

func (r *studentBiometricMappingRepository) List(ctx context.Context, db DBTX, filter BiometricMappingFilter, p Pagination, s Sort) ([]*models.StudentBiometricMapping, error) {
	where, args := r.buildFilter(filter)
	orderBy, err := r.validateSort(s)
	if err != nil {
		return nil, err
	}
	limit, offset := r.validatePagination(p)

	query := fmt.Sprintf(`
		SELECT mapping_id, student_id, company_id, device_id, device_user_code,
		       is_active, enrolled_at, enrolled_by
		FROM academics.student_biometric_mapping m
		%s
		%s
		LIMIT $%d OFFSET $%d
	`, where, orderBy, len(args)+1, len(args)+2)
	args = append(args, limit, offset)

	rows, err := db.QueryContext(ctx, query, args...)
	if err != nil {
		r.logger.Error("failed to list biometric mappings",
			util.Any("filter", filter),
			util.ErrorField(err))
		return nil, fmt.Errorf("list biometric mappings: %w", err)
	}
	defer rows.Close()

	var result []*models.StudentBiometricMapping
	for rows.Next() {
		m, err := r.scanMapping(rows)
		if err != nil {
			return nil, err
		}
		result = append(result, m)
	}
	if err = rows.Err(); err != nil {
		return nil, fmt.Errorf("rows iteration: %w", err)
	}
	return result, nil
}

func (r *studentBiometricMappingRepository) Count(ctx context.Context, db DBTX, filter BiometricMappingFilter) (int64, error) {
	where, args := r.buildFilter(filter)
	query := fmt.Sprintf("SELECT COUNT(*) FROM academics.student_biometric_mapping m %s", where)
	var count int64
	err := db.QueryRowContext(ctx, query, args...).Scan(&count)
	if err != nil {
		r.logger.Error("failed to count biometric mappings",
			util.Any("filter", filter),
			util.ErrorField(err))
		return 0, fmt.Errorf("count biometric mappings: %w", err)
	}
	return count, nil
}

func (r *studentBiometricMappingRepository) Update(ctx context.Context, db DBTX, m *models.StudentBiometricMapping) error {
	query := `
		UPDATE academics.student_biometric_mapping
		SET device_id = $2, device_user_code = $3, is_active = $4,
		    enrolled_at = $5, enrolled_by = $6
		WHERE mapping_id = $1
	`
	result, err := db.ExecContext(ctx, query,
		m.MappingID, m.DeviceID, m.DeviceUserCode, m.IsActive,
		m.EnrolledAt, m.EnrolledBy,
	)
	if err != nil {
		r.logger.Error("failed to update biometric mapping",
			util.String("mapping_id", m.MappingID.String()),
			util.ErrorField(err))
		return fmt.Errorf("update biometric mapping: %w", err)
	}
	rows, err := result.RowsAffected()
	if err != nil {
		return fmt.Errorf("rows affected: %w", err)
	}
	if rows == 0 {
		return fmt.Errorf("biometric mapping %s not found", m.MappingID)
	}
	return nil
}

func (r *studentBiometricMappingRepository) Delete(ctx context.Context, db DBTX, mappingID uuid.UUID) error {
	query := `DELETE FROM academics.student_biometric_mapping WHERE mapping_id = $1`
	result, err := db.ExecContext(ctx, query, mappingID)
	if err != nil {
		r.logger.Error("failed to delete biometric mapping",
			util.String("mapping_id", mappingID.String()),
			util.ErrorField(err))
		return fmt.Errorf("delete biometric mapping: %w", err)
	}
	rows, err := result.RowsAffected()
	if err != nil {
		return fmt.Errorf("rows affected: %w", err)
	}
	if rows == 0 {
		return fmt.Errorf("biometric mapping %s not found", mappingID)
	}
	return nil
}

func (r *studentBiometricMappingRepository) DeactivateByStudent(ctx context.Context, db DBTX, studentID uuid.UUID) error {
	query := `UPDATE academics.student_biometric_mapping SET is_active = false WHERE student_id = $1`
	_, err := db.ExecContext(ctx, query, studentID)
	if err != nil {
		r.logger.Error("failed to deactivate biometric mappings for student",
			util.String("student_id", studentID.String()),
			util.ErrorField(err))
		return fmt.Errorf("deactivate by student: %w", err)
	}
	return nil
}

func (r *studentBiometricMappingRepository) scanMapping(row scanner) (*models.StudentBiometricMapping, error) {
	var m models.StudentBiometricMapping
	var enrolledBy uuid.NullUUID

	err := row.Scan(
		&m.MappingID,
		&m.StudentID,
		&m.CompanyID,
		&m.DeviceID,
		&m.DeviceUserCode,
		&m.IsActive,
		&m.EnrolledAt,
		&enrolledBy,
	)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, nil
		}
		return nil, fmt.Errorf("scan mapping: %w", err)
	}
	if enrolledBy.Valid {
		m.EnrolledBy = &enrolledBy.UUID
	}
	return &m, nil
}

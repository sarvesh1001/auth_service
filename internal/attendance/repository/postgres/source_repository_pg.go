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
	"auth-service/internal/util"
)

type sourceRepository struct {
	client *client.PostgresClient
	logger *zap.Logger
}

func NewSourceRepository(pg *client.PostgresClient, logger *zap.Logger) repository.SourceRepository {
	return &sourceRepository{
		client: pg,
		logger: logger.Named("source_repo"),
	}
}

// ── Source Types ──

func (r *sourceRepository) GetSourceTypes(ctx context.Context, activeOnly bool) ([]*models.AttendanceSourceType, error) {
	query := `
		SELECT source_type, description, category, requires_device,
		       is_system, allow_backdated, allow_future, trust_level,
		       is_self_service, created_at
		FROM attendance.attendance_source_types
	`
	if activeOnly {
		query += " WHERE is_active = true"
	}
	query += " ORDER BY source_type"

	rows, err := r.client.Query(ctx, query)
	if err != nil {
		r.logger.Error("failed to get source types", util.ErrorField(err))
		return nil, fmt.Errorf("get source types: %w", err)
	}
	defer rows.Close()

	var types []*models.AttendanceSourceType
	for rows.Next() {
		var st models.AttendanceSourceType
		err := rows.Scan(
			&st.SourceType,
			&st.Description,
			&st.Category,
			&st.RequiresDevice,
			&st.IsSystem,
			&st.AllowBackdated,
			&st.AllowFuture,
			&st.TrustLevel,
			&st.IsSelfService,
			&st.CreatedAt,
		)
		if err != nil {
			return nil, fmt.Errorf("scan source type: %w", err)
		}
		types = append(types, &st)
	}
	return types, nil
}

func (r *sourceRepository) GetSourceTypeByType(ctx context.Context, sourceType string) (*models.AttendanceSourceType, error) {
	query := `
		SELECT source_type, description, category, requires_device,
		       is_system, allow_backdated, allow_future, trust_level,
		       is_self_service, created_at
		FROM attendance.attendance_source_types
		WHERE source_type = $1
	`
	row := r.client.QueryRow(ctx, query, sourceType)
	var st models.AttendanceSourceType
	err := row.Scan(
		&st.SourceType,
		&st.Description,
		&st.Category,
		&st.RequiresDevice,
		&st.IsSystem,
		&st.AllowBackdated,
		&st.AllowFuture,
		&st.TrustLevel,
		&st.IsSelfService,
		&st.CreatedAt,
	)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, nil
		}
		return nil, fmt.Errorf("get source type by type: %w", err)
	}
	return &st, nil
}

// ── Sources ──

func (r *sourceRepository) Create(ctx context.Context, tx *sql.Tx, source *models.AttendanceSource) error {
	if source.SourceID == uuid.Nil {
		source.SourceID = uuid.New()
	}
	now := time.Now().UTC()
	if source.CreatedAt.IsZero() {
		source.CreatedAt = now
	}

	query := `
		INSERT INTO attendance.attendance_sources (
			source_id, company_id, source_type, name,
			reference_type, reference_id, is_active,
			created_at, created_by
		) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)
	`

	exec := func(q string, args ...interface{}) (sql.Result, error) {
		if tx != nil {
			return tx.ExecContext(ctx, q, args...)
		}
		return r.client.Exec(ctx, q, args...)
	}

	_, err := exec(query,
		source.SourceID,
		source.CompanyID,
		source.SourceType,
		source.Name,
		source.ReferenceType,
		source.ReferenceID,
		source.IsActive,
		source.CreatedAt,
		source.CreatedBy,
	)
	if err != nil {
		r.logger.Error("failed to create attendance source",
			util.String("source_id", source.SourceID.String()),
			util.ErrorField(err))
		return fmt.Errorf("create source: %w", err)
	}
	return nil
}

func (r *sourceRepository) GetByID(ctx context.Context, sourceID uuid.UUID) (*models.AttendanceSource, error) {
	query := `
		SELECT source_id, company_id, source_type, name,
		       reference_type, reference_id, is_active,
		       created_at, created_by
		FROM attendance.attendance_sources
		WHERE source_id = $1
	`
	row := r.client.QueryRow(ctx, query, sourceID)
	return r.scanSource(row)
}

func (r *sourceRepository) GetByCompany(ctx context.Context, companyID uuid.UUID, activeOnly bool) ([]*models.AttendanceSource, error) {
	query := `
		SELECT source_id, company_id, source_type, name,
		       reference_type, reference_id, is_active,
		       created_at, created_by
		FROM attendance.attendance_sources
		WHERE company_id = $1
	`
	if activeOnly {
		query += " AND is_active = true"
	}
	query += " ORDER BY name"

	rows, err := r.client.Query(ctx, query, companyID)
	if err != nil {
		r.logger.Error("failed to get sources by company",
			util.String("company_id", companyID.String()),
			util.ErrorField(err))
		return nil, fmt.Errorf("get sources by company: %w", err)
	}
	defer rows.Close()

	var sources []*models.AttendanceSource
	for rows.Next() {
		s, err := r.scanSourceFromRows(rows)
		if err != nil {
			return nil, err
		}
		sources = append(sources, s)
	}
	return sources, nil
}

func (r *sourceRepository) GetByType(ctx context.Context, companyID uuid.UUID, sourceType string) (*models.AttendanceSource, error) {
	query := `
		SELECT source_id, company_id, source_type, name,
		       reference_type, reference_id, is_active,
		       created_at, created_by
		FROM attendance.attendance_sources
		WHERE company_id = $1 AND source_type = $2
	`
	row := r.client.QueryRow(ctx, query, companyID, sourceType)
	return r.scanSource(row)
}

func (r *sourceRepository) Update(ctx context.Context, tx *sql.Tx, source *models.AttendanceSource) error {
	query := `
		UPDATE attendance.attendance_sources SET
			name = $1,
			reference_type = $2,
			reference_id = $3,
			is_active = $4
		WHERE source_id = $5
	`

	exec := func(q string, args ...interface{}) (sql.Result, error) {
		if tx != nil {
			return tx.ExecContext(ctx, q, args...)
		}
		return r.client.Exec(ctx, q, args...)
	}

	result, err := exec(query,
		source.Name,
		source.ReferenceType,
		source.ReferenceID,
		source.IsActive,
		source.SourceID,
	)
	if err != nil {
		r.logger.Error("failed to update source",
			util.String("source_id", source.SourceID.String()),
			util.ErrorField(err))
		return fmt.Errorf("update source: %w", err)
	}
	rows, _ := result.RowsAffected()
	if rows == 0 {
		return errors.New("source not found")
	}
	return nil
}

func (r *sourceRepository) Delete(ctx context.Context, sourceID uuid.UUID) error {
	query := `DELETE FROM attendance.attendance_sources WHERE source_id = $1`
	result, err := r.client.Exec(ctx, query, sourceID)
	if err != nil {
		r.logger.Error("failed to delete source",
			util.String("source_id", sourceID.String()),
			util.ErrorField(err))
		return fmt.Errorf("delete source: %w", err)
	}
	rows, _ := result.RowsAffected()
	if rows == 0 {
		return errors.New("source not found")
	}
	return nil
}

func (r *sourceRepository) HealthCheck(ctx context.Context) error {
	_, err := r.client.Exec(ctx, `SELECT 1 FROM attendance.attendance_sources LIMIT 1`)
	if err != nil {
		r.logger.Error("source repo health check failed", util.ErrorField(err))
		return fmt.Errorf("health check: %w", err)
	}
	return nil
}

// ── Scanners ──

func (r *sourceRepository) scanSource(row *sql.Row) (*models.AttendanceSource, error) {
	var s models.AttendanceSource
	err := row.Scan(
		&s.SourceID,
		&s.CompanyID,
		&s.SourceType,
		&s.Name,
		&s.ReferenceType,
		&s.ReferenceID,
		&s.IsActive,
		&s.CreatedAt,
		&s.CreatedBy,
	)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, nil
		}
		return nil, fmt.Errorf("scan source: %w", err)
	}
	return &s, nil
}

func (r *sourceRepository) scanSourceFromRows(rows *sql.Rows) (*models.AttendanceSource, error) {
	var s models.AttendanceSource
	err := rows.Scan(
		&s.SourceID,
		&s.CompanyID,
		&s.SourceType,
		&s.Name,
		&s.ReferenceType,
		&s.ReferenceID,
		&s.IsActive,
		&s.CreatedAt,
		&s.CreatedBy,
	)
	if err != nil {
		return nil, fmt.Errorf("scan source rows: %w", err)
	}
	return &s, nil
}
func (r *sourceRepository) GetEventTypes(ctx context.Context, activeOnly bool) ([]*models.AttendanceEventType, error) {
	query := `
		SELECT event_type, category, description,
		       is_user_triggered, is_system_generated, is_active
		FROM attendance.attendance_event_types
	`
	if activeOnly {
		query += " WHERE is_active = true"
	}
	query += " ORDER BY event_type"

	rows, err := r.client.Query(ctx, query)
	if err != nil {
		r.logger.Error("failed to get event types", util.ErrorField(err))
		return nil, fmt.Errorf("get event types: %w", err)
	}
	defer rows.Close()

	var types []*models.AttendanceEventType
	for rows.Next() {
		var et models.AttendanceEventType
		err := rows.Scan(
			&et.EventType,
			&et.Category,
			&et.Description,
			&et.IsUserTriggered,
			&et.IsSystemGenerated,
			&et.IsActive,
		)
		if err != nil {
			return nil, fmt.Errorf("scan event type: %w", err)
		}
		types = append(types, &et)
	}
	return types, nil
}

package repository

import (
	"context"
	"database/sql"
	"fmt"
	"strings"
	"time"

	"github.com/google/uuid"
	"go.uber.org/zap"

	"auth-service/internal/academics/models"
	"auth-service/internal/util"
)

// AcademicEventRepository defines database operations for academic events.
type AcademicEventRepository interface {
	Create(ctx context.Context, db DBTX, event *models.AcademicEvent) error
	GetByID(ctx context.Context, db DBTX, id uuid.UUID) (*models.AcademicEvent, error)
	GetByIDs(ctx context.Context, db DBTX, ids []uuid.UUID) ([]*models.AcademicEvent, error)
	List(ctx context.Context, db DBTX, filter AcademicEventFilter, p Pagination, s Sort) ([]*models.AcademicEvent, error)
	Count(ctx context.Context, db DBTX, filter AcademicEventFilter) (int64, error)
	Update(ctx context.Context, db DBTX, event *models.AcademicEvent) error
	Delete(ctx context.Context, db DBTX, id uuid.UUID) error
	// Domain helpers
	GetByCompany(ctx context.Context, db DBTX, companyID uuid.UUID, p Pagination, s Sort) ([]*models.AcademicEvent, error)
	GetByDateRange(ctx context.Context, db DBTX, companyID uuid.UUID, from, to time.Time) ([]*models.AcademicEvent, error)
}

// AcademicEventFilter defines filter criteria for academic events.
type AcademicEventFilter struct {
	CompanyID     uuid.UUID
	EventDateFrom *time.Time
	EventDateTo   *time.Time
	Location      string
	Search        string // matches event_name, location, description
}

type academicEventRepository struct {
	logger *zap.Logger
}

// NewAcademicEventRepository creates a new academic event repository.
func NewAcademicEventRepository(logger *zap.Logger) AcademicEventRepository {
	return &academicEventRepository{
		logger: logger.Named("academic_event_repo"),
	}
}

var allowedAcademicEventSortFields = map[string]bool{
	"event_date": true,
	"event_name": true,
	"created_at": true,
	"updated_at": true,
	"location":   true,
}

func (r *academicEventRepository) validateSort(s Sort) (string, error) {
	field := s.Field
	if field == "" {
		field = "event_date"
	}
	if !allowedAcademicEventSortFields[field] {
		return "", fmt.Errorf("invalid sort field: %s", field)
	}
	dir := strings.ToUpper(s.Direction)
	if dir != "ASC" && dir != "DESC" {
		dir = "ASC"
	}
	return fmt.Sprintf("ORDER BY e.%s %s", field, dir), nil
}

func (r *academicEventRepository) validatePagination(p Pagination) (int, int) {
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

// buildAcademicEventFilter constructs WHERE clause and arguments.
func (r *academicEventRepository) buildAcademicEventFilter(filter AcademicEventFilter) (string, []interface{}) {
	var conditions []string
	var args []interface{}
	idx := 1

	if filter.CompanyID != uuid.Nil {
		conditions = append(conditions, fmt.Sprintf("e.company_id = $%d", idx))
		args = append(args, filter.CompanyID)
		idx++
	}

	if filter.EventDateFrom != nil {
		conditions = append(conditions, fmt.Sprintf("e.event_date >= $%d", idx))
		args = append(args, *filter.EventDateFrom)
		idx++
	}

	if filter.EventDateTo != nil {
		conditions = append(conditions, fmt.Sprintf("e.event_date <= $%d", idx))
		args = append(args, *filter.EventDateTo)
		idx++
	}

	if filter.Location != "" {
		conditions = append(conditions, fmt.Sprintf("e.location ILIKE $%d", idx))
		args = append(args, "%"+filter.Location+"%")
		idx++
	}

	if filter.Search != "" {
		searchTerm := "%" + filter.Search + "%"
		conditions = append(conditions, fmt.Sprintf("(e.event_name ILIKE $%d OR e.location ILIKE $%d OR e.description ILIKE $%d)", idx, idx, idx))
		args = append(args, searchTerm, searchTerm, searchTerm)
		idx++
	}

	if len(conditions) == 0 {
		return "", args
	}
	return "WHERE " + strings.Join(conditions, " AND "), args
}

// Create inserts a new academic event.
func (r *academicEventRepository) Create(ctx context.Context, db DBTX, event *models.AcademicEvent) error {
	query := `
        INSERT INTO academics.academic_events (
            company_id, event_name, event_date, start_time, end_time,
            location, description, created_by, created_at, updated_at
        ) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, NOW(), NOW())
        RETURNING event_id, created_at, updated_at
    `
	err := db.QueryRowContext(ctx, query,
		event.CompanyID, event.EventName, event.EventDate, event.StartTime, event.EndTime,
		event.Location, event.Description, event.CreatedBy,
	).Scan(&event.EventID, &event.CreatedAt, &event.UpdatedAt)
	if err != nil {
		r.logger.Error("failed to create academic event",
			util.String("company_id", event.CompanyID.String()),
			util.String("event_name", event.EventName),
			util.ErrorField(err))
		return fmt.Errorf("create academic event: %w", err)
	}
	return nil
}

// GetByID retrieves an academic event by its ID.
func (r *academicEventRepository) GetByID(ctx context.Context, db DBTX, id uuid.UUID) (*models.AcademicEvent, error) {
	query := `
        SELECT event_id, company_id, event_name, event_date, start_time, end_time,
               location, description, created_by, created_at, updated_at
        FROM academics.academic_events
        WHERE event_id = $1
    `
	row := db.QueryRowContext(ctx, query, id)
	return r.scanAcademicEvent(row)
}

// GetByIDs retrieves multiple academic events by their IDs.
func (r *academicEventRepository) GetByIDs(ctx context.Context, db DBTX, ids []uuid.UUID) ([]*models.AcademicEvent, error) {
	if len(ids) == 0 {
		return []*models.AcademicEvent{}, nil
	}
	placeholders := make([]string, len(ids))
	args := make([]interface{}, len(ids))
	for i, id := range ids {
		placeholders[i] = fmt.Sprintf("$%d", i+1)
		args[i] = id
	}
	query := fmt.Sprintf(`
        SELECT event_id, company_id, event_name, event_date, start_time, end_time,
               location, description, created_by, created_at, updated_at
        FROM academics.academic_events
        WHERE event_id IN (%s)
    `, strings.Join(placeholders, ","))

	rows, err := db.QueryContext(ctx, query, args...)
	if err != nil {
		r.logger.Error("failed to get academic events by IDs", zap.Error(err))
		return nil, fmt.Errorf("get academic events by IDs: %w", err)
	}
	defer rows.Close()

	var result []*models.AcademicEvent
	for rows.Next() {
		event, err := r.scanAcademicEvent(rows)
		if err != nil {
			return nil, err
		}
		result = append(result, event)
	}
	if err = rows.Err(); err != nil {
		return nil, fmt.Errorf("rows iteration: %w", err)
	}
	return result, nil
}

// List returns a paginated list of academic events matching the filter.
func (r *academicEventRepository) List(ctx context.Context, db DBTX, filter AcademicEventFilter, p Pagination, s Sort) ([]*models.AcademicEvent, error) {
	where, args := r.buildAcademicEventFilter(filter)
	orderBy, err := r.validateSort(s)
	if err != nil {
		return nil, err
	}
	limit, offset := r.validatePagination(p)

	query := fmt.Sprintf(`
        SELECT event_id, company_id, event_name, event_date, start_time, end_time,
               location, description, created_by, created_at, updated_at
        FROM academics.academic_events e
        %s
        %s
        LIMIT $%d OFFSET $%d
    `, where, orderBy, len(args)+1, len(args)+2)

	args = append(args, limit, offset)

	rows, err := db.QueryContext(ctx, query, args...)
	if err != nil {
		r.logger.Error("failed to list academic events",
			util.Any("filter", filter),
			util.ErrorField(err))
		return nil, fmt.Errorf("list academic events: %w", err)
	}
	defer rows.Close()

	var result []*models.AcademicEvent
	for rows.Next() {
		event, err := r.scanAcademicEvent(rows)
		if err != nil {
			return nil, err
		}
		result = append(result, event)
	}
	if err = rows.Err(); err != nil {
		return nil, fmt.Errorf("rows iteration: %w", err)
	}
	return result, nil
}

// Count returns the number of academic events matching the filter.
func (r *academicEventRepository) Count(ctx context.Context, db DBTX, filter AcademicEventFilter) (int64, error) {
	where, args := r.buildAcademicEventFilter(filter)
	query := fmt.Sprintf("SELECT COUNT(*) FROM academics.academic_events e %s", where)

	var count int64
	err := db.QueryRowContext(ctx, query, args...).Scan(&count)
	if err != nil {
		r.logger.Error("failed to count academic events",
			util.Any("filter", filter),
			util.ErrorField(err))
		return 0, fmt.Errorf("count academic events: %w", err)
	}
	return count, nil
}

// Update modifies an existing academic event.
func (r *academicEventRepository) Update(ctx context.Context, db DBTX, event *models.AcademicEvent) error {
	query := `
        UPDATE academics.academic_events
        SET
            event_name = $2,
            event_date = $3,
            start_time = $4,
            end_time = $5,
            location = $6,
            description = $7,
            updated_at = NOW()
        WHERE event_id = $1
        RETURNING updated_at
    `
	err := db.QueryRowContext(ctx, query,
		event.EventID,
		event.EventName,
		event.EventDate,
		event.StartTime,
		event.EndTime,
		event.Location,
		event.Description,
	).Scan(&event.UpdatedAt)

	if err != nil {
		if err == sql.ErrNoRows {
			return fmt.Errorf("%w: academic event %s", ErrNotFound, event.EventID)
		}
		r.logger.Error("failed to update academic event",
			util.String("id", event.EventID.String()),
			util.ErrorField(err))
		return fmt.Errorf("update academic event: %w", err)
	}
	return nil
}

// Delete removes an academic event permanently (no soft delete).
func (r *academicEventRepository) Delete(ctx context.Context, db DBTX, id uuid.UUID) error {
	query := `DELETE FROM academics.academic_events WHERE event_id = $1`
	result, err := db.ExecContext(ctx, query, id)
	if err != nil {
		r.logger.Error("failed to delete academic event",
			util.String("id", id.String()),
			util.ErrorField(err))
		return fmt.Errorf("delete academic event: %w", err)
	}
	rows, err := result.RowsAffected()
	if err != nil {
		return fmt.Errorf("rows affected: %w", err)
	}
	if rows == 0 {
		return fmt.Errorf("%w: academic event %s", ErrNotFound, id)
	}
	return nil
}

// GetByCompany returns all events for a company with pagination.
func (r *academicEventRepository) GetByCompany(ctx context.Context, db DBTX, companyID uuid.UUID, p Pagination, s Sort) ([]*models.AcademicEvent, error) {
	filter := AcademicEventFilter{CompanyID: companyID}
	return r.List(ctx, db, filter, p, s)
}

// GetByDateRange returns events for a company within a date range.
func (r *academicEventRepository) GetByDateRange(ctx context.Context, db DBTX, companyID uuid.UUID, from, to time.Time) ([]*models.AcademicEvent, error) {
	filter := AcademicEventFilter{
		CompanyID:     companyID,
		EventDateFrom: &from,
		EventDateTo:   &to,
	}
	// Use default pagination (limit 1000) to retrieve all.
	return r.List(ctx, db, filter, Pagination{Limit: 1000}, Sort{Field: "event_date", Direction: "ASC"})
}

// scanAcademicEvent scans a row into an AcademicEvent struct.
func (r *academicEventRepository) scanAcademicEvent(row scanner) (*models.AcademicEvent, error) {
	var event models.AcademicEvent
	var startTime, endTime sql.NullTime
	var createdBy uuid.NullUUID

	err := row.Scan(
		&event.EventID,
		&event.CompanyID,
		&event.EventName,
		&event.EventDate,
		&startTime,
		&endTime,
		&event.Location,
		&event.Description,
		&createdBy,
		&event.CreatedAt,
		&event.UpdatedAt,
	)
	if err != nil {
		if err == sql.ErrNoRows {
			return nil, nil
		}
		return nil, fmt.Errorf("scan academic event: %w", err)
	}

	if startTime.Valid {
		event.StartTime = &startTime.Time
	}
	if endTime.Valid {
		event.EndTime = &endTime.Time
	}
	if createdBy.Valid {
		event.CreatedBy = &createdBy.UUID
	}
	return &event, nil
}

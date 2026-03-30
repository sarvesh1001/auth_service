// File: internal/academics/repository/room_repository.go
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

// RoomRepository defines all database operations for rooms.
type RoomRepository interface {
	Create(ctx context.Context, db DBTX, r *models.Room) error
	GetByID(ctx context.Context, db DBTX, id uuid.UUID) (*models.Room, error)
	GetByCode(ctx context.Context, db DBTX, companyID uuid.UUID, code string) (*models.Room, error)
	GetByIDs(ctx context.Context, db DBTX, ids []uuid.UUID) ([]*models.Room, error)
	List(ctx context.Context, db DBTX, filter RoomFilter, p Pagination, s Sort) ([]*models.Room, error)
	Count(ctx context.Context, db DBTX, filter RoomFilter) (int64, error)
	Update(ctx context.Context, db DBTX, r *models.Room) error
	Delete(ctx context.Context, db DBTX, id uuid.UUID, deletedBy *uuid.UUID) error
	BulkCreate(ctx context.Context, db DBTX, rooms []*models.Room) error
	Activate(ctx context.Context, db DBTX, id uuid.UUID, updatedBy *uuid.UUID) error
	Deactivate(ctx context.Context, db DBTX, id uuid.UUID, updatedBy *uuid.UUID) error
	ExistsByCode(ctx context.Context, db DBTX, companyID uuid.UUID, code string) (bool, error)
	// Domain queries
	ListByBuilding(ctx context.Context, db DBTX, companyID uuid.UUID, building string) ([]*models.Room, error)
}

type roomRepository struct {
	logger *zap.Logger
}

func NewRoomRepository(logger *zap.Logger) RoomRepository {
	return &roomRepository{
		logger: logger.Named("room_repo"),
	}
}

var allowedRoomSortFields = map[string]bool{
	"created_at": true,
	"updated_at": true,
	"room_code":  true,
	"room_name":  true,
	"capacity":   true,
	"building":   true,
	"floor":      true,
	"is_active":  true,
}

func (r *roomRepository) validateSort(s Sort) (string, error) {
	field := s.Field
	if field == "" {
		field = "created_at"
	}
	if !allowedRoomSortFields[field] {
		return "", fmt.Errorf("invalid sort field: %s", field)
	}
	dir := strings.ToUpper(s.Direction)
	if dir != "ASC" && dir != "DESC" {
		dir = "DESC"
	}
	return fmt.Sprintf("ORDER BY r.%s %s", field, dir), nil
}

func (r *roomRepository) validatePagination(p Pagination) (int, int) {
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

func (r *roomRepository) buildRoomFilter(filter RoomFilter) (string, []interface{}) {
	var conditions []string
	var args []interface{}
	idx := 1

	if filter.CompanyID != uuid.Nil {
		conditions = append(conditions, fmt.Sprintf("r.company_id = $%d", idx))
		args = append(args, filter.CompanyID)
		idx++
	}

	if filter.RoomCode != "" {
		conditions = append(conditions, fmt.Sprintf("r.room_code = $%d", idx))
		args = append(args, filter.RoomCode)
		idx++
	}

	if filter.IsActive != nil {
		conditions = append(conditions, fmt.Sprintf("r.is_active = $%d", idx))
		args = append(args, *filter.IsActive)
		idx++
	}

	if filter.Building != "" {
		conditions = append(conditions, fmt.Sprintf("r.building = $%d", idx))
		args = append(args, filter.Building)
		idx++
	}

	if filter.MinCapacity != nil {
		conditions = append(conditions, fmt.Sprintf("r.capacity >= $%d", idx))
		args = append(args, *filter.MinCapacity)
		idx++
	}

	if filter.MaxCapacity != nil {
		conditions = append(conditions, fmt.Sprintf("r.capacity <= $%d", idx))
		args = append(args, *filter.MaxCapacity)
		idx++
	}

	if filter.Search != "" {
		conditions = append(conditions, fmt.Sprintf("(r.room_code ILIKE $%d OR r.room_name ILIKE $%d)", idx, idx))
		args = append(args, "%"+filter.Search+"%")
		idx++
	}

	conditions = append(conditions, "r.deleted_at IS NULL")

	if len(conditions) == 0 {
		return "", args
	}
	return "WHERE " + strings.Join(conditions, " AND "), args
}

// --- Create ------------------------------------------------------------

func (r *roomRepository) Create(ctx context.Context, db DBTX, room *models.Room) error {
	query := `
        INSERT INTO academics.rooms (
            company_id, room_code, room_name, capacity, building, floor, is_active,
            created_by, updated_by, created_at, updated_at
        ) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, NOW(), NOW())
        RETURNING room_id, created_at, updated_at
    `
	err := db.QueryRowContext(ctx, query,
		room.CompanyID, room.RoomCode, room.RoomName, room.Capacity, room.Building, room.Floor, room.IsActive,
		room.CreatedBy, room.UpdatedBy,
	).Scan(&room.RoomID, &room.CreatedAt, &room.UpdatedAt)

	if err != nil {
		r.logger.Error("failed to create room",
			util.String("company_id", room.CompanyID.String()),
			util.String("room_code", room.RoomCode),
			util.ErrorField(err))
		return fmt.Errorf("create room: %w", err)
	}
	return nil
}

// --- BulkCreate ---------------------------------------------------------

func (r *roomRepository) BulkCreate(ctx context.Context, db DBTX, rooms []*models.Room) error {
	if len(rooms) == 0 {
		return nil
	}
	tx, isOwner, err := beginTxIfNotTx(ctx, db)
	if err != nil {
		return err
	}
	needRollback := isOwner
	defer func() {
		if needRollback {
			_ = tx.Rollback()
		}
	}()

	stmt, err := tx.PrepareContext(ctx, `
        INSERT INTO academics.rooms (
            company_id, room_code, room_name, capacity, building, floor, is_active,
            created_by, updated_by, created_at, updated_at
        ) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, NOW(), NOW())
        RETURNING room_id, created_at, updated_at
    `)
	if err != nil {
		return fmt.Errorf("prepare statement: %w", err)
	}
	defer stmt.Close()

	for _, room := range rooms {
		err := stmt.QueryRowContext(ctx,
			room.CompanyID, room.RoomCode, room.RoomName, room.Capacity, room.Building, room.Floor, room.IsActive,
			room.CreatedBy, room.UpdatedBy,
		).Scan(&room.RoomID, &room.CreatedAt, &room.UpdatedAt)
		if err != nil {
			r.logger.Error("bulk create room failed",
				util.String("company_id", room.CompanyID.String()),
				util.String("room_code", room.RoomCode),
				util.ErrorField(err))
			return fmt.Errorf("bulk create room row: %w", err)
		}
	}

	if isOwner {
		if err = tx.Commit(); err != nil {
			return fmt.Errorf("commit tx: %w", err)
		}
		needRollback = false
	}
	return nil
}

// --- GetByID ------------------------------------------------------------

func (r *roomRepository) GetByID(ctx context.Context, db DBTX, id uuid.UUID) (*models.Room, error) {
	query := `
        SELECT
            room_id, company_id, room_code, room_name, capacity, building, floor, is_active,
            created_at, updated_at, created_by, updated_by
        FROM academics.rooms
        WHERE room_id = $1 AND deleted_at IS NULL
    `
	row := db.QueryRowContext(ctx, query, id)
	return r.scanRoom(row)
}

// --- GetByCode ----------------------------------------------------------

func (r *roomRepository) GetByCode(ctx context.Context, db DBTX, companyID uuid.UUID, code string) (*models.Room, error) {
	query := `
        SELECT
            room_id, company_id, room_code, room_name, capacity, building, floor, is_active,
            created_at, updated_at, created_by, updated_by
        FROM academics.rooms
        WHERE company_id = $1 AND room_code = $2 AND deleted_at IS NULL
    `
	row := db.QueryRowContext(ctx, query, companyID, code)
	return r.scanRoom(row)
}

// --- GetByIDs -----------------------------------------------------------

func (r *roomRepository) GetByIDs(ctx context.Context, db DBTX, ids []uuid.UUID) ([]*models.Room, error) {
	if len(ids) == 0 {
		return []*models.Room{}, nil
	}
	placeholders := make([]string, len(ids))
	args := make([]interface{}, len(ids))
	for i, id := range ids {
		placeholders[i] = fmt.Sprintf("$%d", i+1)
		args[i] = id
	}
	query := fmt.Sprintf(`
        SELECT
            room_id, company_id, room_code, room_name, capacity, building, floor, is_active,
            created_at, updated_at, created_by, updated_by
        FROM academics.rooms
        WHERE room_id IN (%s) AND deleted_at IS NULL
    `, strings.Join(placeholders, ","))

	rows, err := db.QueryContext(ctx, query, args...)
	if err != nil {
		r.logger.Error("failed to get rooms by IDs", zap.Error(err))
		return nil, fmt.Errorf("get rooms by IDs: %w", err)
	}
	defer rows.Close()

	var result []*models.Room
	for rows.Next() {
		room, err := r.scanRoom(rows)
		if err != nil {
			return nil, err
		}
		result = append(result, room)
	}
	if err = rows.Err(); err != nil {
		return nil, fmt.Errorf("rows iteration: %w", err)
	}
	return result, nil
}

// --- List ---------------------------------------------------------------

func (r *roomRepository) List(ctx context.Context, db DBTX, filter RoomFilter, p Pagination, s Sort) ([]*models.Room, error) {
	where, args := r.buildRoomFilter(filter)
	orderBy, err := r.validateSort(s)
	if err != nil {
		return nil, err
	}
	limit, offset := r.validatePagination(p)

	query := fmt.Sprintf(`
        SELECT
            room_id, company_id, room_code, room_name, capacity, building, floor, is_active,
            created_at, updated_at, created_by, updated_by
        FROM academics.rooms r
        %s
        %s
        LIMIT $%d OFFSET $%d
    `, where, orderBy, len(args)+1, len(args)+2)

	args = append(args, limit, offset)

	rows, err := db.QueryContext(ctx, query, args...)
	if err != nil {
		r.logger.Error("failed to list rooms",
			util.Any("filter", filter),
			util.ErrorField(err))
		return nil, fmt.Errorf("list rooms: %w", err)
	}
	defer rows.Close()

	var result []*models.Room
	for rows.Next() {
		room, err := r.scanRoom(rows)
		if err != nil {
			return nil, err
		}
		result = append(result, room)
	}
	if err = rows.Err(); err != nil {
		return nil, fmt.Errorf("rows iteration: %w", err)
	}
	return result, nil
}

// --- Count --------------------------------------------------------------

func (r *roomRepository) Count(ctx context.Context, db DBTX, filter RoomFilter) (int64, error) {
	where, args := r.buildRoomFilter(filter)

	query := fmt.Sprintf("SELECT COUNT(*) FROM academics.rooms r %s", where)

	var count int64
	err := db.QueryRowContext(ctx, query, args...).Scan(&count)
	if err != nil {
		r.logger.Error("failed to count rooms",
			util.Any("filter", filter),
			util.ErrorField(err))
		return 0, fmt.Errorf("count rooms: %w", err)
	}
	return count, nil
}

// --- Update -------------------------------------------------------------

func (r *roomRepository) Update(ctx context.Context, db DBTX, room *models.Room) error {
	query := `
        UPDATE academics.rooms
        SET
            room_code = $2,
            room_name = $3,
            capacity = $4,
            building = $5,
            floor = $6,
            is_active = $7,
            updated_by = $8,
            updated_at = NOW()
        WHERE room_id = $1 AND deleted_at IS NULL
        RETURNING updated_at
    `
	err := db.QueryRowContext(ctx, query,
		room.RoomID,
		room.RoomCode,
		room.RoomName,
		room.Capacity,
		room.Building,
		room.Floor,
		room.IsActive,
		room.UpdatedBy,
	).Scan(&room.UpdatedAt)

	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return fmt.Errorf("%w: room %s", ErrNotFound, room.RoomID)
		}
		r.logger.Error("failed to update room",
			util.String("id", room.RoomID.String()),
			util.ErrorField(err))
		return fmt.Errorf("update room: %w", err)
	}
	return nil
}

// --- Delete -------------------------------------------------------------

func (r *roomRepository) Delete(ctx context.Context, db DBTX, id uuid.UUID, deletedBy *uuid.UUID) error {
	query := `UPDATE academics.rooms SET deleted_at = NOW(), updated_by = $2, updated_at = NOW() WHERE room_id = $1 AND deleted_at IS NULL`
	result, err := db.ExecContext(ctx, query, id, deletedBy)
	if err != nil {
		r.logger.Error("failed to delete room",
			util.String("id", id.String()),
			util.ErrorField(err))
		return fmt.Errorf("delete room: %w", err)
	}
	rows, err := result.RowsAffected()
	if err != nil {
		return fmt.Errorf("rows affected: %w", err)
	}
	if rows == 0 {
		return fmt.Errorf("room %s not found or already deleted", id)
	}
	return nil
}

// --- Activate -----------------------------------------------------------

func (r *roomRepository) Activate(ctx context.Context, db DBTX, id uuid.UUID, updatedBy *uuid.UUID) error {
	query := `UPDATE academics.rooms SET is_active = true, updated_by = $2, updated_at = NOW() WHERE room_id = $1 AND deleted_at IS NULL`
	result, err := db.ExecContext(ctx, query, id, updatedBy)
	if err != nil {
		r.logger.Error("failed to activate room",
			util.String("id", id.String()),
			util.ErrorField(err))
		return fmt.Errorf("activate room: %w", err)
	}
	rows, err := result.RowsAffected()
	if err != nil {
		return fmt.Errorf("rows affected: %w", err)
	}
	if rows == 0 {
		return fmt.Errorf("room %s not found or deleted", id)
	}
	return nil
}

// --- Deactivate ---------------------------------------------------------

func (r *roomRepository) Deactivate(ctx context.Context, db DBTX, id uuid.UUID, updatedBy *uuid.UUID) error {
	query := `UPDATE academics.rooms SET is_active = false, updated_by = $2, updated_at = NOW() WHERE room_id = $1 AND deleted_at IS NULL`
	result, err := db.ExecContext(ctx, query, id, updatedBy)
	if err != nil {
		r.logger.Error("failed to deactivate room",
			util.String("id", id.String()),
			util.ErrorField(err))
		return fmt.Errorf("deactivate room: %w", err)
	}
	rows, err := result.RowsAffected()
	if err != nil {
		return fmt.Errorf("rows affected: %w", err)
	}
	if rows == 0 {
		return fmt.Errorf("room %s not found or deleted", id)
	}
	return nil
}

// --- ExistsByCode -------------------------------------------------------

func (r *roomRepository) ExistsByCode(ctx context.Context, db DBTX, companyID uuid.UUID, code string) (bool, error) {
	query := `SELECT EXISTS(SELECT 1 FROM academics.rooms WHERE company_id = $1 AND room_code = $2 AND deleted_at IS NULL)`
	var exists bool
	err := db.QueryRowContext(ctx, query, companyID, code).Scan(&exists)
	if err != nil {
		r.logger.Error("failed to check room existence by code",
			util.String("company_id", companyID.String()),
			util.String("room_code", code),
			util.ErrorField(err))
		return false, fmt.Errorf("exists room by code: %w", err)
	}
	return exists, nil
}

// --- ListByBuilding -----------------------------------------------------

func (r *roomRepository) ListByBuilding(ctx context.Context, db DBTX, companyID uuid.UUID, building string) ([]*models.Room, error) {
	activeTrue := true
	filter := RoomFilter{
		CompanyID: companyID,
		Building:  building,
		IsActive:  &activeTrue,
	}
	return r.List(ctx, db, filter, Pagination{Limit: 1000}, Sort{Field: "room_code", Direction: "ASC"})
}

func (r *roomRepository) scanRoom(row scanner) (*models.Room, error) {
	var room models.Room
	var createdBy, updatedBy uuid.NullUUID

	err := row.Scan(
		&room.RoomID,
		&room.CompanyID,
		&room.RoomCode,
		&room.RoomName,
		&room.Capacity,
		&room.Building,
		&room.Floor,
		&room.IsActive,
		&room.CreatedAt,
		&room.UpdatedAt,
		&createdBy,
		&updatedBy,
	)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, nil
		}
		return nil, fmt.Errorf("scan room: %w", err)
	}

	if createdBy.Valid {
		room.CreatedBy = &createdBy.UUID
	}
	if updatedBy.Valid {
		room.UpdatedBy = &updatedBy.UUID
	}

	return &room, nil
}

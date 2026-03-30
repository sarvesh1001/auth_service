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

// NotificationRepository defines all database operations for notifications.
type NotificationRepository interface {
	// Notification CRUD
	Create(ctx context.Context, db DBTX, n *models.Notification, targets []*models.NotificationTarget) error
	GetByID(ctx context.Context, db DBTX, id uuid.UUID) (*models.Notification, error)
	List(ctx context.Context, db DBTX, filter NotificationFilter, p Pagination, s Sort) ([]*models.Notification, error)
	Count(ctx context.Context, db DBTX, filter NotificationFilter) (int64, error)
	Update(ctx context.Context, db DBTX, n *models.Notification) error
	Delete(ctx context.Context, db DBTX, id uuid.UUID, deletedBy *uuid.UUID) error

	// Notification Targets
	AddTargets(ctx context.Context, db DBTX, notificationID uuid.UUID, targets []*models.NotificationTarget) error
	RemoveTargets(ctx context.Context, db DBTX, notificationID uuid.UUID, targetIDs []uuid.UUID) error
	GetTargets(ctx context.Context, db DBTX, notificationID uuid.UUID) ([]*models.NotificationTarget, error)
	GetReadStatuses(ctx context.Context, db DBTX, notificationIDs []uuid.UUID, userID uuid.UUID) (map[uuid.UUID]bool, error)

	// Read Status
	MarkAsRead(ctx context.Context, db DBTX, notificationID, userID uuid.UUID) error
	MarkAsReadByTarget(ctx context.Context, db DBTX, notificationID uuid.UUID, userID uuid.UUID, targetType models.TargetType, targetEntityID uuid.UUID) error
	IsRead(ctx context.Context, db DBTX, notificationID, userID uuid.UUID) (bool, error)
	GetReadCount(ctx context.Context, db DBTX, notificationID uuid.UUID) (int64, error)
}

type notificationRepository struct {
	logger *zap.Logger
}

// NewNotificationRepository creates a new notification repository.
func NewNotificationRepository(logger *zap.Logger) NotificationRepository {
	return &notificationRepository{
		logger: logger.Named("notification_repo"),
	}
}

var allowedNotificationSortFields = map[string]bool{
	"created_at": true,
	"title":      true,
	"type":       true,
	"priority":   true,
	"expires_at": true,
	// FIXED: removed "updated_at" because it doesn't exist in the table
}

func (r *notificationRepository) validateSort(s Sort) (string, error) {
	field := s.Field
	if field == "" {
		field = "created_at"
	}
	if !allowedNotificationSortFields[field] {
		return "", fmt.Errorf("invalid sort field: %s", field)
	}
	dir := strings.ToUpper(s.Direction)
	if dir != "ASC" && dir != "DESC" {
		dir = "DESC"
	}
	return fmt.Sprintf("ORDER BY n.%s %s", field, dir), nil
}

func (r *notificationRepository) validatePagination(p Pagination) (int, int) {
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

// buildNotificationFilter builds WHERE clause and args for notification queries.
// Note: If filter.UserID is set, we also join notification_reads to filter by read/unread status.
// buildNotificationFilter builds WHERE clause and args for notification queries.
// It does NOT include read/unread conditions; those are handled separately.
func (r *notificationRepository) buildNotificationFilter(filter NotificationFilter) (string, []interface{}, bool) {
	var conditions []string
	var args []interface{}
	idx := 1
	needReadsJoin := filter.UserID != nil && filter.ReadStatus != nil

	if filter.CompanyID != uuid.Nil {
		conditions = append(conditions, fmt.Sprintf("n.company_id = $%d", idx))
		args = append(args, filter.CompanyID)
		idx++
	}

	if len(filter.Types) > 0 {
		placeholders := make([]string, len(filter.Types))
		for i, typ := range filter.Types {
			placeholders[i] = fmt.Sprintf("$%d", idx+i)
			args = append(args, string(typ))
		}
		conditions = append(conditions, fmt.Sprintf("n.type IN (%s)", strings.Join(placeholders, ",")))
		idx += len(filter.Types)
	}

	if len(filter.Priorities) > 0 {
		placeholders := make([]string, len(filter.Priorities))
		for i, pri := range filter.Priorities {
			placeholders[i] = fmt.Sprintf("$%d", idx+i)
			args = append(args, string(pri))
		}
		conditions = append(conditions, fmt.Sprintf("n.priority IN (%s)", strings.Join(placeholders, ",")))
		idx += len(filter.Priorities)
	}

	if filter.CreatedBy != nil {
		conditions = append(conditions, fmt.Sprintf("n.created_by = $%d", idx))
		args = append(args, *filter.CreatedBy)
		idx++
	}

	if filter.ExpiresFrom != nil {
		conditions = append(conditions, fmt.Sprintf("n.expires_at >= $%d", idx))
		args = append(args, *filter.ExpiresFrom)
		idx++
	}

	if filter.ExpiresTo != nil {
		conditions = append(conditions, fmt.Sprintf("n.expires_at <= $%d", idx))
		args = append(args, *filter.ExpiresTo)
		idx++
	}

	if filter.CreatedFrom != nil {
		conditions = append(conditions, fmt.Sprintf("n.created_at >= $%d", idx))
		args = append(args, *filter.CreatedFrom)
		idx++
	}

	if filter.CreatedTo != nil {
		conditions = append(conditions, fmt.Sprintf("n.created_at <= $%d", idx))
		args = append(args, *filter.CreatedTo)
		idx++
	}

	if filter.Search != "" {
		conditions = append(conditions, fmt.Sprintf("(n.title ILIKE $%d OR n.message ILIKE $%d)", idx, idx))
		args = append(args, "%"+filter.Search+"%")
		idx++
	}

	// Add soft-delete condition
	conditions = append(conditions, "n.deleted_at IS NULL")

	if len(conditions) == 0 {
		return "", args, needReadsJoin
	}
	return "WHERE " + strings.Join(conditions, " AND "), args, needReadsJoin
}

// --- Create ------------------------------------------------------------

func (r *notificationRepository) Create(ctx context.Context, db DBTX, n *models.Notification, targets []*models.NotificationTarget) error {
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

	// Insert notification
	// FIXED: removed updated_at from RETURNING and scan
	query := `
        INSERT INTO academics.notifications (
            company_id, title, message, type, priority, created_by, updated_by, created_at, expires_at
        ) VALUES ($1, $2, $3, $4, $5, $6, $7, NOW(), $8)
        RETURNING notification_id, created_at
    `
	err = tx.QueryRowContext(ctx, query,
		n.CompanyID, n.Title, n.Message, n.Type, n.Priority,
		n.CreatedBy, n.UpdatedBy, n.ExpiresAt,
	).Scan(&n.NotificationID, &n.CreatedAt)
	if err != nil {
		r.logger.Error("failed to create notification",
			util.String("company_id", n.CompanyID.String()),
			util.String("title", n.Title),
			util.ErrorField(err))
		return fmt.Errorf("create notification: %w", err)
	}

	// Insert targets if any
	if len(targets) > 0 {
		if err := r.addTargetsInTx(ctx, tx, n.NotificationID, targets); err != nil {
			return err
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

// addTargetsInTx inserts notification targets inside a transaction.
func (r *notificationRepository) addTargetsInTx(ctx context.Context, tx DBTX, notificationID uuid.UUID, targets []*models.NotificationTarget) error {
	stmt, err := tx.PrepareContext(ctx, `
        INSERT INTO academics.notification_targets (
            notification_id, target_type, target_entity_id, created_by
        ) VALUES ($1, $2, $3, $4)
        RETURNING notification_target_id, created_at
    `)
	if err != nil {
		return fmt.Errorf("prepare targets statement: %w", err)
	}
	defer stmt.Close()

	for _, t := range targets {
		t.NotificationID = notificationID
		err = stmt.QueryRowContext(ctx,
			t.NotificationID, t.TargetType, t.TargetEntityID, t.CreatedBy,
		).Scan(&t.NotificationTargetID, &t.CreatedAt)
		if err != nil {
			r.logger.Error("failed to insert notification target",
				util.String("notification_id", notificationID.String()),
				util.String("target_type", string(t.TargetType)),
				util.String("target_entity_id", t.TargetEntityID.String()),
				util.ErrorField(err))
			return fmt.Errorf("insert notification target: %w", err)
		}
	}
	return nil
}

// --- GetByID ------------------------------------------------------------

func (r *notificationRepository) GetByID(ctx context.Context, db DBTX, id uuid.UUID) (*models.Notification, error) {
	// FIXED: removed updated_at from SELECT
	query := `
        SELECT
            notification_id, company_id, title, message, type, priority,
            created_by, updated_by, created_at, expires_at
        FROM academics.notifications
        WHERE notification_id = $1 AND deleted_at IS NULL
    `
	row := db.QueryRowContext(ctx, query, id)
	return r.scanNotification(row)
}

// --- List ---------------------------------------------------------------

func (r *notificationRepository) List(ctx context.Context, db DBTX, filter NotificationFilter, p Pagination, s Sort) ([]*models.Notification, error) {
	where, baseArgs, needReadsJoin := r.buildNotificationFilter(filter)
	orderBy, err := r.validateSort(s)
	if err != nil {
		return nil, err
	}
	limit, offset := r.validatePagination(p)

	// Build FROM clause and arguments
	fromClause := "FROM academics.notifications n"
	args := baseArgs
	var readCondition string

	if needReadsJoin {
		// Add LEFT JOIN with placeholder for user_id
		userID := *filter.UserID
		joinPlaceholder := len(args) + 1
		fromClause += fmt.Sprintf(" LEFT JOIN academics.notification_reads nr ON n.notification_id = nr.notification_id AND nr.user_id = $%d", joinPlaceholder)
		args = append(args, userID)

		// Build read condition based on filter.ReadStatus
		if *filter.ReadStatus {
			readCondition = " AND nr.user_id IS NOT NULL"
		} else {
			readCondition = " AND nr.user_id IS NULL"
		}
	}

	query := fmt.Sprintf(`
        SELECT
            n.notification_id, n.company_id, n.title, n.message, n.type, n.priority,
            n.created_by, n.updated_by, n.created_at, n.expires_at
        %s
        %s
        %s
        %s
        LIMIT $%d OFFSET $%d
    `, fromClause, where, readCondition, orderBy, len(args)+1, len(args)+2)

	// Append pagination args
	args = append(args, limit, offset)

	rows, err := db.QueryContext(ctx, query, args...)
	if err != nil {
		r.logger.Error("failed to list notifications",
			util.Any("filter", filter),
			util.ErrorField(err))
		return nil, fmt.Errorf("list notifications: %w", err)
	}
	defer rows.Close()

	var result []*models.Notification
	for rows.Next() {
		n, err := r.scanNotification(rows)
		if err != nil {
			return nil, err
		}
		result = append(result, n)
	}
	if err = rows.Err(); err != nil {
		return nil, fmt.Errorf("rows iteration: %w", err)
	}
	return result, nil
}

// --- Count --------------------------------------------------------------

func (r *notificationRepository) Count(ctx context.Context, db DBTX, filter NotificationFilter) (int64, error) {
	where, baseArgs, needReadsJoin := r.buildNotificationFilter(filter)

	// Build FROM clause and arguments
	fromClause := "FROM academics.notifications n"
	args := baseArgs
	var readCondition string

	if needReadsJoin {
		userID := *filter.UserID
		joinPlaceholder := len(args) + 1
		fromClause += fmt.Sprintf(" LEFT JOIN academics.notification_reads nr ON n.notification_id = nr.notification_id AND nr.user_id = $%d", joinPlaceholder)
		args = append(args, userID)

		if *filter.ReadStatus {
			readCondition = " AND nr.user_id IS NOT NULL"
		} else {
			readCondition = " AND nr.user_id IS NULL"
		}
	}

	query := fmt.Sprintf("SELECT COUNT(*) %s %s %s", fromClause, where, readCondition)

	var count int64
	err := db.QueryRowContext(ctx, query, args...).Scan(&count)
	if err != nil {
		r.logger.Error("failed to count notifications",
			util.Any("filter", filter),
			util.ErrorField(err))
		return 0, fmt.Errorf("count notifications: %w", err)
	}
	return count, nil
}

// --- Update -------------------------------------------------------------

func (r *notificationRepository) Update(ctx context.Context, db DBTX, n *models.Notification) error {
	// FIXED: removed updated_at = NOW() and RETURNING
	query := `
        UPDATE academics.notifications
        SET
            title = $2,
            message = $3,
            type = $4,
            priority = $5,
            updated_by = $6,
            expires_at = $7
        WHERE notification_id = $1 AND deleted_at IS NULL
    `
	_, err := db.ExecContext(ctx, query,
		n.NotificationID,
		n.Title,
		n.Message,
		n.Type,
		n.Priority,
		n.UpdatedBy,
		n.ExpiresAt,
	)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return fmt.Errorf("%w: notification %s", ErrNotFound, n.NotificationID)
		}
		r.logger.Error("failed to update notification",
			util.String("id", n.NotificationID.String()),
			util.ErrorField(err))
		return fmt.Errorf("update notification: %w", err)
	}
	return nil
}

// --- Delete (soft delete) -----------------------------------------------

func (r *notificationRepository) Delete(ctx context.Context, db DBTX, id uuid.UUID, deletedBy *uuid.UUID) error {
	// FIXED: removed updated_at = NOW()
	query := `UPDATE academics.notifications SET deleted_at = NOW(), updated_by = $2 WHERE notification_id = $1 AND deleted_at IS NULL`
	result, err := db.ExecContext(ctx, query, id, deletedBy)
	if err != nil {
		r.logger.Error("failed to delete notification",
			util.String("id", id.String()),
			util.ErrorField(err))
		return fmt.Errorf("delete notification: %w", err)
	}
	rows, err := result.RowsAffected()
	if err != nil {
		return fmt.Errorf("rows affected: %w", err)
	}
	if rows == 0 {
		return fmt.Errorf("notification %s not found or already deleted", id)
	}
	return nil
}

// --- Notification Targets ------------------------------------------------

func (r *notificationRepository) AddTargets(ctx context.Context, db DBTX, notificationID uuid.UUID, targets []*models.NotificationTarget) error {
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

	if err := r.addTargetsInTx(ctx, tx, notificationID, targets); err != nil {
		return err
	}

	if isOwner {
		if err = tx.Commit(); err != nil {
			return fmt.Errorf("commit tx: %w", err)
		}
		needRollback = false
	}
	return nil
}

func (r *notificationRepository) RemoveTargets(ctx context.Context, db DBTX, notificationID uuid.UUID, targetIDs []uuid.UUID) error {
	if len(targetIDs) == 0 {
		return nil
	}
	placeholders := make([]string, len(targetIDs))
	args := make([]interface{}, len(targetIDs)+1)
	args[0] = notificationID
	for i, id := range targetIDs {
		placeholders[i] = fmt.Sprintf("$%d", i+2)
		args[i+1] = id
	}
	query := fmt.Sprintf(`
        DELETE FROM academics.notification_targets
        WHERE notification_id = $1 AND notification_target_id IN (%s)
    `, strings.Join(placeholders, ","))

	_, err := db.ExecContext(ctx, query, args...)
	if err != nil {
		r.logger.Error("failed to remove notification targets",
			util.String("notification_id", notificationID.String()),
			zap.Int("count", len(targetIDs)),
			util.ErrorField(err))
		return fmt.Errorf("remove targets: %w", err)
	}
	return nil
}

func (r *notificationRepository) GetTargets(ctx context.Context, db DBTX, notificationID uuid.UUID) ([]*models.NotificationTarget, error) {
	query := `
        SELECT
            notification_target_id, notification_id, target_type, target_entity_id,
            created_at, created_by
        FROM academics.notification_targets
        WHERE notification_id = $1
    `
	rows, err := db.QueryContext(ctx, query, notificationID)
	if err != nil {
		r.logger.Error("failed to get notification targets",
			util.String("notification_id", notificationID.String()),
			util.ErrorField(err))
		return nil, fmt.Errorf("get targets: %w", err)
	}
	defer rows.Close()

	var targets []*models.NotificationTarget
	for rows.Next() {
		var t models.NotificationTarget
		var createdBy uuid.NullUUID
		err := rows.Scan(
			&t.NotificationTargetID,
			&t.NotificationID,
			&t.TargetType,
			&t.TargetEntityID,
			&t.CreatedAt,
			&createdBy,
		)
		if err != nil {
			return nil, fmt.Errorf("scan target: %w", err)
		}
		if createdBy.Valid {
			t.CreatedBy = &createdBy.UUID
		}
		targets = append(targets, &t)
	}
	if err = rows.Err(); err != nil {
		return nil, fmt.Errorf("rows iteration: %w", err)
	}
	return targets, nil
}

// --- Read Status ---------------------------------------------------------

func (r *notificationRepository) MarkAsRead(ctx context.Context, db DBTX, notificationID, userID uuid.UUID) error {
	query := `
        INSERT INTO academics.notification_reads (notification_id, user_id, read_at, created_by)
        VALUES ($1, $2, NOW(), $2)
        ON CONFLICT (notification_id, user_id) DO UPDATE
        SET read_at = NOW()
    `
	_, err := db.ExecContext(ctx, query, notificationID, userID)
	if err != nil {
		r.logger.Error("failed to mark notification as read",
			util.String("notification_id", notificationID.String()),
			util.String("user_id", userID.String()),
			util.ErrorField(err))
		return fmt.Errorf("mark as read: %w", err)
	}
	return nil
}

func (r *notificationRepository) MarkAsReadByTarget(ctx context.Context, db DBTX, notificationID uuid.UUID, userID uuid.UUID, targetType models.TargetType, targetEntityID uuid.UUID) error {
	// For notifications targeted to a specific entity (like a section), we may need to mark read for all users in that entity.
	// This is a placeholder – implement if needed.
	return r.MarkAsRead(ctx, db, notificationID, userID)
}

func (r *notificationRepository) IsRead(ctx context.Context, db DBTX, notificationID, userID uuid.UUID) (bool, error) {
	query := `SELECT EXISTS(SELECT 1 FROM academics.notification_reads WHERE notification_id = $1 AND user_id = $2)`
	var exists bool
	err := db.QueryRowContext(ctx, query, notificationID, userID).Scan(&exists)
	if err != nil {
		return false, fmt.Errorf("check read status: %w", err)
	}
	return exists, nil
}

func (r *notificationRepository) GetReadCount(ctx context.Context, db DBTX, notificationID uuid.UUID) (int64, error) {
	query := `SELECT COUNT(*) FROM academics.notification_reads WHERE notification_id = $1`
	var count int64
	err := db.QueryRowContext(ctx, query, notificationID).Scan(&count)
	if err != nil {
		return 0, fmt.Errorf("get read count: %w", err)
	}
	return count, nil
}

// --- scanNotification ----------------------------------------------------

func (r *notificationRepository) scanNotification(row scanner) (*models.Notification, error) {
	var n models.Notification
	var createdBy, updatedBy uuid.NullUUID
	var expiresAt sql.NullTime

	// FIXED: removed updated_at from scan
	err := row.Scan(
		&n.NotificationID,
		&n.CompanyID,
		&n.Title,
		&n.Message,
		&n.Type,
		&n.Priority,
		&createdBy,
		&updatedBy,
		&n.CreatedAt,
		&expiresAt,
	)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, nil
		}
		return nil, fmt.Errorf("scan notification: %w", err)
	}

	if createdBy.Valid {
		n.CreatedBy = &createdBy.UUID
	}
	if updatedBy.Valid {
		n.UpdatedBy = &updatedBy.UUID
	}
	if expiresAt.Valid {
		n.ExpiresAt = &expiresAt.Time
	}
	return &n, nil
}
func (r *notificationRepository) GetReadStatuses(ctx context.Context, db DBTX, notificationIDs []uuid.UUID, userID uuid.UUID) (map[uuid.UUID]bool, error) {
	if len(notificationIDs) == 0 {
		return make(map[uuid.UUID]bool), nil
	}

	// Build placeholders for IN clause
	placeholders := make([]string, len(notificationIDs))
	args := make([]interface{}, len(notificationIDs)+1)
	args[0] = userID
	for i, id := range notificationIDs {
		placeholders[i] = fmt.Sprintf("$%d", i+2)
		args[i+1] = id
	}

	query := fmt.Sprintf(`
        SELECT notification_id
        FROM academics.notification_reads
        WHERE user_id = $1 AND notification_id IN (%s)
    `, strings.Join(placeholders, ","))

	rows, err := db.QueryContext(ctx, query, args...)
	if err != nil {
		return nil, fmt.Errorf("get read statuses: %w", err)
	}
	defer rows.Close()

	readMap := make(map[uuid.UUID]bool)
	for rows.Next() {
		var nid uuid.UUID
		if err := rows.Scan(&nid); err != nil {
			return nil, fmt.Errorf("scan read status: %w", err)
		}
		readMap[nid] = true
	}
	if err = rows.Err(); err != nil {
		return nil, fmt.Errorf("rows iteration: %w", err)
	}

	// Fill in false for notifications not in map
	for _, id := range notificationIDs {
		if _, ok := readMap[id]; !ok {
			readMap[id] = false
		}
	}

	return readMap, nil
}

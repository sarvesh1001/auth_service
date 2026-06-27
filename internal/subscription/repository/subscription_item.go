// repository/subscription_item.go
package repository

import (
	"context"
	"database/sql"
	"fmt"
	"strings"
	"time"

	"github.com/google/uuid"
	"go.uber.org/zap"

	"auth-service/internal/subscription/errors"
	"auth-service/internal/subscription/models"
)

// ---------------------------------------------------------------------
// SubscriptionItemRepository Interface
// ---------------------------------------------------------------------

type SubscriptionItemRepository interface {
	// CRUD
	Create(ctx context.Context, db DBTX, item *models.SubscriptionItem) error
	Update(ctx context.Context, db DBTX, item *models.SubscriptionItem) error
	Delete(ctx context.Context, db DBTX, subItemID uuid.UUID) error

	// Single Fetch
	GetByID(ctx context.Context, db DBTX, subItemID uuid.UUID) (*models.SubscriptionItem, error)
	GetBySubscriptionAndPlanItem(ctx context.Context, db DBTX, subscriptionID, planItemID uuid.UUID) (*models.SubscriptionItem, error)

	// Listing
	List(ctx context.Context, db DBTX, filter SubscriptionItemFilter, p Pagination, s Sort) ([]*models.SubscriptionItem, int64, error)
	ListBySubscription(ctx context.Context, db DBTX, subscriptionID uuid.UUID) ([]*models.SubscriptionItem, error)
	ListActive(ctx context.Context, db DBTX, subscriptionID uuid.UUID) ([]*models.SubscriptionItem, error)

	// Updates
	UpdateQuantity(ctx context.Context, db DBTX, subItemID uuid.UUID, quantity float64, updatedBy *uuid.UUID) error
	UpdatePrice(ctx context.Context, db DBTX, subItemID uuid.UUID, unitPrice float64, updatedBy *uuid.UUID) error
	UpdateStatus(ctx context.Context, db DBTX, subItemID uuid.UUID, statusID int16, updatedBy *uuid.UUID) error

	// Validation
	Exists(ctx context.Context, db DBTX, subItemID uuid.UUID) (bool, error)
	ExistsBySubscriptionAndPlanItem(ctx context.Context, db DBTX, subscriptionID, planItemID uuid.UUID) (bool, error)

	// Search
	Search(ctx context.Context, db DBTX, subscriptionID uuid.UUID, query string, limit, offset int) ([]*models.SubscriptionItem, int64, error)

	// Locking
	GetByIDForUpdate(ctx context.Context, db DBTX, subItemID uuid.UUID) (*models.SubscriptionItem, error)
}

// ---------------------------------------------------------------------
// Filter
// ---------------------------------------------------------------------

type SubscriptionItemFilter struct {
	SubscriptionID      uuid.UUID
	SubscriptionItemIDs []uuid.UUID
	PlanItemID          *uuid.UUID
	AddonID             *uuid.UUID
	StatusID            *int16
	MinQuantity         *float64
	MaxQuantity         *float64
	MinUnitPrice        *float64
	MaxUnitPrice        *float64
	Currency            *string
	StartDateFrom       *time.Time
	StartDateTo         *time.Time
	EndDateFrom         *time.Time
	EndDateTo           *time.Time
}

// ---------------------------------------------------------------------
// Implementation
// ---------------------------------------------------------------------

type subscriptionItemRepository struct {
	logger *zap.Logger
}

func NewSubscriptionItemRepository(logger *zap.Logger) SubscriptionItemRepository {
	return &subscriptionItemRepository{
		logger: logger.Named("subscription_item_repo"),
	}
}

const subscriptionItemTable = "subscription.subscription_items"

func (r *subscriptionItemRepository) scanSubscriptionItem(s scanner) (*models.SubscriptionItem, error) {
	var item models.SubscriptionItem
	var addonID, metadata sql.NullString
	var endDate sql.NullTime // ✅ changed from sql.NullString

	var totalPrice float64

	err := s.Scan(
		&item.SubItemID,
		&item.SubscriptionID,
		&item.PlanItemID,
		&addonID,
		&item.Quantity,
		&item.UnitPrice,
		&totalPrice,
		&item.Currency,
		&item.StatusID,
		&item.StartDate,
		&endDate,
		&metadata,
		&item.CreatedAt,
		&item.UpdatedAt,
	)
	if err != nil {
		if err == sql.ErrNoRows {
			return nil, errors.ErrNotFound
		}
		return nil, fmt.Errorf("scan subscription item: %w", err)
	}

	if addonID.Valid {
		if uid, err := uuid.Parse(addonID.String); err == nil {
			item.AddonID = &uid
		}
	}
	if endDate.Valid {
		item.EndDate = &endDate.Time
	}
	if metadata.Valid {
		item.Metadata = []byte(metadata.String)
	}
	item.TotalPrice = totalPrice

	return &item, nil
}

func (r *subscriptionItemRepository) buildSubscriptionItemFilter(filter SubscriptionItemFilter) (string, []interface{}) {
	var conds []string
	var args []interface{}
	idx := 1

	if filter.SubscriptionID != uuid.Nil {
		conds = append(conds, fmt.Sprintf("subscription_id = $%d", idx))
		args = append(args, filter.SubscriptionID)
		idx++
	}

	if len(filter.SubscriptionItemIDs) > 0 {
		placeholders := make([]string, len(filter.SubscriptionItemIDs))
		for i, id := range filter.SubscriptionItemIDs {
			placeholders[i] = fmt.Sprintf("$%d", idx)
			args = append(args, id)
			idx++
		}
		conds = append(conds, fmt.Sprintf("sub_item_id IN (%s)", strings.Join(placeholders, ",")))
	}

	if filter.PlanItemID != nil {
		conds = append(conds, fmt.Sprintf("plan_item_id = $%d", idx))
		args = append(args, *filter.PlanItemID)
		idx++
	}

	if filter.AddonID != nil {
		conds = append(conds, fmt.Sprintf("addon_id = $%d", idx))
		args = append(args, *filter.AddonID)
		idx++
	}

	if filter.StatusID != nil {
		conds = append(conds, fmt.Sprintf("status_id = $%d", idx))
		args = append(args, *filter.StatusID)
		idx++
	}

	if filter.MinQuantity != nil {
		conds = append(conds, fmt.Sprintf("quantity >= $%d", idx))
		args = append(args, *filter.MinQuantity)
		idx++
	}
	if filter.MaxQuantity != nil {
		conds = append(conds, fmt.Sprintf("quantity <= $%d", idx))
		args = append(args, *filter.MaxQuantity)
		idx++
	}

	if filter.MinUnitPrice != nil {
		conds = append(conds, fmt.Sprintf("unit_price >= $%d", idx))
		args = append(args, *filter.MinUnitPrice)
		idx++
	}
	if filter.MaxUnitPrice != nil {
		conds = append(conds, fmt.Sprintf("unit_price <= $%d", idx))
		args = append(args, *filter.MaxUnitPrice)
		idx++
	}

	if filter.Currency != nil {
		conds = append(conds, fmt.Sprintf("currency = $%d", idx))
		args = append(args, *filter.Currency)
		idx++
	}

	if filter.StartDateFrom != nil {
		conds = append(conds, fmt.Sprintf("start_date >= $%d", idx))
		args = append(args, *filter.StartDateFrom)
		idx++
	}
	if filter.StartDateTo != nil {
		conds = append(conds, fmt.Sprintf("start_date <= $%d", idx))
		args = append(args, *filter.StartDateTo)
		idx++
	}

	if filter.EndDateFrom != nil {
		conds = append(conds, fmt.Sprintf("end_date >= $%d", idx))
		args = append(args, *filter.EndDateFrom)
		idx++
	}
	if filter.EndDateTo != nil {
		conds = append(conds, fmt.Sprintf("end_date <= $%d", idx))
		args = append(args, *filter.EndDateTo)
		idx++
	}

	if len(conds) == 0 {
		return "", args
	}
	return "WHERE " + strings.Join(conds, " AND "), args
}

var subscriptionItemAllowedSort = map[string]bool{
	"sub_item_id": true,
	"quantity":    true,
	"unit_price":  true,
	"total_price": true,
	"currency":    true,
	"status_id":   true,
	"start_date":  true,
	"end_date":    true,
	"created_at":  true,
	"updated_at":  true,
}

// ---------------------------------------------------------------------
// CRUD
// ---------------------------------------------------------------------

func (r *subscriptionItemRepository) Create(ctx context.Context, db DBTX, item *models.SubscriptionItem) error {
	query := `
		INSERT INTO subscription.subscription_items (
			sub_item_id, subscription_id, plan_item_id, addon_id,
			quantity, unit_price, currency, status_id,
			start_date, end_date, metadata, created_at, updated_at
		) VALUES (
			$1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, NOW(), NOW()
		)
		RETURNING created_at, updated_at
	`

	err := db.QueryRowContext(ctx, query,
		item.SubItemID,
		item.SubscriptionID,
		item.PlanItemID,
		item.AddonID,
		item.Quantity,
		item.UnitPrice,
		item.Currency,
		item.StatusID,
		item.StartDate,
		item.EndDate,
		item.Metadata,
	).Scan(&item.CreatedAt, &item.UpdatedAt)

	if err != nil {
		return fmt.Errorf("create subscription item: %w", err)
	}
	return nil
}

func (r *subscriptionItemRepository) Update(ctx context.Context, db DBTX, item *models.SubscriptionItem) error {
	query := `
		UPDATE subscription.subscription_items SET
			plan_item_id = $2,
			addon_id = $3,
			quantity = $4,
			unit_price = $5,
			currency = $6,
			status_id = $7,
			start_date = $8,
			end_date = $9,
			metadata = $10,
			updated_at = NOW()
		WHERE sub_item_id = $1
		RETURNING updated_at
	`

	err := db.QueryRowContext(ctx, query,
		item.SubItemID,
		item.PlanItemID,
		item.AddonID,
		item.Quantity,
		item.UnitPrice,
		item.Currency,
		item.StatusID,
		item.StartDate,
		item.EndDate,
		item.Metadata,
	).Scan(&item.UpdatedAt)

	if err != nil {
		if err == sql.ErrNoRows {
			return errors.ErrNotFound
		}
		return fmt.Errorf("update subscription item: %w", err)
	}
	return nil
}

func (r *subscriptionItemRepository) Delete(ctx context.Context, db DBTX, subItemID uuid.UUID) error {
	query := `DELETE FROM subscription.subscription_items WHERE sub_item_id = $1`
	result, err := db.ExecContext(ctx, query, subItemID)
	if err != nil {
		return fmt.Errorf("delete subscription item: %w", err)
	}
	rows, _ := result.RowsAffected()
	if rows == 0 {
		return errors.ErrNotFound
	}
	return nil
}

// ---------------------------------------------------------------------
// Single Fetch
// ---------------------------------------------------------------------

func (r *subscriptionItemRepository) GetByID(ctx context.Context, db DBTX, subItemID uuid.UUID) (*models.SubscriptionItem, error) {
	query := `
		SELECT sub_item_id, subscription_id, plan_item_id, addon_id,
			quantity, unit_price, total_price, currency, status_id,
			start_date, end_date, metadata, created_at, updated_at
		FROM subscription.subscription_items
		WHERE sub_item_id = $1
	`
	row := db.QueryRowContext(ctx, query, subItemID)
	return r.scanSubscriptionItem(row)
}

func (r *subscriptionItemRepository) GetBySubscriptionAndPlanItem(ctx context.Context, db DBTX, subscriptionID, planItemID uuid.UUID) (*models.SubscriptionItem, error) {
	query := `
		SELECT sub_item_id, subscription_id, plan_item_id, addon_id,
			quantity, unit_price, total_price, currency, status_id,
			start_date, end_date, metadata, created_at, updated_at
		FROM subscription.subscription_items
		WHERE subscription_id = $1 AND plan_item_id = $2
	`
	row := db.QueryRowContext(ctx, query, subscriptionID, planItemID)
	return r.scanSubscriptionItem(row)
}

// ---------------------------------------------------------------------
// Listing
// ---------------------------------------------------------------------

func (r *subscriptionItemRepository) List(ctx context.Context, db DBTX, filter SubscriptionItemFilter, p Pagination, s Sort) ([]*models.SubscriptionItem, int64, error) {
	where, args := r.buildSubscriptionItemFilter(filter)
	if where == "" {
		return nil, 0, fmt.Errorf("subscription_id is required in filter")
	}

	orderBy, err := validateSort(s, subscriptionItemAllowedSort)
	if err != nil {
		return nil, 0, err
	}
	if orderBy == "" {
		orderBy = "ORDER BY created_at DESC"
	}

	limit, offset := validatePagination(p)

	countQuery := fmt.Sprintf("SELECT COUNT(*) FROM %s %s", subscriptionItemTable, where)
	var total int64
	err = db.QueryRowContext(ctx, countQuery, args...).Scan(&total)
	if err != nil {
		return nil, 0, fmt.Errorf("count subscription items: %w", err)
	}
	if total == 0 {
		return []*models.SubscriptionItem{}, 0, nil
	}

	query := fmt.Sprintf(`
		SELECT sub_item_id, subscription_id, plan_item_id, addon_id,
			quantity, unit_price, total_price, currency, status_id,
			start_date, end_date, metadata, created_at, updated_at
		FROM %s
		%s
		%s
		LIMIT $%d OFFSET $%d
	`, subscriptionItemTable, where, orderBy, len(args)+1, len(args)+2)
	args = append(args, limit, offset)

	rows, err := db.QueryContext(ctx, query, args...)
	if err != nil {
		return nil, 0, fmt.Errorf("list subscription items: %w", err)
	}
	defer rows.Close()

	var result []*models.SubscriptionItem
	for rows.Next() {
		item, err := r.scanSubscriptionItem(rows)
		if err != nil {
			return nil, 0, err
		}
		result = append(result, item)
	}
	return result, total, rows.Err()
}

func (r *subscriptionItemRepository) ListBySubscription(ctx context.Context, db DBTX, subscriptionID uuid.UUID) ([]*models.SubscriptionItem, error) {
	filter := SubscriptionItemFilter{
		SubscriptionID: subscriptionID,
	}
	items, _, err := r.List(ctx, db, filter, Pagination{Limit: 1000}, Sort{Field: "created_at", Direction: "DESC"})
	return items, err
}

func (r *subscriptionItemRepository) ListActive(ctx context.Context, db DBTX, subscriptionID uuid.UUID) ([]*models.SubscriptionItem, error) {
	statusID := int16(7) // active item status
	filter := SubscriptionItemFilter{
		SubscriptionID: subscriptionID,
		StatusID:       &statusID,
	}
	items, _, err := r.List(ctx, db, filter, Pagination{Limit: 1000}, Sort{Field: "created_at", Direction: "DESC"})
	return items, err
}

// ---------------------------------------------------------------------
// Updates
// ---------------------------------------------------------------------

func (r *subscriptionItemRepository) UpdateQuantity(ctx context.Context, db DBTX, subItemID uuid.UUID, quantity float64, updatedBy *uuid.UUID) error {
	query := `
		UPDATE subscription.subscription_items
		SET quantity = $2, updated_at = NOW()
		WHERE sub_item_id = $1
	`
	result, err := db.ExecContext(ctx, query, subItemID, quantity)
	if err != nil {
		return fmt.Errorf("update quantity: %w", err)
	}
	rows, _ := result.RowsAffected()
	if rows == 0 {
		return errors.ErrNotFound
	}
	return nil
}

func (r *subscriptionItemRepository) UpdatePrice(ctx context.Context, db DBTX, subItemID uuid.UUID, unitPrice float64, updatedBy *uuid.UUID) error {
	query := `
		UPDATE subscription.subscription_items
		SET unit_price = $2, updated_at = NOW()
		WHERE sub_item_id = $1
	`
	result, err := db.ExecContext(ctx, query, subItemID, unitPrice)
	if err != nil {
		return fmt.Errorf("update price: %w", err)
	}
	rows, _ := result.RowsAffected()
	if rows == 0 {
		return errors.ErrNotFound
	}
	return nil
}

func (r *subscriptionItemRepository) UpdateStatus(ctx context.Context, db DBTX, subItemID uuid.UUID, statusID int16, updatedBy *uuid.UUID) error {
	query := `
		UPDATE subscription.subscription_items
		SET status_id = $2, updated_at = NOW()
		WHERE sub_item_id = $1
	`
	result, err := db.ExecContext(ctx, query, subItemID, statusID)
	if err != nil {
		return fmt.Errorf("update status: %w", err)
	}
	rows, _ := result.RowsAffected()
	if rows == 0 {
		return errors.ErrNotFound
	}
	return nil
}

// ---------------------------------------------------------------------
// Validation
// ---------------------------------------------------------------------

func (r *subscriptionItemRepository) Exists(ctx context.Context, db DBTX, subItemID uuid.UUID) (bool, error) {
	var exists bool
	query := `SELECT EXISTS(SELECT 1 FROM subscription.subscription_items WHERE sub_item_id = $1)`
	err := db.QueryRowContext(ctx, query, subItemID).Scan(&exists)
	return exists, err
}

func (r *subscriptionItemRepository) ExistsBySubscriptionAndPlanItem(ctx context.Context, db DBTX, subscriptionID, planItemID uuid.UUID) (bool, error) {
	var exists bool
	query := `SELECT EXISTS(SELECT 1 FROM subscription.subscription_items WHERE subscription_id = $1 AND plan_item_id = $2)`
	err := db.QueryRowContext(ctx, query, subscriptionID, planItemID).Scan(&exists)
	return exists, err
}

// ---------------------------------------------------------------------
// Search
// ---------------------------------------------------------------------

func (r *subscriptionItemRepository) Search(ctx context.Context, db DBTX, subscriptionID uuid.UUID, query string, limit, offset int) ([]*models.SubscriptionItem, int64, error) {
	pattern := "%" + query + "%"
	where := "WHERE subscription_id = $1 AND (currency ILIKE $2 OR CAST(quantity AS TEXT) ILIKE $2)"
	args := []interface{}{subscriptionID, pattern}

	countQuery := fmt.Sprintf("SELECT COUNT(*) FROM %s %s", subscriptionItemTable, where)
	var total int64
	err := db.QueryRowContext(ctx, countQuery, args...).Scan(&total)
	if err != nil {
		return nil, 0, fmt.Errorf("search subscription items count: %w", err)
	}
	if total == 0 {
		return []*models.SubscriptionItem{}, 0, nil
	}

	baseQuery := `
		SELECT sub_item_id, subscription_id, plan_item_id, addon_id,
			quantity, unit_price, total_price, currency, status_id,
			start_date, end_date, metadata, created_at, updated_at
		FROM subscription.subscription_items
	`
	querySQL := fmt.Sprintf(`%s %s ORDER BY created_at DESC LIMIT $%d OFFSET $%d`, baseQuery, where, len(args)+1, len(args)+2)
	args = append(args, limit, offset)

	rows, err := db.QueryContext(ctx, querySQL, args...)
	if err != nil {
		return nil, 0, fmt.Errorf("search subscription items: %w", err)
	}
	defer rows.Close()

	var result []*models.SubscriptionItem
	for rows.Next() {
		item, err := r.scanSubscriptionItem(rows)
		if err != nil {
			return nil, 0, err
		}
		result = append(result, item)
	}
	return result, total, rows.Err()
}

// ---------------------------------------------------------------------
// Locking
// ---------------------------------------------------------------------

func (r *subscriptionItemRepository) GetByIDForUpdate(ctx context.Context, db DBTX, subItemID uuid.UUID) (*models.SubscriptionItem, error) {
	query := `
		SELECT sub_item_id, subscription_id, plan_item_id, addon_id,
			quantity, unit_price, total_price, currency, status_id,
			start_date, end_date, metadata, created_at, updated_at
		FROM subscription.subscription_items
		WHERE sub_item_id = $1
		FOR UPDATE
	`
	row := db.QueryRowContext(ctx, query, subItemID)
	return r.scanSubscriptionItem(row)
}

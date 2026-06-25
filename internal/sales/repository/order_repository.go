package repository

import (
	"context"
	"database/sql"
	"fmt"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/shopspring/decimal"
	"go.uber.org/zap"

	"auth-service/internal/sales/errors"
	"auth-service/internal/sales/models"
	"auth-service/internal/sales/models/enums"
)

// -------------------------------------------------------------------------
// OrderFilter – includes credit fields
// -------------------------------------------------------------------------

type OrderFilter struct {
	CompanyID     uuid.UUID
	CustomerID    *uuid.UUID
	SalesRepID    *uuid.UUID
	OrderIDs      []uuid.UUID
	Statuses      []enums.OrderStatus
	OrderNumber   *string
	ExternalRef   *string
	Currency      *string
	MinSubtotal   *decimal.Decimal
	MaxSubtotal   *decimal.Decimal
	MinGrandTotal *decimal.Decimal
	MaxGrandTotal *decimal.Decimal
	OrderDateFrom *time.Time
	OrderDateTo   *time.Time
	CreatedFrom   *time.Time
	CreatedTo     *time.Time
	UpdatedFrom   *time.Time
	UpdatedTo     *time.Time
	CreditHold    *bool                    // filter by credit hold status
	CreditStatus  *enums.CreditCheckStatus // filter by credit status
}

// OrderRepository interface (includes partial invoicing support)
type OrderRepository interface {
	Create(ctx context.Context, db DBTX, order *models.Order, items []*models.OrderItem) error
	GetByID(ctx context.Context, db DBTX, companyID, orderID uuid.UUID) (*models.Order, error)
	GetByNumber(ctx context.Context, db DBTX, companyID uuid.UUID, orderNumber string) (*models.Order, error)
	Update(ctx context.Context, db DBTX, order *models.Order) error
	Delete(ctx context.Context, db DBTX, companyID, orderID uuid.UUID) error
	AddItems(ctx context.Context, db DBTX, companyID, orderID uuid.UUID, items []*models.OrderItem) error
	ReplaceItems(ctx context.Context, db DBTX, companyID, orderID uuid.UUID, items []*models.OrderItem) error
	DeleteItem(ctx context.Context, db DBTX, companyID, orderID, orderItemID uuid.UUID) error
	GetItems(ctx context.Context, db DBTX, companyID, orderID uuid.UUID) ([]*models.OrderItem, error)
	GetItemByID(ctx context.Context, db DBTX, companyID, orderID, orderItemID uuid.UUID) (*models.OrderItem, error)
	ExistsItem(ctx context.Context, db DBTX, companyID, orderID, orderItemID uuid.UUID) (bool, error)
	RecalculateTotals(ctx context.Context, db DBTX, companyID, orderID uuid.UUID) error
	GetTotals(ctx context.Context, db DBTX, companyID, orderID uuid.UUID) (subtotal, discountTotal, taxTotal, grandTotal decimal.Decimal, err error)
	UpdateStatus(ctx context.Context, db DBTX, companyID, orderID uuid.UUID, status enums.OrderStatus, updatedBy *uuid.UUID) error
	Confirm(ctx context.Context, db DBTX, companyID, orderID uuid.UUID, confirmedAt time.Time, updatedBy *uuid.UUID) error
	MarkProcessing(ctx context.Context, db DBTX, companyID, orderID uuid.UUID, updatedBy *uuid.UUID) error
	MarkShipped(ctx context.Context, db DBTX, companyID, orderID uuid.UUID, shippedAt time.Time, updatedBy *uuid.UUID) error
	MarkDelivered(ctx context.Context, db DBTX, companyID, orderID uuid.UUID, deliveredAt time.Time, updatedBy *uuid.UUID) error
	Cancel(ctx context.Context, db DBTX, companyID, orderID uuid.UUID, reason string, cancelledAt time.Time, updatedBy *uuid.UUID) error
	Exists(ctx context.Context, db DBTX, companyID, orderID uuid.UUID) (bool, error)
	ExistsByNumber(ctx context.Context, db DBTX, companyID uuid.UUID, orderNumber string) (bool, error)
	ExistsByExternalRef(ctx context.Context, db DBTX, companyID uuid.UUID, externalRef string) (bool, error)
	HasInvoices(ctx context.Context, db DBTX, companyID, orderID uuid.UUID) (bool, error)
	HasReturns(ctx context.Context, db DBTX, companyID, orderID uuid.UUID) (bool, error)
	List(ctx context.Context, db DBTX, filter OrderFilter, p Pagination, s Sort) ([]*models.Order, int64, error)
	Search(ctx context.Context, db DBTX, companyID uuid.UUID, query string, limit, offset int) ([]*models.Order, int64, error)
	GetByCustomer(ctx context.Context, db DBTX, companyID, customerID uuid.UUID, p Pagination, s Sort) ([]*models.Order, int64, error)
	GetPendingOrders(ctx context.Context, db DBTX, companyID uuid.UUID) ([]*models.Order, error)
	GetOrdersReadyForInvoicing(ctx context.Context, db DBTX, companyID uuid.UUID) ([]*models.Order, error)
	GetOrderRevenue(ctx context.Context, db DBTX, companyID uuid.UUID, from, to *time.Time) (decimal.Decimal, error)
	GetAverageOrderValue(ctx context.Context, db DBTX, companyID uuid.UUID, from, to *time.Time) (decimal.Decimal, error)
	GetTopOrdersByValue(ctx context.Context, db DBTX, companyID uuid.UUID, limit int, from, to *time.Time) ([]*models.Order, error)
	GetByIDForUpdate(ctx context.Context, db DBTX, companyID, orderID uuid.UUID) (*models.Order, error)
	GetItemByIDForUpdate(ctx context.Context, db DBTX, companyID, orderID, orderItemID uuid.UUID) (*models.OrderItem, error)
	UpdateTaxTotal(ctx context.Context, db DBTX, companyID, orderID uuid.UUID, taxTotal decimal.Decimal, updatedBy *uuid.UUID) error
	UpdateItemTaxAmount(ctx context.Context, tx DBTX, orderItemID uuid.UUID, taxAmount decimal.Decimal) error

	// NEW FOR PARTIAL INVOICING
	GetRemainingQuantities(ctx context.Context, db DBTX, orderID uuid.UUID) (map[uuid.UUID]decimal.Decimal, error)
	UpdateQuantityInvoiced(ctx context.Context, db DBTX, orderItemID uuid.UUID, invoicedQuantity decimal.Decimal) error
	DecreaseQuantityInvoiced(ctx context.Context, db DBTX, orderItemID uuid.UUID, amount decimal.Decimal) error
}

// -------------------------------------------------------------------------
// Implementation
// -------------------------------------------------------------------------

type orderRepository struct {
	logger *zap.Logger
}

func NewOrderRepository(logger *zap.Logger) OrderRepository {
	return &orderRepository{
		logger: logger.Named("sales_order_repo"),
	}
}

// -------------------------------------------------------------------------
// Helpers
// -------------------------------------------------------------------------

func (r *orderRepository) nullUUIDParam(id *uuid.UUID) interface{} {
	if id == nil || *id == uuid.Nil {
		return nil
	}
	return *id
}

func (r *orderRepository) nullStringParam(s *string) interface{} {
	if s == nil {
		return nil
	}
	return *s
}

func (r *orderRepository) validateSort(s Sort, allowed map[string]bool) (string, error) {
	if s.Field == "" {
		return "", nil
	}
	if !allowed[s.Field] {
		return "", fmt.Errorf("invalid sort field: %s", s.Field)
	}
	dir := strings.ToUpper(s.Direction)
	if dir != "ASC" && dir != "DESC" {
		dir = "ASC"
	}
	return fmt.Sprintf("ORDER BY %s %s", s.Field, dir), nil
}

func (r *orderRepository) validatePagination(p Pagination) (int, int) {
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

// buildOrderFilter now includes credit_hold and credit_status
func (r *orderRepository) buildOrderFilter(filter OrderFilter) (string, []interface{}) {
	var conds []string
	var args []interface{}
	idx := 1

	if filter.CompanyID != uuid.Nil {
		conds = append(conds, fmt.Sprintf("company_id = $%d", idx))
		args = append(args, filter.CompanyID)
		idx++
	}
	if filter.CustomerID != nil {
		conds = append(conds, fmt.Sprintf("customer_id = $%d", idx))
		args = append(args, *filter.CustomerID)
		idx++
	}
	if filter.SalesRepID != nil {
		conds = append(conds, fmt.Sprintf("sales_rep_id = $%d", idx))
		args = append(args, *filter.SalesRepID)
		idx++
	}
	if len(filter.OrderIDs) > 0 {
		placeholders := make([]string, len(filter.OrderIDs))
		for i, id := range filter.OrderIDs {
			placeholders[i] = fmt.Sprintf("$%d", idx)
			args = append(args, id)
			idx++
		}
		conds = append(conds, fmt.Sprintf("order_id IN (%s)", strings.Join(placeholders, ",")))
	}
	if len(filter.Statuses) > 0 {
		placeholders := make([]string, len(filter.Statuses))
		for i, st := range filter.Statuses {
			placeholders[i] = fmt.Sprintf("$%d", idx)
			args = append(args, string(st))
			idx++
		}
		conds = append(conds, fmt.Sprintf("status IN (%s)", strings.Join(placeholders, ",")))
	}
	if filter.OrderNumber != nil {
		conds = append(conds, fmt.Sprintf("order_number = $%d", idx))
		args = append(args, *filter.OrderNumber)
		idx++
	}
	if filter.ExternalRef != nil {
		conds = append(conds, fmt.Sprintf("external_ref = $%d", idx))
		args = append(args, *filter.ExternalRef)
		idx++
	}
	if filter.Currency != nil {
		conds = append(conds, fmt.Sprintf("currency = $%d", idx))
		args = append(args, *filter.Currency)
		idx++
	}
	if filter.MinSubtotal != nil {
		conds = append(conds, fmt.Sprintf("subtotal >= $%d", idx))
		args = append(args, *filter.MinSubtotal)
		idx++
	}
	if filter.MaxSubtotal != nil {
		conds = append(conds, fmt.Sprintf("subtotal <= $%d", idx))
		args = append(args, *filter.MaxSubtotal)
		idx++
	}
	if filter.MinGrandTotal != nil {
		conds = append(conds, fmt.Sprintf("grand_total >= $%d", idx))
		args = append(args, *filter.MinGrandTotal)
		idx++
	}
	if filter.MaxGrandTotal != nil {
		conds = append(conds, fmt.Sprintf("grand_total <= $%d", idx))
		args = append(args, *filter.MaxGrandTotal)
		idx++
	}
	if filter.OrderDateFrom != nil {
		conds = append(conds, fmt.Sprintf("order_date >= $%d", idx))
		args = append(args, *filter.OrderDateFrom)
		idx++
	}
	if filter.OrderDateTo != nil {
		conds = append(conds, fmt.Sprintf("order_date <= $%d", idx))
		args = append(args, *filter.OrderDateTo)
		idx++
	}
	if filter.CreatedFrom != nil {
		conds = append(conds, fmt.Sprintf("created_at >= $%d", idx))
		args = append(args, *filter.CreatedFrom)
		idx++
	}
	if filter.CreatedTo != nil {
		conds = append(conds, fmt.Sprintf("created_at <= $%d", idx))
		args = append(args, *filter.CreatedTo)
		idx++
	}
	if filter.UpdatedFrom != nil {
		conds = append(conds, fmt.Sprintf("updated_at >= $%d", idx))
		args = append(args, *filter.UpdatedFrom)
		idx++
	}
	if filter.UpdatedTo != nil {
		conds = append(conds, fmt.Sprintf("updated_at <= $%d", idx))
		args = append(args, *filter.UpdatedTo)
		idx++
	}
	if filter.CreditHold != nil {
		conds = append(conds, fmt.Sprintf("credit_hold = $%d", idx))
		args = append(args, *filter.CreditHold)
		idx++
	}
	if filter.CreditStatus != nil {
		conds = append(conds, fmt.Sprintf("credit_status = $%d", idx))
		args = append(args, string(*filter.CreditStatus))
		idx++
	}

	if len(conds) == 0 {
		return "", args
	}
	return "WHERE " + strings.Join(conds, " AND "), args
}

// scanOrder now includes credit_hold and credit_status
func (r *orderRepository) scanOrder(s scanner) (*models.Order, error) {
	var o models.Order
	var externalRef, notes, cancellationReason sql.NullString
	var confirmedAt, shippedAt, deliveredAt, cancelledAt sql.NullTime
	var createdBy, updatedBy, salesRepID uuid.NullUUID
	var shippingAddress, billingAddress models.JSONB
	var creditStatus string

	err := s.Scan(
		&o.OrderID,
		&o.CompanyID,
		&o.CustomerID,
		&o.OrderNumber,
		&externalRef,
		&o.OrderDate,
		&o.Status,
		&o.Currency,
		&o.Subtotal,
		&o.DiscountTotal,
		&o.TaxTotal,
		&o.GrandTotal,
		&notes,
		&shippingAddress,
		&billingAddress,
		&confirmedAt,
		&shippedAt,
		&deliveredAt,
		&cancelledAt,
		&cancellationReason,
		&salesRepID,
		&o.CreatedAt,
		&o.UpdatedAt,
		&createdBy,
		&updatedBy,
		&o.CreditHold, // new
		&creditStatus, // new
	)
	if err != nil {
		if err == sql.ErrNoRows {
			return nil, errors.ErrNotFound
		}
		return nil, fmt.Errorf("scan order: %w", err)
	}

	if externalRef.Valid {
		o.ExternalRef = &externalRef.String
	}
	if notes.Valid {
		o.Notes = &notes.String
	}
	if cancellationReason.Valid {
		o.CancellationReason = &cancellationReason.String
	}
	if confirmedAt.Valid {
		o.ConfirmedAt = &confirmedAt.Time
	}
	if shippedAt.Valid {
		o.ShippedAt = &shippedAt.Time
	}
	if deliveredAt.Valid {
		o.DeliveredAt = &deliveredAt.Time
	}
	if cancelledAt.Valid {
		o.CancelledAt = &cancelledAt.Time
	}
	if salesRepID.Valid {
		o.SalesRepID = &salesRepID.UUID
	}
	if createdBy.Valid {
		o.CreatedBy = &createdBy.UUID
	}
	if updatedBy.Valid {
		o.UpdatedBy = &updatedBy.UUID
	}
	o.ShippingAddress = shippingAddress
	o.BillingAddress = billingAddress
	o.CreditStatus = enums.CreditCheckStatus(creditStatus)
	return &o, nil
}

// scanOrderItem now includes the `quantity_invoiced` column if present
func (r *orderRepository) scanOrderItem(s scanner) (*models.OrderItem, error) {
	var i models.OrderItem
	var discountAmount, taxAmount sql.NullString
	var metadata models.JSONB

	err := s.Scan(
		&i.OrderItemID,
		&i.OrderID,
		&i.ProductID,
		&i.ProductNameSnapshot,
		&i.Quantity,
		&i.UnitPrice,
		&discountAmount,
		&taxAmount,
		&i.TotalPrice,
		&metadata,
		&i.CreatedAt,
		&i.QuantityInvoiced, // NEW – scan the new column
	)
	if err != nil {
		if err == sql.ErrNoRows {
			return nil, errors.ErrNotFound
		}
		return nil, fmt.Errorf("scan order item: %w", err)
	}

	if discountAmount.Valid {
		dec, _ := decimal.NewFromString(discountAmount.String)
		i.DiscountAmount = &dec
	}
	if taxAmount.Valid {
		dec, _ := decimal.NewFromString(taxAmount.String)
		i.TaxAmount = &dec
	}
	i.Metadata = metadata
	return &i, nil
}

// -------------------------------------------------------------------------
// ORDER CRUD (with credit fields)
// -------------------------------------------------------------------------

func (r *orderRepository) Create(ctx context.Context, db DBTX, order *models.Order, items []*models.OrderItem) error {
	tx, ok := db.(*sql.Tx)
	if !ok {
		return fmt.Errorf("Create requires a transaction")
	}

	orderQuery := `
		INSERT INTO sales.orders (
			order_id, company_id, customer_id, order_number, external_ref,
			order_date, status, currency, subtotal, discount_total, tax_total,
			notes, shipping_address, billing_address,
			confirmed_at, shipped_at, delivered_at, cancelled_at, cancellation_reason,
			sales_rep_id, created_at, updated_at, created_by, updated_by,
			credit_hold, credit_status
		) VALUES (
			$1, $2, $3, $4, $5,
			$6, $7, $8, $9, $10, $11,
			$12, $13, $14,
			$15, $16, $17, $18, $19,
			$20, NOW(), NOW(), $21, $22,
			$23, $24
		)
		RETURNING created_at, updated_at
	`
	err := tx.QueryRowContext(ctx, orderQuery,
		order.OrderID,
		order.CompanyID,
		order.CustomerID,
		order.OrderNumber,
		r.nullStringParam(order.ExternalRef),
		order.OrderDate,
		order.Status,
		order.Currency,
		order.Subtotal,
		order.DiscountTotal,
		order.TaxTotal,
		r.nullStringParam(order.Notes),
		order.ShippingAddress,
		order.BillingAddress,
		order.ConfirmedAt,
		order.ShippedAt,
		order.DeliveredAt,
		order.CancelledAt,
		r.nullStringParam(order.CancellationReason),
		r.nullUUIDParam(order.SalesRepID),
		r.nullUUIDParam(order.CreatedBy),
		r.nullUUIDParam(order.UpdatedBy),
		order.CreditHold,
		string(order.CreditStatus),
	).Scan(&order.CreatedAt, &order.UpdatedAt)
	if err != nil {
		r.logger.Error("failed to create order", zap.Error(err))
		return fmt.Errorf("create order: %w", err)
	}

	if len(items) > 0 {
		if err := r.AddItems(ctx, tx, order.CompanyID, order.OrderID, items); err != nil {
			return err
		}
	}
	return nil
}

func (r *orderRepository) GetByID(ctx context.Context, db DBTX, companyID, orderID uuid.UUID) (*models.Order, error) {
	query := `
		SELECT 
			order_id, company_id, customer_id, order_number, external_ref,
			order_date, status, currency, subtotal, discount_total, tax_total, grand_total,
			notes, shipping_address, billing_address,
			confirmed_at, shipped_at, delivered_at, cancelled_at, cancellation_reason,
			sales_rep_id, created_at, updated_at, created_by, updated_by,
			credit_hold, credit_status
		FROM sales.orders
		WHERE company_id = $1 AND order_id = $2
	`
	row := db.QueryRowContext(ctx, query, companyID, orderID)
	return r.scanOrder(row)
}

func (r *orderRepository) GetByNumber(ctx context.Context, db DBTX, companyID uuid.UUID, orderNumber string) (*models.Order, error) {
	query := `
		SELECT 
			order_id, company_id, customer_id, order_number, external_ref,
			order_date, status, currency, subtotal, discount_total, tax_total, grand_total,
			notes, shipping_address, billing_address,
			confirmed_at, shipped_at, delivered_at, cancelled_at, cancellation_reason,
			sales_rep_id, created_at, updated_at, created_by, updated_by,
			credit_hold, credit_status
		FROM sales.orders
		WHERE company_id = $1 AND order_number = $2
	`
	row := db.QueryRowContext(ctx, query, companyID, orderNumber)
	return r.scanOrder(row)
}

func (r *orderRepository) Update(ctx context.Context, db DBTX, order *models.Order) error {
	query := `
		UPDATE sales.orders SET
			customer_id = $3,
			order_number = $4,
			external_ref = $5,
			order_date = $6,
			status = $7,
			currency = $8,
			subtotal = $9,
			discount_total = $10,
			tax_total = $11,
			notes = $12,
			shipping_address = $13,
			billing_address = $14,
			confirmed_at = $15,
			shipped_at = $16,
			delivered_at = $17,
			cancelled_at = $18,
			cancellation_reason = $19,
			sales_rep_id = $20,
			credit_hold = $21,
			credit_status = $22,
			updated_at = NOW(),
			updated_by = $23
		WHERE order_id = $1 AND company_id = $2
		RETURNING updated_at
	`
	err := db.QueryRowContext(ctx, query,
		order.OrderID,
		order.CompanyID,
		order.CustomerID,
		order.OrderNumber,
		r.nullStringParam(order.ExternalRef),
		order.OrderDate,
		order.Status,
		order.Currency,
		order.Subtotal,
		order.DiscountTotal,
		order.TaxTotal,
		r.nullStringParam(order.Notes),
		order.ShippingAddress,
		order.BillingAddress,
		order.ConfirmedAt,
		order.ShippedAt,
		order.DeliveredAt,
		order.CancelledAt,
		r.nullStringParam(order.CancellationReason),
		r.nullUUIDParam(order.SalesRepID),
		order.CreditHold,
		string(order.CreditStatus),
		r.nullUUIDParam(order.UpdatedBy),
	).Scan(&order.UpdatedAt)
	if err != nil {
		if err == sql.ErrNoRows {
			return errors.ErrNotFound
		}
		return fmt.Errorf("update order: %w", err)
	}
	return nil
}

func (r *orderRepository) Delete(ctx context.Context, db DBTX, companyID, orderID uuid.UUID) error {
	query := `DELETE FROM sales.orders WHERE company_id = $1 AND order_id = $2`
	result, err := db.ExecContext(ctx, query, companyID, orderID)
	if err != nil {
		return fmt.Errorf("delete order: %w", err)
	}
	rows, _ := result.RowsAffected()
	if rows == 0 {
		return errors.ErrNotFound
	}
	return nil
}

// -------------------------------------------------------------------------
// ORDER ITEMS (with quantity_invoiced support)
// -------------------------------------------------------------------------

func (r *orderRepository) AddItems(ctx context.Context, db DBTX, companyID, orderID uuid.UUID, items []*models.OrderItem) error {
	if len(items) == 0 {
		return nil
	}
	var exists bool
	checkQuery := `SELECT EXISTS(SELECT 1 FROM sales.orders WHERE company_id = $1 AND order_id = $2)`
	err := db.QueryRowContext(ctx, checkQuery, companyID, orderID).Scan(&exists)
	if err != nil || !exists {
		return errors.ErrNotFound
	}

	query := `
		INSERT INTO sales.order_items (
			order_item_id, order_id, product_id, product_name_snapshot,
			quantity, unit_price, discount_amount, tax_amount, metadata, created_at,
			quantity_invoiced
		) VALUES (
			$1, $2, $3, $4, $5, $6, $7, $8, $9, NOW(), $10
		)
	`
	for _, item := range items {
		_, err := db.ExecContext(ctx, query,
			item.OrderItemID,
			orderID,
			item.ProductID,
			item.ProductNameSnapshot,
			item.Quantity,
			item.UnitPrice,
			item.DiscountAmount,
			item.TaxAmount,
			item.Metadata,
			item.QuantityInvoiced, // default 0, can be set if needed
		)
		if err != nil {
			return fmt.Errorf("add order item: %w", err)
		}
	}
	return nil
}

func (r *orderRepository) ReplaceItems(ctx context.Context, db DBTX, companyID, orderID uuid.UUID, items []*models.OrderItem) error {
	delQuery := `DELETE FROM sales.order_items WHERE order_id = $1`
	_, err := db.ExecContext(ctx, delQuery, orderID)
	if err != nil {
		return fmt.Errorf("delete existing items: %w", err)
	}
	return r.AddItems(ctx, db, companyID, orderID, items)
}

func (r *orderRepository) DeleteItem(ctx context.Context, db DBTX, companyID, orderID, orderItemID uuid.UUID) error {
	var exists bool
	checkQuery := `SELECT EXISTS(SELECT 1 FROM sales.orders WHERE company_id = $1 AND order_id = $2)`
	err := db.QueryRowContext(ctx, checkQuery, companyID, orderID).Scan(&exists)
	if err != nil || !exists {
		return errors.ErrNotFound
	}
	query := `DELETE FROM sales.order_items WHERE order_item_id = $1 AND order_id = $2`
	result, err := db.ExecContext(ctx, query, orderItemID, orderID)
	if err != nil {
		return fmt.Errorf("delete order item: %w", err)
	}
	rows, _ := result.RowsAffected()
	if rows == 0 {
		return errors.ErrNotFound
	}
	return nil
}

func (r *orderRepository) GetItems(ctx context.Context, db DBTX, companyID, orderID uuid.UUID) ([]*models.OrderItem, error) {
	var exists bool
	checkQuery := `SELECT EXISTS(SELECT 1 FROM sales.orders WHERE company_id = $1 AND order_id = $2)`
	err := db.QueryRowContext(ctx, checkQuery, companyID, orderID).Scan(&exists)
	if err != nil || !exists {
		return nil, errors.ErrNotFound
	}
	query := `
		SELECT 
			order_item_id, order_id, product_id, product_name_snapshot,
			quantity, unit_price, discount_amount, tax_amount, total_price, metadata, created_at,
			quantity_invoiced
		FROM sales.order_items
		WHERE order_id = $1
		ORDER BY created_at
	`
	rows, err := db.QueryContext(ctx, query, orderID)
	if err != nil {
		return nil, fmt.Errorf("get order items: %w", err)
	}
	defer rows.Close()

	var result []*models.OrderItem
	for rows.Next() {
		item, err := r.scanOrderItem(rows)
		if err != nil {
			return nil, err
		}
		result = append(result, item)
	}
	return result, rows.Err()
}

func (r *orderRepository) GetItemByID(ctx context.Context, db DBTX, companyID, orderID, orderItemID uuid.UUID) (*models.OrderItem, error) {
	var exists bool
	checkQuery := `SELECT EXISTS(SELECT 1 FROM sales.orders WHERE company_id = $1 AND order_id = $2)`
	err := db.QueryRowContext(ctx, checkQuery, companyID, orderID).Scan(&exists)
	if err != nil || !exists {
		return nil, errors.ErrNotFound
	}
	query := `
		SELECT 
			order_item_id, order_id, product_id, product_name_snapshot,
			quantity, unit_price, discount_amount, tax_amount, total_price, metadata, created_at,
			quantity_invoiced
		FROM sales.order_items
		WHERE order_item_id = $1 AND order_id = $2
	`
	row := db.QueryRowContext(ctx, query, orderItemID, orderID)
	return r.scanOrderItem(row)
}

func (r *orderRepository) ExistsItem(ctx context.Context, db DBTX, companyID, orderID, orderItemID uuid.UUID) (bool, error) {
	var exists bool
	query := `
		SELECT EXISTS(
			SELECT 1 FROM sales.order_items oi
			JOIN sales.orders o ON oi.order_id = o.order_id
			WHERE o.company_id = $1 AND o.order_id = $2 AND oi.order_item_id = $3
		)
	`
	err := db.QueryRowContext(ctx, query, companyID, orderID, orderItemID).Scan(&exists)
	if err != nil {
		return false, fmt.Errorf("exists item: %w", err)
	}
	return exists, nil
}

// -------------------------------------------------------------------------
// TOTALS / FINANCIALS (unchanged)
// -------------------------------------------------------------------------

func (r *orderRepository) RecalculateTotals(ctx context.Context, db DBTX, companyID, orderID uuid.UUID) error {
	query := `
		SELECT 
			COALESCE(SUM(total_price), 0) as subtotal,
			COALESCE(SUM(discount_amount), 0) as discount_total,
			COALESCE(SUM(tax_amount), 0) as tax_total
		FROM sales.order_items
		WHERE order_id = $1
	`
	var subtotal, discountTotal, taxTotal decimal.Decimal
	err := db.QueryRowContext(ctx, query, orderID).Scan(&subtotal, &discountTotal, &taxTotal)
	if err != nil {
		return fmt.Errorf("recalculate totals: %w", err)
	}
	updateQuery := `
		UPDATE sales.orders
		SET subtotal = $1, discount_total = $2, tax_total = $3, updated_at = NOW()
		WHERE order_id = $4 AND company_id = $5
	`
	_, err = db.ExecContext(ctx, updateQuery, subtotal, discountTotal, taxTotal, orderID, companyID)
	if err != nil {
		return fmt.Errorf("update order totals: %w", err)
	}
	return nil
}

func (r *orderRepository) GetTotals(ctx context.Context, db DBTX, companyID, orderID uuid.UUID) (
	subtotal decimal.Decimal, discountTotal decimal.Decimal, taxTotal decimal.Decimal, grandTotal decimal.Decimal, err error,
) {
	query := `
		SELECT subtotal, discount_total, tax_total, grand_total
		FROM sales.orders
		WHERE company_id = $1 AND order_id = $2
	`
	err = db.QueryRowContext(ctx, query, companyID, orderID).Scan(&subtotal, &discountTotal, &taxTotal, &grandTotal)
	if err != nil {
		if err == sql.ErrNoRows {
			err = errors.ErrNotFound
		}
		return
	}
	return
}

// -------------------------------------------------------------------------
// STATUS / LIFECYCLE (unchanged)
// -------------------------------------------------------------------------

func (r *orderRepository) UpdateStatus(ctx context.Context, db DBTX, companyID, orderID uuid.UUID, status enums.OrderStatus, updatedBy *uuid.UUID) error {
	query := `
		UPDATE sales.orders
		SET status = $3, updated_at = NOW(), updated_by = $4
		WHERE company_id = $1 AND order_id = $2
	`
	result, err := db.ExecContext(ctx, query, companyID, orderID, status, r.nullUUIDParam(updatedBy))
	if err != nil {
		return fmt.Errorf("update status: %w", err)
	}
	rows, _ := result.RowsAffected()
	if rows == 0 {
		return errors.ErrNotFound
	}
	return nil
}

func (r *orderRepository) Confirm(ctx context.Context, db DBTX, companyID, orderID uuid.UUID, confirmedAt time.Time, updatedBy *uuid.UUID) error {
	query := `
		UPDATE sales.orders
		SET status = 'confirmed', confirmed_at = $3, updated_at = NOW(), updated_by = $4
		WHERE company_id = $1 AND order_id = $2
	`
	result, err := db.ExecContext(ctx, query, companyID, orderID, confirmedAt, r.nullUUIDParam(updatedBy))
	if err != nil {
		return fmt.Errorf("confirm order: %w", err)
	}
	rows, _ := result.RowsAffected()
	if rows == 0 {
		return errors.ErrNotFound
	}
	return nil
}

func (r *orderRepository) MarkProcessing(ctx context.Context, db DBTX, companyID, orderID uuid.UUID, updatedBy *uuid.UUID) error {
	return r.UpdateStatus(ctx, db, companyID, orderID, enums.OrderStatusProcessing, updatedBy)
}

func (r *orderRepository) MarkShipped(ctx context.Context, db DBTX, companyID, orderID uuid.UUID, shippedAt time.Time, updatedBy *uuid.UUID) error {
	query := `
		UPDATE sales.orders
		SET status = 'shipped', shipped_at = $3, updated_at = NOW(), updated_by = $4
		WHERE company_id = $1 AND order_id = $2
	`
	result, err := db.ExecContext(ctx, query, companyID, orderID, shippedAt, r.nullUUIDParam(updatedBy))
	if err != nil {
		return fmt.Errorf("mark shipped: %w", err)
	}
	rows, _ := result.RowsAffected()
	if rows == 0 {
		return errors.ErrNotFound
	}
	return nil
}

func (r *orderRepository) MarkDelivered(ctx context.Context, db DBTX, companyID, orderID uuid.UUID, deliveredAt time.Time, updatedBy *uuid.UUID) error {
	query := `
		UPDATE sales.orders
		SET status = 'delivered', delivered_at = $3, updated_at = NOW(), updated_by = $4
		WHERE company_id = $1 AND order_id = $2
	`
	result, err := db.ExecContext(ctx, query, companyID, orderID, deliveredAt, r.nullUUIDParam(updatedBy))
	if err != nil {
		return fmt.Errorf("mark delivered: %w", err)
	}
	rows, _ := result.RowsAffected()
	if rows == 0 {
		return errors.ErrNotFound
	}
	return nil
}

func (r *orderRepository) Cancel(ctx context.Context, db DBTX, companyID, orderID uuid.UUID, reason string, cancelledAt time.Time, updatedBy *uuid.UUID) error {
	query := `
		UPDATE sales.orders
		SET status = 'cancelled', cancelled_at = $3, cancellation_reason = $4, updated_at = NOW(), updated_by = $5
		WHERE company_id = $1 AND order_id = $2
	`
	result, err := db.ExecContext(ctx, query, companyID, orderID, cancelledAt, reason, r.nullUUIDParam(updatedBy))
	if err != nil {
		return fmt.Errorf("cancel order: %w", err)
	}
	rows, _ := result.RowsAffected()
	if rows == 0 {
		return errors.ErrNotFound
	}
	return nil
}

// -------------------------------------------------------------------------
// EXISTENCE / VALIDATION (unchanged)
// -------------------------------------------------------------------------

func (r *orderRepository) Exists(ctx context.Context, db DBTX, companyID, orderID uuid.UUID) (bool, error) {
	var exists bool
	query := `SELECT EXISTS(SELECT 1 FROM sales.orders WHERE company_id = $1 AND order_id = $2)`
	err := db.QueryRowContext(ctx, query, companyID, orderID).Scan(&exists)
	if err != nil {
		return false, fmt.Errorf("exists: %w", err)
	}
	return exists, nil
}

func (r *orderRepository) ExistsByNumber(ctx context.Context, db DBTX, companyID uuid.UUID, orderNumber string) (bool, error) {
	var exists bool
	query := `SELECT EXISTS(SELECT 1 FROM sales.orders WHERE company_id = $1 AND order_number = $2)`
	err := db.QueryRowContext(ctx, query, companyID, orderNumber).Scan(&exists)
	if err != nil {
		return false, fmt.Errorf("exists by number: %w", err)
	}
	return exists, nil
}

func (r *orderRepository) ExistsByExternalRef(ctx context.Context, db DBTX, companyID uuid.UUID, externalRef string) (bool, error) {
	var exists bool
	query := `SELECT EXISTS(SELECT 1 FROM sales.orders WHERE company_id = $1 AND external_ref = $2)`
	err := db.QueryRowContext(ctx, query, companyID, externalRef).Scan(&exists)
	if err != nil {
		return false, fmt.Errorf("exists by external ref: %w", err)
	}
	return exists, nil
}

func (r *orderRepository) HasInvoices(ctx context.Context, db DBTX, companyID, orderID uuid.UUID) (bool, error) {
	var exists bool
	query := `SELECT EXISTS(SELECT 1 FROM sales.invoices WHERE company_id = $1 AND order_id = $2)`
	err := db.QueryRowContext(ctx, query, companyID, orderID).Scan(&exists)
	if err != nil {
		return false, fmt.Errorf("has invoices: %w", err)
	}
	return exists, nil
}

func (r *orderRepository) HasReturns(ctx context.Context, db DBTX, companyID, orderID uuid.UUID) (bool, error) {
	var exists bool
	query := `SELECT EXISTS(SELECT 1 FROM sales.returns WHERE company_id = $1 AND order_id = $2)`
	err := db.QueryRowContext(ctx, query, companyID, orderID).Scan(&exists)
	if err != nil {
		return false, fmt.Errorf("has returns: %w", err)
	}
	return exists, nil
}

// -------------------------------------------------------------------------
// QUERYING / LISTING (with credit fields)
// -------------------------------------------------------------------------

func (r *orderRepository) List(ctx context.Context, db DBTX, filter OrderFilter, p Pagination, s Sort) ([]*models.Order, int64, error) {
	where, args := r.buildOrderFilter(filter)
	if where == "" {
		return nil, 0, fmt.Errorf("list requires at least company_id filter")
	}
	allowedSort := map[string]bool{
		"order_number":  true,
		"order_date":    true,
		"status":        true,
		"customer_id":   true,
		"subtotal":      true,
		"grand_total":   true,
		"created_at":    true,
		"updated_at":    true,
		"credit_hold":   true,
		"credit_status": true,
	}
	orderBy, err := r.validateSort(s, allowedSort)
	if err != nil {
		return nil, 0, err
	}
	if orderBy == "" {
		orderBy = "ORDER BY order_date DESC"
	}
	limit, offset := r.validatePagination(p)

	countQuery := fmt.Sprintf("SELECT COUNT(*) FROM sales.orders %s", where)
	var total int64
	err = db.QueryRowContext(ctx, countQuery, args...).Scan(&total)
	if err != nil {
		return nil, 0, fmt.Errorf("count orders: %w", err)
	}
	if total == 0 {
		return []*models.Order{}, 0, nil
	}

	query := fmt.Sprintf(`
		SELECT 
			order_id, company_id, customer_id, order_number, external_ref,
			order_date, status, currency, subtotal, discount_total, tax_total, grand_total,
			notes, shipping_address, billing_address,
			confirmed_at, shipped_at, delivered_at, cancelled_at, cancellation_reason,
			sales_rep_id, created_at, updated_at, created_by, updated_by,
			credit_hold, credit_status
		FROM sales.orders
		%s
		%s
		LIMIT $%d OFFSET $%d
	`, where, orderBy, len(args)+1, len(args)+2)
	args = append(args, limit, offset)

	rows, err := db.QueryContext(ctx, query, args...)
	if err != nil {
		return nil, 0, fmt.Errorf("list orders: %w", err)
	}
	defer rows.Close()

	var result []*models.Order
	for rows.Next() {
		order, err := r.scanOrder(rows)
		if err != nil {
			return nil, 0, err
		}
		result = append(result, order)
	}
	return result, total, rows.Err()
}

func (r *orderRepository) Search(ctx context.Context, db DBTX, companyID uuid.UUID, queryStr string, limit, offset int) ([]*models.Order, int64, error) {
	searchPattern := "%" + queryStr + "%"
	baseArgs := []interface{}{companyID, searchPattern, searchPattern, searchPattern}
	countQuery := `
		SELECT COUNT(*)
		FROM sales.orders
		WHERE company_id = $1
		AND (order_number ILIKE $2 OR external_ref ILIKE $3 OR notes ILIKE $4)
	`
	var total int64
	err := db.QueryRowContext(ctx, countQuery, baseArgs...).Scan(&total)
	if err != nil {
		return nil, 0, fmt.Errorf("search count: %w", err)
	}
	if total == 0 {
		return []*models.Order{}, 0, nil
	}

	dataQuery := `
		SELECT 
			order_id, company_id, customer_id, order_number, external_ref,
			order_date, status, currency, subtotal, discount_total, tax_total, grand_total,
			notes, shipping_address, billing_address,
			confirmed_at, shipped_at, delivered_at, cancelled_at, cancellation_reason,
			sales_rep_id, created_at, updated_at, created_by, updated_by,
			credit_hold, credit_status
		FROM sales.orders
		WHERE company_id = $1
		AND (order_number ILIKE $2 OR external_ref ILIKE $3 OR notes ILIKE $4)
		ORDER BY order_date DESC
		LIMIT $5 OFFSET $6
	`
	args := append(baseArgs, limit, offset)
	rows, err := db.QueryContext(ctx, dataQuery, args...)
	if err != nil {
		return nil, 0, fmt.Errorf("search data: %w", err)
	}
	defer rows.Close()

	var result []*models.Order
	for rows.Next() {
		order, err := r.scanOrder(rows)
		if err != nil {
			return nil, 0, err
		}
		result = append(result, order)
	}
	return result, total, rows.Err()
}

func (r *orderRepository) GetByCustomer(ctx context.Context, db DBTX, companyID, customerID uuid.UUID, p Pagination, s Sort) ([]*models.Order, int64, error) {
	filter := OrderFilter{
		CompanyID:  companyID,
		CustomerID: &customerID,
	}
	return r.List(ctx, db, filter, p, s)
}

func (r *orderRepository) GetPendingOrders(ctx context.Context, db DBTX, companyID uuid.UUID) ([]*models.Order, error) {
	filter := OrderFilter{
		CompanyID: companyID,
		Statuses:  []enums.OrderStatus{enums.OrderStatusDraft, enums.OrderStatusConfirmed, enums.OrderStatusProcessing},
	}
	orders, _, err := r.List(ctx, db, filter, Pagination{Limit: 1000, Offset: 0}, Sort{Field: "order_date", Direction: "ASC"})
	return orders, err
}

func (r *orderRepository) GetOrdersReadyForInvoicing(ctx context.Context, db DBTX, companyID uuid.UUID) ([]*models.Order, error) {
	query := `
		SELECT 
			o.order_id, o.company_id, o.customer_id, o.order_number, o.external_ref,
			o.order_date, o.status, o.currency, o.subtotal, o.discount_total, o.tax_total, o.grand_total,
			o.notes, o.shipping_address, o.billing_address,
			o.confirmed_at, o.shipped_at, o.delivered_at, o.cancelled_at, o.cancellation_reason,
			o.sales_rep_id, o.created_at, o.updated_at, o.created_by, o.updated_by,
			o.credit_hold, o.credit_status
		FROM sales.orders o
		LEFT JOIN sales.invoices i ON o.order_id = i.order_id
		WHERE o.company_id = $1
		AND o.status IN ('confirmed', 'processing')
		AND i.invoice_id IS NULL
		ORDER BY o.order_date
	`
	rows, err := db.QueryContext(ctx, query, companyID)
	if err != nil {
		return nil, fmt.Errorf("orders ready for invoicing: %w", err)
	}
	defer rows.Close()

	var result []*models.Order
	for rows.Next() {
		order, err := r.scanOrder(rows)
		if err != nil {
			return nil, err
		}
		result = append(result, order)
	}
	return result, rows.Err()
}

// -------------------------------------------------------------------------
// ANALYTICS / REPORTING (unchanged)
// -------------------------------------------------------------------------

func (r *orderRepository) GetOrderRevenue(ctx context.Context, db DBTX, companyID uuid.UUID, from, to *time.Time) (decimal.Decimal, error) {
	var conds []string
	var args []interface{}
	idx := 1
	conds = append(conds, fmt.Sprintf("company_id = $%d", idx))
	args = append(args, companyID)
	idx++
	conds = append(conds, "status IN ('confirmed','processing','shipped','delivered')")
	if from != nil {
		conds = append(conds, fmt.Sprintf("order_date >= $%d", idx))
		args = append(args, *from)
		idx++
	}
	if to != nil {
		conds = append(conds, fmt.Sprintf("order_date <= $%d", idx))
		args = append(args, *to)
		idx++
	}
	whereClause := strings.Join(conds, " AND ")
	query := fmt.Sprintf("SELECT COALESCE(SUM(grand_total), 0) FROM sales.orders WHERE %s", whereClause)
	var revenue decimal.Decimal
	err := db.QueryRowContext(ctx, query, args...).Scan(&revenue)
	if err != nil {
		return decimal.Zero, fmt.Errorf("get order revenue: %w", err)
	}
	return revenue, nil
}

func (r *orderRepository) GetAverageOrderValue(ctx context.Context, db DBTX, companyID uuid.UUID, from, to *time.Time) (decimal.Decimal, error) {
	var conds []string
	var args []interface{}
	idx := 1
	conds = append(conds, fmt.Sprintf("company_id = $%d", idx))
	args = append(args, companyID)
	idx++
	conds = append(conds, "status IN ('confirmed','processing','shipped','delivered')")
	if from != nil {
		conds = append(conds, fmt.Sprintf("order_date >= $%d", idx))
		args = append(args, *from)
		idx++
	}
	if to != nil {
		conds = append(conds, fmt.Sprintf("order_date <= $%d", idx))
		args = append(args, *to)
		idx++
	}
	whereClause := strings.Join(conds, " AND ")
	query := fmt.Sprintf("SELECT COALESCE(AVG(grand_total), 0) FROM sales.orders WHERE %s", whereClause)
	var avg decimal.Decimal
	err := db.QueryRowContext(ctx, query, args...).Scan(&avg)
	if err != nil {
		return decimal.Zero, fmt.Errorf("get average order value: %w", err)
	}
	return avg, nil
}

func (r *orderRepository) GetTopOrdersByValue(ctx context.Context, db DBTX, companyID uuid.UUID, limit int, from, to *time.Time) ([]*models.Order, error) {
	var conds []string
	var args []interface{}
	idx := 1
	conds = append(conds, fmt.Sprintf("company_id = $%d", idx))
	args = append(args, companyID)
	idx++
	conds = append(conds, "status IN ('confirmed','processing','shipped','delivered')")
	if from != nil {
		conds = append(conds, fmt.Sprintf("order_date >= $%d", idx))
		args = append(args, *from)
		idx++
	}
	if to != nil {
		conds = append(conds, fmt.Sprintf("order_date <= $%d", idx))
		args = append(args, *to)
		idx++
	}
	whereClause := strings.Join(conds, " AND ")
	query := fmt.Sprintf(`
		SELECT 
			order_id, company_id, customer_id, order_number, external_ref,
			order_date, status, currency, subtotal, discount_total, tax_total, grand_total,
			notes, shipping_address, billing_address,
			confirmed_at, shipped_at, delivered_at, cancelled_at, cancellation_reason,
			sales_rep_id, created_at, updated_at, created_by, updated_by,
			credit_hold, credit_status
		FROM sales.orders
		WHERE %s
		ORDER BY grand_total DESC
		LIMIT $%d
	`, whereClause, idx)
	args = append(args, limit)

	rows, err := db.QueryContext(ctx, query, args...)
	if err != nil {
		return nil, fmt.Errorf("get top orders: %w", err)
	}
	defer rows.Close()

	var result []*models.Order
	for rows.Next() {
		order, err := r.scanOrder(rows)
		if err != nil {
			return nil, err
		}
		result = append(result, order)
	}
	return result, rows.Err()
}

// -------------------------------------------------------------------------
// CONCURRENCY / LOCKING (with credit fields)
// -------------------------------------------------------------------------

func (r *orderRepository) GetByIDForUpdate(ctx context.Context, db DBTX, companyID, orderID uuid.UUID) (*models.Order, error) {
	query := `
		SELECT 
			order_id, company_id, customer_id, order_number, external_ref,
			order_date, status, currency, subtotal, discount_total, tax_total, grand_total,
			notes, shipping_address, billing_address,
			confirmed_at, shipped_at, delivered_at, cancelled_at, cancellation_reason,
			sales_rep_id, created_at, updated_at, created_by, updated_by,
			credit_hold, credit_status
		FROM sales.orders
		WHERE company_id = $1 AND order_id = $2
		FOR UPDATE
	`
	row := db.QueryRowContext(ctx, query, companyID, orderID)
	return r.scanOrder(row)
}

func (r *orderRepository) GetItemByIDForUpdate(ctx context.Context, db DBTX, companyID, orderID, orderItemID uuid.UUID) (*models.OrderItem, error) {
	query := `
		SELECT 
			oi.order_item_id, oi.order_id, oi.product_id, oi.product_name_snapshot,
			oi.quantity, oi.unit_price, oi.discount_amount, oi.tax_amount, oi.total_price, oi.metadata, oi.created_at,
			oi.quantity_invoiced
		FROM sales.order_items oi
		JOIN sales.orders o ON oi.order_id = o.order_id
		WHERE o.company_id = $1 AND o.order_id = $2 AND oi.order_item_id = $3
		FOR UPDATE
	`
	row := db.QueryRowContext(ctx, query, companyID, orderID, orderItemID)
	return r.scanOrderItem(row)
}

// -------------------------------------------------------------------------
// NEW METHODS FOR PARTIAL INVOICING
// -------------------------------------------------------------------------

// GetRemainingQuantities returns a map of order_item_id -> remaining quantity (quantity - quantity_invoiced)
func (r *orderRepository) GetRemainingQuantities(ctx context.Context, db DBTX, orderID uuid.UUID) (map[uuid.UUID]decimal.Decimal, error) {
	query := `
		SELECT order_item_id, quantity - quantity_invoiced AS remaining
		FROM sales.order_items
		WHERE order_id = $1
	`
	rows, err := db.QueryContext(ctx, query, orderID)
	if err != nil {
		return nil, fmt.Errorf("get remaining quantities: %w", err)
	}
	defer rows.Close()

	result := make(map[uuid.UUID]decimal.Decimal)
	for rows.Next() {
		var itemID uuid.UUID
		var remaining decimal.Decimal
		if err := rows.Scan(&itemID, &remaining); err != nil {
			return nil, err
		}
		result[itemID] = remaining
	}
	return result, rows.Err()
}

// UpdateQuantityInvoiced increments the quantity_invoiced for a given order item.
func (r *orderRepository) UpdateQuantityInvoiced(ctx context.Context, db DBTX, orderItemID uuid.UUID, invoicedQuantity decimal.Decimal) error {
	query := `
		UPDATE sales.order_items
		SET quantity_invoiced = quantity_invoiced + $2,
		    updated_at = NOW()
		WHERE order_item_id = $1
	`
	res, err := db.ExecContext(ctx, query, orderItemID, invoicedQuantity)
	if err != nil {
		return fmt.Errorf("update quantity_invoiced: %w", err)
	}
	rows, _ := res.RowsAffected()
	if rows == 0 {
		return errors.ErrNotFound
	}
	return nil
}

// DecreaseQuantityInvoiced decreases the quantity_invoiced for a given order item (used when an invoice is cancelled/voided).
func (r *orderRepository) DecreaseQuantityInvoiced(ctx context.Context, db DBTX, orderItemID uuid.UUID, amount decimal.Decimal) error {
	query := `
		UPDATE sales.order_items
		SET quantity_invoiced = quantity_invoiced - $2,
		    updated_at = NOW()
		WHERE order_item_id = $1 AND quantity_invoiced >= $2
	`
	res, err := db.ExecContext(ctx, query, orderItemID, amount)
	if err != nil {
		return fmt.Errorf("decrease quantity_invoiced: %w", err)
	}
	rows, _ := res.RowsAffected()
	if rows == 0 {
		return errors.ErrInvalidState // or a more specific error
	}
	return nil
}

// UpdateTaxTotal updates the tax_total of an order.
func (r *orderRepository) UpdateTaxTotal(ctx context.Context, db DBTX, companyID, orderID uuid.UUID, taxTotal decimal.Decimal, updatedBy *uuid.UUID) error {
	query := `
		UPDATE sales.orders
		SET tax_total = $1, updated_at = NOW(), updated_by = $3
		WHERE company_id = $2 AND order_id = $4
	`
	result, err := db.ExecContext(ctx, query, taxTotal, companyID, r.nullUUIDParam(updatedBy), orderID)
	if err != nil {
		return fmt.Errorf("update tax total: %w", err)
	}
	rows, _ := result.RowsAffected()
	if rows == 0 {
		return errors.ErrNotFound
	}
	return nil
}
func (r *orderRepository) UpdateItemTaxAmount(ctx context.Context, tx DBTX, orderItemID uuid.UUID, taxAmount decimal.Decimal) error {
	query := `UPDATE sales.order_items SET tax_amount = $1 WHERE order_item_id = $2`
	res, err := tx.ExecContext(ctx, query, taxAmount, orderItemID)
	if err != nil {
		return fmt.Errorf("update item tax amount: %w", err)
	}
	rows, _ := res.RowsAffected()
	if rows == 0 {
		return errors.ErrNotFound
	}
	return nil
}

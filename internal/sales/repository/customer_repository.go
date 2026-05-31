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
)

// -------------------------------------------------------------------------
// Types & Interface
// -------------------------------------------------------------------------

type CustomerRepository interface {
	Create(ctx context.Context, db DBTX, customer *models.Customer) error
	GetByID(ctx context.Context, db DBTX, companyID, customerID uuid.UUID) (*models.Customer, error)
	GetByCode(ctx context.Context, db DBTX, companyID uuid.UUID, customerCode string) (*models.Customer, error)
	Update(ctx context.Context, db DBTX, customer *models.Customer) error
	Delete(ctx context.Context, db DBTX, companyID, customerID uuid.UUID) error
	ExistsByEmailHashExcluding(ctx context.Context, db DBTX, companyID uuid.UUID, emailHash string, excludeCustomerID uuid.UUID) (bool, error)

	SetActiveStatus(ctx context.Context, db DBTX, companyID, customerID uuid.UUID, isActive bool, updatedBy *uuid.UUID) error
	Exists(ctx context.Context, db DBTX, companyID, customerID uuid.UUID) (bool, error)
	ExistsByCode(ctx context.Context, db DBTX, companyID uuid.UUID, customerCode string) (bool, error)
	ExistsByEmailHash(ctx context.Context, db DBTX, companyID uuid.UUID, emailHash string) (bool, error) // NEW
	IsActive(ctx context.Context, db DBTX, companyID, customerID uuid.UUID) (bool, error)

	ExistsByEncryptedEmail(ctx context.Context, db DBTX, companyID uuid.UUID, emailEncrypted string) (bool, error)
	ExistsByEncryptedPhone(ctx context.Context, db DBTX, companyID uuid.UUID, phoneEncrypted string) (bool, error)

	GetCreditLimit(ctx context.Context, db DBTX, companyID, customerID uuid.UUID) (*models.Customer, error)
	GetCustomersWithOutstandingInvoices(ctx context.Context, db DBTX, companyID uuid.UUID) ([]*models.Customer, error)
	GetTopCustomersByRevenue(ctx context.Context, db DBTX, companyID uuid.UUID, limit int, from, to *time.Time) ([]*models.Customer, error)

	List(ctx context.Context, db DBTX, filter CustomerFilter, p Pagination, s Sort) ([]*models.Customer, int64, error)
	Search(ctx context.Context, db DBTX, companyID uuid.UUID, query string, limit, offset int) ([]*models.Customer, int64, error)

	GetByIDForUpdate(ctx context.Context, db DBTX, companyID, customerID uuid.UUID) (*models.Customer, error)
}

type CustomerFilter struct {
	CompanyID    uuid.UUID
	IsActive     *bool
	CustomerIDs  []uuid.UUID
	CustomerCode *string
	Name         *string
	CreatedFrom  *time.Time
	CreatedTo    *time.Time
	UpdatedFrom  *time.Time
	UpdatedTo    *time.Time
}

type customerRepository struct {
	logger *zap.Logger
}

func NewCustomerRepository(logger *zap.Logger) CustomerRepository {
	return &customerRepository{
		logger: logger.Named("sales_customer_repo"),
	}
}

// -------------------------------------------------------------------------
// Helpers
// -------------------------------------------------------------------------

func (r *customerRepository) nullUUIDParam(id *uuid.UUID) interface{} {
	if id == nil || *id == uuid.Nil {
		return nil
	}
	return *id
}

func (r *customerRepository) validateSort(s Sort, allowed map[string]bool) (string, error) {
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

func (r *customerRepository) validatePagination(p Pagination) (int, int) {
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

func (r *customerRepository) buildFilter(filter CustomerFilter) (string, []interface{}) {
	var conds []string
	var args []interface{}
	idx := 1

	if filter.CompanyID != uuid.Nil {
		conds = append(conds, fmt.Sprintf("company_id = $%d", idx))
		args = append(args, filter.CompanyID)
		idx++
	}
	if filter.IsActive != nil {
		conds = append(conds, fmt.Sprintf("is_active = $%d", idx))
		args = append(args, *filter.IsActive)
		idx++
	}
	if len(filter.CustomerIDs) > 0 {
		placeholders := make([]string, len(filter.CustomerIDs))
		for i, id := range filter.CustomerIDs {
			placeholders[i] = fmt.Sprintf("$%d", idx)
			args = append(args, id)
			idx++
		}
		conds = append(conds, fmt.Sprintf("customer_id IN (%s)", strings.Join(placeholders, ",")))
	}
	if filter.CustomerCode != nil {
		conds = append(conds, fmt.Sprintf("customer_code = $%d", idx))
		args = append(args, *filter.CustomerCode)
		idx++
	}
	if filter.Name != nil {
		conds = append(conds, fmt.Sprintf("name ILIKE $%d", idx))
		args = append(args, "%"+*filter.Name+"%")
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

	if len(conds) == 0 {
		return "", args
	}
	return "WHERE " + strings.Join(conds, " AND "), args
}

// scanCustomer maps a database row to models.Customer (including encrypted fields + payment_term_id + email_hash)
func (r *customerRepository) scanCustomer(s scanner) (*models.Customer, error) {
	var c models.Customer
	var createdBy, updatedBy uuid.NullUUID
	var creditLimit sql.NullString
	var paymentTermID uuid.NullUUID
	var emailHash sql.NullString

	err := s.Scan(
		&c.CustomerID,
		&c.CompanyID,
		&c.CustomerCode,
		&c.Name,
		&c.EmailEncrypted, &c.EmailDEK, &c.EmailKeyID,
		&c.PhoneEncrypted, &c.PhoneDEK, &c.PhoneKeyID,
		&c.TaxIDEncrypted, &c.TaxIDDEK, &c.TaxIDKeyID,
		&c.BillingAddressEncrypted, &c.BillingAddressDEK, &c.BillingAddressKeyID,
		&c.ShippingAddressEncrypted, &c.ShippingAddressDEK, &c.ShippingAddressKeyID,
		&creditLimit,
		&c.IsActive,
		&c.CreatedAt,
		&c.UpdatedAt,
		&createdBy,
		&updatedBy,
		&paymentTermID,
		&emailHash, // NEW: email_hash column
	)
	if err != nil {
		if err == sql.ErrNoRows {
			return nil, errors.ErrNotFound
		}
		return nil, fmt.Errorf("scan customer: %w", err)
	}

	if creditLimit.Valid {
		val, err := decimal.NewFromString(creditLimit.String)
		if err == nil {
			c.CreditLimit = &val
		}
	}
	if createdBy.Valid {
		c.CreatedBy = &createdBy.UUID
	}
	if updatedBy.Valid {
		c.UpdatedBy = &updatedBy.UUID
	}
	if paymentTermID.Valid {
		c.PaymentTermID = &paymentTermID.UUID
	}
	if emailHash.Valid {
		c.EmailHash = &emailHash.String
	}
	return &c, nil
}

// -------------------------------------------------------------------------
// CRUD
// -------------------------------------------------------------------------

func (r *customerRepository) Create(ctx context.Context, db DBTX, customer *models.Customer) error {
	query := `
		INSERT INTO sales.customers (
			customer_id, company_id, customer_code, name,
			email, email_dek, email_key_id,
			phone, phone_dek, phone_key_id,
			tax_id, tax_id_dek, tax_id_key_id,
			billing_address, billing_address_dek, billing_address_key_id,
			shipping_address, shipping_address_dek, shipping_address_key_id,
			credit_limit, is_active, created_at, updated_at, created_by, updated_by,
			payment_term_id, email_hash
		) VALUES (
			$1, $2, $3, $4,
			$5, $6, $7,
			$8, $9, $10,
			$11, $12, $13,
			$14, $15, $16,
			$17, $18, $19,
			$20, $21, NOW(), NOW(), $22, $23,
			$24, $25
		)
		RETURNING created_at, updated_at
	`

	var creditLimit interface{}
	if customer.CreditLimit != nil {
		creditLimit = customer.CreditLimit.String()
	} else {
		creditLimit = nil
	}

	err := db.QueryRowContext(ctx, query,
		customer.CustomerID,
		customer.CompanyID,
		customer.CustomerCode,
		customer.Name,
		customer.EmailEncrypted, customer.EmailDEK, customer.EmailKeyID,
		customer.PhoneEncrypted, customer.PhoneDEK, customer.PhoneKeyID,
		customer.TaxIDEncrypted, customer.TaxIDDEK, customer.TaxIDKeyID,
		customer.BillingAddressEncrypted, customer.BillingAddressDEK, customer.BillingAddressKeyID,
		customer.ShippingAddressEncrypted, customer.ShippingAddressDEK, customer.ShippingAddressKeyID,
		creditLimit,
		customer.IsActive,
		r.nullUUIDParam(customer.CreatedBy),
		r.nullUUIDParam(customer.UpdatedBy),
		r.nullUUIDParam(customer.PaymentTermID),
		customer.EmailHash, // NEW
	).Scan(&customer.CreatedAt, &customer.UpdatedAt)

	if err != nil {
		r.logger.Error("failed to create customer", zap.Error(err))
		return fmt.Errorf("create customer: %w", err)
	}
	return nil
}

func (r *customerRepository) GetByID(ctx context.Context, db DBTX, companyID, customerID uuid.UUID) (*models.Customer, error) {
	query := `
		SELECT 
			customer_id, company_id, customer_code, name,
			email, email_dek, email_key_id,
			phone, phone_dek, phone_key_id,
			tax_id, tax_id_dek, tax_id_key_id,
			billing_address, billing_address_dek, billing_address_key_id,
			shipping_address, shipping_address_dek, shipping_address_key_id,
			credit_limit, is_active, created_at, updated_at, created_by, updated_by,
			payment_term_id, email_hash
		FROM sales.customers
		WHERE company_id = $1 AND customer_id = $2
	`
	row := db.QueryRowContext(ctx, query, companyID, customerID)
	return r.scanCustomer(row)
}

func (r *customerRepository) GetByCode(ctx context.Context, db DBTX, companyID uuid.UUID, customerCode string) (*models.Customer, error) {
	query := `
		SELECT 
			customer_id, company_id, customer_code, name,
			email, email_dek, email_key_id,
			phone, phone_dek, phone_key_id,
			tax_id, tax_id_dek, tax_id_key_id,
			billing_address, billing_address_dek, billing_address_key_id,
			shipping_address, shipping_address_dek, shipping_address_key_id,
			credit_limit, is_active, created_at, updated_at, created_by, updated_by,
			payment_term_id, email_hash
		FROM sales.customers
		WHERE company_id = $1 AND customer_code = $2
	`
	row := db.QueryRowContext(ctx, query, companyID, customerCode)
	return r.scanCustomer(row)
}

func (r *customerRepository) Update(ctx context.Context, db DBTX, customer *models.Customer) error {
	query := `
		UPDATE sales.customers SET
			customer_code = $3,
			name = $4,
			email = $5, email_dek = $6, email_key_id = $7,
			phone = $8, phone_dek = $9, phone_key_id = $10,
			tax_id = $11, tax_id_dek = $12, tax_id_key_id = $13,
			billing_address = $14, billing_address_dek = $15, billing_address_key_id = $16,
			shipping_address = $17, shipping_address_dek = $18, shipping_address_key_id = $19,
			credit_limit = $20,
			is_active = $21,
			updated_at = NOW(),
			updated_by = $22,
			payment_term_id = $23,
			email_hash = $24
		WHERE customer_id = $1 AND company_id = $2
		RETURNING updated_at
	`
	var creditLimit interface{}
	if customer.CreditLimit != nil {
		creditLimit = customer.CreditLimit.String()
	} else {
		creditLimit = nil
	}
	err := db.QueryRowContext(ctx, query,
		customer.CustomerID,
		customer.CompanyID,
		customer.CustomerCode,
		customer.Name,
		customer.EmailEncrypted, customer.EmailDEK, customer.EmailKeyID,
		customer.PhoneEncrypted, customer.PhoneDEK, customer.PhoneKeyID,
		customer.TaxIDEncrypted, customer.TaxIDDEK, customer.TaxIDKeyID,
		customer.BillingAddressEncrypted, customer.BillingAddressDEK, customer.BillingAddressKeyID,
		customer.ShippingAddressEncrypted, customer.ShippingAddressDEK, customer.ShippingAddressKeyID,
		creditLimit,
		customer.IsActive,
		r.nullUUIDParam(customer.UpdatedBy),
		r.nullUUIDParam(customer.PaymentTermID),
		customer.EmailHash, // NEW
	).Scan(&customer.UpdatedAt)
	if err != nil {
		if err == sql.ErrNoRows {
			return errors.ErrNotFound
		}
		return fmt.Errorf("update customer: %w", err)
	}
	return nil
}

func (r *customerRepository) Delete(ctx context.Context, db DBTX, companyID, customerID uuid.UUID) error {
	query := `DELETE FROM sales.customers WHERE company_id = $1 AND customer_id = $2`
	result, err := db.ExecContext(ctx, query, companyID, customerID)
	if err != nil {
		return fmt.Errorf("delete customer: %w", err)
	}
	rows, _ := result.RowsAffected()
	if rows == 0 {
		return errors.ErrNotFound
	}
	return nil
}

// -------------------------------------------------------------------------
// Status / lifecycle
// -------------------------------------------------------------------------

func (r *customerRepository) SetActiveStatus(ctx context.Context, db DBTX, companyID, customerID uuid.UUID, isActive bool, updatedBy *uuid.UUID) error {
	query := `
		UPDATE sales.customers
		SET is_active = $3, updated_at = NOW(), updated_by = $4
		WHERE company_id = $1 AND customer_id = $2
	`
	result, err := db.ExecContext(ctx, query, companyID, customerID, isActive, r.nullUUIDParam(updatedBy))
	if err != nil {
		return fmt.Errorf("set active status: %w", err)
	}
	rows, _ := result.RowsAffected()
	if rows == 0 {
		return errors.ErrNotFound
	}
	return nil
}

func (r *customerRepository) Exists(ctx context.Context, db DBTX, companyID, customerID uuid.UUID) (bool, error) {
	var exists bool
	query := `SELECT EXISTS(SELECT 1 FROM sales.customers WHERE company_id = $1 AND customer_id = $2)`
	err := db.QueryRowContext(ctx, query, companyID, customerID).Scan(&exists)
	if err != nil {
		return false, fmt.Errorf("exists: %w", err)
	}
	return exists, nil
}

func (r *customerRepository) ExistsByCode(ctx context.Context, db DBTX, companyID uuid.UUID, customerCode string) (bool, error) {
	var exists bool
	query := `SELECT EXISTS(SELECT 1 FROM sales.customers WHERE company_id = $1 AND customer_code = $2)`
	err := db.QueryRowContext(ctx, query, companyID, customerCode).Scan(&exists)
	if err != nil {
		return false, fmt.Errorf("exists by code: %w", err)
	}
	return exists, nil
}

// NEW: ExistsByEmailHash checks if another customer already uses the same email hash (i.e., same plaintext email)
func (r *customerRepository) ExistsByEmailHash(ctx context.Context, db DBTX, companyID uuid.UUID, emailHash string) (bool, error) {
	var exists bool
	query := `SELECT EXISTS(SELECT 1 FROM sales.customers WHERE company_id = $1 AND email_hash = $2)`
	err := db.QueryRowContext(ctx, query, companyID, emailHash).Scan(&exists)
	if err != nil {
		return false, fmt.Errorf("exists by email hash: %w", err)
	}
	return exists, nil
}

func (r *customerRepository) IsActive(ctx context.Context, db DBTX, companyID, customerID uuid.UUID) (bool, error) {
	var active bool
	query := `SELECT is_active FROM sales.customers WHERE company_id = $1 AND customer_id = $2`
	err := db.QueryRowContext(ctx, query, companyID, customerID).Scan(&active)
	if err != nil {
		if err == sql.ErrNoRows {
			return false, errors.ErrNotFound
		}
		return false, fmt.Errorf("is active: %w", err)
	}
	return active, nil
}

// -------------------------------------------------------------------------
// Uniqueness for encrypted fields (legacy, kept for compatibility)
// -------------------------------------------------------------------------

func (r *customerRepository) ExistsByEncryptedEmail(ctx context.Context, db DBTX, companyID uuid.UUID, emailEncrypted string) (bool, error) {
	var exists bool
	query := `SELECT EXISTS(SELECT 1 FROM sales.customers WHERE company_id = $1 AND email = $2 AND email IS NOT NULL)`
	err := db.QueryRowContext(ctx, query, companyID, emailEncrypted).Scan(&exists)
	if err != nil {
		return false, fmt.Errorf("exists by encrypted email: %w", err)
	}
	return exists, nil
}

func (r *customerRepository) ExistsByEncryptedPhone(ctx context.Context, db DBTX, companyID uuid.UUID, phoneEncrypted string) (bool, error) {
	var exists bool
	query := `SELECT EXISTS(SELECT 1 FROM sales.customers WHERE company_id = $1 AND phone = $2 AND phone IS NOT NULL)`
	err := db.QueryRowContext(ctx, query, companyID, phoneEncrypted).Scan(&exists)
	if err != nil {
		return false, fmt.Errorf("exists by encrypted phone: %w", err)
	}
	return exists, nil
}

// -------------------------------------------------------------------------
// Financial / business queries (also updated to include email_hash)
// -------------------------------------------------------------------------

func (r *customerRepository) GetCreditLimit(ctx context.Context, db DBTX, companyID, customerID uuid.UUID) (*models.Customer, error) {
	return r.GetByID(ctx, db, companyID, customerID)
}

func (r *customerRepository) GetCustomersWithOutstandingInvoices(ctx context.Context, db DBTX, companyID uuid.UUID) ([]*models.Customer, error) {
	query := `
		SELECT DISTINCT 
			c.customer_id, c.company_id, c.customer_code, c.name,
			c.email, c.email_dek, c.email_key_id,
			c.phone, c.phone_dek, c.phone_key_id,
			c.tax_id, c.tax_id_dek, c.tax_id_key_id,
			c.billing_address, c.billing_address_dek, c.billing_address_key_id,
			c.shipping_address, c.shipping_address_dek, c.shipping_address_key_id,
			c.credit_limit, c.is_active, c.created_at, c.updated_at, c.created_by, c.updated_by,
			c.payment_term_id, c.email_hash
		FROM sales.customers c
		JOIN sales.invoices i ON c.customer_id = i.customer_id
		WHERE c.company_id = $1 AND i.status NOT IN ('paid', 'cancelled') AND i.amount_due > 0
		ORDER BY c.name
	`
	rows, err := db.QueryContext(ctx, query, companyID)
	if err != nil {
		return nil, fmt.Errorf("get customers with outstanding invoices: %w", err)
	}
	defer rows.Close()
	var result []*models.Customer
	for rows.Next() {
		c, err := r.scanCustomer(rows)
		if err != nil {
			return nil, err
		}
		result = append(result, c)
	}
	return result, rows.Err()
}

func (r *customerRepository) GetTopCustomersByRevenue(ctx context.Context, db DBTX, companyID uuid.UUID, limit int, from, to *time.Time) ([]*models.Customer, error) {
	var conds []string
	var args []interface{}
	idx := 1
	conds = append(conds, fmt.Sprintf("i.company_id = $%d", idx))
	args = append(args, companyID)
	idx++
	conds = append(conds, "i.status = 'paid'")
	if from != nil {
		conds = append(conds, fmt.Sprintf("i.invoice_date >= $%d", idx))
		args = append(args, *from)
		idx++
	}
	if to != nil {
		conds = append(conds, fmt.Sprintf("i.invoice_date <= $%d", idx))
		args = append(args, *to)
		idx++
	}
	whereClause := strings.Join(conds, " AND ")

	query := fmt.Sprintf(`
		SELECT 
			c.customer_id, c.company_id, c.customer_code, c.name,
			c.email, c.email_dek, c.email_key_id,
			c.phone, c.phone_dek, c.phone_key_id,
			c.tax_id, c.tax_id_dek, c.tax_id_key_id,
			c.billing_address, c.billing_address_dek, c.billing_address_key_id,
			c.shipping_address, c.shipping_address_dek, c.shipping_address_key_id,
			c.credit_limit, c.is_active, c.created_at, c.updated_at, c.created_by, c.updated_by,
			c.payment_term_id, c.email_hash
		FROM sales.customers c
		JOIN sales.invoices i ON c.customer_id = i.customer_id
		WHERE %s
		GROUP BY c.customer_id
		ORDER BY SUM(i.grand_total) DESC
		LIMIT $%d
	`, whereClause, idx)

	args = append(args, limit)
	rows, err := db.QueryContext(ctx, query, args...)
	if err != nil {
		return nil, fmt.Errorf("get top customers by revenue: %w", err)
	}
	defer rows.Close()
	var result []*models.Customer
	for rows.Next() {
		c, err := r.scanCustomer(rows)
		if err != nil {
			return nil, err
		}
		result = append(result, c)
	}
	return result, rows.Err()
}

// -------------------------------------------------------------------------
// Listing & Search (updated to include email_hash)
// -------------------------------------------------------------------------

func (r *customerRepository) List(ctx context.Context, db DBTX, filter CustomerFilter, p Pagination, s Sort) ([]*models.Customer, int64, error) {
	where, args := r.buildFilter(filter)
	if where == "" {
		return nil, 0, fmt.Errorf("list requires at least company_id filter")
	}
	allowedSort := map[string]bool{
		"customer_code": true,
		"name":          true,
		"is_active":     true,
		"created_at":    true,
		"updated_at":    true,
	}
	orderBy, err := r.validateSort(s, allowedSort)
	if err != nil {
		return nil, 0, err
	}
	if orderBy == "" {
		orderBy = "ORDER BY name ASC"
	}
	limit, offset := r.validatePagination(p)

	countQuery := fmt.Sprintf("SELECT COUNT(*) FROM sales.customers %s", where)
	var total int64
	err = db.QueryRowContext(ctx, countQuery, args...).Scan(&total)
	if err != nil {
		return nil, 0, fmt.Errorf("count customers: %w", err)
	}
	if total == 0 {
		return []*models.Customer{}, 0, nil
	}

	query := fmt.Sprintf(`
		SELECT 
			customer_id, company_id, customer_code, name,
			email, email_dek, email_key_id,
			phone, phone_dek, phone_key_id,
			tax_id, tax_id_dek, tax_id_key_id,
			billing_address, billing_address_dek, billing_address_key_id,
			shipping_address, shipping_address_dek, shipping_address_key_id,
			credit_limit, is_active, created_at, updated_at, created_by, updated_by,
			payment_term_id, email_hash
		FROM sales.customers
		%s
		%s
		LIMIT $%d OFFSET $%d
	`, where, orderBy, len(args)+1, len(args)+2)
	args = append(args, limit, offset)

	rows, err := db.QueryContext(ctx, query, args...)
	if err != nil {
		return nil, 0, fmt.Errorf("list customers: %w", err)
	}
	defer rows.Close()

	var result []*models.Customer
	for rows.Next() {
		c, err := r.scanCustomer(rows)
		if err != nil {
			return nil, 0, err
		}
		result = append(result, c)
	}
	return result, total, rows.Err()
}

func (r *customerRepository) Search(ctx context.Context, db DBTX, companyID uuid.UUID, queryStr string, limit, offset int) ([]*models.Customer, int64, error) {
	searchPattern := "%" + queryStr + "%"
	baseArgs := []interface{}{companyID, searchPattern, searchPattern, searchPattern}
	countQuery := `
		SELECT COUNT(*)
		FROM sales.customers
		WHERE company_id = $1
		AND (customer_code ILIKE $2 OR name ILIKE $3 OR email ILIKE $4)
	`
	var total int64
	err := db.QueryRowContext(ctx, countQuery, baseArgs...).Scan(&total)
	if err != nil {
		return nil, 0, fmt.Errorf("search count: %w", err)
	}
	if total == 0 {
		return []*models.Customer{}, 0, nil
	}

	dataQuery := `
		SELECT 
			customer_id, company_id, customer_code, name,
			email, email_dek, email_key_id,
			phone, phone_dek, phone_key_id,
			tax_id, tax_id_dek, tax_id_key_id,
			billing_address, billing_address_dek, billing_address_key_id,
			shipping_address, shipping_address_dek, shipping_address_key_id,
			credit_limit, is_active, created_at, updated_at, created_by, updated_by,
			payment_term_id, email_hash
		FROM sales.customers
		WHERE company_id = $1
		AND (customer_code ILIKE $2 OR name ILIKE $3 OR email ILIKE $4)
		ORDER BY name ASC
		LIMIT $5 OFFSET $6
	`
	args := append(baseArgs, limit, offset)
	rows, err := db.QueryContext(ctx, dataQuery, args...)
	if err != nil {
		return nil, 0, fmt.Errorf("search data: %w", err)
	}
	defer rows.Close()

	var result []*models.Customer
	for rows.Next() {
		c, err := r.scanCustomer(rows)
		if err != nil {
			return nil, 0, err
		}
		result = append(result, c)
	}
	return result, total, rows.Err()
}

// -------------------------------------------------------------------------
// Concurrency / Locking
// -------------------------------------------------------------------------

func (r *customerRepository) GetByIDForUpdate(ctx context.Context, db DBTX, companyID, customerID uuid.UUID) (*models.Customer, error) {
	query := `
		SELECT 
			customer_id, company_id, customer_code, name,
			email, email_dek, email_key_id,
			phone, phone_dek, phone_key_id,
			tax_id, tax_id_dek, tax_id_key_id,
			billing_address, billing_address_dek, billing_address_key_id,
			shipping_address, shipping_address_dek, shipping_address_key_id,
			credit_limit, is_active, created_at, updated_at, created_by, updated_by,
			payment_term_id, email_hash
		FROM sales.customers
		WHERE company_id = $1 AND customer_id = $2
		FOR UPDATE
	`
	row := db.QueryRowContext(ctx, query, companyID, customerID)
	return r.scanCustomer(row)
}
func (r *customerRepository) ExistsByEmailHashExcluding(ctx context.Context, db DBTX, companyID uuid.UUID, emailHash string, excludeCustomerID uuid.UUID) (bool, error) {
	var exists bool
	query := `SELECT EXISTS(SELECT 1 FROM sales.customers WHERE company_id = $1 AND email_hash = $2 AND customer_id != $3)`
	err := db.QueryRowContext(ctx, query, companyID, emailHash, excludeCustomerID).Scan(&exists)
	return exists, err
}

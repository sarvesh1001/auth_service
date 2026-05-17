package repository

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/shopspring/decimal"
	"go.uber.org/zap"

	"auth-service/internal/encryption"
	"auth-service/internal/inventory/inventory_errors"
	"auth-service/internal/inventory/models"
	"auth-service/internal/util"
)

// VendorPurchaseRepository defines all operations for vendors, purchase orders, and related entities.
type VendorPurchaseRepository interface {
	// Vendors
	CreateVendor(ctx context.Context, db DBTX, v *models.Vendor) error
	GetVendorByID(ctx context.Context, db DBTX, vendorID uuid.UUID) (*models.Vendor, error)
	GetVendorByCode(ctx context.Context, db DBTX, companyID uuid.UUID, code string) (*models.Vendor, error)
	ListVendors(ctx context.Context, db DBTX, filter VendorFilter, p Pagination, s Sort) ([]*models.Vendor, error)
	UpdateVendor(ctx context.Context, db DBTX, v *models.Vendor) error
	DeleteVendor(ctx context.Context, db DBTX, vendorID uuid.UUID) error
	ExistsVendorByCode(ctx context.Context, db DBTX, companyID uuid.UUID, code string) (bool, error)

	// Vendor Tax Identifiers
	AddVendorTaxIdentifier(ctx context.Context, db DBTX, tax *models.VendorTaxIdentifier) error
	GetVendorTaxIdentifiers(ctx context.Context, db DBTX, vendorID uuid.UUID) ([]*models.VendorTaxIdentifier, error)
	GetVendorTaxIdentifierByID(ctx context.Context, db DBTX, taxID uuid.UUID) (*models.VendorTaxIdentifier, error)
	UpdateVendorTaxIdentifier(ctx context.Context, db DBTX, tax *models.VendorTaxIdentifier) error
	DeleteVendorTaxIdentifier(ctx context.Context, db DBTX, taxID uuid.UUID) error
	GetPrimaryTaxIdentifier(ctx context.Context, db DBTX, vendorID uuid.UUID) (*models.VendorTaxIdentifier, error)
	CountVendors(ctx context.Context, db DBTX, filter VendorFilter) (int64, error)
	CountPurchaseOrders(ctx context.Context, db DBTX, filter PurchaseOrderFilter) (int64, error)

	// Purchase Orders (soft-delete enabled)
	CreatePurchaseOrder(ctx context.Context, db DBTX, po *models.PurchaseOrder) error
	GetPurchaseOrderByID(ctx context.Context, db DBTX, poID uuid.UUID) (*models.PurchaseOrder, error)
	GetPurchaseOrderByNumber(ctx context.Context, db DBTX, companyID uuid.UUID, poNumber string) (*models.PurchaseOrder, error)
	ListPurchaseOrders(ctx context.Context, db DBTX, filter PurchaseOrderFilter, p Pagination, s Sort) ([]*models.PurchaseOrder, error)
	UpdatePurchaseOrder(ctx context.Context, db DBTX, po *models.PurchaseOrder) error
	UpdatePurchaseOrderStatus(ctx context.Context, db DBTX, poID uuid.UUID, status string) error
	DeletePurchaseOrder(ctx context.Context, db DBTX, poID uuid.UUID) error // soft delete
	ExistsPurchaseOrderNumber(ctx context.Context, db DBTX, companyID uuid.UUID, poNumber string) (bool, error)

	// Purchase Order Items
	AddPurchaseOrderItem(ctx context.Context, db DBTX, item *models.PurchaseOrderItem) error
	AddPurchaseOrderItems(ctx context.Context, db DBTX, items []*models.PurchaseOrderItem) error
	GetPurchaseOrderItems(ctx context.Context, db DBTX, poID uuid.UUID) ([]*models.PurchaseOrderItem, error)
	GetPurchaseOrderItemByID(ctx context.Context, db DBTX, poItemID uuid.UUID) (*models.PurchaseOrderItem, error)
	UpdatePurchaseOrderItem(ctx context.Context, db DBTX, item *models.PurchaseOrderItem) error
	UpdatePurchaseOrderItemReceivedQty(ctx context.Context, db DBTX, poItemID uuid.UUID, receivedQty decimal.Decimal) error
	DeletePurchaseOrderItem(ctx context.Context, db DBTX, poItemID uuid.UUID) error

	// Purchase Order Receipts
	CreatePurchaseOrderReceipt(ctx context.Context, db DBTX, receipt *models.PurchaseOrderReceipt) error
	GetPurchaseOrderReceipts(ctx context.Context, db DBTX, poID uuid.UUID) ([]*models.PurchaseOrderReceipt, error)
	GetPurchaseOrderReceiptByID(ctx context.Context, db DBTX, receiptID uuid.UUID) (*models.PurchaseOrderReceipt, error)
	DeletePurchaseOrderReceipt(ctx context.Context, db DBTX, receiptID uuid.UUID) error

	// Item Vendors
	AddItemVendor(ctx context.Context, db DBTX, iv *models.ItemVendor) error
	GetItemVendors(ctx context.Context, db DBTX, itemID uuid.UUID) ([]*models.ItemVendor, error)
	GetDefaultItemVendor(ctx context.Context, db DBTX, itemID uuid.UUID) (*models.ItemVendor, error)
	UpdateItemVendor(ctx context.Context, db DBTX, iv *models.ItemVendor) error
	DeleteItemVendor(ctx context.Context, db DBTX, itemID, vendorID uuid.UUID) error
	GetVendorsForItem(ctx context.Context, db DBTX, itemID uuid.UUID) ([]*models.Vendor, error)

	// Helper to ensure only one default vendor per item
	EnsureSingleDefaultVendor(ctx context.Context, db DBTX, itemID uuid.UUID, keepVendorID uuid.UUID) error
}

type vendorPurchaseRepository struct {
	logger     *zap.Logger
	encryption *encryption.EncryptionManager
}

func NewVendorPurchaseRepository(logger *zap.Logger, encryptionManager *encryption.EncryptionManager) VendorPurchaseRepository {
	return &vendorPurchaseRepository{
		logger:     logger.Named("vendor_purchase_repo"),
		encryption: encryptionManager,
	}
}

// ---------- Filter Structs ----------

type VendorFilter struct {
	CompanyID  uuid.UUID
	VendorCode string
	VendorName string
	VendorType string
	IsActive   *bool
	Search     string
}

type PurchaseOrderFilter struct {
	CompanyID      uuid.UUID
	VendorID       *uuid.UUID
	Status         string
	FromOrderDate  *time.Time
	ToOrderDate    *time.Time
	ExpectedBefore *time.Time
	ExpectedAfter  *time.Time
}

// ---------- Encryption Helpers ----------

func (r *vendorPurchaseRepository) encryptField(ctx context.Context, plaintext, purpose string) (*encryption.EncryptedData, error) {
	if plaintext == "" {
		return &encryption.EncryptedData{
			EncryptedValue: "",
			EncryptedDEK:   "",
			KeyID:          "",
		}, nil
	}
	return r.encryption.EncryptField(ctx, plaintext, purpose)
}

func (r *vendorPurchaseRepository) decryptField(ctx context.Context, encValue, encDEK, keyID string) (string, error) {
	if encValue == "" || encDEK == "" || keyID == "" {
		return "", nil
	}
	return r.encryption.DecryptField(ctx, &encryption.EncryptedData{
		EncryptedValue: encValue,
		EncryptedDEK:   encDEK,
		KeyID:          keyID,
	})
}

// ---------- Vendors ----------

func (r *vendorPurchaseRepository) CreateVendor(ctx context.Context, db DBTX, v *models.Vendor) error {
	encContactPerson, err := r.encryptField(ctx, v.ContactPerson, "vendor_contact_person")
	if err != nil {
		return err
	}
	encPhone, err := r.encryptField(ctx, v.Phone, "vendor_phone")
	if err != nil {
		return err
	}
	encEmail, err := r.encryptField(ctx, v.Email, "vendor_email")
	if err != nil {
		return err
	}
	encAddress, err := r.encryptField(ctx, v.Address, "vendor_address")
	if err != nil {
		return err
	}
	encBankAccount, err := r.encryptField(ctx, v.BankAccountNo, "vendor_bank_account")
	if err != nil {
		return err
	}
	encRoutingCode, err := r.encryptField(ctx, v.BankRoutingCode, "vendor_routing_code")
	if err != nil {
		return err
	}
	encBankName, err := r.encryptField(ctx, v.BankName, "vendor_bank_name")
	if err != nil {
		return err
	}

	query := `
		INSERT INTO vendors (
			vendor_id, company_id, vendor_code, vendor_name, vendor_type,
			contact_person, contact_person_dek, contact_person_key_id,
			phone, phone_dek, phone_key_id,
			email, email_dek, email_key_id,
			address, address_dek, address_key_id,
			bank_account_no, bank_account_no_dek, bank_account_no_key_id,
			bank_routing_code, bank_routing_code_dek, bank_routing_code_key_id,
			bank_name, bank_name_dek, bank_name_key_id,
			is_active, created_at, updated_at, created_by, updated_by
		) VALUES ($1, $2, $3, $4, $5,
			$6, $7, $8,
			$9, $10, $11,
			$12, $13, $14,
			$15, $16, $17,
			$18, $19, $20,
			$21, $22, $23,
			$24, $25, $26,
			$27, NOW(), NOW(), $28, $29)
		RETURNING created_at, updated_at
	`
	err = db.QueryRowContext(ctx, query,
		v.VendorID, v.CompanyID, v.VendorCode, v.VendorName, v.VendorType,
		encContactPerson.EncryptedValue, encContactPerson.EncryptedDEK, encContactPerson.KeyID,
		encPhone.EncryptedValue, encPhone.EncryptedDEK, encPhone.KeyID,
		encEmail.EncryptedValue, encEmail.EncryptedDEK, encEmail.KeyID,
		encAddress.EncryptedValue, encAddress.EncryptedDEK, encAddress.KeyID,
		encBankAccount.EncryptedValue, encBankAccount.EncryptedDEK, encBankAccount.KeyID,
		encRoutingCode.EncryptedValue, encRoutingCode.EncryptedDEK, encRoutingCode.KeyID,
		encBankName.EncryptedValue, encBankName.EncryptedDEK, encBankName.KeyID,
		v.IsActive, v.CreatedBy, v.UpdatedBy,
	).Scan(&v.CreatedAt, &v.UpdatedAt)
	if err != nil {
		r.logger.Error("failed to create vendor", util.ErrorField(err))
		return fmt.Errorf("create vendor: %w", err)
	}
	return nil
}

func (r *vendorPurchaseRepository) GetVendorByID(ctx context.Context, db DBTX, vendorID uuid.UUID) (*models.Vendor, error) {
	query := `
		SELECT vendor_id, company_id, vendor_code, vendor_name, vendor_type,
			contact_person, contact_person_dek, contact_person_key_id,
			phone, phone_dek, phone_key_id,
			email, email_dek, email_key_id,
			address, address_dek, address_key_id,
			bank_account_no, bank_account_no_dek, bank_account_no_key_id,
			bank_routing_code, bank_routing_code_dek, bank_routing_code_key_id,
			bank_name, bank_name_dek, bank_name_key_id,
			is_active, created_at, updated_at, created_by, updated_by, deleted_at
		FROM vendors
		WHERE vendor_id = $1 AND deleted_at IS NULL
	`
	row := db.QueryRowContext(ctx, query, vendorID)
	return r.scanVendor(ctx, row)
}

func (r *vendorPurchaseRepository) GetVendorByCode(ctx context.Context, db DBTX, companyID uuid.UUID, code string) (*models.Vendor, error) {
	query := `
		SELECT vendor_id, company_id, vendor_code, vendor_name, vendor_type,
			contact_person, contact_person_dek, contact_person_key_id,
			phone, phone_dek, phone_key_id,
			email, email_dek, email_key_id,
			address, address_dek, address_key_id,
			bank_account_no, bank_account_no_dek, bank_account_no_key_id,
			bank_routing_code, bank_routing_code_dek, bank_routing_code_key_id,
			bank_name, bank_name_dek, bank_name_key_id,
			is_active, created_at, updated_at, created_by, updated_by, deleted_at
		FROM vendors
		WHERE company_id = $1 AND vendor_code = $2 AND deleted_at IS NULL
	`
	row := db.QueryRowContext(ctx, query, companyID, code)
	return r.scanVendor(ctx, row)
}

func (r *vendorPurchaseRepository) ListVendors(ctx context.Context, db DBTX, filter VendorFilter, p Pagination, s Sort) ([]*models.Vendor, error) {
	where, args := r.buildVendorFilter(filter)
	orderBy := r.validateVendorSort(s)
	limit, offset := r.validatePagination(p)

	query := fmt.Sprintf(`
		SELECT vendor_id, company_id, vendor_code, vendor_name, vendor_type,
			contact_person, contact_person_dek, contact_person_key_id,
			phone, phone_dek, phone_key_id,
			email, email_dek, email_key_id,
			address, address_dek, address_key_id,
			bank_account_no, bank_account_no_dek, bank_account_no_key_id,
			bank_routing_code, bank_routing_code_dek, bank_routing_code_key_id,
			bank_name, bank_name_dek, bank_name_key_id,
			is_active, created_at, updated_at, created_by, updated_by, deleted_at
		FROM vendors
		%s
		%s
		LIMIT $%d OFFSET $%d
	`, where, orderBy, len(args)+1, len(args)+2)

	args = append(args, limit, offset)
	rows, err := db.QueryContext(ctx, query, args...)
	if err != nil {
		return nil, fmt.Errorf("list vendors: %w", err)
	}
	defer rows.Close()

	var result []*models.Vendor
	for rows.Next() {
		v, err := r.scanVendor(ctx, rows)
		if err != nil {
			return nil, err
		}
		result = append(result, v)
	}
	return result, rows.Err()
}

func (r *vendorPurchaseRepository) UpdateVendor(ctx context.Context, db DBTX, v *models.Vendor) error {
	encContactPerson, _ := r.encryptField(ctx, v.ContactPerson, "vendor_contact_person")
	encPhone, _ := r.encryptField(ctx, v.Phone, "vendor_phone")
	encEmail, _ := r.encryptField(ctx, v.Email, "vendor_email")
	encAddress, _ := r.encryptField(ctx, v.Address, "vendor_address")
	encBankAccount, _ := r.encryptField(ctx, v.BankAccountNo, "vendor_bank_account")
	encRoutingCode, _ := r.encryptField(ctx, v.BankRoutingCode, "vendor_routing_code")
	encBankName, _ := r.encryptField(ctx, v.BankName, "vendor_bank_name")

	query := `
		UPDATE vendors SET
			vendor_code = $2,
			vendor_name = $3,
			vendor_type = $4,
			contact_person = $5, contact_person_dek = $6, contact_person_key_id = $7,
			phone = $8, phone_dek = $9, phone_key_id = $10,
			email = $11, email_dek = $12, email_key_id = $13,
			address = $14, address_dek = $15, address_key_id = $16,
			bank_account_no = $17, bank_account_no_dek = $18, bank_account_no_key_id = $19,
			bank_routing_code = $20, bank_routing_code_dek = $21, bank_routing_code_key_id = $22,
			bank_name = $23, bank_name_dek = $24, bank_name_key_id = $25,
			is_active = $26,
			updated_by = $27,
			updated_at = NOW()
		WHERE vendor_id = $1 AND deleted_at IS NULL
		RETURNING updated_at
	`
	err := db.QueryRowContext(ctx, query,
		v.VendorID,
		v.VendorCode, v.VendorName, v.VendorType,
		encContactPerson.EncryptedValue, encContactPerson.EncryptedDEK, encContactPerson.KeyID,
		encPhone.EncryptedValue, encPhone.EncryptedDEK, encPhone.KeyID,
		encEmail.EncryptedValue, encEmail.EncryptedDEK, encEmail.KeyID,
		encAddress.EncryptedValue, encAddress.EncryptedDEK, encAddress.KeyID,
		encBankAccount.EncryptedValue, encBankAccount.EncryptedDEK, encBankAccount.KeyID,
		encRoutingCode.EncryptedValue, encRoutingCode.EncryptedDEK, encRoutingCode.KeyID,
		encBankName.EncryptedValue, encBankName.EncryptedDEK, encBankName.KeyID,
		v.IsActive, v.UpdatedBy,
	).Scan(&v.UpdatedAt)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return inventory_errors.ErrNotFound
		}
		return fmt.Errorf("update vendor: %w", err)
	}
	return nil
}

func (r *vendorPurchaseRepository) DeleteVendor(ctx context.Context, db DBTX, vendorID uuid.UUID) error {
	query := `UPDATE vendors SET deleted_at = NOW() WHERE vendor_id = $1 AND deleted_at IS NULL`
	result, err := db.ExecContext(ctx, query, vendorID)
	if err != nil {
		return fmt.Errorf("delete vendor: %w", err)
	}
	rows, _ := result.RowsAffected()
	if rows == 0 {
		return inventory_errors.ErrNotFound
	}
	return nil
}

func (r *vendorPurchaseRepository) ExistsVendorByCode(ctx context.Context, db DBTX, companyID uuid.UUID, code string) (bool, error) {
	query := `SELECT EXISTS(SELECT 1 FROM vendors WHERE company_id = $1 AND vendor_code = $2 AND deleted_at IS NULL)`
	var exists bool
	err := db.QueryRowContext(ctx, query, companyID, code).Scan(&exists)
	if err != nil {
		return false, fmt.Errorf("exists vendor by code: %w", err)
	}
	return exists, nil
}

// ---------- Vendor Tax Identifiers ----------

func (r *vendorPurchaseRepository) AddVendorTaxIdentifier(ctx context.Context, db DBTX, tax *models.VendorTaxIdentifier) error {
	encTaxNumber, err := r.encryptField(ctx, tax.TaxNumber, "tax_number")
	if err != nil {
		return err
	}
	query := `
		INSERT INTO vendor_tax_identifiers (
			tax_id, vendor_id, tax_type, tax_number, tax_number_dek, tax_number_key_id,
			is_primary, created_at, created_by
		) VALUES ($1, $2, $3, $4, $5, $6, $7, NOW(), $8)
		RETURNING created_at
	`
	err = db.QueryRowContext(ctx, query,
		tax.TaxID, tax.VendorID, tax.TaxType,
		encTaxNumber.EncryptedValue, encTaxNumber.EncryptedDEK, encTaxNumber.KeyID,
		tax.IsPrimary, tax.CreatedBy,
	).Scan(&tax.CreatedAt)
	if err != nil {
		return fmt.Errorf("add vendor tax identifier: %w", err)
	}
	return nil
}

func (r *vendorPurchaseRepository) GetVendorTaxIdentifiers(ctx context.Context, db DBTX, vendorID uuid.UUID) ([]*models.VendorTaxIdentifier, error) {
	query := `
		SELECT tax_id, vendor_id, tax_type, tax_number, tax_number_dek, tax_number_key_id,
			is_primary, created_at, created_by
		FROM vendor_tax_identifiers
		WHERE vendor_id = $1
	`
	rows, err := db.QueryContext(ctx, query, vendorID)
	if err != nil {
		return nil, fmt.Errorf("get vendor tax identifiers: %w", err)
	}
	defer rows.Close()

	var result []*models.VendorTaxIdentifier
	for rows.Next() {
		tax := &models.VendorTaxIdentifier{}
		var encNumber, encDEK, keyID sql.NullString
		var createdBy uuid.NullUUID
		err := rows.Scan(&tax.TaxID, &tax.VendorID, &tax.TaxType, &encNumber, &encDEK, &keyID,
			&tax.IsPrimary, &tax.CreatedAt, &createdBy)
		if err != nil {
			return nil, fmt.Errorf("scan tax identifier: %w", err)
		}
		if encNumber.Valid && encDEK.Valid && keyID.Valid {
			tax.TaxNumber, _ = r.decryptField(ctx, encNumber.String, encDEK.String, keyID.String)
		}
		if createdBy.Valid {
			tax.CreatedBy = &createdBy.UUID
		}
		result = append(result, tax)
	}
	return result, rows.Err()
}

func (r *vendorPurchaseRepository) GetVendorTaxIdentifierByID(ctx context.Context, db DBTX, taxID uuid.UUID) (*models.VendorTaxIdentifier, error) {
	query := `
		SELECT tax_id, vendor_id, tax_type, tax_number, tax_number_dek, tax_number_key_id,
			is_primary, created_at, created_by
		FROM vendor_tax_identifiers
		WHERE tax_id = $1
	`
	row := db.QueryRowContext(ctx, query, taxID)
	tax := &models.VendorTaxIdentifier{}
	var encNumber, encDEK, keyID sql.NullString
	var createdBy uuid.NullUUID
	err := row.Scan(&tax.TaxID, &tax.VendorID, &tax.TaxType, &encNumber, &encDEK, &keyID,
		&tax.IsPrimary, &tax.CreatedAt, &createdBy)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, inventory_errors.ErrNotFound
		}
		return nil, fmt.Errorf("get tax identifier by ID: %w", err)
	}
	if encNumber.Valid && encDEK.Valid && keyID.Valid {
		tax.TaxNumber, _ = r.decryptField(ctx, encNumber.String, encDEK.String, keyID.String)
	}
	if createdBy.Valid {
		tax.CreatedBy = &createdBy.UUID
	}
	return tax, nil
}

func (r *vendorPurchaseRepository) UpdateVendorTaxIdentifier(ctx context.Context, db DBTX, tax *models.VendorTaxIdentifier) error {
	encTaxNumber, err := r.encryptField(ctx, tax.TaxNumber, "tax_number")
	if err != nil {
		return err
	}
	query := `
		UPDATE vendor_tax_identifiers
		SET tax_type = $2, tax_number = $3, tax_number_dek = $4, tax_number_key_id = $5,
			is_primary = $6
		WHERE tax_id = $1
	`
	_, err = db.ExecContext(ctx, query,
		tax.TaxID, tax.TaxType,
		encTaxNumber.EncryptedValue, encTaxNumber.EncryptedDEK, encTaxNumber.KeyID,
		tax.IsPrimary)
	if err != nil {
		return fmt.Errorf("update vendor tax identifier: %w", err)
	}
	return nil
}

func (r *vendorPurchaseRepository) DeleteVendorTaxIdentifier(ctx context.Context, db DBTX, taxID uuid.UUID) error {
	query := `DELETE FROM vendor_tax_identifiers WHERE tax_id = $1`
	_, err := db.ExecContext(ctx, query, taxID)
	if err != nil {
		return fmt.Errorf("delete vendor tax identifier: %w", err)
	}
	return nil
}

func (r *vendorPurchaseRepository) GetPrimaryTaxIdentifier(ctx context.Context, db DBTX, vendorID uuid.UUID) (*models.VendorTaxIdentifier, error) {
	query := `
		SELECT tax_id, vendor_id, tax_type, tax_number, tax_number_dek, tax_number_key_id,
			is_primary, created_at, created_by
		FROM vendor_tax_identifiers
		WHERE vendor_id = $1 AND is_primary = true
	`
	row := db.QueryRowContext(ctx, query, vendorID)
	tax := &models.VendorTaxIdentifier{}
	var encNumber, encDEK, keyID sql.NullString
	var createdBy uuid.NullUUID
	err := row.Scan(&tax.TaxID, &tax.VendorID, &tax.TaxType, &encNumber, &encDEK, &keyID,
		&tax.IsPrimary, &tax.CreatedAt, &createdBy)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, nil
		}
		return nil, fmt.Errorf("get primary tax identifier: %w", err)
	}
	if encNumber.Valid && encDEK.Valid && keyID.Valid {
		tax.TaxNumber, _ = r.decryptField(ctx, encNumber.String, encDEK.String, keyID.String)
	}
	if createdBy.Valid {
		tax.CreatedBy = &createdBy.UUID
	}
	return tax, nil
}

// ---------- Purchase Orders (soft delete) ----------

func (r *vendorPurchaseRepository) CreatePurchaseOrder(ctx context.Context, db DBTX, po *models.PurchaseOrder) error {
	query := `
		INSERT INTO purchase_orders (
			purchase_order_id, company_id, po_number, vendor_id, order_date,
			expected_delivery_date, status, total_amount, currency, notes,
			created_at, updated_at, created_by, updated_by
		) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, NOW(), NOW(), $11, $12)
		RETURNING created_at, updated_at
	`
	err := db.QueryRowContext(ctx, query,
		po.PurchaseOrderID, po.CompanyID, po.PONumber, po.VendorID, po.OrderDate,
		po.ExpectedDeliveryDate, po.Status, po.TotalAmount, po.Currency, po.Notes,
		po.CreatedBy, po.UpdatedBy,
	).Scan(&po.CreatedAt, &po.UpdatedAt)
	if err != nil {
		return fmt.Errorf("create purchase order: %w", err)
	}
	return nil
}

func (r *vendorPurchaseRepository) GetPurchaseOrderByID(ctx context.Context, db DBTX, poID uuid.UUID) (*models.PurchaseOrder, error) {
	query := `
		SELECT purchase_order_id, company_id, po_number, vendor_id, order_date,
			expected_delivery_date, status, total_amount, currency, notes,
			created_at, updated_at, created_by, updated_by, deleted_at
		FROM purchase_orders
		WHERE purchase_order_id = $1 AND deleted_at IS NULL
	`
	row := db.QueryRowContext(ctx, query, poID)
	return r.scanPurchaseOrder(row)
}

func (r *vendorPurchaseRepository) GetPurchaseOrderByNumber(ctx context.Context, db DBTX, companyID uuid.UUID, poNumber string) (*models.PurchaseOrder, error) {
	query := `
		SELECT purchase_order_id, company_id, po_number, vendor_id, order_date,
			expected_delivery_date, status, total_amount, currency, notes,
			created_at, updated_at, created_by, updated_by, deleted_at
		FROM purchase_orders
		WHERE company_id = $1 AND po_number = $2 AND deleted_at IS NULL
	`
	row := db.QueryRowContext(ctx, query, companyID, poNumber)
	return r.scanPurchaseOrder(row)
}

func (r *vendorPurchaseRepository) ListPurchaseOrders(ctx context.Context, db DBTX, filter PurchaseOrderFilter, p Pagination, s Sort) ([]*models.PurchaseOrder, error) {
	where, args := r.buildPurchaseOrderFilter(filter)
	// Ensure we exclude soft-deleted rows
	if where == "" {
		where = "WHERE deleted_at IS NULL"
	} else {
		where += " AND deleted_at IS NULL"
	}
	orderBy := r.validatePurchaseOrderSort(s)
	limit, offset := r.validatePagination(p)

	query := fmt.Sprintf(`
		SELECT purchase_order_id, company_id, po_number, vendor_id, order_date,
			expected_delivery_date, status, total_amount, currency, notes,
			created_at, updated_at, created_by, updated_by, deleted_at
		FROM purchase_orders
		%s
		%s
		LIMIT $%d OFFSET $%d
	`, where, orderBy, len(args)+1, len(args)+2)

	args = append(args, limit, offset)
	rows, err := db.QueryContext(ctx, query, args...)
	if err != nil {
		return nil, fmt.Errorf("list purchase orders: %w", err)
	}
	defer rows.Close()

	var result []*models.PurchaseOrder
	for rows.Next() {
		po, err := r.scanPurchaseOrder(rows)
		if err != nil {
			return nil, err
		}
		result = append(result, po)
	}
	return result, rows.Err()
}

func (r *vendorPurchaseRepository) UpdatePurchaseOrder(ctx context.Context, db DBTX, po *models.PurchaseOrder) error {
	query := `
		UPDATE purchase_orders SET
			po_number = $2,
			vendor_id = $3,
			order_date = $4,
			expected_delivery_date = $5,
			status = $6,
			total_amount = $7,
			currency = $8,
			notes = $9,
			updated_by = $10,
			updated_at = NOW()
		WHERE purchase_order_id = $1 AND deleted_at IS NULL
		RETURNING updated_at
	`
	err := db.QueryRowContext(ctx, query,
		po.PurchaseOrderID, po.PONumber, po.VendorID, po.OrderDate,
		po.ExpectedDeliveryDate, po.Status, po.TotalAmount, po.Currency, po.Notes,
		po.UpdatedBy,
	).Scan(&po.UpdatedAt)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return inventory_errors.ErrNotFound
		}
		return fmt.Errorf("update purchase order: %w", err)
	}
	return nil
}

func (r *vendorPurchaseRepository) UpdatePurchaseOrderStatus(ctx context.Context, db DBTX, poID uuid.UUID, status string) error {
	query := `UPDATE purchase_orders SET status = $2, updated_at = NOW() WHERE purchase_order_id = $1 AND deleted_at IS NULL`
	_, err := db.ExecContext(ctx, query, poID, status)
	if err != nil {
		return fmt.Errorf("update purchase order status: %w", err)
	}
	return nil
}

// DeletePurchaseOrder soft-deletes a purchase order by setting deleted_at.
func (r *vendorPurchaseRepository) DeletePurchaseOrder(ctx context.Context, db DBTX, poID uuid.UUID) error {
	query := `UPDATE purchase_orders SET deleted_at = NOW() WHERE purchase_order_id = $1 AND deleted_at IS NULL`
	result, err := db.ExecContext(ctx, query, poID)
	if err != nil {
		return fmt.Errorf("delete purchase order: %w", err)
	}
	rows, _ := result.RowsAffected()
	if rows == 0 {
		return inventory_errors.ErrNotFound
	}
	return nil
}

// ExistsPurchaseOrderNumber checks for active (non-deleted) PO number.
func (r *vendorPurchaseRepository) ExistsPurchaseOrderNumber(ctx context.Context, db DBTX, companyID uuid.UUID, poNumber string) (bool, error) {
	query := `SELECT EXISTS(SELECT 1 FROM purchase_orders WHERE company_id = $1 AND po_number = $2 AND deleted_at IS NULL)`
	var exists bool
	err := db.QueryRowContext(ctx, query, companyID, poNumber).Scan(&exists)
	if err != nil {
		return false, fmt.Errorf("exists purchase order number: %w", err)
	}
	return exists, nil
}

// ---------- Purchase Order Items ----------

func (r *vendorPurchaseRepository) AddPurchaseOrderItem(ctx context.Context, db DBTX, item *models.PurchaseOrderItem) error {
	query := `
		INSERT INTO purchase_order_items (
			po_item_id, purchase_order_id, item_id, quantity_ordered, quantity_received,
			unit_cost, created_at, updated_at
		) VALUES ($1, $2, $3, $4, 0, $5, NOW(), NOW())
		RETURNING created_at, updated_at
	`
	err := db.QueryRowContext(ctx, query,
		item.POItemID, item.PurchaseOrderID, item.ItemID,
		item.QuantityOrdered, item.UnitCost,
	).Scan(&item.CreatedAt, &item.UpdatedAt)
	if err != nil {
		return fmt.Errorf("add purchase order item: %w", err)
	}
	return nil
}

func (r *vendorPurchaseRepository) AddPurchaseOrderItems(ctx context.Context, db DBTX, items []*models.PurchaseOrderItem) error {
	if len(items) == 0 {
		return nil
	}
	query := `
		INSERT INTO purchase_order_items (
			po_item_id, purchase_order_id, item_id, quantity_ordered, quantity_received,
			unit_cost, created_at, updated_at
		) VALUES ($1, $2, $3, $4, 0, $5, NOW(), NOW())
	`
	for _, item := range items {
		err := db.QueryRowContext(ctx, query,
			item.POItemID, item.PurchaseOrderID, item.ItemID,
			item.QuantityOrdered, item.UnitCost,
		).Scan(&item.CreatedAt, &item.UpdatedAt)
		if err != nil {
			return fmt.Errorf("bulk add purchase order item: %w", err)
		}
	}
	return nil
}

func (r *vendorPurchaseRepository) GetPurchaseOrderItems(ctx context.Context, db DBTX, poID uuid.UUID) ([]*models.PurchaseOrderItem, error) {
	query := `
		SELECT po_item_id, purchase_order_id, item_id, quantity_ordered, quantity_received,
			unit_cost, total_line, received_date, created_at, updated_at
		FROM purchase_order_items
		WHERE purchase_order_id = $1
	`
	rows, err := db.QueryContext(ctx, query, poID)
	if err != nil {
		return nil, fmt.Errorf("get purchase order items: %w", err)
	}
	defer rows.Close()

	var result []*models.PurchaseOrderItem
	for rows.Next() {
		item := &models.PurchaseOrderItem{}
		var totalLine sql.NullFloat64
		var receivedDate sql.NullTime
		err := rows.Scan(
			&item.POItemID, &item.PurchaseOrderID, &item.ItemID,
			&item.QuantityOrdered, &item.QuantityReceived,
			&item.UnitCost, &totalLine, &receivedDate,
			&item.CreatedAt, &item.UpdatedAt,
		)
		if err != nil {
			return nil, fmt.Errorf("scan purchase order item: %w", err)
		}
		if receivedDate.Valid {
			item.ReceivedDate = &receivedDate.Time
		}
		result = append(result, item)
	}
	return result, rows.Err()
}

func (r *vendorPurchaseRepository) GetPurchaseOrderItemByID(ctx context.Context, db DBTX, poItemID uuid.UUID) (*models.PurchaseOrderItem, error) {
	query := `
		SELECT po_item_id, purchase_order_id, item_id, quantity_ordered, quantity_received,
			unit_cost, total_line, received_date, created_at, updated_at
		FROM purchase_order_items
		WHERE po_item_id = $1
	`
	row := db.QueryRowContext(ctx, query, poItemID)
	item := &models.PurchaseOrderItem{}
	var totalLine sql.NullFloat64
	var receivedDate sql.NullTime
	err := row.Scan(
		&item.POItemID, &item.PurchaseOrderID, &item.ItemID,
		&item.QuantityOrdered, &item.QuantityReceived,
		&item.UnitCost, &totalLine, &receivedDate,
		&item.CreatedAt, &item.UpdatedAt,
	)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, inventory_errors.ErrNotFound
		}
		return nil, fmt.Errorf("get purchase order item by ID: %w", err)
	}
	if receivedDate.Valid {
		item.ReceivedDate = &receivedDate.Time
	}
	return item, nil
}

func (r *vendorPurchaseRepository) UpdatePurchaseOrderItem(ctx context.Context, db DBTX, item *models.PurchaseOrderItem) error {
	query := `
		UPDATE purchase_order_items SET
			quantity_ordered = $2,
			unit_cost = $3,
			updated_at = NOW()
		WHERE po_item_id = $1
		RETURNING updated_at
	`
	err := db.QueryRowContext(ctx, query,
		item.POItemID, item.QuantityOrdered, item.UnitCost,
	).Scan(&item.UpdatedAt)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return inventory_errors.ErrNotFound
		}
		return fmt.Errorf("update purchase order item: %w", err)
	}
	return nil
}

func (r *vendorPurchaseRepository) UpdatePurchaseOrderItemReceivedQty(ctx context.Context, db DBTX, poItemID uuid.UUID, receivedQty decimal.Decimal) error {
	query := `
		UPDATE purchase_order_items
		SET quantity_received = quantity_received + $2,
			received_date = CASE WHEN quantity_received + $2 >= quantity_ordered THEN NOW() ELSE received_date END,
			updated_at = NOW()
		WHERE po_item_id = $1
	`
	_, err := db.ExecContext(ctx, query, poItemID, receivedQty)
	if err != nil {
		return fmt.Errorf("update received quantity: %w", err)
	}
	return nil
}

func (r *vendorPurchaseRepository) DeletePurchaseOrderItem(ctx context.Context, db DBTX, poItemID uuid.UUID) error {
	query := `DELETE FROM purchase_order_items WHERE po_item_id = $1`
	_, err := db.ExecContext(ctx, query, poItemID)
	if err != nil {
		return fmt.Errorf("delete purchase order item: %w", err)
	}
	return nil
}

// ---------- Purchase Order Receipts ----------

func (r *vendorPurchaseRepository) CreatePurchaseOrderReceipt(ctx context.Context, db DBTX, receipt *models.PurchaseOrderReceipt) error {
	query := `
		INSERT INTO purchase_order_receipts (
			receipt_id, purchase_order_id, po_item_id, receipt_date, quantity_received,
			unit_cost, warehouse_id, batch_id, movement_id, created_at, created_by
		) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, NOW(), $10)
		RETURNING created_at
	`
	err := db.QueryRowContext(ctx, query,
		receipt.ReceiptID, receipt.PurchaseOrderID, receipt.POItemID, receipt.ReceiptDate,
		receipt.QuantityReceived, receipt.UnitCost, receipt.WarehouseID,
		receipt.BatchID, receipt.MovementID, receipt.CreatedBy,
	).Scan(&receipt.CreatedAt)
	if err != nil {
		return fmt.Errorf("create purchase order receipt: %w", err)
	}
	return nil
}

func (r *vendorPurchaseRepository) GetPurchaseOrderReceipts(ctx context.Context, db DBTX, poID uuid.UUID) ([]*models.PurchaseOrderReceipt, error) {
	query := `
		SELECT receipt_id, purchase_order_id, po_item_id, receipt_date, quantity_received,
			unit_cost, warehouse_id, batch_id, movement_id, created_at, created_by
		FROM purchase_order_receipts
		WHERE purchase_order_id = $1
	`
	rows, err := db.QueryContext(ctx, query, poID)
	if err != nil {
		return nil, fmt.Errorf("get purchase order receipts: %w", err)
	}
	defer rows.Close()

	var result []*models.PurchaseOrderReceipt
	for rows.Next() {
		rct := &models.PurchaseOrderReceipt{}
		var batchID, movementID, createdBy uuid.NullUUID
		err := rows.Scan(
			&rct.ReceiptID, &rct.PurchaseOrderID, &rct.POItemID, &rct.ReceiptDate,
			&rct.QuantityReceived, &rct.UnitCost, &rct.WarehouseID,
			&batchID, &movementID, &rct.CreatedAt, &createdBy,
		)
		if err != nil {
			return nil, fmt.Errorf("scan receipt: %w", err)
		}
		if batchID.Valid {
			rct.BatchID = &batchID.UUID
		}
		if movementID.Valid {
			rct.MovementID = &movementID.UUID
		}
		if createdBy.Valid {
			rct.CreatedBy = &createdBy.UUID
		}
		result = append(result, rct)
	}
	return result, rows.Err()
}

func (r *vendorPurchaseRepository) GetPurchaseOrderReceiptByID(ctx context.Context, db DBTX, receiptID uuid.UUID) (*models.PurchaseOrderReceipt, error) {
	query := `
		SELECT receipt_id, purchase_order_id, po_item_id, receipt_date, quantity_received,
			unit_cost, warehouse_id, batch_id, movement_id, created_at, created_by
		FROM purchase_order_receipts
		WHERE receipt_id = $1
	`
	row := db.QueryRowContext(ctx, query, receiptID)
	rct := &models.PurchaseOrderReceipt{}
	var batchID, movementID, createdBy uuid.NullUUID
	err := row.Scan(
		&rct.ReceiptID, &rct.PurchaseOrderID, &rct.POItemID, &rct.ReceiptDate,
		&rct.QuantityReceived, &rct.UnitCost, &rct.WarehouseID,
		&batchID, &movementID, &rct.CreatedAt, &createdBy,
	)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, inventory_errors.ErrNotFound
		}
		return nil, fmt.Errorf("get receipt by ID: %w", err)
	}
	if batchID.Valid {
		rct.BatchID = &batchID.UUID
	}
	if movementID.Valid {
		rct.MovementID = &movementID.UUID
	}
	if createdBy.Valid {
		rct.CreatedBy = &createdBy.UUID
	}
	return rct, nil
}

func (r *vendorPurchaseRepository) DeletePurchaseOrderReceipt(ctx context.Context, db DBTX, receiptID uuid.UUID) error {
	query := `DELETE FROM purchase_order_receipts WHERE receipt_id = $1`
	_, err := db.ExecContext(ctx, query, receiptID)
	if err != nil {
		return fmt.Errorf("delete receipt: %w", err)
	}
	return nil
}

// ---------- Item Vendors ----------

func (r *vendorPurchaseRepository) AddItemVendor(ctx context.Context, db DBTX, iv *models.ItemVendor) error {
	query := `
		INSERT INTO item_vendors (item_id, vendor_id, is_default, lead_time, unit_cost)
		VALUES ($1, $2, $3, $4, $5)
	`
	_, err := db.ExecContext(ctx, query, iv.ItemID, iv.VendorID, iv.IsDefault, iv.LeadTime, iv.UnitCost)
	if err != nil {
		return fmt.Errorf("add item vendor: %w", err)
	}
	if iv.IsDefault {
		_ = r.EnsureSingleDefaultVendor(ctx, db, iv.ItemID, iv.VendorID)
	}
	return nil
}

func (r *vendorPurchaseRepository) GetItemVendors(ctx context.Context, db DBTX, itemID uuid.UUID) ([]*models.ItemVendor, error) {
	query := `
		SELECT item_id, vendor_id, is_default, lead_time, unit_cost
		FROM item_vendors
		WHERE item_id = $1
	`
	rows, err := db.QueryContext(ctx, query, itemID)
	if err != nil {
		return nil, fmt.Errorf("get item vendors: %w", err)
	}
	defer rows.Close()

	var result []*models.ItemVendor
	for rows.Next() {
		iv := &models.ItemVendor{}
		err := rows.Scan(&iv.ItemID, &iv.VendorID, &iv.IsDefault, &iv.LeadTime, &iv.UnitCost)
		if err != nil {
			return nil, fmt.Errorf("scan item vendor: %w", err)
		}
		result = append(result, iv)
	}
	return result, rows.Err()
}

func (r *vendorPurchaseRepository) GetDefaultItemVendor(ctx context.Context, db DBTX, itemID uuid.UUID) (*models.ItemVendor, error) {
	query := `
		SELECT item_id, vendor_id, is_default, lead_time, unit_cost
		FROM item_vendors
		WHERE item_id = $1 AND is_default = true
	`
	row := db.QueryRowContext(ctx, query, itemID)
	iv := &models.ItemVendor{}
	err := row.Scan(&iv.ItemID, &iv.VendorID, &iv.IsDefault, &iv.LeadTime, &iv.UnitCost)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, nil
		}
		return nil, fmt.Errorf("get default item vendor: %w", err)
	}
	return iv, nil
}

func (r *vendorPurchaseRepository) UpdateItemVendor(ctx context.Context, db DBTX, iv *models.ItemVendor) error {
	query := `
		UPDATE item_vendors
		SET is_default = $3, lead_time = $4, unit_cost = $5
		WHERE item_id = $1 AND vendor_id = $2
	`
	_, err := db.ExecContext(ctx, query, iv.ItemID, iv.VendorID, iv.IsDefault, iv.LeadTime, iv.UnitCost)
	if err != nil {
		return fmt.Errorf("update item vendor: %w", err)
	}
	if iv.IsDefault {
		_ = r.EnsureSingleDefaultVendor(ctx, db, iv.ItemID, iv.VendorID)
	}
	return nil
}

func (r *vendorPurchaseRepository) DeleteItemVendor(ctx context.Context, db DBTX, itemID, vendorID uuid.UUID) error {
	query := `DELETE FROM item_vendors WHERE item_id = $1 AND vendor_id = $2`
	_, err := db.ExecContext(ctx, query, itemID, vendorID)
	if err != nil {
		return fmt.Errorf("delete item vendor: %w", err)
	}
	return nil
}

func (r *vendorPurchaseRepository) GetVendorsForItem(ctx context.Context, db DBTX, itemID uuid.UUID) ([]*models.Vendor, error) {
	query := `
		SELECT v.vendor_id, v.company_id, v.vendor_code, v.vendor_name, v.vendor_type,
			v.contact_person, v.contact_person_dek, v.contact_person_key_id,
			v.phone, v.phone_dek, v.phone_key_id,
			v.email, v.email_dek, v.email_key_id,
			v.address, v.address_dek, v.address_key_id,
			v.bank_account_no, v.bank_account_no_dek, v.bank_account_no_key_id,
			v.bank_routing_code, v.bank_routing_code_dek, v.bank_routing_code_key_id,
			v.bank_name, v.bank_name_dek, v.bank_name_key_id,
			v.is_active, v.created_at, v.updated_at, v.created_by, v.updated_by, v.deleted_at
		FROM vendors v
		JOIN item_vendors iv ON v.vendor_id = iv.vendor_id
		WHERE iv.item_id = $1 AND v.deleted_at IS NULL
	`
	rows, err := db.QueryContext(ctx, query, itemID)
	if err != nil {
		return nil, fmt.Errorf("get vendors for item: %w", err)
	}
	defer rows.Close()

	var result []*models.Vendor
	for rows.Next() {
		v, err := r.scanVendor(ctx, rows)
		if err != nil {
			return nil, err
		}
		result = append(result, v)
	}
	return result, rows.Err()
}

func (r *vendorPurchaseRepository) EnsureSingleDefaultVendor(ctx context.Context, db DBTX, itemID uuid.UUID, keepVendorID uuid.UUID) error {
	query := `UPDATE item_vendors SET is_default = false WHERE item_id = $1 AND vendor_id != $2 AND is_default = true`
	_, err := db.ExecContext(ctx, query, itemID, keepVendorID)
	if err != nil {
		r.logger.Error("failed to ensure single default vendor", zap.Error(err))
		return fmt.Errorf("ensure single default vendor: %w", err)
	}
	return nil
}

// ---------- Scanner helpers ----------

func (r *vendorPurchaseRepository) scanVendor(ctx context.Context, row scanner) (*models.Vendor, error) {
	var v models.Vendor
	var (
		contactPerson, contactPersonDEK, contactPersonKeyID sql.NullString
		phone, phoneDEK, phoneKeyID                         sql.NullString
		email, emailDEK, emailKeyID                         sql.NullString
		address, addressDEK, addressKeyID                   sql.NullString
		bankAccount, bankAccountDEK, bankAccountKeyID       sql.NullString
		routingCode, routingCodeDEK, routingCodeKeyID       sql.NullString
		bankName, bankNameDEK, bankNameKeyID                sql.NullString
		createdBy, updatedBy                                uuid.NullUUID
		deletedAt                                           sql.NullTime
	)

	err := row.Scan(
		&v.VendorID, &v.CompanyID, &v.VendorCode, &v.VendorName, &v.VendorType,
		&contactPerson, &contactPersonDEK, &contactPersonKeyID,
		&phone, &phoneDEK, &phoneKeyID,
		&email, &emailDEK, &emailKeyID,
		&address, &addressDEK, &addressKeyID,
		&bankAccount, &bankAccountDEK, &bankAccountKeyID,
		&routingCode, &routingCodeDEK, &routingCodeKeyID,
		&bankName, &bankNameDEK, &bankNameKeyID,
		&v.IsActive, &v.CreatedAt, &v.UpdatedAt, &createdBy, &updatedBy, &deletedAt,
	)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, inventory_errors.ErrNotFound
		}
		return nil, fmt.Errorf("scan vendor: %w", err)
	}

	if contactPerson.Valid {
		dec, err := r.decryptField(ctx, contactPerson.String, contactPersonDEK.String, contactPersonKeyID.String)
		if err != nil {
			r.logger.Warn("failed to decrypt contact_person", zap.Error(err))
		} else {
			v.ContactPerson = dec
		}
	}
	if phone.Valid {
		dec, err := r.decryptField(ctx, phone.String, phoneDEK.String, phoneKeyID.String)
		if err != nil {
			r.logger.Warn("failed to decrypt phone", zap.Error(err))
		} else {
			v.Phone = dec
		}
	}
	if email.Valid {
		dec, err := r.decryptField(ctx, email.String, emailDEK.String, emailKeyID.String)
		if err != nil {
			r.logger.Warn("failed to decrypt email", zap.Error(err))
		} else {
			v.Email = dec
		}
	}
	if address.Valid {
		dec, err := r.decryptField(ctx, address.String, addressDEK.String, addressKeyID.String)
		if err != nil {
			r.logger.Warn("failed to decrypt address", zap.Error(err))
		} else {
			v.Address = dec
		}
	}
	if bankAccount.Valid {
		dec, err := r.decryptField(ctx, bankAccount.String, bankAccountDEK.String, bankAccountKeyID.String)
		if err != nil {
			r.logger.Warn("failed to decrypt bank_account_no", zap.Error(err))
		} else {
			v.BankAccountNo = dec
		}
	}
	if routingCode.Valid {
		dec, err := r.decryptField(ctx, routingCode.String, routingCodeDEK.String, routingCodeKeyID.String)
		if err != nil {
			r.logger.Warn("failed to decrypt bank_routing_code", zap.Error(err))
		} else {
			v.BankRoutingCode = dec
		}
	}
	if bankName.Valid {
		dec, err := r.decryptField(ctx, bankName.String, bankNameDEK.String, bankNameKeyID.String)
		if err != nil {
			r.logger.Warn("failed to decrypt bank_name", zap.Error(err))
		} else {
			v.BankName = dec
		}
	}
	if createdBy.Valid {
		v.CreatedBy = &createdBy.UUID
	}
	if updatedBy.Valid {
		v.UpdatedBy = &updatedBy.UUID
	}
	if deletedAt.Valid {
		v.DeletedAt = &deletedAt.Time
	}
	return &v, nil
}

func (r *vendorPurchaseRepository) scanPurchaseOrder(row scanner) (*models.PurchaseOrder, error) {
	var po models.PurchaseOrder
	var expectedDeliveryDate sql.NullTime
	var notes sql.NullString
	var createdBy, updatedBy uuid.NullUUID
	var deletedAt sql.NullTime

	err := row.Scan(
		&po.PurchaseOrderID, &po.CompanyID, &po.PONumber, &po.VendorID, &po.OrderDate,
		&expectedDeliveryDate, &po.Status, &po.TotalAmount, &po.Currency, &notes,
		&po.CreatedAt, &po.UpdatedAt, &createdBy, &updatedBy, &deletedAt,
	)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, inventory_errors.ErrNotFound
		}
		return nil, fmt.Errorf("scan purchase order: %w", err)
	}
	if expectedDeliveryDate.Valid {
		po.ExpectedDeliveryDate = &expectedDeliveryDate.Time
	}
	if notes.Valid {
		po.Notes = &notes.String
	}
	if createdBy.Valid {
		po.CreatedBy = &createdBy.UUID
	}
	if updatedBy.Valid {
		po.UpdatedBy = &updatedBy.UUID
	}
	if deletedAt.Valid {
		po.DeletedAt = &deletedAt.Time
	}
	return &po, nil
}

// ---------- Helper functions (pagination, sorting, filters) ----------

func (r *vendorPurchaseRepository) validatePagination(p Pagination) (int, int) {
	limit := p.Limit
	if limit <= 0 {
		limit = 20
	}
	if limit > 500 {
		limit = 500
	}
	offset := p.Offset
	if offset < 0 {
		offset = 0
	}
	return limit, offset
}

func (r *vendorPurchaseRepository) validateVendorSort(s Sort) string {
	field := s.Field
	if field == "" {
		field = "vendor_code"
	}
	allowed := map[string]bool{"vendor_code": true, "vendor_name": true, "created_at": true, "updated_at": true}
	if !allowed[field] {
		field = "vendor_code"
	}
	dir := strings.ToUpper(s.Direction)
	if dir != "ASC" && dir != "DESC" {
		dir = "ASC"
	}
	return fmt.Sprintf("ORDER BY %s %s", field, dir)
}

func (r *vendorPurchaseRepository) validatePurchaseOrderSort(s Sort) string {
	field := s.Field
	if field == "" {
		field = "order_date"
	}
	allowed := map[string]bool{"order_date": true, "po_number": true, "status": true, "created_at": true}
	if !allowed[field] {
		field = "order_date"
	}
	dir := strings.ToUpper(s.Direction)
	if dir != "ASC" && dir != "DESC" {
		dir = "DESC"
	}
	return fmt.Sprintf("ORDER BY %s %s", field, dir)
}

func (r *vendorPurchaseRepository) buildVendorFilter(filter VendorFilter) (string, []interface{}) {
	var conditions []string
	var args []interface{}
	idx := 1

	if filter.CompanyID != uuid.Nil {
		conditions = append(conditions, fmt.Sprintf("company_id = $%d", idx))
		args = append(args, filter.CompanyID)
		idx++
	}
	if filter.VendorCode != "" {
		conditions = append(conditions, fmt.Sprintf("vendor_code = $%d", idx))
		args = append(args, filter.VendorCode)
		idx++
	}
	if filter.VendorName != "" {
		conditions = append(conditions, fmt.Sprintf("vendor_name ILIKE $%d", idx))
		args = append(args, "%"+filter.VendorName+"%")
		idx++
	}
	if filter.VendorType != "" {
		conditions = append(conditions, fmt.Sprintf("vendor_type = $%d", idx))
		args = append(args, filter.VendorType)
		idx++
	}
	if filter.IsActive != nil {
		conditions = append(conditions, fmt.Sprintf("is_active = $%d", idx))
		args = append(args, *filter.IsActive)
		idx++
	}
	if filter.Search != "" {
		conditions = append(conditions, fmt.Sprintf("(vendor_code ILIKE $%d OR vendor_name ILIKE $%d)", idx, idx+1))
		args = append(args, "%"+filter.Search+"%", "%"+filter.Search+"%")
		idx += 2
	}
	conditions = append(conditions, "deleted_at IS NULL")

	if len(conditions) == 0 {
		return "", args
	}
	return "WHERE " + strings.Join(conditions, " AND "), args
}

func (r *vendorPurchaseRepository) buildPurchaseOrderFilter(filter PurchaseOrderFilter) (string, []interface{}) {
	var conditions []string
	var args []interface{}
	idx := 1

	if filter.CompanyID != uuid.Nil {
		conditions = append(conditions, fmt.Sprintf("company_id = $%d", idx))
		args = append(args, filter.CompanyID)
		idx++
	}
	if filter.VendorID != nil {
		conditions = append(conditions, fmt.Sprintf("vendor_id = $%d", idx))
		args = append(args, *filter.VendorID)
		idx++
	}
	if filter.Status != "" {
		conditions = append(conditions, fmt.Sprintf("status = $%d", idx))
		args = append(args, filter.Status)
		idx++
	}
	if filter.FromOrderDate != nil {
		conditions = append(conditions, fmt.Sprintf("order_date >= $%d", idx))
		args = append(args, *filter.FromOrderDate)
		idx++
	}
	if filter.ToOrderDate != nil {
		conditions = append(conditions, fmt.Sprintf("order_date <= $%d", idx))
		args = append(args, *filter.ToOrderDate)
		idx++
	}
	if filter.ExpectedAfter != nil {
		conditions = append(conditions, fmt.Sprintf("expected_delivery_date >= $%d", idx))
		args = append(args, *filter.ExpectedAfter)
		idx++
	}
	if filter.ExpectedBefore != nil {
		conditions = append(conditions, fmt.Sprintf("expected_delivery_date <= $%d", idx))
		args = append(args, *filter.ExpectedBefore)
		idx++
	}

	if len(conditions) == 0 {
		return "", args
	}
	return "WHERE " + strings.Join(conditions, " AND "), args
}

func (r *vendorPurchaseRepository) CountVendors(ctx context.Context, db DBTX, filter VendorFilter) (int64, error) {
	where, args := r.buildVendorFilter(filter)
	query := fmt.Sprintf("SELECT COUNT(*) FROM vendors %s", where)
	var count int64
	err := db.QueryRowContext(ctx, query, args...).Scan(&count)
	if err != nil {
		return 0, fmt.Errorf("count vendors: %w", err)
	}
	return count, nil
}

func (r *vendorPurchaseRepository) CountPurchaseOrders(ctx context.Context, db DBTX, filter PurchaseOrderFilter) (int64, error) {
	where, args := r.buildPurchaseOrderFilter(filter)
	// Ensure we exclude soft-deleted rows
	if where == "" {
		where = "WHERE deleted_at IS NULL"
	} else {
		where += " AND deleted_at IS NULL"
	}
	query := fmt.Sprintf("SELECT COUNT(*) FROM purchase_orders %s", where)
	var count int64
	err := db.QueryRowContext(ctx, query, args...).Scan(&count)
	if err != nil {
		return 0, fmt.Errorf("count purchase orders: %w", err)
	}
	return count, nil
}

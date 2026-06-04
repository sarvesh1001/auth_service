package service

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"regexp"
	"time"

	"github.com/google/uuid"
	"github.com/shopspring/decimal"
	"go.uber.org/zap"

	"auth-service/internal/client"
	"auth-service/internal/encryption"
	"auth-service/internal/infrastructure/audit"
	"auth-service/internal/infrastructure/idempotency"
	"auth-service/internal/infrastructure/outbox"
	salesErrors "auth-service/internal/sales/errors"
	salesEvents "auth-service/internal/sales/events"
	"auth-service/internal/sales/models"
	"auth-service/internal/sales/repository"
)

// ---------------------------------------------------------------------
// Service Interface – no transaction parameters (production‑grade pattern)
// ---------------------------------------------------------------------

type CustomerService interface {
	CreateCustomer(ctx context.Context, req CreateCustomerRequest, idempotencyKey string) (*models.Customer, error)
	UpdateCustomer(ctx context.Context, companyID, customerID uuid.UUID, req UpdateCustomerRequest, idempotencyKey string) (*models.Customer, error)
	DeleteCustomer(ctx context.Context, companyID, customerID uuid.UUID, deletedBy *uuid.UUID, idempotencyKey string) error
	GetCustomerByID(ctx context.Context, companyID, customerID uuid.UUID) (*models.Customer, error)
	GetCustomerByCode(ctx context.Context, companyID uuid.UUID, code string) (*models.Customer, error)
	ListCustomers(ctx context.Context, filter CustomerListFilter, p Pagination, s Sort) ([]*models.Customer, int64, error)
	SearchCustomers(ctx context.Context, companyID uuid.UUID, query string, limit, offset int) ([]*models.Customer, int64, error)

	ActivateCustomer(ctx context.Context, companyID, customerID uuid.UUID, updatedBy *uuid.UUID, idempotencyKey string) error
	DeactivateCustomer(ctx context.Context, companyID, customerID uuid.UUID, updatedBy *uuid.UUID, idempotencyKey string) error

	UpdateCreditLimit(ctx context.Context, companyID, customerID uuid.UUID, newLimit decimal.Decimal, reason *string, updatedBy *uuid.UUID, idempotencyKey string) error
	GetCreditLimit(ctx context.Context, companyID, customerID uuid.UUID) (decimal.Decimal, error)
	GetOutstandingBalance(ctx context.Context, companyID, customerID uuid.UUID) (decimal.Decimal, error)
	CanCustomerPurchaseAmount(ctx context.Context, companyID, customerID uuid.UUID, amount decimal.Decimal) (bool, error)

	AssignPaymentTerm(ctx context.Context, companyID, customerID, termID uuid.UUID, updatedBy *uuid.UUID, idempotencyKey string) error
	RemovePaymentTerm(ctx context.Context, companyID, customerID uuid.UUID, updatedBy *uuid.UUID, idempotencyKey string) error

	AssignSalesRep(ctx context.Context, companyID, customerID, salesRepID uuid.UUID, updatedBy *uuid.UUID, idempotencyKey string) error
	RemoveSalesRep(ctx context.Context, companyID, customerID uuid.UUID, updatedBy *uuid.UUID, idempotencyKey string) error

	GetCustomersWithOutstandingInvoices(ctx context.Context, companyID uuid.UUID) ([]*models.Customer, error)
	GetTopCustomersByRevenue(ctx context.Context, companyID uuid.UUID, limit int, from, to *time.Time) ([]*models.Customer, error)

	ValidateCustomer(ctx context.Context, customer *models.Customer) error
	CustomerExists(ctx context.Context, companyID, customerID uuid.UUID) (bool, error)
	IsCustomerActive(ctx context.Context, companyID, customerID uuid.UUID) (bool, error)
}

// ---------------------------------------------------------------------
// Implementation
// ---------------------------------------------------------------------

type customerService struct {
	customerRepo      repository.CustomerRepository
	creditHistoryRepo repository.CreditCheckHistoryRepository
	paymentTermRepo   repository.PaymentTermRepository
	salesRepRepo      repository.SalesRepRepository
	pgClient          *client.PostgresClient
	outboxRepo        outbox.Repository
	idempotencyStore  idempotency.Store
	auditService      *audit.AuditService
	encryptionMgr     *encryption.EncryptionManager
	logger            *zap.Logger
}

func NewCustomerService(
	customerRepo repository.CustomerRepository,
	creditHistoryRepo repository.CreditCheckHistoryRepository,
	paymentTermRepo repository.PaymentTermRepository,
	salesRepRepo repository.SalesRepRepository,
	pgClient *client.PostgresClient,
	outboxRepo outbox.Repository,
	idempotencyStore idempotency.Store,
	auditService *audit.AuditService,
	encryptionMgr *encryption.EncryptionManager,
	logger *zap.Logger,
) CustomerService {
	return &customerService{
		customerRepo:      customerRepo,
		creditHistoryRepo: creditHistoryRepo,
		paymentTermRepo:   paymentTermRepo,
		salesRepRepo:      salesRepRepo,
		pgClient:          pgClient,
		outboxRepo:        outboxRepo,
		idempotencyStore:  idempotencyStore,
		auditService:      auditService,
		encryptionMgr:     encryptionMgr,
		logger:            logger.Named("customer_service"),
	}
}

// ----------------------------------------------------------------------------
// Validation helpers
// ----------------------------------------------------------------------------
const (
	maxCustomerCodeLen = 50
	maxNameLen         = 255
	maxEmailLen        = 255
	maxBillingAddrLen  = 500
)

var emailRegex = regexp.MustCompile(`^[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}$`)

func isValidEmail(email string) bool {
	return emailRegex.MatchString(email)
}

func hashEmail(email string) string {
	hash := sha256.Sum256([]byte(email))
	return hex.EncodeToString(hash[:])
}

// ----------------------------------------------------------------------------
// Encryption helpers
// ----------------------------------------------------------------------------
func (s *customerService) encryptField(ctx context.Context, plainText *string, fieldName string) (encrypted, dek, keyID *string, err error) {
	if plainText == nil || *plainText == "" {
		return nil, nil, nil, nil
	}
	enc, err := s.encryptionMgr.EncryptField(ctx, *plainText, fieldName)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("encrypt %s: %w", fieldName, err)
	}
	return &enc.EncryptedValue, &enc.EncryptedDEK, &enc.KeyID, nil
}

func (s *customerService) decryptField(ctx context.Context, encrypted, dek, keyID *string) (string, error) {
	if encrypted == nil || *encrypted == "" || dek == nil || keyID == nil {
		return "", nil
	}
	encData := &encryption.EncryptedData{
		EncryptedValue: *encrypted,
		EncryptedDEK:   *dek,
		KeyID:          *keyID,
	}
	return s.encryptionMgr.DecryptField(ctx, encData)
}

func (s *customerService) decryptCustomer(ctx context.Context, c *models.Customer) error {
	if c == nil {
		return nil
	}
	if c.EmailEncrypted != nil {
		emailStr, err := s.decryptField(ctx, c.EmailEncrypted, c.EmailDEK, c.EmailKeyID)
		if err != nil {
			return fmt.Errorf("decrypt email: %w", err)
		}
		if emailStr != "" {
			c.Email = &emailStr
		}
	}
	if c.PhoneEncrypted != nil {
		phoneStr, err := s.decryptField(ctx, c.PhoneEncrypted, c.PhoneDEK, c.PhoneKeyID)
		if err != nil {
			return fmt.Errorf("decrypt phone: %w", err)
		}
		if phoneStr != "" {
			c.Phone = &phoneStr
		}
	}
	if c.TaxIDEncrypted != nil {
		taxIDStr, err := s.decryptField(ctx, c.TaxIDEncrypted, c.TaxIDDEK, c.TaxIDKeyID)
		if err != nil {
			return fmt.Errorf("decrypt tax_id: %w", err)
		}
		if taxIDStr != "" {
			c.TaxID = &taxIDStr
		}
	}
	if c.BillingAddressEncrypted != nil {
		addr, err := s.decryptField(ctx, c.BillingAddressEncrypted, c.BillingAddressDEK, c.BillingAddressKeyID)
		if err != nil {
			return fmt.Errorf("decrypt billing_address: %w", err)
		}
		if addr != "" {
			c.BillingAddress = &addr
		}
	}
	if c.ShippingAddressEncrypted != nil {
		addr, err := s.decryptField(ctx, c.ShippingAddressEncrypted, c.ShippingAddressDEK, c.ShippingAddressKeyID)
		if err != nil {
			return fmt.Errorf("decrypt shipping_address: %w", err)
		}
		if addr != "" {
			c.ShippingAddress = &addr
		}
	}
	return nil
}

// ----------------------------------------------------------------------------
// Internal helpers for credit & history
// ----------------------------------------------------------------------------
func (s *customerService) getOutstandingBalance(ctx context.Context, db repository.DBTX, companyID, customerID uuid.UUID) (decimal.Decimal, error) {
	query := `
		SELECT COALESCE(SUM(amount_due), 0)
		FROM sales.invoices
		WHERE company_id = $1 AND customer_id = $2
		AND status NOT IN ('paid', 'cancelled')
	`
	var total decimal.Decimal
	err := db.QueryRowContext(ctx, query, companyID, customerID).Scan(&total)
	if err != nil {
		return decimal.Zero, fmt.Errorf("get outstanding balance: %w", err)
	}
	return total, nil
}

func (s *customerService) logCreditHistory(ctx context.Context, tx repository.DBTX, companyID, customerID uuid.UUID, actionType string,
	prevLimit, newLimit *decimal.Decimal, prevOutstanding, newOutstanding *decimal.Decimal, reason *string, approvedBy, createdBy *uuid.UUID) error {

	history := &models.CreditCheckHistory{
		CreditHistoryID:     uuid.New(),
		CompanyID:           companyID,
		CustomerID:          customerID,
		ActionType:          actionType,
		PreviousLimit:       prevLimit,
		NewLimit:            newLimit,
		PreviousOutstanding: prevOutstanding,
		NewOutstanding:      newOutstanding,
		Reason:              reason,
		ApprovedBy:          approvedBy,
		CreatedBy:           createdBy,
	}
	return s.creditHistoryRepo.Create(ctx, tx, history)
}

// ----------------------------------------------------------------------------
// CRUD – writes start their own transaction
// ----------------------------------------------------------------------------
func (s *customerService) CreateCustomer(ctx context.Context, req CreateCustomerRequest, idempotencyKey string) (*models.Customer, error) {
	logger := s.logger.With(zap.String("method", "CreateCustomer"), zap.String("idempotency_key", idempotencyKey))

	if err := s.validateCreateCustomer(req); err != nil {
		return nil, err
	}
	if err := s.validateCustomerInput(req); err != nil {
		return nil, err
	}

	tx, err := s.pgClient.BeginTx(ctx, nil)
	if err != nil {
		return nil, fmt.Errorf("begin tx: %w", err)
	}
	defer tx.Rollback()

	var cached *models.Customer
	if err := s.idempotencyStore.Get(ctx, tx, idempotencyKey, &cached); err == nil && cached != nil {
		logger.Info("idempotent – returning cached customer")
		return cached, nil
	}

	exists, err := s.customerRepo.ExistsByCode(ctx, tx, req.CompanyID, req.CustomerCode)
	if err != nil {
		return nil, fmt.Errorf("check customer_code: %w", err)
	}
	if exists {
		return nil, fmt.Errorf("%w: customer_code %s already exists", salesErrors.ErrDuplicate, req.CustomerCode)
	}

	if req.Email != nil && *req.Email != "" {
		emailHash := hashEmail(*req.Email)
		hashExists, err := s.customerRepo.ExistsByEmailHash(ctx, tx, req.CompanyID, emailHash)
		if err != nil {
			return nil, fmt.Errorf("check email hash: %w", err)
		}
		if hashExists {
			return nil, fmt.Errorf("%w: email already in use", salesErrors.ErrDuplicate)
		}
	}

	if req.PaymentTermID != nil {
		termExists, err := s.paymentTermRepo.Exists(ctx, tx, req.CompanyID, *req.PaymentTermID)
		if err != nil {
			return nil, fmt.Errorf("check payment term: %w", err)
		}
		if !termExists {
			return nil, fmt.Errorf("%w: payment_term_id does not exist", salesErrors.ErrInvalidInput)
		}
	}

	emailEnc, emailDEK, emailKeyID, _ := s.encryptField(ctx, req.Email, "customer_email")
	phoneEnc, phoneDEK, phoneKeyID, _ := s.encryptField(ctx, req.Phone, "customer_phone")
	taxEnc, taxDEK, taxKeyID, _ := s.encryptField(ctx, req.TaxID, "customer_tax_id")
	billEnc, billDEK, billKeyID, _ := s.encryptField(ctx, req.BillingAddress, "customer_billing")
	shipEnc, shipDEK, shipKeyID, _ := s.encryptField(ctx, req.ShippingAddr, "customer_shipping")

	var emailHashPtr *string
	if req.Email != nil && *req.Email != "" {
		hash := hashEmail(*req.Email)
		emailHashPtr = &hash
	}

	customer := &models.Customer{
		CustomerID:               uuid.New(),
		CompanyID:                req.CompanyID,
		CustomerCode:             req.CustomerCode,
		Name:                     req.Name,
		EmailEncrypted:           emailEnc,
		EmailDEK:                 emailDEK,
		EmailKeyID:               emailKeyID,
		EmailHash:                emailHashPtr,
		PhoneEncrypted:           phoneEnc,
		PhoneDEK:                 phoneDEK,
		PhoneKeyID:               phoneKeyID,
		TaxIDEncrypted:           taxEnc,
		TaxIDDEK:                 taxDEK,
		TaxIDKeyID:               taxKeyID,
		BillingAddressEncrypted:  billEnc,
		BillingAddressDEK:        billDEK,
		BillingAddressKeyID:      billKeyID,
		ShippingAddressEncrypted: shipEnc,
		ShippingAddressDEK:       shipDEK,
		ShippingAddressKeyID:     shipKeyID,
		CreditLimit:              req.CreditLimit,
		IsActive:                 true,
		CreatedBy:                req.CreatedBy,
		UpdatedBy:                req.CreatedBy,
		PaymentTermID:            req.PaymentTermID,
	}

	if err := s.customerRepo.Create(ctx, tx, customer); err != nil {
		return nil, fmt.Errorf("create customer: %w", err)
	}

	if req.CreditLimit != nil && !req.CreditLimit.IsZero() {
		if err := s.logCreditHistory(ctx, tx, req.CompanyID, customer.CustomerID, "limit_change",
			nil, req.CreditLimit, nil, nil, nil, nil, req.CreatedBy); err != nil {
			logger.Warn("failed to log credit history", zap.Error(err))
		}
	}

	if err := s.emitCustomerEvent(ctx, tx, customer, salesEvents.EventCustomerCreated); err != nil {
		logger.Warn("failed to emit customer created event", zap.Error(err))
	}

	_ = s.idempotencyStore.Store(ctx, tx, idempotencyKey, customer)

	if err := tx.Commit(); err != nil {
		return nil, fmt.Errorf("commit tx: %w", err)
	}

	_ = s.decryptCustomer(ctx, customer)

	if s.auditService != nil {
		_ = s.auditService.LogAction(ctx, nil, &req.CompanyID, "sales", "create_customer", "customer",
			&customer.CustomerID, "user", req.CreatedBy, nil, nil, map[string]interface{}{
				"customer_code": customer.CustomerCode,
			})
	}
	return customer, nil
}

func (s *customerService) validateCreateCustomer(req CreateCustomerRequest) error {
	if req.CompanyID == uuid.Nil {
		return fmt.Errorf("%w: company_id required", salesErrors.ErrInvalidInput)
	}
	if req.CustomerCode == "" {
		return fmt.Errorf("%w: customer_code required", salesErrors.ErrInvalidInput)
	}
	if req.Name == "" {
		return fmt.Errorf("%w: name required", salesErrors.ErrInvalidInput)
	}
	return nil
}

func (s *customerService) validateCustomerInput(req CreateCustomerRequest) error {
	if len(req.CustomerCode) > maxCustomerCodeLen {
		return fmt.Errorf("%w: customer_code must not exceed %d characters", salesErrors.ErrInvalidInput, maxCustomerCodeLen)
	}
	if len(req.Name) > maxNameLen {
		return fmt.Errorf("%w: name must not exceed %d characters", salesErrors.ErrInvalidInput, maxNameLen)
	}
	if req.Email != nil && *req.Email != "" {
		if len(*req.Email) > maxEmailLen {
			return fmt.Errorf("%w: email must not exceed %d characters", salesErrors.ErrInvalidInput, maxEmailLen)
		}
		if !isValidEmail(*req.Email) {
			return fmt.Errorf("%w: invalid email format", salesErrors.ErrInvalidInput)
		}
	}
	if req.BillingAddress != nil && *req.BillingAddress != "" && len(*req.BillingAddress) > maxBillingAddrLen {
		return fmt.Errorf("%w: billing_address must not exceed %d characters", salesErrors.ErrInvalidInput, maxBillingAddrLen)
	}
	return nil
}

func (s *customerService) UpdateCustomer(ctx context.Context, companyID, customerID uuid.UUID, req UpdateCustomerRequest, idempotencyKey string) (*models.Customer, error) {
	logger := s.logger.With(zap.String("method", "UpdateCustomer"), zap.String("idempotency_key", idempotencyKey))

	if companyID == uuid.Nil || customerID == uuid.Nil {
		return nil, salesErrors.ErrInvalidInput
	}

	tx, err := s.pgClient.BeginTx(ctx, nil)
	if err != nil {
		return nil, fmt.Errorf("begin tx: %w", err)
	}
	defer tx.Rollback()

	var cached *models.Customer
	if err := s.idempotencyStore.Get(ctx, tx, idempotencyKey, &cached); err == nil && cached != nil {
		logger.Info("idempotent – returning cached customer")
		return cached, nil
	}

	customer, err := s.customerRepo.GetByIDForUpdate(ctx, tx, companyID, customerID)
	if err != nil {
		return nil, err
	}
	if customer.CompanyID != companyID {
		return nil, salesErrors.ErrPermissionDenied
	}

	changes := make(map[string]interface{})

	if req.Name != nil && *req.Name != customer.Name {
		if len(*req.Name) > maxNameLen {
			return nil, fmt.Errorf("%w: name must not exceed %d characters", salesErrors.ErrInvalidInput, maxNameLen)
		}
		changes["name"] = map[string]string{"old": customer.Name, "new": *req.Name}
		customer.Name = *req.Name
	}
	if req.IsActive != nil && *req.IsActive != customer.IsActive {
		changes["is_active"] = map[string]bool{"old": customer.IsActive, "new": *req.IsActive}
		customer.IsActive = *req.IsActive
	}

	if req.Email != nil {
		if len(*req.Email) > maxEmailLen {
			return nil, fmt.Errorf("%w: email must not exceed %d characters", salesErrors.ErrInvalidInput, maxEmailLen)
		}
		if !isValidEmail(*req.Email) {
			return nil, fmt.Errorf("%w: invalid email format", salesErrors.ErrInvalidInput)
		}
		newHash := hashEmail(*req.Email)
		exists, err := s.customerRepo.ExistsByEmailHashExcluding(ctx, tx, companyID, newHash, customerID)
		if err != nil {
			return nil, fmt.Errorf("check email uniqueness: %w", err)
		}
		if exists {
			return nil, fmt.Errorf("%w: email already in use", salesErrors.ErrDuplicate)
		}
		enc, dek, kid, err := s.encryptField(ctx, req.Email, "customer_email")
		if err != nil {
			return nil, err
		}
		oldPlain, _ := s.decryptField(ctx, customer.EmailEncrypted, customer.EmailDEK, customer.EmailKeyID)
		changes["email"] = map[string]string{"old": oldPlain, "new": *req.Email}
		customer.EmailEncrypted = enc
		customer.EmailDEK = dek
		customer.EmailKeyID = kid
		customer.EmailHash = &newHash
	}

	if req.Phone != nil {
		enc, dek, kid, err := s.encryptField(ctx, req.Phone, "customer_phone")
		if err != nil {
			return nil, err
		}
		oldPlain, _ := s.decryptField(ctx, customer.PhoneEncrypted, customer.PhoneDEK, customer.PhoneKeyID)
		changes["phone"] = map[string]string{"old": oldPlain, "new": *req.Phone}
		customer.PhoneEncrypted = enc
		customer.PhoneDEK = dek
		customer.PhoneKeyID = kid
	}
	if req.TaxID != nil {
		enc, dek, kid, err := s.encryptField(ctx, req.TaxID, "customer_tax_id")
		if err != nil {
			return nil, err
		}
		oldPlain, _ := s.decryptField(ctx, customer.TaxIDEncrypted, customer.TaxIDDEK, customer.TaxIDKeyID)
		changes["tax_id"] = map[string]string{"old": oldPlain, "new": *req.TaxID}
		customer.TaxIDEncrypted = enc
		customer.TaxIDDEK = dek
		customer.TaxIDKeyID = kid
	}
	if req.BillingAddress != nil {
		if len(*req.BillingAddress) > maxBillingAddrLen {
			return nil, fmt.Errorf("%w: billing_address must not exceed %d characters", salesErrors.ErrInvalidInput, maxBillingAddrLen)
		}
		enc, dek, kid, err := s.encryptField(ctx, req.BillingAddress, "customer_billing")
		if err != nil {
			return nil, err
		}
		oldPlain, _ := s.decryptField(ctx, customer.BillingAddressEncrypted, customer.BillingAddressDEK, customer.BillingAddressKeyID)
		changes["billing_address"] = map[string]string{"old": oldPlain, "new": *req.BillingAddress}
		customer.BillingAddressEncrypted = enc
		customer.BillingAddressDEK = dek
		customer.BillingAddressKeyID = kid
	}
	if req.ShippingAddr != nil {
		enc, dek, kid, err := s.encryptField(ctx, req.ShippingAddr, "customer_shipping")
		if err != nil {
			return nil, err
		}
		oldPlain, _ := s.decryptField(ctx, customer.ShippingAddressEncrypted, customer.ShippingAddressDEK, customer.ShippingAddressKeyID)
		changes["shipping_address"] = map[string]string{"old": oldPlain, "new": *req.ShippingAddr}
		customer.ShippingAddressEncrypted = enc
		customer.ShippingAddressDEK = dek
		customer.ShippingAddressKeyID = kid
	}

	customer.UpdatedBy = req.UpdatedBy
	if err := s.customerRepo.Update(ctx, tx, customer); err != nil {
		return nil, fmt.Errorf("update customer: %w", err)
	}

	if err := s.emitCustomerEvent(ctx, tx, customer, salesEvents.EventCustomerUpdated); err != nil {
		logger.Warn("failed to emit customer updated event", zap.Error(err))
	}

	_ = s.idempotencyStore.Store(ctx, tx, idempotencyKey, customer)

	if err := tx.Commit(); err != nil {
		return nil, fmt.Errorf("commit tx: %w", err)
	}

	_ = s.decryptCustomer(ctx, customer)

	if s.auditService != nil {
		_ = s.auditService.LogAction(ctx, nil, &companyID, "sales", "update_customer", "customer",
			&customerID, "user", req.UpdatedBy, nil, nil, changes)
	}
	return customer, nil
}

func (s *customerService) DeleteCustomer(ctx context.Context, companyID, customerID uuid.UUID, deletedBy *uuid.UUID, idempotencyKey string) error {
	logger := s.logger.With(zap.String("method", "DeleteCustomer"), zap.String("idempotency_key", idempotencyKey))

	tx, err := s.pgClient.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("begin tx: %w", err)
	}
	defer tx.Rollback()

	var processed bool
	if err := s.idempotencyStore.Get(ctx, tx, idempotencyKey, &processed); err == nil && processed {
		logger.Info("idempotent – already deleted")
		return nil
	}

	customer, err := s.customerRepo.GetByID(ctx, tx, companyID, customerID)
	if err != nil {
		return err
	}
	if customer.CompanyID != companyID {
		return salesErrors.ErrPermissionDenied
	}

	var hasOrders bool
	err = tx.QueryRowContext(ctx, `SELECT EXISTS(SELECT 1 FROM sales.orders WHERE company_id=$1 AND customer_id=$2 LIMIT 1)`, companyID, customerID).Scan(&hasOrders)
	if err != nil && err != sql.ErrNoRows {
		return fmt.Errorf("check orders: %w", err)
	}
	var hasInvoices bool
	err = tx.QueryRowContext(ctx, `SELECT EXISTS(SELECT 1 FROM sales.invoices WHERE company_id=$1 AND customer_id=$2 LIMIT 1)`, companyID, customerID).Scan(&hasInvoices)
	if err != nil && err != sql.ErrNoRows {
		return fmt.Errorf("check invoices: %w", err)
	}

	if hasOrders || hasInvoices {
		if err := s.customerRepo.SetActiveStatus(ctx, tx, companyID, customerID, false, deletedBy); err != nil {
			return fmt.Errorf("deactivate customer: %w", err)
		}
		logger.Info("customer has historical data, deactivated instead of hard delete")
	} else {
		if err := s.customerRepo.Delete(ctx, tx, companyID, customerID); err != nil {
			return fmt.Errorf("delete customer: %w", err)
		}
	}

	if err := s.emitCustomerEvent(ctx, tx, customer, salesEvents.EventCustomerDeleted); err != nil {
		logger.Warn("failed to emit delete event", zap.Error(err))
	}

	_ = s.idempotencyStore.Store(ctx, tx, idempotencyKey, true)

	if err := tx.Commit(); err != nil {
		return fmt.Errorf("commit tx: %w", err)
	}

	if s.auditService != nil {
		_ = s.auditService.LogAction(ctx, nil, &companyID, "sales", "delete_customer", "customer",
			&customerID, "user", deletedBy, nil, nil, nil)
	}
	return nil
}

// ----------------------------------------------------------------------------
// Read methods – use default DB connection (no transaction needed)
// ----------------------------------------------------------------------------
func (s *customerService) GetCustomerByID(ctx context.Context, companyID, customerID uuid.UUID) (*models.Customer, error) {
	db := s.pgClient.DB
	customer, err := s.customerRepo.GetByID(ctx, db, companyID, customerID)
	if err != nil {
		return nil, err
	}
	if err := s.decryptCustomer(ctx, customer); err != nil {
		return nil, err
	}
	return customer, nil
}

func (s *customerService) GetCustomerByCode(ctx context.Context, companyID uuid.UUID, code string) (*models.Customer, error) {
	db := s.pgClient.DB
	customer, err := s.customerRepo.GetByCode(ctx, db, companyID, code)
	if err != nil {
		return nil, err
	}
	if err := s.decryptCustomer(ctx, customer); err != nil {
		return nil, err
	}
	return customer, nil
}

func (s *customerService) ListCustomers(ctx context.Context, filter CustomerListFilter, p Pagination, srt Sort) ([]*models.Customer, int64, error) {
	db := s.pgClient.DB
	repoFilter := repository.CustomerFilter{
		CompanyID:    filter.CompanyID,
		IsActive:     filter.IsActive,
		CustomerIDs:  filter.CustomerIDs,
		CustomerCode: filter.CustomerCode,
		Name:         filter.Name,
		CreatedFrom:  filter.CreatedFrom,
		CreatedTo:    filter.CreatedTo,
		UpdatedFrom:  filter.UpdatedFrom,
		UpdatedTo:    filter.UpdatedTo,
	}
	customers, total, err := s.customerRepo.List(ctx, db, repoFilter, repository.Pagination{Limit: p.Limit, Offset: p.Offset}, repository.Sort{Field: srt.Field, Direction: srt.Direction})
	if err != nil {
		return nil, 0, err
	}
	for _, c := range customers {
		_ = s.decryptCustomer(ctx, c)
	}
	return customers, total, nil
}

func (s *customerService) SearchCustomers(ctx context.Context, companyID uuid.UUID, query string, limit, offset int) ([]*models.Customer, int64, error) {
	db := s.pgClient.DB
	customers, total, err := s.customerRepo.Search(ctx, db, companyID, query, limit, offset)
	if err != nil {
		return nil, 0, err
	}
	for _, c := range customers {
		_ = s.decryptCustomer(ctx, c)
	}
	return customers, total, nil
}

// ----------------------------------------------------------------------------
// Activation – own transaction
// ----------------------------------------------------------------------------
func (s *customerService) ActivateCustomer(ctx context.Context, companyID, customerID uuid.UUID, updatedBy *uuid.UUID, idempotencyKey string) error {
	return s.setActiveStatus(ctx, companyID, customerID, true, updatedBy, idempotencyKey)
}

func (s *customerService) DeactivateCustomer(ctx context.Context, companyID, customerID uuid.UUID, updatedBy *uuid.UUID, idempotencyKey string) error {
	return s.setActiveStatus(ctx, companyID, customerID, false, updatedBy, idempotencyKey)
}

func (s *customerService) setActiveStatus(ctx context.Context, companyID, customerID uuid.UUID, active bool, updatedBy *uuid.UUID, idempotencyKey string) error {
	tx, err := s.pgClient.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("begin tx: %w", err)
	}
	defer tx.Rollback()

	var processed bool
	if err := s.idempotencyStore.Get(ctx, tx, idempotencyKey, &processed); err == nil && processed {
		return nil
	}

	if err := s.customerRepo.SetActiveStatus(ctx, tx, companyID, customerID, active, updatedBy); err != nil {
		return err
	}

	cust, _ := s.customerRepo.GetByID(ctx, tx, companyID, customerID)
	if cust != nil {
		eventType := salesEvents.EventCustomerDeactivated
		if active {
			eventType = salesEvents.EventCustomerActivated
		}
		_ = s.emitCustomerEvent(ctx, tx, cust, eventType)
	}

	_ = s.idempotencyStore.Store(ctx, tx, idempotencyKey, true)
	if err := tx.Commit(); err != nil {
		return fmt.Errorf("commit tx: %w", err)
	}
	return nil
}

// ----------------------------------------------------------------------------
// Credit limit – writes own transaction, reads use default DB
// ----------------------------------------------------------------------------
func (s *customerService) UpdateCreditLimit(ctx context.Context, companyID, customerID uuid.UUID, newLimit decimal.Decimal, reason *string, updatedBy *uuid.UUID, idempotencyKey string) error {
	tx, err := s.pgClient.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("begin tx: %w", err)
	}
	defer tx.Rollback()

	var processed bool
	if err := s.idempotencyStore.Get(ctx, tx, idempotencyKey, &processed); err == nil && processed {
		return nil
	}

	cust, err := s.customerRepo.GetByIDForUpdate(ctx, tx, companyID, customerID)
	if err != nil {
		return err
	}
	oldLimit := decimal.Zero
	if cust.CreditLimit != nil {
		oldLimit = *cust.CreditLimit
	}

	cust.CreditLimit = &newLimit
	cust.UpdatedBy = updatedBy
	if err := s.customerRepo.Update(ctx, tx, cust); err != nil {
		return fmt.Errorf("update credit limit: %w", err)
	}

	if err := s.logCreditHistory(ctx, tx, companyID, customerID, "limit_change",
		&oldLimit, &newLimit, nil, nil, reason, nil, updatedBy); err != nil {
		s.logger.Warn("failed to log credit limit change", zap.Error(err))
	}

	_ = s.emitCustomerEvent(ctx, tx, cust, salesEvents.EventCustomerCreditLimitUpdated)

	_ = s.idempotencyStore.Store(ctx, tx, idempotencyKey, true)
	if err := tx.Commit(); err != nil {
		return fmt.Errorf("commit tx: %w", err)
	}
	return nil
}

func (s *customerService) GetCreditLimit(ctx context.Context, companyID, customerID uuid.UUID) (decimal.Decimal, error) {
	db := s.pgClient.DB
	cust, err := s.customerRepo.GetCreditLimit(ctx, db, companyID, customerID)
	if err != nil {
		return decimal.Zero, err
	}
	if cust.CreditLimit == nil {
		return decimal.Zero, nil
	}
	return *cust.CreditLimit, nil
}

func (s *customerService) GetOutstandingBalance(ctx context.Context, companyID, customerID uuid.UUID) (decimal.Decimal, error) {
	return s.getOutstandingBalance(ctx, s.pgClient.DB, companyID, customerID)
}

func (s *customerService) CanCustomerPurchaseAmount(ctx context.Context, companyID, customerID uuid.UUID, amount decimal.Decimal) (bool, error) {
	limit, err := s.GetCreditLimit(ctx, companyID, customerID)
	if err != nil {
		return false, err
	}
	if limit.IsZero() {
		return true, nil
	}
	outstanding, err := s.GetOutstandingBalance(ctx, companyID, customerID)
	if err != nil {
		return false, err
	}
	available := limit.Sub(outstanding)
	return available.GreaterThanOrEqual(amount), nil
}

// ----------------------------------------------------------------------------
// Payment term – own transaction
// ----------------------------------------------------------------------------
func (s *customerService) AssignPaymentTerm(ctx context.Context, companyID, customerID, termID uuid.UUID, updatedBy *uuid.UUID, idempotencyKey string) error {
	tx, err := s.pgClient.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("begin tx: %w", err)
	}
	defer tx.Rollback()

	var processed bool
	if err := s.idempotencyStore.Get(ctx, tx, idempotencyKey, &processed); err == nil && processed {
		return nil
	}

	term, err := s.paymentTermRepo.GetByID(ctx, tx, companyID, termID)
	if err != nil {
		return fmt.Errorf("payment term: %w", err)
	}
	if !term.IsActive {
		return fmt.Errorf("%w: payment term is inactive", salesErrors.ErrInvalidInput)
	}

	if err := s.paymentTermRepo.ApplyToCustomer(ctx, tx, companyID, customerID, termID, updatedBy); err != nil {
		return err
	}

	_ = s.idempotencyStore.Store(ctx, tx, idempotencyKey, true)
	if err := tx.Commit(); err != nil {
		return fmt.Errorf("commit tx: %w", err)
	}
	return nil
}

func (s *customerService) RemovePaymentTerm(ctx context.Context, companyID, customerID uuid.UUID, updatedBy *uuid.UUID, idempotencyKey string) error {
	tx, err := s.pgClient.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("begin tx: %w", err)
	}
	defer tx.Rollback()

	var processed bool
	if err := s.idempotencyStore.Get(ctx, tx, idempotencyKey, &processed); err == nil && processed {
		return nil
	}

	query := `UPDATE sales.customers SET payment_term_id = NULL, updated_at = NOW(), updated_by = $3 WHERE company_id = $1 AND customer_id = $2`
	_, err = tx.ExecContext(ctx, query, companyID, customerID, s.nullUUID(updatedBy))
	if err != nil {
		return fmt.Errorf("remove payment term: %w", err)
	}

	_ = s.idempotencyStore.Store(ctx, tx, idempotencyKey, true)
	return tx.Commit()
}

// ----------------------------------------------------------------------------
// Sales rep assignment – not supported
// ----------------------------------------------------------------------------
func (s *customerService) AssignSalesRep(ctx context.Context, companyID, customerID, salesRepID uuid.UUID, updatedBy *uuid.UUID, idempotencyKey string) error {
	return fmt.Errorf("customer sales rep assignment not supported – assign at order/invoice level")
}

func (s *customerService) RemoveSalesRep(ctx context.Context, companyID, customerID uuid.UUID, updatedBy *uuid.UUID, idempotencyKey string) error {
	return fmt.Errorf("customer sales rep removal not supported")
}

// ----------------------------------------------------------------------------
// Reporting – use default DB
// ----------------------------------------------------------------------------
func (s *customerService) GetCustomersWithOutstandingInvoices(ctx context.Context, companyID uuid.UUID) ([]*models.Customer, error) {
	db := s.pgClient.DB
	customers, err := s.customerRepo.GetCustomersWithOutstandingInvoices(ctx, db, companyID)
	if err != nil {
		return nil, err
	}
	for _, c := range customers {
		_ = s.decryptCustomer(ctx, c)
	}
	return customers, nil
}

func (s *customerService) GetTopCustomersByRevenue(ctx context.Context, companyID uuid.UUID, limit int, from, to *time.Time) ([]*models.Customer, error) {
	db := s.pgClient.DB
	customers, err := s.customerRepo.GetTopCustomersByRevenue(ctx, db, companyID, limit, from, to)
	if err != nil {
		return nil, err
	}
	for _, c := range customers {
		_ = s.decryptCustomer(ctx, c)
	}
	return customers, nil
}

// ----------------------------------------------------------------------------
// Validation & existence – use default DB
// ----------------------------------------------------------------------------
func (s *customerService) ValidateCustomer(ctx context.Context, customer *models.Customer) error {
	if customer.CustomerCode == "" {
		return fmt.Errorf("%w: customer_code required", salesErrors.ErrInvalidInput)
	}
	if customer.Name == "" {
		return fmt.Errorf("%w: name required", salesErrors.ErrInvalidInput)
	}
	return nil
}

func (s *customerService) CustomerExists(ctx context.Context, companyID, customerID uuid.UUID) (bool, error) {
	return s.customerRepo.Exists(ctx, s.pgClient.DB, companyID, customerID)
}

func (s *customerService) IsCustomerActive(ctx context.Context, companyID, customerID uuid.UUID) (bool, error) {
	return s.customerRepo.IsActive(ctx, s.pgClient.DB, companyID, customerID)
}

// ----------------------------------------------------------------------------
// Event emission – requires a transaction
// ----------------------------------------------------------------------------
func (s *customerService) emitCustomerEvent(ctx context.Context, tx repository.DBTX, customer *models.Customer, eventType string) error {
	sqlTx, ok := tx.(*sql.Tx)
	if !ok {
		return fmt.Errorf("tx is not a *sql.Tx")
	}
	payload := map[string]interface{}{
		"customer_id":   customer.CustomerID.String(),
		"company_id":    customer.CompanyID.String(),
		"customer_code": customer.CustomerCode,
		"name":          customer.Name,
		"is_active":     customer.IsActive,
	}
	data, err := json.Marshal(payload)
	if err != nil {
		return err
	}
	event := &outbox.Event{
		EventID:       uuid.New().String(),
		AggregateType: "customer",
		AggregateID:   customer.CustomerID.String(),
		EventType:     eventType,
		Topic:         salesEvents.TopicSalesEvents,
		Payload:       data,
	}
	return s.outboxRepo.Store(ctx, sqlTx, event)
}

// Helper for nil UUID
func (s *customerService) nullUUID(id *uuid.UUID) interface{} {
	if id == nil || *id == uuid.Nil {
		return nil
	}
	return *id
}

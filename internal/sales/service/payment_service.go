package service

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"time"

	"github.com/google/uuid"
	"github.com/shopspring/decimal"
	"go.uber.org/zap"

	"auth-service/internal/client"
	"auth-service/internal/infrastructure/audit"
	"auth-service/internal/infrastructure/idempotency"
	"auth-service/internal/infrastructure/outbox"
	salesErrors "auth-service/internal/sales/errors"
	salesEvents "auth-service/internal/sales/events"
	"auth-service/internal/sales/models"
	"auth-service/internal/sales/models/enums"
	"auth-service/internal/sales/repository"
)

// =============================================================================
// PaymentService interface (unchanged – included for completeness)
// =============================================================================

type PaymentService interface {
	CreatePayment(ctx context.Context, req *CreatePaymentRequest) (*models.Payment, error)
	UpdatePayment(ctx context.Context, companyID uuid.UUID, paymentID uuid.UUID, req *UpdatePaymentRequest) (*models.Payment, error)
	DeletePayment(ctx context.Context, companyID uuid.UUID, paymentID uuid.UUID, deletedBy uuid.UUID) error
	GetPaymentByID(ctx context.Context, companyID uuid.UUID, paymentID uuid.UUID) (*models.Payment, error)
	GetPaymentByNumber(ctx context.Context, companyID uuid.UUID, paymentNumber string) (*models.Payment, error)
	GetPaymentByGatewayReference(ctx context.Context, companyID uuid.UUID, gatewayReference string) (*models.Payment, error)
	ListPayments(ctx context.Context, filter PaymentListFilter, p Pagination, s Sort) ([]*models.Payment, int64, error)
	SearchPayments(ctx context.Context, companyID uuid.UUID, query string, limit int, offset int) ([]*models.Payment, int64, error)
	GetPaymentsByCustomer(ctx context.Context, companyID uuid.UUID, customerID uuid.UUID, p Pagination, s Sort) ([]*models.Payment, int64, error)
	GetPaymentsByInvoice(ctx context.Context, companyID uuid.UUID, invoiceID uuid.UUID) ([]*models.Payment, error)
	RegisterCashPayment(ctx context.Context, req *RegisterCashPaymentRequest) (*models.Payment, error)
	RegisterCardPayment(ctx context.Context, req *RegisterCardPaymentRequest) (*models.Payment, error)
	RegisterBankTransferPayment(ctx context.Context, req *RegisterBankTransferPaymentRequest) (*models.Payment, error)
	RegisterChequePayment(ctx context.Context, req *RegisterChequePaymentRequest) (*models.Payment, error)
	RegisterWalletPayment(ctx context.Context, req *RegisterWalletPaymentRequest) (*models.Payment, error)
	ProcessGatewayPayment(ctx context.Context, req *ProcessGatewayPaymentRequest) (*models.Payment, error)
	ProcessGatewayWebhook(ctx context.Context, req *ProcessGatewayWebhookRequest) error
	ValidateGatewaySignature(ctx context.Context, gateway string, payload []byte, signature string) error
	EnsureIdempotentPayment(ctx context.Context, companyID uuid.UUID, idempotencyKey string) (*models.Payment, bool, error)
	GetPaymentByIdempotencyKey(ctx context.Context, companyID uuid.UUID, idempotencyKey string) (*models.Payment, error)
	AllocatePayment(ctx context.Context, companyID uuid.UUID, paymentID uuid.UUID, invoiceID uuid.UUID, amount decimal.Decimal, allocatedBy uuid.UUID) error
	AllocatePaymentToInvoices(ctx context.Context, companyID uuid.UUID, paymentID uuid.UUID, allocations []PaymentAllocationRequest, allocatedBy uuid.UUID) error
	AutoAllocatePayment(ctx context.Context, companyID uuid.UUID, paymentID uuid.UUID, allocatedBy uuid.UUID) error
	RemoveAllocation(ctx context.Context, companyID uuid.UUID, paymentID uuid.UUID, allocationID uuid.UUID, removedBy uuid.UUID) error
	GetPaymentAllocations(ctx context.Context, companyID uuid.UUID, paymentID uuid.UUID) ([]*models.PaymentAllocation, error)
	GetUnallocatedAmount(ctx context.Context, companyID uuid.UUID, paymentID uuid.UUID) (decimal.Decimal, error)
	IsFullyAllocated(ctx context.Context, companyID uuid.UUID, paymentID uuid.UUID) (bool, error)
	CreateRefund(ctx context.Context, req *CreateRefundRequest) (*models.PaymentRefund, error)
	RefundFullPayment(ctx context.Context, companyID uuid.UUID, paymentID uuid.UUID, reason string, refundedBy uuid.UUID) (*models.PaymentRefund, error)
	RefundPartialPayment(ctx context.Context, companyID uuid.UUID, paymentID uuid.UUID, amount decimal.Decimal, reason string, refundedBy uuid.UUID) (*models.PaymentRefund, error)
	ProcessGatewayRefund(ctx context.Context, req *ProcessGatewayRefundRequest) (*models.PaymentRefund, error)
	GetRefundByID(ctx context.Context, companyID uuid.UUID, refundID uuid.UUID) (*models.PaymentRefund, error)
	GetPaymentRefunds(ctx context.Context, companyID uuid.UUID, paymentID uuid.UUID) ([]*models.PaymentRefund, error)
	GetRefundedAmount(ctx context.Context, companyID uuid.UUID, paymentID uuid.UUID) (decimal.Decimal, error)
	IsFullyRefunded(ctx context.Context, companyID uuid.UUID, paymentID uuid.UUID) (bool, error)
	UpdateStatus(ctx context.Context, companyID uuid.UUID, paymentID uuid.UUID, status enums.PaymentStatus, updatedBy uuid.UUID) error
	MarkPending(ctx context.Context, companyID uuid.UUID, paymentID uuid.UUID, updatedBy uuid.UUID) error
	MarkProcessing(ctx context.Context, companyID uuid.UUID, paymentID uuid.UUID, updatedBy uuid.UUID) error
	MarkCompleted(ctx context.Context, companyID uuid.UUID, paymentID uuid.UUID, completedAt time.Time, updatedBy uuid.UUID) error
	MarkFailed(ctx context.Context, companyID uuid.UUID, paymentID uuid.UUID, reason string, updatedBy uuid.UUID) error
	CancelPayment(ctx context.Context, companyID uuid.UUID, paymentID uuid.UUID, reason string, cancelledBy uuid.UUID) error
	ReconcilePayment(ctx context.Context, companyID uuid.UUID, paymentID uuid.UUID, reconciledBy uuid.UUID) error
	UnreconcilePayment(ctx context.Context, companyID uuid.UUID, paymentID uuid.UUID, unreconciledBy uuid.UUID) error
	GetUnreconciledPayments(ctx context.Context, companyID uuid.UUID) ([]*models.Payment, error)
	ValidatePayment(ctx context.Context, payment *models.Payment) error
	ValidatePaymentAllocation(ctx context.Context, companyID uuid.UUID, paymentID uuid.UUID, invoiceID uuid.UUID, amount decimal.Decimal) error
	ValidateRefund(ctx context.Context, companyID uuid.UUID, paymentID uuid.UUID, amount decimal.Decimal) error
	ValidatePaymentStatusTransition(ctx context.Context, currentStatus enums.PaymentStatus, nextStatus enums.PaymentStatus) error
	GetTotalPaymentsReceived(ctx context.Context, companyID uuid.UUID, from *time.Time, to *time.Time) (decimal.Decimal, error)
	GetTotalRefundedAmount(ctx context.Context, companyID uuid.UUID, from *time.Time, to *time.Time) (decimal.Decimal, error)
	GetNetCollections(ctx context.Context, companyID uuid.UUID, from *time.Time, to *time.Time) (decimal.Decimal, error)
	GetPaymentsByMethod(ctx context.Context, companyID uuid.UUID, from *time.Time, to *time.Time) (map[enums.PaymentMethod]decimal.Decimal, error)
	GetFailedPayments(ctx context.Context, companyID uuid.UUID, from *time.Time, to *time.Time) ([]*models.Payment, error)
	PaymentExists(ctx context.Context, companyID uuid.UUID, paymentID uuid.UUID) (bool, error)
	PaymentNumberExists(ctx context.Context, companyID uuid.UUID, paymentNumber string) (bool, error)
	GatewayTransactionExists(ctx context.Context, companyID uuid.UUID, gatewayTransactionID string) (bool, error)
	HasRefunds(ctx context.Context, companyID uuid.UUID, paymentID uuid.UUID) (bool, error)
}

// =============================================================================
// Request/Response DTOs (as originally defined)
// =============================================================================

type CreatePaymentRequest struct {
	CompanyID       uuid.UUID
	PaymentNumber   string
	ExternalRef     *string
	PaymentDate     time.Time
	Amount          decimal.Decimal
	PaymentMethod   enums.PaymentMethod
	Reference       *string
	GatewayResponse models.JSONB
	CreatedBy       *uuid.UUID
}

type UpdatePaymentRequest struct {
	ExternalRef     *string
	PaymentDate     *time.Time
	Amount          *decimal.Decimal
	PaymentMethod   *enums.PaymentMethod
	Reference       *string
	GatewayResponse models.JSONB
	UpdatedBy       *uuid.UUID
}

type PaymentListFilter struct {
	CompanyID     uuid.UUID
	CustomerID    *uuid.UUID
	InvoiceID     *uuid.UUID
	Status        *enums.PaymentStatus
	PaymentMethod *enums.PaymentMethod
	FromDate      *time.Time
	ToDate        *time.Time
	MinAmount     *decimal.Decimal
	MaxAmount     *decimal.Decimal
}

type PaymentAllocationRequest struct {
	InvoiceID uuid.UUID
	Amount    decimal.Decimal
}

type RegisterCashPaymentRequest struct {
	CompanyID   uuid.UUID
	CustomerID  uuid.UUID
	Amount      decimal.Decimal
	PaymentDate time.Time
	Reference   *string
	Allocations []PaymentAllocationRequest
	CreatedBy   uuid.UUID
}

type RegisterCardPaymentRequest struct {
	CompanyID       uuid.UUID
	CustomerID      uuid.UUID
	Amount          decimal.Decimal
	PaymentDate     time.Time
	CardLast4       string
	CardBrand       string
	GatewayTxID     string
	GatewayResponse models.JSONB
	Allocations     []PaymentAllocationRequest
	CreatedBy       uuid.UUID
}

type RegisterBankTransferPaymentRequest struct {
	CompanyID       uuid.UUID
	CustomerID      uuid.UUID
	Amount          decimal.Decimal
	PaymentDate     time.Time
	ReferenceNumber string
	BankName        *string
	Allocations     []PaymentAllocationRequest
	CreatedBy       uuid.UUID
}

type RegisterChequePaymentRequest struct {
	CompanyID    uuid.UUID
	CustomerID   uuid.UUID
	Amount       decimal.Decimal
	PaymentDate  time.Time
	ChequeNumber string
	BankName     *string
	Allocations  []PaymentAllocationRequest
	CreatedBy    uuid.UUID
}

type RegisterWalletPaymentRequest struct {
	CompanyID      uuid.UUID
	CustomerID     uuid.UUID
	Amount         decimal.Decimal
	PaymentDate    time.Time
	WalletProvider string
	WalletTxID     string
	Allocations    []PaymentAllocationRequest
	CreatedBy      uuid.UUID
}

type ProcessGatewayPaymentRequest struct {
	CompanyID      uuid.UUID
	CustomerID     uuid.UUID
	Amount         decimal.Decimal
	PaymentMethod  enums.PaymentMethod
	GatewayName    string
	GatewayToken   string
	IdempotencyKey string
	Allocations    []PaymentAllocationRequest
	CreatedBy      uuid.UUID
}

type ProcessGatewayWebhookRequest struct {
	CompanyID   uuid.UUID
	GatewayName string
	GatewayTxID string
	Status      string
	RawPayload  []byte
	Signature   string
}

type CreateRefundRequest struct {
	CompanyID  uuid.UUID
	PaymentID  uuid.UUID
	Amount     decimal.Decimal
	Reason     string
	RefundedBy uuid.UUID
}

type ProcessGatewayRefundRequest struct {
	CompanyID   uuid.UUID
	PaymentID   uuid.UUID
	Amount      decimal.Decimal
	Reason      string
	GatewayName string
	RefundedBy  uuid.UUID
}

// =============================================================================
// paymentService implementation
// =============================================================================

type paymentService struct {
	paymentRepo      repository.PaymentRepository
	invoiceRepo      repository.InvoiceRepository
	refundRepo       repository.PaymentRefundRepository
	outboxRepo       outbox.Repository
	idempotencyStore idempotency.Store
	auditService     *audit.AuditService
	pgClient         *client.PostgresClient
	logger           *zap.Logger
}

func NewPaymentService(
	paymentRepo repository.PaymentRepository,
	invoiceRepo repository.InvoiceRepository,
	refundRepo repository.PaymentRefundRepository,
	outboxRepo outbox.Repository,
	idempotencyStore idempotency.Store,
	auditService *audit.AuditService,
	pgClient *client.PostgresClient,
	logger *zap.Logger,
) PaymentService {
	return &paymentService{
		paymentRepo:      paymentRepo,
		invoiceRepo:      invoiceRepo,
		refundRepo:       refundRepo,
		outboxRepo:       outboxRepo,
		idempotencyStore: idempotencyStore,
		auditService:     auditService,
		pgClient:         pgClient,
		logger:           logger.Named("payment_service"),
	}
}

// --------------------------------------------------------------------------
// Helper functions
// --------------------------------------------------------------------------

func (s *paymentService) generatePaymentNumber(tx repository.DBTX, companyID uuid.UUID) (string, error) {
	prefix := companyID.String()[:8]
	timestamp := time.Now().UnixMilli()
	paymentNumber := fmt.Sprintf("PAY-%s-%d", prefix, timestamp)
	exists, err := s.paymentRepo.ExistsByNumber(context.Background(), tx, companyID, paymentNumber)
	if err != nil {
		return "", err
	}
	if exists {
		return fmt.Sprintf("PAY-%s-%d-1", prefix, timestamp), nil
	}
	return paymentNumber, nil
}

func (s *paymentService) emitPaymentEvent(ctx context.Context, tx repository.DBTX, payment *models.Payment, eventType string, extra map[string]interface{}) error {
	sqlTx, ok := tx.(*sql.Tx)
	if !ok {
		return fmt.Errorf("tx is not a *sql.Tx")
	}
	payload := salesEvents.PaymentPayload{
		PaymentID:     payment.PaymentID.String(),
		CompanyID:     payment.CompanyID.String(),
		PaymentNumber: payment.PaymentNumber,
		Amount:        payment.Amount.String(),
		PaymentMethod: payment.PaymentMethod.String(),
		Status:        payment.Status.String(),
		PaymentDate:   payment.PaymentDate.Format(time.RFC3339),
	}
	if extra != nil {
		if allocs, ok := extra["allocations"].([]salesEvents.PaymentAllocation); ok {
			payload.Allocations = allocs
		}
	}
	data, err := json.Marshal(payload)
	if err != nil {
		return err
	}
	event := &outbox.Event{
		EventID:       uuid.New().String(),
		AggregateType: "payment",
		AggregateID:   payment.PaymentID.String(),
		EventType:     eventType,
		Topic:         salesEvents.TopicSalesEvents,
		Payload:       data,
	}
	return s.outboxRepo.Store(ctx, sqlTx, event)
}

func (s *paymentService) validateStatusTransition(current, next enums.PaymentStatus) error {
	transitions := map[enums.PaymentStatus][]enums.PaymentStatus{
		enums.PaymentStatusPending:           {enums.PaymentStatusProcessing, enums.PaymentStatusCompleted, enums.PaymentStatusFailed},
		enums.PaymentStatusProcessing:        {enums.PaymentStatusCompleted, enums.PaymentStatusFailed},
		enums.PaymentStatusCompleted:         {enums.PaymentStatusRefunded, enums.PaymentStatusPartiallyRefunded},
		enums.PaymentStatusFailed:            {},
		enums.PaymentStatusRefunded:          {},
		enums.PaymentStatusPartiallyRefunded: {enums.PaymentStatusRefunded},
	}
	allowed, ok := transitions[current]
	if !ok {
		return fmt.Errorf("%w: unknown status %s", salesErrors.ErrInvalidStatus, current)
	}
	for _, s := range allowed {
		if s == next {
			return nil
		}
	}
	return fmt.Errorf("%w: cannot transition from %s to %s", salesErrors.ErrInvalidTransition, current, next)
}

func (s *paymentService) applyAllocations(ctx context.Context, tx repository.DBTX, companyID, paymentID uuid.UUID, allocations []PaymentAllocationRequest, updatedBy *uuid.UUID) error {
	if len(allocations) == 0 {
		return nil
	}
	payment, err := s.paymentRepo.GetByIDForUpdate(ctx, tx, companyID, paymentID)
	if err != nil {
		return err
	}
	if payment.Status != enums.PaymentStatusCompleted {
		return fmt.Errorf("%w: allocations can only be applied to completed payments", salesErrors.ErrInvalidStatus)
	}
	allocatedSoFar, err := s.paymentRepo.GetTotalAllocated(ctx, tx, companyID, paymentID)
	if err != nil {
		return err
	}
	totalToAllocate := decimal.Zero
	for _, a := range allocations {
		totalToAllocate = totalToAllocate.Add(a.Amount)
	}
	if allocatedSoFar.Add(totalToAllocate).GreaterThan(payment.Amount) {
		return fmt.Errorf("%w: allocation exceeds payment amount", salesErrors.ErrPaymentOverAlloc)
	}
	allocModels := make([]*models.PaymentAllocation, 0, len(allocations))
	for _, a := range allocations {
		invoice, err := s.invoiceRepo.GetByID(ctx, tx, companyID, a.InvoiceID)
		if err != nil {
			return fmt.Errorf("invoice %s: %w", a.InvoiceID, err)
		}
		if invoice.Status == enums.InvoiceStatusPaid || invoice.Status == enums.InvoiceStatusCancelled {
			return fmt.Errorf("%w: invoice %s is already %s", salesErrors.ErrInvalidStatus, invoice.InvoiceNumber, invoice.Status)
		}
		allocModels = append(allocModels, &models.PaymentAllocation{
			AllocationID: uuid.New(),
			PaymentID:    paymentID,
			InvoiceID:    a.InvoiceID,
			Amount:       a.Amount,
		})
	}
	if err := s.paymentRepo.AddAllocations(ctx, tx, companyID, paymentID, allocModels); err != nil {
		return err
	}
	for _, a := range allocations {
		if err := s.invoiceRepo.UpdateAmounts(ctx, tx, companyID, a.InvoiceID, a.Amount, decimal.Zero, updatedBy); err != nil {
			return err
		}
		due, err := s.invoiceRepo.GetAmountDue(ctx, tx, companyID, a.InvoiceID)
		if err != nil {
			return err
		}
		if due.LessThanOrEqual(decimal.Zero) {
			if err := s.invoiceRepo.MarkPaid(ctx, tx, companyID, a.InvoiceID, time.Now(), updatedBy); err != nil {
				return err
			}
		}
	}
	return nil
}

// --------------------------------------------------------------------------
// Core CRUD
// --------------------------------------------------------------------------

func (s *paymentService) CreatePayment(ctx context.Context, req *CreatePaymentRequest) (*models.Payment, error) {
	logger := s.logger.With(zap.String("method", "CreatePayment"))
	if err := s.validateCreatePayment(req); err != nil {
		return nil, err
	}
	tx, err := s.pgClient.BeginTx(ctx, nil)
	if err != nil {
		return nil, fmt.Errorf("begin tx: %w", err)
	}
	defer tx.Rollback()

	idempKey := req.PaymentNumber
	if idempKey == "" {
		idempKey = uuid.New().String()
	}
	var cached *models.Payment
	if err := s.idempotencyStore.Get(ctx, tx, idempKey, &cached); err == nil && cached != nil {
		logger.Info("idempotent – returning cached payment")
		return cached, nil
	}

	paymentNumber := req.PaymentNumber
	if paymentNumber == "" {
		paymentNumber, err = s.generatePaymentNumber(tx, req.CompanyID)
		if err != nil {
			return nil, fmt.Errorf("generate payment number: %w", err)
		}
	}
	exists, err := s.paymentRepo.ExistsByNumber(ctx, tx, req.CompanyID, paymentNumber)
	if err != nil {
		return nil, err
	}
	if exists {
		return nil, fmt.Errorf("%w: payment number %s already exists", salesErrors.ErrDuplicate, paymentNumber)
	}
	if req.ExternalRef != nil && *req.ExternalRef != "" {
		exists, err = s.paymentRepo.ExistsByExternalRef(ctx, tx, req.CompanyID, *req.ExternalRef)
		if err != nil {
			return nil, err
		}
		if exists {
			return nil, fmt.Errorf("%w: external reference %s already used", salesErrors.ErrDuplicate, *req.ExternalRef)
		}
	}

	payment := &models.Payment{
		PaymentID:       uuid.New(),
		CompanyID:       req.CompanyID,
		PaymentNumber:   paymentNumber,
		ExternalRef:     req.ExternalRef,
		PaymentDate:     req.PaymentDate,
		Amount:          req.Amount,
		PaymentMethod:   req.PaymentMethod,
		Status:          enums.PaymentStatusPending,
		Reference:       req.Reference,
		GatewayResponse: req.GatewayResponse,
		CreatedBy:       req.CreatedBy,
		UpdatedBy:       req.CreatedBy,
	}
	if payment.PaymentDate.IsZero() {
		payment.PaymentDate = time.Now()
	}
	if err := s.paymentRepo.Create(ctx, tx, payment, nil); err != nil {
		return nil, fmt.Errorf("create payment: %w", err)
	}
	if err := s.emitPaymentEvent(ctx, tx, payment, salesEvents.EventPaymentCreated, nil); err != nil {
		logger.Warn("failed to emit payment created event", zap.Error(err))
	}
	_ = s.idempotencyStore.Store(ctx, tx, idempKey, payment)
	if err := tx.Commit(); err != nil {
		return nil, fmt.Errorf("commit tx: %w", err)
	}
	if s.auditService != nil {
		_ = s.auditService.LogAction(ctx, nil, &req.CompanyID, "sales", "create_payment", "payment",
			&payment.PaymentID, "user", req.CreatedBy, nil, nil, map[string]interface{}{
				"payment_number": payment.PaymentNumber,
				"amount":         payment.Amount.String(),
			})
	}
	return payment, nil
}

func (s *paymentService) validateCreatePayment(req *CreatePaymentRequest) error {
	if req.CompanyID == uuid.Nil {
		return fmt.Errorf("%w: company_id required", salesErrors.ErrInvalidInput)
	}
	if req.Amount.LessThanOrEqual(decimal.Zero) {
		return fmt.Errorf("%w: amount must be positive", salesErrors.ErrInvalidAmount)
	}
	if !req.PaymentMethod.IsValid() {
		return fmt.Errorf("%w: invalid payment method", salesErrors.ErrInvalidInput)
	}
	return nil
}

func (s *paymentService) UpdatePayment(ctx context.Context, companyID uuid.UUID, paymentID uuid.UUID, req *UpdatePaymentRequest) (*models.Payment, error) {
	logger := s.logger.With(zap.String("method", "UpdatePayment"))
	tx, err := s.pgClient.BeginTx(ctx, nil)
	if err != nil {
		return nil, fmt.Errorf("begin tx: %w", err)
	}
	defer tx.Rollback()

	idempKey := paymentID.String()
	var cached *models.Payment
	if err := s.idempotencyStore.Get(ctx, tx, idempKey, &cached); err == nil && cached != nil {
		logger.Info("idempotent – returning cached payment")
		return cached, nil
	}

	payment, err := s.paymentRepo.GetByIDForUpdate(ctx, tx, companyID, paymentID)
	if err != nil {
		return nil, err
	}
	if payment.Status != enums.PaymentStatusPending && payment.Status != enums.PaymentStatusProcessing {
		return nil, fmt.Errorf("%w: only pending/processing payments can be updated", salesErrors.ErrInvalidStatus)
	}
	changes := make(map[string]interface{})
	if req.ExternalRef != nil && *req.ExternalRef != "" {
		exists, err := s.paymentRepo.ExistsByExternalRef(ctx, tx, companyID, *req.ExternalRef)
		if err != nil {
			return nil, err
		}
		if exists && (payment.ExternalRef == nil || *payment.ExternalRef != *req.ExternalRef) {
			return nil, fmt.Errorf("%w: external reference already used", salesErrors.ErrDuplicate)
		}
		payment.ExternalRef = req.ExternalRef
		changes["external_ref"] = req.ExternalRef
	}
	if req.PaymentDate != nil {
		payment.PaymentDate = *req.PaymentDate
		changes["payment_date"] = req.PaymentDate
	}
	if req.Amount != nil {
		payment.Amount = *req.Amount
		changes["amount"] = req.Amount
	}
	if req.PaymentMethod != nil {
		payment.PaymentMethod = *req.PaymentMethod
		changes["payment_method"] = req.PaymentMethod
	}
	if req.Reference != nil {
		payment.Reference = req.Reference
		changes["reference"] = req.Reference
	}
	if req.GatewayResponse != nil {
		payment.GatewayResponse = req.GatewayResponse
		changes["gateway_response"] = req.GatewayResponse
	}
	payment.UpdatedBy = req.UpdatedBy
	if err := s.paymentRepo.Update(ctx, tx, payment); err != nil {
		return nil, fmt.Errorf("update payment: %w", err)
	}
	if err := s.emitPaymentEvent(ctx, tx, payment, salesEvents.EventPaymentUpdated, nil); err != nil {
		logger.Warn("failed to emit payment updated event", zap.Error(err))
	}
	_ = s.idempotencyStore.Store(ctx, tx, idempKey, payment)
	if err := tx.Commit(); err != nil {
		return nil, fmt.Errorf("commit tx: %w", err)
	}
	if s.auditService != nil {
		_ = s.auditService.LogAction(ctx, nil, &companyID, "sales", "update_payment", "payment",
			&paymentID, "user", req.UpdatedBy, nil, nil, changes)
	}
	return payment, nil
}

func (s *paymentService) DeletePayment(ctx context.Context, companyID uuid.UUID, paymentID uuid.UUID, deletedBy uuid.UUID) error {
	logger := s.logger.With(zap.String("method", "DeletePayment"))
	tx, err := s.pgClient.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("begin tx: %w", err)
	}
	defer tx.Rollback()

	idempKey := paymentID.String()
	var processed bool
	if err := s.idempotencyStore.Get(ctx, tx, idempKey, &processed); err == nil && processed {
		logger.Info("idempotent – already deleted")
		return nil
	}
	payment, err := s.paymentRepo.GetByID(ctx, tx, companyID, paymentID)
	if err != nil {
		return err
	}
	if payment.Status != enums.PaymentStatusPending && payment.Status != enums.PaymentStatusFailed {
		return fmt.Errorf("%w: only pending or failed payments can be deleted", salesErrors.ErrInvalidStatus)
	}
	hasAllocs, err := s.paymentRepo.HasAllocations(ctx, tx, companyID, paymentID)
	if err != nil {
		return err
	}
	if hasAllocs {
		return fmt.Errorf("%w: cannot delete payment with allocations", salesErrors.ErrConflict)
	}
	if err := s.paymentRepo.Delete(ctx, tx, companyID, paymentID); err != nil {
		return fmt.Errorf("delete payment: %w", err)
	}
	_ = s.idempotencyStore.Store(ctx, tx, idempKey, true)
	if err := tx.Commit(); err != nil {
		return fmt.Errorf("commit tx: %w", err)
	}
	if s.auditService != nil {
		_ = s.auditService.LogAction(ctx, nil, &companyID, "sales", "delete_payment", "payment",
			&paymentID, "user", &deletedBy, nil, nil, nil)
	}
	return nil
}

func (s *paymentService) GetPaymentByID(ctx context.Context, companyID uuid.UUID, paymentID uuid.UUID) (*models.Payment, error) {
	return s.paymentRepo.GetByID(ctx, nil, companyID, paymentID)
}

func (s *paymentService) GetPaymentByNumber(ctx context.Context, companyID uuid.UUID, paymentNumber string) (*models.Payment, error) {
	return s.paymentRepo.GetByNumber(ctx, nil, companyID, paymentNumber)
}

func (s *paymentService) GetPaymentByGatewayReference(ctx context.Context, companyID uuid.UUID, gatewayReference string) (*models.Payment, error) {
	return s.paymentRepo.GetByReference(ctx, nil, companyID, gatewayReference)
}

// --------------------------------------------------------------------------
// ListPayments – fixed to use correct repository.PaymentFilter fields
// --------------------------------------------------------------------------

func (s *paymentService) ListPayments(ctx context.Context, filter PaymentListFilter, p Pagination, srt Sort) ([]*models.Payment, int64, error) {
	repoFilter := repository.PaymentFilter{
		CompanyID: filter.CompanyID,
	}
	if filter.Status != nil {
		repoFilter.Statuses = []enums.PaymentStatus{*filter.Status}
	}
	if filter.PaymentMethod != nil {
		repoFilter.Methods = []enums.PaymentMethod{*filter.PaymentMethod}
	}
	if filter.FromDate != nil {
		repoFilter.PaymentDateFrom = filter.FromDate
	}
	if filter.ToDate != nil {
		repoFilter.PaymentDateTo = filter.ToDate
	}
	if filter.MinAmount != nil {
		repoFilter.MinAmount = filter.MinAmount
	}
	if filter.MaxAmount != nil {
		repoFilter.MaxAmount = filter.MaxAmount
	}
	// Note: CustomerID and InvoiceID are not supported in PaymentFilter directly.
	// They are handled by separate methods (GetPaymentsByCustomer, GetPaymentsByInvoice).

	return s.paymentRepo.List(ctx, nil, repoFilter,
		repository.Pagination{Limit: p.Limit, Offset: p.Offset},
		repository.Sort{Field: srt.Field, Direction: srt.Direction})
}

func (s *paymentService) SearchPayments(ctx context.Context, companyID uuid.UUID, query string, limit, offset int) ([]*models.Payment, int64, error) {
	return s.paymentRepo.Search(ctx, nil, companyID, query, limit, offset)
}

// --------------------------------------------------------------------------
// GetPaymentsByCustomer – implemented via invoices (repository does not support customerID directly)
// --------------------------------------------------------------------------

func (s *paymentService) GetPaymentsByCustomer(ctx context.Context, companyID, customerID uuid.UUID, p Pagination, srt Sort) ([]*models.Payment, int64, error) {
	// 1. Get all invoices for the customer
	invoices, _, err := s.invoiceRepo.GetByCustomer(ctx, nil, companyID, customerID,
		repository.Pagination{Limit: 1000, Offset: 0},
		repository.Sort{Field: "invoice_date", Direction: "DESC"})
	if err != nil {
		return nil, 0, err
	}
	if len(invoices) == 0 {
		return []*models.Payment{}, 0, nil
	}

	// 2. For each invoice, get its payments (deduplicate)
	paymentMap := make(map[uuid.UUID]*models.Payment)
	for _, inv := range invoices {
		payments, err := s.paymentRepo.GetByInvoice(ctx, nil, companyID, inv.InvoiceID)
		if err != nil {
			return nil, 0, err
		}
		for _, pay := range payments {
			if _, exists := paymentMap[pay.PaymentID]; !exists {
				paymentMap[pay.PaymentID] = pay
			}
		}
	}

	// 3. Convert map to slice
	result := make([]*models.Payment, 0, len(paymentMap))
	for _, pay := range paymentMap {
		result = append(result, pay)
	}

	// 4. Apply pagination and sorting (simple in-memory – for production consider a dedicated repository method)
	total := int64(len(result))
	offset := p.Offset
	limit := p.Limit
	if offset > len(result) {
		offset = len(result)
	}
	end := offset + limit
	if end > len(result) {
		end = len(result)
	}
	paginated := result[offset:end]

	return paginated, total, nil
}

// --------------------------------------------------------------------------
// GetPaymentsByInvoice – use repository method directly
// --------------------------------------------------------------------------

func (s *paymentService) GetPaymentsByInvoice(ctx context.Context, companyID, invoiceID uuid.UUID) ([]*models.Payment, error) {
	return s.paymentRepo.GetByInvoice(ctx, nil, companyID, invoiceID)
}

// --------------------------------------------------------------------------
// Registration methods (unchanged – they work as before)
// --------------------------------------------------------------------------

func (s *paymentService) RegisterCashPayment(ctx context.Context, req *RegisterCashPaymentRequest) (*models.Payment, error) {
	createReq := &CreatePaymentRequest{
		CompanyID:     req.CompanyID,
		PaymentDate:   req.PaymentDate,
		Amount:        req.Amount,
		PaymentMethod: enums.PaymentMethodCash,
		Reference:     req.Reference,
		CreatedBy:     &req.CreatedBy,
	}
	payment, err := s.CreatePayment(ctx, createReq)
	if err != nil {
		return nil, err
	}
	if len(req.Allocations) > 0 {
		tx, err := s.pgClient.BeginTx(ctx, nil)
		if err != nil {
			return nil, err
		}
		defer tx.Rollback()
		if err := s.applyAllocations(ctx, tx, req.CompanyID, payment.PaymentID, req.Allocations, &req.CreatedBy); err != nil {
			return nil, err
		}
		if err := s.MarkCompleted(ctx, req.CompanyID, payment.PaymentID, time.Now(), req.CreatedBy); err != nil {
			return nil, err
		}
		if err := tx.Commit(); err != nil {
			return nil, err
		}
		payment, _ = s.paymentRepo.GetByID(ctx, nil, req.CompanyID, payment.PaymentID)
	}
	return payment, nil
}

func (s *paymentService) RegisterCardPayment(ctx context.Context, req *RegisterCardPaymentRequest) (*models.Payment, error) {
	createReq := &CreatePaymentRequest{
		CompanyID:     req.CompanyID,
		PaymentDate:   req.PaymentDate,
		Amount:        req.Amount,
		PaymentMethod: enums.PaymentMethodCard,
		Reference:     &req.GatewayTxID,
		GatewayResponse: models.JSONB{
			"card_last4":    req.CardLast4,
			"card_brand":    req.CardBrand,
			"gateway_tx_id": req.GatewayTxID,
		},
		CreatedBy: &req.CreatedBy,
	}
	payment, err := s.CreatePayment(ctx, createReq)
	if err != nil {
		return nil, err
	}
	if err := s.MarkCompleted(ctx, req.CompanyID, payment.PaymentID, time.Now(), req.CreatedBy); err != nil {
		return nil, err
	}
	if len(req.Allocations) > 0 {
		if err := s.AllocatePaymentToInvoices(ctx, req.CompanyID, payment.PaymentID, req.Allocations, req.CreatedBy); err != nil {
			return nil, err
		}
	}
	return s.paymentRepo.GetByID(ctx, nil, req.CompanyID, payment.PaymentID)
}

func (s *paymentService) RegisterBankTransferPayment(ctx context.Context, req *RegisterBankTransferPaymentRequest) (*models.Payment, error) {
	createReq := &CreatePaymentRequest{
		CompanyID:     req.CompanyID,
		PaymentDate:   req.PaymentDate,
		Amount:        req.Amount,
		PaymentMethod: enums.PaymentMethodBankTransfer,
		Reference:     &req.ReferenceNumber,
		GatewayResponse: models.JSONB{
			"bank_name": req.BankName,
		},
		CreatedBy: &req.CreatedBy,
	}
	payment, err := s.CreatePayment(ctx, createReq)
	if err != nil {
		return nil, err
	}
	if err := s.MarkCompleted(ctx, req.CompanyID, payment.PaymentID, time.Now(), req.CreatedBy); err != nil {
		return nil, err
	}
	if len(req.Allocations) > 0 {
		if err := s.AllocatePaymentToInvoices(ctx, req.CompanyID, payment.PaymentID, req.Allocations, req.CreatedBy); err != nil {
			return nil, err
		}
	}
	return payment, nil
}

func (s *paymentService) RegisterChequePayment(ctx context.Context, req *RegisterChequePaymentRequest) (*models.Payment, error) {
	createReq := &CreatePaymentRequest{
		CompanyID:     req.CompanyID,
		PaymentDate:   req.PaymentDate,
		Amount:        req.Amount,
		PaymentMethod: enums.PaymentMethodOther,
		Reference:     &req.ChequeNumber,
		GatewayResponse: models.JSONB{
			"cheque_number": req.ChequeNumber,
			"bank_name":     req.BankName,
		},
		CreatedBy: &req.CreatedBy,
	}
	payment, err := s.CreatePayment(ctx, createReq)
	if err != nil {
		return nil, err
	}
	if err := s.MarkCompleted(ctx, req.CompanyID, payment.PaymentID, time.Now(), req.CreatedBy); err != nil {
		return nil, err
	}
	if len(req.Allocations) > 0 {
		if err := s.AllocatePaymentToInvoices(ctx, req.CompanyID, payment.PaymentID, req.Allocations, req.CreatedBy); err != nil {
			return nil, err
		}
	}
	return payment, nil
}

func (s *paymentService) RegisterWalletPayment(ctx context.Context, req *RegisterWalletPaymentRequest) (*models.Payment, error) {
	createReq := &CreatePaymentRequest{
		CompanyID:     req.CompanyID,
		PaymentDate:   req.PaymentDate,
		Amount:        req.Amount,
		PaymentMethod: enums.PaymentMethodDigitalWallet,
		Reference:     &req.WalletTxID,
		GatewayResponse: models.JSONB{
			"wallet_provider": req.WalletProvider,
			"wallet_tx_id":    req.WalletTxID,
		},
		CreatedBy: &req.CreatedBy,
	}
	payment, err := s.CreatePayment(ctx, createReq)
	if err != nil {
		return nil, err
	}
	if err := s.MarkCompleted(ctx, req.CompanyID, payment.PaymentID, time.Now(), req.CreatedBy); err != nil {
		return nil, err
	}
	if len(req.Allocations) > 0 {
		if err := s.AllocatePaymentToInvoices(ctx, req.CompanyID, payment.PaymentID, req.Allocations, req.CreatedBy); err != nil {
			return nil, err
		}
	}
	return payment, nil
}

// --------------------------------------------------------------------------
// Gateway integration (unchanged)
// --------------------------------------------------------------------------

func (s *paymentService) ProcessGatewayPayment(ctx context.Context, req *ProcessGatewayPaymentRequest) (*models.Payment, error) {
	tx, err := s.pgClient.BeginTx(ctx, nil)
	if err != nil {
		return nil, err
	}
	defer tx.Rollback()
	var existing *models.Payment
	if err := s.idempotencyStore.Get(ctx, tx, req.IdempotencyKey, &existing); err == nil && existing != nil {
		return existing, nil
	}
	createReq := &CreatePaymentRequest{
		CompanyID:     req.CompanyID,
		PaymentDate:   time.Now(),
		Amount:        req.Amount,
		PaymentMethod: req.PaymentMethod,
		GatewayResponse: models.JSONB{
			"gateway": req.GatewayName,
			"token":   req.GatewayToken,
		},
		CreatedBy: &req.CreatedBy,
	}
	payment, err := s.CreatePayment(ctx, createReq)
	if err != nil {
		return nil, err
	}
	if err := s.MarkProcessing(ctx, req.CompanyID, payment.PaymentID, req.CreatedBy); err != nil {
		return nil, err
	}
	// Simulate gateway call – assume success
	if err := s.MarkCompleted(ctx, req.CompanyID, payment.PaymentID, time.Now(), req.CreatedBy); err != nil {
		return nil, err
	}
	if len(req.Allocations) > 0 {
		if err := s.AllocatePaymentToInvoices(ctx, req.CompanyID, payment.PaymentID, req.Allocations, req.CreatedBy); err != nil {
			return nil, err
		}
	}
	_ = s.idempotencyStore.Store(ctx, tx, req.IdempotencyKey, payment)
	if err := tx.Commit(); err != nil {
		return nil, err
	}
	return payment, nil
}

func (s *paymentService) ProcessGatewayWebhook(ctx context.Context, req *ProcessGatewayWebhookRequest) error {
	payment, err := s.paymentRepo.GetByReference(ctx, nil, req.CompanyID, req.GatewayTxID)
	if err != nil {
		return err
	}
	if err := s.ValidateGatewaySignature(ctx, req.GatewayName, req.RawPayload, req.Signature); err != nil {
		return err
	}
	switch req.Status {
	case "completed":
		return s.MarkCompleted(ctx, req.CompanyID, payment.PaymentID, time.Now(), uuid.Nil)
	case "failed":
		return s.MarkFailed(ctx, req.CompanyID, payment.PaymentID, "gateway failure", uuid.Nil)
	default:
		return nil
	}
}

func (s *paymentService) ValidateGatewaySignature(ctx context.Context, gateway string, payload []byte, signature string) error {
	// Implement actual signature verification per gateway
	return nil
}

// --------------------------------------------------------------------------
// Idempotency helpers (unchanged)
// --------------------------------------------------------------------------

func (s *paymentService) EnsureIdempotentPayment(ctx context.Context, companyID uuid.UUID, idempotencyKey string) (*models.Payment, bool, error) {
	var payment models.Payment
	err := s.idempotencyStore.Get(ctx, nil, idempotencyKey, &payment)
	if err != nil {
		return nil, false, nil
	}
	if payment.PaymentID != uuid.Nil {
		return &payment, true, nil
	}
	return nil, false, nil
}

func (s *paymentService) GetPaymentByIdempotencyKey(ctx context.Context, companyID uuid.UUID, idempotencyKey string) (*models.Payment, error) {
	var payment models.Payment
	err := s.idempotencyStore.Get(ctx, nil, idempotencyKey, &payment)
	if err != nil {
		return nil, err
	}
	if payment.PaymentID == uuid.Nil {
		return nil, salesErrors.ErrNotFound
	}
	return &payment, nil
}

// --------------------------------------------------------------------------
// Payment allocation (unchanged)
// --------------------------------------------------------------------------

func (s *paymentService) AllocatePayment(ctx context.Context, companyID, paymentID, invoiceID uuid.UUID, amount decimal.Decimal, allocatedBy uuid.UUID) error {
	return s.AllocatePaymentToInvoices(ctx, companyID, paymentID, []PaymentAllocationRequest{{InvoiceID: invoiceID, Amount: amount}}, allocatedBy)
}

func (s *paymentService) AllocatePaymentToInvoices(ctx context.Context, companyID, paymentID uuid.UUID, allocations []PaymentAllocationRequest, allocatedBy uuid.UUID) error {
	if len(allocations) == 0 {
		return nil
	}
	tx, err := s.pgClient.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	if err := s.applyAllocations(ctx, tx, companyID, paymentID, allocations, &allocatedBy); err != nil {
		return err
	}
	payment, err := s.paymentRepo.GetByID(ctx, tx, companyID, paymentID)
	if err != nil {
		return err
	}
	allocEvents := make([]salesEvents.PaymentAllocation, 0, len(allocations))
	for _, a := range allocations {
		allocEvents = append(allocEvents, salesEvents.PaymentAllocation{
			InvoiceID: a.InvoiceID.String(),
			Amount:    a.Amount.String(),
		})
	}
	if err := s.emitPaymentEvent(ctx, tx, payment, salesEvents.EventPaymentUpdated, map[string]interface{}{
		"allocations": allocEvents,
	}); err != nil {
		s.logger.Warn("failed to emit payment allocation event", zap.Error(err))
	}
	return tx.Commit()
}

func (s *paymentService) AutoAllocatePayment(ctx context.Context, companyID, paymentID uuid.UUID, allocatedBy uuid.UUID) error {
	// Not implemented – would require customer link on payment
	return fmt.Errorf("auto-allocation not implemented without customer link on payment")
}

func (s *paymentService) RemoveAllocation(ctx context.Context, companyID, paymentID, allocationID uuid.UUID, removedBy uuid.UUID) error {
	tx, err := s.pgClient.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	alloc, err := s.paymentRepo.GetAllocationByIDForUpdate(ctx, tx, companyID, paymentID, allocationID)
	if err != nil {
		return err
	}
	if err := s.invoiceRepo.UpdateAmounts(ctx, tx, companyID, alloc.InvoiceID, decimal.Zero, alloc.Amount.Neg(), &removedBy); err != nil {
		return err
	}
	if err := s.paymentRepo.DeleteAllocation(ctx, tx, companyID, paymentID, allocationID); err != nil {
		return err
	}
	invoice, err := s.invoiceRepo.GetByID(ctx, tx, companyID, alloc.InvoiceID)
	if err != nil {
		return err
	}
	if invoice.Status == enums.InvoiceStatusPaid {
		due, err := s.invoiceRepo.GetAmountDue(ctx, tx, companyID, alloc.InvoiceID)
		if err != nil {
			return err
		}
		if due.GreaterThan(decimal.Zero) {
			if err := s.invoiceRepo.UpdateStatus(ctx, tx, companyID, alloc.InvoiceID, enums.InvoiceStatusIssued, &removedBy); err != nil {
				return err
			}
		}
	}
	return tx.Commit()
}

func (s *paymentService) GetPaymentAllocations(ctx context.Context, companyID, paymentID uuid.UUID) ([]*models.PaymentAllocation, error) {
	return s.paymentRepo.GetAllocations(ctx, nil, companyID, paymentID)
}

func (s *paymentService) GetUnallocatedAmount(ctx context.Context, companyID, paymentID uuid.UUID) (decimal.Decimal, error) {
	payment, err := s.paymentRepo.GetByID(ctx, nil, companyID, paymentID)
	if err != nil {
		return decimal.Zero, err
	}
	allocated, err := s.paymentRepo.GetTotalAllocated(ctx, nil, companyID, paymentID)
	if err != nil {
		return decimal.Zero, err
	}
	return payment.Amount.Sub(allocated), nil
}

func (s *paymentService) IsFullyAllocated(ctx context.Context, companyID, paymentID uuid.UUID) (bool, error) {
	unallocated, err := s.GetUnallocatedAmount(ctx, companyID, paymentID)
	if err != nil {
		return false, err
	}
	return unallocated.LessThanOrEqual(decimal.Zero), nil
}

// --------------------------------------------------------------------------
// Refunds (unchanged, using refundRepo)
// --------------------------------------------------------------------------

func (s *paymentService) CreateRefund(ctx context.Context, req *CreateRefundRequest) (*models.PaymentRefund, error) {
	if err := s.validateRefund(ctx, req.CompanyID, req.PaymentID, req.Amount); err != nil {
		return nil, err
	}
	tx, err := s.pgClient.BeginTx(ctx, nil)
	if err != nil {
		return nil, err
	}
	defer tx.Rollback()
	payment, err := s.paymentRepo.GetByIDForUpdate(ctx, tx, req.CompanyID, req.PaymentID)
	if err != nil {
		return nil, err
	}
	newRefunded := payment.RefundedAmount.Add(req.Amount)
	if newRefunded.GreaterThan(payment.Amount) {
		return nil, salesErrors.ErrOverRefund
	}
	refund := &models.PaymentRefund{
		RefundID:   uuid.New(),
		CompanyID:  req.CompanyID,
		PaymentID:  req.PaymentID,
		Amount:     req.Amount,
		Reason:     req.Reason,
		RefundedBy: &req.RefundedBy,
		Status:     "completed", // or pending if gateway refund async
	}
	if err := s.refundRepo.Create(ctx, tx, refund); err != nil {
		return nil, err
	}
	if err := s.paymentRepo.UpdateRefundedAmount(ctx, tx, req.CompanyID, req.PaymentID, newRefunded, &req.RefundedBy); err != nil {
		return nil, err
	}
	if newRefunded.Equal(payment.Amount) {
		if err := s.paymentRepo.UpdateStatus(ctx, tx, req.CompanyID, req.PaymentID, enums.PaymentStatusRefunded, &req.RefundedBy); err != nil {
			return nil, err
		}
	} else if newRefunded.GreaterThan(decimal.Zero) {
		if err := s.paymentRepo.UpdateStatus(ctx, tx, req.CompanyID, req.PaymentID, enums.PaymentStatusPartiallyRefunded, &req.RefundedBy); err != nil {
			return nil, err
		}
	}
	if err := s.emitPaymentEvent(ctx, tx, payment, salesEvents.EventPaymentRefunded, map[string]interface{}{
		"refund_amount": req.Amount.String(),
	}); err != nil {
		s.logger.Warn("failed to emit refund event", zap.Error(err))
	}
	if err := tx.Commit(); err != nil {
		return nil, err
	}
	return refund, nil
}

func (s *paymentService) RefundFullPayment(ctx context.Context, companyID, paymentID uuid.UUID, reason string, refundedBy uuid.UUID) (*models.PaymentRefund, error) {
	payment, err := s.paymentRepo.GetByID(ctx, nil, companyID, paymentID)
	if err != nil {
		return nil, err
	}
	return s.CreateRefund(ctx, &CreateRefundRequest{
		CompanyID:  companyID,
		PaymentID:  paymentID,
		Amount:     payment.Amount,
		Reason:     reason,
		RefundedBy: refundedBy,
	})
}

func (s *paymentService) RefundPartialPayment(ctx context.Context, companyID, paymentID uuid.UUID, amount decimal.Decimal, reason string, refundedBy uuid.UUID) (*models.PaymentRefund, error) {
	return s.CreateRefund(ctx, &CreateRefundRequest{
		CompanyID:  companyID,
		PaymentID:  paymentID,
		Amount:     amount,
		Reason:     reason,
		RefundedBy: refundedBy,
	})
}

func (s *paymentService) ProcessGatewayRefund(ctx context.Context, req *ProcessGatewayRefundRequest) (*models.PaymentRefund, error) {
	// Call external gateway and then create refund
	return s.CreateRefund(ctx, &CreateRefundRequest{
		CompanyID:  req.CompanyID,
		PaymentID:  req.PaymentID,
		Amount:     req.Amount,
		Reason:     req.Reason,
		RefundedBy: req.RefundedBy,
	})
}

func (s *paymentService) GetRefundByID(ctx context.Context, companyID, refundID uuid.UUID) (*models.PaymentRefund, error) {
	return s.refundRepo.GetByID(ctx, nil, companyID, refundID)
}

func (s *paymentService) GetPaymentRefunds(ctx context.Context, companyID, paymentID uuid.UUID) ([]*models.PaymentRefund, error) {
	return s.refundRepo.GetByPayment(ctx, nil, companyID, paymentID)
}

func (s *paymentService) GetRefundedAmount(ctx context.Context, companyID, paymentID uuid.UUID) (decimal.Decimal, error) {
	payment, err := s.paymentRepo.GetByID(ctx, nil, companyID, paymentID)
	if err != nil {
		return decimal.Zero, err
	}
	return payment.RefundedAmount, nil
}

func (s *paymentService) IsFullyRefunded(ctx context.Context, companyID, paymentID uuid.UUID) (bool, error) {
	payment, err := s.paymentRepo.GetByID(ctx, nil, companyID, paymentID)
	if err != nil {
		return false, err
	}
	return payment.RefundedAmount.Equal(payment.Amount), nil
}

// --------------------------------------------------------------------------
// Status management (unchanged)
// --------------------------------------------------------------------------

func (s *paymentService) UpdateStatus(ctx context.Context, companyID, paymentID uuid.UUID, status enums.PaymentStatus, updatedBy uuid.UUID) error {
	tx, err := s.pgClient.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	payment, err := s.paymentRepo.GetByIDForUpdate(ctx, tx, companyID, paymentID)
	if err != nil {
		return err
	}
	if err := s.validateStatusTransition(payment.Status, status); err != nil {
		return err
	}
	if err := s.paymentRepo.UpdateStatus(ctx, tx, companyID, paymentID, status, &updatedBy); err != nil {
		return err
	}
	var eventType string
	switch status {
	case enums.PaymentStatusProcessing:
		eventType = salesEvents.EventPaymentProcessing
	case enums.PaymentStatusCompleted:
		eventType = salesEvents.EventPaymentCompleted
	case enums.PaymentStatusFailed:
		eventType = salesEvents.EventPaymentFailed
	default:
		eventType = salesEvents.EventPaymentUpdated
	}
	if err := s.emitPaymentEvent(ctx, tx, payment, eventType, nil); err != nil {
		s.logger.Warn("failed to emit payment status event", zap.Error(err))
	}
	return tx.Commit()
}

func (s *paymentService) MarkPending(ctx context.Context, companyID, paymentID uuid.UUID, updatedBy uuid.UUID) error {
	return s.UpdateStatus(ctx, companyID, paymentID, enums.PaymentStatusPending, updatedBy)
}

func (s *paymentService) MarkProcessing(ctx context.Context, companyID, paymentID uuid.UUID, updatedBy uuid.UUID) error {
	return s.UpdateStatus(ctx, companyID, paymentID, enums.PaymentStatusProcessing, updatedBy)
}

func (s *paymentService) MarkCompleted(ctx context.Context, companyID, paymentID uuid.UUID, completedAt time.Time, updatedBy uuid.UUID) error {
	tx, err := s.pgClient.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	if err := s.paymentRepo.MarkCompleted(ctx, tx, companyID, paymentID, completedAt, &updatedBy); err != nil {
		return err
	}
	payment, _ := s.paymentRepo.GetByID(ctx, tx, companyID, paymentID)
	if err := s.emitPaymentEvent(ctx, tx, payment, salesEvents.EventPaymentCompleted, nil); err != nil {
		s.logger.Warn("failed to emit completed event", zap.Error(err))
	}
	return tx.Commit()
}

func (s *paymentService) MarkFailed(ctx context.Context, companyID, paymentID uuid.UUID, reason string, updatedBy uuid.UUID) error {
	tx, err := s.pgClient.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	if err := s.paymentRepo.MarkFailed(ctx, tx, companyID, paymentID, reason, &updatedBy); err != nil {
		return err
	}
	payment, _ := s.paymentRepo.GetByID(ctx, tx, companyID, paymentID)
	if err := s.emitPaymentEvent(ctx, tx, payment, salesEvents.EventPaymentFailed, nil); err != nil {
		s.logger.Warn("failed to emit failed event", zap.Error(err))
	}
	return tx.Commit()
}

func (s *paymentService) CancelPayment(ctx context.Context, companyID, paymentID uuid.UUID, reason string, cancelledBy uuid.UUID) error {
	return s.UpdateStatus(ctx, companyID, paymentID, enums.PaymentStatusFailed, cancelledBy)
}

func (s *paymentService) ReconcilePayment(ctx context.Context, companyID, paymentID uuid.UUID, reconciledBy uuid.UUID) error {
	payment, err := s.paymentRepo.GetByID(ctx, nil, companyID, paymentID)
	if err != nil {
		return err
	}
	if payment.Status != enums.PaymentStatusCompleted {
		return s.MarkCompleted(ctx, companyID, paymentID, time.Now(), reconciledBy)
	}
	return nil
}

func (s *paymentService) UnreconcilePayment(ctx context.Context, companyID, paymentID uuid.UUID, unreconciledBy uuid.UUID) error {
	// Not typically needed; return nil as no-op
	return nil
}

// --------------------------------------------------------------------------
// GetUnreconciledPayments – fixed to use Statuses slice
// --------------------------------------------------------------------------

func (s *paymentService) GetUnreconciledPayments(ctx context.Context, companyID uuid.UUID) ([]*models.Payment, error) {
	filter := repository.PaymentFilter{
		CompanyID: companyID,
		Statuses:  []enums.PaymentStatus{enums.PaymentStatusPending, enums.PaymentStatusProcessing},
	}
	payments, _, err := s.paymentRepo.List(ctx, nil, filter,
		repository.Pagination{Limit: 1000, Offset: 0},
		repository.Sort{Field: "payment_date", Direction: "ASC"})
	return payments, err
}

// --------------------------------------------------------------------------
// Validation methods (unchanged)
// --------------------------------------------------------------------------

func (s *paymentService) ValidatePayment(ctx context.Context, payment *models.Payment) error {
	if payment.Amount.LessThanOrEqual(decimal.Zero) {
		return fmt.Errorf("%w: amount must be positive", salesErrors.ErrInvalidAmount)
	}
	if !payment.PaymentMethod.IsValid() {
		return fmt.Errorf("%w: invalid payment method", salesErrors.ErrInvalidInput)
	}
	return nil
}

func (s *paymentService) ValidatePaymentAllocation(ctx context.Context, companyID, paymentID, invoiceID uuid.UUID, amount decimal.Decimal) error {
	payment, err := s.paymentRepo.GetByID(ctx, nil, companyID, paymentID)
	if err != nil {
		return err
	}
	if payment.Status != enums.PaymentStatusCompleted {
		return fmt.Errorf("%w: payment not completed", salesErrors.ErrInvalidStatus)
	}
	allocated, err := s.paymentRepo.GetTotalAllocated(ctx, nil, companyID, paymentID)
	if err != nil {
		return err
	}
	if allocated.Add(amount).GreaterThan(payment.Amount) {
		return salesErrors.ErrPaymentOverAlloc
	}
	invoice, err := s.invoiceRepo.GetByID(ctx, nil, companyID, invoiceID)
	if err != nil {
		return err
	}
	if invoice.Status == enums.InvoiceStatusPaid || invoice.Status == enums.InvoiceStatusCancelled {
		return fmt.Errorf("%w: invoice cannot accept payment", salesErrors.ErrInvalidStatus)
	}
	return nil
}

func (s *paymentService) ValidateRefund(ctx context.Context, companyID, paymentID uuid.UUID, amount decimal.Decimal) error {
	return s.validateRefund(ctx, companyID, paymentID, amount)
}

func (s *paymentService) validateRefund(ctx context.Context, companyID, paymentID uuid.UUID, amount decimal.Decimal) error {
	if amount.LessThanOrEqual(decimal.Zero) {
		return fmt.Errorf("%w: refund amount must be positive", salesErrors.ErrInvalidAmount)
	}
	payment, err := s.paymentRepo.GetByID(ctx, nil, companyID, paymentID)
	if err != nil {
		return err
	}
	if payment.Status != enums.PaymentStatusCompleted && payment.Status != enums.PaymentStatusPartiallyRefunded {
		return fmt.Errorf("%w: only completed or partially refunded payments can be refunded", salesErrors.ErrInvalidStatus)
	}
	refundable := payment.Amount.Sub(payment.RefundedAmount)
	if amount.GreaterThan(refundable) {
		return salesErrors.ErrOverRefund
	}
	return nil
}

func (s *paymentService) ValidatePaymentStatusTransition(ctx context.Context, current, next enums.PaymentStatus) error {
	return s.validateStatusTransition(current, next)
}

// --------------------------------------------------------------------------
// Reporting methods – fixed filter usage
// --------------------------------------------------------------------------

func (s *paymentService) GetTotalPaymentsReceived(ctx context.Context, companyID uuid.UUID, from, to *time.Time) (decimal.Decimal, error) {
	return s.paymentRepo.GetCollectedAmount(ctx, nil, companyID, from, to)
}

func (s *paymentService) GetTotalRefundedAmount(ctx context.Context, companyID uuid.UUID, from, to *time.Time) (decimal.Decimal, error) {
	return s.paymentRepo.GetRefundedAmountTotal(ctx, nil, companyID, from, to)
}

func (s *paymentService) GetNetCollections(ctx context.Context, companyID uuid.UUID, from, to *time.Time) (decimal.Decimal, error) {
	received, err := s.GetTotalPaymentsReceived(ctx, companyID, from, to)
	if err != nil {
		return decimal.Zero, err
	}
	refunded, err := s.GetTotalRefundedAmount(ctx, companyID, from, to)
	if err != nil {
		return decimal.Zero, err
	}
	return received.Sub(refunded), nil
}

func (s *paymentService) GetPaymentsByMethod(ctx context.Context, companyID uuid.UUID, from, to *time.Time) (map[enums.PaymentMethod]decimal.Decimal, error) {
	return s.paymentRepo.GetPaymentMethodBreakdown(ctx, nil, companyID, from, to)
}

func (s *paymentService) GetFailedPayments(ctx context.Context, companyID uuid.UUID, from, to *time.Time) ([]*models.Payment, error) {
	filter := repository.PaymentFilter{
		CompanyID: companyID,
		Statuses:  []enums.PaymentStatus{enums.PaymentStatusFailed},
	}
	if from != nil {
		filter.PaymentDateFrom = from
	}
	if to != nil {
		filter.PaymentDateTo = to
	}
	payments, _, err := s.paymentRepo.List(ctx, nil, filter,
		repository.Pagination{Limit: 1000, Offset: 0},
		repository.Sort{Field: "payment_date", Direction: "DESC"})
	return payments, err
}

// --------------------------------------------------------------------------
// Existence checks (unchanged)
// --------------------------------------------------------------------------

func (s *paymentService) PaymentExists(ctx context.Context, companyID, paymentID uuid.UUID) (bool, error) {
	return s.paymentRepo.Exists(ctx, nil, companyID, paymentID)
}

func (s *paymentService) PaymentNumberExists(ctx context.Context, companyID uuid.UUID, paymentNumber string) (bool, error) {
	return s.paymentRepo.ExistsByNumber(ctx, nil, companyID, paymentNumber)
}

func (s *paymentService) GatewayTransactionExists(ctx context.Context, companyID uuid.UUID, gatewayTransactionID string) (bool, error) {
	return s.paymentRepo.ExistsByExternalRef(ctx, nil, companyID, gatewayTransactionID)
}

func (s *paymentService) HasRefunds(ctx context.Context, companyID, paymentID uuid.UUID) (bool, error) {
	refunded, err := s.GetRefundedAmount(ctx, companyID, paymentID)
	if err != nil {
		return false, err
	}
	return refunded.GreaterThan(decimal.Zero), nil
}

// --------------------------------------------------------------------------
// Helper (used for pointer conversion)
// --------------------------------------------------------------------------

func pointerToStatus(s enums.PaymentStatus) *enums.PaymentStatus {
	return &s
}

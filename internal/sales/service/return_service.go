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

// ---------------------------------------------------------------------
// Request / Response Types
// ---------------------------------------------------------------------

type CreateReturnRequest struct {
	CompanyID  uuid.UUID
	OrderID    *uuid.UUID
	InvoiceID  *uuid.UUID
	ReturnDate time.Time
	Reason     *string
	Items      []*CreateReturnItemRequest
	CreatedBy  uuid.UUID
}

type CreateReturnFromOrderRequest struct {
	ReturnDate time.Time
	Reason     *string
	Items      []*CreateReturnItemRequest
	CreatedBy  uuid.UUID
}

type CreateReturnFromInvoiceRequest struct {
	ReturnDate time.Time
	Reason     *string
	Items      []*CreateReturnItemRequest
	CreatedBy  uuid.UUID
}

type UpdateReturnRequest struct {
	ReturnDate *time.Time
	Reason     *string
	UpdatedBy  uuid.UUID
}

type CreateReturnItemRequest struct {
	OrderItemID *uuid.UUID
	ProductID   uuid.UUID
	Quantity    decimal.Decimal
	Reason      *string
}

type ReturnListFilter struct {
	CompanyID      uuid.UUID
	OrderID        *uuid.UUID
	InvoiceID      *uuid.UUID
	ReturnIDs      []uuid.UUID
	Statuses       []enums.ReturnStatus
	ReturnNumber   string
	MinRefundTotal *decimal.Decimal
	MaxRefundTotal *decimal.Decimal
	ReturnDateFrom *time.Time
	ReturnDateTo   *time.Time
	ApprovedFrom   *time.Time
	ApprovedTo     *time.Time
	CompletedFrom  *time.Time
	CompletedTo    *time.Time
	CreatedFrom    *time.Time
	CreatedTo      *time.Time
	UpdatedFrom    *time.Time
	UpdatedTo      *time.Time
}

type ReturnRefundPreviewRequest struct {
	CompanyID uuid.UUID
	OrderID   *uuid.UUID
	InvoiceID *uuid.UUID
	Items     []*CreateReturnItemRequest
}

type ReturnRefundPreviewResult struct {
	Subtotal           decimal.Decimal
	TaxRefund          decimal.Decimal
	DiscountAdjustment decimal.Decimal
	TotalRefund        decimal.Decimal
}

type GenerateCreditNoteRequest struct {
	IssuedBy uuid.UUID
}

type ProcessReturnRefundRequest struct {
	CompanyID  uuid.UUID
	ReturnID   uuid.UUID
	Amount     decimal.Decimal
	Reason     string
	RefundedBy uuid.UUID
}

// ---------------------------------------------------------------------
// ReturnService Interface
// ---------------------------------------------------------------------

type ReturnService interface {
	CreateReturnRequest(ctx context.Context, req *CreateReturnRequest, idempotencyKey string) (*models.Return, error)
	CreateReturnFromOrder(ctx context.Context, companyID, orderID uuid.UUID, req *CreateReturnFromOrderRequest, idempotencyKey string) (*models.Return, error)
	CreateReturnFromInvoice(ctx context.Context, companyID, invoiceID uuid.UUID, req *CreateReturnFromInvoiceRequest, idempotencyKey string) (*models.Return, error)
	UpdateReturnRequest(ctx context.Context, companyID, returnID uuid.UUID, req *UpdateReturnRequest, idempotencyKey string) (*models.Return, error)
	DeleteReturnRequest(ctx context.Context, companyID, returnID uuid.UUID, deletedBy uuid.UUID, idempotencyKey string) error
	GetReturnByID(ctx context.Context, companyID, returnID uuid.UUID) (*models.Return, error)
	GetReturnByNumber(ctx context.Context, companyID uuid.UUID, returnNumber string) (*models.Return, error)
	ListReturns(ctx context.Context, filter ReturnListFilter, p Pagination, s Sort) ([]*models.Return, int64, error)
	SearchReturns(ctx context.Context, companyID uuid.UUID, query string, limit, offset int) ([]*models.Return, int64, error)
	GetReturnsByCustomer(ctx context.Context, companyID, customerID uuid.UUID, p Pagination, s Sort) ([]*models.Return, int64, error)
	GetReturnsByOrder(ctx context.Context, companyID, orderID uuid.UUID) ([]*models.Return, error)
	GetReturnsByInvoice(ctx context.Context, companyID, invoiceID uuid.UUID) ([]*models.Return, error)
	AddItems(ctx context.Context, companyID, returnID uuid.UUID, items []*CreateReturnItemRequest, updatedBy uuid.UUID) error
	ReplaceItems(ctx context.Context, companyID, returnID uuid.UUID, items []*CreateReturnItemRequest, updatedBy uuid.UUID) error
	RemoveItem(ctx context.Context, companyID, returnID, returnItemID uuid.UUID, updatedBy uuid.UUID) error
	GetReturnItems(ctx context.Context, companyID, returnID uuid.UUID) ([]*models.ReturnItem, error)
	ApproveReturn(ctx context.Context, companyID, returnID uuid.UUID, approvedBy uuid.UUID) error
	RejectReturn(ctx context.Context, companyID, returnID uuid.UUID, reason string, rejectedBy uuid.UUID) error
	CancelReturn(ctx context.Context, companyID, returnID uuid.UUID, reason string, cancelledBy uuid.UUID) error
	MarkReceived(ctx context.Context, companyID, returnID uuid.UUID, receivedAt time.Time, updatedBy uuid.UUID) error
	CompleteReturn(ctx context.Context, companyID, returnID uuid.UUID, completedAt time.Time, updatedBy uuid.UUID) error
	UpdateStatus(ctx context.Context, companyID, returnID uuid.UUID, status enums.ReturnStatus, updatedBy uuid.UUID) error
	ValidateReturnStatusTransition(ctx context.Context, currentStatus, nextStatus enums.ReturnStatus) error
	CalculateRefundAmount(ctx context.Context, companyID, returnID uuid.UUID) (subtotal, taxRefund, discountAdjustment, totalRefund decimal.Decimal, err error)
	CalculatePartialRefund(ctx context.Context, companyID, returnID uuid.UUID, itemIDs []uuid.UUID) (subtotal, taxRefund, discountAdjustment, totalRefund decimal.Decimal, err error)
	PreviewRefund(ctx context.Context, req *ReturnRefundPreviewRequest) (*ReturnRefundPreviewResult, error)
	GenerateCreditNote(ctx context.Context, companyID, returnID uuid.UUID, req *GenerateCreditNoteRequest) (*models.Invoice, error)
	GetCreditNote(ctx context.Context, companyID, returnID uuid.UUID) (*models.Invoice, error)
	HasCreditNote(ctx context.Context, companyID, returnID uuid.UUID) (bool, error)
	ProcessRefund(ctx context.Context, req *ProcessReturnRefundRequest) (*models.PaymentRefund, error)
	ProcessFullRefund(ctx context.Context, companyID, returnID uuid.UUID, reason string, refundedBy uuid.UUID) (*models.PaymentRefund, error)
	ProcessPartialRefund(ctx context.Context, companyID, returnID uuid.UUID, amount decimal.Decimal, reason string, refundedBy uuid.UUID) (*models.PaymentRefund, error)
	GetRefunds(ctx context.Context, companyID, returnID uuid.UUID) ([]*models.PaymentRefund, error)
	GetRefundedAmount(ctx context.Context, companyID, returnID uuid.UUID) (decimal.Decimal, error)
	IsFullyRefunded(ctx context.Context, companyID, returnID uuid.UUID) (bool, error)
	RestockReturnedItems(ctx context.Context, companyID, returnID, warehouseID uuid.UUID, updatedBy uuid.UUID) error
	MarkItemsAsDamaged(ctx context.Context, companyID, returnID uuid.UUID, itemIDs []uuid.UUID, updatedBy uuid.UUID) error
	ValidateReturn(ctx context.Context, ret *models.Return, items []*models.ReturnItem) error
	ValidateReturnItems(ctx context.Context, companyID uuid.UUID, items []*CreateReturnItemRequest) error
	ValidateReturnEligibility(ctx context.Context, companyID uuid.UUID, orderID, invoiceID *uuid.UUID, itemIDs []uuid.UUID) error
	ValidateRefund(ctx context.Context, companyID, returnID uuid.UUID, amount decimal.Decimal) error
	ValidateCreditNoteGeneration(ctx context.Context, companyID, returnID uuid.UUID) error
	GetPendingReturns(ctx context.Context, companyID uuid.UUID) ([]*models.Return, error)
	GetApprovedReturns(ctx context.Context, companyID uuid.UUID) ([]*models.Return, error)
	GetRejectedReturns(ctx context.Context, companyID uuid.UUID) ([]*models.Return, error)
	GetReturnRate(ctx context.Context, companyID uuid.UUID, from, to *time.Time) (decimal.Decimal, error)
	GetTotalRefundAmount(ctx context.Context, companyID uuid.UUID, from, to *time.Time) (decimal.Decimal, error)
	GetMostReturnedProducts(ctx context.Context, companyID uuid.UUID, limit int, from, to *time.Time) ([]*models.Product, error)
	ReturnExists(ctx context.Context, companyID, returnID uuid.UUID) (bool, error)
	ReturnNumberExists(ctx context.Context, companyID uuid.UUID, returnNumber string) (bool, error)
	IsReturnApproved(ctx context.Context, companyID, returnID uuid.UUID) (bool, error)
	IsReturnCompleted(ctx context.Context, companyID, returnID uuid.UUID) (bool, error)
}

// ---------------------------------------------------------------------
// Service Implementation
// ---------------------------------------------------------------------

type returnService struct {
	returnRepo        repository.ReturnRepository
	paymentRefundRepo repository.PaymentRefundRepository
	invoiceRepo       repository.InvoiceRepository
	orderRepo         repository.OrderRepository
	productRepo       repository.ProductRepository
	pgClient          *client.PostgresClient
	outboxRepo        outbox.Repository
	idempotencyStore  idempotency.Store
	auditService      *audit.AuditService
	logger            *zap.Logger
}

func NewReturnService(
	returnRepo repository.ReturnRepository,
	paymentRefundRepo repository.PaymentRefundRepository,
	invoiceRepo repository.InvoiceRepository,
	orderRepo repository.OrderRepository,
	productRepo repository.ProductRepository,
	pgClient *client.PostgresClient,
	outboxRepo outbox.Repository,
	idempotencyStore idempotency.Store,
	auditService *audit.AuditService,
	logger *zap.Logger,
) ReturnService {
	return &returnService{
		returnRepo:        returnRepo,
		paymentRefundRepo: paymentRefundRepo,
		invoiceRepo:       invoiceRepo,
		orderRepo:         orderRepo,
		productRepo:       productRepo,
		pgClient:          pgClient,
		outboxRepo:        outboxRepo,
		idempotencyStore:  idempotencyStore,
		auditService:      auditService,
		logger:            logger.Named("return_service"),
	}
}

// ---------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------

func toReturnStatus(s string) enums.ReturnStatus {
	switch s {
	case "pending":
		return enums.ReturnStatusPending
	case "approved":
		return enums.ReturnStatusApproved
	case "completed":
		return enums.ReturnStatusCompleted
	case "rejected":
		return enums.ReturnStatusRejected
	default:
		return enums.ReturnStatusPending
	}
}

func fromReturnStatus(s enums.ReturnStatus) string {
	return string(s)
}

// ---------------------------------------------------------------------
// Core CRUD
// ---------------------------------------------------------------------

func (s *returnService) CreateReturnRequest(ctx context.Context, req *CreateReturnRequest, idempotencyKey string) (*models.Return, error) {
	logger := s.logger.With(zap.String("method", "CreateReturnRequest"), zap.String("idempotency_key", idempotencyKey))

	if err := s.validateCreateReturn(req); err != nil {
		return nil, err
	}
	if req.OrderID == nil && req.InvoiceID == nil {
		return nil, fmt.Errorf("%w: either order_id or invoice_id must be provided", salesErrors.ErrInvalidInput)
	}

	tx, err := s.pgClient.BeginTx(ctx, nil)
	if err != nil {
		return nil, fmt.Errorf("begin tx: %w", err)
	}
	defer tx.Rollback()

	var cached *models.Return
	if err := s.idempotencyStore.Get(ctx, tx, idempotencyKey, &cached); err == nil && cached != nil {
		logger.Info("idempotent – returning cached return")
		return cached, nil
	}

	// Resolve customer ID from order or invoice (not stored on return, but used for validation)
	var customerID uuid.UUID
	if req.OrderID != nil && *req.OrderID != uuid.Nil {
		order, err := s.orderRepo.GetByID(ctx, tx, req.CompanyID, *req.OrderID)
		if err != nil {
			return nil, fmt.Errorf("get order: %w", err)
		}
		customerID = order.CustomerID
	} else if req.InvoiceID != nil && *req.InvoiceID != uuid.Nil {
		invoice, err := s.invoiceRepo.GetByID(ctx, tx, req.CompanyID, *req.InvoiceID)
		if err != nil {
			return nil, fmt.Errorf("get invoice: %w", err)
		}
		customerID = invoice.CustomerID
	}
	_ = customerID // used for potential future validation

	returnNumber, err := s.generateReturnNumber(ctx, tx, req.CompanyID)
	if err != nil {
		return nil, fmt.Errorf("generate return number: %w", err)
	}

	var orderID uuid.UUID
	if req.OrderID != nil {
		orderID = *req.OrderID
	}
	var invoiceID *uuid.UUID
	if req.InvoiceID != nil {
		invoiceID = req.InvoiceID
	}

	ret := &models.Return{
		ReturnID:     uuid.New(),
		CompanyID:    req.CompanyID,
		OrderID:      orderID,
		InvoiceID:    invoiceID,
		ReturnNumber: returnNumber,
		ReturnDate:   req.ReturnDate,
		Reason:       req.Reason,
		Status:       fromReturnStatus(enums.ReturnStatusPending),
		TotalRefund:  decimal.Zero,
		CreatedBy:    &req.CreatedBy,
		UpdatedBy:    &req.CreatedBy,
	}

	items := make([]*models.ReturnItem, len(req.Items))
	for i, it := range req.Items {
		product, err := s.productRepo.GetByID(ctx, tx, req.CompanyID, it.ProductID)
		if err != nil {
			return nil, fmt.Errorf("get product %s: %w", it.ProductID, err)
		}
		refundAmount := it.Quantity.Mul(product.UnitPrice) // will be recalculated later
		items[i] = &models.ReturnItem{
			ReturnItemID:        uuid.New(),
			ReturnID:            ret.ReturnID,
			OrderItemID:         it.OrderItemID,
			ProductID:           it.ProductID,
			ProductNameSnapshot: product.Name,
			Quantity:            it.Quantity,
			UnitPrice:           product.UnitPrice,
			RefundAmount:        refundAmount,
			Reason:              it.Reason,
			CreatedBy:           &req.CreatedBy,
		}
	}

	if err := s.returnRepo.Create(ctx, tx, ret, items); err != nil {
		return nil, fmt.Errorf("create return: %w", err)
	}
	if err := s.returnRepo.RecalculateRefundTotal(ctx, tx, req.CompanyID, ret.ReturnID); err != nil {
		logger.Warn("failed to recalculate refund total", zap.Error(err))
	}

	// Refresh totals
	ret, err = s.returnRepo.GetByID(ctx, tx, req.CompanyID, ret.ReturnID)
	if err != nil {
		return nil, fmt.Errorf("refresh return: %w", err)
	}

	if err := s.emitReturnEvent(ctx, tx, ret, salesEvents.EventReturnCreated); err != nil {
		logger.Warn("failed to emit return created event", zap.Error(err))
	}
	_ = s.idempotencyStore.Store(ctx, tx, idempotencyKey, ret)

	if err := tx.Commit(); err != nil {
		return nil, fmt.Errorf("commit tx: %w", err)
	}

	if s.auditService != nil {
		_ = s.auditService.LogAction(ctx, nil, &req.CompanyID, "sales", "create_return", "return",
			&ret.ReturnID, "user", &req.CreatedBy, nil, nil, map[string]interface{}{
				"return_number": ret.ReturnNumber,
				"order_id":      ret.OrderID,
				"invoice_id":    ret.InvoiceID,
			})
	}
	return ret, nil
}

func (s *returnService) CreateReturnFromOrder(ctx context.Context, companyID, orderID uuid.UUID, req *CreateReturnFromOrderRequest, idempotencyKey string) (*models.Return, error) {
	return s.CreateReturnRequest(ctx, &CreateReturnRequest{
		CompanyID:  companyID,
		OrderID:    &orderID,
		ReturnDate: req.ReturnDate,
		Reason:     req.Reason,
		Items:      req.Items,
		CreatedBy:  req.CreatedBy,
	}, idempotencyKey)
}

func (s *returnService) CreateReturnFromInvoice(ctx context.Context, companyID, invoiceID uuid.UUID, req *CreateReturnFromInvoiceRequest, idempotencyKey string) (*models.Return, error) {
	return s.CreateReturnRequest(ctx, &CreateReturnRequest{
		CompanyID:  companyID,
		InvoiceID:  &invoiceID,
		ReturnDate: req.ReturnDate,
		Reason:     req.Reason,
		Items:      req.Items,
		CreatedBy:  req.CreatedBy,
	}, idempotencyKey)
}

func (s *returnService) UpdateReturnRequest(ctx context.Context, companyID, returnID uuid.UUID, req *UpdateReturnRequest, idempotencyKey string) (*models.Return, error) {
	logger := s.logger.With(zap.String("method", "UpdateReturnRequest"), zap.String("idempotency_key", idempotencyKey))
	tx, err := s.pgClient.BeginTx(ctx, nil)
	if err != nil {
		return nil, fmt.Errorf("begin tx: %w", err)
	}
	defer tx.Rollback()

	var cached *models.Return
	if err := s.idempotencyStore.Get(ctx, tx, idempotencyKey, &cached); err == nil && cached != nil {
		logger.Info("idempotent – returning cached return")
		return cached, nil
	}

	ret, err := s.returnRepo.GetByIDForUpdate(ctx, tx, companyID, returnID)
	if err != nil {
		return nil, err
	}
	if toReturnStatus(ret.Status) != enums.ReturnStatusPending {
		return nil, fmt.Errorf("%w: cannot update non-pending return", salesErrors.ErrInvalidStatus)
	}

	changes := make(map[string]interface{})
	if req.ReturnDate != nil && !req.ReturnDate.Equal(ret.ReturnDate) {
		changes["return_date"] = map[string]interface{}{"old": ret.ReturnDate, "new": req.ReturnDate}
		ret.ReturnDate = *req.ReturnDate
	}
	if req.Reason != nil && (ret.Reason == nil || *req.Reason != *ret.Reason) {
		old := ""
		if ret.Reason != nil {
			old = *ret.Reason
		}
		changes["reason"] = map[string]string{"old": old, "new": *req.Reason}
		ret.Reason = req.Reason
	}
	ret.UpdatedBy = &req.UpdatedBy

	if err := s.returnRepo.Update(ctx, tx, ret); err != nil {
		return nil, fmt.Errorf("update return: %w", err)
	}
	if err := s.emitReturnEvent(ctx, tx, ret, salesEvents.EventReturnUpdated); err != nil {
		logger.Warn("failed to emit return updated event", zap.Error(err))
	}
	_ = s.idempotencyStore.Store(ctx, tx, idempotencyKey, ret)

	if err := tx.Commit(); err != nil {
		return nil, fmt.Errorf("commit tx: %w", err)
	}

	if s.auditService != nil {
		_ = s.auditService.LogAction(ctx, nil, &companyID, "sales", "update_return", "return",
			&returnID, "user", &req.UpdatedBy, nil, nil, changes)
	}
	return ret, nil
}

func (s *returnService) DeleteReturnRequest(ctx context.Context, companyID, returnID uuid.UUID, deletedBy uuid.UUID, idempotencyKey string) error {
	logger := s.logger.With(zap.String("method", "DeleteReturnRequest"))
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

	ret, err := s.returnRepo.GetByID(ctx, tx, companyID, returnID)
	if err != nil {
		return err
	}
	if toReturnStatus(ret.Status) != enums.ReturnStatusPending {
		return fmt.Errorf("%w: cannot delete non-pending return", salesErrors.ErrInvalidStatus)
	}
	if err := s.returnRepo.Delete(ctx, tx, companyID, returnID); err != nil {
		return fmt.Errorf("delete return: %w", err)
	}
	if err := s.emitReturnEvent(ctx, tx, ret, salesEvents.EventReturnDeleted); err != nil {
		logger.Warn("failed to emit return deleted event", zap.Error(err))
	}
	_ = s.idempotencyStore.Store(ctx, tx, idempotencyKey, true)

	if err := tx.Commit(); err != nil {
		return fmt.Errorf("commit tx: %w", err)
	}

	if s.auditService != nil {
		_ = s.auditService.LogAction(ctx, nil, &companyID, "sales", "delete_return", "return",
			&returnID, "user", &deletedBy, nil, nil, nil)
	}
	return nil
}

func (s *returnService) GetReturnByID(ctx context.Context, companyID, returnID uuid.UUID) (*models.Return, error) {
	return s.returnRepo.GetByID(ctx, nil, companyID, returnID)
}

func (s *returnService) GetReturnByNumber(ctx context.Context, companyID uuid.UUID, returnNumber string) (*models.Return, error) {
	return s.returnRepo.GetByNumber(ctx, nil, companyID, returnNumber)
}

func (s *returnService) ListReturns(ctx context.Context, filter ReturnListFilter, p Pagination, srt Sort) ([]*models.Return, int64, error) {
	repoFilter := repository.ReturnFilter{
		CompanyID:      filter.CompanyID,
		OrderID:        filter.OrderID,
		InvoiceID:      filter.InvoiceID,
		ReturnIDs:      filter.ReturnIDs,
		Statuses:       filter.Statuses,
		ReturnNumber:   nil,
		MinRefundTotal: filter.MinRefundTotal,
		MaxRefundTotal: filter.MaxRefundTotal,
		ReturnDateFrom: filter.ReturnDateFrom,
		ReturnDateTo:   filter.ReturnDateTo,
		ApprovedFrom:   filter.ApprovedFrom,
		ApprovedTo:     filter.ApprovedTo,
		CompletedFrom:  filter.CompletedFrom,
		CompletedTo:    filter.CompletedTo,
		CreatedFrom:    filter.CreatedFrom,
		CreatedTo:      filter.CreatedTo,
		UpdatedFrom:    filter.UpdatedFrom,
		UpdatedTo:      filter.UpdatedTo,
	}
	if filter.ReturnNumber != "" {
		repoFilter.ReturnNumber = &filter.ReturnNumber
	}
	return s.returnRepo.List(ctx, nil, repoFilter, repository.Pagination{Limit: p.Limit, Offset: p.Offset}, repository.Sort{Field: srt.Field, Direction: srt.Direction})
}

func (s *returnService) SearchReturns(ctx context.Context, companyID uuid.UUID, query string, limit, offset int) ([]*models.Return, int64, error) {
	return s.returnRepo.Search(ctx, nil, companyID, query, limit, offset)
}

func (s *returnService) GetReturnsByCustomer(ctx context.Context, companyID, customerID uuid.UUID, p Pagination, srt Sort) ([]*models.Return, int64, error) {
	// Direct SQL because repository does not have this method
	db := s.pgClient.DB
	query := `
		SELECT r.* FROM sales.returns r
		LEFT JOIN sales.orders o ON r.order_id = o.order_id
		LEFT JOIN sales.invoices i ON r.invoice_id = i.invoice_id
		WHERE r.company_id = $1 AND (o.customer_id = $2 OR i.customer_id = $2)
		ORDER BY r.created_at DESC
		LIMIT $3 OFFSET $4
	`
	rows, err := db.QueryContext(ctx, query, companyID, customerID, p.Limit, p.Offset)
	if err != nil {
		return nil, 0, err
	}
	defer rows.Close()
	var returns []*models.Return
	for rows.Next() {
		var r models.Return
		// Scan all fields – simplified; in real code use a helper
		_ = r
	}
	var total int64
	countQuery := `SELECT COUNT(*) FROM sales.returns r
		LEFT JOIN sales.orders o ON r.order_id = o.order_id
		LEFT JOIN sales.invoices i ON r.invoice_id = i.invoice_id
		WHERE r.company_id = $1 AND (o.customer_id = $2 OR i.customer_id = $2)`
	err = db.QueryRowContext(ctx, countQuery, companyID, customerID).Scan(&total)
	if err != nil {
		return nil, 0, err
	}
	return returns, total, nil
}

func (s *returnService) GetReturnsByOrder(ctx context.Context, companyID, orderID uuid.UUID) ([]*models.Return, error) {
	return s.returnRepo.GetByOrder(ctx, nil, companyID, orderID)
}

func (s *returnService) GetReturnsByInvoice(ctx context.Context, companyID, invoiceID uuid.UUID) ([]*models.Return, error) {
	return s.returnRepo.GetByInvoice(ctx, nil, companyID, invoiceID)
}

// ---------------------------------------------------------------------
// Items Management
// ---------------------------------------------------------------------

func (s *returnService) AddItems(ctx context.Context, companyID, returnID uuid.UUID, items []*CreateReturnItemRequest, updatedBy uuid.UUID) error {
	tx, err := s.pgClient.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("begin tx: %w", err)
	}
	defer tx.Rollback()

	ret, err := s.returnRepo.GetByIDForUpdate(ctx, tx, companyID, returnID)
	if err != nil {
		return err
	}
	if toReturnStatus(ret.Status) != enums.ReturnStatusPending {
		return fmt.Errorf("%w: cannot add items to non-pending return", salesErrors.ErrInvalidStatus)
	}

	modelItems := make([]*models.ReturnItem, len(items))
	for i, it := range items {
		product, err := s.productRepo.GetByID(ctx, tx, companyID, it.ProductID)
		if err != nil {
			return fmt.Errorf("get product %s: %w", it.ProductID, err)
		}
		modelItems[i] = &models.ReturnItem{
			ReturnItemID:        uuid.New(),
			ReturnID:            returnID,
			OrderItemID:         it.OrderItemID,
			ProductID:           it.ProductID,
			ProductNameSnapshot: product.Name,
			Quantity:            it.Quantity,
			UnitPrice:           product.UnitPrice,
			RefundAmount:        it.Quantity.Mul(product.UnitPrice),
			Reason:              it.Reason,
			CreatedBy:           &updatedBy,
		}
	}
	if err := s.returnRepo.AddItems(ctx, tx, companyID, returnID, modelItems); err != nil {
		return fmt.Errorf("add items: %w", err)
	}
	if err := s.returnRepo.RecalculateRefundTotal(ctx, tx, companyID, returnID); err != nil {
		return fmt.Errorf("recalculate total: %w", err)
	}
	return tx.Commit()
}

func (s *returnService) ReplaceItems(ctx context.Context, companyID, returnID uuid.UUID, items []*CreateReturnItemRequest, updatedBy uuid.UUID) error {
	tx, err := s.pgClient.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("begin tx: %w", err)
	}
	defer tx.Rollback()

	ret, err := s.returnRepo.GetByIDForUpdate(ctx, tx, companyID, returnID)
	if err != nil {
		return err
	}
	if toReturnStatus(ret.Status) != enums.ReturnStatusPending {
		return fmt.Errorf("%w: cannot replace items on non-pending return", salesErrors.ErrInvalidStatus)
	}

	modelItems := make([]*models.ReturnItem, len(items))
	for i, it := range items {
		product, err := s.productRepo.GetByID(ctx, tx, companyID, it.ProductID)
		if err != nil {
			return fmt.Errorf("get product %s: %w", it.ProductID, err)
		}
		modelItems[i] = &models.ReturnItem{
			ReturnItemID:        uuid.New(),
			ReturnID:            returnID,
			OrderItemID:         it.OrderItemID,
			ProductID:           it.ProductID,
			ProductNameSnapshot: product.Name,
			Quantity:            it.Quantity,
			UnitPrice:           product.UnitPrice,
			RefundAmount:        it.Quantity.Mul(product.UnitPrice),
			Reason:              it.Reason,
			CreatedBy:           &updatedBy,
		}
	}
	if err := s.returnRepo.ReplaceItems(ctx, tx, companyID, returnID, modelItems); err != nil {
		return fmt.Errorf("replace items: %w", err)
	}
	if err := s.returnRepo.RecalculateRefundTotal(ctx, tx, companyID, returnID); err != nil {
		return fmt.Errorf("recalculate total: %w", err)
	}
	return tx.Commit()
}

func (s *returnService) RemoveItem(ctx context.Context, companyID, returnID, returnItemID uuid.UUID, updatedBy uuid.UUID) error {
	tx, err := s.pgClient.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("begin tx: %w", err)
	}
	defer tx.Rollback()

	ret, err := s.returnRepo.GetByIDForUpdate(ctx, tx, companyID, returnID)
	if err != nil {
		return err
	}
	if toReturnStatus(ret.Status) != enums.ReturnStatusPending {
		return fmt.Errorf("%w: cannot remove item from non-pending return", salesErrors.ErrInvalidStatus)
	}
	if err := s.returnRepo.DeleteItem(ctx, tx, companyID, returnID, returnItemID); err != nil {
		return fmt.Errorf("delete item: %w", err)
	}
	if err := s.returnRepo.RecalculateRefundTotal(ctx, tx, companyID, returnID); err != nil {
		return fmt.Errorf("recalculate total: %w", err)
	}
	return tx.Commit()
}

func (s *returnService) GetReturnItems(ctx context.Context, companyID, returnID uuid.UUID) ([]*models.ReturnItem, error) {
	return s.returnRepo.GetItems(ctx, nil, companyID, returnID)
}

// ---------------------------------------------------------------------
// Status Transitions
// ---------------------------------------------------------------------

func (s *returnService) ApproveReturn(ctx context.Context, companyID, returnID uuid.UUID, approvedBy uuid.UUID) error {
	tx, err := s.pgClient.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("begin tx: %w", err)
	}
	defer tx.Rollback()

	ret, err := s.returnRepo.GetByIDForUpdate(ctx, tx, companyID, returnID)
	if err != nil {
		return err
	}
	current := toReturnStatus(ret.Status)
	if err := s.ValidateReturnStatusTransition(ctx, current, enums.ReturnStatusApproved); err != nil {
		return err
	}
	if err := s.returnRepo.Approve(ctx, tx, companyID, returnID, time.Now(), &approvedBy); err != nil {
		return fmt.Errorf("approve return: %w", err)
	}
	if err := s.emitReturnEvent(ctx, tx, ret, salesEvents.EventReturnApproved); err != nil {
		s.logger.Warn("failed to emit return approved event", zap.Error(err))
	}
	return tx.Commit()
}

func (s *returnService) RejectReturn(ctx context.Context, companyID, returnID uuid.UUID, reason string, rejectedBy uuid.UUID) error {
	tx, err := s.pgClient.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("begin tx: %w", err)
	}
	defer tx.Rollback()

	ret, err := s.returnRepo.GetByIDForUpdate(ctx, tx, companyID, returnID)
	if err != nil {
		return err
	}
	current := toReturnStatus(ret.Status)
	if err := s.ValidateReturnStatusTransition(ctx, current, enums.ReturnStatusRejected); err != nil {
		return err
	}
	if err := s.returnRepo.Reject(ctx, tx, companyID, returnID, &rejectedBy); err != nil {
		return fmt.Errorf("reject return: %w", err)
	}
	if err := s.emitReturnEvent(ctx, tx, ret, salesEvents.EventReturnRejected); err != nil {
		s.logger.Warn("failed to emit return rejected event", zap.Error(err))
	}
	return tx.Commit()
}

func (s *returnService) CancelReturn(ctx context.Context, companyID, returnID uuid.UUID, reason string, cancelledBy uuid.UUID) error {
	return s.RejectReturn(ctx, companyID, returnID, reason, cancelledBy)
}

func (s *returnService) MarkReceived(ctx context.Context, companyID, returnID uuid.UUID, receivedAt time.Time, updatedBy uuid.UUID) error {
	// optional – can be implemented if needed
	return nil
}

func (s *returnService) CompleteReturn(ctx context.Context, companyID, returnID uuid.UUID, completedAt time.Time, updatedBy uuid.UUID) error {
	tx, err := s.pgClient.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("begin tx: %w", err)
	}
	defer tx.Rollback()

	ret, err := s.returnRepo.GetByIDForUpdate(ctx, tx, companyID, returnID)
	if err != nil {
		return err
	}
	current := toReturnStatus(ret.Status)
	if err := s.ValidateReturnStatusTransition(ctx, current, enums.ReturnStatusCompleted); err != nil {
		return err
	}
	if err := s.returnRepo.Complete(ctx, tx, companyID, returnID, completedAt, &updatedBy); err != nil {
		return fmt.Errorf("complete return: %w", err)
	}
	if err := s.emitReturnEvent(ctx, tx, ret, salesEvents.EventReturnCompleted); err != nil {
		s.logger.Warn("failed to emit return completed event", zap.Error(err))
	}
	return tx.Commit()
}

func (s *returnService) UpdateStatus(ctx context.Context, companyID, returnID uuid.UUID, status enums.ReturnStatus, updatedBy uuid.UUID) error {
	switch status {
	case enums.ReturnStatusApproved:
		return s.ApproveReturn(ctx, companyID, returnID, updatedBy)
	case enums.ReturnStatusRejected:
		return s.RejectReturn(ctx, companyID, returnID, "", updatedBy)
	case enums.ReturnStatusCompleted:
		return s.CompleteReturn(ctx, companyID, returnID, time.Now(), updatedBy)
	default:
		return fmt.Errorf("%w: unsupported status update", salesErrors.ErrInvalidInput)
	}
}

func (s *returnService) ValidateReturnStatusTransition(ctx context.Context, currentStatus, nextStatus enums.ReturnStatus) error {
	allowed := map[enums.ReturnStatus][]enums.ReturnStatus{
		enums.ReturnStatusPending:   {enums.ReturnStatusApproved, enums.ReturnStatusRejected},
		enums.ReturnStatusApproved:  {enums.ReturnStatusCompleted, enums.ReturnStatusRejected},
		enums.ReturnStatusCompleted: {},
		enums.ReturnStatusRejected:  {},
	}
	allowedNext, ok := allowed[currentStatus]
	if !ok {
		return fmt.Errorf("%w: invalid current status %s", salesErrors.ErrInvalidStatus, currentStatus)
	}
	for _, ns := range allowedNext {
		if ns == nextStatus {
			return nil
		}
	}
	return fmt.Errorf("%w: cannot transition from %s to %s", salesErrors.ErrInvalidTransition, currentStatus, nextStatus)
}

// ---------------------------------------------------------------------
// Refund Calculations (with real tax handling)
// ---------------------------------------------------------------------

func (s *returnService) CalculateRefundAmount(ctx context.Context, companyID, returnID uuid.UUID) (subtotal, taxRefund, discountAdjustment, totalRefund decimal.Decimal, err error) {
	items, err := s.returnRepo.GetItems(ctx, nil, companyID, returnID)
	if err != nil {
		return decimal.Zero, decimal.Zero, decimal.Zero, decimal.Zero, err
	}
	// Get original invoice/order to retrieve actual tax rates
	var originalTaxRate decimal.Decimal = decimal.NewFromInt(10) // fallback
	if len(items) > 0 {
		ret, err := s.returnRepo.GetByID(ctx, nil, companyID, returnID)
		if err == nil {
			if ret.OrderID != uuid.Nil {
				order, _ := s.orderRepo.GetByID(ctx, nil, companyID, ret.OrderID)
				if order != nil && order.TaxTotal.GreaterThan(decimal.Zero) && order.Subtotal.GreaterThan(decimal.Zero) {
					originalTaxRate = order.TaxTotal.Div(order.Subtotal).Mul(decimal.NewFromInt(100))
				}
			} else if ret.InvoiceID != nil && *ret.InvoiceID != uuid.Nil {
				invoice, _ := s.invoiceRepo.GetByID(ctx, nil, companyID, *ret.InvoiceID)
				if invoice != nil && invoice.TaxTotal.GreaterThan(decimal.Zero) && invoice.Subtotal.GreaterThan(decimal.Zero) {
					originalTaxRate = invoice.TaxTotal.Div(invoice.Subtotal).Mul(decimal.NewFromInt(100))
				}
			}
		}
	}
	for _, it := range items {
		lineTotal := it.UnitPrice.Mul(it.Quantity)
		subtotal = subtotal.Add(lineTotal)
		taxRefund = taxRefund.Add(lineTotal.Mul(originalTaxRate).Div(decimal.NewFromInt(100)))
		totalRefund = totalRefund.Add(it.RefundAmount)
	}
	discountAdjustment = subtotal.Sub(totalRefund).Sub(taxRefund).Neg()
	return
}

func (s *returnService) CalculatePartialRefund(ctx context.Context, companyID, returnID uuid.UUID, itemIDs []uuid.UUID) (subtotal, taxRefund, discountAdjustment, totalRefund decimal.Decimal, err error) {
	items, err := s.returnRepo.GetItems(ctx, nil, companyID, returnID)
	if err != nil {
		return decimal.Zero, decimal.Zero, decimal.Zero, decimal.Zero, err
	}
	var originalTaxRate decimal.Decimal = decimal.NewFromInt(10)
	ret, _ := s.returnRepo.GetByID(ctx, nil, companyID, returnID)
	if ret != nil {
		if ret.OrderID != uuid.Nil {
			order, _ := s.orderRepo.GetByID(ctx, nil, companyID, ret.OrderID)
			if order != nil && order.TaxTotal.GreaterThan(decimal.Zero) && order.Subtotal.GreaterThan(decimal.Zero) {
				originalTaxRate = order.TaxTotal.Div(order.Subtotal).Mul(decimal.NewFromInt(100))
			}
		} else if ret.InvoiceID != nil && *ret.InvoiceID != uuid.Nil {
			invoice, _ := s.invoiceRepo.GetByID(ctx, nil, companyID, *ret.InvoiceID)
			if invoice != nil && invoice.TaxTotal.GreaterThan(decimal.Zero) && invoice.Subtotal.GreaterThan(decimal.Zero) {
				originalTaxRate = invoice.TaxTotal.Div(invoice.Subtotal).Mul(decimal.NewFromInt(100))
			}
		}
	}
	for _, it := range items {
		for _, id := range itemIDs {
			if it.ReturnItemID == id {
				lineTotal := it.UnitPrice.Mul(it.Quantity)
				subtotal = subtotal.Add(lineTotal)
				taxRefund = taxRefund.Add(lineTotal.Mul(originalTaxRate).Div(decimal.NewFromInt(100)))
				totalRefund = totalRefund.Add(it.RefundAmount)
				break
			}
		}
	}
	discountAdjustment = subtotal.Sub(totalRefund).Sub(taxRefund).Neg()
	return
}

func (s *returnService) PreviewRefund(ctx context.Context, req *ReturnRefundPreviewRequest) (*ReturnRefundPreviewResult, error) {
	var subtotal, tax, total decimal.Decimal
	var originalTaxRate decimal.Decimal = decimal.NewFromInt(10)
	if req.OrderID != nil && *req.OrderID != uuid.Nil {
		order, err := s.orderRepo.GetByID(ctx, nil, req.CompanyID, *req.OrderID)
		if err == nil && order.TaxTotal.GreaterThan(decimal.Zero) && order.Subtotal.GreaterThan(decimal.Zero) {
			originalTaxRate = order.TaxTotal.Div(order.Subtotal).Mul(decimal.NewFromInt(100))
		}
	} else if req.InvoiceID != nil && *req.InvoiceID != uuid.Nil {
		invoice, err := s.invoiceRepo.GetByID(ctx, nil, req.CompanyID, *req.InvoiceID)
		if err == nil && invoice.TaxTotal.GreaterThan(decimal.Zero) && invoice.Subtotal.GreaterThan(decimal.Zero) {
			originalTaxRate = invoice.TaxTotal.Div(invoice.Subtotal).Mul(decimal.NewFromInt(100))
		}
	}
	for _, it := range req.Items {
		product, err := s.productRepo.GetByID(ctx, nil, req.CompanyID, it.ProductID)
		if err != nil {
			return nil, err
		}
		lineTotal := product.UnitPrice.Mul(it.Quantity)
		subtotal = subtotal.Add(lineTotal)
		tax = tax.Add(lineTotal.Mul(originalTaxRate).Div(decimal.NewFromInt(100)))
		total = total.Add(lineTotal)
	}
	discountAdj := subtotal.Sub(total).Sub(tax).Neg()
	return &ReturnRefundPreviewResult{
		Subtotal:           subtotal,
		TaxRefund:          tax,
		DiscountAdjustment: discountAdj,
		TotalRefund:        total,
	}, nil
}

// ---------------------------------------------------------------------
// Credit Notes
// ---------------------------------------------------------------------

func (s *returnService) GenerateCreditNote(ctx context.Context, companyID, returnID uuid.UUID, req *GenerateCreditNoteRequest) (*models.Invoice, error) {
	tx, err := s.pgClient.BeginTx(ctx, nil)
	if err != nil {
		return nil, fmt.Errorf("begin tx: %w", err)
	}
	defer tx.Rollback()

	ret, err := s.returnRepo.GetByIDForUpdate(ctx, tx, companyID, returnID)
	if err != nil {
		return nil, err
	}
	if toReturnStatus(ret.Status) != enums.ReturnStatusApproved {
		return nil, fmt.Errorf("%w: credit note can only be generated for approved returns", salesErrors.ErrInvalidStatus)
	}
	if has, _ := s.returnRepo.HasCreditNote(ctx, tx, companyID, returnID); has {
		return nil, fmt.Errorf("%w: credit note already exists", salesErrors.ErrConflict)
	}

	creditNoteNumber, err := s.generateCreditNoteNumber(ctx, tx, companyID)
	if err != nil {
		return nil, err
	}
	items, err := s.returnRepo.GetItems(ctx, tx, companyID, returnID)
	if err != nil {
		return nil, err
	}
	var subtotal, discountTotal, taxTotal decimal.Decimal
	for _, it := range items {
		lineTotal := it.UnitPrice.Mul(it.Quantity)
		subtotal = subtotal.Add(lineTotal)
	}
	var customerID uuid.UUID
	var originalInvoice *models.Invoice
	if ret.OrderID != uuid.Nil {
		order, err := s.orderRepo.GetByID(ctx, tx, companyID, ret.OrderID)
		if err != nil {
			return nil, fmt.Errorf("get order for credit note: %w", err)
		}
		customerID = order.CustomerID
		// find invoice associated with order
		invoices, _ := s.invoiceRepo.GetByOrder(ctx, tx, companyID, order.OrderID)
		if len(invoices) > 0 {
			originalInvoice = invoices[0]
		}
	} else if ret.InvoiceID != nil && *ret.InvoiceID != uuid.Nil {
		inv, err := s.invoiceRepo.GetByID(ctx, tx, companyID, *ret.InvoiceID)
		if err != nil {
			return nil, fmt.Errorf("get invoice for credit note: %w", err)
		}
		customerID = inv.CustomerID
		originalInvoice = inv
	} else {
		return nil, fmt.Errorf("cannot determine customer for credit note")
	}

	if originalInvoice != nil && originalInvoice.Subtotal.GreaterThan(decimal.Zero) {
		ratio := subtotal.Div(originalInvoice.Subtotal)
		discountTotal = originalInvoice.DiscountTotal.Mul(ratio).Neg()
		taxTotal = originalInvoice.TaxTotal.Mul(ratio).Neg()
	}

	// Prepare order ID pointer
	var orderIDPtr *uuid.UUID
	if ret.OrderID != uuid.Nil {
		orderIDPtr = &ret.OrderID
	}

	creditNote := &models.Invoice{
		InvoiceID:     uuid.New(),
		CompanyID:     companyID,
		OrderID:       orderIDPtr,
		CustomerID:    customerID,
		InvoiceNumber: creditNoteNumber,
		InvoiceDate:   time.Now(),
		DueDate:       time.Now(),
		Status:        enums.InvoiceStatusCredited,
		Currency:      "USD",
		Subtotal:      subtotal.Neg(),
		DiscountTotal: discountTotal,
		TaxTotal:      taxTotal,
		GrandTotal:    subtotal.Add(taxTotal).Sub(discountTotal).Neg(),
		AmountPaid:    decimal.Zero,
		AmountDue:     subtotal.Add(taxTotal).Sub(discountTotal).Neg(),
		Notes:         &[]string{"Credit note for return " + ret.ReturnNumber}[0],
		IsLocked:      true,
		CreatedBy:     &req.IssuedBy,
	}
	invoiceItems := make([]*models.InvoiceItem, len(items))
	for i, it := range items {
		invoiceItems[i] = &models.InvoiceItem{
			InvoiceItemID:       uuid.New(),
			InvoiceID:           creditNote.InvoiceID,
			ProductID:           &it.ProductID,
			ProductNameSnapshot: it.ProductNameSnapshot,
			Quantity:            it.Quantity.Neg(),
			UnitPrice:           it.UnitPrice,
			DiscountAmount:      nil,
			TaxAmount:           nil,
		}
	}
	if err := s.invoiceRepo.Create(ctx, tx, creditNote, invoiceItems); err != nil {
		return nil, fmt.Errorf("create credit note: %w", err)
	}
	if err := s.returnRepo.SetCreditNote(ctx, tx, companyID, returnID, &creditNote.InvoiceID, &req.IssuedBy); err != nil {
		return nil, fmt.Errorf("link credit note to return: %w", err)
	}
	if err := tx.Commit(); err != nil {
		return nil, fmt.Errorf("commit tx: %w", err)
	}
	return creditNote, nil
}

func (s *returnService) GetCreditNote(ctx context.Context, companyID, returnID uuid.UUID) (*models.Invoice, error) {
	return s.returnRepo.GetCreditNote(ctx, nil, companyID, returnID)
}

func (s *returnService) HasCreditNote(ctx context.Context, companyID, returnID uuid.UUID) (bool, error) {
	return s.returnRepo.HasCreditNote(ctx, nil, companyID, returnID)
}

// ---------------------------------------------------------------------
// Refund Processing (with proper payment linking)
// ---------------------------------------------------------------------

func (s *returnService) ProcessRefund(ctx context.Context, req *ProcessReturnRefundRequest) (*models.PaymentRefund, error) {
	tx, err := s.pgClient.BeginTx(ctx, nil)
	if err != nil {
		return nil, fmt.Errorf("begin tx: %w", err)
	}
	defer tx.Rollback()

	ret, err := s.returnRepo.GetByIDForUpdate(ctx, tx, req.CompanyID, req.ReturnID)
	if err != nil {
		return nil, err
	}
	if toReturnStatus(ret.Status) != enums.ReturnStatusApproved {
		return nil, fmt.Errorf("%w: refunds only allowed for approved returns", salesErrors.ErrInvalidStatus)
	}
	if err := s.ValidateRefund(ctx, req.CompanyID, req.ReturnID, req.Amount); err != nil {
		return nil, err
	}
	// Find original payment from order/invoice
	var paymentID uuid.UUID
	if ret.OrderID != uuid.Nil {
		// get payment allocations for the order's invoice
		invoices, _ := s.invoiceRepo.GetByOrder(ctx, tx, req.CompanyID, ret.OrderID)
		if len(invoices) > 0 {
			allocRows, err := tx.QueryContext(ctx, `SELECT payment_id FROM sales.payment_allocations WHERE invoice_id = $1`, invoices[0].InvoiceID)
			if err == nil {
				defer allocRows.Close()
				if allocRows.Next() {
					_ = allocRows.Scan(&paymentID)
				}
			}
		}
	} else if ret.InvoiceID != nil && *ret.InvoiceID != uuid.Nil {
		allocRows, err := tx.QueryContext(ctx, `SELECT payment_id FROM sales.payment_allocations WHERE invoice_id = $1`, *ret.InvoiceID)
		if err == nil {
			defer allocRows.Close()
			if allocRows.Next() {
				_ = allocRows.Scan(&paymentID)
			}
		}
	}
	if paymentID == uuid.Nil {
		return nil, fmt.Errorf("cannot determine original payment for return")
	}

	refund := &models.PaymentRefund{
		RefundID:    uuid.New(),
		CompanyID:   req.CompanyID,
		PaymentID:   paymentID,
		ReturnID:    &req.ReturnID, // Link refund to this return
		Amount:      req.Amount,
		Reason:      req.Reason,
		Status:      "completed",
		RefundedBy:  &req.RefundedBy,
		CompletedAt: nil,
	}
	if err := s.paymentRefundRepo.Create(ctx, tx, refund); err != nil {
		return nil, fmt.Errorf("create refund: %w", err)
	}
	if err := tx.Commit(); err != nil {
		return nil, fmt.Errorf("commit tx: %w", err)
	}
	return refund, nil
}

func (s *returnService) ProcessFullRefund(ctx context.Context, companyID, returnID uuid.UUID, reason string, refundedBy uuid.UUID) (*models.PaymentRefund, error) {
	ret, err := s.returnRepo.GetByID(ctx, nil, companyID, returnID)
	if err != nil {
		return nil, err
	}
	return s.ProcessRefund(ctx, &ProcessReturnRefundRequest{
		CompanyID:  companyID,
		ReturnID:   returnID,
		Amount:     ret.TotalRefund,
		Reason:     reason,
		RefundedBy: refundedBy,
	})
}

func (s *returnService) ProcessPartialRefund(ctx context.Context, companyID, returnID uuid.UUID, amount decimal.Decimal, reason string, refundedBy uuid.UUID) (*models.PaymentRefund, error) {
	return s.ProcessRefund(ctx, &ProcessReturnRefundRequest{
		CompanyID:  companyID,
		ReturnID:   returnID,
		Amount:     amount,
		Reason:     reason,
		RefundedBy: refundedBy,
	})
}

func (s *returnService) GetRefunds(ctx context.Context, companyID, returnID uuid.UUID) ([]*models.PaymentRefund, error) {
	// Use the new repository method to fetch refunds linked to this return
	return s.paymentRefundRepo.GetByReturnID(ctx, nil, companyID, returnID)
}

func (s *returnService) GetRefundedAmount(ctx context.Context, companyID, returnID uuid.UUID) (decimal.Decimal, error) {
	refunds, err := s.GetRefunds(ctx, companyID, returnID)
	if err != nil {
		return decimal.Zero, err
	}
	total := decimal.Zero
	for _, r := range refunds {
		if r.Status == "completed" { // Only count completed refunds
			total = total.Add(r.Amount)
		}
	}
	return total, nil
}

func (s *returnService) IsFullyRefunded(ctx context.Context, companyID, returnID uuid.UUID) (bool, error) {
	refunded, err := s.GetRefundedAmount(ctx, companyID, returnID)
	if err != nil {
		return false, err
	}
	ret, err := s.returnRepo.GetByID(ctx, nil, companyID, returnID)
	if err != nil {
		return false, err
	}
	return refunded.GreaterThanOrEqual(ret.TotalRefund), nil
}

// ---------------------------------------------------------------------
// Inventory (stubs)
// ---------------------------------------------------------------------

func (s *returnService) RestockReturnedItems(ctx context.Context, companyID, returnID, warehouseID uuid.UUID, updatedBy uuid.UUID) error {
	// Call inventory service if available
	return nil
}

func (s *returnService) MarkItemsAsDamaged(ctx context.Context, companyID, returnID uuid.UUID, itemIDs []uuid.UUID, updatedBy uuid.UUID) error {
	// Update return items with damaged flag
	return nil
}

// ---------------------------------------------------------------------
// Validation
// ---------------------------------------------------------------------

func (s *returnService) ValidateReturn(ctx context.Context, ret *models.Return, items []*models.ReturnItem) error {
	if ret.ReturnNumber == "" {
		return fmt.Errorf("%w: return number required", salesErrors.ErrInvalidInput)
	}
	if ret.ReturnDate.IsZero() {
		return fmt.Errorf("%w: return date required", salesErrors.ErrInvalidInput)
	}
	if len(items) == 0 {
		return fmt.Errorf("%w: at least one return item required", salesErrors.ErrInvalidInput)
	}
	return nil
}

func (s *returnService) ValidateReturnItems(ctx context.Context, companyID uuid.UUID, items []*CreateReturnItemRequest) error {
	for _, it := range items {
		if it.Quantity.LessThanOrEqual(decimal.Zero) {
			return fmt.Errorf("%w: quantity must be positive", salesErrors.ErrInvalidQuantity)
		}
		if _, err := s.productRepo.GetByID(ctx, nil, companyID, it.ProductID); err != nil {
			return fmt.Errorf("product %s: %w", it.ProductID, err)
		}
	}
	return nil
}

func (s *returnService) ValidateReturnEligibility(ctx context.Context, companyID uuid.UUID, orderID, invoiceID *uuid.UUID, itemIDs []uuid.UUID) error {
	// Placeholder – check order status, return window, etc.
	return nil
}

func (s *returnService) ValidateRefund(ctx context.Context, companyID, returnID uuid.UUID, amount decimal.Decimal) error {
	ret, err := s.returnRepo.GetByID(ctx, nil, companyID, returnID)
	if err != nil {
		return err
	}
	if amount.GreaterThan(ret.TotalRefund) {
		return fmt.Errorf("%w: refund amount exceeds total refundable", salesErrors.ErrOverRefund)
	}
	return nil
}

func (s *returnService) ValidateCreditNoteGeneration(ctx context.Context, companyID, returnID uuid.UUID) error {
	ret, err := s.returnRepo.GetByID(ctx, nil, companyID, returnID)
	if err != nil {
		return err
	}
	if toReturnStatus(ret.Status) != enums.ReturnStatusApproved {
		return fmt.Errorf("%w: credit note only for approved returns", salesErrors.ErrInvalidStatus)
	}
	return nil
}

// ---------------------------------------------------------------------
// Reporting
// ---------------------------------------------------------------------

func (s *returnService) GetPendingReturns(ctx context.Context, companyID uuid.UUID) ([]*models.Return, error) {
	return s.returnRepo.GetPendingReturns(ctx, nil, companyID)
}

func (s *returnService) GetApprovedReturns(ctx context.Context, companyID uuid.UUID) ([]*models.Return, error) {
	return s.returnRepo.GetApprovedReturns(ctx, nil, companyID)
}

func (s *returnService) GetRejectedReturns(ctx context.Context, companyID uuid.UUID) ([]*models.Return, error) {
	filter := repository.ReturnFilter{
		CompanyID: companyID,
		Statuses:  []enums.ReturnStatus{enums.ReturnStatusRejected},
	}
	results, _, err := s.returnRepo.List(ctx, nil, filter, repository.Pagination{Limit: 1000}, repository.Sort{})
	return results, err
}

func (s *returnService) GetReturnRate(ctx context.Context, companyID uuid.UUID, from, to *time.Time) (decimal.Decimal, error) {
	return s.returnRepo.GetReturnRate(ctx, nil, companyID, from, to)
}

func (s *returnService) GetTotalRefundAmount(ctx context.Context, companyID uuid.UUID, from, to *time.Time) (decimal.Decimal, error) {
	return s.returnRepo.GetTotalRefundedAmount(ctx, nil, companyID, from, to)
}

func (s *returnService) GetMostReturnedProducts(ctx context.Context, companyID uuid.UUID, limit int, from, to *time.Time) ([]*models.Product, error) {
	return s.returnRepo.GetTopReturnedProducts(ctx, nil, companyID, limit, from, to)
}

// ---------------------------------------------------------------------
// Existence / Helpers
// ---------------------------------------------------------------------

func (s *returnService) ReturnExists(ctx context.Context, companyID, returnID uuid.UUID) (bool, error) {
	return s.returnRepo.Exists(ctx, nil, companyID, returnID)
}

func (s *returnService) ReturnNumberExists(ctx context.Context, companyID uuid.UUID, returnNumber string) (bool, error) {
	return s.returnRepo.ExistsByNumber(ctx, nil, companyID, returnNumber)
}

func (s *returnService) IsReturnApproved(ctx context.Context, companyID, returnID uuid.UUID) (bool, error) {
	ret, err := s.returnRepo.GetByID(ctx, nil, companyID, returnID)
	if err != nil {
		return false, err
	}
	return toReturnStatus(ret.Status) == enums.ReturnStatusApproved, nil
}

func (s *returnService) IsReturnCompleted(ctx context.Context, companyID, returnID uuid.UUID) (bool, error) {
	ret, err := s.returnRepo.GetByID(ctx, nil, companyID, returnID)
	if err != nil {
		return false, err
	}
	return toReturnStatus(ret.Status) == enums.ReturnStatusCompleted, nil
}

// ---------------------------------------------------------------------
// Private Helpers
// ---------------------------------------------------------------------

func (s *returnService) validateCreateReturn(req *CreateReturnRequest) error {
	if req.CompanyID == uuid.Nil {
		return fmt.Errorf("%w: company_id required", salesErrors.ErrInvalidInput)
	}
	if req.ReturnDate.IsZero() {
		return fmt.Errorf("%w: return_date required", salesErrors.ErrInvalidInput)
	}
	if len(req.Items) == 0 {
		return fmt.Errorf("%w: at least one return item required", salesErrors.ErrInvalidInput)
	}
	return nil
}

func (s *returnService) generateReturnNumber(ctx context.Context, tx repository.DBTX, companyID uuid.UUID) (string, error) {
	var seq int
	err := tx.QueryRowContext(ctx, `SELECT nextval('sales.return_number_seq')`).Scan(&seq)
	if err != nil {
		err = tx.QueryRowContext(ctx, `
			SELECT COALESCE(MAX(CAST(SUBSTRING(return_number FROM '^RET-([0-9]+)$') AS INTEGER)), 0) + 1
			FROM sales.returns
			WHERE company_id = $1 AND return_number LIKE 'RET-%'
		`, companyID).Scan(&seq)
		if err != nil {
			return "", err
		}
	}
	return fmt.Sprintf("RET-%06d", seq), nil
}

func (s *returnService) generateCreditNoteNumber(ctx context.Context, tx repository.DBTX, companyID uuid.UUID) (string, error) {
	var seq int
	err := tx.QueryRowContext(ctx, `SELECT nextval('sales.credit_note_number_seq')`).Scan(&seq)
	if err != nil {
		err = tx.QueryRowContext(ctx, `
			SELECT COALESCE(MAX(CAST(SUBSTRING(invoice_number FROM '^CN-([0-9]+)$') AS INTEGER)), 0) + 1
			FROM sales.invoices
			WHERE company_id = $1 AND invoice_number LIKE 'CN-%'
		`, companyID).Scan(&seq)
		if err != nil {
			return "", err
		}
	}
	return fmt.Sprintf("CN-%06d", seq), nil
}

func (s *returnService) emitReturnEvent(ctx context.Context, tx repository.DBTX, ret *models.Return, eventType string) error {
	sqlTx, ok := tx.(*sql.Tx)
	if !ok {
		return fmt.Errorf("tx is not a *sql.Tx")
	}
	items, _ := s.returnRepo.GetItems(ctx, tx, ret.CompanyID, ret.ReturnID)
	itemPayload := make([]map[string]interface{}, len(items))
	for i, it := range items {
		itemPayload[i] = map[string]interface{}{
			"product_id":    it.ProductID.String(),
			"quantity":      it.Quantity.String(),
			"refund_amount": it.RefundAmount.String(),
			"product_name":  it.ProductNameSnapshot,
		}
	}
	payload := map[string]interface{}{
		"return_id":     ret.ReturnID.String(),
		"company_id":    ret.CompanyID.String(),
		"return_number": ret.ReturnNumber,
		"status":        ret.Status,
		"total_refund":  ret.TotalRefund.String(),
		"return_date":   ret.ReturnDate.Format(time.RFC3339),
		"items":         itemPayload,
	}
	if ret.OrderID != uuid.Nil {
		payload["order_id"] = ret.OrderID.String()
	}
	if ret.InvoiceID != nil && *ret.InvoiceID != uuid.Nil {
		payload["invoice_id"] = ret.InvoiceID.String()
	}
	data, err := json.Marshal(payload)
	if err != nil {
		return err
	}
	event := &outbox.Event{
		EventID:       uuid.New().String(),
		AggregateType: "return",
		AggregateID:   ret.ReturnID.String(),
		EventType:     eventType,
		Topic:         salesEvents.TopicSalesEvents,
		Payload:       data,
	}
	return s.outboxRepo.Store(ctx, sqlTx, event)
}

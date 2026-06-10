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

// CreditCheckService defines the credit management operations.
type CreditCheckService interface {
	CheckCustomerCreditLimit(ctx context.Context, companyID, customerID uuid.UUID, requestedAmount decimal.Decimal) (*CreditCheckResult, error)
	CheckOrderCreditEligibility(ctx context.Context, companyID, orderID uuid.UUID) (*CreditCheckResult, error)
	CheckInvoiceCreditEligibility(ctx context.Context, companyID, invoiceID uuid.UUID) (*CreditCheckResult, error)
	GetCustomerAvailableCredit(ctx context.Context, companyID, customerID uuid.UUID) (decimal.Decimal, error)
	GetCustomerOutstandingBalance(ctx context.Context, companyID, customerID uuid.UUID) (decimal.Decimal, error)
	GetCustomerCreditExposure(ctx context.Context, companyID, customerID uuid.UUID) (decimal.Decimal, error)
	CanCustomerPlaceOrder(ctx context.Context, companyID, customerID uuid.UUID, orderAmount decimal.Decimal) (bool, error)
	HoldOrderForCredit(ctx context.Context, companyID, orderID uuid.UUID, reason string, heldBy uuid.UUID) error
	ReleaseOrderCreditHold(ctx context.Context, companyID, orderID uuid.UUID, reason string, releasedBy uuid.UUID) error
	IsOrderOnCreditHold(ctx context.Context, companyID, orderID uuid.UUID) (bool, error)
	GetOrdersOnCreditHold(ctx context.Context, companyID uuid.UUID) ([]*models.Order, error)
	UpdateOrderCreditStatus(ctx context.Context, companyID, orderID uuid.UUID, status enums.CreditCheckStatus, updatedBy uuid.UUID) error
	SetCustomerCreditLimit(ctx context.Context, companyID, customerID uuid.UUID, creditLimit decimal.Decimal, updatedBy uuid.UUID) error
	IncreaseCustomerCreditLimit(ctx context.Context, companyID, customerID uuid.UUID, increaseAmount decimal.Decimal, reason string, updatedBy uuid.UUID) error
	DecreaseCustomerCreditLimit(ctx context.Context, companyID, customerID uuid.UUID, decreaseAmount decimal.Decimal, reason string, updatedBy uuid.UUID) error
	SuspendCustomerCredit(ctx context.Context, companyID, customerID uuid.UUID, reason string, suspendedBy uuid.UUID) error
	RestoreCustomerCredit(ctx context.Context, companyID, customerID uuid.UUID, restoredBy uuid.UUID) error
	GetCustomerCreditLimit(ctx context.Context, companyID, customerID uuid.UUID) (decimal.Decimal, error)
	IsCustomerCreditSuspended(ctx context.Context, companyID, customerID uuid.UUID) (bool, error)
	LogCreditCheck(ctx context.Context, req *CreateCreditCheckHistoryRequest) (*models.CreditCheckHistory, error)
	GetCreditCheckHistoryByID(ctx context.Context, companyID, historyID uuid.UUID) (*models.CreditCheckHistory, error)
	GetCustomerCreditHistory(ctx context.Context, companyID, customerID uuid.UUID, p Pagination, s Sort) ([]*models.CreditCheckHistory, int64, error)
	GetOrderCreditHistory(ctx context.Context, companyID, orderID uuid.UUID) ([]*models.CreditCheckHistory, error)
	GetFailedCreditChecks(ctx context.Context, companyID uuid.UUID, from, to *time.Time) ([]*models.CreditCheckHistory, error)
	RunAutomaticCreditReview(ctx context.Context, companyID, customerID uuid.UUID, triggeredBy uuid.UUID) (*CreditReviewResult, error)
	GetCustomersExceedingCreditLimit(ctx context.Context, companyID uuid.UUID) ([]*models.Customer, error)
	GetCustomersNearCreditLimit(ctx context.Context, companyID uuid.UUID, thresholdPercent decimal.Decimal) ([]*models.Customer, error)
	GetHighRiskCustomers(ctx context.Context, companyID uuid.UUID) ([]*models.Customer, error)
	GetAveragePaymentDelay(ctx context.Context, companyID, customerID uuid.UUID, from, to *time.Time) (decimal.Decimal, error)
	GetCustomerCollectionScore(ctx context.Context, companyID, customerID uuid.UUID) (decimal.Decimal, error)
	GetCustomerCreditUtilization(ctx context.Context, companyID, customerID uuid.UUID) (decimal.Decimal, error)
	ValidateCreditLimit(ctx context.Context, creditLimit decimal.Decimal) error
	ValidateCreditHold(ctx context.Context, companyID, orderID uuid.UUID) error
	ValidateCreditRelease(ctx context.Context, companyID, orderID uuid.UUID) error
	ValidateCreditStatusTransition(ctx context.Context, currentStatus, nextStatus enums.CreditCheckStatus) error
	GetTotalOutstandingCredit(ctx context.Context, companyID uuid.UUID) (decimal.Decimal, error)
	GetTotalCreditExposure(ctx context.Context, companyID uuid.UUID) (decimal.Decimal, error)
	GetAverageCreditUtilization(ctx context.Context, companyID uuid.UUID, from, to *time.Time) (decimal.Decimal, error)
	GetCreditHoldRate(ctx context.Context, companyID uuid.UUID, from, to *time.Time) (decimal.Decimal, error)
	CreditHistoryExists(ctx context.Context, companyID, historyID uuid.UUID) (bool, error)
	OrderHasCreditIssues(ctx context.Context, companyID, orderID uuid.UUID) (bool, error)
	CustomerExceededCreditLimit(ctx context.Context, companyID, customerID uuid.UUID) (bool, error)
}

type creditCheckService struct {
	customerRepo      repository.CustomerRepository
	orderRepo         repository.OrderRepository
	invoiceRepo       repository.InvoiceRepository
	creditHistoryRepo repository.CreditCheckHistoryRepository
	pgClient          *client.PostgresClient
	outboxRepo        outbox.Repository
	idempotencyStore  idempotency.Store
	auditService      *audit.AuditService
	logger            *zap.Logger
}

func NewCreditCheckService(
	customerRepo repository.CustomerRepository,
	orderRepo repository.OrderRepository,
	invoiceRepo repository.InvoiceRepository,
	creditHistoryRepo repository.CreditCheckHistoryRepository,
	pgClient *client.PostgresClient,
	outboxRepo outbox.Repository,
	idempotencyStore idempotency.Store,
	auditService *audit.AuditService,
	logger *zap.Logger,
) CreditCheckService {
	return &creditCheckService{
		customerRepo:      customerRepo,
		orderRepo:         orderRepo,
		invoiceRepo:       invoiceRepo,
		creditHistoryRepo: creditHistoryRepo,
		pgClient:          pgClient,
		outboxRepo:        outboxRepo,
		idempotencyStore:  idempotencyStore,
		auditService:      auditService,
		logger:            logger.Named("credit_check_service"),
	}
}

// ----------------------------------------------------------------------
// Helper methods
// ----------------------------------------------------------------------

func (s *creditCheckService) getOutstandingBalance(ctx context.Context, tx repository.DBTX, companyID, customerID uuid.UUID) (decimal.Decimal, error) {
	query := `
        SELECT COALESCE(SUM(amount_due), 0)
        FROM sales.invoices
        WHERE company_id = $1 AND customer_id = $2
          AND status NOT IN ('paid', 'cancelled')
    `
	var total decimal.Decimal
	err := tx.QueryRowContext(ctx, query, companyID, customerID).Scan(&total)
	if err != nil {
		return decimal.Zero, fmt.Errorf("get outstanding balance: %w", err)
	}
	return total, nil
}

func (s *creditCheckService) getCustomerCreditLimit(ctx context.Context, tx repository.DBTX, companyID, customerID uuid.UUID) (decimal.Decimal, error) {
	cust, err := s.customerRepo.GetCreditLimit(ctx, tx, companyID, customerID)
	if err != nil {
		return decimal.Zero, err
	}
	if cust.CreditLimit == nil {
		return decimal.Zero, nil
	}
	return *cust.CreditLimit, nil
}

func (s *creditCheckService) isCustomerSuspended(ctx context.Context, tx repository.DBTX, companyID, customerID uuid.UUID) (bool, error) {
	query := `
        SELECT EXISTS(
            SELECT 1 FROM sales.credit_check_history
            WHERE company_id = $1 AND customer_id = $2 AND action_type = 'suspend'
              AND created_at > COALESCE(
                  (SELECT MAX(created_at) FROM sales.credit_check_history
                   WHERE company_id = $1 AND customer_id = $2 AND action_type = 'restore'), '0001-01-01')
        )
    `
	var suspended bool
	err := tx.QueryRowContext(ctx, query, companyID, customerID).Scan(&suspended)
	if err != nil {
		return false, fmt.Errorf("check suspension: %w", err)
	}
	return suspended, nil
}

func (s *creditCheckService) logCreditHistory(ctx context.Context, tx repository.DBTX, req *CreateCreditCheckHistoryRequest) error {
	history := &models.CreditCheckHistory{
		CreditHistoryID:     uuid.New(),
		CompanyID:           req.CompanyID,
		CustomerID:          req.CustomerID,
		ActionType:          req.ActionType,
		PreviousLimit:       req.PreviousLimit,
		NewLimit:            req.NewLimit,
		PreviousOutstanding: req.PreviousOutstanding,
		NewOutstanding:      req.NewOutstanding,
		Reason:              req.Reason,
		ApprovedBy:          req.ApprovedBy,
		CreatedBy:           req.CreatedBy,
	}
	return s.creditHistoryRepo.Create(ctx, tx, history)
}

func (s *creditCheckService) emitEvent(ctx context.Context, tx *sql.Tx, aggregateType, aggregateID, eventType string, payload interface{}) error {
	data, err := json.Marshal(payload)
	if err != nil {
		return err
	}
	event := &outbox.Event{
		EventID:       uuid.New().String(),
		AggregateType: aggregateType,
		AggregateID:   aggregateID,
		EventType:     eventType,
		Topic:         salesEvents.TopicSalesEvents,
		Payload:       data,
	}
	return s.outboxRepo.Store(ctx, tx, event)
}

// ----------------------------------------------------------------------
// Read‑only methods (all use read‑only transactions)
// ----------------------------------------------------------------------

func (s *creditCheckService) CheckCustomerCreditLimit(ctx context.Context, companyID, customerID uuid.UUID, requestedAmount decimal.Decimal) (*CreditCheckResult, error) {
	tx, err := s.pgClient.BeginTx(ctx, nil)
	if err != nil {
		return nil, fmt.Errorf("begin tx: %w", err)
	}
	defer tx.Rollback()

	limit, err := s.getCustomerCreditLimit(ctx, tx, companyID, customerID)
	if err != nil {
		return nil, err
	}
	outstanding, err := s.getOutstandingBalance(ctx, tx, companyID, customerID)
	if err != nil {
		return nil, err
	}
	available := limit.Sub(outstanding)
	eligible := available.GreaterThanOrEqual(requestedAmount)
	reason := ""
	if !eligible {
		reason = fmt.Sprintf("insufficient credit: available %.2f, requested %.2f", available.InexactFloat64(), requestedAmount.InexactFloat64())
	}
	suspended, err := s.isCustomerSuspended(ctx, tx, companyID, customerID)
	if err != nil {
		return nil, err
	}
	if suspended {
		eligible = false
		reason = "customer credit is suspended"
	}
	var count int
	countQuery := `SELECT COUNT(*) FROM sales.invoices WHERE company_id=$1 AND customer_id=$2 AND status NOT IN ('paid','cancelled')`
	tx.QueryRowContext(ctx, countQuery, companyID, customerID).Scan(&count)

	return &CreditCheckResult{
		Eligible:         eligible,
		Reason:           reason,
		CurrentBalance:   outstanding,
		CreditLimit:      limit,
		AvailableCredit:  available,
		RequestedAmount:  requestedAmount,
		OutstandingCount: count,
	}, tx.Commit()
}

func (s *creditCheckService) CheckOrderCreditEligibility(ctx context.Context, companyID, orderID uuid.UUID) (*CreditCheckResult, error) {
	tx, err := s.pgClient.BeginTx(ctx, nil)
	if err != nil {
		return nil, fmt.Errorf("begin tx: %w", err)
	}
	defer tx.Rollback()

	order, err := s.orderRepo.GetByID(ctx, tx, companyID, orderID)
	if err != nil {
		return nil, err
	}
	customerID := order.CustomerID
	limit, err := s.getCustomerCreditLimit(ctx, tx, companyID, customerID)
	if err != nil {
		return nil, err
	}
	outstanding, err := s.getOutstandingBalance(ctx, tx, companyID, customerID)
	if err != nil {
		return nil, err
	}
	requested := order.GrandTotal
	available := limit.Sub(outstanding)
	eligible := available.GreaterThanOrEqual(requested)

	reason := ""
	if !eligible {
		reason = fmt.Sprintf("order would exceed credit limit: available %.2f, order total %.2f", available.InexactFloat64(), requested.InexactFloat64())
	}
	suspended, _ := s.isCustomerSuspended(ctx, tx, companyID, customerID)
	if suspended {
		eligible = false
		reason = "customer credit suspended"
	}
	var hold bool
	tx.QueryRowContext(ctx, `SELECT credit_hold FROM sales.orders WHERE order_id=$1`, orderID).Scan(&hold)
	if hold {
		eligible = false
		reason = "order already on credit hold"
	}

	return &CreditCheckResult{
		Eligible:         eligible,
		Reason:           reason,
		CurrentBalance:   outstanding,
		CreditLimit:      limit,
		AvailableCredit:  available,
		RequestedAmount:  requested,
		OutstandingCount: 0,
	}, tx.Commit()
}

func (s *creditCheckService) CheckInvoiceCreditEligibility(ctx context.Context, companyID, invoiceID uuid.UUID) (*CreditCheckResult, error) {
	tx, err := s.pgClient.BeginTx(ctx, nil)
	if err != nil {
		return nil, fmt.Errorf("begin tx: %w", err)
	}
	defer tx.Rollback()

	inv, err := s.invoiceRepo.GetByID(ctx, tx, companyID, invoiceID)
	if err != nil {
		return nil, err
	}
	limit, err := s.getCustomerCreditLimit(ctx, tx, companyID, inv.CustomerID)
	if err != nil {
		return nil, err
	}
	outstanding, err := s.getOutstandingBalance(ctx, tx, companyID, inv.CustomerID)
	if err != nil {
		return nil, err
	}
	requested := inv.GrandTotal
	available := limit.Sub(outstanding)
	eligible := available.GreaterThanOrEqual(requested)
	reason := ""
	if !eligible {
		reason = fmt.Sprintf("invoice would exceed credit limit: available %.2f, invoice total %.2f", available.InexactFloat64(), requested.InexactFloat64())
	}
	suspended, _ := s.isCustomerSuspended(ctx, tx, companyID, inv.CustomerID)
	if suspended {
		eligible = false
		reason = "customer credit suspended"
	}
	return &CreditCheckResult{
		Eligible:        eligible,
		Reason:          reason,
		CurrentBalance:  outstanding,
		CreditLimit:     limit,
		AvailableCredit: available,
		RequestedAmount: requested,
	}, tx.Commit()
}

func (s *creditCheckService) GetCustomerAvailableCredit(ctx context.Context, companyID, customerID uuid.UUID) (decimal.Decimal, error) {
	tx, err := s.pgClient.BeginTx(ctx, &sql.TxOptions{ReadOnly: true})
	if err != nil {
		return decimal.Zero, err
	}
	defer tx.Rollback()
	limit, err := s.getCustomerCreditLimit(ctx, tx, companyID, customerID)
	if err != nil {
		return decimal.Zero, err
	}
	outstanding, err := s.getOutstandingBalance(ctx, tx, companyID, customerID)
	if err != nil {
		return decimal.Zero, err
	}
	return limit.Sub(outstanding), nil
}

func (s *creditCheckService) GetCustomerOutstandingBalance(ctx context.Context, companyID, customerID uuid.UUID) (decimal.Decimal, error) {
	tx, err := s.pgClient.BeginTx(ctx, &sql.TxOptions{ReadOnly: true})
	if err != nil {
		return decimal.Zero, err
	}
	defer tx.Rollback()
	return s.getOutstandingBalance(ctx, tx, companyID, customerID)
}

func (s *creditCheckService) GetCustomerCreditExposure(ctx context.Context, companyID, customerID uuid.UUID) (decimal.Decimal, error) {
	tx, err := s.pgClient.BeginTx(ctx, &sql.TxOptions{ReadOnly: true})
	if err != nil {
		return decimal.Zero, err
	}
	defer tx.Rollback()

	limit, err := s.getCustomerCreditLimit(ctx, tx, companyID, customerID)
	if err != nil {
		return decimal.Zero, err
	}
	outstanding, err := s.getOutstandingBalance(ctx, tx, companyID, customerID)
	if err != nil {
		return decimal.Zero, err
	}
	var openOrdersTotal decimal.Decimal
	query := `SELECT COALESCE(SUM(grand_total), 0) FROM sales.orders WHERE company_id=$1 AND customer_id=$2 AND status NOT IN ('cancelled','delivered') AND credit_hold=false`
	err = tx.QueryRowContext(ctx, query, companyID, customerID).Scan(&openOrdersTotal)
	if err != nil {
		return decimal.Zero, err
	}
	exposure := outstanding.Add(openOrdersTotal)
	if exposure.GreaterThan(limit) {
		exposure = limit
	}
	return exposure, nil
}

func (s *creditCheckService) CanCustomerPlaceOrder(ctx context.Context, companyID, customerID uuid.UUID, orderAmount decimal.Decimal) (bool, error) {
	result, err := s.CheckCustomerCreditLimit(ctx, companyID, customerID, orderAmount)
	if err != nil {
		return false, err
	}
	return result.Eligible, nil
}

func (s *creditCheckService) IsOrderOnCreditHold(ctx context.Context, companyID, orderID uuid.UUID) (bool, error) {
	var hold bool
	err := s.pgClient.DB.QueryRowContext(ctx, `SELECT credit_hold FROM sales.orders WHERE order_id=$1`, orderID).Scan(&hold)
	if err != nil {
		if err == sql.ErrNoRows {
			return false, salesErrors.ErrNotFound
		}
		return false, err
	}
	return hold, nil
}

func (s *creditCheckService) GetOrdersOnCreditHold(ctx context.Context, companyID uuid.UUID) ([]*models.Order, error) {
	query := `SELECT order_id FROM sales.orders WHERE company_id=$1 AND credit_hold=true`
	rows, err := s.pgClient.DB.QueryContext(ctx, query, companyID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var orderIDs []uuid.UUID
	for rows.Next() {
		var id uuid.UUID
		if err := rows.Scan(&id); err != nil {
			return nil, err
		}
		orderIDs = append(orderIDs, id)
	}
	orders := make([]*models.Order, 0, len(orderIDs))
	tx, err := s.pgClient.BeginTx(ctx, &sql.TxOptions{ReadOnly: true})
	if err != nil {
		return nil, err
	}
	defer tx.Rollback()
	for _, id := range orderIDs {
		o, err := s.orderRepo.GetByID(ctx, tx, companyID, id)
		if err != nil {
			s.logger.Warn("failed to fetch order", zap.String("order_id", id.String()), zap.Error(err))
			continue
		}
		orders = append(orders, o)
	}
	return orders, nil
}

func (s *creditCheckService) GetCustomerCreditLimit(ctx context.Context, companyID, customerID uuid.UUID) (decimal.Decimal, error) {
	tx, err := s.pgClient.BeginTx(ctx, &sql.TxOptions{ReadOnly: true})
	if err != nil {
		return decimal.Zero, err
	}
	defer tx.Rollback()
	return s.getCustomerCreditLimit(ctx, tx, companyID, customerID)
}

func (s *creditCheckService) IsCustomerCreditSuspended(ctx context.Context, companyID, customerID uuid.UUID) (bool, error) {
	tx, err := s.pgClient.BeginTx(ctx, &sql.TxOptions{ReadOnly: true})
	if err != nil {
		return false, err
	}
	defer tx.Rollback()
	return s.isCustomerSuspended(ctx, tx, companyID, customerID)
}

func (s *creditCheckService) GetCreditCheckHistoryByID(ctx context.Context, companyID, historyID uuid.UUID) (*models.CreditCheckHistory, error) {
	tx, err := s.pgClient.BeginTx(ctx, &sql.TxOptions{ReadOnly: true})
	if err != nil {
		return nil, err
	}
	defer tx.Rollback()
	history, err := s.creditHistoryRepo.GetByID(ctx, tx, companyID, historyID)
	if err != nil {
		return nil, err
	}
	return history, tx.Commit()
}

func (s *creditCheckService) GetCustomerCreditHistory(ctx context.Context, companyID, customerID uuid.UUID, p Pagination, srt Sort) ([]*models.CreditCheckHistory, int64, error) {
	tx, err := s.pgClient.BeginTx(ctx, &sql.TxOptions{ReadOnly: true})
	if err != nil {
		return nil, 0, err
	}
	defer tx.Rollback()

	filter := repository.CreditCheckHistoryFilter{
		CompanyID:  companyID,
		CustomerID: &customerID,
	}
	histories, total, err := s.creditHistoryRepo.List(ctx, tx, filter,
		repository.Pagination{Limit: p.Limit, Offset: p.Offset},
		repository.Sort{Field: srt.Field, Direction: srt.Direction})
	if err != nil {
		return nil, 0, err
	}
	return histories, total, tx.Commit()
}

func (s *creditCheckService) GetOrderCreditHistory(ctx context.Context, companyID, orderID uuid.UUID) ([]*models.CreditCheckHistory, error) {
	tx, err := s.pgClient.BeginTx(ctx, &sql.TxOptions{ReadOnly: true})
	if err != nil {
		return nil, err
	}
	defer tx.Rollback()

	var customerID uuid.UUID
	err = tx.QueryRowContext(ctx, `SELECT customer_id FROM sales.orders WHERE order_id=$1`, orderID).Scan(&customerID)
	if err != nil {
		return nil, err
	}

	filter := repository.CreditCheckHistoryFilter{
		CompanyID:  companyID,
		CustomerID: &customerID,
	}
	histories, _, err := s.creditHistoryRepo.List(ctx, tx, filter,
		repository.Pagination{Limit: 100},
		repository.Sort{Field: "created_at", Direction: "DESC"})
	if err != nil {
		return nil, err
	}

	var orderHistories []*models.CreditCheckHistory
	for _, h := range histories {
		if h.ActionType == "order_hold" || h.ActionType == "order_release" || h.ActionType == "order_status_change" {
			orderHistories = append(orderHistories, h)
		}
	}
	return orderHistories, tx.Commit()
}

func (s *creditCheckService) GetFailedCreditChecks(ctx context.Context, companyID uuid.UUID, from, to *time.Time) ([]*models.CreditCheckHistory, error) {
	query := `
        SELECT credit_history_id, company_id, customer_id, action_type,
               previous_limit, new_limit, previous_outstanding, new_outstanding,
               reason, approved_by, created_by, created_at
        FROM sales.credit_check_history
        WHERE company_id = $1
          AND (action_type = 'order_check' OR action_type = 'invoice_check')
          AND reason IS NOT NULL AND reason != ''
    `
	args := []interface{}{companyID}
	if from != nil {
		query += " AND created_at >= $2"
		args = append(args, *from)
	}
	if to != nil {
		query += " AND created_at <= $3"
		args = append(args, *to)
	}

	rows, err := s.pgClient.DB.QueryContext(ctx, query, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var failed []*models.CreditCheckHistory
	for rows.Next() {
		var h models.CreditCheckHistory
		err := rows.Scan(&h.CreditHistoryID, &h.CompanyID, &h.CustomerID, &h.ActionType,
			&h.PreviousLimit, &h.NewLimit, &h.PreviousOutstanding, &h.NewOutstanding,
			&h.Reason, &h.ApprovedBy, &h.CreatedBy, &h.CreatedAt)
		if err != nil {
			return nil, err
		}
		failed = append(failed, &h)
	}
	return failed, nil
}

func (s *creditCheckService) GetCustomersExceedingCreditLimit(ctx context.Context, companyID uuid.UUID) ([]*models.Customer, error) {
	tx, err := s.pgClient.BeginTx(ctx, &sql.TxOptions{ReadOnly: true})
	if err != nil {
		return nil, err
	}
	defer tx.Rollback()

	query := `
        SELECT c.customer_id
        FROM sales.customers c
        WHERE c.company_id = $1
          AND c.credit_limit IS NOT NULL AND c.credit_limit > 0
          AND (SELECT COALESCE(SUM(i.amount_due),0) FROM sales.invoices i
               WHERE i.customer_id = c.customer_id AND i.status NOT IN ('paid','cancelled')) > c.credit_limit
    `
	rows, err := tx.QueryContext(ctx, query, companyID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var customerIDs []uuid.UUID
	for rows.Next() {
		var id uuid.UUID
		if err := rows.Scan(&id); err != nil {
			return nil, err
		}
		customerIDs = append(customerIDs, id)
	}
	customers := make([]*models.Customer, 0, len(customerIDs))
	for _, id := range customerIDs {
		cust, err := s.customerRepo.GetByID(ctx, tx, companyID, id)
		if err != nil {
			s.logger.Warn("failed to fetch customer", zap.String("customer_id", id.String()), zap.Error(err))
			continue
		}
		customers = append(customers, cust)
	}
	return customers, nil
}

func (s *creditCheckService) GetCustomersNearCreditLimit(ctx context.Context, companyID uuid.UUID, thresholdPercent decimal.Decimal) ([]*models.Customer, error) {
	tx, err := s.pgClient.BeginTx(ctx, &sql.TxOptions{ReadOnly: true})
	if err != nil {
		return nil, err
	}
	defer tx.Rollback()
	query := `
        SELECT c.customer_id
        FROM sales.customers c
        WHERE c.company_id = $1
          AND c.credit_limit IS NOT NULL AND c.credit_limit > 0
          AND (SELECT COALESCE(SUM(i.amount_due),0) FROM sales.invoices i
               WHERE i.customer_id = c.customer_id AND i.status NOT IN ('paid','cancelled')) >= (c.credit_limit * $2 / 100)
    `
	rows, err := tx.QueryContext(ctx, query, companyID, thresholdPercent)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var customerIDs []uuid.UUID
	for rows.Next() {
		var id uuid.UUID
		rows.Scan(&id)
		customerIDs = append(customerIDs, id)
	}
	customers := make([]*models.Customer, 0, len(customerIDs))
	for _, id := range customerIDs {
		cust, _ := s.customerRepo.GetByID(ctx, tx, companyID, id)
		customers = append(customers, cust)
	}
	return customers, nil
}

func (s *creditCheckService) GetHighRiskCustomers(ctx context.Context, companyID uuid.UUID) ([]*models.Customer, error) {
	tx, err := s.pgClient.BeginTx(ctx, &sql.TxOptions{ReadOnly: true})
	if err != nil {
		return nil, err
	}
	defer tx.Rollback()
	query := `
        SELECT DISTINCT c.customer_id
        FROM sales.customers c
        WHERE c.company_id = $1
          AND (
            (c.credit_limit IS NOT NULL AND c.credit_limit > 0 AND
             (SELECT COALESCE(SUM(i.amount_due),0) FROM sales.invoices i
              WHERE i.customer_id = c.customer_id AND i.status NOT IN ('paid','cancelled')) >= c.credit_limit * 0.9)
            OR
            EXISTS (
                SELECT 1 FROM sales.invoices i2
                WHERE i2.customer_id = c.customer_id AND i2.status = 'paid'
                AND i2.paid_at - i2.invoice_date > interval '60 days'
            )
          )
    `
	rows, err := tx.QueryContext(ctx, query, companyID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var customerIDs []uuid.UUID
	for rows.Next() {
		var id uuid.UUID
		rows.Scan(&id)
		customerIDs = append(customerIDs, id)
	}
	customers := make([]*models.Customer, 0, len(customerIDs))
	for _, id := range customerIDs {
		cust, _ := s.customerRepo.GetByID(ctx, tx, companyID, id)
		customers = append(customers, cust)
	}
	return customers, nil
}

func (s *creditCheckService) GetAveragePaymentDelay(ctx context.Context, companyID, customerID uuid.UUID, from, to *time.Time) (decimal.Decimal, error) {
	tx, err := s.pgClient.BeginTx(ctx, &sql.TxOptions{ReadOnly: true})
	if err != nil {
		return decimal.Zero, err
	}
	defer tx.Rollback()
	query := `
        SELECT COALESCE(AVG(EXTRACT(EPOCH FROM (paid_at - invoice_date)) / 86400), 0)
        FROM sales.invoices
        WHERE company_id = $1 AND customer_id = $2 AND status = 'paid'
          AND paid_at IS NOT NULL
    `
	var avgDays float64
	err = tx.QueryRowContext(ctx, query, companyID, customerID).Scan(&avgDays)
	if err != nil {
		return decimal.Zero, err
	}
	return decimal.NewFromFloat(avgDays), nil
}

func (s *creditCheckService) GetCustomerCollectionScore(ctx context.Context, companyID, customerID uuid.UUID) (decimal.Decimal, error) {
	avgDelay, err := s.GetAveragePaymentDelay(ctx, companyID, customerID, nil, nil)
	if err != nil {
		return decimal.Zero, err
	}
	limit, err := s.GetCustomerCreditLimit(ctx, companyID, customerID)
	if err != nil {
		return decimal.Zero, err
	}
	outstanding, err := s.GetCustomerOutstandingBalance(ctx, companyID, customerID)
	if err != nil {
		return decimal.Zero, err
	}
	util := decimal.Zero
	if limit.GreaterThan(decimal.Zero) {
		util = outstanding.Div(limit).Mul(decimal.NewFromInt(100))
	}
	score := decimal.NewFromInt(100).Sub(avgDelay).Sub(util)
	if score.LessThan(decimal.Zero) {
		score = decimal.Zero
	}
	if score.GreaterThan(decimal.NewFromInt(100)) {
		score = decimal.NewFromInt(100)
	}
	return score, nil
}

func (s *creditCheckService) GetCustomerCreditUtilization(ctx context.Context, companyID, customerID uuid.UUID) (decimal.Decimal, error) {
	tx, err := s.pgClient.BeginTx(ctx, &sql.TxOptions{ReadOnly: true})
	if err != nil {
		return decimal.Zero, err
	}
	defer tx.Rollback()
	limit, err := s.getCustomerCreditLimit(ctx, tx, companyID, customerID)
	if err != nil {
		return decimal.Zero, err
	}
	if limit.IsZero() {
		return decimal.Zero, nil
	}
	outstanding, err := s.getOutstandingBalance(ctx, tx, companyID, customerID)
	if err != nil {
		return decimal.Zero, err
	}
	return outstanding.Div(limit).Mul(decimal.NewFromInt(100)), nil
}

func (s *creditCheckService) ValidateCreditLimit(ctx context.Context, creditLimit decimal.Decimal) error {
	if creditLimit.LessThan(decimal.Zero) {
		return fmt.Errorf("%w: credit limit cannot be negative", salesErrors.ErrInvalidInput)
	}
	return nil
}

func (s *creditCheckService) ValidateCreditHold(ctx context.Context, companyID, orderID uuid.UUID) error {
	hold, err := s.IsOrderOnCreditHold(ctx, companyID, orderID)
	if err != nil {
		return err
	}
	if hold {
		return fmt.Errorf("%w: order already on credit hold", salesErrors.ErrInvalidState)
	}
	return nil
}

func (s *creditCheckService) ValidateCreditRelease(ctx context.Context, companyID, orderID uuid.UUID) error {
	hold, err := s.IsOrderOnCreditHold(ctx, companyID, orderID)
	if err != nil {
		return err
	}
	if !hold {
		return fmt.Errorf("%w: order not on credit hold", salesErrors.ErrInvalidState)
	}
	return nil
}

func (s *creditCheckService) ValidateCreditStatusTransition(ctx context.Context, currentStatus, nextStatus enums.CreditCheckStatus) error {
	if currentStatus == nextStatus {
		return nil
	}
	if currentStatus == enums.CreditCheckHold && nextStatus != enums.CreditCheckApproved {
		return fmt.Errorf("%w: cannot transition from hold to %s", salesErrors.ErrInvalidTransition, nextStatus)
	}
	if currentStatus == enums.CreditCheckApproved && nextStatus == enums.CreditCheckRejected {
		return nil
	}
	return nil
}

func (s *creditCheckService) GetTotalOutstandingCredit(ctx context.Context, companyID uuid.UUID) (decimal.Decimal, error) {
	var total decimal.Decimal
	err := s.pgClient.DB.QueryRowContext(ctx, `SELECT COALESCE(SUM(amount_due),0) FROM sales.invoices WHERE company_id=$1 AND status NOT IN ('paid','cancelled')`, companyID).Scan(&total)
	return total, err
}

func (s *creditCheckService) GetTotalCreditExposure(ctx context.Context, companyID uuid.UUID) (decimal.Decimal, error) {
	var total decimal.Decimal
	err := s.pgClient.DB.QueryRowContext(ctx, `SELECT COALESCE(SUM(credit_limit),0) FROM sales.customers WHERE company_id=$1 AND credit_limit IS NOT NULL`, companyID).Scan(&total)
	return total, err
}

func (s *creditCheckService) GetAverageCreditUtilization(ctx context.Context, companyID uuid.UUID, from, to *time.Time) (decimal.Decimal, error) {
	query := `
        SELECT COALESCE(AVG(CASE WHEN credit_limit > 0 THEN outstanding / credit_limit * 100 ELSE 0 END), 0)
        FROM (
            SELECT c.credit_limit,
                   (SELECT COALESCE(SUM(i.amount_due),0) FROM sales.invoices i
                    WHERE i.customer_id = c.customer_id AND i.status NOT IN ('paid','cancelled')) AS outstanding
            FROM sales.customers c
            WHERE c.company_id = $1 AND c.credit_limit IS NOT NULL
        ) t
    `
	var avg decimal.Decimal
	err := s.pgClient.DB.QueryRowContext(ctx, query, companyID).Scan(&avg)
	return avg, err
}

func (s *creditCheckService) GetCreditHoldRate(ctx context.Context, companyID uuid.UUID, from, to *time.Time) (decimal.Decimal, error) {
	var totalOrders int64
	var holdOrders int64
	err := s.pgClient.DB.QueryRowContext(ctx, `SELECT COUNT(*) FROM sales.orders WHERE company_id=$1`, companyID).Scan(&totalOrders)
	if err != nil {
		return decimal.Zero, err
	}
	err = s.pgClient.DB.QueryRowContext(ctx, `SELECT COUNT(*) FROM sales.orders WHERE company_id=$1 AND credit_hold=true`, companyID).Scan(&holdOrders)
	if err != nil {
		return decimal.Zero, err
	}
	if totalOrders == 0 {
		return decimal.Zero, nil
	}
	rate := decimal.NewFromInt(holdOrders).Div(decimal.NewFromInt(totalOrders)).Mul(decimal.NewFromInt(100))
	return rate, nil
}

func (s *creditCheckService) CreditHistoryExists(ctx context.Context, companyID, historyID uuid.UUID) (bool, error) {
	tx, err := s.pgClient.BeginTx(ctx, &sql.TxOptions{ReadOnly: true})
	if err != nil {
		return false, err
	}
	defer tx.Rollback()
	exists, err := s.creditHistoryRepo.Exists(ctx, tx, companyID, historyID)
	if err != nil {
		return false, err
	}
	return exists, tx.Commit()
}

func (s *creditCheckService) OrderHasCreditIssues(ctx context.Context, companyID, orderID uuid.UUID) (bool, error) {
	var hold bool
	err := s.pgClient.DB.QueryRowContext(ctx, `SELECT credit_hold FROM sales.orders WHERE order_id=$1`, orderID).Scan(&hold)
	if err != nil {
		return false, err
	}
	if hold {
		return true, nil
	}
	var count int
	err = s.pgClient.DB.QueryRowContext(ctx, `
        SELECT COUNT(*) FROM sales.credit_check_history h
        JOIN sales.orders o ON o.customer_id = h.customer_id
        WHERE o.order_id=$1 AND (h.action_type='order_hold' OR h.action_type='order_reject')
    `, orderID).Scan(&count)
	return count > 0, err
}

func (s *creditCheckService) CustomerExceededCreditLimit(ctx context.Context, companyID, customerID uuid.UUID) (bool, error) {
	limit, err := s.GetCustomerCreditLimit(ctx, companyID, customerID)
	if err != nil {
		return false, err
	}
	outstanding, err := s.GetCustomerOutstandingBalance(ctx, companyID, customerID)
	if err != nil {
		return false, err
	}
	return outstanding.GreaterThan(limit), nil
}

// ----------------------------------------------------------------------
// Mutating methods
// ----------------------------------------------------------------------

func (s *creditCheckService) HoldOrderForCredit(ctx context.Context, companyID, orderID uuid.UUID, reason string, heldBy uuid.UUID) error {
	tx, err := s.pgClient.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()

	idempKey, _ := ctx.Value("idempotency_key").(string)
	if idempKey == "" {
		idempKey = fmt.Sprintf("hold-order-%s", orderID.String())
	}
	var processed bool
	if err := s.idempotencyStore.Get(ctx, tx, idempKey, &processed); err == nil && processed {
		s.logger.Info("idempotent – order already placed on hold", zap.String("order_id", orderID.String()))
		return nil
	}

	var alreadyHold bool
	err = tx.QueryRowContext(ctx, `SELECT credit_hold FROM sales.orders WHERE order_id=$1 FOR UPDATE`, orderID).Scan(&alreadyHold)
	if err != nil {
		return err
	}
	if alreadyHold {
		if err := s.idempotencyStore.Store(ctx, tx, idempKey, true); err != nil {
			s.logger.Warn("failed to store idempotency record", zap.Error(err))
		}
		return tx.Commit()
	}

	_, err = tx.ExecContext(ctx, `UPDATE sales.orders SET credit_hold=true, credit_status='hold', updated_at=NOW() WHERE order_id=$1`, orderID)
	if err != nil {
		return err
	}

	var custID uuid.UUID
	tx.QueryRowContext(ctx, `SELECT customer_id FROM sales.orders WHERE order_id=$1`, orderID).Scan(&custID)
	histReq := &CreateCreditCheckHistoryRequest{
		CompanyID:  companyID,
		CustomerID: custID,
		ActionType: "order_hold",
		Reason:     &reason,
		CreatedBy:  &heldBy,
	}
	if err := s.logCreditHistory(ctx, tx, histReq); err != nil {
		s.logger.Warn("failed to log order hold history", zap.Error(err))
	}

	order, _ := s.orderRepo.GetByID(ctx, tx, companyID, orderID)
	if order != nil {
		payload := map[string]interface{}{
			"order_id":    orderID.String(),
			"company_id":  companyID.String(),
			"customer_id": order.CustomerID.String(),
			"reason":      reason,
			"held_by":     heldBy.String(),
			"held_at":     time.Now().Format(time.RFC3339),
		}
		if err := s.emitEvent(ctx, tx, "order", orderID.String(), salesEvents.EventOrderCreditHeld, payload); err != nil {
			s.logger.Warn("failed to emit order hold event", zap.Error(err))
		}
	}
	if s.auditService != nil {
		_ = s.auditService.LogAction(ctx, nil, &companyID, "sales", "credit_hold", "order", &orderID, "user", &heldBy, nil, nil, map[string]interface{}{"reason": reason})
	}

	if err := s.idempotencyStore.Store(ctx, tx, idempKey, true); err != nil {
		s.logger.Warn("failed to store idempotency record", zap.Error(err))
	}
	return tx.Commit()
}

func (s *creditCheckService) ReleaseOrderCreditHold(ctx context.Context, companyID, orderID uuid.UUID, reason string, releasedBy uuid.UUID) error {
	tx, err := s.pgClient.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()

	idempKey, _ := ctx.Value("idempotency_key").(string)
	if idempKey == "" {
		idempKey = fmt.Sprintf("release-order-%s", orderID.String())
	}
	var processed bool
	if err := s.idempotencyStore.Get(ctx, tx, idempKey, &processed); err == nil && processed {
		s.logger.Info("idempotent – order hold already released", zap.String("order_id", orderID.String()))
		return nil
	}

	var currentlyHold bool
	err = tx.QueryRowContext(ctx, `SELECT credit_hold FROM sales.orders WHERE order_id=$1 FOR UPDATE`, orderID).Scan(&currentlyHold)
	if err != nil {
		return err
	}
	// FIX: Return error if order is not on credit hold
	if !currentlyHold {
		return fmt.Errorf("%w: order not on credit hold", salesErrors.ErrInvalidState)
	}

	_, err = tx.ExecContext(ctx, `UPDATE sales.orders SET credit_hold=false, credit_status='approved', updated_at=NOW() WHERE order_id=$1`, orderID)
	if err != nil {
		return err
	}

	var custID uuid.UUID
	tx.QueryRowContext(ctx, `SELECT customer_id FROM sales.orders WHERE order_id=$1`, orderID).Scan(&custID)
	histReq := &CreateCreditCheckHistoryRequest{
		CompanyID:  companyID,
		CustomerID: custID,
		ActionType: "order_release",
		Reason:     &reason,
		CreatedBy:  &releasedBy,
	}
	if err := s.logCreditHistory(ctx, tx, histReq); err != nil {
		s.logger.Warn("failed to log order release history", zap.Error(err))
	}

	order, _ := s.orderRepo.GetByID(ctx, tx, companyID, orderID)
	if order != nil {
		payload := map[string]interface{}{
			"order_id":    orderID.String(),
			"company_id":  companyID.String(),
			"customer_id": order.CustomerID.String(),
			"reason":      reason,
			"released_by": releasedBy.String(),
			"released_at": time.Now().Format(time.RFC3339),
		}
		_ = s.emitEvent(ctx, tx, "order", orderID.String(), salesEvents.EventOrderCreditReleased, payload)
	}
	if s.auditService != nil {
		_ = s.auditService.LogAction(ctx, nil, &companyID, "sales", "credit_release", "order", &orderID, "user", &releasedBy, nil, nil, map[string]interface{}{"reason": reason})
	}

	if err := s.idempotencyStore.Store(ctx, tx, idempKey, true); err != nil {
		s.logger.Warn("failed to store idempotency record", zap.Error(err))
	}
	return tx.Commit()
}
func (s *creditCheckService) UpdateOrderCreditStatus(ctx context.Context, companyID, orderID uuid.UUID, status enums.CreditCheckStatus, updatedBy uuid.UUID) error {
	tx, err := s.pgClient.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()

	idempKey, _ := ctx.Value("idempotency_key").(string)
	if idempKey == "" {
		idempKey = fmt.Sprintf("update-status-%s", orderID.String())
	}
	var processed bool
	if err := s.idempotencyStore.Get(ctx, tx, idempKey, &processed); err == nil && processed {
		s.logger.Info("idempotent – order status already updated", zap.String("order_id", orderID.String()))
		return nil
	}

	_, err = tx.ExecContext(ctx, `UPDATE sales.orders SET credit_status=$1, updated_at=NOW() WHERE order_id=$2`, string(status), orderID)
	if err != nil {
		return err
	}
	var custID uuid.UUID
	tx.QueryRowContext(ctx, `SELECT customer_id FROM sales.orders WHERE order_id=$1`, orderID).Scan(&custID)
	histReq := &CreateCreditCheckHistoryRequest{
		CompanyID:  companyID,
		CustomerID: custID,
		ActionType: "order_status_change",
		CreatedBy:  &updatedBy,
	}
	_ = s.logCreditHistory(ctx, tx, histReq)

	if err := s.idempotencyStore.Store(ctx, tx, idempKey, true); err != nil {
		s.logger.Warn("failed to store idempotency record", zap.Error(err))
	}
	return tx.Commit()
}

func (s *creditCheckService) SetCustomerCreditLimit(ctx context.Context, companyID, customerID uuid.UUID, creditLimit decimal.Decimal, updatedBy uuid.UUID) error {
	if err := s.ValidateCreditLimit(ctx, creditLimit); err != nil {
		return err
	}
	tx, err := s.pgClient.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()

	idempKey, _ := ctx.Value("idempotency_key").(string)
	if idempKey == "" {
		idempKey = fmt.Sprintf("set-limit-%s-%s", companyID.String(), customerID.String())
	}
	var cached bool
	if err := s.idempotencyStore.Get(ctx, tx, idempKey, &cached); err == nil && cached {
		s.logger.Info("idempotent – credit limit already set")
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
	cust.CreditLimit = &creditLimit
	cust.UpdatedBy = &updatedBy
	if err := s.customerRepo.Update(ctx, tx, cust); err != nil {
		return err
	}

	histReq := &CreateCreditCheckHistoryRequest{
		CompanyID:     companyID,
		CustomerID:    customerID,
		ActionType:    "limit_change",
		PreviousLimit: &oldLimit,
		NewLimit:      &creditLimit,
		CreatedBy:     &updatedBy,
	}
	if err := s.logCreditHistory(ctx, tx, histReq); err != nil {
		s.logger.Warn("failed to log credit limit change", zap.Error(err))
	}

	payload := map[string]interface{}{
		"customer_id":    customerID.String(),
		"company_id":     companyID.String(),
		"previous_limit": oldLimit.String(),
		"new_limit":      creditLimit.String(),
		"updated_by":     updatedBy.String(),
		"updated_at":     time.Now().Format(time.RFC3339),
	}
	if err := s.emitEvent(ctx, tx, "customer", customerID.String(), salesEvents.EventCustomerCreditLimitChanged, payload); err != nil {
		s.logger.Warn("failed to emit credit limit event", zap.Error(err))
	}
	if s.auditService != nil {
		_ = s.auditService.LogAction(ctx, nil, &companyID, "sales", "set_credit_limit", "customer", &customerID, "user", &updatedBy, nil, nil, map[string]interface{}{
			"old_limit": oldLimit.String(),
			"new_limit": creditLimit.String(),
		})
	}

	if err := s.idempotencyStore.Store(ctx, tx, idempKey, true); err != nil {
		s.logger.Warn("failed to store idempotency record", zap.Error(err))
	}
	return tx.Commit()
}

func (s *creditCheckService) IncreaseCustomerCreditLimit(ctx context.Context, companyID, customerID uuid.UUID, increaseAmount decimal.Decimal, reason string, updatedBy uuid.UUID) error {
	if increaseAmount.LessThanOrEqual(decimal.Zero) {
		return fmt.Errorf("%w: increase amount must be positive", salesErrors.ErrInvalidInput)
	}
	current, err := s.GetCustomerCreditLimit(ctx, companyID, customerID)
	if err != nil {
		return err
	}
	newLimit := current.Add(increaseAmount)
	return s.SetCustomerCreditLimit(ctx, companyID, customerID, newLimit, updatedBy)
}

func (s *creditCheckService) DecreaseCustomerCreditLimit(ctx context.Context, companyID, customerID uuid.UUID, decreaseAmount decimal.Decimal, reason string, updatedBy uuid.UUID) error {
	if decreaseAmount.LessThanOrEqual(decimal.Zero) {
		return fmt.Errorf("%w: decrease amount must be positive", salesErrors.ErrInvalidInput)
	}
	current, err := s.GetCustomerCreditLimit(ctx, companyID, customerID)
	if err != nil {
		return err
	}
	newLimit := current.Sub(decreaseAmount)
	if newLimit.LessThan(decimal.Zero) {
		newLimit = decimal.Zero
	}
	return s.SetCustomerCreditLimit(ctx, companyID, customerID, newLimit, updatedBy)
}

func (s *creditCheckService) SuspendCustomerCredit(ctx context.Context, companyID, customerID uuid.UUID, reason string, suspendedBy uuid.UUID) error {
	tx, err := s.pgClient.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()

	idempKey, _ := ctx.Value("idempotency_key").(string)
	if idempKey == "" {
		idempKey = fmt.Sprintf("suspend-%s", customerID.String())
	}
	var processed bool
	if err := s.idempotencyStore.Get(ctx, tx, idempKey, &processed); err == nil && processed {
		s.logger.Info("idempotent – customer already suspended")
		return nil
	}

	// FIX: Verify customer exists before logging history
	var exists bool
	err = tx.QueryRowContext(ctx, `SELECT EXISTS(SELECT 1 FROM sales.customers WHERE customer_id=$1 AND company_id=$2)`, customerID, companyID).Scan(&exists)
	if err != nil {
		return err
	}
	if !exists {
		return salesErrors.ErrNotFound
	}

	histReq := &CreateCreditCheckHistoryRequest{
		CompanyID:  companyID,
		CustomerID: customerID,
		ActionType: "suspend",
		Reason:     &reason,
		CreatedBy:  &suspendedBy,
	}
	if err := s.logCreditHistory(ctx, tx, histReq); err != nil {
		return err
	}
	payload := map[string]interface{}{
		"customer_id":  customerID.String(),
		"company_id":   companyID.String(),
		"reason":       reason,
		"suspended_by": suspendedBy.String(),
		"suspended_at": time.Now().Format(time.RFC3339),
	}
	if err := s.emitEvent(ctx, tx, "customer", customerID.String(), "sales.customer.credit_suspended", payload); err != nil {
		s.logger.Warn("failed to emit credit suspension event", zap.Error(err))
	}
	if err := s.idempotencyStore.Store(ctx, tx, idempKey, true); err != nil {
		s.logger.Warn("failed to store idempotency record", zap.Error(err))
	}
	return tx.Commit()
}
func (s *creditCheckService) RestoreCustomerCredit(ctx context.Context, companyID, customerID uuid.UUID, restoredBy uuid.UUID) error {
	tx, err := s.pgClient.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()

	idempKey, _ := ctx.Value("idempotency_key").(string)
	if idempKey == "" {
		idempKey = fmt.Sprintf("restore-%s", customerID.String())
	}
	var processed bool
	if err := s.idempotencyStore.Get(ctx, tx, idempKey, &processed); err == nil && processed {
		s.logger.Info("idempotent – customer already restored")
		return nil
	}

	// FIX: Verify customer exists before logging history
	var exists bool
	err = tx.QueryRowContext(ctx, `SELECT EXISTS(SELECT 1 FROM sales.customers WHERE customer_id=$1 AND company_id=$2)`, customerID, companyID).Scan(&exists)
	if err != nil {
		return err
	}
	if !exists {
		return salesErrors.ErrNotFound
	}

	histReq := &CreateCreditCheckHistoryRequest{
		CompanyID:  companyID,
		CustomerID: customerID,
		ActionType: "restore",
		CreatedBy:  &restoredBy,
	}
	if err := s.logCreditHistory(ctx, tx, histReq); err != nil {
		return err
	}
	payload := map[string]interface{}{
		"customer_id": customerID.String(),
		"company_id":  companyID.String(),
		"restored_by": restoredBy.String(),
		"restored_at": time.Now().Format(time.RFC3339),
	}
	_ = s.emitEvent(ctx, tx, "customer", customerID.String(), "sales.customer.credit_restored", payload)
	if err := s.idempotencyStore.Store(ctx, tx, idempKey, true); err != nil {
		s.logger.Warn("failed to store idempotency record", zap.Error(err))
	}
	return tx.Commit()
}
func (s *creditCheckService) LogCreditCheck(ctx context.Context, req *CreateCreditCheckHistoryRequest) (*models.CreditCheckHistory, error) {
	tx, err := s.pgClient.BeginTx(ctx, nil)
	if err != nil {
		return nil, err
	}
	defer tx.Rollback()

	idempKey, _ := ctx.Value("idempotency_key").(string)
	if idempKey == "" {
		idempKey = fmt.Sprintf("log-credit-%s", uuid.New().String())
	}
	var cached *models.CreditCheckHistory
	if err := s.idempotencyStore.Get(ctx, tx, idempKey, &cached); err == nil && cached != nil {
		s.logger.Info("idempotent – returning cached history")
		return cached, nil
	}

	history := &models.CreditCheckHistory{
		CreditHistoryID:     uuid.New(),
		CompanyID:           req.CompanyID,
		CustomerID:          req.CustomerID,
		ActionType:          req.ActionType,
		PreviousLimit:       req.PreviousLimit,
		NewLimit:            req.NewLimit,
		PreviousOutstanding: req.PreviousOutstanding,
		NewOutstanding:      req.NewOutstanding,
		Reason:              req.Reason,
		ApprovedBy:          req.ApprovedBy,
		CreatedBy:           req.CreatedBy,
	}
	if err := s.creditHistoryRepo.Create(ctx, tx, history); err != nil {
		return nil, err
	}
	if err := s.idempotencyStore.Store(ctx, tx, idempKey, history); err != nil {
		s.logger.Warn("failed to store idempotency record", zap.Error(err))
	}
	if err := tx.Commit(); err != nil {
		return nil, err
	}
	return history, nil
}

func (s *creditCheckService) RunAutomaticCreditReview(ctx context.Context, companyID, customerID uuid.UUID, triggeredBy uuid.UUID) (*CreditReviewResult, error) {
	tx, err := s.pgClient.BeginTx(ctx, nil)
	if err != nil {
		return nil, err
	}
	defer tx.Rollback()

	idempKey, _ := ctx.Value("idempotency_key").(string)
	if idempKey == "" {
		idempKey = fmt.Sprintf("auto-review-%s", customerID.String())
	}
	var cached *CreditReviewResult
	if err := s.idempotencyStore.Get(ctx, tx, idempKey, &cached); err == nil && cached != nil {
		s.logger.Info("idempotent – returning cached review result")
		return cached, nil
	}

	limit, err := s.getCustomerCreditLimit(ctx, tx, companyID, customerID)
	if err != nil {
		return nil, err
	}
	outstanding, err := s.getOutstandingBalance(ctx, tx, companyID, customerID)
	if err != nil {
		return nil, err
	}
	avgDelay, err := s.GetAveragePaymentDelay(ctx, companyID, customerID, nil, nil)
	if err != nil {
		avgDelay = decimal.Zero
	}
	var recommendedLimit = limit
	var action string = "maintain"
	var reasonReview string = "normal"

	if outstanding.GreaterThan(limit.Mul(decimal.NewFromInt(90)).Div(decimal.NewFromInt(100))) {
		recommendedLimit = limit.Mul(decimal.NewFromInt(80)).Div(decimal.NewFromInt(100))
		action = "decrease"
		reasonReview = "utilization >90%"
	} else if avgDelay.GreaterThan(decimal.NewFromInt(45)) {
		recommendedLimit = limit.Mul(decimal.NewFromInt(70)).Div(decimal.NewFromInt(100))
		action = "decrease"
		reasonReview = "average payment delay >45 days"
	} else if avgDelay.LessThan(decimal.NewFromInt(15)) && outstanding.LessThan(limit.Mul(decimal.NewFromInt(50)).Div(decimal.NewFromInt(100))) {
		recommendedLimit = limit.Mul(decimal.NewFromInt(120)).Div(decimal.NewFromInt(100))
		action = "increase"
		reasonReview = "good payment history and low utilization"
	}

	if action != "maintain" {
		if action == "increase" {
			err = s.IncreaseCustomerCreditLimit(ctx, companyID, customerID, recommendedLimit.Sub(limit), reasonReview, triggeredBy)
		} else if action == "decrease" {
			err = s.DecreaseCustomerCreditLimit(ctx, companyID, customerID, limit.Sub(recommendedLimit), reasonReview, triggeredBy)
		}
		if err != nil {
			s.logger.Error("auto credit review failed to adjust limit", zap.Error(err))
		}
	}

	result := &CreditReviewResult{
		CustomerID:          customerID,
		PreviousLimit:       limit,
		RecommendedLimit:    recommendedLimit,
		CurrentOutstanding:  outstanding,
		PaymentHistoryScore: decimal.NewFromInt(100).Sub(avgDelay.Mul(decimal.NewFromInt(2))),
		ActionTaken:         action,
		Reason:              reasonReview,
	}
	if err := s.idempotencyStore.Store(ctx, tx, idempKey, result); err != nil {
		s.logger.Warn("failed to store idempotency record", zap.Error(err))
	}
	return result, tx.Commit()
}

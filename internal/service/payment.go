// internal/service/payment.go
package service

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/google/uuid"
	"go.uber.org/zap"

	"auth-service/internal/client"
	apperrors "auth-service/internal/errors"
	"auth-service/internal/infrastructure/audit"
	"auth-service/internal/infrastructure/idempotency"
	"auth-service/internal/models"
	"auth-service/internal/repository/postgres"
)

// PaymentConfig holds configuration for payment processing.
type PaymentConfig struct {
	InvoiceDueDays int
}

// DefaultPaymentConfig returns sensible defaults.
func DefaultPaymentConfig() PaymentConfig {
	return PaymentConfig{
		InvoiceDueDays: 7,
	}
}

// PaymentService handles payment records, webhooks, and subscription extension.
type PaymentService struct {
	paymentRepo      postgres.CompanyPaymentRepository
	companyRepo      postgres.CompanyRepository
	planRepo         postgres.SubscriptionPlanRepository
	invoiceService   *SubscriptionInvoiceService
	auditService     *audit.AuditService
	idempotencyStore idempotency.Store
	db               *client.PostgresClient
	cfg              PaymentConfig
	logger           *zap.Logger
}

// NewPaymentService creates a new PaymentService.
func NewPaymentService(
	paymentRepo postgres.CompanyPaymentRepository,
	companyRepo postgres.CompanyRepository,
	planRepo postgres.SubscriptionPlanRepository,
	invoiceService *SubscriptionInvoiceService,
	auditService *audit.AuditService,
	idempotencyStore idempotency.Store,
	db *client.PostgresClient,
	cfg *PaymentConfig,
) *PaymentService {
	if cfg == nil {
		defaultCfg := DefaultPaymentConfig()
		cfg = &defaultCfg
	}
	return &PaymentService{
		paymentRepo:      paymentRepo,
		companyRepo:      companyRepo,
		planRepo:         planRepo,
		invoiceService:   invoiceService,
		auditService:     auditService,
		idempotencyStore: idempotencyStore,
		db:               db,
		cfg:              *cfg,
		logger:           zap.L(),
	}
}

// ---------- Internal Helper ----------

// extendSubscription calls the database function to extend the company's subscription.
func (s *PaymentService) extendSubscription(
	ctx context.Context,
	companyID uuid.UUID,
	planCode string,
	paymentID uuid.UUID,
	gatewayResponse json.RawMessage,
) error {
	s.logger.Info("extendSubscription called",
		zap.String("company_id", companyID.String()),
		zap.String("plan_code", planCode),
		zap.String("payment_id", paymentID.String()),
	)

	if companyID == uuid.Nil || planCode == "" || paymentID == uuid.Nil {
		return fmt.Errorf("%w: missing required parameters for subscription extension", apperrors.ErrInvalidInput)
	}

	query := `SELECT extend_company_subscription($1, $2, $3, $4)`
	_, err := s.db.Exec(ctx, query, companyID, planCode, paymentID, gatewayResponse)
	if err != nil {
		s.logger.Error("extendSubscription failed",
			zap.Error(err),
			zap.String("company_id", companyID.String()),
			zap.String("plan_code", planCode),
		)
		return fmt.Errorf("failed to extend subscription: %w", err)
	}

	s.logger.Info("extendSubscription succeeded",
		zap.String("company_id", companyID.String()),
		zap.String("plan_code", planCode),
	)
	return nil
}

// ---------- Create Payment Record (simple insert) ----------

// createPaymentRecord inserts a payment record without extending the subscription.
func (s *PaymentService) createPaymentRecord(ctx context.Context, payment *models.CompanyPayment) error {
	if payment.PaymentID == uuid.Nil {
		payment.PaymentID = uuid.New()
	}
	now := time.Now().UTC()
	if payment.CreatedAt.IsZero() {
		payment.CreatedAt = now
	}
	if payment.UpdatedAt.IsZero() {
		payment.UpdatedAt = now
	}
	if payment.Currency == "" {
		payment.Currency = "USD"
	}
	if payment.Status == "" {
		payment.Status = models.PaymentStatusPending
	}
	return s.paymentRepo.Create(ctx, payment)
}

// ---------- Manual Payment with Subscription Extension ----------

// RecordManualPayment records a manual/offline payment.
// If status is 'success', it also extends the company's subscription.
// It returns apperrors.ErrDuplicate if a payment with the same gateway_txn_id already exists.
func (s *PaymentService) RecordManualPayment(
	ctx context.Context,
	payment *models.CompanyPayment,
) error {
	s.logger.Info("RecordManualPayment called",
		zap.String("company_id", payment.CompanyID.String()),
		zap.String("status", payment.Status),
		zap.String("gateway_txn_id", func() string {
			if payment.GatewayTxnID != nil {
				return *payment.GatewayTxnID
			}
			return ""
		}()),
	)

	// Validate
	if payment.CompanyID == uuid.Nil {
		return fmt.Errorf("%w: company_id is required", apperrors.ErrInvalidInput)
	}
	if payment.PlanID == nil || *payment.PlanID == uuid.Nil {
		return fmt.Errorf("%w: plan_id is required", apperrors.ErrInvalidInput)
	}
	if payment.GatewayTxnID == nil || *payment.GatewayTxnID == "" {
		return fmt.Errorf("%w: gateway_txn_id is required for idempotency", apperrors.ErrInvalidInput)
	}
	if payment.Amount < 0 {
		return fmt.Errorf("%w: amount cannot be negative", apperrors.ErrInvalidInput)
	}
	if payment.Currency == "" {
		payment.Currency = "USD"
	}
	if payment.Status == "" {
		payment.Status = models.PaymentStatusPending
	}
	if payment.PaymentDate.IsZero() {
		payment.PaymentDate = time.Now().UTC()
	}

	// Idempotency: check if a payment with this gateway_txn_id already exists
	existing, err := s.paymentRepo.GetByGatewayTxnID(ctx, *payment.GatewayTxnID)
	if err != nil && !errors.Is(err, apperrors.ErrNotFound) {
		return fmt.Errorf("%w: failed to check existing payment: %v", apperrors.ErrInternal, err)
	}
	if existing != nil {
		s.logger.Error("Duplicate manual payment attempt",
			zap.String("gateway_txn_id", *payment.GatewayTxnID),
			zap.String("existing_payment_id", existing.PaymentID.String()),
		)
		// Return a duplicate error to be mapped to 409 Conflict
		return fmt.Errorf("%w: payment with gateway_txn_id '%s' already exists",
			apperrors.ErrDuplicate, *payment.GatewayTxnID)
	}

	// If status is success, we need to extend the subscription first
	if payment.Status == models.PaymentStatusSuccess {
		s.logger.Info("Payment status is success, extending subscription",
			zap.String("company_id", payment.CompanyID.String()),
			zap.String("plan_id", payment.PlanID.String()),
		)
		// Fetch the plan to get the plan code
		plan, err := s.planRepo.GetByID(ctx, *payment.PlanID)
		if err != nil {
			if errors.Is(err, apperrors.ErrNotFound) {
				return fmt.Errorf("%w: plan %s not found", apperrors.ErrNotFound, payment.PlanID)
			}
			return fmt.Errorf("%w: %v", apperrors.ErrInternal, err)
		}
		// Call the database function to extend subscription
		if err := s.extendSubscription(ctx, payment.CompanyID, plan.PlanCode, payment.PaymentID, payment.GatewayResponse); err != nil {
			return fmt.Errorf("failed to extend subscription: %w", err)
		}
	} else {
		s.logger.Info("Payment status is not success, skipping subscription extension",
			zap.String("status", payment.Status),
		)
	}

	// Now insert the payment record
	s.logger.Info("Inserting payment record", zap.String("payment_id", payment.PaymentID.String()))
	if err := s.createPaymentRecord(ctx, payment); err != nil {
		return fmt.Errorf("failed to create payment record: %w", err)
	}

	// If status is success, generate an invoice
	if payment.Status == models.PaymentStatusSuccess && s.invoiceService != nil {
		s.logger.Info("Generating invoice for successful payment", zap.String("payment_id", payment.PaymentID.String()))
		plan, err := s.planRepo.GetByID(ctx, *payment.PlanID)
		if err == nil {
			inv, err := s.invoiceService.GenerateInvoiceFromPayment(ctx, payment, plan)
			if err != nil {
				s.logger.Error("Invoice generation failed", zap.Error(err), zap.String("payment_id", payment.PaymentID.String()))
				_ = s.auditService.LogAction(ctx, nil, nil, "invoice", "generation_failed", "invoice",
					nil, "system", nil, nil, nil, map[string]interface{}{
						"payment_id": payment.PaymentID,
						"error":      err.Error(),
					})
			} else {
				s.logger.Info("Invoice generated successfully", zap.String("invoice_id", inv.InvoiceID.String()))
				if err := s.paymentRepo.UpdateInvoiceID(ctx, payment.PaymentID, inv.InvoiceID); err != nil {
					s.logger.Error("Failed to link invoice to payment", zap.Error(err))
					_ = s.auditService.LogAction(ctx, nil, nil, "payment", "invoice_link_failed", "payment",
						&payment.PaymentID, "system", nil, nil, nil, map[string]interface{}{
							"invoice_id": inv.InvoiceID,
							"error":      err.Error(),
						})
				}
			}
		}
	}

	// Audit
	if s.auditService != nil {
		ip, _ := ctx.Value("ip_address").(string)
		_ = s.auditService.LogAction(ctx, nil, nil, "payment", "manual_recorded", "company",
			&payment.CompanyID, "system", nil, nil, nil, map[string]interface{}{
				"payment_id":     payment.PaymentID,
				"gateway_txn_id": payment.GatewayTxnID,
				"amount":         payment.Amount,
				"status":         payment.Status,
				"ip_address":     ip,
			})
	}

	s.logger.Info("RecordManualPayment completed successfully",
		zap.String("payment_id", payment.PaymentID.String()),
		zap.String("status", payment.Status),
	)
	return nil
}

// ---------- Webhook Processing ----------

// ProcessPaymentWebhook handles a successful payment webhook.
// It is idempotent based on gateway_txn_id.
// It calls extend_company_subscription, creates a payment record, and generates an invoice.
func (s *PaymentService) ProcessPaymentWebhook(
	ctx context.Context,
	gatewayTxnID string,
	companyID uuid.UUID,
	planCode string,
	amount float64,
	currency string,
	gatewayResponse json.RawMessage,
) error {
	s.logger.Info("ProcessPaymentWebhook called",
		zap.String("gateway_txn_id", gatewayTxnID),
		zap.String("company_id", companyID.String()),
		zap.String("plan_code", planCode),
		zap.Float64("amount", amount),
	)

	if gatewayTxnID == "" {
		return fmt.Errorf("%w: gateway_txn_id is required", apperrors.ErrInvalidInput)
	}
	if companyID == uuid.Nil {
		return fmt.Errorf("%w: company_id is required", apperrors.ErrInvalidInput)
	}
	if planCode == "" {
		return fmt.Errorf("%w: plan_code is required", apperrors.ErrInvalidInput)
	}
	if amount < 0 {
		return fmt.Errorf("%w: amount cannot be negative", apperrors.ErrInvalidInput)
	}
	if currency == "" {
		currency = "USD"
	}

	// Idempotency: check if already processed
	existing, err := s.paymentRepo.GetByGatewayTxnID(ctx, gatewayTxnID)
	if err != nil && !errors.Is(err, apperrors.ErrNotFound) {
		return fmt.Errorf("%w: failed to check existing payment: %v", apperrors.ErrInternal, err)
	}
	if existing != nil {
		s.logger.Info("Webhook already processed, skipping (idempotency)",
			zap.String("gateway_txn_id", gatewayTxnID),
		)
		return nil
	}

	// Get the plan to get plan_id
	plan, err := s.planRepo.GetByCode(ctx, planCode)
	if err != nil {
		if errors.Is(err, apperrors.ErrNotFound) {
			return fmt.Errorf("%w: plan with code '%s' not found", apperrors.ErrNotFound, planCode)
		}
		return fmt.Errorf("%w: %v", apperrors.ErrInternal, err)
	}

	// Generate IDs for payment and invoice
	paymentID := uuid.New()
	invoiceID := uuid.New()

	s.logger.Info("Calling extendSubscription from webhook",
		zap.String("company_id", companyID.String()),
		zap.String("plan_code", planCode),
		zap.String("payment_id", paymentID.String()),
	)
	// Call the database function to extend subscription
	if err := s.extendSubscription(ctx, companyID, planCode, paymentID, gatewayResponse); err != nil {
		return fmt.Errorf("failed to extend subscription: %w", err)
	}

	// Create the payment record
	now := time.Now().UTC()
	payment := &models.CompanyPayment{
		PaymentID:       paymentID,
		CompanyID:       companyID,
		PlanID:          &plan.PlanID,
		InvoiceID:       &invoiceID,
		Amount:          amount,
		Currency:        currency,
		PaymentDate:     now,
		PaymentMethod:   nil,
		GatewayTxnID:    &gatewayTxnID,
		GatewayResponse: gatewayResponse,
		Status:          models.PaymentStatusSuccess,
		CreatedAt:       now,
		UpdatedAt:       now,
	}
	s.logger.Info("Inserting payment record from webhook", zap.String("payment_id", paymentID.String()))
	if err := s.createPaymentRecord(ctx, payment); err != nil {
		_ = s.auditService.LogAction(ctx, nil, nil, "payment", "payment_creation_failed", "payment",
			&paymentID, "system", nil, nil, nil, map[string]interface{}{
				"error": err.Error(),
			})
		return fmt.Errorf("failed to create payment record: %w", err)
	}

	// Generate invoice
	if s.invoiceService != nil {
		s.logger.Info("Generating invoice from webhook", zap.String("payment_id", paymentID.String()))
		inv, err := s.invoiceService.GenerateInvoiceFromPayment(ctx, payment, plan)
		if err != nil {
			s.logger.Error("Invoice generation failed from webhook", zap.Error(err))
			_ = s.auditService.LogAction(ctx, nil, nil, "invoice", "generation_failed", "invoice",
				&invoiceID, "system", nil, nil, nil, map[string]interface{}{
					"payment_id": paymentID,
					"error":      err.Error(),
				})
		} else {
			s.logger.Info("Invoice generated from webhook", zap.String("invoice_id", inv.InvoiceID.String()))
			if err := s.paymentRepo.UpdateInvoiceID(ctx, paymentID, inv.InvoiceID); err != nil {
				s.logger.Error("Failed to link invoice to payment from webhook", zap.Error(err))
				_ = s.auditService.LogAction(ctx, nil, nil, "payment", "invoice_link_failed", "payment",
					&paymentID, "system", nil, nil, nil, map[string]interface{}{
						"invoice_id": inv.InvoiceID,
						"error":      err.Error(),
					})
			}
		}
	}

	// Audit
	if s.auditService != nil {
		ip, _ := ctx.Value("ip_address").(string)
		_ = s.auditService.LogAction(ctx, nil, nil, "payment", "webhook_success", "company",
			&companyID, "system", nil, nil, nil, map[string]interface{}{
				"gateway_txn_id": gatewayTxnID,
				"plan_code":      planCode,
				"amount":         amount,
				"payment_id":     paymentID,
				"ip_address":     ip,
			})
	}

	s.logger.Info("ProcessPaymentWebhook completed successfully",
		zap.String("payment_id", paymentID.String()),
	)
	return nil
}

// ---------- Read Methods ----------

// GetPaymentByID retrieves a payment by ID.
func (s *PaymentService) GetPaymentByID(ctx context.Context, paymentID uuid.UUID) (*models.CompanyPayment, error) {
	if paymentID == uuid.Nil {
		return nil, fmt.Errorf("%w: payment_id is required", apperrors.ErrInvalidInput)
	}
	payment, err := s.paymentRepo.GetByID(ctx, paymentID)
	if err != nil {
		if errors.Is(err, apperrors.ErrNotFound) {
			return nil, fmt.Errorf("%w: payment with id %s not found", apperrors.ErrNotFound, paymentID)
		}
		return nil, fmt.Errorf("%w: %v", apperrors.ErrInternal, err)
	}
	return payment, nil
}

// GetPaymentByGatewayTxnID retrieves a payment by gateway transaction ID.
func (s *PaymentService) GetPaymentByGatewayTxnID(ctx context.Context, gatewayTxnID string) (*models.CompanyPayment, error) {
	if gatewayTxnID == "" {
		return nil, fmt.Errorf("%w: gateway_txn_id is required", apperrors.ErrInvalidInput)
	}
	payment, err := s.paymentRepo.GetByGatewayTxnID(ctx, gatewayTxnID)
	if err != nil {
		if errors.Is(err, apperrors.ErrNotFound) {
			return nil, nil // not found is not an error here
		}
		return nil, fmt.Errorf("%w: %v", apperrors.ErrInternal, err)
	}
	return payment, nil
}

// ListPaymentsForCompany returns payments for a company with pagination.
func (s *PaymentService) ListPaymentsForCompany(ctx context.Context, companyID uuid.UUID, limit, offset int) ([]*models.CompanyPayment, int, error) {
	if companyID == uuid.Nil {
		return nil, 0, fmt.Errorf("%w: company_id is required", apperrors.ErrInvalidInput)
	}
	if limit <= 0 {
		limit = 50
	}
	if limit > 1000 {
		limit = 1000
	}
	if offset < 0 {
		offset = 0
	}
	return s.paymentRepo.ListByCompany(ctx, companyID, limit, offset)
}

// ---------- Update Methods ----------

// UpdatePaymentStatus updates the status of a payment.
func (s *PaymentService) UpdatePaymentStatus(ctx context.Context, paymentID uuid.UUID, status string) error {
	if paymentID == uuid.Nil {
		return fmt.Errorf("%w: payment_id is required", apperrors.ErrInvalidInput)
	}
	validStatuses := map[string]bool{
		models.PaymentStatusPending:  true,
		models.PaymentStatusSuccess:  true,
		models.PaymentStatusFailed:   true,
		models.PaymentStatusRefunded: true,
	}
	if !validStatuses[status] {
		return fmt.Errorf("%w: invalid status '%s'", apperrors.ErrInvalidInput, status)
	}
	if err := s.paymentRepo.UpdateStatus(ctx, paymentID, status); err != nil {
		return fmt.Errorf("%w: %v", apperrors.ErrInternal, err)
	}
	return nil
}

// UpdatePaymentInvoiceID links a payment to an invoice.
func (s *PaymentService) UpdatePaymentInvoiceID(ctx context.Context, paymentID, invoiceID uuid.UUID) error {
	if paymentID == uuid.Nil || invoiceID == uuid.Nil {
		return fmt.Errorf("%w: payment_id and invoice_id are required", apperrors.ErrInvalidInput)
	}
	if err := s.paymentRepo.UpdateInvoiceID(ctx, paymentID, invoiceID); err != nil {
		return fmt.Errorf("%w: %v", apperrors.ErrInternal, err)
	}
	return nil
}

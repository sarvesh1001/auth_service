package service

import (
	"context"
	"database/sql"
	"fmt"
	"time"

	"github.com/google/uuid"
	"github.com/shopspring/decimal"
	"go.uber.org/zap"

	accountingService "auth-service/internal/accounting/service"
	"auth-service/internal/client"
	"auth-service/internal/infrastructure/audit"
	"auth-service/internal/infrastructure/idempotency"
	"auth-service/internal/infrastructure/outbox"
	salesErrors "auth-service/internal/sales/errors"
	"auth-service/internal/sales/models"
	"auth-service/internal/sales/repository"
)

// TaxIntegrationService defines the interface for sales tax operations.
type TaxIntegrationService interface {
	// Calculation (without persistence)
	CalculateOrderTaxes(ctx context.Context, req *CalculateOrderTaxRequest) (*TaxCalculationResult, error)
	CalculateQuoteTaxes(ctx context.Context, req *CalculateQuoteTaxRequest) (*TaxCalculationResult, error)
	CalculateInvoiceTaxes(ctx context.Context, req *CalculateInvoiceTaxRequest) (*TaxCalculationResult, error)
	CalculateReturnTaxes(ctx context.Context, req *CalculateReturnTaxRequest) (*TaxCalculationResult, error)
	CalculateLineTax(ctx context.Context, req *CalculateLineTaxRequest) (*TaxLineResult, error)
	PreviewTaxes(ctx context.Context, req *TaxPreviewRequest) (*TaxPreviewResult, error)

	// Apply and persist taxes to entities (each starts its own transaction)
	ApplyTaxesToOrder(ctx context.Context, companyID, orderID uuid.UUID, appliedBy uuid.UUID, idempotencyKey string) (*TaxCalculationResult, error)
	ApplyTaxesToQuote(ctx context.Context, companyID, quoteID uuid.UUID, appliedBy uuid.UUID, idempotencyKey string) (*TaxCalculationResult, error)
	ApplyTaxesToInvoice(ctx context.Context, companyID, invoiceID uuid.UUID, appliedBy uuid.UUID, idempotencyKey string) (*TaxCalculationResult, error)

	// Apply taxes using an existing transaction (for atomic operations)
	ApplyTaxesToOrderWithTx(ctx context.Context, tx *sql.Tx, companyID, orderID uuid.UUID, appliedBy uuid.UUID, idempotencyKey string) (*TaxCalculationResult, error)
	ApplyTaxesToInvoiceWithTx(ctx context.Context, tx *sql.Tx, companyID, invoiceID uuid.UUID, appliedBy uuid.UUID, idempotencyKey string) (*TaxCalculationResult, error)

	RefreshOrderTaxes(ctx context.Context, companyID, orderID uuid.UUID, updatedBy uuid.UUID, idempotencyKey string) error
	RefreshInvoiceTaxes(ctx context.Context, companyID, invoiceID uuid.UUID, updatedBy uuid.UUID, idempotencyKey string) error

	// Tax snapshot queries
	GetOrderTaxBreakdown(ctx context.Context, companyID, orderID uuid.UUID) ([]*TaxBreakdownLine, error)
	GetInvoiceTaxBreakdown(ctx context.Context, companyID, invoiceID uuid.UUID) ([]*TaxBreakdownLine, error)
	GetQuoteTaxBreakdown(ctx context.Context, companyID, quoteID uuid.UUID) ([]*TaxBreakdownLine, error)

	// Tax snapshot management
	CreateTaxSnapshot(ctx context.Context, req *CreateTaxSnapshotRequest) (*models.TaxSnapshot, error)
	GetTaxSnapshotByID(ctx context.Context, companyID, snapshotID uuid.UUID) (*models.TaxSnapshot, error)
	GetLatestTaxSnapshot(ctx context.Context, companyID uuid.UUID, entityType string, entityID uuid.UUID) (*models.TaxSnapshot, error)
	GetTaxSnapshots(ctx context.Context, companyID uuid.UUID, entityType string, entityID uuid.UUID) ([]*models.TaxSnapshot, error)
	RecalculateTaxSnapshot(ctx context.Context, companyID, snapshotID uuid.UUID, recalculatedBy uuid.UUID, idempotencyKey string) (*models.TaxSnapshot, error)
	ArchiveTaxSnapshot(ctx context.Context, companyID, snapshotID uuid.UUID, archivedBy uuid.UUID, idempotencyKey string) error

	// Existence checks
	TaxSnapshotExists(ctx context.Context, companyID, snapshotID uuid.UUID) (bool, error)
}

// ------------------------------------------------------------
// Request/Response Types
// ------------------------------------------------------------

// ------------------------------------------------------------
// Service Implementation
// ------------------------------------------------------------

type taxIntegrationService struct {
	taxSnapshotRepo     repository.TaxSnapshotRepository
	orderRepo           repository.OrderRepository
	quoteRepo           repository.QuoteRepository
	invoiceRepo         repository.InvoiceRepository
	productRepo         repository.ProductRepository
	customerRepo        repository.CustomerRepository
	accountingTaxEngine accountingService.TaxEngineService
	pgClient            *client.PostgresClient
	outboxRepo          outbox.Repository
	idempotencyStore    idempotency.Store
	auditService        *audit.AuditService
	logger              *zap.Logger
}

func NewTaxIntegrationService(
	taxSnapshotRepo repository.TaxSnapshotRepository,
	orderRepo repository.OrderRepository,
	quoteRepo repository.QuoteRepository,
	invoiceRepo repository.InvoiceRepository,
	productRepo repository.ProductRepository,
	customerRepo repository.CustomerRepository,
	accountingTaxEngine accountingService.TaxEngineService,
	pgClient *client.PostgresClient,
	outboxRepo outbox.Repository,
	idempotencyStore idempotency.Store,
	auditService *audit.AuditService,
	logger *zap.Logger,
) TaxIntegrationService {
	return &taxIntegrationService{
		taxSnapshotRepo:     taxSnapshotRepo,
		orderRepo:           orderRepo,
		quoteRepo:           quoteRepo,
		invoiceRepo:         invoiceRepo,
		productRepo:         productRepo,
		customerRepo:        customerRepo,
		accountingTaxEngine: accountingTaxEngine,
		pgClient:            pgClient,
		outboxRepo:          outboxRepo,
		idempotencyStore:    idempotencyStore,
		auditService:        auditService,
		logger:              logger.Named("tax_integration_service"),
	}
}

// ------------------------------------------------------------
// Calculation (without persistence)
// ------------------------------------------------------------

func (s *taxIntegrationService) CalculateOrderTaxes(ctx context.Context, req *CalculateOrderTaxRequest) (*TaxCalculationResult, error) {
	return s.calculateTaxesForEntity(ctx, req.CompanyID, "order", req.OrderID, req.LineItems, req.CustomerID, req.BillingAddress)
}

func (s *taxIntegrationService) CalculateQuoteTaxes(ctx context.Context, req *CalculateQuoteTaxRequest) (*TaxCalculationResult, error) {
	return s.calculateTaxesForEntity(ctx, req.CompanyID, "quote", req.QuoteID, req.LineItems, req.CustomerID, req.BillingAddress)
}

func (s *taxIntegrationService) CalculateInvoiceTaxes(ctx context.Context, req *CalculateInvoiceTaxRequest) (*TaxCalculationResult, error) {
	return s.calculateTaxesForEntity(ctx, req.CompanyID, "invoice", req.InvoiceID, req.LineItems, req.CustomerID, req.BillingAddress)
}

func (s *taxIntegrationService) CalculateReturnTaxes(ctx context.Context, req *CalculateReturnTaxRequest) (*TaxCalculationResult, error) {
	return s.calculateTaxesForEntity(ctx, req.CompanyID, "return", req.ReturnID, req.LineItems, req.CustomerID, req.BillingAddress)
}

// CalculateLineTax computes tax for a single line item (no persistence).
func (s *taxIntegrationService) CalculateLineTax(ctx context.Context, req *CalculateLineTaxRequest) (*TaxLineResult, error) {
	input := s.buildTaxComputationInput(req.CompanyID, req.ProductID, req.LineAmount, req.TaxableAmount, req.CustomerID, req.BillingCountry, req.BillingState)
	items, err := s.accountingTaxEngine.ComputeTaxBreakdown(ctx, req.CompanyID, input)
	if err != nil {
		return nil, err
	}
	if len(items) == 0 {
		return &TaxLineResult{TaxAmount: decimal.Zero, ApplicableRate: decimal.Zero}, nil
	}
	totalTax := decimal.Zero
	for _, it := range items {
		totalTax = totalTax.Add(it.TaxAmount)
	}
	return &TaxLineResult{
		TaxAmount:      totalTax,
		ApplicableRate: decimal.Zero,
		Details:        items,
	}, nil
}

func (s *taxIntegrationService) PreviewTaxes(ctx context.Context, req *TaxPreviewRequest) (*TaxPreviewResult, error) {
	result, err := s.calculateTaxesForEntity(ctx, req.CompanyID, "preview", uuid.Nil, req.LineItems, req.CustomerID, req.BillingAddress)
	if err != nil {
		return nil, err
	}
	return &TaxPreviewResult{
		TotalTax:            result.TotalTax,
		LineTaxes:           result.LineTaxes,
		TaxesByJurisdiction: result.TaxesByJurisdiction,
		ApplicableRates:     result.ApplicableRates,
		ExemptionsApplied:   result.ExemptionsApplied,
	}, nil
}

// ------------------------------------------------------------
// Apply and Persist (with optional transaction)
// ------------------------------------------------------------

// ApplyTaxesToOrder starts its own transaction.
func (s *taxIntegrationService) ApplyTaxesToOrder(ctx context.Context, companyID, orderID uuid.UUID, appliedBy uuid.UUID, idempotencyKey string) (*TaxCalculationResult, error) {
	return s.applyTaxesToEntity(ctx, nil, companyID, "order", orderID, appliedBy, idempotencyKey)
}

// ApplyTaxesToOrderWithTx uses the provided transaction.
func (s *taxIntegrationService) ApplyTaxesToOrderWithTx(ctx context.Context, tx *sql.Tx, companyID, orderID uuid.UUID, appliedBy uuid.UUID, idempotencyKey string) (*TaxCalculationResult, error) {
	return s.applyTaxesToEntity(ctx, tx, companyID, "order", orderID, appliedBy, idempotencyKey)
}

// ApplyTaxesToQuote starts its own transaction.
func (s *taxIntegrationService) ApplyTaxesToQuote(ctx context.Context, companyID, quoteID uuid.UUID, appliedBy uuid.UUID, idempotencyKey string) (*TaxCalculationResult, error) {
	return s.applyTaxesToEntity(ctx, nil, companyID, "quote", quoteID, appliedBy, idempotencyKey)
}

// ApplyTaxesToInvoice starts its own transaction.
func (s *taxIntegrationService) ApplyTaxesToInvoice(ctx context.Context, companyID, invoiceID uuid.UUID, appliedBy uuid.UUID, idempotencyKey string) (*TaxCalculationResult, error) {
	return s.applyTaxesToEntity(ctx, nil, companyID, "invoice", invoiceID, appliedBy, idempotencyKey)
}

// ApplyTaxesToInvoiceWithTx uses the provided transaction.
func (s *taxIntegrationService) ApplyTaxesToInvoiceWithTx(ctx context.Context, tx *sql.Tx, companyID, invoiceID uuid.UUID, appliedBy uuid.UUID, idempotencyKey string) (*TaxCalculationResult, error) {
	return s.applyTaxesToEntity(ctx, tx, companyID, "invoice", invoiceID, appliedBy, idempotencyKey)
}

func (s *taxIntegrationService) RefreshOrderTaxes(ctx context.Context, companyID, orderID uuid.UUID, updatedBy uuid.UUID, idempotencyKey string) error {
	_, err := s.applyTaxesToEntity(ctx, nil, companyID, "order", orderID, updatedBy, idempotencyKey)
	return err
}

func (s *taxIntegrationService) RefreshInvoiceTaxes(ctx context.Context, companyID, invoiceID uuid.UUID, updatedBy uuid.UUID, idempotencyKey string) error {
	_, err := s.applyTaxesToEntity(ctx, nil, companyID, "invoice", invoiceID, updatedBy, idempotencyKey)
	return err
}

// ------------------------------------------------------------
// Tax Snapshot Queries
// ------------------------------------------------------------

func (s *taxIntegrationService) GetOrderTaxBreakdown(ctx context.Context, companyID, orderID uuid.UUID) ([]*TaxBreakdownLine, error) {
	return s.getEntityTaxBreakdown(ctx, companyID, "order", orderID)
}

func (s *taxIntegrationService) GetInvoiceTaxBreakdown(ctx context.Context, companyID, invoiceID uuid.UUID) ([]*TaxBreakdownLine, error) {
	return s.getEntityTaxBreakdown(ctx, companyID, "invoice", invoiceID)
}

func (s *taxIntegrationService) GetQuoteTaxBreakdown(ctx context.Context, companyID, quoteID uuid.UUID) ([]*TaxBreakdownLine, error) {
	return s.getEntityTaxBreakdown(ctx, companyID, "quote", quoteID)
}

// ------------------------------------------------------------
// Tax Snapshot Management (with idempotency)
// ------------------------------------------------------------

func (s *taxIntegrationService) CreateTaxSnapshot(ctx context.Context, req *CreateTaxSnapshotRequest) (*models.TaxSnapshot, error) {
	snapshot := &models.TaxSnapshot{
		TaxSnapshotID: uuid.New(),
		CompanyID:     req.CompanyID,
		EntityType:    req.EntityType,
		EntityID:      req.EntityID,
		LineID:        req.LineID,
		TaxRateID:     req.TaxRateID,
		TaxName:       req.TaxName,
		TaxPercentage: req.TaxPercentage,
		TaxableAmount: req.TaxableAmount,
		TaxAmount:     req.TaxAmount,
	}
	db := s.pgClient.DB
	if err := s.taxSnapshotRepo.Create(ctx, db, snapshot); err != nil {
		return nil, err
	}
	return snapshot, nil
}

func (s *taxIntegrationService) GetTaxSnapshotByID(ctx context.Context, companyID, snapshotID uuid.UUID) (*models.TaxSnapshot, error) {
	db := s.pgClient.DB
	return s.taxSnapshotRepo.GetByID(ctx, db, companyID, snapshotID)
}

func (s *taxIntegrationService) GetLatestTaxSnapshot(ctx context.Context, companyID uuid.UUID, entityType string, entityID uuid.UUID) (*models.TaxSnapshot, error) {
	db := s.pgClient.DB
	snapshots, err := s.taxSnapshotRepo.GetByEntity(ctx, db, companyID, entityType, entityID)
	if err != nil {
		return nil, err
	}
	if len(snapshots) == 0 {
		return nil, salesErrors.ErrNotFound
	}
	return snapshots[len(snapshots)-1], nil
}

func (s *taxIntegrationService) GetTaxSnapshots(ctx context.Context, companyID uuid.UUID, entityType string, entityID uuid.UUID) ([]*models.TaxSnapshot, error) {
	db := s.pgClient.DB
	return s.taxSnapshotRepo.GetByEntity(ctx, db, companyID, entityType, entityID)
}

func (s *taxIntegrationService) RecalculateTaxSnapshot(ctx context.Context, companyID, snapshotID uuid.UUID, recalculatedBy uuid.UUID, idempotencyKey string) (*models.TaxSnapshot, error) {
	tx, err := s.pgClient.BeginTx(ctx, nil)
	if err != nil {
		return nil, err
	}
	defer tx.Rollback()

	var cached *models.TaxSnapshot
	if idempotencyKey != "" {
		if err := s.idempotencyStore.Get(ctx, tx, idempotencyKey, &cached); err == nil && cached != nil {
			s.logger.Info("idempotent – returning cached snapshot")
			return cached, nil
		}
		if err != nil && !isIdempotencyNotFound(err) {
			return nil, fmt.Errorf("idempotency check failed: %w", err)
		}
	}

	snapshot, err := s.taxSnapshotRepo.GetByIDForUpdate(ctx, tx, companyID, snapshotID)
	if err != nil {
		return nil, err
	}

	if snapshot.TaxPercentage == nil {
		return nil, fmt.Errorf("snapshot %s has no tax percentage stored, cannot recalculate", snapshotID)
	}

	newTax := snapshot.TaxableAmount.Mul(*snapshot.TaxPercentage).Div(decimal.NewFromInt(100))
	snapshot.TaxAmount = newTax

	if err := s.taxSnapshotRepo.Delete(ctx, tx, companyID, snapshotID); err != nil {
		return nil, err
	}
	if err := s.taxSnapshotRepo.Create(ctx, tx, snapshot); err != nil {
		return nil, err
	}

	if idempotencyKey != "" {
		_ = s.idempotencyStore.Store(ctx, tx, idempotencyKey, snapshot)
	}
	if err := tx.Commit(); err != nil {
		return nil, err
	}
	return snapshot, nil
}

func (s *taxIntegrationService) ArchiveTaxSnapshot(ctx context.Context, companyID, snapshotID uuid.UUID, archivedBy uuid.UUID, idempotencyKey string) error {
	tx, err := s.pgClient.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()

	var processed bool
	if idempotencyKey != "" {
		if err := s.idempotencyStore.Get(ctx, tx, idempotencyKey, &processed); err == nil && processed {
			return nil
		}
		if err != nil && !isIdempotencyNotFound(err) {
			return fmt.Errorf("idempotency check failed: %w", err)
		}
	}

	err = s.taxSnapshotRepo.Delete(ctx, tx, companyID, snapshotID)
	if err != nil {
		return err
	}
	if idempotencyKey != "" {
		_ = s.idempotencyStore.Store(ctx, tx, idempotencyKey, true)
	}
	return tx.Commit()
}

// ------------------------------------------------------------
// Existence Helpers
// ------------------------------------------------------------

func (s *taxIntegrationService) TaxSnapshotExists(ctx context.Context, companyID, snapshotID uuid.UUID) (bool, error) {
	db := s.pgClient.DB
	return s.taxSnapshotRepo.Exists(ctx, db, companyID, snapshotID)
}

// ------------------------------------------------------------
// Private Helpers
// ------------------------------------------------------------

// calculateTaxesForEntity performs tax calculation without persisting.
func (s *taxIntegrationService) calculateTaxesForEntity(ctx context.Context, companyID uuid.UUID, entityType string, entityID uuid.UUID, items []*LineItemInput, customerID *uuid.UUID, billingAddress *AddressInput) (*TaxCalculationResult, error) {
	if billingAddress == nil {
		billingAddress = &AddressInput{CountryCode: "US"}
	}
	if billingAddress.CountryCode == "" {
		billingAddress.CountryCode = "US"
	}

	var allLineDetails []TaxLineDetail
	totalTax := decimal.Zero
	perRateTaxable := make(map[string]decimal.Decimal)
	perRateTax := make(map[string]decimal.Decimal)

	for _, item := range items {
		input := s.buildTaxComputationInput(
			companyID,
			item.ProductID,
			item.LineAmount,
			item.TaxableAmount,
			customerID,
			billingAddress.CountryCode,
			&billingAddress.StateCode,
		)
		breakdownItems, err := s.accountingTaxEngine.ComputeTaxBreakdown(ctx, companyID, input)
		if err != nil {
			return nil, fmt.Errorf("failed to compute tax breakdown for product %s: %w", item.ProductID, err)
		}
		for _, ti := range breakdownItems {
			totalTax = totalTax.Add(ti.TaxAmount)
			allLineDetails = append(allLineDetails, TaxLineDetail{
				ProductID:     item.ProductID,
				LineAmount:    item.LineAmount,
				TaxableAmount: ti.TaxableAmount,
				TaxAmount:     ti.TaxAmount,
				TaxRateName:   ti.LineType,
			})
			rateName := ti.LineType
			perRateTaxable[rateName] = perRateTaxable[rateName].Add(ti.TaxableAmount)
			perRateTax[rateName] = perRateTax[rateName].Add(ti.TaxAmount)
		}
	}

	return &TaxCalculationResult{
		TotalTax:            totalTax,
		LineTaxes:           allLineDetails,
		TaxesByJurisdiction: perRateTax,
		ApplicableRates:     perRateTaxable,
		ExemptionsApplied:   false,
	}, nil
}

// applyTaxesToEntity is the core function that can accept an existing transaction.
// If tx is nil, it starts its own transaction.
func (s *taxIntegrationService) applyTaxesToEntity(ctx context.Context, tx *sql.Tx, companyID uuid.UUID, entityType string, entityID uuid.UUID, appliedBy uuid.UUID, idempotencyKey string) (*TaxCalculationResult, error) {
	var ownTx bool
	if tx == nil {
		var err error
		tx, err = s.pgClient.BeginTx(ctx, nil)
		if err != nil {
			return nil, err
		}
		ownTx = true
		defer tx.Rollback()
	}

	// Idempotency check
	if idempotencyKey != "" {
		var cached *TaxCalculationResult
		err := s.idempotencyStore.Get(ctx, tx, idempotencyKey, &cached)
		if err == nil && cached != nil {
			s.logger.Info("idempotent – returning cached result")
			return cached, nil
		}
		if err != nil && !isIdempotencyNotFound(err) {
			return nil, fmt.Errorf("idempotency check failed: %w", err)
		}
	}

	// Fetch entity details to build line items
	var lineItems []*LineItemInput
	var customerID *uuid.UUID
	var billingAddress *AddressInput
	var orderItems []*models.OrderItem
	var invoiceItems []*models.InvoiceItem

	switch entityType {
	case "order":
		order, err := s.orderRepo.GetByID(ctx, tx, companyID, entityID)
		if err != nil {
			return nil, err
		}
		customerID = &order.CustomerID
		billingAddress = s.parseAddressFromJSON(order.BillingAddress)
		items, err := s.orderRepo.GetItems(ctx, tx, companyID, entityID)
		if err != nil {
			return nil, err
		}
		orderItems = items
		for _, it := range items {
			subtotal := it.UnitPrice.Mul(it.Quantity)
			discount := decimal.Zero
			if it.DiscountAmount != nil {
				discount = *it.DiscountAmount
			}
			taxable := subtotal.Sub(discount)
			lineItems = append(lineItems, &LineItemInput{
				ProductID:     it.ProductID,
				Quantity:      it.Quantity,
				UnitPrice:     it.UnitPrice,
				LineAmount:    subtotal,
				TaxableAmount: taxable,
			})
		}
	case "quote":
		quote, err := s.quoteRepo.GetByID(ctx, tx, companyID, entityID)
		if err != nil {
			return nil, err
		}
		customerID = &quote.CustomerID
		cust, _ := s.customerRepo.GetByID(ctx, tx, companyID, *customerID)
		if cust != nil && cust.BillingAddress != nil {
			billingAddress = s.parseAddressFromString(*cust.BillingAddress)
		}
		items, err := s.quoteRepo.GetItems(ctx, tx, companyID, entityID)
		if err != nil {
			return nil, err
		}
		for _, it := range items {
			subtotal := it.UnitPrice.Mul(it.Quantity)
			// 🔧 FIXED: QuoteItem.DiscountAmount is a value type (decimal.Decimal)
			taxable := subtotal.Sub(it.DiscountAmount)
			lineItems = append(lineItems, &LineItemInput{
				ProductID:     it.ProductID,
				Quantity:      it.Quantity,
				UnitPrice:     it.UnitPrice,
				LineAmount:    subtotal,
				TaxableAmount: taxable,
			})
		}
	case "invoice":
		inv, err := s.invoiceRepo.GetByID(ctx, tx, companyID, entityID)
		if err != nil {
			return nil, err
		}
		customerID = &inv.CustomerID
		cust, _ := s.customerRepo.GetByID(ctx, tx, companyID, *customerID)
		if cust != nil && cust.BillingAddress != nil {
			billingAddress = s.parseAddressFromString(*cust.BillingAddress)
		}
		items, err := s.invoiceRepo.GetItems(ctx, tx, companyID, entityID)
		if err != nil {
			return nil, err
		}
		invoiceItems = items
		for _, it := range items {
			if it.ProductID == nil {
				continue
			}
			subtotal := it.UnitPrice.Mul(it.Quantity)
			discount := decimal.Zero
			if it.DiscountAmount != nil {
				discount = *it.DiscountAmount
			}
			taxable := subtotal.Sub(discount)
			lineItems = append(lineItems, &LineItemInput{
				ProductID:     *it.ProductID,
				Quantity:      it.Quantity,
				UnitPrice:     it.UnitPrice,
				LineAmount:    subtotal,
				TaxableAmount: taxable,
			})
		}
	default:
		return nil, fmt.Errorf("unsupported entity type: %s", entityType)
	}

	if billingAddress == nil {
		billingAddress = &AddressInput{CountryCode: "US"}
	}

	// Calculate taxes
	calcResult, err := s.calculateTaxesForEntity(ctx, companyID, entityType, entityID, lineItems, customerID, billingAddress)
	if err != nil {
		return nil, err
	}

	// Delete old tax snapshots
	_ = s.taxSnapshotRepo.DeleteByEntity(ctx, tx, companyID, entityType, entityID)

	// Create snapshots
	for rateName, taxAmount := range calcResult.TaxesByJurisdiction {
		taxableAmount := calcResult.ApplicableRates[rateName]
		snapshot := &models.TaxSnapshot{
			TaxSnapshotID: uuid.New(),
			CompanyID:     companyID,
			EntityType:    entityType,
			EntityID:      entityID,
			TaxName:       &rateName,
			TaxPercentage: nil,
			TaxableAmount: taxableAmount,
			TaxAmount:     taxAmount,
		}
		if err := s.taxSnapshotRepo.Create(ctx, tx, snapshot); err != nil {
			return nil, err
		}
	}

	// Build tax map
	taxMap := make(map[uuid.UUID]decimal.Decimal)
	for _, lt := range calcResult.LineTaxes {
		taxMap[lt.ProductID] = lt.TaxAmount
	}

	// Update order item tax amounts
	if entityType == "order" && len(orderItems) > 0 {
		for _, item := range orderItems {
			if taxAmt, ok := taxMap[item.ProductID]; ok {
				if err := s.orderRepo.UpdateItemTaxAmount(ctx, tx, item.OrderItemID, taxAmt); err != nil {
					return nil, fmt.Errorf("update order item tax amount: %w", err)
				}
			}
		}
	}

	// Update invoice item tax amounts
	if entityType == "invoice" && len(invoiceItems) > 0 {
		for _, item := range invoiceItems {
			if item.ProductID != nil {
				if taxAmt, ok := taxMap[*item.ProductID]; ok {
					if err := s.invoiceRepo.UpdateItemTaxAmount(ctx, tx, item.InvoiceItemID, taxAmt); err != nil {
						return nil, fmt.Errorf("update invoice item tax amount: %w", err)
					}
				}
			}
		}
	}

	// Update entity tax total
	switch entityType {
	case "order":
		if err := s.orderRepo.UpdateTaxTotal(ctx, tx, companyID, entityID, calcResult.TotalTax, &appliedBy); err != nil {
			return nil, err
		}
	case "invoice":
		if err := s.invoiceRepo.UpdateTaxTotal(ctx, tx, companyID, entityID, calcResult.TotalTax, &appliedBy); err != nil {
			return nil, err
		}
	case "quote":
		if err := s.quoteRepo.RecalculateTotals(ctx, tx, companyID, entityID); err != nil {
			return nil, err
		}
	}

	// Store idempotency
	if idempotencyKey != "" {
		_ = s.idempotencyStore.Store(ctx, tx, idempotencyKey, calcResult)
	}

	// Audit
	if s.auditService != nil {
		_ = s.auditService.LogAction(ctx, tx, &companyID, "sales", "apply_taxes", entityType,
			&entityID, "user", &appliedBy, nil, nil, map[string]interface{}{
				"total_tax": calcResult.TotalTax.String(),
				"rates":     calcResult.TaxesByJurisdiction,
			})
	}

	if ownTx {
		if err := tx.Commit(); err != nil {
			return nil, err
		}
	}
	return calcResult, nil
}

// getEntityTaxBreakdown uses a read‑only DB connection to fetch tax snapshots.
func (s *taxIntegrationService) getEntityTaxBreakdown(ctx context.Context, companyID uuid.UUID, entityType string, entityID uuid.UUID) ([]*TaxBreakdownLine, error) {
	db := s.pgClient.DB
	snapshots, err := s.taxSnapshotRepo.GetByEntity(ctx, db, companyID, entityType, entityID)
	if err != nil {
		return nil, err
	}
	lines := make([]*TaxBreakdownLine, len(snapshots))
	for i, snap := range snapshots {
		lines[i] = &TaxBreakdownLine{
			TaxName:       snap.TaxName,
			TaxPercentage: snap.TaxPercentage,
			TaxableAmount: snap.TaxableAmount,
			TaxAmount:     snap.TaxAmount,
		}
	}
	return lines, nil
}

// buildTaxComputationInput creates an accounting engine input from sales line data.
func (s *taxIntegrationService) buildTaxComputationInput(companyID, productID uuid.UUID, lineAmount, taxableAmount decimal.Decimal, customerID *uuid.UUID, countryCode string, stateCode *string) accountingService.TaxComputationInput {
	metadata := map[string]interface{}{
		"product_id":   productID.String(),
		"line_amount":  lineAmount,
		"country_code": countryCode,
	}
	if customerID != nil {
		metadata["customer_id"] = customerID.String()
	}
	if stateCode != nil {
		metadata["state_code"] = *stateCode
	}
	return accountingService.TaxComputationInput{
		Amount:          taxableAmount,
		Currency:        "USD",
		TransactionType: "sales",
		ProductType:     "product",
		CustomerType:    "customer",
		Jurisdiction:    countryCode,
		Date:            time.Now(),
		Metadata:        metadata,
	}
}

func (s *taxIntegrationService) parseAddressFromJSON(jsonb models.JSONB) *AddressInput {
	if jsonb == nil {
		return &AddressInput{CountryCode: "US"}
	}
	addr := &AddressInput{}
	if cc, ok := jsonb["countryCode"].(string); ok {
		addr.CountryCode = cc
	}
	if sc, ok := jsonb["stateCode"].(string); ok {
		addr.StateCode = sc
	}
	if pc, ok := jsonb["postalCode"].(string); ok {
		addr.PostalCode = pc
	}
	if addr.CountryCode == "" {
		addr.CountryCode = "US"
	}
	return addr
}

func (s *taxIntegrationService) parseAddressFromString(addrStr string) *AddressInput {
	// In a real implementation, you would parse JSON stored in the customer's billing_address column.
	// For simplicity, default to US.
	return &AddressInput{CountryCode: "US"}
}

// Helper to detect idempotency not found error
func isIdempotencyNotFound(err error) bool {
	if err == nil {
		return false
	}
	if err == sql.ErrNoRows {
		return true
	}
	return err.Error() == "idempotency: key not found"
}

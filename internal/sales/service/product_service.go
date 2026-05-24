// file: internal/sales/service/product_service.go
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
	"auth-service/internal/sales/repository"
)

// ProductService defines the interface for product management operations.
type ProductService interface {
	CreateProduct(ctx context.Context, req CreateProductRequest, idempotencyKey string) (*models.Product, error)
	UpdateProduct(ctx context.Context, companyID, productID uuid.UUID, req UpdateProductRequest, idempotencyKey string) (*models.Product, error)
	DeleteProduct(ctx context.Context, companyID, productID uuid.UUID, deletedBy *uuid.UUID, idempotencyKey string) error
	GetProductByID(ctx context.Context, companyID, productID uuid.UUID) (*models.Product, error)
	GetProductBySKU(ctx context.Context, companyID uuid.UUID, sku string) (*models.Product, error)
	ListProducts(ctx context.Context, filter ProductListFilter, p Pagination, s Sort) ([]*models.Product, int64, error)
	SearchProducts(ctx context.Context, companyID uuid.UUID, query string, limit, offset int) ([]*models.Product, int64, error)
	ActivateProduct(ctx context.Context, companyID, productID uuid.UUID, updatedBy *uuid.UUID, idempotencyKey string) error
	DeactivateProduct(ctx context.Context, companyID, productID uuid.UUID, updatedBy *uuid.UUID, idempotencyKey string) error
	IsProductActive(ctx context.Context, companyID, productID uuid.UUID) (bool, error)
	UpdateUnitPrice(ctx context.Context, companyID, productID uuid.UUID, unitPrice decimal.Decimal, updatedBy *uuid.UUID, idempotencyKey string) error
	GetUnitPrice(ctx context.Context, companyID, productID uuid.UUID) (decimal.Decimal, error)
	GetProductsByPriceRange(ctx context.Context, companyID uuid.UUID, minPrice, maxPrice *decimal.Decimal) ([]*models.Product, error)
	LinkInventoryItem(ctx context.Context, companyID, productID, inventoryItemID uuid.UUID, updatedBy *uuid.UUID, idempotencyKey string) error
	UnlinkInventoryItem(ctx context.Context, companyID, productID uuid.UUID, updatedBy *uuid.UUID, idempotencyKey string) error
	GetByInventoryItemID(ctx context.Context, companyID, inventoryItemID uuid.UUID) (*models.Product, error)
	GetTopSellingProducts(ctx context.Context, companyID uuid.UUID, limit int, from, to *time.Time) ([]*models.Product, error)
	GetProductsNeverSold(ctx context.Context, companyID uuid.UUID) ([]*models.Product, error)
	GetProductsWithReturns(ctx context.Context, companyID uuid.UUID, from, to *time.Time) ([]*models.Product, error)
	ValidateProduct(ctx context.Context, product *models.Product) error
	ProductExists(ctx context.Context, companyID, productID uuid.UUID) (bool, error)
	ProductSKUExists(ctx context.Context, companyID uuid.UUID, sku string) (bool, error)
}

type productService struct {
	productRepo      repository.ProductRepository
	pgClient         *client.PostgresClient
	outboxRepo       outbox.Repository
	idempotencyStore idempotency.Store
	auditService     *audit.AuditService
	logger           *zap.Logger
}

// NewProductService creates a new product service instance.
func NewProductService(
	productRepo repository.ProductRepository,
	pgClient *client.PostgresClient,
	outboxRepo outbox.Repository,
	idempotencyStore idempotency.Store,
	auditService *audit.AuditService,
	logger *zap.Logger,
) ProductService {
	return &productService{
		productRepo:      productRepo,
		pgClient:         pgClient,
		outboxRepo:       outboxRepo,
		idempotencyStore: idempotencyStore,
		auditService:     auditService,
		logger:           logger.Named("product_service"),
	}
}

// ----------------------------------------------------------------------------
// Core CRUD operations
// ----------------------------------------------------------------------------

func (s *productService) CreateProduct(ctx context.Context, req CreateProductRequest, idempotencyKey string) (*models.Product, error) {
	logger := s.logger.With(zap.String("method", "CreateProduct"), zap.String("idempotency_key", idempotencyKey))

	if err := s.validateCreateProduct(req); err != nil {
		return nil, err
	}

	tx, err := s.pgClient.BeginTx(ctx, nil)
	if err != nil {
		return nil, fmt.Errorf("begin tx: %w", err)
	}
	defer tx.Rollback()

	// Idempotency check
	var cached *models.Product
	if err := s.idempotencyStore.Get(ctx, tx, idempotencyKey, &cached); err == nil && cached != nil {
		logger.Info("idempotent – returning cached product")
		return cached, nil
	}

	// Check SKU uniqueness
	exists, err := s.productRepo.ExistsBySKU(ctx, tx, req.CompanyID, req.SKU)
	if err != nil {
		return nil, fmt.Errorf("check sku existence: %w", err)
	}
	if exists {
		return nil, fmt.Errorf("%w: sku %s already exists", salesErrors.ErrDuplicate, req.SKU)
	}

	isActive := true
	if req.IsActive != nil {
		isActive = *req.IsActive
	}

	product := &models.Product{
		ProductID:       uuid.New(),
		CompanyID:       req.CompanyID,
		SKU:             req.SKU,
		Name:            req.Name,
		Description:     req.Description,
		UnitPrice:       req.UnitPrice,
		IsActive:        isActive,
		InventoryItemID: req.InventoryItemID,
		CreatedBy:       req.CreatedBy,
		UpdatedBy:       req.CreatedBy,
	}

	if err := s.productRepo.Create(ctx, tx, product); err != nil {
		return nil, fmt.Errorf("create product: %w", err)
	}

	// Emit creation event
	if err := s.emitProductEvent(ctx, tx, product, salesEvents.EventProductCreated); err != nil {
		logger.Warn("failed to emit product created event", zap.Error(err))
	}

	// Store idempotency result
	_ = s.idempotencyStore.Store(ctx, tx, idempotencyKey, product)

	if err := tx.Commit(); err != nil {
		return nil, fmt.Errorf("commit tx: %w", err)
	}

	// Audit log
	if s.auditService != nil {
		_ = s.auditService.LogAction(ctx, nil, &req.CompanyID, "sales", "create_product", "product",
			&product.ProductID, "user", req.CreatedBy, nil, nil, map[string]interface{}{
				"sku":  product.SKU,
				"name": product.Name,
			})
	}

	return product, nil
}

func (s *productService) UpdateProduct(ctx context.Context, companyID, productID uuid.UUID, req UpdateProductRequest, idempotencyKey string) (*models.Product, error) {
	logger := s.logger.With(zap.String("method", "UpdateProduct"), zap.String("idempotency_key", idempotencyKey))

	if companyID == uuid.Nil || productID == uuid.Nil {
		return nil, salesErrors.ErrInvalidInput
	}

	tx, err := s.pgClient.BeginTx(ctx, nil)
	if err != nil {
		return nil, fmt.Errorf("begin tx: %w", err)
	}
	defer tx.Rollback()

	var cached *models.Product
	if err := s.idempotencyStore.Get(ctx, tx, idempotencyKey, &cached); err == nil && cached != nil {
		logger.Info("idempotent – returning cached product")
		return cached, nil
	}

	product, err := s.productRepo.GetByIDForUpdate(ctx, tx, companyID, productID)
	if err != nil {
		return nil, err
	}
	if product.CompanyID != companyID {
		return nil, salesErrors.ErrPermissionDenied
	}

	changes := make(map[string]interface{})
	emitPriceChanged := false

	if req.Name != nil && *req.Name != product.Name {
		changes["name"] = map[string]string{"old": product.Name, "new": *req.Name}
		product.Name = *req.Name
	}
	if req.Description != nil {
		product.Description = req.Description
	}
	if req.UnitPrice != nil && !req.UnitPrice.Equal(product.UnitPrice) {
		changes["unit_price"] = map[string]string{"old": product.UnitPrice.String(), "new": req.UnitPrice.String()}
		product.UnitPrice = *req.UnitPrice
		emitPriceChanged = true
	}
	if req.IsActive != nil && *req.IsActive != product.IsActive {
		changes["is_active"] = map[string]bool{"old": product.IsActive, "new": *req.IsActive}
		product.IsActive = *req.IsActive
	}
	if req.InventoryItemID != nil {
		old := product.InventoryItemID
		product.InventoryItemID = req.InventoryItemID
		changes["inventory_item_id"] = map[string]interface{}{
			"old": old,
			"new": req.InventoryItemID,
		}
	}

	product.UpdatedBy = req.UpdatedBy

	if err := s.productRepo.Update(ctx, tx, product); err != nil {
		return nil, fmt.Errorf("update product: %w", err)
	}

	// Emit appropriate events
	if err := s.emitProductEvent(ctx, tx, product, salesEvents.EventProductUpdated); err != nil {
		logger.Warn("failed to emit product updated event", zap.Error(err))
	}
	if emitPriceChanged {
		if err := s.emitProductEvent(ctx, tx, product, salesEvents.EventProductPriceChanged); err != nil {
			logger.Warn("failed to emit price changed event", zap.Error(err))
		}
	}
	if req.InventoryItemID != nil {
		if *req.InventoryItemID != uuid.Nil {
			_ = s.emitProductEvent(ctx, tx, product, salesEvents.EventProductInventoryLinked)
		} else {
			_ = s.emitProductEvent(ctx, tx, product, salesEvents.EventProductInventoryUnlinked)
		}
	}

	_ = s.idempotencyStore.Store(ctx, tx, idempotencyKey, product)

	if err := tx.Commit(); err != nil {
		return nil, fmt.Errorf("commit tx: %w", err)
	}

	if s.auditService != nil {
		_ = s.auditService.LogAction(ctx, nil, &companyID, "sales", "update_product", "product",
			&productID, "user", req.UpdatedBy, nil, nil, changes)
	}

	return product, nil
}

func (s *productService) DeleteProduct(ctx context.Context, companyID, productID uuid.UUID, deletedBy *uuid.UUID, idempotencyKey string) error {
	logger := s.logger.With(zap.String("method", "DeleteProduct"), zap.String("idempotency_key", idempotencyKey))

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

	product, err := s.productRepo.GetByID(ctx, tx, companyID, productID)
	if err != nil {
		return err
	}
	if product.CompanyID != companyID {
		return salesErrors.ErrPermissionDenied
	}

	// Check if product is referenced in any sales documents
	hasReferences, err := s.hasSalesReferences(ctx, tx, companyID, productID)
	if err != nil {
		return fmt.Errorf("check references: %w", err)
	}

	if hasReferences {
		// Soft delete: deactivate instead
		if product.IsActive {
			if err := s.productRepo.SetActiveStatus(ctx, tx, companyID, productID, false, deletedBy); err != nil {
				return fmt.Errorf("deactivate product: %w", err)
			}
			logger.Info("product has sales references, deactivated instead of hard delete")
		}
	} else {
		if err := s.productRepo.Delete(ctx, tx, companyID, productID); err != nil {
			return fmt.Errorf("delete product: %w", err)
		}
	}

	if err := s.emitProductEvent(ctx, tx, product, salesEvents.EventProductDeleted); err != nil {
		logger.Warn("failed to emit delete event", zap.Error(err))
	}

	_ = s.idempotencyStore.Store(ctx, tx, idempotencyKey, true)

	if err := tx.Commit(); err != nil {
		return fmt.Errorf("commit tx: %w", err)
	}

	if s.auditService != nil {
		_ = s.auditService.LogAction(ctx, nil, &companyID, "sales", "delete_product", "product",
			&productID, "user", deletedBy, nil, nil, nil)
	}

	return nil
}

// ----------------------------------------------------------------------------
// Queries
// ----------------------------------------------------------------------------

func (s *productService) GetProductByID(ctx context.Context, companyID, productID uuid.UUID) (*models.Product, error) {
	return s.productRepo.GetByID(ctx, nil, companyID, productID)
}

func (s *productService) GetProductBySKU(ctx context.Context, companyID uuid.UUID, sku string) (*models.Product, error) {
	return s.productRepo.GetBySKU(ctx, nil, companyID, sku)
}

func (s *productService) ListProducts(ctx context.Context, filter ProductListFilter, p Pagination, srt Sort) ([]*models.Product, int64, error) {
	repoFilter := repository.ProductFilter{
		CompanyID:        filter.CompanyID,
		IsActive:         filter.IsActive,
		HasInventoryItem: filter.InventoryLinked, // map InventoryLinked -> HasInventoryItem
		MinUnitPrice:     filter.MinPrice,
		MaxUnitPrice:     filter.MaxPrice,
		SearchTerm:       filter.Search,
	}
	return s.productRepo.List(ctx, nil, repoFilter,
		repository.Pagination{Limit: p.Limit, Offset: p.Offset},
		repository.Sort{Field: srt.Field, Direction: srt.Direction})
}
func (s *productService) SearchProducts(ctx context.Context, companyID uuid.UUID, query string, limit, offset int) ([]*models.Product, int64, error) {
	return s.productRepo.Search(ctx, nil, companyID, query, limit, offset)
}

func (s *productService) IsProductActive(ctx context.Context, companyID, productID uuid.UUID) (bool, error) {
	return s.productRepo.IsActive(ctx, nil, companyID, productID)
}

func (s *productService) GetUnitPrice(ctx context.Context, companyID, productID uuid.UUID) (decimal.Decimal, error) {
	return s.productRepo.GetUnitPrice(ctx, nil, companyID, productID)
}

func (s *productService) GetProductsByPriceRange(ctx context.Context, companyID uuid.UUID, minPrice, maxPrice *decimal.Decimal) ([]*models.Product, error) {
	return s.productRepo.GetProductsByPriceRange(ctx, nil, companyID, minPrice, maxPrice)
}

func (s *productService) GetByInventoryItemID(ctx context.Context, companyID, inventoryItemID uuid.UUID) (*models.Product, error) {
	return s.productRepo.GetByInventoryItemID(ctx, nil, companyID, inventoryItemID)
}

func (s *productService) GetTopSellingProducts(ctx context.Context, companyID uuid.UUID, limit int, from, to *time.Time) ([]*models.Product, error) {
	return s.productRepo.GetTopSellingProducts(ctx, nil, companyID, limit, from, to)
}

func (s *productService) GetProductsNeverSold(ctx context.Context, companyID uuid.UUID) ([]*models.Product, error) {
	return s.productRepo.GetProductsNeverSold(ctx, nil, companyID)
}

func (s *productService) GetProductsWithReturns(ctx context.Context, companyID uuid.UUID, from, to *time.Time) ([]*models.Product, error) {
	return s.productRepo.GetProductsWithReturns(ctx, nil, companyID, from, to)
}

func (s *productService) ProductExists(ctx context.Context, companyID, productID uuid.UUID) (bool, error) {
	return s.productRepo.Exists(ctx, nil, companyID, productID)
}

func (s *productService) ProductSKUExists(ctx context.Context, companyID uuid.UUID, sku string) (bool, error) {
	return s.productRepo.ExistsBySKU(ctx, nil, companyID, sku)
}

// ----------------------------------------------------------------------------
// State transitions
// ----------------------------------------------------------------------------

func (s *productService) ActivateProduct(ctx context.Context, companyID, productID uuid.UUID, updatedBy *uuid.UUID, idempotencyKey string) error {
	return s.setActiveStatus(ctx, companyID, productID, true, updatedBy, idempotencyKey, salesEvents.EventProductActivated)
}

func (s *productService) DeactivateProduct(ctx context.Context, companyID, productID uuid.UUID, updatedBy *uuid.UUID, idempotencyKey string) error {
	return s.setActiveStatus(ctx, companyID, productID, false, updatedBy, idempotencyKey, salesEvents.EventProductDeactivated)
}

func (s *productService) setActiveStatus(ctx context.Context, companyID, productID uuid.UUID, active bool, updatedBy *uuid.UUID, idempotencyKey, eventType string) error {
	tx, err := s.pgClient.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("begin tx: %w", err)
	}
	defer tx.Rollback()

	var processed bool
	if err := s.idempotencyStore.Get(ctx, tx, idempotencyKey, &processed); err == nil && processed {
		return nil
	}

	if err := s.productRepo.SetActiveStatus(ctx, tx, companyID, productID, active, updatedBy); err != nil {
		return err
	}

	product, _ := s.productRepo.GetByID(ctx, tx, companyID, productID)
	if product != nil {
		_ = s.emitProductEvent(ctx, tx, product, eventType)
	}

	_ = s.idempotencyStore.Store(ctx, tx, idempotencyKey, true)

	if err := tx.Commit(); err != nil {
		return fmt.Errorf("commit tx: %w", err)
	}
	return nil
}

func (s *productService) UpdateUnitPrice(ctx context.Context, companyID, productID uuid.UUID, unitPrice decimal.Decimal, updatedBy *uuid.UUID, idempotencyKey string) error {
	tx, err := s.pgClient.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("begin tx: %w", err)
	}
	defer tx.Rollback()

	var processed bool
	if err := s.idempotencyStore.Get(ctx, tx, idempotencyKey, &processed); err == nil && processed {
		return nil
	}

	product, err := s.productRepo.GetByIDForUpdate(ctx, tx, companyID, productID)
	if err != nil {
		return err
	}
	if product.CompanyID != companyID {
		return salesErrors.ErrPermissionDenied
	}

	if err := s.productRepo.UpdateUnitPrice(ctx, tx, companyID, productID, unitPrice, updatedBy); err != nil {
		return err
	}

	product.UnitPrice = unitPrice
	product.UpdatedBy = updatedBy
	_ = s.emitProductEvent(ctx, tx, product, salesEvents.EventProductPriceChanged)

	_ = s.idempotencyStore.Store(ctx, tx, idempotencyKey, true)

	if err := tx.Commit(); err != nil {
		return fmt.Errorf("commit tx: %w", err)
	}
	return nil
}

func (s *productService) LinkInventoryItem(ctx context.Context, companyID, productID, inventoryItemID uuid.UUID, updatedBy *uuid.UUID, idempotencyKey string) error {
	return s.updateInventoryLink(ctx, companyID, productID, &inventoryItemID, updatedBy, idempotencyKey, salesEvents.EventProductInventoryLinked)
}

func (s *productService) UnlinkInventoryItem(ctx context.Context, companyID, productID uuid.UUID, updatedBy *uuid.UUID, idempotencyKey string) error {
	return s.updateInventoryLink(ctx, companyID, productID, nil, updatedBy, idempotencyKey, salesEvents.EventProductInventoryUnlinked)
}

func (s *productService) updateInventoryLink(ctx context.Context, companyID, productID uuid.UUID, inventoryItemID *uuid.UUID, updatedBy *uuid.UUID, idempotencyKey, eventType string) error {
	tx, err := s.pgClient.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("begin tx: %w", err)
	}
	defer tx.Rollback()

	var processed bool
	if err := s.idempotencyStore.Get(ctx, tx, idempotencyKey, &processed); err == nil && processed {
		return nil
	}

	product, err := s.productRepo.GetByIDForUpdate(ctx, tx, companyID, productID)
	if err != nil {
		return err
	}
	if product.CompanyID != companyID {
		return salesErrors.ErrPermissionDenied
	}

	if err := s.productRepo.UpdateInventoryItemLink(ctx, tx, companyID, productID, inventoryItemID, updatedBy); err != nil {
		return err
	}

	product.InventoryItemID = inventoryItemID
	product.UpdatedBy = updatedBy
	_ = s.emitProductEvent(ctx, tx, product, eventType)

	_ = s.idempotencyStore.Store(ctx, tx, idempotencyKey, true)

	if err := tx.Commit(); err != nil {
		return fmt.Errorf("commit tx: %w", err)
	}
	return nil
}

// ----------------------------------------------------------------------------
// Validation & helpers
// ----------------------------------------------------------------------------

func (s *productService) ValidateProduct(ctx context.Context, product *models.Product) error {
	if product.SKU == "" {
		return fmt.Errorf("%w: sku required", salesErrors.ErrInvalidInput)
	}
	if product.Name == "" {
		return fmt.Errorf("%w: name required", salesErrors.ErrInvalidInput)
	}
	if product.UnitPrice.IsNegative() {
		return fmt.Errorf("%w: unit_price cannot be negative", salesErrors.ErrInvalidInput)
	}
	return nil
}

func (s *productService) validateCreateProduct(req CreateProductRequest) error {
	if req.CompanyID == uuid.Nil {
		return fmt.Errorf("%w: company_id required", salesErrors.ErrInvalidInput)
	}
	if req.SKU == "" {
		return fmt.Errorf("%w: sku required", salesErrors.ErrInvalidInput)
	}
	if req.Name == "" {
		return fmt.Errorf("%w: name required", salesErrors.ErrInvalidInput)
	}
	if req.UnitPrice.IsNegative() {
		return fmt.Errorf("%w: unit_price cannot be negative", salesErrors.ErrInvalidInput)
	}
	return nil
}

func (s *productService) hasSalesReferences(ctx context.Context, tx repository.DBTX, companyID, productID uuid.UUID) (bool, error) {
	var count int
	query := `
		SELECT EXISTS (
			SELECT 1 FROM sales.order_items WHERE company_id = $1 AND product_id = $2
			UNION ALL
			SELECT 1 FROM sales.invoice_items WHERE company_id = $1 AND product_id = $2
			UNION ALL
			SELECT 1 FROM sales.return_items WHERE company_id = $1 AND product_id = $2
			UNION ALL
			SELECT 1 FROM sales.quote_items WHERE company_id = $1 AND product_id = $2
		)`
	err := tx.QueryRowContext(ctx, query, companyID, productID).Scan(&count)
	if err != nil && err != sql.ErrNoRows {
		return false, err
	}
	return count > 0, nil
}

// ----------------------------------------------------------------------------
// Event emission
// ----------------------------------------------------------------------------

func (s *productService) emitProductEvent(ctx context.Context, tx repository.DBTX, product *models.Product, eventType string) error {
	sqlTx, ok := tx.(*sql.Tx)
	if !ok {
		return fmt.Errorf("tx is not a *sql.Tx")
	}

	payload := salesEvents.ProductPayload{
		ProductID:       product.ProductID.String(),
		CompanyID:       product.CompanyID.String(),
		SKU:             product.SKU,
		Name:            product.Name,
		UnitPrice:       product.UnitPrice.String(),
		IsActive:        product.IsActive,
		InventoryItemID: uuid.Nil.String(),
	}
	if product.InventoryItemID != nil {
		payload.InventoryItemID = product.InventoryItemID.String()
	}

	data, err := json.Marshal(payload)
	if err != nil {
		return err
	}

	event := &outbox.Event{
		EventID:       uuid.New().String(),
		AggregateType: "product",
		AggregateID:   product.ProductID.String(),
		EventType:     eventType,
		Topic:         salesEvents.TopicSalesEvents,
		Payload:       data,
	}
	return s.outboxRepo.Store(ctx, sqlTx, event)
}

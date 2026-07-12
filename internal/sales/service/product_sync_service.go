package service

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"

	"github.com/google/uuid"
	"github.com/shopspring/decimal"
	"go.uber.org/zap"

	salesErrors "auth-service/internal/sales/errors"
	subEvents "auth-service/internal/subscription/events"
)

// ProductSyncService implements consumer.SubscriptionAnalyticsService.
// It listens to subscription-events and syncs Product catalog from Plan Items.
type ProductSyncService struct {
	productSvc      ProductService
	planItemUpdater PlanItemUpdater
	logger          *zap.Logger
}

// NewProductSyncService creates a new ProductSyncService.
func NewProductSyncService(
	productSvc ProductService,
	planItemUpdater PlanItemUpdater,
	logger *zap.Logger,
) *ProductSyncService {
	return &ProductSyncService{
		productSvc:      productSvc,
		planItemUpdater: planItemUpdater,
		logger:          logger.Named("product_sync_service"),
	}
}

// SetPlanItemUpdater updates the updater used for back‑linking.
// This allows late injection after the service is created.
func (s *ProductSyncService) SetPlanItemUpdater(updater PlanItemUpdater) {
	s.planItemUpdater = updater
}

// ProcessSubscriptionEvent handles incoming subscription events.
func (s *ProductSyncService) ProcessSubscriptionEvent(ctx context.Context, eventType string, payload []byte) error {
	logger := s.logger.With(zap.String("event_type", eventType))

	switch eventType {
	case subEvents.EventPlanItemCreated,
		subEvents.EventPlanItemUpdated,
		subEvents.EventPlanItemRestored,
		subEvents.EventPlanItemPriceUpdated:
		var p subEvents.PlanItemPayload
		if err := json.Unmarshal(payload, &p); err != nil {
			return fmt.Errorf("unmarshal plan item payload: %w", err)
		}
		return s.syncProductFromPlanItem(ctx, p)

	case subEvents.EventPlanItemActivated:
		var p subEvents.PlanItemPayload
		if err := json.Unmarshal(payload, &p); err != nil {
			return err
		}
		return s.activateProduct(ctx, p)

	case subEvents.EventPlanItemDeactivated:
		var p subEvents.PlanItemPayload
		if err := json.Unmarshal(payload, &p); err != nil {
			return err
		}
		return s.deactivateProduct(ctx, p)

	case subEvents.EventPlanItemDeleted:
		var p subEvents.PlanItemPayload
		if err := json.Unmarshal(payload, &p); err != nil {
			return err
		}
		return s.archiveProduct(ctx, p)

	default:
		logger.Debug("ignoring event type (not a plan item event)")
		return nil
	}
}

// syncProductFromPlanItem creates or updates a product and back‑links the product ID.
func (s *ProductSyncService) syncProductFromPlanItem(ctx context.Context, payload subEvents.PlanItemPayload) error {
	logger := s.logger.With(
		zap.String("plan_item_id", payload.PlanItemID),
		zap.String("plan_id", payload.PlanID),
	)

	companyID, err := uuid.Parse(payload.CompanyID)
	if err != nil {
		return fmt.Errorf("invalid company_id: %w", err)
	}

	price, err := decimal.NewFromString(payload.Price)
	if err != nil {
		return fmt.Errorf("invalid price: %w", err)
	}

	var taxRate *decimal.Decimal
	if payload.TaxRate != nil && *payload.TaxRate != "" {
		tr, err := decimal.NewFromString(*payload.TaxRate)
		if err == nil && tr.GreaterThan(decimal.Zero) {
			taxRate = &tr
		}
	}

	sku := "PLANITEM-" + payload.PlanItemID

	// Check if product already exists
	existing, err := s.productSvc.GetProductBySKU(ctx, companyID, sku)
	if err != nil && !errors.Is(err, salesErrors.ErrNotFound) {
		return fmt.Errorf("get product by SKU: %w", err)
	}

	desc := ""
	if payload.Description != nil {
		desc = *payload.Description
	}

	planItemID, err := uuid.Parse(payload.PlanItemID)
	if err != nil {
		return fmt.Errorf("invalid plan_item_id: %w", err)
	}

	if existing != nil {
		// Update existing product
		req := UpdateProductRequest{
			Name:        &payload.Name,
			Description: &desc,
			UnitPrice:   &price,
			IsActive:    &payload.IsActive,
			TaxRate:     taxRate,
		}
		_, err = s.productSvc.UpdateProduct(ctx, companyID, existing.ProductID, req)
		if err != nil {
			return fmt.Errorf("update product: %w", err)
		}
		logger.Info("updated product from plan item",
			zap.String("product_id", existing.ProductID.String()),
		)
		// Ensure product is linked (if not already)
		if payload.ProductID == nil || *payload.ProductID == "" {
			// Try to link (idempotent)
			if err := s.planItemUpdater.UpdatePlanItemProductID(ctx, planItemID, existing.ProductID); err != nil {
				logger.Error("failed to back‑link product ID after update", zap.Error(err))
				return fmt.Errorf("back‑link after update: %w", err)
			}
		}
		return nil
	}

	// Create new product
	isActive := payload.IsActive
	req := CreateProductRequest{
		CompanyID:   companyID,
		SKU:         sku,
		Name:        payload.Name,
		Description: &desc,
		UnitPrice:   price,
		IsActive:    &isActive,
		TaxRate:     taxRate,
	}
	product, err := s.productSvc.CreateProduct(ctx, req)
	if err != nil {
		return fmt.Errorf("create product: %w", err)
	}

	logger.Info("created product from plan item",
		zap.String("product_id", product.ProductID.String()),
	)

	// 🔥 CRITICAL: Back‑link the product ID to the plan item
	if err := s.planItemUpdater.UpdatePlanItemProductID(ctx, planItemID, product.ProductID); err != nil {
		// Log error but do not fail the whole event? We should retry, so return error.
		logger.Error("failed to back‑link product ID to plan item", zap.Error(err))
		return fmt.Errorf("back‑link product ID: %w", err)
	}

	logger.Info("successfully back‑linked product ID to plan item")
	return nil
}

// activateProduct activates the corresponding product.
func (s *ProductSyncService) activateProduct(ctx context.Context, payload subEvents.PlanItemPayload) error {
	companyID, _ := uuid.Parse(payload.CompanyID)
	sku := "PLANITEM-" + payload.PlanItemID
	product, err := s.productSvc.GetProductBySKU(ctx, companyID, sku)
	if err != nil {
		if errors.Is(err, salesErrors.ErrNotFound) {
			return s.syncProductFromPlanItem(ctx, payload)
		}
		return err
	}
	return s.productSvc.ActivateProduct(ctx, companyID, product.ProductID, nil)
}

// deactivateProduct deactivates the corresponding product.
func (s *ProductSyncService) deactivateProduct(ctx context.Context, payload subEvents.PlanItemPayload) error {
	companyID, _ := uuid.Parse(payload.CompanyID)
	sku := "PLANITEM-" + payload.PlanItemID
	product, err := s.productSvc.GetProductBySKU(ctx, companyID, sku)
	if err != nil {
		if errors.Is(err, salesErrors.ErrNotFound) {
			return nil
		}
		return err
	}
	return s.productSvc.DeactivateProduct(ctx, companyID, product.ProductID, nil)
}

// archiveProduct soft-deletes the corresponding product.
func (s *ProductSyncService) archiveProduct(ctx context.Context, payload subEvents.PlanItemPayload) error {
	companyID, _ := uuid.Parse(payload.CompanyID)
	sku := "PLANITEM-" + payload.PlanItemID
	product, err := s.productSvc.GetProductBySKU(ctx, companyID, sku)
	if err != nil {
		if errors.Is(err, salesErrors.ErrNotFound) {
			return nil
		}
		return err
	}
	return s.productSvc.DeleteProduct(ctx, companyID, product.ProductID, nil)
}

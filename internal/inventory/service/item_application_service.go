package service

import (
	"context"

	"github.com/google/uuid"
	"go.uber.org/zap"

	"auth-service/internal/inventory/inventory_errors"
	"auth-service/internal/inventory/models"
	"auth-service/internal/inventory/repository"
)

// ItemApplicationService defines the interface for item operations (both commands and queries).
type ItemApplicationService interface {
	CreateItem(ctx context.Context, req CreateItemRequest, idempotencyKey string) (*models.Item, error)
	UpdateItem(ctx context.Context, req UpdateItemRequest, idempotencyKey string) (*models.Item, error)
	DeleteItem(ctx context.Context, companyID, itemID uuid.UUID, deletedBy *uuid.UUID, idempotencyKey string) error

	GetItemByID(ctx context.Context, companyID, itemID uuid.UUID) (*models.Item, error)
	ListItems(ctx context.Context, companyID uuid.UUID, filter ItemFilter, pagination repository.Pagination, sort repository.Sort) ([]*models.Item, int64, error)
	GetLowStockItems(ctx context.Context, companyID uuid.UUID) ([]*repository.ReorderItem, error)
}

// ItemFilter mirrors the handler's filter but uses repository types.
type ItemFilter struct {
	SKU      *string
	Name     *string
	ItemType *string // use string for simplicity, can be enums.ItemType if needed
	IsActive *bool
}

type itemApplicationService struct {
	writeSvc InventoryService          // the existing service for mutations
	readRepo repository.ItemRepository // for direct queries
	querySvc InventoryQueryService     // optional, for low stock etc.
	db       repository.DBTX
	logger   *zap.Logger
}

// NewItemApplicationService creates a new ItemApplicationService.
func NewItemApplicationService(
	writeSvc InventoryService,
	readRepo repository.ItemRepository,
	querySvc InventoryQueryService,
	db repository.DBTX,
	logger *zap.Logger,
) ItemApplicationService {
	return &itemApplicationService{
		writeSvc: writeSvc,
		readRepo: readRepo,
		querySvc: querySvc,
		db:       db,
		logger:   logger.Named("item_application_service"),
	}
}

// CreateItem delegates to the underlying InventoryService.
func (s *itemApplicationService) CreateItem(ctx context.Context, req CreateItemRequest, idempotencyKey string) (*models.Item, error) {
	return s.writeSvc.CreateItem(ctx, req, idempotencyKey)
}

// UpdateItem delegates to the underlying InventoryService.
func (s *itemApplicationService) UpdateItem(ctx context.Context, req UpdateItemRequest, idempotencyKey string) (*models.Item, error) {
	return s.writeSvc.UpdateItem(ctx, req, idempotencyKey)
}

// DeleteItem delegates to the underlying InventoryService.
func (s *itemApplicationService) DeleteItem(ctx context.Context, companyID, itemID uuid.UUID, deletedBy *uuid.UUID, idempotencyKey string) error {
	return s.writeSvc.DeleteItem(ctx, companyID, itemID, deletedBy, idempotencyKey)
}

// GetItemByID retrieves an item with company ownership check.
func (s *itemApplicationService) GetItemByID(ctx context.Context, companyID, itemID uuid.UUID) (*models.Item, error) {
	item, err := s.readRepo.GetByID(ctx, s.db, itemID)
	if err != nil {
		return nil, err
	}
	if item.CompanyID != companyID {
		return nil, inventory_errors.ErrPermissionDenied
	}
	return item, nil
}

// ListItems returns paginated items with filtering.
func (s *itemApplicationService) ListItems(ctx context.Context, companyID uuid.UUID, filter ItemFilter, pagination repository.Pagination, sort repository.Sort) ([]*models.Item, int64, error) {
	repoFilter := repository.ItemFilter{
		CompanyID: companyID,
		IsActive:  filter.IsActive,
	}
	if filter.SKU != nil {
		repoFilter.Search = *filter.SKU // approximate; for exact SKU you'd need a different field
	}
	if filter.Name != nil {
		repoFilter.Search = *filter.Name
	}
	if filter.ItemType != nil {
		repoFilter.ItemType = filter.ItemType
	}
	items, err := s.readRepo.List(ctx, s.db, repoFilter, pagination, sort)
	if err != nil {
		return nil, 0, err
	}
	total, err := s.readRepo.Count(ctx, s.db, repoFilter)
	if err != nil {
		return nil, 0, err
	}
	return items, total, nil
}

// GetLowStockItems uses the inventory query service (or the item repository directly) to return items needing reorder.
func (s *itemApplicationService) GetLowStockItems(ctx context.Context, companyID uuid.UUID) ([]*repository.ReorderItem, error) {
	if s.querySvc != nil {
		return s.querySvc.GetLowStockItems(ctx, companyID)
	}
	// Fallback to the item repository's method
	return s.readRepo.GetLowStockItems(ctx, s.db, companyID)
}

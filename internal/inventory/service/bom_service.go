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
	"auth-service/internal/inventory/events"
	"auth-service/internal/inventory/inventory_errors"
	"auth-service/internal/inventory/models"
	"auth-service/internal/inventory/repository"
)

// BOMService defines the interface for BOM operations.
type BOMService interface {
	Create(ctx context.Context, req CreateBOMRequest, idempotencyKey string) (*models.BOM, error)
	GetByID(ctx context.Context, bomID, companyID uuid.UUID) (*models.BOM, error)
	Update(ctx context.Context, req UpdateBOMRequest, idempotencyKey string) (*models.BOM, error)
	Delete(ctx context.Context, bomID, companyID uuid.UUID, idempotencyKey string) error
	List(ctx context.Context, companyID uuid.UUID, filter BOMFilter, pagination repository.Pagination, sort repository.Sort) ([]*models.BOM, int64, error)
	GetByProductItemID(ctx context.Context, companyID, productItemID uuid.UUID) ([]*models.BOM, error)

	AddBOMItem(ctx context.Context, req AddBOMItemRequest, idempotencyKey string) (*models.BOMItem, error)
	UpdateBOMItem(ctx context.Context, req UpdateBOMItemRequest, idempotencyKey string) (*models.BOMItem, error)
	RemoveBOMItem(ctx context.Context, bomItemID, companyID uuid.UUID, idempotencyKey string) error
	GetBOMItems(ctx context.Context, bomID, companyID uuid.UUID) ([]*models.BOMItem, error)
}

// Request types for BOM operations.
type CreateBOMRequest struct {
	CompanyID     uuid.UUID
	ProductItemID uuid.UUID
	BOMCode       string
	Name          string
	Version       int
	Quantity      decimal.Decimal
	IsActive      bool
	CreatedBy     *uuid.UUID
}

type UpdateBOMRequest struct {
	BOMID         uuid.UUID
	CompanyID     uuid.UUID
	ProductItemID *uuid.UUID
	BOMCode       *string
	Name          *string
	Version       *int
	Quantity      *decimal.Decimal
	IsActive      *bool
	UpdatedBy     *uuid.UUID
}

type AddBOMItemRequest struct {
	CompanyID       uuid.UUID
	BOMID           uuid.UUID
	ComponentItemID uuid.UUID
	Quantity        decimal.Decimal
	ScrapPercentage *decimal.Decimal
	CreatedBy       *uuid.UUID
}

type UpdateBOMItemRequest struct {
	BOMItemID       uuid.UUID
	CompanyID       uuid.UUID
	Quantity        *decimal.Decimal
	ScrapPercentage *decimal.Decimal
}

type BOMFilter struct {
	IsActive *bool
}

type bomService struct {
	bomRepo          repository.BOMRepository
	itemRepo         repository.ItemRepository
	pgClient         *client.PostgresClient
	outboxRepo       outbox.Repository
	idempotencyStore idempotency.Store
	auditService     *audit.AuditService
	logger           *zap.Logger
}

// NewBOMService creates a new BOMService.
func NewBOMService(
	bomRepo repository.BOMRepository,
	itemRepo repository.ItemRepository,
	pgClient *client.PostgresClient,
	outboxRepo outbox.Repository,
	idempotencyStore idempotency.Store,
	auditService *audit.AuditService,
	logger *zap.Logger,
) BOMService {
	return &bomService{
		bomRepo:          bomRepo,
		itemRepo:         itemRepo,
		pgClient:         pgClient,
		outboxRepo:       outboxRepo,
		idempotencyStore: idempotencyStore,
		auditService:     auditService,
		logger:           logger.Named("bom_service"),
	}
}

// Create a new BOM.
func (s *bomService) Create(ctx context.Context, req CreateBOMRequest, idempotencyKey string) (*models.BOM, error) {
	logger := s.logger.With(zap.String("method", "Create"), zap.String("idempotency_key", idempotencyKey))

	if err := s.validateCreateBOM(req); err != nil {
		return nil, err
	}

	tx, err := s.pgClient.BeginTx(ctx, nil)
	if err != nil {
		return nil, fmt.Errorf("begin tx: %w", err)
	}
	defer tx.Rollback()

	// 1. Idempotency check
	var cached *models.BOM
	if err := s.idempotencyStore.Get(ctx, tx, idempotencyKey, &cached); err == nil && cached != nil {
		logger.Info("idempotent request – returning cached BOM")
		return cached, nil
	}

	// 2. Duplicate check: BOM with same company, product, version already exists?
	exists, err := s.bomRepo.ExistsBOMByProductAndVersion(ctx, tx, req.CompanyID, req.ProductItemID, req.Version)
	if err != nil {
		return nil, fmt.Errorf("check BOM existence: %w", err)
	}
	if exists {
		return nil, fmt.Errorf("%w: BOM with version %d for product %s already exists",
			inventory_errors.ErrDuplicate, req.Version, req.ProductItemID)
	}

	// 3. Validate product item exists
	exists, err = s.itemRepo.ExistsByID(ctx, tx, req.ProductItemID)
	if err != nil {
		return nil, fmt.Errorf("check product item: %w", err)
	}
	if !exists {
		return nil, fmt.Errorf("%w: product item %s not found", inventory_errors.ErrInvalidInput, req.ProductItemID)
	}

	now := time.Now()
	bom := &models.BOM{
		BOMID:         uuid.New(),
		CompanyID:     req.CompanyID,
		ProductItemID: req.ProductItemID,
		BOMCode:       req.BOMCode,
		Name:          req.Name,
		Version:       req.Version,
		Quantity:      req.Quantity,
		IsActive:      req.IsActive,
		CreatedAt:     now,
		UpdatedAt:     now,
		CreatedBy:     req.CreatedBy,
		UpdatedBy:     req.CreatedBy,
	}

	if err := s.bomRepo.CreateBOM(ctx, tx, bom); err != nil {
		return nil, fmt.Errorf("create BOM: %w", err)
	}

	// Emit event
	if err := s.emitBOMEvent(ctx, tx, bom, events.EventBOMCreated); err != nil {
		logger.Warn("failed to emit BOM created event", zap.Error(err))
	}

	_ = s.idempotencyStore.Store(ctx, tx, idempotencyKey, bom)

	if err := tx.Commit(); err != nil {
		return nil, fmt.Errorf("commit tx: %w", err)
	}

	if s.auditService != nil {
		_ = s.auditService.LogAction(ctx, nil, &req.CompanyID, "inventory", "create_bom", "bom",
			&bom.BOMID, "user", req.CreatedBy, nil, nil, map[string]interface{}{
				"bom_code": bom.BOMCode,
				"product":  bom.ProductItemID.String(),
			})
	}

	logger.Info("BOM created", zap.String("bom_id", bom.BOMID.String()))
	return bom, nil
}

// GetByID retrieves a BOM by ID, checking company ownership.
func (s *bomService) GetByID(ctx context.Context, bomID, companyID uuid.UUID) (*models.BOM, error) {
	bom, err := s.bomRepo.GetBOMByID(ctx, s.pgClient.DB, bomID)
	if err != nil {
		return nil, err
	}
	if bom.CompanyID != companyID {
		return nil, inventory_errors.ErrPermissionDenied
	}
	return bom, nil
}

// Update modifies an existing BOM with duplicate version check.
func (s *bomService) Update(ctx context.Context, req UpdateBOMRequest, idempotencyKey string) (*models.BOM, error) {
	logger := s.logger.With(zap.String("method", "Update"), zap.String("idempotency_key", idempotencyKey))

	tx, err := s.pgClient.BeginTx(ctx, nil)
	if err != nil {
		return nil, fmt.Errorf("begin tx: %w", err)
	}
	defer tx.Rollback()

	var cached *models.BOM
	if err := s.idempotencyStore.Get(ctx, tx, idempotencyKey, &cached); err == nil && cached != nil {
		logger.Info("idempotent – returning cached BOM")
		return cached, nil
	}

	bom, err := s.bomRepo.GetBOMByID(ctx, tx, req.BOMID)
	if err != nil {
		return nil, err
	}
	if bom.CompanyID != req.CompanyID {
		return nil, inventory_errors.ErrPermissionDenied
	}

	// Apply updates
	if req.ProductItemID != nil {
		if exists, err := s.itemRepo.ExistsByID(ctx, tx, *req.ProductItemID); err != nil || !exists {
			return nil, fmt.Errorf("%w: product item %s not found", inventory_errors.ErrInvalidInput, *req.ProductItemID)
		}
		bom.ProductItemID = *req.ProductItemID
	}
	if req.BOMCode != nil {
		bom.BOMCode = *req.BOMCode
	}
	if req.Name != nil {
		bom.Name = *req.Name
	}
	// Version change requires uniqueness check
	if req.Version != nil && *req.Version != bom.Version {
		exists, err := s.bomRepo.ExistsBOMByProductAndVersion(ctx, tx, bom.CompanyID, bom.ProductItemID, *req.Version)
		if err != nil {
			return nil, fmt.Errorf("check version uniqueness: %w", err)
		}
		if exists {
			return nil, fmt.Errorf("%w: BOM with version %d for product %s already exists",
				inventory_errors.ErrDuplicate, *req.Version, bom.ProductItemID)
		}
		bom.Version = *req.Version
	}
	if req.Quantity != nil {
		if req.Quantity.LessThanOrEqual(decimal.Zero) {
			return nil, fmt.Errorf("%w: quantity must be positive", inventory_errors.ErrInvalidInput)
		}
		bom.Quantity = *req.Quantity
	}
	if req.IsActive != nil {
		bom.IsActive = *req.IsActive
	}
	bom.UpdatedBy = req.UpdatedBy
	bom.UpdatedAt = time.Now()

	if err := s.bomRepo.UpdateBOM(ctx, tx, bom); err != nil {
		return nil, fmt.Errorf("update BOM: %w", err)
	}

	if err := s.emitBOMEvent(ctx, tx, bom, events.EventBOMUpdated); err != nil {
		logger.Warn("failed to emit BOM updated event", zap.Error(err))
	}

	_ = s.idempotencyStore.Store(ctx, tx, idempotencyKey, bom)

	if err := tx.Commit(); err != nil {
		return nil, fmt.Errorf("commit tx: %w", err)
	}

	if s.auditService != nil {
		_ = s.auditService.LogAction(ctx, nil, &req.CompanyID, "inventory", "update_bom", "bom",
			&bom.BOMID, "user", req.UpdatedBy, nil, nil, nil)
	}

	return bom, nil
}

// Delete deactivates a BOM (soft delete by setting is_active=false).
func (s *bomService) Delete(ctx context.Context, bomID, companyID uuid.UUID, idempotencyKey string) error {
	logger := s.logger.With(zap.String("method", "Delete"), zap.String("idempotency_key", idempotencyKey))

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

	bom, err := s.bomRepo.GetBOMByID(ctx, tx, bomID)
	if err != nil {
		return err
	}
	if bom.CompanyID != companyID {
		return inventory_errors.ErrPermissionDenied
	}

	if err := s.bomRepo.DeactivateBOM(ctx, tx, bomID); err != nil {
		return fmt.Errorf("deactivate BOM: %w", err)
	}

	if err := s.emitBOMEvent(ctx, tx, bom, events.EventBOMDeleted); err != nil {
		logger.Warn("failed to emit BOM deleted event", zap.Error(err))
	}

	_ = s.idempotencyStore.Store(ctx, tx, idempotencyKey, true)

	if err := tx.Commit(); err != nil {
		return fmt.Errorf("commit tx: %w", err)
	}

	if s.auditService != nil {
		_ = s.auditService.LogAction(ctx, nil, &companyID, "inventory", "delete_bom", "bom",
			&bomID, "system", nil, nil, nil, nil)
	}

	return nil
}

// List returns paginated BOMs with filtering.
func (s *bomService) List(ctx context.Context, companyID uuid.UUID, filter BOMFilter, pagination repository.Pagination, sort repository.Sort) ([]*models.BOM, int64, error) {
	repoFilter := repository.BOMFilter{
		CompanyID: companyID,
		IsActive:  filter.IsActive,
	}
	return s.bomRepo.ListBOMs(ctx, s.pgClient.DB, repoFilter, pagination, sort)
}

// GetByProductItemID returns all BOM versions for a product.
func (s *bomService) GetByProductItemID(ctx context.Context, companyID, productItemID uuid.UUID) ([]*models.BOM, error) {
	return s.bomRepo.GetBOMVersions(ctx, s.pgClient.DB, companyID, productItemID)
}

// AddBOMItem adds a component to a BOM (with circular reference check).
func (s *bomService) AddBOMItem(ctx context.Context, req AddBOMItemRequest, idempotencyKey string) (*models.BOMItem, error) {
	logger := s.logger.With(zap.String("method", "AddBOMItem"), zap.String("idempotency_key", idempotencyKey))

	// Validate quantity > 0
	if req.Quantity.LessThanOrEqual(decimal.Zero) {
		return nil, fmt.Errorf("%w: quantity must be positive", inventory_errors.ErrInvalidInput)
	}
	// Validate scrap percentage >= 0 if provided
	if req.ScrapPercentage != nil && req.ScrapPercentage.LessThan(decimal.Zero) {
		return nil, fmt.Errorf("%w: scrap_percentage cannot be negative", inventory_errors.ErrInvalidInput)
	}

	tx, err := s.pgClient.BeginTx(ctx, nil)
	if err != nil {
		return nil, fmt.Errorf("begin tx: %w", err)
	}
	defer tx.Rollback()

	var cached *models.BOMItem
	if err := s.idempotencyStore.Get(ctx, tx, idempotencyKey, &cached); err == nil && cached != nil {
		logger.Info("idempotent – returning cached BOM item")
		return cached, nil
	}

	// Verify BOM belongs to company and is active
	bom, err := s.bomRepo.GetBOMByID(ctx, tx, req.BOMID)
	if err != nil {
		return nil, err
	}
	if bom.CompanyID != req.CompanyID {
		return nil, inventory_errors.ErrPermissionDenied
	}
	if !bom.IsActive {
		return nil, fmt.Errorf("cannot add items to inactive BOM")
	}

	// CIRCULAR REFERENCE CHECK
	if bom.ProductItemID == req.ComponentItemID {
		return nil, fmt.Errorf("%w: cannot add the product itself as a component", inventory_errors.ErrInvalidInput)
	}

	// Verify component item exists
	exists, err := s.itemRepo.ExistsByID(ctx, tx, req.ComponentItemID)
	if err != nil {
		return nil, fmt.Errorf("check component item: %w", err)
	}
	if !exists {
		return nil, fmt.Errorf("%w: component item %s not found", inventory_errors.ErrInvalidInput, req.ComponentItemID)
	}

	// Duplicate component check
	exists, err = s.bomRepo.ExistsBOMItemByComponent(ctx, tx, req.BOMID, req.ComponentItemID)
	if err != nil {
		return nil, fmt.Errorf("check duplicate component: %w", err)
	}
	if exists {
		return nil, fmt.Errorf("%w: component %s already exists in this BOM", inventory_errors.ErrDuplicate, req.ComponentItemID)
	}

	item := &models.BOMItem{
		BOMItemID:       uuid.New(),
		BOMID:           req.BOMID,
		ComponentItemID: req.ComponentItemID,
		Quantity:        req.Quantity,
		ScrapPercentage: req.ScrapPercentage,
		CreatedAt:       time.Now(),
	}

	if err := s.bomRepo.AddBOMItems(ctx, tx, []*models.BOMItem{item}); err != nil {
		return nil, fmt.Errorf("add BOM item: %w", err)
	}

	_ = s.idempotencyStore.Store(ctx, tx, idempotencyKey, item)

	if err := tx.Commit(); err != nil {
		return nil, fmt.Errorf("commit tx: %w", err)
	}

	if s.auditService != nil {
		_ = s.auditService.LogAction(ctx, nil, &req.CompanyID, "inventory", "add_bom_item", "bom_item",
			&item.BOMItemID, "user", req.CreatedBy, nil, nil, map[string]interface{}{
				"bom_id":   req.BOMID.String(),
				"item_id":  req.ComponentItemID.String(),
				"quantity": req.Quantity,
			})
	}

	return item, nil
}

// UpdateBOMItem modifies a component in a BOM.
func (s *bomService) UpdateBOMItem(ctx context.Context, req UpdateBOMItemRequest, idempotencyKey string) (*models.BOMItem, error) {
	logger := s.logger.With(zap.String("method", "UpdateBOMItem"), zap.String("idempotency_key", idempotencyKey))

	// Validate quantity if provided (> 0)
	if req.Quantity != nil && req.Quantity.LessThanOrEqual(decimal.Zero) {
		return nil, fmt.Errorf("%w: quantity must be positive", inventory_errors.ErrInvalidInput)
	}
	// Validate scrap percentage if provided (>= 0)
	if req.ScrapPercentage != nil && req.ScrapPercentage.LessThan(decimal.Zero) {
		return nil, fmt.Errorf("%w: scrap_percentage cannot be negative", inventory_errors.ErrInvalidInput)
	}

	tx, err := s.pgClient.BeginTx(ctx, nil)
	if err != nil {
		return nil, fmt.Errorf("begin tx: %w", err)
	}
	defer tx.Rollback()

	var cached *models.BOMItem
	if err := s.idempotencyStore.Get(ctx, tx, idempotencyKey, &cached); err == nil && cached != nil {
		logger.Info("idempotent – returning cached BOM item")
		return cached, nil
	}

	item, err := s.bomRepo.GetBOMItemByID(ctx, tx, req.BOMItemID)
	if err != nil {
		return nil, err
	}

	// Verify ownership via BOM
	bom, err := s.bomRepo.GetBOMByID(ctx, tx, item.BOMID)
	if err != nil {
		return nil, err
	}
	if bom.CompanyID != req.CompanyID {
		return nil, inventory_errors.ErrPermissionDenied
	}

	if req.Quantity != nil {
		item.Quantity = *req.Quantity
	}
	if req.ScrapPercentage != nil {
		item.ScrapPercentage = req.ScrapPercentage
	}

	if err := s.bomRepo.UpdateBOMItem(ctx, tx, item); err != nil {
		return nil, fmt.Errorf("update BOM item: %w", err)
	}

	_ = s.idempotencyStore.Store(ctx, tx, idempotencyKey, item)

	if err := tx.Commit(); err != nil {
		return nil, fmt.Errorf("commit tx: %w", err)
	}

	return item, nil
}

// RemoveBOMItem deletes a component from a BOM.
func (s *bomService) RemoveBOMItem(ctx context.Context, bomItemID, companyID uuid.UUID, idempotencyKey string) error {
	logger := s.logger.With(zap.String("method", "RemoveBOMItem"), zap.String("idempotency_key", idempotencyKey))

	tx, err := s.pgClient.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("begin tx: %w", err)
	}
	defer tx.Rollback()

	var processed bool
	if err := s.idempotencyStore.Get(ctx, tx, idempotencyKey, &processed); err == nil && processed {
		logger.Info("idempotent – already removed")
		return nil
	}

	if err := s.bomRepo.DeleteBOMItem(ctx, tx, bomItemID, companyID); err != nil {
		return err
	}

	_ = s.idempotencyStore.Store(ctx, tx, idempotencyKey, true)

	if err := tx.Commit(); err != nil {
		return fmt.Errorf("commit tx: %w", err)
	}

	if s.auditService != nil {
		_ = s.auditService.LogAction(ctx, nil, &companyID, "inventory", "remove_bom_item", "bom_item",
			&bomItemID, "user", nil, nil, nil, nil)
	}

	return nil
}

// GetBOMItems returns all components of a BOM.
func (s *bomService) GetBOMItems(ctx context.Context, bomID, companyID uuid.UUID) ([]*models.BOMItem, error) {
	// Verify BOM belongs to company
	bom, err := s.bomRepo.GetBOMByID(ctx, s.pgClient.DB, bomID)
	if err != nil {
		return nil, err
	}
	if bom.CompanyID != companyID {
		return nil, inventory_errors.ErrPermissionDenied
	}
	return s.bomRepo.GetBOMItems(ctx, s.pgClient.DB, bomID)
}

// validateCreateBOM checks required fields.
func (s *bomService) validateCreateBOM(req CreateBOMRequest) error {
	if req.CompanyID == uuid.Nil {
		return fmt.Errorf("%w: company_id required", inventory_errors.ErrInvalidInput)
	}
	if req.ProductItemID == uuid.Nil {
		return fmt.Errorf("%w: product_item_id required", inventory_errors.ErrInvalidInput)
	}
	if req.BOMCode == "" {
		return fmt.Errorf("%w: bom_code required", inventory_errors.ErrInvalidInput)
	}
	if req.Name == "" {
		return fmt.Errorf("%w: name required", inventory_errors.ErrInvalidInput)
	}
	if req.Quantity.LessThanOrEqual(decimal.Zero) {
		return fmt.Errorf("%w: quantity must be positive", inventory_errors.ErrInvalidInput)
	}
	return nil
}

// emitBOMEvent publishes a BOM event to the outbox.
func (s *bomService) emitBOMEvent(ctx context.Context, tx *sql.Tx, bom *models.BOM, eventType string) error {
	payload := events.BOMPayload{
		BOMID:         bom.BOMID.String(),
		CompanyID:     bom.CompanyID.String(),
		ProductItemID: bom.ProductItemID.String(),
		BOMCode:       bom.BOMCode,
		Name:          bom.Name,
		Version:       bom.Version,
		Quantity:      toFloat64(bom.Quantity),
		IsActive:      bom.IsActive,
	}
	data, err := json.Marshal(payload)
	if err != nil {
		return err
	}
	event := &outbox.Event{
		EventID:       uuid.New().String(),
		AggregateType: "bom",
		AggregateID:   bom.BOMID.String(),
		EventType:     eventType,
		Topic:         events.TopicInventoryEvents,
		Payload:       data,
	}
	return s.outboxRepo.Store(ctx, tx, event)
}

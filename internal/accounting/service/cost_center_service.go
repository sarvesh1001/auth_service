package service

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/google/uuid"
	"go.uber.org/zap"

	"auth-service/internal/accounting/events"
	"auth-service/internal/accounting/models"
	"auth-service/internal/accounting/repository"
	"auth-service/internal/client"
	"auth-service/internal/infrastructure/audit"
	"auth-service/internal/infrastructure/idempotency"
	"auth-service/internal/infrastructure/outbox"
)

// =============================================================================
// Input / Output DTOs
// =============================================================================

type CreateCostCenterRequest struct {
	CompanyID   uuid.UUID
	Code        string
	Name        string
	Description *string
	ParentID    *uuid.UUID
	AccountID   *uuid.UUID
	IsActive    *bool
	CreatedBy   *uuid.UUID
}

type UpdateCostCenterRequest struct {
	CostCenterID uuid.UUID
	CompanyID    uuid.UUID
	Code         string
	Name         string
	Description  *string
	ParentID     *uuid.UUID
	AccountID    *uuid.UUID
	IsActive     *bool
	UpdatedBy    *uuid.UUID
}

// =============================================================================
// Interface
// =============================================================================

type CostCenterService interface {
	Create(ctx context.Context, req CreateCostCenterRequest) (*models.CostCenter, error)
	Update(ctx context.Context, req UpdateCostCenterRequest) (*models.CostCenter, error)
	Deactivate(ctx context.Context, companyID, id uuid.UUID, by *uuid.UUID) error
	GetByID(ctx context.Context, companyID, id uuid.UUID) (*models.CostCenter, error)
	GetByCode(ctx context.Context, companyID uuid.UUID, code string) (*models.CostCenter, error)
	List(ctx context.Context, companyID uuid.UUID, includeInactive bool, p Pagination) ([]*models.CostCenter, int64, error)
	GetTree(ctx context.Context, companyID uuid.UUID, includeInactive bool) ([]*repository.CostCenterTreeNode, error)
}

// =============================================================================
// Implementation
// =============================================================================

type costCenterService struct {
	repo             repository.CostCenterRepository
	pgClient         *client.PostgresClient
	logger           *zap.Logger
	outboxRepo       outbox.Repository
	idempotencyStore idempotency.Store
	auditService     *audit.AuditService
}

func NewCostCenterService(
	repo repository.CostCenterRepository,
	pgClient *client.PostgresClient,
	logger *zap.Logger,
	outboxRepo outbox.Repository,
	idempotencyStore idempotency.Store,
	auditService *audit.AuditService,
) CostCenterService {
	return &costCenterService{
		repo:             repo,
		pgClient:         pgClient,
		logger:           logger.Named("cost_center_service"),
		outboxRepo:       outboxRepo,
		idempotencyStore: idempotencyStore,
		auditService:     auditService,
	}
}

// =============================================================================
// CREATE
// =============================================================================

func (s *costCenterService) Create(ctx context.Context, req CreateCostCenterRequest) (*models.CostCenter, error) {
	logger := s.logger.With(
		zap.String("method", "Create"),
		zap.String("company_id", req.CompanyID.String()),
		zap.String("code", req.Code),
	)

	if req.CompanyID == uuid.Nil {
		return nil, fmt.Errorf("%w: company_id is required", ErrInvalidInput)
	}
	if req.Code == "" || req.Name == "" {
		return nil, fmt.Errorf("%w: code and name are required", ErrInvalidInput)
	}

	idempotencyKey, _ := ctx.Value("idempotency_key").(string)

	tx, err := s.pgClient.BeginTx(ctx, nil)
	if err != nil {
		return nil, fmt.Errorf("begin tx: %w", err)
	}
	defer tx.Rollback()

	if idempotencyKey != "" {
		var cached models.CostCenter
		err := s.idempotencyStore.Get(ctx, tx, idempotencyKey, &cached)
		if err == nil && cached.CostCenterID != uuid.Nil {
			logger.Info("idempotent request, returning cached cost center")
			return &cached, nil
		}
		if err != nil && !isIdempotencyNotFound(err) {
			return nil, fmt.Errorf("idempotency check failed: %w", err)
		}
	}

	exists, err := s.repo.ExistsByCode(ctx, tx, req.CompanyID, req.Code)
	if err != nil {
		return nil, fmt.Errorf("check code uniqueness: %w", err)
	}
	if exists {
		return nil, fmt.Errorf("%w: cost center code %q already exists", ErrDuplicate, req.Code)
	}

	if req.ParentID != nil {
		parent, err := s.repo.GetByID(ctx, tx, *req.ParentID)
		if err != nil {
			return nil, fmt.Errorf("parent not found: %w", err)
		}
		if parent.CompanyID != req.CompanyID {
			return nil, fmt.Errorf("%w: parent belongs to a different company", ErrInvalidInput)
		}
	}

	isActive := true
	if req.IsActive != nil {
		isActive = *req.IsActive
	}

	now := time.Now().UTC()
	cc := &models.CostCenter{
		CostCenterID:   uuid.New(),
		CompanyID:      req.CompanyID,
		CostCenterCode: req.Code,
		CostCenterName: req.Name,
		Description:    req.Description,
		ParentID:       req.ParentID,
		AccountID:      req.AccountID,
		IsActive:       isActive,
		CreatedAt:      now,
		UpdatedAt:      now,
		CreatedBy:      req.CreatedBy,
		UpdatedBy:      req.CreatedBy,
	}

	if err := s.repo.Create(ctx, tx, cc); err != nil {
		return nil, fmt.Errorf("create cost center: %w", err)
	}

	payload, _ := json.Marshal(map[string]interface{}{
		"cost_center_id":   cc.CostCenterID.String(),
		"company_id":       cc.CompanyID.String(),
		"cost_center_code": cc.CostCenterCode,
		"cost_center_name": cc.CostCenterName,
	})
	outboxEvent := &outbox.Event{
		EventID:       uuid.New().String(),
		AggregateType: "cost_center",
		AggregateID:   cc.CostCenterID.String(),
		EventType:     events.EventCostCenterCreated,
		Topic:         TopicAccountingEvents,
		Payload:       payload,
		Status:        "pending",
	}
	if err := s.outboxRepo.Store(ctx, tx, outboxEvent); err != nil {
		return nil, fmt.Errorf("store outbox event: %w", err)
	}

	if idempotencyKey != "" {
		_ = s.idempotencyStore.Store(ctx, tx, idempotencyKey, cc)
	}

	if err := tx.Commit(); err != nil {
		return nil, fmt.Errorf("commit tx: %w", err)
	}

	if s.auditService != nil {
		_ = s.auditService.LogAction(ctx, nil, &req.CompanyID, "accounting", "create", "cost_center",
			&cc.CostCenterID, "user", req.CreatedBy, nil, nil, map[string]interface{}{
				"code": cc.CostCenterCode,
				"name": cc.CostCenterName,
			})
	}

	logger.Info("cost center created")
	return cc, nil
}

// =============================================================================
// UPDATE
// =============================================================================

func (s *costCenterService) Update(ctx context.Context, req UpdateCostCenterRequest) (*models.CostCenter, error) {
	logger := s.logger.With(
		zap.String("method", "Update"),
		zap.String("id", req.CostCenterID.String()),
	)

	if req.CostCenterID == uuid.Nil || req.CompanyID == uuid.Nil {
		return nil, fmt.Errorf("%w: cost_center_id and company_id are required", ErrInvalidInput)
	}

	idempotencyKey, _ := ctx.Value("idempotency_key").(string)

	tx, err := s.pgClient.BeginTx(ctx, nil)
	if err != nil {
		return nil, fmt.Errorf("begin tx: %w", err)
	}
	defer tx.Rollback()

	if idempotencyKey != "" {
		var processed bool
		err := s.idempotencyStore.Get(ctx, tx, idempotencyKey, &processed)
		if err == nil && processed {
			logger.Info("idempotent request, update already applied")
			return s.repo.GetByID(ctx, tx, req.CostCenterID)
		}
		if err != nil && !isIdempotencyNotFound(err) {
			return nil, fmt.Errorf("idempotency check failed: %w", err)
		}
	}

	existing, err := s.repo.GetByIDForUpdate(ctx, tx, req.CostCenterID)
	if err != nil {
		if errors.Is(err, repository.ErrNotFound) {
			return nil, fmt.Errorf("%w: cost center not found", ErrNotFound)
		}
		return nil, fmt.Errorf("get cost center: %w", err)
	}
	if existing.CompanyID != req.CompanyID {
		return nil, fmt.Errorf("%w: cost center belongs to a different company", ErrInvalidInput)
	}

	if req.Code != "" && req.Code != existing.CostCenterCode {
		dup, err := s.repo.ExistsByCode(ctx, tx, req.CompanyID, req.Code)
		if err != nil {
			return nil, fmt.Errorf("check code: %w", err)
		}
		if dup {
			return nil, fmt.Errorf("%w: code %q already in use", ErrDuplicate, req.Code)
		}
		existing.CostCenterCode = req.Code
	}
	if req.Name != "" {
		existing.CostCenterName = req.Name
	}
	if req.Description != nil {
		existing.Description = req.Description
	}
	if req.AccountID != nil {
		existing.AccountID = req.AccountID
	}
	if req.IsActive != nil {
		existing.IsActive = *req.IsActive
	}

	// Parent change — validate circular reference
	if req.ParentID != nil {
		if *req.ParentID == existing.CostCenterID {
			return nil, fmt.Errorf("%w: cost center cannot be its own parent", ErrInvalidInput)
		}
		if *req.ParentID != uuid.Nil {
			parent, err := s.repo.GetByID(ctx, tx, *req.ParentID)
			if err != nil {
				return nil, fmt.Errorf("parent not found: %w", err)
			}
			if parent.CompanyID != req.CompanyID {
				return nil, fmt.Errorf("%w: parent belongs to a different company", ErrInvalidInput)
			}
			circular, err := s.repo.CheckCircularReference(ctx, tx, existing.CostCenterID, req.ParentID)
			if err != nil {
				return nil, fmt.Errorf("circular reference check: %w", err)
			}
			if circular {
				return nil, fmt.Errorf("%w: parent change would create a cycle", ErrInvalidInput)
			}
		}
		existing.ParentID = req.ParentID
	}

	existing.UpdatedAt = time.Now().UTC()
	existing.UpdatedBy = req.UpdatedBy

	if err := s.repo.Update(ctx, tx, existing); err != nil {
		return nil, fmt.Errorf("update cost center: %w", err)
	}

	payload, _ := json.Marshal(map[string]interface{}{
		"cost_center_id": existing.CostCenterID.String(),
		"company_id":     existing.CompanyID.String(),
	})
	outboxEvent := &outbox.Event{
		EventID:       uuid.New().String(),
		AggregateType: "cost_center",
		AggregateID:   existing.CostCenterID.String(),
		EventType:     events.EventCostCenterUpdated,
		Topic:         TopicAccountingEvents,
		Payload:       payload,
		Status:        "pending",
	}
	if err := s.outboxRepo.Store(ctx, tx, outboxEvent); err != nil {
		return nil, fmt.Errorf("store outbox event: %w", err)
	}

	if idempotencyKey != "" {
		_ = s.idempotencyStore.Store(ctx, tx, idempotencyKey, true)
	}

	if err := tx.Commit(); err != nil {
		return nil, fmt.Errorf("commit tx: %w", err)
	}

	if s.auditService != nil {
		_ = s.auditService.LogAction(ctx, nil, &req.CompanyID, "accounting", "update", "cost_center",
			&existing.CostCenterID, "user", req.UpdatedBy, nil, nil, nil)
	}

	logger.Info("cost center updated")
	return existing, nil
}

// =============================================================================
// DEACTIVATE (soft delete)
// =============================================================================

func (s *costCenterService) Deactivate(ctx context.Context, companyID, id uuid.UUID, by *uuid.UUID) error {
	logger := s.logger.With(
		zap.String("method", "Deactivate"),
		zap.String("id", id.String()),
	)

	tx, err := s.pgClient.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("begin tx: %w", err)
	}
	defer tx.Rollback()

	existing, err := s.repo.GetByIDForUpdate(ctx, tx, id)
	if err != nil {
		if errors.Is(err, repository.ErrNotFound) {
			return fmt.Errorf("%w: cost center not found", ErrNotFound)
		}
		return fmt.Errorf("get cost center: %w", err)
	}
	if existing.CompanyID != companyID {
		return fmt.Errorf("%w: cost center belongs to a different company", ErrInvalidInput)
	}

	usedByEmployees, err := s.repo.CheckUsageInEmployees(ctx, tx, id)
	if err != nil {
		return fmt.Errorf("check employee usage: %w", err)
	}
	if usedByEmployees {
		return fmt.Errorf("%w: cost center is still assigned to one or more employees", ErrInvalidState)
	}

	// 👇 pass `by` as-is (repository wants *uuid.UUID)
	if err := s.repo.Delete(ctx, tx, id, by); err != nil {
		return fmt.Errorf("soft delete: %w", err)
	}

	if err := tx.Commit(); err != nil {
		return fmt.Errorf("commit tx: %w", err)
	}

	if s.auditService != nil {
		_ = s.auditService.LogAction(ctx, nil, &companyID, "accounting", "deactivate", "cost_center",
			&id, "user", by, nil, nil, nil)
	}

	logger.Info("cost center deactivated")
	return nil
}

func (s *costCenterService) GetByID(ctx context.Context, companyID, id uuid.UUID) (*models.CostCenter, error) {
	cc, err := s.repo.GetByID(ctx, s.pgClient.DB, id)
	if err != nil {
		if errors.Is(err, repository.ErrNotFound) {
			return nil, fmt.Errorf("%w: cost center not found", ErrNotFound)
		}
		return nil, err
	}
	if cc.CompanyID != companyID {
		return nil, fmt.Errorf("%w: cost center belongs to a different company", ErrNotFound)
	}
	return cc, nil
}

func (s *costCenterService) GetByCode(ctx context.Context, companyID uuid.UUID, code string) (*models.CostCenter, error) {
	cc, err := s.repo.GetByCode(ctx, s.pgClient.DB, companyID, code)
	if err != nil {
		if errors.Is(err, repository.ErrNotFound) {
			return nil, fmt.Errorf("%w: cost center not found", ErrNotFound)
		}
		return nil, err
	}
	return cc, nil
}

func (s *costCenterService) List(ctx context.Context, companyID uuid.UUID, includeInactive bool, p Pagination) ([]*models.CostCenter, int64, error) {
	limit, offset := s.validatePagination(p)

	filter := repository.CostCenterFilter{CompanyID: companyID}
	if !includeInactive {
		active := true
		filter.IsActive = &active
	}

	items, err := s.repo.List(ctx, s.pgClient.DB, filter,
		repository.Pagination{Limit: limit, Offset: offset},
		repository.Sort{Field: "cost_center_code", Direction: "ASC"},
	)
	if err != nil {
		return nil, 0, fmt.Errorf("list cost centers: %w", err)
	}

	total, err := s.repo.Count(ctx, s.pgClient.DB, filter)
	if err != nil {
		return nil, 0, fmt.Errorf("count cost centers: %w", err)
	}

	return items, total, nil
}

func (s *costCenterService) GetTree(ctx context.Context, companyID uuid.UUID, includeInactive bool) ([]*repository.CostCenterTreeNode, error) {
	return s.repo.GetTree(ctx, s.pgClient.DB, companyID, includeInactive)
}

func (s *costCenterService) validatePagination(p Pagination) (int, int) {
	limit := p.Limit
	if limit <= 0 {
		limit = 50
	}
	if limit > 1000 {
		limit = 1000
	}
	offset := p.Offset
	if offset < 0 {
		offset = 0
	}
	return limit, offset
}

// =============================================================================
// GET / LIST / TREE
// =============================================================================

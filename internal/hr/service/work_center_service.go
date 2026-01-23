// auth-service/internal/hr/service/work_center_service.go
package service

import (
	"auth-service/internal/hr/models/workcenter"
	"auth-service/internal/hr/repository"
	"auth-service/internal/util"
	"context"
	"fmt"
	"time"

	"github.com/google/uuid"
	"go.uber.org/zap"
)

type WorkCenterService struct {
	workCenterRepo repository.WorkCenterRepository
	auditService   *AuditService
	logger         *zap.Logger
}

func NewWorkCenterService(
	workCenterRepo repository.WorkCenterRepository,
	auditService *AuditService,
	logger *zap.Logger,
) *WorkCenterService {
	if auditService == nil {
		panic("auditService is required for WorkCenterService")
	}

	return &WorkCenterService{
		workCenterRepo: workCenterRepo,
		auditService:   auditService,
		logger:         logger,
	}
}

func (s *WorkCenterService) GetWorkCenter(
	ctx context.Context,
	companyID uuid.UUID,
	workCenterCode string,
) (*workcenter.WorkCenter, error) {
	if workCenterCode == "" {
		return nil, fmt.Errorf("work center code is required")
	}

	workCenter, err := s.workCenterRepo.GetWorkCenterByCode(ctx, companyID, workCenterCode)
	if err != nil {
		return nil, err
	}

	return workCenter, nil
}

func (s *WorkCenterService) CreateWorkCenter(
	ctx context.Context,
	companyID uuid.UUID,
	req *workcenter.CreateWorkCenterRequest,
	actorType string,
	actorID uuid.UUID,
	metadata map[string]interface{},
) (*workcenter.WorkCenter, error) {
	startTime := time.Now()

	// Check if work center code already exists
	exists, err := s.workCenterRepo.CheckWorkCenterExists(ctx, companyID, req.WorkCenterCode)
	if err != nil {
		return nil, fmt.Errorf("failed to check work center existence: %w", err)
	}
	if exists {
		return nil, fmt.Errorf("work center code already exists: %s", req.WorkCenterCode)
	}

	// Check if work center name already exists
	nameExists, err := s.workCenterRepo.CheckWorkCenterNameExists(ctx, companyID, req.Name)
	if err != nil {
		return nil, fmt.Errorf("failed to check work center name existence: %w", err)
	}
	if nameExists {
		return nil, fmt.Errorf("work center name already exists: %s", req.Name)
	}

	now := time.Now().UTC()
	workCenter := &workcenter.WorkCenter{
		WorkCenterCode: req.WorkCenterCode,
		CompanyID:      companyID,
		Name:           req.Name,
		Description:    req.Description,
		Timezone:       req.Timezone,
		IsActive:       req.IsActive,
		CreatedAt:      now,
		UpdatedAt:      now,
	}

	err = s.workCenterRepo.CreateWorkCenter(ctx, workCenter)
	if err != nil {
		s.logger.Error("Failed to create work center",
			util.String("work_center_code", req.WorkCenterCode),
			util.String("company_id", companyID.String()),
			util.ErrorField(err))
		return nil, fmt.Errorf("failed to create work center: %w", err)
	}

	afterState, _ := util.ToJSON(workCenter)

	// Create a copy of metadata and add work_center_code
	auditMetadata := make(map[string]interface{})
	for k, v := range metadata {
		auditMetadata[k] = v
	}
	auditMetadata["work_center_code"] = req.WorkCenterCode

	// For audit, use nil for entityID since work_center_code is a string, not UUID
	// but include the code in metadata
	auditErr := s.auditService.LogAction(
		ctx,
		&companyID,
		"operations",
		"work_center.create",
		"work_centers",
		nil, // entityID is nil since work_center_code is a string
		actorType,
		&actorID,
		[]byte("{}"),
		afterState,
		auditMetadata,
	)
	if auditErr != nil {
		s.logger.Warn("Failed to log audit entry for work center creation",
			util.String("work_center_code", req.WorkCenterCode),
			util.ErrorField(auditErr))
	}

	s.logger.Info("Work center created",
		util.String("work_center_code", req.WorkCenterCode),
		util.String("company_id", companyID.String()),
		util.String("name", req.Name),
		util.String("actor_type", actorType),
		util.String("actor_id", actorID.String()),
		util.Duration("duration", time.Since(startTime)))

	return workCenter, nil
}

func (s *WorkCenterService) UpdateWorkCenter(
	ctx context.Context,
	companyID uuid.UUID,
	workCenterCode string,
	req *workcenter.UpdateWorkCenterRequest,
	actorType string,
	actorID uuid.UUID,
	metadata map[string]interface{},
) (*workcenter.WorkCenter, error) {
	startTime := time.Now()

	existingWorkCenter, err := s.workCenterRepo.GetWorkCenterByCode(ctx, companyID, workCenterCode)
	if err != nil {
		return nil, fmt.Errorf("failed to get existing work center: %w", err)
	}

	beforeState, _ := util.ToJSON(existingWorkCenter)
	updatedWorkCenter := *existingWorkCenter

	// Update fields if provided
	if req.Name != nil {
		// Check if new name already exists (excluding current work center)
		if *req.Name != existingWorkCenter.Name {
			nameExists, err := s.workCenterRepo.CheckWorkCenterNameExists(ctx, companyID, *req.Name)
			if err != nil {
				return nil, fmt.Errorf("failed to check work center name existence: %w", err)
			}
			if nameExists {
				return nil, fmt.Errorf("work center name already exists: %s", *req.Name)
			}
		}
		updatedWorkCenter.Name = *req.Name
	}

	if req.Description != nil {
		updatedWorkCenter.Description = req.Description
	}

	if req.Timezone != nil {
		updatedWorkCenter.Timezone = *req.Timezone
	}

	if req.IsActive != nil {
		updatedWorkCenter.IsActive = *req.IsActive
	}

	err = s.workCenterRepo.UpdateWorkCenter(ctx, &updatedWorkCenter)
	if err != nil {
		return nil, fmt.Errorf("failed to update work center: %w", err)
	}

	afterState, _ := util.ToJSON(&updatedWorkCenter)

	// Create a copy of metadata and add work_center_code
	auditMetadata := make(map[string]interface{})
	for k, v := range metadata {
		auditMetadata[k] = v
	}
	auditMetadata["work_center_code"] = workCenterCode

	auditErr := s.auditService.LogAction(
		ctx,
		&companyID,
		"operations",
		"work_center.update",
		"work_centers",
		nil, // entityID is nil since work_center_code is a string
		actorType,
		&actorID,
		beforeState,
		afterState,
		auditMetadata,
	)
	if auditErr != nil {
		s.logger.Warn("Failed to log audit entry for work center update",
			util.String("work_center_code", workCenterCode),
			util.ErrorField(auditErr))
	}

	s.logger.Info("Work center updated",
		util.String("work_center_code", workCenterCode),
		util.String("company_id", companyID.String()),
		util.String("actor_type", actorType),
		util.String("actor_id", actorID.String()),
		util.Duration("duration", time.Since(startTime)))

	return &updatedWorkCenter, nil
}

func (s *WorkCenterService) DeleteWorkCenter(
	ctx context.Context,
	companyID uuid.UUID,
	workCenterCode string,
	actorType string,
	actorID uuid.UUID,
	metadata map[string]interface{},
) error {
	startTime := time.Now()

	workCenter, err := s.workCenterRepo.GetWorkCenterByCode(ctx, companyID, workCenterCode)
	if err != nil {
		return fmt.Errorf("failed to get work center for deletion: %w", err)
	}

	beforeState, _ := util.ToJSON(workCenter)

	err = s.workCenterRepo.DeleteWorkCenter(ctx, companyID, workCenterCode)
	if err != nil {
		return fmt.Errorf("failed to delete work center: %w", err)
	}

	// Create a copy of metadata and add work_center_code
	auditMetadata := make(map[string]interface{})
	for k, v := range metadata {
		auditMetadata[k] = v
	}
	auditMetadata["work_center_code"] = workCenterCode

	auditErr := s.auditService.LogAction(
		ctx,
		&companyID,
		"operations",
		"work_center.delete",
		"work_centers",
		nil, // entityID is nil since work_center_code is a string
		actorType,
		&actorID,
		beforeState,
		[]byte("{}"),
		auditMetadata,
	)
	if auditErr != nil {
		s.logger.Warn("Failed to log audit entry for work center deletion",
			util.String("work_center_code", workCenterCode),
			util.ErrorField(auditErr))
	}

	s.logger.Info("Work center deleted",
		util.String("work_center_code", workCenterCode),
		util.String("company_id", companyID.String()),
		util.String("actor_type", actorType),
		util.String("actor_id", actorID.String()),
		util.Duration("duration", time.Since(startTime)))

	return nil
}
func (s *WorkCenterService) ListWorkCenters(
	ctx context.Context,
	companyID uuid.UUID,
	page, pageSize int,
) ([]*workcenter.WorkCenter, int, error) {
	if page < 1 {
		page = 1
	}
	if pageSize < 1 || pageSize > 100 {
		pageSize = 50
	}

	offset := (page - 1) * pageSize
	workCenters, totalCount, err := s.workCenterRepo.ListWorkCenters(ctx, companyID, pageSize, offset)
	if err != nil {
		return nil, 0, fmt.Errorf("failed to list work centers: %w", err)
	}

	return workCenters, totalCount, nil
}

func (s *WorkCenterService) SearchWorkCenters(
	ctx context.Context,
	companyID uuid.UUID,
	filters map[string]interface{},
	page, pageSize int,
) ([]*workcenter.WorkCenter, int, error) {
	if page < 1 {
		page = 1
	}
	if pageSize < 1 || pageSize > 100 {
		pageSize = 50
	}

	offset := (page - 1) * pageSize
	workCenters, totalCount, err := s.workCenterRepo.SearchWorkCenters(ctx, companyID, filters, pageSize, offset)
	if err != nil {
		return nil, 0, fmt.Errorf("failed to search work centers: %w", err)
	}

	return workCenters, totalCount, nil
}

func (s *WorkCenterService) GetActiveWorkCenters(
	ctx context.Context,
	companyID uuid.UUID,
) ([]*workcenter.WorkCenter, error) {
	workCenters, err := s.workCenterRepo.GetActiveWorkCenters(ctx, companyID)
	if err != nil {
		return nil, fmt.Errorf("failed to get active work centers: %w", err)
	}

	return workCenters, nil
}

func (s *WorkCenterService) HealthCheck(ctx context.Context) error {
	if err := s.workCenterRepo.HealthCheck(ctx); err != nil {
		return fmt.Errorf("work center repository health check failed: %w", err)
	}
	return nil
}

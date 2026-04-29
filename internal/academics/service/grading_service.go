package service

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"github.com/google/uuid"
	"go.uber.org/zap"

	"auth-service/internal/academics/models"
	"auth-service/internal/academics/repository"
	"auth-service/internal/client"
	"auth-service/internal/infrastructure/audit"
	"auth-service/internal/infrastructure/idempotency"
	"auth-service/internal/infrastructure/outbox"
)

// GradingService defines the business operations for grading policies and boundaries.
type GradingService interface {
	// GradingPolicy methods
	CreateGradingPolicy(ctx context.Context, req CreateGradingPolicyRequest, idempotencyKey string) (*models.GradingPolicy, error)
	GetGradingPolicyByID(ctx context.Context, id uuid.UUID) (*models.GradingPolicy, error)
	GetGradingPolicyByCompanyAndName(ctx context.Context, companyID uuid.UUID, name string) (*models.GradingPolicy, error)
	GetDefaultGradingPolicy(ctx context.Context, companyID uuid.UUID) (*models.GradingPolicy, error)
	ListGradingPolicies(ctx context.Context, filter repository.GradingPolicyFilter, p repository.Pagination, srt repository.Sort) ([]*models.GradingPolicy, error)
	UpdateGradingPolicy(ctx context.Context, req UpdateGradingPolicyRequest) (*models.GradingPolicy, error)
	DeleteGradingPolicy(ctx context.Context, id uuid.UUID, deletedBy *uuid.UUID) error

	// GradeBoundary methods
	CreateGradeBoundary(ctx context.Context, req CreateGradeBoundaryRequest) (*models.GradeBoundary, error)
	BulkCreateGradeBoundaries(ctx context.Context, reqs []CreateGradeBoundaryRequest) ([]*models.GradeBoundary, error)
	GetGradeBoundaryByID(ctx context.Context, id uuid.UUID) (*models.GradeBoundary, error)
	ListGradeBoundaries(ctx context.Context, filter repository.GradeBoundaryFilter, p repository.Pagination, srt repository.Sort) ([]*models.GradeBoundary, error)
	UpdateGradeBoundary(ctx context.Context, req UpdateGradeBoundaryRequest) (*models.GradeBoundary, error)
	DeleteGradeBoundary(ctx context.Context, id uuid.UUID) error
	DeleteGradeBoundariesByPolicy(ctx context.Context, policyID uuid.UUID) error
}

type gradingService struct {
	repo             repository.GradingRepository
	pgClient         *client.PostgresClient
	logger           *zap.Logger
	outboxStore      outbox.Repository
	idempotencyStore idempotency.Store
	auditService     *audit.AuditService
	eventPublisher   EventPublisher      // optional, for real-time events
	notifSvc         NotificationService // added
}

// NewGradingService creates a new grading service instance.
func NewGradingService(
	repo repository.GradingRepository,
	pgClient *client.PostgresClient,
	logger *zap.Logger,
	outboxStore outbox.Repository,
	idempotencyStore idempotency.Store,
	auditService *audit.AuditService,
	eventPublisher EventPublisher,
	notifSvc NotificationService, // new
) GradingService {
	return &gradingService{
		repo:             repo,
		pgClient:         pgClient,
		logger:           logger.Named("grading_service"),
		outboxStore:      outboxStore,
		idempotencyStore: idempotencyStore,
		auditService:     auditService,
		eventPublisher:   eventPublisher,
		notifSvc:         notifSvc,
	}
}

// ----------------------------------------------------------------------
// Helper: send notification for grading events
// ----------------------------------------------------------------------

// createNotification creates a notification for the given company.
// It uses the notification service and logs errors.
func (s *gradingService) createNotification(ctx context.Context, companyID uuid.UUID, title, message string, notifType models.NotificationType, priority models.NotificationPriority, createdBy *uuid.UUID) {
	if s.notifSvc == nil {
		return
	}
	// Target the whole company (all users in that company can receive the notification)
	targets := []NotificationTargetInput{
		{
			TargetType:     models.TargetCompany,
			TargetEntityID: companyID,
		},
	}
	req := CreateNotificationRequest{
		CompanyID: companyID,
		Title:     title,
		Message:   message,
		Type:      notifType,
		Priority:  priority,
		ExpiresAt: nil,
		Targets:   targets,
		CreatedBy: createdBy,
	}
	// Use background context to avoid cancellation of the main request
	_, err := s.notifSvc.Create(context.Background(), req, "")
	if err != nil {
		s.logger.Error("failed to send grading notification",
			zap.String("title", title),
			zap.String("company_id", companyID.String()),
			zap.Error(err))
	}
}

// ----------------------------------------------------------------------
// GradingPolicy methods
// ----------------------------------------------------------------------

func (s *gradingService) CreateGradingPolicy(ctx context.Context, req CreateGradingPolicyRequest, idempotencyKey string) (*models.GradingPolicy, error) {
	logger := s.logger.With(
		zap.String("method", "CreateGradingPolicy"),
		zap.String("company_id", req.CompanyID.String()),
		zap.String("policy_name", req.PolicyName),
	)

	if err := s.validateGradingPolicyInput(req.CompanyID, req.PolicyName, req.GradingScale); err != nil {
		return nil, err
	}

	tx, err := s.pgClient.BeginTx(ctx, nil)
	if err != nil {
		return nil, fmt.Errorf("begin tx: %w", err)
	}
	defer tx.Rollback()

	// Idempotency check inside transaction
	if idempotencyKey != "" {
		var existing *models.GradingPolicy
		if err := s.idempotencyStore.Get(ctx, tx, idempotencyKey, &existing); err == nil && existing != nil {
			logger.Info("idempotent request, returning cached response")
			return existing, nil
		}
	}

	// Check duplicate name
	existing, _ := s.repo.GetGradingPolicyByCompanyAndName(ctx, tx, req.CompanyID, req.PolicyName)
	if existing != nil {
		return nil, fmt.Errorf("%w: grading policy with name %s already exists", ErrDuplicate, req.PolicyName)
	}

	// If this policy is default, unset any existing default for this company
	if req.IsDefault {
		if err := s.unsetDefaultPolicy(ctx, tx, req.CompanyID, req.UpdatedBy); err != nil {
			return nil, fmt.Errorf("unset default: %w", err)
		}
	}

	policy := &models.GradingPolicy{
		CompanyID:    req.CompanyID,
		PolicyName:   req.PolicyName,
		GradingScale: req.GradingScale,
		IsDefault:    req.IsDefault,
		CreatedBy:    req.CreatedBy,
		UpdatedBy:    req.UpdatedBy,
	}

	if err := s.repo.CreateGradingPolicy(ctx, tx, policy); err != nil {
		return nil, err
	}

	// Store outbox event
	payload, _ := json.Marshal(policy)
	outboxEvent := &outbox.Event{
		EventID:       uuid.New().String(),
		AggregateType: "grading_policy",
		AggregateID:   policy.PolicyID.String(),
		EventType:     string(EventGradingPolicyCreated),
		Topic:         TopicStudent,
		Payload:       payload,
		Headers:       map[string]string{},
		CreatedAt:     time.Now().UTC(),
	}
	if err := s.outboxStore.Store(ctx, tx, outboxEvent); err != nil {
		return nil, fmt.Errorf("store outbox event: %w", err)
	}

	// Store idempotency response inside transaction
	if idempotencyKey != "" {
		if err := s.idempotencyStore.Store(ctx, tx, idempotencyKey, policy); err != nil {
			return nil, fmt.Errorf("store idempotency key: %w", err)
		}
	}

	if err := tx.Commit(); err != nil {
		return nil, fmt.Errorf("commit tx: %w", err)
	}

	logger.Info("grading policy created", zap.String("policy_id", policy.PolicyID.String()))

	// Audit logging
	if s.auditService != nil {
		_ = s.auditService.LogAction(ctx, nil, &req.CompanyID, "academics", "create", "grading_policy",
			&policy.PolicyID, "user", req.CreatedBy, nil, nil,
			map[string]interface{}{"policy_name": policy.PolicyName, "grading_scale": policy.GradingScale})
	}

	// Publish real-time event if needed
	if s.eventPublisher != nil {
		_ = s.eventPublisher.Publish(ctx, Event{Type: EventGradingPolicyCreated, Data: policy})
	}

	// Send notification
	title := "New Grading Policy Created"
	message := fmt.Sprintf("A new grading policy '%s' (%s) has been created.", policy.PolicyName, policy.GradingScale)
	s.createNotification(ctx, policy.CompanyID, title, message, models.NotificationTypeInfo, models.PriorityNormal, req.CreatedBy)

	return policy, nil
}

func (s *gradingService) GetGradingPolicyByID(ctx context.Context, id uuid.UUID) (*models.GradingPolicy, error) {
	p, err := s.repo.GetGradingPolicyByID(ctx, s.pgClient.DB, id)
	if err != nil {
		return nil, err
	}
	if p == nil {
		return nil, fmt.Errorf("%w: grading policy %s", ErrNotFound, id)
	}
	return p, nil
}

func (s *gradingService) GetGradingPolicyByCompanyAndName(ctx context.Context, companyID uuid.UUID, name string) (*models.GradingPolicy, error) {
	p, err := s.repo.GetGradingPolicyByCompanyAndName(ctx, s.pgClient.DB, companyID, name)
	if err != nil {
		return nil, err
	}
	if p == nil {
		return nil, fmt.Errorf("%w: grading policy %s for company %s", ErrNotFound, name, companyID)
	}
	return p, nil
}

func (s *gradingService) GetDefaultGradingPolicy(ctx context.Context, companyID uuid.UUID) (*models.GradingPolicy, error) {
	p, err := s.repo.GetDefaultGradingPolicy(ctx, s.pgClient.DB, companyID)
	if err != nil {
		return nil, err
	}
	if p == nil {
		return nil, fmt.Errorf("%w: no default grading policy for company %s", ErrNotFound, companyID)
	}
	return p, nil
}

func (s *gradingService) ListGradingPolicies(ctx context.Context, filter repository.GradingPolicyFilter, p repository.Pagination, srt repository.Sort) ([]*models.GradingPolicy, error) {
	return s.repo.ListGradingPolicies(ctx, s.pgClient.DB, filter, p, srt)
}

func (s *gradingService) UpdateGradingPolicy(ctx context.Context, req UpdateGradingPolicyRequest) (*models.GradingPolicy, error) {
	logger := s.logger.With(zap.String("method", "UpdateGradingPolicy"), zap.String("policy_id", req.PolicyID.String()))

	tx, err := s.pgClient.BeginTx(ctx, nil)
	if err != nil {
		return nil, fmt.Errorf("begin tx: %w", err)
	}
	defer tx.Rollback()

	policy, err := s.repo.GetGradingPolicyByID(ctx, tx, req.PolicyID)
	if err != nil {
		return nil, err
	}
	if policy == nil {
		return nil, fmt.Errorf("%w: grading policy %s", ErrNotFound, req.PolicyID)
	}

	// If name changed, check uniqueness
	if req.PolicyName != policy.PolicyName {
		existing, _ := s.repo.GetGradingPolicyByCompanyAndName(ctx, tx, policy.CompanyID, req.PolicyName)
		if existing != nil && existing.PolicyID != policy.PolicyID {
			return nil, fmt.Errorf("%w: policy name %s already exists", ErrDuplicate, req.PolicyName)
		}
	}

	// If this policy is being set as default, unset any existing default
	if req.IsDefault && !policy.IsDefault {
		if err := s.unsetDefaultPolicy(ctx, tx, policy.CompanyID, req.UpdatedBy); err != nil {
			return nil, fmt.Errorf("unset default: %w", err)
		}
	}

	oldPolicy := *policy

	policy.PolicyName = req.PolicyName
	policy.GradingScale = req.GradingScale
	policy.IsDefault = req.IsDefault
	policy.UpdatedBy = req.UpdatedBy

	if err := s.repo.UpdateGradingPolicy(ctx, tx, policy); err != nil {
		return nil, err
	}

	payload, _ := json.Marshal(map[string]interface{}{
		"old": oldPolicy,
		"new": policy,
	})
	outboxEvent := &outbox.Event{
		EventID:       uuid.New().String(),
		AggregateType: "grading_policy",
		AggregateID:   policy.PolicyID.String(),
		EventType:     string(EventGradingPolicyUpdated),
		Topic:         TopicStudent,
		Payload:       payload,
		Headers:       map[string]string{},
		CreatedAt:     time.Now().UTC(),
	}
	if err := s.outboxStore.Store(ctx, tx, outboxEvent); err != nil {
		return nil, fmt.Errorf("store outbox event: %w", err)
	}

	if err := tx.Commit(); err != nil {
		return nil, fmt.Errorf("commit tx: %w", err)
	}

	logger.Info("grading policy updated")

	if s.auditService != nil {
		_ = s.auditService.LogAction(ctx, nil, &policy.CompanyID, "academics", "update", "grading_policy",
			&policy.PolicyID, "user", req.UpdatedBy, nil, nil, nil)
	}

	// Publish real-time event
	if s.eventPublisher != nil {
		_ = s.eventPublisher.Publish(ctx, Event{Type: EventGradingPolicyUpdated, Data: policy})
	}

	// Send notification
	title := "Grading Policy Updated"
	message := fmt.Sprintf("Grading policy '%s' has been updated.", policy.PolicyName)
	s.createNotification(ctx, policy.CompanyID, title, message, models.NotificationTypeInfo, models.PriorityNormal, req.UpdatedBy)

	return policy, nil
}

func (s *gradingService) DeleteGradingPolicy(ctx context.Context, id uuid.UUID, deletedBy *uuid.UUID) error {
	logger := s.logger.With(zap.String("method", "DeleteGradingPolicy"), zap.String("policy_id", id.String()))

	tx, err := s.pgClient.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("begin tx: %w", err)
	}
	defer tx.Rollback()

	policy, err := s.repo.GetGradingPolicyByID(ctx, tx, id)
	if err != nil {
		return err
	}
	if policy == nil {
		return fmt.Errorf("%w: grading policy %s", ErrNotFound, id)
	}

	if err := s.repo.DeleteGradingPolicy(ctx, tx, id, deletedBy); err != nil {
		return err
	}

	// Delete all associated grade boundaries (cascade handled by DB, but we can also call repo method if needed)
	// The DB foreign key is ON DELETE CASCADE, so we don't need to delete manually.

	payload, _ := json.Marshal(map[string]interface{}{
		"policy_id":  id,
		"deleted_by": deletedBy,
	})
	outboxEvent := &outbox.Event{
		EventID:       uuid.New().String(),
		AggregateType: "grading_policy",
		AggregateID:   id.String(),
		EventType:     string(EventGradingPolicyDeleted),
		Topic:         TopicStudent,
		Payload:       payload,
		Headers:       map[string]string{},
		CreatedAt:     time.Now().UTC(),
	}
	if err := s.outboxStore.Store(ctx, tx, outboxEvent); err != nil {
		return fmt.Errorf("store outbox event: %w", err)
	}

	if err := tx.Commit(); err != nil {
		return fmt.Errorf("commit tx: %w", err)
	}

	logger.Info("grading policy deleted")

	if s.auditService != nil {
		_ = s.auditService.LogAction(ctx, nil, &policy.CompanyID, "academics", "delete", "grading_policy",
			&id, "user", deletedBy, nil, nil, nil)
	}

	// Publish real-time event
	if s.eventPublisher != nil {
		_ = s.eventPublisher.Publish(ctx, Event{Type: EventGradingPolicyDeleted, Data: map[string]interface{}{"policy_id": id}})
	}

	// Send notification
	title := "Grading Policy Deleted"
	message := fmt.Sprintf("Grading policy '%s' has been deleted.", policy.PolicyName)
	s.createNotification(ctx, policy.CompanyID, title, message, models.NotificationTypeWarning, models.PriorityLow, deletedBy)

	return nil
}

// Helper to unset any existing default policy for a company.
func (s *gradingService) unsetDefaultPolicy(ctx context.Context, tx *sql.Tx, companyID uuid.UUID, updatedBy *uuid.UUID) error {
	defaultPolicy, err := s.repo.GetDefaultGradingPolicy(ctx, tx, companyID)
	if err != nil {
		// If no default policy, that's fine
		return nil
	}
	if defaultPolicy == nil {
		return nil
	}
	// Update the existing default to false
	defaultPolicy.IsDefault = false
	defaultPolicy.UpdatedBy = updatedBy
	return s.repo.UpdateGradingPolicy(ctx, tx, defaultPolicy)
}

// ----------------------------------------------------------------------
// GradeBoundary methods
// ----------------------------------------------------------------------

func (s *gradingService) CreateGradeBoundary(ctx context.Context, req CreateGradeBoundaryRequest) (*models.GradeBoundary, error) {
	logger := s.logger.With(
		zap.String("method", "CreateGradeBoundary"),
		zap.String("policy_id", req.PolicyID.String()),
		zap.String("grade", req.Grade),
	)

	if err := s.validateGradeBoundaryInput(req); err != nil {
		return nil, err
	}

	tx, err := s.pgClient.BeginTx(ctx, nil)
	if err != nil {
		return nil, fmt.Errorf("begin tx: %w", err)
	}
	defer tx.Rollback()

	// Ensure policy exists
	policy, err := s.repo.GetGradingPolicyByID(ctx, tx, req.PolicyID)
	if err != nil {
		return nil, err
	}
	if policy == nil {
		return nil, fmt.Errorf("%w: grading policy %s", ErrNotFound, req.PolicyID)
	}

	boundary := &models.GradeBoundary{
		PolicyID:      req.PolicyID,
		Grade:         req.Grade,
		MinPercentage: req.MinPercentage,
		MaxPercentage: req.MaxPercentage,
		GradePoint:    req.GradePoint,
	}

	if err := s.repo.CreateGradeBoundary(ctx, tx, boundary); err != nil {
		return nil, err
	}

	payload, _ := json.Marshal(boundary)
	outboxEvent := &outbox.Event{
		EventID:       uuid.New().String(),
		AggregateType: "grade_boundary",
		AggregateID:   boundary.BoundaryID.String(),
		EventType:     string(EventGradeBoundaryCreated),
		Topic:         TopicStudent,
		Payload:       payload,
		Headers:       map[string]string{},
		CreatedAt:     time.Now().UTC(),
	}
	if err := s.outboxStore.Store(ctx, tx, outboxEvent); err != nil {
		return nil, fmt.Errorf("store outbox event: %w", err)
	}

	if err := tx.Commit(); err != nil {
		return nil, fmt.Errorf("commit tx: %w", err)
	}

	logger.Info("grade boundary created", zap.String("boundary_id", boundary.BoundaryID.String()))

	if s.auditService != nil {
		_ = s.auditService.LogAction(ctx, nil, &policy.CompanyID, "academics", "create", "grade_boundary",
			&boundary.BoundaryID, "user", nil, nil, nil,
			map[string]interface{}{"grade": boundary.Grade, "min": boundary.MinPercentage, "max": boundary.MaxPercentage})
	}

	if s.eventPublisher != nil {
		_ = s.eventPublisher.Publish(ctx, Event{Type: EventGradeBoundaryCreated, Data: boundary})
	}

	// Send notification
	title := "Grade Boundary Added"
	message := fmt.Sprintf("A new grade boundary '%s' (%0.1f - %0.1f%%) has been added to policy '%s'.", boundary.Grade, boundary.MinPercentage, boundary.MaxPercentage, policy.PolicyName)
	s.createNotification(ctx, policy.CompanyID, title, message, models.NotificationTypeInfo, models.PriorityLow, nil)

	return boundary, nil
}

func (s *gradingService) BulkCreateGradeBoundaries(ctx context.Context, reqs []CreateGradeBoundaryRequest) ([]*models.GradeBoundary, error) {
	if len(reqs) == 0 {
		return nil, nil
	}
	logger := s.logger.With(zap.String("method", "BulkCreateGradeBoundaries"), zap.Int("count", len(reqs)))

	// Validate all requests first
	policyID := reqs[0].PolicyID
	for _, req := range reqs {
		if req.PolicyID != policyID {
			return nil, fmt.Errorf("%w: all boundaries must belong to the same policy", ErrInvalidInput)
		}
		if err := s.validateGradeBoundaryInput(req); err != nil {
			return nil, err
		}
	}

	tx, err := s.pgClient.BeginTx(ctx, nil)
	if err != nil {
		return nil, fmt.Errorf("begin tx: %w", err)
	}
	defer tx.Rollback()

	policy, err := s.repo.GetGradingPolicyByID(ctx, tx, policyID)
	if err != nil {
		return nil, err
	}
	if policy == nil {
		return nil, fmt.Errorf("%w: grading policy %s", ErrNotFound, policyID)
	}

	boundaries := make([]*models.GradeBoundary, len(reqs))
	for i, req := range reqs {
		boundaries[i] = &models.GradeBoundary{
			PolicyID:      req.PolicyID,
			Grade:         req.Grade,
			MinPercentage: req.MinPercentage,
			MaxPercentage: req.MaxPercentage,
			GradePoint:    req.GradePoint,
		}
	}

	if err := s.repo.BulkCreateGradeBoundaries(ctx, tx, boundaries); err != nil {
		return nil, err
	}

	// Store events for each boundary
	for _, b := range boundaries {
		payload, _ := json.Marshal(b)
		outboxEvent := &outbox.Event{
			EventID:       uuid.New().String(),
			AggregateType: "grade_boundary",
			AggregateID:   b.BoundaryID.String(),
			EventType:     string(EventGradeBoundaryCreated),
			Topic:         TopicStudent,
			Payload:       payload,
			Headers:       map[string]string{},
			CreatedAt:     time.Now().UTC(),
		}
		if err := s.outboxStore.Store(ctx, tx, outboxEvent); err != nil {
			return nil, fmt.Errorf("store outbox event for boundary %s: %w", b.BoundaryID, err)
		}
	}

	if err := tx.Commit(); err != nil {
		return nil, fmt.Errorf("commit tx: %w", err)
	}

	logger.Info("bulk created grade boundaries")

	// Audit and events
	for _, b := range boundaries {
		if s.auditService != nil {
			_ = s.auditService.LogAction(ctx, nil, &policy.CompanyID, "academics", "bulk_create", "grade_boundary",
				&b.BoundaryID, "user", nil, nil, nil, nil)
		}
		if s.eventPublisher != nil {
			_ = s.eventPublisher.Publish(ctx, Event{Type: EventGradeBoundaryCreated, Data: b})
		}
	}

	// Send one notification for the bulk creation
	title := "Grade Boundaries Added"
	message := fmt.Sprintf("%d grade boundaries have been added to policy '%s'.", len(boundaries), policy.PolicyName)
	s.createNotification(ctx, policy.CompanyID, title, message, models.NotificationTypeInfo, models.PriorityLow, nil)

	return boundaries, nil
}

func (s *gradingService) GetGradeBoundaryByID(ctx context.Context, id uuid.UUID) (*models.GradeBoundary, error) {
	b, err := s.repo.GetGradeBoundaryByID(ctx, s.pgClient.DB, id)
	if err != nil {
		return nil, err
	}
	if b == nil {
		return nil, fmt.Errorf("%w: grade boundary %s", ErrNotFound, id)
	}
	return b, nil
}

func (s *gradingService) ListGradeBoundaries(ctx context.Context, filter repository.GradeBoundaryFilter, p repository.Pagination, srt repository.Sort) ([]*models.GradeBoundary, error) {
	return s.repo.ListGradeBoundaries(ctx, s.pgClient.DB, filter, p, srt)
}

func (s *gradingService) UpdateGradeBoundary(ctx context.Context, req UpdateGradeBoundaryRequest) (*models.GradeBoundary, error) {
	logger := s.logger.With(
		zap.String("method", "UpdateGradeBoundary"),
		zap.String("boundary_id", req.BoundaryID.String()),
	)

	// Validate only the fields that are actually updatable (PolicyID is not needed for an update)
	if strings.TrimSpace(req.Grade) == "" {
		return nil, fmt.Errorf("%w: grade is required", ErrInvalidInput)
	}
	if req.MinPercentage < 0 || req.MaxPercentage < 0 {
		return nil, fmt.Errorf("%w: percentages cannot be negative", ErrInvalidInput)
	}
	if req.MinPercentage > req.MaxPercentage {
		return nil, fmt.Errorf("%w: min_percentage must be <= max_percentage", ErrInvalidInput)
	}
	if req.GradePoint != nil && *req.GradePoint < 0 {
		return nil, fmt.Errorf("%w: grade_point cannot be negative", ErrInvalidInput)
	}

	tx, err := s.pgClient.BeginTx(ctx, nil)
	if err != nil {
		return nil, fmt.Errorf("begin tx: %w", err)
	}
	defer tx.Rollback()

	boundary, err := s.repo.GetGradeBoundaryByID(ctx, tx, req.BoundaryID)
	if err != nil {
		return nil, err
	}
	if boundary == nil {
		return nil, fmt.Errorf("%w: grade boundary %s", ErrNotFound, req.BoundaryID)
	}

	oldBoundary := *boundary
	boundary.Grade = req.Grade
	boundary.MinPercentage = req.MinPercentage
	boundary.MaxPercentage = req.MaxPercentage
	boundary.GradePoint = req.GradePoint

	if err := s.repo.UpdateGradeBoundary(ctx, tx, boundary); err != nil {
		return nil, err
	}

	payload, _ := json.Marshal(map[string]interface{}{
		"old": oldBoundary,
		"new": boundary,
	})
	outboxEvent := &outbox.Event{
		EventID:       uuid.New().String(),
		AggregateType: "grade_boundary",
		AggregateID:   boundary.BoundaryID.String(),
		EventType:     string(EventGradeBoundaryUpdated),
		Topic:         TopicStudent,
		Payload:       payload,
		Headers:       map[string]string{},
		CreatedAt:     time.Now().UTC(),
	}
	if err := s.outboxStore.Store(ctx, tx, outboxEvent); err != nil {
		return nil, fmt.Errorf("store outbox event: %w", err)
	}

	if err := tx.Commit(); err != nil {
		return nil, fmt.Errorf("commit tx: %w", err)
	}

	logger.Info("grade boundary updated")

	if s.auditService != nil {
		policy, _ := s.repo.GetGradingPolicyByID(ctx, s.pgClient.DB, boundary.PolicyID)
		if policy != nil {
			_ = s.auditService.LogAction(ctx, nil, &policy.CompanyID, "academics", "update", "grade_boundary",
				&boundary.BoundaryID, "user", nil, nil, nil, nil)
		}
	}
	if s.eventPublisher != nil {
		_ = s.eventPublisher.Publish(ctx, Event{Type: EventGradeBoundaryUpdated, Data: boundary})
	}

	policy, _ := s.repo.GetGradingPolicyByID(ctx, s.pgClient.DB, boundary.PolicyID)
	if policy != nil {
		title := "Grade Boundary Updated"
		message := fmt.Sprintf("Grade boundary for '%s' has been updated (old: %0.1f-%0.1f%%, new: %0.1f-%0.1f%%).",
			oldBoundary.Grade, oldBoundary.MinPercentage, oldBoundary.MaxPercentage,
			boundary.MinPercentage, boundary.MaxPercentage)
		s.createNotification(ctx, policy.CompanyID, title, message, models.NotificationTypeInfo, models.PriorityLow, nil)
	}

	return boundary, nil
}
func (s *gradingService) DeleteGradeBoundary(ctx context.Context, id uuid.UUID) error {
	logger := s.logger.With(zap.String("method", "DeleteGradeBoundary"), zap.String("boundary_id", id.String()))

	tx, err := s.pgClient.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("begin tx: %w", err)
	}
	defer tx.Rollback()

	boundary, err := s.repo.GetGradeBoundaryByID(ctx, tx, id)
	if err != nil {
		return err
	}
	if boundary == nil {
		return fmt.Errorf("%w: grade boundary %s", ErrNotFound, id)
	}

	if err := s.repo.DeleteGradeBoundary(ctx, tx, id); err != nil {
		return err
	}

	payload, _ := json.Marshal(map[string]interface{}{
		"boundary_id": id,
	})
	outboxEvent := &outbox.Event{
		EventID:       uuid.New().String(),
		AggregateType: "grade_boundary",
		AggregateID:   id.String(),
		EventType:     string(EventGradeBoundaryDeleted),
		Topic:         TopicStudent,
		Payload:       payload,
		Headers:       map[string]string{},
		CreatedAt:     time.Now().UTC(),
	}
	if err := s.outboxStore.Store(ctx, tx, outboxEvent); err != nil {
		return fmt.Errorf("store outbox event: %w", err)
	}

	if err := tx.Commit(); err != nil {
		return fmt.Errorf("commit tx: %w", err)
	}

	logger.Info("grade boundary deleted")

	if s.auditService != nil {
		policy, _ := s.repo.GetGradingPolicyByID(ctx, s.pgClient.DB, boundary.PolicyID)
		if policy != nil {
			_ = s.auditService.LogAction(ctx, nil, &policy.CompanyID, "academics", "delete", "grade_boundary",
				&id, "user", nil, nil, nil, nil)
		}
	}

	if s.eventPublisher != nil {
		_ = s.eventPublisher.Publish(ctx, Event{Type: EventGradeBoundaryDeleted, Data: map[string]interface{}{"boundary_id": id}})
	}

	// Send notification
	policy, _ := s.repo.GetGradingPolicyByID(ctx, s.pgClient.DB, boundary.PolicyID)
	if policy != nil {
		title := "Grade Boundary Removed"
		message := fmt.Sprintf("Grade boundary '%s' (%0.1f-%0.1f%%) has been removed from policy '%s'.", boundary.Grade, boundary.MinPercentage, boundary.MaxPercentage, policy.PolicyName)
		s.createNotification(ctx, policy.CompanyID, title, message, models.NotificationTypeWarning, models.PriorityLow, nil)
	}

	return nil
}

func (s *gradingService) DeleteGradeBoundariesByPolicy(ctx context.Context, policyID uuid.UUID) error {
	logger := s.logger.With(zap.String("method", "DeleteGradeBoundariesByPolicy"), zap.String("policy_id", policyID.String()))

	tx, err := s.pgClient.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("begin tx: %w", err)
	}
	defer tx.Rollback()

	policy, err := s.repo.GetGradingPolicyByID(ctx, tx, policyID)
	if err != nil {
		return err
	}
	if policy == nil {
		return fmt.Errorf("%w: grading policy %s", ErrNotFound, policyID)
	}

	if err := s.repo.DeleteGradeBoundariesByPolicy(ctx, tx, policyID); err != nil {
		return err
	}

	payload, _ := json.Marshal(map[string]interface{}{
		"policy_id": policyID,
	})
	outboxEvent := &outbox.Event{
		EventID:       uuid.New().String(),
		AggregateType: "grade_boundary",
		AggregateID:   policyID.String(),
		EventType:     string(EventGradeBoundaryDeleted),
		Topic:         TopicStudent,
		Payload:       payload,
		Headers:       map[string]string{},
		CreatedAt:     time.Now().UTC(),
	}
	if err := s.outboxStore.Store(ctx, tx, outboxEvent); err != nil {
		return fmt.Errorf("store outbox event: %w", err)
	}

	if err := tx.Commit(); err != nil {
		return fmt.Errorf("commit tx: %w", err)
	}

	logger.Info("grade boundaries deleted for policy")

	if s.auditService != nil {
		_ = s.auditService.LogAction(ctx, nil, &policy.CompanyID, "academics", "delete_boundaries", "grade_boundary",
			&policyID, "user", nil, nil, nil, nil)
	}

	// Send notification
	title := "Grade Boundaries Removed"
	message := fmt.Sprintf("All grade boundaries have been removed from policy '%s'.", policy.PolicyName)
	s.createNotification(ctx, policy.CompanyID, title, message, models.NotificationTypeWarning, models.PriorityLow, nil)

	return nil
}

// ----------------------------------------------------------------------
// Validation helpers
// ----------------------------------------------------------------------

func (s *gradingService) validateGradingPolicyInput(companyID uuid.UUID, name string, scale models.GradingScale) error {
	if companyID == uuid.Nil {
		return fmt.Errorf("%w: company_id is required", ErrInvalidInput)
	}
	if strings.TrimSpace(name) == "" {
		return fmt.Errorf("%w: policy_name is required", ErrInvalidInput)
	}
	if scale == "" {
		return fmt.Errorf("%w: grading_scale is required", ErrInvalidInput)
	}
	// Additional validation: ensure scale is valid (can check against constants)
	switch scale {
	case models.GradingScalePercentage, models.GradingScaleGradePoint, models.GradingScaleLetterGrade:
		// valid
	default:
		return fmt.Errorf("%w: invalid grading_scale %s", ErrInvalidInput, scale)
	}
	return nil
}

func (s *gradingService) validateGradeBoundaryInput(req CreateGradeBoundaryRequest) error {
	if req.PolicyID == uuid.Nil {
		return fmt.Errorf("%w: policy_id is required", ErrInvalidInput)
	}
	if strings.TrimSpace(req.Grade) == "" {
		return fmt.Errorf("%w: grade is required", ErrInvalidInput)
	}
	if req.MinPercentage < 0 || req.MaxPercentage < 0 {
		return fmt.Errorf("%w: percentages cannot be negative", ErrInvalidInput)
	}
	if req.MinPercentage > req.MaxPercentage {
		return fmt.Errorf("%w: min_percentage must be <= max_percentage", ErrInvalidInput)
	}
	if req.GradePoint != nil && *req.GradePoint < 0 {
		return fmt.Errorf("%w: grade_point cannot be negative", ErrInvalidInput)
	}
	return nil
}

type CreateGradingPolicyRequest struct {
	CompanyID    uuid.UUID           `json:"company_id,omitempty"`
	PolicyName   string              `json:"policy_name"`
	GradingScale models.GradingScale `json:"grading_scale"`
	IsDefault    bool                `json:"is_default"`
	CreatedBy    *uuid.UUID          `json:"created_by,omitempty"`
	UpdatedBy    *uuid.UUID          `json:"updated_by,omitempty"`
}

type UpdateGradingPolicyRequest struct {
	PolicyID     uuid.UUID           `json:"policy_id"`
	PolicyName   string              `json:"policy_name"`
	GradingScale models.GradingScale `json:"grading_scale"`
	IsDefault    bool                `json:"is_default"`
	UpdatedBy    *uuid.UUID          `json:"updated_by,omitempty"`
}

type CreateGradeBoundaryRequest struct {
	PolicyID      uuid.UUID `json:"policy_id"`
	Grade         string    `json:"grade"`
	MinPercentage float64   `json:"min_percentage"`
	MaxPercentage float64   `json:"max_percentage"`
	GradePoint    *float64  `json:"grade_point,omitempty"`
}

type UpdateGradeBoundaryRequest struct {
	BoundaryID    uuid.UUID `json:"boundary_id"`
	Grade         string    `json:"grade"`
	MinPercentage float64   `json:"min_percentage"`
	MaxPercentage float64   `json:"max_percentage"`
	GradePoint    *float64  `json:"grade_point,omitempty"`
}

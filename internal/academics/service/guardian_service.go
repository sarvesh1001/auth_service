package service

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"strings"

	"github.com/google/uuid"
	"go.uber.org/zap"

	"auth-service/internal/academics/models"
	"auth-service/internal/academics/repository"
	"auth-service/internal/client"
	"auth-service/internal/infrastructure/audit"
	"auth-service/internal/infrastructure/idempotency"
	"auth-service/internal/infrastructure/outbox"
)

// GuardianService defines the business operations for guardians.
type GuardianService interface {
	Create(ctx context.Context, req CreateGuardianRequest) (*models.Guardian, error)
	BulkCreate(ctx context.Context, reqs []CreateGuardianRequest) ([]*models.Guardian, error)
	GetByID(ctx context.Context, id uuid.UUID) (*models.Guardian, error)
	GetByStudentID(ctx context.Context, studentID uuid.UUID) ([]*models.Guardian, error)
	GetPrimaryGuardian(ctx context.Context, studentID uuid.UUID) (*models.Guardian, error)
	List(ctx context.Context, filter GuardianFilter, p repository.Pagination, s repository.Sort) ([]*models.Guardian, error)
	Count(ctx context.Context, filter GuardianFilter) (int64, error)
	Update(ctx context.Context, req UpdateGuardianRequest) (*models.Guardian, error)
	Delete(ctx context.Context, id uuid.UUID, deletedBy *uuid.UUID) error
	SetPrimary(ctx context.Context, studentID, guardianID uuid.UUID, updatedBy *uuid.UUID) error
	Exists(ctx context.Context, studentID uuid.UUID, guardianName, relation string) (bool, error)
}

// guardianService is the concrete implementation.
type guardianService struct {
	repo                repository.GuardianRepository
	studentRepo         repository.StudentRepository
	pgClient            *client.PostgresClient
	logger              *zap.Logger
	outboxRepo          outbox.Repository
	idempotencyStore    idempotency.Store
	auditService        *audit.AuditService
	notificationService NotificationService
}

// NewGuardianService creates a new service instance.
func NewGuardianService(
	repo repository.GuardianRepository,
	studentRepo repository.StudentRepository,
	pgClient *client.PostgresClient,
	logger *zap.Logger,
	outboxRepo outbox.Repository,
	idempotencyStore idempotency.Store,
	auditService *audit.AuditService,
	notificationService NotificationService,
) GuardianService {
	return &guardianService{
		repo:                repo,
		studentRepo:         studentRepo,
		pgClient:            pgClient,
		logger:              logger.Named("guardian_service"),
		outboxRepo:          outboxRepo,
		idempotencyStore:    idempotencyStore,
		auditService:        auditService,
		notificationService: notificationService,
	}
}

// ---------------------------------------------------------------------
// Helper methods
// ---------------------------------------------------------------------

func (s *guardianService) sanitizeCreate(req *CreateGuardianRequest) {
	req.GuardianName = strings.TrimSpace(req.GuardianName)
	req.Relation = strings.TrimSpace(req.Relation)
	req.Phone = strings.TrimSpace(req.Phone)
	req.Email = strings.TrimSpace(req.Email)
	req.Address = strings.TrimSpace(req.Address)
	req.Occupation = strings.TrimSpace(req.Occupation)
}

func (s *guardianService) validateCreateInput(ctx context.Context, tx *sql.Tx, req CreateGuardianRequest) error {
	if req.StudentID == uuid.Nil {
		return fmt.Errorf("%w: student_id is required", ErrInvalidInput)
	}
	if req.GuardianName == "" {
		return fmt.Errorf("%w: guardian_name is required", ErrInvalidInput)
	}
	if req.Relation == "" {
		return fmt.Errorf("%w: relation is required", ErrInvalidInput)
	}
	// Validate that the student exists
	student, err := s.studentRepo.GetByID(ctx, tx, req.StudentID)
	if err != nil {
		return fmt.Errorf("%w: student validation failed: %w", ErrInvalidInput, err)
	}
	if student == nil {
		return fmt.Errorf("%w: student %s does not exist", ErrNotFound, req.StudentID)
	}
	return nil
}

func (s *guardianService) buildNotificationRequest(
	guardian *models.Guardian,
	student *models.Student,
	operation string,
	actor *uuid.UUID,
) CreateNotificationRequest {
	var title, message string
	var notificationType models.NotificationType
	priority := models.PriorityNormal

	switch operation {
	case "created":
		title = "Guardian Added"
		message = fmt.Sprintf("Guardian %s (%s) has been added for student %s %s",
			guardian.GuardianName, guardian.Relation, student.FirstName, student.LastName)
		notificationType = models.NotificationTypeInfo
	case "updated":
		title = "Guardian Updated"
		message = fmt.Sprintf("Guardian %s (%s) has been updated.", guardian.GuardianName, guardian.Relation)
		notificationType = models.NotificationTypeInfo
	case "deleted":
		title = "Guardian Deleted"
		message = fmt.Sprintf("Guardian %s (%s) has been deleted.", guardian.GuardianName, guardian.Relation)
		notificationType = models.NotificationTypeWarning
		priority = models.PriorityHigh
	case "primary_set":
		title = "Primary Guardian Changed"
		message = fmt.Sprintf("Guardian %s (%s) is now the primary guardian for student %s %s",
			guardian.GuardianName, guardian.Relation, student.FirstName, student.LastName)
		notificationType = models.NotificationTypeInfo
	default:
		title = "Guardian Change"
		message = fmt.Sprintf("Guardian %s (%s) was modified.", guardian.GuardianName, guardian.Relation)
		notificationType = models.NotificationTypeInfo
	}

	return CreateNotificationRequest{
		CompanyID: student.CompanyID,
		Title:     title,
		Message:   message,
		Type:      notificationType,
		Priority:  priority,
		ExpiresAt: nil,
		Targets: []NotificationTargetInput{
			{
				TargetType:     models.TargetUser,
				TargetEntityID: *actor,
			},
		},
		CreatedBy: actor,
	}
}

// ---------------------------------------------------------------------
// Core CRUD Operations
// ---------------------------------------------------------------------

func (s *guardianService) Create(ctx context.Context, req CreateGuardianRequest) (*models.Guardian, error) {
	logger := s.logger.With(
		zap.String("method", "Create"),
		zap.String("student_id", req.StudentID.String()),
		zap.String("guardian_name", req.GuardianName),
	)
	s.sanitizeCreate(&req)

	// Extract idempotency key from context
	idempotencyKey, _ := ctx.Value("idempotency_key").(string)

	tx, err := s.pgClient.BeginTx(ctx, nil)
	if err != nil {
		return nil, fmt.Errorf("begin tx: %w", err)
	}
	defer tx.Rollback()

	// Idempotency check (inside transaction)
	if idempotencyKey != "" {
		var existingGuardian models.Guardian
		if err := s.idempotencyStore.Get(ctx, tx, idempotencyKey, &existingGuardian); err == nil && existingGuardian.GuardianID != uuid.Nil {
			logger.Info("idempotent request, returning cached response")
			return &existingGuardian, nil
		}
	}

	if err := s.validateCreateInput(ctx, tx, req); err != nil {
		return nil, err
	}

	guardian := &models.Guardian{
		StudentID:    req.StudentID,
		GuardianName: req.GuardianName,
		Relation:     req.Relation,
		Phone:        req.Phone,
		Email:        req.Email,
		Address:      req.Address,
		IsPrimary:    req.IsPrimary,
		Occupation:   req.Occupation,
		Income:       req.Income,
	}

	if err := s.repo.Create(ctx, tx, guardian); err != nil {
		return nil, err
	}

	// Store idempotency key after successful insert
	if idempotencyKey != "" {
		if err := s.idempotencyStore.Store(ctx, tx, idempotencyKey, guardian); err != nil {
			logger.Error("failed to store idempotency key", zap.Error(err))
			// Continue – data already inserted; idempotency not critical
		}
	}

	// Outbox event
	payload, _ := json.Marshal(guardian)
	outboxEvent := &outbox.Event{
		EventID:       uuid.New().String(),
		AggregateType: "guardian",
		AggregateID:   guardian.GuardianID.String(),
		EventType:     string(EventGuardianCreated),
		Topic:         TopicStudent,
		Payload:       payload,
		Headers:       map[string]string{},
		Status:        "pending",
	}
	if err := s.outboxRepo.Store(ctx, tx, outboxEvent); err != nil {
		return nil, fmt.Errorf("store outbox event: %w", err)
	}

	// Fetch student for company ID (used after commit)
	student, err := s.studentRepo.GetByID(ctx, tx, req.StudentID)
	if err != nil {
		logger.Error("failed to fetch student for company ID", zap.Error(err))
		student = nil
	}

	if err := tx.Commit(); err != nil {
		return nil, fmt.Errorf("commit tx: %w", err)
	}

	logger.Info("guardian created", zap.String("id", guardian.GuardianID.String()))

	// Audit logging (after commit – no transaction)
	if s.auditService != nil && student != nil {
		_ = s.auditService.LogAction(ctx, nil, &student.CompanyID, "academics", "create", "guardian",
			&guardian.GuardianID, "user", req.CreatedBy, nil, nil,
			map[string]interface{}{"guardian_name": guardian.GuardianName})
	}

	// Create notification (after commit)
	if s.notificationService != nil && student != nil && req.CreatedBy != nil && *req.CreatedBy != uuid.Nil {
		notifReq := s.buildNotificationRequest(guardian, student, "created", req.CreatedBy)
		if _, err := s.notificationService.Create(ctx, notifReq, uuid.New().String()); err != nil {
			logger.Error("failed to create notification", zap.Error(err))
		}
	}

	return guardian, nil
}

func (s *guardianService) BulkCreate(ctx context.Context, reqs []CreateGuardianRequest) ([]*models.Guardian, error) {
	if len(reqs) == 0 {
		return nil, nil
	}

	logger := s.logger.With(zap.String("method", "BulkCreate"), zap.Int("batch_size", len(reqs)))
	for i := range reqs {
		s.sanitizeCreate(&reqs[i])
	}

	idempotencyKey, _ := ctx.Value("idempotency_key").(string)

	tx, err := s.pgClient.BeginTx(ctx, nil)
	if err != nil {
		return nil, fmt.Errorf("begin tx: %w", err)
	}
	defer tx.Rollback()

	// Idempotency check for entire bulk operation
	if idempotencyKey != "" {
		var existing []*models.Guardian
		if err := s.idempotencyStore.Get(ctx, tx, idempotencyKey, &existing); err == nil && existing != nil {
			logger.Info("idempotent bulk request, returning cached response")
			return existing, nil
		}
	}

	// Validate each request
	for i, req := range reqs {
		if err := s.validateCreateInput(ctx, tx, req); err != nil {
			return nil, fmt.Errorf("item %d: %w", i, err)
		}
	}

	guardians := make([]*models.Guardian, 0, len(reqs))
	for _, req := range reqs {
		guardians = append(guardians, &models.Guardian{
			StudentID:    req.StudentID,
			GuardianName: req.GuardianName,
			Relation:     req.Relation,
			Phone:        req.Phone,
			Email:        req.Email,
			Address:      req.Address,
			IsPrimary:    req.IsPrimary,
			Occupation:   req.Occupation,
			Income:       req.Income,
		})
	}

	if err := s.repo.BulkCreate(ctx, tx, guardians); err != nil {
		return nil, err
	}

	// Store idempotency key after successful insert
	if idempotencyKey != "" {
		if err := s.idempotencyStore.Store(ctx, tx, idempotencyKey, guardians); err != nil {
			logger.Error("failed to store idempotency key", zap.Error(err))
		}
	}

	// Store outbox events for each guardian
	for _, g := range guardians {
		payload, _ := json.Marshal(g)
		outboxEvent := &outbox.Event{
			EventID:       uuid.New().String(),
			AggregateType: "guardian",
			AggregateID:   g.GuardianID.String(),
			EventType:     string(EventGuardianCreated),
			Topic:         TopicStudent,
			Payload:       payload,
			Status:        "pending",
		}
		if err := s.outboxRepo.Store(ctx, tx, outboxEvent); err != nil {
			return nil, fmt.Errorf("store outbox event for %s: %w", g.GuardianID, err)
		}
	}

	// Pre‑fetch students for notifications
	students := make(map[uuid.UUID]*models.Student)
	for _, g := range guardians {
		if _, ok := students[g.StudentID]; !ok {
			student, err := s.studentRepo.GetByID(ctx, tx, g.StudentID)
			if err != nil {
				logger.Error("failed to fetch student", zap.String("student_id", g.StudentID.String()), zap.Error(err))
				continue
			}
			if student != nil {
				students[g.StudentID] = student
			}
		}
	}

	if err := tx.Commit(); err != nil {
		return nil, fmt.Errorf("commit tx: %w", err)
	}

	logger.Info("bulk created guardians", zap.Int("count", len(guardians)))

	// Audit and notifications (after commit)
	for i, g := range guardians {
		student := students[g.StudentID]
		if s.auditService != nil && student != nil {
			_ = s.auditService.LogAction(ctx, nil, &student.CompanyID, "academics", "bulk_create", "guardian",
				&g.GuardianID, "user", reqs[i].CreatedBy, nil, nil, nil)
		}
		if s.notificationService != nil && student != nil && reqs[i].CreatedBy != nil && *reqs[i].CreatedBy != uuid.Nil {
			notifReq := s.buildNotificationRequest(g, student, "created", reqs[i].CreatedBy)
			if _, err := s.notificationService.Create(ctx, notifReq, uuid.New().String()); err != nil {
				logger.Error("failed to create notification for guardian",
					zap.String("id", g.GuardianID.String()),
					zap.Error(err))
			}
		}
	}

	return guardians, nil
}

func (s *guardianService) GetByID(ctx context.Context, id uuid.UUID) (*models.Guardian, error) {
	logger := s.logger.With(zap.String("method", "GetByID"), zap.String("id", id.String()))
	guardian, err := s.repo.GetByID(ctx, s.pgClient.DB, id)
	if err != nil {
		return nil, err
	}
	if guardian == nil {
		return nil, fmt.Errorf("%w: guardian %s", ErrNotFound, id)
	}
	logger.Debug("guardian retrieved")
	return guardian, nil
}

func (s *guardianService) GetByStudentID(ctx context.Context, studentID uuid.UUID) ([]*models.Guardian, error) {
	logger := s.logger.With(zap.String("method", "GetByStudentID"), zap.String("student_id", studentID.String()))
	logger.Debug("listing guardians for student")
	return s.repo.GetByStudentID(ctx, s.pgClient.DB, studentID)
}

func (s *guardianService) GetPrimaryGuardian(ctx context.Context, studentID uuid.UUID) (*models.Guardian, error) {
	logger := s.logger.With(zap.String("method", "GetPrimaryGuardian"), zap.String("student_id", studentID.String()))
	logger.Debug("getting primary guardian")
	return s.repo.GetPrimaryGuardian(ctx, s.pgClient.DB, studentID)
}

func (s *guardianService) List(ctx context.Context, filter GuardianFilter, p repository.Pagination, srt repository.Sort) ([]*models.Guardian, error) {
	logger := s.logger.With(zap.String("method", "List"))
	logger.Debug("listing guardians")
	repoFilter := repository.GuardianFilter{
		StudentID: filter.StudentID,
		IsPrimary: filter.IsPrimary,
		Relation:  filter.Relation,
		Search:    filter.Search,
	}
	return s.repo.List(ctx, s.pgClient.DB, repoFilter, p, srt)
}

func (s *guardianService) Count(ctx context.Context, filter GuardianFilter) (int64, error) {
	logger := s.logger.With(zap.String("method", "Count"))
	logger.Debug("counting guardians")
	repoFilter := repository.GuardianFilter{
		StudentID: filter.StudentID,
		IsPrimary: filter.IsPrimary,
		Relation:  filter.Relation,
		Search:    filter.Search,
	}
	return s.repo.Count(ctx, s.pgClient.DB, repoFilter)
}

func (s *guardianService) Update(ctx context.Context, req UpdateGuardianRequest) (*models.Guardian, error) {
	logger := s.logger.With(
		zap.String("method", "Update"),
		zap.String("guardian_id", req.GuardianID.String()),
	)

	if req.GuardianID == uuid.Nil {
		return nil, fmt.Errorf("%w: guardian_id is required", ErrInvalidInput)
	}

	idempotencyKey, _ := ctx.Value("idempotency_key").(string)

	tx, err := s.pgClient.BeginTx(ctx, nil)
	if err != nil {
		return nil, fmt.Errorf("begin tx: %w", err)
	}
	defer tx.Rollback()

	// Idempotency check
	if idempotencyKey != "" {
		var existingGuardian models.Guardian
		if err := s.idempotencyStore.Get(ctx, tx, idempotencyKey, &existingGuardian); err == nil && existingGuardian.GuardianID != uuid.Nil {
			logger.Info("idempotent request, returning cached response")
			return &existingGuardian, nil
		}
	}

	existing, err := s.repo.GetByID(ctx, tx, req.GuardianID)
	if err != nil {
		return nil, err
	}
	if existing == nil {
		return nil, fmt.Errorf("%w: guardian %s", ErrNotFound, req.GuardianID)
	}

	oldGuardian := *existing

	existing.GuardianName = req.GuardianName
	existing.Relation = req.Relation
	existing.Phone = req.Phone
	existing.Email = req.Email
	existing.Address = req.Address
	existing.IsPrimary = req.IsPrimary
	existing.Occupation = req.Occupation
	existing.Income = req.Income

	if err := s.repo.Update(ctx, tx, existing); err != nil {
		return nil, err
	}

	// Store idempotency key after successful update
	if idempotencyKey != "" {
		if err := s.idempotencyStore.Store(ctx, tx, idempotencyKey, existing); err != nil {
			logger.Error("failed to store idempotency key", zap.Error(err))
		}
	}

	// Outbox event
	payload, _ := json.Marshal(map[string]interface{}{
		"old": oldGuardian,
		"new": existing,
	})
	outboxEvent := &outbox.Event{
		EventID:       uuid.New().String(),
		AggregateType: "guardian",
		AggregateID:   existing.GuardianID.String(),
		EventType:     string(EventGuardianUpdated),
		Topic:         TopicStudent,
		Payload:       payload,
		Status:        "pending",
	}
	if err := s.outboxRepo.Store(ctx, tx, outboxEvent); err != nil {
		return nil, fmt.Errorf("store outbox event: %w", err)
	}

	// Fetch student for company ID
	student, err := s.studentRepo.GetByID(ctx, tx, existing.StudentID)
	if err != nil {
		logger.Error("failed to fetch student for company ID", zap.Error(err))
		student = nil
	}

	if err := tx.Commit(); err != nil {
		return nil, fmt.Errorf("commit tx: %w", err)
	}

	logger.Info("guardian updated")

	// Audit logging (after commit)
	if s.auditService != nil && student != nil {
		_ = s.auditService.LogAction(ctx, nil, &student.CompanyID, "academics", "update", "guardian",
			&existing.GuardianID, "user", req.UpdatedBy, nil, nil,
			map[string]interface{}{"guardian_name": existing.GuardianName})
	}

	// Notification (after commit)
	if s.notificationService != nil && student != nil && req.UpdatedBy != nil && *req.UpdatedBy != uuid.Nil {
		notifReq := s.buildNotificationRequest(existing, student, "updated", req.UpdatedBy)
		if _, err := s.notificationService.Create(ctx, notifReq, uuid.New().String()); err != nil {
			logger.Error("failed to create notification", zap.Error(err))
		}
	}

	return existing, nil
}

func (s *guardianService) Delete(ctx context.Context, id uuid.UUID, deletedBy *uuid.UUID) error {
	logger := s.logger.With(zap.String("method", "Delete"), zap.String("guardian_id", id.String()))
	// Idempotency not critical for delete (deleting twice is harmless).

	tx, err := s.pgClient.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("begin tx: %w", err)
	}
	defer tx.Rollback()

	guardian, err := s.repo.GetByID(ctx, tx, id)
	if err != nil {
		return err
	}
	if guardian == nil {
		return fmt.Errorf("%w: guardian %s", ErrNotFound, id)
	}

	// Fetch student before deletion (for audit/notification)
	student, err := s.studentRepo.GetByID(ctx, tx, guardian.StudentID)
	if err != nil {
		logger.Error("failed to fetch student for company ID", zap.Error(err))
		student = nil
	}

	if err := s.repo.Delete(ctx, tx, id); err != nil {
		return err
	}

	// Outbox event
	payload, _ := json.Marshal(map[string]interface{}{
		"guardian_id": id,
		"deleted_by":  deletedBy,
	})
	outboxEvent := &outbox.Event{
		EventID:       uuid.New().String(),
		AggregateType: "guardian",
		AggregateID:   id.String(),
		EventType:     string(EventGuardianDeleted),
		Topic:         TopicStudent,
		Payload:       payload,
		Status:        "pending",
	}
	if err := s.outboxRepo.Store(ctx, tx, outboxEvent); err != nil {
		return fmt.Errorf("store outbox event: %w", err)
	}

	if err := tx.Commit(); err != nil {
		return fmt.Errorf("commit tx: %w", err)
	}

	logger.Info("guardian deleted")

	// Audit logging (after commit)
	if s.auditService != nil && student != nil {
		_ = s.auditService.LogAction(ctx, nil, &student.CompanyID, "academics", "delete", "guardian",
			&id, "user", deletedBy, nil, nil, nil)
	}

	// Notification (after commit)
	if s.notificationService != nil && student != nil && deletedBy != nil && *deletedBy != uuid.Nil {
		notifReq := s.buildNotificationRequest(guardian, student, "deleted", deletedBy)
		if _, err := s.notificationService.Create(ctx, notifReq, uuid.New().String()); err != nil {
			logger.Error("failed to create notification", zap.Error(err))
		}
	}

	return nil
}

func (s *guardianService) SetPrimary(ctx context.Context, studentID, guardianID uuid.UUID, updatedBy *uuid.UUID) error {
	logger := s.logger.With(
		zap.String("method", "SetPrimary"),
		zap.String("student_id", studentID.String()),
		zap.String("guardian_id", guardianID.String()),
	)

	idempotencyKey, _ := ctx.Value("idempotency_key").(string)

	tx, err := s.pgClient.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("begin tx: %w", err)
	}
	defer tx.Rollback()

	// Idempotency check (optional, because this is a simple update)
	if idempotencyKey != "" {
		var result interface{}
		if err := s.idempotencyStore.Get(ctx, tx, idempotencyKey, &result); err == nil && result != nil {
			logger.Info("idempotent request, skipping")
			return nil
		}
	}

	if err := s.repo.SetPrimary(ctx, tx, studentID, guardianID); err != nil {
		return err
	}

	// Store idempotency key
	if idempotencyKey != "" {
		if err := s.idempotencyStore.Store(ctx, tx, idempotencyKey, true); err != nil {
			logger.Error("failed to store idempotency key", zap.Error(err))
		}
	}

	// Fetch guardian and student for outbox, audit, notification
	guardian, err := s.repo.GetByID(ctx, tx, guardianID)
	if err != nil {
		logger.Error("failed to fetch guardian for outbox", zap.Error(err))
		guardian = nil
	}
	student, err := s.studentRepo.GetByID(ctx, tx, studentID)
	if err != nil {
		logger.Error("failed to fetch student for outbox", zap.Error(err))
		student = nil
	}

	// Outbox event
	eventPayload := map[string]interface{}{
		"student_id":  studentID,
		"guardian_id": guardianID,
		"updated_by":  updatedBy,
	}
	if guardian != nil {
		eventPayload["guardian_name"] = guardian.GuardianName
		eventPayload["relation"] = guardian.Relation
	}
	payload, _ := json.Marshal(eventPayload)
	outboxEvent := &outbox.Event{
		EventID:       uuid.New().String(),
		AggregateType: "guardian",
		AggregateID:   guardianID.String(),
		EventType:     string(EventGuardianPrimarySet),
		Topic:         TopicStudent,
		Payload:       payload,
		Status:        "pending",
	}
	if err := s.outboxRepo.Store(ctx, tx, outboxEvent); err != nil {
		return fmt.Errorf("store outbox event: %w", err)
	}

	if err := tx.Commit(); err != nil {
		return fmt.Errorf("commit tx: %w", err)
	}

	logger.Info("primary guardian set")

	// Audit logging (after commit)
	if s.auditService != nil && student != nil {
		_ = s.auditService.LogAction(ctx, nil, &student.CompanyID, "academics", "set_primary", "guardian",
			&guardianID, "user", updatedBy, nil, nil,
			map[string]interface{}{"student_id": studentID, "guardian_id": guardianID})
	}

	// Notification (after commit)
	if s.notificationService != nil && guardian != nil && student != nil && updatedBy != nil && *updatedBy != uuid.Nil {
		notifReq := s.buildNotificationRequest(guardian, student, "primary_set", updatedBy)
		if _, err := s.notificationService.Create(ctx, notifReq, uuid.New().String()); err != nil {
			logger.Error("failed to create notification", zap.Error(err))
		}
	}

	return nil
}

func (s *guardianService) Exists(ctx context.Context, studentID uuid.UUID, guardianName, relation string) (bool, error) {
	logger := s.logger.With(
		zap.String("method", "Exists"),
		zap.String("student_id", studentID.String()),
		zap.String("guardian_name", guardianName),
		zap.String("relation", relation),
	)
	logger.Debug("checking existence")
	filter := repository.GuardianFilter{
		StudentID: studentID,
		Search:    guardianName,
		Relation:  relation,
	}
	guardians, err := s.repo.List(ctx, s.pgClient.DB, filter, repository.Pagination{Limit: 1, Offset: 0}, repository.Sort{Field: "created_at", Direction: "DESC"})
	if err != nil {
		return false, err
	}
	return len(guardians) > 0, nil
}

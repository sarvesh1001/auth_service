package service

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/google/uuid"
	"go.uber.org/zap"

	"auth-service/internal/academics/models"
	"auth-service/internal/academics/repository"
	"auth-service/internal/client"
)

type GuardianService interface {
	Create(ctx context.Context, req CreateGuardianRequest, idempotencyKey string) (*models.Guardian, error)
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

type guardianService struct {
	repo             repository.GuardianRepository
	studentRepo      repository.StudentRepository // to validate student exists
	idempotencyStore IdempotencyStore
	auditLogger      AuditLogger
	outboxStore      OutboxStore
	eventPublisher   EventPublisher
	pgClient         *client.PostgresClient
	logger           *zap.Logger
	notificationSvc  NotificationService // Added for notifications
}

func NewGuardianService(
	repo repository.GuardianRepository,
	studentRepo repository.StudentRepository,
	idempotencyStore IdempotencyStore,
	auditLogger AuditLogger,
	outboxStore OutboxStore,
	eventPublisher EventPublisher,
	pgClient *client.PostgresClient,
	logger *zap.Logger,
	notificationSvc NotificationService, // New parameter
) GuardianService {
	return &guardianService{
		repo:             repo,
		studentRepo:      studentRepo,
		idempotencyStore: idempotencyStore,
		auditLogger:      auditLogger,
		outboxStore:      outboxStore,
		eventPublisher:   eventPublisher,
		pgClient:         pgClient,
		logger:           logger.Named("guardian_service"),
		notificationSvc:  notificationSvc,
	}
}

func (s *guardianService) sanitizeCreate(req *CreateGuardianRequest) {
	req.GuardianName = strings.TrimSpace(req.GuardianName)
	req.Relation = strings.TrimSpace(req.Relation)
	req.Phone = strings.TrimSpace(req.Phone)
	req.Email = strings.TrimSpace(req.Email)
	req.Address = strings.TrimSpace(req.Address)
	req.Occupation = strings.TrimSpace(req.Occupation)
}

func (s *guardianService) validateCreateInput(req CreateGuardianRequest) error {
	if req.StudentID == uuid.Nil {
		return fmt.Errorf("%w: student_id is required", ErrInvalidInput)
	}
	if req.GuardianName == "" {
		return fmt.Errorf("%w: guardian_name is required", ErrInvalidInput)
	}
	if req.Relation == "" {
		return fmt.Errorf("%w: relation is required", ErrInvalidInput)
	}
	// Optionally validate that the student exists
	student, err := s.studentRepo.GetByID(context.Background(), s.pgClient.DB, req.StudentID)
	if err != nil {
		return fmt.Errorf("%w: student validation failed: %w", ErrInvalidInput, err)
	}
	if student == nil {
		return fmt.Errorf("%w: student %s does not exist", ErrNotFound, req.StudentID)
	}
	return nil
}

func (s *guardianService) Create(ctx context.Context, req CreateGuardianRequest, idempotencyKey string) (*models.Guardian, error) {
	logger := s.logger.With(
		zap.String("method", "Create"),
		zap.String("student_id", req.StudentID.String()),
		zap.String("guardian_name", req.GuardianName),
		zap.String("idempotency_key", idempotencyKey),
	)
	s.sanitizeCreate(&req)

	tx, err := s.pgClient.BeginTx(ctx, nil)
	if err != nil {
		return nil, fmt.Errorf("begin tx: %w", err)
	}
	defer tx.Rollback()

	if idempotencyKey != "" {
		exists, err := s.idempotencyStore.Exists(ctx, tx, idempotencyKey)
		if err != nil {
			return nil, fmt.Errorf("idempotency check: %w", err)
		}
		if exists {
			var guardian models.Guardian
			if err := s.idempotencyStore.Get(ctx, tx, idempotencyKey, &guardian); err != nil {
				return nil, fmt.Errorf("failed to retrieve idempotent response: %w", err)
			}
			logger.Info("returning idempotent response")
			return &guardian, nil
		}
	}

	if err := s.validateCreateInput(req); err != nil {
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
		// CreatedBy, UpdatedBy not in model; handled by repo default timestamps
	}

	if err := s.repo.Create(ctx, tx, guardian); err != nil {
		return nil, err
	}

	if idempotencyKey != "" {
		if err := s.idempotencyStore.Store(ctx, tx, idempotencyKey, guardian); err != nil {
			logger.Error("failed to store idempotency key", zap.Error(err))
			return nil, fmt.Errorf("failed to store idempotency key: %w", err)
		}
	}

	// Audit log - use req.CreatedBy as actor
	if err := s.auditLogger.Log(ctx, tx, "CREATE", guardian.GuardianID, nil, guardian, req.CreatedBy); err != nil {
		logger.Error("audit log failed", zap.Error(err))
	}

	// Outbox event
	if err := s.outboxStore.Store(ctx, tx, string(EventGuardianCreated), guardian); err != nil {
		logger.Error("failed to store outbox event", zap.Error(err))
		return nil, fmt.Errorf("failed to store outbox event: %w", err)
	}

	// Fetch student to get company ID for notification
	var companyID uuid.UUID
	student, err := s.studentRepo.GetByID(ctx, tx, req.StudentID)
	if err != nil {
		logger.Error("failed to fetch student for company ID", zap.Error(err))
	} else if student != nil {
		companyID = student.CompanyID
	}

	if err := tx.Commit(); err != nil {
		return nil, fmt.Errorf("commit tx: %w", err)
	}

	logger.Info("guardian created", zap.String("id", guardian.GuardianID.String()))

	// Notify the actor about guardian creation
	if req.CreatedBy != nil && *req.CreatedBy != uuid.Nil {
		go func() {
			notifyCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			notifReq := CreateNotificationRequest{
				CompanyID: companyID,
				Title:     "Guardian Added",
				Message:   fmt.Sprintf("Guardian %s (%s) has been added for student.", guardian.GuardianName, guardian.Relation),
				Type:      models.NotificationTypeInfo,
				Priority:  models.PriorityNormal,
				Targets: []NotificationTargetInput{
					{
						TargetType:     models.TargetUser,
						TargetEntityID: *req.CreatedBy,
					},
				},
				CreatedBy: req.CreatedBy,
			}
			if _, err := s.notificationSvc.Create(notifyCtx, notifReq, "guardian.created:"+guardian.GuardianID.String()); err != nil {
				logger.Error("failed to create notification for guardian creation", zap.Error(err))
			}
		}()
	}

	return guardian, nil
}

func (s *guardianService) BulkCreate(ctx context.Context, reqs []CreateGuardianRequest) ([]*models.Guardian, error) {
	if len(reqs) == 0 {
		return nil, nil
	}

	logger := s.logger.With(zap.String("method", "BulkCreate"), zap.Int("count", len(reqs)))
	for i := range reqs {
		s.sanitizeCreate(&reqs[i])
	}

	// Validate all inputs
	for i, req := range reqs {
		if err := s.validateCreateInput(req); err != nil {
			return nil, fmt.Errorf("item %d: %w", i, err)
		}
	}

	tx, err := s.pgClient.BeginTx(ctx, nil)
	if err != nil {
		return nil, fmt.Errorf("begin tx: %w", err)
	}
	defer tx.Rollback()

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
			// CreatedBy, UpdatedBy not in model
		})
	}

	if err := s.repo.BulkCreate(ctx, tx, guardians); err != nil {
		return nil, err
	}

	for i, g := range guardians {
		// Audit log - use the request's CreatedBy
		if err := s.auditLogger.Log(ctx, tx, "CREATE", g.GuardianID, nil, g, reqs[i].CreatedBy); err != nil {
			logger.Error("audit log failed", zap.String("guardian_id", g.GuardianID.String()), zap.Error(err))
		}
		if err := s.outboxStore.Store(ctx, tx, string(EventGuardianCreated), g); err != nil {
			logger.Error("failed to store outbox event", zap.String("guardian_id", g.GuardianID.String()), zap.Error(err))
			return nil, fmt.Errorf("failed to store outbox event for guardian %s: %w", g.GuardianID, err)
		}
	}

	// Pre-fetch company IDs for each student
	companyIDs := make([]uuid.UUID, len(reqs))
	for i, req := range reqs {
		student, err := s.studentRepo.GetByID(ctx, tx, req.StudentID)
		if err != nil {
			logger.Error("failed to fetch student for company ID", zap.String("student_id", req.StudentID.String()), zap.Error(err))
		} else if student != nil {
			companyIDs[i] = student.CompanyID
		}
	}

	if err := tx.Commit(); err != nil {
		return nil, fmt.Errorf("commit tx: %w", err)
	}

	logger.Info("bulk created guardians", zap.Int("count", len(guardians)))

	// Notify each actor (if different)
	for i, g := range guardians {
		if reqs[i].CreatedBy != nil && *reqs[i].CreatedBy != uuid.Nil {
			go func(req CreateGuardianRequest, guardian *models.Guardian, companyID uuid.UUID) {
				notifyCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
				defer cancel()
				notifReq := CreateNotificationRequest{
					CompanyID: companyID,
					Title:     "Guardian Added (Bulk)",
					Message:   fmt.Sprintf("Guardian %s (%s) has been added for student.", guardian.GuardianName, guardian.Relation),
					Type:      models.NotificationTypeInfo,
					Priority:  models.PriorityNormal,
					Targets: []NotificationTargetInput{
						{
							TargetType:     models.TargetUser,
							TargetEntityID: *req.CreatedBy,
						},
					},
					CreatedBy: req.CreatedBy,
				}
				if _, err := s.notificationSvc.Create(notifyCtx, notifReq, "guardian.created:"+guardian.GuardianID.String()); err != nil {
					logger.Error("failed to create notification for bulk guardian creation",
						zap.String("guardian_id", guardian.GuardianID.String()),
						zap.Error(err))
				}
			}(reqs[i], g, companyIDs[i])
		}
	}

	return guardians, nil
}

func (s *guardianService) GetByID(ctx context.Context, id uuid.UUID) (*models.Guardian, error) {
	guardian, err := s.repo.GetByID(ctx, s.pgClient.DB, id)
	if err != nil {
		return nil, err
	}
	if guardian == nil {
		return nil, fmt.Errorf("%w: guardian %s", ErrNotFound, id)
	}
	return guardian, nil
}

func (s *guardianService) GetByStudentID(ctx context.Context, studentID uuid.UUID) ([]*models.Guardian, error) {
	return s.repo.GetByStudentID(ctx, s.pgClient.DB, studentID)
}

func (s *guardianService) GetPrimaryGuardian(ctx context.Context, studentID uuid.UUID) (*models.Guardian, error) {
	return s.repo.GetPrimaryGuardian(ctx, s.pgClient.DB, studentID)
}

func (s *guardianService) List(ctx context.Context, filter GuardianFilter, p repository.Pagination, srt repository.Sort) ([]*models.Guardian, error) {
	repoFilter := repository.GuardianFilter{
		StudentID: filter.StudentID,
		IsPrimary: filter.IsPrimary,
		Relation:  filter.Relation,
		Search:    filter.Search,
	}
	return s.repo.List(ctx, s.pgClient.DB, repoFilter, p, srt)
}

func (s *guardianService) Count(ctx context.Context, filter GuardianFilter) (int64, error) {
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

	tx, err := s.pgClient.BeginTx(ctx, nil)
	if err != nil {
		return nil, fmt.Errorf("begin tx: %w", err)
	}
	defer tx.Rollback()

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
	// Note: UpdatedBy not stored in model; repo will update updated_at automatically

	if err := s.repo.Update(ctx, tx, existing); err != nil {
		return nil, err
	}

	// Audit log - use req.UpdatedBy as actor
	if err := s.auditLogger.Log(ctx, tx, "UPDATE", existing.GuardianID, oldGuardian, existing, req.UpdatedBy); err != nil {
		logger.Error("audit log failed", zap.Error(err))
	}

	if err := s.outboxStore.Store(ctx, tx, string(EventGuardianUpdated), map[string]interface{}{
		"old": oldGuardian,
		"new": existing,
	}); err != nil {
		logger.Error("failed to store outbox event", zap.Error(err))
		return nil, fmt.Errorf("failed to store outbox event: %w", err)
	}

	// Get company ID for notification
	var companyID uuid.UUID
	student, err := s.studentRepo.GetByID(ctx, tx, existing.StudentID)
	if err != nil {
		logger.Error("failed to fetch student for company ID", zap.Error(err))
	} else if student != nil {
		companyID = student.CompanyID
	}

	if err := tx.Commit(); err != nil {
		return nil, fmt.Errorf("commit tx: %w", err)
	}

	logger.Info("guardian updated")

	// Notify the actor about guardian update
	if req.UpdatedBy != nil && *req.UpdatedBy != uuid.Nil {
		go func() {
			notifyCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			notifReq := CreateNotificationRequest{
				CompanyID: companyID,
				Title:     "Guardian Updated",
				Message:   fmt.Sprintf("Guardian %s (%s) has been updated.", existing.GuardianName, existing.Relation),
				Type:      models.NotificationTypeInfo,
				Priority:  models.PriorityNormal,
				Targets: []NotificationTargetInput{
					{
						TargetType:     models.TargetUser,
						TargetEntityID: *req.UpdatedBy,
					},
				},
				CreatedBy: req.UpdatedBy,
			}
			if _, err := s.notificationSvc.Create(notifyCtx, notifReq, "guardian.updated:"+existing.GuardianID.String()); err != nil {
				logger.Error("failed to create notification for guardian update", zap.Error(err))
			}
		}()
	}

	return existing, nil
}

func (s *guardianService) Delete(ctx context.Context, id uuid.UUID, deletedBy *uuid.UUID) error {
	logger := s.logger.With(zap.String("method", "Delete"), zap.String("guardian_id", id.String()))

	tx, err := s.pgClient.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("begin tx: %w", err)
	}
	defer tx.Rollback()

	// Fetch guardian for notification (before delete)
	guardian, err := s.repo.GetByID(ctx, tx, id)
	if err != nil {
		return err
	}
	if guardian == nil {
		return fmt.Errorf("%w: guardian %s", ErrNotFound, id)
	}

	// Get student for company ID
	var companyID uuid.UUID
	student, err := s.studentRepo.GetByID(ctx, tx, guardian.StudentID)
	if err != nil {
		logger.Error("failed to fetch student for company ID", zap.Error(err))
	} else if student != nil {
		companyID = student.CompanyID
	}

	if err := s.repo.Delete(ctx, tx, id); err != nil {
		return err
	}

	if err := s.auditLogger.Log(ctx, tx, "DELETE", id, nil, nil, deletedBy); err != nil {
		logger.Error("audit log failed", zap.Error(err))
	}

	if err := s.outboxStore.Store(ctx, tx, string(EventGuardianDeleted), map[string]interface{}{
		"guardian_id": id,
		"deleted_by":  deletedBy,
	}); err != nil {
		logger.Error("failed to store outbox event", zap.Error(err))
		return fmt.Errorf("failed to store outbox event: %w", err)
	}

	if err := tx.Commit(); err != nil {
		return fmt.Errorf("commit tx: %w", err)
	}

	logger.Info("guardian deleted")

	// Notify the actor about guardian deletion
	if deletedBy != nil && *deletedBy != uuid.Nil {
		go func() {
			notifyCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			notifReq := CreateNotificationRequest{
				CompanyID: companyID,
				Title:     "Guardian Deleted",
				Message:   fmt.Sprintf("Guardian %s (%s) has been deleted.", guardian.GuardianName, guardian.Relation),
				Type:      models.NotificationTypeWarning,
				Priority:  models.PriorityHigh,
				Targets: []NotificationTargetInput{
					{
						TargetType:     models.TargetUser,
						TargetEntityID: *deletedBy,
					},
				},
				CreatedBy: deletedBy,
			}
			if _, err := s.notificationSvc.Create(notifyCtx, notifReq, "guardian.deleted:"+id.String()); err != nil {
				logger.Error("failed to create notification for guardian deletion", zap.Error(err))
			}
		}()
	}

	return nil
}

func (s *guardianService) SetPrimary(ctx context.Context, studentID, guardianID uuid.UUID, updatedBy *uuid.UUID) error {
	logger := s.logger.With(
		zap.String("method", "SetPrimary"),
		zap.String("student_id", studentID.String()),
		zap.String("guardian_id", guardianID.String()),
	)

	tx, err := s.pgClient.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("begin tx: %w", err)
	}
	defer tx.Rollback()

	if err := s.repo.SetPrimary(ctx, tx, studentID, guardianID); err != nil {
		return err
	}

	if err := s.auditLogger.Log(ctx, tx, "SET_PRIMARY", guardianID, nil, map[string]interface{}{"student_id": studentID}, updatedBy); err != nil {
		logger.Error("audit log failed", zap.Error(err))
	}

	if err := s.outboxStore.Store(ctx, tx, string(EventGuardianPrimarySet), map[string]interface{}{
		"student_id":  studentID,
		"guardian_id": guardianID,
		"updated_by":  updatedBy,
	}); err != nil {
		logger.Error("failed to store outbox event", zap.Error(err))
		return fmt.Errorf("failed to store outbox event: %w", err)
	}

	// Fetch guardian and student for notification
	guardian, err := s.repo.GetByID(ctx, tx, guardianID)
	if err != nil {
		logger.Error("failed to fetch guardian for notification", zap.Error(err))
	}
	student, err := s.studentRepo.GetByID(ctx, tx, studentID)
	if err != nil {
		logger.Error("failed to fetch student for notification", zap.Error(err))
	}
	companyID := uuid.Nil
	if student != nil {
		companyID = student.CompanyID
	}

	if err := tx.Commit(); err != nil {
		return fmt.Errorf("commit tx: %w", err)
	}

	logger.Info("primary guardian set")

	// Notify the actor about primary change
	if updatedBy != nil && *updatedBy != uuid.Nil {
		go func() {
			notifyCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			notifReq := CreateNotificationRequest{
				CompanyID: companyID,
				Title:     "Primary Guardian Changed",
				Message:   fmt.Sprintf("Guardian %s (%s) has been set as primary for the student.", guardian.GuardianName, guardian.Relation),
				Type:      models.NotificationTypeInfo,
				Priority:  models.PriorityNormal,
				Targets: []NotificationTargetInput{
					{
						TargetType:     models.TargetUser,
						TargetEntityID: *updatedBy,
					},
				},
				CreatedBy: updatedBy,
			}
			if _, err := s.notificationSvc.Create(notifyCtx, notifReq, "guardian.primary:"+guardianID.String()); err != nil {
				logger.Error("failed to create notification for primary guardian change", zap.Error(err))
			}
		}()
	}

	return nil
}

func (s *guardianService) Exists(ctx context.Context, studentID uuid.UUID, guardianName, relation string) (bool, error) {
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

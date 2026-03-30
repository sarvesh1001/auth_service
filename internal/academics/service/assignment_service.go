package service

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/google/uuid"
	"go.uber.org/zap"

	"auth-service/internal/academics/models"
	"auth-service/internal/academics/repository"
	"auth-service/internal/client"
)

// Request/Response structures
type CreateAssignmentRequest struct {
	SectionID     uuid.UUID  `json:"section_id"`
	SubjectID     uuid.UUID  `json:"subject_id"`
	TeacherID     uuid.UUID  `json:"teacher_id"`
	Title         string     `json:"title"`
	Description   string     `json:"description,omitempty"`
	DueDate       time.Time  `json:"due_date"`
	MaxMarks      *float64   `json:"max_marks,omitempty"`
	AttachmentURL string     `json:"attachment_url,omitempty"`
	IsPublished   bool       `json:"is_published"`
	CreatedBy     *uuid.UUID `json:"created_by,omitempty"`
	UpdatedBy     *uuid.UUID `json:"updated_by,omitempty"`
}

type UpdateAssignmentRequest struct {
	AssignmentID  uuid.UUID  `json:"assignment_id"`
	SectionID     uuid.UUID  `json:"section_id"`
	SubjectID     uuid.UUID  `json:"subject_id"`
	TeacherID     uuid.UUID  `json:"teacher_id"`
	Title         string     `json:"title"`
	Description   string     `json:"description,omitempty"`
	DueDate       time.Time  `json:"due_date"`
	MaxMarks      *float64   `json:"max_marks,omitempty"`
	AttachmentURL string     `json:"attachment_url,omitempty"`
	IsPublished   bool       `json:"is_published"`
	UpdatedBy     *uuid.UUID `json:"updated_by,omitempty"`
}

type AssignmentService interface {
	Create(ctx context.Context, req CreateAssignmentRequest, idempotencyKey string) (*models.Assignment, error)
	BulkCreate(ctx context.Context, reqs []CreateAssignmentRequest) ([]*models.Assignment, error)
	GetByID(ctx context.Context, id uuid.UUID) (*models.Assignment, error)
	List(ctx context.Context, filter repository.AssignmentFilter, pagination repository.Pagination, sort repository.Sort) ([]*models.Assignment, error)
	Count(ctx context.Context, filter repository.AssignmentFilter) (int64, error)
	Update(ctx context.Context, req UpdateAssignmentRequest) (*models.Assignment, error)
	Delete(ctx context.Context, id uuid.UUID, deletedBy *uuid.UUID) error
	Publish(ctx context.Context, id uuid.UUID, published bool, updatedBy *uuid.UUID) error
}

type assignmentService struct {
	repo             repository.AssignmentRepository
	teacherRepo      repository.TeacherRepository
	subjectRepo      repository.SubjectRepository
	courseRepo       repository.CourseRepository
	sectionRepo      repository.SectionRepository
	idempotencyStore IdempotencyStore
	auditLogger      AuditLogger
	outboxStore      OutboxStore
	eventPublisher   EventPublisher
	notificationSvc  NotificationService
	pgClient         *client.PostgresClient
	logger           *zap.Logger
}

func NewAssignmentService(
	repo repository.AssignmentRepository,
	teacherRepo repository.TeacherRepository,
	subjectRepo repository.SubjectRepository,
	courseRepo repository.CourseRepository, // <-- added
	sectionRepo repository.SectionRepository,
	idempotencyStore IdempotencyStore,
	auditLogger AuditLogger,
	outboxStore OutboxStore,
	eventPublisher EventPublisher,
	notificationSvc NotificationService,
	pgClient *client.PostgresClient,
	logger *zap.Logger,
) AssignmentService {
	return &assignmentService{
		repo:             repo,
		teacherRepo:      teacherRepo,
		subjectRepo:      subjectRepo,
		courseRepo:       courseRepo,
		sectionRepo:      sectionRepo,
		idempotencyStore: idempotencyStore,
		auditLogger:      auditLogger,
		outboxStore:      outboxStore,
		eventPublisher:   eventPublisher,
		notificationSvc:  notificationSvc,
		pgClient:         pgClient,
		logger:           logger.Named("assignment_service"),
	}
}

// Validation helpers
func (s *assignmentService) validateCreate(req CreateAssignmentRequest) error {
	if req.SectionID == uuid.Nil {
		return fmt.Errorf("%w: section_id is required", ErrInvalidInput)
	}
	if req.SubjectID == uuid.Nil {
		return fmt.Errorf("%w: subject_id is required", ErrInvalidInput)
	}
	if req.TeacherID == uuid.Nil {
		return fmt.Errorf("%w: teacher_id is required", ErrInvalidInput)
	}
	if strings.TrimSpace(req.Title) == "" {
		return fmt.Errorf("%w: title is required", ErrInvalidInput)
	}
	if req.DueDate.IsZero() {
		return fmt.Errorf("%w: due_date is required", ErrInvalidInput)
	}
	// Optional: validate due date not in the past (allow same day)
	if req.DueDate.Before(time.Now().Truncate(24 * time.Hour)) {
		return fmt.Errorf("%w: due_date cannot be in the past", ErrInvalidInput)
	}
	if req.MaxMarks != nil && *req.MaxMarks < 0 {
		return fmt.Errorf("%w: max_marks cannot be negative", ErrInvalidInput)
	}
	return nil
}

func (s *assignmentService) validateUpdate(req UpdateAssignmentRequest) error {
	if req.AssignmentID == uuid.Nil {
		return fmt.Errorf("%w: assignment_id is required", ErrInvalidInput)
	}
	if req.SectionID == uuid.Nil {
		return fmt.Errorf("%w: section_id is required", ErrInvalidInput)
	}
	if req.SubjectID == uuid.Nil {
		return fmt.Errorf("%w: subject_id is required", ErrInvalidInput)
	}
	if req.TeacherID == uuid.Nil {
		return fmt.Errorf("%w: teacher_id is required", ErrInvalidInput)
	}
	if strings.TrimSpace(req.Title) == "" {
		return fmt.Errorf("%w: title is required", ErrInvalidInput)
	}
	if req.DueDate.IsZero() {
		return fmt.Errorf("%w: due_date is required", ErrInvalidInput)
	}
	if req.DueDate.Before(time.Now().Truncate(24 * time.Hour)) {
		return fmt.Errorf("%w: due_date cannot be in the past", ErrInvalidInput)
	}
	if req.MaxMarks != nil && *req.MaxMarks < 0 {
		return fmt.Errorf("%w: max_marks cannot be negative", ErrInvalidInput)
	}
	return nil
}

func (s *assignmentService) validateDomain(ctx context.Context, tx repository.DBTX, sectionID, subjectID, teacherID uuid.UUID) error {
	// Check section exists
	section, err := s.sectionRepo.GetByID(ctx, tx, sectionID)
	if err != nil {
		return err
	}
	if section == nil {
		return fmt.Errorf("%w: section %s", ErrNotFound, sectionID)
	}
	// Check subject exists
	subject, err := s.subjectRepo.GetByID(ctx, tx, subjectID)
	if err != nil {
		return err
	}
	if subject == nil {
		return fmt.Errorf("%w: subject %s", ErrNotFound, subjectID)
	}
	// Check teacher exists
	teacher, err := s.teacherRepo.GetByID(ctx, tx, teacherID)
	if err != nil {
		return err
	}
	if teacher == nil {
		return fmt.Errorf("%w: teacher %s", ErrNotFound, teacherID)
	}
	// Optional: verify that teacher is assigned to this subject (maybe via teacher_subject)
	// We'll skip for simplicity, but you can add checks.
	return nil
}

// Create implements AssignmentService.
func (s *assignmentService) Create(ctx context.Context, req CreateAssignmentRequest, idempotencyKey string) (*models.Assignment, error) {
	logger := s.logger.With(
		zap.String("method", "Create"),
		zap.String("section_id", req.SectionID.String()),
		zap.String("subject_id", req.SubjectID.String()),
		zap.String("teacher_id", req.TeacherID.String()),
		zap.String("title", req.Title),
		zap.String("idempotency_key", idempotencyKey),
	)

	// Sanitize
	req.Title = strings.TrimSpace(req.Title)
	req.Description = strings.TrimSpace(req.Description)

	if err := s.validateCreate(req); err != nil {
		return nil, err
	}

	tx, err := s.pgClient.BeginTx(ctx, nil)
	if err != nil {
		return nil, fmt.Errorf("begin tx: %w", err)
	}
	defer tx.Rollback()

	// Idempotency check
	if idempotencyKey != "" {
		exists, err := s.idempotencyStore.Exists(ctx, tx, idempotencyKey)
		if err != nil {
			return nil, fmt.Errorf("idempotency check: %w", err)
		}
		if exists {
			var assignment models.Assignment
			if err := s.idempotencyStore.Get(ctx, tx, idempotencyKey, &assignment); err != nil {
				return nil, fmt.Errorf("failed to retrieve idempotent response: %w", err)
			}
			logger.Info("returning idempotent response")
			return &assignment, nil
		}
	}

	// Validate domain objects
	if err := s.validateDomain(ctx, tx, req.SectionID, req.SubjectID, req.TeacherID); err != nil {
		return nil, err
	}

	assignment := &models.Assignment{
		SectionID:     req.SectionID,
		SubjectID:     req.SubjectID,
		TeacherID:     req.TeacherID,
		Title:         req.Title,
		Description:   req.Description,
		DueDate:       req.DueDate,
		MaxMarks:      req.MaxMarks,
		AttachmentURL: req.AttachmentURL,
		IsPublished:   req.IsPublished,
		CreatedBy:     req.CreatedBy,
		UpdatedBy:     req.UpdatedBy,
	}

	if err := s.repo.Create(ctx, tx, assignment); err != nil {
		return nil, err
	}

	// Store idempotency key
	if idempotencyKey != "" {
		if err := s.idempotencyStore.Store(ctx, tx, idempotencyKey, assignment); err != nil {
			logger.Error("failed to store idempotency key", zap.Error(err))
			return nil, fmt.Errorf("failed to store idempotency key: %w", err)
		}
	}

	// Audit log
	if err := s.auditLogger.Log(ctx, tx, "ASSIGNMENT_CREATE", assignment.AssignmentID, nil, assignment, req.CreatedBy); err != nil {
		logger.Error("audit log failed", zap.Error(err))
	}

	// Outbox event
	eventType := EventAssignmentCreated
	if err := s.outboxStore.Store(ctx, tx, string(eventType), assignment); err != nil {
		logger.Error("failed to store outbox event", zap.Error(err))
		return nil, fmt.Errorf("store outbox event: %w", err)
	}

	// Commit transaction
	if err := tx.Commit(); err != nil {
		return nil, fmt.Errorf("commit tx: %w", err)
	}

	logger.Info("assignment created", zap.String("assignment_id", assignment.AssignmentID.String()))

	// Send notifications if published
	if assignment.IsPublished {
		s.sendAssignmentNotification(ctx, assignment, "created and published", req.CreatedBy)
	} else {
		// Optionally notify teacher that draft is created
		s.sendTeacherNotification(ctx, assignment, "draft created", req.CreatedBy)
	}

	return assignment, nil
}

// BulkCreate implements AssignmentService.
func (s *assignmentService) BulkCreate(ctx context.Context, reqs []CreateAssignmentRequest) ([]*models.Assignment, error) {
	if len(reqs) == 0 {
		return nil, nil
	}
	logger := s.logger.With(zap.String("method", "BulkCreate"), zap.Int("count", len(reqs)))

	// Sanitize and validate all
	for i, req := range reqs {
		req.Title = strings.TrimSpace(req.Title)
		req.Description = strings.TrimSpace(req.Description)
		if err := s.validateCreate(req); err != nil {
			return nil, fmt.Errorf("item %d: %w", i, err)
		}
	}

	tx, err := s.pgClient.BeginTx(ctx, nil)
	if err != nil {
		return nil, fmt.Errorf("begin tx: %w", err)
	}
	defer tx.Rollback()

	// Pre-load domain objects for uniqueness
	// We'll simply call validateDomain for each (could be optimized with batch queries)
	assignments := make([]*models.Assignment, 0, len(reqs))
	for i, req := range reqs {
		if err := s.validateDomain(ctx, tx, req.SectionID, req.SubjectID, req.TeacherID); err != nil {
			return nil, fmt.Errorf("item %d: %w", i, err)
		}
		assignments = append(assignments, &models.Assignment{
			SectionID:     req.SectionID,
			SubjectID:     req.SubjectID,
			TeacherID:     req.TeacherID,
			Title:         req.Title,
			Description:   req.Description,
			DueDate:       req.DueDate,
			MaxMarks:      req.MaxMarks,
			AttachmentURL: req.AttachmentURL,
			IsPublished:   req.IsPublished,
			CreatedBy:     req.CreatedBy,
			UpdatedBy:     req.UpdatedBy,
		})
	}

	// Bulk create (repository must support bulk insert)
	if err := s.repo.BulkCreate(ctx, tx, assignments); err != nil {
		return nil, err
	}

	// Audit logs and outbox events
	for _, a := range assignments {
		if err := s.auditLogger.Log(ctx, tx, "ASSIGNMENT_BULK_CREATE", a.AssignmentID, nil, a, a.CreatedBy); err != nil {
			logger.Error("audit log failed", zap.String("assignment_id", a.AssignmentID.String()), zap.Error(err))
		}
		if err := s.outboxStore.Store(ctx, tx, string(EventAssignmentCreated), a); err != nil {
			logger.Error("failed to store outbox event", zap.String("assignment_id", a.AssignmentID.String()), zap.Error(err))
			return nil, fmt.Errorf("store outbox event for assignment %s: %w", a.AssignmentID, err)
		}
	}

	if err := tx.Commit(); err != nil {
		return nil, fmt.Errorf("commit tx: %w", err)
	}

	logger.Info("bulk created assignments", zap.Int("count", len(assignments)))

	// Send notifications in background
	for _, a := range assignments {
		if a.IsPublished {
			s.sendAssignmentNotification(ctx, a, "created and published", a.CreatedBy)
		} else {
			s.sendTeacherNotification(ctx, a, "draft created", a.CreatedBy)
		}
	}

	return assignments, nil
}

// GetByID implements AssignmentService.
func (s *assignmentService) GetByID(ctx context.Context, id uuid.UUID) (*models.Assignment, error) {
	a, err := s.repo.GetByID(ctx, s.pgClient.DB, id)
	if err != nil {
		return nil, err
	}
	if a == nil {
		return nil, fmt.Errorf("%w: assignment %s", ErrNotFound, id)
	}
	return a, nil
}

// List implements AssignmentService.
func (s *assignmentService) List(ctx context.Context, filter repository.AssignmentFilter, pagination repository.Pagination, sort repository.Sort) ([]*models.Assignment, error) {
	return s.repo.List(ctx, s.pgClient.DB, filter, pagination, sort)
}

// Count implements AssignmentService.
func (s *assignmentService) Count(ctx context.Context, filter repository.AssignmentFilter) (int64, error) {
	return s.repo.Count(ctx, s.pgClient.DB, filter)
}

// Update implements AssignmentService.
func (s *assignmentService) Update(ctx context.Context, req UpdateAssignmentRequest) (*models.Assignment, error) {
	logger := s.logger.With(zap.String("method", "Update"), zap.String("assignment_id", req.AssignmentID.String()))

	req.Title = strings.TrimSpace(req.Title)
	req.Description = strings.TrimSpace(req.Description)

	if err := s.validateUpdate(req); err != nil {
		return nil, err
	}

	tx, err := s.pgClient.BeginTx(ctx, nil)
	if err != nil {
		return nil, fmt.Errorf("begin tx: %w", err)
	}
	defer tx.Rollback()

	// Fetch existing for concurrency check
	existing, err := s.repo.GetByID(ctx, tx, req.AssignmentID)
	if err != nil {
		return nil, err
	}
	if existing == nil {
		return nil, fmt.Errorf("%w: assignment %s", ErrNotFound, req.AssignmentID)
	}

	// Validate domain references (they might have changed)
	if err := s.validateDomain(ctx, tx, req.SectionID, req.SubjectID, req.TeacherID); err != nil {
		return nil, err
	}

	// Prepare updated assignment
	updated := &models.Assignment{
		AssignmentID:  req.AssignmentID,
		SectionID:     req.SectionID,
		SubjectID:     req.SubjectID,
		TeacherID:     req.TeacherID,
		Title:         req.Title,
		Description:   req.Description,
		DueDate:       req.DueDate,
		MaxMarks:      req.MaxMarks,
		AttachmentURL: req.AttachmentURL,
		IsPublished:   req.IsPublished,
		UpdatedBy:     req.UpdatedBy,
	}

	if err := s.repo.Update(ctx, tx, updated); err != nil {
		if errors.Is(err, repository.ErrVersionConflict) {
			return nil, fmt.Errorf("%w: assignment was modified concurrently", ErrConcurrentUpdate)
		}
		return nil, err
	}

	// Audit log
	if err := s.auditLogger.Log(ctx, tx, "ASSIGNMENT_UPDATE", req.AssignmentID, existing, updated, req.UpdatedBy); err != nil {
		logger.Error("audit log failed", zap.Error(err))
	}

	// Outbox event
	if err := s.outboxStore.Store(ctx, tx, string(EventAssignmentUpdated), map[string]interface{}{
		"old": existing,
		"new": updated,
	}); err != nil {
		logger.Error("failed to store outbox event", zap.Error(err))
		return nil, fmt.Errorf("store outbox event: %w", err)
	}

	if err := tx.Commit(); err != nil {
		return nil, fmt.Errorf("commit tx: %w", err)
	}

	logger.Info("assignment updated")

	// Send notification if published status changed
	if !existing.IsPublished && updated.IsPublished {
		s.sendAssignmentNotification(ctx, updated, "published", req.UpdatedBy)
	} else if updated.IsPublished {
		s.sendAssignmentNotification(ctx, updated, "updated", req.UpdatedBy)
	} else {
		s.sendTeacherNotification(ctx, updated, "updated (draft)", req.UpdatedBy)
	}

	return updated, nil
}

// Delete implements AssignmentService.
func (s *assignmentService) Delete(ctx context.Context, id uuid.UUID, deletedBy *uuid.UUID) error {
	logger := s.logger.With(zap.String("method", "Delete"), zap.String("assignment_id", id.String()))

	tx, err := s.pgClient.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("begin tx: %w", err)
	}
	defer tx.Rollback()

	// Fetch for audit
	existing, _ := s.repo.GetByID(ctx, tx, id)

	if err := s.repo.Delete(ctx, tx, id, deletedBy); err != nil {
		return err
	}

	// Audit
	if err := s.auditLogger.Log(ctx, tx, "ASSIGNMENT_DELETE", id, existing, nil, deletedBy); err != nil {
		logger.Error("audit log failed", zap.Error(err))
	}

	// Outbox
	if err := s.outboxStore.Store(ctx, tx, string(EventAssignmentDeleted), map[string]interface{}{
		"assignment_id": id,
		"deleted_by":    deletedBy,
	}); err != nil {
		logger.Error("failed to store outbox event", zap.Error(err))
		return fmt.Errorf("store outbox event: %w", err)
	}

	if err := tx.Commit(); err != nil {
		return fmt.Errorf("commit tx: %w", err)
	}

	logger.Info("assignment deleted")
	return nil
}

// Publish implements AssignmentService.
func (s *assignmentService) Publish(ctx context.Context, id uuid.UUID, published bool, updatedBy *uuid.UUID) error {
	logger := s.logger.With(
		zap.String("method", "Publish"),
		zap.String("assignment_id", id.String()),
		zap.Bool("publish", published),
	)

	tx, err := s.pgClient.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("begin tx: %w", err)
	}
	defer tx.Rollback()

	// Fetch existing to check current state
	existing, err := s.repo.GetByID(ctx, tx, id)
	if err != nil {
		return err
	}
	if existing == nil {
		return fmt.Errorf("%w: assignment %s", ErrNotFound, id)
	}

	if existing.IsPublished == published {
		logger.Info("assignment already in requested state")
		return nil
	}

	if err := s.repo.Publish(ctx, tx, id, published, updatedBy); err != nil {
		return err
	}

	// Audit
	if err := s.auditLogger.Log(ctx, tx, "ASSIGNMENT_PUBLISH", id, map[string]interface{}{"is_published": existing.IsPublished}, map[string]interface{}{"is_published": published}, updatedBy); err != nil {
		logger.Error("audit log failed", zap.Error(err))
	}

	// Outbox event
	eventType := EventAssignmentPublished
	if err := s.outboxStore.Store(ctx, tx, string(eventType), map[string]interface{}{
		"assignment_id": id,
		"published":     published,
		"updated_by":    updatedBy,
	}); err != nil {
		logger.Error("failed to store outbox event", zap.Error(err))
		return fmt.Errorf("store outbox event: %w", err)
	}

	if err := tx.Commit(); err != nil {
		return fmt.Errorf("commit tx: %w", err)
	}

	logger.Info("assignment publish status changed")

	if published {
		// Send notification to students (and teacher)
		s.sendAssignmentNotification(ctx, existing, "published", updatedBy)
	} else {
		s.sendTeacherNotification(ctx, existing, "unpublished", updatedBy)
	}

	return nil
}

// Helper to get company ID from a section (via course)
func (s *assignmentService) getCompanyIDForSection(ctx context.Context, db repository.DBTX, sectionID uuid.UUID) (uuid.UUID, error) {
	section, err := s.sectionRepo.GetByID(ctx, db, sectionID)
	if err != nil {
		return uuid.Nil, err
	}
	if section == nil {
		return uuid.Nil, fmt.Errorf("%w: section %s", ErrNotFound, sectionID)
	}
	course, err := s.courseRepo.GetByID(ctx, db, section.CourseID)
	if err != nil {
		return uuid.Nil, err
	}
	if course == nil {
		return uuid.Nil, fmt.Errorf("%w: course %s", ErrNotFound, section.CourseID)
	}
	return course.CompanyID, nil
}

// Helper to send notification to students in the section (and optionally teacher)
func (s *assignmentService) sendAssignmentNotification(ctx context.Context, a *models.Assignment, action string, createdBy *uuid.UUID) {
	go func() {
		notifyCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()

		// Fetch company ID for the section (needed for notification)
		companyID, err := s.getCompanyIDForSection(notifyCtx, s.pgClient.DB, a.SectionID)
		if err != nil {
			s.logger.Error("failed to get company ID for section", zap.String("section_id", a.SectionID.String()), zap.Error(err))
			return
		}

		notifReq := CreateNotificationRequest{
			CompanyID: companyID,
			Title:     fmt.Sprintf("New Assignment: %s", a.Title),
			Message:   fmt.Sprintf("A new assignment '%s' has been %s. Due date: %s.", a.Title, action, a.DueDate.Format("2006-01-02")),
			Type:      models.NotificationTypeInfo,
			Priority:  models.PriorityNormal,
			Targets: []NotificationTargetInput{
				{
					TargetType:     models.TargetSection,
					TargetEntityID: a.SectionID,
				},
			},
			CreatedBy: createdBy,
		}
		if _, err := s.notificationSvc.Create(notifyCtx, notifReq, "assignment."+a.AssignmentID.String()); err != nil {
			s.logger.Error("failed to create notification for assignment", zap.Error(err))
		}
	}()
}

func (s *assignmentService) sendTeacherNotification(ctx context.Context, a *models.Assignment, action string, createdBy *uuid.UUID) {
	go func() {
		notifyCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()

		// Fetch teacher using the DB handle
		teacher, err := s.teacherRepo.GetByID(notifyCtx, s.pgClient.DB, a.TeacherID)
		if err != nil || teacher == nil {
			s.logger.Error("failed to fetch teacher for notification", zap.String("teacher_id", a.TeacherID.String()), zap.Error(err))
			return
		}

		notifReq := CreateNotificationRequest{
			CompanyID: teacher.CompanyID, // Use teacher's companyID
			Title:     fmt.Sprintf("Assignment %s: %s", action, a.Title),
			Message:   fmt.Sprintf("Your assignment '%s' has been %s.", a.Title, action),
			Type:      models.NotificationTypeInfo,
			Priority:  models.PriorityNormal,
			Targets: []NotificationTargetInput{
				{
					TargetType:     models.TargetUser,
					TargetEntityID: teacher.UserID,
				},
			},
			CreatedBy: createdBy,
		}
		if _, err := s.notificationSvc.Create(notifyCtx, notifReq, "assignment.teacher."+a.AssignmentID.String()); err != nil {
			s.logger.Error("failed to create teacher notification for assignment", zap.Error(err))
		}
	}()
}

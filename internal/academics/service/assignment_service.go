package service

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
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

// ================================
// Request & Response Types
// ================================

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

// ================================
// Service Interface
// ================================

type AssignmentService interface {
	Create(ctx context.Context, req CreateAssignmentRequest, idempotencyKey string) (*models.Assignment, error)
	BulkCreate(ctx context.Context, reqs []CreateAssignmentRequest, idempotencyKey string) ([]*models.Assignment, error)
	GetByID(ctx context.Context, id uuid.UUID) (*models.Assignment, error)
	List(ctx context.Context, filter repository.AssignmentFilter, pagination repository.Pagination, sort repository.Sort) ([]*models.Assignment, error)
	Count(ctx context.Context, filter repository.AssignmentFilter) (int64, error)
	Update(ctx context.Context, req UpdateAssignmentRequest) (*models.Assignment, error)
	Delete(ctx context.Context, id uuid.UUID, deletedBy *uuid.UUID) error
	Publish(ctx context.Context, id uuid.UUID, published bool, updatedBy *uuid.UUID) error
}

// ================================
// Service Implementation
// ================================

type assignmentService struct {
	repo             repository.AssignmentRepository
	teacherRepo      repository.TeacherRepository
	subjectRepo      repository.SubjectRepository
	courseRepo       repository.CourseRepository
	sectionRepo      repository.SectionRepository
	pgClient         *client.PostgresClient
	logger           *zap.Logger
	notificationSvc  NotificationService
	eventPublisher   EventPublisher
	idempotencyStore idempotency.Store
	auditService     *audit.AuditService
	outboxRepo       outbox.Repository
}

func NewAssignmentService(
	repo repository.AssignmentRepository,
	teacherRepo repository.TeacherRepository,
	subjectRepo repository.SubjectRepository,
	courseRepo repository.CourseRepository,
	sectionRepo repository.SectionRepository,
	pgClient *client.PostgresClient,
	logger *zap.Logger,
	notificationSvc NotificationService,
	eventPublisher EventPublisher,
	idempotencyStore idempotency.Store,
	auditService *audit.AuditService,
	outboxRepo outbox.Repository,
) AssignmentService {
	return &assignmentService{
		repo:             repo,
		teacherRepo:      teacherRepo,
		subjectRepo:      subjectRepo,
		courseRepo:       courseRepo,
		sectionRepo:      sectionRepo,
		pgClient:         pgClient,
		logger:           logger.Named("assignment_service"),
		notificationSvc:  notificationSvc,
		eventPublisher:   eventPublisher,
		idempotencyStore: idempotencyStore,
		auditService:     auditService,
		outboxRepo:       outboxRepo,
	}
}

// ------------------------------
// Create (single)
// ------------------------------
func (s *assignmentService) Create(ctx context.Context, req CreateAssignmentRequest, idempotencyKey string) (*models.Assignment, error) {
	logger := s.logger.With(
		zap.String("method", "Create"),
		zap.String("section_id", req.SectionID.String()),
		zap.String("subject_id", req.SubjectID.String()),
		zap.String("teacher_id", req.TeacherID.String()),
		zap.String("title", req.Title),
		zap.String("idempotency_key", idempotencyKey),
	)

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
		var existing models.Assignment
		if err := s.idempotencyStore.Get(ctx, tx, idempotencyKey, &existing); err == nil && existing.AssignmentID != uuid.Nil {
			logger.Info("returning idempotent response")
			return &existing, nil
		}
	}

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

	// Store idempotency response
	if idempotencyKey != "" {
		if err := s.idempotencyStore.Store(ctx, tx, idempotencyKey, assignment); err != nil {
			logger.Error("failed to store idempotency key", zap.Error(err))
		}
	}

	// Audit
	if s.auditService != nil {
		_ = s.auditService.LogAction(ctx, nil, nil, "academics", "create", "assignment",
			&assignment.AssignmentID, "user", req.CreatedBy, nil, nil, map[string]interface{}{
				"title":        assignment.Title,
				"section_id":   assignment.SectionID.String(),
				"subject_id":   assignment.SubjectID.String(),
				"teacher_id":   assignment.TeacherID.String(),
				"due_date":     assignment.DueDate,
				"is_published": assignment.IsPublished,
			})
	}

	// Outbox
	if err := s.storeOutboxEvent(ctx, tx, EventAssignmentCreated, assignment, nil); err != nil {
		return nil, fmt.Errorf("outbox store: %w", err)
	}

	if err := tx.Commit(); err != nil {
		return nil, fmt.Errorf("commit tx: %w", err)
	}

	logger.Info("assignment created", zap.String("assignment_id", assignment.AssignmentID.String()))

	// Async notifications
	if assignment.IsPublished {
		s.sendAssignmentNotification(ctx, assignment, "created and published", req.CreatedBy)
	} else {
		s.sendTeacherNotification(ctx, assignment, "draft created", req.CreatedBy)
	}

	return assignment, nil
}

// ------------------------------
// Bulk Create (with idempotency)
// ------------------------------
func (s *assignmentService) BulkCreate(ctx context.Context, reqs []CreateAssignmentRequest, idempotencyKey string) ([]*models.Assignment, error) {
	if len(reqs) == 0 {
		return nil, nil
	}

	logger := s.logger.With(zap.String("method", "BulkCreate"), zap.Int("count", len(reqs)), zap.String("idempotency_key", idempotencyKey))

	// Validate all requests
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

	// Idempotency check for bulk
	if idempotencyKey != "" {
		var existing []*models.Assignment
		if err := s.idempotencyStore.Get(ctx, tx, idempotencyKey, &existing); err == nil && existing != nil {
			logger.Info("returning idempotent response for bulk")
			return existing, nil
		}
	}

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

	if err := s.repo.BulkCreate(ctx, tx, assignments); err != nil {
		return nil, err
	}

	// Store idempotency response
	if idempotencyKey != "" {
		if err := s.idempotencyStore.Store(ctx, tx, idempotencyKey, assignments); err != nil {
			logger.Error("failed to store idempotency key for bulk", zap.Error(err))
		}
	}

	// Audit & outbox for each assignment
	for _, a := range assignments {
		if s.auditService != nil {
			_ = s.auditService.LogAction(ctx, nil, nil, "academics", "bulk_create", "assignment",
				&a.AssignmentID, "user", a.CreatedBy, nil, nil, map[string]interface{}{
					"title": a.Title,
				})
		}
		if err := s.storeOutboxEvent(ctx, tx, EventAssignmentCreated, a, nil); err != nil {
			return nil, fmt.Errorf("outbox store for assignment %s: %w", a.AssignmentID, err)
		}
	}

	if err := tx.Commit(); err != nil {
		return nil, fmt.Errorf("commit tx: %w", err)
	}

	logger.Info("bulk created assignments", zap.Int("count", len(assignments)))

	// Async notifications
	for _, a := range assignments {
		if a.IsPublished {
			s.sendAssignmentNotification(ctx, a, "created and published", a.CreatedBy)
		} else {
			s.sendTeacherNotification(ctx, a, "draft created", a.CreatedBy)
		}
	}

	return assignments, nil
}

// ------------------------------
// GetByID
// ------------------------------
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

// ------------------------------
// List
// ------------------------------
func (s *assignmentService) List(ctx context.Context, filter repository.AssignmentFilter, pagination repository.Pagination, sort repository.Sort) ([]*models.Assignment, error) {
	return s.repo.List(ctx, s.pgClient.DB, filter, pagination, sort)
}

// ------------------------------
// Count
// ------------------------------
func (s *assignmentService) Count(ctx context.Context, filter repository.AssignmentFilter) (int64, error) {
	return s.repo.Count(ctx, s.pgClient.DB, filter)
}

// ------------------------------
// Update
// ------------------------------
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

	existing, err := s.repo.GetByID(ctx, tx, req.AssignmentID)
	if err != nil {
		return nil, err
	}
	if existing == nil {
		return nil, fmt.Errorf("%w: assignment %s", ErrNotFound, req.AssignmentID)
	}

	if err := s.validateDomain(ctx, tx, req.SectionID, req.SubjectID, req.TeacherID); err != nil {
		return nil, err
	}

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

	if s.auditService != nil {
		_ = s.auditService.LogAction(ctx, nil, nil, "academics", "update", "assignment",
			&req.AssignmentID, "user", req.UpdatedBy, nil, nil, map[string]interface{}{
				"old_title":     existing.Title,
				"new_title":     updated.Title,
				"old_due_date":  existing.DueDate,
				"new_due_date":  updated.DueDate,
				"old_published": existing.IsPublished,
				"new_published": updated.IsPublished,
			})
	}

	if err := s.storeOutboxEvent(ctx, tx, EventAssignmentUpdated, updated, map[string]interface{}{
		"old": existing,
		"new": updated,
	}); err != nil {
		return nil, fmt.Errorf("outbox store: %w", err)
	}

	if err := tx.Commit(); err != nil {
		return nil, fmt.Errorf("commit tx: %w", err)
	}

	logger.Info("assignment updated")

	if !existing.IsPublished && updated.IsPublished {
		s.sendAssignmentNotification(ctx, updated, "published", req.UpdatedBy)
	} else if updated.IsPublished {
		s.sendAssignmentNotification(ctx, updated, "updated", req.UpdatedBy)
	} else {
		s.sendTeacherNotification(ctx, updated, "updated (draft)", req.UpdatedBy)
	}

	return updated, nil
}

// ------------------------------
// Delete
// ------------------------------
func (s *assignmentService) Delete(ctx context.Context, id uuid.UUID, deletedBy *uuid.UUID) error {
	logger := s.logger.With(zap.String("method", "Delete"), zap.String("assignment_id", id.String()))

	tx, err := s.pgClient.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("begin tx: %w", err)
	}
	defer tx.Rollback()

	if _, err := s.repo.GetByID(ctx, tx, id); err != nil {
		return err
	}

	if err := s.repo.Delete(ctx, tx, id, deletedBy); err != nil {
		return err
	}

	if s.auditService != nil {
		_ = s.auditService.LogAction(ctx, nil, nil, "academics", "delete", "assignment",
			&id, "user", deletedBy, nil, nil, nil)
	}

	placeholder := &models.Assignment{AssignmentID: id}
	if err := s.storeOutboxEvent(ctx, tx, EventAssignmentDeleted, placeholder, map[string]interface{}{
		"assignment_id": id,
		"deleted_by":    deletedBy,
	}); err != nil {
		return fmt.Errorf("outbox store: %w", err)
	}

	if err := tx.Commit(); err != nil {
		return fmt.Errorf("commit tx: %w", err)
	}

	logger.Info("assignment deleted")
	return nil
}

// ------------------------------
// Publish
// ------------------------------
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

	if s.auditService != nil {
		_ = s.auditService.LogAction(ctx, nil, nil, "academics", "publish", "assignment",
			&id, "user", updatedBy, nil, nil, map[string]interface{}{
				"old_published": existing.IsPublished,
				"new_published": published,
			})
	}

	if err := s.storeOutboxEvent(ctx, tx, EventAssignmentPublished, existing, map[string]interface{}{
		"assignment_id": id,
		"published":     published,
		"updated_by":    updatedBy,
	}); err != nil {
		return fmt.Errorf("outbox store: %w", err)
	}

	if err := tx.Commit(); err != nil {
		return fmt.Errorf("commit tx: %w", err)
	}

	logger.Info("assignment publish status changed")

	if published {
		s.sendAssignmentNotification(ctx, existing, "published", updatedBy)
	} else {
		s.sendTeacherNotification(ctx, existing, "unpublished", updatedBy)
	}
	return nil
}

// ================================
// Helper Functions
// ================================

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

func (s *assignmentService) validateDomain(ctx context.Context, db repository.DBTX, sectionID, subjectID, teacherID uuid.UUID) error {
	section, err := s.sectionRepo.GetByID(ctx, db, sectionID)
	if err != nil {
		return err
	}
	if section == nil {
		return fmt.Errorf("%w: section %s", ErrNotFound, sectionID)
	}

	subject, err := s.subjectRepo.GetByID(ctx, db, subjectID)
	if err != nil {
		return err
	}
	if subject == nil {
		return fmt.Errorf("%w: subject %s", ErrNotFound, subjectID)
	}

	teacher, err := s.teacherRepo.GetByID(ctx, db, teacherID)
	if err != nil {
		return err
	}
	if teacher == nil {
		return fmt.Errorf("%w: teacher %s", ErrNotFound, teacherID)
	}
	return nil
}

func (s *assignmentService) storeOutboxEvent(ctx context.Context, tx *sql.Tx, eventType EventType, assignment *models.Assignment, extraData interface{}) error {
	var payload []byte
	var err error
	if extraData != nil {
		payload, err = json.Marshal(extraData)
	} else {
		payload, err = json.Marshal(assignment)
	}
	if err != nil {
		return fmt.Errorf("marshal outbox payload: %w", err)
	}
	outboxEvent := &outbox.Event{
		EventID:       uuid.New().String(),
		AggregateType: "assignment",
		AggregateID:   assignment.AssignmentID.String(),
		EventType:     string(eventType),
		Payload:       payload,
		Headers:       map[string]string{},
		Status:        "pending",
	}
	return s.outboxRepo.Store(ctx, tx, outboxEvent)
}

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

func (s *assignmentService) sendAssignmentNotification(ctx context.Context, a *models.Assignment, action string, createdBy *uuid.UUID) {
	go func() {
		notifyCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
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
		teacher, err := s.teacherRepo.GetByID(notifyCtx, s.pgClient.DB, a.TeacherID)
		if err != nil || teacher == nil {
			s.logger.Error("failed to fetch teacher for notification", zap.String("teacher_id", a.TeacherID.String()), zap.Error(err))
			return
		}
		notifReq := CreateNotificationRequest{
			CompanyID: teacher.CompanyID,
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

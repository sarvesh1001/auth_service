package service

import (
	"context"
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

// CourseService defines the business operations for courses.
type CourseService interface {
	Create(ctx context.Context, req CreateCourseRequest) (*models.Course, error)
	BulkCreate(ctx context.Context, req []CreateCourseRequest) ([]*models.Course, error)
	Upsert(ctx context.Context, req CreateCourseRequest) (*models.Course, error)

	GetByID(ctx context.Context, id uuid.UUID) (*models.Course, error)
	GetByCode(ctx context.Context, companyID uuid.UUID, code string) (*models.Course, error)

	List(ctx context.Context, filter repository.CourseFilter, p repository.Pagination, s repository.Sort) ([]*models.Course, error)
	ListActive(ctx context.Context, companyID uuid.UUID) ([]*models.Course, error)
	Count(ctx context.Context, filter repository.CourseFilter) (int64, error)

	Exists(ctx context.Context, companyID uuid.UUID, code string) (bool, error)

	Update(ctx context.Context, req UpdateCourseRequest) (*models.Course, error)

	Activate(ctx context.Context, id uuid.UUID, updatedBy *uuid.UUID) error
	Deactivate(ctx context.Context, id uuid.UUID, updatedBy *uuid.UUID) error

	Delete(ctx context.Context, id uuid.UUID, deletedBy *uuid.UUID) error

	ValidateUniqueCode(ctx context.Context, companyID uuid.UUID, code string) error
}

type courseService struct {
	repo                repository.CourseRepository
	sectionRepo         repository.SectionRepository
	pgClient            *client.PostgresClient
	logger              *zap.Logger
	outboxRepo          outbox.Repository
	idempotencyStore    idempotency.Store
	auditService        *audit.AuditService
	notificationService NotificationService // added
}

// NewCourseService creates a new course service instance with outbox, idempotency, audit, and notifications.
func NewCourseService(
	repo repository.CourseRepository,
	sectionRepo repository.SectionRepository,
	pgClient *client.PostgresClient,
	logger *zap.Logger,
	outboxRepo outbox.Repository,
	idempotencyStore idempotency.Store,
	auditService *audit.AuditService,
	notificationService NotificationService, // new parameter
) CourseService {
	return &courseService{
		repo:                repo,
		sectionRepo:         sectionRepo,
		pgClient:            pgClient,
		logger:              logger.Named("course_service"),
		outboxRepo:          outboxRepo,
		idempotencyStore:    idempotencyStore,
		auditService:        auditService,
		notificationService: notificationService,
	}
}

// ---------------------------------------------------------------------
// Helper for notification creation
// ---------------------------------------------------------------------

// buildNotificationRequest constructs a CreateNotificationRequest for a course event.
// buildNotificationRequest constructs a CreateNotificationRequest for a course event.
func (s *courseService) buildNotificationRequest(
	course *models.Course,
	operation string, // "created", "updated", "activated", "deactivated", "deleted"
	actor *uuid.UUID,
) CreateNotificationRequest {
	var title, message string
	var notificationType models.NotificationType
	priority := models.PriorityNormal

	switch operation {
	case "created":
		title = "New Course Created"
		message = fmt.Sprintf("Course '%s' (%s) has been created", course.Name, course.Code)
		notificationType = models.NotificationTypeInfo
	case "updated":
		title = "Course Updated"
		message = fmt.Sprintf("Course '%s' (%s) has been updated", course.Name, course.Code)
		notificationType = models.NotificationTypeInfo
	case "activated":
		title = "Course Activated"
		message = fmt.Sprintf("Course '%s' (%s) has been activated", course.Name, course.Code)
		notificationType = models.NotificationTypeEvent // replaced NotificationTypeSuccess
		priority = models.PriorityHigh
	case "deactivated":
		title = "Course Deactivated"
		message = fmt.Sprintf("Course '%s' (%s) has been deactivated", course.Name, course.Code)
		notificationType = models.NotificationTypeWarning
		priority = models.PriorityHigh
	case "deleted":
		title = "Course Deleted"
		message = fmt.Sprintf("Course '%s' (%s) has been deleted", course.Name, course.Code)
		notificationType = models.NotificationTypeWarning
		priority = models.PriorityHigh
	default:
		title = "Course Changed"
		message = fmt.Sprintf("Course '%s' (%s) was modified", course.Name, course.Code)
		notificationType = models.NotificationTypeInfo
	}

	return CreateNotificationRequest{
		CompanyID: course.CompanyID,
		Title:     title,
		Message:   message,
		Type:      notificationType,
		Priority:  priority,
		ExpiresAt: nil,
		Targets: []NotificationTargetInput{
			{
				TargetType:     models.TargetCompany,
				TargetEntityID: course.CompanyID,
			},
		},
		CreatedBy: actor,
	}
}

// ---------------------------------------------------------------------
// Core CRUD Operations
// ---------------------------------------------------------------------

// Create creates a new course.
func (s *courseService) Create(ctx context.Context, req CreateCourseRequest) (*models.Course, error) {
	logger := s.logger.With(
		zap.String("method", "Create"),
		zap.String("company_id", req.CompanyID.String()),
		zap.String("code", req.Code),
	)

	// Idempotency check
	if key, ok := ctx.Value("idempotency_key").(string); ok && key != "" {
		var existing *models.Course
		if err := s.idempotencyStore.Get(ctx, nil, key, &existing); err == nil && existing != nil {
			logger.Info("idempotent request, returning cached response")
			return existing, nil
		}
	}

	if err := s.validateInput(req); err != nil {
		return nil, err
	}

	tx, err := s.pgClient.BeginTx(ctx, nil)
	if err != nil {
		return nil, fmt.Errorf("begin tx: %w", err)
	}
	defer tx.Rollback()

	exists, err := s.repo.Exists(ctx, tx, req.CompanyID, req.Code)
	if err != nil {
		return nil, err
	}
	if exists {
		return nil, fmt.Errorf("%w: course code %s already exists for this company", ErrDuplicate, req.Code)
	}

	course := &models.Course{
		CompanyID:   req.CompanyID,
		Code:        req.Code,
		Name:        req.Name,
		Description: req.Description,
		Credits:     req.Credits,
		IsActive:    req.IsActive,
		CreatedBy:   req.CreatedBy,
		UpdatedBy:   req.UpdatedBy,
	}

	if err := s.repo.Create(ctx, tx, course); err != nil {
		return nil, err
	}

	// Store outbox event
	payload, _ := json.Marshal(course)
	outboxEvent := &outbox.Event{
		EventID:       uuid.New().String(),
		AggregateType: "course",
		AggregateID:   course.CourseID.String(),
		EventType:     string(EventCourseCreated),
		Payload:       payload,
		Headers:       map[string]string{},
		Status:        "pending",
	}
	if err := s.outboxRepo.Store(ctx, tx, outboxEvent); err != nil {
		return nil, fmt.Errorf("store outbox event: %w", err)
	}

	if err := tx.Commit(); err != nil {
		return nil, fmt.Errorf("commit tx: %w", err)
	}

	logger.Info("course created", zap.String("id", course.CourseID.String()))

	// Audit logging
	if s.auditService != nil {
		_ = s.auditService.LogAction(ctx, nil, &req.CompanyID, "academics", "create", "course",
			&course.CourseID, "user", req.CreatedBy, nil, nil,
			map[string]interface{}{"code": course.Code, "name": course.Name})
	}

	// Create notification
	if s.notificationService != nil {
		notifReq := s.buildNotificationRequest(course, "created", req.CreatedBy)
		if _, err := s.notificationService.Create(ctx, notifReq, uuid.New().String()); err != nil {
			logger.Error("failed to create notification", zap.Error(err))
		}
	}

	// Store idempotency key response
	if key, ok := ctx.Value("idempotency_key").(string); ok && key != "" {
		_ = s.idempotencyStore.Store(ctx, nil, key, course)
	}

	return course, nil
}

// BulkCreate creates multiple courses in one transaction.
func (s *courseService) BulkCreate(ctx context.Context, reqs []CreateCourseRequest) ([]*models.Course, error) {
	if len(reqs) == 0 {
		return nil, nil
	}

	logger := s.logger.With(zap.String("method", "BulkCreate"), zap.Int("batch_size", len(reqs)))

	// Pre‑load existing courses for all (company, code) pairs in the batch
	type companyCode struct {
		CompanyID uuid.UUID
		Code      string
	}
	toFetch := make(map[companyCode]bool)
	for _, req := range reqs {
		toFetch[companyCode{CompanyID: req.CompanyID, Code: req.Code}] = true
	}

	existingMap := make(map[companyCode]*models.Course)
	if len(toFetch) > 0 {
		keys := make([]struct {
			CompanyID uuid.UUID
			Code      string
		}, 0, len(toFetch))
		for cc := range toFetch {
			keys = append(keys, struct {
				CompanyID uuid.UUID
				Code      string
			}{CompanyID: cc.CompanyID, Code: cc.Code})
		}

		existing, err := s.repo.ListByCompanyAndCodes(ctx, s.pgClient.DB, keys)
		if err != nil {
			return nil, fmt.Errorf("pre‑load existing courses: %w", err)
		}
		for _, c := range existing {
			key := companyCode{CompanyID: c.CompanyID, Code: c.Code}
			existingMap[key] = c
		}
	}

	tx, err := s.pgClient.BeginTx(ctx, nil)
	if err != nil {
		return nil, fmt.Errorf("begin tx: %w", err)
	}
	defer tx.Rollback()

	courses := make([]*models.Course, 0, len(reqs))
	seenInBatch := make(map[companyCode]bool)

	for i, req := range reqs {
		if err := s.validateInput(req); err != nil {
			return nil, fmt.Errorf("item %d: %w", i, err)
		}

		key := companyCode{CompanyID: req.CompanyID, Code: req.Code}
		if seenInBatch[key] {
			return nil, fmt.Errorf("item %d: %w: duplicate code %s in batch", i, ErrDuplicate, req.Code)
		}
		seenInBatch[key] = true

		if existingMap[key] != nil {
			return nil, fmt.Errorf("item %d: %w: code %s already exists", i, ErrDuplicate, req.Code)
		}

		courses = append(courses, &models.Course{
			CompanyID:   req.CompanyID,
			Code:        req.Code,
			Name:        req.Name,
			Description: req.Description,
			Credits:     req.Credits,
			IsActive:    req.IsActive,
			CreatedBy:   req.CreatedBy,
			UpdatedBy:   req.UpdatedBy,
		})
	}

	if err := s.repo.BulkCreate(ctx, tx, courses); err != nil {
		return nil, err
	}

	// Store outbox events for each created course
	for _, course := range courses {
		payload, _ := json.Marshal(course)
		outboxEvent := &outbox.Event{
			EventID:       uuid.New().String(),
			AggregateType: "course",
			AggregateID:   course.CourseID.String(),
			EventType:     string(EventCourseCreated),
			Payload:       payload,
			Status:        "pending",
		}
		if err := s.outboxRepo.Store(ctx, tx, outboxEvent); err != nil {
			return nil, fmt.Errorf("store outbox event for %s: %w", course.CourseID, err)
		}
	}

	if err := tx.Commit(); err != nil {
		return nil, fmt.Errorf("commit tx: %w", err)
	}

	logger.Info("bulk created courses", zap.Int("count", len(courses)))

	// Audit each (optional)
	if s.auditService != nil {
		for _, course := range courses {
			_ = s.auditService.LogAction(ctx, nil, &course.CompanyID, "academics", "bulk_create", "course",
				&course.CourseID, "user", course.CreatedBy, nil, nil, nil)
		}
	}

	// Create notifications
	if s.notificationService != nil {
		for _, course := range courses {
			notifReq := s.buildNotificationRequest(course, "created", course.CreatedBy)
			if _, err := s.notificationService.Create(ctx, notifReq, uuid.New().String()); err != nil {
				logger.Error("failed to create notification for course",
					zap.String("id", course.CourseID.String()),
					zap.Error(err))
			}
		}
	}

	return courses, nil
}

// Upsert creates or updates a course based on (company_id, code).
func (s *courseService) Upsert(ctx context.Context, req CreateCourseRequest) (*models.Course, error) {
	logger := s.logger.With(
		zap.String("method", "Upsert"),
		zap.String("company_id", req.CompanyID.String()),
		zap.String("code", req.Code),
	)

	if err := s.validateInput(req); err != nil {
		return nil, err
	}

	tx, err := s.pgClient.BeginTx(ctx, nil)
	if err != nil {
		return nil, fmt.Errorf("begin tx: %w", err)
	}
	defer tx.Rollback()

	// Check existing to determine event type
	existing, _ := s.repo.GetByCode(ctx, tx, req.CompanyID, req.Code)

	course := &models.Course{
		CompanyID:   req.CompanyID,
		Code:        req.Code,
		Name:        req.Name,
		Description: req.Description,
		Credits:     req.Credits,
		IsActive:    req.IsActive,
		CreatedBy:   req.CreatedBy,
		UpdatedBy:   req.UpdatedBy,
	}

	eventType := EventCourseCreated
	operation := "created"
	if existing != nil {
		eventType = EventCourseUpdated
		operation = "updated"
	}

	if err := s.repo.Upsert(ctx, tx, course); err != nil {
		return nil, err
	}

	payload, _ := json.Marshal(course)
	outboxEvent := &outbox.Event{
		EventID:       uuid.New().String(),
		AggregateType: "course",
		AggregateID:   course.CourseID.String(),
		EventType:     string(eventType),
		Payload:       payload,
		Status:        "pending",
	}
	if err := s.outboxRepo.Store(ctx, tx, outboxEvent); err != nil {
		return nil, fmt.Errorf("store outbox event: %w", err)
	}

	if err := tx.Commit(); err != nil {
		return nil, fmt.Errorf("commit tx: %w", err)
	}

	logger.Info("course upserted", zap.String("id", course.CourseID.String()))

	if s.auditService != nil {
		_ = s.auditService.LogAction(ctx, nil, &req.CompanyID, "academics", "upsert", "course",
			&course.CourseID, "user", req.CreatedBy, nil, nil, map[string]interface{}{"code": course.Code})
	}

	// Create notification
	if s.notificationService != nil {
		notifReq := s.buildNotificationRequest(course, operation, req.CreatedBy)
		if _, err := s.notificationService.Create(ctx, notifReq, uuid.New().String()); err != nil {
			logger.Error("failed to create notification", zap.Error(err))
		}
	}

	return course, nil
}

// GetByID retrieves a course by its ID.
func (s *courseService) GetByID(ctx context.Context, id uuid.UUID) (*models.Course, error) {
	c, err := s.repo.GetByID(ctx, s.pgClient.DB, id)
	if err != nil {
		return nil, err
	}
	if c == nil {
		return nil, fmt.Errorf("%w: course %s", ErrNotFound, id)
	}
	return c, nil
}

// GetByCode retrieves a course by company and code.
func (s *courseService) GetByCode(ctx context.Context, companyID uuid.UUID, code string) (*models.Course, error) {
	c, err := s.repo.GetByCode(ctx, s.pgClient.DB, companyID, code)
	if err != nil {
		return nil, err
	}
	if c == nil {
		return nil, fmt.Errorf("%w: course code %s for company %s", ErrNotFound, code, companyID)
	}
	return c, nil
}

// List returns a paginated list of courses based on filter and sort.
func (s *courseService) List(ctx context.Context, filter repository.CourseFilter, p repository.Pagination, srt repository.Sort) ([]*models.Course, error) {
	return s.repo.List(ctx, s.pgClient.DB, filter, p, srt)
}

// ListActive returns all active courses for a company.
func (s *courseService) ListActive(ctx context.Context, companyID uuid.UUID) ([]*models.Course, error) {
	return s.repo.ListActive(ctx, s.pgClient.DB, companyID)
}

// Count returns the total number of courses matching a filter.
func (s *courseService) Count(ctx context.Context, filter repository.CourseFilter) (int64, error) {
	return s.repo.Count(ctx, s.pgClient.DB, filter)
}

// Exists checks if a course with given code exists in a company.
func (s *courseService) Exists(ctx context.Context, companyID uuid.UUID, code string) (bool, error) {
	return s.repo.Exists(ctx, s.pgClient.DB, companyID, code)
}

// Update updates an existing course.
func (s *courseService) Update(ctx context.Context, req UpdateCourseRequest) (*models.Course, error) {
	logger := s.logger.With(zap.String("method", "Update"), zap.String("course_id", req.CourseID.String()))

	tx, err := s.pgClient.BeginTx(ctx, nil)
	if err != nil {
		return nil, fmt.Errorf("begin tx: %w", err)
	}
	defer tx.Rollback()

	course, err := s.repo.GetByIDForUpdate(ctx, tx, req.CourseID)
	if err != nil {
		return nil, err
	}
	if course == nil {
		return nil, fmt.Errorf("%w: course %s", ErrNotFound, req.CourseID)
	}

	if req.Code != course.Code {
		exists, err := s.repo.Exists(ctx, tx, course.CompanyID, req.Code)
		if err != nil {
			return nil, err
		}
		if exists {
			return nil, fmt.Errorf("%w: course code %s already exists", ErrDuplicate, req.Code)
		}
	}

	// Capture old state for event
	oldCourse := *course

	course.Code = req.Code
	course.Name = req.Name
	course.Description = req.Description
	course.Credits = req.Credits
	course.IsActive = req.IsActive
	course.UpdatedBy = req.UpdatedBy

	if err := s.repo.Update(ctx, tx, course); err != nil {
		return nil, err
	}

	// Store outbox event with old/new state
	payload, _ := json.Marshal(map[string]interface{}{
		"old": oldCourse,
		"new": course,
	})
	outboxEvent := &outbox.Event{
		EventID:       uuid.New().String(),
		AggregateType: "course",
		AggregateID:   course.CourseID.String(),
		EventType:     string(EventCourseUpdated),
		Payload:       payload,
		Status:        "pending",
	}
	if err := s.outboxRepo.Store(ctx, tx, outboxEvent); err != nil {
		return nil, fmt.Errorf("store outbox event: %w", err)
	}

	if err := tx.Commit(); err != nil {
		return nil, fmt.Errorf("commit tx: %w", err)
	}

	logger.Info("course updated")

	if s.auditService != nil {
		_ = s.auditService.LogAction(ctx, nil, &course.CompanyID, "academics", "update", "course",
			&course.CourseID, "user", req.UpdatedBy, nil, nil, nil)
	}

	// Create notification
	if s.notificationService != nil {
		notifReq := s.buildNotificationRequest(course, "updated", req.UpdatedBy)
		if _, err := s.notificationService.Create(ctx, notifReq, uuid.New().String()); err != nil {
			logger.Error("failed to create notification", zap.Error(err))
		}
	}

	return course, nil
}

// Activate sets a course as active.
func (s *courseService) Activate(ctx context.Context, id uuid.UUID, updatedBy *uuid.UUID) error {
	logger := s.logger.With(zap.String("method", "Activate"), zap.String("course_id", id.String()))

	tx, err := s.pgClient.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("begin tx: %w", err)
	}
	defer tx.Rollback()

	if err := s.repo.Activate(ctx, tx, id, updatedBy); err != nil {
		return err
	}

	// Fetch the updated course for outbox event
	course, err := s.repo.GetByID(ctx, tx, id)
	if err != nil {
		return err
	}
	if course == nil {
		return fmt.Errorf("%w: course %s", ErrNotFound, id)
	}

	payload, _ := json.Marshal(course)
	outboxEvent := &outbox.Event{
		EventID:       uuid.New().String(),
		AggregateType: "course",
		AggregateID:   id.String(),
		EventType:     string(EventCourseUpdated), // or a dedicated activate event
		Payload:       payload,
		Status:        "pending",
	}
	if err := s.outboxRepo.Store(ctx, tx, outboxEvent); err != nil {
		return fmt.Errorf("store outbox event: %w", err)
	}

	if err := tx.Commit(); err != nil {
		return fmt.Errorf("commit tx: %w", err)
	}

	logger.Info("course activated")

	if s.auditService != nil {
		_ = s.auditService.LogAction(ctx, nil, &course.CompanyID, "academics", "activate", "course",
			&id, "user", updatedBy, nil, nil, nil)
	}

	// Create notification
	if s.notificationService != nil {
		notifReq := s.buildNotificationRequest(course, "activated", updatedBy)
		if _, err := s.notificationService.Create(ctx, notifReq, uuid.New().String()); err != nil {
			logger.Error("failed to create notification", zap.Error(err))
		}
	}

	return nil
}

// Deactivate sets a course as inactive.
func (s *courseService) Deactivate(ctx context.Context, id uuid.UUID, updatedBy *uuid.UUID) error {
	logger := s.logger.With(zap.String("method", "Deactivate"), zap.String("course_id", id.String()))

	tx, err := s.pgClient.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("begin tx: %w", err)
	}
	defer tx.Rollback()

	if err := s.repo.Deactivate(ctx, tx, id, updatedBy); err != nil {
		return err
	}

	course, err := s.repo.GetByID(ctx, tx, id)
	if err != nil {
		return err
	}
	if course == nil {
		return fmt.Errorf("%w: course %s", ErrNotFound, id)
	}

	payload, _ := json.Marshal(course)
	outboxEvent := &outbox.Event{
		EventID:       uuid.New().String(),
		AggregateType: "course",
		AggregateID:   id.String(),
		EventType:     string(EventCourseUpdated),
		Payload:       payload,
		Status:        "pending",
	}
	if err := s.outboxRepo.Store(ctx, tx, outboxEvent); err != nil {
		return fmt.Errorf("store outbox event: %w", err)
	}

	if err := tx.Commit(); err != nil {
		return fmt.Errorf("commit tx: %w", err)
	}

	logger.Info("course deactivated")

	if s.auditService != nil {
		_ = s.auditService.LogAction(ctx, nil, &course.CompanyID, "academics", "deactivate", "course",
			&id, "user", updatedBy, nil, nil, nil)
	}

	// Create notification
	if s.notificationService != nil {
		notifReq := s.buildNotificationRequest(course, "deactivated", updatedBy)
		if _, err := s.notificationService.Create(ctx, notifReq, uuid.New().String()); err != nil {
			logger.Error("failed to create notification", zap.Error(err))
		}
	}

	return nil
}

// Delete soft-deletes a course.
func (s *courseService) Delete(ctx context.Context, id uuid.UUID, deletedBy *uuid.UUID) error {
	logger := s.logger.With(zap.String("method", "Delete"), zap.String("course_id", id.String()))

	tx, err := s.pgClient.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("begin tx: %w", err)
	}
	defer tx.Rollback()

	// Check for dependencies (sections)
	sections, err := s.sectionRepo.ListByCourse(ctx, tx, id)
	if err != nil {
		return fmt.Errorf("check sections: %w", err)
	}
	if len(sections) > 0 {
		return fmt.Errorf("%w: course has %d active sections", ErrHasDependencies, len(sections))
	}

	course, err := s.repo.GetByIDForUpdate(ctx, tx, id)
	if err != nil {
		return err
	}
	if course == nil {
		return fmt.Errorf("%w: course %s", ErrNotFound, id)
	}

	if err := s.repo.Delete(ctx, tx, id, deletedBy); err != nil {
		return err
	}

	payload, _ := json.Marshal(map[string]interface{}{
		"course_id":  id,
		"deleted_by": deletedBy,
	})
	outboxEvent := &outbox.Event{
		EventID:       uuid.New().String(),
		AggregateType: "course",
		AggregateID:   id.String(),
		EventType:     string(EventCourseDeleted),
		Payload:       payload,
		Status:        "pending",
	}
	if err := s.outboxRepo.Store(ctx, tx, outboxEvent); err != nil {
		return fmt.Errorf("store outbox event: %w", err)
	}

	if err := tx.Commit(); err != nil {
		return fmt.Errorf("commit tx: %w", err)
	}

	logger.Info("course deleted")

	if s.auditService != nil {
		_ = s.auditService.LogAction(ctx, nil, &course.CompanyID, "academics", "delete", "course",
			&id, "user", deletedBy, nil, nil, nil)
	}

	// Create notification
	if s.notificationService != nil {
		notifReq := s.buildNotificationRequest(course, "deleted", deletedBy)
		if _, err := s.notificationService.Create(ctx, notifReq, uuid.New().String()); err != nil {
			logger.Error("failed to create notification", zap.Error(err))
		}
	}

	return nil
}

// ValidateUniqueCode checks if a course code is unique within a company.
func (s *courseService) ValidateUniqueCode(ctx context.Context, companyID uuid.UUID, code string) error {
	exists, err := s.repo.Exists(ctx, s.pgClient.DB, companyID, code)
	if err != nil {
		return err
	}
	if exists {
		return fmt.Errorf("%w: code %s", ErrDuplicate, code)
	}
	return nil
}

// validateInput performs basic validation on request data.
func (s *courseService) validateInput(req CreateCourseRequest) error {
	if req.CompanyID == uuid.Nil {
		return fmt.Errorf("%w: company_id is required", ErrInvalidInput)
	}
	if strings.TrimSpace(req.Code) == "" {
		return fmt.Errorf("%w: code is required", ErrInvalidInput)
	}
	if strings.TrimSpace(req.Name) == "" {
		return fmt.Errorf("%w: name is required", ErrInvalidInput)
	}
	if req.Credits < 0 {
		return fmt.Errorf("%w: credits cannot be negative", ErrInvalidInput)
	}
	return nil
}

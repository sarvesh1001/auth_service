package service

import (
	"context"
	"fmt"
	"strings"

	"github.com/google/uuid"
	"go.uber.org/zap"

	"auth-service/internal/academics/models"
	"auth-service/internal/academics/repository"
	"auth-service/internal/client"
)

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
	repo           repository.CourseRepository
	sectionRepo    repository.SectionRepository
	eventPublisher EventPublisher
	pgClient       *client.PostgresClient
	logger         *zap.Logger
}

func NewCourseService(
	repo repository.CourseRepository,
	sectionRepo repository.SectionRepository,
	eventPublisher EventPublisher,
	pgClient *client.PostgresClient,
	logger *zap.Logger,
) CourseService {
	return &courseService{
		repo:           repo,
		sectionRepo:    sectionRepo,
		eventPublisher: eventPublisher,
		pgClient:       pgClient,
		logger:         logger.Named("course_service"),
	}
}

func (s *courseService) Create(ctx context.Context, req CreateCourseRequest) (*models.Course, error) {
	logger := s.logger.With(
		zap.String("method", "Create"),
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

	if err := tx.Commit(); err != nil {
		return nil, fmt.Errorf("commit tx: %w", err)
	}

	logger.Info("course created", zap.String("id", course.CourseID.String()))

	// Publish event
	if err := s.eventPublisher.Publish(ctx, Event{
		Type: EventCourseCreated,
		Data: course,
	}); err != nil {
		logger.Error("failed to publish course.created event", zap.Error(err))
	}

	return course, nil
}

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
		// Convert map keys to slice for repository method
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

		// Check against pre‑loaded existing courses
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

	if err := tx.Commit(); err != nil {
		return nil, fmt.Errorf("commit tx: %w", err)
	}

	logger.Info("bulk created courses", zap.Int("count", len(courses)))

	// Publish events for each created course (optional, can be batched)
	for _, c := range courses {
		if err := s.eventPublisher.Publish(ctx, Event{
			Type: EventCourseCreated,
			Data: c,
		}); err != nil {
			logger.Error("failed to publish course.created event", zap.String("course_id", c.CourseID.String()), zap.Error(err))
		}
	}

	return courses, nil
}

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

	if err := s.repo.Upsert(ctx, tx, course); err != nil {
		return nil, err
	}

	if err := tx.Commit(); err != nil {
		return nil, fmt.Errorf("commit tx: %w", err)
	}

	logger.Info("course upserted", zap.String("id", course.CourseID.String()))

	// Publish event (you might want a separate EventCourseUpserted, but we can reuse created/updated)
	// Here we check if the course was newly created or updated by checking CreatedAt/UpdatedAt,
	// but that's not reliable without another query. For simplicity, we publish both?
	// Alternatively, we can treat upsert as either create or update.
	// The repository's Upsert returns the record, but we don't know if it was inserted or updated.
	// We could query the creation time before/after, but that adds complexity.
	// For now, we'll publish a generic event or skip.
	// Many systems treat upsert as a single operation and downstream handles idempotency.
	// We'll skip event for upsert to avoid duplicate events. If needed, implement proper detection.

	return course, nil
}

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

func (s *courseService) List(ctx context.Context, filter repository.CourseFilter, p repository.Pagination, srt repository.Sort) ([]*models.Course, error) {
	return s.repo.List(ctx, s.pgClient.DB, filter, p, srt)
}

func (s *courseService) ListActive(ctx context.Context, companyID uuid.UUID) ([]*models.Course, error) {
	return s.repo.ListActive(ctx, s.pgClient.DB, companyID)
}

func (s *courseService) Count(ctx context.Context, filter repository.CourseFilter) (int64, error) {
	return s.repo.Count(ctx, s.pgClient.DB, filter)
}

func (s *courseService) Exists(ctx context.Context, companyID uuid.UUID, code string) (bool, error) {
	return s.repo.Exists(ctx, s.pgClient.DB, companyID, code)
}

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

	// Capture old state for event if needed
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

	if err := tx.Commit(); err != nil {
		return nil, fmt.Errorf("commit tx: %w", err)
	}

	logger.Info("course updated")

	// Publish event
	if err := s.eventPublisher.Publish(ctx, Event{
		Type: EventCourseUpdated,
		Data: map[string]interface{}{
			"old": oldCourse,
			"new": course,
		},
	}); err != nil {
		logger.Error("failed to publish course.updated event", zap.Error(err))
	}

	return course, nil
}

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

	if err := tx.Commit(); err != nil {
		return fmt.Errorf("commit tx: %w", err)
	}

	logger.Info("course activated")

	// Optionally publish an event
	// For simplicity, we can treat activation as an update or a separate event type
	// We'll skip for now, but you could add EventCourseActivated if needed.

	return nil
}

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

	if err := tx.Commit(); err != nil {
		return fmt.Errorf("commit tx: %w", err)
	}

	logger.Info("course deactivated")
	return nil
}

func (s *courseService) Delete(ctx context.Context, id uuid.UUID, deletedBy *uuid.UUID) error {
	logger := s.logger.With(zap.String("method", "Delete"), zap.String("course_id", id.String()))

	tx, err := s.pgClient.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("begin tx: %w", err)
	}
	defer tx.Rollback()

	// Check if there are any sections linked to this course (soft‑delete safety)
	sections, err := s.sectionRepo.ListByCourse(ctx, tx, id)
	if err != nil {
		return fmt.Errorf("check sections: %w", err)
	}
	if len(sections) > 0 {
		return fmt.Errorf("%w: course has %d active sections", ErrHasDependencies, len(sections))
	}

	// Also check subject‑course mappings (optional, but recommended)
	// You could inject mappingRepo and check here.

	if err := s.repo.Delete(ctx, tx, id, deletedBy); err != nil {
		return err
	}

	if err := tx.Commit(); err != nil {
		return fmt.Errorf("commit tx: %w", err)
	}

	logger.Info("course deleted")

	// Publish event
	if err := s.eventPublisher.Publish(ctx, Event{
		Type: EventCourseDeleted,
		Data: map[string]interface{}{
			"course_id":  id,
			"deleted_by": deletedBy,
		},
	}); err != nil {
		logger.Error("failed to publish course.deleted event", zap.Error(err))
	}

	return nil
}

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

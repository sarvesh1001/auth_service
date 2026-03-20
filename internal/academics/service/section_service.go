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

type SectionService interface {
	Create(ctx context.Context, req CreateSectionRequest) (*models.Section, error)
	BulkCreate(ctx context.Context, req []CreateSectionRequest) ([]*models.Section, error)
	Upsert(ctx context.Context, req CreateSectionRequest) (*models.Section, error)
	GetByID(ctx context.Context, id uuid.UUID) (*models.Section, error)
	List(ctx context.Context, filter repository.SectionFilter, p repository.Pagination, s repository.Sort) ([]*models.Section, error)
	ListByCourse(ctx context.Context, courseID uuid.UUID) ([]*models.Section, error)
	ListByTerm(ctx context.Context, termID uuid.UUID) ([]*models.Section, error)
	Count(ctx context.Context, filter repository.SectionFilter) (int64, error)
	Exists(ctx context.Context, courseID, termID uuid.UUID, name string) (bool, error)
	Update(ctx context.Context, req UpdateSectionRequest) (*models.Section, error)
	UpdateCapacity(ctx context.Context, sectionID uuid.UUID, capacity int, updatedBy *uuid.UUID) error
	Activate(ctx context.Context, id uuid.UUID, updatedBy *uuid.UUID) error
	Deactivate(ctx context.Context, id uuid.UUID, updatedBy *uuid.UUID) error
	Delete(ctx context.Context, id uuid.UUID, deletedBy *uuid.UUID) error
	ValidateCapacity(ctx context.Context, sectionID uuid.UUID) error
}

type sectionService struct {
	repo           repository.SectionRepository
	courseRepo     repository.CourseRepository
	termRepo       repository.TermRepository
	enrollmentRepo repository.EnrollmentRepository // added for dependency checks
	eventPublisher EventPublisher
	pgClient       *client.PostgresClient
	logger         *zap.Logger
}

func NewSectionService(
	repo repository.SectionRepository,
	courseRepo repository.CourseRepository,
	termRepo repository.TermRepository,
	enrollmentRepo repository.EnrollmentRepository,
	eventPublisher EventPublisher,
	pgClient *client.PostgresClient,
	logger *zap.Logger,
) SectionService {
	return &sectionService{
		repo:           repo,
		courseRepo:     courseRepo,
		termRepo:       termRepo,
		enrollmentRepo: enrollmentRepo,
		eventPublisher: eventPublisher,
		pgClient:       pgClient,
		logger:         logger.Named("section_service"),
	}
}

// validateInput performs basic validation for CreateSectionRequest.
func (s *sectionService) validateInput(req CreateSectionRequest) error {
	if req.CourseID == uuid.Nil {
		return fmt.Errorf("%w: course_id is required", ErrInvalidInput)
	}
	if req.TermID == uuid.Nil {
		return fmt.Errorf("%w: term_id is required", ErrInvalidInput)
	}
	if strings.TrimSpace(req.Name) == "" {
		return fmt.Errorf("%w: name is required", ErrInvalidInput)
	}
	if req.Capacity < 0 {
		return fmt.Errorf("%w: capacity cannot be negative", ErrInvalidInput)
	}
	return nil
}

// Create inserts a new section.
func (s *sectionService) Create(ctx context.Context, req CreateSectionRequest) (*models.Section, error) {
	logger := s.logger.With(
		zap.String("method", "Create"),
		zap.String("course_id", req.CourseID.String()),
		zap.String("term_id", req.TermID.String()),
		zap.String("name", req.Name),
	)

	if err := s.validateInput(req); err != nil {
		return nil, err
	}

	tx, err := s.pgClient.BeginTx(ctx, nil)
	if err != nil {
		return nil, fmt.Errorf("begin tx: %w", err)
	}
	defer tx.Rollback()

	// Verify course exists (not deleted)
	course, err := s.courseRepo.GetByID(ctx, tx, req.CourseID)
	if err != nil {
		return nil, err
	}
	if course == nil {
		return nil, fmt.Errorf("%w: course %s", ErrNotFound, req.CourseID)
	}

	// Verify term exists (not deleted)
	term, err := s.termRepo.GetByID(ctx, tx, req.TermID)
	if err != nil {
		return nil, err
	}
	if term == nil {
		return nil, fmt.Errorf("%w: term %s", ErrNotFound, req.TermID)
	}

	// Domain rule: term must belong to the same company as course
	if err := s.validateTermBelongsToCompany(ctx, tx, term.TermID, course.CompanyID); err != nil {
		return nil, err
	}

	// Check uniqueness of (course_id, term_id, name)
	exists, err := s.repo.Exists(ctx, tx, req.CourseID, req.TermID, req.Name)
	if err != nil {
		return nil, err
	}
	if exists {
		return nil, fmt.Errorf("%w: section name %s already exists for this course and term", ErrDuplicate, req.Name)
	}

	section := &models.Section{
		CourseID:  req.CourseID,
		TermID:    req.TermID,
		Name:      req.Name,
		Capacity:  req.Capacity,
		IsActive:  req.IsActive,
		CreatedBy: req.CreatedBy,
		UpdatedBy: req.UpdatedBy,
	}

	if err := s.repo.Create(ctx, tx, section); err != nil {
		return nil, err
	}

	if err := tx.Commit(); err != nil {
		return nil, fmt.Errorf("commit tx: %w", err)
	}

	logger.Info("section created", zap.String("id", section.SectionID.String()))

	// Publish event
	if err := s.eventPublisher.Publish(ctx, Event{
		Type: EventSectionCreated,
		Data: section,
	}); err != nil {
		logger.Error("failed to publish section.created event", zap.Error(err))
	}

	return section, nil
}

// BulkCreate inserts multiple sections in a single transaction with optimised validation.
func (s *sectionService) BulkCreate(ctx context.Context, reqs []CreateSectionRequest) ([]*models.Section, error) {
	if len(reqs) == 0 {
		return nil, nil
	}
	logger := s.logger.With(zap.String("method", "BulkCreate"), zap.Int("count", len(reqs)))

	// Collect all course and term IDs
	courseIDs := make(map[uuid.UUID]struct{})
	termIDs := make(map[uuid.UUID]struct{})
	for _, req := range reqs {
		courseIDs[req.CourseID] = struct{}{}
		termIDs[req.TermID] = struct{}{}
	}

	tx, err := s.pgClient.BeginTx(ctx, nil)
	if err != nil {
		return nil, fmt.Errorf("begin tx: %w", err)
	}
	defer tx.Rollback()

	// Preload courses
	courseList := keysToSlice(courseIDs)
	coursesMap, err := s.courseRepo.GetByIDs(ctx, tx, courseList)
	if err != nil {
		return nil, fmt.Errorf("failed to preload courses: %w", err)
	}
	if len(coursesMap) != len(courseList) {
		for _, cid := range courseList {
			if _, ok := coursesMap[cid]; !ok {
				return nil, fmt.Errorf("%w: course %s", ErrNotFound, cid)
			}
		}
	}

	// Preload terms
	termList := keysToSlice(termIDs)
	termsMap, err := s.termRepo.GetByIDs(ctx, tx, termList)
	if err != nil {
		return nil, fmt.Errorf("failed to preload terms: %w", err)
	}
	if len(termsMap) != len(termList) {
		for _, tid := range termList {
			if _, ok := termsMap[tid]; !ok {
				return nil, fmt.Errorf("%w: term %s", ErrNotFound, tid)
			}
		}
	}

	// Preload academic years for terms (to validate company)
	termToAYMap, err := s.termRepo.GetAcademicYearsByTermIDs(ctx, tx, termList)
	if err != nil {
		return nil, fmt.Errorf("failed to preload academic years for terms: %w", err)
	}

	// Preload existing sections
	existingSections, err := s.repo.List(ctx, tx, repository.SectionFilter{
		CourseIDs: courseList,
		TermIDs:   termList,
	}, repository.Pagination{Limit: 10000}, repository.Sort{})
	if err != nil {
		return nil, fmt.Errorf("failed to pre‑load existing sections: %w", err)
	}
	existingKeys := make(map[string]bool)
	for _, sec := range existingSections {
		key := sec.CourseID.String() + ":" + sec.TermID.String() + ":" + sec.Name
		existingKeys[key] = true
	}

	seen := make(map[string]bool)
	var toCreate []*models.Section
	for i, req := range reqs {
		if err := s.validateInput(req); err != nil {
			return nil, fmt.Errorf("item %d: %w", i, err)
		}

		key := req.CourseID.String() + ":" + req.TermID.String() + ":" + req.Name
		if seen[key] {
			return nil, fmt.Errorf("item %d: %w: duplicate section name %s in batch", i, ErrDuplicate, req.Name)
		}
		seen[key] = true

		if existingKeys[key] {
			return nil, fmt.Errorf("item %d: %w: section name %s already exists for this course and term", i, ErrDuplicate, req.Name)
		}

		course, ok := coursesMap[req.CourseID]
		if !ok {
			return nil, fmt.Errorf("item %d: course %s not found", i, req.CourseID)
		}
		ay, ok := termToAYMap[req.TermID]
		if !ok {
			return nil, fmt.Errorf("item %d: term %s academic year not found", i, req.TermID)
		}
		if course.CompanyID != ay.CompanyID {
			return nil, fmt.Errorf("item %d: term %s does not belong to the same company as course %s", i, req.TermID, req.CourseID)
		}

		toCreate = append(toCreate, &models.Section{
			CourseID:  req.CourseID,
			TermID:    req.TermID,
			Name:      req.Name,
			Capacity:  req.Capacity,
			IsActive:  req.IsActive,
			CreatedBy: req.CreatedBy,
			UpdatedBy: req.UpdatedBy,
		})
	}

	if err := s.repo.BulkCreate(ctx, tx, toCreate); err != nil {
		return nil, err
	}

	if err := tx.Commit(); err != nil {
		return nil, fmt.Errorf("commit tx: %w", err)
	}

	logger.Info("bulk created sections", zap.Int("count", len(toCreate)))

	// Publish events for each created section
	for _, sec := range toCreate {
		if err := s.eventPublisher.Publish(ctx, Event{
			Type: EventSectionCreated,
			Data: sec,
		}); err != nil {
			logger.Error("failed to publish section.created event", zap.String("section_id", sec.SectionID.String()), zap.Error(err))
		}
	}

	return toCreate, nil
}

// Upsert creates or updates a section based on unique (course_id, term_id, name).
func (s *sectionService) Upsert(ctx context.Context, req CreateSectionRequest) (*models.Section, error) {
	logger := s.logger.With(
		zap.String("method", "Upsert"),
		zap.String("course_id", req.CourseID.String()),
		zap.String("term_id", req.TermID.String()),
		zap.String("name", req.Name),
	)

	if err := s.validateInput(req); err != nil {
		return nil, err
	}

	tx, err := s.pgClient.BeginTx(ctx, nil)
	if err != nil {
		return nil, fmt.Errorf("begin tx: %w", err)
	}
	defer tx.Rollback()

	// Verify course exists
	course, err := s.courseRepo.GetByID(ctx, tx, req.CourseID)
	if err != nil {
		return nil, err
	}
	if course == nil {
		return nil, fmt.Errorf("%w: course %s", ErrNotFound, req.CourseID)
	}

	// Verify term exists
	term, err := s.termRepo.GetByID(ctx, tx, req.TermID)
	if err != nil {
		return nil, err
	}
	if term == nil {
		return nil, fmt.Errorf("%w: term %s", ErrNotFound, req.TermID)
	}

	// Domain rule: term must belong to the same company as course
	if err := s.validateTermBelongsToCompany(ctx, tx, term.TermID, course.CompanyID); err != nil {
		return nil, err
	}

	section := &models.Section{
		CourseID:  req.CourseID,
		TermID:    req.TermID,
		Name:      req.Name,
		Capacity:  req.Capacity,
		IsActive:  req.IsActive,
		CreatedBy: req.CreatedBy,
		UpdatedBy: req.UpdatedBy,
	}

	if err := s.repo.Upsert(ctx, tx, section); err != nil {
		return nil, err
	}

	if err := tx.Commit(); err != nil {
		return nil, fmt.Errorf("commit tx: %w", err)
	}

	logger.Info("section upserted", zap.String("id", section.SectionID.String()))
	// No event for upsert (or could detect create/update and publish accordingly)
	return section, nil
}

// GetByID retrieves a section by ID.
func (s *sectionService) GetByID(ctx context.Context, id uuid.UUID) (*models.Section, error) {
	sec, err := s.repo.GetByID(ctx, s.pgClient.DB, id)
	if err != nil {
		return nil, err
	}
	if sec == nil {
		return nil, fmt.Errorf("%w: section %s", ErrNotFound, id)
	}
	return sec, nil
}

// List returns sections matching the filter with pagination and sorting.
func (s *sectionService) List(ctx context.Context, filter repository.SectionFilter, p repository.Pagination, srt repository.Sort) ([]*models.Section, error) {
	return s.repo.List(ctx, s.pgClient.DB, filter, p, srt)
}

// ListByCourse returns all sections for a given course.
func (s *sectionService) ListByCourse(ctx context.Context, courseID uuid.UUID) ([]*models.Section, error) {
	return s.repo.ListByCourse(ctx, s.pgClient.DB, courseID)
}

// ListByTerm returns all sections for a given term.
func (s *sectionService) ListByTerm(ctx context.Context, termID uuid.UUID) ([]*models.Section, error) {
	return s.repo.ListByTerm(ctx, s.pgClient.DB, termID)
}

// Count returns the number of sections matching the filter.
func (s *sectionService) Count(ctx context.Context, filter repository.SectionFilter) (int64, error) {
	return s.repo.Count(ctx, s.pgClient.DB, filter)
}

// Exists checks if a section with given course, term, and name exists.
func (s *sectionService) Exists(ctx context.Context, courseID, termID uuid.UUID, name string) (bool, error) {
	return s.repo.Exists(ctx, s.pgClient.DB, courseID, termID, name)
}

// Update modifies an existing section.
func (s *sectionService) Update(ctx context.Context, req UpdateSectionRequest) (*models.Section, error) {
	logger := s.logger.With(zap.String("method", "Update"), zap.String("section_id", req.SectionID.String()))

	if req.SectionID == uuid.Nil {
		return nil, fmt.Errorf("%w: section_id is required", ErrInvalidInput)
	}
	if strings.TrimSpace(req.Name) == "" {
		return nil, fmt.Errorf("%w: name is required", ErrInvalidInput)
	}
	if req.Capacity < 0 {
		return nil, fmt.Errorf("%w: capacity cannot be negative", ErrInvalidInput)
	}

	tx, err := s.pgClient.BeginTx(ctx, nil)
	if err != nil {
		return nil, fmt.Errorf("begin tx: %w", err)
	}
	defer tx.Rollback()

	section, err := s.repo.GetByIDForUpdate(ctx, tx, req.SectionID)
	if err != nil {
		return nil, err
	}
	if section == nil {
		return nil, fmt.Errorf("%w: section %s", ErrNotFound, req.SectionID)
	}

	// Capture old state for event
	oldSection := *section

	// If name changed, check uniqueness within same course and term
	if req.Name != section.Name {
		exists, err := s.repo.Exists(ctx, tx, section.CourseID, section.TermID, req.Name)
		if err != nil {
			return nil, err
		}
		if exists {
			return nil, fmt.Errorf("%w: section name %s already exists for this course and term", ErrDuplicate, req.Name)
		}
	}

	section.Name = req.Name
	section.Capacity = req.Capacity
	section.IsActive = req.IsActive
	section.UpdatedBy = req.UpdatedBy

	if err := s.repo.Update(ctx, tx, section); err != nil {
		return nil, err
	}

	if err := tx.Commit(); err != nil {
		return nil, fmt.Errorf("commit tx: %w", err)
	}

	logger.Info("section updated")

	// Publish event
	if err := s.eventPublisher.Publish(ctx, Event{
		Type: EventSectionUpdated,
		Data: map[string]interface{}{
			"old": oldSection,
			"new": section,
		},
	}); err != nil {
		logger.Error("failed to publish section.updated event", zap.Error(err))
	}

	return section, nil
}

// UpdateCapacity updates only the capacity of a section.
func (s *sectionService) UpdateCapacity(ctx context.Context, sectionID uuid.UUID, capacity int, updatedBy *uuid.UUID) error {
	logger := s.logger.With(zap.String("method", "UpdateCapacity"), zap.String("section_id", sectionID.String()))

	if capacity < 0 {
		return fmt.Errorf("%w: capacity cannot be negative", ErrInvalidInput)
	}

	tx, err := s.pgClient.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("begin tx: %w", err)
	}
	defer tx.Rollback()

	// Fetch current state for event
	section, err := s.repo.GetByIDForUpdate(ctx, tx, sectionID)
	if err != nil {
		return err
	}
	if section == nil {
		return fmt.Errorf("%w: section %s", ErrNotFound, sectionID)
	}
	oldCapacity := section.Capacity

	if err := s.repo.UpdateCapacity(ctx, tx, sectionID, capacity, updatedBy); err != nil {
		return err
	}

	if err := tx.Commit(); err != nil {
		return fmt.Errorf("commit tx: %w", err)
	}

	logger.Info("section capacity updated", zap.Int("capacity", capacity))

	// Publish update event with capacity change
	if err := s.eventPublisher.Publish(ctx, Event{
		Type: EventSectionUpdated,
		Data: map[string]interface{}{
			"old":        map[string]interface{}{"capacity": oldCapacity},
			"new":        map[string]interface{}{"capacity": capacity},
			"section_id": sectionID,
		},
	}); err != nil {
		logger.Error("failed to publish section.updated event", zap.Error(err))
	}

	return nil
}

// Activate sets is_active to true.
func (s *sectionService) Activate(ctx context.Context, id uuid.UUID, updatedBy *uuid.UUID) error {
	logger := s.logger.With(zap.String("method", "Activate"), zap.String("section_id", id.String()))

	tx, err := s.pgClient.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("begin tx: %w", err)
	}
	defer tx.Rollback()

	// Fetch current state for event
	section, err := s.repo.GetByIDForUpdate(ctx, tx, id)
	if err != nil {
		return err
	}
	if section == nil {
		return fmt.Errorf("%w: section %s", ErrNotFound, id)
	}
	oldActive := section.IsActive

	if err := s.repo.Activate(ctx, tx, id, updatedBy); err != nil {
		return err
	}

	if err := tx.Commit(); err != nil {
		return fmt.Errorf("commit tx: %w", err)
	}

	logger.Info("section activated")

	// Publish update event
	if err := s.eventPublisher.Publish(ctx, Event{
		Type: EventSectionUpdated,
		Data: map[string]interface{}{
			"old":        map[string]interface{}{"is_active": oldActive},
			"new":        map[string]interface{}{"is_active": true},
			"section_id": id,
		},
	}); err != nil {
		logger.Error("failed to publish section.updated event", zap.Error(err))
	}

	return nil
}

// Deactivate sets is_active to false.
func (s *sectionService) Deactivate(ctx context.Context, id uuid.UUID, updatedBy *uuid.UUID) error {
	logger := s.logger.With(zap.String("method", "Deactivate"), zap.String("section_id", id.String()))

	tx, err := s.pgClient.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("begin tx: %w", err)
	}
	defer tx.Rollback()

	// Fetch current state for event
	section, err := s.repo.GetByIDForUpdate(ctx, tx, id)
	if err != nil {
		return err
	}
	if section == nil {
		return fmt.Errorf("%w: section %s", ErrNotFound, id)
	}
	oldActive := section.IsActive

	if err := s.repo.Deactivate(ctx, tx, id, updatedBy); err != nil {
		return err
	}

	if err := tx.Commit(); err != nil {
		return fmt.Errorf("commit tx: %w", err)
	}

	logger.Info("section deactivated")

	// Publish update event
	if err := s.eventPublisher.Publish(ctx, Event{
		Type: EventSectionUpdated,
		Data: map[string]interface{}{
			"old":        map[string]interface{}{"is_active": oldActive},
			"new":        map[string]interface{}{"is_active": false},
			"section_id": id,
		},
	}); err != nil {
		logger.Error("failed to publish section.updated event", zap.Error(err))
	}

	return nil
}

// Delete soft-deletes a section.
func (s *sectionService) Delete(ctx context.Context, id uuid.UUID, deletedBy *uuid.UUID) error {
	logger := s.logger.With(zap.String("method", "Delete"), zap.String("section_id", id.String()))

	tx, err := s.pgClient.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("begin tx: %w", err)
	}
	defer tx.Rollback()

	// Check for dependent records (enrollments)
	count, err := s.enrollmentRepo.CountBySection(ctx, tx, id)
	if err != nil {
		return fmt.Errorf("failed to check enrollments: %w", err)
	}
	if count > 0 {
		return fmt.Errorf("%w: section has %d active enrollments", ErrDependencyExists, count)
	}

	// Additional dependency checks (timetable entries, etc.) can be added here.

	if err := s.repo.Delete(ctx, tx, id, deletedBy); err != nil {
		return err
	}

	if err := tx.Commit(); err != nil {
		return fmt.Errorf("commit tx: %w", err)
	}

	logger.Info("section deleted")

	// Publish event
	if err := s.eventPublisher.Publish(ctx, Event{
		Type: EventSectionDeleted,
		Data: map[string]interface{}{
			"section_id": id,
			"deleted_by": deletedBy,
		},
	}); err != nil {
		logger.Error("failed to publish section.deleted event", zap.Error(err))
	}

	return nil
}

// ValidateCapacity checks if the current enrollment count exceeds capacity.
func (s *sectionService) ValidateCapacity(ctx context.Context, sectionID uuid.UUID) error {
	logger := s.logger.With(zap.String("method", "ValidateCapacity"), zap.String("section_id", sectionID.String()))

	// Get section and its capacity
	section, err := s.repo.GetByID(ctx, s.pgClient.DB, sectionID)
	if err != nil {
		return err
	}
	if section == nil {
		return fmt.Errorf("%w: section %s", ErrNotFound, sectionID)
	}
	if section.Capacity <= 0 {
		// No capacity limit
		return nil
	}

	// Count active enrollments in this section
	enrolled, err := s.enrollmentRepo.CountActiveBySection(ctx, s.pgClient.DB, sectionID)
	if err != nil {
		return fmt.Errorf("failed to count enrollments: %w", err)
	}

	if enrolled >= int64(section.Capacity) {
		logger.Warn("section capacity exceeded",
			zap.Int("capacity", section.Capacity),
			zap.Int64("enrolled", enrolled))
		return fmt.Errorf("%w: section capacity %d exceeded (enrolled: %d)", ErrCapacityExceeded, section.Capacity, enrolled)
	}

	logger.Info("section capacity valid", zap.Int("capacity", section.Capacity), zap.Int64("enrolled", enrolled))
	return nil
}

// validateTermBelongsToCompany checks that the term's academic year belongs to the given company.
func (s *sectionService) validateTermBelongsToCompany(ctx context.Context, db repository.DBTX, termID, expectedCompanyID uuid.UUID) error {
	// This requires a new repo method: TermRepository.GetAcademicYearByTerm
	ay, err := s.termRepo.GetAcademicYearByTerm(ctx, db, termID)
	if err != nil {
		return err
	}
	if ay == nil {
		return fmt.Errorf("academic year for term %s not found", termID)
	}
	if ay.CompanyID != expectedCompanyID {
		return fmt.Errorf("%w: term belongs to a different company (expected %s, got %s)", ErrInvalidInput, expectedCompanyID, ay.CompanyID)
	}
	return nil
}

// Helper to convert map keys to slice (used in BulkCreate)
func keysToSlice(m map[uuid.UUID]struct{}) []uuid.UUID {
	s := make([]uuid.UUID, 0, len(m))
	for k := range m {
		s = append(s, k)
	}
	return s
}

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

// ---------------------------------------------------------------------
// SectionService interface (unchanged)
// ---------------------------------------------------------------------

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

// ---------------------------------------------------------------------
// sectionService struct (updated with audit/outbox)
// ---------------------------------------------------------------------

type sectionService struct {
	repo           repository.SectionRepository
	courseRepo     repository.CourseRepository
	termRepo       repository.TermRepository
	enrollmentRepo repository.EnrollmentRepository

	auditLogger AuditLogger
	outboxStore OutboxStore

	pgClient *client.PostgresClient
	logger   *zap.Logger
}

// ---------------------------------------------------------------------
// Constructor (updated)
// ---------------------------------------------------------------------

func NewSectionService(
	repo repository.SectionRepository,
	courseRepo repository.CourseRepository,
	termRepo repository.TermRepository,
	enrollmentRepo repository.EnrollmentRepository,
	auditLogger AuditLogger,
	outboxStore OutboxStore,
	pgClient *client.PostgresClient,
	logger *zap.Logger,
) SectionService {
	return &sectionService{
		repo:           repo,
		courseRepo:     courseRepo,
		termRepo:       termRepo,
		enrollmentRepo: enrollmentRepo,
		auditLogger:    auditLogger,
		outboxStore:    outboxStore,
		pgClient:       pgClient,
		logger:         logger.Named("section_service"),
	}
}

// ---------------------------------------------------------------------
// Validation helpers (reusable)
// ---------------------------------------------------------------------

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

// validateDomain ensures course exists, term exists, and term belongs to the same company as course.
// Returns the course and term for reuse.
func (s *sectionService) validateDomain(ctx context.Context, tx repository.DBTX, courseID, termID uuid.UUID) (*models.Course, *models.Term, error) {
	course, err := s.courseRepo.GetByID(ctx, tx, courseID)
	if err != nil {
		return nil, nil, err
	}
	if course == nil {
		return nil, nil, fmt.Errorf("%w: course %s", ErrNotFound, courseID)
	}

	term, err := s.termRepo.GetByID(ctx, tx, termID)
	if err != nil {
		return nil, nil, err
	}
	if term == nil {
		return nil, nil, fmt.Errorf("%w: term %s", ErrNotFound, termID)
	}

	ay, err := s.termRepo.GetAcademicYearByTerm(ctx, tx, termID)
	if err != nil {
		return nil, nil, err
	}
	if ay == nil {
		return nil, nil, fmt.Errorf("academic year for term %s not found", termID)
	}
	if course.CompanyID != ay.CompanyID {
		return nil, nil, fmt.Errorf("%w: term belongs to different company", ErrInvalidInput)
	}
	return course, term, nil
}

// ---------------------------------------------------------------------
// Core CRUD (upgraded with outbox, audit, locking)
// ---------------------------------------------------------------------

func (s *sectionService) Create(ctx context.Context, req CreateSectionRequest) (*models.Section, error) {
	// Add timeout for safety
	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()

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

	// Validate domain (course, term, company consistency)
	_, _, err = s.validateDomain(ctx, tx, req.CourseID, req.TermID)
	if err != nil {
		return nil, err
	}

	// Check uniqueness
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

	// Audit log
	if err := s.auditLogger.Log(ctx, tx, "SECTION_CREATE", section.SectionID, nil, section, req.CreatedBy); err != nil {
		logger.Error("audit log failed", zap.Error(err))
	}

	// Outbox event
	if err := s.outboxStore.Store(ctx, tx, string(EventSectionCreated), section); err != nil {
		return nil, fmt.Errorf("store outbox event: %w", err)
	}

	if err := tx.Commit(); err != nil {
		return nil, fmt.Errorf("commit tx: %w", err)
	}

	logger.Info("section created", zap.String("section_id", section.SectionID.String()))
	return section, nil
}

func (s *sectionService) BulkCreate(ctx context.Context, reqs []CreateSectionRequest) ([]*models.Section, error) {
	if len(reqs) == 0 {
		return nil, nil
	}
	ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()

	logger := s.logger.With(zap.String("method", "BulkCreate"), zap.Int("count", len(reqs)))

	tx, err := s.pgClient.BeginTx(ctx, nil)
	if err != nil {
		return nil, fmt.Errorf("begin tx: %w", err)
	}
	defer tx.Rollback()

	// Collect unique course and term IDs
	courseIDs := make(map[uuid.UUID]struct{})
	termIDs := make(map[uuid.UUID]struct{})
	for _, req := range reqs {
		courseIDs[req.CourseID] = struct{}{}
		termIDs[req.TermID] = struct{}{}
	}
	courseList := keysToSlice(courseIDs)
	termList := keysToSlice(termIDs)

	// Preload and lock courses (optional: lock only if needed)
	coursesMap := make(map[uuid.UUID]*models.Course)
	for _, cid := range courseList {
		course, err := s.courseRepo.GetByIDForUpdate(ctx, tx, cid)
		if err != nil {
			return nil, err
		}
		if course == nil {
			return nil, fmt.Errorf("%w: course %s", ErrNotFound, cid)
		}
		coursesMap[cid] = course
	}

	// Preload terms
	termsMap, err := s.termRepo.GetByIDs(ctx, tx, termList)
	if err != nil {
		return nil, fmt.Errorf("preload terms: %w", err)
	}
	for _, tid := range termList {
		if _, ok := termsMap[tid]; !ok {
			return nil, fmt.Errorf("%w: term %s", ErrNotFound, tid)
		}
	}

	// Preload academic years for terms (to validate company)
	termToAYMap, err := s.termRepo.GetAcademicYearsByTermIDs(ctx, tx, termList)
	if err != nil {
		return nil, fmt.Errorf("preload academic years: %w", err)
	}

	// Preload existing sections
	existingSections, err := s.repo.List(ctx, tx, repository.SectionFilter{
		CourseIDs: courseList,
		TermIDs:   termList,
	}, repository.Pagination{Limit: 10000}, repository.Sort{})
	if err != nil {
		return nil, fmt.Errorf("preload existing sections: %w", err)
	}
	existingKeyMap := make(map[string]bool)
	for _, sec := range existingSections {
		key := sec.CourseID.String() + ":" + sec.TermID.String() + ":" + sec.Name
		existingKeyMap[key] = true
	}

	seen := make(map[string]bool)
	var toCreate []*models.Section
	for i, req := range reqs {
		if err := s.validateInput(req); err != nil {
			return nil, fmt.Errorf("item %d: %w", i, err)
		}
		key := req.CourseID.String() + ":" + req.TermID.String() + ":" + req.Name
		if seen[key] {
			return nil, fmt.Errorf("item %d: %w: duplicate in batch", i, ErrDuplicate)
		}
		seen[key] = true
		if existingKeyMap[key] {
			return nil, fmt.Errorf("item %d: %w: already exists", i, ErrDuplicate)
		}

		// Validate company consistency
		course := coursesMap[req.CourseID]
		ay := termToAYMap[req.TermID]
		if course == nil {
			return nil, fmt.Errorf("item %d: course %s not found", i, req.CourseID)
		}
		if ay == nil {
			return nil, fmt.Errorf("item %d: academic year for term %s not found", i, req.TermID)
		}
		if course.CompanyID != ay.CompanyID {
			return nil, fmt.Errorf("item %d: term does not belong to same company as course", i)
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

	// Audit and outbox for each created section
	for _, sec := range toCreate {
		if err := s.auditLogger.Log(ctx, tx, "SECTION_BULK_CREATE", sec.SectionID, nil, sec, sec.CreatedBy); err != nil {
			logger.Error("audit failed", zap.String("section_id", sec.SectionID.String()), zap.Error(err))
		}
		if err := s.outboxStore.Store(ctx, tx, string(EventSectionCreated), sec); err != nil {
			return nil, fmt.Errorf("outbox store for section %s: %w", sec.SectionID, err)
		}
	}

	if err := tx.Commit(); err != nil {
		return nil, fmt.Errorf("commit tx: %w", err)
	}

	logger.Info("bulk created sections", zap.Int("count", len(toCreate)))
	return toCreate, nil
}

func (s *sectionService) Upsert(ctx context.Context, req CreateSectionRequest) (*models.Section, error) {
	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()

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

	// Validate domain
	_, _, err = s.validateDomain(ctx, tx, req.CourseID, req.TermID)
	if err != nil {
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

	// For upsert, we don't know if it was insert or update. We'll publish a generic event.
	// If you need to differentiate, you could fetch before and after.
	if err := s.auditLogger.Log(ctx, tx, "SECTION_UPSERT", section.SectionID, nil, section, req.UpdatedBy); err != nil {
		logger.Error("audit log failed", zap.Error(err))
	}
	if err := s.outboxStore.Store(ctx, tx, string(EventSectionUpdated), section); err != nil {
		return nil, fmt.Errorf("outbox store: %w", err)
	}

	if err := tx.Commit(); err != nil {
		return nil, fmt.Errorf("commit tx: %w", err)
	}

	logger.Info("section upserted", zap.String("section_id", section.SectionID.String()))
	return section, nil
}

// ---------------------------------------------------------------------
// Read‑only operations (unchanged, no transaction needed)
// ---------------------------------------------------------------------

func (s *sectionService) GetByID(ctx context.Context, id uuid.UUID) (*models.Section, error) {
	ctx, cancel := context.WithTimeout(ctx, 2*time.Second)
	defer cancel()
	sec, err := s.repo.GetByID(ctx, s.pgClient.DB, id)
	if err != nil {
		return nil, err
	}
	if sec == nil {
		return nil, fmt.Errorf("%w: section %s", ErrNotFound, id)
	}
	return sec, nil
}

func (s *sectionService) List(ctx context.Context, filter repository.SectionFilter, p repository.Pagination, srt repository.Sort) ([]*models.Section, error) {
	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	return s.repo.List(ctx, s.pgClient.DB, filter, p, srt)
}

func (s *sectionService) ListByCourse(ctx context.Context, courseID uuid.UUID) ([]*models.Section, error) {
	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	return s.repo.ListByCourse(ctx, s.pgClient.DB, courseID)
}

func (s *sectionService) ListByTerm(ctx context.Context, termID uuid.UUID) ([]*models.Section, error) {
	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	return s.repo.ListByTerm(ctx, s.pgClient.DB, termID)
}

func (s *sectionService) Count(ctx context.Context, filter repository.SectionFilter) (int64, error) {
	ctx, cancel := context.WithTimeout(ctx, 2*time.Second)
	defer cancel()
	return s.repo.Count(ctx, s.pgClient.DB, filter)
}

func (s *sectionService) Exists(ctx context.Context, courseID, termID uuid.UUID, name string) (bool, error) {
	ctx, cancel := context.WithTimeout(ctx, 2*time.Second)
	defer cancel()
	return s.repo.Exists(ctx, s.pgClient.DB, courseID, termID, name)
}

// ---------------------------------------------------------------------
// Update operations (with locking, audit, outbox)
// ---------------------------------------------------------------------

func (s *sectionService) Update(ctx context.Context, req UpdateSectionRequest) (*models.Section, error) {
	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()

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
	oldSection := *section

	// If name changed, check uniqueness
	if req.Name != section.Name {
		exists, err := s.repo.Exists(ctx, tx, section.CourseID, section.TermID, req.Name)
		if err != nil {
			return nil, err
		}
		if exists {
			return nil, fmt.Errorf("%w: section name %s already exists", ErrDuplicate, req.Name)
		}
	}

	section.Name = req.Name
	section.Capacity = req.Capacity
	section.IsActive = req.IsActive
	section.UpdatedBy = req.UpdatedBy

	if err := s.repo.Update(ctx, tx, section); err != nil {
		return nil, err
	}

	// Audit
	if err := s.auditLogger.Log(ctx, tx, "SECTION_UPDATE", req.SectionID, &oldSection, section, req.UpdatedBy); err != nil {
		logger.Error("audit log failed", zap.Error(err))
	}
	// Outbox
	if err := s.outboxStore.Store(ctx, tx, string(EventSectionUpdated), map[string]interface{}{
		"old": oldSection,
		"new": section,
	}); err != nil {
		return nil, fmt.Errorf("outbox store: %w", err)
	}

	if err := tx.Commit(); err != nil {
		return nil, fmt.Errorf("commit tx: %w", err)
	}

	logger.Info("section updated")
	return section, nil
}

func (s *sectionService) UpdateCapacity(ctx context.Context, sectionID uuid.UUID, capacity int, updatedBy *uuid.UUID) error {
	ctx, cancel := context.WithTimeout(ctx, 3*time.Second)
	defer cancel()

	logger := s.logger.With(zap.String("method", "UpdateCapacity"), zap.String("section_id", sectionID.String()))

	if capacity < 0 {
		return fmt.Errorf("%w: capacity cannot be negative", ErrInvalidInput)
	}

	tx, err := s.pgClient.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("begin tx: %w", err)
	}
	defer tx.Rollback()

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

	// Audit
	if err := s.auditLogger.Log(ctx, tx, "SECTION_CAPACITY_UPDATE", sectionID, map[string]interface{}{"capacity": oldCapacity}, map[string]interface{}{"capacity": capacity}, updatedBy); err != nil {
		logger.Error("audit log failed", zap.Error(err))
	}
	// Outbox
	if err := s.outboxStore.Store(ctx, tx, string(EventSectionUpdated), map[string]interface{}{
		"section_id": sectionID,
		"old":        map[string]interface{}{"capacity": oldCapacity},
		"new":        map[string]interface{}{"capacity": capacity},
	}); err != nil {
		return fmt.Errorf("outbox store: %w", err)
	}

	if err := tx.Commit(); err != nil {
		return fmt.Errorf("commit tx: %w", err)
	}

	logger.Info("section capacity updated", zap.Int("capacity", capacity))
	return nil
}

func (s *sectionService) Activate(ctx context.Context, id uuid.UUID, updatedBy *uuid.UUID) error {
	ctx, cancel := context.WithTimeout(ctx, 3*time.Second)
	defer cancel()

	logger := s.logger.With(zap.String("method", "Activate"), zap.String("section_id", id.String()))

	tx, err := s.pgClient.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("begin tx: %w", err)
	}
	defer tx.Rollback()

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

	// Audit
	if err := s.auditLogger.Log(ctx, tx, "SECTION_ACTIVATE", id, map[string]interface{}{"is_active": oldActive}, map[string]interface{}{"is_active": true}, updatedBy); err != nil {
		logger.Error("audit log failed", zap.Error(err))
	}
	// Outbox
	if err := s.outboxStore.Store(ctx, tx, string(EventSectionUpdated), map[string]interface{}{
		"section_id": id,
		"old":        map[string]interface{}{"is_active": oldActive},
		"new":        map[string]interface{}{"is_active": true},
	}); err != nil {
		return fmt.Errorf("outbox store: %w", err)
	}

	if err := tx.Commit(); err != nil {
		return fmt.Errorf("commit tx: %w", err)
	}

	logger.Info("section activated")
	return nil
}

func (s *sectionService) Deactivate(ctx context.Context, id uuid.UUID, updatedBy *uuid.UUID) error {
	ctx, cancel := context.WithTimeout(ctx, 3*time.Second)
	defer cancel()

	logger := s.logger.With(zap.String("method", "Deactivate"), zap.String("section_id", id.String()))

	tx, err := s.pgClient.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("begin tx: %w", err)
	}
	defer tx.Rollback()

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

	// Audit
	if err := s.auditLogger.Log(ctx, tx, "SECTION_DEACTIVATE", id, map[string]interface{}{"is_active": oldActive}, map[string]interface{}{"is_active": false}, updatedBy); err != nil {
		logger.Error("audit log failed", zap.Error(err))
	}
	// Outbox
	if err := s.outboxStore.Store(ctx, tx, string(EventSectionUpdated), map[string]interface{}{
		"section_id": id,
		"old":        map[string]interface{}{"is_active": oldActive},
		"new":        map[string]interface{}{"is_active": false},
	}); err != nil {
		return fmt.Errorf("outbox store: %w", err)
	}

	if err := tx.Commit(); err != nil {
		return fmt.Errorf("commit tx: %w", err)
	}

	logger.Info("section deactivated")
	return nil
}

func (s *sectionService) Delete(ctx context.Context, id uuid.UUID, deletedBy *uuid.UUID) error {
	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()

	logger := s.logger.With(zap.String("method", "Delete"), zap.String("section_id", id.String()))

	tx, err := s.pgClient.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("begin tx: %w", err)
	}
	defer tx.Rollback()

	// Lock the section to prevent concurrent deletes
	section, err := s.repo.GetByIDForUpdate(ctx, tx, id)
	if err != nil {
		return err
	}
	if section == nil {
		// Idempotent: already deleted
		logger.Info("section already deleted (idempotent)")
		return nil
	}

	// Check for dependent enrollments
	count, err := s.enrollmentRepo.CountBySection(ctx, tx, id)
	if err != nil {
		return fmt.Errorf("failed to check enrollments: %w", err)
	}
	if count > 0 {
		return fmt.Errorf("%w: section has %d active enrollments", ErrDependencyExists, count)
	}

	if err := s.repo.Delete(ctx, tx, id, deletedBy); err != nil {
		return err
	}

	// Audit
	if err := s.auditLogger.Log(ctx, tx, "SECTION_DELETE", id, section, nil, deletedBy); err != nil {
		logger.Error("audit log failed", zap.Error(err))
	}
	// Outbox
	if err := s.outboxStore.Store(ctx, tx, string(EventSectionDeleted), map[string]interface{}{
		"section_id": id,
		"deleted_by": deletedBy,
	}); err != nil {
		return fmt.Errorf("outbox store: %w", err)
	}

	if err := tx.Commit(); err != nil {
		return fmt.Errorf("commit tx: %w", err)
	}

	logger.Info("section deleted")
	return nil
}

// ---------------------------------------------------------------------
// Validation (read-only, but should be done within transaction if used in critical path)
// ---------------------------------------------------------------------

func (s *sectionService) ValidateCapacity(ctx context.Context, sectionID uuid.UUID) error {
	ctx, cancel := context.WithTimeout(ctx, 2*time.Second)
	defer cancel()

	// For validation, we don't need a transaction unless we intend to lock.
	// But to avoid race conditions, we should use a row lock when the caller is about to enroll.
	// This method is read-only; we'll rely on caller to lock if needed.
	section, err := s.repo.GetByID(ctx, s.pgClient.DB, sectionID)
	if err != nil {
		return err
	}
	if section == nil {
		return fmt.Errorf("%w: section %s", ErrNotFound, sectionID)
	}
	if section.Capacity <= 0 {
		return nil
	}

	enrolled, err := s.enrollmentRepo.CountActiveBySection(ctx, s.pgClient.DB, sectionID)
	if err != nil {
		return fmt.Errorf("failed to count enrollments: %w", err)
	}

	if enrolled >= int64(section.Capacity) {
		return fmt.Errorf("%w: section capacity %d exceeded (enrolled: %d)", ErrCapacityExceeded, section.Capacity, enrolled)
	}
	return nil
}

// ---------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------

// keysToSlice converts a map of UUIDs to a slice (reused from earlier)
func keysToSlice(m map[uuid.UUID]struct{}) []uuid.UUID {
	s := make([]uuid.UUID, 0, len(m))
	for k := range m {
		s = append(s, k)
	}
	return s
}

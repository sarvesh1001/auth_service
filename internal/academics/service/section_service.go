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

// SectionService defines the interface for section operations.
type SectionService interface {
	Create(ctx context.Context, req CreateSectionRequest) (*models.Section, error)
	BulkCreate(ctx context.Context, reqs []CreateSectionRequest) ([]*models.Section, error)
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
	repo             repository.SectionRepository
	courseRepo       repository.CourseRepository
	termRepo         repository.TermRepository
	enrollmentRepo   repository.EnrollmentRepository
	auditService     *audit.AuditService
	outboxRepo       outbox.Repository
	idempotencyStore idempotency.Store
	pgClient         *client.PostgresClient
	logger           *zap.Logger
}

// NewSectionService creates a new section service with all dependencies.
func NewSectionService(
	repo repository.SectionRepository,
	courseRepo repository.CourseRepository,
	termRepo repository.TermRepository,
	enrollmentRepo repository.EnrollmentRepository,
	auditService *audit.AuditService,
	outboxRepo outbox.Repository,
	idempotencyStore idempotency.Store,
	pgClient *client.PostgresClient,
	logger *zap.Logger,
) SectionService {
	return &sectionService{
		repo:             repo,
		courseRepo:       courseRepo,
		termRepo:         termRepo,
		enrollmentRepo:   enrollmentRepo,
		auditService:     auditService,
		outboxRepo:       outboxRepo,
		idempotencyStore: idempotencyStore,
		pgClient:         pgClient,
		logger:           logger.Named("section_service"),
	}
}

// validateInput performs basic validation on the request.
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

// validateDomain ensures the course and term exist and belong to the same company.
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
	// Get academic year for term to verify company consistency
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

// Create implements SectionService.
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

	// Idempotency check
	idempotencyKey, _ := ctx.Value("idempotency_key").(string)
	if idempotencyKey != "" {
		var existing *models.Section
		if err := s.idempotencyStore.Get(ctx, tx, idempotencyKey, &existing); err == nil && existing != nil {
			logger.Info("idempotent request, returning cached response")
			return existing, nil
		}
	}

	// Validate domain (course and term)
	_, _, err = s.validateDomain(ctx, tx, req.CourseID, req.TermID)
	if err != nil {
		return nil, err
	}

	// Check uniqueness (course_id, term_id, name)
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

	// Store idempotency response
	if idempotencyKey != "" {
		if err := s.idempotencyStore.Store(ctx, tx, idempotencyKey, section); err != nil {
			logger.Error("failed to store idempotency key", zap.Error(err))
		}
	}

	// Audit log
	if s.auditService != nil {
		_ = s.auditService.LogAction(ctx, tx, nil, "academics", "create", "section",
			&section.SectionID, "user", req.CreatedBy, nil, nil,
			map[string]interface{}{"name": section.Name, "course_id": section.CourseID, "term_id": section.TermID})
	}

	// Outbox event
	payload, _ := json.Marshal(section)
	outboxEvent := &outbox.Event{
		EventID:       uuid.New().String(),
		AggregateType: "section",
		AggregateID:   section.SectionID.String(),
		EventType:     string(EventSectionCreated),
		Payload:       payload,
		Status:        "pending",
	}
	if err := s.outboxRepo.Store(ctx, tx, outboxEvent); err != nil {
		return nil, fmt.Errorf("store outbox event: %w", err)
	}

	if err := tx.Commit(); err != nil {
		return nil, fmt.Errorf("commit tx: %w", err)
	}

	logger.Info("section created", zap.String("section_id", section.SectionID.String()))
	return section, nil
}

// BulkCreate implements SectionService.
func (s *sectionService) BulkCreate(ctx context.Context, reqs []CreateSectionRequest) ([]*models.Section, error) {
	if len(reqs) == 0 {
		return nil, nil
	}
	logger := s.logger.With(zap.String("method", "BulkCreate"), zap.Int("batch_size", len(reqs)))

	// Validate each request first (without transaction)
	for i, req := range reqs {
		if err := s.validateInput(req); err != nil {
			return nil, fmt.Errorf("item %d: %w", i, err)
		}
	}

	tx, err := s.pgClient.BeginTx(ctx, nil)
	if err != nil {
		return nil, fmt.Errorf("begin tx: %w", err)
	}
	defer tx.Rollback()

	// Idempotency check (optional for bulk)
	idempotencyKey, _ := ctx.Value("idempotency_key").(string)
	if idempotencyKey != "" {
		var existing []*models.Section
		if err := s.idempotencyStore.Get(ctx, tx, idempotencyKey, &existing); err == nil && existing != nil {
			logger.Info("idempotent bulk request, returning cached response")
			return existing, nil
		}
	}

	// Preload all needed courses and terms
	courseIDs := make(map[uuid.UUID]struct{})
	termIDs := make(map[uuid.UUID]struct{})
	for _, req := range reqs {
		courseIDs[req.CourseID] = struct{}{}
		termIDs[req.TermID] = struct{}{}
	}
	courseList := keysToSlice(courseIDs)
	termList := keysToSlice(termIDs)

	// Load courses
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

	// Load terms
	termsMap, err := s.termRepo.GetByIDs(ctx, tx, termList)
	if err != nil {
		return nil, fmt.Errorf("preload terms: %w", err)
	}
	for _, tid := range termList {
		if _, ok := termsMap[tid]; !ok {
			return nil, fmt.Errorf("%w: term %s", ErrNotFound, tid)
		}
	}

	// Get academic years for terms to verify company consistency
	termToAYMap, err := s.termRepo.GetAcademicYearsByTermIDs(ctx, tx, termList)
	if err != nil {
		return nil, fmt.Errorf("preload academic years: %w", err)
	}

	// Load existing sections to check duplicates
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

	// Prepare sections for creation
	seen := make(map[string]bool)
	var toCreate []*models.Section
	for i, req := range reqs {
		key := req.CourseID.String() + ":" + req.TermID.String() + ":" + req.Name
		if seen[key] {
			return nil, fmt.Errorf("item %d: %w: duplicate in batch", i, ErrDuplicate)
		}
		seen[key] = true
		if existingKeyMap[key] {
			return nil, fmt.Errorf("item %d: %w: already exists", i, ErrDuplicate)
		}
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

	// Bulk insert
	if err := s.repo.BulkCreate(ctx, tx, toCreate); err != nil {
		return nil, err
	}

	// Store idempotency response
	if idempotencyKey != "" {
		if err := s.idempotencyStore.Store(ctx, tx, idempotencyKey, toCreate); err != nil {
			logger.Error("failed to store idempotency key", zap.Error(err))
		}
	}

	// Audit and outbox for each created section
	for _, sec := range toCreate {
		if s.auditService != nil {
			_ = s.auditService.LogAction(ctx, tx, nil, "academics", "bulk_create", "section",
				&sec.SectionID, "user", sec.CreatedBy, nil, nil,
				map[string]interface{}{"name": sec.Name})
		}
		payload, _ := json.Marshal(sec)
		outboxEvent := &outbox.Event{
			EventID:       uuid.New().String(),
			AggregateType: "section",
			AggregateID:   sec.SectionID.String(),
			EventType:     string(EventSectionCreated),
			Payload:       payload,
			Status:        "pending",
		}
		if err := s.outboxRepo.Store(ctx, tx, outboxEvent); err != nil {
			return nil, fmt.Errorf("store outbox event for %s: %w", sec.SectionID, err)
		}
	}

	if err := tx.Commit(); err != nil {
		return nil, fmt.Errorf("commit tx: %w", err)
	}

	logger.Info("bulk created sections", zap.Int("count", len(toCreate)))
	return toCreate, nil
}

// Upsert implements SectionService.
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

	// Idempotency
	idempotencyKey, _ := ctx.Value("idempotency_key").(string)
	if idempotencyKey != "" {
		var existing *models.Section
		if err := s.idempotencyStore.Get(ctx, tx, idempotencyKey, &existing); err == nil && existing != nil {
			logger.Info("idempotent request, returning cached response")
			return existing, nil
		}
	}

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

	// Upsert operation (create or update)
	if err := s.repo.Upsert(ctx, tx, section); err != nil {
		return nil, err
	}

	// Idempotency store
	if idempotencyKey != "" {
		if err := s.idempotencyStore.Store(ctx, tx, idempotencyKey, section); err != nil {
			logger.Error("failed to store idempotency key", zap.Error(err))
		}
	}

	// Audit log
	if s.auditService != nil {
		_ = s.auditService.LogAction(ctx, tx, nil, "academics", "upsert", "section",
			&section.SectionID, "user", req.UpdatedBy, nil, nil,
			map[string]interface{}{"name": section.Name})
	}

	// Outbox event (use created/updated based on existence? Simpler: always "section.updated" for upsert)
	payload, _ := json.Marshal(section)
	outboxEvent := &outbox.Event{
		EventID:       uuid.New().String(),
		AggregateType: "section",
		AggregateID:   section.SectionID.String(),
		EventType:     string(EventSectionUpdated),
		Payload:       payload,
		Status:        "pending",
	}
	if err := s.outboxRepo.Store(ctx, tx, outboxEvent); err != nil {
		return nil, fmt.Errorf("store outbox event: %w", err)
	}

	if err := tx.Commit(); err != nil {
		return nil, fmt.Errorf("commit tx: %w", err)
	}

	logger.Info("section upserted", zap.String("section_id", section.SectionID.String()))
	return section, nil
}

// GetByID implements SectionService.
func (s *sectionService) GetByID(ctx context.Context, id uuid.UUID) (*models.Section, error) {
	section, err := s.repo.GetByID(ctx, s.pgClient.DB, id)
	if err != nil {
		return nil, err
	}
	if section == nil {
		return nil, fmt.Errorf("%w: section %s", ErrNotFound, id)
	}
	return section, nil
}

// List implements SectionService.
func (s *sectionService) List(ctx context.Context, filter repository.SectionFilter, p repository.Pagination, srt repository.Sort) ([]*models.Section, error) {
	return s.repo.List(ctx, s.pgClient.DB, filter, p, srt)
}

// ListByCourse implements SectionService.
func (s *sectionService) ListByCourse(ctx context.Context, courseID uuid.UUID) ([]*models.Section, error) {
	return s.repo.ListByCourse(ctx, s.pgClient.DB, courseID)
}

// ListByTerm implements SectionService.
func (s *sectionService) ListByTerm(ctx context.Context, termID uuid.UUID) ([]*models.Section, error) {
	return s.repo.ListByTerm(ctx, s.pgClient.DB, termID)
}

// Count implements SectionService.
func (s *sectionService) Count(ctx context.Context, filter repository.SectionFilter) (int64, error) {
	return s.repo.Count(ctx, s.pgClient.DB, filter)
}

// Exists implements SectionService.
func (s *sectionService) Exists(ctx context.Context, courseID, termID uuid.UUID, name string) (bool, error) {
	return s.repo.Exists(ctx, s.pgClient.DB, courseID, termID, name)
}

// Update implements SectionService.
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

	// Idempotency
	idempotencyKey, _ := ctx.Value("idempotency_key").(string)
	if idempotencyKey != "" {
		var existing *models.Section
		if err := s.idempotencyStore.Get(ctx, tx, idempotencyKey, &existing); err == nil && existing != nil {
			logger.Info("idempotent request, returning cached response")
			return existing, nil
		}
	}

	// Lock and fetch current section
	section, err := s.repo.GetByIDForUpdate(ctx, tx, req.SectionID)
	if err != nil {
		return nil, err
	}
	if section == nil {
		return nil, fmt.Errorf("%w: section %s", ErrNotFound, req.SectionID)
	}
	oldSection := *section

	// Check name uniqueness if changed
	if req.Name != section.Name {
		exists, err := s.repo.Exists(ctx, tx, section.CourseID, section.TermID, req.Name)
		if err != nil {
			return nil, err
		}
		if exists {
			return nil, fmt.Errorf("%w: section name %s already exists", ErrDuplicate, req.Name)
		}
	}

	// Update fields
	section.Name = req.Name
	section.Capacity = req.Capacity
	section.IsActive = req.IsActive
	section.UpdatedBy = req.UpdatedBy

	if err := s.repo.Update(ctx, tx, section); err != nil {
		return nil, err
	}

	// Idempotency store
	if idempotencyKey != "" {
		if err := s.idempotencyStore.Store(ctx, tx, idempotencyKey, section); err != nil {
			logger.Error("failed to store idempotency key", zap.Error(err))
		}
	}

	// Audit log with before/after
	if s.auditService != nil {
		beforeJSON, _ := json.Marshal(oldSection)
		afterJSON, _ := json.Marshal(section)
		_ = s.auditService.LogAction(ctx, tx, nil, "academics", "update", "section",
			&req.SectionID, "user", req.UpdatedBy, beforeJSON, afterJSON, nil)
	}

	// Outbox event (store the full updated object)
	payload, _ := json.Marshal(section)
	outboxEvent := &outbox.Event{
		EventID:       uuid.New().String(),
		AggregateType: "section",
		AggregateID:   section.SectionID.String(),
		EventType:     string(EventSectionUpdated),
		Payload:       payload,
		Status:        "pending",
	}
	if err := s.outboxRepo.Store(ctx, tx, outboxEvent); err != nil {
		return nil, fmt.Errorf("store outbox event: %w", err)
	}

	if err := tx.Commit(); err != nil {
		return nil, fmt.Errorf("commit tx: %w", err)
	}

	logger.Info("section updated")
	return section, nil
}

// UpdateCapacity implements SectionService.
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

	// Fetch old capacity for audit
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

	// Audit log
	if s.auditService != nil {
		_ = s.auditService.LogAction(ctx, tx, nil, "academics", "update_capacity", "section",
			&sectionID, "user", updatedBy, nil, nil,
			map[string]interface{}{"old_capacity": oldCapacity, "new_capacity": capacity})
	}

	// Outbox event (partial update)
	eventData := map[string]interface{}{
		"section_id": sectionID,
		"old":        map[string]interface{}{"capacity": oldCapacity},
		"new":        map[string]interface{}{"capacity": capacity},
	}
	payload, _ := json.Marshal(eventData)
	outboxEvent := &outbox.Event{
		EventID:       uuid.New().String(),
		AggregateType: "section",
		AggregateID:   sectionID.String(),
		EventType:     string(EventSectionUpdated),
		Payload:       payload,
		Status:        "pending",
	}
	if err := s.outboxRepo.Store(ctx, tx, outboxEvent); err != nil {
		return fmt.Errorf("store outbox event: %w", err)
	}

	if err := tx.Commit(); err != nil {
		return fmt.Errorf("commit tx: %w", err)
	}

	logger.Info("section capacity updated", zap.Int("capacity", capacity))
	return nil
}

// Activate implements SectionService.
func (s *sectionService) Activate(ctx context.Context, id uuid.UUID, updatedBy *uuid.UUID) error {
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

	if s.auditService != nil {
		_ = s.auditService.LogAction(ctx, tx, nil, "academics", "activate", "section",
			&id, "user", updatedBy, nil, nil,
			map[string]interface{}{"was_active": oldActive, "is_active": true})
	}

	eventData := map[string]interface{}{
		"section_id": id,
		"old":        map[string]interface{}{"is_active": oldActive},
		"new":        map[string]interface{}{"is_active": true},
	}
	payload, _ := json.Marshal(eventData)
	outboxEvent := &outbox.Event{
		EventID:       uuid.New().String(),
		AggregateType: "section",
		AggregateID:   id.String(),
		EventType:     string(EventSectionUpdated),
		Payload:       payload,
		Status:        "pending",
	}
	if err := s.outboxRepo.Store(ctx, tx, outboxEvent); err != nil {
		return fmt.Errorf("store outbox event: %w", err)
	}

	if err := tx.Commit(); err != nil {
		return fmt.Errorf("commit tx: %w", err)
	}

	logger.Info("section activated")
	return nil
}

// Deactivate implements SectionService.
func (s *sectionService) Deactivate(ctx context.Context, id uuid.UUID, updatedBy *uuid.UUID) error {
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

	if s.auditService != nil {
		_ = s.auditService.LogAction(ctx, tx, nil, "academics", "deactivate", "section",
			&id, "user", updatedBy, nil, nil,
			map[string]interface{}{"was_active": oldActive, "is_active": false})
	}

	eventData := map[string]interface{}{
		"section_id": id,
		"old":        map[string]interface{}{"is_active": oldActive},
		"new":        map[string]interface{}{"is_active": false},
	}
	payload, _ := json.Marshal(eventData)
	outboxEvent := &outbox.Event{
		EventID:       uuid.New().String(),
		AggregateType: "section",
		AggregateID:   id.String(),
		EventType:     string(EventSectionUpdated),
		Payload:       payload,
		Status:        "pending",
	}
	if err := s.outboxRepo.Store(ctx, tx, outboxEvent); err != nil {
		return fmt.Errorf("store outbox event: %w", err)
	}

	if err := tx.Commit(); err != nil {
		return fmt.Errorf("commit tx: %w", err)
	}

	logger.Info("section deactivated")
	return nil
}

// Delete implements SectionService.
func (s *sectionService) Delete(ctx context.Context, id uuid.UUID, deletedBy *uuid.UUID) error {
	logger := s.logger.With(zap.String("method", "Delete"), zap.String("section_id", id.String()))

	tx, err := s.pgClient.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("begin tx: %w", err)
	}
	defer tx.Rollback()

	// Lock and fetch
	section, err := s.repo.GetByIDForUpdate(ctx, tx, id)
	if err != nil {
		return err
	}
	if section == nil {
		// Idempotent: already deleted
		logger.Info("section already deleted (idempotent)")
		return nil
	}

	// Check for dependencies (enrollments)
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
	if s.auditService != nil {
		beforeJSON, _ := json.Marshal(section)
		_ = s.auditService.LogAction(ctx, tx, nil, "academics", "delete", "section",
			&id, "user", deletedBy, beforeJSON, nil, nil)
	}

	// Outbox
	eventData := map[string]interface{}{
		"section_id": id,
		"deleted_by": deletedBy,
	}
	payload, _ := json.Marshal(eventData)
	outboxEvent := &outbox.Event{
		EventID:       uuid.New().String(),
		AggregateType: "section",
		AggregateID:   id.String(),
		EventType:     string(EventSectionDeleted),
		Payload:       payload,
		Status:        "pending",
	}
	if err := s.outboxRepo.Store(ctx, tx, outboxEvent); err != nil {
		return fmt.Errorf("store outbox event: %w", err)
	}

	if err := tx.Commit(); err != nil {
		return fmt.Errorf("commit tx: %w", err)
	}

	logger.Info("section deleted")
	return nil
}

// ValidateCapacity implements SectionService.
func (s *sectionService) ValidateCapacity(ctx context.Context, sectionID uuid.UUID) error {
	section, err := s.repo.GetByID(ctx, s.pgClient.DB, sectionID)
	if err != nil {
		return err
	}
	if section == nil {
		return fmt.Errorf("%w: section %s", ErrNotFound, sectionID)
	}
	if section.Capacity <= 0 {
		return nil // unlimited capacity
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

// Helper
func keysToSlice(m map[uuid.UUID]struct{}) []uuid.UUID {
	s := make([]uuid.UUID, 0, len(m))
	for k := range m {
		s = append(s, k)
	}
	return s
}

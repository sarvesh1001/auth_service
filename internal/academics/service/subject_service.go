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

type SubjectService interface {
	Create(ctx context.Context, req CreateSubjectRequest) (*models.Subject, error)
	BulkCreate(ctx context.Context, req []CreateSubjectRequest) ([]*models.Subject, error)
	Upsert(ctx context.Context, req CreateSubjectRequest) (*models.Subject, error)

	GetByID(ctx context.Context, id uuid.UUID) (*models.Subject, error)
	GetByCode(ctx context.Context, companyID uuid.UUID, code string) (*models.Subject, error)

	List(ctx context.Context, filter repository.SubjectFilter, p repository.Pagination, s repository.Sort) ([]*models.Subject, error)
	ListActive(ctx context.Context, companyID uuid.UUID) ([]*models.Subject, error)

	Count(ctx context.Context, filter repository.SubjectFilter) (int64, error)

	Exists(ctx context.Context, companyID uuid.UUID, code string) (bool, error)

	Update(ctx context.Context, req UpdateSubjectRequest) (*models.Subject, error)

	Activate(ctx context.Context, id uuid.UUID, updatedBy *uuid.UUID) error
	Deactivate(ctx context.Context, id uuid.UUID, updatedBy *uuid.UUID) error

	Delete(ctx context.Context, id uuid.UUID, deletedBy *uuid.UUID) error

	ValidateUniqueCode(ctx context.Context, companyID uuid.UUID, code string) error
}

type subjectService struct {
	repo           repository.SubjectRepository
	eventPublisher EventPublisher
	pgClient       *client.PostgresClient
	logger         *zap.Logger
}

func NewSubjectService(
	repo repository.SubjectRepository,
	eventPublisher EventPublisher,
	pgClient *client.PostgresClient,
	logger *zap.Logger,
) SubjectService {
	return &subjectService{
		repo:           repo,
		eventPublisher: eventPublisher,
		pgClient:       pgClient,
		logger:         logger.Named("subject_service"),
	}
}

// Create inserts a new subject.
func (s *subjectService) Create(ctx context.Context, req CreateSubjectRequest) (*models.Subject, error) {
	logger := s.logger.With(
		zap.String("method", "Create"),
		zap.String("company_id", req.CompanyID.String()),
		zap.String("code", req.Code),
	)

	if err := s.validateInput(req); err != nil {
		logger.Warn("validation failed", zap.Error(err))
		return nil, err
	}

	tx, err := s.pgClient.BeginTx(ctx, nil)
	if err != nil {
		logger.Error("failed to begin transaction", zap.Error(err))
		return nil, fmt.Errorf("begin tx: %w", err)
	}
	defer tx.Rollback()

	exists, err := s.repo.Exists(ctx, tx, req.CompanyID, req.Code)
	if err != nil {
		logger.Error("failed to check existence", zap.Error(err))
		return nil, err
	}
	if exists {
		logger.Warn("subject already exists")
		return nil, fmt.Errorf("%w: subject code %s already exists for this company", ErrDuplicate, req.Code)
	}

	subject := &models.Subject{
		CompanyID:   req.CompanyID,
		Code:        req.Code,
		Name:        req.Name,
		Description: req.Description,
		Credits:     req.Credits,
		IsActive:    req.IsActive,
		CreatedBy:   req.CreatedBy,
		UpdatedBy:   req.UpdatedBy,
	}

	if err := s.repo.Create(ctx, tx, subject); err != nil {
		logger.Error("failed to create subject", zap.Error(err))
		return nil, err
	}

	if err := tx.Commit(); err != nil {
		logger.Error("failed to commit transaction", zap.Error(err))
		return nil, fmt.Errorf("commit tx: %w", err)
	}

	logger.Info("subject created", zap.String("id", subject.SubjectID.String()))

	// Publish event
	if err := s.eventPublisher.Publish(ctx, Event{
		Type: EventSubjectCreated,
		Data: subject,
	}); err != nil {
		logger.Error("failed to publish subject.created event", zap.Error(err))
	}

	return subject, nil
}

// BulkCreate inserts multiple subjects in a transaction with optimised validation.
func (s *subjectService) BulkCreate(ctx context.Context, reqs []CreateSubjectRequest) ([]*models.Subject, error) {
	if len(reqs) == 0 {
		return nil, nil
	}

	logger := s.logger.With(zap.String("method", "BulkCreate"), zap.Int("count", len(reqs)))

	// 1. Basic input validation and collect unique keys per company
	type key struct {
		companyID uuid.UUID
		code      string
	}
	requestKeys := make(map[key]int) // map key to index for error reporting
	keysByCompany := make(map[uuid.UUID][]string)

	for i, req := range reqs {
		if err := s.validateInput(req); err != nil {
			logger.Warn("validation failed", zap.Int("index", i), zap.Error(err))
			return nil, fmt.Errorf("item %d: %w", i, err)
		}
		k := key{companyID: req.CompanyID, code: req.Code}
		if _, dup := requestKeys[k]; dup {
			logger.Warn("duplicate in batch", zap.Int("index", i), zap.String("code", req.Code))
			return nil, fmt.Errorf("item %d: %w: duplicate code %s in batch", i, ErrDuplicate, req.Code)
		}
		requestKeys[k] = i
		keysByCompany[req.CompanyID] = append(keysByCompany[req.CompanyID], req.Code)
	}

	tx, err := s.pgClient.BeginTx(ctx, nil)
	if err != nil {
		logger.Error("failed to begin transaction", zap.Error(err))
		return nil, fmt.Errorf("begin tx: %w", err)
	}
	defer tx.Rollback()

	// 2. Pre‑load existing subjects for each company
	existingMap := make(map[key]*models.Subject) // key -> existing subject
	for companyID, codes := range keysByCompany {
		existing, err := s.repo.FindByCompanyAndCodes(ctx, tx, companyID, codes)
		if err != nil {
			logger.Error("failed to pre‑load existing subjects", zap.String("company_id", companyID.String()), zap.Error(err))
			return nil, err
		}
		for _, subj := range existing {
			existingMap[key{companyID: subj.CompanyID, code: subj.Code}] = subj
		}
	}

	// 3. Validate uniqueness against existing data and prepare final slice
	subjects := make([]*models.Subject, 0, len(reqs))
	for i, req := range reqs {
		k := key{companyID: req.CompanyID, code: req.Code}
		if _, exists := existingMap[k]; exists {
			logger.Warn("duplicate with existing", zap.Int("index", i), zap.String("code", req.Code))
			return nil, fmt.Errorf("item %d: %w: code %s already exists", i, ErrDuplicate, req.Code)
		}
		subjects = append(subjects, &models.Subject{
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

	if err := s.repo.BulkCreate(ctx, tx, subjects); err != nil {
		logger.Error("failed to bulk create", zap.Error(err))
		return nil, err
	}

	if err := tx.Commit(); err != nil {
		logger.Error("failed to commit transaction", zap.Error(err))
		return nil, fmt.Errorf("commit tx: %w", err)
	}

	logger.Info("bulk created subjects")

	// Publish events for each created subject
	for _, subj := range subjects {
		if err := s.eventPublisher.Publish(ctx, Event{
			Type: EventSubjectCreated,
			Data: subj,
		}); err != nil {
			logger.Error("failed to publish subject.created event", zap.String("subject_id", subj.SubjectID.String()), zap.Error(err))
		}
	}

	return subjects, nil
}

// Upsert creates or updates a subject based on unique (company_id, code) where deleted_at is null.
func (s *subjectService) Upsert(ctx context.Context, req CreateSubjectRequest) (*models.Subject, error) {
	logger := s.logger.With(
		zap.String("method", "Upsert"),
		zap.String("company_id", req.CompanyID.String()),
		zap.String("code", req.Code),
	)

	if err := s.validateInput(req); err != nil {
		logger.Warn("validation failed", zap.Error(err))
		return nil, err
	}

	tx, err := s.pgClient.BeginTx(ctx, nil)
	if err != nil {
		logger.Error("failed to begin transaction", zap.Error(err))
		return nil, fmt.Errorf("begin tx: %w", err)
	}
	defer tx.Rollback()

	subject := &models.Subject{
		CompanyID:   req.CompanyID,
		Code:        req.Code,
		Name:        req.Name,
		Description: req.Description,
		Credits:     req.Credits,
		IsActive:    req.IsActive,
		CreatedBy:   req.CreatedBy,
		UpdatedBy:   req.UpdatedBy,
	}

	if err := s.repo.Upsert(ctx, tx, subject); err != nil {
		logger.Error("failed to upsert subject", zap.Error(err))
		return nil, err
	}

	if err := tx.Commit(); err != nil {
		logger.Error("failed to commit transaction", zap.Error(err))
		return nil, fmt.Errorf("commit tx: %w", err)
	}

	logger.Info("subject upserted", zap.String("id", subject.SubjectID.String()))
	// We skip event for upsert to avoid duplicate/ambiguous events.
	return subject, nil
}

// GetByID retrieves a subject by ID.
func (s *subjectService) GetByID(ctx context.Context, id uuid.UUID) (*models.Subject, error) {
	logger := s.logger.With(zap.String("method", "GetByID"), zap.String("id", id.String()))

	subject, err := s.repo.GetByID(ctx, s.pgClient.DB, id)
	if err != nil {
		logger.Error("failed to get subject", zap.Error(err))
		return nil, err
	}
	if subject == nil {
		logger.Warn("subject not found")
		return nil, fmt.Errorf("%w: subject %s", ErrNotFound, id)
	}
	return subject, nil
}

// GetByCode retrieves a subject by company and code.
func (s *subjectService) GetByCode(ctx context.Context, companyID uuid.UUID, code string) (*models.Subject, error) {
	logger := s.logger.With(zap.String("method", "GetByCode"), zap.String("company_id", companyID.String()), zap.String("code", code))

	subject, err := s.repo.GetByCode(ctx, s.pgClient.DB, companyID, code)
	if err != nil {
		logger.Error("failed to get subject by code", zap.Error(err))
		return nil, err
	}
	if subject == nil {
		logger.Warn("subject not found")
		return nil, fmt.Errorf("%w: subject code %s for company %s", ErrNotFound, code, companyID)
	}
	return subject, nil
}

// List returns subjects matching the filter.
func (s *subjectService) List(ctx context.Context, filter repository.SubjectFilter, p repository.Pagination, srt repository.Sort) ([]*models.Subject, error) {
	return s.repo.List(ctx, s.pgClient.DB, filter, p, srt)
}

// ListActive returns all active subjects for a company.
func (s *subjectService) ListActive(ctx context.Context, companyID uuid.UUID) ([]*models.Subject, error) {
	return s.repo.ListActive(ctx, s.pgClient.DB, companyID)
}

// Count returns the number of subjects matching the filter.
func (s *subjectService) Count(ctx context.Context, filter repository.SubjectFilter) (int64, error) {
	return s.repo.Count(ctx, s.pgClient.DB, filter)
}

// Exists checks if a subject with given company and code exists.
func (s *subjectService) Exists(ctx context.Context, companyID uuid.UUID, code string) (bool, error) {
	return s.repo.Exists(ctx, s.pgClient.DB, companyID, code)
}

// Update modifies an existing subject.
func (s *subjectService) Update(ctx context.Context, req UpdateSubjectRequest) (*models.Subject, error) {
	logger := s.logger.With(zap.String("method", "Update"), zap.String("id", req.SubjectID.String()))

	if req.SubjectID == uuid.Nil {
		return nil, fmt.Errorf("%w: subject_id is required", ErrInvalidInput)
	}
	if strings.TrimSpace(req.Code) == "" {
		return nil, fmt.Errorf("%w: code is required", ErrInvalidInput)
	}
	if strings.TrimSpace(req.Name) == "" {
		return nil, fmt.Errorf("%w: name is required", ErrInvalidInput)
	}
	if req.Credits < 0 {
		return nil, fmt.Errorf("%w: credits cannot be negative", ErrInvalidInput)
	}

	tx, err := s.pgClient.BeginTx(ctx, nil)
	if err != nil {
		logger.Error("failed to begin transaction", zap.Error(err))
		return nil, fmt.Errorf("begin tx: %w", err)
	}
	defer tx.Rollback()

	subject, err := s.repo.GetByIDForUpdate(ctx, tx, req.SubjectID)
	if err != nil {
		logger.Error("failed to get subject for update", zap.Error(err))
		return nil, err
	}
	if subject == nil {
		logger.Warn("subject not found")
		return nil, fmt.Errorf("%w: subject %s", ErrNotFound, req.SubjectID)
	}

	// Capture old state for event
	oldSubject := *subject

	// If code changed, check uniqueness
	if req.Code != subject.Code {
		exists, err := s.repo.Exists(ctx, tx, subject.CompanyID, req.Code)
		if err != nil {
			logger.Error("failed to check code uniqueness", zap.Error(err))
			return nil, err
		}
		if exists {
			logger.Warn("new code already exists", zap.String("new_code", req.Code))
			return nil, fmt.Errorf("%w: subject code %s already exists", ErrDuplicate, req.Code)
		}
	}

	subject.Code = req.Code
	subject.Name = req.Name
	subject.Description = req.Description
	subject.Credits = req.Credits
	subject.IsActive = req.IsActive
	subject.UpdatedBy = req.UpdatedBy

	if err := s.repo.Update(ctx, tx, subject); err != nil {
		logger.Error("failed to update subject", zap.Error(err))
		return nil, err
	}

	if err := tx.Commit(); err != nil {
		logger.Error("failed to commit transaction", zap.Error(err))
		return nil, fmt.Errorf("commit tx: %w", err)
	}

	logger.Info("subject updated")

	// Publish event
	if err := s.eventPublisher.Publish(ctx, Event{
		Type: EventSubjectUpdated,
		Data: map[string]interface{}{
			"old": oldSubject,
			"new": subject,
		},
	}); err != nil {
		logger.Error("failed to publish subject.updated event", zap.Error(err))
	}

	return subject, nil
}

// Activate sets is_active to true.
func (s *subjectService) Activate(ctx context.Context, id uuid.UUID, updatedBy *uuid.UUID) error {
	logger := s.logger.With(zap.String("method", "Activate"), zap.String("id", id.String()))

	tx, err := s.pgClient.BeginTx(ctx, nil)
	if err != nil {
		logger.Error("failed to begin transaction", zap.Error(err))
		return fmt.Errorf("begin tx: %w", err)
	}
	defer tx.Rollback()

	if err := s.repo.Activate(ctx, tx, id, updatedBy); err != nil {
		logger.Error("failed to activate subject", zap.Error(err))
		return err
	}

	if err := tx.Commit(); err != nil {
		logger.Error("failed to commit transaction", zap.Error(err))
		return fmt.Errorf("commit tx: %w", err)
	}

	logger.Info("subject activated")

	// Optionally publish an event
	// We'll treat activation as an update; can add EventSubjectActivated if needed
	// For now, skip.

	return nil
}

// Deactivate sets is_active to false.
func (s *subjectService) Deactivate(ctx context.Context, id uuid.UUID, updatedBy *uuid.UUID) error {
	logger := s.logger.With(zap.String("method", "Deactivate"), zap.String("id", id.String()))

	tx, err := s.pgClient.BeginTx(ctx, nil)
	if err != nil {
		logger.Error("failed to begin transaction", zap.Error(err))
		return fmt.Errorf("begin tx: %w", err)
	}
	defer tx.Rollback()

	if err := s.repo.Deactivate(ctx, tx, id, updatedBy); err != nil {
		logger.Error("failed to deactivate subject", zap.Error(err))
		return err
	}

	if err := tx.Commit(); err != nil {
		logger.Error("failed to commit transaction", zap.Error(err))
		return fmt.Errorf("commit tx: %w", err)
	}

	logger.Info("subject deactivated")
	return nil
}

// Delete soft-deletes a subject after ensuring no active dependencies.
func (s *subjectService) Delete(ctx context.Context, id uuid.UUID, deletedBy *uuid.UUID) error {
	logger := s.logger.With(zap.String("method", "Delete"), zap.String("id", id.String()))

	tx, err := s.pgClient.BeginTx(ctx, nil)
	if err != nil {
		logger.Error("failed to begin transaction", zap.Error(err))
		return fmt.Errorf("begin tx: %w", err)
	}
	defer tx.Rollback()

	// Check if the subject is assigned to any course
	assigned, err := s.repo.IsAssignedToAnyCourse(ctx, tx, id)
	if err != nil {
		logger.Error("failed to check course assignments", zap.Error(err))
		return err
	}
	if assigned {
		logger.Warn("cannot delete subject with existing course assignments")
		return fmt.Errorf("%w: subject is assigned to one or more courses", ErrInvalidInput)
	}

	if err := s.repo.Delete(ctx, tx, id, deletedBy); err != nil {
		logger.Error("failed to delete subject", zap.Error(err))
		return err
	}

	if err := tx.Commit(); err != nil {
		logger.Error("failed to commit transaction", zap.Error(err))
		return fmt.Errorf("commit tx: %w", err)
	}

	logger.Info("subject deleted")

	// Publish event
	if err := s.eventPublisher.Publish(ctx, Event{
		Type: EventSubjectDeleted,
		Data: map[string]interface{}{
			"subject_id": id,
			"deleted_by": deletedBy,
		},
	}); err != nil {
		logger.Error("failed to publish subject.deleted event", zap.Error(err))
	}

	return nil
}

// ValidateUniqueCode checks if a subject code is unique for the company.
func (s *subjectService) ValidateUniqueCode(ctx context.Context, companyID uuid.UUID, code string) error {
	logger := s.logger.With(zap.String("method", "ValidateUniqueCode"), zap.String("company_id", companyID.String()), zap.String("code", code))

	exists, err := s.repo.Exists(ctx, s.pgClient.DB, companyID, code)
	if err != nil {
		logger.Error("failed to check existence", zap.Error(err))
		return err
	}
	if exists {
		logger.Warn("code already exists")
		return fmt.Errorf("%w: code %s", ErrDuplicate, code)
	}
	return nil
}

// validateInput performs basic validation on create/upsert requests.
func (s *subjectService) validateInput(req CreateSubjectRequest) error {
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

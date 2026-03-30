package service

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/lib/pq"
	"go.uber.org/zap"

	"auth-service/internal/academics/models"
	"auth-service/internal/academics/repository"
	"auth-service/internal/client"
)

// ---------------------------------------------------------------------
// Timeout constants
// ---------------------------------------------------------------------
const (
	writeTimeout  = 5 * time.Second
	readTimeout   = 2 * time.Second
	deleteTimeout = 5 * time.Second
)

// ---------------------------------------------------------------------
// SubjectService interface
// ---------------------------------------------------------------------
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

// ---------------------------------------------------------------------
// subjectService struct
// ---------------------------------------------------------------------
type subjectService struct {
	repo        repository.SubjectRepository
	auditLogger AuditLogger
	outboxStore OutboxStore
	pgClient    *client.PostgresClient
	logger      *zap.Logger
}

// ---------------------------------------------------------------------
// Constructor
// ---------------------------------------------------------------------
func NewSubjectService(
	repo repository.SubjectRepository,
	auditLogger AuditLogger,
	outboxStore OutboxStore,
	pgClient *client.PostgresClient,
	logger *zap.Logger,
) SubjectService {
	return &subjectService{
		repo:        repo,
		auditLogger: auditLogger,
		outboxStore: outboxStore,
		pgClient:    pgClient,
		logger:      logger.Named("subject_service"),
	}
}

// ---------------------------------------------------------------------
// Validation helper
// ---------------------------------------------------------------------
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

// ---------------------------------------------------------------------
// Create
// ---------------------------------------------------------------------
func (s *subjectService) Create(ctx context.Context, req CreateSubjectRequest) (*models.Subject, error) {
	ctx, cancel := context.WithTimeout(ctx, writeTimeout)
	defer cancel()

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

	// Check uniqueness (application‑level check, but DB constraint is the final guard)
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
		// Check for unique violation from DB (e.g., if race condition bypassed application check)
		if pqErr, ok := err.(*pq.Error); ok && pqErr.Code == "23505" { // unique_violation
			logger.Warn("duplicate key violation", zap.Error(err))
			return nil, fmt.Errorf("%w: subject code %s already exists", ErrDuplicate, req.Code)
		}
		logger.Error("failed to create subject", zap.Error(err))
		return nil, err
	}

	// Audit log (non‑critical – we log error but don’t fail the operation)
	if err := s.auditLogger.Log(ctx, tx, "SUBJECT_CREATE", subject.SubjectID, nil, subject, req.CreatedBy); err != nil {
		logger.Error("audit log failed", zap.Error(err))
	}

	// Outbox event
	if err := s.outboxStore.Store(ctx, tx, string(EventSubjectCreated), subject); err != nil {
		logger.Error("failed to store outbox event", zap.Error(err))
		return nil, fmt.Errorf("store outbox event: %w", err)
	}

	if err := tx.Commit(); err != nil {
		logger.Error("failed to commit transaction", zap.Error(err))
		return nil, fmt.Errorf("commit tx: %w", err)
	}

	logger.Info("subject created", zap.String("subject_id", subject.SubjectID.String()))
	return subject, nil
}

// ---------------------------------------------------------------------
// BulkCreate
// ---------------------------------------------------------------------
func (s *subjectService) BulkCreate(ctx context.Context, reqs []CreateSubjectRequest) ([]*models.Subject, error) {
	if len(reqs) == 0 {
		return nil, nil
	}
	ctx, cancel := context.WithTimeout(ctx, writeTimeout)
	defer cancel()

	logger := s.logger.With(zap.String("method", "BulkCreate"), zap.Int("count", len(reqs)))

	// Basic input validation and collect unique keys per company
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

	// Pre‑load existing subjects for each company to reduce DB duplicate checks
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

	// Build subjects, checking duplicates against existing data
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

	// Execute bulk insert – DB unique constraint will catch any race condition
	if err := s.repo.BulkCreate(ctx, tx, subjects); err != nil {
		if pqErr, ok := err.(*pq.Error); ok && pqErr.Code == "23505" {
			logger.Warn("duplicate key violation during bulk create", zap.Error(err))
			return nil, fmt.Errorf("%w: one or more subject codes already exist", ErrDuplicate)
		}
		logger.Error("failed to bulk create", zap.Error(err))
		return nil, err
	}

	// Audit and outbox for each created subject
	for _, subj := range subjects {
		if err := s.auditLogger.Log(ctx, tx, "SUBJECT_BULK_CREATE", subj.SubjectID, nil, subj, subj.CreatedBy); err != nil {
			logger.Error("audit log failed", zap.String("subject_id", subj.SubjectID.String()), zap.Error(err))
		}
		if err := s.outboxStore.Store(ctx, tx, string(EventSubjectCreated), subj); err != nil {
			logger.Error("failed to store outbox event", zap.String("subject_id", subj.SubjectID.String()), zap.Error(err))
			return nil, fmt.Errorf("store outbox event for subject %s: %w", subj.SubjectID, err)
		}
	}

	if err := tx.Commit(); err != nil {
		logger.Error("failed to commit transaction", zap.Error(err))
		return nil, fmt.Errorf("commit tx: %w", err)
	}

	logger.Info("bulk created subjects", zap.Int("count", len(subjects)))
	return subjects, nil
}

// ---------------------------------------------------------------------
// Upsert (with correct event type)
// ---------------------------------------------------------------------
func (s *subjectService) Upsert(ctx context.Context, req CreateSubjectRequest) (*models.Subject, error) {
	ctx, cancel := context.WithTimeout(ctx, writeTimeout)
	defer cancel()

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

	// Upsert returns true if a new record was inserted
	inserted, err := s.repo.Upsert(ctx, tx, subject)
	if err != nil {
		if pqErr, ok := err.(*pq.Error); ok && pqErr.Code == "23505" {
			logger.Warn("duplicate key violation", zap.Error(err))
			return nil, fmt.Errorf("%w: subject code %s already exists", ErrDuplicate, req.Code)
		}
		logger.Error("failed to upsert subject", zap.Error(err))
		return nil, err
	}

	// Choose correct event type
	eventType := EventSubjectUpdated
	if inserted {
		eventType = EventSubjectCreated
	}

	// Audit log (treat upsert as create/update accordingly)
	auditAction := "SUBJECT_UPSERT"
	if inserted {
		auditAction = "SUBJECT_CREATE"
	}
	if err := s.auditLogger.Log(ctx, tx, auditAction, subject.SubjectID, nil, subject, req.UpdatedBy); err != nil {
		logger.Error("audit log failed", zap.Error(err))
	}
	// Outbox event
	if err := s.outboxStore.Store(ctx, tx, string(eventType), subject); err != nil {
		logger.Error("failed to store outbox event", zap.Error(err))
		return nil, fmt.Errorf("store outbox event: %w", err)
	}

	if err := tx.Commit(); err != nil {
		logger.Error("failed to commit transaction", zap.Error(err))
		return nil, fmt.Errorf("commit tx: %w", err)
	}

	logger.Info("subject upserted", zap.String("subject_id", subject.SubjectID.String()), zap.Bool("inserted", inserted))
	return subject, nil
}

// ---------------------------------------------------------------------
// Read‑only operations (with timeouts)
// ---------------------------------------------------------------------
func (s *subjectService) GetByID(ctx context.Context, id uuid.UUID) (*models.Subject, error) {
	ctx, cancel := context.WithTimeout(ctx, readTimeout)
	defer cancel()
	return s.repo.GetByID(ctx, s.pgClient.DB, id)
}

func (s *subjectService) GetByCode(ctx context.Context, companyID uuid.UUID, code string) (*models.Subject, error) {
	ctx, cancel := context.WithTimeout(ctx, readTimeout)
	defer cancel()
	return s.repo.GetByCode(ctx, s.pgClient.DB, companyID, code)
}

func (s *subjectService) List(ctx context.Context, filter repository.SubjectFilter, p repository.Pagination, srt repository.Sort) ([]*models.Subject, error) {
	ctx, cancel := context.WithTimeout(ctx, readTimeout)
	defer cancel()
	return s.repo.List(ctx, s.pgClient.DB, filter, p, srt)
}

func (s *subjectService) ListActive(ctx context.Context, companyID uuid.UUID) ([]*models.Subject, error) {
	ctx, cancel := context.WithTimeout(ctx, readTimeout)
	defer cancel()
	return s.repo.ListActive(ctx, s.pgClient.DB, companyID)
}

func (s *subjectService) Count(ctx context.Context, filter repository.SubjectFilter) (int64, error) {
	ctx, cancel := context.WithTimeout(ctx, readTimeout)
	defer cancel()
	return s.repo.Count(ctx, s.pgClient.DB, filter)
}

func (s *subjectService) Exists(ctx context.Context, companyID uuid.UUID, code string) (bool, error) {
	ctx, cancel := context.WithTimeout(ctx, readTimeout)
	defer cancel()
	return s.repo.Exists(ctx, s.pgClient.DB, companyID, code)
}

// ---------------------------------------------------------------------
// Update (with locking, audit, outbox)
// ---------------------------------------------------------------------
func (s *subjectService) Update(ctx context.Context, req UpdateSubjectRequest) (*models.Subject, error) {
	ctx, cancel := context.WithTimeout(ctx, writeTimeout)
	defer cancel()

	logger := s.logger.With(zap.String("method", "Update"), zap.String("subject_id", req.SubjectID.String()))

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

	// Audit
	if err := s.auditLogger.Log(ctx, tx, "SUBJECT_UPDATE", req.SubjectID, &oldSubject, subject, req.UpdatedBy); err != nil {
		logger.Error("audit log failed", zap.Error(err))
	}
	// Outbox
	if err := s.outboxStore.Store(ctx, tx, string(EventSubjectUpdated), map[string]interface{}{
		"old": oldSubject,
		"new": subject,
	}); err != nil {
		logger.Error("failed to store outbox event", zap.Error(err))
		return nil, fmt.Errorf("store outbox event: %w", err)
	}

	if err := tx.Commit(); err != nil {
		logger.Error("failed to commit transaction", zap.Error(err))
		return nil, fmt.Errorf("commit tx: %w", err)
	}

	logger.Info("subject updated")
	return subject, nil
}

// ---------------------------------------------------------------------
// Activate / Deactivate
// ---------------------------------------------------------------------
func (s *subjectService) Activate(ctx context.Context, id uuid.UUID, updatedBy *uuid.UUID) error {
	return s.toggleActive(ctx, id, updatedBy, true)
}

func (s *subjectService) Deactivate(ctx context.Context, id uuid.UUID, updatedBy *uuid.UUID) error {
	return s.toggleActive(ctx, id, updatedBy, false)
}

func (s *subjectService) toggleActive(ctx context.Context, id uuid.UUID, updatedBy *uuid.UUID, active bool) error {
	ctx, cancel := context.WithTimeout(ctx, writeTimeout)
	defer cancel()

	logger := s.logger.With(
		zap.String("method", "toggleActive"),
		zap.String("subject_id", id.String()),
		zap.Bool("active", active),
	)

	tx, err := s.pgClient.BeginTx(ctx, nil)
	if err != nil {
		logger.Error("failed to begin transaction", zap.Error(err))
		return fmt.Errorf("begin tx: %w", err)
	}
	defer tx.Rollback()

	subject, err := s.repo.GetByIDForUpdate(ctx, tx, id)
	if err != nil {
		return err
	}
	if subject == nil {
		return fmt.Errorf("%w: subject %s", ErrNotFound, id)
	}
	oldActive := subject.IsActive

	var updateErr error
	if active {
		updateErr = s.repo.Activate(ctx, tx, id, updatedBy)
	} else {
		updateErr = s.repo.Deactivate(ctx, tx, id, updatedBy)
	}
	if updateErr != nil {
		logger.Error("failed to toggle active", zap.Error(updateErr))
		return updateErr
	}

	// Audit
	auditAction := "SUBJECT_ACTIVATE"
	if !active {
		auditAction = "SUBJECT_DEACTIVATE"
	}
	if err := s.auditLogger.Log(ctx, tx, auditAction, id, map[string]interface{}{"is_active": oldActive}, map[string]interface{}{"is_active": active}, updatedBy); err != nil {
		logger.Error("audit log failed", zap.Error(err))
	}
	// Outbox
	if err := s.outboxStore.Store(ctx, tx, string(EventSubjectUpdated), map[string]interface{}{
		"subject_id": id,
		"old":        map[string]interface{}{"is_active": oldActive},
		"new":        map[string]interface{}{"is_active": active},
	}); err != nil {
		logger.Error("failed to store outbox event", zap.Error(err))
		return fmt.Errorf("store outbox event: %w", err)
	}

	if err := tx.Commit(); err != nil {
		logger.Error("failed to commit transaction", zap.Error(err))
		return fmt.Errorf("commit tx: %w", err)
	}

	logger.Info("subject status toggled")
	return nil
}

// ---------------------------------------------------------------------
// Delete (idempotent, with assignment check)
// ---------------------------------------------------------------------
func (s *subjectService) Delete(ctx context.Context, id uuid.UUID, deletedBy *uuid.UUID) error {
	ctx, cancel := context.WithTimeout(ctx, deleteTimeout)
	defer cancel()

	logger := s.logger.With(zap.String("method", "Delete"), zap.String("subject_id", id.String()))

	tx, err := s.pgClient.BeginTx(ctx, nil)
	if err != nil {
		logger.Error("failed to begin transaction", zap.Error(err))
		return fmt.Errorf("begin tx: %w", err)
	}
	defer tx.Rollback()

	// Lock the subject
	subject, err := s.repo.GetByIDForUpdate(ctx, tx, id)
	if err != nil {
		return err
	}
	if subject == nil {
		// Idempotent: already deleted
		logger.Info("subject already deleted (idempotent)")
		return nil
	}

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

	// Audit
	if err := s.auditLogger.Log(ctx, tx, "SUBJECT_DELETE", id, subject, nil, deletedBy); err != nil {
		logger.Error("audit log failed", zap.Error(err))
	}
	// Outbox
	if err := s.outboxStore.Store(ctx, tx, string(EventSubjectDeleted), map[string]interface{}{
		"subject_id": id,
		"deleted_by": deletedBy,
	}); err != nil {
		logger.Error("failed to store outbox event", zap.Error(err))
		return fmt.Errorf("store outbox event: %w", err)
	}

	if err := tx.Commit(); err != nil {
		logger.Error("failed to commit transaction", zap.Error(err))
		return fmt.Errorf("commit tx: %w", err)
	}

	logger.Info("subject deleted")
	return nil
}

// ---------------------------------------------------------------------
// ValidateUniqueCode
// ---------------------------------------------------------------------
func (s *subjectService) ValidateUniqueCode(ctx context.Context, companyID uuid.UUID, code string) error {
	ctx, cancel := context.WithTimeout(ctx, readTimeout)
	defer cancel()

	exists, err := s.repo.Exists(ctx, s.pgClient.DB, companyID, code)
	if err != nil {
		return err
	}
	if exists {
		return fmt.Errorf("%w: code %s", ErrDuplicate, code)
	}
	return nil
}

package service

import (
	"context"
	"fmt"
	"time"

	"github.com/google/uuid"
	"go.uber.org/zap"

	"auth-service/internal/academics/models"
	"auth-service/internal/academics/repository"
	"auth-service/internal/client"
)

type AcademicYearService interface {
	Create(ctx context.Context, req CreateAcademicYearRequest) (*models.AcademicYear, error)
	BulkCreate(ctx context.Context, req []CreateAcademicYearRequest) ([]*models.AcademicYear, error)
	Upsert(ctx context.Context, req CreateAcademicYearRequest) (*models.AcademicYear, error)

	GetByID(ctx context.Context, id uuid.UUID) (*models.AcademicYear, error)
	GetByName(ctx context.Context, companyID uuid.UUID, name string) (*models.AcademicYear, error)
	GetCurrent(ctx context.Context, companyID uuid.UUID) (*models.AcademicYear, error)

	List(ctx context.Context, filter repository.AcademicYearFilter, p repository.Pagination, s repository.Sort) ([]*models.AcademicYear, error)
	ListByCompany(ctx context.Context, companyID uuid.UUID) ([]*models.AcademicYear, error)
	Count(ctx context.Context, filter repository.AcademicYearFilter) (int64, error)

	Exists(ctx context.Context, companyID uuid.UUID, name string) (bool, error)

	Update(ctx context.Context, req UpdateAcademicYearRequest) (*models.AcademicYear, error)
	UpdateDates(ctx context.Context, id uuid.UUID, start, end time.Time, updatedBy *uuid.UUID) error

	SetCurrent(ctx context.Context, companyID, academicYearID uuid.UUID, updatedBy *uuid.UUID) error

	Delete(ctx context.Context, id uuid.UUID, deletedBy *uuid.UUID) error

	ValidateOverlap(ctx context.Context, companyID uuid.UUID, start, end time.Time) error
}

type academicYearService struct {
	repo           repository.AcademicYearRepository
	pgClient       *client.PostgresClient
	logger         *zap.Logger
	eventPublisher EventPublisher
}

func NewAcademicYearService(
	repo repository.AcademicYearRepository,
	pgClient *client.PostgresClient,
	logger *zap.Logger,
	eventPublisher EventPublisher,
) AcademicYearService {
	return &academicYearService{
		repo:           repo,
		pgClient:       pgClient,
		logger:         logger.Named("academic_year_service"),
		eventPublisher: eventPublisher,
	}
}

// Create creates a new academic year.
func (s *academicYearService) Create(ctx context.Context, req CreateAcademicYearRequest) (*models.AcademicYear, error) {
	logger := s.logger.With(
		zap.String("method", "Create"),
		zap.String("company_id", req.CompanyID.String()),
		zap.String("name", req.Name),
	)

	if err := s.validateInput(req.CompanyID, req.Name, req.StartDate, req.EndDate); err != nil {
		return nil, err
	}

	tx, err := s.pgClient.BeginTx(ctx, nil)
	if err != nil {
		return nil, fmt.Errorf("begin tx: %w", err)
	}
	defer tx.Rollback()

	overlap, err := s.repo.CheckOverlap(ctx, tx, req.CompanyID, req.StartDate, req.EndDate, uuid.Nil)
	if err != nil {
		return nil, fmt.Errorf("overlap check: %w", err)
	}
	if overlap {
		return nil, fmt.Errorf("%w: academic year dates overlap with an existing year", ErrOverlap)
	}

	exists, err := s.repo.Exists(ctx, tx, req.CompanyID, req.Name)
	if err != nil {
		return nil, fmt.Errorf("check existence: %w", err)
	}
	if exists {
		return nil, fmt.Errorf("%w: academic year name %s already exists", ErrDuplicate, req.Name)
	}

	ay := &models.AcademicYear{
		CompanyID: req.CompanyID,
		Name:      req.Name,
		StartDate: req.StartDate,
		EndDate:   req.EndDate,
		IsCurrent: req.IsCurrent,
		CreatedBy: req.CreatedBy,
		UpdatedBy: req.UpdatedBy,
	}

	if err := s.repo.Create(ctx, tx, ay); err != nil {
		return nil, err
	}

	if err := tx.Commit(); err != nil {
		return nil, fmt.Errorf("commit tx: %w", err)
	}

	logger.Info("academic year created", zap.String("id", ay.AcademicYearID.String()))

	// Emit event
	if err := s.eventPublisher.Publish(ctx, Event{
		Type: EventAcademicYearCreated,
		Data: ay,
	}); err != nil {
		logger.Error("failed to publish academic_year.created event", zap.Error(err))
	}

	return ay, nil
}

// BulkCreate creates multiple academic years in a single transaction.
func (s *academicYearService) BulkCreate(ctx context.Context, reqs []CreateAcademicYearRequest) ([]*models.AcademicYear, error) {
	if len(reqs) == 0 {
		return nil, nil
	}

	logger := s.logger.With(zap.String("method", "BulkCreate"), zap.Int("batch_size", len(reqs)))

	tx, err := s.pgClient.BeginTx(ctx, nil)
	if err != nil {
		return nil, fmt.Errorf("begin tx: %w", err)
	}
	defer tx.Rollback()

	companyIDs := make(map[uuid.UUID]struct{})
	for _, req := range reqs {
		companyIDs[req.CompanyID] = struct{}{}
	}
	existingByCompany := make(map[uuid.UUID][]*models.AcademicYear)
	for cid := range companyIDs {
		years, err := s.repo.List(ctx, tx, repository.AcademicYearFilter{CompanyID: cid}, repository.Pagination{Limit: 1000}, repository.Sort{})
		if err != nil {
			return nil, fmt.Errorf("pre‑load years for company %s: %w", cid, err)
		}
		existingByCompany[cid] = years
	}

	years := make([]*models.AcademicYear, 0, len(reqs))
	batchByName := make(map[uuid.UUID]map[string]bool)

	for i, req := range reqs {
		if err := s.validateInput(req.CompanyID, req.Name, req.StartDate, req.EndDate); err != nil {
			return nil, fmt.Errorf("item %d: %w", i, err)
		}

		if batchByName[req.CompanyID] == nil {
			batchByName[req.CompanyID] = make(map[string]bool)
		}
		if batchByName[req.CompanyID][req.Name] {
			return nil, fmt.Errorf("item %d: %w: duplicate name %s in batch", i, ErrDuplicate, req.Name)
		}
		batchByName[req.CompanyID][req.Name] = true

		existing := existingByCompany[req.CompanyID]
		tempExisting := make([]*models.AcademicYear, len(existing)+len(years))
		copy(tempExisting, existing)
		for _, ay := range years {
			if ay.CompanyID == req.CompanyID {
				tempExisting = append(tempExisting, ay)
			}
		}
		if err := s.checkOverlapInMemory(tempExisting, req.StartDate, req.EndDate, uuid.Nil); err != nil {
			return nil, fmt.Errorf("item %d: %w", i, err)
		}

		for _, ay := range existing {
			if ay.Name == req.Name {
				return nil, fmt.Errorf("item %d: %w: name %s already exists", i, ErrDuplicate, req.Name)
			}
		}

		ay := &models.AcademicYear{
			CompanyID: req.CompanyID,
			Name:      req.Name,
			StartDate: req.StartDate,
			EndDate:   req.EndDate,
			IsCurrent: req.IsCurrent,
			CreatedBy: req.CreatedBy,
			UpdatedBy: req.UpdatedBy,
		}
		years = append(years, ay)
	}

	if err := s.repo.BulkCreate(ctx, tx, years); err != nil {
		return nil, err
	}

	if err := tx.Commit(); err != nil {
		return nil, fmt.Errorf("commit tx: %w", err)
	}

	logger.Info("bulk created academic years", zap.Int("count", len(years)))

	// Emit events for each created year
	for _, ay := range years {
		if err := s.eventPublisher.Publish(ctx, Event{
			Type: EventAcademicYearCreated,
			Data: ay,
		}); err != nil {
			logger.Error("failed to publish academic_year.created event", zap.Error(err), zap.String("id", ay.AcademicYearID.String()))
		}
	}

	return years, nil
}

// Upsert creates or updates an academic year based on unique (company_id, name).
func (s *academicYearService) Upsert(ctx context.Context, req CreateAcademicYearRequest) (*models.AcademicYear, error) {
	logger := s.logger.With(
		zap.String("method", "Upsert"),
		zap.String("company_id", req.CompanyID.String()),
		zap.String("name", req.Name),
	)

	if err := s.validateInput(req.CompanyID, req.Name, req.StartDate, req.EndDate); err != nil {
		return nil, err
	}

	tx, err := s.pgClient.BeginTx(ctx, nil)
	if err != nil {
		return nil, fmt.Errorf("begin tx: %w", err)
	}
	defer tx.Rollback()

	existing, _ := s.repo.GetByName(ctx, tx, req.CompanyID, req.Name)
	excludeID := uuid.Nil
	if existing != nil {
		excludeID = existing.AcademicYearID
	}

	overlap, err := s.repo.CheckOverlap(ctx, tx, req.CompanyID, req.StartDate, req.EndDate, excludeID)
	if err != nil {
		return nil, fmt.Errorf("overlap check: %w", err)
	}
	if overlap {
		return nil, fmt.Errorf("%w: academic year dates overlap with an existing year", ErrOverlap)
	}

	ay := &models.AcademicYear{
		CompanyID: req.CompanyID,
		Name:      req.Name,
		StartDate: req.StartDate,
		EndDate:   req.EndDate,
		IsCurrent: req.IsCurrent,
		CreatedBy: req.CreatedBy,
		UpdatedBy: req.UpdatedBy,
	}

	var eventType EventType
	if existing == nil {
		eventType = EventAcademicYearCreated
	} else {
		eventType = EventAcademicYearUpdated
	}

	if err := s.repo.Upsert(ctx, tx, ay); err != nil {
		return nil, err
	}

	if err := tx.Commit(); err != nil {
		return nil, fmt.Errorf("commit tx: %w", err)
	}

	logger.Info("academic year upserted", zap.String("id", ay.AcademicYearID.String()))

	// Emit event
	if err := s.eventPublisher.Publish(ctx, Event{
		Type: eventType,
		Data: ay,
	}); err != nil {
		logger.Error("failed to publish academic_year event", zap.Error(err))
	}

	return ay, nil
}

// GetByID retrieves an academic year by ID.
func (s *academicYearService) GetByID(ctx context.Context, id uuid.UUID) (*models.AcademicYear, error) {
	logger := s.logger.With(zap.String("method", "GetByID"), zap.String("id", id.String()))

	ay, err := s.repo.GetByID(ctx, s.pgClient.DB, id)
	if err != nil {
		return nil, err
	}
	if ay == nil {
		return nil, fmt.Errorf("%w: academic year %s", ErrNotFound, id)
	}
	logger.Debug("academic year retrieved")
	return ay, nil
}

// GetByName retrieves an academic year by company and name.
func (s *academicYearService) GetByName(ctx context.Context, companyID uuid.UUID, name string) (*models.AcademicYear, error) {
	logger := s.logger.With(zap.String("method", "GetByName"), zap.String("company_id", companyID.String()), zap.String("name", name))

	ay, err := s.repo.GetByName(ctx, s.pgClient.DB, companyID, name)
	if err != nil {
		return nil, err
	}
	if ay == nil {
		return nil, fmt.Errorf("%w: academic year %s for company %s", ErrNotFound, name, companyID)
	}
	logger.Debug("academic year retrieved")
	return ay, nil
}

// GetCurrent retrieves the current academic year for a company.
func (s *academicYearService) GetCurrent(ctx context.Context, companyID uuid.UUID) (*models.AcademicYear, error) {
	logger := s.logger.With(zap.String("method", "GetCurrent"), zap.String("company_id", companyID.String()))

	ay, err := s.repo.GetCurrent(ctx, s.pgClient.DB, companyID)
	if err != nil {
		return nil, err
	}
	if ay == nil {
		return nil, fmt.Errorf("%w: no current academic year for company %s", ErrNotFound, companyID)
	}
	logger.Debug("current academic year retrieved")
	return ay, nil
}

// List returns filtered academic years.
func (s *academicYearService) List(ctx context.Context, filter repository.AcademicYearFilter, p repository.Pagination, srt repository.Sort) ([]*models.AcademicYear, error) {
	logger := s.logger.With(zap.String("method", "List"))
	logger.Debug("listing academic years")
	return s.repo.List(ctx, s.pgClient.DB, filter, p, srt)
}

// ListByCompany returns all academic years for a company.
func (s *academicYearService) ListByCompany(ctx context.Context, companyID uuid.UUID) ([]*models.AcademicYear, error) {
	logger := s.logger.With(zap.String("method", "ListByCompany"), zap.String("company_id", companyID.String()))
	logger.Debug("listing academic years for company")
	return s.repo.ListByCompany(ctx, s.pgClient.DB, companyID)
}

// Count returns the count of academic years matching the filter.
func (s *academicYearService) Count(ctx context.Context, filter repository.AcademicYearFilter) (int64, error) {
	logger := s.logger.With(zap.String("method", "Count"))
	logger.Debug("counting academic years")
	return s.repo.Count(ctx, s.pgClient.DB, filter)
}

// Exists checks if an academic year with given company and name exists.
func (s *academicYearService) Exists(ctx context.Context, companyID uuid.UUID, name string) (bool, error) {
	logger := s.logger.With(zap.String("method", "Exists"), zap.String("company_id", companyID.String()), zap.String("name", name))
	logger.Debug("checking existence")
	return s.repo.Exists(ctx, s.pgClient.DB, companyID, name)
}

// Update modifies an existing academic year.
func (s *academicYearService) Update(ctx context.Context, req UpdateAcademicYearRequest) (*models.AcademicYear, error) {
	logger := s.logger.With(zap.String("method", "Update"), zap.String("id", req.AcademicYearID.String()))

	tx, err := s.pgClient.BeginTx(ctx, nil)
	if err != nil {
		return nil, fmt.Errorf("begin tx: %w", err)
	}
	defer tx.Rollback()

	existing, err := s.repo.GetByIDForUpdate(ctx, tx, req.AcademicYearID)
	if err != nil {
		return nil, err
	}
	if existing == nil {
		return nil, fmt.Errorf("%w: academic year %s", ErrNotFound, req.AcademicYearID)
	}

	overlap, err := s.repo.CheckOverlap(ctx, tx, existing.CompanyID, req.StartDate, req.EndDate, existing.AcademicYearID)
	if err != nil {
		return nil, fmt.Errorf("overlap check: %w", err)
	}
	if overlap {
		return nil, fmt.Errorf("%w: academic year dates overlap with an existing year", ErrOverlap)
	}

	if req.Name != existing.Name {
		exists, err := s.repo.Exists(ctx, tx, existing.CompanyID, req.Name)
		if err != nil {
			return nil, err
		}
		if exists {
			return nil, fmt.Errorf("%w: academic year name %s already exists", ErrDuplicate, req.Name)
		}
	}

	existing.Name = req.Name
	existing.StartDate = req.StartDate
	existing.EndDate = req.EndDate
	existing.IsCurrent = req.IsCurrent
	existing.UpdatedBy = req.UpdatedBy

	if err := s.repo.Update(ctx, tx, existing); err != nil {
		return nil, err
	}

	if err := tx.Commit(); err != nil {
		return nil, fmt.Errorf("commit tx: %w", err)
	}

	logger.Info("academic year updated")

	// Emit event
	if err := s.eventPublisher.Publish(ctx, Event{
		Type: EventAcademicYearUpdated,
		Data: existing,
	}); err != nil {
		logger.Error("failed to publish academic_year.updated event", zap.Error(err))
	}

	return existing, nil
}

// UpdateDates updates only the start and end dates of an academic year.
func (s *academicYearService) UpdateDates(ctx context.Context, id uuid.UUID, start, end time.Time, updatedBy *uuid.UUID) error {
	logger := s.logger.With(zap.String("method", "UpdateDates"), zap.String("id", id.String()))

	tx, err := s.pgClient.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("begin tx: %w", err)
	}
	defer tx.Rollback()

	ay, err := s.repo.GetByIDForUpdate(ctx, tx, id)
	if err != nil {
		return err
	}
	if ay == nil {
		return fmt.Errorf("%w: academic year %s", ErrNotFound, id)
	}

	overlap, err := s.repo.CheckOverlap(ctx, tx, ay.CompanyID, start, end, id)
	if err != nil {
		return fmt.Errorf("overlap check: %w", err)
	}
	if overlap {
		return fmt.Errorf("%w: updated dates overlap with an existing year", ErrOverlap)
	}

	if err := s.repo.UpdateDates(ctx, tx, id, start, end, updatedBy); err != nil {
		return err
	}

	if err := tx.Commit(); err != nil {
		return fmt.Errorf("commit tx: %w", err)
	}

	logger.Info("academic year dates updated")

	// Emit event (optional, you can also treat as update)
	updatedAy, _ := s.repo.GetByID(ctx, s.pgClient.DB, id) // fetch fresh for event data
	if updatedAy != nil {
		if err := s.eventPublisher.Publish(ctx, Event{
			Type: EventAcademicYearUpdated,
			Data: updatedAy,
		}); err != nil {
			logger.Error("failed to publish academic_year.updated event", zap.Error(err))
		}
	}

	return nil
}

// SetCurrent marks the given academic year as current and unsets all others for the company.
func (s *academicYearService) SetCurrent(ctx context.Context, companyID, academicYearID uuid.UUID, updatedBy *uuid.UUID) error {
	logger := s.logger.With(zap.String("method", "SetCurrent"), zap.String("company_id", companyID.String()), zap.String("id", academicYearID.String()))

	tx, err := s.pgClient.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("begin tx: %w", err)
	}
	defer tx.Rollback()

	if err := s.repo.SetCurrent(ctx, tx, companyID, academicYearID, updatedBy); err != nil {
		return err
	}

	if err := tx.Commit(); err != nil {
		return fmt.Errorf("commit tx: %w", err)
	}

	logger.Info("academic year set as current")

	// Emit event
	ay, _ := s.repo.GetByID(ctx, s.pgClient.DB, academicYearID)
	if ay != nil {
		if err := s.eventPublisher.Publish(ctx, Event{
			Type: EventAcademicYearSetCurrent,
			Data: ay,
		}); err != nil {
			logger.Error("failed to publish academic_year.set_current event", zap.Error(err))
		}
	}

	return nil
}

// Delete soft-deletes an academic year.
func (s *academicYearService) Delete(ctx context.Context, id uuid.UUID, deletedBy *uuid.UUID) error {
	logger := s.logger.With(zap.String("method", "Delete"), zap.String("id", id.String()))

	tx, err := s.pgClient.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("begin tx: %w", err)
	}
	defer tx.Rollback()

	// Fetch the academic year before deletion to have data for event
	ay, err := s.repo.GetByIDForUpdate(ctx, tx, id)
	if err != nil {
		return err
	}
	if ay == nil {
		return fmt.Errorf("%w: academic year %s", ErrNotFound, id)
	}

	if err := s.repo.Delete(ctx, tx, id, deletedBy); err != nil {
		return err
	}

	if err := tx.Commit(); err != nil {
		return fmt.Errorf("commit tx: %w", err)
	}

	logger.Info("academic year deleted")

	// Emit event
	if err := s.eventPublisher.Publish(ctx, Event{
		Type: EventAcademicYearDeleted,
		Data: ay, // includes the deleted year data (before soft delete)
	}); err != nil {
		logger.Error("failed to publish academic_year.deleted event", zap.Error(err))
	}

	return nil
}

// ValidateOverlap checks if the given date range overlaps with any existing academic year for the same company.
func (s *academicYearService) ValidateOverlap(ctx context.Context, companyID uuid.UUID, start, end time.Time) error {
	overlap, err := s.repo.CheckOverlap(ctx, s.pgClient.DB, companyID, start, end, uuid.Nil)
	if err != nil {
		return err
	}
	if overlap {
		return fmt.Errorf("%w: academic year dates overlap with an existing year", ErrOverlap)
	}
	return nil
}

// Internal helper to validate date ranges and basic input.
func (s *academicYearService) validateInput(companyID uuid.UUID, name string, start, end time.Time) error {
	if companyID == uuid.Nil {
		return fmt.Errorf("%w: company_id is required", ErrInvalidInput)
	}
	if name == "" {
		return fmt.Errorf("%w: name is required", ErrInvalidInput)
	}
	if start.IsZero() || end.IsZero() {
		return fmt.Errorf("%w: start and end dates are required", ErrInvalidInput)
	}
	if start.After(end) || start.Equal(end) {
		return fmt.Errorf("%w: start date must be before end date", ErrInvalidInput)
	}
	return nil
}

// checkOverlapInMemory performs an in‑memory overlap check against a list of academic years.
// excludeID can be used to skip a particular year (e.g., when updating).
func (s *academicYearService) checkOverlapInMemory(years []*models.AcademicYear, start, end time.Time, excludeID uuid.UUID) error {
	for _, ay := range years {
		if excludeID != uuid.Nil && ay.AcademicYearID == excludeID {
			continue
		}
		// Overlap if not (start > ay.EndDate OR end < ay.StartDate)
		if !(start.After(ay.EndDate) || end.Before(ay.StartDate)) {
			return fmt.Errorf("%w: overlaps with %s (%s - %s)", ErrOverlap, ay.Name, ay.StartDate, ay.EndDate)
		}
	}
	return nil
}

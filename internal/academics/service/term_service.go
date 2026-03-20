package service

import (
	"context"
	"fmt"

	"github.com/google/uuid"
	"go.uber.org/zap"

	"auth-service/internal/academics/models"
	"auth-service/internal/academics/repository"
	"auth-service/internal/client"
)

type TermService interface {
	Create(ctx context.Context, req CreateTermRequest) (*models.Term, error)
	BulkCreate(ctx context.Context, req []CreateTermRequest) ([]*models.Term, error)
	Upsert(ctx context.Context, req CreateTermRequest) (*models.Term, error)

	GetByID(ctx context.Context, id uuid.UUID) (*models.Term, error)
	GetCurrent(ctx context.Context, academicYearID uuid.UUID) (*models.Term, error)

	List(ctx context.Context, filter repository.TermFilter, p repository.Pagination, s repository.Sort) ([]*models.Term, error)
	ListByAcademicYear(ctx context.Context, academicYearID uuid.UUID) ([]*models.Term, error)
	Count(ctx context.Context, filter repository.TermFilter) (int64, error)

	Exists(ctx context.Context, academicYearID uuid.UUID, name string) (bool, error)

	Update(ctx context.Context, req UpdateTermRequest) (*models.Term, error)

	SetCurrent(ctx context.Context, academicYearID, termID uuid.UUID, updatedBy *uuid.UUID) error

	Delete(ctx context.Context, id uuid.UUID, deletedBy *uuid.UUID) error

	ValidateTermWithinAcademicYear(ctx context.Context, term *models.Term) error
}

type termService struct {
	repo           repository.TermRepository
	ayRepo         repository.AcademicYearRepository
	eventPublisher EventPublisher
	pgClient       *client.PostgresClient
	logger         *zap.Logger
}

func NewTermService(
	repo repository.TermRepository,
	ayRepo repository.AcademicYearRepository,
	eventPublisher EventPublisher,
	pgClient *client.PostgresClient,
	logger *zap.Logger,
) TermService {
	return &termService{
		repo:           repo,
		ayRepo:         ayRepo,
		eventPublisher: eventPublisher,
		pgClient:       pgClient,
		logger:         logger.Named("term_service"),
	}
}

// ---------------------------------------------------------------------
// Create
// ---------------------------------------------------------------------
func (s *termService) Create(ctx context.Context, req CreateTermRequest) (*models.Term, error) {
	logger := s.logger.With(
		zap.String("method", "Create"),
		zap.String("academic_year_id", req.AcademicYearID.String()),
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

	// Ensure the academic year exists
	ay, err := s.ayRepo.GetByID(ctx, tx, req.AcademicYearID)
	if err != nil {
		return nil, err
	}
	if ay == nil {
		return nil, fmt.Errorf("%w: academic year %s", ErrNotFound, req.AcademicYearID)
	}

	// Validate term dates are within academic year
	if req.StartDate.Before(ay.StartDate) || req.EndDate.After(ay.EndDate) {
		return nil, fmt.Errorf("%w: term dates must be within academic year %s (%s - %s)",
			ErrInvalidInput, ay.Name, ay.StartDate, ay.EndDate)
	}

	// Efficient overlap check (single query)
	overlap, err := s.repo.CheckOverlap(ctx, tx, req.AcademicYearID, req.StartDate, req.EndDate, uuid.Nil)
	if err != nil {
		return nil, err
	}
	if overlap {
		return nil, fmt.Errorf("%w: term dates overlap with an existing term", ErrOverlap)
	}

	// Check uniqueness of name within academic year
	exists, err := s.repo.Exists(ctx, tx, req.AcademicYearID, req.Name)
	if err != nil {
		return nil, err
	}
	if exists {
		return nil, fmt.Errorf("%w: term name %s already exists in this academic year", ErrDuplicate, req.Name)
	}

	term := &models.Term{
		AcademicYearID: req.AcademicYearID,
		Name:           req.Name,
		StartDate:      req.StartDate,
		EndDate:        req.EndDate,
		IsCurrent:      req.IsCurrent,
		CreatedBy:      req.CreatedBy,
		UpdatedBy:      req.UpdatedBy,
	}

	if err := s.repo.Create(ctx, tx, term); err != nil {
		return nil, err
	}

	if err := tx.Commit(); err != nil {
		return nil, fmt.Errorf("commit tx: %w", err)
	}

	logger.Info("term created", zap.String("id", term.TermID.String()))

	// Publish event
	if err := s.eventPublisher.Publish(ctx, Event{
		Type: EventTermCreated,
		Data: term,
	}); err != nil {
		logger.Error("failed to publish term.created event", zap.Error(err))
	}

	return term, nil
}

// ---------------------------------------------------------------------
// BulkCreate (optimized)
// ---------------------------------------------------------------------
func (s *termService) BulkCreate(ctx context.Context, reqs []CreateTermRequest) ([]*models.Term, error) {
	if len(reqs) == 0 {
		return nil, nil
	}

	logger := s.logger.With(zap.String("method", "BulkCreate"), zap.Int("count", len(reqs)))

	tx, err := s.pgClient.BeginTx(ctx, nil)
	if err != nil {
		return nil, fmt.Errorf("begin tx: %w", err)
	}
	defer tx.Rollback()

	// 1. Collect unique academic year IDs
	ayIDSet := make(map[uuid.UUID]struct{})
	for _, req := range reqs {
		ayIDSet[req.AcademicYearID] = struct{}{}
	}
	ayIDs := make([]uuid.UUID, 0, len(ayIDSet))
	for id := range ayIDSet {
		ayIDs = append(ayIDs, id)
	}

	// 2. Preload all required academic years
	ayMap := make(map[uuid.UUID]*models.AcademicYear)
	for _, id := range ayIDs {
		ay, err := s.ayRepo.GetByID(ctx, tx, id)
		if err != nil {
			return nil, err
		}
		if ay == nil {
			return nil, fmt.Errorf("%w: academic year %s", ErrNotFound, id)
		}
		ayMap[id] = ay
	}

	// 3. Preload existing terms for each academic year
	existingTermsMap := make(map[uuid.UUID][]*models.Term) // key: academic year ID
	for _, id := range ayIDs {
		terms, err := s.repo.ListByAcademicYear(ctx, tx, id)
		if err != nil {
			return nil, err
		}
		existingTermsMap[id] = terms
	}

	// 4. Validate each request and build provisional terms grouped by academic year
	type provisionalTerm struct {
		req  CreateTermRequest
		term *models.Term
	}
	grouped := make(map[uuid.UUID][]provisionalTerm)

	for i, req := range reqs {
		if err := s.validateInput(req); err != nil {
			return nil, fmt.Errorf("item %d: %w", i, err)
		}

		ay := ayMap[req.AcademicYearID]
		if req.StartDate.Before(ay.StartDate) || req.EndDate.After(ay.EndDate) {
			return nil, fmt.Errorf("item %d: term dates must be within academic year %s", i, ay.Name)
		}

		term := &models.Term{
			AcademicYearID: req.AcademicYearID,
			Name:           req.Name,
			StartDate:      req.StartDate,
			EndDate:        req.EndDate,
			IsCurrent:      req.IsCurrent,
			CreatedBy:      req.CreatedBy,
			UpdatedBy:      req.UpdatedBy,
		}
		grouped[req.AcademicYearID] = append(grouped[req.AcademicYearID], provisionalTerm{req: req, term: term})
	}

	// 5. For each academic year, check conflicts within batch and with existing terms
	allTerms := make([]*models.Term, 0, len(reqs))
	for ayID, provList := range grouped {
		existing := existingTermsMap[ayID]

		// 5a. Check name uniqueness within batch
		nameSet := make(map[string]bool)
		for _, pt := range provList {
			if nameSet[pt.req.Name] {
				return nil, fmt.Errorf("%w: duplicate term name '%s' within batch for academic year %s", ErrDuplicate, pt.req.Name, ayID)
			}
			nameSet[pt.req.Name] = true
		}

		// 5b. Check date overlap within batch
		for i := 0; i < len(provList); i++ {
			for j := i + 1; j < len(provList); j++ {
				a := provList[i].term
				b := provList[j].term
				if !(a.StartDate.After(b.EndDate) || a.EndDate.Before(b.StartDate)) {
					return nil, fmt.Errorf("%w: term '%s' overlaps with term '%s' within batch", ErrOverlap, a.Name, b.Name)
				}
			}
		}

		// 5c. Check overlap with existing terms
		for _, pt := range provList {
			for _, ex := range existing {
				if !(pt.term.StartDate.After(ex.EndDate) || pt.term.EndDate.Before(ex.StartDate)) {
					return nil, fmt.Errorf("%w: term '%s' overlaps with existing term '%s' (%s - %s)",
						ErrOverlap, pt.term.Name, ex.Name, ex.StartDate, ex.EndDate)
				}
			}
			allTerms = append(allTerms, pt.term)
		}
	}

	// 6. Bulk insert
	if err := s.repo.BulkCreate(ctx, tx, allTerms); err != nil {
		return nil, err
	}

	if err := tx.Commit(); err != nil {
		return nil, fmt.Errorf("commit tx: %w", err)
	}

	logger.Info("bulk created terms", zap.Int("count", len(allTerms)))

	// Publish events for each created term (optional, can be batched)
	for _, term := range allTerms {
		if err := s.eventPublisher.Publish(ctx, Event{
			Type: EventTermCreated,
			Data: term,
		}); err != nil {
			logger.Error("failed to publish term.created event", zap.String("term_id", term.TermID.String()), zap.Error(err))
		}
	}

	return allTerms, nil
}

// ---------------------------------------------------------------------
// Upsert
// ---------------------------------------------------------------------
func (s *termService) Upsert(ctx context.Context, req CreateTermRequest) (*models.Term, error) {
	logger := s.logger.With(
		zap.String("method", "Upsert"),
		zap.String("academic_year_id", req.AcademicYearID.String()),
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

	ay, err := s.ayRepo.GetByID(ctx, tx, req.AcademicYearID)
	if err != nil {
		return nil, err
	}
	if ay == nil {
		return nil, fmt.Errorf("%w: academic year %s", ErrNotFound, req.AcademicYearID)
	}
	if req.StartDate.Before(ay.StartDate) || req.EndDate.After(ay.EndDate) {
		return nil, fmt.Errorf("%w: term dates must be within academic year", ErrInvalidInput)
	}

	// Find existing term ID (if any) by name
	var existingID uuid.UUID
	terms, err := s.repo.ListByAcademicYear(ctx, tx, req.AcademicYearID)
	if err != nil {
		return nil, err
	}
	for _, t := range terms {
		if t.Name == req.Name {
			existingID = t.TermID
			break
		}
	}

	// Overlap check (efficient)
	overlap, err := s.repo.CheckOverlap(ctx, tx, req.AcademicYearID, req.StartDate, req.EndDate, existingID)
	if err != nil {
		return nil, err
	}
	if overlap {
		return nil, fmt.Errorf("%w: term dates overlap with another term", ErrOverlap)
	}

	term := &models.Term{
		AcademicYearID: req.AcademicYearID,
		Name:           req.Name,
		StartDate:      req.StartDate,
		EndDate:        req.EndDate,
		IsCurrent:      req.IsCurrent,
		CreatedBy:      req.CreatedBy,
		UpdatedBy:      req.UpdatedBy,
	}

	if err := s.repo.Upsert(ctx, tx, term); err != nil {
		return nil, err
	}

	if err := tx.Commit(); err != nil {
		return nil, fmt.Errorf("commit tx: %w", err)
	}

	logger.Info("term upserted", zap.String("id", term.TermID.String()))

	// For upsert, we don't know if it was insert or update without extra query.
	// We'll skip event to avoid duplicate/incorrect events.
	// If needed, you can add logic to determine operation and publish accordingly.

	return term, nil
}

// ---------------------------------------------------------------------
// GetByID
// ---------------------------------------------------------------------
func (s *termService) GetByID(ctx context.Context, id uuid.UUID) (*models.Term, error) {
	logger := s.logger.With(zap.String("method", "GetByID"), zap.String("id", id.String()))

	term, err := s.repo.GetByID(ctx, s.pgClient.DB, id)
	if err != nil {
		return nil, err
	}
	if term == nil {
		return nil, fmt.Errorf("%w: term %s", ErrNotFound, id)
	}
	logger.Debug("term retrieved")
	return term, nil
}

// ---------------------------------------------------------------------
// GetCurrent
// ---------------------------------------------------------------------
func (s *termService) GetCurrent(ctx context.Context, academicYearID uuid.UUID) (*models.Term, error) {
	logger := s.logger.With(zap.String("method", "GetCurrent"), zap.String("academic_year_id", academicYearID.String()))

	term, err := s.repo.GetCurrent(ctx, s.pgClient.DB, academicYearID)
	if err != nil {
		return nil, err
	}
	if term == nil {
		return nil, fmt.Errorf("%w: no current term for academic year %s", ErrNotFound, academicYearID)
	}
	logger.Debug("current term retrieved", zap.String("id", term.TermID.String()))
	return term, nil
}

// ---------------------------------------------------------------------
// List
// ---------------------------------------------------------------------
func (s *termService) List(ctx context.Context, filter repository.TermFilter, p repository.Pagination, srt repository.Sort) ([]*models.Term, error) {
	logger := s.logger.With(zap.String("method", "List"))
	terms, err := s.repo.List(ctx, s.pgClient.DB, filter, p, srt)
	if err != nil {
		return nil, err
	}
	logger.Debug("terms listed", zap.Int("count", len(terms)))
	return terms, nil
}

// ---------------------------------------------------------------------
// ListByAcademicYear
// ---------------------------------------------------------------------
func (s *termService) ListByAcademicYear(ctx context.Context, academicYearID uuid.UUID) ([]*models.Term, error) {
	logger := s.logger.With(zap.String("method", "ListByAcademicYear"), zap.String("academic_year_id", academicYearID.String()))
	terms, err := s.repo.ListByAcademicYear(ctx, s.pgClient.DB, academicYearID)
	if err != nil {
		return nil, err
	}
	logger.Debug("terms listed by academic year", zap.Int("count", len(terms)))
	return terms, nil
}

// ---------------------------------------------------------------------
// Count
// ---------------------------------------------------------------------
func (s *termService) Count(ctx context.Context, filter repository.TermFilter) (int64, error) {
	logger := s.logger.With(zap.String("method", "Count"))
	count, err := s.repo.Count(ctx, s.pgClient.DB, filter)
	if err != nil {
		return 0, err
	}
	logger.Debug("terms counted", zap.Int64("count", count))
	return count, nil
}

// ---------------------------------------------------------------------
// Exists
// ---------------------------------------------------------------------
func (s *termService) Exists(ctx context.Context, academicYearID uuid.UUID, name string) (bool, error) {
	logger := s.logger.With(zap.String("method", "Exists"), zap.String("academic_year_id", academicYearID.String()), zap.String("name", name))
	exists, err := s.repo.Exists(ctx, s.pgClient.DB, academicYearID, name)
	if err != nil {
		return false, err
	}
	logger.Debug("exists check", zap.Bool("exists", exists))
	return exists, nil
}

// ---------------------------------------------------------------------
// Update
// ---------------------------------------------------------------------
func (s *termService) Update(ctx context.Context, req UpdateTermRequest) (*models.Term, error) {
	logger := s.logger.With(zap.String("method", "Update"), zap.String("id", req.TermID.String()))

	tx, err := s.pgClient.BeginTx(ctx, nil)
	if err != nil {
		return nil, fmt.Errorf("begin tx: %w", err)
	}
	defer tx.Rollback()

	term, err := s.repo.GetByIDForUpdate(ctx, tx, req.TermID)
	if err != nil {
		return nil, err
	}
	if term == nil {
		return nil, fmt.Errorf("%w: term %s", ErrNotFound, req.TermID)
	}

	// Capture old state for event
	oldTerm := *term

	ay, err := s.ayRepo.GetByID(ctx, tx, term.AcademicYearID)
	if err != nil {
		return nil, err
	}
	if ay == nil {
		return nil, fmt.Errorf("academic year %s not found for term", term.AcademicYearID)
	}

	if req.StartDate.Before(ay.StartDate) || req.EndDate.After(ay.EndDate) {
		return nil, fmt.Errorf("%w: updated dates must be within academic year %s", ErrInvalidInput, ay.Name)
	}

	overlap, err := s.repo.CheckOverlap(ctx, tx, term.AcademicYearID, req.StartDate, req.EndDate, term.TermID)
	if err != nil {
		return nil, err
	}
	if overlap {
		return nil, fmt.Errorf("%w: updated dates overlap with another term", ErrOverlap)
	}

	if req.Name != term.Name {
		exists, err := s.repo.Exists(ctx, tx, term.AcademicYearID, req.Name)
		if err != nil {
			return nil, err
		}
		if exists {
			return nil, fmt.Errorf("%w: term name %s already exists in this academic year", ErrDuplicate, req.Name)
		}
	}

	term.Name = req.Name
	term.StartDate = req.StartDate
	term.EndDate = req.EndDate
	term.IsCurrent = req.IsCurrent
	term.UpdatedBy = req.UpdatedBy

	if err := s.repo.Update(ctx, tx, term); err != nil {
		return nil, err
	}

	if err := tx.Commit(); err != nil {
		return nil, fmt.Errorf("commit tx: %w", err)
	}

	logger.Info("term updated")

	// Publish event
	if err := s.eventPublisher.Publish(ctx, Event{
		Type: EventTermUpdated,
		Data: map[string]interface{}{
			"old": oldTerm,
			"new": term,
		},
	}); err != nil {
		logger.Error("failed to publish term.updated event", zap.Error(err))
	}

	return term, nil
}

// ---------------------------------------------------------------------
// SetCurrent
// ---------------------------------------------------------------------
func (s *termService) SetCurrent(ctx context.Context, academicYearID, termID uuid.UUID, updatedBy *uuid.UUID) error {
	logger := s.logger.With(zap.String("method", "SetCurrent"), zap.String("id", termID.String()), zap.String("academic_year_id", academicYearID.String()))

	tx, err := s.pgClient.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("begin tx: %w", err)
	}
	defer tx.Rollback()

	if err := s.repo.SetCurrent(ctx, tx, academicYearID, termID, updatedBy); err != nil {
		return err
	}

	if err := tx.Commit(); err != nil {
		return fmt.Errorf("commit tx: %w", err)
	}

	logger.Info("term set as current")

	// Publish event (optional)
	if err := s.eventPublisher.Publish(ctx, Event{
		Type: EventTermSetCurrent,
		Data: map[string]interface{}{
			"academic_year_id": academicYearID,
			"term_id":          termID,
			"updated_by":       updatedBy,
		},
	}); err != nil {
		logger.Error("failed to publish term.set_current event", zap.Error(err))
	}

	return nil
}

// ---------------------------------------------------------------------
// Delete (with soft‑delete dependency check)
// ---------------------------------------------------------------------
func (s *termService) Delete(ctx context.Context, id uuid.UUID, deletedBy *uuid.UUID) error {
	logger := s.logger.With(zap.String("method", "Delete"), zap.String("id", id.String()))

	tx, err := s.pgClient.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("begin tx: %w", err)
	}
	defer tx.Rollback()

	// Optional: check for dependent sections
	// This is just an example – you would use a SectionRepository to count sections linked to this term
	// For now we skip, but a production check is recommended.
	// count, err := s.sectionRepo.CountByTerm(ctx, tx, id)
	// if err != nil { return err }
	// if count > 0 {
	//     return fmt.Errorf("cannot delete term with %d active sections", count)
	// }

	if err := s.repo.Delete(ctx, tx, id, deletedBy); err != nil {
		return err
	}

	if err := tx.Commit(); err != nil {
		return fmt.Errorf("commit tx: %w", err)
	}

	logger.Info("term deleted")

	// Publish event
	if err := s.eventPublisher.Publish(ctx, Event{
		Type: EventTermDeleted,
		Data: map[string]interface{}{
			"term_id":    id,
			"deleted_by": deletedBy,
		},
	}); err != nil {
		logger.Error("failed to publish term.deleted event", zap.Error(err))
	}

	return nil
}

// ---------------------------------------------------------------------
// ValidateTermWithinAcademicYear
// ---------------------------------------------------------------------
func (s *termService) ValidateTermWithinAcademicYear(ctx context.Context, term *models.Term) error {
	logger := s.logger.With(zap.String("method", "ValidateTermWithinAcademicYear"), zap.String("term_id", term.TermID.String()))

	ay, err := s.ayRepo.GetByID(ctx, s.pgClient.DB, term.AcademicYearID)
	if err != nil {
		return err
	}
	if ay == nil {
		return fmt.Errorf("academic year %s not found", term.AcademicYearID)
	}
	if term.StartDate.Before(ay.StartDate) || term.EndDate.After(ay.EndDate) {
		return fmt.Errorf("term dates must be within academic year %s", ay.Name)
	}
	logger.Debug("term is within academic year")
	return nil
}

// ---------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------
func (s *termService) validateInput(req CreateTermRequest) error {
	if req.AcademicYearID == uuid.Nil {
		return fmt.Errorf("%w: academic_year_id is required", ErrInvalidInput)
	}
	if req.Name == "" {
		return fmt.Errorf("%w: name is required", ErrInvalidInput)
	}
	if req.StartDate.IsZero() || req.EndDate.IsZero() {
		return fmt.Errorf("%w: start and end dates are required", ErrInvalidInput)
	}
	if req.StartDate.After(req.EndDate) || req.StartDate.Equal(req.EndDate) {
		return fmt.Errorf("%w: start date must be before end date", ErrInvalidInput)
	}
	return nil
}

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

// ---------------------------------------------------------------------
// TermService interface (unchanged)
// ---------------------------------------------------------------------

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

// ---------------------------------------------------------------------
// termService struct (updated with notification service)
// ---------------------------------------------------------------------

type termService struct {
	repo        repository.TermRepository
	ayRepo      repository.AcademicYearRepository
	sectionRepo repository.SectionRepository // for dependency checks

	auditLogger      AuditLogger
	outboxStore      OutboxStore
	idempotencyStore IdempotencyStore
	notifSvc         NotificationService // added

	pgClient *client.PostgresClient
	logger   *zap.Logger
}

// ---------------------------------------------------------------------
// Constructor (updated)
// ---------------------------------------------------------------------

func NewTermService(
	repo repository.TermRepository,
	ayRepo repository.AcademicYearRepository,
	sectionRepo repository.SectionRepository,
	auditLogger AuditLogger,
	outboxStore OutboxStore,
	idempotencyStore IdempotencyStore,
	notifSvc NotificationService, // added
	pgClient *client.PostgresClient,
	logger *zap.Logger,
) TermService {
	return &termService{
		repo:             repo,
		ayRepo:           ayRepo,
		sectionRepo:      sectionRepo,
		auditLogger:      auditLogger,
		outboxStore:      outboxStore,
		idempotencyStore: idempotencyStore,
		notifSvc:         notifSvc,
		pgClient:         pgClient,
		logger:           logger.Named("term_service"),
	}
}

// ---------------------------------------------------------------------
// Helper: createNotification (same as in exam service)
// ---------------------------------------------------------------------

// getUserIDsForTerm returns a list of user IDs (students + teachers) that are affected by this term.
// This is a placeholder – you should implement it using your enrollment and teacher repositories.
func (s *termService) getUserIDsForTerm(ctx context.Context, tx repository.DBTX, termID uuid.UUID) ([]uuid.UUID, error) {
	// Example: fetch enrollments and teacher assignments for this term
	// For now, return empty slice and log a warning.
	s.logger.Warn("getUserIDsForTerm not implemented – returning empty list", zap.String("term_id", termID.String()))
	return nil, nil
}

// createNotification sends a notification to the specified user IDs.
func (s *termService) createNotification(ctx context.Context, title, message string, notifType models.NotificationType, priority models.NotificationPriority, companyID uuid.UUID, userIDs []uuid.UUID, createdBy *uuid.UUID) {
	if s.notifSvc == nil || len(userIDs) == 0 {
		return
	}
	targets := make([]NotificationTargetInput, len(userIDs))
	for i, uid := range userIDs {
		targets[i] = NotificationTargetInput{
			TargetType:     models.TargetUser, // or TargetStudent / TargetTeacher
			TargetEntityID: uid,
		}
	}
	req := CreateNotificationRequest{
		CompanyID: companyID,
		Title:     title,
		Message:   message,
		Type:      notifType,
		Priority:  priority,
		ExpiresAt: nil,
		Targets:   targets,
		CreatedBy: createdBy,
	}
	// Use background context to avoid cancellation of the main request
	_, err := s.notifSvc.Create(context.Background(), req, "")
	if err != nil {
		s.logger.Error("failed to send notification",
			zap.String("title", title),
			zap.Error(err))
	}
}

// ---------------------------------------------------------------------
// Validation helpers (unchanged)
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

func (s *termService) validateAcademicYear(ctx context.Context, tx repository.DBTX, academicYearID uuid.UUID) (*models.AcademicYear, error) {
	ay, err := s.ayRepo.GetByID(ctx, tx, academicYearID)
	if err != nil {
		return nil, err
	}
	if ay == nil {
		return nil, fmt.Errorf("%w: academic year %s", ErrNotFound, academicYearID)
	}
	return ay, nil
}

func (s *termService) validateTermDates(ay *models.AcademicYear, startDate, endDate time.Time) error {
	if startDate.Before(ay.StartDate) || endDate.After(ay.EndDate) {
		return fmt.Errorf("%w: term dates must be within academic year %s (%s - %s)",
			ErrInvalidInput, ay.Name, ay.StartDate, ay.EndDate)
	}
	return nil
}

// ---------------------------------------------------------------------
// Create (with notification after commit)
// ---------------------------------------------------------------------

func (s *termService) Create(ctx context.Context, req CreateTermRequest) (*models.Term, error) {
	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()

	logger := s.logger.With(
		zap.String("method", "Create"),
		zap.String("academic_year_id", req.AcademicYearID.String()),
		zap.String("name", req.Name),
	)

	// Idempotency check
	if idempotencyKey, ok := ctx.Value("idempotency_key").(string); ok && idempotencyKey != "" {
		var existing *models.Term
		if err := s.idempotencyStore.Get(ctx, nil, idempotencyKey, &existing); err == nil && existing != nil {
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

	ay, err := s.validateAcademicYear(ctx, tx, req.AcademicYearID)
	if err != nil {
		return nil, err
	}
	if err := s.validateTermDates(ay, req.StartDate, req.EndDate); err != nil {
		return nil, err
	}

	overlap, err := s.repo.CheckOverlap(ctx, tx, req.AcademicYearID, req.StartDate, req.EndDate, uuid.Nil)
	if err != nil {
		return nil, err
	}
	if overlap {
		return nil, fmt.Errorf("%w: term dates overlap with an existing term", ErrOverlap)
	}

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

	if err := s.auditLogger.Log(ctx, tx, "TERM_CREATE", term.TermID, nil, term, req.CreatedBy); err != nil {
		logger.Error("audit log failed", zap.Error(err))
	}

	if err := s.outboxStore.Store(ctx, tx, string(EventTermCreated), term); err != nil {
		return nil, fmt.Errorf("store outbox event: %w", err)
	}

	if idempotencyKey, ok := ctx.Value("idempotency_key").(string); ok && idempotencyKey != "" {
		if err := s.idempotencyStore.Store(ctx, tx, idempotencyKey, term); err != nil {
			logger.Error("failed to store idempotency key", zap.Error(err))
		}
	}

	if err := tx.Commit(); err != nil {
		return nil, fmt.Errorf("commit tx: %w", err)
	}

	// --- Notification after commit ---
	userIDs, _ := s.getUserIDsForTerm(ctx, nil, term.TermID) // use nil DB (separate connection)
	title := fmt.Sprintf("New Term: %s", term.Name)
	message := fmt.Sprintf("A new term '%s' has been added for academic year %s, from %s to %s.",
		term.Name, ay.Name, term.StartDate.Format("2006-01-02"), term.EndDate.Format("2006-01-02"))
	s.createNotification(ctx, title, message, models.NotificationTypeEvent, models.PriorityNormal, ay.CompanyID, userIDs, req.CreatedBy)

	logger.Info("term created", zap.String("term_id", term.TermID.String()))
	return term, nil
}

// ---------------------------------------------------------------------
// BulkCreate (with notifications after commit)
// ---------------------------------------------------------------------

func (s *termService) BulkCreate(ctx context.Context, reqs []CreateTermRequest) ([]*models.Term, error) {
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

	// Preload academic years and existing terms (same as before)
	ayIDSet := make(map[uuid.UUID]struct{})
	for _, req := range reqs {
		ayIDSet[req.AcademicYearID] = struct{}{}
	}
	ayIDs := make([]uuid.UUID, 0, len(ayIDSet))
	for id := range ayIDSet {
		ayIDs = append(ayIDs, id)
	}

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

	existingTermsMap := make(map[uuid.UUID][]*models.Term)
	for _, id := range ayIDs {
		terms, err := s.repo.ListByAcademicYear(ctx, tx, id)
		if err != nil {
			return nil, err
		}
		existingTermsMap[id] = terms
	}

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
		if err := s.validateTermDates(ay, req.StartDate, req.EndDate); err != nil {
			return nil, fmt.Errorf("item %d: %w", i, err)
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

	// Validate each group (overlaps, duplicates) – same as before
	allTerms := make([]*models.Term, 0, len(reqs))
	for ayID, provList := range grouped {
		existing := existingTermsMap[ayID]

		// duplicate names within batch
		nameSet := make(map[string]bool)
		for _, pt := range provList {
			if nameSet[pt.req.Name] {
				return nil, fmt.Errorf("%w: duplicate term name '%s' in batch for academic year %s", ErrDuplicate, pt.req.Name, ayID)
			}
			nameSet[pt.req.Name] = true
		}

		// overlaps within batch
		for i := 0; i < len(provList); i++ {
			for j := i + 1; j < len(provList); j++ {
				a := provList[i].term
				b := provList[j].term
				if !(a.StartDate.After(b.EndDate) || a.EndDate.Before(b.StartDate)) {
					return nil, fmt.Errorf("%w: term '%s' overlaps with term '%s' in batch", ErrOverlap, a.Name, b.Name)
				}
			}
		}

		// overlaps with existing
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

	if err := s.repo.BulkCreate(ctx, tx, allTerms); err != nil {
		return nil, err
	}

	// Audit and outbox for each term
	for _, term := range allTerms {
		if err := s.auditLogger.Log(ctx, tx, "TERM_BULK_CREATE", term.TermID, nil, term, term.CreatedBy); err != nil {
			logger.Error("audit failed", zap.String("term_id", term.TermID.String()), zap.Error(err))
		}
		if err := s.outboxStore.Store(ctx, tx, string(EventTermCreated), term); err != nil {
			return nil, fmt.Errorf("outbox store for term %s: %w", term.TermID, err)
		}
	}

	if err := tx.Commit(); err != nil {
		return nil, fmt.Errorf("commit tx: %w", err)
	}

	// --- Notifications after commit (for each term) ---
	for _, term := range allTerms {
		ay := ayMap[term.AcademicYearID]
		userIDs, _ := s.getUserIDsForTerm(ctx, nil, term.TermID)
		title := fmt.Sprintf("New Term: %s", term.Name)
		message := fmt.Sprintf("A new term '%s' has been added for academic year %s, from %s to %s.",
			term.Name, ay.Name, term.StartDate.Format("2006-01-02"), term.EndDate.Format("2006-01-02"))
		s.createNotification(ctx, title, message, models.NotificationTypeEvent, models.PriorityNormal, ay.CompanyID, userIDs, term.CreatedBy)
	}

	logger.Info("bulk created terms", zap.Int("count", len(allTerms)))
	return allTerms, nil
}

// ---------------------------------------------------------------------
// Upsert (with notification after commit)
// ---------------------------------------------------------------------

func (s *termService) Upsert(ctx context.Context, req CreateTermRequest) (*models.Term, error) {
	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()

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

	ay, err := s.validateAcademicYear(ctx, tx, req.AcademicYearID)
	if err != nil {
		return nil, err
	}
	if err := s.validateTermDates(ay, req.StartDate, req.EndDate); err != nil {
		return nil, err
	}

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

	if err := s.auditLogger.Log(ctx, tx, "TERM_UPSERT", term.TermID, nil, term, req.UpdatedBy); err != nil {
		logger.Error("audit log failed", zap.Error(err))
	}
	if err := s.outboxStore.Store(ctx, tx, string(EventTermUpdated), term); err != nil {
		return nil, fmt.Errorf("outbox store: %w", err)
	}

	if err := tx.Commit(); err != nil {
		return nil, fmt.Errorf("commit tx: %w", err)
	}

	// --- Notification after commit ---
	userIDs, _ := s.getUserIDsForTerm(ctx, nil, term.TermID)
	title := fmt.Sprintf("Term Updated: %s", term.Name)
	message := fmt.Sprintf("Term '%s' has been updated. New dates: %s to %s.",
		term.Name, term.StartDate.Format("2006-01-02"), term.EndDate.Format("2006-01-02"))
	s.createNotification(ctx, title, message, models.NotificationTypeEvent, models.PriorityNormal, ay.CompanyID, userIDs, req.UpdatedBy)

	logger.Info("term upserted", zap.String("term_id", term.TermID.String()))
	return term, nil
}

// ---------------------------------------------------------------------
// Read‑only methods (unchanged)
// ---------------------------------------------------------------------

func (s *termService) GetByID(ctx context.Context, id uuid.UUID) (*models.Term, error) {
	ctx, cancel := context.WithTimeout(ctx, 2*time.Second)
	defer cancel()
	term, err := s.repo.GetByID(ctx, s.pgClient.DB, id)
	if err != nil {
		return nil, err
	}
	if term == nil {
		return nil, fmt.Errorf("%w: term %s", ErrNotFound, id)
	}
	return term, nil
}

func (s *termService) GetCurrent(ctx context.Context, academicYearID uuid.UUID) (*models.Term, error) {
	ctx, cancel := context.WithTimeout(ctx, 2*time.Second)
	defer cancel()
	term, err := s.repo.GetCurrent(ctx, s.pgClient.DB, academicYearID)
	if err != nil {
		return nil, err
	}
	if term == nil {
		return nil, fmt.Errorf("%w: no current term for academic year %s", ErrNotFound, academicYearID)
	}
	return term, nil
}

func (s *termService) List(ctx context.Context, filter repository.TermFilter, p repository.Pagination, srt repository.Sort) ([]*models.Term, error) {
	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	return s.repo.List(ctx, s.pgClient.DB, filter, p, srt)
}

func (s *termService) ListByAcademicYear(ctx context.Context, academicYearID uuid.UUID) ([]*models.Term, error) {
	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	return s.repo.ListByAcademicYear(ctx, s.pgClient.DB, academicYearID)
}

func (s *termService) Count(ctx context.Context, filter repository.TermFilter) (int64, error) {
	ctx, cancel := context.WithTimeout(ctx, 2*time.Second)
	defer cancel()
	return s.repo.Count(ctx, s.pgClient.DB, filter)
}

func (s *termService) Exists(ctx context.Context, academicYearID uuid.UUID, name string) (bool, error) {
	ctx, cancel := context.WithTimeout(ctx, 2*time.Second)
	defer cancel()
	return s.repo.Exists(ctx, s.pgClient.DB, academicYearID, name)
}

// ---------------------------------------------------------------------
// Update (with notification after commit)
// ---------------------------------------------------------------------

func (s *termService) Update(ctx context.Context, req UpdateTermRequest) (*models.Term, error) {
	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()

	logger := s.logger.With(zap.String("method", "Update"), zap.String("term_id", req.TermID.String()))

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
	oldTerm := *term

	ay, err := s.validateAcademicYear(ctx, tx, term.AcademicYearID)
	if err != nil {
		return nil, err
	}
	if err := s.validateTermDates(ay, req.StartDate, req.EndDate); err != nil {
		return nil, err
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
			return nil, fmt.Errorf("%w: term name %s already exists", ErrDuplicate, req.Name)
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

	if err := s.auditLogger.Log(ctx, tx, "TERM_UPDATE", req.TermID, &oldTerm, term, req.UpdatedBy); err != nil {
		logger.Error("audit log failed", zap.Error(err))
	}
	if err := s.outboxStore.Store(ctx, tx, string(EventTermUpdated), map[string]interface{}{
		"old": oldTerm,
		"new": term,
	}); err != nil {
		return nil, fmt.Errorf("outbox store: %w", err)
	}

	if err := tx.Commit(); err != nil {
		return nil, fmt.Errorf("commit tx: %w", err)
	}

	// --- Notification after commit ---
	userIDs, _ := s.getUserIDsForTerm(ctx, nil, term.TermID)
	title := fmt.Sprintf("Term Updated: %s", term.Name)
	message := fmt.Sprintf("Term '%s' has been updated. New dates: %s to %s.",
		term.Name, term.StartDate.Format("2006-01-02"), term.EndDate.Format("2006-01-02"))
	s.createNotification(ctx, title, message, models.NotificationTypeEvent, models.PriorityNormal, ay.CompanyID, userIDs, req.UpdatedBy)

	logger.Info("term updated")
	return term, nil
}

// ---------------------------------------------------------------------
// SetCurrent (with notification after commit)
// ---------------------------------------------------------------------

func (s *termService) SetCurrent(ctx context.Context, academicYearID, termID uuid.UUID, updatedBy *uuid.UUID) error {
	ctx, cancel := context.WithTimeout(ctx, 3*time.Second)
	defer cancel()

	logger := s.logger.With(
		zap.String("method", "SetCurrent"),
		zap.String("academic_year_id", academicYearID.String()),
		zap.String("term_id", termID.String()),
	)

	tx, err := s.pgClient.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("begin tx: %w", err)
	}
	defer tx.Rollback()

	if err := s.repo.SetCurrent(ctx, tx, academicYearID, termID, updatedBy); err != nil {
		return err
	}

	term, err := s.repo.GetByID(ctx, tx, termID)
	if err != nil {
		return err
	}
	if term == nil {
		return fmt.Errorf("%w: term %s", ErrNotFound, termID)
	}

	if err := s.auditLogger.Log(ctx, tx, "TERM_SET_CURRENT", termID, nil, term, updatedBy); err != nil {
		logger.Error("audit log failed", zap.Error(err))
	}
	if err := s.outboxStore.Store(ctx, tx, string(EventTermSetCurrent), map[string]interface{}{
		"academic_year_id": academicYearID,
		"term_id":          termID,
		"updated_by":       updatedBy,
	}); err != nil {
		return fmt.Errorf("outbox store: %w", err)
	}

	ay, err := s.ayRepo.GetByID(ctx, tx, academicYearID)
	if err != nil {
		return err
	}
	if ay == nil {
		return fmt.Errorf("academic year %s not found", academicYearID)
	}

	if err := tx.Commit(); err != nil {
		return fmt.Errorf("commit tx: %w", err)
	}

	// --- Notification after commit ---
	userIDs, _ := s.getUserIDsForTerm(ctx, nil, termID)
	title := fmt.Sprintf("Current Term Changed: %s", term.Name)
	message := fmt.Sprintf("The current term for academic year %s is now '%s'.", ay.Name, term.Name)
	s.createNotification(ctx, title, message, models.NotificationTypeEvent, models.PriorityHigh, ay.CompanyID, userIDs, updatedBy)

	logger.Info("term set as current")
	return nil
}

// ---------------------------------------------------------------------
// Delete (with notification after commit)
// ---------------------------------------------------------------------

func (s *termService) Delete(ctx context.Context, id uuid.UUID, deletedBy *uuid.UUID) error {
	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()

	logger := s.logger.With(zap.String("method", "Delete"), zap.String("term_id", id.String()))

	tx, err := s.pgClient.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("begin tx: %w", err)
	}
	defer tx.Rollback()

	term, err := s.repo.GetByIDForUpdate(ctx, tx, id)
	if err != nil {
		return err
	}
	if term == nil {
		// Idempotent: already deleted
		logger.Info("term already deleted (idempotent)")
		return nil
	}

	// Check for dependent sections
	if s.sectionRepo != nil {
		count, err := s.sectionRepo.CountByTerm(ctx, tx, id)
		if err != nil {
			return fmt.Errorf("failed to check sections: %w", err)
		}
		if count > 0 {
			return fmt.Errorf("%w: term has %d active sections", ErrDependencyExists, count)
		}
	}

	if err := s.repo.Delete(ctx, tx, id, deletedBy); err != nil {
		return err
	}

	if err := s.auditLogger.Log(ctx, tx, "TERM_DELETE", id, term, nil, deletedBy); err != nil {
		logger.Error("audit log failed", zap.Error(err))
	}
	if err := s.outboxStore.Store(ctx, tx, string(EventTermDeleted), map[string]interface{}{
		"term_id":    id,
		"deleted_by": deletedBy,
	}); err != nil {
		return fmt.Errorf("outbox store: %w", err)
	}

	ay, err := s.ayRepo.GetByID(ctx, tx, term.AcademicYearID)
	if err != nil {
		return err
	}
	if ay == nil {
		return fmt.Errorf("academic year %s not found", term.AcademicYearID)
	}

	if err := tx.Commit(); err != nil {
		return fmt.Errorf("commit tx: %w", err)
	}

	// --- Notification after commit ---
	userIDs, _ := s.getUserIDsForTerm(ctx, nil, id)
	title := fmt.Sprintf("Term Deleted: %s", term.Name)
	message := fmt.Sprintf("Term '%s' for academic year %s has been deleted.", term.Name, ay.Name)
	s.createNotification(ctx, title, message, models.NotificationTypeAlert, models.PriorityNormal, ay.CompanyID, userIDs, deletedBy)

	logger.Info("term deleted")
	return nil
}

// ---------------------------------------------------------------------
// ValidateTermWithinAcademicYear (unchanged)
// ---------------------------------------------------------------------

func (s *termService) ValidateTermWithinAcademicYear(ctx context.Context, term *models.Term) error {
	ctx, cancel := context.WithTimeout(ctx, 2*time.Second)
	defer cancel()

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
	return nil
}

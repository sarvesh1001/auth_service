package service

import (
	"context"
	"encoding/json"
	"fmt"
	"time"

	"github.com/google/uuid"
	"go.uber.org/zap"

	"auth-service/internal/academics/models"
	"auth-service/internal/academics/repository"
	"auth-service/internal/client"
	"auth-service/internal/infrastructure/audit"
	"auth-service/internal/infrastructure/idempotency"
	"auth-service/internal/infrastructure/outbox"
)

// TermService defines the interface for term operations
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
	repo             repository.TermRepository
	ayRepo           repository.AcademicYearRepository
	sectionRepo      repository.SectionRepository
	pgClient         *client.PostgresClient
	logger           *zap.Logger
	outboxRepo       outbox.Repository
	idempotencyStore idempotency.Store
	auditService     *audit.AuditService
	notificationSvc  NotificationService
}

// NewTermService creates a new term service
func NewTermService(
	repo repository.TermRepository,
	ayRepo repository.AcademicYearRepository,
	sectionRepo repository.SectionRepository,
	pgClient *client.PostgresClient,
	logger *zap.Logger,
	outboxRepo outbox.Repository,
	idempotencyStore idempotency.Store,
	auditService *audit.AuditService,
	notificationSvc NotificationService,
) TermService {
	return &termService{
		repo:             repo,
		ayRepo:           ayRepo,
		sectionRepo:      sectionRepo,
		pgClient:         pgClient,
		logger:           logger.Named("term_service"),
		outboxRepo:       outboxRepo,
		idempotencyStore: idempotencyStore,
		auditService:     auditService,
		notificationSvc:  notificationSvc,
	}
}

// Helper: build notification request (similar to academic year)
func (s *termService) buildNotificationRequest(
	term *models.Term,
	ay *models.AcademicYear,
	operation string,
	actor *uuid.UUID,
) CreateNotificationRequest {
	var title, message string
	var notifType models.NotificationType
	priority := models.PriorityNormal

	switch operation {
	case "created":
		title = "New Term Created"
		message = fmt.Sprintf("Term '%s' has been created for academic year %s (%s - %s)",
			term.Name, ay.Name, term.StartDate.Format("2006-01-02"), term.EndDate.Format("2006-01-02"))
		notifType = models.NotificationTypeInfo
	case "updated":
		title = "Term Updated"
		message = fmt.Sprintf("Term '%s' has been updated (%s - %s)",
			term.Name, term.StartDate.Format("2006-01-02"), term.EndDate.Format("2006-01-02"))
		notifType = models.NotificationTypeInfo
	case "set_current":
		title = "Current Term Changed"
		message = fmt.Sprintf("Term '%s' is now the current term for academic year %s", term.Name, ay.Name)
		notifType = models.NotificationTypeEvent
		priority = models.PriorityHigh
	case "deleted":
		title = "Term Deleted"
		message = fmt.Sprintf("Term '%s' has been deleted from academic year %s", term.Name, ay.Name)
		notifType = models.NotificationTypeWarning
		priority = models.PriorityHigh
	default:
		title = "Term Changed"
		message = fmt.Sprintf("Term '%s' was modified", term.Name)
		notifType = models.NotificationTypeInfo
	}

	return CreateNotificationRequest{
		CompanyID: ay.CompanyID,
		Title:     title,
		Message:   message,
		Type:      notifType,
		Priority:  priority,
		ExpiresAt: nil,
		Targets: []NotificationTargetInput{
			{
				TargetType:     models.TargetCompany,
				TargetEntityID: ay.CompanyID,
			},
		},
		CreatedBy: actor,
	}
}

// Helper: send notification (non‑blocking)
func (s *termService) sendNotification(ctx context.Context, req CreateNotificationRequest, idempotencyKey string) {
	if s.notificationSvc == nil {
		return
	}
	_, _ = s.notificationSvc.Create(ctx, req, idempotencyKey)
}

// Validation helpers
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
			ErrInvalidInput, ay.Name, ay.StartDate.Format("2006-01-02"), ay.EndDate.Format("2006-01-02"))
	}
	return nil
}

// Create a single term
func (s *termService) Create(ctx context.Context, req CreateTermRequest) (*models.Term, error) {
	logger := s.logger.With(
		zap.String("method", "Create"),
		zap.String("academic_year_id", req.AcademicYearID.String()),
		zap.String("name", req.Name),
	)

	idempotencyKey, _ := ctx.Value("idempotency_key").(string)
	if idempotencyKey != "" {
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

	// After creation, if this term should be current, atomically unset others and set this one.
	if req.IsCurrent {
		if err := s.repo.SetCurrent(ctx, tx, req.AcademicYearID, term.TermID, req.UpdatedBy); err != nil {
			return nil, fmt.Errorf("set current term: %w", err)
		}
		term.IsCurrent = true
	}

	if idempotencyKey != "" {
		if err := s.idempotencyStore.Store(ctx, tx, idempotencyKey, term); err != nil {
			logger.Error("failed to store idempotency key", zap.Error(err))
		}
	}

	payload, _ := json.Marshal(term)
	outboxEvent := &outbox.Event{
		EventID:       uuid.New().String(),
		AggregateType: "term",
		AggregateID:   term.TermID.String(),
		EventType:     string(EventTermCreated),
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

	if s.auditService != nil {
		_ = s.auditService.LogAction(ctx, nil, &ay.CompanyID, "academics", "create", "term",
			&term.TermID, "user", req.CreatedBy, nil, nil,
			map[string]interface{}{"name": term.Name, "academic_year_id": term.AcademicYearID})
	}

	if s.notificationSvc != nil {
		notifReq := s.buildNotificationRequest(term, ay, "created", req.CreatedBy)
		s.sendNotification(ctx, notifReq, uuid.New().String())
	}

	logger.Info("term created", zap.String("term_id", term.TermID.String()))
	return term, nil
}

// BulkCreate creates multiple terms in one transaction
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

	// Group by academic year
	ayIDSet := make(map[uuid.UUID]struct{})
	for _, req := range reqs {
		ayIDSet[req.AcademicYearID] = struct{}{}
	}
	ayIDs := make([]uuid.UUID, 0, len(ayIDSet))
	for id := range ayIDSet {
		ayIDs = append(ayIDs, id)
	}

	// Load academic years
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

	// Load existing terms for each academic year
	existingTermsMap := make(map[uuid.UUID][]*models.Term)
	for _, id := range ayIDs {
		terms, err := s.repo.ListByAcademicYear(ctx, tx, id)
		if err != nil {
			return nil, err
		}
		existingTermsMap[id] = terms
	}

	// Prepare all terms and validate overlaps/duplicates in batch
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

	allTerms := make([]*models.Term, 0, len(reqs))
	termsToSetCurrent := make(map[uuid.UUID]*models.Term) // academicYearID -> term that should be current

	for ayID, provList := range grouped {
		// Check duplicate names within batch
		nameSet := make(map[string]bool)
		currentCount := 0
		var currentTerm *models.Term

		for _, pt := range provList {
			if nameSet[pt.req.Name] {
				return nil, fmt.Errorf("%w: duplicate term name '%s' in batch for academic year %s", ErrDuplicate, pt.req.Name, ayID)
			}
			nameSet[pt.req.Name] = true

			if pt.req.IsCurrent {
				currentCount++
				currentTerm = pt.term
			}
		}

		if currentCount > 1 {
			return nil, fmt.Errorf("%w: only one term can be current per academic year (academic year %s)", ErrInvalidInput, ayID)
		}
		if currentCount == 1 {
			termsToSetCurrent[ayID] = currentTerm
		}

		// Check overlaps within batch
		for i := 0; i < len(provList); i++ {
			for j := i + 1; j < len(provList); j++ {
				a := provList[i].term
				b := provList[j].term
				if !(a.StartDate.After(b.EndDate) || a.EndDate.Before(b.StartDate)) {
					return nil, fmt.Errorf("%w: term '%s' overlaps with term '%s' in batch", ErrOverlap, a.Name, b.Name)
				}
			}
		}
		// Check overlaps with existing terms
		existing := existingTermsMap[ayID]
		for _, pt := range provList {
			for _, ex := range existing {
				if !(pt.term.StartDate.After(ex.EndDate) || pt.term.EndDate.Before(ex.StartDate)) {
					return nil, fmt.Errorf("%w: term '%s' overlaps with existing term '%s' (%s - %s)",
						ErrOverlap, pt.term.Name, ex.Name, ex.StartDate.Format("2006-01-02"), ex.EndDate.Format("2006-01-02"))
				}
			}
			allTerms = append(allTerms, pt.term)
		}
	}

	// Bulk insert
	if err := s.repo.BulkCreate(ctx, tx, allTerms); err != nil {
		return nil, err
	}

	// After insertion, set the appropriate term(s) as current
	for ayID, termToSet := range termsToSetCurrent {
		if err := s.repo.SetCurrent(ctx, tx, ayID, termToSet.TermID, termToSet.UpdatedBy); err != nil {
			return nil, fmt.Errorf("set current term for academic year %s: %w", ayID, err)
		}
		termToSet.IsCurrent = true
	}

	// Outbox events for each term
	for _, term := range allTerms {
		payload, _ := json.Marshal(term)
		outboxEvent := &outbox.Event{
			EventID:       uuid.New().String(),
			AggregateType: "term",
			AggregateID:   term.TermID.String(),
			EventType:     string(EventTermCreated),
			Payload:       payload,
			Headers:       map[string]string{},
			Status:        "pending",
		}
		if err := s.outboxRepo.Store(ctx, tx, outboxEvent); err != nil {
			return nil, fmt.Errorf("store outbox event for term %s: %w", term.TermID, err)
		}
	}

	if err := tx.Commit(); err != nil {
		return nil, fmt.Errorf("commit tx: %w", err)
	}

	// Audit and notifications (async, best-effort)
	for _, term := range allTerms {
		ay := ayMap[term.AcademicYearID]
		if s.auditService != nil {
			_ = s.auditService.LogAction(ctx, nil, &ay.CompanyID, "academics", "bulk_create", "term",
				&term.TermID, "user", term.CreatedBy, nil, nil,
				map[string]interface{}{"name": term.Name, "academic_year_id": term.AcademicYearID})
		}
		if s.notificationSvc != nil {
			notifReq := s.buildNotificationRequest(term, ay, "created", term.CreatedBy)
			s.sendNotification(ctx, notifReq, uuid.New().String())
		}
	}

	logger.Info("bulk created terms", zap.Int("count", len(allTerms)))
	return allTerms, nil
}

// Upsert creates or replaces a term by name (unique per academic year)
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

	ay, err := s.validateAcademicYear(ctx, tx, req.AcademicYearID)
	if err != nil {
		return nil, err
	}
	if err := s.validateTermDates(ay, req.StartDate, req.EndDate); err != nil {
		return nil, err
	}

	// Find existing term by name
	existing, _ := s.repo.GetByName(ctx, tx, req.AcademicYearID, req.Name)
	excludeID := uuid.Nil
	if existing != nil {
		excludeID = existing.TermID
	}

	overlap, err := s.repo.CheckOverlap(ctx, tx, req.AcademicYearID, req.StartDate, req.EndDate, excludeID)
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

	var eventType EventType
	if existing == nil {
		eventType = EventTermCreated
	} else {
		eventType = EventTermUpdated
	}

	if err := s.repo.Upsert(ctx, tx, term); err != nil {
		return nil, err
	}

	// After upsert, if the term should be current, ensure only this one is current
	if req.IsCurrent {
		if err := s.repo.SetCurrent(ctx, tx, term.AcademicYearID, term.TermID, req.UpdatedBy); err != nil {
			return nil, fmt.Errorf("set current term: %w", err)
		}
		term.IsCurrent = true
	}

	payload, _ := json.Marshal(term)
	outboxEvent := &outbox.Event{
		EventID:       uuid.New().String(),
		AggregateType: "term",
		AggregateID:   term.TermID.String(),
		EventType:     string(eventType),
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

	if s.auditService != nil {
		action := "upsert"
		if existing == nil {
			action = "create"
		}
		_ = s.auditService.LogAction(ctx, nil, &ay.CompanyID, "academics", action, "term",
			&term.TermID, "user", req.CreatedBy, nil, nil,
			map[string]interface{}{"name": term.Name})
	}

	if s.notificationSvc != nil {
		operation := "created"
		if existing != nil {
			operation = "updated"
		}
		notifReq := s.buildNotificationRequest(term, ay, operation, req.CreatedBy)
		s.sendNotification(ctx, notifReq, uuid.New().String())
	}

	logger.Info("term upserted", zap.String("term_id", term.TermID.String()))
	return term, nil
}

// GetByID retrieves a term by its ID
func (s *termService) GetByID(ctx context.Context, id uuid.UUID) (*models.Term, error) {
	term, err := s.repo.GetByID(ctx, s.pgClient.DB, id)
	if err != nil {
		return nil, err
	}
	if term == nil {
		return nil, fmt.Errorf("%w: term %s", ErrNotFound, id)
	}
	return term, nil
}

// GetCurrent returns the current term for an academic year
func (s *termService) GetCurrent(ctx context.Context, academicYearID uuid.UUID) (*models.Term, error) {
	term, err := s.repo.GetCurrent(ctx, s.pgClient.DB, academicYearID)
	if err != nil {
		return nil, err
	}
	if term == nil {
		return nil, fmt.Errorf("%w: no current term for academic year %s", ErrNotFound, academicYearID)
	}
	return term, nil
}

// List returns a filtered list of terms
func (s *termService) List(ctx context.Context, filter repository.TermFilter, p repository.Pagination, srt repository.Sort) ([]*models.Term, error) {
	return s.repo.List(ctx, s.pgClient.DB, filter, p, srt)
}

// ListByAcademicYear returns all terms for a given academic year
func (s *termService) ListByAcademicYear(ctx context.Context, academicYearID uuid.UUID) ([]*models.Term, error) {
	return s.repo.ListByAcademicYear(ctx, s.pgClient.DB, academicYearID)
}

// Count returns the number of terms matching the filter
func (s *termService) Count(ctx context.Context, filter repository.TermFilter) (int64, error) {
	return s.repo.Count(ctx, s.pgClient.DB, filter)
}

// Exists checks if a term with the given name exists in the academic year
func (s *termService) Exists(ctx context.Context, academicYearID uuid.UUID, name string) (bool, error) {
	return s.repo.Exists(ctx, s.pgClient.DB, academicYearID, name)
}

// Update modifies an existing term
func (s *termService) Update(ctx context.Context, req UpdateTermRequest) (*models.Term, error) {
	logger := s.logger.With(zap.String("method", "Update"), zap.String("term_id", req.TermID.String()))

	idempotencyKey, _ := ctx.Value("idempotency_key").(string)
	if idempotencyKey != "" {
		var existing *models.Term
		if err := s.idempotencyStore.Get(ctx, nil, idempotencyKey, &existing); err == nil && existing != nil {
			logger.Info("idempotent request, returning cached response")
			return existing, nil
		}
	}

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

	// If the term should be current, ensure only this one is current
	if req.IsCurrent {
		if err := s.repo.SetCurrent(ctx, tx, term.AcademicYearID, term.TermID, req.UpdatedBy); err != nil {
			return nil, fmt.Errorf("set current term: %w", err)
		}
		term.IsCurrent = true
	}

	if idempotencyKey != "" {
		_ = s.idempotencyStore.Store(ctx, tx, idempotencyKey, term)
	}

	// Outbox event for update
	payload, _ := json.Marshal(term)
	outboxEvent := &outbox.Event{
		EventID:       uuid.New().String(),
		AggregateType: "term",
		AggregateID:   term.TermID.String(),
		EventType:     string(EventTermUpdated),
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

	if s.auditService != nil {
		_ = s.auditService.LogAction(ctx, nil, &ay.CompanyID, "academics", "update", "term",
			&term.TermID, "user", req.UpdatedBy, nil, nil,
			map[string]interface{}{"old_name": oldTerm.Name, "new_name": term.Name})
	}

	if s.notificationSvc != nil {
		notifReq := s.buildNotificationRequest(term, ay, "updated", req.UpdatedBy)
		s.sendNotification(ctx, notifReq, uuid.New().String())
	}

	logger.Info("term updated")
	return term, nil
}

// SetCurrent marks a term as the current one for its academic year (unsetting any previous current)
func (s *termService) SetCurrent(ctx context.Context, academicYearID, termID uuid.UUID, updatedBy *uuid.UUID) error {
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

	// Retrieve the term for outbox and notification
	term, err := s.repo.GetByID(ctx, tx, termID)
	if err != nil {
		return err
	}
	if term == nil {
		return fmt.Errorf("%w: term %s", ErrNotFound, termID)
	}

	// Outbox event
	payload, _ := json.Marshal(term)
	outboxEvent := &outbox.Event{
		EventID:       uuid.New().String(),
		AggregateType: "term",
		AggregateID:   term.TermID.String(),
		EventType:     string(EventTermSetCurrent),
		Payload:       payload,
		Headers:       map[string]string{},
		Status:        "pending",
	}
	if err := s.outboxRepo.Store(ctx, tx, outboxEvent); err != nil {
		return fmt.Errorf("store outbox event: %w", err)
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

	if s.auditService != nil {
		_ = s.auditService.LogAction(ctx, nil, &ay.CompanyID, "academics", "set_current", "term",
			&termID, "user", updatedBy, nil, nil,
			map[string]interface{}{"is_current": true})
	}

	if s.notificationSvc != nil {
		notifReq := s.buildNotificationRequest(term, ay, "set_current", updatedBy)
		s.sendNotification(ctx, notifReq, uuid.New().String())
	}

	logger.Info("term set as current")
	return nil
}

// Delete soft-deletes a term, checking for dependent sections first
func (s *termService) Delete(ctx context.Context, id uuid.UUID, deletedBy *uuid.UUID) error {
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

	// Outbox event
	payload, _ := json.Marshal(term)
	outboxEvent := &outbox.Event{
		EventID:       uuid.New().String(),
		AggregateType: "term",
		AggregateID:   term.TermID.String(),
		EventType:     string(EventTermDeleted),
		Payload:       payload,
		Headers:       map[string]string{},
		Status:        "pending",
	}
	if err := s.outboxRepo.Store(ctx, tx, outboxEvent); err != nil {
		return fmt.Errorf("store outbox event: %w", err)
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

	if s.auditService != nil {
		_ = s.auditService.LogAction(ctx, nil, &ay.CompanyID, "academics", "delete", "term",
			&id, "user", deletedBy, nil, nil,
			map[string]interface{}{"name": term.Name})
	}

	if s.notificationSvc != nil {
		notifReq := s.buildNotificationRequest(term, ay, "deleted", deletedBy)
		s.sendNotification(ctx, notifReq, uuid.New().String())
	}

	logger.Info("term deleted")
	return nil
}

// ValidateTermWithinAcademicYear checks that a term's dates fall inside its academic year
func (s *termService) ValidateTermWithinAcademicYear(ctx context.Context, term *models.Term) error {
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

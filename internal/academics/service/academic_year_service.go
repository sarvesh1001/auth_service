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

// AcademicYearService defines the business operations for academic years.
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

// academicYearService is the concrete implementation.
type academicYearService struct {
	repo                repository.AcademicYearRepository
	pgClient            *client.PostgresClient
	logger              *zap.Logger
	outboxRepo          outbox.Repository
	idempotencyStore    idempotency.Store
	auditService        *audit.AuditService
	notificationService NotificationService
}

// NewAcademicYearService creates a new service instance.
func NewAcademicYearService(
	repo repository.AcademicYearRepository,
	pgClient *client.PostgresClient,
	logger *zap.Logger,
	outboxRepo outbox.Repository,
	idempotencyStore idempotency.Store,
	auditService *audit.AuditService,
	notificationService NotificationService,
) AcademicYearService {
	return &academicYearService{
		repo:                repo,
		pgClient:            pgClient,
		logger:              logger.Named("academic_year_service"),
		outboxRepo:          outboxRepo,
		idempotencyStore:    idempotencyStore,
		auditService:        auditService,
		notificationService: notificationService,
	}
}

// ---------------------------------------------------------------------
// Helper for notification creation
// ---------------------------------------------------------------------

func (s *academicYearService) buildNotificationRequest(
	ay *models.AcademicYear,
	operation string,
	actor *uuid.UUID,
) CreateNotificationRequest {
	var title, message string
	var notificationType models.NotificationType
	priority := models.PriorityNormal

	switch operation {
	case "created":
		title = "New Academic Year Created"
		message = fmt.Sprintf("Academic year '%s' has been created (%s - %s)", ay.Name, ay.StartDate.Format("2006-01-02"), ay.EndDate.Format("2006-01-02"))
		notificationType = models.NotificationTypeInfo
	case "updated":
		title = "Academic Year Updated"
		message = fmt.Sprintf("Academic year '%s' has been updated (%s - %s)", ay.Name, ay.StartDate.Format("2006-01-02"), ay.EndDate.Format("2006-01-02"))
		notificationType = models.NotificationTypeInfo
	case "dates_updated":
		title = "Academic Year Dates Updated"
		message = fmt.Sprintf("Dates for academic year '%s' have been changed to %s - %s", ay.Name, ay.StartDate.Format("2006-01-02"), ay.EndDate.Format("2006-01-02"))
		notificationType = models.NotificationTypeInfo
	case "set_current":
		title = "Academic Year Set as Current"
		message = fmt.Sprintf("Academic year '%s' is now the current academic year", ay.Name)
		notificationType = models.NotificationTypeEvent
		priority = models.PriorityHigh
	case "deleted":
		title = "Academic Year Deleted"
		message = fmt.Sprintf("Academic year '%s' has been deleted", ay.Name)
		notificationType = models.NotificationTypeWarning
		priority = models.PriorityHigh
	default:
		title = "Academic Year Changed"
		message = fmt.Sprintf("Academic year '%s' was modified", ay.Name)
		notificationType = models.NotificationTypeInfo
	}

	return CreateNotificationRequest{
		CompanyID: ay.CompanyID,
		Title:     title,
		Message:   message,
		Type:      notificationType,
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

// ---------------------------------------------------------------------
// Core CRUD Operations
// ---------------------------------------------------------------------

func (s *academicYearService) Create(ctx context.Context, req CreateAcademicYearRequest) (*models.AcademicYear, error) {
	logger := s.logger.With(
		zap.String("method", "Create"),
		zap.String("company_id", req.CompanyID.String()),
		zap.String("name", req.Name),
	)

	// Extract idempotency key once
	idempotencyKey, _ := ctx.Value("idempotency_key").(string)

	if err := s.validateInput(req.CompanyID, req.Name, req.StartDate, req.EndDate); err != nil {
		return nil, err
	}

	tx, err := s.pgClient.BeginTx(ctx, nil)
	if err != nil {
		return nil, fmt.Errorf("begin tx: %w", err)
	}
	defer tx.Rollback()

	// Idempotency check (inside transaction)
	if idempotencyKey != "" {
		var existing *models.AcademicYear
		if err := s.idempotencyStore.Get(ctx, tx, idempotencyKey, &existing); err == nil && existing != nil {
			logger.Info("idempotent request, returning cached response")
			return existing, nil
		}
	}

	// Overlap check
	overlap, err := s.repo.CheckOverlap(ctx, tx, req.CompanyID, req.StartDate, req.EndDate, uuid.Nil)
	if err != nil {
		return nil, fmt.Errorf("overlap check: %w", err)
	}
	if overlap {
		return nil, fmt.Errorf("%w: academic year dates overlap with an existing year", ErrOverlap)
	}

	// Duplicate name check
	exists, err := s.repo.Exists(ctx, tx, req.CompanyID, req.Name)
	if err != nil {
		return nil, fmt.Errorf("check existence: %w", err)
	}
	if exists {
		return nil, fmt.Errorf("%w: academic year name %s already exists", ErrDuplicate, req.Name)
	}

	// If this year should be current, unset any existing current year
	if req.IsCurrent {
		if err := s.repo.UnsetCurrent(ctx, tx, req.CompanyID, req.UpdatedBy); err != nil {
			return nil, fmt.Errorf("unset current: %w", err)
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

	if err := s.repo.Create(ctx, tx, ay); err != nil {
		return nil, err
	}

	// Store idempotency key after successful insert (before commit)
	if idempotencyKey != "" {
		if err := s.idempotencyStore.Store(ctx, tx, idempotencyKey, ay); err != nil {
			logger.Error("failed to store idempotency key", zap.Error(err))
			// Continue – data already inserted; idempotency not critical for correctness
		}
	}

	// Outbox event
	payload, _ := json.Marshal(ay)
	outboxEvent := &outbox.Event{
		EventID:       uuid.New().String(),
		AggregateType: "academic_year",
		AggregateID:   ay.AcademicYearID.String(),
		EventType:     string(EventAcademicYearCreated),
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

	logger.Info("academic year created", zap.String("id", ay.AcademicYearID.String()))

	// Audit logging (after commit – no transaction)
	if s.auditService != nil {
		_ = s.auditService.LogAction(ctx, nil, &req.CompanyID, "academics", "create", "academic_year",
			&ay.AcademicYearID, "user", req.CreatedBy, nil, nil,
			map[string]interface{}{"name": ay.Name})
	}

	// Create notification
	if s.notificationService != nil {
		notifReq := s.buildNotificationRequest(ay, "created", req.CreatedBy)
		if _, err := s.notificationService.Create(ctx, notifReq, uuid.New().String()); err != nil {
			logger.Error("failed to create notification", zap.Error(err))
		}
	}

	return ay, nil
}

func (s *academicYearService) BulkCreate(ctx context.Context, reqs []CreateAcademicYearRequest) ([]*models.AcademicYear, error) {
	if len(reqs) == 0 {
		return nil, nil
	}

	logger := s.logger.With(zap.String("method", "BulkCreate"), zap.Int("batch_size", len(reqs)))
	idempotencyKey, _ := ctx.Value("idempotency_key").(string)

	tx, err := s.pgClient.BeginTx(ctx, nil)
	if err != nil {
		return nil, fmt.Errorf("begin tx: %w", err)
	}
	defer tx.Rollback()

	// Idempotency check (entire bulk operation)
	if idempotencyKey != "" {
		var existing []*models.AcademicYear
		if err := s.idempotencyStore.Get(ctx, tx, idempotencyKey, &existing); err == nil && existing != nil {
			logger.Info("idempotent bulk request, returning cached response")
			return existing, nil
		}
	}

	// Pre-load existing years to avoid duplicate name checks per company
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

		// Check duplicate name in batch
		if batchByName[req.CompanyID] == nil {
			batchByName[req.CompanyID] = make(map[string]bool)
		}
		if batchByName[req.CompanyID][req.Name] {
			return nil, fmt.Errorf("item %d: %w: duplicate name %s in batch", i, ErrDuplicate, req.Name)
		}
		batchByName[req.CompanyID][req.Name] = true

		// Check against existing DB records (name)
		for _, ay := range existingByCompany[req.CompanyID] {
			if ay.Name == req.Name {
				return nil, fmt.Errorf("item %d: %w: name %s already exists", i, ErrDuplicate, req.Name)
			}
		}

		// Overlap check in memory (combine existing + already validated in this batch)
		tempExisting := make([]*models.AcademicYear, 0, len(existingByCompany[req.CompanyID])+len(years))
		tempExisting = append(tempExisting, existingByCompany[req.CompanyID]...)
		for _, ay := range years {
			if ay.CompanyID == req.CompanyID {
				tempExisting = append(tempExisting, ay)
			}
		}
		if err := s.checkOverlapInMemory(tempExisting, req.StartDate, req.EndDate, uuid.Nil); err != nil {
			return nil, fmt.Errorf("item %d: %w", i, err)
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

	// Bulk insert
	if err := s.repo.BulkCreate(ctx, tx, years); err != nil {
		return nil, err
	}

	// Store idempotency key after successful insert
	if idempotencyKey != "" {
		if err := s.idempotencyStore.Store(ctx, tx, idempotencyKey, years); err != nil {
			logger.Error("failed to store idempotency key", zap.Error(err))
		}
	}

	// Store outbox events for each created year
	for _, ay := range years {
		payload, _ := json.Marshal(ay)
		outboxEvent := &outbox.Event{
			EventID:       uuid.New().String(),
			AggregateType: "academic_year",
			AggregateID:   ay.AcademicYearID.String(),
			EventType:     string(EventAcademicYearCreated),
			Payload:       payload,
			Status:        "pending",
		}
		if err := s.outboxRepo.Store(ctx, tx, outboxEvent); err != nil {
			return nil, fmt.Errorf("store outbox event for %s: %w", ay.AcademicYearID, err)
		}
	}

	if err := tx.Commit(); err != nil {
		return nil, fmt.Errorf("commit tx: %w", err)
	}

	logger.Info("bulk created academic years", zap.Int("count", len(years)))

	// Audit each (optional)
	if s.auditService != nil {
		for _, ay := range years {
			_ = s.auditService.LogAction(ctx, nil, &ay.CompanyID, "academics", "bulk_create", "academic_year",
				&ay.AcademicYearID, "user", ay.CreatedBy, nil, nil, nil)
		}
	}

	// Create notifications
	if s.notificationService != nil {
		for _, ay := range years {
			notifReq := s.buildNotificationRequest(ay, "created", ay.CreatedBy)
			if _, err := s.notificationService.Create(ctx, notifReq, uuid.New().String()); err != nil {
				logger.Error("failed to create notification for year",
					zap.String("id", ay.AcademicYearID.String()),
					zap.Error(err))
			}
		}
	}

	return years, nil
}

func (s *academicYearService) Upsert(ctx context.Context, req CreateAcademicYearRequest) (*models.AcademicYear, error) {
	logger := s.logger.With(
		zap.String("method", "Upsert"),
		zap.String("company_id", req.CompanyID.String()),
		zap.String("name", req.Name),
	)
	idempotencyKey, _ := ctx.Value("idempotency_key").(string)

	if err := s.validateInput(req.CompanyID, req.Name, req.StartDate, req.EndDate); err != nil {
		return nil, err
	}

	tx, err := s.pgClient.BeginTx(ctx, nil)
	if err != nil {
		return nil, fmt.Errorf("begin tx: %w", err)
	}
	defer tx.Rollback()

	// Idempotency check
	if idempotencyKey != "" {
		var existing *models.AcademicYear
		if err := s.idempotencyStore.Get(ctx, tx, idempotencyKey, &existing); err == nil && existing != nil {
			logger.Info("idempotent request, returning cached response")
			return existing, nil
		}
	}

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
	var operation string
	if existing == nil {
		eventType = EventAcademicYearCreated
		operation = "created"
	} else {
		eventType = EventAcademicYearUpdated
		operation = "updated"
	}

	if err := s.repo.Upsert(ctx, tx, ay); err != nil {
		return nil, err
	}

	// Store idempotency key after successful upsert
	if idempotencyKey != "" {
		if err := s.idempotencyStore.Store(ctx, tx, idempotencyKey, ay); err != nil {
			logger.Error("failed to store idempotency key", zap.Error(err))
		}
	}

	payload, _ := json.Marshal(ay)
	outboxEvent := &outbox.Event{
		EventID:       uuid.New().String(),
		AggregateType: "academic_year",
		AggregateID:   ay.AcademicYearID.String(),
		EventType:     string(eventType),
		Payload:       payload,
		Status:        "pending",
	}
	if err := s.outboxRepo.Store(ctx, tx, outboxEvent); err != nil {
		return nil, fmt.Errorf("store outbox event: %w", err)
	}

	if err := tx.Commit(); err != nil {
		return nil, fmt.Errorf("commit tx: %w", err)
	}

	logger.Info("academic year upserted", zap.String("id", ay.AcademicYearID.String()))

	if s.auditService != nil {
		_ = s.auditService.LogAction(ctx, nil, &req.CompanyID, "academics", "upsert", "academic_year",
			&ay.AcademicYearID, "user", req.CreatedBy, nil, nil, map[string]interface{}{"name": ay.Name})
	}

	if s.notificationService != nil {
		notifReq := s.buildNotificationRequest(ay, operation, req.CreatedBy)
		if _, err := s.notificationService.Create(ctx, notifReq, uuid.New().String()); err != nil {
			logger.Error("failed to create notification", zap.Error(err))
		}
	}

	return ay, nil
}

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

func (s *academicYearService) List(ctx context.Context, filter repository.AcademicYearFilter, p repository.Pagination, srt repository.Sort) ([]*models.AcademicYear, error) {
	logger := s.logger.With(zap.String("method", "List"))
	logger.Debug("listing academic years")
	return s.repo.List(ctx, s.pgClient.DB, filter, p, srt)
}

func (s *academicYearService) ListByCompany(ctx context.Context, companyID uuid.UUID) ([]*models.AcademicYear, error) {
	logger := s.logger.With(zap.String("method", "ListByCompany"), zap.String("company_id", companyID.String()))
	logger.Debug("listing academic years for company")
	return s.repo.ListByCompany(ctx, s.pgClient.DB, companyID)
}

func (s *academicYearService) Count(ctx context.Context, filter repository.AcademicYearFilter) (int64, error) {
	logger := s.logger.With(zap.String("method", "Count"))
	logger.Debug("counting academic years")
	return s.repo.Count(ctx, s.pgClient.DB, filter)
}

func (s *academicYearService) Exists(ctx context.Context, companyID uuid.UUID, name string) (bool, error) {
	logger := s.logger.With(zap.String("method", "Exists"), zap.String("company_id", companyID.String()), zap.String("name", name))
	logger.Debug("checking existence")
	return s.repo.Exists(ctx, s.pgClient.DB, companyID, name)
}

func (s *academicYearService) Update(ctx context.Context, req UpdateAcademicYearRequest) (*models.AcademicYear, error) {
	logger := s.logger.With(zap.String("method", "Update"), zap.String("id", req.AcademicYearID.String()))
	idempotencyKey, _ := ctx.Value("idempotency_key").(string)

	tx, err := s.pgClient.BeginTx(ctx, nil)
	if err != nil {
		return nil, fmt.Errorf("begin tx: %w", err)
	}
	defer tx.Rollback()

	// Idempotency check
	if idempotencyKey != "" {
		var existing *models.AcademicYear
		if err := s.idempotencyStore.Get(ctx, tx, idempotencyKey, &existing); err == nil && existing != nil {
			logger.Info("idempotent request, returning cached response")
			return existing, nil
		}
	}

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

	// Store idempotency key after successful update
	if idempotencyKey != "" {
		if err := s.idempotencyStore.Store(ctx, tx, idempotencyKey, existing); err != nil {
			logger.Error("failed to store idempotency key", zap.Error(err))
		}
	}

	payload, _ := json.Marshal(existing)
	outboxEvent := &outbox.Event{
		EventID:       uuid.New().String(),
		AggregateType: "academic_year",
		AggregateID:   existing.AcademicYearID.String(),
		EventType:     string(EventAcademicYearUpdated),
		Payload:       payload,
		Status:        "pending",
	}
	if err := s.outboxRepo.Store(ctx, tx, outboxEvent); err != nil {
		return nil, fmt.Errorf("store outbox event: %w", err)
	}

	if err := tx.Commit(); err != nil {
		return nil, fmt.Errorf("commit tx: %w", err)
	}

	logger.Info("academic year updated")

	if s.auditService != nil {
		_ = s.auditService.LogAction(ctx, nil, &existing.CompanyID, "academics", "update", "academic_year",
			&existing.AcademicYearID, "user", req.UpdatedBy, nil, nil, nil)
	}

	if s.notificationService != nil {
		notifReq := s.buildNotificationRequest(existing, "updated", req.UpdatedBy)
		if _, err := s.notificationService.Create(ctx, notifReq, uuid.New().String()); err != nil {
			logger.Error("failed to create notification", zap.Error(err))
		}
	}

	return existing, nil
}

func (s *academicYearService) UpdateDates(ctx context.Context, id uuid.UUID, start, end time.Time, updatedBy *uuid.UUID) error {
	logger := s.logger.With(zap.String("method", "UpdateDates"), zap.String("id", id.String()))
	// Idempotency not implemented for this method because it's a partial update.
	// Could be added if needed.

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

	updatedAy, err := s.repo.GetByID(ctx, tx, id)
	if err != nil {
		return err
	}
	if updatedAy == nil {
		return fmt.Errorf("%w: academic year %s after update", ErrNotFound, id)
	}

	payload, _ := json.Marshal(updatedAy)
	outboxEvent := &outbox.Event{
		EventID:       uuid.New().String(),
		AggregateType: "academic_year",
		AggregateID:   updatedAy.AcademicYearID.String(),
		EventType:     string(EventAcademicYearUpdated),
		Payload:       payload,
		Status:        "pending",
	}
	if err := s.outboxRepo.Store(ctx, tx, outboxEvent); err != nil {
		return fmt.Errorf("store outbox event: %w", err)
	}

	if err := tx.Commit(); err != nil {
		return fmt.Errorf("commit tx: %w", err)
	}

	logger.Info("academic year dates updated")

	if s.auditService != nil {
		_ = s.auditService.LogAction(ctx, nil, &ay.CompanyID, "academics", "update_dates", "academic_year",
			&id, "user", updatedBy, nil, nil, map[string]interface{}{"start_date": start, "end_date": end})
	}

	if s.notificationService != nil {
		notifReq := s.buildNotificationRequest(updatedAy, "dates_updated", updatedBy)
		if _, err := s.notificationService.Create(ctx, notifReq, uuid.New().String()); err != nil {
			logger.Error("failed to create notification", zap.Error(err))
		}
	}

	return nil
}

func (s *academicYearService) SetCurrent(ctx context.Context, companyID, academicYearID uuid.UUID, updatedBy *uuid.UUID) error {
	logger := s.logger.With(zap.String("method", "SetCurrent"), zap.String("company_id", companyID.String()), zap.String("id", academicYearID.String()))
	// Idempotency not critical for this operation.

	tx, err := s.pgClient.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("begin tx: %w", err)
	}
	defer tx.Rollback()

	if err := s.repo.SetCurrent(ctx, tx, companyID, academicYearID, updatedBy); err != nil {
		return err
	}

	ay, err := s.repo.GetByID(ctx, tx, academicYearID)
	if err != nil {
		return err
	}
	if ay == nil {
		return fmt.Errorf("%w: academic year %s", ErrNotFound, academicYearID)
	}

	payload, _ := json.Marshal(ay)
	outboxEvent := &outbox.Event{
		EventID:       uuid.New().String(),
		AggregateType: "academic_year",
		AggregateID:   ay.AcademicYearID.String(),
		EventType:     string(EventAcademicYearSetCurrent),
		Payload:       payload,
		Status:        "pending",
	}
	if err := s.outboxRepo.Store(ctx, tx, outboxEvent); err != nil {
		return fmt.Errorf("store outbox event: %w", err)
	}

	if err := tx.Commit(); err != nil {
		return fmt.Errorf("commit tx: %w", err)
	}

	logger.Info("academic year set as current")

	if s.auditService != nil {
		_ = s.auditService.LogAction(ctx, nil, &companyID, "academics", "set_current", "academic_year",
			&academicYearID, "user", updatedBy, nil, nil, map[string]interface{}{"is_current": true})
	}

	if s.notificationService != nil {
		notifReq := s.buildNotificationRequest(ay, "set_current", updatedBy)
		if _, err := s.notificationService.Create(ctx, notifReq, uuid.New().String()); err != nil {
			logger.Error("failed to create notification", zap.Error(err))
		}
	}

	return nil
}

func (s *academicYearService) Delete(ctx context.Context, id uuid.UUID, deletedBy *uuid.UUID) error {
	logger := s.logger.With(zap.String("method", "Delete"), zap.String("id", id.String()))
	// Idempotency not needed for delete (deleting twice should be harmless or return not found).

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

	if err := s.repo.Delete(ctx, tx, id, deletedBy); err != nil {
		return err
	}

	payload, _ := json.Marshal(ay)
	outboxEvent := &outbox.Event{
		EventID:       uuid.New().String(),
		AggregateType: "academic_year",
		AggregateID:   ay.AcademicYearID.String(),
		EventType:     string(EventAcademicYearDeleted),
		Payload:       payload,
		Status:        "pending",
	}
	if err := s.outboxRepo.Store(ctx, tx, outboxEvent); err != nil {
		return fmt.Errorf("store outbox event: %w", err)
	}

	if err := tx.Commit(); err != nil {
		return fmt.Errorf("commit tx: %w", err)
	}

	logger.Info("academic year deleted")

	if s.auditService != nil {
		_ = s.auditService.LogAction(ctx, nil, &ay.CompanyID, "academics", "delete", "academic_year",
			&id, "user", deletedBy, nil, nil, nil)
	}

	if s.notificationService != nil {
		notifReq := s.buildNotificationRequest(ay, "deleted", deletedBy)
		if _, err := s.notificationService.Create(ctx, notifReq, uuid.New().String()); err != nil {
			logger.Error("failed to create notification", zap.Error(err))
		}
	}

	return nil
}

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

func (s *academicYearService) checkOverlapInMemory(years []*models.AcademicYear, start, end time.Time, excludeID uuid.UUID) error {
	for _, ay := range years {
		if excludeID != uuid.Nil && ay.AcademicYearID == excludeID {
			continue
		}
		if !(start.After(ay.EndDate) || end.Before(ay.StartDate)) {
			return fmt.Errorf("%w: overlaps with %s (%s - %s)", ErrOverlap, ay.Name, ay.StartDate, ay.EndDate)
		}
	}
	return nil
}

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

// AdmissionService defines business operations for admissions.
type AdmissionService interface {
	Create(ctx context.Context, req CreateAdmissionRequest) (*models.Admission, error)
	BulkCreate(ctx context.Context, req []CreateAdmissionRequest) ([]*models.Admission, error)
	GetByID(ctx context.Context, id uuid.UUID) (*models.Admission, error)
	GetByStudentID(ctx context.Context, studentID uuid.UUID) ([]*models.Admission, error)
	GetByAcademicYearID(ctx context.Context, academicYearID uuid.UUID) ([]*models.Admission, error)
	GetByStudentAndYear(ctx context.Context, studentID, academicYearID uuid.UUID) (*models.Admission, error)
	List(ctx context.Context, filter repository.AdmissionFilter, p repository.Pagination, s repository.Sort) ([]*models.Admission, error)
	Count(ctx context.Context, filter repository.AdmissionFilter) (int64, error)
	Update(ctx context.Context, req UpdateAdmissionRequest) (*models.Admission, error)
	UpdateStatus(ctx context.Context, id uuid.UUID, status string, updatedBy *uuid.UUID) error
	Delete(ctx context.Context, id uuid.UUID) error
}

// CreateAdmissionRequest holds data for creating an admission.
type CreateAdmissionRequest struct {
	StudentID       uuid.UUID `json:"student_id"`
	AcademicYearID  uuid.UUID `json:"academic_year_id"`
	AdmissionDate   time.Time `json:"admission_date"`
	ClassAppliedFor string    `json:"class_applied_for,omitempty"`
	AdmissionStatus string    `json:"admission_status"` // pending, approved, rejected
	Remarks         string    `json:"remarks,omitempty"`
	CreatedBy       *uuid.UUID
	UpdatedBy       *uuid.UUID
	// For idempotency – optional
	IdempotencyKey string `json:"-"`
}

// UpdateAdmissionRequest holds data for updating an admission.
type UpdateAdmissionRequest struct {
	AdmissionID     uuid.UUID  `json:"admission_id"`
	StudentID       uuid.UUID  `json:"student_id"`
	AcademicYearID  uuid.UUID  `json:"academic_year_id"`
	AdmissionDate   time.Time  `json:"admission_date"`
	ClassAppliedFor string     `json:"class_applied_for,omitempty"`
	AdmissionStatus string     `json:"admission_status"`
	Remarks         string     `json:"remarks,omitempty"`
	UpdatedBy       *uuid.UUID `json:"updated_by,omitempty"`
}

type admissionService struct {
	repo             repository.AdmissionRepository
	pgClient         *client.PostgresClient
	logger           *zap.Logger
	outboxRepo       outbox.Repository
	idempotencyStore idempotency.Store
	auditService     *audit.AuditService
	notificationSvc  NotificationService
}

// NewAdmissionService creates a new service instance.
func NewAdmissionService(
	repo repository.AdmissionRepository,
	pgClient *client.PostgresClient,
	logger *zap.Logger,
	outboxRepo outbox.Repository,
	idempotencyStore idempotency.Store,
	auditService *audit.AuditService,
	notificationSvc NotificationService,
) AdmissionService {
	return &admissionService{
		repo:             repo,
		pgClient:         pgClient,
		logger:           logger.Named("admission_service"),
		outboxRepo:       outboxRepo,
		idempotencyStore: idempotencyStore,
		auditService:     auditService,
		notificationSvc:  notificationSvc,
	}
}

// ----------------------------------------------------------------------
// Create
// ----------------------------------------------------------------------

func (s *admissionService) Create(ctx context.Context, req CreateAdmissionRequest) (*models.Admission, error) {
	logger := s.logger.With(
		zap.String("method", "Create"),
		zap.String("student_id", req.StudentID.String()),
		zap.String("academic_year_id", req.AcademicYearID.String()),
	)

	// Idempotency handling
	if req.IdempotencyKey != "" {
		var existing *models.Admission
		if err := s.idempotencyStore.Get(ctx, nil, req.IdempotencyKey, &existing); err == nil && existing != nil {
			logger.Info("idempotent request, returning cached response")
			return existing, nil
		}
	}

	// Validate input
	if err := s.validateCreate(req); err != nil {
		return nil, err
	}

	tx, err := s.pgClient.BeginTx(ctx, nil)
	if err != nil {
		return nil, fmt.Errorf("begin tx: %w", err)
	}
	defer tx.Rollback()

	// Check if admission already exists for this student & year
	existing, _ := s.repo.GetByStudentAndYear(ctx, tx, req.StudentID, req.AcademicYearID)
	if existing != nil {
		return nil, fmt.Errorf("%w: admission already exists for student %s and year %s", ErrDuplicate, req.StudentID, req.AcademicYearID)
	}

	admission := &models.Admission{
		StudentID:       req.StudentID,
		AcademicYearID:  req.AcademicYearID,
		AdmissionDate:   req.AdmissionDate,
		ClassAppliedFor: req.ClassAppliedFor,
		AdmissionStatus: models.AdmissionStatus(req.AdmissionStatus),
		Remarks:         req.Remarks,
		CreatedBy:       req.CreatedBy,
	}

	if err := s.repo.Create(ctx, tx, admission); err != nil {
		return nil, err
	}

	// Store outbox event
	payload, _ := json.Marshal(admission)
	outboxEvent := &outbox.Event{
		EventID:       uuid.New().String(),
		AggregateType: "admission",
		AggregateID:   admission.AdmissionID.String(),
		EventType:     string(EventAdmissionCreated),
		Payload:       payload,
		Headers:       map[string]string{},
		Status:        "pending",
	}
	if err := s.outboxRepo.Store(ctx, tx, outboxEvent); err != nil {
		return nil, fmt.Errorf("store outbox event: %w", err)
	}

	// Prepare data for notification (we need company ID)
	var companyID uuid.UUID
	if err := tx.QueryRowContext(ctx, "SELECT company_id FROM academics.students WHERE student_id = $1", admission.StudentID).Scan(&companyID); err != nil {
		logger.Error("failed to fetch student company ID for notification", zap.Error(err))
		// Non-fatal, continue
	}

	if err := tx.Commit(); err != nil {
		return nil, fmt.Errorf("commit tx: %w", err)
	}

	logger.Info("admission created", zap.String("id", admission.AdmissionID.String()))

	// Audit after commit
	if s.auditService != nil {
		_ = s.auditService.LogAction(ctx, nil, nil, "academics", "create", "admission",
			&admission.AdmissionID, "user", req.CreatedBy, nil, nil,
			map[string]interface{}{"student_id": admission.StudentID, "academic_year_id": admission.AcademicYearID})
	}

	// Store idempotency key response
	if req.IdempotencyKey != "" {
		_ = s.idempotencyStore.Store(ctx, nil, req.IdempotencyKey, admission)
	}

	// Send notification asynchronously (after commit to avoid nested tx)
	if companyID != uuid.Nil {
		go func() {
			if err := s.sendAdmissionNotification(context.Background(), admission, companyID, "created"); err != nil {
				logger.Error("failed to send admission notification", zap.Error(err))
			}
		}()
	}

	return admission, nil
}

// ----------------------------------------------------------------------
// BulkCreate
// ----------------------------------------------------------------------

func (s *admissionService) BulkCreate(ctx context.Context, reqs []CreateAdmissionRequest) ([]*models.Admission, error) {
	if len(reqs) == 0 {
		return nil, nil
	}

	logger := s.logger.With(zap.String("method", "BulkCreate"), zap.Int("batch_size", len(reqs)))

	// Validate all before transaction
	for i, req := range reqs {
		if err := s.validateCreate(req); err != nil {
			return nil, fmt.Errorf("item %d: %w", i, err)
		}
	}

	tx, err := s.pgClient.BeginTx(ctx, nil)
	if err != nil {
		return nil, fmt.Errorf("begin tx: %w", err)
	}
	defer tx.Rollback()

	// Check for duplicates within batch and with existing DB records
	existingMap := make(map[string]bool) // key = student_id:academic_year_id
	for i, req := range reqs {
		key := fmt.Sprintf("%s:%s", req.StudentID.String(), req.AcademicYearID.String())
		if existingMap[key] {
			return nil, fmt.Errorf("item %d: duplicate admission in batch for student %s and year %s", i, req.StudentID, req.AcademicYearID)
		}
		existingMap[key] = true

		// Check DB
		existing, _ := s.repo.GetByStudentAndYear(ctx, tx, req.StudentID, req.AcademicYearID)
		if existing != nil {
			return nil, fmt.Errorf("item %d: admission already exists for student %s and year %s", i, req.StudentID, req.AcademicYearID)
		}
	}

	admissions := make([]*models.Admission, len(reqs))
	for i, req := range reqs {
		admissions[i] = &models.Admission{
			StudentID:       req.StudentID,
			AcademicYearID:  req.AcademicYearID,
			AdmissionDate:   req.AdmissionDate,
			ClassAppliedFor: req.ClassAppliedFor,
			AdmissionStatus: models.AdmissionStatus(req.AdmissionStatus),
			Remarks:         req.Remarks,
			CreatedBy:       req.CreatedBy,
		}
	}

	if err := s.repo.BulkCreate(ctx, tx, admissions); err != nil {
		return nil, err
	}

	// Outbox events & collect company IDs for notifications
	companyIDs := make(map[uuid.UUID]uuid.UUID) // admissionID -> companyID
	for _, admission := range admissions {
		payload, _ := json.Marshal(admission)
		outboxEvent := &outbox.Event{
			EventID:       uuid.New().String(),
			AggregateType: "admission",
			AggregateID:   admission.AdmissionID.String(),
			EventType:     string(EventAdmissionCreated),
			Payload:       payload,
			Status:        "pending",
		}
		if err := s.outboxRepo.Store(ctx, tx, outboxEvent); err != nil {
			return nil, fmt.Errorf("store outbox event for %s: %w", admission.AdmissionID, err)
		}

		var companyID uuid.UUID
		if err := tx.QueryRowContext(ctx, "SELECT company_id FROM academics.students WHERE student_id = $1", admission.StudentID).Scan(&companyID); err != nil {
			logger.Error("failed to fetch student company ID", zap.String("student_id", admission.StudentID.String()), zap.Error(err))
		}
		if companyID != uuid.Nil {
			companyIDs[admission.AdmissionID] = companyID
		}
	}

	if err := tx.Commit(); err != nil {
		return nil, fmt.Errorf("commit tx: %w", err)
	}

	logger.Info("bulk created admissions", zap.Int("count", len(admissions)))

	// Audit each (optional)
	if s.auditService != nil {
		for _, a := range admissions {
			_ = s.auditService.LogAction(ctx, nil, nil, "academics", "bulk_create", "admission",
				&a.AdmissionID, "user", a.CreatedBy, nil, nil, nil)
		}
	}

	// Send notifications asynchronously
	for _, a := range admissions {
		if cid, ok := companyIDs[a.AdmissionID]; ok {
			go func(admission *models.Admission, companyID uuid.UUID) {
				if err := s.sendAdmissionNotification(context.Background(), admission, companyID, "created"); err != nil {
					logger.Error("failed to send admission notification", zap.String("admission_id", admission.AdmissionID.String()), zap.Error(err))
				}
			}(a, cid)
		}
	}

	return admissions, nil
}

// ----------------------------------------------------------------------
// GetByID
// ----------------------------------------------------------------------

func (s *admissionService) GetByID(ctx context.Context, id uuid.UUID) (*models.Admission, error) {
	admission, err := s.repo.GetByID(ctx, s.pgClient.DB, id)
	if err != nil {
		return nil, err
	}
	if admission == nil {
		return nil, fmt.Errorf("%w: admission %s", ErrNotFound, id)
	}
	s.logger.Debug("admission retrieved", zap.String("id", id.String()))
	return admission, nil
}

// GetByStudentID retrieves all admissions for a student.
func (s *admissionService) GetByStudentID(ctx context.Context, studentID uuid.UUID) ([]*models.Admission, error) {
	s.logger.Debug("getting admissions by student", zap.String("student_id", studentID.String()))
	return s.repo.GetByStudentID(ctx, s.pgClient.DB, studentID)
}

// GetByAcademicYearID retrieves all admissions for an academic year.
func (s *admissionService) GetByAcademicYearID(ctx context.Context, academicYearID uuid.UUID) ([]*models.Admission, error) {
	s.logger.Debug("getting admissions by academic year", zap.String("academic_year_id", academicYearID.String()))
	return s.repo.GetByAcademicYearID(ctx, s.pgClient.DB, academicYearID)
}

// GetByStudentAndYear retrieves an admission for a specific student and academic year.
func (s *admissionService) GetByStudentAndYear(ctx context.Context, studentID, academicYearID uuid.UUID) (*models.Admission, error) {
	s.logger.Debug("getting admission by student and year",
		zap.String("student_id", studentID.String()),
		zap.String("academic_year_id", academicYearID.String()))
	return s.repo.GetByStudentAndYear(ctx, s.pgClient.DB, studentID, academicYearID)
}

// List returns paginated admissions based on filter and sort.
func (s *admissionService) List(ctx context.Context, filter repository.AdmissionFilter, p repository.Pagination, srt repository.Sort) ([]*models.Admission, error) {
	s.logger.Debug("listing admissions")
	return s.repo.List(ctx, s.pgClient.DB, filter, p, srt)
}

// Count returns total count of admissions matching filter.
func (s *admissionService) Count(ctx context.Context, filter repository.AdmissionFilter) (int64, error) {
	s.logger.Debug("counting admissions")
	return s.repo.Count(ctx, s.pgClient.DB, filter)
}

// ----------------------------------------------------------------------
// Update
// ----------------------------------------------------------------------

func (s *admissionService) Update(ctx context.Context, req UpdateAdmissionRequest) (*models.Admission, error) {
	logger := s.logger.With(zap.String("method", "Update"), zap.String("id", req.AdmissionID.String()))

	tx, err := s.pgClient.BeginTx(ctx, nil)
	if err != nil {
		return nil, fmt.Errorf("begin tx: %w", err)
	}
	defer tx.Rollback()

	existing, err := s.repo.GetByID(ctx, tx, req.AdmissionID)
	if err != nil {
		return nil, err
	}
	if existing == nil {
		return nil, fmt.Errorf("%w: admission %s", ErrNotFound, req.AdmissionID)
	}

	// Remember old status for notification
	oldStatus := existing.AdmissionStatus

	// Update fields
	existing.StudentID = req.StudentID
	existing.AcademicYearID = req.AcademicYearID
	existing.AdmissionDate = req.AdmissionDate
	existing.ClassAppliedFor = req.ClassAppliedFor
	existing.AdmissionStatus = models.AdmissionStatus(req.AdmissionStatus)
	existing.Remarks = req.Remarks

	if err := s.repo.Update(ctx, tx, existing); err != nil {
		return nil, err
	}

	// Outbox event
	payload, _ := json.Marshal(existing)
	outboxEvent := &outbox.Event{
		EventID:       uuid.New().String(),
		AggregateType: "admission",
		AggregateID:   existing.AdmissionID.String(),
		EventType:     string(EventAdmissionUpdated),
		Payload:       payload,
		Status:        "pending",
	}
	if err := s.outboxRepo.Store(ctx, tx, outboxEvent); err != nil {
		return nil, fmt.Errorf("store outbox event: %w", err)
	}

	// Fetch company ID for notification if status changed
	var companyID uuid.UUID
	statusChanged := existing.AdmissionStatus != oldStatus
	if statusChanged {
		if err := tx.QueryRowContext(ctx, "SELECT company_id FROM academics.students WHERE student_id = $1", existing.StudentID).Scan(&companyID); err != nil {
			logger.Error("failed to fetch student company ID", zap.Error(err))
		}
	}

	if err := tx.Commit(); err != nil {
		return nil, fmt.Errorf("commit tx: %w", err)
	}

	logger.Info("admission updated")

	if s.auditService != nil {
		_ = s.auditService.LogAction(ctx, nil, nil, "academics", "update", "admission",
			&existing.AdmissionID, "user", req.UpdatedBy, nil, nil,
			map[string]interface{}{"status": existing.AdmissionStatus})
	}

	// Send notification after commit if status changed
	if statusChanged && companyID != uuid.Nil {
		go func() {
			if err := s.sendAdmissionNotification(context.Background(), existing, companyID, "status_updated"); err != nil {
				logger.Error("failed to send status update notification", zap.Error(err))
			}
		}()
	}

	return existing, nil
}

// ----------------------------------------------------------------------
// UpdateStatus
// ----------------------------------------------------------------------

func (s *admissionService) UpdateStatus(ctx context.Context, id uuid.UUID, status string, updatedBy *uuid.UUID) error {
	logger := s.logger.With(
		zap.String("method", "UpdateStatus"),
		zap.String("id", id.String()),
		zap.String("status", status),
	)

	tx, err := s.pgClient.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("begin tx: %w", err)
	}
	defer tx.Rollback()

	existing, err := s.repo.GetByID(ctx, tx, id)
	if err != nil {
		return err
	}
	if existing == nil {
		return fmt.Errorf("%w: admission %s", ErrNotFound, id)
	}

	oldStatus := existing.AdmissionStatus
	if string(oldStatus) == status {
		return nil // no change
	}

	if err := s.repo.UpdateStatus(ctx, tx, id, status, updatedBy); err != nil {
		return err
	}

	// Fetch updated admission for outbox event
	updated, err := s.repo.GetByID(ctx, tx, id)
	if err != nil {
		return err
	}

	payload, _ := json.Marshal(updated)
	outboxEvent := &outbox.Event{
		EventID:       uuid.New().String(),
		AggregateType: "admission",
		AggregateID:   updated.AdmissionID.String(),
		EventType:     string(EventAdmissionStatusUpdated),
		Payload:       payload,
		Status:        "pending",
	}
	if err := s.outboxRepo.Store(ctx, tx, outboxEvent); err != nil {
		return fmt.Errorf("store outbox event: %w", err)
	}

	// Fetch company ID for notification
	var companyID uuid.UUID
	if err := tx.QueryRowContext(ctx, "SELECT company_id FROM academics.students WHERE student_id = $1", updated.StudentID).Scan(&companyID); err != nil {
		logger.Error("failed to fetch student company ID", zap.Error(err))
	}

	if err := tx.Commit(); err != nil {
		return fmt.Errorf("commit tx: %w", err)
	}

	logger.Info("admission status updated")

	if s.auditService != nil {
		_ = s.auditService.LogAction(ctx, nil, nil, "academics", "update_status", "admission",
			&id, "user", updatedBy, nil, nil, map[string]interface{}{"new_status": status})
	}

	// Send notification after commit
	if companyID != uuid.Nil {
		go func() {
			if err := s.sendAdmissionNotification(context.Background(), updated, companyID, "status_updated"); err != nil {
				logger.Error("failed to send status update notification", zap.Error(err))
			}
		}()
	}

	return nil
}

// ----------------------------------------------------------------------
// Delete
// ----------------------------------------------------------------------

func (s *admissionService) Delete(ctx context.Context, id uuid.UUID) error {
	logger := s.logger.With(zap.String("method", "Delete"), zap.String("id", id.String()))

	tx, err := s.pgClient.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("begin tx: %w", err)
	}
	defer tx.Rollback()

	existing, err := s.repo.GetByID(ctx, tx, id)
	if err != nil {
		return err
	}
	if existing == nil {
		return fmt.Errorf("%w: admission %s", ErrNotFound, id)
	}

	if err := s.repo.Delete(ctx, tx, id); err != nil {
		return err
	}

	// Outbox event for deletion
	payload, _ := json.Marshal(existing)
	outboxEvent := &outbox.Event{
		EventID:       uuid.New().String(),
		AggregateType: "admission",
		AggregateID:   existing.AdmissionID.String(),
		EventType:     string(EventAdmissionDeleted),
		Payload:       payload,
		Status:        "pending",
	}
	if err := s.outboxRepo.Store(ctx, tx, outboxEvent); err != nil {
		return fmt.Errorf("store outbox event: %w", err)
	}

	if err := tx.Commit(); err != nil {
		return fmt.Errorf("commit tx: %w", err)
	}

	logger.Info("admission deleted")

	if s.auditService != nil {
		_ = s.auditService.LogAction(ctx, nil, nil, "academics", "delete", "admission",
			&id, "user", nil, nil, nil, nil)
	}

	return nil
}

// ----------------------------------------------------------------------
// Private helpers
// ----------------------------------------------------------------------

func (s *admissionService) validateCreate(req CreateAdmissionRequest) error {
	if req.StudentID == uuid.Nil {
		return fmt.Errorf("%w: student_id is required", ErrInvalidInput)
	}
	if req.AcademicYearID == uuid.Nil {
		return fmt.Errorf("%w: academic_year_id is required", ErrInvalidInput)
	}
	if req.AdmissionDate.IsZero() {
		return fmt.Errorf("%w: admission_date is required", ErrInvalidInput)
	}
	if req.AdmissionStatus == "" {
		req.AdmissionStatus = string(models.AdmissionStatusPending)
	}
	if !models.IsValidAdmissionStatus(req.AdmissionStatus) {
		return fmt.Errorf("%w: invalid admission_status %q", ErrInvalidInput, req.AdmissionStatus)
	}
	return nil
}

// sendAdmissionNotification creates a notification for the admission event.
// This function is meant to be called after the main transaction has committed,
// so it uses its own transaction.
func (s *admissionService) sendAdmissionNotification(ctx context.Context, admission *models.Admission, companyID uuid.UUID, event string) error {
	// Determine target – the student (and possibly guardians). For now, just student.
	targets := []NotificationTargetInput{
		{
			TargetType:     models.TargetStudent,
			TargetEntityID: admission.StudentID,
		},
	}

	var title, message string
	switch event {
	case "created":
		title = "Admission Created"
		message = fmt.Sprintf("Your admission has been submitted for review.")
	case "status_updated":
		title = "Admission Status Updated"
		message = fmt.Sprintf("Your admission status has been updated to %s.", admission.AdmissionStatus)
	default:
		return nil
	}

	notifReq := CreateNotificationRequest{
		CompanyID: companyID,
		Title:     title,
		Message:   message,
		Type:      models.NotificationTypeInfo,
		Priority:  models.PriorityNormal,
		Targets:   targets,
		CreatedBy: admission.CreatedBy,
	}

	// Note: notificationSvc.Create will start its own transaction.
	// This is safe because this function is called after the main transaction committed.
	_, err := s.notificationSvc.Create(ctx, notifReq, "")
	return err
}

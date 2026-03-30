package service

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"time"

	"github.com/google/uuid"
	"go.uber.org/zap"

	"auth-service/internal/academics/models"
	"auth-service/internal/academics/repository"
	"auth-service/internal/client"
)

// ---------------------------------------------------------------------
// Enrollment status constants (matching repository)
// ---------------------------------------------------------------------

const (
	EnrollmentStatusActive    = "active"
	EnrollmentStatusCompleted = "completed"
	EnrollmentStatusWithdrawn = "withdrawn"
)

// ---------------------------------------------------------------------
// Event types (outbox)
// ---------------------------------------------------------------------

type EnrollmentEventType string

const (
	EventEnrollmentCreated     EnrollmentEventType = "enrollment.created"
	EventEnrollmentUpdated     EnrollmentEventType = "enrollment.updated"
	EventEnrollmentDeleted     EnrollmentEventType = "enrollment.deleted"
	EventEnrollmentActivated   EnrollmentEventType = "enrollment.activated"
	EventEnrollmentCompleted   EnrollmentEventType = "enrollment.completed"
	EventEnrollmentWithdrawn   EnrollmentEventType = "enrollment.withdrawn"
	EventEnrollmentTransferred EnrollmentEventType = "enrollment.transferred"
	EventEnrollmentPromoted    EnrollmentEventType = "enrollment.promoted"
)

// ---------------------------------------------------------------------
// Request/Response DTOs
// ---------------------------------------------------------------------

type EnrollStudentRequest struct {
	StudentID      uuid.UUID
	AcademicYearID uuid.UUID
	SectionID      uuid.UUID
	RollNumber     string
	EnrollmentDate time.Time
	CreatedBy      *uuid.UUID
	UpdatedBy      *uuid.UUID
}

type UpdateEnrollmentRequest struct {
	EnrollmentID   uuid.UUID
	SectionID      uuid.UUID
	RollNumber     string
	EnrollmentDate time.Time
	Status         string
	UpdatedBy      *uuid.UUID
}

type TransferSectionRequest struct {
	EnrollmentID uuid.UUID
	NewSectionID uuid.UUID
	UpdatedBy    *uuid.UUID
}

type PromoteStudentRequest struct {
	StudentID         uuid.UUID
	NewSectionID      uuid.UUID
	NewAcademicYearID uuid.UUID
	UpdatedBy         *uuid.UUID
}

type BulkEnrollmentStatusUpdateRequest struct {
	EnrollmentIDs []uuid.UUID
	Status        string
	UpdatedBy     *uuid.UUID
}

type BulkRollNumberRequest struct {
	RollNumbers map[uuid.UUID]string
	UpdatedBy   *uuid.UUID
}

// ---------------------------------------------------------------------
// Service interface (as previously defined)
// ---------------------------------------------------------------------

type EnrollmentService interface {
	EnrollStudent(ctx context.Context, req EnrollStudentRequest, idempotencyKey string) (*models.Enrollment, error)
	BulkEnroll(ctx context.Context, reqs []EnrollStudentRequest) ([]*models.Enrollment, error)
	UpsertEnrollment(ctx context.Context, req EnrollStudentRequest) (*models.Enrollment, error)

	GetByID(ctx context.Context, id uuid.UUID) (*models.Enrollment, error)
	GetByIDForUpdate(ctx context.Context, id uuid.UUID) (*models.Enrollment, error)
	GetByStudentAndYear(ctx context.Context, studentID, academicYearID uuid.UUID) (*models.Enrollment, error)
	GetActiveByStudent(ctx context.Context, studentID uuid.UUID) (*models.Enrollment, error)

	List(ctx context.Context, filter repository.EnrollmentFilter, p repository.Pagination, s repository.Sort) ([]*models.Enrollment, error)
	ListByStudent(ctx context.Context, studentID uuid.UUID) ([]*models.Enrollment, error)
	ListBySection(ctx context.Context, sectionID uuid.UUID) ([]*models.Enrollment, error)
	ListByAcademicYear(ctx context.Context, academicYearID uuid.UUID) ([]*models.Enrollment, error)

	Count(ctx context.Context, filter repository.EnrollmentFilter) (int64, error)
	ValidateEnrollment(ctx context.Context, req EnrollStudentRequest) error
	ValidateCapacity(ctx context.Context, sectionID uuid.UUID) error
	ValidateStudentEligibility(ctx context.Context, studentID uuid.UUID) error
	ValidateDuplicateEnrollment(ctx context.Context, studentID, academicYearID uuid.UUID) error
	Exists(ctx context.Context, studentID, academicYearID uuid.UUID) (bool, error)

	Activate(ctx context.Context, enrollmentID uuid.UUID, updatedBy *uuid.UUID) error
	Deactivate(ctx context.Context, enrollmentID uuid.UUID, updatedBy *uuid.UUID) error
	Complete(ctx context.Context, enrollmentID uuid.UUID, updatedBy *uuid.UUID) error
	Withdraw(ctx context.Context, enrollmentID uuid.UUID, updatedBy *uuid.UUID) error
	UpdateStatus(ctx context.Context, enrollmentID uuid.UUID, status string, updatedBy *uuid.UUID) error

	Update(ctx context.Context, req UpdateEnrollmentRequest) (*models.Enrollment, error)
	UpdateRollNumber(ctx context.Context, enrollmentID uuid.UUID, rollNumber string, updatedBy *uuid.UUID) error
	TransferSection(ctx context.Context, req TransferSectionRequest) (*models.Enrollment, error)
	BulkTransferSection(ctx context.Context, reqs []TransferSectionRequest) error
	SwapSections(ctx context.Context, enrollmentID1, enrollmentID2 uuid.UUID, updatedBy *uuid.UUID) error

	PromoteStudent(ctx context.Context, req PromoteStudentRequest) (*models.Enrollment, error)
	BulkPromote(ctx context.Context, reqs []PromoteStudentRequest) error
	PromoteSection(ctx context.Context, sectionID, nextSectionID uuid.UUID, academicYearID uuid.UUID, updatedBy *uuid.UUID) error
	RollOverAcademicYear(ctx context.Context, fromYearID, toYearID uuid.UUID, updatedBy *uuid.UUID) error

	GraduateStudent(ctx context.Context, enrollmentID uuid.UUID, updatedBy *uuid.UUID) error
	MarkAlumni(ctx context.Context, studentID uuid.UUID, updatedBy *uuid.UUID) error

	BulkUpdateStatus(ctx context.Context, req BulkEnrollmentStatusUpdateRequest) error
	BulkAssignRollNumbers(ctx context.Context, req BulkRollNumberRequest) error

	Search(ctx context.Context, query string, companyID uuid.UUID, p repository.Pagination) ([]*models.Enrollment, error)
	GetSectionStrength(ctx context.Context, sectionID uuid.UUID) (int64, error)
	GetAcademicYearStrength(ctx context.Context, academicYearID uuid.UUID) (int64, error)
	GetDropoutCount(ctx context.Context, academicYearID uuid.UUID) (int64, error)
	GetPromotionStats(ctx context.Context, academicYearID uuid.UUID) (map[string]int64, error)

	RebuildEnrollments(ctx context.Context, academicYearID uuid.UUID) error
	FixDuplicateEnrollments(ctx context.Context, academicYearID uuid.UUID) error

	PublishEnrollmentCreated(ctx context.Context, enrollment *models.Enrollment) error
	PublishEnrollmentUpdated(ctx context.Context, enrollment *models.Enrollment) error
	PublishEnrollmentDeleted(ctx context.Context, enrollmentID uuid.UUID) error
}

// ---------------------------------------------------------------------
// Service implementation
// ---------------------------------------------------------------------

type enrollmentService struct {
	repo                repository.EnrollmentRepository
	studentRepo         repository.StudentRepository
	sectionRepo         repository.SectionRepository
	courseRepo          repository.CourseRepository
	ayRepo              repository.AcademicYearRepository
	termRepo            repository.TermRepository
	idempotencyStore    IdempotencyStore
	auditLogger         AuditLogger
	outboxStore         OutboxStore
	eventPublisher      EventPublisher
	pgClient            *client.PostgresClient
	logger              *zap.Logger
	notificationService NotificationService
}

func NewEnrollmentService(
	repo repository.EnrollmentRepository,
	studentRepo repository.StudentRepository,
	sectionRepo repository.SectionRepository,
	courseRepo repository.CourseRepository,
	ayRepo repository.AcademicYearRepository,
	termRepo repository.TermRepository,
	idempotencyStore IdempotencyStore,
	auditLogger AuditLogger,
	outboxStore OutboxStore,
	eventPublisher EventPublisher,
	pgClient *client.PostgresClient,
	logger *zap.Logger,
	notificationService NotificationService,
) EnrollmentService {
	return &enrollmentService{
		repo:                repo,
		studentRepo:         studentRepo,
		sectionRepo:         sectionRepo,
		courseRepo:          courseRepo,
		ayRepo:              ayRepo,
		termRepo:            termRepo,
		idempotencyStore:    idempotencyStore,
		auditLogger:         auditLogger,
		outboxStore:         outboxStore,
		eventPublisher:      eventPublisher,
		pgClient:            pgClient,
		logger:              logger.Named("enrollment_service"),
		notificationService: notificationService,
	}
}

// ---------------------------------------------------------------------
// Helper methods
// ---------------------------------------------------------------------

func (s *enrollmentService) getCompanyIDFromStudent(ctx context.Context, db repository.DBTX, studentID uuid.UUID) (uuid.UUID, error) {
	student, err := s.studentRepo.GetByID(ctx, db, studentID)
	if err != nil {
		return uuid.Nil, err
	}
	if student == nil {
		return uuid.Nil, fmt.Errorf("%w: student %s", ErrNotFound, studentID)
	}
	return student.CompanyID, nil
}

// validateStatusTransition checks if moving from oldStatus to newStatus is allowed.
func (s *enrollmentService) validateStatusTransition(oldStatus, newStatus string) error {
	allowed := map[string]map[string]bool{
		EnrollmentStatusActive: {
			EnrollmentStatusCompleted: true,
			EnrollmentStatusWithdrawn: true,
		},
		EnrollmentStatusCompleted: {},
		EnrollmentStatusWithdrawn: {},
	}
	if allowed[oldStatus] == nil {
		return fmt.Errorf("%w: unknown status %s", ErrInvalidInput, oldStatus)
	}
	if !allowed[oldStatus][newStatus] && newStatus != oldStatus {
		return fmt.Errorf("%w: cannot transition from %s to %s", ErrInvalidInput, oldStatus, newStatus)
	}
	return nil
}

// validateEnrollmentInput checks required fields.
func (s *enrollmentService) validateEnrollmentInput(req EnrollStudentRequest) error {
	if req.StudentID == uuid.Nil {
		return fmt.Errorf("%w: student_id is required", ErrInvalidInput)
	}
	if req.AcademicYearID == uuid.Nil {
		return fmt.Errorf("%w: academic_year_id is required", ErrInvalidInput)
	}
	if req.SectionID == uuid.Nil {
		return fmt.Errorf("%w: section_id is required", ErrInvalidInput)
	}
	return nil
}

// checkCapacity ensures the section has enough free seats (with lock).
func (s *enrollmentService) checkCapacity(ctx context.Context, tx *sql.Tx, sectionID uuid.UUID) error {
	section, err := s.sectionRepo.GetByIDForUpdate(ctx, tx, sectionID)
	if err != nil {
		return err
	}
	if section == nil {
		return fmt.Errorf("%w: section %s", ErrNotFound, sectionID)
	}
	if section.Capacity <= 0 {
		return nil
	}
	enrolled, err := s.repo.CountActiveBySection(ctx, tx, sectionID)
	if err != nil {
		return err
	}
	if enrolled >= int64(section.Capacity) {
		return fmt.Errorf("%w: section %s capacity %d reached", ErrCapacityExceeded, sectionID, section.Capacity)
	}
	return nil
}

// validateCapacityReadOnly does not use a lock (for validation only).
func (s *enrollmentService) validateCapacityReadOnly(ctx context.Context, sectionID uuid.UUID) error {
	section, err := s.sectionRepo.GetByID(ctx, s.pgClient.DB, sectionID)
	if err != nil {
		return err
	}
	if section == nil {
		return fmt.Errorf("%w: section %s", ErrNotFound, sectionID)
	}
	if section.Capacity <= 0 {
		return nil
	}
	enrolled, err := s.repo.CountActiveBySection(ctx, s.pgClient.DB, sectionID)
	if err != nil {
		return err
	}
	if enrolled >= int64(section.Capacity) {
		return fmt.Errorf("%w: section %s capacity %d reached", ErrCapacityExceeded, sectionID, section.Capacity)
	}
	return nil
}

// internalGetByIDForUpdate is for use within the service with a transaction.
func (s *enrollmentService) internalGetByIDForUpdate(ctx context.Context, db repository.DBTX, id uuid.UUID) (*models.Enrollment, error) {
	if tx, ok := db.(*sql.Tx); ok {
		return s.repo.GetByIDForUpdateUnsafe(ctx, tx, id)
	}
	return nil, ErrNotInTransaction
}

// updateStatusWithValidation changes enrollment status after validation.
func (s *enrollmentService) updateStatusWithValidation(ctx context.Context, tx *sql.Tx, enrollmentID uuid.UUID, newStatus string, updatedBy *uuid.UUID) error {
	enrollment, err := s.internalGetByIDForUpdate(ctx, tx, enrollmentID)
	if err != nil {
		return err
	}
	if enrollment == nil {
		return fmt.Errorf("%w: enrollment %s", ErrNotFound, enrollmentID)
	}
	if err := s.validateStatusTransition(enrollment.Status, newStatus); err != nil {
		return err
	}
	if err := s.repo.UpdateStatus(ctx, tx, enrollmentID, newStatus, updatedBy); err != nil {
		return err
	}
	return nil
}

// ---------------------------------------------------------------------
// Notification helper
// ---------------------------------------------------------------------

func (s *enrollmentService) buildNotificationRequest(
	enrollment *models.Enrollment,
	student *models.Student,
	operation string,
	actor *uuid.UUID,
) CreateNotificationRequest {
	var title, message string
	var notificationType models.NotificationType
	priority := models.PriorityNormal

	studentName := student.FirstName
	if student.LastName != "" {
		studentName += " " + student.LastName
	}

	switch operation {
	case "created":
		title = "New Enrollment"
		message = fmt.Sprintf("Student %s has been enrolled in %s", studentName, enrollment.RollNumber)
		notificationType = models.NotificationTypeInfo
	case "updated":
		title = "Enrollment Updated"
		message = fmt.Sprintf("Enrollment details for %s have been updated", studentName)
		notificationType = models.NotificationTypeInfo
	case "transferred":
		title = "Section Transfer"
		message = fmt.Sprintf("Student %s has been transferred to a new section", studentName)
		notificationType = models.NotificationTypeInfo
		priority = models.PriorityHigh
	case "promoted":
		title = "Student Promoted"
		message = fmt.Sprintf("Student %s has been promoted to the next academic year", studentName)
		notificationType = models.NotificationTypeInfo
		priority = models.PriorityHigh
	case "completed":
		title = "Enrollment Completed"
		message = fmt.Sprintf("Student %s has completed the academic year", studentName)
		notificationType = models.NotificationTypeInfo
	case "withdrawn":
		title = "Enrollment Withdrawn"
		message = fmt.Sprintf("Student %s has been withdrawn from the academic year", studentName)
		notificationType = models.NotificationTypeWarning
		priority = models.PriorityHigh
	case "activated":
		title = "Enrollment Activated"
		message = fmt.Sprintf("Student %s enrollment has been activated", studentName)
		notificationType = models.NotificationTypeInfo
	case "graduated":
		title = "Student Graduated"
		message = fmt.Sprintf("Student %s has graduated", studentName)
		notificationType = models.NotificationTypeInfo
		priority = models.PriorityHigh
	case "alumni":
		title = "Student Marked as Alumni"
		message = fmt.Sprintf("Student %s has been marked as alumni", studentName)
		notificationType = models.NotificationTypeInfo
	default:
		title = "Enrollment Changed"
		message = fmt.Sprintf("Enrollment for %s has been modified", studentName)
		notificationType = models.NotificationTypeInfo
	}

	return CreateNotificationRequest{
		CompanyID: student.CompanyID,
		Title:     title,
		Message:   message,
		Type:      notificationType,
		Priority:  priority,
		ExpiresAt: nil,
		Targets: []NotificationTargetInput{
			{
				TargetType:     models.TargetStudent,
				TargetEntityID: enrollment.StudentID,
			},
		},
		CreatedBy: actor,
	}
}

// ---------------------------------------------------------------------
// Public methods
// ---------------------------------------------------------------------

func (s *enrollmentService) EnrollStudent(ctx context.Context, req EnrollStudentRequest, idempotencyKey string) (*models.Enrollment, error) {
	logger := s.logger.With(
		zap.String("method", "EnrollStudent"),
		zap.String("student_id", req.StudentID.String()),
		zap.String("section_id", req.SectionID.String()),
	)

	if err := s.validateEnrollmentInput(req); err != nil {
		return nil, err
	}

	tx, err := s.pgClient.BeginTx(ctx, nil)
	if err != nil {
		return nil, fmt.Errorf("begin tx: %w", err)
	}
	defer tx.Rollback()

	// Idempotency
	if idempotencyKey != "" {
		exists, err := s.idempotencyStore.Exists(ctx, tx, idempotencyKey)
		if err != nil {
			return nil, fmt.Errorf("idempotency check: %w", err)
		}
		if exists {
			var enrollment models.Enrollment
			if err := s.idempotencyStore.Get(ctx, tx, idempotencyKey, &enrollment); err != nil {
				return nil, fmt.Errorf("failed to retrieve idempotent response: %w", err)
			}
			logger.Info("returning idempotent response")
			return &enrollment, nil
		}
	}

	// Get company ID from student
	companyID, err := s.getCompanyIDFromStudent(ctx, tx, req.StudentID)
	if err != nil {
		return nil, err
	}

	// Check duplicate active enrollment
	exists, err := s.repo.ExistsActiveEnrollment(ctx, tx, companyID, req.StudentID, req.AcademicYearID)
	if err != nil {
		return nil, err
	}
	if exists {
		return nil, fmt.Errorf("%w: student already has active enrollment for this academic year", ErrDuplicate)
	}

	// Check capacity
	if err := s.checkCapacity(ctx, tx, req.SectionID); err != nil {
		return nil, err
	}

	// Create enrollment
	enrollment := &models.Enrollment{
		StudentID:      req.StudentID,
		AcademicYearID: req.AcademicYearID,
		SectionID:      req.SectionID,
		EnrollmentDate: req.EnrollmentDate,
		RollNumber:     req.RollNumber,
		Status:         EnrollmentStatusActive,
		CreatedBy:      req.CreatedBy,
		UpdatedBy:      req.UpdatedBy,
	}
	if err := s.repo.Create(ctx, tx, enrollment); err != nil {
		return nil, err
	}

	// Idempotency store
	if idempotencyKey != "" {
		if err := s.idempotencyStore.Store(ctx, tx, idempotencyKey, enrollment); err != nil {
			logger.Error("failed to store idempotency key", zap.Error(err))
			return nil, fmt.Errorf("failed to store idempotency key: %w", err)
		}
	}

	// Audit
	if err := s.auditLogger.Log(ctx, tx, "CREATE", enrollment.EnrollmentID, nil, enrollment, req.CreatedBy); err != nil {
		logger.Error("audit log failed", zap.Error(err))
	}

	// Outbox
	if err := s.outboxStore.Store(ctx, tx, string(EventEnrollmentCreated), enrollment); err != nil {
		logger.Error("failed to store outbox event", zap.Error(err))
		return nil, fmt.Errorf("failed to store outbox event: %w", err)
	}

	if err := tx.Commit(); err != nil {
		return nil, fmt.Errorf("commit tx: %w", err)
	}

	logger.Info("enrollment created", zap.String("enrollment_id", enrollment.EnrollmentID.String()))

	// Create notification
	if s.notificationService != nil {
		student, err := s.studentRepo.GetByID(ctx, s.pgClient.DB, req.StudentID)
		if err != nil {
			logger.Error("failed to fetch student for notification", zap.Error(err))
		} else if student != nil {
			notifReq := s.buildNotificationRequest(enrollment, student, "created", req.CreatedBy)
			if _, err := s.notificationService.Create(ctx, notifReq, uuid.New().String()); err != nil {
				logger.Error("failed to create notification", zap.Error(err))
			}
		}
	}

	return enrollment, nil
}

func (s *enrollmentService) BulkEnroll(ctx context.Context, reqs []EnrollStudentRequest) ([]*models.Enrollment, error) {
	if len(reqs) == 0 {
		return nil, nil
	}
	logger := s.logger.With(zap.String("method", "BulkEnroll"), zap.Int("count", len(reqs)))

	tx, err := s.pgClient.BeginTx(ctx, nil)
	if err != nil {
		return nil, fmt.Errorf("begin tx: %w", err)
	}
	defer tx.Rollback()

	// Validate inputs and group by section for capacity check
	sectionCounts := make(map[uuid.UUID]int)
	studentIDs := make([]uuid.UUID, 0, len(reqs))
	for i, req := range reqs {
		if err := s.validateEnrollmentInput(req); err != nil {
			return nil, fmt.Errorf("item %d: %w", i, err)
		}
		studentIDs = append(studentIDs, req.StudentID)
		sectionCounts[req.SectionID]++
	}

	// Fetch all students to get company IDs and validate existence
	students, err := s.studentRepo.GetByIDs(ctx, tx, studentIDs)
	if err != nil {
		return nil, err
	}
	studentMap := make(map[uuid.UUID]*models.Student)
	for _, st := range students {
		studentMap[st.StudentID] = st
	}

	// Prepare enrollments
	enrollments := make([]*models.Enrollment, 0, len(reqs))
	seen := make(map[string]bool) // "studentID:academicYearID"
	for i, req := range reqs {
		student, ok := studentMap[req.StudentID]
		if !ok {
			return nil, fmt.Errorf("item %d: %w: student %s", i, ErrNotFound, req.StudentID)
		}
		key := fmt.Sprintf("%s:%s", req.StudentID, req.AcademicYearID)
		if seen[key] {
			return nil, fmt.Errorf("item %d: duplicate student %s in same academic year", i, req.StudentID)
		}
		seen[key] = true

		// Check duplicate active enrollment
		exists, err := s.repo.ExistsActiveEnrollment(ctx, tx, student.CompanyID, req.StudentID, req.AcademicYearID)
		if err != nil {
			return nil, err
		}
		if exists {
			return nil, fmt.Errorf("item %d: %w: student %s already has active enrollment for this academic year", i, ErrDuplicate, req.StudentID)
		}

		enrollments = append(enrollments, &models.Enrollment{
			StudentID:      req.StudentID,
			AcademicYearID: req.AcademicYearID,
			SectionID:      req.SectionID,
			EnrollmentDate: req.EnrollmentDate,
			RollNumber:     req.RollNumber,
			Status:         EnrollmentStatusActive,
			CreatedBy:      req.CreatedBy,
			UpdatedBy:      req.UpdatedBy,
		})
	}

	// Validate capacity per section (with lock and extra check)
	for sectionID, count := range sectionCounts {
		if err := s.checkCapacity(ctx, tx, sectionID); err != nil {
			return nil, err
		}
		section, err := s.sectionRepo.GetByIDForUpdate(ctx, tx, sectionID)
		if err != nil {
			return nil, err
		}
		if section == nil {
			return nil, fmt.Errorf("%w: section %s", ErrNotFound, sectionID)
		}
		if section.Capacity > 0 {
			current, err := s.repo.CountActiveBySection(ctx, tx, sectionID)
			if err != nil {
				return nil, err
			}
			if current+int64(count) > int64(section.Capacity) {
				return nil, fmt.Errorf("%w: section %s capacity %d insufficient for %d new enrollments", ErrCapacityExceeded, sectionID, section.Capacity, count)
			}
		}
	}

	// Bulk insert
	if err := s.repo.BulkCreate(ctx, tx, enrollments); err != nil {
		return nil, err
	}

	// Audit and outbox
	for _, e := range enrollments {
		if err := s.auditLogger.Log(ctx, tx, "CREATE", e.EnrollmentID, nil, e, e.CreatedBy); err != nil {
			logger.Error("audit log failed", zap.String("enrollment_id", e.EnrollmentID.String()), zap.Error(err))
		}
		if err := s.outboxStore.Store(ctx, tx, string(EventEnrollmentCreated), e); err != nil {
			logger.Error("failed to store outbox event", zap.String("enrollment_id", e.EnrollmentID.String()), zap.Error(err))
			return nil, fmt.Errorf("failed to store outbox event: %w", err)
		}
	}

	if err := tx.Commit(); err != nil {
		return nil, fmt.Errorf("commit tx: %w", err)
	}
	logger.Info("bulk enrollments created", zap.Int("count", len(enrollments)))

	// Create notifications
	if s.notificationService != nil {
		for _, e := range enrollments {
			student := studentMap[e.StudentID]
			if student != nil {
				notifReq := s.buildNotificationRequest(e, student, "created", e.CreatedBy)
				if _, err := s.notificationService.Create(ctx, notifReq, uuid.New().String()); err != nil {
					logger.Error("failed to create notification", zap.String("enrollment_id", e.EnrollmentID.String()), zap.Error(err))
				}
			}
		}
	}

	return enrollments, nil
}

func (s *enrollmentService) UpsertEnrollment(ctx context.Context, req EnrollStudentRequest) (*models.Enrollment, error) {
	logger := s.logger.With(
		zap.String("method", "UpsertEnrollment"),
		zap.String("student_id", req.StudentID.String()),
		zap.String("section_id", req.SectionID.String()),
	)

	if err := s.validateEnrollmentInput(req); err != nil {
		return nil, err
	}

	tx, err := s.pgClient.BeginTx(ctx, nil)
	if err != nil {
		return nil, fmt.Errorf("begin tx: %w", err)
	}
	defer tx.Rollback()

	companyID, err := s.getCompanyIDFromStudent(ctx, tx, req.StudentID)
	if err != nil {
		return nil, err
	}

	existing, err := s.repo.GetByStudentAndYear(ctx, tx, companyID, req.StudentID, req.AcademicYearID)
	if err != nil {
		return nil, err
	}

	var enrollment *models.Enrollment
	operation := "created"
	if existing == nil {
		// Create new
		if err := s.checkCapacity(ctx, tx, req.SectionID); err != nil {
			return nil, err
		}
		enrollment = &models.Enrollment{
			StudentID:      req.StudentID,
			AcademicYearID: req.AcademicYearID,
			SectionID:      req.SectionID,
			EnrollmentDate: req.EnrollmentDate,
			RollNumber:     req.RollNumber,
			Status:         EnrollmentStatusActive,
			CreatedBy:      req.CreatedBy,
			UpdatedBy:      req.UpdatedBy,
		}
		if err := s.repo.Create(ctx, tx, enrollment); err != nil {
			return nil, err
		}
	} else {
		operation = "updated"
		enrollment = existing
		old := *enrollment
		enrollment.SectionID = req.SectionID
		enrollment.RollNumber = req.RollNumber
		enrollment.EnrollmentDate = req.EnrollmentDate
		enrollment.UpdatedBy = req.UpdatedBy
		if err := s.repo.Update(ctx, tx, enrollment); err != nil {
			return nil, err
		}
		// Audit for update
		if err := s.auditLogger.Log(ctx, tx, "UPDATE", enrollment.EnrollmentID, old, enrollment, req.UpdatedBy); err != nil {
			logger.Error("audit log failed", zap.Error(err))
		}
	}

	if err := s.auditLogger.Log(ctx, tx, "CREATE", enrollment.EnrollmentID, existing, enrollment, req.CreatedBy); err != nil {
		logger.Error("audit log failed", zap.Error(err))
	}

	eventType := EventEnrollmentCreated
	if existing != nil {
		eventType = EventEnrollmentUpdated
	}
	if err := s.outboxStore.Store(ctx, tx, string(eventType), enrollment); err != nil {
		logger.Error("failed to store outbox event", zap.Error(err))
		return nil, fmt.Errorf("failed to store outbox event: %w", err)
	}

	if err := tx.Commit(); err != nil {
		return nil, fmt.Errorf("commit tx: %w", err)
	}

	// Create notification
	if s.notificationService != nil {
		student, err := s.studentRepo.GetByID(ctx, s.pgClient.DB, req.StudentID)
		if err != nil {
			logger.Error("failed to fetch student for notification", zap.Error(err))
		} else if student != nil {
			notifReq := s.buildNotificationRequest(enrollment, student, operation, req.CreatedBy)
			if _, err := s.notificationService.Create(ctx, notifReq, uuid.New().String()); err != nil {
				logger.Error("failed to create notification", zap.Error(err))
			}
		}
	}

	return enrollment, nil
}

func (s *enrollmentService) GetByID(ctx context.Context, id uuid.UUID) (*models.Enrollment, error) {
	return s.repo.GetByIDUnsafe(ctx, s.pgClient.DB, id)
}

func (s *enrollmentService) GetByIDForUpdate(ctx context.Context, id uuid.UUID) (*models.Enrollment, error) {
	return nil, fmt.Errorf("GetByIDForUpdate must be called with a transaction; use internal method")
}

func (s *enrollmentService) GetByStudentAndYear(ctx context.Context, studentID, academicYearID uuid.UUID) (*models.Enrollment, error) {
	companyID, err := s.getCompanyIDFromStudent(ctx, s.pgClient.DB, studentID)
	if err != nil {
		return nil, err
	}
	return s.repo.GetByStudentAndYear(ctx, s.pgClient.DB, companyID, studentID, academicYearID)
}

func (s *enrollmentService) GetActiveByStudent(ctx context.Context, studentID uuid.UUID) (*models.Enrollment, error) {
	companyID, err := s.getCompanyIDFromStudent(ctx, s.pgClient.DB, studentID)
	if err != nil {
		return nil, err
	}
	return s.repo.GetActiveByStudent(ctx, s.pgClient.DB, companyID, studentID)
}

func (s *enrollmentService) List(ctx context.Context, filter repository.EnrollmentFilter, p repository.Pagination, sort repository.Sort) ([]*models.Enrollment, error) {
	return s.repo.List(ctx, s.pgClient.DB, filter, p, sort)
}

func (s *enrollmentService) ListByStudent(ctx context.Context, studentID uuid.UUID) ([]*models.Enrollment, error) {
	companyID, err := s.getCompanyIDFromStudent(ctx, s.pgClient.DB, studentID)
	if err != nil {
		return nil, err
	}
	return s.repo.ListByStudent(ctx, s.pgClient.DB, companyID, studentID)
}

func (s *enrollmentService) ListBySection(ctx context.Context, sectionID uuid.UUID) ([]*models.Enrollment, error) {
	section, err := s.sectionRepo.GetByID(ctx, s.pgClient.DB, sectionID)
	if err != nil {
		return nil, err
	}
	if section == nil {
		return nil, fmt.Errorf("%w: section %s", ErrNotFound, sectionID)
	}
	course, err := s.courseRepo.GetByID(ctx, s.pgClient.DB, section.CourseID)
	if err != nil {
		return nil, err
	}
	if course == nil {
		return nil, fmt.Errorf("course not found for section")
	}
	return s.repo.ListBySection(ctx, s.pgClient.DB, course.CompanyID, sectionID)
}

func (s *enrollmentService) ListByAcademicYear(ctx context.Context, academicYearID uuid.UUID) ([]*models.Enrollment, error) {
	ay, err := s.ayRepo.GetByID(ctx, s.pgClient.DB, academicYearID)
	if err != nil {
		return nil, err
	}
	if ay == nil {
		return nil, fmt.Errorf("%w: academic year %s", ErrNotFound, academicYearID)
	}
	return s.repo.ListByAcademicYear(ctx, s.pgClient.DB, ay.CompanyID, academicYearID)
}

func (s *enrollmentService) Count(ctx context.Context, filter repository.EnrollmentFilter) (int64, error) {
	return s.repo.Count(ctx, s.pgClient.DB, filter)
}

func (s *enrollmentService) ValidateEnrollment(ctx context.Context, req EnrollStudentRequest) error {
	if err := s.validateEnrollmentInput(req); err != nil {
		return err
	}
	student, err := s.studentRepo.GetByID(ctx, s.pgClient.DB, req.StudentID)
	if err != nil {
		return err
	}
	if student == nil {
		return fmt.Errorf("%w: student %s", ErrNotFound, req.StudentID)
	}
	if student.Status != models.StudentActive {
		return fmt.Errorf("student is not active")
	}
	ay, err := s.ayRepo.GetByID(ctx, s.pgClient.DB, req.AcademicYearID)
	if err != nil {
		return err
	}
	if ay == nil {
		return fmt.Errorf("%w: academic year %s", ErrNotFound, req.AcademicYearID)
	}
	section, err := s.sectionRepo.GetByID(ctx, s.pgClient.DB, req.SectionID)
	if err != nil {
		return err
	}
	if section == nil {
		return fmt.Errorf("%w: section %s", ErrNotFound, req.SectionID)
	}
	if section.Capacity > 0 {
		enrolled, err := s.repo.CountActiveBySection(ctx, s.pgClient.DB, req.SectionID)
		if err != nil {
			return err
		}
		if enrolled >= int64(section.Capacity) {
			return fmt.Errorf("%w: section %s capacity %d reached", ErrCapacityExceeded, req.SectionID, section.Capacity)
		}
	}
	exists, err := s.repo.ExistsActiveEnrollment(ctx, s.pgClient.DB, student.CompanyID, req.StudentID, req.AcademicYearID)
	if err != nil {
		return err
	}
	if exists {
		return fmt.Errorf("%w: student already has active enrollment for this academic year", ErrDuplicate)
	}
	return nil
}

func (s *enrollmentService) ValidateCapacity(ctx context.Context, sectionID uuid.UUID) error {
	return s.validateCapacityReadOnly(ctx, sectionID)
}

func (s *enrollmentService) ValidateStudentEligibility(ctx context.Context, studentID uuid.UUID) error {
	student, err := s.studentRepo.GetByID(ctx, s.pgClient.DB, studentID)
	if err != nil {
		return err
	}
	if student == nil {
		return fmt.Errorf("%w: student %s", ErrNotFound, studentID)
	}
	if student.Status != models.StudentActive {
		return fmt.Errorf("student is not active")
	}
	return nil
}

func (s *enrollmentService) ValidateDuplicateEnrollment(ctx context.Context, studentID, academicYearID uuid.UUID) error {
	companyID, err := s.getCompanyIDFromStudent(ctx, s.pgClient.DB, studentID)
	if err != nil {
		return err
	}
	exists, err := s.repo.ExistsActiveEnrollment(ctx, s.pgClient.DB, companyID, studentID, academicYearID)
	if err != nil {
		return err
	}
	if exists {
		return fmt.Errorf("%w: student already has active enrollment for this academic year", ErrDuplicate)
	}
	return nil
}

func (s *enrollmentService) Exists(ctx context.Context, studentID, academicYearID uuid.UUID) (bool, error) {
	return s.repo.Exists(ctx, s.pgClient.DB, studentID, academicYearID)
}

// ---------------------------------------------------------------------
// Status change methods with notifications
// ---------------------------------------------------------------------

func (s *enrollmentService) Activate(ctx context.Context, enrollmentID uuid.UUID, updatedBy *uuid.UUID) error {
	tx, err := s.pgClient.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("begin tx: %w", err)
	}
	defer tx.Rollback()

	if err := s.updateStatusWithValidation(ctx, tx, enrollmentID, EnrollmentStatusActive, updatedBy); err != nil {
		return err
	}

	enrollment, _ := s.internalGetByIDForUpdate(ctx, tx, enrollmentID)
	if err := s.auditLogger.Log(ctx, tx, "ACTIVATE", enrollmentID, enrollment, nil, updatedBy); err != nil {
		s.logger.Error("audit log failed", zap.Error(err))
	}
	if err := s.outboxStore.Store(ctx, tx, string(EventEnrollmentActivated), map[string]interface{}{
		"enrollment_id": enrollmentID,
		"updated_by":    updatedBy,
	}); err != nil {
		return fmt.Errorf("failed to store outbox event: %w", err)
	}

	if err := tx.Commit(); err != nil {
		return fmt.Errorf("commit tx: %w", err)
	}

	// Create notification
	if s.notificationService != nil && enrollment != nil {
		student, err := s.studentRepo.GetByID(ctx, s.pgClient.DB, enrollment.StudentID)
		if err != nil {
			s.logger.Error("failed to fetch student for notification", zap.Error(err))
		} else if student != nil {
			notifReq := s.buildNotificationRequest(enrollment, student, "activated", updatedBy)
			if _, err := s.notificationService.Create(ctx, notifReq, uuid.New().String()); err != nil {
				s.logger.Error("failed to create notification", zap.Error(err))
			}
		}
	}

	return nil
}

func (s *enrollmentService) Deactivate(ctx context.Context, enrollmentID uuid.UUID, updatedBy *uuid.UUID) error {
	return s.Withdraw(ctx, enrollmentID, updatedBy)
}

func (s *enrollmentService) Complete(ctx context.Context, enrollmentID uuid.UUID, updatedBy *uuid.UUID) error {
	tx, err := s.pgClient.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("begin tx: %w", err)
	}
	defer tx.Rollback()

	if err := s.updateStatusWithValidation(ctx, tx, enrollmentID, EnrollmentStatusCompleted, updatedBy); err != nil {
		return err
	}

	enrollment, _ := s.internalGetByIDForUpdate(ctx, tx, enrollmentID)
	if err := s.auditLogger.Log(ctx, tx, "COMPLETE", enrollmentID, nil, nil, updatedBy); err != nil {
		s.logger.Error("audit log failed", zap.Error(err))
	}
	if err := s.outboxStore.Store(ctx, tx, string(EventEnrollmentCompleted), map[string]interface{}{
		"enrollment_id": enrollmentID,
		"updated_by":    updatedBy,
	}); err != nil {
		return fmt.Errorf("failed to store outbox event: %w", err)
	}

	if err := tx.Commit(); err != nil {
		return fmt.Errorf("commit tx: %w", err)
	}

	// Create notification
	if s.notificationService != nil && enrollment != nil {
		student, err := s.studentRepo.GetByID(ctx, s.pgClient.DB, enrollment.StudentID)
		if err != nil {
			s.logger.Error("failed to fetch student for notification", zap.Error(err))
		} else if student != nil {
			notifReq := s.buildNotificationRequest(enrollment, student, "completed", updatedBy)
			if _, err := s.notificationService.Create(ctx, notifReq, uuid.New().String()); err != nil {
				s.logger.Error("failed to create notification", zap.Error(err))
			}
		}
	}

	return nil
}

func (s *enrollmentService) Withdraw(ctx context.Context, enrollmentID uuid.UUID, updatedBy *uuid.UUID) error {
	tx, err := s.pgClient.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("begin tx: %w", err)
	}
	defer tx.Rollback()

	if err := s.updateStatusWithValidation(ctx, tx, enrollmentID, EnrollmentStatusWithdrawn, updatedBy); err != nil {
		return err
	}

	enrollment, _ := s.internalGetByIDForUpdate(ctx, tx, enrollmentID)
	if err := s.auditLogger.Log(ctx, tx, "WITHDRAW", enrollmentID, nil, nil, updatedBy); err != nil {
		s.logger.Error("audit log failed", zap.Error(err))
	}
	if err := s.outboxStore.Store(ctx, tx, string(EventEnrollmentWithdrawn), map[string]interface{}{
		"enrollment_id": enrollmentID,
		"updated_by":    updatedBy,
	}); err != nil {
		return fmt.Errorf("failed to store outbox event: %w", err)
	}

	if err := tx.Commit(); err != nil {
		return fmt.Errorf("commit tx: %w", err)
	}

	// Create notification
	if s.notificationService != nil && enrollment != nil {
		student, err := s.studentRepo.GetByID(ctx, s.pgClient.DB, enrollment.StudentID)
		if err != nil {
			s.logger.Error("failed to fetch student for notification", zap.Error(err))
		} else if student != nil {
			notifReq := s.buildNotificationRequest(enrollment, student, "withdrawn", updatedBy)
			if _, err := s.notificationService.Create(ctx, notifReq, uuid.New().String()); err != nil {
				s.logger.Error("failed to create notification", zap.Error(err))
			}
		}
	}

	return nil
}

func (s *enrollmentService) UpdateStatus(ctx context.Context, enrollmentID uuid.UUID, status string, updatedBy *uuid.UUID) error {
	if status != EnrollmentStatusActive && status != EnrollmentStatusCompleted && status != EnrollmentStatusWithdrawn {
		return fmt.Errorf("%w: invalid status %s", ErrInvalidInput, status)
	}
	tx, err := s.pgClient.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("begin tx: %w", err)
	}
	defer tx.Rollback()

	enrollment, err := s.internalGetByIDForUpdate(ctx, tx, enrollmentID)
	if err != nil {
		return err
	}
	if enrollment == nil {
		return fmt.Errorf("%w: enrollment %s", ErrNotFound, enrollmentID)
	}
	if enrollment.Status == status {
		return nil
	}
	if err := s.validateStatusTransition(enrollment.Status, status); err != nil {
		return err
	}
	if err := s.repo.UpdateStatus(ctx, tx, enrollmentID, status, updatedBy); err != nil {
		return err
	}

	if err := s.auditLogger.Log(ctx, tx, "UPDATE_STATUS", enrollmentID, enrollment, nil, updatedBy); err != nil {
		s.logger.Error("audit log failed", zap.Error(err))
	}
	if err := s.outboxStore.Store(ctx, tx, string(EventEnrollmentUpdated), map[string]interface{}{
		"enrollment_id": enrollmentID,
		"old_status":    enrollment.Status,
		"new_status":    status,
		"updated_by":    updatedBy,
	}); err != nil {
		return fmt.Errorf("failed to store outbox event: %w", err)
	}

	if err := tx.Commit(); err != nil {
		return fmt.Errorf("commit tx: %w", err)
	}
	return nil
}

// ---------------------------------------------------------------------
// Update operations (with notifications where applicable)
// ---------------------------------------------------------------------

func (s *enrollmentService) Update(ctx context.Context, req UpdateEnrollmentRequest) (*models.Enrollment, error) {
	logger := s.logger.With(zap.String("method", "Update"), zap.String("enrollment_id", req.EnrollmentID.String()))

	if req.EnrollmentID == uuid.Nil {
		return nil, fmt.Errorf("%w: enrollment_id required", ErrInvalidInput)
	}

	tx, err := s.pgClient.BeginTx(ctx, nil)
	if err != nil {
		return nil, fmt.Errorf("begin tx: %w", err)
	}
	defer tx.Rollback()

	enrollment, err := s.internalGetByIDForUpdate(ctx, tx, req.EnrollmentID)
	if err != nil {
		return nil, err
	}
	if enrollment == nil {
		return nil, fmt.Errorf("%w: enrollment %s", ErrNotFound, req.EnrollmentID)
	}

	old := *enrollment
	if req.SectionID != uuid.Nil && req.SectionID != enrollment.SectionID {
		if err := s.checkCapacity(ctx, tx, req.SectionID); err != nil {
			return nil, err
		}
		enrollment.SectionID = req.SectionID
	}
	if req.RollNumber != "" {
		enrollment.RollNumber = req.RollNumber
	}
	if !req.EnrollmentDate.IsZero() {
		enrollment.EnrollmentDate = req.EnrollmentDate
	}
	if req.Status != "" {
		if err := s.validateStatusTransition(enrollment.Status, req.Status); err != nil {
			return nil, err
		}
		enrollment.Status = req.Status
	}
	enrollment.UpdatedBy = req.UpdatedBy

	if err := s.repo.Update(ctx, tx, enrollment); err != nil {
		if errors.Is(err, repository.ErrVersionConflict) {
			return nil, fmt.Errorf("%w: enrollment %s", ErrConcurrentUpdate, req.EnrollmentID)
		}
		return nil, err
	}

	if err := s.auditLogger.Log(ctx, tx, "UPDATE", enrollment.EnrollmentID, old, enrollment, req.UpdatedBy); err != nil {
		logger.Error("audit log failed", zap.Error(err))
	}
	if err := s.outboxStore.Store(ctx, tx, string(EventEnrollmentUpdated), enrollment); err != nil {
		logger.Error("failed to store outbox event", zap.Error(err))
		return nil, fmt.Errorf("failed to store outbox event: %w", err)
	}

	if err := tx.Commit(); err != nil {
		return nil, fmt.Errorf("commit tx: %w", err)
	}

	// Create notification for update
	if s.notificationService != nil {
		student, err := s.studentRepo.GetByID(ctx, s.pgClient.DB, enrollment.StudentID)
		if err != nil {
			logger.Error("failed to fetch student for notification", zap.Error(err))
		} else if student != nil {
			notifReq := s.buildNotificationRequest(enrollment, student, "updated", req.UpdatedBy)
			if _, err := s.notificationService.Create(ctx, notifReq, uuid.New().String()); err != nil {
				logger.Error("failed to create notification", zap.Error(err))
			}
		}
	}

	return enrollment, nil
}

func (s *enrollmentService) UpdateRollNumber(ctx context.Context, enrollmentID uuid.UUID, rollNumber string, updatedBy *uuid.UUID) error {
	tx, err := s.pgClient.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("begin tx: %w", err)
	}
	defer tx.Rollback()

	enrollment, err := s.internalGetByIDForUpdate(ctx, tx, enrollmentID)
	if err != nil {
		return err
	}
	if enrollment == nil {
		return fmt.Errorf("%w: enrollment %s", ErrNotFound, enrollmentID)
	}
	if err := s.repo.UpdateRollNumber(ctx, tx, enrollmentID, rollNumber, updatedBy); err != nil {
		return err
	}
	if err := s.auditLogger.Log(ctx, tx, "UPDATE_ROLL_NUMBER", enrollmentID, enrollment, nil, updatedBy); err != nil {
		s.logger.Error("audit log failed", zap.Error(err))
	}
	if err := s.outboxStore.Store(ctx, tx, string(EventEnrollmentUpdated), map[string]interface{}{
		"enrollment_id":   enrollmentID,
		"new_roll_number": rollNumber,
		"updated_by":      updatedBy,
	}); err != nil {
		return fmt.Errorf("failed to store outbox event: %w", err)
	}
	if err := tx.Commit(); err != nil {
		return fmt.Errorf("commit tx: %w", err)
	}
	return nil
}

func (s *enrollmentService) TransferSection(ctx context.Context, req TransferSectionRequest) (*models.Enrollment, error) {
	logger := s.logger.With(
		zap.String("method", "TransferSection"),
		zap.String("enrollment_id", req.EnrollmentID.String()),
		zap.String("new_section_id", req.NewSectionID.String()),
	)

	if req.EnrollmentID == uuid.Nil || req.NewSectionID == uuid.Nil {
		return nil, fmt.Errorf("%w: enrollment_id and new_section_id required", ErrInvalidInput)
	}

	tx, err := s.pgClient.BeginTx(ctx, nil)
	if err != nil {
		return nil, fmt.Errorf("begin tx: %w", err)
	}
	defer tx.Rollback()

	enrollment, err := s.internalGetByIDForUpdate(ctx, tx, req.EnrollmentID)
	if err != nil {
		return nil, err
	}
	if enrollment == nil {
		return nil, fmt.Errorf("%w: enrollment %s", ErrNotFound, req.EnrollmentID)
	}
	if enrollment.Status != EnrollmentStatusActive {
		return nil, ErrInactiveEnrollment
	}
	if enrollment.SectionID == req.NewSectionID {
		return enrollment, nil
	}
	if err := s.checkCapacity(ctx, tx, req.NewSectionID); err != nil {
		return nil, err
	}
	old := *enrollment
	enrollment.SectionID = req.NewSectionID
	enrollment.UpdatedBy = req.UpdatedBy
	if err := s.repo.Update(ctx, tx, enrollment); err != nil {
		return nil, err
	}
	if err := s.auditLogger.Log(ctx, tx, "TRANSFER", enrollment.EnrollmentID, old, enrollment, req.UpdatedBy); err != nil {
		logger.Error("audit log failed", zap.Error(err))
	}
	if err := s.outboxStore.Store(ctx, tx, string(EventEnrollmentTransferred), enrollment); err != nil {
		logger.Error("failed to store outbox event", zap.Error(err))
		return nil, fmt.Errorf("failed to store outbox event: %w", err)
	}
	if err := tx.Commit(); err != nil {
		return nil, fmt.Errorf("commit tx: %w", err)
	}

	// Create notification
	if s.notificationService != nil {
		student, err := s.studentRepo.GetByID(ctx, s.pgClient.DB, enrollment.StudentID)
		if err != nil {
			logger.Error("failed to fetch student for notification", zap.Error(err))
		} else if student != nil {
			notifReq := s.buildNotificationRequest(enrollment, student, "transferred", req.UpdatedBy)
			if _, err := s.notificationService.Create(ctx, notifReq, uuid.New().String()); err != nil {
				logger.Error("failed to create notification", zap.Error(err))
			}
		}
	}

	return enrollment, nil
}

func (s *enrollmentService) BulkTransferSection(ctx context.Context, reqs []TransferSectionRequest) error {
	if len(reqs) == 0 {
		return nil
	}
	logger := s.logger.With(zap.String("method", "BulkTransferSection"), zap.Int("count", len(reqs)))

	tx, err := s.pgClient.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("begin tx: %w", err)
	}
	defer tx.Rollback()

	sectionCounts := make(map[uuid.UUID]int)
	for _, req := range reqs {
		if req.EnrollmentID == uuid.Nil || req.NewSectionID == uuid.Nil {
			return fmt.Errorf("%w: enrollment_id and new_section_id required", ErrInvalidInput)
		}
		sectionCounts[req.NewSectionID]++
	}
	for sectionID, count := range sectionCounts {
		if err := s.checkCapacity(ctx, tx, sectionID); err != nil {
			return err
		}
		section, err := s.sectionRepo.GetByIDForUpdate(ctx, tx, sectionID)
		if err != nil {
			return err
		}
		if section == nil {
			return fmt.Errorf("%w: section %s", ErrNotFound, sectionID)
		}
		if section.Capacity > 0 {
			current, err := s.repo.CountActiveBySection(ctx, tx, sectionID)
			if err != nil {
				return err
			}
			if current+int64(count) > int64(section.Capacity) {
				return fmt.Errorf("%w: section %s capacity %d insufficient for %d transfers", ErrCapacityExceeded, sectionID, section.Capacity, count)
			}
		}
	}

	// Perform updates
	for _, req := range reqs {
		enrollment, err := s.internalGetByIDForUpdate(ctx, tx, req.EnrollmentID)
		if err != nil {
			return err
		}
		if enrollment == nil {
			return fmt.Errorf("%w: enrollment %s", ErrNotFound, req.EnrollmentID)
		}
		if enrollment.Status != EnrollmentStatusActive {
			return ErrInactiveEnrollment
		}
		enrollment.SectionID = req.NewSectionID
		enrollment.UpdatedBy = req.UpdatedBy
		if err := s.repo.Update(ctx, tx, enrollment); err != nil {
			return err
		}
		if err := s.auditLogger.Log(ctx, tx, "TRANSFER", enrollment.EnrollmentID, nil, enrollment, req.UpdatedBy); err != nil {
			logger.Error("audit log failed", zap.String("enrollment_id", enrollment.EnrollmentID.String()), zap.Error(err))
		}
	}
	if err := s.outboxStore.Store(ctx, tx, string(EventEnrollmentTransferred), map[string]interface{}{
		"count":      len(reqs),
		"updated_by": reqs[0].UpdatedBy,
	}); err != nil {
		return fmt.Errorf("failed to store outbox event: %w", err)
	}
	if err := tx.Commit(); err != nil {
		return fmt.Errorf("commit tx: %w", err)
	}
	logger.Info("bulk transfer completed")
	return nil
}

func (s *enrollmentService) SwapSections(ctx context.Context, enrollmentID1, enrollmentID2 uuid.UUID, updatedBy *uuid.UUID) error {
	if enrollmentID1 == uuid.Nil || enrollmentID2 == uuid.Nil {
		return fmt.Errorf("%w: both enrollment IDs required", ErrInvalidInput)
	}
	if enrollmentID1 == enrollmentID2 {
		return nil
	}
	tx, err := s.pgClient.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("begin tx: %w", err)
	}
	defer tx.Rollback()

	e1, err := s.internalGetByIDForUpdate(ctx, tx, enrollmentID1)
	if err != nil {
		return err
	}
	if e1 == nil {
		return fmt.Errorf("%w: enrollment %s", ErrNotFound, enrollmentID1)
	}
	e2, err := s.internalGetByIDForUpdate(ctx, tx, enrollmentID2)
	if err != nil {
		return err
	}
	if e2 == nil {
		return fmt.Errorf("%w: enrollment %s", ErrNotFound, enrollmentID2)
	}
	if e1.Status != EnrollmentStatusActive || e2.Status != EnrollmentStatusActive {
		return ErrInactiveEnrollment
	}
	old1 := *e1
	old2 := *e2
	e1.SectionID, e2.SectionID = e2.SectionID, e1.SectionID
	e1.UpdatedBy = updatedBy
	e2.UpdatedBy = updatedBy
	if err := s.repo.Update(ctx, tx, e1); err != nil {
		return err
	}
	if err := s.repo.Update(ctx, tx, e2); err != nil {
		return err
	}
	if err := s.auditLogger.Log(ctx, tx, "SWAP_SECTIONS", e1.EnrollmentID, old1, e1, updatedBy); err != nil {
		s.logger.Error("audit log failed", zap.Error(err))
	}
	if err := s.auditLogger.Log(ctx, tx, "SWAP_SECTIONS", e2.EnrollmentID, old2, e2, updatedBy); err != nil {
		s.logger.Error("audit log failed", zap.Error(err))
	}
	if err := s.outboxStore.Store(ctx, tx, string(EventEnrollmentUpdated), map[string]interface{}{
		"enrollment_id1": enrollmentID1,
		"enrollment_id2": enrollmentID2,
		"updated_by":     updatedBy,
	}); err != nil {
		return fmt.Errorf("failed to store outbox event: %w", err)
	}
	if err := tx.Commit(); err != nil {
		return fmt.Errorf("commit tx: %w", err)
	}
	return nil
}

// ---------------------------------------------------------------------
// Promotion methods
// ---------------------------------------------------------------------

func (s *enrollmentService) PromoteStudent(ctx context.Context, req PromoteStudentRequest) (*models.Enrollment, error) {
	logger := s.logger.With(
		zap.String("method", "PromoteStudent"),
		zap.String("student_id", req.StudentID.String()),
		zap.String("new_section", req.NewSectionID.String()),
		zap.String("new_academic_year", req.NewAcademicYearID.String()),
	)

	if req.StudentID == uuid.Nil || req.NewSectionID == uuid.Nil || req.NewAcademicYearID == uuid.Nil {
		return nil, fmt.Errorf("%w: student_id, new_section_id, new_academic_year_id required", ErrInvalidInput)
	}

	tx, err := s.pgClient.BeginTx(ctx, nil)
	if err != nil {
		return nil, fmt.Errorf("begin tx: %w", err)
	}
	defer tx.Rollback()

	student, err := s.studentRepo.GetByIDForUpdate(ctx, tx, req.StudentID)
	if err != nil {
		return nil, err
	}
	if student == nil {
		return nil, fmt.Errorf("%w: student %s", ErrNotFound, req.StudentID)
	}
	companyID := student.CompanyID

	currentEnrollment, err := s.repo.GetActiveByStudent(ctx, tx, companyID, req.StudentID)
	if err != nil {
		return nil, err
	}
	if currentEnrollment == nil {
		return nil, fmt.Errorf("%w: student has no active enrollment", ErrNotEnrolled)
	}

	section, err := s.sectionRepo.GetByIDForUpdate(ctx, tx, req.NewSectionID)
	if err != nil {
		return nil, err
	}
	if section == nil {
		return nil, fmt.Errorf("%w: section %s", ErrNotFound, req.NewSectionID)
	}
	term, err := s.termRepo.GetByID(ctx, tx, section.TermID)
	if err != nil {
		return nil, err
	}
	if term == nil || term.AcademicYearID != req.NewAcademicYearID {
		return nil, fmt.Errorf("section does not belong to the new academic year")
	}
	if err := s.checkCapacity(ctx, tx, req.NewSectionID); err != nil {
		return nil, err
	}

	if err := s.repo.CompleteActiveEnrollment(ctx, tx, companyID, req.StudentID, currentEnrollment.AcademicYearID, req.UpdatedBy); err != nil {
		return nil, err
	}

	newEnrollmentID, err := s.repo.CreateEnrollment(ctx, tx, companyID, req.StudentID, req.NewAcademicYearID, req.NewSectionID, req.UpdatedBy, req.UpdatedBy)
	if err != nil {
		return nil, err
	}
	newEnrollment, err := s.repo.GetByIDUnsafe(ctx, tx, newEnrollmentID)
	if err != nil {
		return nil, err
	}

	if student.Status != models.StudentActive {
		if err := s.studentRepo.UpdateStatus(ctx, tx, req.StudentID, string(models.StudentActive), req.UpdatedBy); err != nil {
			return nil, err
		}
	}

	if err := s.auditLogger.Log(ctx, tx, "PROMOTE", req.StudentID, currentEnrollment, newEnrollment, req.UpdatedBy); err != nil {
		logger.Error("audit log failed", zap.Error(err))
	}

	if err := s.outboxStore.Store(ctx, tx, string(EventEnrollmentPromoted), map[string]interface{}{
		"student_id":           req.StudentID,
		"old_enrollment_id":    currentEnrollment.EnrollmentID,
		"new_enrollment_id":    newEnrollmentID,
		"new_section_id":       req.NewSectionID,
		"new_academic_year_id": req.NewAcademicYearID,
		"updated_by":           req.UpdatedBy,
	}); err != nil {
		logger.Error("failed to store outbox event", zap.Error(err))
		return nil, fmt.Errorf("failed to store outbox event: %w", err)
	}

	if err := tx.Commit(); err != nil {
		return nil, fmt.Errorf("commit tx: %w", err)
	}

	// Create notification
	if s.notificationService != nil {
		notifReq := s.buildNotificationRequest(newEnrollment, student, "promoted", req.UpdatedBy)
		if _, err := s.notificationService.Create(ctx, notifReq, uuid.New().String()); err != nil {
			logger.Error("failed to create notification", zap.Error(err))
		}
	}

	return newEnrollment, nil
}

func (s *enrollmentService) BulkPromote(ctx context.Context, reqs []PromoteStudentRequest) error {
	if len(reqs) == 0 {
		return nil
	}
	logger := s.logger.With(zap.String("method", "BulkPromote"), zap.Int("count", len(reqs)))

	tx, err := s.pgClient.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("begin tx: %w", err)
	}
	defer tx.Rollback()

	studentIDs := make([]uuid.UUID, 0, len(reqs))
	sectionCounts := make(map[uuid.UUID]int)
	for _, req := range reqs {
		if req.StudentID == uuid.Nil || req.NewSectionID == uuid.Nil || req.NewAcademicYearID == uuid.Nil {
			return fmt.Errorf("%w: missing fields", ErrInvalidInput)
		}
		studentIDs = append(studentIDs, req.StudentID)
		sectionCounts[req.NewSectionID]++
	}

	students, err := s.studentRepo.GetByIDs(ctx, tx, studentIDs)
	if err != nil {
		return err
	}
	studentMap := make(map[uuid.UUID]*models.Student)
	for _, st := range students {
		studentMap[st.StudentID] = st
	}

	for sectionID, count := range sectionCounts {
		if err := s.checkCapacity(ctx, tx, sectionID); err != nil {
			return err
		}
		section, err := s.sectionRepo.GetByIDForUpdate(ctx, tx, sectionID)
		if err != nil {
			return err
		}
		if section == nil {
			return fmt.Errorf("%w: section %s", ErrNotFound, sectionID)
		}
		if section.Capacity > 0 {
			current, err := s.repo.CountActiveBySection(ctx, tx, sectionID)
			if err != nil {
				return err
			}
			if current+int64(count) > int64(section.Capacity) {
				return fmt.Errorf("%w: section %s capacity %d insufficient", ErrCapacityExceeded, sectionID, section.Capacity)
			}
		}
	}

	// Process each promotion
	for _, req := range reqs {
		student, ok := studentMap[req.StudentID]
		if !ok {
			return fmt.Errorf("%w: student %s", ErrNotFound, req.StudentID)
		}
		companyID := student.CompanyID

		currentEnrollment, err := s.repo.GetActiveByStudent(ctx, tx, companyID, req.StudentID)
		if err != nil {
			return err
		}
		if currentEnrollment == nil {
			return fmt.Errorf("%w: student %s has no active enrollment", ErrNotEnrolled, req.StudentID)
		}

		section, err := s.sectionRepo.GetByIDForUpdate(ctx, tx, req.NewSectionID)
		if err != nil {
			return err
		}
		if section == nil {
			return fmt.Errorf("%w: section %s", ErrNotFound, req.NewSectionID)
		}
		term, err := s.termRepo.GetByID(ctx, tx, section.TermID)
		if err != nil {
			return err
		}
		if term == nil || term.AcademicYearID != req.NewAcademicYearID {
			return fmt.Errorf("section does not belong to the new academic year")
		}

		if err := s.repo.CompleteActiveEnrollment(ctx, tx, companyID, req.StudentID, currentEnrollment.AcademicYearID, req.UpdatedBy); err != nil {
			return err
		}

		if _, err := s.repo.CreateEnrollment(ctx, tx, companyID, req.StudentID, req.NewAcademicYearID, req.NewSectionID, req.UpdatedBy, req.UpdatedBy); err != nil {
			return err
		}

		if student.Status != models.StudentActive {
			if err := s.studentRepo.UpdateStatus(ctx, tx, req.StudentID, string(models.StudentActive), req.UpdatedBy); err != nil {
				return err
			}
		}
	}

	if err := s.outboxStore.Store(ctx, tx, string(EventEnrollmentPromoted), map[string]interface{}{
		"count":      len(reqs),
		"updated_by": reqs[0].UpdatedBy,
	}); err != nil {
		return fmt.Errorf("failed to store outbox event: %w", err)
	}

	if err := tx.Commit(); err != nil {
		return fmt.Errorf("commit tx: %w", err)
	}
	logger.Info("bulk promotions completed")
	return nil
}

func (s *enrollmentService) PromoteSection(ctx context.Context, sectionID, nextSectionID uuid.UUID, academicYearID uuid.UUID, updatedBy *uuid.UUID) error {
	enrollments, err := s.repo.GetBySectionForPromotion(ctx, s.pgClient.DB, sectionID)
	if err != nil {
		return err
	}
	if len(enrollments) == 0 {
		return nil
	}
	reqs := make([]PromoteStudentRequest, len(enrollments))
	for i, e := range enrollments {
		reqs[i] = PromoteStudentRequest{
			StudentID:         e.StudentID,
			NewSectionID:      nextSectionID,
			NewAcademicYearID: academicYearID,
			UpdatedBy:         updatedBy,
		}
	}
	return s.BulkPromote(ctx, reqs)
}

func (s *enrollmentService) RollOverAcademicYear(ctx context.Context, fromYearID, toYearID uuid.UUID, updatedBy *uuid.UUID) error {
	s.logger.Warn("RollOverAcademicYear not implemented",
		zap.String("from_year", fromYearID.String()),
		zap.String("to_year", toYearID.String()))
	return nil
}

// ---------------------------------------------------------------------
// Graduation and alumni
// ---------------------------------------------------------------------

func (s *enrollmentService) GraduateStudent(ctx context.Context, enrollmentID uuid.UUID, updatedBy *uuid.UUID) error {
	logger := s.logger.With(zap.String("method", "GraduateStudent"), zap.String("enrollment_id", enrollmentID.String()))

	tx, err := s.pgClient.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("begin tx: %w", err)
	}
	defer tx.Rollback()

	enrollment, err := s.internalGetByIDForUpdate(ctx, tx, enrollmentID)
	if err != nil {
		return err
	}
	if enrollment == nil {
		return fmt.Errorf("%w: enrollment %s", ErrNotFound, enrollmentID)
	}
	if enrollment.Status != EnrollmentStatusActive {
		return ErrInactiveEnrollment
	}
	if err := s.repo.UpdateStatus(ctx, tx, enrollmentID, EnrollmentStatusCompleted, updatedBy); err != nil {
		return err
	}
	if err := s.studentRepo.UpdateStatus(ctx, tx, enrollment.StudentID, string(models.StudentAlumni), updatedBy); err != nil {
		return err
	}
	if err := s.auditLogger.Log(ctx, tx, "GRADUATE", enrollmentID, enrollment, nil, updatedBy); err != nil {
		s.logger.Error("audit log failed", zap.Error(err))
	}
	if err := s.outboxStore.Store(ctx, tx, string(EventEnrollmentCompleted), map[string]interface{}{
		"enrollment_id": enrollmentID,
		"student_id":    enrollment.StudentID,
		"updated_by":    updatedBy,
	}); err != nil {
		return fmt.Errorf("failed to store outbox event: %w", err)
	}
	if err := tx.Commit(); err != nil {
		return fmt.Errorf("commit tx: %w", err)
	}

	// Create notification
	if s.notificationService != nil {
		student, err := s.studentRepo.GetByID(ctx, s.pgClient.DB, enrollment.StudentID)
		if err != nil {
			logger.Error("failed to fetch student for notification", zap.Error(err))
		} else if student != nil {
			notifReq := s.buildNotificationRequest(enrollment, student, "graduated", updatedBy)
			if _, err := s.notificationService.Create(ctx, notifReq, uuid.New().String()); err != nil {
				logger.Error("failed to create notification", zap.Error(err))
			}
		}
	}

	return nil
}

func (s *enrollmentService) MarkAlumni(ctx context.Context, studentID uuid.UUID, updatedBy *uuid.UUID) error {
	logger := s.logger.With(zap.String("method", "MarkAlumni"), zap.String("student_id", studentID.String()))

	tx, err := s.pgClient.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("begin tx: %w", err)
	}
	defer tx.Rollback()

	student, err := s.studentRepo.GetByIDForUpdate(ctx, tx, studentID)
	if err != nil {
		return err
	}
	if student == nil {
		return fmt.Errorf("%w: student %s", ErrNotFound, studentID)
	}
	if err := s.repo.CompleteAllActiveEnrollments(ctx, tx, student.CompanyID, studentID, updatedBy); err != nil {
		return err
	}
	if err := s.studentRepo.UpdateStatus(ctx, tx, studentID, string(models.StudentAlumni), updatedBy); err != nil {
		return err
	}
	if err := s.auditLogger.Log(ctx, tx, "MARK_ALUMNI", studentID, nil, nil, updatedBy); err != nil {
		s.logger.Error("audit log failed", zap.Error(err))
	}
	if err := s.outboxStore.Store(ctx, tx, string(EventEnrollmentCompleted), map[string]interface{}{
		"student_id": studentID,
		"updated_by": updatedBy,
	}); err != nil {
		return fmt.Errorf("failed to store outbox event: %w", err)
	}
	if err := tx.Commit(); err != nil {
		return fmt.Errorf("commit tx: %w", err)
	}

	// Create notification (no specific enrollment)
	if s.notificationService != nil {
		notifReq := CreateNotificationRequest{
			CompanyID: student.CompanyID,
			Title:     "Student Marked as Alumni",
			Message:   fmt.Sprintf("Student %s %s has been marked as alumni", student.FirstName, student.LastName),
			Type:      models.NotificationTypeInfo,
			Priority:  models.PriorityNormal,
			ExpiresAt: nil,
			Targets: []NotificationTargetInput{
				{
					TargetType:     models.TargetStudent,
					TargetEntityID: studentID,
				},
			},
			CreatedBy: updatedBy,
		}
		if _, err := s.notificationService.Create(ctx, notifReq, uuid.New().String()); err != nil {
			logger.Error("failed to create notification", zap.Error(err))
		}
	}

	return nil
}

// ---------------------------------------------------------------------
// Bulk operations
// ---------------------------------------------------------------------

func (s *enrollmentService) BulkUpdateStatus(ctx context.Context, req BulkEnrollmentStatusUpdateRequest) error {
	if len(req.EnrollmentIDs) == 0 {
		return nil
	}
	if req.Status != EnrollmentStatusActive && req.Status != EnrollmentStatusCompleted && req.Status != EnrollmentStatusWithdrawn {
		return fmt.Errorf("%w: invalid status", ErrInvalidInput)
	}
	tx, err := s.pgClient.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("begin tx: %w", err)
	}
	defer tx.Rollback()

	for _, id := range req.EnrollmentIDs {
		enrollment, err := s.internalGetByIDForUpdate(ctx, tx, id)
		if err != nil {
			return err
		}
		if enrollment == nil {
			return fmt.Errorf("%w: enrollment %s", ErrNotFound, id)
		}
		if err := s.validateStatusTransition(enrollment.Status, req.Status); err != nil {
			return err
		}
	}
	if err := s.repo.BulkUpdateStatus(ctx, tx, req.EnrollmentIDs, req.Status, req.UpdatedBy); err != nil {
		return err
	}
	if err := s.auditLogger.Log(ctx, tx, "BULK_UPDATE_STATUS", uuid.Nil, nil, map[string]interface{}{
		"enrollment_ids": req.EnrollmentIDs,
		"new_status":     req.Status,
		"count":          len(req.EnrollmentIDs),
	}, req.UpdatedBy); err != nil {
		s.logger.Error("audit log failed", zap.Error(err))
	}
	if err := s.outboxStore.Store(ctx, tx, string(EventEnrollmentUpdated), map[string]interface{}{
		"enrollment_ids": req.EnrollmentIDs,
		"new_status":     req.Status,
		"updated_by":     req.UpdatedBy,
	}); err != nil {
		return fmt.Errorf("failed to store outbox event: %w", err)
	}
	if err := tx.Commit(); err != nil {
		return fmt.Errorf("commit tx: %w", err)
	}
	return nil
}

func (s *enrollmentService) BulkAssignRollNumbers(ctx context.Context, req BulkRollNumberRequest) error {
	if len(req.RollNumbers) == 0 {
		return nil
	}
	tx, err := s.pgClient.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("begin tx: %w", err)
	}
	defer tx.Rollback()

	for id := range req.RollNumbers {
		enrollment, err := s.internalGetByIDForUpdate(ctx, tx, id)
		if err != nil {
			return err
		}
		if enrollment == nil {
			return fmt.Errorf("%w: enrollment %s", ErrNotFound, id)
		}
	}
	if err := s.repo.BulkAssignRollNumbers(ctx, tx, req.RollNumbers, req.UpdatedBy); err != nil {
		return err
	}
	if err := s.auditLogger.Log(ctx, tx, "BULK_ASSIGN_ROLL_NUMBERS", uuid.Nil, nil, map[string]interface{}{
		"count": len(req.RollNumbers),
	}, req.UpdatedBy); err != nil {
		s.logger.Error("audit log failed", zap.Error(err))
	}
	if err := s.outboxStore.Store(ctx, tx, string(EventEnrollmentUpdated), map[string]interface{}{
		"roll_numbers_assigned": len(req.RollNumbers),
		"updated_by":            req.UpdatedBy,
	}); err != nil {
		return fmt.Errorf("failed to store outbox event: %w", err)
	}
	if err := tx.Commit(); err != nil {
		return fmt.Errorf("commit tx: %w", err)
	}
	return nil
}

// ---------------------------------------------------------------------
// Search and statistics
// ---------------------------------------------------------------------

func (s *enrollmentService) Search(ctx context.Context, query string, companyID uuid.UUID, p repository.Pagination) ([]*models.Enrollment, error) {
	return s.repo.Search(ctx, s.pgClient.DB, query, companyID, p)
}

func (s *enrollmentService) GetSectionStrength(ctx context.Context, sectionID uuid.UUID) (int64, error) {
	return s.repo.CountActiveBySection(ctx, s.pgClient.DB, sectionID)
}

func (s *enrollmentService) GetAcademicYearStrength(ctx context.Context, academicYearID uuid.UUID) (int64, error) {
	return s.repo.CountByAcademicYear(ctx, s.pgClient.DB, academicYearID)
}

func (s *enrollmentService) GetDropoutCount(ctx context.Context, academicYearID uuid.UUID) (int64, error) {
	filter := repository.EnrollmentFilter{
		AcademicYearID: academicYearID,
		Status:         stringPtr(EnrollmentStatusWithdrawn),
	}
	return s.repo.Count(ctx, s.pgClient.DB, filter)
}

func (s *enrollmentService) GetPromotionStats(ctx context.Context, academicYearID uuid.UUID) (map[string]int64, error) {
	statuses := []string{EnrollmentStatusActive, EnrollmentStatusCompleted, EnrollmentStatusWithdrawn}
	stats := make(map[string]int64)
	for _, status := range statuses {
		filter := repository.EnrollmentFilter{
			AcademicYearID: academicYearID,
			Status:         stringPtr(status),
		}
		count, err := s.repo.Count(ctx, s.pgClient.DB, filter)
		if err != nil {
			return nil, err
		}
		stats[status] = count
	}
	return stats, nil
}

// ---------------------------------------------------------------------
// Administrative methods
// ---------------------------------------------------------------------

func (s *enrollmentService) RebuildEnrollments(ctx context.Context, academicYearID uuid.UUID) error {
	s.logger.Warn("RebuildEnrollments called but not implemented", zap.String("academic_year_id", academicYearID.String()))
	return nil
}

func (s *enrollmentService) FixDuplicateEnrollments(ctx context.Context, academicYearID uuid.UUID) error {
	duplicates, err := s.repo.FindDuplicates(ctx, s.pgClient.DB, academicYearID)
	if err != nil {
		return err
	}
	if len(duplicates) == 0 {
		return nil
	}
	studentMap := make(map[uuid.UUID][]*models.Enrollment)
	for _, e := range duplicates {
		studentMap[e.StudentID] = append(studentMap[e.StudentID], e)
	}
	tx, err := s.pgClient.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	for _, enrollments := range studentMap {
		var keep *models.Enrollment
		for _, e := range enrollments {
			if keep == nil {
				keep = e
				continue
			}
			if e.Status == EnrollmentStatusActive && keep.Status != EnrollmentStatusActive {
				keep = e
			} else if e.CreatedAt.After(keep.CreatedAt) {
				keep = e
			}
		}
		for _, e := range enrollments {
			if e.EnrollmentID == keep.EnrollmentID {
				continue
			}
			if err := s.repo.UpdateStatus(ctx, tx, e.EnrollmentID, EnrollmentStatusCompleted, nil); err != nil {
				return err
			}
		}
	}
	if err := tx.Commit(); err != nil {
		return fmt.Errorf("commit tx: %w", err)
	}
	return nil
}

// ---------------------------------------------------------------------
// Publishing methods (for event-driven architecture)
// ---------------------------------------------------------------------

func (s *enrollmentService) PublishEnrollmentCreated(ctx context.Context, enrollment *models.Enrollment) error {
	return s.eventPublisher.Publish(ctx, Event{Type: EventType(EventEnrollmentCreated), Data: enrollment})
}

func (s *enrollmentService) PublishEnrollmentUpdated(ctx context.Context, enrollment *models.Enrollment) error {
	return s.eventPublisher.Publish(ctx, Event{Type: EventType(EventEnrollmentUpdated), Data: enrollment})
}

func (s *enrollmentService) PublishEnrollmentDeleted(ctx context.Context, enrollmentID uuid.UUID) error {
	return s.eventPublisher.Publish(ctx, Event{Type: EventType(EventEnrollmentDeleted), Data: map[string]interface{}{
		"enrollment_id": enrollmentID,
	}})
}

// Helper
func stringPtr(s string) *string {
	return &s
}

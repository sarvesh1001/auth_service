package service

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
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

const (
	EnrollmentStatusActive    = "active"
	EnrollmentStatusCompleted = "completed"
	EnrollmentStatusWithdrawn = "withdrawn"
)

const (
	EventEnrollmentCreated     EventType = "enrollment.created"
	EventEnrollmentUpdated     EventType = "enrollment.updated"
	EventEnrollmentDeleted     EventType = "enrollment.deleted"
	EventEnrollmentActivated   EventType = "enrollment.activated"
	EventEnrollmentCompleted   EventType = "enrollment.completed"
	EventEnrollmentWithdrawn   EventType = "enrollment.withdrawn"
	EventEnrollmentTransferred EventType = "enrollment.transferred"
	EventEnrollmentPromoted    EventType = "enrollment.promoted"
)

type EnrollStudentRequest struct {
	StudentID      uuid.UUID  `json:"student_id"`
	AcademicYearID uuid.UUID  `json:"academic_year_id"`
	SectionID      uuid.UUID  `json:"section_id"`
	RollNumber     string     `json:"roll_number,omitempty"`
	EnrollmentDate time.Time  `json:"enrollment_date"`
	CreatedBy      *uuid.UUID `json:"created_by,omitempty"`
	UpdatedBy      *uuid.UUID `json:"updated_by,omitempty"`
}

type UpdateEnrollmentRequest struct {
	EnrollmentID   uuid.UUID  `json:"enrollment_id"`
	SectionID      uuid.UUID  `json:"section_id,omitempty"`
	RollNumber     string     `json:"roll_number,omitempty"`
	EnrollmentDate time.Time  `json:"enrollment_date,omitempty"`
	Status         string     `json:"status,omitempty"`
	UpdatedBy      *uuid.UUID `json:"updated_by,omitempty"`
}

type TransferSectionRequest struct {
	EnrollmentID uuid.UUID  `json:"enrollment_id"`
	NewSectionID uuid.UUID  `json:"new_section_id"`
	UpdatedBy    *uuid.UUID `json:"updated_by,omitempty"`
}

type PromoteStudentRequest struct {
	StudentID         uuid.UUID  `json:"student_id"`
	NewSectionID      uuid.UUID  `json:"new_section_id"`
	NewAcademicYearID uuid.UUID  `json:"new_academic_year_id"`
	UpdatedBy         *uuid.UUID `json:"updated_by,omitempty"`
}

type BulkEnrollmentStatusUpdateRequest struct {
	EnrollmentIDs []uuid.UUID `json:"enrollment_ids"`
	Status        string      `json:"status"`
	UpdatedBy     *uuid.UUID  `json:"updated_by,omitempty"`
}

type BulkRollNumberRequest struct {
	RollNumbers map[uuid.UUID]string `json:"roll_numbers"`
	UpdatedBy   *uuid.UUID           `json:"updated_by,omitempty"`
}

type EnrollmentService interface {
	EnrollStudent(ctx context.Context, req EnrollStudentRequest, idempotencyKey string) (*models.Enrollment, error)
	BulkEnroll(ctx context.Context, reqs []EnrollStudentRequest, idempotencyKey string) ([]*models.Enrollment, error)
	UpsertEnrollment(ctx context.Context, req EnrollStudentRequest, idempotencyKey string) (*models.Enrollment, error)
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
	Activate(ctx context.Context, enrollmentID uuid.UUID, updatedBy *uuid.UUID, idempotencyKey string) error
	Deactivate(ctx context.Context, enrollmentID uuid.UUID, updatedBy *uuid.UUID, idempotencyKey string) error
	Complete(ctx context.Context, enrollmentID uuid.UUID, updatedBy *uuid.UUID, idempotencyKey string) error
	Withdraw(ctx context.Context, enrollmentID uuid.UUID, updatedBy *uuid.UUID, idempotencyKey string) error
	UpdateStatus(ctx context.Context, enrollmentID uuid.UUID, status string, updatedBy *uuid.UUID, idempotencyKey string) error
	Update(ctx context.Context, req UpdateEnrollmentRequest, idempotencyKey string) (*models.Enrollment, error)
	UpdateRollNumber(ctx context.Context, enrollmentID uuid.UUID, rollNumber string, updatedBy *uuid.UUID, idempotencyKey string) error
	TransferSection(ctx context.Context, req TransferSectionRequest, idempotencyKey string) (*models.Enrollment, error)
	BulkTransferSection(ctx context.Context, reqs []TransferSectionRequest, idempotencyKey string) error
	SwapSections(ctx context.Context, enrollmentID1, enrollmentID2 uuid.UUID, updatedBy *uuid.UUID, idempotencyKey string) error
	PromoteStudent(ctx context.Context, req PromoteStudentRequest, idempotencyKey string) (*models.Enrollment, error)
	BulkPromote(ctx context.Context, reqs []PromoteStudentRequest, idempotencyKey string) error
	PromoteSection(ctx context.Context, sectionID, nextSectionID uuid.UUID, academicYearID uuid.UUID, updatedBy *uuid.UUID, idempotencyKey string) error
	RollOverAcademicYear(ctx context.Context, fromYearID, toYearID uuid.UUID, updatedBy *uuid.UUID, idempotencyKey string) error
	GraduateStudent(ctx context.Context, enrollmentID uuid.UUID, updatedBy *uuid.UUID, idempotencyKey string) error
	MarkAlumni(ctx context.Context, studentID uuid.UUID, updatedBy *uuid.UUID, idempotencyKey string) error
	BulkUpdateStatus(ctx context.Context, req BulkEnrollmentStatusUpdateRequest, idempotencyKey string) error
	BulkAssignRollNumbers(ctx context.Context, req BulkRollNumberRequest, idempotencyKey string) error
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

type enrollmentService struct {
	repo                repository.EnrollmentRepository
	studentRepo         repository.StudentRepository
	sectionRepo         repository.SectionRepository
	courseRepo          repository.CourseRepository
	ayRepo              repository.AcademicYearRepository
	termRepo            repository.TermRepository
	pgClient            *client.PostgresClient
	logger              *zap.Logger
	notificationService NotificationService
	idempotencyStore    idempotency.Store
	auditService        *audit.AuditService
	outboxRepo          outbox.Repository
	eventPublisher      EventPublisher
}

func NewEnrollmentService(
	repo repository.EnrollmentRepository,
	studentRepo repository.StudentRepository,
	sectionRepo repository.SectionRepository,
	courseRepo repository.CourseRepository,
	ayRepo repository.AcademicYearRepository,
	termRepo repository.TermRepository,
	pgClient *client.PostgresClient,
	logger *zap.Logger,
	notificationService NotificationService,
	idempotencyStore idempotency.Store,
	auditService *audit.AuditService,
	outboxRepo outbox.Repository,
	eventPublisher EventPublisher,
) EnrollmentService {
	return &enrollmentService{
		repo:                repo,
		studentRepo:         studentRepo,
		sectionRepo:         sectionRepo,
		courseRepo:          courseRepo,
		ayRepo:              ayRepo,
		termRepo:            termRepo,
		pgClient:            pgClient,
		logger:              logger.Named("enrollment_service"),
		notificationService: notificationService,
		idempotencyStore:    idempotencyStore,
		auditService:        auditService,
		outboxRepo:          outboxRepo,
		eventPublisher:      eventPublisher,
	}
}

// storeOutboxEvent creates and stores an outbox event. All enrollment events
// are published to the "student-events" topic (TopicStudent).
func (s *enrollmentService) storeOutboxEvent(ctx context.Context, tx *sql.Tx, eventType EventType, aggregateID uuid.UUID, payload interface{}) error {
	var data []byte
	var err error
	if payload != nil {
		data, err = json.Marshal(payload)
		if err != nil {
			return fmt.Errorf("marshal outbox payload: %w", err)
		}
	}
	outboxEvent := &outbox.Event{
		EventID:       uuid.New().String(),
		AggregateType: "enrollment",
		AggregateID:   aggregateID.String(),
		EventType:     string(eventType),
		Topic:         TopicStudent, // <-- NEW: required field, using student-events topic
		Payload:       data,
		Headers:       map[string]string{},
		Status:        "pending",
	}
	return s.outboxRepo.Store(ctx, tx, outboxEvent)
}

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

func (s *enrollmentService) internalGetByIDForUpdate(ctx context.Context, db repository.DBTX, id uuid.UUID) (*models.Enrollment, error) {
	if tx, ok := db.(*sql.Tx); ok {
		return s.repo.GetByIDForUpdateUnsafe(ctx, tx, id)
	}
	return nil, ErrNotInTransaction
}

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

// ----------------------------------------------------------------------------
// Business Methods
// ----------------------------------------------------------------------------

func (s *enrollmentService) EnrollStudent(ctx context.Context, req EnrollStudentRequest, idempotencyKey string) (*models.Enrollment, error) {
	logger := s.logger.With(
		zap.String("method", "EnrollStudent"),
		zap.String("student_id", req.StudentID.String()),
		zap.String("section_id", req.SectionID.String()),
		zap.String("idempotency_key", idempotencyKey),
	)

	if err := s.validateEnrollmentInput(req); err != nil {
		return nil, err
	}

	tx, err := s.pgClient.BeginTx(ctx, nil)
	if err != nil {
		return nil, fmt.Errorf("begin tx: %w", err)
	}
	defer tx.Rollback()

	if idempotencyKey != "" {
		var existing models.Enrollment
		if err := s.idempotencyStore.Get(ctx, tx, idempotencyKey, &existing); err == nil && existing.EnrollmentID != uuid.Nil {
			logger.Info("returning idempotent response")
			return &existing, nil
		}
	}

	companyID, err := s.getCompanyIDFromStudent(ctx, tx, req.StudentID)
	if err != nil {
		return nil, err
	}

	exists, err := s.repo.ExistsActiveEnrollment(ctx, tx, companyID, req.StudentID, req.AcademicYearID)
	if err != nil {
		return nil, err
	}
	if exists {
		return nil, fmt.Errorf("%w: student already has active enrollment for this academic year", ErrDuplicate)
	}

	if err := s.checkCapacity(ctx, tx, req.SectionID); err != nil {
		return nil, err
	}

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

	if idempotencyKey != "" {
		if err := s.idempotencyStore.Store(ctx, tx, idempotencyKey, enrollment); err != nil {
			logger.Error("failed to store idempotency key", zap.Error(err))
		}
	}

	if s.auditService != nil {
		_ = s.auditService.LogAction(ctx, nil, nil, "academics", "create", "enrollment",
			&enrollment.EnrollmentID, "user", req.CreatedBy, nil, nil, map[string]interface{}{
				"student_id":       enrollment.StudentID,
				"academic_year_id": enrollment.AcademicYearID,
				"section_id":       enrollment.SectionID,
			})
	}

	if err := s.storeOutboxEvent(ctx, tx, EventEnrollmentCreated, enrollment.EnrollmentID, enrollment); err != nil {
		return nil, fmt.Errorf("outbox store: %w", err)
	}

	if err := tx.Commit(); err != nil {
		return nil, fmt.Errorf("commit tx: %w", err)
	}

	logger.Info("enrollment created", zap.String("enrollment_id", enrollment.EnrollmentID.String()))

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

func (s *enrollmentService) BulkEnroll(ctx context.Context, reqs []EnrollStudentRequest, idempotencyKey string) ([]*models.Enrollment, error) {
	if len(reqs) == 0 {
		return nil, nil
	}

	logger := s.logger.With(
		zap.String("method", "BulkEnroll"),
		zap.Int("count", len(reqs)),
		zap.String("idempotency_key", idempotencyKey),
	)

	tx, err := s.pgClient.BeginTx(ctx, nil)
	if err != nil {
		return nil, fmt.Errorf("begin tx: %w", err)
	}
	defer tx.Rollback()

	if idempotencyKey != "" {
		var existing []*models.Enrollment
		if err := s.idempotencyStore.Get(ctx, tx, idempotencyKey, &existing); err == nil && len(existing) > 0 {
			logger.Info("returning idempotent response")
			return existing, nil
		}
	}

	sectionCounts := make(map[uuid.UUID]int)
	studentIDs := make([]uuid.UUID, 0, len(reqs))
	for i, req := range reqs {
		if err := s.validateEnrollmentInput(req); err != nil {
			return nil, fmt.Errorf("item %d: %w", i, err)
		}
		studentIDs = append(studentIDs, req.StudentID)
		sectionCounts[req.SectionID]++
	}

	students, err := s.studentRepo.GetByIDs(ctx, tx, studentIDs)
	if err != nil {
		return nil, err
	}
	studentMap := make(map[uuid.UUID]*models.Student)
	for _, st := range students {
		studentMap[st.StudentID] = st
	}

	enrollments := make([]*models.Enrollment, 0, len(reqs))
	seen := make(map[string]bool)

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

	if err := s.repo.BulkCreate(ctx, tx, enrollments); err != nil {
		return nil, err
	}

	if idempotencyKey != "" {
		if err := s.idempotencyStore.Store(ctx, tx, idempotencyKey, enrollments); err != nil {
			logger.Error("failed to store idempotency key", zap.Error(err))
		}
	}

	for _, e := range enrollments {
		if s.auditService != nil {
			_ = s.auditService.LogAction(ctx, nil, nil, "academics", "bulk_create", "enrollment",
				&e.EnrollmentID, "user", e.CreatedBy, nil, nil, map[string]interface{}{
					"student_id":       e.StudentID,
					"academic_year_id": e.AcademicYearID,
					"section_id":       e.SectionID,
				})
		}
		if err := s.storeOutboxEvent(ctx, tx, EventEnrollmentCreated, e.EnrollmentID, e); err != nil {
			return nil, fmt.Errorf("outbox store for %s: %w", e.EnrollmentID, err)
		}
	}

	if err := tx.Commit(); err != nil {
		return nil, fmt.Errorf("commit tx: %w", err)
	}

	logger.Info("bulk enrollments created", zap.Int("count", len(enrollments)))

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

func (s *enrollmentService) UpsertEnrollment(ctx context.Context, req EnrollStudentRequest, idempotencyKey string) (*models.Enrollment, error) {
	logger := s.logger.With(
		zap.String("method", "UpsertEnrollment"),
		zap.String("student_id", req.StudentID.String()),
		zap.String("section_id", req.SectionID.String()),
		zap.String("idempotency_key", idempotencyKey),
	)

	if err := s.validateEnrollmentInput(req); err != nil {
		return nil, err
	}

	tx, err := s.pgClient.BeginTx(ctx, nil)
	if err != nil {
		return nil, fmt.Errorf("begin tx: %w", err)
	}
	defer tx.Rollback()

	if idempotencyKey != "" {
		var existing models.Enrollment
		if err := s.idempotencyStore.Get(ctx, tx, idempotencyKey, &existing); err == nil && existing.EnrollmentID != uuid.Nil {
			logger.Info("returning idempotent response")
			return &existing, nil
		}
	}

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
		if s.auditService != nil {
			_ = s.auditService.LogAction(ctx, nil, nil, "academics", "update", "enrollment",
				&enrollment.EnrollmentID, "user", req.UpdatedBy, nil, nil, map[string]interface{}{
					"old_section_id": old.SectionID,
					"new_section_id": enrollment.SectionID,
				})
		}
	}

	if idempotencyKey != "" {
		if err := s.idempotencyStore.Store(ctx, tx, idempotencyKey, enrollment); err != nil {
			logger.Error("failed to store idempotency key", zap.Error(err))
		}
	}

	if s.auditService != nil && existing == nil {
		_ = s.auditService.LogAction(ctx, nil, nil, "academics", "create", "enrollment",
			&enrollment.EnrollmentID, "user", req.CreatedBy, nil, nil, map[string]interface{}{
				"student_id":       enrollment.StudentID,
				"academic_year_id": enrollment.AcademicYearID,
				"section_id":       enrollment.SectionID,
			})
	}

	eventType := EventEnrollmentCreated
	if existing != nil {
		eventType = EventEnrollmentUpdated
	}
	if err := s.storeOutboxEvent(ctx, tx, eventType, enrollment.EnrollmentID, enrollment); err != nil {
		return nil, fmt.Errorf("outbox store: %w", err)
	}

	if err := tx.Commit(); err != nil {
		return nil, fmt.Errorf("commit tx: %w", err)
	}

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

func (s *enrollmentService) Activate(ctx context.Context, enrollmentID uuid.UUID, updatedBy *uuid.UUID, idempotencyKey string) error {
	logger := s.logger.With(
		zap.String("method", "Activate"),
		zap.String("enrollment_id", enrollmentID.String()),
		zap.String("idempotency_key", idempotencyKey),
	)

	tx, err := s.pgClient.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("begin tx: %w", err)
	}
	defer tx.Rollback()

	if idempotencyKey != "" {
		var dummy struct{}
		if err := s.idempotencyStore.Get(ctx, tx, idempotencyKey, &dummy); err == nil {
			logger.Info("idempotent operation: already processed")
			return nil
		}
	}

	if err := s.updateStatusWithValidation(ctx, tx, enrollmentID, EnrollmentStatusActive, updatedBy); err != nil {
		return err
	}

	if idempotencyKey != "" {
		if err := s.idempotencyStore.Store(ctx, tx, idempotencyKey, struct{}{}); err != nil {
			logger.Error("failed to store idempotency key", zap.Error(err))
		}
	}

	enrollment, _ := s.internalGetByIDForUpdate(ctx, tx, enrollmentID)

	if s.auditService != nil {
		_ = s.auditService.LogAction(ctx, nil, nil, "academics", "activate", "enrollment",
			&enrollmentID, "user", updatedBy, nil, nil, nil)
	}

	if err := s.storeOutboxEvent(ctx, tx, EventEnrollmentActivated, enrollmentID, map[string]interface{}{
		"enrollment_id": enrollmentID,
		"updated_by":    updatedBy,
	}); err != nil {
		return fmt.Errorf("outbox store: %w", err)
	}

	if err := tx.Commit(); err != nil {
		return fmt.Errorf("commit tx: %w", err)
	}

	if s.notificationService != nil && enrollment != nil {
		student, err := s.studentRepo.GetByID(ctx, s.pgClient.DB, enrollment.StudentID)
		if err != nil {
			logger.Error("failed to fetch student for notification", zap.Error(err))
		} else if student != nil {
			notifReq := s.buildNotificationRequest(enrollment, student, "activated", updatedBy)
			if _, err := s.notificationService.Create(ctx, notifReq, uuid.New().String()); err != nil {
				logger.Error("failed to create notification", zap.Error(err))
			}
		}
	}

	return nil
}

func (s *enrollmentService) Deactivate(ctx context.Context, enrollmentID uuid.UUID, updatedBy *uuid.UUID, idempotencyKey string) error {
	return s.Withdraw(ctx, enrollmentID, updatedBy, idempotencyKey)
}

func (s *enrollmentService) Complete(ctx context.Context, enrollmentID uuid.UUID, updatedBy *uuid.UUID, idempotencyKey string) error {
	logger := s.logger.With(
		zap.String("method", "Complete"),
		zap.String("enrollment_id", enrollmentID.String()),
		zap.String("idempotency_key", idempotencyKey),
	)

	tx, err := s.pgClient.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("begin tx: %w", err)
	}
	defer tx.Rollback()

	if idempotencyKey != "" {
		var dummy struct{}
		if err := s.idempotencyStore.Get(ctx, tx, idempotencyKey, &dummy); err == nil {
			logger.Info("idempotent operation: already processed")
			return nil
		}
	}

	if err := s.updateStatusWithValidation(ctx, tx, enrollmentID, EnrollmentStatusCompleted, updatedBy); err != nil {
		return err
	}

	if idempotencyKey != "" {
		if err := s.idempotencyStore.Store(ctx, tx, idempotencyKey, struct{}{}); err != nil {
			logger.Error("failed to store idempotency key", zap.Error(err))
		}
	}

	enrollment, _ := s.internalGetByIDForUpdate(ctx, tx, enrollmentID)

	if s.auditService != nil {
		_ = s.auditService.LogAction(ctx, nil, nil, "academics", "complete", "enrollment",
			&enrollmentID, "user", updatedBy, nil, nil, nil)
	}

	if err := s.storeOutboxEvent(ctx, tx, EventEnrollmentCompleted, enrollmentID, map[string]interface{}{
		"enrollment_id": enrollmentID,
		"updated_by":    updatedBy,
	}); err != nil {
		return fmt.Errorf("outbox store: %w", err)
	}

	if err := tx.Commit(); err != nil {
		return fmt.Errorf("commit tx: %w", err)
	}

	if s.notificationService != nil && enrollment != nil {
		student, err := s.studentRepo.GetByID(ctx, s.pgClient.DB, enrollment.StudentID)
		if err != nil {
			logger.Error("failed to fetch student for notification", zap.Error(err))
		} else if student != nil {
			notifReq := s.buildNotificationRequest(enrollment, student, "completed", updatedBy)
			if _, err := s.notificationService.Create(ctx, notifReq, uuid.New().String()); err != nil {
				logger.Error("failed to create notification", zap.Error(err))
			}
		}
	}

	return nil
}

func (s *enrollmentService) Withdraw(ctx context.Context, enrollmentID uuid.UUID, updatedBy *uuid.UUID, idempotencyKey string) error {
	logger := s.logger.With(
		zap.String("method", "Withdraw"),
		zap.String("enrollment_id", enrollmentID.String()),
		zap.String("idempotency_key", idempotencyKey),
	)

	tx, err := s.pgClient.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("begin tx: %w", err)
	}
	defer tx.Rollback()

	if idempotencyKey != "" {
		var dummy struct{}
		if err := s.idempotencyStore.Get(ctx, tx, idempotencyKey, &dummy); err == nil {
			logger.Info("idempotent operation: already processed")
			return nil
		}
	}

	if err := s.updateStatusWithValidation(ctx, tx, enrollmentID, EnrollmentStatusWithdrawn, updatedBy); err != nil {
		return err
	}

	if idempotencyKey != "" {
		if err := s.idempotencyStore.Store(ctx, tx, idempotencyKey, struct{}{}); err != nil {
			logger.Error("failed to store idempotency key", zap.Error(err))
		}
	}

	enrollment, _ := s.internalGetByIDForUpdate(ctx, tx, enrollmentID)

	if s.auditService != nil {
		_ = s.auditService.LogAction(ctx, nil, nil, "academics", "withdraw", "enrollment",
			&enrollmentID, "user", updatedBy, nil, nil, nil)
	}

	if err := s.storeOutboxEvent(ctx, tx, EventEnrollmentWithdrawn, enrollmentID, map[string]interface{}{
		"enrollment_id": enrollmentID,
		"updated_by":    updatedBy,
	}); err != nil {
		return fmt.Errorf("outbox store: %w", err)
	}

	if err := tx.Commit(); err != nil {
		return fmt.Errorf("commit tx: %w", err)
	}

	if s.notificationService != nil && enrollment != nil {
		student, err := s.studentRepo.GetByID(ctx, s.pgClient.DB, enrollment.StudentID)
		if err != nil {
			logger.Error("failed to fetch student for notification", zap.Error(err))
		} else if student != nil {
			notifReq := s.buildNotificationRequest(enrollment, student, "withdrawn", updatedBy)
			if _, err := s.notificationService.Create(ctx, notifReq, uuid.New().String()); err != nil {
				logger.Error("failed to create notification", zap.Error(err))
			}
		}
	}

	return nil
}

func (s *enrollmentService) UpdateStatus(ctx context.Context, enrollmentID uuid.UUID, status string, updatedBy *uuid.UUID, idempotencyKey string) error {
	logger := s.logger.With(
		zap.String("method", "UpdateStatus"),
		zap.String("enrollment_id", enrollmentID.String()),
		zap.String("new_status", status),
		zap.String("idempotency_key", idempotencyKey),
	)

	if status != EnrollmentStatusActive && status != EnrollmentStatusCompleted && status != EnrollmentStatusWithdrawn {
		return fmt.Errorf("%w: invalid status %s", ErrInvalidInput, status)
	}

	tx, err := s.pgClient.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("begin tx: %w", err)
	}
	defer tx.Rollback()

	if idempotencyKey != "" {
		var dummy struct{}
		if err := s.idempotencyStore.Get(ctx, tx, idempotencyKey, &dummy); err == nil {
			logger.Info("idempotent operation: already processed")
			return nil
		}
	}

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

	if idempotencyKey != "" {
		if err := s.idempotencyStore.Store(ctx, tx, idempotencyKey, struct{}{}); err != nil {
			logger.Error("failed to store idempotency key", zap.Error(err))
		}
	}

	if s.auditService != nil {
		_ = s.auditService.LogAction(ctx, nil, nil, "academics", "update_status", "enrollment",
			&enrollmentID, "user", updatedBy, nil, nil, map[string]interface{}{
				"old_status": enrollment.Status,
				"new_status": status,
			})
	}

	if err := s.storeOutboxEvent(ctx, tx, EventEnrollmentUpdated, enrollmentID, map[string]interface{}{
		"enrollment_id": enrollmentID,
		"old_status":    enrollment.Status,
		"new_status":    status,
		"updated_by":    updatedBy,
	}); err != nil {
		return fmt.Errorf("outbox store: %w", err)
	}

	if err := tx.Commit(); err != nil {
		return fmt.Errorf("commit tx: %w", err)
	}

	return nil
}

func (s *enrollmentService) Update(ctx context.Context, req UpdateEnrollmentRequest, idempotencyKey string) (*models.Enrollment, error) {
	logger := s.logger.With(
		zap.String("method", "Update"),
		zap.String("enrollment_id", req.EnrollmentID.String()),
		zap.String("idempotency_key", idempotencyKey),
	)

	if req.EnrollmentID == uuid.Nil {
		return nil, fmt.Errorf("%w: enrollment_id required", ErrInvalidInput)
	}

	tx, err := s.pgClient.BeginTx(ctx, nil)
	if err != nil {
		return nil, fmt.Errorf("begin tx: %w", err)
	}
	defer tx.Rollback()

	if idempotencyKey != "" {
		var existing models.Enrollment
		if err := s.idempotencyStore.Get(ctx, tx, idempotencyKey, &existing); err == nil && existing.EnrollmentID != uuid.Nil {
			logger.Info("returning idempotent response")
			return &existing, nil
		}
	}

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

	if idempotencyKey != "" {
		if err := s.idempotencyStore.Store(ctx, tx, idempotencyKey, enrollment); err != nil {
			logger.Error("failed to store idempotency key", zap.Error(err))
		}
	}

	if s.auditService != nil {
		_ = s.auditService.LogAction(ctx, nil, nil, "academics", "update", "enrollment",
			&enrollment.EnrollmentID, "user", req.UpdatedBy, nil, nil, map[string]interface{}{
				"old_section_id": old.SectionID,
				"new_section_id": enrollment.SectionID,
				"old_status":     old.Status,
				"new_status":     enrollment.Status,
			})
	}

	if err := s.storeOutboxEvent(ctx, tx, EventEnrollmentUpdated, enrollment.EnrollmentID, enrollment); err != nil {
		return nil, fmt.Errorf("outbox store: %w", err)
	}

	if err := tx.Commit(); err != nil {
		return nil, fmt.Errorf("commit tx: %w", err)
	}

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

func (s *enrollmentService) UpdateRollNumber(ctx context.Context, enrollmentID uuid.UUID, rollNumber string, updatedBy *uuid.UUID, idempotencyKey string) error {
	logger := s.logger.With(
		zap.String("method", "UpdateRollNumber"),
		zap.String("enrollment_id", enrollmentID.String()),
		zap.String("idempotency_key", idempotencyKey),
	)

	tx, err := s.pgClient.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("begin tx: %w", err)
	}
	defer tx.Rollback()

	if idempotencyKey != "" {
		var dummy struct{}
		if err := s.idempotencyStore.Get(ctx, tx, idempotencyKey, &dummy); err == nil {
			logger.Info("idempotent operation: already processed")
			return nil
		}
	}

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

	if idempotencyKey != "" {
		if err := s.idempotencyStore.Store(ctx, tx, idempotencyKey, struct{}{}); err != nil {
			logger.Error("failed to store idempotency key", zap.Error(err))
		}
	}

	if s.auditService != nil {
		_ = s.auditService.LogAction(ctx, nil, nil, "academics", "update_roll_number", "enrollment",
			&enrollmentID, "user", updatedBy, nil, nil, map[string]interface{}{
				"new_roll_number": rollNumber,
			})
	}

	if err := s.storeOutboxEvent(ctx, tx, EventEnrollmentUpdated, enrollmentID, map[string]interface{}{
		"enrollment_id":   enrollmentID,
		"new_roll_number": rollNumber,
		"updated_by":      updatedBy,
	}); err != nil {
		return fmt.Errorf("outbox store: %w", err)
	}

	if err := tx.Commit(); err != nil {
		return fmt.Errorf("commit tx: %w", err)
	}

	return nil
}

func (s *enrollmentService) TransferSection(ctx context.Context, req TransferSectionRequest, idempotencyKey string) (*models.Enrollment, error) {
	logger := s.logger.With(
		zap.String("method", "TransferSection"),
		zap.String("enrollment_id", req.EnrollmentID.String()),
		zap.String("new_section_id", req.NewSectionID.String()),
		zap.String("idempotency_key", idempotencyKey),
	)

	if req.EnrollmentID == uuid.Nil || req.NewSectionID == uuid.Nil {
		return nil, fmt.Errorf("%w: enrollment_id and new_section_id required", ErrInvalidInput)
	}

	tx, err := s.pgClient.BeginTx(ctx, nil)
	if err != nil {
		return nil, fmt.Errorf("begin tx: %w", err)
	}
	defer tx.Rollback()

	if idempotencyKey != "" {
		var existing models.Enrollment
		if err := s.idempotencyStore.Get(ctx, tx, idempotencyKey, &existing); err == nil && existing.EnrollmentID != uuid.Nil {
			logger.Info("returning idempotent response")
			return &existing, nil
		}
	}

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

	if idempotencyKey != "" {
		if err := s.idempotencyStore.Store(ctx, tx, idempotencyKey, enrollment); err != nil {
			logger.Error("failed to store idempotency key", zap.Error(err))
		}
	}

	if s.auditService != nil {
		_ = s.auditService.LogAction(ctx, nil, nil, "academics", "transfer_section", "enrollment",
			&enrollment.EnrollmentID, "user", req.UpdatedBy, nil, nil, map[string]interface{}{
				"old_section_id": old.SectionID,
				"new_section_id": enrollment.SectionID,
			})
	}

	if err := s.storeOutboxEvent(ctx, tx, EventEnrollmentTransferred, enrollment.EnrollmentID, enrollment); err != nil {
		return nil, fmt.Errorf("outbox store: %w", err)
	}

	if err := tx.Commit(); err != nil {
		return nil, fmt.Errorf("commit tx: %w", err)
	}

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

func (s *enrollmentService) BulkTransferSection(ctx context.Context, reqs []TransferSectionRequest, idempotencyKey string) error {
	if len(reqs) == 0 {
		return nil
	}

	logger := s.logger.With(
		zap.String("method", "BulkTransferSection"),
		zap.Int("count", len(reqs)),
		zap.String("idempotency_key", idempotencyKey),
	)

	tx, err := s.pgClient.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("begin tx: %w", err)
	}
	defer tx.Rollback()

	if idempotencyKey != "" {
		var dummy struct{}
		if err := s.idempotencyStore.Get(ctx, tx, idempotencyKey, &dummy); err == nil {
			logger.Info("idempotent operation: already processed")
			return nil
		}
	}

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
		if s.auditService != nil {
			_ = s.auditService.LogAction(ctx, nil, nil, "academics", "bulk_transfer_section", "enrollment",
				&enrollment.EnrollmentID, "user", req.UpdatedBy, nil, nil, nil)
		}
	}

	if idempotencyKey != "" {
		if err := s.idempotencyStore.Store(ctx, tx, idempotencyKey, struct{}{}); err != nil {
			logger.Error("failed to store idempotency key", zap.Error(err))
		}
	}

	if err := s.storeOutboxEvent(ctx, tx, EventEnrollmentTransferred, uuid.Nil, map[string]interface{}{
		"count":      len(reqs),
		"updated_by": reqs[0].UpdatedBy,
	}); err != nil {
		return fmt.Errorf("outbox store: %w", err)
	}

	if err := tx.Commit(); err != nil {
		return fmt.Errorf("commit tx: %w", err)
	}

	logger.Info("bulk transfer completed")
	return nil
}

func (s *enrollmentService) SwapSections(ctx context.Context, enrollmentID1, enrollmentID2 uuid.UUID, updatedBy *uuid.UUID, idempotencyKey string) error {
	logger := s.logger.With(
		zap.String("method", "SwapSections"),
		zap.String("enrollment_id1", enrollmentID1.String()),
		zap.String("enrollment_id2", enrollmentID2.String()),
		zap.String("idempotency_key", idempotencyKey),
	)

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

	if idempotencyKey != "" {
		var dummy struct{}
		if err := s.idempotencyStore.Get(ctx, tx, idempotencyKey, &dummy); err == nil {
			logger.Info("idempotent operation: already processed")
			return nil
		}
	}

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

	if idempotencyKey != "" {
		if err := s.idempotencyStore.Store(ctx, tx, idempotencyKey, struct{}{}); err != nil {
			logger.Error("failed to store idempotency key", zap.Error(err))
		}
	}

	if s.auditService != nil {
		_ = s.auditService.LogAction(ctx, nil, nil, "academics", "swap_sections", "enrollment",
			&e1.EnrollmentID, "user", updatedBy, nil, nil, map[string]interface{}{
				"old_section_id": old1.SectionID,
				"new_section_id": e1.SectionID,
			})
		_ = s.auditService.LogAction(ctx, nil, nil, "academics", "swap_sections", "enrollment",
			&e2.EnrollmentID, "user", updatedBy, nil, nil, map[string]interface{}{
				"old_section_id": old2.SectionID,
				"new_section_id": e2.SectionID,
			})
	}

	if err := s.storeOutboxEvent(ctx, tx, EventEnrollmentUpdated, uuid.Nil, map[string]interface{}{
		"enrollment_id1": enrollmentID1,
		"enrollment_id2": enrollmentID2,
		"updated_by":     updatedBy,
	}); err != nil {
		return fmt.Errorf("outbox store: %w", err)
	}

	if err := tx.Commit(); err != nil {
		return fmt.Errorf("commit tx: %w", err)
	}

	return nil
}

func (s *enrollmentService) PromoteStudent(ctx context.Context, req PromoteStudentRequest, idempotencyKey string) (*models.Enrollment, error) {
	logger := s.logger.With(
		zap.String("method", "PromoteStudent"),
		zap.String("student_id", req.StudentID.String()),
		zap.String("new_section", req.NewSectionID.String()),
		zap.String("new_academic_year", req.NewAcademicYearID.String()),
		zap.String("idempotency_key", idempotencyKey),
	)

	if req.StudentID == uuid.Nil || req.NewSectionID == uuid.Nil || req.NewAcademicYearID == uuid.Nil {
		return nil, fmt.Errorf("%w: student_id, new_section_id, new_academic_year_id required", ErrInvalidInput)
	}

	tx, err := s.pgClient.BeginTx(ctx, nil)
	if err != nil {
		return nil, fmt.Errorf("begin tx: %w", err)
	}
	defer tx.Rollback()

	if idempotencyKey != "" {
		var existing models.Enrollment
		if err := s.idempotencyStore.Get(ctx, tx, idempotencyKey, &existing); err == nil && existing.EnrollmentID != uuid.Nil {
			logger.Info("returning idempotent response")
			return &existing, nil
		}
	}

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

	if idempotencyKey != "" {
		if err := s.idempotencyStore.Store(ctx, tx, idempotencyKey, newEnrollment); err != nil {
			logger.Error("failed to store idempotency key", zap.Error(err))
		}
	}

	if s.auditService != nil {
		_ = s.auditService.LogAction(ctx, nil, nil, "academics", "promote", "enrollment",
			&newEnrollment.EnrollmentID, "user", req.UpdatedBy, nil, nil, map[string]interface{}{
				"old_enrollment_id": currentEnrollment.EnrollmentID,
				"new_section_id":    req.NewSectionID,
				"new_academic_year": req.NewAcademicYearID,
			})
	}

	if err := s.storeOutboxEvent(ctx, tx, EventEnrollmentPromoted, newEnrollment.EnrollmentID, map[string]interface{}{
		"student_id":           req.StudentID,
		"old_enrollment_id":    currentEnrollment.EnrollmentID,
		"new_enrollment_id":    newEnrollmentID,
		"new_section_id":       req.NewSectionID,
		"new_academic_year_id": req.NewAcademicYearID,
		"updated_by":           req.UpdatedBy,
	}); err != nil {
		return nil, fmt.Errorf("outbox store: %w", err)
	}

	if err := tx.Commit(); err != nil {
		return nil, fmt.Errorf("commit tx: %w", err)
	}

	if s.notificationService != nil {
		notifReq := s.buildNotificationRequest(newEnrollment, student, "promoted", req.UpdatedBy)
		if _, err := s.notificationService.Create(ctx, notifReq, uuid.New().String()); err != nil {
			logger.Error("failed to create notification", zap.Error(err))
		}
	}

	return newEnrollment, nil
}

func (s *enrollmentService) BulkPromote(ctx context.Context, reqs []PromoteStudentRequest, idempotencyKey string) error {
	if len(reqs) == 0 {
		return nil
	}

	logger := s.logger.With(
		zap.String("method", "BulkPromote"),
		zap.Int("count", len(reqs)),
		zap.String("idempotency_key", idempotencyKey),
	)

	tx, err := s.pgClient.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("begin tx: %w", err)
	}
	defer tx.Rollback()

	if idempotencyKey != "" {
		var dummy struct{}
		if err := s.idempotencyStore.Get(ctx, tx, idempotencyKey, &dummy); err == nil {
			logger.Info("idempotent operation: already processed")
			return nil
		}
	}

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

	if idempotencyKey != "" {
		if err := s.idempotencyStore.Store(ctx, tx, idempotencyKey, struct{}{}); err != nil {
			logger.Error("failed to store idempotency key", zap.Error(err))
		}
	}

	if err := s.storeOutboxEvent(ctx, tx, EventEnrollmentPromoted, uuid.Nil, map[string]interface{}{
		"count":      len(reqs),
		"updated_by": reqs[0].UpdatedBy,
	}); err != nil {
		return fmt.Errorf("outbox store: %w", err)
	}

	if err := tx.Commit(); err != nil {
		return fmt.Errorf("commit tx: %w", err)
	}

	logger.Info("bulk promotions completed")
	return nil
}

func (s *enrollmentService) PromoteSection(ctx context.Context, sectionID, nextSectionID uuid.UUID, academicYearID uuid.UUID, updatedBy *uuid.UUID, idempotencyKey string) error {
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
	return s.BulkPromote(ctx, reqs, idempotencyKey)
}

func (s *enrollmentService) RollOverAcademicYear(ctx context.Context, fromYearID, toYearID uuid.UUID, updatedBy *uuid.UUID, idempotencyKey string) error {
	s.logger.Warn("RollOverAcademicYear not implemented",
		zap.String("from_year", fromYearID.String()),
		zap.String("to_year", toYearID.String()))
	return nil
}

func (s *enrollmentService) GraduateStudent(ctx context.Context, enrollmentID uuid.UUID, updatedBy *uuid.UUID, idempotencyKey string) error {
	logger := s.logger.With(
		zap.String("method", "GraduateStudent"),
		zap.String("enrollment_id", enrollmentID.String()),
		zap.String("idempotency_key", idempotencyKey),
	)

	tx, err := s.pgClient.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("begin tx: %w", err)
	}
	defer tx.Rollback()

	if idempotencyKey != "" {
		var dummy struct{}
		if err := s.idempotencyStore.Get(ctx, tx, idempotencyKey, &dummy); err == nil {
			logger.Info("idempotent operation: already processed")
			return nil
		}
	}

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

	if idempotencyKey != "" {
		if err := s.idempotencyStore.Store(ctx, tx, idempotencyKey, struct{}{}); err != nil {
			logger.Error("failed to store idempotency key", zap.Error(err))
		}
	}

	if s.auditService != nil {
		_ = s.auditService.LogAction(ctx, nil, nil, "academics", "graduate", "enrollment",
			&enrollmentID, "user", updatedBy, nil, nil, nil)
	}

	if err := s.storeOutboxEvent(ctx, tx, EventEnrollmentCompleted, enrollmentID, map[string]interface{}{
		"enrollment_id": enrollmentID,
		"student_id":    enrollment.StudentID,
		"updated_by":    updatedBy,
	}); err != nil {
		return fmt.Errorf("outbox store: %w", err)
	}

	if err := tx.Commit(); err != nil {
		return fmt.Errorf("commit tx: %w", err)
	}

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

func (s *enrollmentService) MarkAlumni(ctx context.Context, studentID uuid.UUID, updatedBy *uuid.UUID, idempotencyKey string) error {
	logger := s.logger.With(
		zap.String("method", "MarkAlumni"),
		zap.String("student_id", studentID.String()),
		zap.String("idempotency_key", idempotencyKey),
	)

	tx, err := s.pgClient.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("begin tx: %w", err)
	}
	defer tx.Rollback()

	if idempotencyKey != "" {
		var dummy struct{}
		if err := s.idempotencyStore.Get(ctx, tx, idempotencyKey, &dummy); err == nil {
			logger.Info("idempotent operation: already processed")
			return nil
		}
	}

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

	if idempotencyKey != "" {
		if err := s.idempotencyStore.Store(ctx, tx, idempotencyKey, struct{}{}); err != nil {
			logger.Error("failed to store idempotency key", zap.Error(err))
		}
	}

	if s.auditService != nil {
		_ = s.auditService.LogAction(ctx, nil, nil, "academics", "mark_alumni", "student",
			&studentID, "user", updatedBy, nil, nil, nil)
	}

	if err := s.storeOutboxEvent(ctx, tx, EventEnrollmentCompleted, studentID, map[string]interface{}{
		"student_id": studentID,
		"updated_by": updatedBy,
	}); err != nil {
		return fmt.Errorf("outbox store: %w", err)
	}

	if err := tx.Commit(); err != nil {
		return fmt.Errorf("commit tx: %w", err)
	}

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

func (s *enrollmentService) BulkUpdateStatus(ctx context.Context, req BulkEnrollmentStatusUpdateRequest, idempotencyKey string) error {
	if len(req.EnrollmentIDs) == 0 {
		return nil
	}
	if req.Status != EnrollmentStatusActive && req.Status != EnrollmentStatusCompleted && req.Status != EnrollmentStatusWithdrawn {
		return fmt.Errorf("%w: invalid status", ErrInvalidInput)
	}

	logger := s.logger.With(
		zap.String("method", "BulkUpdateStatus"),
		zap.Int("count", len(req.EnrollmentIDs)),
		zap.String("status", req.Status),
		zap.String("idempotency_key", idempotencyKey),
	)

	tx, err := s.pgClient.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("begin tx: %w", err)
	}
	defer tx.Rollback()

	if idempotencyKey != "" {
		var dummy struct{}
		if err := s.idempotencyStore.Get(ctx, tx, idempotencyKey, &dummy); err == nil {
			logger.Info("idempotent operation: already processed")
			return nil
		}
	}

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

	if idempotencyKey != "" {
		if err := s.idempotencyStore.Store(ctx, tx, idempotencyKey, struct{}{}); err != nil {
			logger.Error("failed to store idempotency key", zap.Error(err))
		}
	}

	if s.auditService != nil {
		_ = s.auditService.LogAction(ctx, nil, nil, "academics", "bulk_update_status", "enrollment",
			nil, "user", req.UpdatedBy, nil, nil, map[string]interface{}{
				"enrollment_ids": req.EnrollmentIDs,
				"new_status":     req.Status,
				"count":          len(req.EnrollmentIDs),
			})
	}

	if err := s.storeOutboxEvent(ctx, tx, EventEnrollmentUpdated, uuid.Nil, map[string]interface{}{
		"enrollment_ids": req.EnrollmentIDs,
		"new_status":     req.Status,
		"updated_by":     req.UpdatedBy,
	}); err != nil {
		return fmt.Errorf("outbox store: %w", err)
	}

	if err := tx.Commit(); err != nil {
		return fmt.Errorf("commit tx: %w", err)
	}

	return nil
}

func (s *enrollmentService) BulkAssignRollNumbers(ctx context.Context, req BulkRollNumberRequest, idempotencyKey string) error {
	if len(req.RollNumbers) == 0 {
		return nil
	}

	logger := s.logger.With(
		zap.String("method", "BulkAssignRollNumbers"),
		zap.Int("count", len(req.RollNumbers)),
		zap.String("idempotency_key", idempotencyKey),
	)

	tx, err := s.pgClient.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("begin tx: %w", err)
	}
	defer tx.Rollback()

	if idempotencyKey != "" {
		var dummy struct{}
		if err := s.idempotencyStore.Get(ctx, tx, idempotencyKey, &dummy); err == nil {
			logger.Info("idempotent operation: already processed")
			return nil
		}
	}

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

	if idempotencyKey != "" {
		if err := s.idempotencyStore.Store(ctx, tx, idempotencyKey, struct{}{}); err != nil {
			logger.Error("failed to store idempotency key", zap.Error(err))
		}
	}

	if s.auditService != nil {
		_ = s.auditService.LogAction(ctx, nil, nil, "academics", "bulk_assign_roll_numbers", "enrollment",
			nil, "user", req.UpdatedBy, nil, nil, map[string]interface{}{
				"count": len(req.RollNumbers),
			})
	}

	if err := s.storeOutboxEvent(ctx, tx, EventEnrollmentUpdated, uuid.Nil, map[string]interface{}{
		"roll_numbers_assigned": len(req.RollNumbers),
		"updated_by":            req.UpdatedBy,
	}); err != nil {
		return fmt.Errorf("outbox store: %w", err)
	}

	if err := tx.Commit(); err != nil {
		return fmt.Errorf("commit tx: %w", err)
	}

	return nil
}

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

func stringPtr(s string) *string {
	return &s
}

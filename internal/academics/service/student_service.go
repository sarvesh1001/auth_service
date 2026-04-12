package service

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"strings"

	"github.com/google/uuid"
	"go.uber.org/zap"

	"auth-service/internal/academics/models"
	"auth-service/internal/academics/repository"
	"auth-service/internal/client"
	"auth-service/internal/infrastructure/audit"
	"auth-service/internal/infrastructure/idempotency"
	"auth-service/internal/infrastructure/outbox"
)

// StudentService defines the business operations for students.
type StudentService interface {
	Create(ctx context.Context, req CreateStudentRequest, idempotencyKey string) (*models.Student, error)
	BulkCreate(ctx context.Context, req []CreateStudentRequest) ([]*models.Student, error)
	Upsert(ctx context.Context, req CreateStudentRequest) (*models.Student, error)
	GetByID(ctx context.Context, id uuid.UUID) (*models.Student, error)
	GetByAdmissionNumber(ctx context.Context, companyID uuid.UUID, admissionNo string) (*models.Student, error)
	List(ctx context.Context, filter repository.StudentFilter, p repository.Pagination, s repository.Sort) ([]*models.Student, error)
	ListActive(ctx context.Context, companyID uuid.UUID) ([]*models.Student, error)
	Count(ctx context.Context, filter repository.StudentFilter) (int64, error)
	Exists(ctx context.Context, companyID uuid.UUID, admissionNo string) (bool, error)
	ValidateAdmissionNumber(ctx context.Context, companyID uuid.UUID, admissionNo string) error
	Update(ctx context.Context, req UpdateStudentRequest) (*models.Student, error)
	UpdateContactInfo(ctx context.Context, studentID uuid.UUID, phone string, updatedBy *uuid.UUID) error
	Activate(ctx context.Context, id uuid.UUID, updatedBy *uuid.UUID) error
	Deactivate(ctx context.Context, id uuid.UUID, updatedBy *uuid.UUID) error
	Promote(ctx context.Context, studentID uuid.UUID, newCourseID, newSectionID uuid.UUID, updatedBy *uuid.UUID) error
	Graduate(ctx context.Context, studentID uuid.UUID, updatedBy *uuid.UUID) error
	Dropout(ctx context.Context, studentID uuid.UUID, reason string, updatedBy *uuid.UUID) error
	BulkPromote(ctx context.Context, studentIDs []uuid.UUID, newCourseID, newSectionID uuid.UUID, updatedBy *uuid.UUID) error
	BulkUpdateStatus(ctx context.Context, studentIDs []uuid.UUID, status string, updatedBy *uuid.UUID) error
	Delete(ctx context.Context, id uuid.UUID, deletedBy *uuid.UUID) error
	ValidateSectionCapacity(ctx context.Context, sectionID uuid.UUID) error
	ValidateStudentPromotion(ctx context.Context, studentID uuid.UUID, newCourseID uuid.UUID) error
	Search(ctx context.Context, companyID uuid.UUID, query string, limit int) ([]*models.Student, error)
}

type studentService struct {
	repo           repository.StudentRepository
	enrollmentRepo repository.EnrollmentRepository
	sectionRepo    repository.SectionRepository
	courseRepo     repository.CourseRepository
	termRepo       repository.TermRepository
	ayRepo         repository.AcademicYearRepository
	pgClient       *client.PostgresClient
	logger         *zap.Logger
	notifSvc       NotificationService

	// Infrastructure dependencies
	outboxRepo       outbox.Repository
	idempotencyStore idempotency.Store
	auditService     *audit.AuditService
}

// NewStudentService creates a new student service instance.
func NewStudentService(
	repo repository.StudentRepository,
	enrollmentRepo repository.EnrollmentRepository,
	sectionRepo repository.SectionRepository,
	courseRepo repository.CourseRepository,
	termRepo repository.TermRepository,
	ayRepo repository.AcademicYearRepository,
	pgClient *client.PostgresClient,
	logger *zap.Logger,
	notifSvc NotificationService,
	outboxRepo outbox.Repository,
	idempotencyStore idempotency.Store,
	auditService *audit.AuditService,
) StudentService {
	return &studentService{
		repo:             repo,
		enrollmentRepo:   enrollmentRepo,
		sectionRepo:      sectionRepo,
		courseRepo:       courseRepo,
		termRepo:         termRepo,
		ayRepo:           ayRepo,
		pgClient:         pgClient,
		logger:           logger.Named("student_service"),
		notifSvc:         notifSvc,
		outboxRepo:       outboxRepo,
		idempotencyStore: idempotencyStore,
		auditService:     auditService,
	}
}

// ---------------------------------------------------------------------
// Helper: store outbox event for a student
// ---------------------------------------------------------------------
func (s *studentService) storeOutboxEvent(ctx context.Context, tx *sql.Tx, eventType EventType, student *models.Student, extraData interface{}) error {
	var payload []byte
	var err error
	if extraData != nil {
		payload, err = json.Marshal(extraData)
	} else {
		payload, err = json.Marshal(student)
	}
	if err != nil {
		return fmt.Errorf("marshal outbox payload: %w", err)
	}

	outboxEvent := &outbox.Event{
		EventID:       uuid.New().String(),
		AggregateType: "student",
		AggregateID:   student.StudentID.String(),
		EventType:     string(eventType),
		Payload:       payload,
		Headers:       map[string]string{},
		Status:        "pending",
	}
	return s.outboxRepo.Store(ctx, tx, outboxEvent)
}

// ---------------------------------------------------------------------
// Helper: send notification (unchanged)
// ---------------------------------------------------------------------
func (s *studentService) sendNotification(ctx context.Context, studentID, companyID uuid.UUID, title, message string, notifType models.NotificationType, priority models.NotificationPriority, createdBy *uuid.UUID) {
	if s.notifSvc == nil {
		return
	}
	targets := []NotificationTargetInput{
		{
			TargetType:     models.TargetStudent,
			TargetEntityID: studentID,
		},
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
	_, err := s.notifSvc.Create(context.Background(), req, "")
	if err != nil {
		s.logger.Error("failed to send notification",
			zap.String("student_id", studentID.String()),
			zap.String("title", title),
			zap.Error(err))
	}
}

// ---------------------------------------------------------------------
// Input sanitization & validation helpers
// ---------------------------------------------------------------------
func (s *studentService) sanitizeCreate(req *CreateStudentRequest) {
	req.FirstName = strings.TrimSpace(req.FirstName)
	req.LastName = strings.TrimSpace(req.LastName)
	req.AdmissionNo = strings.TrimSpace(strings.ToUpper(req.AdmissionNo))
	req.Email = strings.TrimSpace(req.Email)
	req.Phone = strings.TrimSpace(req.Phone)
}

func (s *studentService) sanitizeUpdate(req *UpdateStudentRequest) {
	req.AdmissionNo = strings.TrimSpace(strings.ToUpper(req.AdmissionNo))
	req.Email = strings.TrimSpace(req.Email)
	req.Phone = strings.TrimSpace(req.Phone)
}

func (s *studentService) validateCreateInput(req CreateStudentRequest) error {
	if req.CompanyID == uuid.Nil {
		return fmt.Errorf("%w: company_id is required", ErrInvalidInput)
	}
	if req.FirstName == "" {
		return fmt.Errorf("%w: first_name is required", ErrInvalidInput)
	}
	if req.AdmissionNo == "" {
		return fmt.Errorf("%w: admission_no is required", ErrInvalidInput)
	}
	if req.Status == "" {
		req.Status = string(models.StudentActive)
	}
	if !models.IsValidStudentStatus(req.Status) {
		return fmt.Errorf("%w: invalid status %q", ErrInvalidInput, req.Status)
	}
	return nil
}

func (s *studentService) validateUpdateInput(req UpdateStudentRequest) error {
	if req.StudentID == uuid.Nil {
		return fmt.Errorf("%w: student_id is required", ErrInvalidInput)
	}
	if req.AdmissionNo == "" {
		return fmt.Errorf("%w: admission_no is required", ErrInvalidInput)
	}
	if req.Status != "" && !models.IsValidStudentStatus(req.Status) {
		return fmt.Errorf("%w: invalid status %q", ErrInvalidInput, req.Status)
	}
	return nil
}

// ---------------------------------------------------------------------
// Create
// ---------------------------------------------------------------------
func (s *studentService) Create(ctx context.Context, req CreateStudentRequest, idempotencyKey string) (*models.Student, error) {
	logger := s.logger.With(
		zap.String("method", "Create"),
		zap.String("company_id", req.CompanyID.String()),
		zap.String("admission_no", req.AdmissionNo),
		zap.String("idempotency_key", idempotencyKey),
	)
	s.sanitizeCreate(&req)

	tx, err := s.pgClient.BeginTx(ctx, nil)
	if err != nil {
		return nil, fmt.Errorf("begin tx: %w", err)
	}
	defer tx.Rollback()

	// Idempotency check
	if idempotencyKey != "" {
		var existing models.Student
		if err := s.idempotencyStore.Get(ctx, tx, idempotencyKey, &existing); err == nil && existing.StudentID != uuid.Nil {
			logger.Info("returning idempotent response")
			return &existing, nil
		}
	}

	if err := s.validateCreateInput(req); err != nil {
		return nil, err
	}
	exists, err := s.repo.ExistsByAdmissionNumber(ctx, tx, req.CompanyID, req.AdmissionNo)
	if err != nil {
		return nil, err
	}
	if exists {
		return nil, fmt.Errorf("%w: admission number %s already exists", ErrDuplicate, req.AdmissionNo)
	}

	student := &models.Student{
		CompanyID:             req.CompanyID,
		FirstName:             req.FirstName,
		LastName:              req.LastName,
		AdmissionNo:           req.AdmissionNo,
		Email:                 req.Email,
		Phone:                 req.Phone,
		DateOfBirth:           req.DateOfBirth,
		Gender:                req.Gender,
		BloodGroup:            req.BloodGroup,
		Nationality:           req.Nationality,
		Religion:              req.Religion,
		Category:              req.Category,
		AadharNo:              req.AadharNo,
		EmergencyContactName:  req.EmergencyContactName,
		EmergencyContactPhone: req.EmergencyContactPhone,
		MedicalConditions:     req.MedicalConditions,
		Status:                models.StudentStatus(req.Status),
		CreatedBy:             req.CreatedBy,
		UpdatedBy:             req.UpdatedBy,
	}

	if err := s.repo.Create(ctx, tx, student); err != nil {
		return nil, err
	}

	if idempotencyKey != "" {
		if err := s.idempotencyStore.Store(ctx, tx, idempotencyKey, student); err != nil {
			logger.Error("failed to store idempotency key", zap.Error(err))
		}
	}

	// Audit log
	if s.auditService != nil {
		_ = s.auditService.LogAction(ctx, nil, &student.CompanyID, "academics", "create", "student",
			&student.StudentID, "user", req.CreatedBy, nil, nil, map[string]interface{}{
				"admission_no": student.AdmissionNo,
				"first_name":   student.FirstName,
			})
	}

	// Outbox event
	if err := s.storeOutboxEvent(ctx, tx, EventStudentCreated, student, nil); err != nil {
		return nil, fmt.Errorf("outbox store: %w", err)
	}

	if err := tx.Commit(); err != nil {
		return nil, fmt.Errorf("commit tx: %w", err)
	}

	title := "Welcome to the School"
	message := fmt.Sprintf("Dear %s %s, your student profile has been created successfully. Admission number: %s.",
		student.FirstName, student.LastName, student.AdmissionNo)
	s.sendNotification(ctx, student.StudentID, student.CompanyID, title, message, models.NotificationTypeInfo, models.PriorityNormal, req.CreatedBy)

	logger.Info("student created", zap.String("id", student.StudentID.String()))
	return student, nil
}

// ---------------------------------------------------------------------
// BulkCreate
// ---------------------------------------------------------------------
func (s *studentService) BulkCreate(ctx context.Context, reqs []CreateStudentRequest) ([]*models.Student, error) {
	if len(reqs) == 0 {
		return nil, nil
	}
	logger := s.logger.With(zap.String("method", "BulkCreate"), zap.Int("count", len(reqs)))
	idempotencyKey, _ := ctx.Value("idempotency_key").(string)

	tx, err := s.pgClient.BeginTx(ctx, nil)
	if err != nil {
		return nil, fmt.Errorf("begin tx: %w", err)
	}
	defer tx.Rollback()

	if idempotencyKey != "" {
		var existing []*models.Student
		if err := s.idempotencyStore.Get(ctx, tx, idempotencyKey, &existing); err == nil && existing != nil {
			logger.Info("returning idempotent response for bulk create")
			return existing, nil
		}
	}

	// Sanitize and validate all
	for i := range reqs {
		s.sanitizeCreate(&reqs[i])
		if err := s.validateCreateInput(reqs[i]); err != nil {
			return nil, fmt.Errorf("item %d: %w", i, err)
		}
	}
	// Check duplicates in batch
	admissionSet := make(map[string]int)
	for i, req := range reqs {
		if _, dup := admissionSet[req.AdmissionNo]; dup {
			return nil, fmt.Errorf("item %d: duplicate admission number %s in batch", i, req.AdmissionNo)
		}
		admissionSet[req.AdmissionNo] = i
	}
	// Check against DB
	for admission := range admissionSet {
		exists, err := s.repo.ExistsByAdmissionNumber(ctx, tx, reqs[0].CompanyID, admission)
		if err != nil {
			return nil, err
		}
		if exists {
			return nil, fmt.Errorf("%w: admission number %s already exists", ErrDuplicate, admission)
		}
	}

	students := make([]*models.Student, 0, len(reqs))
	for _, req := range reqs {
		students = append(students, &models.Student{
			CompanyID:             req.CompanyID,
			FirstName:             req.FirstName,
			LastName:              req.LastName,
			AdmissionNo:           req.AdmissionNo,
			Email:                 req.Email,
			Phone:                 req.Phone,
			DateOfBirth:           req.DateOfBirth,
			Gender:                req.Gender,
			BloodGroup:            req.BloodGroup,
			Nationality:           req.Nationality,
			Religion:              req.Religion,
			Category:              req.Category,
			AadharNo:              req.AadharNo,
			EmergencyContactName:  req.EmergencyContactName,
			EmergencyContactPhone: req.EmergencyContactPhone,
			MedicalConditions:     req.MedicalConditions,
			Status:                models.StudentStatus(req.Status),
			CreatedBy:             req.CreatedBy,
			UpdatedBy:             req.UpdatedBy,
		})
	}

	if err := s.repo.BulkCreate(ctx, tx, students); err != nil {
		return nil, err
	}

	if idempotencyKey != "" {
		if err := s.idempotencyStore.Store(ctx, tx, idempotencyKey, students); err != nil {
			logger.Error("failed to store idempotency key", zap.Error(err))
		}
	}

	// Audit and outbox for each student
	for _, stu := range students {
		if s.auditService != nil {
			_ = s.auditService.LogAction(ctx, nil, &stu.CompanyID, "academics", "bulk_create", "student",
				&stu.StudentID, "user", stu.CreatedBy, nil, nil, map[string]interface{}{
					"admission_no": stu.AdmissionNo,
				})
		}
		if err := s.storeOutboxEvent(ctx, tx, EventStudentCreated, stu, nil); err != nil {
			return nil, fmt.Errorf("outbox store for %s: %w", stu.StudentID, err)
		}
	}

	if err := tx.Commit(); err != nil {
		return nil, fmt.Errorf("commit tx: %w", err)
	}

	for _, stu := range students {
		title := "Welcome to the School"
		message := fmt.Sprintf("Dear %s %s, your student profile has been created successfully. Admission number: %s.",
			stu.FirstName, stu.LastName, stu.AdmissionNo)
		s.sendNotification(ctx, stu.StudentID, stu.CompanyID, title, message, models.NotificationTypeInfo, models.PriorityNormal, stu.CreatedBy)
	}
	logger.Info("bulk created students", zap.Int("count", len(students)))
	return students, nil
}

// ---------------------------------------------------------------------
// Upsert
// ---------------------------------------------------------------------
func (s *studentService) Upsert(ctx context.Context, req CreateStudentRequest) (*models.Student, error) {
	logger := s.logger.With(
		zap.String("method", "Upsert"),
		zap.String("company_id", req.CompanyID.String()),
		zap.String("admission_no", req.AdmissionNo),
	)
	idempotencyKey, _ := ctx.Value("idempotency_key").(string)
	s.sanitizeCreate(&req)

	tx, err := s.pgClient.BeginTx(ctx, nil)
	if err != nil {
		return nil, fmt.Errorf("begin tx: %w", err)
	}
	defer tx.Rollback()

	if idempotencyKey != "" {
		var existing *models.Student
		if err := s.idempotencyStore.Get(ctx, tx, idempotencyKey, &existing); err == nil && existing != nil {
			logger.Info("idempotent upsert, returning cached")
			return existing, nil
		}
	}

	if err := s.validateCreateInput(req); err != nil {
		return nil, err
	}

	existing, err := s.repo.GetByAdmissionNumber(ctx, tx, req.CompanyID, req.AdmissionNo)
	if err != nil {
		return nil, err
	}

	var student *models.Student
	var eventType EventType
	if existing == nil {
		student = &models.Student{
			CompanyID:             req.CompanyID,
			FirstName:             req.FirstName,
			LastName:              req.LastName,
			AdmissionNo:           req.AdmissionNo,
			Email:                 req.Email,
			Phone:                 req.Phone,
			DateOfBirth:           req.DateOfBirth,
			Gender:                req.Gender,
			BloodGroup:            req.BloodGroup,
			Nationality:           req.Nationality,
			Religion:              req.Religion,
			Category:              req.Category,
			AadharNo:              req.AadharNo,
			EmergencyContactName:  req.EmergencyContactName,
			EmergencyContactPhone: req.EmergencyContactPhone,
			MedicalConditions:     req.MedicalConditions,
			Status:                models.StudentStatus(req.Status),
			CreatedBy:             req.CreatedBy,
			UpdatedBy:             req.UpdatedBy,
		}
		if err := s.repo.Create(ctx, tx, student); err != nil {
			return nil, err
		}
		eventType = EventStudentCreated
	} else {
		student = existing
		student.FirstName = req.FirstName
		student.LastName = req.LastName
		student.Email = req.Email
		student.Phone = req.Phone
		student.DateOfBirth = req.DateOfBirth
		student.Gender = req.Gender
		student.BloodGroup = req.BloodGroup
		student.Nationality = req.Nationality
		student.Religion = req.Religion
		student.Category = req.Category
		student.AadharNo = req.AadharNo
		student.EmergencyContactName = req.EmergencyContactName
		student.EmergencyContactPhone = req.EmergencyContactPhone
		student.MedicalConditions = req.MedicalConditions
		student.Status = models.StudentStatus(req.Status)
		student.UpdatedBy = req.UpdatedBy
		if err := s.repo.Update(ctx, tx, student); err != nil {
			return nil, err
		}
		eventType = EventStudentUpdated
	}

	if idempotencyKey != "" {
		if err := s.idempotencyStore.Store(ctx, tx, idempotencyKey, student); err != nil {
			logger.Error("failed to store idempotency key", zap.Error(err))
		}
	}

	if s.auditService != nil {
		action := "upsert_create"
		if existing != nil {
			action = "upsert_update"
		}
		_ = s.auditService.LogAction(ctx, nil, &student.CompanyID, "academics", action, "student",
			&student.StudentID, "user", req.UpdatedBy, nil, nil, map[string]interface{}{
				"admission_no": student.AdmissionNo,
				"first_name":   student.FirstName,
			})
	}

	if err := s.storeOutboxEvent(ctx, tx, eventType, student, nil); err != nil {
		return nil, fmt.Errorf("outbox store: %w", err)
	}

	if err := tx.Commit(); err != nil {
		return nil, fmt.Errorf("commit tx: %w", err)
	}

	if existing == nil {
		title := "Welcome to the School"
		message := fmt.Sprintf("Dear %s %s, your student profile has been created successfully. Admission number: %s.",
			student.FirstName, student.LastName, student.AdmissionNo)
		s.sendNotification(ctx, student.StudentID, student.CompanyID, title, message, models.NotificationTypeInfo, models.PriorityNormal, req.CreatedBy)
	} else {
		title := "Profile Updated"
		message := fmt.Sprintf("Dear %s %s, your profile has been updated.", student.FirstName, student.LastName)
		s.sendNotification(ctx, student.StudentID, student.CompanyID, title, message, models.NotificationTypeInfo, models.PriorityNormal, req.UpdatedBy)
	}
	logger.Info("student upserted", zap.String("id", student.StudentID.String()))
	return student, nil
}

// ---------------------------------------------------------------------
// GetByID
// ---------------------------------------------------------------------
func (s *studentService) GetByID(ctx context.Context, id uuid.UUID) (*models.Student, error) {
	stu, err := s.repo.GetByID(ctx, s.pgClient.DB, id)
	if err != nil {
		return nil, err
	}
	if stu == nil {
		return nil, fmt.Errorf("%w: student %s", ErrNotFound, id)
	}
	return stu, nil
}

// ---------------------------------------------------------------------
// GetByAdmissionNumber
// ---------------------------------------------------------------------
func (s *studentService) GetByAdmissionNumber(ctx context.Context, companyID uuid.UUID, admissionNo string) (*models.Student, error) {
	admissionNo = strings.TrimSpace(strings.ToUpper(admissionNo))
	stu, err := s.repo.GetByAdmissionNumber(ctx, s.pgClient.DB, companyID, admissionNo)
	if err != nil {
		return nil, err
	}
	if stu == nil {
		return nil, fmt.Errorf("%w: admission number %s for company %s", ErrNotFound, admissionNo, companyID)
	}
	return stu, nil
}

// ---------------------------------------------------------------------
// List
// ---------------------------------------------------------------------
func (s *studentService) List(ctx context.Context, filter repository.StudentFilter, p repository.Pagination, srt repository.Sort) ([]*models.Student, error) {
	return s.repo.List(ctx, s.pgClient.DB, filter, p, srt)
}

// ---------------------------------------------------------------------
// ListActive
// ---------------------------------------------------------------------
func (s *studentService) ListActive(ctx context.Context, companyID uuid.UUID) ([]*models.Student, error) {
	return s.repo.ListActive(ctx, s.pgClient.DB, companyID)
}

// ---------------------------------------------------------------------
// Count
// ---------------------------------------------------------------------
func (s *studentService) Count(ctx context.Context, filter repository.StudentFilter) (int64, error) {
	return s.repo.Count(ctx, s.pgClient.DB, filter)
}

// ---------------------------------------------------------------------
// Exists
// ---------------------------------------------------------------------
func (s *studentService) Exists(ctx context.Context, companyID uuid.UUID, admissionNo string) (bool, error) {
	admissionNo = strings.TrimSpace(strings.ToUpper(admissionNo))
	return s.repo.ExistsByAdmissionNumber(ctx, s.pgClient.DB, companyID, admissionNo)
}

// ---------------------------------------------------------------------
// ValidateAdmissionNumber
// ---------------------------------------------------------------------
func (s *studentService) ValidateAdmissionNumber(ctx context.Context, companyID uuid.UUID, admissionNo string) error {
	admissionNo = strings.TrimSpace(strings.ToUpper(admissionNo))
	exists, err := s.repo.ExistsByAdmissionNumber(ctx, s.pgClient.DB, companyID, admissionNo)
	if err != nil {
		return err
	}
	if exists {
		return fmt.Errorf("%w: admission number %s", ErrDuplicate, admissionNo)
	}
	return nil
}

// ---------------------------------------------------------------------
// Update
// ---------------------------------------------------------------------
func (s *studentService) Update(ctx context.Context, req UpdateStudentRequest) (*models.Student, error) {
	logger := s.logger.With(zap.String("method", "Update"), zap.String("student_id", req.StudentID.String()))
	idempotencyKey, _ := ctx.Value("idempotency_key").(string)
	s.sanitizeUpdate(&req)

	tx, err := s.pgClient.BeginTx(ctx, nil)
	if err != nil {
		return nil, fmt.Errorf("begin tx: %w", err)
	}
	defer tx.Rollback()

	if idempotencyKey != "" {
		var existing *models.Student
		if err := s.idempotencyStore.Get(ctx, tx, idempotencyKey, &existing); err == nil && existing != nil {
			logger.Info("idempotent update, returning cached")
			return existing, nil
		}
	}

	if err := s.validateUpdateInput(req); err != nil {
		return nil, err
	}

	student, err := s.repo.GetByIDForUpdate(ctx, tx, req.StudentID)
	if err != nil {
		return nil, err
	}
	if student == nil {
		return nil, fmt.Errorf("%w: student %s", ErrNotFound, req.StudentID)
	}

	if req.AdmissionNo != student.AdmissionNo {
		exists, err := s.repo.ExistsByAdmissionNumber(ctx, tx, student.CompanyID, req.AdmissionNo)
		if err != nil {
			return nil, err
		}
		if exists {
			return nil, fmt.Errorf("%w: admission number %s already exists", ErrDuplicate, req.AdmissionNo)
		}
	}

	oldStudent := *student
	student.AdmissionNo = req.AdmissionNo
	student.Email = req.Email
	student.Phone = req.Phone
	student.DateOfBirth = req.DateOfBirth
	student.Gender = req.Gender
	student.BloodGroup = req.BloodGroup
	student.Nationality = req.Nationality
	student.Religion = req.Religion
	student.Category = req.Category
	student.AadharNo = req.AadharNo
	student.EmergencyContactName = req.EmergencyContactName
	student.EmergencyContactPhone = req.EmergencyContactPhone
	student.MedicalConditions = req.MedicalConditions
	if req.Status != "" {
		student.Status = models.StudentStatus(req.Status)
	}
	student.UpdatedBy = req.UpdatedBy

	if err := s.repo.Update(ctx, tx, student); err != nil {
		if errors.Is(err, repository.ErrVersionConflict) {
			return nil, fmt.Errorf("%w: student was modified concurrently", ErrConcurrentUpdate)
		}
		return nil, err
	}

	if idempotencyKey != "" {
		if err := s.idempotencyStore.Store(ctx, tx, idempotencyKey, student); err != nil {
			logger.Error("failed to store idempotency key", zap.Error(err))
		}
	}

	if s.auditService != nil {
		_ = s.auditService.LogAction(ctx, nil, &student.CompanyID, "academics", "update", "student",
			&student.StudentID, "user", req.UpdatedBy, nil, nil, map[string]interface{}{
				"old_admission_no": oldStudent.AdmissionNo,
				"new_admission_no": student.AdmissionNo,
				"old_email":        oldStudent.Email,
				"new_email":        student.Email,
				"old_phone":        oldStudent.Phone,
				"new_phone":        student.Phone,
				"old_status":       oldStudent.Status,
				"new_status":       student.Status,
			})
	}

	if err := s.storeOutboxEvent(ctx, tx, EventStudentUpdated, student, map[string]interface{}{
		"old": oldStudent,
		"new": student,
	}); err != nil {
		return nil, fmt.Errorf("outbox store: %w", err)
	}

	if err := tx.Commit(); err != nil {
		return nil, fmt.Errorf("commit tx: %w", err)
	}

	title := "Profile Updated"
	message := fmt.Sprintf("Dear %s %s, your profile has been updated.", student.FirstName, student.LastName)
	s.sendNotification(ctx, student.StudentID, student.CompanyID, title, message, models.NotificationTypeInfo, models.PriorityNormal, req.UpdatedBy)
	logger.Info("student updated")
	return student, nil
}

// ---------------------------------------------------------------------
// UpdateContactInfo
// ---------------------------------------------------------------------
func (s *studentService) UpdateContactInfo(ctx context.Context, studentID uuid.UUID, phone string, updatedBy *uuid.UUID) error {
	logger := s.logger.With(zap.String("method", "UpdateContactInfo"), zap.String("student_id", studentID.String()))
	idempotencyKey, _ := ctx.Value("idempotency_key").(string)

	tx, err := s.pgClient.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("begin tx: %w", err)
	}
	defer tx.Rollback()

	if idempotencyKey != "" {
		var result map[string]interface{}
		if err := s.idempotencyStore.Get(ctx, tx, idempotencyKey, &result); err == nil && result != nil {
			logger.Info("idempotent update contact, skipping")
			return nil
		}
	}

	student, err := s.repo.GetByIDForUpdate(ctx, tx, studentID)
	if err != nil {
		return err
	}
	if student == nil {
		return fmt.Errorf("%w: student %s", ErrNotFound, studentID)
	}

	if err := s.repo.UpdateContactInfo(ctx, tx, studentID, phone, updatedBy); err != nil {
		return err
	}

	if idempotencyKey != "" {
		if err := s.idempotencyStore.Store(ctx, tx, idempotencyKey, map[string]interface{}{"updated": true}); err != nil {
			logger.Error("failed to store idempotency key", zap.Error(err))
		}
	}

	if s.auditService != nil {
		_ = s.auditService.LogAction(ctx, nil, &student.CompanyID, "academics", "update_contact", "student",
			&studentID, "user", updatedBy, nil, nil, map[string]interface{}{
				"new_phone": phone,
			})
	}

	if err := s.storeOutboxEvent(ctx, tx, EventStudentContactUpdated, student, map[string]interface{}{
		"student_id": studentID,
		"phone":      phone,
		"updated_by": updatedBy,
	}); err != nil {
		return fmt.Errorf("outbox store: %w", err)
	}

	if err := tx.Commit(); err != nil {
		return fmt.Errorf("commit tx: %w", err)
	}

	title := "Contact Information Updated"
	message := fmt.Sprintf("Dear %s %s, your contact phone number has been updated.", student.FirstName, student.LastName)
	s.sendNotification(ctx, studentID, student.CompanyID, title, message, models.NotificationTypeInfo, models.PriorityLow, updatedBy)
	logger.Info("contact info updated")
	return nil
}

// ---------------------------------------------------------------------
// Activate
// ---------------------------------------------------------------------
func (s *studentService) Activate(ctx context.Context, id uuid.UUID, updatedBy *uuid.UUID) error {
	logger := s.logger.With(zap.String("method", "Activate"), zap.String("student_id", id.String()))
	idempotencyKey, _ := ctx.Value("idempotency_key").(string)

	tx, err := s.pgClient.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("begin tx: %w", err)
	}
	defer tx.Rollback()

	if idempotencyKey != "" {
		var result map[string]interface{}
		if err := s.idempotencyStore.Get(ctx, tx, idempotencyKey, &result); err == nil && result != nil {
			logger.Info("idempotent activate, skipping")
			return nil
		}
	}

	student, err := s.repo.GetByIDForUpdate(ctx, tx, id)
	if err != nil {
		return err
	}
	if student == nil {
		return fmt.Errorf("%w: student %s", ErrNotFound, id)
	}

	if err := s.repo.Activate(ctx, tx, id, updatedBy); err != nil {
		return err
	}

	if idempotencyKey != "" {
		if err := s.idempotencyStore.Store(ctx, tx, idempotencyKey, map[string]interface{}{"activated": true}); err != nil {
			logger.Error("failed to store idempotency key", zap.Error(err))
		}
	}

	if s.auditService != nil {
		_ = s.auditService.LogAction(ctx, nil, &student.CompanyID, "academics", "activate", "student",
			&id, "user", updatedBy, nil, nil, map[string]interface{}{
				"status": "active",
			})
	}

	if err := s.storeOutboxEvent(ctx, tx, EventStudentActivated, student, map[string]interface{}{
		"student_id": id,
		"updated_by": updatedBy,
	}); err != nil {
		return fmt.Errorf("outbox store: %w", err)
	}

	if err := tx.Commit(); err != nil {
		return fmt.Errorf("commit tx: %w", err)
	}

	title := "Account Activated"
	message := fmt.Sprintf("Dear %s %s, your account has been activated.", student.FirstName, student.LastName)
	s.sendNotification(ctx, id, student.CompanyID, title, message, models.NotificationTypeInfo, models.PriorityNormal, updatedBy)
	logger.Info("student activated")
	return nil
}

// ---------------------------------------------------------------------
// Deactivate
// ---------------------------------------------------------------------
func (s *studentService) Deactivate(ctx context.Context, id uuid.UUID, updatedBy *uuid.UUID) error {
	logger := s.logger.With(zap.String("method", "Deactivate"), zap.String("student_id", id.String()))
	idempotencyKey, _ := ctx.Value("idempotency_key").(string)

	tx, err := s.pgClient.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("begin tx: %w", err)
	}
	defer tx.Rollback()

	if idempotencyKey != "" {
		var result map[string]interface{}
		if err := s.idempotencyStore.Get(ctx, tx, idempotencyKey, &result); err == nil && result != nil {
			logger.Info("idempotent deactivate, skipping")
			return nil
		}
	}

	student, err := s.repo.GetByIDForUpdate(ctx, tx, id)
	if err != nil {
		return err
	}
	if student == nil {
		return fmt.Errorf("%w: student %s", ErrNotFound, id)
	}

	if err := s.repo.Deactivate(ctx, tx, id, updatedBy); err != nil {
		return err
	}

	if idempotencyKey != "" {
		if err := s.idempotencyStore.Store(ctx, tx, idempotencyKey, map[string]interface{}{"deactivated": true}); err != nil {
			logger.Error("failed to store idempotency key", zap.Error(err))
		}
	}

	if s.auditService != nil {
		_ = s.auditService.LogAction(ctx, nil, &student.CompanyID, "academics", "deactivate", "student",
			&id, "user", updatedBy, nil, nil, map[string]interface{}{
				"status": "deactivated",
			})
	}

	if err := s.storeOutboxEvent(ctx, tx, EventStudentDeactivated, student, map[string]interface{}{
		"student_id": id,
		"updated_by": updatedBy,
	}); err != nil {
		return fmt.Errorf("outbox store: %w", err)
	}

	if err := tx.Commit(); err != nil {
		return fmt.Errorf("commit tx: %w", err)
	}

	title := "Account Deactivated"
	message := fmt.Sprintf("Dear %s %s, your account has been deactivated.", student.FirstName, student.LastName)
	s.sendNotification(ctx, id, student.CompanyID, title, message, models.NotificationTypeWarning, models.PriorityNormal, updatedBy)
	logger.Info("student deactivated")
	return nil
}

// ---------------------------------------------------------------------
// Promote
// ---------------------------------------------------------------------
func (s *studentService) Promote(ctx context.Context, studentID uuid.UUID, newCourseID, newSectionID uuid.UUID, updatedBy *uuid.UUID) error {
	logger := s.logger.With(
		zap.String("method", "Promote"),
		zap.String("student_id", studentID.String()),
		zap.String("new_course", newCourseID.String()),
		zap.String("new_section", newSectionID.String()),
	)
	idempotencyKey, _ := ctx.Value("idempotency_key").(string)

	tx, err := s.pgClient.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("begin tx: %w", err)
	}
	defer tx.Rollback()

	if idempotencyKey != "" {
		var result map[string]interface{}
		if err := s.idempotencyStore.Get(ctx, tx, idempotencyKey, &result); err == nil && result != nil {
			logger.Info("idempotent promote, skipping")
			return nil
		}
	}

	student, err := s.repo.GetByIDForUpdate(ctx, tx, studentID)
	if err != nil {
		return err
	}
	if student == nil {
		return fmt.Errorf("%w: student %s", ErrNotFound, studentID)
	}

	section, err := s.sectionRepo.GetByIDForUpdate(ctx, tx, newSectionID)
	if err != nil {
		return err
	}
	if section == nil {
		return fmt.Errorf("%w: section %s", ErrNotFound, newSectionID)
	}
	if section.CourseID != newCourseID {
		return fmt.Errorf("%w: section does not belong to the provided course", ErrInvalidInput)
	}

	enrolled, err := s.enrollmentRepo.CountActiveBySection(ctx, tx, newSectionID)
	if err != nil {
		return err
	}
	if section.Capacity > 0 && enrolled >= int64(section.Capacity) {
		return fmt.Errorf("%w: section %s capacity %d reached", ErrCapacityExceeded, newSectionID, section.Capacity)
	}

	ay, err := s.termRepo.GetAcademicYearByTerm(ctx, tx, section.TermID)
	if err != nil {
		return err
	}
	if ay == nil {
		return fmt.Errorf("academic year for term %s not found", section.TermID)
	}

	if err := s.enrollmentRepo.CompleteActiveEnrollment(ctx, tx, student.CompanyID, studentID, ay.AcademicYearID, updatedBy); err != nil && !errors.Is(err, sql.ErrNoRows) {
		return fmt.Errorf("failed to complete previous enrollment: %w", err)
	}
	newEnrollmentID, err := s.enrollmentRepo.CreateEnrollment(ctx, tx, student.CompanyID, studentID, ay.AcademicYearID, newSectionID, updatedBy, updatedBy)
	if err != nil {
		return fmt.Errorf("failed to create new enrollment: %w", err)
	}
	if student.Status != models.StudentActive {
		if err := s.repo.UpdateStatus(ctx, tx, studentID, string(models.StudentActive), updatedBy); err != nil {
			return err
		}
	}

	if idempotencyKey != "" {
		if err := s.idempotencyStore.Store(ctx, tx, idempotencyKey, map[string]interface{}{"promoted": true}); err != nil {
			logger.Error("failed to store idempotency key", zap.Error(err))
		}
	}

	if s.auditService != nil {
		_ = s.auditService.LogAction(ctx, nil, &student.CompanyID, "academics", "promote", "student",
			&studentID, "user", updatedBy, nil, nil, map[string]interface{}{
				"new_course_id":     newCourseID.String(),
				"new_section_id":    newSectionID.String(),
				"new_enrollment_id": newEnrollmentID.String(),
			})
	}

	if err := s.storeOutboxEvent(ctx, tx, EventStudentPromoted, student, map[string]interface{}{
		"student_id":        studentID,
		"new_course_id":     newCourseID,
		"new_section_id":    newSectionID,
		"new_enrollment_id": newEnrollmentID,
		"updated_by":        updatedBy,
	}); err != nil {
		return fmt.Errorf("outbox store: %w", err)
	}

	if err := tx.Commit(); err != nil {
		return fmt.Errorf("commit tx: %w", err)
	}

	title := "Promotion Notification"
	message := fmt.Sprintf("Dear %s %s, you have been promoted to a new class/section.", student.FirstName, student.LastName)
	s.sendNotification(ctx, studentID, student.CompanyID, title, message, models.NotificationTypeInfo, models.PriorityHigh, updatedBy)
	logger.Info("student promoted")
	return nil
}

// ---------------------------------------------------------------------
// Graduate
// ---------------------------------------------------------------------
func (s *studentService) Graduate(ctx context.Context, studentID uuid.UUID, updatedBy *uuid.UUID) error {
	logger := s.logger.With(zap.String("method", "Graduate"), zap.String("student_id", studentID.String()))
	idempotencyKey, _ := ctx.Value("idempotency_key").(string)

	tx, err := s.pgClient.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("begin tx: %w", err)
	}
	defer tx.Rollback()

	if idempotencyKey != "" {
		var result map[string]interface{}
		if err := s.idempotencyStore.Get(ctx, tx, idempotencyKey, &result); err == nil && result != nil {
			logger.Info("idempotent graduate, skipping")
			return nil
		}
	}

	student, err := s.repo.GetByIDForUpdate(ctx, tx, studentID)
	if err != nil {
		return err
	}
	if student == nil {
		return fmt.Errorf("%w: student %s", ErrNotFound, studentID)
	}
	if err := s.enrollmentRepo.CompleteAllActiveEnrollments(ctx, tx, student.CompanyID, studentID, updatedBy); err != nil {
		return fmt.Errorf("failed to complete enrollments: %w", err)
	}
	if err := s.repo.UpdateStatus(ctx, tx, studentID, string(models.StudentAlumni), updatedBy); err != nil {
		return err
	}

	if idempotencyKey != "" {
		if err := s.idempotencyStore.Store(ctx, tx, idempotencyKey, map[string]interface{}{"graduated": true}); err != nil {
			logger.Error("failed to store idempotency key", zap.Error(err))
		}
	}

	if s.auditService != nil {
		_ = s.auditService.LogAction(ctx, nil, &student.CompanyID, "academics", "graduate", "student",
			&studentID, "user", updatedBy, nil, nil, map[string]interface{}{
				"status": "alumni",
			})
	}

	if err := s.storeOutboxEvent(ctx, tx, EventStudentGraduated, student, map[string]interface{}{
		"student_id": studentID,
		"updated_by": updatedBy,
	}); err != nil {
		return fmt.Errorf("outbox store: %w", err)
	}

	if err := tx.Commit(); err != nil {
		return fmt.Errorf("commit tx: %w", err)
	}

	title := "Congratulations on Graduation!"
	message := fmt.Sprintf("Dear %s %s, congratulations on your graduation! We wish you all the best for your future endeavors.", student.FirstName, student.LastName)
	s.sendNotification(ctx, studentID, student.CompanyID, title, message, models.NotificationTypeEvent, models.PriorityHigh, updatedBy)
	logger.Info("student graduated")
	return nil
}

// ---------------------------------------------------------------------
// Dropout
// ---------------------------------------------------------------------
func (s *studentService) Dropout(ctx context.Context, studentID uuid.UUID, reason string, updatedBy *uuid.UUID) error {
	logger := s.logger.With(zap.String("method", "Dropout"), zap.String("student_id", studentID.String()))
	idempotencyKey, _ := ctx.Value("idempotency_key").(string)

	tx, err := s.pgClient.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("begin tx: %w", err)
	}
	defer tx.Rollback()

	if idempotencyKey != "" {
		var result map[string]interface{}
		if err := s.idempotencyStore.Get(ctx, tx, idempotencyKey, &result); err == nil && result != nil {
			logger.Info("idempotent dropout, skipping")
			return nil
		}
	}

	student, err := s.repo.GetByIDForUpdate(ctx, tx, studentID)
	if err != nil {
		return err
	}
	if student == nil {
		return fmt.Errorf("%w: student %s", ErrNotFound, studentID)
	}
	if err := s.enrollmentRepo.WithdrawAllActiveEnrollments(ctx, tx, student.CompanyID, studentID, updatedBy); err != nil {
		return fmt.Errorf("failed to withdraw enrollments: %w", err)
	}
	if err := s.repo.UpdateStatus(ctx, tx, studentID, string(models.StudentTransferred), updatedBy); err != nil {
		return err
	}

	if idempotencyKey != "" {
		if err := s.idempotencyStore.Store(ctx, tx, idempotencyKey, map[string]interface{}{"dropped_out": true}); err != nil {
			logger.Error("failed to store idempotency key", zap.Error(err))
		}
	}

	if s.auditService != nil {
		_ = s.auditService.LogAction(ctx, nil, &student.CompanyID, "academics", "dropout", "student",
			&studentID, "user", updatedBy, nil, nil, map[string]interface{}{
				"reason": reason,
				"status": "transferred",
			})
	}

	if err := s.storeOutboxEvent(ctx, tx, EventStudentDroppedOut, student, map[string]interface{}{
		"student_id": studentID,
		"reason":     reason,
		"updated_by": updatedBy,
	}); err != nil {
		return fmt.Errorf("outbox store: %w", err)
	}

	if err := tx.Commit(); err != nil {
		return fmt.Errorf("commit tx: %w", err)
	}

	title := "Withdrawal Confirmation"
	message := fmt.Sprintf("Dear %s %s, your withdrawal from the school has been processed. Reason: %s", student.FirstName, student.LastName, reason)
	s.sendNotification(ctx, studentID, student.CompanyID, title, message, models.NotificationTypeWarning, models.PriorityNormal, updatedBy)
	logger.Info("student dropped out")
	return nil
}

// ---------------------------------------------------------------------
// BulkPromote
// ---------------------------------------------------------------------
func (s *studentService) BulkPromote(ctx context.Context, studentIDs []uuid.UUID, newCourseID, newSectionID uuid.UUID, updatedBy *uuid.UUID) error {
	if len(studentIDs) == 0 {
		return nil
	}
	logger := s.logger.With(
		zap.String("method", "BulkPromote"),
		zap.Int("count", len(studentIDs)),
		zap.String("new_course", newCourseID.String()),
		zap.String("new_section", newSectionID.String()),
	)
	idempotencyKey, _ := ctx.Value("idempotency_key").(string)

	tx, err := s.pgClient.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("begin tx: %w", err)
	}
	defer tx.Rollback()

	if idempotencyKey != "" {
		var result map[string]interface{}
		if err := s.idempotencyStore.Get(ctx, tx, idempotencyKey, &result); err == nil && result != nil {
			logger.Info("idempotent bulk promote, skipping")
			return nil
		}
	}

	section, err := s.sectionRepo.GetByIDForUpdate(ctx, tx, newSectionID)
	if err != nil {
		return err
	}
	if section == nil {
		return fmt.Errorf("%w: section %s", ErrNotFound, newSectionID)
	}
	if section.CourseID != newCourseID {
		return fmt.Errorf("%w: section does not belong to the provided course", ErrInvalidInput)
	}
	enrolled, err := s.enrollmentRepo.CountActiveBySection(ctx, tx, newSectionID)
	if err != nil {
		return err
	}
	if section.Capacity > 0 && enrolled+int64(len(studentIDs)) > int64(section.Capacity) {
		return fmt.Errorf("%w: not enough capacity in section %s", ErrCapacityExceeded, newSectionID)
	}
	ay, err := s.termRepo.GetAcademicYearByTerm(ctx, tx, section.TermID)
	if err != nil {
		return err
	}
	if ay == nil {
		return fmt.Errorf("academic year for term %s not found", section.TermID)
	}

	for _, sid := range studentIDs {
		if err := s.promoteSingle(ctx, tx, sid, newCourseID, newSectionID, ay.AcademicYearID, updatedBy); err != nil {
			return fmt.Errorf("failed to promote student %s: %w", sid, err)
		}
	}

	if idempotencyKey != "" {
		if err := s.idempotencyStore.Store(ctx, tx, idempotencyKey, map[string]interface{}{"bulk_promoted": true}); err != nil {
			logger.Error("failed to store idempotency key", zap.Error(err))
		}
	}

	// We need a representative student for outbox aggregate; pick the first one.
	firstStudent, err := s.repo.GetByID(ctx, tx, studentIDs[0])
	if err != nil {
		return err
	}
	if err := s.storeOutboxEvent(ctx, tx, EventStudentBulkPromoted, firstStudent, map[string]interface{}{
		"student_ids":    studentIDs,
		"new_course_id":  newCourseID,
		"new_section_id": newSectionID,
		"updated_by":     updatedBy,
	}); err != nil {
		return fmt.Errorf("outbox store: %w", err)
	}

	if err := tx.Commit(); err != nil {
		return fmt.Errorf("commit tx: %w", err)
	}
	logger.Info("bulk promotion completed")
	return nil
}

func (s *studentService) promoteSingle(ctx context.Context, tx *sql.Tx, studentID uuid.UUID, newCourseID, newSectionID, academicYearID uuid.UUID, updatedBy *uuid.UUID) error {
	student, err := s.repo.GetByIDForUpdate(ctx, tx, studentID)
	if err != nil {
		return err
	}
	if student == nil {
		return fmt.Errorf("%w: student %s", ErrNotFound, studentID)
	}
	if err := s.enrollmentRepo.CompleteActiveEnrollment(ctx, tx, student.CompanyID, studentID, academicYearID, updatedBy); err != nil && !errors.Is(err, sql.ErrNoRows) {
		return fmt.Errorf("failed to complete previous enrollment: %w", err)
	}
	if _, err := s.enrollmentRepo.CreateEnrollment(ctx, tx, student.CompanyID, studentID, academicYearID, newSectionID, updatedBy, updatedBy); err != nil {
		return fmt.Errorf("failed to create new enrollment: %w", err)
	}
	if student.Status != models.StudentActive {
		if err := s.repo.UpdateStatus(ctx, tx, studentID, string(models.StudentActive), updatedBy); err != nil {
			return err
		}
	}
	return nil
}

// ---------------------------------------------------------------------
// BulkUpdateStatus
// ---------------------------------------------------------------------
func (s *studentService) BulkUpdateStatus(ctx context.Context, studentIDs []uuid.UUID, status string, updatedBy *uuid.UUID) error {
	if len(studentIDs) == 0 {
		return nil
	}
	logger := s.logger.With(zap.String("method", "BulkUpdateStatus"), zap.Int("count", len(studentIDs)), zap.String("status", status))
	idempotencyKey, _ := ctx.Value("idempotency_key").(string)

	if !models.IsValidStudentStatus(status) {
		return fmt.Errorf("%w: invalid status %q", ErrInvalidInput, status)
	}

	tx, err := s.pgClient.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("begin tx: %w", err)
	}
	defer tx.Rollback()

	if idempotencyKey != "" {
		var result map[string]interface{}
		if err := s.idempotencyStore.Get(ctx, tx, idempotencyKey, &result); err == nil && result != nil {
			logger.Info("idempotent bulk status update, skipping")
			return nil
		}
	}

	if err := s.repo.BulkUpdateStatus(ctx, tx, studentIDs, status, updatedBy); err != nil {
		return err
	}

	if idempotencyKey != "" {
		if err := s.idempotencyStore.Store(ctx, tx, idempotencyKey, map[string]interface{}{"bulk_updated": true}); err != nil {
			logger.Error("failed to store idempotency key", zap.Error(err))
		}
	}

	// Pick first student for outbox aggregate (representative)
	firstStudent, err := s.repo.GetByID(ctx, tx, studentIDs[0])
	if err != nil {
		return err
	}
	if err := s.storeOutboxEvent(ctx, tx, EventStudentBulkStatusUpdated, firstStudent, map[string]interface{}{
		"student_ids": studentIDs,
		"status":      status,
		"updated_by":  updatedBy,
	}); err != nil {
		return fmt.Errorf("outbox store: %w", err)
	}

	if err := tx.Commit(); err != nil {
		return fmt.Errorf("commit tx: %w", err)
	}
	logger.Info("bulk status update completed")
	return nil
}

// ---------------------------------------------------------------------
// Delete
// ---------------------------------------------------------------------
func (s *studentService) Delete(ctx context.Context, id uuid.UUID, deletedBy *uuid.UUID) error {
	logger := s.logger.With(zap.String("method", "Delete"), zap.String("student_id", id.String()))
	idempotencyKey, _ := ctx.Value("idempotency_key").(string)

	count, err := s.enrollmentRepo.CountActiveByStudent(ctx, s.pgClient.DB, id)
	if err != nil {
		return err
	}
	if count > 0 {
		return fmt.Errorf("%w: student has %d active enrollments", ErrHasDependencies, count)
	}

	tx, err := s.pgClient.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("begin tx: %w", err)
	}
	defer tx.Rollback()

	if idempotencyKey != "" {
		var result map[string]interface{}
		if err := s.idempotencyStore.Get(ctx, tx, idempotencyKey, &result); err == nil && result != nil {
			logger.Info("idempotent delete, skipping")
			return nil
		}
	}

	student, err := s.repo.GetByIDForUpdate(ctx, tx, id)
	if err != nil {
		return err
	}
	if student == nil {
		return fmt.Errorf("%w: student %s", ErrNotFound, id)
	}

	if err := s.repo.Delete(ctx, tx, id, deletedBy); err != nil {
		return err
	}

	if idempotencyKey != "" {
		if err := s.idempotencyStore.Store(ctx, tx, idempotencyKey, map[string]interface{}{"deleted": true}); err != nil {
			logger.Error("failed to store idempotency key", zap.Error(err))
		}
	}

	if s.auditService != nil {
		_ = s.auditService.LogAction(ctx, nil, &student.CompanyID, "academics", "delete", "student",
			&id, "user", deletedBy, nil, nil, nil)
	}

	if err := s.storeOutboxEvent(ctx, tx, EventStudentDeleted, student, map[string]interface{}{
		"student_id": id,
		"deleted_by": deletedBy,
	}); err != nil {
		return fmt.Errorf("outbox store: %w", err)
	}

	if err := tx.Commit(); err != nil {
		return fmt.Errorf("commit tx: %w", err)
	}
	logger.Info("student deleted")
	return nil
}

// ---------------------------------------------------------------------
// ValidateSectionCapacity
// ---------------------------------------------------------------------
func (s *studentService) ValidateSectionCapacity(ctx context.Context, sectionID uuid.UUID) error {
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
	enrolled, err := s.enrollmentRepo.CountActiveBySection(ctx, s.pgClient.DB, sectionID)
	if err != nil {
		return err
	}
	if enrolled >= int64(section.Capacity) {
		return fmt.Errorf("%w: section %s capacity %d reached", ErrCapacityExceeded, sectionID, section.Capacity)
	}
	return nil
}

// ---------------------------------------------------------------------
// ValidateStudentPromotion
// ---------------------------------------------------------------------
func (s *studentService) ValidateStudentPromotion(ctx context.Context, studentID uuid.UUID, newCourseID uuid.UUID) error {
	course, err := s.courseRepo.GetByID(ctx, s.pgClient.DB, newCourseID)
	if err != nil {
		return err
	}
	if course == nil {
		return fmt.Errorf("%w: course %s", ErrNotFound, newCourseID)
	}
	return nil
}

// ---------------------------------------------------------------------
// Search
// ---------------------------------------------------------------------
func (s *studentService) Search(ctx context.Context, companyID uuid.UUID, query string, limit int) ([]*models.Student, error) {
	logger := s.logger.With(
		zap.String("method", "Search"),
		zap.String("company_id", companyID.String()),
		zap.String("query", query),
	)
	query = strings.TrimSpace(query)
	if query == "" {
		return []*models.Student{}, nil
	}
	if limit <= 0 {
		limit = 20
	}
	if limit > 50 {
		limit = 50
	}
	students, err := s.repo.Search(ctx, s.pgClient.DB, companyID, query, limit)
	if err != nil {
		logger.Error("search failed", zap.Error(err))
		return nil, err
	}
	return students, nil
}

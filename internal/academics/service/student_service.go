package service

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"strings"

	"github.com/google/uuid"
	"go.uber.org/zap"

	"auth-service/internal/academics/models"
	"auth-service/internal/academics/repository"
	"auth-service/internal/client"
)

// ---------------------------------------------------------------------
// Request DTOs
// ---------------------------------------------------------------------

// ---------------------------------------------------------------------
// Enterprise interfaces (updated for transactional idempotency)
// ---------------------------------------------------------------------

type IdempotencyStore interface {
	Exists(ctx context.Context, tx *sql.Tx, key string) (bool, error)
	Store(ctx context.Context, tx *sql.Tx, key string, response interface{}) error
	Get(ctx context.Context, key string, target interface{}) error // now accepts a target to unmarshal into
}

type AuditLogger interface {
	Log(ctx context.Context, action string, entityID uuid.UUID, old, new interface{}, userID *uuid.UUID) error
}

type OutboxStore interface {
	Store(ctx context.Context, tx *sql.Tx, eventType string, payload interface{}) error
}

// ---------------------------------------------------------------------
// StudentService interface
// ---------------------------------------------------------------------

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

// ---------------------------------------------------------------------
// studentService struct
// ---------------------------------------------------------------------

type studentService struct {
	repo           repository.StudentRepository
	enrollmentRepo repository.EnrollmentRepository
	sectionRepo    repository.SectionRepository
	courseRepo     repository.CourseRepository
	termRepo       repository.TermRepository
	ayRepo         repository.AcademicYearRepository

	idempotencyStore IdempotencyStore
	auditLogger      AuditLogger
	outboxStore      OutboxStore
	eventPublisher   EventPublisher
	pgClient         *client.PostgresClient
	logger           *zap.Logger
}

// NewStudentService creates a new student service.
func NewStudentService(
	repo repository.StudentRepository,
	enrollmentRepo repository.EnrollmentRepository,
	sectionRepo repository.SectionRepository,
	courseRepo repository.CourseRepository,
	termRepo repository.TermRepository,
	ayRepo repository.AcademicYearRepository,
	idempotencyStore IdempotencyStore,
	auditLogger AuditLogger,
	outboxStore OutboxStore,
	eventPublisher EventPublisher,
	pgClient *client.PostgresClient,
	logger *zap.Logger,
) StudentService {
	return &studentService{
		repo:             repo,
		enrollmentRepo:   enrollmentRepo,
		sectionRepo:      sectionRepo,
		courseRepo:       courseRepo,
		termRepo:         termRepo,
		ayRepo:           ayRepo,
		idempotencyStore: idempotencyStore,
		auditLogger:      auditLogger,
		outboxStore:      outboxStore,
		eventPublisher:   eventPublisher,
		pgClient:         pgClient,
		logger:           logger.Named("student_service"),
	}
}

// ---------------------------------------------------------------------
// Input sanitization helpers
// ---------------------------------------------------------------------

func (s *studentService) sanitizeCreate(req *CreateStudentRequest) {
	req.FirstName = strings.TrimSpace(req.FirstName)
	req.LastName = strings.TrimSpace(req.LastName)
	req.AdmissionNo = strings.TrimSpace(strings.ToUpper(req.AdmissionNo)) // normalize
	req.Email = strings.TrimSpace(req.Email)                              // NEW
	req.Phone = strings.TrimSpace(req.Phone)                              // NEW
	// other fields could be trimmed as needed
}

func (s *studentService) sanitizeUpdate(req *UpdateStudentRequest) {
	req.AdmissionNo = strings.TrimSpace(strings.ToUpper(req.AdmissionNo))
	req.Email = strings.TrimSpace(req.Email) // NEW
	req.Phone = strings.TrimSpace(req.Phone) // NEW
}

// ---------------------------------------------------------------------
// Validation helpers (using models enums)
// ---------------------------------------------------------------------

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
// Core CRUD
// ---------------------------------------------------------------------

func (s *studentService) Create(ctx context.Context, req CreateStudentRequest, idempotencyKey string) (*models.Student, error) {
	logger := s.logger.With(
		zap.String("method", "Create"),
		zap.String("company_id", req.CompanyID.String()),
		zap.String("admission_no", req.AdmissionNo),
		zap.String("idempotency_key", idempotencyKey),
	)

	s.sanitizeCreate(&req)

	// Start transaction early – idempotency check must be inside the same TX
	tx, err := s.pgClient.BeginTx(ctx, nil)
	if err != nil {
		return nil, fmt.Errorf("begin tx: %w", err)
	}
	defer tx.Rollback()

	// Idempotency check – now race‑safe
	if idempotencyKey != "" {
		exists, err := s.idempotencyStore.Exists(ctx, tx, idempotencyKey)
		if err != nil {
			return nil, fmt.Errorf("idempotency check: %w", err)
		}
		if exists {
			var student models.Student
			if err := s.idempotencyStore.Get(ctx, idempotencyKey, &student); err != nil {
				return nil, fmt.Errorf("failed to retrieve idempotent response: %w", err)
			}
			logger.Info("returning idempotent response")
			return &student, nil
		}
	}

	if err := s.validateCreateInput(req); err != nil {
		return nil, err
	}

	// Uniqueness check
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
		Email:                 req.Email, // NEW
		Phone:                 req.Phone, // NEW
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

	// Store idempotency key within the same transaction
	if idempotencyKey != "" {
		if err := s.idempotencyStore.Store(ctx, tx, idempotencyKey, student); err != nil {
			logger.Error("failed to store idempotency key", zap.Error(err))
			return nil, fmt.Errorf("failed to store idempotency key: %w", err)
		}
	}

	// Audit log (currently not TX‑aware – consider improving later)
	if err := s.auditLogger.Log(ctx, "CREATE", student.StudentID, nil, student, req.CreatedBy); err != nil {
		logger.Error("audit log failed", zap.Error(err))
	}

	// Outbox event (payload could be slimmed down in future)
	if err := s.outboxStore.Store(ctx, tx, string(EventStudentCreated), student); err != nil {
		logger.Error("failed to store outbox event", zap.Error(err))
		return nil, fmt.Errorf("failed to store outbox event: %w", err)
	}

	if err := tx.Commit(); err != nil {
		return nil, fmt.Errorf("commit tx: %w", err)
	}

	logger.Info("student created", zap.String("id", student.StudentID.String()))
	return student, nil
}

func (s *studentService) BulkCreate(ctx context.Context, reqs []CreateStudentRequest) ([]*models.Student, error) {
	if len(reqs) == 0 {
		return nil, nil
	}
	logger := s.logger.With(zap.String("method", "BulkCreate"), zap.Int("count", len(reqs)))

	// Sanitize all
	for i := range reqs {
		s.sanitizeCreate(&reqs[i])
	}

	// Pre‑check duplicate admission numbers in batch
	type key struct {
		companyID uuid.UUID
		admission string
	}
	batchKeys := make(map[key]int)
	for i, req := range reqs {
		if err := s.validateCreateInput(req); err != nil {
			return nil, fmt.Errorf("item %d: %w", i, err)
		}
		k := key{companyID: req.CompanyID, admission: req.AdmissionNo}
		if _, dup := batchKeys[k]; dup {
			return nil, fmt.Errorf("item %d: %w: duplicate admission number %s in batch", i, ErrDuplicate, req.AdmissionNo)
		}
		batchKeys[k] = i
	}

	tx, err := s.pgClient.BeginTx(ctx, nil)
	if err != nil {
		return nil, fmt.Errorf("begin tx: %w", err)
	}
	defer tx.Rollback()

	// Check DB for existing admission numbers
	for k := range batchKeys {
		exists, err := s.repo.ExistsByAdmissionNumber(ctx, tx, k.companyID, k.admission)
		if err != nil {
			return nil, err
		}
		if exists {
			return nil, fmt.Errorf("%w: admission number %s already exists", ErrDuplicate, k.admission)
		}
	}

	students := make([]*models.Student, 0, len(reqs))
	for _, req := range reqs {
		students = append(students, &models.Student{
			CompanyID:             req.CompanyID,
			FirstName:             req.FirstName,
			LastName:              req.LastName,
			AdmissionNo:           req.AdmissionNo,
			Email:                 req.Email, // NEW
			Phone:                 req.Phone, // NEW
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

	// Audit and outbox for each student – inside transaction
	for _, stu := range students {
		if err := s.auditLogger.Log(ctx, "CREATE", stu.StudentID, nil, stu, stu.CreatedBy); err != nil {
			logger.Error("audit log failed", zap.String("student_id", stu.StudentID.String()), zap.Error(err))
		}
		if err := s.outboxStore.Store(ctx, tx, string(EventStudentCreated), stu); err != nil {
			logger.Error("failed to store outbox event", zap.String("student_id", stu.StudentID.String()), zap.Error(err))
			return nil, fmt.Errorf("failed to store outbox event for student %s: %w", stu.StudentID, err)
		}
	}

	if err := tx.Commit(); err != nil {
		return nil, fmt.Errorf("commit tx: %w", err)
	}

	logger.Info("bulk created students", zap.Int("count", len(students)))
	return students, nil
}

func (s *studentService) Upsert(ctx context.Context, req CreateStudentRequest) (*models.Student, error) {
	logger := s.logger.With(
		zap.String("method", "Upsert"),
		zap.String("company_id", req.CompanyID.String()),
		zap.String("admission_no", req.AdmissionNo),
	)

	s.sanitizeCreate(&req)
	if err := s.validateCreateInput(req); err != nil {
		return nil, err
	}

	tx, err := s.pgClient.BeginTx(ctx, nil)
	if err != nil {
		return nil, fmt.Errorf("begin tx: %w", err)
	}
	defer tx.Rollback()

	// ✅ Fix: handle error from GetByAdmissionNumber
	existing, err := s.repo.GetByAdmissionNumber(ctx, tx, req.CompanyID, req.AdmissionNo)
	if err != nil {
		return nil, err
	}

	student := &models.Student{
		CompanyID:             req.CompanyID,
		FirstName:             req.FirstName,
		LastName:              req.LastName,
		AdmissionNo:           req.AdmissionNo,
		Email:                 req.Email, // NEW
		Phone:                 req.Phone, // NEW
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

	var eventType EventType
	if existing == nil {
		eventType = EventStudentCreated
		if err := s.repo.Create(ctx, tx, student); err != nil {
			return nil, err
		}
	} else {
		eventType = EventStudentUpdated
		student.StudentID = existing.StudentID
		student.Version = existing.Version
		if err := s.repo.Update(ctx, tx, student); err != nil {
			return nil, err
		}
	}

	// Audit
	if err := s.auditLogger.Log(ctx, "UPSERT", student.StudentID, existing, student, req.UpdatedBy); err != nil {
		logger.Error("audit log failed", zap.Error(err))
	}

	// Outbox
	if err := s.outboxStore.Store(ctx, tx, string(eventType), student); err != nil {
		logger.Error("failed to store outbox event", zap.Error(err))
		return nil, fmt.Errorf("failed to store outbox event: %w", err)
	}

	if err := tx.Commit(); err != nil {
		return nil, fmt.Errorf("commit tx: %w", err)
	}

	logger.Info("student upserted", zap.String("id", student.StudentID.String()))
	return student, nil
}

// GetByID, GetByAdmissionNumber, List, ListActive, Count, Exists – unchanged except no UserID.
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

func (s *studentService) List(ctx context.Context, filter repository.StudentFilter, p repository.Pagination, srt repository.Sort) ([]*models.Student, error) {
	return s.repo.List(ctx, s.pgClient.DB, filter, p, srt)
}

func (s *studentService) ListActive(ctx context.Context, companyID uuid.UUID) ([]*models.Student, error) {
	return s.repo.ListActive(ctx, s.pgClient.DB, companyID)
}

func (s *studentService) Count(ctx context.Context, filter repository.StudentFilter) (int64, error) {
	return s.repo.Count(ctx, s.pgClient.DB, filter)
}

func (s *studentService) Exists(ctx context.Context, companyID uuid.UUID, admissionNo string) (bool, error) {
	admissionNo = strings.TrimSpace(strings.ToUpper(admissionNo))
	return s.repo.ExistsByAdmissionNumber(ctx, s.pgClient.DB, companyID, admissionNo)
}

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

func (s *studentService) Update(ctx context.Context, req UpdateStudentRequest) (*models.Student, error) {
	logger := s.logger.With(zap.String("method", "Update"), zap.String("student_id", req.StudentID.String()))

	s.sanitizeUpdate(&req)
	if err := s.validateUpdateInput(req); err != nil {
		return nil, err
	}

	tx, err := s.pgClient.BeginTx(ctx, nil)
	if err != nil {
		return nil, fmt.Errorf("begin tx: %w", err)
	}
	defer tx.Rollback()

	student, err := s.repo.GetByIDForUpdate(ctx, tx, req.StudentID)
	if err != nil {
		return nil, err
	}
	if student == nil {
		return nil, fmt.Errorf("%w: student %s", ErrNotFound, req.StudentID)
	}

	// Check admission number uniqueness if changed
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
	student.Email = req.Email // NEW
	student.Phone = req.Phone // NEW
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
		student.Status = models.StudentStatus(req.Status) // ✅ enum
	}
	student.UpdatedBy = req.UpdatedBy

	if err := s.repo.Update(ctx, tx, student); err != nil {
		if errors.Is(err, repository.ErrNotFound) {
			return nil, fmt.Errorf("%w: student was modified concurrently", ErrConcurrentUpdate)
		}
		return nil, err
	}

	// Audit
	if err := s.auditLogger.Log(ctx, "UPDATE", student.StudentID, oldStudent, student, req.UpdatedBy); err != nil {
		logger.Error("audit log failed", zap.Error(err))
	}

	// Outbox
	if err := s.outboxStore.Store(ctx, tx, string(EventStudentUpdated), map[string]interface{}{
		"old": oldStudent,
		"new": student,
	}); err != nil {
		logger.Error("failed to store outbox event", zap.Error(err))
		return nil, fmt.Errorf("failed to store outbox event: %w", err)
	}

	if err := tx.Commit(); err != nil {
		return nil, fmt.Errorf("commit tx: %w", err)
	}

	logger.Info("student updated")
	return student, nil
}

func (s *studentService) UpdateContactInfo(ctx context.Context, studentID uuid.UUID, phone string, updatedBy *uuid.UUID) error {
	logger := s.logger.With(zap.String("method", "UpdateContactInfo"), zap.String("student_id", studentID.String()))
	tx, err := s.pgClient.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("begin tx: %w", err)
	}
	defer tx.Rollback()

	if err := s.repo.UpdateContactInfo(ctx, tx, studentID, phone, updatedBy); err != nil {
		return err
	}

	// Audit
	if err := s.auditLogger.Log(ctx, "UPDATE_CONTACT", studentID, nil, map[string]string{"phone": phone}, updatedBy); err != nil {
		logger.Error("audit log failed", zap.Error(err))
	}

	// Outbox
	if err := s.outboxStore.Store(ctx, tx, string(EventStudentContactUpdated), map[string]interface{}{
		"student_id": studentID,
		"phone":      phone,
		"updated_by": updatedBy,
	}); err != nil {
		logger.Error("failed to store outbox event", zap.Error(err))
		return fmt.Errorf("failed to store outbox event: %w", err)
	}

	if err := tx.Commit(); err != nil {
		return fmt.Errorf("commit tx: %w", err)
	}
	logger.Info("contact info updated")
	return nil
}

func (s *studentService) Activate(ctx context.Context, id uuid.UUID, updatedBy *uuid.UUID) error {
	logger := s.logger.With(zap.String("method", "Activate"), zap.String("student_id", id.String()))
	tx, err := s.pgClient.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("begin tx: %w", err)
	}
	defer tx.Rollback()

	if err := s.repo.Activate(ctx, tx, id, updatedBy); err != nil {
		return err
	}

	if err := s.auditLogger.Log(ctx, "ACTIVATE", id, nil, nil, updatedBy); err != nil {
		logger.Error("audit log failed", zap.Error(err))
	}
	if err := s.outboxStore.Store(ctx, tx, string(EventStudentActivated), map[string]interface{}{
		"student_id": id,
		"updated_by": updatedBy,
	}); err != nil {
		logger.Error("failed to store outbox event", zap.Error(err))
		return fmt.Errorf("failed to store outbox event: %w", err)
	}

	if err := tx.Commit(); err != nil {
		return fmt.Errorf("commit tx: %w", err)
	}
	logger.Info("student activated")
	return nil
}

func (s *studentService) Deactivate(ctx context.Context, id uuid.UUID, updatedBy *uuid.UUID) error {
	logger := s.logger.With(zap.String("method", "Deactivate"), zap.String("student_id", id.String()))
	tx, err := s.pgClient.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("begin tx: %w", err)
	}
	defer tx.Rollback()

	if err := s.repo.Deactivate(ctx, tx, id, updatedBy); err != nil {
		return err
	}

	if err := s.auditLogger.Log(ctx, "DEACTIVATE", id, nil, nil, updatedBy); err != nil {
		logger.Error("audit log failed", zap.Error(err))
	}
	if err := s.outboxStore.Store(ctx, tx, string(EventStudentDeactivated), map[string]interface{}{
		"student_id": id,
		"updated_by": updatedBy,
	}); err != nil {
		logger.Error("failed to store outbox event", zap.Error(err))
		return fmt.Errorf("failed to store outbox event: %w", err)
	}

	if err := tx.Commit(); err != nil {
		return fmt.Errorf("commit tx: %w", err)
	}
	logger.Info("student deactivated")
	return nil
}

// ---------------------------------------------------------------------
// Business operations
// ---------------------------------------------------------------------

func (s *studentService) Promote(ctx context.Context, studentID uuid.UUID, newCourseID, newSectionID uuid.UUID, updatedBy *uuid.UUID) error {
	logger := s.logger.With(
		zap.String("method", "Promote"),
		zap.String("student_id", studentID.String()),
		zap.String("new_course", newCourseID.String()),
		zap.String("new_section", newSectionID.String()),
	)

	tx, err := s.pgClient.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("begin tx: %w", err)
	}
	defer tx.Rollback()

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

	var oldEnrollmentID uuid.UUID
	err = tx.QueryRowContext(ctx, `
		SELECT enrollment_id FROM academics.enrollments
		WHERE student_id = $1 AND academic_year_id = $2 AND status = 'active' AND deleted_at IS NULL
	`, studentID, ay.AcademicYearID).Scan(&oldEnrollmentID)
	if err != nil && !errors.Is(err, sql.ErrNoRows) {
		return fmt.Errorf("failed to check active enrollment: %w", err)
	}
	if err == nil {
		_, err = tx.ExecContext(ctx, `
			UPDATE academics.enrollments
			SET status = 'completed', updated_at = NOW(), updated_by = $2
			WHERE enrollment_id = $1 AND deleted_at IS NULL
		`, oldEnrollmentID, updatedBy)
		if err != nil {
			return fmt.Errorf("failed to update previous enrollment to completed: %w", err)
		}
	}

	var newEnrollmentID uuid.UUID
	err = tx.QueryRowContext(ctx, `
		INSERT INTO academics.enrollments (
			student_id, academic_year_id, section_id, enrollment_date, status,
			created_by, updated_by, created_at, updated_at
		) VALUES ($1, $2, $3, NOW(), 'active', $4, $5, NOW(), NOW())
		RETURNING enrollment_id
	`, studentID, ay.AcademicYearID, newSectionID, updatedBy, updatedBy).Scan(&newEnrollmentID)
	if err != nil {
		return fmt.Errorf("failed to create new enrollment: %w", err)
	}

	// ✅ enum comparison
	if student.Status != models.StudentActive {
		if err := s.repo.UpdateStatus(ctx, tx, studentID, string(models.StudentActive), updatedBy); err != nil {
			return err
		}
	}

	if err := s.auditLogger.Log(ctx, "PROMOTE", studentID,
		map[string]interface{}{"old_enrollment": oldEnrollmentID},
		map[string]interface{}{"new_enrollment": newEnrollmentID, "new_course": newCourseID, "new_section": newSectionID},
		updatedBy); err != nil {
		logger.Error("audit log failed", zap.Error(err))
	}

	if err := s.outboxStore.Store(ctx, tx, string(EventStudentPromoted), map[string]interface{}{
		"student_id":        studentID,
		"new_course_id":     newCourseID,
		"new_section_id":    newSectionID,
		"new_enrollment_id": newEnrollmentID,
		"updated_by":        updatedBy,
	}); err != nil {
		logger.Error("failed to store outbox event", zap.Error(err))
		return fmt.Errorf("failed to store outbox event: %w", err)
	}

	if err := tx.Commit(); err != nil {
		return fmt.Errorf("commit tx: %w", err)
	}

	logger.Info("student promoted")
	return nil
}

func (s *studentService) Graduate(ctx context.Context, studentID uuid.UUID, updatedBy *uuid.UUID) error {
	logger := s.logger.With(zap.String("method", "Graduate"), zap.String("student_id", studentID.String()))
	tx, err := s.pgClient.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("begin tx: %w", err)
	}
	defer tx.Rollback()

	student, err := s.repo.GetByIDForUpdate(ctx, tx, studentID)
	if err != nil {
		return err
	}
	if student == nil {
		return fmt.Errorf("%w: student %s", ErrNotFound, studentID)
	}

	_, err = tx.ExecContext(ctx, `
		UPDATE academics.enrollments
		SET status = 'completed', updated_at = NOW(), updated_by = $2
		WHERE student_id = $1 AND status = 'active' AND deleted_at IS NULL
	`, studentID, updatedBy)
	if err != nil {
		return fmt.Errorf("failed to complete enrollments: %w", err)
	}

	if err := s.repo.UpdateStatus(ctx, tx, studentID, string(models.StudentAlumni), updatedBy); err != nil {
		return err
	}

	if err := s.auditLogger.Log(ctx, "GRADUATE", studentID, student, &models.Student{Status: models.StudentAlumni}, updatedBy); err != nil {
		logger.Error("audit log failed", zap.Error(err))
	}

	if err := s.outboxStore.Store(ctx, tx, string(EventStudentGraduated), map[string]interface{}{
		"student_id": studentID,
		"updated_by": updatedBy,
	}); err != nil {
		logger.Error("failed to store outbox event", zap.Error(err))
		return fmt.Errorf("failed to store outbox event: %w", err)
	}

	if err := tx.Commit(); err != nil {
		return fmt.Errorf("commit tx: %w", err)
	}
	logger.Info("student graduated")
	return nil
}

func (s *studentService) Dropout(ctx context.Context, studentID uuid.UUID, reason string, updatedBy *uuid.UUID) error {
	logger := s.logger.With(zap.String("method", "Dropout"), zap.String("student_id", studentID.String()))
	tx, err := s.pgClient.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("begin tx: %w", err)
	}
	defer tx.Rollback()

	student, err := s.repo.GetByIDForUpdate(ctx, tx, studentID)
	if err != nil {
		return err
	}
	if student == nil {
		return fmt.Errorf("%w: student %s", ErrNotFound, studentID)
	}

	_, err = tx.ExecContext(ctx, `
		UPDATE academics.enrollments
		SET status = 'withdrawn', updated_at = NOW(), updated_by = $2
		WHERE student_id = $1 AND status = 'active' AND deleted_at IS NULL
	`, studentID, updatedBy)
	if err != nil {
		return fmt.Errorf("failed to withdraw enrollments: %w", err)
	}

	if err := s.repo.UpdateStatus(ctx, tx, studentID, string(models.StudentTransferred), updatedBy); err != nil {
		return err
	}

	if err := s.auditLogger.Log(ctx, "DROPOUT", studentID, student, &models.Student{Status: models.StudentTransferred}, updatedBy); err != nil {
		logger.Error("audit log failed", zap.Error(err))
	}

	if err := s.outboxStore.Store(ctx, tx, string(EventStudentDroppedOut), map[string]interface{}{
		"student_id": studentID,
		"reason":     reason,
		"updated_by": updatedBy,
	}); err != nil {
		logger.Error("failed to store outbox event", zap.Error(err))
		return fmt.Errorf("failed to store outbox event: %w", err)
	}

	if err := tx.Commit(); err != nil {
		return fmt.Errorf("commit tx: %w", err)
	}
	logger.Info("student dropped out")
	return nil
}

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

	tx, err := s.pgClient.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("begin tx: %w", err)
	}
	defer tx.Rollback()

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

	if err := s.outboxStore.Store(ctx, tx, string(EventStudentBulkPromoted), map[string]interface{}{
		"student_ids":    studentIDs,
		"new_course_id":  newCourseID,
		"new_section_id": newSectionID,
		"updated_by":     updatedBy,
	}); err != nil {
		logger.Error("failed to store outbox event", zap.Error(err))
		return fmt.Errorf("failed to store outbox event: %w", err)
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

	var oldEnrollmentID uuid.UUID
	err = tx.QueryRowContext(ctx, `
		SELECT enrollment_id FROM academics.enrollments
		WHERE student_id = $1 AND academic_year_id = $2 AND status = 'active' AND deleted_at IS NULL
	`, studentID, academicYearID).Scan(&oldEnrollmentID)
	if err != nil && !errors.Is(err, sql.ErrNoRows) {
		return fmt.Errorf("failed to check active enrollment: %w", err)
	}
	if err == nil {
		_, err = tx.ExecContext(ctx, `
			UPDATE academics.enrollments
			SET status = 'completed', updated_at = NOW(), updated_by = $2
			WHERE enrollment_id = $1 AND deleted_at IS NULL
		`, oldEnrollmentID, updatedBy)
		if err != nil {
			return fmt.Errorf("failed to update previous enrollment: %w", err)
		}
	}

	_, err = tx.ExecContext(ctx, `
		INSERT INTO academics.enrollments (
			student_id, academic_year_id, section_id, enrollment_date, status,
			created_by, updated_by, created_at, updated_at
		) VALUES ($1, $2, $3, NOW(), 'active', $4, $5, NOW(), NOW())
	`, studentID, academicYearID, newSectionID, updatedBy, updatedBy)
	if err != nil {
		return fmt.Errorf("failed to create new enrollment: %w", err)
	}

	if student.Status != models.StudentActive {
		if err := s.repo.UpdateStatus(ctx, tx, studentID, string(models.StudentActive), updatedBy); err != nil {
			return err
		}
	}
	return nil
}

func (s *studentService) BulkUpdateStatus(ctx context.Context, studentIDs []uuid.UUID, status string, updatedBy *uuid.UUID) error {
	if len(studentIDs) == 0 {
		return nil
	}
	logger := s.logger.With(zap.String("method", "BulkUpdateStatus"), zap.Int("count", len(studentIDs)), zap.String("status", status))

	if !models.IsValidStudentStatus(status) {
		return fmt.Errorf("%w: invalid status %q", ErrInvalidInput, status)
	}

	tx, err := s.pgClient.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("begin tx: %w", err)
	}
	defer tx.Rollback()

	if err := s.repo.BulkUpdateStatus(ctx, tx, studentIDs, status, updatedBy); err != nil {
		return err
	}

	if err := s.outboxStore.Store(ctx, tx, string(EventStudentBulkStatusUpdated), map[string]interface{}{
		"student_ids": studentIDs,
		"status":      status,
		"updated_by":  updatedBy,
	}); err != nil {
		logger.Error("failed to store outbox event", zap.Error(err))
		return fmt.Errorf("failed to store outbox event: %w", err)
	}

	if err := tx.Commit(); err != nil {
		return fmt.Errorf("commit tx: %w", err)
	}
	logger.Info("bulk status update completed")
	return nil
}

func (s *studentService) Delete(ctx context.Context, id uuid.UUID, deletedBy *uuid.UUID) error {
	logger := s.logger.With(zap.String("method", "Delete"), zap.String("student_id", id.String()))

	// CountActiveByStudent must be implemented in enrollmentRepo
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

	if err := s.repo.Delete(ctx, tx, id, deletedBy); err != nil {
		return err
	}

	if err := s.auditLogger.Log(ctx, "DELETE", id, nil, nil, deletedBy); err != nil {
		logger.Error("audit log failed", zap.Error(err))
	}

	if err := s.outboxStore.Store(ctx, tx, string(EventStudentDeleted), map[string]interface{}{
		"student_id": id,
		"deleted_by": deletedBy,
	}); err != nil {
		logger.Error("failed to store outbox event", zap.Error(err))
		return fmt.Errorf("failed to store outbox event: %w", err)
	}

	if err := tx.Commit(); err != nil {
		return fmt.Errorf("commit tx: %w", err)
	}
	logger.Info("student deleted")
	return nil
}

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
		limit = 50 // prevent abuse
	}

	students, err := s.repo.Search(ctx, s.pgClient.DB, companyID, query, limit)
	if err != nil {
		logger.Error("search failed", zap.Error(err))
		return nil, err
	}
	return students, nil
}
